"""Recovery and destructive-order gates for the review handover coordinator."""
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace

from . import case_review_handover as review
from .case_runtime_bootstrap import BootstrapStopped
from .staging_participant_flux_bootstrap import ReceiptSink, RawResult, canonical_sha256

NOW = datetime(2026, 9, 10, 12, tzinfo=timezone.utc)
sha = lambda value: canonical_sha256(value)
uid = lambda number: f'00000000-0000-4000-8000-{number:012d}'


def fixture():
    plan = {'schemaVersion':'roebel_review_handover_plan_v1','operationId':'a'*64,
            'caseId':'urn:stadtstack:synthetic-case:municipality:roebel-mueritz:'+uid(100),
            'pins':{k:sha(k) for k in review.PINS},
            'identities':{k:uid(i+1) for i,k in enumerate(sorted(review.IDENTITIES))},
            'notBeforeUtc':'2026-09-10T11:59:00.000Z','expiresAtUtc':'2026-09-10T12:59:00.000Z'}
    plan['pins']['operationsRevision'] = 'b'*40
    plan['planSha256'] = sha(plan)
    ids, pins = plan['identities'], plan['pins']
    take = lambda source, *keys:{k:source[k] for k in keys}
    backup = {'sourceSealChecksum':sha('seal'),'sourceDeploymentClaimChecksum':sha('claim'),
              'sourceDatabaseSha256':sha('database'),'encryptedArchiveSha256':sha('encrypted'),
              'restoredFilesSha256':sha('files'),'sourceFilesSha256':sha('files'),
              'caseId':plan['caseId'],'caseVersion':3,'admissionReceiptChecksum':pins['admissionReceiptChecksum']}
    evidence = {
        'fence-source':take(ids,'sourceDeploymentUid','reconcilerUid') | {'sourceReplicas':0,'reconcilerSuspended':True},
        'release-mounts':take(ids,'sourcePodUid','initializerPodUid','nodeUid') | dict.fromkeys(('sourceApiAbsent','initializerApiAbsent','sourceMountAbsent','initializerMountAbsent','positiveControlVerified'),True),
        'verify-backup':backup,
        'prepare-migration':take(backup,'sourceSealChecksum','sourceDeploymentClaimChecksum','admissionReceiptChecksum') | {'candidateChecksum':sha('candidate'),'targetDeploymentClaimChecksum':pins['targetDeploymentClaimChecksum']},
        'activate-migration':take(backup,'sourceSealChecksum','sourceDeploymentClaimChecksum','sourceDatabaseSha256') | {'activationReceiptChecksum':sha('activation'),'candidateChecksum':sha('candidate'),'targetDeploymentClaimChecksum':pins['targetDeploymentClaimChecksum'],'targetSealChecksum':sha('target seal')},
        'release-migration':{'migrationPodUid':uid(500),'apiAbsent':True,'mountAbsent':True,'positiveControlVerified':True},
        'start-review-runtime':take(ids,'sourceDeploymentUid','targetPvcUid','configurationSecretUid') | take(pins,'targetBindingSha256','migrationImageDigest') | {'runtimePodUid':uid(501)},
        'verify-review-runtime':{'runtimePodUid':uid(501),'admissionReceiptChecksum':pins['admissionReceiptChecksum'],'allFourListenersReady':True,'cleanRestartVerified':True,'sourceDatabaseSha256':backup['sourceDatabaseSha256'],'publicServicesPreserved':True},
        'restore-gitops':{'reconcilerUid':ids['reconcilerUid'],'reconcilerSuspended':False,'targetRenderSha256':pins['targetRenderSha256'],'reconciled':True,'sourceRetained':True,'targetRetained':True},
    }
    for key,value in evidence.items():value['receiptSha256'] = sha(key)
    return plan, evidence


class Adapter:
    def __init__(self, evidence, sink):
        self.evidence,self.sink=evidence,sink
        self.observed={};self.effects=[];self.lost=None;self.wait=None;self.fail=None;self.ready=True
    def verify_ready(self,plan,state):
        if not self.ready:raise RuntimeError('complete implementation missing')
    def observe(self,plan,step,state):
        return copy.deepcopy(self.observed.get(step))
    def perform(self,plan,step,state):
        saved=json.loads(self.sink.path.read_text())
        assert saved['pending']==step and saved['status']=='effect-intent'
        self.effects.append(step)
        if step==self.fail:raise RuntimeError('private payload must not escape')
        if step!=self.wait:self.observed[step]=copy.deepcopy(self.evidence[step])
        if step==self.lost:raise TimeoutError('lost response')


class ReviewHandoverTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.plan,self.evidence=fixture();self.index=0
        self.sink=self.new_sink();self.adapter=Adapter(self.evidence,self.sink)
    def new_sink(self):
        self.index+=1
        return ReceiptSink.reserve(Path(self.directory.name)/f'receipt-{self.index}.json')
    def advance(self,prior=None,pin=None,clock=lambda:NOW):
        return review.advance_review_handover(self.plan,expected_plan_sha256=self.plan['planSha256'],adapter=self.adapter,sink=self.sink,
                   prior=prior,expected_prior_sha256=pin,clock=clock)
    def resume(self):
        prior=json.loads(self.sink.path.read_text());self.sink=self.new_sink();self.adapter.sink=self.sink
        return self.advance(prior,prior['canonicalSha256'])
    def test_complete_flow_rechecks_receipts_and_never_replays_completed_effects(self):
        result=self.advance();self.assertEqual(result['status'],'complete')
        self.assertEqual(self.adapter.effects,list(review.STEPS))
        self.assertEqual(self.resume()['status'],'complete')
        self.assertEqual(self.adapter.effects,list(review.STEPS))
    def test_missing_complete_implementation_prevents_source_shutdown(self):
        self.adapter.ready=False
        with self.assertRaises(BootstrapStopped):self.advance()
        self.assertEqual(self.adapter.effects,[])
    def test_lost_response_at_every_stage_is_observed_not_repeated(self):
        for step in review.STEPS:
            with self.subTest(step=step):
                self.sink=self.new_sink();self.adapter=Adapter(self.evidence,self.sink);self.adapter.lost=step
                self.assertEqual(self.advance()['status'],'complete')
                self.assertEqual(self.adapter.effects,list(review.STEPS))
    def test_incomplete_stage_waits_across_recovery_without_repeating_effect(self):
        self.adapter.wait='activate-migration'
        self.assertEqual(self.advance()['status'],'awaiting-evidence')
        sent=list(self.adapter.effects)
        self.assertEqual(self.resume()['status'],'awaiting-evidence');self.assertEqual(self.adapter.effects,sent)
        self.adapter.observed['activate-migration']=copy.deepcopy(self.evidence['activate-migration'])
        self.assertEqual(self.resume()['status'],'complete');self.assertEqual(self.adapter.effects,list(review.STEPS))
    def test_failure_keeps_fence_and_never_automatically_restores_gitops(self):
        self.adapter.fail='activate-migration'
        with self.assertRaisesRegex(BootstrapStopped,'retain both stores'):self.advance()
        self.assertNotIn('restore-gitops',self.adapter.effects)
        self.assertTrue(self.adapter.observed['fence-source']['reconcilerSuspended'])
        self.assertEqual(self.resume()['status'],'awaiting-evidence')
        self.assertEqual(self.adapter.effects.count('activate-migration'),1)
        self.assertNotIn('private payload',self.sink.path.read_text())
    def test_backup_mount_release_activation_and_runtime_failures_block_next_effect(self):
        faults=[('release-mounts','sourceMountAbsent',False),('verify-backup','restoredFilesSha256',sha('wrong')),
                ('verify-backup','caseVersion',4),('prepare-migration','sourceSealChecksum',sha('new seal')),
                ('activate-migration','candidateChecksum',sha('wrong candidate')),
                ('activate-migration','sourceDeploymentClaimChecksum',sha('wrong claim')),
                ('release-migration','mountAbsent',False),('start-review-runtime','targetPvcUid',uid(800)),
                ('verify-review-runtime','cleanRestartVerified',False),('verify-review-runtime','admissionReceiptChecksum',sha('new admission'))]
        for step,key,value in faults:
            with self.subTest(step=step,key=key):
                evidence=copy.deepcopy(self.evidence);evidence[step][key]=value
                self.sink=self.new_sink();self.adapter=Adapter(evidence,self.sink)
                with self.assertRaises(BootstrapStopped):self.advance()
                self.assertEqual(self.adapter.effects[-1],step)
                self.assertNotIn('restore-gitops',self.adapter.effects)
    def test_already_present_effect_without_owned_intent_is_not_adopted(self):
        self.adapter.observed['fence-source']=self.evidence['fence-source']
        with self.assertRaises(BootstrapStopped):self.advance()
        self.assertEqual(self.adapter.effects,[])
    def test_changed_or_skipped_prior_evidence_is_rejected(self):
        self.adapter.wait='verify-backup';self.advance()
        prior=json.loads(self.sink.path.read_text());prior['completed'].pop(0);prior.pop('canonicalSha256');prior['canonicalSha256']=sha(prior)
        self.sink=self.new_sink();self.adapter.sink=self.sink
        with self.assertRaises(BootstrapStopped):self.advance(prior,prior['canonicalSha256'])
        self.assertNotIn('prepare-migration',self.adapter.effects)
    def test_expired_or_aliased_plan_performs_no_effect(self):
        with self.assertRaises(BootstrapStopped):self.advance(clock=lambda:NOW+timedelta(hours=2))
        self.assertEqual(self.adapter.effects,[])
        self.plan['identities']['targetPvcUid']=self.plan['identities']['sourcePvcUid']
        self.plan.pop('planSha256');self.plan['planSha256']=sha(self.plan)
        with self.assertRaises(BootstrapStopped):self.advance()
        self.assertEqual(self.adapter.effects,[])
    def test_failure_to_persist_intent_sends_no_effect(self):
        commit=self.sink.commit
        def fail_intent(value):
            if value['pending']=='fence-source':raise OSError('disk full')
            commit(value)
        self.sink.commit=fail_intent
        with self.assertRaises(BootstrapStopped):self.advance()
        self.assertEqual(self.adapter.effects,[])

    def test_lost_final_receipt_write_can_recover_without_repeating_handover(self):
        commit=self.sink.commit;failed=False
        def fail_once(value):
            nonlocal failed
            if value['status']=='complete' and not failed:
                failed=True
                raise OSError('result write failed')
            commit(value)
        self.sink.commit=fail_once
        with self.assertRaises(BootstrapStopped):self.advance()
        self.assertEqual(self.adapter.effects,list(review.STEPS))
        self.assertEqual(self.resume()['status'],'complete')
        self.assertEqual(self.adapter.effects,list(review.STEPS))


class ReviewRuntimeCompilerTests(unittest.TestCase):
    def setUp(self):
        from .test_case_review_storage import ReviewInitializationTests, ROOT
        self.root=ROOT;self.storage=ReviewInitializationTests();self.storage.setUp();self.addCleanup(self.storage.doCleanups)
        value={'schemaVersion':'roebel_case_configuration_receipt_v1','planSha256':sha('provisioning plan'),
               'reference':{'namespace':'stadtstack-roebel-staging-lab','name':'roebel-case-steward-review-runtime-v1','key':'application-json'},
               'configurationSha256':sha('synthetic private file bytes'),'nonce':'d'*64,'status':'provisioned','uid':uid(900)}
        self.receipt=value | {'canonicalSha256':sha(value)}
    def compile(self):
        return review.compile_review_runtime(self.root,self.storage.storage_plan,self.storage.plan,
           expected_initialization_sha256=self.storage.plan['planSha256'],configuration_receipt=self.receipt,
           expected_configuration_receipt_sha256=self.receipt['canonicalSha256'])
    def test_only_control_configuration_and_named_reconciler_map_permission_change(self):
        result=self.compile()
        original=json.loads((self.root/'reviewed-render/roebel-staging/case-runtime/resources.json').read_text())
        changed=[(a['kind'],a['metadata']['name']) for a,b in zip(original['items'],result['resources']['items'],strict=True) if a!=b]
        self.assertEqual(changed,[('ConfigMap','roebel-case-steward-control-reviewed'),('Deployment','roebel-case-steward-control')])
        role=copy.deepcopy(result['targetReconcilerRole'])
        rule=next(r for r in role['rules'] if r['resources']==['configmaps'])
        self.assertEqual(rule['resourceNames'].pop(),'roebel-case-steward-review-reviewed-v1')
        self.assertEqual(role,result['sourceReconcilerRole'])
        self.assertFalse(any('secrets' in r['resources'] for r in role['rules']))
        self.assertEqual(result['status'],'inactive-not-admitted')
    def test_malicious_program_or_unprovisioned_secret_is_rejected(self):
        self.storage.plan['pod']['spec']['containers'][0]['command']=['arbitrary']
        with self.assertRaises(BootstrapStopped):self.compile()
        self.setUp();self.receipt['status']='reserved';self.receipt.pop('canonicalSha256');self.receipt['canonicalSha256']=sha(self.receipt)
        with self.assertRaises(BootstrapStopped):self.compile()
    def test_pvc_binding_and_review_listener_match_the_initializer_without_other_network_changes(self):
        result=self.compile();items=result['resources']['items']
        deployment=next(o for o in items if o['kind']=='Deployment' and o['metadata']['name']=='roebel-case-steward-control')
        spec=deployment['spec']['template']['spec'];binding=self.storage.plan['targetBinding']
        self.assertEqual(next(v for v in spec['volumes'] if v['name']=='case-state')['persistentVolumeClaim']['claimName'],binding['storage']['pvcName'])
        self.assertEqual(spec['containers'][0]['ports'][-1]['containerPort'],18090)
        self.assertEqual(next(e for e in spec['containers'][0]['env'] if e['name']=='STADTSTACK_CASE_CONTROL_BINDING_SHA256')['value'],binding['bindingChecksum'])
        self.assertNotIn('nodePort',json.dumps(items))

    def worker_fixture(self):
        candidate=self.compile();plan,_=fixture()
        source=json.loads((self.root/'proposals/synthetic-case-runtime/control-binding.json').read_text())
        original=json.loads((self.root/'reviewed-render/roebel-staging/case-runtime/resources.json').read_text())
        deployment=next(o for o in original['items'] if o['kind']=='Deployment' and o['metadata']['name']=='roebel-case-steward-control')
        env=deployment['spec']['template']['spec']['initContainers'][0]['env']
        for key in ('sourceRenderSha256','targetRenderSha256','targetBindingSha256'):plan['pins'][key]=candidate[key]
        plan['pins']['sourceBindingSha256']=source['bindingChecksum']
        plan['pins']['sourceConfigurationSha256']='sha256:'+next(e['value'] for e in env if e['name']=='ROEBEL_CASE_PRIVATE_CONFIG_SHA256')
        plan['pins']['targetConfigurationSha256']=self.receipt['configurationSha256']
        plan['pins']['migrationImageDigest']=self.storage.plan['targetBinding']['releaseDigest']
        plan['identities'].update(sourcePvcUid=source['storage']['pvcUid'],targetPvcUid=self.storage.plan['targetBinding']['storage']['pvcUid'],
                                  configurationSecretUid=self.receipt['uid'])
        plan.pop('planSha256');plan['planSha256']=sha(plan)
        return plan,candidate

    def test_worker_uses_fixed_image_and_pinned_secret_files_without_network_or_application_start(self):
        plan,candidate=self.worker_fixture()
        worker=review.compile_migration_worker(self.root,plan,expected_plan_sha256=plan['planSha256'],candidate=candidate,
                    expected_candidate_sha256=candidate['candidateSha256'],node_name='example-node')
        spec=worker['pod']['spec'];container=spec['containers'][0]
        self.assertFalse(spec['automountServiceAccountToken']);self.assertFalse(spec['enableServiceLinks'])
        self.assertEqual(spec['restartPolicy'],'Never');self.assertEqual(spec['nodeSelector'],{'kubernetes.io/hostname':'example-node'})
        self.assertTrue(container['image'].endswith('@'+plan['pins']['migrationImageDigest']))
        self.assertEqual(container['command'],['node','/reviewed/worker-entry.mjs'])
        self.assertEqual(container['env'],[{'name':'TMPDIR','value':'/work/private'}, {'name':'ROEBEL_REVIEW_WORKER_UID','valueFrom':{'fieldRef':{'apiVersion':'v1','fieldPath':'metadata.uid'}}}])
        self.assertEqual(worker['networkPolicy']['spec']['ingress'],[]);self.assertEqual(worker['networkPolicy']['spec']['egress'],[])
        self.assertEqual(len([v for v in spec['volumes'] if 'persistentVolumeClaim' in v]),2)
        self.assertNotIn('hostPath',json.dumps(worker));self.assertNotIn('application-json',json.dumps(worker['configMap']))
        self.assertEqual(set(worker['configMap']['data']),{'worker-entry.mjs','run-case-review-migration.mjs','case_review_backup.mjs'})
        self.assertEqual(worker['status'],'inactive-not-admitted')

    def test_worker_rejects_changed_candidate_configuration_or_volume_before_compiling(self):
        for fault in ('candidate','source-configuration','target-claim','image'):
            plan,candidate=self.worker_fixture()
            if fault=='candidate':candidate['resources']['items'].pop()
            if fault=='source-configuration':plan['pins']['sourceConfigurationSha256']=sha('wrong')
            if fault=='target-claim':plan['identities']['targetPvcUid']=uid(333)
            if fault=='image':plan['pins']['migrationImageDigest']=sha('wrong')
            plan.pop('planSha256');plan['planSha256']=sha(plan)
            with self.subTest(fault=fault),self.assertRaises(BootstrapStopped):
                review.compile_migration_worker(self.root,plan,expected_plan_sha256=plan['planSha256'],candidate=candidate,
                    expected_candidate_sha256=candidate['candidateSha256'],node_name='example-node')



class SourceFenceTests(unittest.TestCase):
    def setUp(self):
        from . import case_runtime_bootstrap as core, case_runtime_kubernetes as kube
        self.core,self.kube=core,kube;self.root=Path(__file__).resolve().parent.parent
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup);self.number=0
        self.plan,_=fixture()
        now=datetime.now(timezone.utc)
        self.plan['notBeforeUtc']=(now-timedelta(minutes=1)).isoformat(timespec='milliseconds').replace('+00:00','Z')
        self.plan['expiresAtUtc']=(now+timedelta(minutes=30)).isoformat(timespec='milliseconds').replace('+00:00','Z')
        self.plan['identities']['clusterUid']=kube.CLUSTER_UID
        active=json.loads((self.root/'reviewed-render/roebel-staging/case-runtime/resources.json').read_text())
        self.plan['pins']['sourceRenderSha256']=sha(active)
        self.plan.pop('planSha256');self.plan['planSha256']=sha(self.plan)
        parent={'schemaVersion':'roebel_review_handover_receipt_v1','planSha256':self.plan['planSha256'],'operationId':self.plan['operationId'],
                'previousReceiptSha256':None,'status':'effect-intent','completed':[],'pending':'fence-source'}
        self.parent=parent|{'canonicalSha256':sha(parent)}
        baseline=core.build_plan(self.root)
        self.flux=copy.deepcopy(baseline['objects'][-1]['desired']);self.flux['spec']['suspend']=False
        self.deployment=copy.deepcopy(next(o['desired'] for o in baseline['objects'] if o['target']['kind']=='Deployment' and o['target']['name']=='roebel-case-steward-control'))
        for obj,key in ((self.flux,'reconcilerUid'),(self.deployment,'sourceDeploymentUid')):
            obj['metadata'].update(uid=self.plan['identities'][key],resourceVersion='10',generation=1)
        self.paths={kube.resource_path(core.target(o)):o for o in (self.flux,self.deployment)}
        self.paths['/api/v1/namespaces/kube-system']={'metadata':{'uid':kube.CLUSTER_UID}}
        self.patches=[];self.fault=None;self.ready=True;self.sink=self.new_sink()
    def new_sink(self):
        self.number+=1
        return ReceiptSink.reserve(Path(self.directory.name)/f'fence-{self.number}.json')
    def request(self,method,path,payload):
        self.assertIn(path,self.paths)
        if method=='GET':return copy.deepcopy(self.paths[path])
        self.assertEqual(method,'PATCH');self.patches.append(path)
        saved=json.loads(self.sink.path.read_text());self.assertEqual(saved['status'],'patch-intent')
        obj=self.paths[path];field=payload[-1]['path'].split('/')[-1]
        self.assertEqual(payload,[{'op':'test','path':'/metadata/uid','value':obj['metadata']['uid']},
            {'op':'test','path':'/metadata/resourceVersion','value':obj['metadata']['resourceVersion']},
            {'op':'test','path':'/spec/'+field,'value':obj['spec'][field]},
            {'op':'replace','path':'/spec/'+field,'value':True if field=='suspend' else 0}])
        if self.fault=='lost-without-write':raise TimeoutError('unresolved')
        obj['spec'][field]=payload[-1]['value'];obj['metadata']['generation']+=1;obj['metadata']['resourceVersion']='11'
        if self.fault=='reconciling' and field=='suspend':obj['status']={'conditions':[{'type':'Reconciling','status':'True'}]}
        if self.fault=='uid-after-suspend' and field=='suspend':self.deployment['metadata']['uid']=uid(999)
        if self.fault=='lost-after-write':raise TimeoutError('private server error')
        return copy.deepcopy(obj)
    def prerequisites(self,plan,state):
        if not self.ready:raise RuntimeError('full handover missing')
    def advance(self,prior=None):
        return review.advance_source_fence(self.root,self.plan,expected_plan_sha256=self.plan['planSha256'],parent_receipt=self.parent,
               expected_parent_sha256=self.parent['canonicalSha256'],transport=self,sink=self.sink,verify_ready=self.prerequisites,
               prior=prior,expected_prior_sha256=prior and prior['canonicalSha256'])
    def resume(self):
        prior=json.loads(self.sink.path.read_text());self.sink=self.new_sink();return self.advance(prior)
    def test_suspend_then_guarded_scale_and_read_only_recovery(self):
        self.assertEqual(self.advance()['status'],'source-fenced')
        self.assertEqual(self.patches,[self.kube.resource_path(self.core.target(o)) for o in (self.flux,self.deployment)])
        self.assertEqual(self.resume()['status'],'source-fenced');self.assertEqual(len(self.patches),2)
    def test_lost_applied_response_never_repeats_a_patch(self):
        self.fault='lost-after-write';self.assertEqual(self.advance()['status'],'source-fenced')
        self.assertEqual(len(self.patches),2)
    def test_unresolved_patch_waits_without_blind_retry(self):
        self.fault='lost-without-write';self.assertEqual(self.advance()['status'],'awaiting-patch')
        self.assertEqual(self.resume()['status'],'awaiting-patch');self.assertEqual(len(self.patches),1)
        self.assertEqual(self.deployment['spec']['replicas'],1)
    def test_inflight_reconciliation_blocks_scaling_until_reobserved(self):
        self.fault='reconciling';self.assertEqual(self.advance()['status'],'awaiting-patch')
        self.assertEqual(self.deployment['spec']['replicas'],1)
        self.flux['status']['conditions']=[];self.fault=None
        self.assertEqual(self.resume()['status'],'source-fenced');self.assertEqual(len(self.patches),2)
    def test_changed_source_identity_preserves_existing_fence_without_scaling(self):
        self.fault='uid-after-suspend'
        with self.assertRaises(BootstrapStopped):self.advance()
        self.assertTrue(self.flux['spec']['suspend']);self.assertEqual(self.deployment['spec']['replicas'],1)
        self.assertEqual(len(self.patches),1)
    def test_missing_parent_intent_or_full_prerequisites_prevents_shutdown(self):
        self.ready=False
        with self.assertRaises(BootstrapStopped):self.advance()
        self.assertEqual(self.patches,[])
        self.ready=True;self.parent['pending']=None;self.parent.pop('canonicalSha256');self.parent['canonicalSha256']=sha(self.parent)
        with self.assertRaises(BootstrapStopped):self.advance()
        self.assertEqual(self.patches,[])
    def test_foreign_suspend_or_generation_drift_is_not_adopted(self):
        self.flux['spec']['suspend']=True
        with self.assertRaises(BootstrapStopped):self.advance()
        self.assertEqual(self.patches,[])
        self.flux['spec']['suspend']=False;self.sink=self.new_sink();self.advance()
        self.deployment['metadata']['generation']+=1
        with self.assertRaises(BootstrapStopped):self.resume()
        self.assertEqual(len(self.patches),2)


class MountReleaseTests(unittest.TestCase):
    def setUp(self):
        from . import case_runtime_kubernetes as kube
        self.plan,_=fixture();self.plan['identities']['clusterUid']=kube.CLUSTER_UID
        self.plan.pop('planSha256');self.plan['planSha256']=sha(self.plan)
        self.root=Path(__file__).resolve().parent.parent
        binding=json.loads((self.root/'proposals/synthetic-case-runtime/control-binding.json').read_text())
        self.plan['pins']['sourceBindingSha256']=binding['bindingChecksum'];self.plan['identities']['sourcePvcUid']=binding['storage']['pvcUid']
        self.plan.pop('planSha256');self.plan['planSha256']=sha(self.plan)
        self.ids=self.plan['identities'];self.node_name='synthetic-node'
        self.observer={'metadata':{'uid':self.ids['mountObserverPodUid']},'spec':{'nodeName':self.node_name,'volumes':[]},
                       'status':{'phase':'Running','conditions':[{'type':'Ready','status':'True'}]}}
        self.pods=[self.observer];self.reads=0;self.fault=None
        self.names=[self.ids['mountObserverPodUid']]
        self.mounts=f"100 1 1:1 / /var/lib/kubelet/pods/{self.ids['mountObserverPodUid']}/volumes/example rw - tmpfs tmpfs rw\n"
    def request(self,method,path,payload):
        self.assertEqual(method,'GET');self.assertIsNone(payload)
        if path.endswith('/kube-system'):return {'metadata':{'uid':self.ids['clusterUid']}}
        if '/persistentvolumeclaims/' in path:
            uid_key='targetPvcUid' if path.endswith('roebel-case-steward-review-state-v1') else 'sourcePvcUid'
            return {'metadata':{'uid':self.ids[uid_key]},'spec':{'accessModes':['ReadWriteOncePod']},'status':{'phase':'Bound'}}
        if path.endswith('/pods'):
            self.reads+=1
            return {'items':copy.deepcopy(self.pods),'metadata':{'continue':'next'} if self.fault=='paginated' else {}}
        self.assertEqual(path,'/api/v1/nodes/'+self.node_name)
        return {'metadata':{'uid':uid(999) if self.fault=='node' else self.ids['nodeUid']}}
    def view(self,name,node_uid):
        self.assertEqual((name,node_uid),(self.node_name,self.ids['nodeUid']))
        if self.fault=='observer-dies':self.observer['status']['phase']='Succeeded'
        return {'mountInfo':self.mounts,'podDirectoryNames':self.names}
    def observe(self):
        return review.observe_mount_release(self.root,self.plan,expected_plan_sha256=self.plan['planSha256'],transport=self,node_filesystem=self.view,verify_ready=lambda p:None)
    def test_api_and_physical_release_have_a_live_positive_control(self):
        result=self.observe();self.assertTrue(result['evidence']['sourceMountAbsent'])
        self.assertEqual(self.reads,2);self.assertNotIn(self.mounts,json.dumps(result))
    def test_either_leftover_mount_or_directory_prevents_release(self):
        for key in ('sourcePodUid','initializerPodUid'):
            with self.subTest(key=key):
                old=self.mounts;self.mounts+=f"101 1 1:1 / /var/lib/kubelet/pods/{self.ids[key]}/volumes/source rw - ext4 /dev/device rw\n"
                self.assertIsNone(self.observe());self.mounts=old
                self.names.append(self.ids[key]);self.assertIsNone(self.observe());self.names.pop()
    def test_unexpected_new_pod_using_source_claim_blocks_release(self):
        source=json.loads((self.root/'proposals/synthetic-case-runtime/control-binding.json').read_text())['storage']
        self.pods.append({'metadata':{'uid':uid(999)},'spec':{'volumes':[{'persistentVolumeClaim':{'claimName':source['pvcName']}}]},'status':{'phase':'Pending'}})
        self.assertIsNone(self.observe())
    def test_empty_wrong_node_or_disappearing_positive_control_cannot_attest_absence(self):
        original=self.mounts
        self.mounts='unrelated mount view'
        with self.assertRaises(BootstrapStopped):self.observe()
        self.mounts=original;self.fault='node'
        with self.assertRaises(BootstrapStopped):self.observe()
        self.fault='observer-dies'
        with self.assertRaises(BootstrapStopped):self.observe()

    def test_incomplete_api_list_or_changed_binding_is_not_a_release_proof(self):
        self.fault='paginated'
        with self.assertRaises(BootstrapStopped):self.observe()
        self.fault=None;self.plan['pins']['sourceBindingSha256']=sha('different binding')
        self.plan.pop('planSha256');self.plan['planSha256']=sha(self.plan)
        with self.assertRaises(BootstrapStopped):self.observe()

    def test_system_positive_control_and_static_pod_directories(self):
        original=self.request
        self.names.append('a'*32)
        def request(method,path,payload):
            if path=='/api/v1/pods':return {'items':[self.observer]}
            if path.endswith('/pods'):return {'items':[]}
            return original(method,path,payload)
        self.request=request
        self.assertTrue(self.observe()['evidence']['positiveControlVerified'])
        self.observer['metadata']['deletionTimestamp']='2026-09-10T12:00:00Z'
        with self.assertRaises(BootstrapStopped):self.observe()


class TalosMountTransportTests(unittest.TestCase):
    def test_fixed_reads_keep_all_entries_and_recheck_node_identity(self):
        node={'metadata':{'uid':uid(10)},'status':{'addresses':[{'type':'InternalIP','address':'10.42.0.11'}]}}
        commands=[]
        listing=f'NODE NAME\n10.42.0.11 .\n10.42.0.11 {uid(11)}\n10.42.0.11 '+('a'*32)+'\n'
        def run(command):commands.append(command);return 'mounts' if command[0]=='read' else listing
        observe=review.TalosReviewMountObserver(transport=SimpleNamespace(request=lambda *args:node),run=run,node_name='example-node',node_uid=uid(10),node_ip='10.42.0.11')
        self.assertEqual(observe('example-node',uid(10))['podDirectoryNames'],[uid(11),'a'*32])
        self.assertEqual(commands,[['read','/proc/1/mountinfo'],['ls','/var/lib/kubelet/pods']])
        for value in ('NODE NAME\n10.42.0.12 .\n','NODE NAME\n10.42.0.11 ../bad\n','NODE NAME\n10.42.0.11 .\n10.42.0.11 .\n'):
            listing=value
            with self.assertRaises(BootstrapStopped):observe('example-node',uid(10))
        listing=f'NODE NAME\n10.42.0.11 .\n10.42.0.11 {uid(11)}\n'
        def changed(command):node['metadata']['uid']=uid(12);return run(command)
        observe.run=changed
        with self.assertRaises(BootstrapStopped):observe('example-node',uid(10))


class ReviewAdmissionTests(unittest.TestCase):
    def test_only_exact_forward_render_is_admitted(self):
        import shutil
        from . import case_runtime_bootstrap as core,case_runtime_admission as admission
        verifier=core._verifier();base=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'candidate'
            shutil.copytree(base,target,ignore=shutil.ignore_patterns('.git','__pycache__'))
            path=target/'reviewed-render/roebel-staging/case-runtime/resources.json'
            path.write_bytes((target/admission.REVIEW_RESOURCES).read_bytes())
            verifier.verify(target,base)
            with self.assertRaises(verifier.VerificationError):verifier.verify(base,target)
            extra=target/'unexpected.txt';extra.write_text('unexpected\n')
            with self.assertRaises(verifier.VerificationError):verifier.verify(target,base)
            extra.unlink();value=json.loads(path.read_text())
            next(o for o in value['items'] if o['kind']=='Deployment')['spec']['replicas']=2
            path.write_text(json.dumps(value,indent=2)+'\n')
            with self.assertRaises(verifier.VerificationError):verifier.verify(target,base)


class WorkerTransportTests(unittest.TestCase):
    compile=ReviewRuntimeCompilerTests.compile
    worker_fixture=ReviewRuntimeCompilerTests.worker_fixture
    def setUp(self):
        from . import case_runtime_kubernetes as kube
        from .staging_participant_flux_bootstrap import RawResult
        from types import SimpleNamespace
        ReviewRuntimeCompilerTests.setUp(self)
        self.plan,self.candidate=self.worker_fixture()
        self.plan['identities']['clusterUid']=kube.CLUSTER_UID
        self.plan.pop('planSha256');self.plan['planSha256']=sha(self.plan)
        self.worker=review.compile_migration_worker(self.root,self.plan,expected_plan_sha256=self.plan['planSha256'],
            candidate=self.candidate,expected_candidate_sha256=self.candidate['candidateSha256'],node_name='example-node')
        self.ids=self.plan['identities'];self.pod_uid=uid(777);self.calls=[];self.after_fault=False;self.ready=True
        ns=kube.NAMESPACE;name='roebel-case-review-migration-v1'
        def observed(value,number):
            value=copy.deepcopy(value);value['metadata'].update(uid=uid(number),resourceVersion='10');return value
        pod=observed(self.worker['pod'],777);pod['spec']['nodeName']='example-node'
        pod['status']={'phase':'Running','containerStatuses':[{'name':'migration','ready':True,'restartCount':0,
            'imageID':'containerd://'+self.worker['pod']['spec']['containers'][0]['image']}]}
        self.pod_path=f'/api/v1/namespaces/{ns}/pods/{name}'
        self.objects={self.pod_path:pod,'/api/v1/namespaces/kube-system':{'metadata':{'uid':kube.CLUSTER_UID}},
            '/api/v1/nodes/example-node':{'metadata':{'uid':self.ids['nodeUid']}},
            f'/api/v1/namespaces/{ns}/configmaps/{name}':observed(self.worker['configMap'],778),
            f'/apis/networking.k8s.io/v1/namespaces/{ns}/networkpolicies/{name}':observed(self.worker['networkPolicy'],779),
            f'/apis/apps/v1/namespaces/{ns}/deployments/roebel-case-steward-control':{'metadata':{'uid':self.ids['sourceDeploymentUid']},'spec':{'replicas':0}},
            '/apis/kustomize.toolkit.fluxcd.io/v1/namespaces/flux-roebel-staging/kustomizations/roebel-case-runtime':{'metadata':{'uid':self.ids['reconcilerUid']},'spec':{'suspend':True}},
            f'/api/v1/namespaces/{ns}/pods':{'items':[pod]}}
        for side,claim_name in [('source','roebel-case-steward-control-state'),('target','roebel-case-steward-review-state-v1')]:
            self.objects[f'/api/v1/namespaces/{ns}/persistentvolumeclaims/{claim_name}']={'metadata':{'uid':self.ids[side+'PvcUid']},
                'spec':{'volumeName':side+'-pv','accessModes':['ReadWriteOncePod']},'status':{'phase':'Bound'}}
            self.objects['/api/v1/persistentvolumes/'+side+'-pv']={'metadata':{'uid':self.ids[side+'PvUid']},
                'spec':{'persistentVolumeReclaimPolicy':'Retain','claimRef':{'uid':self.ids[side+'PvcUid']}}}
        _,evidence=fixture()
        parent={'schemaVersion':'roebel_review_handover_receipt_v1','planSha256':self.plan['planSha256'],'operationId':self.plan['operationId'],
            'previousReceiptSha256':None,'status':'effect-intent','completed':[{'step':step,'evidence':evidence[step]} for step in review.STEPS[:2]],'pending':'verify-backup'}
        self.parent=parent | {'canonicalSha256':sha(parent)}
        self.request={'schemaVersion':'roebel_case_review_migration_request_v1','sourceRevision':'fdb0b7f36c33d925be141d8e9037b48d17612df8','mode':'capture-backup','sourceSealChecksum':sha('seal'),'caseId':self.plan['caseId'],'sourceRootDir':'/var/lib/stadtstack/case-control',
            'controlImageDigest':self.plan['pins']['migrationImageDigest'],'targetBinding':{'bindingChecksum':self.plan['pins']['targetBindingSha256']},
            **{key:self.plan['pins'][key] for key in ('sourceConfigurationSha256','targetConfigurationSha256','admissionReceiptChecksum')}}
        self.output=json.dumps({'status':'private-archive-captured','resultSha256':sha('result')})
        def run(args,input_text=None,timeout=None):
            self.calls.append((args,input_text,timeout))
            if 'exec' in args:
                if self.after_fault:self.objects[self.pod_path]['metadata']['uid']=uid(999)
                return RawResult(out=self.output)
            return RawResult(out=json.dumps(self.objects[args[-1]]))
        def ready(*args):
            if not self.ready:raise RuntimeError('private diagnostics')
        self.transport=review.KubectlReviewWorkerTransport(self.root,self.plan,self.worker,expected_plan_sha256=self.plan['planSha256'],
            expected_worker_sha256=self.worker['workerSha256'],pod_uid=self.pod_uid,runner=SimpleNamespace(run=run),snapshot=SimpleNamespace(path='/private/example'),
            verify_ready=ready,candidate=self.candidate,expected_candidate_sha256=self.candidate['candidateSha256'],clock=lambda:NOW)
    def exchange(self,action='invoke',**kwargs):
        import hashlib
        data=json.dumps(self.request).encode()
        return self.transport.exchange(action,data,request_sha256='sha256:'+hashlib.sha256(data).hexdigest(),
            parent_receipt=self.parent,expected_parent_sha256=self.parent['canonicalSha256'],**kwargs)
    def test_fixed_command_has_worker_uid_and_rechecks_ownership(self):
        self.assertEqual(self.exchange()['status'],'private-archive-captured')
        calls=[c for c in self.calls if 'exec' in c[0]];self.assertEqual(len(calls),1)
        command,data,timeout=calls[0];self.assertEqual(command[-2:],['--expected-worker-uid',self.pod_uid]);self.assertIn('-i',command)
        self.assertNotIn('-t',command);self.assertEqual(timeout,60);self.assertEqual(json.loads(data),self.request)
        self.assertEqual(sum(c[0][-1]==self.pod_path for c in self.calls),2)

    def test_unused_mailbox_observer_is_read_only_and_keeps_ownership_checks_after_expiry(self):
        value={'schemaVersion':'roebel_unused_review_worker_v1','workerPodUid':self.pod_uid,'requestCount':0,
            **{k:self.plan['pins'][k] for k in ('sourceConfigurationSha256','targetConfigurationSha256')}}
        self.output=json.dumps(value);self.transport.clock=lambda:NOW+timedelta(hours=2)
        self.assertEqual(self.transport.observe_unused()['workerPodUid'],self.pod_uid)
        call=next(c for c in self.calls if 'exec' in c[0])
        self.assertEqual(call[0][-3:],['node','-e',review.UNUSED_REVIEW_MAILBOX_JS]);self.assertIsNone(call[1])
        self.assertNotIn('-i',call[0])
        for changed in ({'requestCount':1},{'requestCount':False},{'workerPodUid':uid(994)}):
            self.output=json.dumps(value|changed)
            with self.assertRaises(BootstrapStopped):self.transport.observe_unused()
        self.output=json.dumps(value);self.after_fault=True
        with self.assertRaises(BootstrapStopped):self.transport.observe_unused()

    def test_unused_mailbox_probe_rejects_even_an_empty_reserved_request(self):
        import hashlib,os,subprocess
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary).resolve();directory.chmod(0o700)
            for side in ('source','target'):
                path=directory/(side+'.json');path.write_bytes(b'{}');path.chmod(0o600)
            program=review.UNUSED_REVIEW_MAILBOX_JS.replace("root='/work/private'",'root='+json.dumps(str(directory)))
            def run():return subprocess.run(['node','-e',program],capture_output=True,text=True,timeout=10,
                env=os.environ|{'ROEBEL_REVIEW_WORKER_UID':self.pod_uid})
            good=run();self.assertEqual(good.returncode,0,good.stderr)
            self.assertEqual(json.loads(good.stdout)['sourceConfigurationSha256'],'sha256:'+hashlib.sha256(b'{}').hexdigest())
            (directory/('request-'+'a'*64)).mkdir(mode=0o700)
            stopped=run();self.assertEqual(stopped.returncode,78);self.assertEqual(stopped.stdout,'')
    def test_cri_digest_identity_and_window_expiring_during_reads(self):
        self.objects[self.pod_path]['status']['containerStatuses'][0]['imageID']='containerd://'+self.plan['pins']['migrationImageDigest']
        self.assertEqual(self.exchange()['status'],'private-archive-captured')
        self.calls=[]
        self.transport.clock=lambda: review._utc(self.plan['expiresAtUtc']) if self.calls else NOW
        with self.assertRaises(BootstrapStopped):self.exchange()
        self.assertFalse(any('exec' in c[0] for c in self.calls))

    def test_wrong_parent_case_or_incomplete_adapter_cannot_exec(self):
        self.request['caseId']='other'
        with self.assertRaises(BootstrapStopped):self.exchange()
        self.request['caseId']=self.plan['caseId'];self.ready=False
        with self.assertRaises(BootstrapStopped):self.exchange()
        self.ready=True;self.parent['pending']='activate-migration'
        self.parent['canonicalSha256']=sha({k:v for k,v in self.parent.items() if k!='canonicalSha256'})
        with self.assertRaises(BootstrapStopped):self.exchange()
        self.assertFalse(any('exec' in c[0] for c in self.calls))
    def test_changed_worker_template_volume_or_source_fence_prevents_exec(self):
        originals=copy.deepcopy(self.objects)
        for fault in ('image','sidecar','volume','writer','policy'):
            self.objects=copy.deepcopy(originals);self.calls=[]
            if fault=='image':self.objects[self.pod_path]['status']['containerStatuses'][0]['imageID']='changed'
            if fault=='sidecar':self.objects[self.pod_path]['spec']['containers'].append({'name':'injected'})
            if fault=='volume':self.objects['/api/v1/persistentvolumes/source-pv']['metadata']['uid']=uid(999)
            if fault=='writer':next(v for k,v in self.objects.items() if '/deployments/' in k)['spec']['replicas']=1
            if fault=='policy':next(v for k,v in self.objects.items() if '/networkpolicies/' in k)['spec']['egress']=[{}]
            with self.subTest(fault=fault),self.assertRaises(BootstrapStopped):self.exchange()
            self.assertFalse(any('exec' in c[0] for c in self.calls))
    def test_post_exec_replacement_is_uncertain_and_is_not_retried(self):
        self.after_fault=True
        with self.assertRaises(BootstrapStopped):self.exchange()
        self.assertEqual(sum('exec' in c[0] for c in self.calls),1)
    def test_archive_only_writes_verified_bytes_to_fresh_private_descriptor(self):
        import hashlib,os
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'archive';fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600)
            try:
                self.output='private archived Case'
                pin='sha256:'+hashlib.sha256(self.output.encode()).hexdigest()
                with self.assertRaises(BootstrapStopped):self.exchange('archive',output_fd=fd,expected_archive_sha256=sha('wrong'))
                self.assertEqual(path.read_bytes(),b'')
                result=self.exchange('archive',output_fd=fd,expected_archive_sha256=pin)
                self.assertEqual(result['sha256'],pin);self.assertEqual(path.read_text(),self.output)
                self.assertNotIn(self.output,json.dumps(result))
                with self.assertRaises(BootstrapStopped):self.exchange('archive',output_fd=fd,expected_archive_sha256=pin)
            finally:os.close(fd)

    def test_activation_must_match_the_prepared_candidate_and_backup_claim(self):
        _,evidence=fixture()
        self.parent['completed']=[{'step':step,'evidence':evidence[step]} for step in review.STEPS[:4]]
        self.parent['pending']='activate-migration'
        self.parent['canonicalSha256']=sha({k:v for k,v in self.parent.items() if k!='canonicalSha256'})
        migration={'caseId':self.plan['caseId'],'deploymentEnvironment':'staging',
            'candidateChecksum':evidence['prepare-migration']['candidateChecksum'],
            'sourceDeploymentClaimChecksum':evidence['verify-backup']['sourceDeploymentClaimChecksum'],
            'targetDeploymentClaimChecksum':self.plan['pins']['targetDeploymentClaimChecksum'],
            'notBeforeUtc':self.plan['notBeforeUtc'],'expiresAtUtc':self.plan['expiresAtUtc']}
        self.request.update(mode='activate',sourceSealChecksum=evidence['verify-backup']['sourceSealChecksum'])
        self.request['migrationPlan']=migration | {'planChecksum':sha(migration)}
        self.output=json.dumps({'status':'target-sealed','resultSha256':sha('result')})
        changed=migration | {'candidateChecksum':sha('other')}
        self.request['migrationPlan']=changed | {'planChecksum':sha(changed)}
        with self.assertRaises(BootstrapStopped):self.exchange()
        self.assertFalse(any('exec' in c[0] for c in self.calls))
        self.request['migrationPlan']=migration | {'planChecksum':sha(migration)}
        self.assertEqual(self.exchange()['status'],'target-sealed')


class WorkerLifecycleTests(unittest.TestCase):
    compile=ReviewRuntimeCompilerTests.compile
    worker_fixture=ReviewRuntimeCompilerTests.worker_fixture
    def setUp(self):
        WorkerTransportTests.setUp(self)
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.index=0;self.effects=[];self.live={};self.lost=None;self.before=None;self.mount_held=False
        self.collections=review._worker_inventory(self.worker)
        self.start_parent=copy.deepcopy(self.parent)
        self.transport=review.KubectlWorkerLifecycleTransport(self.worker,runner=SimpleNamespace(run=self.run_command),snapshot=SimpleNamespace(path='/private/verified-kubeconfig'))
        self.new_sink()
    def new_sink(self):
        self.index+=1;self.sink=ReceiptSink.reserve(Path(self.directory.name)/f'receipt-{self.index}.json')
    def run_command(self,args,input_text=None,timeout=None):
        self.assertEqual(timeout,25)
        method=next(name for name in ('get','create','delete') if name in args)
        path=args[args.index('--raw')+1]
        if method=='get':
            return RawResult(out=json.dumps(self.live[path])) if path in self.live else RawResult(code=1,err='Error from server (NotFound): missing')
        saved=json.loads(self.sink.path.read_text());self.assertEqual(saved['status'],'intent')
        self.effects.append((method,path,json.loads(input_text)))
        if self.before==method:raise TimeoutError('not delivered')
        if method=='create':
            value=json.loads(input_text);key=next(k for k,v in self.collections.items() if v==path)
            value['metadata'].update(uid=uid(800+list(review.WORKER_RESOURCE_ORDER).index(key)),resourceVersion='10')
            if key=='pod':
                value['spec']['nodeName']=self.worker['nodeName']
                value['spec'].update(serviceAccountName='default',serviceAccount='default')
                value['status']={'phase':'Running','containerStatuses':[{'name':'migration','ready':True,'restartCount':0,'imageID':'containerd://'+self.plan['pins']['migrationImageDigest']}]}
            self.live[path+'/'+value['metadata']['name']]=value
        else:
            value=self.live[path];options=json.loads(input_text)
            self.assertEqual(options['preconditions'],{k:value['metadata'][k] for k in ('uid','resourceVersion')})
            del self.live[path]
        if self.lost==method:raise TimeoutError('response lost')
        return RawResult(out=json.dumps(value))
    def lifecycle_ready(self,*args):
        if not self.ready_flag:raise RuntimeError('incomplete parent')
    def release(self,pod_uid):
        if self.mount_held:return None
        value={'schemaVersion':'roebel_review_migration_mount_release_v1','planSha256':self.plan['planSha256'],
               'evidence':{'migrationPodUid':pod_uid,'apiAbsent':True,'mountAbsent':True,'positiveControlVerified':True}}
        return value | {'canonicalSha256':sha(value)}
    def advance(self,operation='create',prior=None,created=None):
        self.ready_flag=getattr(self,'ready_flag',True)
        return review.advance_worker_lifecycle(self.root,self.plan,self.worker,candidate=self.candidate,
            expected_plan_sha256=self.plan['planSha256'],expected_worker_sha256=self.worker['workerSha256'],
            parent_receipt=self.parent,expected_parent_sha256=self.parent['canonicalSha256'],operation=operation,
            transport=self.transport,sink=self.sink,verify_ready=self.lifecycle_ready,observe_release=self.release,
            creation_receipt=created,expected_creation_sha256=created['canonicalSha256'] if created else None,
            prior=prior,expected_prior_sha256=prior['canonicalSha256'] if prior else None,clock=lambda:NOW)
    def resume(self,operation='create',created=None):
        prior=json.loads(self.sink.path.read_text())
        self.new_sink();return self.advance(operation,prior,created)
    def retirement_parent(self):
        _,evidence=fixture()
        # Compiler fixtures change some pins; use their current values.
        for step in evidence:
            for name in evidence[step]:
                if name in self.plan['pins']:evidence[step][name]=self.plan['pins'][name]
                if name in self.plan['identities']:evidence[step][name]=self.plan['identities'][name]
        self.parent['completed']=[{'step':step,'evidence':evidence[step]} for step in review.STEPS[:5]]
        self.parent['pending']='release-migration'
        self.parent['canonicalSha256']=sha({k:v for k,v in self.parent.items() if k!='canonicalSha256'})
    def test_create_recover_lost_responses_and_revalidate_completed_receipt(self):
        self.lost='create';result=self.advance()
        self.assertEqual(result['status'],'ready');self.assertEqual(len(self.effects),3)
        self.assertEqual(self.resume()['status'],'ready');self.assertEqual(len(self.effects),3)
        self.assertEqual([entry[2]['kind'] for entry in self.effects],['NetworkPolicy','ConfigMap','Pod'])
    def test_default_account_does_not_allow_named_account_or_token_mounting(self):
        self.assertEqual(self.advance()['status'],'ready')
        path=self.collections['pod']+'/'+self.worker['pod']['metadata']['name']
        original=copy.deepcopy(self.live[path])
        for field,value in [('serviceAccountName','privileged-operator'),('automountServiceAccountToken',True)]:
            self.live[path]=copy.deepcopy(original);self.live[path]['spec'][field]=value
            with self.assertRaises(BootstrapStopped):self.resume()
        self.assertEqual(len(self.effects),3)

    def test_undelivered_create_is_not_repeated_or_adopted_without_intent(self):
        self.before='create';self.assertEqual(self.advance()['status'],'waiting')
        self.before=None;self.assertEqual(self.resume()['status'],'waiting');self.assertEqual(len(self.effects),1)
        self.new_sink()
        self.live[self.collections['networkPolicy']+'/'+self.worker['networkPolicy']['metadata']['name']]=copy.deepcopy(self.worker['networkPolicy'])
        with self.assertRaises(BootstrapStopped):self.advance()
        self.assertEqual(len(self.effects),1)
    def test_existing_pod_blocks_policy_creation(self):
        path=self.collections['pod']+'/'+self.worker['pod']['metadata']['name']
        self.live[path]=copy.deepcopy(self.worker['pod'])
        with self.assertRaises(BootstrapStopped):self.advance()
        self.assertEqual(self.effects,[])

    def test_incomplete_readiness_and_wrong_stage_prevent_creation(self):
        self.ready_flag=False
        with self.assertRaises(BootstrapStopped):self.advance()
        self.ready_flag=True;self.parent['pending']='prepare-migration';self.parent['canonicalSha256']=sha({k:v for k,v in self.parent.items() if k!='canonicalSha256'})
        with self.assertRaises(BootstrapStopped):self.advance()
        self.assertEqual(self.effects,[])
    def test_retirement_waits_for_physical_release_then_recovers_lost_deletes(self):
        created=self.advance();self.retirement_parent();self.new_sink();self.mount_held=True;self.lost='delete'
        result=self.advance('retire',created=created)
        self.assertEqual(result['status'],'waiting');self.assertEqual(len(self.effects),4)
        self.assertEqual(self.resume('retire',created)['status'],'waiting');self.assertEqual(len(self.effects),4)
        self.mount_held=False;result=self.resume('retire',created)
        self.assertEqual(result['status'],'retired');self.assertEqual(len(self.effects),6);self.assertEqual(self.live,{})
        self.assertEqual(self.resume('retire',created)['status'],'retired');self.assertEqual(len(self.effects),6)
    def test_replacement_pod_is_never_deleted(self):
        created=self.advance();self.retirement_parent();self.new_sink()
        path=self.collections['pod']+'/'+self.worker['pod']['metadata']['name'];self.live[path]['metadata']['uid']=uid(999)
        with self.assertRaises(BootstrapStopped):self.advance('retire',created=created)
        self.assertEqual(len(self.effects),3)
    def test_delete_transport_rejects_unobserved_or_changed_preconditions_and_other_paths(self):
        created=self.advance();path=self.collections['pod']+'/'+self.worker['pod']['metadata']['name']
        self.transport.observed.clear()
        options={'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':created['records']['pod']['uid'],'resourceVersion':'10'}}
        with self.assertRaises(BootstrapStopped):self.transport.request('DELETE',path,options)
        self.transport.request('GET',path,None);options['preconditions']['resourceVersion']='11'
        with self.assertRaises(BootstrapStopped):self.transport.request('DELETE',path,options)
        with self.assertRaises(BootstrapStopped):self.transport.request('GET','/api/v1/secrets',None)
        self.assertEqual(len(self.effects),3)


class MigrationMountReleaseTests(unittest.TestCase):
    def setUp(self):
        self.fixture=MountReleaseTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
    def observe(self):
        f=self.fixture
        return review.observe_mount_release(f.root,f.plan,expected_plan_sha256=f.plan['planSha256'],transport=f,
            node_filesystem=f.view,verify_ready=lambda p:None,migration_pod_uid=uid(888))
    def test_deleted_worker_with_remaining_mount_or_directory_is_not_released(self):
        f=self.fixture;f.names.append(uid(888));self.assertIsNone(self.observe());f.names.remove(uid(888))
        original=f.mounts;f.mounts+=f'101 1 1:1 / /var/lib/kubelet/pods/{uid(888)}/volumes/example rw - tmpfs tmpfs rw\n'
        self.assertIsNone(self.observe());f.mounts=original
        proof=self.observe();self.assertEqual(proof['schemaVersion'],'roebel_review_migration_mount_release_v1')
        self.assertEqual(proof['evidence']['migrationPodUid'],uid(888))
    def test_worker_api_presence_blocks_release_even_without_claim_entries(self):
        self.fixture.pods.append({'metadata':{'uid':uid(888)},'spec':{}})
        self.assertIsNone(self.observe())


class ReviewTransitionTests(unittest.TestCase):
    compile=ReviewRuntimeCompilerTests.compile
    worker_fixture=ReviewRuntimeCompilerTests.worker_fixture
    def setUp(self):
        WorkerTransportTests.setUp(self)
        from unittest.mock import patch
        mocked=patch.object(review,'verify_review_gitops_target',return_value={'status':'gitops-successor-observed'})
        mocked.start();self.addCleanup(mocked.stop)
        from . import case_runtime_bootstrap as core, case_runtime_kubernetes as kube
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup);self.index=0
        self.effects=[];self.live={};self.lost=False;self.undelivered=False;self.can_run=True;self.complete=True
        _,self.evidence=fixture()
        for evidence in self.evidence.values():
            for key in evidence:
                if key in self.plan['pins']:evidence[key]=self.plan['pins'][key]
                if key in self.plan['identities']:evidence[key]=self.plan['identities'][key]
        self.kube,self.core=kube,core
        self.set_operation('start');self.new_sink()
    def new_sink(self):
        self.index+=1;self.sink=ReceiptSink.reserve(Path(self.directory.name)/f'transition-{self.index}.json')
    def set_operation(self,operation):
        self.operation=operation;stage={'start':'start-review-runtime','restore':'restore-gitops'}[operation]
        self.parent['completed']=[{'step':s,'evidence':self.evidence[s]} for s in review.STEPS[:review.STEPS.index(stage)]]
        self.parent['pending']=stage;self.parent['canonicalSha256']=sha({k:v for k,v in self.parent.items() if k!='canonicalSha256'})
        self.changes=review._review_transition_changes(self.root,self.plan,self.candidate,self.candidate['candidateSha256'],operation)
        for index,(_,before,after,_,fixed_uid) in enumerate(self.changes):
            if before:
                value=copy.deepcopy(before);value['metadata'].update(uid=fixed_uid or uid(950+index),resourceVersion='10',generation=1)
                self.live[self.kube.resource_path(self.core.target(after))]=value
        self.transport=review.KubectlReviewTransitionTransport(self.root,self.plan,self.candidate,expected_candidate_sha256=self.candidate['candidateSha256'],
            operation=operation,runner=SimpleNamespace(run=self.command),snapshot=SimpleNamespace(path='/private/snapshot'))
    def command(self,args,input_text=None,timeout=None):
        self.assertEqual(timeout,25)
        if 'get' in args:
            path=args[-1];return RawResult(out=json.dumps(self.live[path])) if path in self.live else RawResult(code=1,err='Error from server (NotFound): missing')
        self.assertEqual(json.loads(self.sink.path.read_text())['status'],'intent')
        self.effects.append(args)
        if self.undelivered or getattr(self,'delay_deployment',False) and 'deployment' in args:raise TimeoutError()
        if 'create' in args:
            value=json.loads(input_text);value['metadata'].update(uid=uid(960),resourceVersion='10')
            self.live[self.kube.resource_path(self.core.target(value))]=value
        else:
            after=next(after for _,_,after,_,_ in self.changes if after['metadata']['name']==args[args.index('patch')+2])
            path=self.kube.resource_path(self.core.target(after));value=self.live[path];patch=json.loads(args[args.index('-p')+1])
            self.assertEqual(patch[:2],[{'op':'test','path':'/metadata/uid','value':value['metadata']['uid']},
                                       {'op':'test','path':'/metadata/resourceVersion','value':value['metadata']['resourceVersion']}])
            field=patch[-1]['path'][1:];self.assertEqual(patch[-2]['value'],value[field]);value[field]=patch[-1]['value']
            value['metadata']['resourceVersion']=str(int(value['metadata']['resourceVersion'])+1)
        if self.lost:raise TimeoutError()
        return RawResult(out=json.dumps(value))
    def verify(self,*args):
        if not self.can_run:raise RuntimeError('not admitted')
    def observed(self,*args):
        return self.evidence[{'start':'start-review-runtime','restore':'restore-gitops'}[self.operation]] if self.complete else None
    def advance(self,prior=None):
        return review.advance_review_runtime_transition(self.root,self.plan,self.candidate,expected_plan_sha256=self.plan['planSha256'],
            expected_candidate_sha256=self.candidate['candidateSha256'],operation=self.operation,parent_receipt=self.parent,
            expected_parent_sha256=self.parent['canonicalSha256'],transport=self.transport,sink=self.sink,verify_ready=self.verify,
            verify_complete=self.observed,prior=prior,expected_prior_sha256=prior['canonicalSha256'] if prior else None,clock=lambda:NOW)
    def resume(self):
        prior=json.loads(self.sink.path.read_text());self.new_sink();return self.advance(prior)
    def test_successor_switch_and_gitops_resume_recover_lost_responses(self):
        self.lost=True;self.assertEqual(self.advance()['status'],'complete');self.assertEqual(len(self.effects),3)
        self.assertEqual(self.resume()['status'],'complete');self.assertEqual(len(self.effects),3)
        self.set_operation('restore');self.new_sink();self.assertEqual(self.advance()['status'],'complete');self.assertEqual(len(self.effects),4)
        self.assertEqual(self.resume()['status'],'complete');self.assertEqual(len(self.effects),4)
    def test_unadmitted_candidate_and_undelivered_create_do_not_progress(self):
        self.can_run=False
        with self.assertRaises(BootstrapStopped):self.advance()
        self.assertEqual(self.effects,[]);self.new_sink();self.can_run=True;self.undelivered=True
        self.assertEqual(self.advance()['status'],'waiting');self.undelivered=False
        self.assertEqual(self.resume()['status'],'waiting');self.assertEqual(len(self.effects),1)
    def test_replacement_and_unreviewed_semantics_block_deployment_patch(self):
        path=next(path for path in self.live if '/deployments/' in path)
        self.live[path]['metadata']['uid']=uid(999)
        with self.assertRaises(BootstrapStopped):self.advance()
        self.assertEqual(len(self.effects),2)
        self.assertFalse(any('deployment' in args for args in self.effects))
    def test_readiness_wait_does_not_repeat_writes_or_resume_gitops(self):
        self.complete=False;self.assertEqual(self.advance()['status'],'waiting');self.assertEqual(len(self.effects),3)
        self.assertEqual(self.resume()['status'],'waiting');self.assertEqual(len(self.effects),3)
        self.complete=True;self.assertEqual(self.resume()['status'],'complete');self.assertEqual(len(self.effects),3)
    def test_even_rehashed_candidate_cannot_widen_the_role(self):
        self.candidate['targetReconcilerRole']['rules'].append({'apiGroups':[''],'resources':['secrets'],'verbs':['get']})
        self.candidate['candidateSha256']=sha({k:v for k,v in self.candidate.items() if k!='candidateSha256'})
        with self.assertRaises(BootstrapStopped):self.advance()
        self.assertEqual(self.effects,[])

    def test_resume_requires_runtime_verification_parent(self):
        self.set_operation('restore');self.new_sink();self.parent['completed']=self.parent['completed'][:-1]
        self.parent['canonicalSha256']=sha({k:v for k,v in self.parent.items() if k!='canonicalSha256'})
        with self.assertRaises(BootstrapStopped):self.advance()
        self.assertEqual(self.effects,[])


    def test_server_defaulted_deployment_with_lost_patch_stays_pending_without_retry(self):
        path=next(path for path in self.live if '/deployments/' in path)
        self.live[path]['spec']['progressDeadlineSeconds']=600
        self.delay_deployment=True
        self.assertEqual(self.advance()['status'],'waiting');self.assertEqual(len(self.effects),3)
        self.delay_deployment=False
        self.assertEqual(self.resume()['status'],'waiting');self.assertEqual(len(self.effects),3)


class InitializerRetirementTests(unittest.TestCase):
    def setUp(self):
        from .test_case_review_storage import ReviewInitializationTests
        self.h=ReviewInitializationTests();self.h.setUp();self.addCleanup(self.h.doCleanups)
        self.h.advance();self.h.api.complete();self.receipt=self.h.resume()
        self.plan,evidence=fixture();self.plan['identities'].update(sourcePvcUid=uid(701),sourcePvUid=uid(702),sourcePodUid=uid(703),mountObserverPodUid=uid(704),initializerPodUid=self.receipt['podUid'],targetPvcUid=self.receipt['claimUid'],targetPvUid=self.receipt['volumeUid'])
        self.plan['pins']['initializationReceiptSha256']=self.receipt['canonicalSha256'];self.plan.pop('planSha256');self.plan['planSha256']=sha(self.plan)
        parent={'schemaVersion':'roebel_review_handover_receipt_v1','planSha256':self.plan['planSha256'],'operationId':self.plan['operationId'],
                'previousReceiptSha256':None,'status':'effect-intent','completed':[{'step':'fence-source','evidence':evidence['fence-source']}],'pending':'release-mounts'}
        self.parent=parent|{'canonicalSha256':sha(parent)};self.pod=copy.deepcopy(self.h.plan['pod'])
        self.pod['metadata'].update(uid=self.receipt['podUid'],resourceVersion='10')
        self.pod['status']={'phase':'Succeeded','containerStatuses':[{'state':{'terminated':{'exitCode':0}}}]}
        self.deletes=0;self.lost=False;self.sink=ReceiptSink.reserve(self.h.root/'retire-1.json')
    def request(self,method,path,payload):
        self.assertTrue(path.endswith('/pods/'+self.h.plan['pod']['metadata']['name']))
        if method=='GET':return copy.deepcopy(self.pod)
        self.assertEqual(method,'DELETE');self.assertEqual(json.loads(self.sink.path.read_text())['status'],'intent')
        self.assertEqual(payload['preconditions'],{'uid':self.receipt['podUid'],'resourceVersion':'10'})
        self.deletes+=1;self.pod=None
        if self.lost:raise TimeoutError()
    def advance(self,prior=None):
        return review.advance_initializer_retirement(Path(__file__).resolve().parent.parent,self.plan,self.h.plan,self.h.storage_plan,
            expected_plan_sha256=self.plan['planSha256'],initialization_receipt=self.receipt,expected_initialization_receipt_sha256=self.receipt['canonicalSha256'],
            parent_receipt=self.parent,expected_parent_sha256=self.parent['canonicalSha256'],transport=self,sink=self.sink,verify_ready=lambda *args:None,
            prior=prior,expected_prior_sha256=prior['canonicalSha256'] if prior else None,clock=lambda:NOW)
    def test_owned_completed_initializer_retires_once_after_lost_response(self):
        self.lost=True;result=self.advance();self.assertEqual(result['status'],'api-absent');self.assertEqual(self.deletes,1)
        self.sink=ReceiptSink.reserve(self.h.root/'retire-2.json');self.assertEqual(self.advance(result)['status'],'api-absent');self.assertEqual(self.deletes,1)
        self.assertNotIn('mountAbsent',result)
    def test_running_or_replaced_initializer_is_not_deleted(self):
        self.pod['status']['phase']='Running'
        with self.assertRaises(BootstrapStopped):self.advance()
        self.sink=ReceiptSink.reserve(self.h.root/'retire-2.json');self.pod['status']['phase']='Succeeded';self.pod['metadata']['uid']=uid(999)
        with self.assertRaises(BootstrapStopped):self.advance()
        self.assertEqual(self.deletes,0)


class ReviewRestartTests(unittest.TestCase):
    compile=ReviewRuntimeCompilerTests.compile
    worker_fixture=ReviewRuntimeCompilerTests.worker_fixture
    def setUp(self):
        WorkerTransportTests.setUp(self);del self.request
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup);self.index=0
        _,self.evidence=fixture()
        for evidence in self.evidence.values():
            for key in evidence:
                if key in self.plan['pins']:evidence[key]=self.plan['pins'][key]
                if key in self.plan['identities']:evidence[key]=self.plan['identities'][key]
        self.parent['completed']=[{'step':s,'evidence':self.evidence[s]} for s in review.STEPS[:7]];self.parent['pending']='verify-review-runtime'
        self.parent['canonicalSha256']=sha({k:v for k,v in self.parent.items() if k!='canonicalSha256'})
        self.deployment=copy.deepcopy(next(o for o in self.candidate['resources']['items'] if o['kind']=='Deployment' and o['metadata']['name']=='roebel-case-steward-control'))
        self.deployment['metadata'].update(uid=self.plan['identities']['sourceDeploymentUid'],resourceVersion='10',generation=2)
        self.deployment['status']={'observedGeneration':2,**dict.fromkeys(('replicas','updatedReplicas','readyReplicas','availableReplicas'),1)}
        template=self.deployment['spec']['template'];self.pod={'apiVersion':'v1','kind':'Pod','metadata':{**copy.deepcopy(template['metadata']),
          'name':'review-control-example','namespace':'stadtstack-roebel-staging-lab','uid':uid(501),'resourceVersion':'11','ownerReferences':[{'controller':True,'uid':uid(970)}]},'spec':copy.deepcopy(template['spec'])}
        self.pod['metadata']['labels']['pod-template-hash']='abc123';self.pod['spec']['nodeName']='example-node'
        self.pod['status']={'phase':'Running','conditions':[{'type':'Ready','status':'True'}],
           'containerStatuses':[{'name':'runtime','ready':True,'imageID':'containerd://'+self.plan['pins']['migrationImageDigest'],
                                 'containerID':'containerd://'+'a'*64,'restartCount':0}]}
        self.rs={'metadata':{'uid':uid(970),'labels':{'pod-template-hash':'abc123'},'ownerReferences':[{'controller':True,'uid':self.plan['identities']['sourceDeploymentUid']}]}}
        self.execs=0;self.lost=False;self.undelivered=False;self.exit_code=0;self.new_sink()
    def new_sink(self):
        self.index+=1;self.sink=ReceiptSink.reserve(Path(self.directory.name)/f'restart-{self.index}.json')
    def request(self,method,path,payload):
        self.assertEqual(method,'GET')
        if '/deployments/' in path:return copy.deepcopy(self.deployment)
        if path.endswith('/replicasets'):return {'items':[copy.deepcopy(self.rs)]}
        self.assertTrue(path.endswith('/pods'));return {'items':[copy.deepcopy(self.pod)]}
    def exec_pod(self,namespace,name,pod_uid,container,argv):
        self.assertEqual((name,pod_uid,container),(self.pod['metadata']['name'],uid(501),'runtime'))
        self.assertEqual(argv,['node','-e',"process.kill(1, 'SIGTERM')"])
        self.assertEqual(json.loads(self.sink.path.read_text())['status'],'intent');self.execs+=1
        if self.undelivered:raise TimeoutError()
        self.pod['status']['containerStatuses'][0].update(containerID='containerd://'+'b'*64,restartCount=1,lastState={'terminated':{'exitCode':self.exit_code}})
        if self.lost:raise TimeoutError()
    def advance(self,prior=None):
        return review.advance_review_runtime_restart(self.root,self.plan,self.candidate,expected_plan_sha256=self.plan['planSha256'],
            expected_candidate_sha256=self.candidate['candidateSha256'],parent_receipt=self.parent,expected_parent_sha256=self.parent['canonicalSha256'],
            transport=self,sink=self.sink,verify_ready=lambda *args:None,verify_complete=lambda *args:self.evidence['verify-review-runtime'],
            prior=prior,expected_prior_sha256=prior['canonicalSha256'] if prior else None,clock=lambda:NOW)
    def resume(self):
        prior=json.loads(self.sink.path.read_text());self.new_sink();return self.advance(prior)
    def test_clean_restart_with_lost_response_recovers_without_second_signal(self):
        self.lost=True;self.assertEqual(self.advance()['status'],'complete');self.assertEqual(self.execs,1)
        self.assertEqual(self.resume()['status'],'complete');self.assertEqual(self.execs,1)
    def test_uncertain_signal_is_not_repeated(self):
        self.undelivered=True;self.assertEqual(self.advance()['status'],'waiting')
        self.undelivered=False;self.assertEqual(self.resume()['status'],'waiting');self.assertEqual(self.execs,1)
    def test_wrong_pod_or_crashed_restart_cannot_complete(self):
        self.pod['metadata']['uid']=uid(999)
        with self.assertRaises(BootstrapStopped):self.advance()
        self.assertEqual(self.execs,0);self.pod['metadata']['uid']=uid(501);self.new_sink();self.exit_code=137
        with self.assertRaises(BootstrapStopped):self.advance()
        self.assertEqual(self.execs,1)


class ConnectedRuntimeHandoverTests(unittest.TestCase):
    def test_switch_restart_and_gitops_share_ordered_receipts_and_recover_without_repeating_writes(self):
        switch=ReviewTransitionTests();switch.setUp();self.addCleanup(switch.doCleanups)
        restart=ReviewRestartTests();restart.setUp();self.addCleanup(restart.doCleanups)
        self.assertEqual(switch.plan,restart.plan)
        plan=switch.plan;initial=copy.deepcopy(switch.parent);initial.update(status='reserved',pending=None)
        initial['canonicalSha256']=sha({k:v for k,v in initial.items() if k!='canonicalSha256'})
        prefix={r['step']:r['evidence'] for r in initial['completed']};outcomes={}
        signals=[]
        original_exec=restart.exec_pod
        def signal(*args):
            signals.append(args);original_exec(*args)
        restart.exec_pod=signal;restart.undelivered=True
        directory=Path(switch.directory.name)
        class Connected:
            def verify_ready(self,active,state):
                if state['pending']=='restore-gitops':
                    assert outcomes.get('verify-review-runtime',{}).get('evidence',{}).get('cleanRestartVerified') is True
            def observe(self,active,step,state):
                if step in prefix:return prefix[step]
                return outcomes.get(step,{}).get('evidence')
            def perform(self,active,step,state):
                parent=state|{'canonicalSha256':sha(state)}
                if step=='verify-review-runtime':
                    restart.parent=parent;outcomes[step]=restart.advance()
                else:
                    switch.set_operation('start' if step=='start-review-runtime' else 'restore')
                    switch.parent=parent;switch.new_sink();outcomes[step]=switch.advance()
        adapter=Connected();sink=ReceiptSink.reserve(directory/'connected-1.json')
        result=review.advance_review_handover(plan,expected_plan_sha256=plan['planSha256'],adapter=adapter,sink=sink,
            prior=initial,expected_prior_sha256=initial['canonicalSha256'],clock=lambda:NOW)
        self.assertEqual(result['status'],'awaiting-evidence');self.assertEqual(result['pending'],'verify-review-runtime')
        self.assertEqual(len(switch.effects),3);self.assertEqual(len(signals),1)
        self.assertNotIn('restore-gitops',outcomes)
        # The first signal's response was inconclusive. Observe its later clean
        # completion using the same receipt; neither coordinator nor helper resends.
        restart.pod['status']['containerStatuses'][0].update(containerID='containerd://'+'b'*64,restartCount=1,lastState={'terminated':{'exitCode':0}})
        outcomes['verify-review-runtime']=restart.resume()
        self.assertEqual(len(signals),1)
        prior=json.loads(sink.path.read_text());sink=ReceiptSink.reserve(directory/'connected-2.json')
        result=review.advance_review_handover(plan,expected_plan_sha256=plan['planSha256'],adapter=adapter,sink=sink,
            prior=prior,expected_prior_sha256=prior['canonicalSha256'],clock=lambda:NOW)
        self.assertEqual(result['status'],'complete');self.assertEqual(len(switch.effects),4);self.assertEqual(len(signals),1)
        self.assertEqual([r['step'] for r in result['completed']],list(review.STEPS))


class WorkerDriverTests(unittest.TestCase):
    compile=ReviewRuntimeCompilerTests.compile
    worker_fixture=ReviewRuntimeCompilerTests.worker_fixture
    def setUp(self):
        WorkerTransportTests.setUp(self)
        self.binding=json.loads(next(o for o in self.candidate['resources']['items'] if o['kind']=='ConfigMap' and o['metadata']['name']=='roebel-case-steward-review-reviewed-v1')['data']['reviewed-binding.json'])
        self.request=review.build_review_worker_request(self.plan,self.binding,'capture-backup')
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup);self.directory_path=Path(self.directory.name).resolve()
        self.index=0;self.actions=[];self.lost=True;self.missing=False
        self.archive=b'private synthetic archived bytes'
        import hashlib
        self.archive_pin='sha256:'+hashlib.sha256(self.archive).hexdigest()
        self.facts={'sourceSealChecksum':sha('seal'),'sourceDeploymentClaimChecksum':sha('claim'),'sourceDatabaseSha256':sha('db'),
            'sourceFilesSha256':sha('files'),'caseId':self.plan['caseId'],'caseVersion':3,
            'admissionReceiptChecksum':self.plan['pins']['admissionReceiptChecksum'],'archiveSha256':self.archive_pin}
        self.capture=self.envelope(self.request,self.facts)
        self.new_sink()
        self.worker_transport=SimpleNamespace(pod_uid=self.pod_uid,exchange=self.exchange)
    def envelope(self,request,result):
        body={'schemaVersion':'roebel_case_review_migration_result_v1','mode':request['mode'],'requestSha256':sha(request),
              **{k:request[k] for k in ('sourceRevision','controlImageDigest','sourceConfigurationSha256','targetConfigurationSha256')},'result':result}
        return body|{'resultSha256':sha(body)}
    def new_sink(self):
        self.index+=1;self.sink=ReceiptSink.reserve(self.directory_path/f'driver-{self.index}.json')
    def exchange(self,action,request_bytes,**kwargs):
        import os,hashlib
        self.actions.append(action)
        self.assertEqual(json.loads(request_bytes),self.request)
        self.assertTrue(json.loads(self.sink.path.read_text())['uploadIntent' if action in ('upload-archive','verify-archive') else 'invokeIntent'])
        if action=='upload-archive':
            if not getattr(self,'drop_upload',False):self.uploaded=True
            raise BootstrapStopped('upload response lost')
        if action=='verify-archive':
            if not getattr(self,'uploaded',False):raise BootstrapStopped('upload missing')
            return {'status':'private-archive-stored','archiveSha256':self.archive_pin}
        if action=='invoke':
            if self.lost:raise TimeoutError('lost response')
            return {'status':'private-archive-captured','resultSha256':self.capture['resultSha256']}
        if self.missing:raise BootstrapStopped('missing retained result')
        data=json.dumps(self.capture,sort_keys=True,separators=(',',':')).encode() if action=='result' else self.archive
        if action=='archive':self.assertEqual(kwargs['expected_archive_sha256'],self.archive_pin)
        os.write(kwargs['output_fd'],data);os.fsync(kwargs['output_fd'])
        return {'status':'private-output-saved','bytes':len(data),'sha256':'sha256:'+hashlib.sha256(data).hexdigest()}
    def advance(self,prior=None):
        return review.advance_review_worker_exchange(self.plan,self.request,expected_plan_sha256=self.plan['planSha256'],
            parent_receipt=self.parent,expected_parent_sha256=self.parent['canonicalSha256'],transport=self.worker_transport,sink=self.sink,
            artifact_directory=self.directory_path,verify_ready=lambda *args:None,archive_bytes=self.archive if self.request['mode']=='verify-backup' else None,prior=prior,
            expected_prior_sha256=prior['canonicalSha256'] if prior else None)
    def resume(self):
        prior=json.loads(self.sink.path.read_text());self.new_sink();return self.advance(prior)
    def test_lost_invoke_response_recovers_private_result_and_archive_without_reinvoking(self):
        result=self.advance();self.assertEqual(result['status'],'complete');self.assertEqual(self.actions,['invoke','result','archive'])
        self.assertEqual(self.resume()['status'],'complete');self.assertEqual(self.actions,['invoke','result','archive'])
        self.assertEqual(set(result['artifacts']),{'result','archive'})
        self.assertNotIn(self.archive.decode(),json.dumps(result))
    def test_missing_result_recovery_never_repeats_worker_invocation(self):
        self.missing=True;self.assertEqual(self.advance()['status'],'waiting');self.assertEqual(self.resume()['status'],'waiting')
        self.missing=False;self.assertEqual(self.resume()['status'],'complete')
        self.assertEqual(self.actions.count('invoke'),1)
    def test_modified_retained_archive_cannot_complete_again(self):
        result=self.advance();path=self.directory_path/result['artifacts']['archive']['name'];path.write_bytes(b'changed')
        self.assertNotEqual(self.resume()['status'],'complete');self.assertEqual(self.actions.count('invoke'),1)
    def test_request_builder_carries_discovered_pins_and_prepared_candidate_into_activation(self):
        self.assertIsNone(self.request['sourceSealChecksum'])
        self.assertEqual(self.request['sourceBindingChecksum'],self.plan['pins']['sourceBindingSha256'])
        verified=review.build_review_worker_request(self.plan,self.binding,'verify-backup',captured=self.capture)
        self.assertEqual(verified['sourceSealChecksum'],self.facts['sourceSealChecksum']);self.assertEqual(verified['archiveSha256'],self.archive_pin)
        prepare=review.build_review_worker_request(self.plan,self.binding,'prepare',captured=self.capture)
        prepared=self.envelope(prepare,{'receipt':{**{k:self.facts[k] for k in ('caseId','caseVersion','sourceSealChecksum','sourceDatabaseSha256','admissionReceiptChecksum')},
            'testOnly':True,'authorityBinding':'none','candidateChecksum':sha('candidate')}})
        activate=review.build_review_worker_request(self.plan,self.binding,'activate',captured=self.capture,prepared=prepared)
        self.assertEqual(activate['migrationPlan']['candidateChecksum'],sha('candidate'))
        self.assertEqual(activate['migrationPlan']['sourceDeploymentClaimChecksum'],self.facts['sourceDeploymentClaimChecksum'])
        prepared['result']['receipt']['sourceSealChecksum']=sha('foreign-seal');prepared['resultSha256']=sha({k:v for k,v in prepared.items() if k!='resultSha256'})
        with self.assertRaises(BootstrapStopped):review.build_review_worker_request(self.plan,self.binding,'activate',captured=self.capture,prepared=prepared)
    def test_restore_upload_is_verified_after_lost_response_and_never_repeated(self):
        self.request=review.build_review_worker_request(self.plan,self.binding,'verify-backup',captured=self.capture)
        self.capture=self.envelope(self.request,self.facts|{'restoredFilesSha256':self.facts['sourceFilesSha256'],'restoredCandidateChecksum':sha('restored')})
        self.drop_upload=True
        self.assertEqual(self.advance()['status'],'waiting');self.assertNotIn('invoke',self.actions)
        self.assertEqual(self.resume()['status'],'waiting');self.assertEqual(self.actions.count('upload-archive'),1)
        # Late delivery becomes observable; it is never resent to the worker.
        self.uploaded=True
        self.assertEqual(self.resume()['status'],'complete');self.assertEqual(self.actions.count('upload-archive'),1)
        self.assertEqual(self.actions.count('invoke'),1);self.assertNotIn('archive',self.actions)



class PrivateConfigurationPreflightTests(unittest.TestCase):
    def setUp(self):
        import base64,os
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.plan,_=fixture();self.token=lambda i:base64.urlsafe_b64encode(bytes([i])*32).decode().rstrip('=')
        self.source={'municipalityId':'roebel-mueritz','policyVersion':'synthetic-v1','actorRegistry':[{'actorId':'example:steward','actorClass':'case_steward'}],
            'allowedSignerPubkeys':[],'allowedAgentPubkeys':[],'syntheticAdoption':{},'credentials':[{'token':self.token(250)}],
            'admissionAllowedHosts':['admission.internal'],'outboxAllowedHosts':['outbox.internal'],'probeAllowedHosts':['127.0.0.1'],'drainTimeoutMs':5000}
        self.target=copy.deepcopy(self.source);self.target['requiredDepartmentIds']=['planning']
        self.target['actorRegistry'] += [{'actorId':'example:admin','actorClass':'administration'},{'actorId':'example:public','actorClass':'public'},
            {'actorId':'example:agent','actorClass':'department_agent','departmentId':'planning'},
            {'actorId':'example:reviewer','actorClass':'department_reviewer','departmentId':'planning'}]
        self.target['administrationReview']={'caseId':self.plan['caseId'],'allowedHosts':['review.internal'],'grants':[
            {'actor':{k:a[k] for k in ('actorId','actorClass')},'caseId':self.plan['caseId'],'notBefore':int(NOW.timestamp()*1000)-120000,
             'expiresAt':int(NOW.timestamp()*1000)+7200000,'token':self.token(i+1)} for i,a in enumerate(self.target['actorRegistry']) if a['actorClass']!='public']}
    def verify(self):
        import os,hashlib
        fds=[]
        try:
            for side,value in [('source',self.source),('target',self.target)]:
                path=Path(self.directory.name)/side;raw=json.dumps(value).encode();path.write_bytes(raw);path.chmod(0o600)
                fds.append(os.open(path,os.O_RDONLY));self.plan['pins'][side+'ConfigurationSha256']='sha256:'+hashlib.sha256(raw).hexdigest()
            self.plan['planSha256']=sha({k:v for k,v in self.plan.items() if k!='planSha256'})
            return review.verify_review_private_configuration(self.plan,source_fd=fds[0],target_fd=fds[1])
        finally:
            for fd in fds:os.close(fd)
    def test_all_review_roles_cover_the_entire_handover_window(self):
        result=self.verify();self.assertEqual(result['status'],'configuration-window-verified');self.assertEqual(result['grantCount'],4)
        self.assertNotIn(self.token(1),json.dumps(result));self.assertNotIn('example:',json.dumps(result))
    def test_mid_handover_expiry_and_missing_role_fail_before_source_shutdown(self):
        grants=self.target['administrationReview']['grants'];original=copy.deepcopy(grants)
        grants[0]['expiresAt']=int(NOW.timestamp()*1000)+1000
        with self.assertRaises(BootstrapStopped):self.verify()
        self.target['administrationReview']['grants']=original[:-1]
        with self.assertRaises(BootstrapStopped):self.verify()
    def test_changed_source_policy_or_reused_admission_credential_is_rejected(self):
        self.target['policyVersion']='changed'
        with self.assertRaises(BootstrapStopped):self.verify()
        self.target['policyVersion']=self.source['policyVersion'];self.target['administrationReview']['grants'][0]['token']=self.token(250)
        with self.assertRaises(BootstrapStopped):self.verify()


class LiveConfigurationObservationTests(unittest.TestCase):
    def setUp(self):
        import base64,hashlib,os
        from . import case_runtime_kubernetes as kube, case_runtime_bootstrap as core
        self.fixture=PrivateConfigurationPreflightTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.plan=self.fixture.plan;self.plan['identities']['clusterUid']=kube.CLUSTER_UID
        self.fds=[];self.receipts={};self.objects={};self.calls=[];self.fail=None;self.change=None
        for i,(side,name) in enumerate((('source','roebel-case-steward-control-runtime'),('target','roebel-case-steward-review-runtime-v1'))):
            raw=json.dumps(getattr(self.fixture,side)).encode();path=Path(self.fixture.directory.name)/side
            path.write_bytes(raw);path.chmod(0o600);fd=os.open(path,os.O_RDONLY);self.fds.append(fd);self.addCleanup(os.close,fd)
            self.plan['pins'][side+'ConfigurationSha256']='sha256:'+hashlib.sha256(raw).hexdigest()
            identity=uid(950) if side=='source' else self.plan['identities']['configurationSecretUid']
            receipt={'schemaVersion':'roebel_case_configuration_receipt_v1','planSha256':sha(side+' provisioning'),
                'reference':{'namespace':kube.NAMESPACE,'name':name,'key':'application-json'},'configurationSha256':self.plan['pins'][side+'ConfigurationSha256'],
                'nonce':str(i+1)*64,'status':'provisioned','uid':identity}
            self.receipts[side]=receipt|{'canonicalSha256':sha(receipt)}
            self.objects[f'/api/v1/namespaces/{kube.NAMESPACE}/secrets/{name}']={
                'apiVersion':'v1','kind':'Secret','metadata':{'name':name,'namespace':kube.NAMESPACE,'uid':identity,'resourceVersion':'1',
                    'annotations':{core.NONCE:receipt['nonce']}},'immutable':True,'type':'Opaque','data':{'application-json':base64.b64encode(raw).decode()}}
        self.plan['pins']['configurationReceiptSha256']=self.receipts['target']['canonicalSha256']
        self.plan['planSha256']=sha({k:v for k,v in self.plan.items() if k!='planSha256'})
        self.objects['/api/v1/namespaces/kube-system']={'metadata':{'uid':kube.CLUSTER_UID}}
    def request(self,method,path,payload):
        self.assertEqual((method,payload),('GET',None));self.calls.append(path)
        if self.fail:raise RuntimeError(self.fail)
        if self.change:self.change(path)
        return copy.deepcopy(self.objects.get(path))
    def observe(self,clock=lambda:NOW):
        return review.observe_review_configuration(self.plan,expected_plan_sha256=self.plan['planSha256'],source_fd=self.fds[0],target_fd=self.fds[1],
            source_receipt=self.receipts['source'],expected_source_receipt_sha256=self.receipts['source']['canonicalSha256'],
            target_receipt=self.receipts['target'],transport=self,clock=clock)
    def test_checks_both_live_identities_and_bytes_without_disclosing_configuration(self):
        result=self.observe();self.assertEqual(result['configuration']['grantCount'],4)
        self.assertEqual(len(self.calls),6);self.assertEqual(result['identities']['source']['uid'],uid(950))
        self.assertNotIn(self.fixture.token(1),json.dumps(result));self.assertNotIn('example:',json.dumps(result))
    def test_replaced_terminating_or_changed_secret_is_rejected(self):
        path=next(p for p in self.objects if p.endswith('review-runtime-v1'));original=copy.deepcopy(self.objects[path])
        for mutate in (lambda s:s['metadata'].update(uid=uid(999)),lambda s:s['metadata'].update(deletionTimestamp='now'),
                       lambda s:s.update(immutable=False),lambda s:s['data'].update({'application-json':'e30='})):
            with self.subTest(mutation=mutate):
                self.objects[path]=copy.deepcopy(original);mutate(self.objects[path])
                with self.assertRaises(BootstrapStopped):self.observe()
    def test_secret_change_during_observation_and_expiry_are_rejected(self):
        path=next(p for p in self.objects if p.endswith('review-runtime-v1'))
        def change(p):
            if p==path and self.calls.count(path)>1:self.objects[path]['metadata']['resourceVersion']='2'
        self.change=change
        with self.assertRaises(BootstrapStopped):self.observe()
        self.change=None;times=iter((NOW,NOW+timedelta(hours=1)))
        with self.assertRaises(BootstrapStopped):self.observe(clock=lambda:next(times))
    def test_unpinned_receipt_and_outside_window_fail_before_secret_reads(self):
        self.receipts['source']['uid']=uid(999)
        with self.assertRaises(BootstrapStopped):self.observe()
        self.assertEqual(self.calls,[])
        with self.assertRaises(BootstrapStopped):self.observe(clock=lambda:NOW+timedelta(hours=1))
        self.assertEqual(self.calls,[])
    def test_transport_errors_cannot_disclose_tokens(self):
        self.fail=self.fixture.token(1)
        with self.assertRaises(BootstrapStopped) as stopped:self.observe()
        self.assertNotIn(self.fail,str(stopped.exception));self.assertTrue(stopped.exception.__suppress_context__)


class GitOpsTargetProofTests(unittest.TestCase):
    compile=ReviewRuntimeCompilerTests.compile
    worker_fixture=ReviewRuntimeCompilerTests.worker_fixture
    def setUp(self):
        import subprocess
        WorkerTransportTests.setUp(self);del self.request
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.target=Path(self.directory.name).resolve()/'target'
        def run(*args,cwd=None):return subprocess.check_output(['git',*args],cwd=cwd,text=True,stderr=subprocess.PIPE).strip()
        self.git=run;run('clone','--shared','--quiet',str(self.root),str(self.target))
        run('remote','set-url','origin','https://github.com/GiraeffleAeffle/roebel-staging-operations.git',cwd=self.target)
        self.plan['pins']['operationsRevision']=run('rev-parse','HEAD',cwd=self.root)
        self.plan['planSha256']=sha({k:v for k,v in self.plan.items() if k!='planSha256'})
        path=self.target/'reviewed-render/roebel-staging/case-runtime/resources.json';path.write_text(json.dumps(self.candidate['resources'],indent=2)+'\n')
        run('add',str(path),cwd=self.target);run('-c','user.name=Local Rehearsal','-c','user.email=rehearsal@example.invalid','commit','--quiet','-m','Synthetic exact successor',cwd=self.target)
        self.revision=run('rev-parse','HEAD',cwd=self.target)
        self.source={'metadata':{'generation':1},'spec':{'url':'https://github.com/GiraeffleAeffle/roebel-staging-operations.git','ref':{'branch':'main'}},
           'status':{'observedGeneration':1,'artifact':{'revision':'main@sha1:'+self.revision},'conditions':[{'type':'Ready','status':'True'}]}}
    def request(self,method,path,payload):
        self.assertEqual(method,'GET')
        if path.endswith('/kube-system'):return {'metadata':{'uid':self.plan['identities']['clusterUid']}}
        return self.source
    def verify(self):
        return review.verify_review_gitops_target(self.root,self.plan,self.candidate,target_checkout=self.target,expected_target_revision=self.revision,transport=self)
    def test_only_exact_successor_commit_observed_by_flux_can_resume(self):
        self.assertEqual(self.verify()['status'],'gitops-successor-observed')
        self.source['status']['artifact']['revision']='main@sha1:'+self.plan['pins']['operationsRevision']
        with self.assertRaises(BootstrapStopped):self.verify()
    def test_extra_source_change_and_dirty_checkout_are_rejected(self):
        path=self.target/'README.md';path.write_text(path.read_text()+'\nUnexpected change\n')
        with self.assertRaises(BootstrapStopped):self.verify()
        self.git('add','README.md',cwd=self.target);self.git('-c','user.name=Local Rehearsal','-c','user.email=rehearsal@example.invalid','commit','--quiet','-m','Unexpected source',cwd=self.target)
        self.revision=self.git('rev-parse','HEAD',cwd=self.target);self.source['status']['artifact']['revision']='main@sha1:'+self.revision
        with self.assertRaises(BootstrapStopped):self.verify()


class MigrationStageDriverTests(unittest.TestCase):
    compile=ReviewRuntimeCompilerTests.compile
    worker_fixture=ReviewRuntimeCompilerTests.worker_fixture
    envelope=WorkerDriverTests.envelope
    exchange=WorkerDriverTests.exchange
    new_sink=WorkerDriverTests.new_sink
    def setUp(self):
        WorkerDriverTests.setUp(self)
        self.captured=self.capture;self.stage_actions=[];self.missing=False
        _,evidence=fixture()
        for e in evidence.values():
            for key in e:
                if key in self.plan['pins']:e[key]=self.plan['pins'][key]
                if key in self.plan['identities']:e[key]=self.plan['identities'][key]
        evidence['verify-backup'].update({k:v for k,v in self.facts.items() if k in evidence['verify-backup']})
        evidence['verify-backup']['restoredFilesSha256']=self.facts['sourceFilesSha256']
        self.parent['pending']='prepare-migration';self.parent['completed']=[{'step':s,'evidence':evidence[s]} for s in review.STEPS[:3]]
        self.parent['canonicalSha256']=sha({k:v for k,v in self.parent.items() if k!='canonicalSha256'})
        self.original_pin=self.parent['canonicalSha256']
        self.request=review.build_review_worker_request(self.plan,self.binding,'prepare',captured=self.captured)
        candidate={k:sha(k) for k in ('journalHeadChecksum','sourceConfigFingerprint','targetConfigFingerprint','sourceOptionsFingerprint',
                                    'targetOptionsFingerprint','preservedTablesChecksum','targetDatabaseSha256')}
        candidate.update(schemaVersion='synthetic_review_migration_candidate_v1',caseId=self.plan['caseId'],caseVersion=3,
            admissionReceiptChecksum=self.facts['admissionReceiptChecksum'],sourceSealChecksum=self.facts['sourceSealChecksum'],
            sourceDatabaseSha256=self.facts['sourceDatabaseSha256'],targetDatabaseByteLength=4096,testOnly=True,authorityBinding='none')
        candidate['candidateChecksum']=sha(candidate)
        self.output=self.envelope(self.request,{'candidateRootDir':'/private/synthetic-candidate','receipt':candidate})
        self.worker_transport=SimpleNamespace(pod_uid=self.pod_uid,exchange=self.stage_exchange)
    def stage_exchange(self,action,request_bytes,**kwargs):
        import os,hashlib
        self.stage_actions.append(action)
        self.assertEqual(kwargs['expected_parent_sha256'],self.original_pin)
        self.assertEqual(json.loads(request_bytes),self.request)
        stage=json.loads(self.sink.path.read_text());child=stage['commands']['prepare']
        saved=json.loads((self.directory_path/child['receiptFile']).read_text())
        self.assertTrue(saved['invokeIntent'])
        if action=='invoke':raise TimeoutError('response lost after preparation')
        self.assertEqual(action,'result')
        if self.missing:raise BootstrapStopped('retained result not yet visible')
        data=json.dumps(self.output,sort_keys=True,separators=(',',':')).encode();os.write(kwargs['output_fd'],data);os.fsync(kwargs['output_fd'])
        return {'status':'private-output-saved','bytes':len(data),'sha256':'sha256:'+hashlib.sha256(data).hexdigest()}
    def advance(self,prior=None):
        return review.advance_review_migration_stage(self.plan,self.binding,expected_plan_sha256=self.plan['planSha256'],
            parent_receipt=self.parent,expected_parent_sha256=self.parent['canonicalSha256'],transport=self.worker_transport,sink=self.sink,
            artifact_directory=self.directory_path,verify_ready=lambda *args:None,captured=self.captured,prior=prior,
            expected_prior_sha256=prior['canonicalSha256'] if prior else None,clock=lambda:NOW)
    def resume(self):
        prior=json.loads(self.sink.path.read_text());self.new_sink();return self.advance(prior)
    def test_real_worker_operator_composes_preparation_and_recovers_original_parent_intent(self):
        result=self.advance();self.assertEqual(result['status'],'complete')
        self.assertEqual(result['evidence']['candidateChecksum'],self.output['result']['receipt']['candidateChecksum'])
        self.parent['status']='awaiting-evidence';self.parent['previousReceiptSha256']=self.original_pin
        self.parent['canonicalSha256']=sha({k:v for k,v in self.parent.items() if k!='canonicalSha256'})
        self.assertNotEqual(self.parent['canonicalSha256'],self.original_pin)
        self.assertEqual(self.resume()['status'],'complete');self.assertEqual(self.stage_actions,['invoke','result'])
    def test_incomplete_child_is_resumed_from_its_checkpoint_without_new_invocation(self):
        self.missing=True;self.assertEqual(self.advance()['status'],'waiting')
        self.assertEqual(self.resume()['status'],'waiting')
        self.missing=False;self.assertEqual(self.resume()['status'],'complete')
        self.assertEqual(self.stage_actions.count('invoke'),1)
    def test_lost_stage_completion_reuses_the_newer_child_checkpoint(self):
        commit=self.sink.commit
        def fail(value):
            if value['status']=='complete':raise OSError('stage response lost')
            commit(value)
        self.sink.commit=fail
        with self.assertRaises(BootstrapStopped):self.advance()
        self.assertEqual(self.resume()['status'],'complete');self.assertEqual(self.stage_actions,['invoke','result'])
    def test_missing_child_checkpoint_never_falls_back_to_reissuing_preparation(self):
        self.missing=True;result=self.advance()
        (self.directory_path/result['commands']['prepare']['receiptFile']).unlink()
        with self.assertRaises(BootstrapStopped):self.resume()
        self.assertEqual(self.stage_actions,['invoke','result'])
    def test_changed_parent_prefix_allows_no_new_effect(self):
        self.missing=True;self.advance();before=list(self.stage_actions)
        self.parent['completed'][2]['evidence']['sourceDatabaseSha256']=sha('changed')
        self.parent['canonicalSha256']=sha({k:v for k,v in self.parent.items() if k!='canonicalSha256'})
        with self.assertRaises(BootstrapStopped):self.resume()
        self.assertEqual(self.stage_actions,before)

    def test_three_migration_stages_compose_real_encryption_and_controlled_worker_recovery(self):
        import hashlib,os,shutil,subprocess
        age=shutil.which('age');keygen=shutil.which('age-keygen')
        if not age or not keygen:self.skipTest('real age executables not installed')
        age=str(Path(age).resolve());key=self.directory_path/'disposable-age.key'
        subprocess.run([keygen,'-o',str(key)],capture_output=True,check=True)
        recipient=subprocess.check_output([keygen,'-y',str(key)],text=True,stderr=subprocess.PIPE).strip()
        options={'age_binary':age,'expected_age_sha256':'sha256:'+hashlib.sha256(Path(age).read_bytes()).hexdigest(),
                 'recipient':recipient,'identity_path':str(key)}
        def checked(body,key):return body|{key:sha(body)}
        target_claim=checked({'schemaVersion':'case_durable_deployment_claim_v1','municipalityId':self.binding['municipalityId'],
            'releaseDigest':self.binding['releaseDigest'],'controlDeploymentBindingChecksum':self.binding['bindingChecksum'],
            'pvc':{'namespace':self.binding['storage']['pvcNamespace'],'name':self.binding['storage']['pvcName'],'uid':self.binding['storage']['pvcUid']},
            'pvName':self.binding['storage']['pvName']},'claimChecksum')
        source_claim=checked({'schemaVersion':'case_durable_deployment_claim_v1','controlDeploymentBindingChecksum':self.plan['pins']['sourceBindingSha256']},'claimChecksum')
        # Controlled worker result fixtures. Actual runtime/SQLite seal semantics
        # are exercised by the separate public-source integration suite.
        source_seal=checked({'deploymentClaimChecksum':source_claim['claimChecksum'],'databaseSha256':self.facts['sourceDatabaseSha256'],
            'recoveryEvidence':{'syntheticFixture':True}},'sealChecksum')
        self.facts.update(sourceDeploymentClaimChecksum=source_claim['claimChecksum'],sourceSealChecksum=source_seal['sealChecksum'])
        self.plan['pins']['targetDeploymentClaimChecksum']=target_claim['claimChecksum']
        self.plan['planSha256']=sha({k:v for k,v in self.plan.items() if k!='planSha256'})
        self.parent.update(planSha256=self.plan['planSha256'],pending='verify-backup',completed=self.parent['completed'][:2])
        self.parent['canonicalSha256']=sha({k:v for k,v in self.parent.items() if k!='canonicalSha256'});self.original_pin=self.parent['canonicalSha256']
        requests={};results={};effects=[];uploaded=False;missing=True
        capture_request=review.build_review_worker_request(self.plan,self.binding,'capture-backup')
        captured=self.envelope(capture_request,self.facts);requests['capture-backup']=capture_request;results['capture-backup']=captured
        verification=review.build_review_worker_request(self.plan,self.binding,'verify-backup',captured=captured)
        requests['verify-backup']=verification;results['verify-backup']=self.envelope(verification,self.facts|{
            'restoredFilesSha256':self.facts['sourceFilesSha256'],'restoredCandidateChecksum':sha('restored')})
        def exchange(action,raw,**kwargs):
            nonlocal uploaded
            req=json.loads(raw);mode=req['mode'];self.assertEqual(req,requests[mode])
            self.assertEqual(kwargs['expected_parent_sha256'],self.original_pin)
            stage=json.loads(self.sink.path.read_text());command=stage['commands'][mode]
            child=json.loads((self.directory_path/command['receiptFile']).read_text())
            if action=='upload-archive':
                self.assertTrue(child['uploadIntent']);self.assertEqual(kwargs['archive_bytes'],self.archive)
                effects.append((mode,action));uploaded=True;raise TimeoutError('lost upload response')
            if action=='verify-archive':
                self.assertTrue(uploaded);return {'status':'private-archive-stored','archiveSha256':self.archive_pin}
            self.assertTrue(child['invokeIntent'])
            if action=='invoke':effects.append((mode,action));raise TimeoutError('lost invoke response')
            if mode=='verify-backup' and missing:raise BootstrapStopped('verification result delayed')
            data=self.archive if action=='archive' else json.dumps(results[mode],sort_keys=True,separators=(',',':')).encode()
            os.write(kwargs['output_fd'],data);os.fsync(kwargs['output_fd'])
            return {'status':'private-output-saved','bytes':len(data),'sha256':'sha256:'+hashlib.sha256(data).hexdigest()}
        transport=SimpleNamespace(pod_uid=self.pod_uid,exchange=exchange)
        def advance(prior=None,**inputs):
            return review.advance_review_migration_stage(self.plan,self.binding,expected_plan_sha256=self.plan['planSha256'],
                parent_receipt=self.parent,expected_parent_sha256=self.parent['canonicalSha256'],transport=transport,sink=self.sink,
                artifact_directory=self.directory_path,verify_ready=lambda *args:None,prior=prior,
                expected_prior_sha256=prior['canonicalSha256'] if prior else None,clock=lambda:NOW,**inputs)
        with self.assertRaises(BootstrapStopped):advance(backup_options=options)
        prior=json.loads(self.sink.path.read_text());cipher=next(self.directory_path.glob('encrypted-*/case-backup.age'));cipher_before=cipher.read_bytes()
        self.assertNotIn('activate',dict(effects));missing=False;self.new_sink()
        backup=advance(prior,backup_options=options);self.assertEqual(backup['status'],'complete');self.assertEqual(cipher.read_bytes(),cipher_before)
        self.parent['completed'].append({'step':'verify-backup','evidence':backup['evidence']});self.parent['pending']='prepare-migration'
        self.parent['canonicalSha256']=sha({k:v for k,v in self.parent.items() if k!='canonicalSha256'});self.original_pin=self.parent['canonicalSha256']
        preparation=review.build_review_worker_request(self.plan,self.binding,'prepare',captured=captured)
        candidate=copy.deepcopy(self.output['result']['receipt']);candidate.update(sourceSealChecksum=source_seal['sealChecksum']);candidate['candidateChecksum']=sha({k:v for k,v in candidate.items() if k!='candidateChecksum'})
        prepared=self.envelope(preparation,{'candidateRootDir':'/private/synthetic-candidate','receipt':candidate});requests['prepare']=preparation;results['prepare']=prepared
        self.new_sink();prepared_stage=advance(captured=captured);self.assertEqual(prepared_stage['status'],'complete')
        self.parent['completed'].append({'step':'prepare-migration','evidence':prepared_stage['evidence']});self.parent['pending']='activate-migration'
        self.parent['canonicalSha256']=sha({k:v for k,v in self.parent.items() if k!='canonicalSha256'});self.original_pin=self.parent['canonicalSha256']
        activation=review.build_review_worker_request(self.plan,self.binding,'activate',captured=captured,prepared=prepared)
        target_seal=checked({'deploymentClaimChecksum':target_claim['claimChecksum'],'databaseSha256':candidate['targetDatabaseSha256'],
            'databaseByteLength':candidate['targetDatabaseByteLength'],'configFingerprint':candidate['targetConfigFingerprint'],
            'recoveryEvidence':source_seal['recoveryEvidence'],'closedAtUtc':'2026-09-10T12:00:01.000Z'},'sealChecksum')
        activated=checked({'schemaVersion':'synthetic_review_migration_activation_v1','planChecksum':activation['migrationPlan']['planChecksum'],
            'candidate':candidate,'sourceClaim':source_claim,'sourceSeal':source_seal,'targetClaim':target_claim,'targetSeal':target_seal,
            'startedAtUtc':'2026-09-10T12:00:00.000Z'},'activationChecksum')
        requests['activate']=activation;results['activate']=self.envelope(activation,activated)
        self.new_sink();final=advance(captured=captured,prepared=prepared);self.assertEqual(final['status'],'complete')
        self.assertEqual(final['evidence']['candidateChecksum'],prepared_stage['evidence']['candidateChecksum'])
        self.assertEqual(effects,[('capture-backup','invoke'),('verify-backup','upload-archive'),('verify-backup','invoke'),('prepare','invoke'),('activate','invoke')])
        # Reverify history after the worker/identity are no longer available.
        key.unlink()
        from unittest.mock import patch
        with patch('subprocess.run',side_effect=AssertionError('historical observation must not execute')):
            for record,inputs in [(backup,{'backup_options':options}),(prepared_stage,{'captured':captured}),(final,{'captured':captured,'prepared':prepared})]:
                observed=review.observe_review_migration_stage(self.plan,self.binding,expected_plan_sha256=self.plan['planSha256'],
                    receipt=record,expected_receipt_sha256=record['canonicalSha256'],**inputs)
                self.assertEqual(observed,record['evidence'])
        cipher.write_bytes(b'corrupted')
        with self.assertRaises(BootstrapStopped):review.observe_review_migration_stage(self.plan,self.binding,expected_plan_sha256=self.plan['planSha256'],
            receipt=backup,expected_receipt_sha256=backup['canonicalSha256'],backup_options=options)



    def test_historical_observer_rechecks_retained_result_without_transport(self):
        record=self.advance();before=list(self.stage_actions)
        observed=review.observe_review_migration_stage(self.plan,self.binding,expected_plan_sha256=self.plan['planSha256'],
            receipt=record,expected_receipt_sha256=record['canonicalSha256'],captured=self.captured)
        self.assertEqual(observed,record['evidence']);self.assertEqual(self.stage_actions,before)
        command=record['commands']['prepare'];child=json.loads((self.directory_path/command['receiptFile']).read_text())
        (self.directory_path/child['artifacts']['result']['name']).write_bytes(b'altered')
        with self.assertRaises(BootstrapStopped):review.observe_review_migration_stage(self.plan,self.binding,expected_plan_sha256=self.plan['planSha256'],
            receipt=record,expected_receipt_sha256=record['canonicalSha256'],captured=self.captured)
        self.assertEqual(self.stage_actions,before)


class IntegratedDriverTests(unittest.TestCase):
    """Real orchestration/operations/age; Kubernetes and runtime outputs controlled."""
    envelope=WorkerDriverTests.envelope
    def setUp(self):
        import hashlib,shutil,subprocess
        from . import case_runtime_bootstrap as core, case_runtime_kubernetes as kube
        from unittest.mock import patch
        self.h=WorkerDriverTests();self.h.setUp();self.addCleanup(self.h.doCleanups)
        self.root,self.plan,self.candidate=self.h.root,self.h.plan,self.h.candidate
        self.directory=self.h.directory_path;self.binding=self.h.binding;self.kube,self.core=kube,core
        self.h.storage.advance();self.h.storage.api.complete();self.initialized=self.h.storage.resume()
        self.plan['pins']['initializationReceiptSha256']=self.initialized['canonicalSha256']
        self.plan['identities'].update(initializerPodUid=self.initialized['podUid'],targetPvcUid=self.initialized['claimUid'],targetPvUid=self.initialized['volumeUid'])
        self.plan['identities'].update(sourcePvUid=uid(702),sourcePodUid=uid(703),mountObserverPodUid=uid(704))
        self.age=shutil.which('age');keygen=shutil.which('age-keygen')
        if not self.age or not keygen:self.skipTest('real age executables not installed')
        self.age=str(Path(self.age).resolve());key=self.directory/'fixture-age.key'
        subprocess.run([keygen,'-o',str(key)],capture_output=True,check=True)
        self.backup={'age_binary':self.age,'expected_age_sha256':'sha256:'+hashlib.sha256(Path(self.age).read_bytes()).hexdigest(),
                    'recipient':subprocess.check_output([keygen,'-y',str(key)],text=True,stderr=subprocess.PIPE).strip(),'identity_path':str(key)}
        def checked(body,key):return body|{key:sha(body)}
        self.checked=checked
        self.source_claim=checked({'schemaVersion':'case_durable_deployment_claim_v1','controlDeploymentBindingChecksum':self.plan['pins']['sourceBindingSha256']},'claimChecksum')
        self.target_claim=checked({'schemaVersion':'case_durable_deployment_claim_v1','municipalityId':self.binding['municipalityId'],
            'releaseDigest':self.binding['releaseDigest'],'controlDeploymentBindingChecksum':self.binding['bindingChecksum'],
            'pvc':{'namespace':self.binding['storage']['pvcNamespace'],'name':self.binding['storage']['pvcName'],'uid':self.binding['storage']['pvcUid']},
            'pvName':self.binding['storage']['pvName']},'claimChecksum')
        self.plan['pins']['targetDeploymentClaimChecksum']=self.target_claim['claimChecksum']
        self.plan['planSha256']=sha({k:v for k,v in self.plan.items() if k!='planSha256'})
        self.facts=copy.deepcopy(self.h.facts);self.source_seal=checked({'deploymentClaimChecksum':self.source_claim['claimChecksum'],
            'databaseSha256':self.facts['sourceDatabaseSha256'],'recoveryEvidence':{'syntheticFixture':True}},'sealChecksum')
        self.facts.update(sourceDeploymentClaimChecksum=self.source_claim['claimChecksum'],sourceSealChecksum=self.source_seal['sealChecksum'])
        self.migration_candidate={k:sha(k) for k in ('journalHeadChecksum','sourceConfigFingerprint','targetConfigFingerprint','sourceOptionsFingerprint',
            'targetOptionsFingerprint','preservedTablesChecksum','targetDatabaseSha256')}
        self.migration_candidate.update(schemaVersion='synthetic_review_migration_candidate_v1',caseId=self.plan['caseId'],caseVersion=3,
            admissionReceiptChecksum=self.plan['pins']['admissionReceiptChecksum'],sourceSealChecksum=self.facts['sourceSealChecksum'],
            sourceDatabaseSha256=self.facts['sourceDatabaseSha256'],targetDatabaseByteLength=4096,testOnly=True,authorityBinding='none')
        self.migration_candidate=checked(self.migration_candidate,'candidateChecksum')
        self.effects=[];self.results={};self.ready=True;self.pause_restart=False;self.pause_worker=False;self.counter=8000;self.driver=None
        self.objects={};self.pods=[];self.sets=[]
        def live(desired,identity=None):
            value=copy.deepcopy(desired);self.counter+=1;value['metadata'].update(uid=identity or uid(self.counter),resourceVersion='10',generation=1)
            self.objects[kube.resource_path(core.target(value))]=value;return value
        self.live=live
        source=core.build_plan(self.root)
        self.flux=live(source['objects'][-1]['desired'],self.plan['identities']['reconcilerUid']);self.flux['spec']['suspend']=False
        self.control=live(next(r['desired'] for r in source['objects'] if r['target']['name']=='roebel-case-steward-control' and r['target']['kind']=='Deployment'),self.plan['identities']['sourceDeploymentUid'])
        live(self.candidate['sourceReconcilerRole'])
        self.initializer=copy.deepcopy(self.h.storage.plan['pod']);self.initializer['metadata'].update(uid=self.initialized['podUid'],resourceVersion='10')
        self.initializer['status']={'phase':'Succeeded','containerStatuses':[{'state':{'terminated':{'exitCode':0}}}]};self.pods.append(self.initializer)
        self.observer={'metadata':{'uid':self.plan['identities']['mountObserverPodUid']},'spec':{'nodeName':'example-node'},
            'status':{'phase':'Running','conditions':[{'type':'Ready','status':'True'}]}};self.pods.append(self.observer)
        mocked=patch.object(review,'verify_review_gitops_target',return_value={'status':'gitops-successor-observed'})
        mocked.start();self.addCleanup(mocked.stop)
        self.index=0;self.new_driver()
    def new_driver(self,prior=None):
        self.index+=1;self.journal_sink=ReceiptSink.reserve(self.directory/f'full-driver-{self.index}.json')
        self.driver=review.ReviewHandoverDriver(self.root,self.plan,self.candidate,expected_plan_sha256=self.plan['planSha256'],
            storage_plan=self.h.storage.storage_plan,initialization_plan=self.h.storage.plan,initialization_receipt=self.initialized,node_name='example-node',
            transport=self,worker_transport_factory=lambda identity,ready:SimpleNamespace(pod_uid=identity,exchange=self.exchange),checks=self,
            backup_options=self.backup,artifact_directory=self.directory,sink=self.journal_sink,prior=prior,
            expected_prior_sha256=prior['canonicalSha256'] if prior else None,clock=lambda:NOW)
    def recover(self):
        prior=json.loads(self.journal_sink.path.read_text());self.new_driver(prior)
        return self.driver.advance()
    def request(self,method,path,payload):
        if method=='GET':
            if path.endswith('/kube-system'):return {'metadata':{'uid':self.plan['identities']['clusterUid']}}
            if path.startswith('/api/v1/nodes/'):return {'metadata':{'uid':self.plan['identities']['nodeUid']}}
            if '/persistentvolumeclaims/' in path:
                side='target' if path.endswith('roebel-case-steward-review-state-v1') else 'source'
                return {'metadata':{'uid':self.plan['identities'][side+'PvcUid']},'spec':{'accessModes':['ReadWriteOncePod']},'status':{'phase':'Bound'}}
            if path.endswith('/pods'):return {'items':copy.deepcopy(self.pods)}
            if path.endswith('/replicasets'):return {'items':copy.deepcopy(self.sets)}
            if '/pods/' in path:return copy.deepcopy(next((p for p in self.pods if p['metadata'].get('name')==path.rsplit('/',1)[-1]),None))
            return copy.deepcopy(self.objects.get(path))
        self.effects.append((method,path))
        if method=='PATCH':
            value=self.objects[path]
            for op in payload:
                parts=op['path'].strip('/').split('/');location=value
                for part in parts[:-1]:location=location[part]
                if op['op']=='test':self.assertEqual(location[parts[-1]],op['value'])
                else:location[parts[-1]]=copy.deepcopy(op['value'])
            value['metadata']['resourceVersion']=str(int(value['metadata']['resourceVersion'])+1);value['metadata']['generation']+=1
            if value['kind']=='Deployment' and payload[-1]['path']=='/spec':self.start_runtime()
            raise TimeoutError('controlled response lost after patch')
        if method=='POST':
            if payload['kind']=='Pod':
                pod=copy.deepcopy(payload);pod['metadata'].update(uid=uid(777),resourceVersion='10')
                pod['spec']['nodeName']='example-node'
                pod['status']={'phase':'Pending' if self.pause_worker else 'Running','containerStatuses':[{'name':'migration','ready':not self.pause_worker,'restartCount':0,
                    'imageID':'containerd://'+self.plan['pins']['migrationImageDigest']}]};self.pods.append(pod)
            else:self.live(payload)
            raise TimeoutError('controlled response lost after create')
        self.assertEqual(method,'DELETE')
        value=self.request('GET',path,None);self.assertEqual(payload['preconditions'],{k:value['metadata'][k] for k in ('uid','resourceVersion')})
        if '/pods/' in path:self.pods=[p for p in self.pods if p['metadata']['uid']!=value['metadata']['uid']]
        else:del self.objects[path]
        raise TimeoutError('controlled response lost after delete')
    def start_runtime(self):
        self.control['status']={'observedGeneration':self.control['metadata']['generation'],**{k:1 for k in ('replicas','updatedReplicas','readyReplicas','availableReplicas')}}
        template=self.control['spec']['template'];pod={'apiVersion':'v1','kind':'Pod','metadata':copy.deepcopy(template['metadata']), 'spec':copy.deepcopy(template['spec'])}
        pod['metadata'].update(name='synthetic-review-runtime',namespace=self.kube.NAMESPACE,uid=uid(8500),resourceVersion='10',
            ownerReferences=[{'uid':uid(8501),'controller':True}]);pod['metadata'].setdefault('labels',{})['pod-template-hash']='abc123'
        pod['status']={'phase':'Running','conditions':[{'type':'Ready','status':'True'}],'containerStatuses':[{'name':'runtime','ready':True,
            'restartCount':0,'containerID':'containerd://'+'a'*64,'imageID':'containerd://'+self.plan['pins']['migrationImageDigest']}]}
        self.runtime=pod;self.pods.append(pod);self.sets=[{'metadata':{'uid':uid(8501),'labels':{'pod-template-hash':'abc123'},
            'ownerReferences':[{'controller':True,'uid':self.plan['identities']['sourceDeploymentUid']}]}}]
    def exec_pod(self,namespace,name,identity,container,args):
        self.assertEqual((identity,container,args),(uid(8500),'runtime',['node','-e',"process.kill(1, 'SIGTERM')"]))
        self.effects.append(('SIGTERM',identity))
        if not self.pause_restart:self.complete_restart()
        raise TimeoutError('controlled signal response lost')
    def complete_restart(self):
        self.runtime['status']['containerStatuses'][0].update(restartCount=1,containerID='containerd://'+'b'*64,lastState={'terminated':{'exitCode':0}})
    def verify_ready(self,plan,parent,driver):
        if not self.ready:raise BootstrapStopped('fixture preflight unavailable')
        if parent['completed'] and parent['pending']!='restore-gitops' and len(parent['completed'])<9:
            self.assertTrue(self.flux['spec']['suspend'])
        if len(parent['completed'])<6:self.assertEqual(self.control['spec']['replicas'],0 if parent['completed'] else self.control['spec']['replicas'])
    def observe_release(self,plan,parent,driver,pod_uid):
        identity=plan['identities']['mountObserverPodUid']
        return review.observe_mount_release(self.root,plan,expected_plan_sha256=plan['planSha256'],transport=self,verify_ready=lambda p:None,
            node_filesystem=lambda *args:{'podDirectoryNames':[identity],'mountInfo':f'10 1 1:1 / /var/lib/kubelet/pods/{identity}/volumes/fixture rw - tmpfs tmpfs rw\n'},migration_pod_uid=pod_uid)
    def verify_complete(self,plan,parent,child,driver):
        step=parent['pending'];previous={r['step']:r['evidence'] for r in parent['completed']}
        runtime=review.observe_review_runtime(self.root,plan,self.candidate,expected_candidate_sha256=self.candidate['candidateSha256'],transport=self)
        if runtime is None:return None
        if step=='start-review-runtime':
            result={k:plan['identities'][k] for k in ('sourceDeploymentUid','targetPvcUid','configurationSecretUid')}
            result.update({k:plan['pins'][k] for k in ('targetBindingSha256','migrationImageDigest')});result['runtimePodUid']=runtime['podUid']
        elif step=='verify-review-runtime':
            result={'runtimePodUid':runtime['podUid'],'admissionReceiptChecksum':plan['pins']['admissionReceiptChecksum'],
                'allFourListenersReady':True,'cleanRestartVerified':True,'sourceDatabaseSha256':previous['verify-backup']['sourceDatabaseSha256'],'publicServicesPreserved':True}
        else:result={'reconcilerUid':plan['identities']['reconcilerUid'],'reconcilerSuspended':self.flux['spec']['suspend'],
            'targetRenderSha256':plan['pins']['targetRenderSha256'],'reconciled':True,'sourceRetained':True,'targetRetained':True}
        return result|{'receiptSha256':sha(result)}
    def exchange(self,action,raw,**kwargs):
        import os,hashlib
        request=json.loads(raw);mode=request['mode'];pin=sha(request)
        if action in ('invoke','upload-archive'):self.effects.append((mode,action))
        if action=='upload-archive':self.assertEqual(kwargs['archive_bytes'],self.h.archive);return {'status':'private-archive-stored','archiveSha256':self.h.archive_pin}
        if action=='verify-archive':return {'status':'private-archive-stored','archiveSha256':self.h.archive_pin}
        if action=='invoke':
            if mode=='capture-backup':result=self.facts
            elif mode=='verify-backup':result=self.facts|{'restoredFilesSha256':self.facts['sourceFilesSha256'],'restoredCandidateChecksum':sha('restored')}
            elif mode=='prepare':result={'candidateRootDir':'/private/synthetic-candidate','receipt':self.migration_candidate}
            else:
                started=getattr(self,'runtime_now',NOW)
                stamp=lambda time:time.isoformat(timespec='milliseconds').replace('+00:00','Z')
                seal=self.checked({'deploymentClaimChecksum':self.target_claim['claimChecksum'],'databaseSha256':self.migration_candidate['targetDatabaseSha256'],
                    'databaseByteLength':4096,'configFingerprint':self.migration_candidate['targetConfigFingerprint'],'recoveryEvidence':self.source_seal['recoveryEvidence'],
                    'closedAtUtc':stamp(started+timedelta(seconds=1))},'sealChecksum')
                result=self.checked({'schemaVersion':'synthetic_review_migration_activation_v1','planChecksum':request['migrationPlan']['planChecksum'],
                    'candidate':self.migration_candidate,'sourceClaim':self.source_claim,'sourceSeal':self.source_seal,'targetClaim':self.target_claim,'targetSeal':seal,
                    'startedAtUtc':stamp(started)},'activationChecksum')
            self.results[pin]=self.envelope(request,result);raise TimeoutError('controlled worker response lost')
        data=self.h.archive if action=='archive' else json.dumps(self.results[pin],sort_keys=True,separators=(',',':')).encode()
        os.write(kwargs['output_fd'],data);os.fsync(kwargs['output_fd'])
        return {'status':'private-output-saved','bytes':len(data),'sha256':'sha256:'+hashlib.sha256(data).hexdigest()}
    def test_all_nine_stages_connect_and_recovery_repeats_no_effect(self):
        result=self.driver.advance();self.assertEqual(result['status'],'complete')
        self.assertEqual([r['step'] for r in result['completed']],list(review.STEPS))
        effects=list(self.effects);self.assertEqual(self.recover()['status'],'complete');self.assertEqual(self.effects,effects)
        self.assertEqual([e for e in effects if e[0]=='SIGTERM'],[('SIGTERM',uid(8500))])
        self.assertFalse(self.flux['spec']['suspend']);self.assertTrue(list(self.directory.glob('encrypted-*/case-backup.age')))
    def test_delayed_worker_and_restart_resume_without_manual_child_calls(self):
        self.pause_worker=True
        self.assertEqual(self.driver.advance()['pending'],'verify-backup')
        pod=next(p for p in self.pods if p['metadata'].get('name')=='roebel-case-review-migration-v1')
        pod['status']['phase']='Running';pod['status']['containerStatuses'][0]['ready']=True
        self.pause_restart=True;self.assertEqual(self.recover()['pending'],'verify-review-runtime')
        self.complete_restart();self.assertEqual(self.recover()['status'],'complete')
        self.assertEqual(sum(e[0]=='SIGTERM' for e in self.effects),1)
        self.assertEqual(sum(e[0]=='capture-backup' and e[1]=='invoke' for e in self.effects),1)
    def test_preflight_failure_cannot_fence_source(self):
        self.ready=False
        with self.assertRaises(BootstrapStopped):self.driver.advance()
        self.assertEqual(self.effects,[]);self.assertEqual(self.control['spec']['replicas'],1)
    def test_missing_owned_child_checkpoint_never_restarts_the_stage(self):
        self.pause_worker=True;self.driver.advance();ref=self.driver.journal['children']['worker-create']
        (self.directory/ref['file']).unlink();before=list(self.effects)
        with self.assertRaises(BootstrapStopped):self.recover()
        self.assertEqual(self.effects,before)

    def test_all_stages_use_bounded_kubectl_transport_and_live_writer_gates(self):
        def run(args,input_text=None,timeout=None):
            if 'get' in args:return RawResult(out=json.dumps(self.request('GET',args[-1],None)))
            if 'create' in args:return RawResult(out=json.dumps(self.request('POST',args[args.index('--raw')+1],json.loads(input_text))))
            if 'delete' in args:return RawResult(out=json.dumps(self.request('DELETE',args[args.index('--raw')+1],json.loads(input_text))))
            if 'patch' in args:
                index=args.index('patch');kind,name=args[index+1:index+3]
                paths=[path for path,value in self.objects.items() if value['kind'].lower()==kind.lower() and value['metadata']['name']==name]
                self.assertEqual(len(paths),1)
                return RawResult(out=json.dumps(self.request('PATCH',paths[0],json.loads(args[args.index('-p')+1]))))
            self.assertIn('exec',args);self.exec_pod(self.kube.NAMESPACE,args[args.index('-n')+2],uid(8500),'runtime',['node','-e',"process.kill(1, 'SIGTERM')"])
            return RawResult(out='')
        # The fixture API deliberately loses every write response after apply.
        # The actual transport and stage gates must recover those observations.
        self.driver.transport=review.KubectlReviewHandoverTransport(self.root,self.plan,self.candidate,self.driver.worker,self.h.storage.plan,
            runner=SimpleNamespace(run=run),snapshot=SimpleNamespace(path='/private/test-kubeconfig'))
        gate=object.__new__(review.ReviewLiveChecks);gate.root=self.root;gate.plan=self.plan;gate.candidate=self.candidate
        gate.source=self.core.build_plan(self.root);gate.transport=self.driver.transport
        before=self.verify_ready
        def ready(plan,parent,driver):before(plan,parent,driver);gate._objects(parent,driver)
        self.verify_ready=ready
        result=self.driver.advance();self.assertEqual(result['status'],'complete')
        self.assertEqual([r['step'] for r in result['completed']],list(review.STEPS))


class PublicPreservationTests(unittest.TestCase):
    def setUp(self):
        from . import test_case_runtime_kubernetes as existing
        from . import case_runtime_kubernetes as kube
        existing.KubernetesTests.setUpClass()
        self.addCleanup(existing.KubernetesTests.tearDownClass)
        self.fixture=existing.KubernetesTests();self.addCleanup(self.fixture.doCleanups)
        self.adapter,self.api=self.fixture.adapter_environment();self.root=self.adapter.root;self.kube=kube
        self.plan,evidence=fixture();self.plan['pins']['operationsRevision']=self.adapter.revision
        resources=json.loads((self.root/'reviewed-render/roebel-staging/case-runtime/resources.json').read_text())
        self.plan['pins']['sourceRenderSha256']=sha(resources);self.plan['identities']['clusterUid']=kube.CLUSTER_UID
        self.plan['planSha256']=sha({k:v for k,v in self.plan.items() if k!='planSha256'})
        self.parent=review._state(self.plan,None,None);self.parent['canonicalSha256']=sha(self.parent)
        self.source_path=f'/apis/apps/v1/namespaces/{kube.NAMESPACE}/deployments/roebel-case-steward-control'
        self.flux_path=f'/apis/kustomize.toolkit.fluxcd.io/v1/namespaces/{kube.FLUX}/kustomizations/roebel-case-runtime'
        self.api.objects[self.source_path]={'metadata':{'uid':self.plan['identities']['sourceDeploymentUid']},'spec':{'replicas':1}}
        self.api.objects[self.flux_path]={'metadata':{'uid':self.plan['identities']['reconcilerUid']},'spec':{'suspend':False}}
        for i,desired in enumerate(resources['items']):
            if not desired['metadata']['name'].startswith('roebel-case-public-binding'):continue
            live=copy.deepcopy(desired);live['metadata'].update(uid=uid(2000+i),resourceVersion='1',generation=1)
            if live['kind']=='Deployment':
                live['status']={'observedGeneration':1,**dict.fromkeys(('replicas','updatedReplicas','readyReplicas','availableReplicas'),1)}
                rsuid=uid(3000);self.api.sets.append({'metadata':{'uid':rsuid,'labels':{'pod-template-hash':'abc123'},'ownerReferences':[{'controller':True,'uid':live['metadata']['uid']}]}})
                template=live['spec']['template'];pod={'apiVersion':'v1','kind':'Pod','metadata':{**copy.deepcopy(template['metadata']),
                    'name':'public-reader-fixture','namespace':kube.NAMESPACE,'uid':uid(3001),'resourceVersion':'1','ownerReferences':[{'controller':True,'uid':rsuid}]},
                    'spec':copy.deepcopy(template['spec']),'status':{'phase':'Running','conditions':[{'type':'Ready','status':'True'}],
                    'containerStatuses':[{'name':'runtime','ready':True,'restartCount':0,'containerID':'containerd://'+'a'*64,'imageID':template['spec']['containers'][0]['image']}]}}
                pod['metadata'].setdefault('labels',{})['pod-template-hash']='abc123';self.api.pods.append(pod);self.reader=pod
            self.api.objects[kube.resource_path({'apiVersion':desired['apiVersion'],'kind':desired['kind'],**{k:desired['metadata'][k] for k in ('name','namespace')}})]=live
    def observe(self,baseline=None):
        return review.observe_review_public_preservation(self.root,self.plan,expected_plan_sha256=self.plan['planSha256'],parent_receipt=self.parent,
            expected_parent_sha256=self.parent['canonicalSha256'],adapter=self.adapter,baseline=baseline,
            expected_baseline_sha256=baseline['canonicalSha256'] if baseline else None)
    def test_baseline_remains_verifiable_while_case_writer_is_stopped_without_secret_reads(self):
        baseline=self.observe();self.api.calls.clear()
        self.api.objects[self.source_path]['spec']['replicas']=0;self.api.objects[self.flux_path]['spec']['suspend']=True
        self.assertEqual(self.observe(baseline),baseline)
        self.assertTrue(all(method=='GET' and '/secrets/' not in path for method,path in self.api.calls))
        with self.assertRaises(BootstrapStopped):self.observe()
    def test_reader_restart_injection_and_tracer_drift_are_rejected(self):
        baseline=self.observe();original=copy.deepcopy(self.reader)
        self.reader['status']['containerStatuses'][0]['restartCount']=1
        with self.assertRaises(BootstrapStopped):self.observe(baseline)
        self.reader.clear();self.reader.update(copy.deepcopy(original));self.reader['spec']['containers'].append({'name':'injected','image':'foreign'})
        with self.assertRaises(BootstrapStopped):self.observe(baseline)
        self.reader.clear();self.reader.update(original);self.api.pods[0]['status']['containerStatuses'][0]['restartCount']=1
        with self.assertRaises(BootstrapStopped):self.observe(baseline)

    def test_cached_reader_can_be_unready_only_during_the_owned_fence(self):
        baseline=self.observe();_,evidence=fixture()
        evidence['fence-source'].update({k:self.plan['identities'][k] for k in ('sourceDeploymentUid','reconcilerUid')})
        self.parent['completed']=[{'step':'fence-source','evidence':evidence['fence-source']}]
        self.parent['pending']='release-mounts';self.parent['status']='effect-intent'
        self.parent['canonicalSha256']=sha({k:v for k,v in self.parent.items() if k!='canonicalSha256'})
        self.api.objects[self.source_path]['spec']['replicas']=0;self.api.objects[self.flux_path]['spec']['suspend']=True
        self.reader['status']['conditions'][0]['status']='False';self.reader['status']['containerStatuses'][0]['ready']=False
        path=f'/apis/apps/v1/namespaces/{self.kube.NAMESPACE}/deployments/roebel-case-public-binding'
        self.api.objects[path]['status'].update(readyReplicas=0,availableReplicas=0)
        with self.assertRaises(BootstrapStopped):self.observe(baseline)
        def observe():return review.observe_review_public_preservation(self.root,self.plan,expected_plan_sha256=self.plan['planSha256'],
            parent_receipt=self.parent,expected_parent_sha256=self.parent['canonicalSha256'],adapter=self.adapter,
            baseline=baseline,expected_baseline_sha256=baseline['canonicalSha256'],allow_reader_degraded=True)
        self.assertEqual(observe(),baseline)
        self.api.objects[self.flux_path]['spec']['suspend']=False
        with self.assertRaises(BootstrapStopped):observe()

    def test_listed_pod_type_omission_and_generated_name_keep_exact_owner(self):
        baseline=self.observe();owner=self.reader['metadata']['ownerReferences'][0]['uid']
        rs=next(r for r in self.api.sets if r['metadata']['uid']==owner)
        rs['metadata']['name']='public-reader'
        self.reader['metadata']['generateName']='public-reader-'
        self.reader.pop('kind');self.reader.pop('apiVersion')
        self.assertEqual(self.observe(baseline),baseline)
        self.reader['metadata']['generateName']='foreign-'
        with self.assertRaises(BootstrapStopped):self.observe(baseline)
        self.reader['metadata']['generateName']='public-reader-';self.reader['kind']='Secret'
        with self.assertRaises(BootstrapStopped):self.observe(baseline)


class ExpiredReviewSetupRecoveryTests(unittest.TestCase):
    """Exercise an actual stopped driver, lost DELETE responses and continuation."""
    def setUp(self):
        from unittest.mock import patch
        self.h=IntegratedDriverTests();self.h.setUp();self.addCleanup(self.h.doCleanups)
        original=review.storage._consumer_object
        def reject_created_pod(observed,desired):
            if desired.get('kind')=='Pod' and desired.get('metadata',{}).get('name')=='roebel-case-review-migration-v1':
                raise BootstrapStopped('synthetic old ownership incompatibility')
            return original(observed,desired)
        with patch.object(review.storage,'_consumer_object',side_effect=reject_created_pod):
            with self.assertRaises(BootstrapStopped):self.h.driver.advance()
        self.old=self.h.driver;self.old.journal['publicBaseline']={
            'schemaVersion':'roebel_review_public_preservation_v1','planSha256':self.old.plan['planSha256'],
            'operationsRevision':self.old.plan['pins']['operationsRevision'],'snapshot':{'syntheticFixture':True}}
        self.old.journal['publicBaseline']['canonicalSha256']=sha(self.old.journal['publicBaseline']);self.old._commit()
        self.pod=next(p for p in self.h.pods if p['metadata'].get('name')=='roebel-case-review-migration-v1')
        self.pod['status'].update(phase='Failed',reason='DeadlineExceeded')
        self.pod['status']['containerStatuses'][0].update(ready=False,state={'terminated':{'exitCode':0}})
        self.now=NOW+timedelta(hours=2);self.old.clock=lambda:self.now
        self.plan=copy.deepcopy(self.old.plan)
        self.plan.update(operationId='c'*64,notBeforeUtc='2026-09-10T13:59:00.000Z',expiresAtUtc='2026-09-10T14:59:00.000Z')
        self.plan['pins'].update(operationsRevision='d'*40,implementationSha256=sha('new admitted implementation'))
        self.pin_plan();self.recovery=self.make_recovery()
        # The controlled cluster has no credentials or Git server. Its readiness
        # port checks the actual writer/fence, journal and clock at every call.
        self.recovery.verify_ready=self.ready
        self.old.checks.node_filesystem=lambda *args:{'podDirectoryNames':[self.plan['identities']['mountObserverPodUid']],
            'mountInfo':f"10 1 1:1 / /var/lib/kubelet/pods/{self.plan['identities']['mountObserverPodUid']}/volumes/fixture rw - tmpfs tmpfs rw\n"}
        self.index=0
        self.before={p:p.read_bytes() for p in self.h.directory.glob('*') if p.is_file()}
        self.effects_before=list(self.h.effects)
    def pin_plan(self):self.plan['planSha256']=sha({k:v for k,v in self.plan.items() if k!='planSha256'})
    def make_recovery(self):
        return review.ExpiredReviewSetupRecovery(self.old,self.plan,expected_plan_sha256=self.plan['planSha256'],
            expected_driver_sha256=sha(self.old.journal),expected_worker_pod_uid=self.pod['metadata']['uid'])
    def ready(self):
        if not review._utc(self.plan['notBeforeUtc'])<=self.now<review._utc(self.plan['expiresAtUtc']):raise BootstrapStopped('window closed')
        if not self.h.flux['spec']['suspend'] or self.h.control['spec']['replicas']!=0:raise BootstrapStopped('fence changed')
        self.assertEqual(sha(self.old.journal),self.recovery.driver_pin)
        return {'canonicalSha256':sha('synthetic verified configuration')}
    def sink(self):
        self.index+=1;self.output=ReceiptSink.reserve(self.h.directory/f'expired-{self.index}.json');return self.output
    def retire(self,prior=None):
        return self.recovery.retire(sink=self.sink(),prior=prior,expected_prior_sha256=prior['canonicalSha256'] if prior else None)
    def test_expired_setup_continues_all_stages_without_replaying_fences_or_changing_old_receipts(self):
        retired=self.retire();self.assertEqual(retired['status'],'retired')
        changes=self.h.effects[len(self.effects_before):]
        self.assertEqual([m for m,p in changes],['DELETE']*3)
        self.assertEqual([p for m,p in changes],[self.recovery.paths[k] for k in ('pod','configMap','networkPolicy')])
        # All fixture DELETEs lose their response after application. None repeats.
        again=self.retire(retired);self.assertEqual(again['status'],'retired');self.assertEqual(self.h.effects[len(self.effects_before):],changes)
        directory=self.h.directory/'continued'
        result=self.recovery.continue_fenced(again,expected_retirement_sha256=again['canonicalSha256'],artifact_directory=directory,sink=self.sink())
        prior=json.loads(Path(result['driverJournal']).read_text())
        self.assertEqual(prior['canonicalSha256'],result['driverJournalSha256'])
        self.assertEqual(prior['previousReceiptSha256'],self.recovery.driver_pin)
        self.assertEqual(set(prior['children']),{'fence','initializer'})
        for p,raw in self.before.items():self.assertEqual(p.read_bytes(),raw)
        self.h.plan=self.plan;self.h.directory=directory;self.h.runtime_now=self.now;self.h.new_driver(prior)
        self.h.driver.clock=lambda:self.now
        completed=self.h.driver.advance()
        self.assertEqual(completed['status'],'complete')
        self.assertEqual([r['step'] for r in completed['completed']],list(review.STEPS))
        after=self.h.effects[len(self.effects_before):]
        self.assertEqual(sum(m=='capture-backup' and p=='invoke' for m,p in after),1)
        self.assertEqual(sum(m=='SIGTERM' for m,p in after),1)
        self.assertFalse(self.h.flux['spec']['suspend'])
        self.assertTrue(list(directory.glob('encrypted-*/case-backup.age')))
        for p,raw in self.before.items():self.assertEqual(p.read_bytes(),raw)
    def test_running_replaced_and_drifted_workers_are_preserved(self):
        original=copy.deepcopy(self.pod)
        for change in ('running','replacement','injected-code'):
            with self.subTest(change=change):
                self.pod.clear();self.pod.update(copy.deepcopy(original))
                if change=='running':self.pod['status']['phase']='Running'
                elif change=='replacement':self.pod['metadata']['uid']=uid(991)
                else:self.pod['spec']['containers'][0]['command']=['foreign-command']
                with self.assertRaises(BootstrapStopped):self.retire()
                self.assertEqual(self.h.effects,self.effects_before)
    def test_closed_window_and_lost_fence_cannot_delete(self):
        self.now+=timedelta(hours=1)
        with self.assertRaises(BootstrapStopped):self.retire()
        self.now-=timedelta(hours=1);self.h.flux['spec']['suspend']=False
        with self.assertRaises(BootstrapStopped):self.retire()
        self.assertEqual(self.h.effects,self.effects_before)
    def test_live_readiness_uses_new_window_and_main_revision_with_the_old_fence(self):
        from unittest.mock import Mock,patch
        gate=object.__new__(review.ReviewLiveChecks)
        gate.root=self.h.root;gate.plan=self.old.plan;gate.candidate=self.old.candidate
        gate.source=self.h.core.build_plan(self.h.root);gate.transport=self.h
        self.old.checks=SimpleNamespace(_objects=gate._objects,_stores=Mock(),_public=Mock(),adapter=object(),
            source_fd=11,target_fd=12,source_receipt={},source_receipt_pin=sha('source'),target_receipt={})
        path='/apis/source.toolkit.fluxcd.io/v1/namespaces/flux-roebel-staging/gitrepositories/roebel-staging-operations'
        source={'metadata':{'generation':1},'spec':{'url':'https://github.com/GiraeffleAeffle/roebel-staging-operations.git','ref':{'branch':'main'}},
            'status':{'artifact':{'revision':'main@sha1:'+self.plan['pins']['operationsRevision']},'observedGeneration':1,'conditions':[{'type':'Ready','status':'True'}]}}
        self.h.objects[path]=source
        with patch.object(review,'verify_review_implementation') as implementation,patch.object(review,'verify_review_gitops_checkout'),\
             patch.object(self.h.core,'_verifier',return_value=SimpleNamespace(verify_tree=lambda root:None)),\
             patch.object(review,'observe_review_public_preservation') as public,patch.object(review,'observe_review_configuration',return_value={'verified':True}) as configuration:
            run=lambda:review.ExpiredReviewSetupRecovery.verify_ready(self.recovery)
            self.assertEqual(run(),{'verified':True})
            implementation.assert_called_once_with(self.h.root,self.plan)
            self.assertEqual(configuration.call_args.args[0],self.plan)
            self.assertEqual(public.call_args.args[1],self.old.plan)
            self.h.control['spec']['replicas']=1
            with self.assertRaises(BootstrapStopped):run()
            self.h.control['spec']['replicas']=0;source['status']['artifact']['revision']='main@sha1:'+self.old.plan['pins']['operationsRevision']
            with self.assertRaises(BootstrapStopped):run()
            source['status']['artifact']['revision']='main@sha1:'+self.plan['pins']['operationsRevision'];self.now+=timedelta(hours=1)
            with self.assertRaises(BootstrapStopped):run()
        self.assertEqual(self.h.effects,self.effects_before)
    def test_retains_policy_until_host_mount_release_and_recovers_owned_deletion(self):
        normal=self.recovery.release;self.recovery.release=lambda:None
        first=self.retire();self.assertEqual(first['status'],'waiting')
        self.assertEqual([m for m,p in self.h.effects[len(self.effects_before):]],['DELETE'])
        self.recovery.release=normal
        self.assertEqual(self.retire(first)['status'],'retired')
        self.assertEqual([m for m,p in self.h.effects[len(self.effects_before):]],['DELETE']*3)
    def test_plan_changes_and_work_after_creation_cannot_be_carried(self):
        original=copy.deepcopy(self.plan)
        for kind in ('case','store','window','operation'):
            self.plan=copy.deepcopy(original)
            if kind=='case':self.plan['caseId']='urn:stadtstack:synthetic-case:municipality:roebel-mueritz:'+uid(999)
            elif kind=='store':self.plan['identities']['targetPvcUid']=uid(998)
            elif kind=='window':self.plan['notBeforeUtc']='2026-09-10T11:59:00.000Z';self.plan['expiresAtUtc']='2026-09-10T12:59:00.000Z'
            else:self.plan['operationId']=self.old.plan['operationId']
            self.pin_plan()
            with self.assertRaises(BootstrapStopped):self.make_recovery()
        self.plan=original;self.old.journal['children']['verify-backup']=self.old.journal['children']['worker-create']
        with self.assertRaises(BootstrapStopped):self.make_recovery()


class UnstartedReviewSetupRecoveryTests(unittest.TestCase):
    pin_plan=ExpiredReviewSetupRecoveryTests.pin_plan
    ready=ExpiredReviewSetupRecoveryTests.ready
    sink=ExpiredReviewSetupRecoveryTests.sink
    retire=ExpiredReviewSetupRecoveryTests.retire
    test_continues_without_replaying_old_intent=ExpiredReviewSetupRecoveryTests.test_expired_setup_continues_all_stages_without_replaying_fences_or_changing_old_receipts
    test_preserves_after_lost_delete=ExpiredReviewSetupRecoveryTests.test_retains_policy_until_host_mount_release_and_recovers_owned_deletion
    test_closed_window_and_lost_fence_cannot_delete=ExpiredReviewSetupRecoveryTests.test_closed_window_and_lost_fence_cannot_delete

    def setUp(self):
        from unittest.mock import patch
        self.h=IntegratedDriverTests();self.h.setUp();self.addCleanup(self.h.doCleanups)
        with patch.object(self.h,'exchange',side_effect=BootstrapStopped('entry did not create a reservation')):
            self.assertEqual(self.h.driver.advance()['status'],'awaiting-evidence')
        self.old=self.h.driver
        self.old.journal['publicBaseline']={'schemaVersion':'roebel_review_public_preservation_v1',
            'planSha256':self.old.plan['planSha256'],'operationsRevision':self.old.plan['pins']['operationsRevision'],'snapshot':{'syntheticFixture':True}}
        self.old.journal['publicBaseline']['canonicalSha256']=sha(self.old.journal['publicBaseline']);self.old._commit()
        self.pod=next(p for p in self.h.pods if p['metadata'].get('name')=='roebel-case-review-migration-v1')
        self.now=NOW+timedelta(hours=2);self.old.clock=lambda:self.now
        self.plan=copy.deepcopy(self.old.plan)
        self.plan.update(operationId='c'*64,notBeforeUtc='2026-09-10T13:59:00.000Z',expiresAtUtc='2026-09-10T14:59:00.000Z')
        self.plan['pins'].update(operationsRevision='d'*40,implementationSha256=sha('repaired worker entry'));self.pin_plan()
        self.recovery=self.make_recovery();self.recovery.verify_ready=self.ready
        self.mailbox_empty=True
        self.old.worker_transport_factory=lambda identity,ready:SimpleNamespace(observe_unused=self.observe_unused)
        self.old.checks.node_filesystem=lambda *args:{'podDirectoryNames':[self.plan['identities']['mountObserverPodUid']],
            'mountInfo':f"10 1 1:1 / /var/lib/kubelet/pods/{self.plan['identities']['mountObserverPodUid']}/volumes/fixture rw - tmpfs tmpfs rw\n"}
        self.index=0;self.before={p:p.read_bytes() for p in self.h.directory.glob('*') if p.is_file()};self.effects_before=list(self.h.effects)

    def make_recovery(self):
        return review.ExpiredReviewSetupRecovery(self.old,self.plan,expected_plan_sha256=self.plan['planSha256'],
            expected_driver_sha256=sha(self.old.journal),expected_worker_pod_uid=self.pod['metadata']['uid'],unstarted_capture=True,recovery_root=self.h.root)

    def observe_unused(self):
        if not self.mailbox_empty:raise BootstrapStopped('reserved invocation exists')
        value={'schemaVersion':'roebel_unused_review_worker_v1','workerPodUid':self.pod['metadata']['uid'],'requestCount':0,
            'planSha256':self.old.plan['planSha256'],'workerSha256':self.old.worker['workerSha256'],
            **{k:self.old.plan['pins'][k] for k in ('sourceConfigurationSha256','targetConfigurationSha256')}}
        return value|{'canonicalSha256':sha(value)}

    def test_reserved_mailbox_or_replaced_worker_cannot_be_deleted(self):
        self.mailbox_empty=False
        with self.assertRaises(BootstrapStopped):self.retire()
        self.assertEqual(self.h.effects,self.effects_before)
        self.mailbox_empty=True;self.pod['metadata']['uid']=uid(993)
        with self.assertRaises(BootstrapStopped):self.retire()
        self.assertEqual(self.h.effects,self.effects_before)

    def test_backup_artifact_or_later_command_cannot_be_carried(self):
        ref=self.old.journal['children']['verify-backup'];path=self.old.directory/ref['file'];original=path.read_bytes()
        for key,value in (('backupReceipt',{'started':True}),('evidence',{'started':True}),('commands',{'verify-backup':{}})):
            stage=json.loads(original);stage[key]=value;stage.pop('canonicalSha256');stage['canonicalSha256']=sha(stage)
            path.write_text(json.dumps(stage))
            with self.assertRaises(BootstrapStopped):self.make_recovery()
        path.write_bytes(original)


class ReviewRecoveryImplementationTests(unittest.TestCase):
    def setUp(self):
        import subprocess
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.directory_path=Path(self.directory.name).resolve();self.root=self.directory_path/'repair'
        source=Path(__file__).resolve().parents[1]
        def git(*args,cwd=None):
            return subprocess.check_output(['git',*args],cwd=cwd or self.root,text=True,stderr=subprocess.PIPE).strip()
        self.git=git;git('clone','--shared','--quiet',str(source),str(self.root),cwd=self.directory_path)
        git('remote','set-url','origin','https://github.com/GiraeffleAeffle/roebel-staging-operations.git')
        self.plan,self.evidence=fixture()
        base=git('rev-parse','HEAD')
        self.plan['pins'].update(operationsRevision=base,implementationSha256=sha(git('ls-tree','-r','HEAD')))
        self.plan['planSha256']=sha({k:v for k,v in self.plan.items() if k!='planSha256'})
        for name in ('case_review_storage.py','case_review_handover.py','test_case_review_handover.py'):
            path=self.root/'scripts'/name
            # On a committed CI checkout the current code is already present;
            # a comment produces the same three-path implementation boundary.
            path.write_bytes((source/'scripts'/name).read_bytes()+b'\n# Synthetic recovery revision fixture.\n')
        git('add','scripts');git('-c','user.name=Synthetic Test','-c','user.email=test@example.invalid','commit','--quiet','-m','Synthetic recovery implementation')
        self.binding={'schemaVersion':'roebel_review_default_account_recovery_v1','planSha256':self.plan['planSha256'],
            'originalRevision':base,'revision':git('rev-parse','HEAD'),'implementationSha256':sha(git('ls-tree','-r','HEAD')),
            'parentJournalSha256':sha('stopped journal')}
    def verify(self):
        review.verify_review_implementation(self.root,self.plan,recovery_implementation=self.binding)
    def test_separate_exact_execution_binding_preserves_the_original_plan(self):
        original=copy.deepcopy(self.plan);self.verify();self.assertEqual(self.plan,original)
        with self.assertRaises(BootstrapStopped):review.verify_review_implementation(self.root,self.plan)
        self.binding['implementationSha256']=sha('different implementation')
        with self.assertRaises(BootstrapStopped):self.verify()
    def test_unrelated_committed_change_and_dirty_checkout_are_rejected(self):
        path=self.root/'README.md';path.write_text(path.read_text()+'\nUnexpected\n')
        with self.assertRaises(BootstrapStopped):self.verify()
        self.git('add','README.md');self.git('-c','user.name=Synthetic Test','-c','user.email=test@example.invalid','commit','--quiet','-m','Unexpected change')
        self.binding.update(revision=self.git('rev-parse','HEAD'),implementationSha256=sha(self.git('ls-tree','-r','HEAD')))
        with self.assertRaises(BootstrapStopped):self.verify()
    def test_successor_keeps_the_repair_and_changes_only_the_runtime_render(self):
        target=self.directory_path/'successor';self.git('clone','--shared','--quiet',str(self.root),str(target))
        self.git('remote','set-url','origin','https://github.com/GiraeffleAeffle/roebel-staging-operations.git',cwd=target)
        resources=json.loads((self.root/'proposals/synthetic-case-review-migration/review-resources.json').read_text())
        self.plan['pins']['targetRenderSha256']=sha(resources)
        self.plan['planSha256']=sha({k:v for k,v in self.plan.items() if k!='planSha256'});self.binding['planSha256']=self.plan['planSha256']
        path='reviewed-render/roebel-staging/case-runtime/resources.json'
        def commit_render():
            (target/path).write_text(json.dumps(resources)+'\n');self.git('add',path,cwd=target)
            self.git('-c','user.name=Synthetic Test','-c','user.email=test@example.invalid','commit','--quiet','-m','Synthetic exact successor',cwd=target)
            return self.git('rev-parse','HEAD',cwd=target)
        def verify(revision):review.verify_review_gitops_checkout(self.root,self.plan,{'resources':resources},target_checkout=target,
            expected_target_revision=revision,recovery_implementation=self.binding)
        verify(commit_render())
        self.git('checkout','--quiet','--detach',self.binding['originalRevision'],cwd=target)
        with self.assertRaises(BootstrapStopped):verify(commit_render())
    def test_journal_lineage_requires_the_original_stopped_worker_intent(self):
        directory=self.directory_path/'receipts';directory.mkdir(mode=0o700)
        parent={'schemaVersion':'roebel_review_handover_receipt_v1','planSha256':self.plan['planSha256'],
            'operationId':self.plan['operationId'],'previousReceiptSha256':None,'status':'stopped-preserve-state',
            'completed':[{'step':s,'evidence':self.evidence[s]} for s in review.STEPS[:2]],'pending':'verify-backup'}
        parent_name='a'*32+'-checkpoint.json';ReceiptSink.reserve(directory/parent_name).commit(parent)
        anchor={'schemaVersion':'roebel_review_driver_v1','planSha256':self.plan['planSha256'],'artifactDirectory':str(directory),
            'previousReceiptSha256':None,'parent':{'file':parent_name,'prior':None,'parentIntent':None},
            'children':dict.fromkeys(('fence','initializer','worker-create'),{})}
        ReceiptSink.reserve(directory/('b'*32+'-driver.json')).commit(anchor)
        anchor=json.loads((directory/('b'*32+'-driver.json')).read_text())
        self.binding['parentJournalSha256']=anchor['canonicalSha256']
        latest=copy.deepcopy(anchor);latest.pop('canonicalSha256');latest['previousReceiptSha256']=anchor['canonicalSha256']
        ReceiptSink.reserve(directory/('c'*32+'-driver.json')).commit(latest)
        latest=json.loads((directory/('c'*32+'-driver.json')).read_text())
        ReceiptSink.reserve(directory/('d'*32+'-driver.json'))
        def verify():review.verify_review_recovery_lineage(self.plan,self.binding,latest,latest['canonicalSha256'],directory)
        verify()
        with self.assertRaises(BootstrapStopped):review.verify_review_recovery_lineage(self.plan,self.binding,None,None,directory)
        (directory/('b'*32+'-driver.json')).unlink()
        with self.assertRaises(BootstrapStopped):verify()
