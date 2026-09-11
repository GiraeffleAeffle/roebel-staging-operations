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
        self.request={'schemaVersion':'roebel_case_review_migration_request_v1','sourceRevision':'fdb0b7f36c33d925be141d8e9037b48d17612df8','mode':'capture-backup','caseId':self.plan['caseId'],'sourceRootDir':'/var/lib/stadtstack/case-control',
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
