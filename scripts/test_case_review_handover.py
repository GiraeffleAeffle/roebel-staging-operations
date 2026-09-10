"""Recovery and destructive-order gates for the review handover coordinator."""
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from . import case_review_handover as review
from .case_runtime_bootstrap import BootstrapStopped
from .staging_participant_flux_bootstrap import ReceiptSink, canonical_sha256

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
        self.assertEqual(container['env'],[{'name':'TMPDIR','value':'/work/private'}])
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
