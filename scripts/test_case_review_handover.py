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
