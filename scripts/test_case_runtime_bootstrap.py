"""Fault rehearsal for the draft coordinator; no live Kubernetes adapter."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import io
import tempfile
import unittest

from . import case_runtime_bootstrap as bootstrap
from .staging_participant_flux_bootstrap import ReceiptSink


class Adapter:
    def __init__(self, sink):
        self.sink = sink
        self.objects = {}
        self.calls = []
        self.fault = None
        self.fail_at = None

    def key(self, obj):
        return json.dumps(obj, sort_keys=True)

    def verify_preconditions(self, plan):
        self.calls.append('preconditions')
        if self.fault == 'preflight':
            raise ValueError('private token must never enter the receipt')

    def get(self, target):
        return copy.deepcopy(self.objects.get(self.key(target)))

    def create(self, desired):
        receipt = json.loads(self.sink.path.read_text())
        intent = receipt['objects'][-1]
        assert intent['state'] == 'create-intent'
        assert intent['target'] == bootstrap.target(desired)
        assert intent['desiredSha256'] == bootstrap.canonical_sha256(desired)
        index = len([c for c in self.calls if isinstance(c, tuple)])
        self.calls.append(('create', bootstrap.target(desired)))
        fault = self.fault if self.fail_at in (None, index) else None
        if fault == 'conflict':
            raise bootstrap.CreateConflict('409')
        if fault == 'absent-timeout':
            raise TimeoutError('sensitive server error')
        observed = copy.deepcopy(desired)
        observed['metadata'].update(uid=f'uid-{index}', resourceVersion=str(index+1))
        if fault == 'foreign-timeout':
            observed['metadata']['annotations'][bootstrap.NONCE] = 'foreign'
        self.objects[self.key(bootstrap.target(desired))] = observed
        if fault in ('timeout', 'foreign-timeout'):
            raise TimeoutError('sensitive server error')
        return copy.deepcopy(observed)

    def require_exact(self, observed, desired):
        actual = copy.deepcopy(observed)
        actual['metadata'].pop('uid', None)
        actual['metadata'].pop('resourceVersion', None)
        if actual != desired:
            raise ValueError('semantic mismatch')

    def verify_control_restart(self, owned, plan):
        self.calls.append('control-restart')
        assert owned['uid'] and owned['state'] == 'created'
        if self.fault == 'restart':
            raise ValueError('private runtime error')
        return {'podUid':'fixture-control','beforeContainerId':'before','afterContainerId':'after','exitCode':0,'restartCount':1}

    def verify_public(self, owned, plan):
        self.calls.append('public-replay')
        assert owned['uid'] and owned['state'] == 'created'
        if self.fault == 'public':
            raise ValueError('private runtime error')
        if self.fault == 'replace-uid':
            first = next(iter(self.objects.values()))
            first['metadata']['uid'] = 'replacement'
        return {'podUid':'fixture-public','imageId':'fixture-image'}


class CaseBootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admitted = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.admitted.cleanup)
        cls.root = Path(cls.admitted.name)
        # Complete prospective protected tree; candidate policy is never loaded
        # by the verifier. Security tests mutate independent copied data roots.
        shutil.copytree(Path(__file__).resolve().parents[1],cls.root,dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns('.git','__pycache__','*.pyc'))

    def environment(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        sink = ReceiptSink.reserve(Path(temporary.name)/'receipt.json')
        adapter = Adapter(sink)
        return sink, adapter

    def run_case(self, sink, adapter):
        return bootstrap.run_bootstrap(self.root, adapter=adapter, sink=sink)

    def test_complete_order_and_durable_intent_for_every_create(self):
        sink, adapter = self.environment()
        result = self.run_case(sink, adapter)
        self.assertEqual(len(result['objects']), 19)
        self.assertEqual(len({r['uid'] for r in result['objects']}), 19)
        self.assertEqual(result['status'], 'bootstrap-verified-flux-suspended')
        self.assertTrue(result['fluxSuspended'])
        self.assertFalse(result['caseAdmitted'])
        self.assertFalse(result['webConnected'])
        creates = [c[1] for c in adapter.calls if isinstance(c, tuple)]
        self.assertTrue(all(o['kind'] != 'Deployment' for o in creates[:13]))
        self.assertEqual(creates[13]['name'], 'roebel-case-steward-control')
        self.assertEqual(creates[14]['name'], 'roebel-case-public-binding')
        restart = adapter.calls.index('control-restart')
        public = adapter.calls.index(('create', creates[14]))
        self.assertLess(restart, public)
        self.assertTrue(all(o['kind'] not in {'Secret','PersistentVolumeClaim','PersistentVolume'} for o in creates))
        self.assertTrue(all(o['spec']['suspend'] for o in adapter.objects.values() if o['kind']=='Kustomization'))

    def test_owned_timeout_is_discovered_without_resending_at_every_boundary(self):
        for boundary in range(19):
            with self.subTest(boundary=boundary):
                sink, adapter = self.environment()
                adapter.fault, adapter.fail_at = 'timeout', boundary
                self.run_case(sink, adapter)
                self.assertEqual(len([c for c in adapter.calls if isinstance(c, tuple)]), 19)

    def test_unresolved_create_preserves_intent_and_never_progresses(self):
        for fault in ('conflict','absent-timeout','foreign-timeout'):
            for boundary in range(19):
                with self.subTest(fault=fault, boundary=boundary):
                    sink, adapter = self.environment()
                    adapter.fault, adapter.fail_at = fault, boundary
                    with self.assertRaises(bootstrap.BootstrapStopped): self.run_case(sink, adapter)
                    receipt = json.loads(sink.path.read_text())
                    self.assertEqual(receipt['status'], 'stopped-preserve-owned-objects')
                    self.assertIsNone(receipt['objects'][-1]['uid'])
                    self.assertEqual(len([c for c in adapter.calls if isinstance(c, tuple)]), boundary+1)
                    self.assertGreaterEqual(len(adapter.objects), boundary)
                    self.assertNotIn('sensitive', sink.path.read_text())

    def test_preexisting_target_is_not_adopted(self):
        sink, adapter = self.environment()
        target = bootstrap.build_plan(self.root)['objects'][-1]['target']
        adapter.objects[adapter.key(target)] = {'foreign': True}
        with self.assertRaises(bootstrap.BootstrapStopped): self.run_case(sink, adapter)
        self.assertFalse(any(isinstance(c, tuple) for c in adapter.calls))
        self.assertEqual(adapter.objects[adapter.key(target)], {'foreign': True})

    def test_failed_health_or_preservation_stops_later_phases_and_redacts(self):
        for fault, count in [('preflight',0), ('restart',14), ('public',15), ('replace-uid',19)]:
            with self.subTest(fault=fault):
                sink, adapter = self.environment(); adapter.fault = fault
                with self.assertRaisesRegex(bootstrap.BootstrapStopped, 'preserve objects'):
                    self.run_case(sink, adapter)
                self.assertEqual(len([c for c in adapter.calls if isinstance(c, tuple)]), count)
                self.assertNotIn('private runtime error', sink.path.read_text())
                self.assertNotIn('private token must never enter the receipt', sink.path.read_text())

    def test_receipt_failure_prevents_unsaved_create(self):
        sink, adapter = self.environment()
        commit = sink.commit
        def fail_on_intent(value):
            if value['objects'] and value['objects'][-1]['state'] == 'create-intent':
                raise OSError('disk full')
            commit(value)
        sink.commit = fail_on_intent
        with self.assertRaises(bootstrap.BootstrapStopped): self.run_case(sink, adapter)
        self.assertFalse(any(isinstance(c, tuple) for c in adapter.calls))

    def test_failed_receipt_after_create_retains_pre_send_intent_and_stops(self):
        sink, adapter = self.environment()
        commit = sink.commit
        def fail_after_create(value):
            if value['objects'] and value['objects'][-1]['state'] == 'created':
                raise OSError('disk full')
            commit(value)
        sink.commit = fail_after_create
        with self.assertRaises(bootstrap.BootstrapStopped): self.run_case(sink, adapter)
        self.assertEqual(len(adapter.objects), 1)
        receipt = json.loads(sink.path.read_text())
        self.assertEqual(receipt['objects'][0]['state'], 'create-intent')
        self.assertIsNone(receipt['objects'][0]['uid'])
        self.assertEqual(receipt['nonce'], next(iter(adapter.objects.values()))['metadata']['annotations'][bootstrap.NONCE])

    def test_semantic_drift_is_not_accepted(self):
        sink, adapter = self.environment()
        create = adapter.create
        def changed_create(desired):
            observed = create(desired)
            observed['unexpected'] = True
            return observed
        adapter.create = changed_create
        with self.assertRaises(bootstrap.BootstrapStopped): self.run_case(sink, adapter)
        self.assertEqual(len(adapter.objects), 1)
        self.assertIsNone(json.loads(sink.path.read_text())['objects'][-1]['uid'])

    def test_resume_adopts_only_durable_owned_prefix_without_duplicate_creates(self):
        for boundary in (0,13,14,18):
            with self.subTest(boundary=boundary):
                sink, adapter = self.environment()
                adapter.fault, adapter.fail_at = 'timeout', boundary
                original_commit=sink.commit
                def fail_after_owned(value):
                    if len(value['objects'])==boundary+1 and value['objects'][-1]['state']=='created':
                        raise OSError('receipt unavailable')
                    original_commit(value)
                sink.commit=fail_after_owned
                with self.assertRaises(bootstrap.BootstrapStopped):self.run_case(sink,adapter)
                prior=json.loads(sink.path.read_text())
                next_sink,_=self.environment();adapter.sink=next_sink
                adapter.fault=None
                result=bootstrap.run_bootstrap(self.root,adapter=adapter,sink=next_sink,prior_receipt=prior)
                self.assertEqual(len([c for c in adapter.calls if isinstance(c,tuple)]),19)
                self.assertEqual(result['status'],'bootstrap-verified-flux-suspended')

    def test_recovery_rejects_tampering_replacement_and_missing_uncertain_object(self):
        for fault in ('tamper','replacement','absent'):
            with self.subTest(fault=fault):
                sink, adapter=self.environment();adapter.fault='restart'
                with self.assertRaises(bootstrap.BootstrapStopped):self.run_case(sink,adapter)
                prior=json.loads(sink.path.read_text())
                if fault=='tamper':prior['planSha256']='sha256:'+'0'*64
                elif fault=='replacement':next(iter(adapter.objects.values()))['metadata']['uid']='other'
                else:
                    adapter.objects.pop(next(iter(adapter.objects)))
                next_sink,_=self.environment();adapter.sink=next_sink;adapter.fault=None
                before=len([c for c in adapter.calls if isinstance(c,tuple)])
                with self.assertRaises(bootstrap.BootstrapStopped):bootstrap.run_bootstrap(self.root,adapter=adapter,sink=next_sink,prior_receipt=prior)
                self.assertEqual(len([c for c in adapter.calls if isinstance(c,tuple)]),before)

    def test_protected_admission_rejects_runtime_render_or_candidate_code_changes(self):
        verifier=bootstrap._verifier()
        for path in ('reviewed-render/roebel-staging/case-runtime/resources.json','scripts/case_runtime_kubernetes.py'):
            with self.subTest(path=path), tempfile.TemporaryDirectory() as temporary:
                candidate=Path(temporary)
                shutil.copytree(self.root,candidate,dirs_exist_ok=True)
                changed=candidate/path
                if path.endswith('resources.json'):
                    changed.write_bytes(changed.read_bytes().replace(b'0c074f77',b'1c074f77'))
                    with self.assertRaises(verifier.VerificationError):verifier.verify_tree(candidate)
                else:
                    changed.write_text("raise RuntimeError('candidate code must never execute')")
                    with self.assertRaisesRegex(verifier.VerificationError,'protected Case bootstrap'):
                        verifier.verify_transition(verifier.verify_tree(candidate),verifier.verify_tree(self.root))

    def test_web_connection_transition_is_exact_and_rejects_extra_changes(self):
        verifier=bootstrap._verifier()
        base=verifier.verify_tree(self.root)
        with tempfile.TemporaryDirectory() as temporary:
            candidate=Path(temporary);shutil.copytree(self.root,candidate,dirs_exist_ok=True)
            enable_web(candidate,verifier)
            verifier.verify_transition(verifier.verify_tree(candidate),base)
            deployment=candidate/verifier.RENDER_ROOT/'web/deployment.json'
            record=json.loads(deployment.read_text())
            record['spec']['template']['spec']['containers'][0]['env'][-1]['value']='http://unreviewed.invalid'
            deployment.write_text(json.dumps(record))
            with self.assertRaises(verifier.VerificationError):verifier.verify_tree(candidate)

    def test_restart_of_coordinator_never_blindly_replays_prior_creates(self):
        sink, adapter = self.environment(); adapter.fault = 'restart'
        with self.assertRaises(bootstrap.BootstrapStopped): self.run_case(sink, adapter)
        prior = len(adapter.objects)
        other_sink, _ = self.environment()
        adapter.sink = other_sink; adapter.fault = None
        with self.assertRaises(bootstrap.BootstrapStopped): self.run_case(other_sink, adapter)
        self.assertEqual(len(adapter.objects), prior)


def enable_web(root,verifier):
    """Construct the exact credential-free Web successor as test/review data."""
    base=verifier.verify_tree(root)
    directory=root/verifier.RENDER_ROOT
    proposal=json.loads((root/'proposals/synthetic-case-runtime/web-connection.json').read_text())
    web=copy.deepcopy(base['deployments']['roebel-web-staging'])
    web['spec']['template']['spec']['containers'][0]['env'].append(proposal['environmentAddition'])
    network=json.loads((directory/'web/networkpolicy.json').read_text())
    network['spec']['egress'].append(proposal['egressAddition'])
    def write(path,value):(directory/path).write_text(json.dumps(value,indent=2)+'\n')
    write('web/deployment.json',web);write('web/networkpolicy.json',network)
    boundary=copy.deepcopy(base['migration'])
    for obj in boundary['objects']:
        if obj['kind']=='NetworkPolicy' and obj['name']==proposal['networkPolicy'] and obj['namespace']==proposal['namespace']:obj['sha256']=verifier.digest(network)
    verifier.CASE_RUNTIME.extend_web_boundary(verifier,root,boundary)
    write('network-boundary-migration.json',boundary)
    objects=copy.deepcopy(base['objects']);objects[3]=web;objects[4]=network
    payload={'nextEnvironmentHead':base['head'],'objects':objects,'reviewedPublicKnowledge':base['reviewedPublicKnowledge'],
             'stagingParticipantGateway':{k:v for k,v in base['stagingParticipantGateway'].items() if k!='civicProjectionRoute'}}
    integrity=copy.deepcopy(base['integrity']);integrity['desiredRenderSha256']=verifier.digest(payload)
    integrity['networkBoundaryMigrationSha256']=verifier.digest(boundary)
    write('integrity.json',integrity)


if __name__ == '__main__':
    unittest.main()
