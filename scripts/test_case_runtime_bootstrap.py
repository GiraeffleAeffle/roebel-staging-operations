"""Fault rehearsal for the draft coordinator; no live Kubernetes adapter."""
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from scripts import case_runtime_bootstrap as bootstrap
from scripts.staging_participant_flux_bootstrap import ReceiptSink


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

    def verify_public(self, owned, plan):
        self.calls.append('public-replay')
        assert owned['uid'] and owned['state'] == 'created'
        if self.fault == 'public':
            raise ValueError('private runtime error')
        if self.fault == 'replace-uid':
            first = next(iter(self.objects.values()))
            first['metadata']['uid'] = 'replacement'


class CaseBootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admitted = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.admitted.cleanup)
        cls.root = Path(cls.admitted.name)
        # Exercise the admitted predecessor inventory, excluding only this
        # draft's two unadmitted files. Production must use a trusted checkout.
        shutil.copytree(Path(__file__).resolve().parents[1], cls.root, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns('.git', '__pycache__', '*.pyc',
                            'case_runtime_bootstrap.py', 'test_case_runtime_bootstrap.py'))

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

    def test_restart_of_coordinator_never_blindly_replays_prior_creates(self):
        sink, adapter = self.environment(); adapter.fault = 'restart'
        with self.assertRaises(bootstrap.BootstrapStopped): self.run_case(sink, adapter)
        prior = len(adapter.objects)
        other_sink, _ = self.environment()
        adapter.sink = other_sink; adapter.fault = None
        with self.assertRaises(bootstrap.BootstrapStopped): self.run_case(other_sink, adapter)
        self.assertEqual(len(adapter.objects), prior)


if __name__ == '__main__':
    unittest.main()
