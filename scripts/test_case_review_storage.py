"""Exercise the storage transaction through its real durable receipt interface."""
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from . import case_review_storage as storage
from .case_runtime_bootstrap import BootstrapStopped, CreateConflict
from .staging_participant_flux_bootstrap import ReceiptSink, canonical_sha256

ROOT = Path(__file__).resolve().parent.parent
CLAIM_UID = '00000000-0000-4000-8000-000000000001'
VOLUME_UID = '00000000-0000-4000-8000-000000000002'


class Kubernetes:
    def __init__(self, plan, receipt):
        self.plan, self.receipt = plan, receipt
        self.calls = []
        self.pending = False
        self.fault = None
        self.target = None
        self.volume = None
        self.source = copy.deepcopy(plan['target'])
        self.source['metadata'].update(name=plan['source']['pvcName'], uid=plan['source']['pvcUid'], resourceVersion='1')
        self.source['spec']['volumeName'] = plan['source']['pvName']
        self.source['status'] = {'phase': 'Bound'}

    def bind(self):
        self.target['status'] = {'phase': 'Bound'}
        self.target['spec']['volumeName'] = 'pvc-review-fixture'
        self.volume = {'apiVersion': 'v1', 'kind': 'PersistentVolume',
                       'metadata': {'name': 'pvc-review-fixture', 'uid': VOLUME_UID, 'resourceVersion': '2'},
                       'spec': {'claimRef': {'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim', 'namespace': self.plan['source']['pvcNamespace'],
                                             'name': storage.TARGET_NAME, 'uid': CLAIM_UID},
                                'storageClassName': 'hcloud-volumes', 'volumeMode': 'Filesystem', 'accessModes': ['ReadWriteOncePod'],
                                'capacity': {'storage': '10Gi'}, 'csi': {'driver': 'csi.hetzner.cloud', 'fsType': 'ext4', 'volumeHandle': 'fixture-volume'},
                                'persistentVolumeReclaimPolicy': 'Delete'}, 'status': {'phase': 'Bound'}}

    def request(self, method, path, payload):
        self.calls.append((method, path, copy.deepcopy(payload)))
        if method == 'GET':
            if path.endswith('/' + self.plan['source']['pvcName']):
                return copy.deepcopy(self.source)
            if path.endswith('/' + storage.TARGET_NAME):
                return copy.deepcopy(self.target)
            if path == '/api/v1/persistentvolumes/pvc-review-fixture':
                return copy.deepcopy(self.volume)
            raise AssertionError('unexpected read')
        durable = json.loads(self.receipt.read_text())
        if method == 'POST':
            assert durable['status'] == 'create-intent', 'creation preceded durable intent'
            assert payload == self.plan['target'] and self.target is None
            if self.fault == 'conflict':
                raise CreateConflict('untrusted server details')
            if self.fault == 'missing-create':
                raise TimeoutError('untrusted server details')
            self.target = copy.deepcopy(payload)
            self.target['metadata'].update(uid=CLAIM_UID, resourceVersion='1')
            self.target['status'] = {'phase': 'Pending'}
            if not self.pending:
                self.bind()
            if self.fault == 'lost-create':
                raise TimeoutError('untrusted server details')
            return copy.deepcopy(self.target)
        if method == 'PATCH':
            assert durable['status'] == 'retain-intent', 'patch preceded durable intent'
            assert path == '/api/v1/persistentvolumes/pvc-review-fixture'
            if self.fault == 'patch-conflict':
                self.volume['metadata']['resourceVersion'] = '3'
            for operation in payload:
                section, key = operation['path'].strip('/').split('/')
                if operation['op'] == 'test':
                    if self.volume[section][key] != operation['value']:
                        raise CreateConflict('JSON Patch test failed')
                else:
                    assert operation == {'op': 'replace', 'path': '/spec/persistentVolumeReclaimPolicy', 'value': 'Retain'}
                    self.volume[section][key] = operation['value']
            if self.fault == 'lost-patch':
                raise TimeoutError('untrusted server details')
            return copy.deepcopy(self.volume)
        raise AssertionError('unexpected verb')


class ReviewStorageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.plan = storage.build_plan(ROOT, 'a' * 64)
        self.sink = ReceiptSink.reserve(self.root / 'first.json')
        self.api = Kubernetes(self.plan, self.sink.path)

    def advance(self, prior=None, sink=None, pin=None):
        sink = sink or self.sink
        self.api.receipt = sink.path
        return storage.advance_storage(self.plan, expected_plan_sha256=self.plan['planSha256'], transport=self.api, sink=sink,
                                       prior=prior, expected_prior_sha256=pin if pin is not None else prior and prior['canonicalSha256'])

    def saved(self):
        return json.loads(self.api.receipt.read_text())

    def resume(self):
        prior = self.saved()
        return self.advance(prior, ReceiptSink.reserve(self.root / 'resume.json'))

    def test_fresh_volume_is_retained_with_identity_guarded_patch_and_unchanged_source(self):
        source = copy.deepcopy(self.api.source)
        result = self.advance()
        self.assertEqual(result['status'], 'retained')
        self.assertEqual(result['volumeUid'], VOLUME_UID)
        self.assertEqual(result, self.saved())
        self.assertEqual(self.api.source, source)
        writes = [c for c in self.api.calls if c[0] != 'GET']
        self.assertEqual([c[0] for c in writes], ['POST', 'PATCH'])
        self.assertNotIn(self.plan['source']['pvName'], writes[1][1])
        self.assertEqual(writes[1][2][0], {'op': 'test', 'path': '/metadata/uid', 'value': VOLUME_UID})
        self.assertEqual(writes[1][2][1]['path'], '/metadata/resourceVersion')

    def test_pending_binding_resumes_without_recreating_the_claim(self):
        self.api.pending = True
        first = self.advance()
        self.assertEqual(first['status'], 'awaiting-binding')
        self.api.bind()
        result = self.resume()
        self.assertEqual(result['previousReceiptSha256'], first['canonicalSha256'])
        self.assertEqual(result['status'], 'retained')
        self.assertEqual(sum(c[0] == 'POST' for c in self.api.calls), 1)

    def test_lost_create_or_retention_response_is_resolved_without_duplicate_write(self):
        for fault in ('lost-create', 'lost-patch'):
            with self.subTest(fault=fault):
                self.setUp()
                self.api.fault = fault
                self.assertEqual(self.advance()['status'], 'retained')
                self.assertEqual(sum(c[0] == 'POST' for c in self.api.calls), 1)
                self.assertEqual(sum(c[0] == 'PATCH' for c in self.api.calls), 1)

    def test_unresolved_create_is_never_repeated_and_conflict_is_terminal(self):
        for fault, status in (('missing-create', 'create-intent'), ('conflict', 'conflict')):
            with self.subTest(fault=fault):
                self.setUp(); self.api.fault = fault
                with self.assertRaises(BootstrapStopped): self.advance()
                self.assertEqual(self.saved()['status'], status)
                with self.assertRaises(BootstrapStopped): self.resume()
                self.assertEqual(sum(c[0] == 'POST' for c in self.api.calls), 1)

    def test_foreign_existing_claim_and_changed_source_are_rejected_before_write(self):
        for fault in ('existing', 'source'):
            with self.subTest(fault=fault):
                self.setUp()
                if fault == 'existing': self.api.target = copy.deepcopy(self.api.source)
                else: self.api.source['metadata']['uid'] = CLAIM_UID
                with self.assertRaises(BootstrapStopped): self.advance()
                self.assertFalse(any(c[0] != 'GET' for c in self.api.calls))

    def test_wrong_volume_binding_or_source_volume_reuse_never_gets_a_patch(self):
        for fault in ('claim-uid', 'source-volume', 'csi', 'capacity'):
            with self.subTest(fault=fault):
                self.setUp(); self.api.pending = True; self.advance(); self.api.bind()
                if fault == 'claim-uid': self.api.volume['spec']['claimRef']['uid'] = 'ffffffff-ffff-4fff-8fff-ffffffffffff'
                if fault == 'source-volume': self.api.target['spec']['volumeName'] = self.plan['source']['pvName']
                if fault == 'csi': self.api.volume['spec']['csi']['driver'] = 'other-driver'
                if fault == 'capacity': self.api.volume['spec']['capacity']['storage'] = '1Gi'
                with self.assertRaises(BootstrapStopped): self.resume()
                self.assertFalse(any(c[0] == 'PATCH' for c in self.api.calls))

    def test_patch_conflict_retains_intent_and_can_resume_at_the_same_volume(self):
        self.api.fault = 'patch-conflict'
        with self.assertRaises(BootstrapStopped): self.advance()
        self.assertEqual(self.saved()['status'], 'retain-intent')
        self.assertEqual(self.api.volume['spec']['persistentVolumeReclaimPolicy'], 'Delete')
        self.api.fault = None
        self.assertEqual(self.resume()['status'], 'retained')
        self.assertEqual(sum(c[0] == 'POST' for c in self.api.calls), 1)

    def test_completed_receipt_reobserves_identity_and_does_not_repair_drift(self):
        first = self.advance()
        writes = sum(c[0] != 'GET' for c in self.api.calls)
        self.assertEqual(self.resume()['status'], 'retained')
        self.assertEqual(sum(c[0] != 'GET' for c in self.api.calls), writes)
        self.api.volume['spec']['persistentVolumeReclaimPolicy'] = 'Delete'
        with self.assertRaises(BootstrapStopped):
            self.advance(first, ReceiptSink.reserve(self.root / 'drift.json'))
        self.assertEqual(sum(c[0] != 'GET' for c in self.api.calls), writes)

    def test_changed_plan_or_recovery_pin_stops_before_transport(self):
        first = self.advance(); self.api.calls.clear()
        with self.assertRaises(BootstrapStopped):
            self.advance(first, ReceiptSink.reserve(self.root / 'wrong-pin.json'), pin='sha256:' + '0' * 64)
        self.assertEqual(self.api.calls, [])
        self.plan['target']['spec']['resources']['requests']['storage'] = '100Gi'
        body = dict(self.plan); body.pop('planSha256'); self.plan['planSha256'] = canonical_sha256(body)
        with self.assertRaises(BootstrapStopped): self.advance()
        self.assertEqual(self.api.calls, [])

    def test_failure_to_persist_intent_prevents_creation(self):
        class BrokenSink:
            def commit(self, value): raise OSError('private receipt disk failure')
        with self.assertRaisesRegex(BootstrapStopped, '^review storage stopped; retain the target and private receipts$'):
            self.advance(sink=type('Sink', (), {'path': self.sink.path, 'commit': BrokenSink().commit})())
        self.assertFalse(any(c[0] != 'GET' for c in self.api.calls))

    def command_transport(self):
        api = self.api
        commands = []
        class Runner:
            def run(self, args, *, timeout, input_text=None):
                commands.append(copy.deepcopy(args))
                assert args[:4] == ['kubectl', '--kubeconfig', '/private/bound-kubeconfig', '--request-timeout=20s']
                assert timeout == 25
                command = args[4:]
                if command[:2] == ['get', '--raw']:
                    value = api.request('GET', command[2], None)
                elif command[:2] == ['create', '--raw']:
                    assert command[3:] == ['-f', '-']
                    value = api.request('POST', command[2], json.loads(input_text))
                elif command[:2] == ['patch', 'persistentvolume']:
                    assert command[3:5] == ['--type=json', '-p'] and command[6:] == ['-o', 'json']
                    value = api.request('PATCH', '/api/v1/persistentvolumes/' + command[2], json.loads(command[5]))
                else:
                    raise AssertionError('unexpected kubectl command')
                return SimpleNamespace(code=0, out=json.dumps(value), err='') if value is not None else SimpleNamespace(code=1, out='', err='Error from server (NotFound): fixture')
        transport = storage.KubectlStorageTransport(Runner(), SimpleNamespace(path='/private/bound-kubeconfig'), self.plan, self.plan['planSha256'])
        return transport, commands

    def test_real_transport_completes_transaction_using_only_the_bound_commands(self):
        transport, commands = self.command_transport()
        result = storage.advance_storage(self.plan, expected_plan_sha256=self.plan['planSha256'], transport=transport, sink=self.sink)
        self.assertEqual(result['status'], 'retained')
        self.assertEqual(sum(command[4] == 'create' for command in commands), 1)
        self.assertEqual(sum(command[4] == 'patch' for command in commands), 1)

    def test_transport_refuses_unobserved_volume_secrets_deletion_and_changed_claim(self):
        transport, commands = self.command_transport()
        attempts = [('GET', '/api/v1/secrets', None), ('GET', '/api/v1/persistentvolumes/arbitrary', None),
                    ('DELETE', transport.target_path, None), ('PATCH', '/api/v1/persistentvolumes/arbitrary', []),
                    ('POST', transport.collection, {**self.plan['target'], 'spec': {}})]
        for method, path, body in attempts:
            with self.subTest(method=method, path=path), self.assertRaises(BootstrapStopped):
                transport.request(method, path, body)
        self.assertEqual(commands, [])


if __name__ == '__main__':
    unittest.main()
