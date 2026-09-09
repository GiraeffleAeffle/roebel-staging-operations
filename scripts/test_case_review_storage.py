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




class ConsumerKubernetes:
    def __init__(self, storage_api, plan, receipt):
        self.storage_api, self.plan, self.receipt = storage_api, plan, receipt
        self.objects, self.writes = {}, []
        self.fault = None
        self.sc = {'provisioner': 'csi.hetzner.cloud', 'volumeBindingMode': 'WaitForFirstConsumer', 'reclaimPolicy': 'Retain'}

    def request(self, method, path, payload):
        if '/persistentvolumeclaims/' in path:
            return self.storage_api.request(method, path, payload)
        if path.endswith('/storageclasses/hcloud-volumes'):
            assert method == 'GET' and payload is None
            return copy.deepcopy(self.sc)
        key = 'networkPolicy' if '/networkpolicies' in path else 'pod'
        assert path.endswith(('/networkpolicies', '/pods', '/' + storage.CONSUMER_NAME))
        if method == 'GET':
            return copy.deepcopy(self.objects.get(key))
        assert method == 'POST' and payload == self.plan[key]
        durable = json.loads(self.receipt.read_text())
        assert durable['status'] == ('policy-intent' if key == 'networkPolicy' else 'pod-intent')
        assert key not in self.objects
        self.writes.append(key)
        if self.fault == 'conflict-' + key:
            raise CreateConflict('untrusted conflict body')
        if self.fault == 'missing-' + key:
            raise TimeoutError('untrusted timeout')
        obj = copy.deepcopy(payload)
        obj['metadata'].update(uid='00000000-0000-4000-8000-00000000000' + ('3' if key == 'networkPolicy' else '4'), resourceVersion='1')
        if key == 'pod':
            obj['status'] = {'phase': 'Pending'}
        self.objects[key] = obj
        if self.fault == 'lost-' + key:
            raise TimeoutError('untrusted timeout')
        return copy.deepcopy(obj)

    def complete(self):
        self.storage_api.bind()
        self.storage_api.volume['spec']['persistentVolumeReclaimPolicy'] = 'Retain'
        self.objects['pod']['spec']['nodeName'] = 'fixture-node'
        self.objects['pod']['status'] = {'phase': 'Succeeded', 'containerStatuses': [
            {'name': 'check', 'restartCount': 0, 'imageID': storage.CONSUMER_IMAGE,
             'state': {'terminated': {'exitCode': 0}}}]}


class BindingConsumerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.storage_plan = storage.build_plan(ROOT, 'b' * 64)
        initial = ReceiptSink.reserve(self.root / 'storage.json')
        self.storage_api = Kubernetes(self.storage_plan, initial.path); self.storage_api.pending = True
        self.owned = storage.advance_storage(self.storage_plan, expected_plan_sha256=self.storage_plan['planSha256'],
                                             transport=self.storage_api, sink=initial)
        self.plan = storage.build_consumer_plan(self.storage_plan)
        self.sink = ReceiptSink.reserve(self.root / 'consumer.json')
        self.api = ConsumerKubernetes(self.storage_api, self.plan, self.sink.path)

    def advance(self, prior=None, sink=None, transport=None):
        sink = sink or self.sink; self.api.receipt = sink.path
        return storage.advance_consumer(self.plan, self.storage_plan, expected_plan_sha256=self.plan['planSha256'],
            storage_receipt=self.owned, expected_storage_receipt_sha256=self.owned['canonicalSha256'],
            transport=transport or self.api, sink=sink, prior=prior, expected_prior_sha256=prior and prior['canonicalSha256'])

    def resume(self, name='resume.json'):
        prior = json.loads(self.api.receipt.read_text())
        return self.advance(prior, ReceiptSink.reserve(self.root / name))

    def test_pending_consumer_then_completed_check_and_separate_retention_receipt(self):
        source = copy.deepcopy(self.storage_api.source)
        first = self.advance()
        self.assertEqual(first['status'], 'awaiting-check')
        self.assertEqual(self.api.writes, ['networkPolicy', 'pod'])
        self.api.complete()
        complete = self.resume()
        self.assertEqual(complete['status'], 'verified')
        self.assertEqual(complete['previousReceiptSha256'], first['canonicalSha256'])
        replay = self.resume('replay.json')
        self.assertEqual(replay['status'], 'verified')
        self.assertEqual(self.api.writes, ['networkPolicy', 'pod'])
        retained = storage.advance_storage(self.storage_plan, expected_plan_sha256=self.storage_plan['planSha256'],
            transport=self.storage_api, sink=ReceiptSink.reserve(self.root / 'retained.json'), prior=self.owned,
            expected_prior_sha256=self.owned['canonicalSha256'])
        self.assertEqual(retained['status'], 'retained')
        self.assertEqual(self.storage_api.source, source)

    def test_lost_policy_and_pod_responses_observe_without_recreating(self):
        self.api.fault = 'lost-networkPolicy'
        self.assertEqual(self.advance()['status'], 'awaiting-check')
        self.assertEqual(self.api.writes, ['networkPolicy', 'pod'])
        # A separate operation exercises loss after Pod creation.
        self.setUp(); self.api.fault = 'lost-pod'
        self.assertEqual(self.advance()['status'], 'awaiting-check')
        self.assertEqual(self.api.writes, ['networkPolicy', 'pod'])

    def test_unknown_create_is_not_repeated_and_conflicts_are_terminal(self):
        for key in ('networkPolicy', 'pod'):
            for fault in ('missing-', 'conflict-'):
                with self.subTest(key=key, fault=fault):
                    self.setUp(); self.api.fault = fault + key
                    with self.assertRaises(BootstrapStopped): self.advance()
                    before = list(self.api.writes)
                    with self.assertRaises(BootstrapStopped): self.resume()
                    self.assertEqual(self.api.writes, before)

    def test_source_target_storage_class_and_pins_block_before_creation(self):
        for changed in ('source', 'target', 'class', 'receipt', 'plan', 'existing-pod'):
            with self.subTest(changed=changed):
                self.setUp()
                if changed == 'existing-pod': self.api.objects['pod'] = copy.deepcopy(self.plan['pod'])
                if changed == 'source': self.storage_api.source['metadata']['uid'] = CLAIM_UID
                if changed == 'target': self.storage_api.target['metadata']['uid'] = VOLUME_UID
                if changed == 'class': self.api.sc['reclaimPolicy'] = 'Delete'
                if changed == 'receipt': self.owned['claimUid'] = VOLUME_UID
                if changed == 'plan': self.plan['pod']['spec']['volumes'][0]['persistentVolumeClaim']['claimName'] = self.storage_plan['source']['pvcName']
                with self.assertRaises(BootstrapStopped): self.advance()
                self.assertEqual(self.api.writes, [])

    def test_server_defaults_allowed_but_injection_and_failed_completion_rejected(self):
        self.advance(); self.api.complete()
        desired = copy.deepcopy(self.api.objects['pod'])
        desired['spec'].update(serviceAccount='roebel-case-steward-control', dnsPolicy='ClusterFirst',
            schedulerName='default-scheduler', priority=0, preemptionPolicy='PreemptLowerPriority', imagePullSecrets=[])
        desired['spec']['containers'][0].update(terminationMessagePath='/dev/termination-log', terminationMessagePolicy='File')
        self.api.objects['pod'] = desired
        self.assertEqual(self.resume()['status'], 'verified')
        mutations = [lambda p: p['spec'].update(automountServiceAccountToken=True),
                     lambda p: p['spec'].update(hostNetwork=True),
                     lambda p: p['spec']['containers'].append({'name':'injected'}),
                     lambda p: p['spec']['volumes'].append({'name':'secret','secret':{'secretName':'private'}}),
                     lambda p: p['spec']['containers'][0]['volumeMounts'][0].update(readOnly=False),
                     lambda p: p['status']['containerStatuses'][0]['state']['terminated'].update(exitCode=1),
                     lambda p: p['status']['containerStatuses'][0].update(imageID='wrong-image'),
                     lambda p: p['metadata'].update(uid=CLAIM_UID)]
        for i, mutate in enumerate(mutations):
            self.api.objects['pod'] = copy.deepcopy(desired); mutate(self.api.objects['pod'])
            prior = json.loads((self.root / 'resume.json').read_text())
            with self.assertRaises(BootstrapStopped):
                self.advance(prior, ReceiptSink.reserve(self.root / f'reject-{i}.json'))
        self.assertEqual(self.api.writes, ['networkPolicy', 'pod'])

    def test_receipt_failure_prevents_every_create(self):
        class Broken:
            def commit(self, state): raise OSError('fixture disk failure')
        with self.assertRaises(OSError): self.advance(sink=SimpleNamespace(path=self.sink.path, commit=Broken().commit))
        self.assertEqual(self.api.writes, [])

    def test_real_command_adapter_and_forbidden_operations(self):
        api = self.api
        class Runner:
            def run(self, args, input_text=None, timeout=None):
                assert args[:4] == ['kubectl','--kubeconfig','/fixture/config','--request-timeout=20s']
                assert timeout == 25
                method = {'get':'GET', 'create':'POST'}[args[4]]
                assert args[5] == '--raw'
                value = api.request(method, args[6], json.loads(input_text) if input_text else None)
                if value is None:
                    return SimpleNamespace(code=1, out='', err='Error from server (NotFound): fixture')
                return SimpleNamespace(code=0, out=json.dumps(value), err='')
        transport = storage.KubectlConsumerTransport(Runner(), SimpleNamespace(path='/fixture/config'),
            self.plan, self.storage_plan, self.plan['planSha256'])
        self.assertEqual(self.advance(transport=transport)['status'], 'awaiting-check')
        for method, path, payload in [('DELETE','/api/v1/namespaces/x/pods/x',None),
                                      ('GET','/api/v1/secrets',None),
                                      ('PATCH',transport.storage.target_path,[]),
                                      ('POST',next(iter(transport.collections)),{'kind':'Pod'})]:
            with self.assertRaises(BootstrapStopped): transport.request(method,path,payload)


if __name__ == '__main__':
    unittest.main()
