"""Retained target-volume provisioning for the review migration.

The storage operation creates one fresh PVC and can set its bound PV to Retain.
A separately pinned consumer operation creates a deny-all policy and one short
Pod that reads only the target filesystem. A separately pinned initializer
creates its exact new root and marker. None of these operations reads Secrets,
changes an existing workload or imports a Case. Callers supply independent plan
pins, bounded transports and pre-reserved private durable receipts.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path

from .case_runtime_bootstrap import BootstrapStopped, CreateConflict
from .staging_participant_flux_bootstrap import canonical_sha256

SOURCE_BINDING = 'sha256:f6a2fc46f0fda7722f2826d52c61cfb9bf5b3da9ca280670d105e5fe6acffcce'
TARGET_NAME = 'roebel-case-steward-review-state-v1'
OWNER = 'stadtstack.io/case-review-storage-operation'
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
SHA = re.compile(r'sha256:[0-9a-f]{64}')


def require(condition, reason):
    if not condition:
        raise BootstrapStopped(reason)


def build_plan(admitted_root: Path, operation_id: str) -> dict:
    """Compile one inert target plan from the protected original binding.

    operation_id is a fresh random 32-byte hex nonce reserved by Operations.
    The returned checksum identifies bytes; it is not deployment authorization.
    """
    require(isinstance(operation_id, str) and re.fullmatch('[0-9a-f]{64}', operation_id), 'storage operation nonce invalid')
    binding = json.loads((admitted_root / 'proposals/synthetic-case-runtime/control-binding.json').read_text())
    unsigned = dict(binding)
    require(unsigned.pop('bindingChecksum') == SOURCE_BINDING == canonical_sha256(unsigned), 'original storage binding changed')
    source = binding['storage']
    desired = {'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim',
               'metadata': {'namespace': source['pvcNamespace'], 'name': TARGET_NAME,
                            'labels': {'app.kubernetes.io/part-of': 'roebel-case-staging', 'stadtstack.io/authority': 'none'},
                            'annotations': {OWNER: operation_id}},
               'spec': {'accessModes': ['ReadWriteOncePod'], 'volumeMode': 'Filesystem',
                        'storageClassName': 'hcloud-volumes', 'resources': {'requests': {'storage': '10Gi'}}}}
    body = {'schemaVersion': 'roebel_case_review_storage_plan_v1', 'operationId': operation_id,
            'sourceBindingChecksum': SOURCE_BINDING,
            'source': {key: source[key] for key in ('pvcNamespace', 'pvcName', 'pvcUid', 'pvName')},
            'target': desired, 'requiredReclaimPolicy': 'Retain'}
    return {**body, 'planSha256': canonical_sha256(body)}


def _validate_plan(plan, expected_sha):
    require(isinstance(plan, dict) and set(plan) == {'schemaVersion', 'operationId', 'sourceBindingChecksum', 'source', 'target', 'requiredReclaimPolicy', 'planSha256'}, 'storage plan shape invalid')
    body = dict(plan); actual = body.pop('planSha256')
    require(isinstance(expected_sha, str) and SHA.fullmatch(expected_sha) and actual == expected_sha == canonical_sha256(body), 'storage plan pin mismatch')
    # All executable choices must also reproduce the fixed reviewed compiler.
    # Its input binding is part of this module's protected source checkout.
    require(plan == build_plan(Path(__file__).resolve().parent.parent, plan['operationId']), 'storage plan differs from reviewed operation')


def _identity(obj):
    metadata = obj.get('metadata', {})
    uid, version = metadata.get('uid'), metadata.get('resourceVersion')
    require(isinstance(uid, str) and UUID.fullmatch(uid) and isinstance(version, str) and version.isdigit(), 'storage object identity invalid')
    require(not metadata.get('deletionTimestamp'), 'storage object is terminating')
    return {'uid': uid, 'resourceVersion': version}


def _claim(obj, desired, *, owned):
    require(isinstance(obj, dict) and obj.get('apiVersion') == 'v1' and obj.get('kind') == 'PersistentVolumeClaim', 'storage claim missing')
    metadata = obj.get('metadata', {})
    require(all(metadata.get(key) == desired['metadata'][key] for key in ('namespace', 'name')), 'storage claim target mismatch')
    if owned:
        require(metadata.get('annotations', {}).get(OWNER) == desired['metadata']['annotations'][OWNER], 'storage create ownership unresolved')
        require(all(metadata.get('labels', {}).get(k) == v for k, v in desired['metadata']['labels'].items()), 'storage claim labels changed')
    spec = obj.get('spec', {})
    require(set(spec) <= set(desired['spec']) | {'volumeName'}, 'storage claim has unexpected options')
    require(all(spec.get(k) == v for k, v in desired['spec'].items()), 'storage claim spec changed')
    return _identity(obj)


def _source(plan, transport):
    ref = plan['source']
    source = transport.request('GET', f"/api/v1/namespaces/{ref['pvcNamespace']}/persistentvolumeclaims/{ref['pvcName']}", None)
    desired = copy.deepcopy(plan['target'])
    desired['metadata'].update(namespace=ref['pvcNamespace'], name=ref['pvcName'])
    observed = _claim(source, desired, owned=False)
    require(observed['uid'] == ref['pvcUid'] and source.get('status', {}).get('phase') == 'Bound' and source['spec'].get('volumeName') == ref['pvName'], 'original storage identity or binding changed')


def _volume(plan, claim, volume):
    require(isinstance(volume, dict) and volume.get('apiVersion') == 'v1' and volume.get('kind') == 'PersistentVolume', 'target volume missing')
    require(volume.get('metadata', {}).get('name') == claim['spec']['volumeName'], 'target volume name mismatch')
    identity = _identity(volume)
    spec = volume.get('spec', {})
    ref = spec.get('claimRef', {})
    require(ref.get('kind') == 'PersistentVolumeClaim' and ref.get('apiVersion') == 'v1' and
            ref.get('namespace') == plan['source']['pvcNamespace'] and ref.get('name') == TARGET_NAME and ref.get('uid') == claim['metadata']['uid'], 'target volume belongs to another claim')
    require(spec.get('storageClassName') == 'hcloud-volumes' and spec.get('volumeMode') == 'Filesystem' and
            spec.get('accessModes') == ['ReadWriteOncePod'] and spec.get('capacity') == {'storage': '10Gi'} and
            spec.get('csi', {}).get('driver') == 'csi.hetzner.cloud' and spec.get('csi', {}).get('fsType') == 'ext4' and
            isinstance(spec.get('csi', {}).get('volumeHandle'), str) and bool(spec['csi']['volumeHandle']) and
            spec.get('persistentVolumeReclaimPolicy') in ('Delete', 'Retain') and volume.get('status', {}).get('phase') == 'Bound', 'target volume class, capacity or state invalid')
    return identity


def advance_storage(plan, *, expected_plan_sha256, transport, sink, prior=None, expected_prior_sha256=None):
    """Advance once; Pending binding is a receipted state, not a busy wait.

    Recovery uses an independently pinned prior receipt and a NEW sink. A
    create-intent with no observed claim remains uncertain and never re-POSTs.
    Conflicts are terminal. Retention patches test UID, resourceVersion and the
    old policy. Every resume re-observes both claim bindings before any write.
    """
    plan = copy.deepcopy(plan)
    _validate_plan(plan, expected_plan_sha256)
    state = {'schemaVersion': 'roebel_case_review_storage_receipt_v1', 'planSha256': plan['planSha256'],
             'operationId': plan['operationId'], 'previousReceiptSha256': None,
             'status': 'reserved', 'claimUid': None, 'volumeName': None, 'volumeUid': None}
    if prior is not None:
        require(isinstance(prior, dict) and set(prior) == set(state) | {'canonicalSha256'}, 'storage recovery receipt shape invalid')
        unsigned = copy.deepcopy(prior); digest = unsigned.pop('canonicalSha256')
        require(isinstance(expected_prior_sha256, str) and SHA.fullmatch(expected_prior_sha256) and digest == expected_prior_sha256 == canonical_sha256(unsigned), 'storage recovery receipt pin mismatch')
        require(all(unsigned[k] == state[k] for k in ('schemaVersion', 'planSha256', 'operationId')), 'storage recovery operation mismatch')
        require(unsigned['status'] in ('reserved', 'create-intent', 'awaiting-binding', 'retain-intent', 'retained'), 'storage recovery state cannot continue')
        for key in ('claimUid', 'volumeUid'):
            require(unsigned[key] is None or isinstance(unsigned[key], str) and UUID.fullmatch(unsigned[key]), 'storage recovery UID invalid')
        require(unsigned['volumeName'] is None or isinstance(unsigned['volumeName'], str) and re.fullmatch('[a-z0-9][a-z0-9.-]{0,252}', unsigned['volumeName']), 'storage recovery volume name invalid')
        require(unsigned['status'] in ('reserved', 'create-intent') or unsigned['claimUid'] is not None, 'storage recovery ownership absent')
        require(unsigned['status'] not in ('retain-intent', 'retained') or unsigned['volumeUid'] is not None and unsigned['volumeName'] is not None, 'storage recovery volume ownership absent')
        state = unsigned; state['previousReceiptSha256'] = digest
    else:
        require(expected_prior_sha256 is None, 'unexpected recovery pin')

    def commit(status):
        state['status'] = status
        sink.commit(copy.deepcopy(state))
        return {**copy.deepcopy(state), 'canonicalSha256': canonical_sha256(state)}

    try:
        _source(plan, transport)
        collection = f"/api/v1/namespaces/{plan['source']['pvcNamespace']}/persistentvolumeclaims"
        path = collection + '/' + TARGET_NAME
        claim = transport.request('GET', path, None)
        if state['status'] == 'reserved':
            require(claim is None, 'target claim already exists; never adopt it')
            commit('create-intent')
            try:
                claim = transport.request('POST', collection, copy.deepcopy(plan['target']))
            except CreateConflict:
                commit('conflict')
                raise BootstrapStopped('target claim create conflict') from None
            except Exception:
                claim = transport.request('GET', path, None)
        require(claim is not None, 'claim create outcome unresolved; retain receipt, do not repeat create')
        identity = _claim(claim, plan['target'], owned=True)
        require(identity['uid'] != plan['source']['pvcUid'] and state['claimUid'] in (None, identity['uid']), 'target claim UID changed')
        state['claimUid'] = identity['uid']
        if claim.get('status', {}).get('phase') == 'Pending':
            require(state['status'] in ('create-intent', 'awaiting-binding'), 'bound claim regressed')
            return commit('awaiting-binding')
        require(claim.get('status', {}).get('phase') == 'Bound', 'target claim is not usable')
        name = claim.get('spec', {}).get('volumeName')
        require(isinstance(name, str) and re.fullmatch('[a-z0-9][a-z0-9.-]{0,252}', name) and name != plan['source']['pvName'], 'target volume must be separate')
        require(state['volumeName'] in (None, name), 'target volume name changed')
        pv_path = '/api/v1/persistentvolumes/' + name
        volume = transport.request('GET', pv_path, None)
        identity = _volume(plan, claim, volume)
        require(state['volumeUid'] in (None, identity['uid']), 'target volume UID changed')
        state.update(volumeName=name, volumeUid=identity['uid'])
        if volume['spec']['persistentVolumeReclaimPolicy'] != 'Retain':
            require(state['status'] != 'retained', 'retained volume policy changed')
            commit('retain-intent')
            _source(plan, transport)
            latest = transport.request('GET', path, None)
            require(_claim(latest, plan['target'], owned=True)['uid'] == state['claimUid'] and latest['spec'].get('volumeName') == name and latest.get('status', {}).get('phase') == 'Bound', 'claim changed before retention')
            patch = [{'op': 'test', 'path': '/metadata/uid', 'value': identity['uid']},
                     {'op': 'test', 'path': '/metadata/resourceVersion', 'value': identity['resourceVersion']},
                     {'op': 'test', 'path': '/spec/persistentVolumeReclaimPolicy', 'value': 'Delete'},
                     {'op': 'replace', 'path': '/spec/persistentVolumeReclaimPolicy', 'value': 'Retain'}]
            try:
                transport.request('PATCH', pv_path, patch)
            except Exception:
                # Re-observe after an uncertain response; never issue a second
                # patch in this attempt and never restore Delete on failure.
                pass
            volume = transport.request('GET', pv_path, None)
            require(_volume(plan, latest, volume)['uid'] == state['volumeUid'] and volume['spec']['persistentVolumeReclaimPolicy'] == 'Retain', 'volume retention outcome unresolved')
        _source(plan, transport)
        latest = transport.request('GET', path, None)
        require(_claim(latest, plan['target'], owned=True)['uid'] == state['claimUid'] and latest['spec'].get('volumeName') == name and latest.get('status', {}).get('phase') == 'Bound', 'claim changed before completion')
        return commit('retained')
    except Exception:
        raise BootstrapStopped('review storage stopped; retain the target and private receipts') from None


class KubectlStorageTransport:
    """Bound kubectl/kubeconfig Adapter; only this plan's storage paths exist.

    The caller owns the verified executable and kubeconfig snapshot lifetime.
    PV access becomes available only after observing the owned, bound target
    claim. A patch must match the last validated PV UID/resourceVersion exactly.
    """
    def __init__(self, runner, snapshot, plan, expected_plan_sha256):
        _validate_plan(plan, expected_plan_sha256)
        self.runner, self.snapshot, self.plan = runner, snapshot, copy.deepcopy(plan)
        self.collection = f"/api/v1/namespaces/{plan['source']['pvcNamespace']}/persistentvolumeclaims"
        self.source_path = self.collection + '/' + plan['source']['pvcName']
        self.target_path = self.collection + '/' + TARGET_NAME
        self.claim = None
        self.volume = None

    def request(self, method, path, payload):
        base = ['kubectl', '--kubeconfig', str(self.snapshot.path), '--request-timeout=20s']
        pv_path = '/api/v1/persistentvolumes/' + self.claim['spec']['volumeName'] if self.claim and self.claim.get('status', {}).get('phase') == 'Bound' else None
        if method == 'GET':
            require(payload is None and path in {self.source_path, self.target_path, pv_path} and path is not None, 'read outside review storage inventory')
            result = self.runner.run(base + ['get', '--raw', path], timeout=25)
            if result.code and result.err.startswith('Error from server (NotFound):'):
                if path == self.target_path: self.claim = self.volume = None
                return None
        elif method == 'POST':
            require(path == self.collection and payload == self.plan['target'], 'create outside exact target claim')
            result = self.runner.run(base + ['create', '--raw', path, '-f', '-'], input_text=json.dumps(payload, separators=(',', ':')), timeout=25)
            if result.code and result.err.startswith('Error from server (AlreadyExists):'):
                raise CreateConflict('target claim already exists')
        elif method == 'PATCH':
            require(pv_path is not None and path == pv_path and self.volume is not None, 'patch requires observed target volume')
            identity = _volume(self.plan, self.claim, self.volume)
            expected = [{'op': 'test', 'path': '/metadata/uid', 'value': identity['uid']},
                        {'op': 'test', 'path': '/metadata/resourceVersion', 'value': identity['resourceVersion']},
                        {'op': 'test', 'path': '/spec/persistentVolumeReclaimPolicy', 'value': 'Delete'},
                        {'op': 'replace', 'path': '/spec/persistentVolumeReclaimPolicy', 'value': 'Retain'}]
            require(payload == expected and self.volume['spec']['persistentVolumeReclaimPolicy'] == 'Delete', 'patch outside exact retention change')
            result = self.runner.run(base + ['patch', 'persistentvolume', self.volume['metadata']['name'], '--type=json',
                                            '-p', json.dumps(expected, separators=(',', ':')), '-o', 'json'], timeout=25)
        else:
            raise BootstrapStopped('method outside review storage operation')
        require(result.code == 0 and len(result.out) <= 4 * 1024 * 1024, 'storage request failed or outcome unresolved')
        try:
            observed = json.loads(result.out)
        except (ValueError, TypeError):
            raise BootstrapStopped('storage response invalid') from None
        if path == self.target_path or method == 'POST':
            _claim(observed, self.plan['target'], owned=True)
            name = observed.get('spec', {}).get('volumeName')
            if name is not None:
                require(isinstance(name, str) and re.fullmatch('[a-z0-9][a-z0-9.-]{0,252}', name) and name != self.plan['source']['pvName'], 'target volume path invalid')
            same_binding = self.claim is not None and self.claim['metadata']['uid'] == observed['metadata']['uid'] and self.claim.get('spec', {}).get('volumeName') == name and observed.get('status', {}).get('phase') == 'Bound'
            self.claim = copy.deepcopy(observed)
            if not same_binding:
                self.volume = None
        elif path == pv_path:
            _volume(self.plan, self.claim, observed)
            self.volume = copy.deepcopy(observed)
        return observed


CONSUMER_NAME = 'roebel-case-review-storage-check'
CONSUMER_LABEL = 'stadtstack.io/review-storage-consumer'
CONSUMER_IMAGE = 'ghcr.io/giraeffleaeffle/stadtstack-case-steward-control@sha256:0c074f77b66a96116d8fc4e976d5e5f64b33f8fbd6e4ce158a91f8c57abdf430'
CONSUMER_CHECK = """const fs = require('node:fs');
const root = '/review-target';
const info = fs.lstatSync(root);
const stat = fs.statfsSync(root, { bigint: true });
if (!info.isDirectory() || info.isSymbolicLink() || stat.type !== 0xef53n ||
    stat.bavail * stat.bsize < 1073741824n ||
    fs.readdirSync(root).some(name => name !== 'lost+found')) process.exit(1);
console.log('Empty review filesystem verified');
"""


def build_consumer_plan(storage_plan, predecessor=None):
    """Inert, separate authority for WFFC scheduling; never mounts the source."""
    _validate_plan(storage_plan, storage_plan['planSha256'])
    namespace = storage_plan['source']['pvcNamespace']
    metadata = {'name': CONSUMER_NAME, 'namespace': namespace,
                'labels': {CONSUMER_LABEL: storage_plan['operationId'][:32]},
                'annotations': {OWNER: storage_plan['operationId']}}
    policy = {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
              'metadata': copy.deepcopy(metadata),
              'spec': {'podSelector': {'matchLabels': {CONSUMER_LABEL: storage_plan['operationId'][:32]}},
                       'policyTypes': ['Ingress', 'Egress'], 'ingress': [], 'egress': []}}
    pod = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': copy.deepcopy(metadata),
           'spec': {'serviceAccountName': 'roebel-case-steward-control',
                    'automountServiceAccountToken': False, 'enableServiceLinks': False,
                    'restartPolicy': 'Never', 'activeDeadlineSeconds': 300,
                    'terminationGracePeriodSeconds': 5,
                    'securityContext': {'runAsNonRoot': True, 'runAsUser': 1000, 'runAsGroup': 1000,
                                        'fsGroup': 1000, 'seccompProfile': {'type': 'RuntimeDefault'}},
                    'affinity': {'podAffinity': {'requiredDuringSchedulingIgnoredDuringExecution': [
                        {'labelSelector': {'matchLabels': {'app.kubernetes.io/name': 'roebel-case-steward-control'}},
                         'namespaces': [namespace], 'topologyKey': 'kubernetes.io/hostname'}]}},
                    'containers': [{'name': 'check', 'image': CONSUMER_IMAGE, 'imagePullPolicy': 'IfNotPresent',
                                    'command': ['node', '-e', CONSUMER_CHECK],
                                    'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                                        'capabilities': {'drop': ['ALL']}},
                                    'resources': {'requests': {'cpu': '10m', 'memory': '32Mi'},
                                                  'limits': {'cpu': '100m', 'memory': '128Mi'}},
                                    'volumeMounts': [{'name': 'target', 'mountPath': '/review-target', 'readOnly': True}]}],
                    'volumes': [{'name': 'target', 'persistentVolumeClaim': {'claimName': TARGET_NAME, 'readOnly': True}}]}}
    value = {'schemaVersion': 'roebel_case_review_binding_consumer_plan_v1',
             'storagePlanSha256': storage_plan['planSha256'], 'operationId': storage_plan['operationId'],
             'networkPolicy': policy, 'pod': pod}
    if predecessor is not None:
        previous = _pinned_receipt(predecessor, predecessor.get('canonicalSha256'))
        original = build_consumer_plan(storage_plan)
        require(previous.get('schemaVersion') == 'roebel_case_review_binding_consumer_receipt_v1' and
                previous.get('planSha256') == original['planSha256'] and
                previous.get('status') in ('awaiting-check', 'verified') and
                all(isinstance(previous.get(k), str) and UUID.fullmatch(previous[k]) for k in ('claimUid', 'podUid', 'networkPolicyUid')),
                'formatting consumer requires the original owned consumer receipt')
        value['schemaVersion'] = 'roebel_case_review_binding_consumer_plan_v2'
        value['predecessorReceipt'] = copy.deepcopy(predecessor)
        for key in ('networkPolicy', 'pod'):
            value[key]['metadata']['name'] = CONSUMER_NAME + '-v2'
        # CSI must format the fresh disk before a read-only filesystem mount
        # exists. The fixed non-root program still performs filesystem reads only.
        value['pod']['spec']['volumes'][0]['persistentVolumeClaim']['readOnly'] = False
        value['pod']['spec']['containers'][0]['volumeMounts'][0]['readOnly'] = False
    return {**value, 'planSha256': canonical_sha256(value)}


def _consumer_plan(plan, storage_plan, pin):
    require(plan == build_consumer_plan(storage_plan, plan.get('predecessorReceipt')) and plan['planSha256'] == pin and SHA.fullmatch(pin),
            'binding consumer plan mismatch')


def _consumer_object(observed, desired):
    from .case_runtime_kubernetes import normalize, _default
    require(isinstance(observed, dict) and observed.get('kind') == desired['kind'] and
            observed.get('apiVersion') == desired['apiVersion'], 'binding consumer object invalid')
    identity = _identity(observed)
    actual = normalize(observed)
    expected = normalize(desired)
    if desired['kind'] == 'Pod':
        # PodTopologyLabels admission copies these Node labels at binding,
        # after initial CREATE/dry-run. They convey topology, not authority.
        # Keep every other label and the reviewed scheduling constraints exact.
        labels = actual['metadata'].get('labels', {})
        for key in ('topology.kubernetes.io/region', 'topology.kubernetes.io/zone'):
            if key in labels:
                require(bool(actual['spec'].get('nodeName')) and isinstance(labels[key], str) and
                        re.fullmatch('[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?', labels[key]),
                        'consumer topology label invalid or not yet node-bound')
                labels.pop(key)
        for value in (actual, expected):
            spec = value['spec']
            node = spec.pop('nodeName', None)
            require(node is None or isinstance(node, str) and re.fullmatch('[a-z0-9][a-z0-9.-]{0,252}', node), 'consumer node invalid')
            for key, default in [('priority', 0), ('preemptionPolicy', 'PreemptLowerPriority'),
                                 ('tolerations', [{'key':'node.kubernetes.io/not-ready','operator':'Exists','effect':'NoExecute','tolerationSeconds':300},
                                                  {'key':'node.kubernetes.io/unreachable','operator':'Exists','effect':'NoExecute','tolerationSeconds':300}])]:
                _default(spec, key, default)
            for volume in spec.get('volumes', []):
                claim = volume.get('persistentVolumeClaim', {})
                if claim.get('readOnly') is False:
                    claim.pop('readOnly')
            for container in spec.get('containers', []):
                for mount in container.get('volumeMounts', []):
                    if mount.get('readOnly') is False:
                        mount.pop('readOnly')
            # Reuse the established Pod-template default normalization. Extras
            # such as injected volumes, env, sidecars and host access still fail.
            wrapped = {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {},
                       'spec': {'template': {'metadata': {}, 'spec': spec}}}
            value['spec'] = normalize(wrapped)['spec']['template']['spec']
    require(actual == expected, 'binding consumer semantics changed')
    return identity


def _pinned_receipt(receipt, pin):
    require(isinstance(receipt, dict) and isinstance(pin, str) and SHA.fullmatch(pin), 'receipt pin missing')
    body = copy.deepcopy(receipt)
    require(body.pop('canonicalSha256', None) == pin == canonical_sha256(body), 'receipt pin mismatch')
    return body


def advance_consumer(plan, storage_plan, *, expected_plan_sha256, storage_receipt, expected_storage_receipt_sha256,
                     transport, sink, prior=None, expected_prior_sha256=None):
    """Advance the fixed check or initializer; no delete or application writes.

    The existing storage receipt must already own the target claim. Each create
    is preceded by a durable intent. Unknown outcomes never trigger re-creation.
    Check completion proves only this Pod's empty-filesystem check, not PV retention
    or migration authority; resume the separate storage operation for Retain.
    """
    initializing = _initializer(plan)
    (_initialization_plan if initializing else _consumer_plan)(plan, storage_plan, expected_plan_sha256)
    if initializing:
        require(storage_receipt == plan['retainedReceipt'], 'initializer retained receipt changed')
    owned = _pinned_receipt(storage_receipt, expected_storage_receipt_sha256)
    require(owned.get('schemaVersion') == 'roebel_case_review_storage_receipt_v1' and
            owned.get('planSha256') == storage_plan['planSha256'] and owned.get('operationId') == plan['operationId'] and
            owned.get('status') in ('awaiting-binding', 'retain-intent', 'retained') and
            isinstance(owned.get('claimUid'), str) and UUID.fullmatch(owned['claimUid']), 'consumer requires owned target claim')
    state = {'schemaVersion': 'roebel_case_review_binding_consumer_receipt_v1', 'planSha256': plan['planSha256'],
             'storageReceiptSha256': expected_storage_receipt_sha256, 'claimUid': owned['claimUid'],
             'previousReceiptSha256': None, 'status': 'reserved', 'networkPolicyUid': None, 'podUid': None}
    if initializing:
        state['schemaVersion'] = 'roebel_case_review_initialization_receipt_v1'
        state['configMapUid'] = None
        state['volumeUid'] = owned['volumeUid']
    if prior is not None:
        previous = _pinned_receipt(prior, expected_prior_sha256)
        require(set(previous) == set(state) and all(previous[k] == state[k] for k in
                ('schemaVersion', 'planSha256', 'storageReceiptSha256', 'claimUid') + (('volumeUid',) if initializing else ())), 'consumer recovery identity changed')
        require(previous['status'] in ('reserved', 'policy-intent', 'policy-created', 'pod-intent', 'awaiting-check', 'verified') + (('config-intent','config-created') if initializing else ()),
                'consumer recovery state cannot continue')
        for key in ('networkPolicyUid', 'podUid') + (('configMapUid',) if initializing else ()):
            require(previous[key] is None or isinstance(previous[key], str) and UUID.fullmatch(previous[key]), 'consumer receipt UID invalid')
        require(previous['status'] in ('reserved', 'policy-intent') or previous['networkPolicyUid'] is not None, 'policy ownership absent')
        require(previous['status'] not in ('awaiting-check', 'verified') or previous['podUid'] is not None, 'Pod ownership absent')
        if initializing:
            require(previous['status'] not in ('config-created','pod-intent','awaiting-check','verified') or previous['configMapUid'] is not None, 'initializer config ownership absent')
        state = previous; state['previousReceiptSha256'] = expected_prior_sha256
    else:
        require(expected_prior_sha256 is None, 'unexpected consumer recovery pin')

    def commit(status):
        state['status'] = status
        sink.commit(copy.deepcopy(state))
        return {**copy.deepcopy(state), 'canonicalSha256': canonical_sha256(state)}

    def check_source_target():
        _source(storage_plan, transport)
        path = f"/api/v1/namespaces/{storage_plan['source']['pvcNamespace']}/persistentvolumeclaims/{TARGET_NAME}"
        claim = transport.request('GET', path, None)
        require(_claim(claim, storage_plan['target'], owned=True)['uid'] == owned['claimUid'] and
                claim.get('status', {}).get('phase') in ('Pending', 'Bound'), 'consumer target ownership changed')
        if claim['status']['phase'] == 'Bound':
            require(isinstance(claim['spec'].get('volumeName'), str) and claim['spec']['volumeName'] != storage_plan['source']['pvName'] and
                    owned.get('volumeName') in (None, claim['spec']['volumeName']), 'consumer volume binding changed')
        sc = transport.request('GET', '/apis/storage.k8s.io/v1/storageclasses/hcloud-volumes', None)
        require(sc.get('provisioner') == 'csi.hetzner.cloud' and sc.get('volumeBindingMode') == 'WaitForFirstConsumer' and
                sc.get('reclaimPolicy') == 'Retain', 'consumer storage class changed')
        if 'predecessorReceipt' in plan:
            predecessor = plan['predecessorReceipt']
            require(predecessor['claimUid'] == owned['claimUid'], 'formatting target differs from predecessor')
            old_path = f"/api/v1/namespaces/{storage_plan['source']['pvcNamespace']}/pods/{CONSUMER_NAME}"
            old = transport.request('GET', old_path, None)
            if old is not None:
                require(_consumer_object(old, build_consumer_plan(storage_plan)['pod'])['uid'] == predecessor['podUid'],
                        'predecessor Pod identity changed')
                require(old.get('status', {}).get('phase') in ('Failed', 'Succeeded') and
                        all('running' not in item.get('state', {}) for item in old['status'].get('containerStatuses', [])),
                        'predecessor consumer must be terminal before replacement')
        if initializing:
            require(claim.get('status',{}).get('phase') == 'Bound' and claim['spec'].get('volumeName') == owned['volumeName'], 'initializer target binding changed')
            pv = transport.request('GET','/api/v1/persistentvolumes/' + owned['volumeName'],None)
            require(_volume(storage_plan,claim,pv)['uid'] == owned['volumeUid'] and pv['spec']['persistentVolumeReclaimPolicy'] == 'Retain', 'initializer retained PV changed')
            for name in (CONSUMER_NAME,CONSUMER_NAME+'-v2'):
                require(transport.request('GET',f"/api/v1/namespaces/{storage_plan['source']['pvcNamespace']}/pods/{name}",None) is None,
                        'prior check Pod still exists; separate retirement required')
        return claim

    check_source_target()
    objects = [('networkPolicy', 'networkPolicyUid', 'reserved', 'policy-intent', 'policy-created',
                f"/apis/networking.k8s.io/v1/namespaces/{storage_plan['source']['pvcNamespace']}/networkpolicies"),
               ('pod', 'podUid', 'policy-created', 'pod-intent', 'awaiting-check',
                f"/api/v1/namespaces/{storage_plan['source']['pvcNamespace']}/pods")]
    if initializing:
        objects.insert(1,('configMap','configMapUid','policy-created','config-intent','config-created',
                          f"/api/v1/namespaces/{storage_plan['source']['pvcNamespace']}/configmaps"))
        objects[2] = ('pod','podUid','config-created','pod-intent','awaiting-check',objects[2][-1])
    if state['status'] == 'reserved':
        require(transport.request('GET', objects[-1][-1] + '/' + plan['pod']['metadata']['name'], None) is None,
                'consumer Pod already exists; do not create its network policy')
    for key, uid_key, start, intent, completed, collection in objects:
        desired = plan[key]; path = collection + '/' + desired['metadata']['name']
        observed = transport.request('GET', path, None)
        if state['status'] == start:
            require(observed is None, 'consumer object already exists; never adopt it')
            check_source_target(); commit(intent)
            try:
                observed = transport.request('POST', collection, copy.deepcopy(desired))
            except CreateConflict:
                commit('conflict'); raise BootstrapStopped('consumer create conflict') from None
            except Exception:
                observed = transport.request('GET', path, None)
        require(observed is not None, 'consumer create outcome unresolved; never repeat create')
        identity = _consumer_object(observed, desired)
        require(state[uid_key] in (None, identity['uid']), 'consumer object UID changed')
        state[uid_key] = identity['uid']
        if state['status'] == intent:
            commit(completed)
    phase = observed.get('status', {}).get('phase')
    require(phase in ('Pending', 'Running', 'Succeeded'), 'consumer failed; retain evidence')
    if phase != 'Succeeded':
        require(state['status'] != 'verified', 'completed consumer regressed')
        return commit('awaiting-check')
    statuses = observed['status'].get('containerStatuses', [])
    require(len(statuses) == 1 and statuses[0].get('name') == ('initialize-target' if initializing else 'check') and statuses[0].get('restartCount') == 0 and
            statuses[0].get('state', {}).get('terminated', {}).get('exitCode') == 0 and
            statuses[0].get('imageID', '').endswith((REVIEW_IMAGE if initializing else CONSUMER_IMAGE).split('@')[1]), 'consumer completion unverified')
    require(check_source_target()['status']['phase'] == 'Bound', 'consumer target binding regressed')
    return commit('verified')


class KubectlConsumerTransport:
    """Bound storage reads and exact check/initializer objects GET+POST only."""
    def __init__(self, runner, snapshot, plan, storage_plan, expected_plan_sha256):
        (_initialization_plan if _initializer(plan) else _consumer_plan)(plan, storage_plan, expected_plan_sha256)
        self.runner, self.snapshot, self.plan = runner, snapshot, copy.deepcopy(plan)
        self.storage = KubectlStorageTransport(runner, snapshot, storage_plan, storage_plan['planSha256'])
        ns = storage_plan['source']['pvcNamespace']
        self.collections = {f'/api/v1/namespaces/{ns}/pods': 'pod',
                            f'/apis/networking.k8s.io/v1/namespaces/{ns}/networkpolicies': 'networkPolicy'}

        if _initializer(plan):
            self.collections[f'/api/v1/namespaces/{ns}/configmaps'] = 'configMap'

    def request(self, method, path, payload):
        if _initializer(self.plan) and method == 'GET' and path == '/api/v1/persistentvolumes/' + self.plan['retainedReceipt']['volumeName']:
            return self.storage.request(method,path,payload)
        if method == 'GET' and payload is None and path in (self.storage.source_path, self.storage.target_path):
            return self.storage.request(method, path, payload)
        base = ['kubectl', '--kubeconfig', str(self.snapshot.path), '--request-timeout=20s']
        known = {collection + '/' + self.plan[key]['metadata']['name']: key for collection, key in self.collections.items()}
        predecessor_path = next(collection for collection, key in self.collections.items() if key == 'pod') + '/' + CONSUMER_NAME
        if 'predecessorReceipt' in self.plan:
            known[predecessor_path] = 'predecessor'
        if _initializer(self.plan):
            known[predecessor_path] = 'retired'
            known[predecessor_path+'-v2'] = 'retired'
        if method == 'GET':
            require(payload is None and path in {*known, '/apis/storage.k8s.io/v1/storageclasses/hcloud-volumes'}, 'consumer read outside inventory')
            result = self.runner.run(base + ['get', '--raw', path], timeout=25)
            if result.code and result.err.startswith('Error from server (NotFound):') and path in known:
                return None
        elif method == 'POST':
            require(path in self.collections and payload == self.plan[self.collections[path]], 'consumer create outside plan')
            result = self.runner.run(base + ['create', '--raw', path, '-f', '-'], input_text=json.dumps(payload, separators=(',', ':')), timeout=25)
            if result.code and result.err.startswith('Error from server (AlreadyExists):'):
                raise CreateConflict('consumer create conflict')
        else:
            raise BootstrapStopped('consumer method outside inventory')
        require(result.code == 0 and len(result.out) <= 4 * 1024 * 1024, 'consumer response unresolved')
        observed = json.loads(result.out)
        key = known.get(path) if method == 'GET' else self.collections[path]
        if key is not None:
            if key == 'retired':
                raise BootstrapStopped('prior check Pod still exists; separate retirement required')
            elif key == 'predecessor':
                require(_consumer_object(observed, build_consumer_plan(self.storage.plan)['pod'])['uid'] == self.plan['predecessorReceipt']['podUid'],
                        'predecessor transport identity changed')
            else:
                _consumer_object(observed, self.plan[key])
        return observed


INITIALIZER_PROGRAM = r'''// The protected Operations caller must verify retained PVC/PV identity,
// exclusive mount release, image and this program's pin before launching it.
import {constants as C, openSync,closeSync,fstatSync,lstatSync,realpathSync,readdirSync,statfsSync,mkdirSync,fchmodSync,writeSync,fsyncSync} from 'node:fs';
import {dirname,join} from 'node:path';
import {createHash} from 'node:crypto';
import {verifyStagingCaseControlReviewedBinding,createStagingCaseControlDeploymentProof,createNodeStagingCaseControlStorageObserver} from '/runtime/src/staging-case-control-preflight.ts';
const canonical=v=>Array.isArray(v)?`[${v.map(canonical).join(',')}]`:v&&typeof v==='object'?`{${Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')}}`:JSON.stringify(v);
const hash=b=>'sha256:'+createHash('sha256').update(b).digest('hex');
function requireFact(ok){if(!ok)throw new Error('review_target_initialization_stopped');}
export function initialize(binding,pin,markerText){
 verifyStagingCaseControlReviewedBinding(binding);
 requireFact(binding.schemaVersion==='staging_case_control_deployment_binding_v2'&&binding.bindingChecksum===pin);
 const s=binding.storage, parent=dirname(s.rootDir);
 requireFact(s.uid===process.getuid()&&s.gid===process.getgid()&&s.marker.uid===s.uid&&s.marker.gid===s.gid);
 requireFact(s.mode==='0700'&&s.marker.mode==='0600'&&s.rootDir===join(parent,'case-control'));
 const m={};for(const k of ['deploymentEnvironment','municipalityId','workloadName','workload','releaseDigest','operationsTopologyChecksum','deployment'])m[k]=binding[k];
 Object.assign(m,s);m.schemaVersion='staging_case_control_storage_marker_v1';m.marker={...s.marker};delete m.marker.checksum;
 requireFact(markerText===canonical(m)+'\n'&&hash(markerText)===s.marker.checksum);
 requireFact(realpathSync(parent)===parent&&!lstatSync(parent).isSymbolicLink());
 const fds=[];
 try{
  const parentFd=openSync(parent,C.O_RDONLY|C.O_DIRECTORY|C.O_NOFOLLOW);fds.push(parentFd);
  const parentStat=fstatSync(parentFd),observed=statfsSync(parent,{bigint:true});
  requireFact(observed.type===BigInt(s.filesystemType)&&observed.bavail*observed.bsize>=BigInt(s.minAvailableBytes));
  const entries=readdirSync(parent);requireFact(entries.every(n=>n==='lost+found'));
  if(entries.length){const lost=lstatSync(join(parent,'lost+found'));requireFact(lost.isDirectory()&&!lost.isSymbolicLink());}
  const fresh=lstatSync(parent);requireFact(fresh.dev===parentStat.dev&&fresh.ino===parentStat.ino);
  // Create only. Existing or partially initialized targets are retained for
  // inspection; this program never repairs, overwrites, deletes or retries them.
  mkdirSync(s.rootDir,{mode:0o700});
  const rootFd=openSync(s.rootDir,C.O_RDONLY|C.O_DIRECTORY|C.O_NOFOLLOW);fds.push(rootFd);
  const root=fstatSync(rootFd);requireFact(root.uid===s.uid&&root.gid===s.gid&&root.dev===parentStat.dev);
  fchmodSync(rootFd,0o700); // clear fsGroup-inherited setgid only on our new root
  const markerFd=openSync(join(s.rootDir,s.marker.fileName),C.O_WRONLY|C.O_CREAT|C.O_EXCL|C.O_NOFOLLOW,0o600);fds.push(markerFd);
  const marker=fstatSync(markerFd);requireFact(marker.isFile()&&marker.uid===s.uid&&marker.gid===s.gid&&marker.nlink===1);
  const bytes=Buffer.from(markerText);let offset=0;
  while(offset<bytes.length){const n=writeSync(markerFd,bytes,offset,bytes.length-offset);requireFact(n>0);offset+=n;}
  fsyncSync(markerFd);fsyncSync(rootFd);fsyncSync(parentFd);
  createStagingCaseControlDeploymentProof({reviewedBinding:binding,expectedBindingChecksum:pin,storageObserver:createNodeStagingCaseControlStorageObserver()});
  return {status:'target-marker-initialized',bindingChecksum:pin,markerChecksum:s.marker.checksum};
 }finally{for(const fd of fds.reverse())closeSync(fd);}
}
'''

INITIALIZER_NAME = 'roebel-case-review-initialize-v1'
REVIEW_IMAGE = 'ghcr.io/giraeffleaeffle/stadtstack-case-steward-control@sha256:5f0eeec46e1e00150ce5f370ba9749a0f4d6d652dac73839f25699771adb1d60'


def build_initialization_plan(storage_plan, retained_receipt, consumer_plan, consumer_receipt):
    """Inert fixed compiler; linked retained-volume and successful check evidence.

    Old check Pods must subsequently be removed by their separately authorized
    owner. This operation has no deletion, Secret, source-mount or migration path.
    Pod absence is not an attestation of physical kubelet mount release.
    """
    _validate_plan(storage_plan, storage_plan['planSha256'])
    _consumer_plan(consumer_plan, storage_plan, consumer_plan['planSha256'])
    owned = _pinned_receipt(retained_receipt, retained_receipt.get('canonicalSha256'))
    checked = _pinned_receipt(consumer_receipt, consumer_receipt.get('canonicalSha256'))
    require(owned.get('schemaVersion') == 'roebel_case_review_storage_receipt_v1' and
            owned.get('planSha256') == storage_plan['planSha256'] and owned.get('operationId') == storage_plan['operationId'] and
            owned.get('status') == 'retained' and all(isinstance(owned.get(k), str) and UUID.fullmatch(owned[k]) for k in ('claimUid','volumeUid')) and
            isinstance(owned.get('volumeName'), str) and re.fullmatch('[a-z0-9][a-z0-9.-]{0,252}', owned['volumeName']) and
            owned['volumeName'] != storage_plan['source']['pvName'], 'initializer requires retained target identity')
    require(checked.get('schemaVersion') == 'roebel_case_review_binding_consumer_receipt_v1' and
            checked.get('planSha256') == consumer_plan['planSha256'] and checked.get('status') == 'verified' and
            checked.get('claimUid') == owned['claimUid'] and all(isinstance(checked.get(k), str) and UUID.fullmatch(checked[k]) for k in ('podUid','networkPolicyUid')),
            'initializer requires verified check on the same target')
    root = Path(__file__).resolve().parent.parent
    binding = json.loads((root / 'proposals/synthetic-case-runtime/control-binding.json').read_text())
    binding.pop('bindingChecksum')
    binding['schemaVersion'] = 'staging_case_control_deployment_binding_v2'
    binding['releaseDigest'] = REVIEW_IMAGE.split('@')[1]
    topology = json.loads((root / 'proposals/synthetic-case-runtime/topology.json').read_text())
    topology['controlImage'] = REVIEW_IMAGE
    binding['operationsTopologyChecksum'] = canonical_sha256(topology)
    binding['listeners'].append({'id':'administration-review','port':18090,'bindScope':'pod_network'})
    binding['storage'].update(rootDir='/var/lib/stadtstack-review/case-control', pvcName=TARGET_NAME,
                              pvcUid=owned['claimUid'], pvName=owned['volumeName'])
    marker = {k:binding[k] for k in ('deploymentEnvironment','municipalityId','workloadName','workload','releaseDigest','operationsTopologyChecksum','deployment')}
    marker.update(copy.deepcopy(binding['storage']))
    marker['schemaVersion'] = 'staging_case_control_storage_marker_v1'
    marker['marker'].pop('checksum')
    marker_text = json.dumps(marker, sort_keys=True, separators=(',',':'), ensure_ascii=False) + '\n'
    binding['storage']['marker']['checksum'] = 'sha256:' + hashlib.sha256(marker_text.encode()).hexdigest()
    binding['bindingChecksum'] = canonical_sha256(binding)
    meta = {'name':INITIALIZER_NAME,'namespace':storage_plan['source']['pvcNamespace'],
            'labels':{'stadtstack.io/review-storage-initializer':storage_plan['operationId'][:32]},
            'annotations':{OWNER:storage_plan['operationId']}}
    config = {'apiVersion':'v1','kind':'ConfigMap','metadata':copy.deepcopy(meta),'immutable':True,
              'data':{'initialize.mjs':INITIALIZER_PROGRAM,'reviewed-binding.json':json.dumps(binding,sort_keys=True,separators=(',',':')),
                      'storage-marker.json':marker_text}}
    pod = copy.deepcopy(consumer_plan['pod']);pod['metadata'] = copy.deepcopy(meta)
    container = pod['spec']['containers'][0];container['name'] = 'initialize-target';container['image'] = REVIEW_IMAGE
    container['command'] = ['node','--input-type=module','-e',
        "import {readFileSync} from 'node:fs';import {initialize} from '/reviewed/initialize.mjs';try{console.log(JSON.stringify(initialize(JSON.parse(readFileSync('/reviewed/reviewed-binding.json','utf8')),'" + binding['bindingChecksum'] + "',readFileSync('/reviewed/storage-marker.json','utf8'))));}catch{console.error('review_target_initialization_stopped');process.exitCode=78;}"]
    container['volumeMounts'] = [{'name':'target-state','mountPath':'/var/lib/stadtstack-review','readOnly':False},
                                {'name':'reviewed','mountPath':'/reviewed','readOnly':True}]
    pod['spec']['volumes'] = [{'name':'target-state','persistentVolumeClaim':{'claimName':TARGET_NAME,'readOnly':False}},
                             {'name':'reviewed','configMap':{'name':INITIALIZER_NAME,'defaultMode':292}}]
    policy = {'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy','metadata':copy.deepcopy(meta),
              'spec':{'podSelector':{'matchLabels':meta['labels']},'policyTypes':['Ingress','Egress'],'ingress':[],'egress':[]}}
    body = {'schemaVersion':'roebel_case_review_initialization_plan_v1','storagePlanSha256':storage_plan['planSha256'],
            'operationId':storage_plan['operationId'],'retainedReceipt':copy.deepcopy(retained_receipt),
            'checkedPlan':copy.deepcopy(consumer_plan),'checkedReceipt':copy.deepcopy(consumer_receipt),
            'targetBinding':binding,'networkPolicy':policy,'configMap':config,'pod':pod}
    return {**body,'planSha256':canonical_sha256(body)}


def _initializer(plan):
    return plan.get('schemaVersion') == 'roebel_case_review_initialization_plan_v1'


def _initialization_plan(plan, storage_plan, pin):
    require(isinstance(pin,str) and SHA.fullmatch(pin) and plan.get('planSha256') == pin and
            plan == build_initialization_plan(storage_plan,plan['retainedReceipt'],plan['checkedPlan'],plan['checkedReceipt']),
            'initialization differs from reviewed compiler')
