"""Retained target-volume provisioning for the review migration.

This module creates one fresh PVC and can change only its bound PV's reclaim
policy to Retain. It never mounts storage, reads Secrets, stops a workload or
imports a Case. A protected caller supplies the independently approved plan
hash, a bounded Kubernetes transport, and a pre-reserved private ReceiptSink.
"""
from __future__ import annotations

import copy
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
