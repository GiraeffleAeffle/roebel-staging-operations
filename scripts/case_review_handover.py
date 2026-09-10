"""Ordered review migration with durable intent and no automatic rollback.

The trusted Operations Adapter verifies concrete Kubernetes/runtime receipts;
this Module enforces their order, cross-links and recovery semantics. It has no
ambient cluster access. No source shutdown is allowed until the Adapter proves
that the complete pinned migration and handover implementation is ready.
"""
from __future__ import annotations

import copy
import re
from datetime import datetime, timezone

from .case_runtime_bootstrap import BootstrapStopped, _require
from .staging_participant_flux_bootstrap import canonical_sha256

STEPS = ('fence-source', 'release-mounts', 'verify-backup', 'prepare-migration',
         'activate-migration', 'release-migration', 'start-review-runtime',
         'verify-review-runtime', 'restore-gitops')
SHA = re.compile(r'sha256:[0-9a-f]{64}')
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
PINS = {'operationsRevision', 'implementationSha256', 'sourceRenderSha256',
        'targetRenderSha256', 'sourceBindingSha256', 'targetBindingSha256',
        'sourceConfigurationSha256', 'targetConfigurationSha256',
        'initializationReceiptSha256', 'configurationReceiptSha256',
        'admissionReceiptChecksum', 'targetDeploymentClaimChecksum', 'migrationImageDigest'}
IDENTITIES = {'clusterUid', 'sourceDeploymentUid', 'reconcilerUid', 'sourcePodUid',
              'initializerPodUid', 'sourcePvcUid', 'targetPvcUid', 'sourcePvUid',
              'targetPvUid', 'configurationSecretUid', 'nodeUid'}


def _closed(value, fields, message):
    _require(isinstance(value, dict) and set(value) == set(fields), message)


def _sha(value):
    _require(isinstance(value, str) and SHA.fullmatch(value), 'review handover checksum invalid')


def _utc(value):
    _require(isinstance(value, str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z', value), 'review handover timestamp invalid')
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise BootstrapStopped('review handover timestamp invalid') from None


def validate_plan(plan, expected_sha256):
    """Checks a separately reviewed full plan; a checksum is not authorization."""
    _closed(plan, {'schemaVersion', 'operationId', 'caseId', 'pins', 'identities',
                   'notBeforeUtc', 'expiresAtUtc', 'planSha256'}, 'review handover plan shape invalid')
    unsigned = {k:v for k,v in plan.items() if k != 'planSha256'}
    _sha(expected_sha256)
    _require(plan['schemaVersion'] == 'roebel_review_handover_plan_v1' and
             plan['planSha256'] == expected_sha256 == canonical_sha256(unsigned), 'review handover plan pin mismatch')
    _require(isinstance(plan['operationId'], str) and re.fullmatch('[0-9a-f]{64}', plan['operationId']), 'review handover operation identity invalid')
    _require(isinstance(plan['caseId'], str) and plan['caseId'].startswith('urn:stadtstack:synthetic-case:municipality:roebel-mueritz:') and UUID.fullmatch(plan['caseId'].rsplit(':',1)[-1]), 'review handover Case invalid')
    _closed(plan['pins'], PINS, 'review handover implementation pins incomplete')
    for name, value in plan['pins'].items():
        if name == 'operationsRevision':
            _require(isinstance(value, str) and re.fullmatch('[0-9a-f]{40}', value), 'review Operations revision invalid')
        else:
            _sha(value)
    _closed(plan['identities'], IDENTITIES, 'review handover identities incomplete')
    for value in plan['identities'].values():
        _require(isinstance(value, str) and UUID.fullmatch(value), 'review handover resource identity invalid')
    for a,b in (('sourcePvcUid','targetPvcUid'), ('sourcePvUid','targetPvUid'), ('sourcePodUid','initializerPodUid')):
        _require(plan['identities'][a] != plan['identities'][b], 'review handover source/target alias')
    for a,b in (('sourceRenderSha256','targetRenderSha256'), ('sourceBindingSha256','targetBindingSha256'),
                ('sourceConfigurationSha256','targetConfigurationSha256')):
        _require(plan['pins'][a] != plan['pins'][b], 'review handover configuration alias')
    start, end = _utc(plan['notBeforeUtc']), _utc(plan['expiresAtUtc'])
    _require(0 < (end-start).total_seconds() <= 3600, 'review handover window invalid')


def _evidence(plan, step, value, previous):
    """Closed, credential-free links to independently verified private records."""
    common = {'receiptSha256'}
    fields = {
        'fence-source': {'sourceDeploymentUid','reconcilerUid','sourceReplicas','reconcilerSuspended'},
        'release-mounts': {'sourcePodUid','initializerPodUid','nodeUid','sourceApiAbsent','initializerApiAbsent','sourceMountAbsent','initializerMountAbsent','positiveControlVerified'},
        'verify-backup': {'sourceSealChecksum','sourceDeploymentClaimChecksum','sourceDatabaseSha256','encryptedArchiveSha256','restoredFilesSha256','sourceFilesSha256','caseId','caseVersion','admissionReceiptChecksum'},
        'prepare-migration': {'candidateChecksum','sourceSealChecksum','sourceDeploymentClaimChecksum','admissionReceiptChecksum','targetDeploymentClaimChecksum'},
        'activate-migration': {'activationReceiptChecksum','candidateChecksum','sourceSealChecksum','sourceDeploymentClaimChecksum','targetDeploymentClaimChecksum','sourceDatabaseSha256','targetSealChecksum'},
        'release-migration': {'migrationPodUid','apiAbsent','mountAbsent','positiveControlVerified'},
        'start-review-runtime': {'sourceDeploymentUid','targetPvcUid','configurationSecretUid','targetBindingSha256','migrationImageDigest','runtimePodUid'},
        'verify-review-runtime': {'runtimePodUid','admissionReceiptChecksum','allFourListenersReady','cleanRestartVerified','sourceDatabaseSha256','publicServicesPreserved'},
        'restore-gitops': {'reconcilerUid','reconcilerSuspended','targetRenderSha256','reconciled','sourceRetained','targetRetained'},
    }[step]
    _closed(value, common | fields, 'review handover evidence shape invalid')
    _sha(value['receiptSha256'])
    for key, item in value.items():
        if key.endswith(('Checksum','Sha256','Digest')):
            _sha(item)
        if key.endswith('Uid'):
            _require(isinstance(item, str) and UUID.fullmatch(item), 'review handover evidence identity invalid')
        if key in plan['identities']:
            _require(item == plan['identities'][key], 'review handover evidence identity drift')
        if key in plan['pins']:
            _require(item == plan['pins'][key], 'review handover evidence pin drift')
    expect = {}
    if step == 'fence-source':
        _require(type(value['sourceReplicas']) is int and value['sourceReplicas'] == 0, 'source writer is not fenced')
        expect = {'reconcilerSuspended':True}
    elif step == 'release-mounts':
        expect = {k:True for k in ('sourceApiAbsent','initializerApiAbsent','sourceMountAbsent','initializerMountAbsent','positiveControlVerified')}
    elif step == 'verify-backup':
        _require(value['caseId'] == plan['caseId'] and type(value['caseVersion']) is int and value['caseVersion'] == 3 and
                 value['restoredFilesSha256'] == value['sourceFilesSha256'], 'Case backup does not reproduce sealed source')
    elif step in ('prepare-migration','activate-migration'):
        backup = previous['verify-backup']
        _require(value['sourceSealChecksum'] == backup['sourceSealChecksum'] and value['sourceDeploymentClaimChecksum'] == backup['sourceDeploymentClaimChecksum'], 'migration source seal changed')
        if step == 'activate-migration':
            _require(value['candidateChecksum'] == previous['prepare-migration']['candidateChecksum'] and
                     value['sourceDatabaseSha256'] == backup['sourceDatabaseSha256'], 'migration did not preserve prepared source')
    elif step == 'release-migration':
        expect = {k:True for k in ('apiAbsent','mountAbsent','positiveControlVerified')}
    elif step == 'verify-review-runtime':
        _require(value['runtimePodUid'] == previous['start-review-runtime']['runtimePodUid'] and
                 value['sourceDatabaseSha256'] == previous['verify-backup']['sourceDatabaseSha256'], 'review runtime preservation drift')
        expect = {k:True for k in ('allFourListenersReady','cleanRestartVerified','publicServicesPreserved')}
    elif step == 'restore-gitops':
        expect = {'reconcilerSuspended':False,'reconciled':True,'sourceRetained':True,'targetRetained':True}
    _require(all(value[k] is expected for k,expected in expect.items()), 'review handover evidence gate incomplete')


def _state(plan, prior, expected_prior_sha256):
    if prior is None:
        _require(expected_prior_sha256 is None, 'orphan prior receipt pin')
        return {'schemaVersion':'roebel_review_handover_receipt_v1','planSha256':plan['planSha256'],
                'operationId':plan['operationId'],'previousReceiptSha256':None,'status':'reserved','completed':[],'pending':None}
    state = copy.deepcopy(prior)
    pin = state.pop('canonicalSha256', None)
    _sha(expected_prior_sha256)
    _require(pin == expected_prior_sha256 == canonical_sha256(state), 'review handover prior receipt pin mismatch')
    _closed(state, {'schemaVersion','planSha256','operationId','previousReceiptSha256','status','completed','pending'}, 'review handover prior receipt shape invalid')
    _require(state['schemaVersion'] == 'roebel_review_handover_receipt_v1' and state['planSha256'] == plan['planSha256'] and
             state['operationId'] == plan['operationId'], 'review handover prior operation drift')
    _require(state['status'] in ('reserved','effect-intent','awaiting-evidence','stopped-preserve-state','complete'), 'review handover prior status invalid')
    if state['previousReceiptSha256'] is not None:
        _sha(state['previousReceiptSha256'])
    records = state['completed']
    _require(isinstance(records, list) and len(records) <= len(STEPS), 'review handover prior prefix invalid')
    previous = {}
    for step,record in zip(STEPS, records):
        _closed(record, {'step','evidence'}, 'review handover prior record shape invalid')
        _require(record['step'] == step, 'review handover prior order invalid')
        _evidence(plan, step, record['evidence'], previous)
        previous[step] = record['evidence']
    _require(state['pending'] is None or (len(records) < len(STEPS) and state['pending'] == STEPS[len(records)]), 'review handover pending intent invalid')
    _require(state['status'] != 'complete' or (len(records) == len(STEPS) and state['pending'] is None), 'review handover completion invalid')
    state['previousReceiptSha256'] = pin
    return state


def advance_review_handover(plan, *, expected_plan_sha256, adapter, sink, prior=None, expected_prior_sha256=None, clock=None):
    """Advance ordered effects once; recover by observation, never blind replay.

    Adapter.verify_ready(plan, state) must verify the complete concrete pinned
    implementation and current stage's live ownership/fencing before any work.
    Adapter.observe(plan, step, state) returns a verified receipt summary or None.
    It must check current fencing and preserve state; absence is never success.
    Adapter.perform(plan, step, state) performs only this reviewed stage, with
    its own durable sub-receipts and compare-and-swap Kubernetes operations.
    Partially complete stages resume in that concrete operator, not by calling
    perform again here. Every completed prefix is reverified on recovery.
    """
    validate_plan(plan, expected_plan_sha256)
    state = _state(plan, prior, expected_prior_sha256)
    now = clock or (lambda:datetime.now(timezone.utc))
    def fresh():
        value = now()
        _require(isinstance(value, datetime) and value.tzinfo is not None and
                 _utc(plan['notBeforeUtc']) <= value < _utc(plan['expiresAtUtc']), 'review handover window closed')
        adapter.verify_ready(copy.deepcopy(plan), copy.deepcopy(state))
    sink.commit(state)
    try:
        fresh()
        previous = {}
        for record in state['completed']:
            observed = adapter.observe(copy.deepcopy(plan), record['step'], copy.deepcopy(state))
            _require(observed == record['evidence'], 'review handover completed evidence changed')
            previous[record['step']] = observed
        for step in STEPS[len(state['completed']):]:
            fresh()
            if state['pending'] is None:
                _require(adapter.observe(copy.deepcopy(plan), step, copy.deepcopy(state)) is None, 'review handover effect has no owned intent')
                state.update(status='effect-intent', pending=step)
                sink.commit(state)
                fresh()
                try:
                    adapter.perform(copy.deepcopy(plan), step, copy.deepcopy(state))
                except Exception:
                    # A lost response is reconciled only through verified
                    # persisted evidence; no second effect is sent.
                    observed = adapter.observe(copy.deepcopy(plan), step, copy.deepcopy(state))
                    if observed is None:
                        raise BootstrapStopped('review handover effect unresolved') from None
                else:
                    observed = adapter.observe(copy.deepcopy(plan), step, copy.deepcopy(state))
            else:
                observed = adapter.observe(copy.deepcopy(plan), step, copy.deepcopy(state))
            if observed is None:
                state['status'] = 'awaiting-evidence'
                sink.commit(state)
                return state
            _evidence(plan, step, observed, previous)
            state['completed'].append({'step':step,'evidence':copy.deepcopy(observed)})
            previous[step] = observed
            state.update(status='complete' if len(state['completed']) == len(STEPS) else 'reserved', pending=None)
            sink.commit(state)
        state['status'] = 'complete'
        sink.commit(state)
        return state
    except Exception:
        state['status'] = 'stopped-preserve-state'
        try:
            sink.commit(state)
        except Exception:
            pass
        raise BootstrapStopped('review handover stopped; retain both stores and stage receipts') from None


def compile_review_runtime(root, storage_plan, initialization_plan, *, expected_initialization_sha256,
                           configuration_receipt, expected_configuration_receipt_sha256):
    """Compile an INACTIVE successor render from existing reviewed material.

    No Secret payload, arbitrary image/program, live UID guess, apply or policy
    admission is accepted here. The caller still needs a verified initialization
    completion, full handover plan and separately admitted successor render.
    """
    import json
    from . import case_review_storage as storage
    from . import case_runtime_bootstrap as core
    from . import case_runtime_admission as admission
    storage._initialization_plan(initialization_plan, storage_plan, expected_initialization_sha256)
    receipt = storage._pinned_receipt(configuration_receipt, expected_configuration_receipt_sha256)
    _closed(receipt, {'schemaVersion','planSha256','reference','configurationSha256','nonce','status','uid'}, 'review configuration receipt shape invalid')
    _require(receipt['schemaVersion'] == 'roebel_case_configuration_receipt_v1' and receipt['status'] == 'provisioned' and
             isinstance(receipt['uid'], str) and UUID.fullmatch(receipt['uid']) and
             isinstance(receipt['nonce'], str) and re.fullmatch('[0-9a-f]{64}',receipt['nonce']), 'review configuration has not been provisioned')
    _sha(receipt['configurationSha256']);_sha(receipt['planSha256'])
    ref = {'namespace':storage_plan['source']['pvcNamespace'],'name':'roebel-case-steward-review-runtime-v1','key':'application-json'}
    _require(receipt['reference'] == ref, 'review configuration reference changed')
    verifier = core._verifier()
    verifier.verify_tree(root)
    original = verifier.load_json(root/'reviewed-render/roebel-staging/case-runtime/resources.json')
    candidate = copy.deepcopy(original)
    config = next(o for o in candidate['items'] if o['kind'] == 'ConfigMap' and o['metadata']['name'] == 'roebel-case-steward-control-reviewed')
    config['metadata']['name'] = 'roebel-case-steward-review-reviewed-v1'
    config['data'] = {k:initialization_plan['configMap']['data'][k] for k in ('reviewed-binding.json','storage-marker.json')}
    # Preserve the reviewed application's canonical JSON + newline convention.
    config['data']['reviewed-binding.json'] += '\n'
    binding = initialization_plan['targetBinding']
    deployment = next(o for o in candidate['items'] if o['kind'] == 'Deployment' and o['metadata']['name'] == 'roebel-case-steward-control')
    spec = deployment['spec']['template']['spec']
    runtime, initializer = spec['containers'][0], spec['initContainers'][0]
    runtime['image'] = initializer['image'] = storage.REVIEW_IMAGE
    next(e for e in runtime['env'] if e['name'] == 'STADTSTACK_CASE_CONTROL_BINDING_SHA256')['value'] = binding['bindingChecksum']
    runtime['ports'].append({'name':'admin-review','containerPort':18090,'protocol':'TCP'})
    for container in (runtime, initializer):
        next(m for m in container['volumeMounts'] if m['name'] == 'case-state')['mountPath'] = '/var/lib/stadtstack-review'
    initializer['command'][2] = initializer['command'][2].replace("const root = '/var/lib/stadtstack/case-control';", "const root = '/var/lib/stadtstack-review/case-control';")
    next(e for e in initializer['env'] if e['name'] == 'ROEBEL_CASE_PRIVATE_CONFIG')['valueFrom']['secretKeyRef'] = {'name':ref['name'],'key':ref['key']}
    next(e for e in initializer['env'] if e['name'] == 'ROEBEL_CASE_PRIVATE_CONFIG_SHA256')['value'] = receipt['configurationSha256'].removeprefix('sha256:')
    next(v for v in spec['volumes'] if v['name'] == 'case-state')['persistentVolumeClaim']['claimName'] = storage.TARGET_NAME
    next(v for v in spec['volumes'] if v['name'] == 'reviewed')['configMap']['name'] = config['metadata']['name']
    proposed_flux = verifier.load_json(root/'proposals/synthetic-case-runtime/flux-bootstrap.json')['items']
    original_flux = admission.flux_bootstrap_objects(verifier,root,proposed_flux)
    old_role = next(o for o in original_flux if o['kind'] == 'Role')
    role = copy.deepcopy(old_role)
    next(rule for rule in role['rules'] if rule['resources'] == ['configmaps'])['resourceNames'].append(config['metadata']['name'])
    result = {'schemaVersion':'roebel_review_runtime_candidate_v1','status':'inactive-not-admitted',
              'sourceRenderSha256':canonical_sha256(original),'targetRenderSha256':canonical_sha256(candidate),
              'initializationPlanSha256':expected_initialization_sha256,'configurationReceiptSha256':expected_configuration_receipt_sha256,
              'configurationSecretUid':receipt['uid'],'targetBindingSha256':binding['bindingChecksum'],
              'resources':candidate,'sourceReconcilerRole':old_role,'targetReconcilerRole':role}
    return {**result,'candidateSha256':canonical_sha256(result)}
