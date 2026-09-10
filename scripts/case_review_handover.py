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
              'targetPvUid', 'configurationSecretUid', 'nodeUid', 'mountObserverPodUid'}


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
    for a,b in (('sourcePvcUid','targetPvcUid'), ('sourcePvUid','targetPvUid'), ('sourcePodUid','initializerPodUid'), ('sourcePodUid','mountObserverPodUid'), ('initializerPodUid','mountObserverPodUid')):
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


def advance_source_fence(root, plan, *, expected_plan_sha256, parent_receipt,
                         expected_parent_sha256, transport, sink, verify_ready,
                         prior=None, expected_prior_sha256=None):
    """Concrete GET/JSON-Patch adapter for the coordinator's first stage.

    Only suspend this Case Kustomization and scale its existing control
    Deployment from one to zero. Never delete a Pod, change permissions or
    release the fence. Mount release and the clean seal are later proofs.
    transport.request supports bounded GET and PATCH (JSON Patch), with fixed
    safe errors. verify_ready must recheck the complete handover prerequisites.
    """
    import json
    from . import case_runtime_bootstrap as core
    from . import case_runtime_kubernetes as kube
    validate_plan(plan, expected_plan_sha256)
    parent = _state(plan, parent_receipt, expected_parent_sha256)
    _require(parent['pending'] == 'fence-source' and not parent['completed'] and
             parent['status'] in ('effect-intent','awaiting-evidence','stopped-preserve-state'), 'source fencing requires owned parent intent')
    baseline = core.build_plan(root)
    active = json.loads((root/'reviewed-render/roebel-staging/case-runtime/resources.json').read_text())
    _require(canonical_sha256(active) == plan['pins']['sourceRenderSha256'], 'source fence render drift')
    deployment = next(o['desired'] for o in baseline['objects'] if o['target']['kind'] == 'Deployment' and o['target']['name'] == 'roebel-case-steward-control')
    reconciler = copy.deepcopy(baseline['objects'][-1]['desired']);reconciler['spec']['suspend'] = False
    _require(deployment['spec']['replicas'] == 1 and reconciler['kind'] == 'Kustomization' and
             reconciler['metadata']['name'] == 'roebel-case-runtime', 'source fence inventory drift')
    targets = [('suspend',reconciler,'reconcilerUid','suspend',False,True),
               ('scale-zero',deployment,'sourceDeploymentUid','replicas',1,0)]
    if prior is None:
        _require(expected_prior_sha256 is None, 'source fence orphan recovery pin')
        state = {'schemaVersion':'roebel_review_source_fence_v1','planSha256':expected_plan_sha256,
                 'parentIntentSha256':expected_parent_sha256,'status':'reserved','changes':[],
                 'previousReceiptSha256':None}
    else:
        state = copy.deepcopy(prior);pin = state.pop('canonicalSha256',None)
        _require(pin == expected_prior_sha256 == canonical_sha256(state), 'source fence prior pin mismatch')
        _closed(state, {'schemaVersion','planSha256','parentIntentSha256','status','changes','previousReceiptSha256'}, 'source fence receipt shape invalid')
        _require(state['schemaVersion'] == 'roebel_review_source_fence_v1' and state['planSha256'] == expected_plan_sha256 and
                 state['parentIntentSha256'] == expected_parent_sha256 and state['status'] in ('reserved','patch-intent','awaiting-patch','stopped-preserve-fence','source-fenced') and
                 isinstance(state['changes'],list) and len(state['changes']) <= 2, 'source fence receipt binding invalid')
        for index,record in enumerate(state['changes']):
            _closed(record, {'step','uid','beforeResourceVersion','beforeGeneration','observedResourceVersion'}, 'source fence intent shape invalid')
            _require(record['step'] == targets[index][0] and record['uid'] == plan['identities'][targets[index][2]] and
                     isinstance(record['beforeResourceVersion'],str) and record['beforeResourceVersion'].isdigit() and
                     type(record['beforeGeneration']) is int and record['beforeGeneration'] > 0 and
                     (record['observedResourceVersion'] is None or (isinstance(record['observedResourceVersion'],str) and record['observedResourceVersion'].isdigit())), 'source fence intent invalid')
            _require(record['observedResourceVersion'] is not None or index == len(state['changes'])-1, 'source fence unordered intent')
        _require(state['status'] != 'source-fenced' or len(state['changes']) == 2 and all(r['observedResourceVersion'] for r in state['changes']), 'source fence completion invalid')
        state['previousReceiptSha256'] = pin
    def observed(desired, identity_key, field, allowed):
        current = transport.request('GET',kube.resource_path(core.target(desired)),None)
        _require(isinstance(current,dict) and current.get('metadata',{}).get('uid') == plan['identities'][identity_key], 'source fence UID changed')
        meta = current['metadata']
        _require(isinstance(meta.get('resourceVersion'),str) and meta['resourceVersion'].isdigit() and type(meta.get('generation')) is int and meta['generation'] > 0, 'source fence server identity invalid')
        value = current.get('spec',{}).get(field)
        _require(any(type(value) is type(item) and value == item for item in allowed), 'source fence field drift')
        expected = copy.deepcopy(desired);expected['spec'][field] = value
        clean = copy.deepcopy(current)
        if desired['kind'] == 'Deployment':
            labels = clean['metadata'].get('labels',{})
            for key,wanted in [('kustomize.toolkit.fluxcd.io/name','roebel-case-runtime'),('kustomize.toolkit.fluxcd.io/namespace',kube.FLUX)]:
                if key in labels:
                    _require(labels.pop(key) == wanted, 'source fence Flux ownership drift')
        _require(kube.normalize(clean) == kube.normalize(expected), 'source fence workload semantics changed')
        return current
    def fresh():
        _require(_utc(plan['notBeforeUtc']) <= datetime.now(timezone.utc) < _utc(plan['expiresAtUtc']), 'source fence window closed')
        verify_ready(copy.deepcopy(plan), copy.deepcopy(state))
        cluster = transport.request('GET','/api/v1/namespaces/kube-system',None)
        _require(cluster and cluster.get('metadata',{}).get('uid') == plan['identities']['clusterUid'] == kube.CLUSTER_UID, 'source fence cluster mismatch')
    sink.commit(state)
    try:
        for index,(step,desired,identity,field,before,after) in enumerate(targets):
            fresh()
            if index:
                flux = observed(reconciler,'reconcilerUid','suspend',[True])
                if any(c.get('type') == 'Reconciling' and c.get('status') == 'True' for c in flux.get('status',{}).get('conditions',[])):
                    state['status'] = 'awaiting-patch';sink.commit(state);return state
            record = state['changes'][index] if index < len(state['changes']) else None
            current = observed(desired,identity,field,[before,after] if record else [before])
            if record is None:
                record = {'step':step,'uid':current['metadata']['uid'],'beforeResourceVersion':current['metadata']['resourceVersion'],
                          'beforeGeneration':current['metadata']['generation'],'observedResourceVersion':None}
                state['changes'].append(record);state['status'] = 'patch-intent';sink.commit(state)
                fresh()
                patch = [{'op':'test','path':'/metadata/uid','value':record['uid']},
                         {'op':'test','path':'/metadata/resourceVersion','value':record['beforeResourceVersion']},
                         {'op':'test','path':'/spec/'+field,'value':before},
                         {'op':'replace','path':'/spec/'+field,'value':after}]
                try:
                    transport.request('PATCH',kube.resource_path(core.target(desired)),patch)
                except Exception:
                    pass  # uncertain write: inspect once, never send it again
                current = observed(desired,identity,field,[before,after])
            if current['spec'][field] == before:
                _require(record['observedResourceVersion'] is None, 'completed source fence regressed')
                state['status'] = 'awaiting-patch';sink.commit(state);return state
            _require(current['metadata']['generation'] == record['beforeGeneration']+1, 'source fence generation drift')
            if record['observedResourceVersion'] is None:
                record['observedResourceVersion'] = current['metadata']['resourceVersion'];sink.commit(state)
        fresh()
        flux = observed(reconciler,'reconcilerUid','suspend',[True])
        if any(c.get('type') == 'Reconciling' and c.get('status') == 'True' for c in flux.get('status',{}).get('conditions',[])):
            state['status'] = 'awaiting-patch';sink.commit(state);return state
        observed(deployment,'sourceDeploymentUid','replicas',[0])
        state['status'] = 'source-fenced';sink.commit(state)
        return state
    except Exception:
        state['status'] = 'stopped-preserve-fence'
        try:
            sink.commit(state)
        except Exception:
            pass
        raise BootstrapStopped('source fencing stopped; inspect owned intents without replay or automatic resume') from None


def observe_mount_release(root, plan, *, expected_plan_sha256, transport, node_filesystem, verify_ready):
    """Read-only API + host filesystem proof for the two released RWOP mounts.

    node_filesystem(node_name, node_uid) must use the pinned node transport and
    return complete host /proc/1/mountinfo plus /var/lib/kubelet/pods directory
    names. A separately pinned, still-running Pod on that node is a positive
    control. API absence alone, an empty host response or a vanished observer
    cannot produce a release receipt. This helper never retires a Pod itself.
    """
    import json
    from . import case_runtime_kubernetes as kube
    validate_plan(plan,expected_plan_sha256)
    ids = plan['identities']
    binding = json.loads((root/'proposals/synthetic-case-runtime/control-binding.json').read_text())
    body = dict(binding);binding_pin = body.pop('bindingChecksum')
    _require(binding_pin == plan['pins']['sourceBindingSha256'] == canonical_sha256(body), 'mount observation source binding drift')
    source = binding['storage']
    _require(source['pvcUid'] == ids['sourcePvcUid'], 'mount observation source claim mismatch')
    def api_observation():
        verify_ready(copy.deepcopy(plan))
        cluster=transport.request('GET','/api/v1/namespaces/kube-system',None)
        _require(cluster and cluster.get('metadata',{}).get('uid') == ids['clusterUid'] == kube.CLUSTER_UID, 'mount observation cluster drift')
        for name,identity in ((source['pvcName'],'sourcePvcUid'),('roebel-case-steward-review-state-v1','targetPvcUid')):
            claim=transport.request('GET',f'/api/v1/namespaces/{kube.NAMESPACE}/persistentvolumeclaims/{name}',None)
            _require(claim and claim.get('metadata',{}).get('uid') == ids[identity] and not claim['metadata'].get('deletionTimestamp') and
                     claim.get('spec',{}).get('accessModes') == ['ReadWriteOncePod'] and claim.get('status',{}).get('phase') == 'Bound', 'mount observation retained claim drift')
        pods=transport.request('GET',f'/api/v1/namespaces/{kube.NAMESPACE}/pods',None)
        _require(isinstance(pods,dict) and isinstance(pods.get('items'),list) and not pods.get('metadata',{}).get('continue') and pods.get('metadata',{}).get('remainingItemCount') in (None,0), 'mount observation Pod list invalid')
        observer=[p for p in pods['items'] if p.get('metadata',{}).get('uid') == ids['mountObserverPodUid']]
        _require(len(observer) == 1, 'mount observation positive control missing')
        observer=observer[0]
        _require(observer.get('status',{}).get('phase') == 'Running' and not observer['metadata'].get('deletionTimestamp') and
                 any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in observer['status'].get('conditions',[])), 'mount observation positive control not ready')
        node_name=observer.get('spec',{}).get('nodeName')
        _require(isinstance(node_name,str) and re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,252}',node_name), 'mount observation node name invalid')
        node=transport.request('GET','/api/v1/nodes/'+node_name,None)
        _require(node and node.get('metadata',{}).get('uid') == ids['nodeUid'] and not node['metadata'].get('deletionTimestamp'), 'mount observation node identity drift')
        blocked=[]
        for pod in pods['items']:
            pod_uid=pod.get('metadata',{}).get('uid')
            claims={v.get('persistentVolumeClaim',{}).get('claimName') for v in pod.get('spec',{}).get('volumes',[])}
            if pod_uid in (ids['sourcePodUid'],ids['initializerPodUid']) or claims & {source['pvcName'],'roebel-case-steward-review-state-v1'}:
                blocked.append(pod_uid)
        return node_name,blocked
    node_name,blocked=api_observation()
    if blocked:return None
    view=node_filesystem(node_name,ids['nodeUid'])
    _closed(view, {'mountInfo','podDirectoryNames'}, 'host mount observation shape invalid')
    text,names=view['mountInfo'],view['podDirectoryNames']
    _require(isinstance(text,str) and 0 < len(text.encode()) <= 4*1024*1024 and
             isinstance(names,list) and len(names) <= 10000 and
             all(isinstance(n,str) and UUID.fullmatch(n) for n in names) and len(names) == len(set(names)), 'host mount observation invalid')
    prefix='/var/lib/kubelet/pods/'
    def mounted(uid):
        return re.search(re.escape(prefix+uid)+r'(?:/|\s)',text) is not None
    _require(mounted(ids['mountObserverPodUid']) and ids['mountObserverPodUid'] in names, 'host mount view has no positive control')
    if any(mounted(ids[key]) or ids[key] in names for key in ('sourcePodUid','initializerPodUid')):
        return None
    after,blocked=api_observation()
    _require(after == node_name, 'mount observation node changed during read')
    if blocked:return None
    evidence={'sourcePodUid':ids['sourcePodUid'],'initializerPodUid':ids['initializerPodUid'],'nodeUid':ids['nodeUid'],
              'sourceApiAbsent':True,'initializerApiAbsent':True,'sourceMountAbsent':True,'initializerMountAbsent':True,'positiveControlVerified':True}
    receipt={'schemaVersion':'roebel_review_mount_release_v1','planSha256':expected_plan_sha256,
             'mountObserverPodUid':ids['mountObserverPodUid'],'nodeName':node_name,
             'hostViewSha256':canonical_sha256(view),'observedAtUtc':datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z'),'evidence':evidence}
    return {**receipt,'canonicalSha256':canonical_sha256(receipt)}
