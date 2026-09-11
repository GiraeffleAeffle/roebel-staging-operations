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


def encrypt_and_verify_case_backup(*, capture, expected_capture_sha256, archive_path,
                                   output_directory, age_binary, expected_age_sha256,
                                   recipient, identity_path, expected_verification_request_sha256,
                                   verify_restored):
    """Encrypt an owned capture and verify a *decrypted* restore with the runtime.

    verify_restored(path, archive_sha256) invokes the fixed-image descriptor
    operator's verify-backup mode and returns its private result envelope. It
    must bind the independently pinned verification request and actual image.
    This host operation only writes a fresh local directory. It cannot stop a
    workload, mount a volume, import a Case or manufacture runtime validation.
    Ciphertext and a private completion receipt are retained. The temporary
    decrypted archive is removed even on failure; caller owns the input archive.
    """
    import hashlib
    import os
    from pathlib import Path
    import stat
    import subprocess
    from .staging_participant_flux_bootstrap import ReceiptSink

    limit = 64 * 1024 * 1024
    def envelope(value, expected, mode):
        _closed(value, {'schemaVersion','mode','requestSha256','sourceRevision','controlImageDigest',
                       'sourceConfigurationSha256','targetConfigurationSha256','result','resultSha256'},
                'backup runtime result shape invalid')
        _sha(expected)
        _require(value['resultSha256'] == expected == canonical_sha256({k:v for k,v in value.items() if k != 'resultSha256'}) and
                 value['schemaVersion'] == 'roebel_case_review_migration_result_v1' and value['mode'] == mode and
                 value['sourceRevision'] == 'fdb0b7f36c33d925be141d8e9037b48d17612df8' and
                 value['controlImageDigest'] == 'sha256:5f0eeec46e1e00150ce5f370ba9749a0f4d6d652dac73839f25699771adb1d60',
                 'backup runtime result pin mismatch')
    envelope(capture, expected_capture_sha256, 'capture-backup')
    expected_fields = {'sourceSealChecksum','sourceDeploymentClaimChecksum','sourceDatabaseSha256',
                       'sourceFilesSha256','caseId','caseVersion','admissionReceiptChecksum','archiveSha256'}
    facts = capture['result']
    _closed(facts, expected_fields, 'backup capture evidence invalid')
    for key,value in facts.items():
        if key.endswith(('Checksum','Sha256')): _sha(value)
    _require(type(facts['caseVersion']) is int and facts['caseVersion'] == 3, 'backup Case version invalid')
    _sha(expected_verification_request_sha256)
    _sha(expected_age_sha256)
    _require(isinstance(recipient, str) and re.fullmatch(r'age1[0-9a-z]{58}', recipient), 'backup requires one explicit age recipient')
    binary = Path(age_binary)
    _require(binary.is_absolute() and binary.resolve() == binary and binary.is_file() and
             'sha256:'+hashlib.sha256(binary.read_bytes()).hexdigest() == expected_age_sha256,
             'backup age binary pin mismatch')

    def private_file(path):
        path = Path(path)
        _require(path.is_absolute() and path.resolve() == path, 'backup private path is not canonical')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        info = os.fstat(fd)
        if not (stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and
                info.st_uid == os.getuid() and info.st_nlink == 1 and 0 < info.st_size <= limit):
            os.close(fd)
            raise BootstrapStopped('backup private input invalid')
        return fd
    def file_hash(fd):
        os.lseek(fd, 0, os.SEEK_SET); digest = hashlib.sha256(); total = 0
        while block := os.read(fd, 1024 * 1024):
            total += len(block)
            _require(total <= limit + 1024 * 1024, 'backup exceeds bounded size')
            digest.update(block)
        os.lseek(fd, 0, os.SEEK_SET)
        return 'sha256:'+digest.hexdigest()
    def retained(path, fd):
        actual, opened = os.lstat(path), os.fstat(fd)
        _require(stat.S_ISREG(actual.st_mode) and stat.S_IMODE(actual.st_mode) == 0o600 and
                 actual.st_uid == os.getuid() and actual.st_nlink == 1 and
                 (actual.st_dev,actual.st_ino) == (opened.st_dev,opened.st_ino), 'backup retained file replaced')

    descriptors = []
    decrypted = None
    try:
        archive_fd = private_file(archive_path); descriptors.append(archive_fd)
        identity_fd = private_file(identity_path); descriptors.append(identity_fd)
        _require(os.fstat(archive_fd).st_ino != os.fstat(identity_fd).st_ino or
                 os.fstat(archive_fd).st_dev != os.fstat(identity_fd).st_dev, 'backup input alias')
        _require(file_hash(archive_fd) == facts['archiveSha256'], 'backup captured archive changed')
        output = Path(output_directory)
        _require(output.is_absolute() and output.parent.resolve() == output.parent, 'backup output parent is not canonical')
        output.mkdir(mode=0o700, exist_ok=False)
        cipher = output/'case-backup.age'
        decrypted = output/'restored.archive'
        cipher_fd = os.open(cipher, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600); descriptors.append(cipher_fd)
        def run(arguments, source_fd, target_fd, pass_fds=()):
            _require('sha256:'+hashlib.sha256(binary.read_bytes()).hexdigest() == expected_age_sha256, 'backup age binary changed')
            result = subprocess.run([str(binary), *arguments], stdin=source_fd, stdout=target_fd,
                                    stderr=subprocess.PIPE, pass_fds=pass_fds, timeout=120,
                                    env={'PATH':'/usr/bin:/bin','LC_ALL':'C'}, check=False)
            _require(result.returncode == 0, 'backup encryption or decryption failed')
            os.fsync(target_fd); os.lseek(target_fd, 0, os.SEEK_SET)
        run(['--encrypt','--recipient',recipient], archive_fd, cipher_fd)
        encrypted_sha = file_hash(cipher_fd)
        _require(os.fstat(cipher_fd).st_size > 0 and encrypted_sha != facts['archiveSha256'], 'backup ciphertext missing')
        restored_fd = os.open(decrypted, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600); descriptors.append(restored_fd)
        run(['--decrypt','--identity',f'/dev/fd/{identity_fd}'], cipher_fd, restored_fd, (identity_fd,))
        _require(file_hash(restored_fd) == facts['archiveSha256'] == file_hash(archive_fd), 'backup decrypt did not reproduce capture')
        verified = verify_restored(decrypted, facts['archiveSha256'])
        envelope(verified, verified.get('resultSha256'), 'verify-backup')
        _require(verified['requestSha256'] == expected_verification_request_sha256 and
                 all(verified[key] == capture[key] for key in ('sourceConfigurationSha256','targetConfigurationSha256')),
                 'backup verification request changed')
        restored = verified['result']
        _closed(restored, expected_fields | {'restoredFilesSha256','restoredCandidateChecksum'}, 'backup restore evidence invalid')
        _sha(restored['restoredCandidateChecksum'])
        _require(all(restored[key] == value for key,value in facts.items()) and restored['restoredFilesSha256'] == facts['sourceFilesSha256'] and
                 file_hash(restored_fd) == facts['archiveSha256'] and file_hash(cipher_fd) == encrypted_sha and
                 file_hash(archive_fd) == facts['archiveSha256'], 'backup restore or retained ciphertext changed')
        retained(cipher,cipher_fd); retained(decrypted,restored_fd); retained(archive_path,archive_fd)
        record = {'schemaVersion':'roebel_encrypted_case_backup_receipt_v1', 'ageBinarySha256':expected_age_sha256,
                  'captureResultSha256':expected_capture_sha256,'verificationResultSha256':verified['resultSha256'],
                  'encryptedArchiveSha256':encrypted_sha, **restored}
        sink = ReceiptSink.reserve(output/'backup-verified.json')
        sink.commit(record)
        return record | {'receiptSha256':canonical_sha256(record)}
    except Exception:
        raise BootstrapStopped('Case backup stopped; retain the source and owned encrypted artifacts') from None
    finally:
        for fd in descriptors: os.close(fd)
        if decrypted is not None: decrypted.unlink(missing_ok=True)

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


def compile_migration_worker(root, plan, *, expected_plan_sha256, candidate,
                             expected_candidate_sha256, node_name):
    """Inactive, fixed-image worker for the already ordered handover stages.

    Its two mounts permit the public runtime's ownership locks. No command
    starts automatically beyond copying pinned private configuration to tmpfs.
    The live Adapter must verify Pod/node/claim UIDs and parent stage receipts
    before each descriptor invocation; this compiler grants no live authority.
    """
    import json
    from . import case_runtime_bootstrap as core, case_review_storage as storage
    validate_plan(plan, expected_plan_sha256)
    _require(candidate.get('candidateSha256') == expected_candidate_sha256 ==
             canonical_sha256({k:v for k,v in candidate.items() if k != 'candidateSha256'}) and
             candidate.get('schemaVersion') == 'roebel_review_runtime_candidate_v1', 'migration worker candidate changed')
    _require(isinstance(node_name, str) and re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', node_name), 'migration node name invalid')
    for name in ('sourceRenderSha256','targetRenderSha256','targetBindingSha256'):
        _require(candidate[name] == plan['pins'][name], 'migration worker render pin changed')
    _require(candidate['configurationSecretUid'] == plan['identities']['configurationSecretUid'] and
             canonical_sha256(candidate['resources']) == plan['pins']['targetRenderSha256'] and
             plan['pins']['migrationImageDigest'] == storage.REVIEW_IMAGE.split('@')[1], 'migration worker runtime identity changed')
    core._verifier().verify_tree(root)
    original = json.loads((root/'reviewed-render/roebel-staging/case-runtime/resources.json').read_text())
    binding = json.loads((root/'proposals/synthetic-case-runtime/control-binding.json').read_text())
    _require(canonical_sha256(original) == plan['pins']['sourceRenderSha256'] and
             binding['bindingChecksum'] == plan['pins']['sourceBindingSha256'] and
             binding['storage']['pvcUid'] == plan['identities']['sourcePvcUid'], 'migration worker source changed')
    def control(items):
        return next(o for o in items if o['kind']=='Deployment' and o['metadata']['name']=='roebel-case-steward-control')['spec']['template']['spec']
    old, new = control(original['items']), control(candidate['resources']['items'])
    target_map = next(o for o in candidate['resources']['items'] if o['kind']=='ConfigMap' and o['metadata']['name']=='roebel-case-steward-review-reviewed-v1')
    target_binding = json.loads(target_map['data']['reviewed-binding.json'])
    _require(target_binding['bindingChecksum'] == plan['pins']['targetBindingSha256'] and
             target_binding['storage']['pvcUid'] == plan['identities']['targetPvcUid'] and
             target_binding['storage']['rootDir'] == '/var/lib/stadtstack-review/case-control' and
             binding['storage']['rootDir'] == '/var/lib/stadtstack/case-control', 'migration worker target changed')
    refs = []
    for spec, pin in ((old, plan['pins']['sourceConfigurationSha256']), (new, plan['pins']['targetConfigurationSha256'])):
        env = spec['initContainers'][0]['env']
        _require(next(e['value'] for e in env if e['name']=='ROEBEL_CASE_PRIVATE_CONFIG_SHA256') == pin.removeprefix('sha256:'),
                 'migration worker configuration pin changed')
        refs.append(next(e['valueFrom']['secretKeyRef'] for e in env if e['name']=='ROEBEL_CASE_PRIVATE_CONFIG'))
    name = 'roebel-case-review-migration-v1'
    label = {'stadtstack.io/review-migration':plan['operationId'][:32]}
    meta = {'name':name,'namespace':binding['storage']['pvcNamespace'],'labels':label,
            'annotations':{'stadtstack.io/review-handover-plan':plan['planSha256']}}
    # Secret volumes are read-only and non-public. Copy their bytes once into
    # owned 0600 files: the descriptor operator rejects Kubernetes symlinks and
    # group-readable inputs. Never put their payloads in an environment or log.
    entry = """import {createHash} from 'node:crypto';
import {mkdirSync,readFileSync,openSync,writeSync,fsyncSync,closeSync} from 'node:fs';
try {
 process.umask(0o077); mkdirSync('/work/private',{mode:0o700});
 const expected = EXPECTED;
 for (const name of ['source','target']) {
  const bytes=readFileSync('/'+name+'-configuration/application.json');
  if(bytes.length<1 || bytes.length>1048576 || 'sha256:'+createHash('sha256').update(bytes).digest('hex')!==expected[name]) throw Error();
  const fd=openSync('/work/private/'+name+'.json','wx',0o600);
  try {let offset=0;while(offset<bytes.length){const n=writeSync(fd,bytes,offset,bytes.length-offset);if(n<1)throw Error();offset+=n;}fsyncSync(fd);} finally {closeSync(fd);}
 }
 const fd=openSync('/work/private','r');try{fsyncSync(fd);}finally{closeSync(fd);}
 console.log('review-migration-worker-ready');
 process.on('SIGTERM',()=>process.exit(0)); setInterval(()=>{},1000);
} catch {console.error('review_migration_worker_stopped');process.exitCode=78;}
""".replace('EXPECTED', json.dumps(dict(zip(('source','target'),(plan['pins']['sourceConfigurationSha256'],plan['pins']['targetConfigurationSha256']))),sort_keys=True))
    programs = {file:(root/'scripts'/file).read_text() for file in ('run-case-review-migration.mjs','case_review_backup.mjs')}
    programs['worker-entry.mjs'] = entry
    config = {'apiVersion':'v1','kind':'ConfigMap','metadata':copy.deepcopy(meta),'immutable':True,'data':programs}
    volumes = [{'name':'source-state','persistentVolumeClaim':{'claimName':binding['storage']['pvcName']}},
               {'name':'target-state','persistentVolumeClaim':{'claimName':target_binding['storage']['pvcName']}},
               {'name':'reviewed','configMap':{'name':name,'defaultMode':0o444}},
               {'name':'work','emptyDir':{'medium':'Memory','sizeLimit':'512Mi'}}]
    mounts = [{'name':'source-state','mountPath':'/var/lib/stadtstack','readOnly':False},
              {'name':'target-state','mountPath':'/var/lib/stadtstack-review','readOnly':False},
              {'name':'reviewed','mountPath':'/reviewed','readOnly':True},
              {'name':'work','mountPath':'/work','readOnly':False}]
    for side, ref in zip(('source','target'), refs):
        volumes.append({'name':side+'-configuration','secret':{'secretName':ref['name'],'defaultMode':0o440,
                        'items':[{'key':ref['key'],'path':'application.json'}]}})
        mounts.append({'name':side+'-configuration','mountPath':'/'+side+'-configuration','readOnly':True})
    container = {'name':'migration','image':storage.REVIEW_IMAGE,'imagePullPolicy':'IfNotPresent',
                 'command':['node','/reviewed/worker-entry.mjs'],'env':[{'name':'TMPDIR','value':'/work/private'},
                         {'name':'ROEBEL_REVIEW_WORKER_UID','valueFrom':{'fieldRef':{'apiVersion':'v1','fieldPath':'metadata.uid'}}}],
                 'securityContext':copy.deepcopy(old['containers'][0]['securityContext']),
                 'resources':{'requests':{'cpu':'100m','memory':'256Mi'},'limits':{'cpu':'1','memory':'1Gi'}},'volumeMounts':mounts}
    pod = {'apiVersion':'v1','kind':'Pod','metadata':copy.deepcopy(meta), 'spec':{
        'automountServiceAccountToken':False,'enableServiceLinks':False,'restartPolicy':'Never','activeDeadlineSeconds':3600,
        'terminationGracePeriodSeconds':30,'nodeSelector':{'kubernetes.io/hostname':node_name},
        'securityContext':copy.deepcopy(old['securityContext']),'containers':[container],'volumes':volumes}}
    policy = {'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy','metadata':copy.deepcopy(meta),
              'spec':{'podSelector':{'matchLabels':label},'policyTypes':['Ingress','Egress'],'ingress':[],'egress':[]}}
    result = {'schemaVersion':'roebel_review_migration_worker_v1','status':'inactive-not-admitted',
              'handoverPlanSha256':plan['planSha256'],'candidateSha256':expected_candidate_sha256,
              'nodeUid':plan['identities']['nodeUid'],'nodeName':node_name,'networkPolicy':policy,'configMap':config,'pod':pod}
    return result | {'workerSha256':canonical_sha256(result)}


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


class KubectlReviewWorkerTransport:
    """Fixed worker exec, guarded by ordered parent intent and live ownership.

    runner/snapshot are the existing verified executable and kubeconfig ports.
    verify_ready must verify the complete handover, active stage and private
    configuration receipts; this transport cannot authorize its own effects.
    Archive/result output goes only to an owned, empty private descriptor.
    """
    def __init__(self, root, plan, worker, *, expected_plan_sha256, expected_worker_sha256,
                 pod_uid, runner, snapshot, verify_ready, candidate, expected_candidate_sha256, clock=None):
        validate_plan(plan, expected_plan_sha256)
        _require(worker.get('workerSha256') == expected_worker_sha256 == canonical_sha256(
            {k:v for k,v in worker.items() if k != 'workerSha256'}), 'worker compiler pin changed')
        _require(worker.get('handoverPlanSha256') == expected_plan_sha256 and
                 worker.get('nodeUid') == plan['identities']['nodeUid'] and UUID.fullmatch(pod_uid), 'worker identity pin invalid')
        from . import case_runtime_kubernetes as kube
        _require(worker['pod']['metadata']['namespace'] == kube.NAMESPACE and
                 worker['pod']['metadata']['name'] == 'roebel-case-review-migration-v1' and
                 worker['pod']['spec']['containers'][0]['image'].endswith('@'+plan['pins']['migrationImageDigest']), 'worker target changed')
        _require(worker == compile_migration_worker(root,plan,expected_plan_sha256=expected_plan_sha256,
                 candidate=candidate,expected_candidate_sha256=expected_candidate_sha256,node_name=worker['nodeName']), 'worker differs from fixed compiler')
        self.root,self.plan,self.worker = root,copy.deepcopy(plan),copy.deepcopy(worker)
        self.pod_uid,self.runner,self.snapshot = pod_uid,runner,snapshot
        self.verify_ready,self.clock = verify_ready,clock or (lambda:datetime.now(timezone.utc))
        self.base=['kubectl','--kubeconfig',str(snapshot.path),'--request-timeout=20s']
        self.namespace=kube.NAMESPACE

    def _get(self, path):
        import json
        result=self.runner.run(self.base+['get','--raw',path],timeout=25)
        _require(result.code == 0 and len(result.out.encode()) <= 4*1024*1024,'worker ownership read failed')
        try:return json.loads(result.out)
        except (TypeError,ValueError):raise BootstrapStopped('worker ownership response invalid') from None

    def _ownership(self):
        from . import case_review_storage as storage, case_runtime_kubernetes as kube
        p,ids=self.plan,self.plan['identities'];ns=self.namespace
        cluster=self._get('/api/v1/namespaces/kube-system')
        _require(cluster.get('metadata',{}).get('uid') == ids['clusterUid'] == kube.CLUSTER_UID,'worker cluster changed')
        node=self._get('/api/v1/nodes/'+self.worker['nodeName'])
        _require(node.get('metadata',{}).get('uid') == ids['nodeUid'] and not node['metadata'].get('deletionTimestamp'),'worker node changed')
        desired=self.worker['pod'];name=desired['metadata']['name']
        pod=self._get(f'/api/v1/namespaces/{ns}/pods/{name}')
        _require(storage._consumer_object(pod,desired)['uid'] == self.pod_uid and
                 pod['spec'].get('nodeName') == self.worker['nodeName'] and pod.get('status',{}).get('phase') == 'Running','worker Pod changed')
        statuses=pod['status'].get('containerStatuses',[])
        _require(len(statuses)==1 and statuses[0].get('name')=='migration' and statuses[0].get('ready') is True and
                 statuses[0].get('restartCount') == 0 and statuses[0].get('imageID','').removeprefix('containerd://').removeprefix('docker-pullable://').split('@')[-1] == p['pins']['migrationImageDigest'], 'worker container identity changed')
        for key,path in [('configMap',f'/api/v1/namespaces/{ns}/configmaps/{name}'),
                         ('networkPolicy',f'/apis/networking.k8s.io/v1/namespaces/{ns}/networkpolicies/{name}')]:
            storage._consumer_object(self._get(path),self.worker[key])
        for side,name in [('source','roebel-case-steward-control-state'),('target','roebel-case-steward-review-state-v1')]:
            claim=self._get(f'/api/v1/namespaces/{ns}/persistentvolumeclaims/{name}')
            meta,spec=claim.get('metadata',{}),claim.get('spec',{})
            _require(meta.get('uid') == ids[side+'PvcUid'] and not meta.get('deletionTimestamp') and
                     spec.get('accessModes') == ['ReadWriteOncePod'] and claim.get('status',{}).get('phase') == 'Bound','worker claim changed')
            volume_name=spec.get('volumeName')
            _require(isinstance(volume_name,str) and re.fullmatch('[a-z0-9][a-z0-9.-]{0,252}',volume_name),'worker PV path invalid')
            volume=self._get('/api/v1/persistentvolumes/'+volume_name)
            _require(volume.get('metadata',{}).get('uid') == ids[side+'PvUid'] and not volume['metadata'].get('deletionTimestamp') and
                     volume.get('spec',{}).get('persistentVolumeReclaimPolicy') == 'Retain' and
                     volume['spec'].get('claimRef',{}).get('uid') == ids[side+'PvcUid'],'worker retained volume changed')
        deployment=self._get(f'/apis/apps/v1/namespaces/{ns}/deployments/roebel-case-steward-control')
        flux=self._get('/apis/kustomize.toolkit.fluxcd.io/v1/namespaces/flux-roebel-staging/kustomizations/roebel-case-runtime')
        _require(deployment.get('metadata',{}).get('uid') == ids['sourceDeploymentUid'] and not deployment['metadata'].get('deletionTimestamp') and
                 type(deployment.get('spec',{}).get('replicas')) is int and deployment['spec']['replicas']==0 and
                 flux.get('metadata',{}).get('uid') == ids['reconcilerUid'] and not flux['metadata'].get('deletionTimestamp') and flux.get('spec',{}).get('suspend') is True and
                 not any(c.get('type')=='Reconciling' and c.get('status')=='True' for c in flux.get('status',{}).get('conditions',[])), 'source fence no longer held')
        pods=self._get(f'/api/v1/namespaces/{ns}/pods')
        _require(isinstance(pods.get('items'),list) and not pods.get('metadata',{}).get('continue') and
                 pods.get('metadata',{}).get('remainingItemCount') in (None,0),'worker Pod inventory incomplete')
        for item in pods['items']:
            if item.get('metadata',{}).get('uid') == self.pod_uid:continue
            _require(item.get('metadata',{}).get('uid') not in (ids['sourcePodUid'],ids['initializerPodUid']) and
                     not any(v.get('persistentVolumeClaim',{}).get('claimName') in ('roebel-case-steward-control-state','roebel-case-steward-review-state-v1')
                             for v in item.get('spec',{}).get('volumes',[])), 'another Pod still holds a migration claim')
        return pod['metadata']['resourceVersion']

    def exchange(self, action, request_bytes, *, request_sha256, parent_receipt,
                 expected_parent_sha256, archive_bytes=None, output_fd=None, expected_archive_sha256=None):
        import hashlib,json,os,stat
        try:
            _require(action in ('invoke','result','archive','upload-archive') and isinstance(request_bytes,bytes) and
                     0<len(request_bytes)<=1048576 and 'sha256:'+hashlib.sha256(request_bytes).hexdigest()==request_sha256,'worker request bytes changed')
            request=json.loads(request_bytes)
            state=_state(self.plan,parent_receipt,expected_parent_sha256)
            stage={'capture-backup':'verify-backup','verify-backup':'verify-backup','prepare':'prepare-migration','activate':'activate-migration'}.get(request.get('mode'))
            _require(stage and state['pending']==stage and len(state['completed'])==STEPS.index(stage) and
                     state['status'] in ('effect-intent','awaiting-evidence','stopped-preserve-state'),'worker command lacks ordered parent intent')
            _require(_utc(self.plan['notBeforeUtc']) <= self.clock() < _utc(self.plan['expiresAtUtc']),'worker handover window expired')
            _require(request.get('schemaVersion')=='roebel_case_review_migration_request_v1' and request.get('sourceRevision')=='fdb0b7f36c33d925be141d8e9037b48d17612df8','worker source revision changed')
            for name in ('caseId',):_require(request.get(name)==self.plan[name],'worker Case changed')
            for name in ('sourceConfigurationSha256','targetConfigurationSha256','admissionReceiptChecksum'):
                _require(request.get(name)==self.plan['pins'][name],'worker request binding changed')
            _require(request.get('sourceRootDir')=='/var/lib/stadtstack/case-control' and
                     request.get('controlImageDigest')==self.plan['pins']['migrationImageDigest'] and
                     request.get('targetBinding',{}).get('bindingChecksum')==self.plan['pins']['targetBindingSha256'],'worker runtime binding changed')
            previous={r['step']:r['evidence'] for r in state['completed']}
            if stage in ('prepare-migration','activate-migration'):
                _require(request.get('sourceSealChecksum')==previous['verify-backup']['sourceSealChecksum'],'worker source seal changed')
            if stage=='activate-migration':
                migration=request.get('migrationPlan',{})
                _require(migration.get('planChecksum')==canonical_sha256({k:v for k,v in migration.items() if k!='planChecksum'}) and
                         migration.get('caseId')==self.plan['caseId'] and migration.get('deploymentEnvironment')=='staging' and
                         migration.get('candidateChecksum')==previous['prepare-migration']['candidateChecksum'] and
                         migration.get('sourceDeploymentClaimChecksum')==previous['verify-backup']['sourceDeploymentClaimChecksum'] and
                         migration.get('targetDeploymentClaimChecksum')==self.plan['pins']['targetDeploymentClaimChecksum'] and
                         _utc(self.plan['notBeforeUtc']) <= _utc(migration.get('notBeforeUtc')) <= self.clock() <
                         _utc(migration.get('expiresAtUtc')) <= _utc(self.plan['expiresAtUtc']), 'activation request differs from prepared handover')
            if action=='archive':
                _require(request['mode']=='capture-backup','archive read outside capture');_sha(expected_archive_sha256)
            else:_require(expected_archive_sha256 is None,'unexpected archive output pin')
            if action=='upload-archive':
                _require(request['mode']=='verify-backup' and isinstance(archive_bytes,bytes) and 0<len(archive_bytes)<=64*1024*1024 and
                         'sha256:'+hashlib.sha256(archive_bytes).hexdigest()==request.get('archiveSha256'),'restore archive changed')
            else:_require(archive_bytes is None,'unexpected archive input')
            output_stat=None
            if action in ('result','archive'):
                _require(type(output_fd) is int and output_fd>=3,'private output descriptor required')
                output_stat=os.fstat(output_fd)
                _require(stat.S_ISREG(output_stat.st_mode) and stat.S_IMODE(output_stat.st_mode)==0o600 and
                         output_stat.st_uid==os.getuid() and output_stat.st_nlink==1 and output_stat.st_size==0,'worker output is not fresh/private')
            else:_require(output_fd is None,'unexpected output descriptor')
            self.verify_ready(copy.deepcopy(self.plan),copy.deepcopy(state),copy.deepcopy(request))
            self._ownership()
            pin=request['archiveSha256'] if action=='upload-archive' else request_sha256
            input_bytes=request_bytes if action=='invoke' else archive_bytes if action=='upload-archive' else None
            command=self.base+['exec','-n',self.namespace,'roebel-case-review-migration-v1','-c','migration']
            if input_bytes is not None:command+=['-i']
            command+=['--','node','/reviewed/run-case-review-migration.mjs','--worker-'+action,pin,'--expected-worker-uid',self.pod_uid]
            _require(_utc(self.plan['notBeforeUtc']) <= self.clock() < _utc(self.plan['expiresAtUtc']),'worker handover window expired before exec')
            result=self.runner.run(command,input_text=input_bytes.decode('utf-8') if input_bytes is not None else None,timeout=60)
            self._ownership()
            self.verify_ready(copy.deepcopy(self.plan),copy.deepcopy(state),copy.deepcopy(request))
            _require(self.clock() < _utc(self.plan['expiresAtUtc']),'worker result arrived after handover window')
            limit=64*1024*1024 if action=='archive' else 1048576 if action=='result' else 4096
            _require(result.code==0 and len(result.out.encode())<=limit,'worker outcome unresolved; observe retained result, do not resend')
            data=result.out.encode('utf-8')
            if output_stat is not None:
                current=os.fstat(output_fd)
                _require((current.st_dev,current.st_ino,current.st_mode,current.st_uid,current.st_nlink,current.st_size)==
                         (output_stat.st_dev,output_stat.st_ino,output_stat.st_mode,output_stat.st_uid,1,0),'private output descriptor changed')
                if action=='archive':_require('sha256:'+hashlib.sha256(data).hexdigest()==expected_archive_sha256,'captured archive bytes changed')
                if action=='result':
                    record=json.loads(data);body={k:v for k,v in record.items() if k!='resultSha256'}
                    _require(record.get('resultSha256')==canonical_sha256(body) and record.get('requestSha256')==request_sha256 and
                             record.get('mode')==request['mode'] and record.get('schemaVersion')=='roebel_case_review_migration_result_v1' and
                             record.get('controlImageDigest')==request['controlImageDigest'] and
                             all(record.get(k)==request.get(k) for k in ('sourceRevision','sourceConfigurationSha256','targetConfigurationSha256')),'worker result link changed')
                offset=0
                while offset<len(data):
                    n=os.pwrite(output_fd,data[offset:],offset);_require(n>0,'private output write failed');offset+=n
                os.fsync(output_fd)
                return {'status':'private-output-saved','sha256':'sha256:'+hashlib.sha256(data).hexdigest(),'bytes':len(data)}
            summary=json.loads(data)
            expected={{'prepare':'candidate-prepared','activate':'target-sealed','capture-backup':'private-archive-captured','verify-backup':'restored-case-verified'}[request['mode']]} if action=='invoke' else {'private-archive-stored'}
            _require(isinstance(summary,dict) and summary.get('status') in expected and
                     set(summary)==({'status','resultSha256'} if action=='invoke' else {'status','archiveSha256'}),'worker summary invalid')
            if action=='upload-archive':_require(summary['archiveSha256']==request['archiveSha256'],'uploaded archive acknowledgement changed')
            _sha(summary.get('resultSha256') if action=='invoke' else summary.get('archiveSha256'))
            return summary
        except Exception:
            raise BootstrapStopped('review worker exchange stopped; retain stage receipts and private artifacts') from None
