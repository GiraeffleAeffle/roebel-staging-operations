"""Exact staged Town Workspace rollout; candidates supply data, never policy.

The whole proposal has one independent protected pin. Prepared, login and
review are complete shapes. The identity has its own dormant Flux path so TLS
and real subject verification can finish before review access is enabled.
"""
import copy
import hashlib
import json
from pathlib import Path

ROOT = 'reviewed-render/roebel-staging/'
PROPOSAL = 'proposals/town-workspace-connection/'
ROLLOUT = PROPOSAL + 'rollout.json'
STATE = ROOT + 'town-workspace.json'
ROLLOUT_SHA256 = 'sha256:ec9219e2b1ffa0e66148577239153cc27e60dca44baa253200dfd3a2008a48ba'
FILES = {
    PROPOSAL + name for name in (
        'README.md', 'connection.json', 'oidc-registration.json',
        'workspace-sessions.sql', 'rehearse-session-access.sql',
        'identity-instance.json', 'identity-state.sql',
        'rehearse-identity-access.sql', 'identity-certificate.json',
        'flux-bootstrap.json', 'rollout.json',
    )
} | {
    STATE, ROOT + 'identity/resources.json', ROOT + 'identity/kustomization.yaml',
    'scripts/town_workspace_connection.py', 'scripts/test_town_workspace_connection.py',
    'proposals/synthetic-multi-case-runtime-upgrade/README.md',
    'proposals/synthetic-multi-case-runtime-upgrade/transition.json',
    'proposals/synthetic-multi-case-runtime-upgrade/topology.json',
}
STAGES = ('prepared', 'login', 'review', 'brief', 'multi-case')
RELEASE_RECORDS = {ROOT + name for name in ('head.json', 'integrity.json', 'live-preconditions.json')}
RELEASE_DEPLOYMENTS = {ROOT + name for name in ('web/deployment.json', 'public-mecky/deployment.json')}
BRIEF_READER_ENV = [
    {'name': 'MECKY_ALLOW_SYNTHETIC_BRIEF', 'value': 'true'},
    {'name': 'MECKY_SYNTHETIC_BRIEF_CONFIG', 'value': json.dumps({
        'caseId': 'urn:stadtstack:synthetic-case:municipality:roebel-mueritz:01a070fa-8770-7afd-9a92-2965149e730d',
        'discussionId': '111c8d6752760fe73e7d0fc0bb3392aeefe690391ea2721fd68101adbca782b8',
        'environment': 'staging',
        'publicOrigin': 'https://roebel-web.staging.agentcart.eu',
        'topicId': 'urn:stadtstack:topic:municipality:roebel-mueritz:staging-test-05-09-2026-verkehrssicherheit-am-abzweig-b-198',
        'transport': 'staging_web_service',
    }, sort_keys=True, separators=(',', ':'))},
]
BRIEF_READER_INITIAL_HEAD = {
    'schemaVersion': 'roebel_staging_release_set_head_v1',
    'promotionRevision': 'e2add2c498c3d1fe80a6f80ba56890e2ac33c62e',
    'releaseSetDigest': 'sha256:2bd4d213d9d84327a90fb3fd75a83ea463efa1c91d9de71c9cac44db1d44c67b',
    'components': [
        {'component': 'public-mecky', 'sourceRevision': 'e2add2c498c3d1fe80a6f80ba56890e2ac33c62e',
         'manifestDigest': 'sha256:3e2c5367440aaa35236f4bc1d26548410d21cd4bbd90a0d8385223bee811ca6e'},
        {'component': 'roebel-web-staging', 'sourceRevision': '6ce216f0b172dee3baec935be378d6d6adaaaaf4',
         'manifestDigest': 'sha256:b709001cba85ecaa87de1f119a4905f327d2896e0627a3c61eaad3964f38fe80'},
    ],
}


def stable_deployment(value):
    """Exclude the checked release fields and the exact staging Brief reader.

    The complete verifier still validates image/source/head/integrity/CAS. This
    keeps an activated workspace from freezing ordinary reviewed image updates.
    """
    result = copy.deepcopy(value)
    result['metadata']['annotations'].pop('stadtstack.io/source-revision', None)
    result['metadata']['annotations'].pop('stadtstack.io/release-set-sha256', None)
    result['spec']['template']['metadata']['annotations'].pop('stadtstack.io/source-revision', None)
    container = result['spec']['template']['spec']['containers'][0]
    container.pop('image', None)
    container.pop('imagePullPolicy', None)
    if result['metadata']['name'] == 'public-mecky' and container.get('env', [])[-2:] == BRIEF_READER_ENV:
        del container['env'][-2:]
    return result


def sha(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def bundle(v, root):
    path = root / ROLLOUT
    v.require(path.is_file() and not path.is_symlink(), 'workspace rollout must be a regular file')
    raw = path.read_bytes()
    v.require(sha(raw) == ROLLOUT_SHA256, 'workspace rollout independent pin mismatch')
    return json.loads(raw)


def stage(v, root):
    path = root / STATE
    if not path.exists():
        return None  # Historical complete trees have no connection files.
    v.require(path.is_file() and not path.is_symlink(), 'workspace state must be a regular file')
    value = v.load_json(path)
    v.require(set(value) == {'schemaVersion', 'stage'} and
              value['schemaVersion'] == 'roebel_town_workspace_state_v1' and
              value['stage'] in STAGES, 'workspace stage invalid')
    return value['stage']


def expected_files(data, selected):
    result = {}
    for name in STAGES[1:STAGES.index(selected) + 1]:
        result.update(data['stages'][name]['files'])
    return result


def verify(v, root):
    present = {p for p in FILES if (root / p).exists()}
    if not present:
        return None
    v.require(present == FILES, 'workspace proposal/implementation file set incomplete')
    data = bundle(v, root)
    selected = stage(v, root)
    for path, expected in data['proposalFiles'].items():
        file = root / path
        v.require(file.is_file() and not file.is_symlink() and sha(file.read_bytes()) == expected,
                  'workspace pinned input changed: ' + path)
    active = expected_files(data, selected)
    for path, before in data['predecessorFiles'].items():
        file = root / path
        if selected in ('brief', 'multi-case') and path in RELEASE_RECORDS:
            continue  # Validated by the complete head/integrity/CAS verifier.
        if selected in ('brief', 'multi-case') and path == ROOT + 'network-boundary-migration.json' and v.COMMENT_MECKY.enabled(root):
            # Apply only the independently pinned comment route and its two
            # gateway object hashes to the exact reviewed workspace boundary.
            gateway = v.COMMENT_MECKY.resources(v, v.PARTICIPANT_POLICY.APPROVED_NEXT_ACTIVATION_POLICY, True)
            expected = v.COMMENT_MECKY.network_receipt(v, json.loads(active[path]), gateway)
            v.require(file.is_file() and not file.is_symlink() and v.load_json(file) == expected,
                      'workspace comment boundary drift')
            continue
        if selected in ('brief', 'multi-case') and path in RELEASE_DEPLOYMENTS:
            v.require(file.is_file() and not file.is_symlink() and
                      stable_deployment(v.load_json(file)) == stable_deployment(json.loads(active[path])),
                      'workspace deployment changed outside reviewed release fields: ' + path)
            continue
        expected = sha(active[path].encode()) if path in active else before
        v.require(file.is_file() and not file.is_symlink() and sha(file.read_bytes()) == expected,
                  'workspace stage file mismatch: ' + path)
    return {'stage': selected, 'rolloutSha256': ROLLOUT_SHA256,
            'identityAutomaticallyActivated': False, 'civicAuthority': 'none'}


def expected_file(v, root, path, default):
    selected = stage(v, root)
    if selected not in ('login', 'review', 'brief', 'multi-case'):
        return default
    raw = expected_files(bundle(v, root), selected).get(path)
    return json.loads(raw) if raw is not None else default


def web_image(v, root, previous):
    if stage(v, root) in ('brief', 'multi-case'):
        head = v.load_json(root / (ROOT + 'head.json'))
        component = next(c for c in head['components'] if c['component'] == 'roebel-web-staging')
        return 'ghcr.io/giraeffleaeffle/roebel-web-staging@' + component['manifestDigest']
    expected = expected_file(v, root, ROOT + 'web/deployment.json', None)
    return expected['spec']['template']['spec']['containers'][0]['image'] if expected else previous


def extend_boundary(v, root, boundary):
    selected = stage(v, root)
    if selected in ('login', 'review', 'brief', 'multi-case'):
        boundary['boundary']['townWorkspace'] = copy.deepcopy(bundle(v, root)['stages'][selected]['boundary'])


def verify_transition(v, candidate, base):
    a, b = stage(v, base), stage(v, candidate)
    if a == b:
        v.require(not (v.changed_repository_files(candidate, base) & FILES),
                  'workspace promotion changed protected rollout inputs or implementation')
        if a in ('brief', 'multi-case'):
            path = ROOT + 'public-mecky/deployment.json'
            enabled = lambda root: v.load_json(root / path)['spec']['template']['spec']['containers'][0]['env'][-2:] == BRIEF_READER_ENV
            before, after = enabled(base), enabled(candidate)
            v.require(not (before and not after), 'workspace Brief reader cannot regress')
            if after and not before:
                v.require(v.changed_repository_files(candidate, base) == RELEASE_RECORDS | RELEASE_DEPLOYMENTS,
                          'workspace Brief reader activation must accompany only its reviewed Release Set')
                v.require(v.load_json(candidate / (ROOT + 'head.json')) == BRIEF_READER_INITIAL_HEAD,
                          'workspace Brief reader requires its exact initial transport release')
                # Return False: the complete Release Set/CAS verifier must also
                # admit this image transition; the pair grants no early return.
        return False
    v.require(a is not None and b is not None and STAGES.index(b) == STAGES.index(a) + 1,
              'workspace activation must advance exactly one reviewed stage')
    verify(v, candidate)
    verify(v, base)
    data = bundle(v, base)
    expected = set(data['stages'][b]['files']) | {STATE}
    v.require(v.changed_repository_files(candidate, base) == expected,
              'workspace activation changed unrelated files or omitted a stage resource')
    if b in ('brief', 'multi-case'):
        for path, raw in data['stages'][b]['files'].items():
            v.require((candidate / path).read_bytes() == raw.encode(),
                      'initial Brief activation must use the exact published release: ' + path)
    return True
