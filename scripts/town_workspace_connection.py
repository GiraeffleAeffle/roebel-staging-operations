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
ROLLOUT_SHA256 = 'sha256:b34c7717c5b989453bf5ac31b18709ee8d046b7bd0860929729bb81f064f6716'
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
}
STAGES = ('prepared', 'login', 'review')


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
        expected = sha(active[path].encode()) if path in active else before
        v.require(file.is_file() and not file.is_symlink() and sha(file.read_bytes()) == expected,
                  'workspace stage file mismatch: ' + path)
    return {'stage': selected, 'rolloutSha256': ROLLOUT_SHA256,
            'identityAutomaticallyActivated': False, 'civicAuthority': 'none'}


def expected_file(v, root, path, default):
    selected = stage(v, root)
    if selected not in ('login', 'review'):
        return default
    raw = expected_files(bundle(v, root), selected).get(path)
    return json.loads(raw) if raw is not None else default


def web_image(v, root, previous):
    expected = expected_file(v, root, ROOT + 'web/deployment.json', None)
    return expected['spec']['template']['spec']['containers'][0]['image'] if expected else previous


def extend_boundary(v, root, boundary):
    selected = stage(v, root)
    if selected in ('login', 'review'):
        boundary['boundary']['townWorkspace'] = copy.deepcopy(bundle(v, root)['stages'][selected]['boundary'])


def verify_transition(v, candidate, base):
    a, b = stage(v, base), stage(v, candidate)
    if a == b:
        v.require(not (v.changed_repository_files(candidate, base) & FILES),
                  'workspace promotion changed protected rollout inputs or implementation')
        return False
    v.require(a is not None and b is not None and STAGES.index(b) == STAGES.index(a) + 1,
              'workspace activation must advance exactly one reviewed stage')
    verify(v, candidate)
    verify(v, base)
    data = bundle(v, base)
    expected = set(data['stages'][b]['files']) | {STATE}
    v.require(v.changed_repository_files(candidate, base) == expected,
              'workspace activation changed unrelated files or omitted a stage resource')
    return True
