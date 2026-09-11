"""Closed Case bootstrap implementation and independently pinned Flux render."""
import copy
import json
from pathlib import Path

FILES={
    'scripts/case_runtime_admission.py',
    'scripts/case_runtime_bootstrap.py',
    'scripts/case_runtime_configuration.py',
    'scripts/case_runtime_handover.py',
    'scripts/case_review_handover.py',
    'scripts/test_case_review_handover.py',
    'scripts/case_runtime_kubernetes.py',
    'scripts/case_runtime_saved_adoption.py',
    'scripts/run-case-runtime.py',
    'scripts/run-case-review-migration.mjs',
    'scripts/case_review_backup.mjs',
    'scripts/case_review_storage.py',
    'scripts/run-case-review-storage.py',
    'scripts/test_case_review_storage.py',
    'scripts/test_case_review_migration.mjs',
    'scripts/test_case_review_migration_integration.mjs',
    'proposals/synthetic-case-review-migration/README.md',
    'proposals/synthetic-case-review-migration/review-resources.json',
    'scripts/test_case_runtime_bootstrap.py',
    'scripts/test_case_runtime_configuration.py',
    'scripts/test_case_runtime_handover.py',
    'scripts/test_case_runtime_kubernetes.py',
    'scripts/test_case_runtime_saved_adoption.py',
    'reviewed-render/roebel-staging/case-runtime/resources.json',
    'reviewed-render/roebel-staging/case-runtime/kustomization.yaml',
}


PUBLIC_READER_HOST = 'roebel-case-public-binding.stadtstack-roebel-staging-lab.svc.cluster.local'
PUBLIC_READER_CONFIG = 'roebel-case-public-binding-reviewed'
REVIEW_RESOURCES = 'proposals/synthetic-case-review-migration/review-resources.json'
REVIEW_RENDER_SHA256 = 'sha256:f7e156d67cf7209d9f8f887d5a091b8f88f85065f781393008120ed83b0a69e7'


def review_resources(v, root):
    """One inactive, independently pinned successor; no arbitrary render input."""
    import hashlib
    path=root/REVIEW_RESOURCES
    v.require(path.is_file() and not path.is_symlink(),'review successor must be a regular file')
    value=v.load_json(path)
    raw=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    v.require('sha256:'+hashlib.sha256(raw).hexdigest()==REVIEW_RENDER_SHA256,'review successor pin changed')
    return value


def public_host_resources(original):
    """Exact versioned configuration repair; retain the saved replay Host."""
    expected=copy.deepcopy(original)
    config=next(o for o in expected['items'] if o['kind']=='ConfigMap' and o['metadata']['name']==PUBLIC_READER_CONFIG)
    config['metadata']['name']=PUBLIC_READER_CONFIG+'-v2'
    application=json.loads(config['data']['application.json'])
    application['publicAllowedHosts']=[PUBLIC_READER_HOST,PUBLIC_READER_HOST+':18086']
    config['data']['application.json']=json.dumps(application,sort_keys=True,separators=(',',':'))+'\n'
    deployment=next(o for o in expected['items'] if o['kind']=='Deployment' and o['metadata']['name']=='roebel-case-public-binding')
    volume=next(o for o in deployment['spec']['template']['spec']['volumes'] if o.get('configMap',{}).get('name')==PUBLIC_READER_CONFIG)
    volume['configMap']['name']=PUBLIC_READER_CONFIG+'-v2'
    return expected


def flux_bootstrap_objects(v,root,original):
    """Allow reconciliation of the exact precreated v2 map, without create/delete."""
    expected=copy.deepcopy(original)
    runtime=v.load_json(root/'reviewed-render/roebel-staging/case-runtime/resources.json')['items']
    if any(o['kind']=='ConfigMap' and o['metadata']['name']==PUBLIC_READER_CONFIG+'-v2' for o in runtime):
        role=next(o for o in expected if o['kind']=='Role')
        rule=next(r for r in role['rules'] if r['resources']==['configmaps'])
        rule['resourceNames'].append(PUBLIC_READER_CONFIG+'-v2')
    if any(o['kind']=='ConfigMap' and o['metadata']['name']=='roebel-case-steward-review-reviewed-v1' for o in runtime):
        role=next(o for o in expected if o['kind']=='Role')
        next(r for r in role['rules'] if r['resources']==['configmaps'])['resourceNames'].append('roebel-case-steward-review-reviewed-v1')
    return expected


def verify(v,root):
    # The protected proposal checker has already verified independent byte pins.
    successor=(json.dumps(review_resources(v,root),indent=2)+'\n').encode()
    for name in ('resources.json','kustomization.yaml'):
        active=root/'reviewed-render/roebel-staging/case-runtime'/name
        proposed=root/'proposals/synthetic-case-runtime'/name
        v.require(active.is_file() and not active.is_symlink(),'Case runtime render requires regular files')
        expected=proposed.read_bytes()
        repaired=(json.dumps(public_host_resources(json.loads(expected)),indent=2)+'\n').encode() if name=='resources.json' else expected
        allowed=(expected,repaired,successor) if name=='resources.json' else (expected,repaired)
        v.require(active.read_bytes() in allowed,'Case runtime render differs from independently pinned source, exact public Host repair or review successor')
    return {'bootstrapImplementationPresent':True,'automaticActivation':False,
            'webConnectionIncluded':False,'restoreActivation':False}


def verify_transition(v,candidate,base):
    changed=v.changed_repository_files(candidate,base)
    path='reviewed-render/roebel-staging/case-runtime/resources.json'
    if changed=={path}:
        successor=(json.dumps(review_resources(v,base),indent=2)+'\n').encode()
        v.require((candidate/path).read_bytes()==successor and (base/path).read_bytes()!=successor,'review activation is not the exact forward transition')
        verify(v,candidate);verify(v,base)
        return True
    v.require(not changed&FILES,'promotion changed protected Case bootstrap implementation or render')
    return False


def connection(v,root):
    # Historical transition fixtures predate the Case proposal. A missing
    # proposal is accepted only when the Case origin is also absent; current
    # complete trees independently require the pinned proposal.
    proposal_path=root/'proposals/synthetic-case-runtime/web-connection.json'
    if not proposal_path.exists():
        web_path=root/v.RENDER_ROOT/'web/deployment.json'
        if web_path.exists():
            old=v.load_json(web_path)
            v.require(not any(e.get('name')=='STADTSTACK_PUBLIC_CASE_BINDING_ORIGIN' for c in old['spec']['template']['spec']['containers'] for e in c.get('env',[])),'Case origin without reviewed proposal')
        return None
    proposal=v.load_json(proposal_path)
    web=v.load_json(root/v.RENDER_ROOT/'web/deployment.json')
    container=web['spec']['template']['spec']['containers'][0]
    found=[e for e in container['env'] if e.get('name')==proposal['environmentAddition']['name']]
    v.require(not found or (found==[proposal['environmentAddition']] and container['image']==proposal['webImage']),'Case Web connection is not the reviewed credential-free origin/image')
    return proposal if found else None


PUBLIC_LOOKUP_PATTERN = r'^/api/stadtstack/case-bindings/by-discussion/[0-9a-f]{64}$'
PUBLIC_LOOKUP_ACL = ' !{ path_reg ' + PUBLIC_LOOKUP_PATTERN + ' }'


def public_lookup_enabled(v,root):
    ingress=v.load_json(root/v.RENDER_ROOT/'web/ingress.json')
    early=ingress['metadata']['annotations']['haproxy-ingress.github.io/config-backend-early']
    enabled=PUBLIC_LOOKUP_ACL in early
    v.require(not enabled or connection(v,root) is not None,'public Case lookup requires the reviewed Web connection')
    return enabled


def extend_web_boundary(v,root,boundary):
    proposal=connection(v,root)
    if proposal:
        boundary['boundary']['webCaseBinding']={
            'authority':'none','credentials':'none','origin':proposal['environmentAddition']['value'],
            'egress':proposal['egressAddition'],'sourceNamespace':proposal['namespace'],
        }
        if public_lookup_enabled(v,root):
            boundary['boundary']['webCaseBinding']['publicLookup']={'pathPattern':PUBLIC_LOOKUP_PATTERN,'methods':['GET','HEAD'],'credentials':'none'}


def verify_web_transition(v,candidate,base):
    import copy
    a,b=connection(v,base['root']),connection(v,candidate['root'])
    if bool(a)==bool(b):return False
    v.require(a is None and b is not None,'Case Web disconnection requires separate review')
    files={str(Path(v.RENDER_ROOT)/name) for name in ('web/deployment.json','web/networkpolicy.json','network-boundary-migration.json','integrity.json')}
    v.require(v.changed_repository_files(candidate['root'],base['root'])==files,'Case Web connection changed unrelated files')
    expected=copy.deepcopy(base['deployments']['roebel-web-staging'])
    expected['spec']['template']['spec']['containers'][0]['env'].append(b['environmentAddition'])
    v.require(candidate['deployments']['roebel-web-staging']==expected,'Case Web connection changed workload beyond exact origin')
    policy=v.load_json(base['root']/v.RENDER_ROOT/'web/networkpolicy.json')
    policy['spec']['egress'].append(b['egressAddition'])
    v.require(v.load_json(candidate['root']/v.RENDER_ROOT/'web/networkpolicy.json')==policy,'Case Web connection widened egress beyond public reader')
    # Both trees have already passed complete independent integrity and boundary
    # validation. The exact four-file surface forbids image/head/authority changes.
    return True
