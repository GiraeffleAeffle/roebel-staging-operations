"""Closed Case bootstrap implementation and independently pinned Flux render."""
from pathlib import Path

FILES={
    'scripts/case_runtime_admission.py',
    'scripts/case_runtime_bootstrap.py',
    'scripts/case_runtime_configuration.py',
    'scripts/case_runtime_handover.py',
    'scripts/case_runtime_kubernetes.py',
    'scripts/case_runtime_saved_adoption.py',
    'scripts/run-case-runtime.py',
    'scripts/test_case_runtime_bootstrap.py',
    'scripts/test_case_runtime_configuration.py',
    'scripts/test_case_runtime_handover.py',
    'scripts/test_case_runtime_kubernetes.py',
    'scripts/test_case_runtime_saved_adoption.py',
    'reviewed-render/roebel-staging/case-runtime/resources.json',
    'reviewed-render/roebel-staging/case-runtime/kustomization.yaml',
}


def verify(v,root):
    # The protected proposal checker has already verified independent byte pins.
    for name in ('resources.json','kustomization.yaml'):
        active=root/'reviewed-render/roebel-staging/case-runtime'/name
        proposed=root/'proposals/synthetic-case-runtime'/name
        v.require(active.is_file() and not active.is_symlink() and active.read_bytes()==proposed.read_bytes(),'Case runtime render differs from independently pinned proposal')
    return {'bootstrapImplementationPresent':True,'automaticActivation':False,
            'webConnectionIncluded':False,'restoreActivation':False}


def verify_transition(v,candidate,base):
    v.require(not v.changed_repository_files(candidate,base)&FILES,'promotion changed protected Case bootstrap implementation or render')


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


def extend_web_boundary(v,root,boundary):
    proposal=connection(v,root)
    if proposal:
        boundary['boundary']['webCaseBinding']={
            'authority':'none','credentials':'none','origin':proposal['environmentAddition']['value'],
            'egress':proposal['egressAddition'],'sourceNamespace':proposal['namespace'],
        }


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
