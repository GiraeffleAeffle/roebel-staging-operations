"""UID-bound Case nonce removal and Flux handover with durable recovery intent.

Requires a separately admitted active render, an exact bootstrap receipt and a
fresh live adapter. Does not create a resource or modify private configuration.
"""
import copy
from . import case_runtime_bootstrap as core
from .case_runtime_kubernetes import resource_path


class HandoverStopped(core.BootstrapStopped):
    pass


def run_handover(plan, bootstrap_receipt, *, adapter, sink, prior_receipt=None):
    bootstrap=core.bind_recovery(plan,bootstrap_receipt)
    core._require(bootstrap['status']=='bootstrap-verified-flux-suspended' and len(bootstrap['objects'])==19 and all(r['state']=='created' for r in bootstrap['objects']),'complete owned bootstrap required')
    core._require(set(bootstrap['runtimeChecks'])=={'control','public'},'verified control/public runtime evidence required')
    if prior_receipt is None:
        state={'schemaVersion':'roebel_case_flux_handover_receipt_v1',
            'bootstrapSha256':bootstrap_receipt['canonicalSha256'],'planSha256':plan['planSha256'],
            'status':'reserved','removed':[],'pending':None,'unsuspendIntent':False,'fluxReady':False}
    else:
        state=copy.deepcopy(prior_receipt);digest=state.pop('canonicalSha256',None)
        core._require(digest==core.canonical_sha256(state),'handover receipt checksum mismatch')
        core._require(set(state)=={'schemaVersion','bootstrapSha256','planSha256','status','removed','pending','unsuspendIntent','fluxReady'} and state['schemaVersion']=='roebel_case_flux_handover_receipt_v1','handover receipt shape mismatch')
        core._require(state['bootstrapSha256']==bootstrap_receipt['canonicalSha256'] and state['planSha256']==plan['planSha256'],'handover receipt binding mismatch')
        core._require(isinstance(state['removed'],list) and state['removed']==list(range(len(state['removed']))) and len(state['removed'])<=19,'handover ordered prefix invalid')
        core._require(state['pending'] is None or (type(state['pending']) is int and state['pending']==len(state['removed']) and state['pending']<19),'handover pending intent invalid')
        core._require(type(state['unsuspendIntent']) is bool and type(state['fluxReady']) is bool,'handover effect flags invalid')
        core._require(not state['unsuspendIntent'] or len(state['removed'])==19,'handover premature unsuspend intent')
    sink.commit(state)
    try:
        adapter.verify_active_render(plan)
        adapter.verify_preconditions(plan)
        for index,(item,owned) in enumerate(zip(plan['objects'],bootstrap['objects'],strict=True)):
            live=adapter.get(item['target'])
            core._require(live and live['metadata']['uid']==owned['uid'],'handover owned UID changed')
            nonce=live.get('metadata',{}).get('annotations',{}).get(core.NONCE)
            if index in state['removed']:
                core._require(nonce is None,'removed nonce reappeared')
                desired=copy.deepcopy(item['desired'])
                if item['target']['kind']=='Kustomization' and state['unsuspendIntent']:
                    core._require(live['spec']['suspend'] in (True,False),'invalid suspend state')
                    desired['spec']['suspend']=live['spec']['suspend']
                if state['unsuspendIntent']:
                    live=adapter.without_case_flux_labels(live)
                adapter.require_exact(live,desired)
                continue
            if nonce is None:
                core._require(state['pending']==index,'nonce removal has no durable intent')
                adapter.require_exact(live,item['desired'])
            else:
                core._require(nonce==bootstrap['nonce'],'handover foreign ownership nonce')
                desired=copy.deepcopy(item['desired']);desired['metadata'].setdefault('annotations',{})[core.NONCE]=nonce
                adapter.require_exact(live,desired)
                state.update(status='removing-nonces',pending=index)
                sink.commit(state)
                adapter.transport.patch_owned(item['target'],owned['uid'],live['metadata']['resourceVersion'],[
                    {'op':'test','path':'/metadata/annotations/stadtstack.io~1case-bootstrap-nonce','value':nonce},
                    {'op':'remove','path':'/metadata/annotations/stadtstack.io~1case-bootstrap-nonce'}])
                after=adapter.get(item['target'])
                core._require(after and after['metadata']['uid']==owned['uid'],'nonce removal UID changed')
                adapter.require_exact(after,item['desired'])
            state['removed'].append(index);state['pending']=None
            sink.commit(state)
        flux_item=plan['objects'][-1];flux_owned=bootstrap['objects'][-1]
        core._require(flux_item['target']['kind']=='Kustomization','handover Flux ordering mismatch')
        adapter.verify_active_render(plan)
        adapter.verify_preconditions(plan)
        live=adapter.get(flux_item['target'])
        core._require(live and live['metadata']['uid']==flux_owned['uid'],'Flux handover UID changed')
        if live['spec']['suspend'] is False:
            core._require(state['unsuspendIntent'],'Flux activation has no durable intent')
        else:
            adapter.require_exact(live,flux_item['desired'])
            state.update(status='unsuspend-intent',unsuspendIntent=True)
            sink.commit(state)
            adapter.transport.patch_owned(flux_item['target'],flux_owned['uid'],live['metadata']['resourceVersion'],[
                {'op':'test','path':'/spec/suspend','value':True},
                {'op':'replace','path':'/spec/suspend','value':False}])
        adapter.verify_flux_ready(flux_owned,bootstrap['objects'])
        state.update(status='flux-ready',fluxReady=True)
        sink.commit(state)
        return state
    except Exception:
        state['status']='stopped-preserve-owned-objects'
        try:sink.commit(state)
        except Exception:pass
        raise HandoverStopped('Case handover stopped; preserve ownership receipts and inspect Flux state') from None
