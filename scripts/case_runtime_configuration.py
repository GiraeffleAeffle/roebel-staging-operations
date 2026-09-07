"""Separate create-only provisioning of the pinned private Case configuration."""
import base64
import hashlib
import os
import secrets
import stat
from . import case_runtime_bootstrap as core


def provision_configuration(plan,fd,*,adapter,sink):
    ref=plan['review']['separateCredentialProvisioning']
    info=os.fstat(fd)
    core._require(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and info.st_nlink in (0,1) and stat.S_IMODE(info.st_mode)==0o600 and 0<info.st_size<=262144,'private configuration descriptor invalid')
    raw=os.pread(fd,info.st_size+1,0)
    core._require(len(raw)==info.st_size and 'sha256:'+hashlib.sha256(raw).hexdigest()==ref['configurationSha256'],'private configuration bytes do not match approved pin')
    after=os.fstat(fd)
    core._require((info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'private configuration changed while reading')
    nonce=secrets.token_hex(32)
    state={'schemaVersion':'roebel_case_configuration_receipt_v1','planSha256':plan['planSha256'],'reference':{k:ref[k] for k in ('namespace','name','key')},'configurationSha256':ref['configurationSha256'],'nonce':nonce,'status':'reserved','uid':None}
    sink.commit(state)
    adapter.verify_preconditions(plan,require_secret=False)
    path=f"/api/v1/namespaces/{ref['namespace']}/secrets"
    core._require(adapter.transport.request('GET',path+'/'+ref['name'],None) is None,'configuration already exists; provisioning will not adopt or replace it')
    desired={'apiVersion':'v1','kind':'Secret','metadata':{'namespace':ref['namespace'],'name':ref['name'],'annotations':{core.NONCE:nonce}},'immutable':True,'type':'Opaque','data':{ref['key']:base64.b64encode(raw).decode()}}
    del raw
    state['status']='create-intent';sink.commit(state)
    try:
        try:created=adapter.transport.request('POST',path,desired)
        except core.CreateConflict:raise core.BootstrapStopped('configuration create conflict') from None
        except Exception:created=adapter.transport.request('GET',path+'/'+ref['name'],None)
        core._require(created and created.get('metadata',{}).get('annotations',{}).get(core.NONCE)==nonce,'configuration create outcome unresolved')
        core._require(created.get('data')==desired['data'] and created.get('immutable') is True and created.get('type')=='Opaque','configuration object mismatch')
        core._require(created['metadata'].get('name')==ref['name'] and created['metadata'].get('namespace')==ref['namespace'] and created['metadata'].get('uid'),'configuration identity mismatch')
        state.update(status='provisioned',uid=created['metadata']['uid'])
        sink.commit(state)
        adapter.verify_preconditions(plan)
        return state
    except Exception:
        # No retry/delete; preserve nonce and durable intent after an ambiguous
        # result. Never include a server error or payload in an exception.
        raise core.BootstrapStopped('configuration provisioning stopped; inspect durable ownership receipt') from None
    finally:
        desired['data'].clear()
