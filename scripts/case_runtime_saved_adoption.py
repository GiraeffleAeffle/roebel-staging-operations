"""Admit only the already signed synthetic adoption; credentials stay in the Pod."""
import copy
import hashlib
import json
from . import case_runtime_bootstrap as core

BUNDLE_SHA256='72e32f3c17271a26d5661d511c912fef9b8fff6074e280afcc3336668a697b81'
ROOT_EVENT='111c8d6752760fe73e7d0fc0bb3392aeefe690391ea2721fd68101adbca782b8'
PROOF_EVENT='c3d649c68745c8cb61b386ee027bd1c5ca05c9bfbaff9968911eb5bfa29e96f4'
SUGGESTION_EVENT='296c33e55767bb44d8082a763f316d83fc44c6a5b59c9381271221d0a0822827'

COMMON_JS=r"""
import http from 'node:http';
import {verifyPublicCaseBindingReceipt} from '/runtime/src/case-binding-projection.ts';
const root='111c8d6752760fe73e7d0fc0bb3392aeefe690391ea2721fd68101adbca782b8';
function checked(value){const r=verifyPublicCaseBindingReceipt(value);if(r.schemaVersion!=='public_synthetic_case_binding_receipt_v1'||r.rootEventId!==root||r.candidateEventId!=='c3d649c68745c8cb61b386ee027bd1c5ca05c9bfbaff9968911eb5bfa29e96f4'||r.participantSuggestionEventId!=='296c33e55767bb44d8082a763f316d83fc44c6a5b59c9381271221d0a0822827')throw Error('receipt mismatch');return r;}
function request(port,path,headers,body){return new Promise((resolve,reject)=>{const req=http.request({hostname:'127.0.0.1',port,path,method:body?'POST':'GET',headers,timeout:15000},res=>{let chunks=[],size=0;res.on('data',chunk=>{size+=chunk.length;if(size>32768){res.destroy();reject(Error('response bound'));}else chunks.push(chunk);});res.on('end',()=>resolve({status:res.statusCode,body:Buffer.concat(chunks).toString('utf8')}));res.on('error',reject);});req.on('timeout',()=>req.destroy(Error('timeout')));req.on('error',reject);req.end(body);});}
"""
ADMIT_JS=COMMON_JS+r"""
import fs from 'node:fs';import crypto from 'node:crypto';
try{
 const raw=fs.readFileSync(0);if(raw.length>262144||crypto.createHash('sha256').update(raw).digest('hex')!=='72e32f3c17271a26d5661d511c912fef9b8fff6074e280afcc3336668a697b81')throw Error('bundle pin');
 const fd=fs.openSync('/run/stadtstack-control/private/application.json',fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);let bytes;
 try{const st=fs.fstatSync(fd);if(!st.isFile()||st.uid!==1000||st.nlink!==1||(st.mode&0o7777)!==0o600||st.size>262144)throw Error('configuration metadata');bytes=fs.readFileSync(fd);}finally{fs.closeSync(fd);}
 if(crypto.createHash('sha256').update(bytes).digest('hex')!=='b9f2e527e3459e3626e7255c57841388c477a8f51feab0f6ba39a8efd6e5e287')throw Error('configuration pin');
 const config=JSON.parse(bytes),credential=config.credentials.find(c=>c.principal.actorId==='staging:roebel:staging-gast-ba8498');if(!credential||credential.principal.actorClass!=='case_steward')throw Error('principal');
 const body=Buffer.from(JSON.stringify({schemaVersion:'roebel_case_steward_synthetic_adoption_request_v1',bundle:JSON.parse(raw)}));
 const result=await request(18085,'/v1/nostr/suggestions/admit',{'host':config.admissionAllowedHosts[0],'authorization':'Bearer '+credential.token,'content-type':'application/json','content-length':String(body.length)},body);
 if(result.status!==200)throw Error('admission unavailable');process.stdout.write(JSON.stringify(checked(JSON.parse(result.body))));
}catch{process.stderr.write('saved synthetic admission outcome unavailable\n');process.exitCode=1;}
"""
READ_JS=COMMON_JS+r"""
try{const result=await request(18086,'/v1/public/case-bindings/by-discussion/'+root,{'host':'roebel-case-public-binding.stadtstack-roebel-staging-lab.svc.cluster.local'});
 if(result.status===404)process.stdout.write(JSON.stringify({found:false}));
 else{if(result.status!==200)throw Error('public unavailable');process.stdout.write(JSON.stringify({found:true,receipt:checked(JSON.parse(result.body))}));}
}catch{process.stderr.write('public Case receipt unavailable\n');process.exitCode=1;}
"""


def check_receipt(value):
    core._require(isinstance(value,dict) and value.get('schemaVersion')=='public_synthetic_case_binding_receipt_v1' and value.get('rootEventId')==ROOT_EVENT and value.get('candidateEventId')==PROOF_EVENT and value.get('participantSuggestionEventId')==SUGGESTION_EVENT,'saved synthetic receipt identity mismatch')
    expected_fields={'schemaVersion','rootEventId','topicId','candidateId','candidateEventId','sourceAnswerEventId','caseId','caseVersion','caseEventIds','journalHeadChecksum','admissionEventChecksum','authorityBinding','openDeskWrite','candidateKind','environment','testOnly','civicCaseCreated','syntheticCaseCreated','participantSuggestionEventId','adopterPubkey','testPolicyVersion','adoptionAcceptanceReceiptChecksum','sourceAnswerReceiptId','administrativeEndorsement','bindingVote','councilDecision','treasuryEffect','paymentEffect','receiptChecksum'}
    core._require(set(value)==expected_fields,'saved synthetic receipt shape mismatch')
    core._require(value['authorityBinding']=='none' and value['environment']=='staging' and value['testOnly'] is True and value['syntheticCaseCreated'] is True and value['candidateKind']=='synthetic_citizen_adoption_tracer_v1','saved receipt is not synthetic-only')
    core._require(all(value[key] is False for key in ('openDeskWrite','civicCaseCreated','administrativeEndorsement','bindingVote','councilDecision','treasuryEffect','paymentEffect')),'saved receipt claims civic authority')
    digest=value.get('receiptChecksum');unsigned=copy.deepcopy(value);unsigned.pop('receiptChecksum',None)
    core._require(digest==core.canonical_sha256(unsigned),'saved synthetic receipt checksum mismatch')
    return value


def run_saved_adoption(plan,bootstrap_receipt,bundle,*,adapter,sink):
    core._require(hashlib.sha256(bundle).hexdigest()==BUNDLE_SHA256,'only the saved signed synthetic bundle is admitted')
    bootstrap=core.bind_recovery(plan,bootstrap_receipt)
    core._require(bootstrap['status']=='bootstrap-verified-flux-suspended','verified bootstrap required before test admission')
    control=bootstrap['objects'][13];public=bootstrap['objects'][14]
    state={'schemaVersion':'roebel_saved_synthetic_case_admission_receipt_v1','planSha256':plan['planSha256'],'bootstrapSha256':bootstrap_receipt['canonicalSha256'],'bundleSha256':'sha256:'+BUNDLE_SHA256,'status':'reserved','receipt':None,'restart':None}
    sink.commit(state)
    def request(component,owned,body=None):
        adapter.verify_preconditions(plan)
        pod=adapter._wait(lambda:adapter._pod(owned),component+' exact Pod')
        return adapter.transport.exec_case_request(pod['metadata']['name'],pod['metadata']['uid'],component,body)
    prior=request('public',public)
    if prior.get('found') is True:
        receipt=check_receipt(prior['receipt'])
    else:
        core._require(prior=={'found':False},'public receipt lookup invalid')
        state['status']='admission-intent';sink.commit(state)
        # Do not resend on uncertain response. A later invocation checks the
        # public reader first and the source service is transaction-idempotent.
        receipt=check_receipt(request('control',control,bundle))
    state.update(status='admitted-restart-intent',receipt=receipt);sink.commit(state)
    state['restart']=adapter.verify_control_restart(control,plan)
    sink.commit(state)
    def replayed():
        value=request('public',public)
        if value.get('found') is not True:return None
        observed=check_receipt(value['receipt'])
        core._require(observed==receipt,'public receipt differs after clean restart')
        return observed
    adapter._wait(replayed,'durable public Case receipt')
    state['status']='saved-synthetic-case-publicly-verified';sink.commit(state)
    return state
