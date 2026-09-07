"""Production adapter rehearsal over a JSON Kubernetes API double."""
import base64
import copy
import hashlib
import json
import unittest
from unittest import mock

from . import test_case_runtime_bootstrap as fixtures
from . import case_runtime_bootstrap as core
from . import case_runtime_kubernetes as kube


class API:
    def __init__(self,adapter):
        self.adapter=adapter
        self.objects={}
        self.pods=[]
        self.sets=[]
        self.calls=[]
        self.exec_failure=False
        for name in (kube.NAMESPACE,kube.FLUX):self.objects['/api/v1/namespaces/'+name]={'metadata':{'uid':'namespace-'+name,'labels':{'kubernetes.io/metadata.name':name}},'status':{'phase':'Active'}}
        self.objects['/api/v1/namespaces/kube-system']={'metadata':{'uid':kube.CLUSTER_UID}}
        self.objects[f'/apis/source.toolkit.fluxcd.io/v1/namespaces/{kube.FLUX}/gitrepositories/roebel-staging-operations']={
            'metadata':{'uid':'source','generation':1},'spec':{'url':'https://github.com/GiraeffleAeffle/roebel-staging-operations.git','ref':{'branch':'main'}},'status':{'observedGeneration':1,'artifact':{'revision':'main@sha1:'+adapter.revision},'conditions':[{'type':'Ready','status':'True'}]}}
        claim=adapter.plan['review']['existingStorage']['claim']
        self.objects[f"/api/v1/namespaces/{kube.NAMESPACE}/persistentvolumeclaims/{claim['pvcName']}"]={
            'metadata':{'uid':claim['pvcUid']},'spec':{'volumeName':claim['pvName'],'accessModes':['ReadWriteOncePod'],'volumeMode':'Filesystem','storageClassName':'hcloud-volumes','resources':{'requests':{'storage':'10Gi'}}},'status':{'phase':'Bound'}}
        self.objects['/api/v1/persistentvolumes/'+claim['pvName']]={
            'metadata':{'uid':adapter.plan['review']['existingStorage']['volumeUid']},'spec':{'accessModes':['ReadWriteOncePod'],'volumeMode':'Filesystem','storageClassName':'hcloud-volumes','claimRef':{'uid':claim['pvcUid']},'persistentVolumeReclaimPolicy':'Retain','capacity':{'storage':'10Gi'}},'status':{'phase':'Bound'}}
        self.objects[f'/api/v1/namespaces/{kube.NAMESPACE}/persistentvolumeclaims/roebel-tracer-postgres-data-v1']={'metadata':{'uid':'d1c0ae47-37fc-43a8-8f2b-43fe7ca1a504'},'spec':{'volumeName':'tracer-pv'}}
        self.objects['/api/v1/persistentvolumes/tracer-pv']={'metadata':{'uid':'fdc96282-7d83-4f18-a463-3a3b9998cbe7'},'spec':{'persistentVolumeReclaimPolicy':'Retain','claimRef':{'uid':'d1c0ae47-37fc-43a8-8f2b-43fe7ca1a504'}}}
        ref=adapter.plan['review']['separateCredentialProvisioning']
        self.secret_path=f"/api/v1/namespaces/{ref['namespace']}/secrets/{ref['name']}"
        self.objects[self.secret_path]={'metadata':{'uid':'secret'},'type':'Opaque','immutable':True,'data':{ref['key']:base64.b64encode(b'synthetic-fixture').decode()}}
        self.pods.append({'metadata':{'uid':kube.POSTGRES_UID},'spec':{'fixture':'tracer'},'status':{'phase':'Running','containerStatuses':[{'restartCount':0,'ready':True}]}})
        for desired in adapter.existing:
            obj=copy.deepcopy(desired);obj['metadata'].update(uid=obj['metadata']['name'],generation=1)
            if desired['kind']=='Deployment':obj['status']={'observedGeneration':1,**{k:desired['spec']['replicas'] for k in ('replicas','updatedReplicas','readyReplicas','availableReplicas')}}
            self.objects[kube.resource_path(core.target(obj))]=obj

    def request(self,method,path,payload):
        self.calls.append((method,path))
        if method=='GET':
            if path==f'/api/v1/namespaces/{kube.NAMESPACE}/pods':return {'items':copy.deepcopy(self.pods)}
            if path==f'/apis/apps/v1/namespaces/{kube.NAMESPACE}/replicasets':return {'items':copy.deepcopy(self.sets)}
            return copy.deepcopy(self.objects.get(path))
        assert method=='POST'
        obj=copy.deepcopy(payload);uid=f'created-{len(self.objects)}'
        obj['metadata'].update(uid=uid,resourceVersion='1',generation=1)
        if obj['kind']=='Deployment':
            obj['status']={'observedGeneration':1,'replicas':1,'readyReplicas':1,'updatedReplicas':1,'availableReplicas':1}
            rsuid='rs-'+uid
            self.sets.append({'metadata':{'uid':rsuid,'ownerReferences':[{'uid':uid,'controller':True}]}})
            pod={'metadata':{'name':'pod-'+uid,'uid':'pod-'+uid,'ownerReferences':[{'uid':rsuid,'controller':True}]},'spec':copy.deepcopy(obj['spec']['template']['spec']),
                'status':{'phase':'Running','conditions':[{'type':'Ready','status':'True'}],'containerStatuses':[{'name':'runtime','ready':True,'restartCount':0,'containerID':'container-'+uid,'imageID':obj['spec']['template']['spec']['containers'][0]['image']}]}}
            self.pods.append(pod)
        self.objects[path+'/'+obj['metadata']['name'] if obj['kind']=='Secret' else kube.resource_path(core.target(obj))]=obj
        return copy.deepcopy(obj)

    def exec_pod(self,namespace,name,uid,container,argv):
        assert argv==['node','-e',"process.kill(1, 'SIGTERM')"]
        pod=next(p for p in self.pods if p['metadata']['uid']==uid)
        status=pod['status']['containerStatuses'][0]
        status.update(restartCount=status['restartCount']+1,containerID='restarted-'+status['containerID'],lastState={'terminated':{'exitCode':137 if self.exec_failure else 0}})


    def patch_owned(self,target,uid,version,operations):
        path=kube.resource_path(target);obj=self.objects[path]
        assert obj['metadata']['uid']==uid and obj['metadata']['resourceVersion']==version
        if operations[0]['path'].startswith('/metadata/annotations/'):
            assert obj['metadata']['annotations'][core.NONCE]==operations[0]['value']
            obj['metadata']['annotations'].pop(core.NONCE)
            if not obj['metadata']['annotations']:obj['metadata'].pop('annotations')
        else:
            assert obj['spec']['suspend'] is True
            obj['spec']['suspend']=False;obj['metadata']['generation']+=1
            for item in self.adapter.plan['objects'][:15]:
                self.objects[kube.resource_path(item['target'])]['metadata'].setdefault('labels',{}).update({'kustomize.toolkit.fluxcd.io/name':'roebel-case-runtime','kustomize.toolkit.fluxcd.io/namespace':kube.FLUX})
            obj['status']={'observedGeneration':obj['metadata']['generation'],'lastAppliedRevision':'main@sha1:'+self.adapter.revision,'conditions':[{'type':'Ready','status':'True'}]}
        obj['metadata']['resourceVersion']=str(int(version)+1)
        return copy.deepcopy(obj)


class KubernetesTests(unittest.TestCase):
    setUpClass = classmethod(fixtures.CaseBootstrapTests.setUpClass.__func__)
    environment = fixtures.CaseBootstrapTests.environment
    def adapter_environment(self):
        plan=core.build_plan(self.root)
        # Only the credential checksum is replaced with a synthetic test value;
        # no real credential is read, and the production factory remains pinned.
        plan['review']['separateCredentialProvisioning']['configurationSha256']='sha256:'+hashlib.sha256(b'synthetic-fixture').hexdigest()
        plan.pop('planSha256');plan['planSha256']=core.canonical_sha256(plan)
        patch=mock.patch.object(core,'build_plan',return_value=plan);patch.start();self.addCleanup(patch.stop)
        adapter=kube.KubernetesAdapter(self.root,'a8dfc228995d8e2a82f3255f8a1b79e47701dbc8',None)
        api=API(adapter);adapter.transport=api
        return adapter,api

    def test_real_adapter_complete_bootstrap_and_restart(self):
        sink,_=self.environment();adapter,api=self.adapter_environment()
        result=core.run_bootstrap(self.root,adapter=adapter,sink=sink)
        self.assertEqual(result['status'],'bootstrap-verified-flux-suspended')
        self.assertEqual(adapter.evidence['controlRestart']['exitCode'],0)
        self.assertEqual(len([c for c in api.calls if c[0]=='POST']),19)

    def test_live_preflight_rejects_storage_secret_source_and_tracer_drift(self):
        for fault in ('cluster','secret','storage','source','tracer'):
            with self.subTest(fault=fault):
                adapter,api=self.adapter_environment()
                if fault=='cluster':api.objects['/api/v1/namespaces/kube-system']['metadata']['uid']='other'
                elif fault=='secret':api.objects[api.secret_path]['data']['application-json']=base64.b64encode(b'wrong').decode()
                elif fault=='storage':
                    pv=next(v for k,v in api.objects.items() if k.startswith('/api/v1/persistentvolumes/') and k.endswith(adapter.plan['review']['existingStorage']['claim']['pvName']))
                    pv['spec']['persistentVolumeReclaimPolicy']='Delete'
                elif fault=='source':
                    source=next(v for k,v in api.objects.items() if 'gitrepositories' in k);source['status']['artifact']['revision']='main@sha1:'+'0'*40
                else:api.pods[0]['status']['containerStatuses'][0]['restartCount']=1
                with self.assertRaises(core.BootstrapStopped):adapter.verify_preconditions(adapter.plan)
                self.assertFalse(any(c[0]=='POST' for c in api.calls))

    def test_unclean_restart_prevents_public_creation(self):
        sink,_=self.environment();adapter,api=self.adapter_environment();api.exec_failure=True
        with self.assertRaises(core.BootstrapStopped):core.run_bootstrap(self.root,adapter=adapter,sink=sink)
        self.assertEqual(len([c for c in api.calls if c[0]=='POST']),14)

    def test_service_account_omitted_empty_pull_secrets_keeps_nonempty_references_visible(self):
        adapter,_=self.adapter_environment()
        desired=adapter.plan['objects'][0]['desired']
        actual=copy.deepcopy(desired);actual.pop('imagePullSecrets')
        adapter.require_exact(actual,desired)
        actual['imagePullSecrets']=[{'name':'unreviewed-registry-credential'}]
        with self.assertRaises(core.BootstrapStopped):adapter.require_exact(actual,desired)

    def test_default_normalization_keeps_security_changes(self):
        adapter,_=self.adapter_environment()
        desired=next(o['desired'] for o in adapter.plan['objects'] if o['phase']=='control')
        actual=copy.deepcopy(desired)
        actual['metadata'].update(uid='uid',resourceVersion='5',generation=1)
        actual['spec']['revisionHistoryLimit']=10
        actual['spec']['template']['spec']['initContainers'][0]['terminationMessagePath']='/dev/termination-log'
        adapter.require_exact(actual,desired)
        actual['spec']['template']['spec']['containers'][0]['securityContext']['privileged']=True
        with self.assertRaises(core.BootstrapStopped):adapter.require_exact(actual,desired)
