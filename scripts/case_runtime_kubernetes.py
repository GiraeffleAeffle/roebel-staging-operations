"""Case-only Kubernetes adapter. Live execution still requires admitted CLI policy.

Transport supplies JSON API requests and bounded, exact-Pod exec. No shell,
Secret/PVC creation, arbitrary patch, delete, or Web mutation is exposed here.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import ipaddress
import time
import json

from . import case_runtime_bootstrap as core

CLUSTER_UID = '7bc769bc-e860-4d54-a0d5-d426f3a52420'
NAMESPACE = 'stadtstack-roebel-staging-lab'
POSTGRES_UID = '608d10ba-f28a-41cd-909e-4a121a6967dd'
FLUX = 'flux-roebel-staging'
KINDS = {
    ('v1','ServiceAccount'): ('/api/v1','serviceaccounts'),
    ('v1','Service'): ('/api/v1','services'),
    ('v1','ConfigMap'): ('/api/v1','configmaps'),
    ('apps/v1','Deployment'): ('/apis/apps/v1','deployments'),
    ('networking.k8s.io/v1','NetworkPolicy'): ('/apis/networking.k8s.io/v1','networkpolicies'),
    ('rbac.authorization.k8s.io/v1','Role'): ('/apis/rbac.authorization.k8s.io/v1','roles'),
    ('rbac.authorization.k8s.io/v1','RoleBinding'): ('/apis/rbac.authorization.k8s.io/v1','rolebindings'),
    ('kustomize.toolkit.fluxcd.io/v1','Kustomization'): ('/apis/kustomize.toolkit.fluxcd.io/v1','kustomizations'),
}


def resource_path(target, collection=False):
    prefix, plural = KINDS[(target['apiVersion'],target['kind'])]
    value = f"{prefix}/namespaces/{target['namespace']}/{plural}"
    return value if collection else value + '/' + target['name']


def _default(mapping, name, value):
    if mapping.get(name) == value:
        mapping.pop(name, None)


def normalize(obj):
    """Strict semantics with only known server identities/defaults removed."""
    value = copy.deepcopy(obj)
    meta = value['metadata']
    core._require(not meta.get('deletionTimestamp'), 'object is terminating')
    for key in ('uid','resourceVersion','generation','creationTimestamp','managedFields'):
        meta.pop(key,None)
    value.pop('status',None)
    annotations = meta.get('annotations',{})
    revision = annotations.get('deployment.kubernetes.io/revision')
    if value['kind']=='Deployment' and isinstance(revision,str) and revision.isdigit():
        annotations.pop('deployment.kubernetes.io/revision')
    annotations.pop('kubectl.kubernetes.io/last-applied-configuration',None)
    if not annotations: meta.pop('annotations',None)
    if value['kind']=='Kustomization':
        _default(meta,'finalizers',['finalizers.fluxcd.io'])
    if value['kind']=='ServiceAccount':
        _default(value,'secrets',[])
        _default(value,'imagePullSecrets',[])
    spec = value.get('spec',{})
    if value['kind']=='Service':
        core._require(spec.get('type','ClusterIP')=='ClusterIP' and not spec.get('externalIPs') and not spec.get('externalName'), 'non-internal Service forbidden')
        if 'clusterIP' in spec:
            core._require(ipaddress.ip_address(spec['clusterIP']).version == 4, 'Service IP family mismatch')
            core._require(spec.get('clusterIPs',[spec['clusterIP']]) == [spec['clusterIP']], 'Service IP allocation mismatch')
        for key in ('clusterIP','clusterIPs'): spec.pop(key,None)
        for key,default in [('type','ClusterIP'),('sessionAffinity','None'),('internalTrafficPolicy','Cluster'),('ipFamilyPolicy','SingleStack'),('ipFamilies',['IPv4'])]:
            _default(spec,key,default)
    if value['kind']=='NetworkPolicy':
        for direction in ('Ingress','Egress'):
            if direction in spec.get('policyTypes',[]): spec.setdefault(direction.lower(),[])
    if value['kind']=='Deployment':
        for key,default in [('progressDeadlineSeconds',600),('revisionHistoryLimit',10),('paused',False)]: _default(spec,key,default)
        _default(spec,'strategy',{'type':'RollingUpdate','rollingUpdate':{'maxSurge':'25%','maxUnavailable':'25%'}})
        template=spec['template']; template['metadata'].pop('creationTimestamp',None)
        pod=template['spec']
        if pod.get('serviceAccount') == pod.get('serviceAccountName'): pod.pop('serviceAccount',None)
        for key,default in [('dnsPolicy','ClusterFirst'),('restartPolicy','Always'),('schedulerName','default-scheduler'),('terminationGracePeriodSeconds',30),('imagePullSecrets',[])]: _default(pod,key,default)
        for volume in pod.get('volumes',[]):
            for kind in ('configMap','secret'):
                if kind in volume: _default(volume[kind],'defaultMode',420)
            if 'persistentVolumeClaim' in volume: _default(volume['persistentVolumeClaim'],'readOnly',False)
        for container in pod.get('containers',[])+pod.get('initContainers',[]):
            for key,default in [('terminationMessagePath','/dev/termination-log'),('terminationMessagePolicy','File'),('stdin',False),('tty',False),('env',[]),('resources',{})]: _default(container,key,default)
            for probe in ('startupProbe','livenessProbe','readinessProbe'):
                if probe in container:
                    for key,default in [('successThreshold',1),('initialDelaySeconds',0)]: _default(container[probe],key,default)
                    _default(container[probe].get('httpGet',{}),'scheme','HTTP')
    return value


class KubernetesAdapter:
    def __init__(self, admitted_root, revision, transport, *, clock=time.monotonic, pause=time.sleep):
        self.plan=core.build_plan(admitted_root)
        self.revision=revision
        self.transport=transport
        self.clock,self.pause=clock,pause
        self.allowed={resource_path(item['target']):item for item in self.plan['objects']}
        self.verifier=core._verifier()
        self.active=self.verifier.verify_tree(admitted_root)
        self.root=admitted_root
        self.existing=[]
        self.existing_flux={}
        for path in (admitted_root/'reviewed-render/roebel-staging').rglob('*.json'):
            if 'case-runtime' in path.relative_to(admitted_root/'reviewed-render/roebel-staging').parts:continue
            value=json.loads(path.read_text())
            if isinstance(value,dict) and value.get('kind') in {'Deployment','NetworkPolicy','Service','ServiceAccount','ConfigMap'} and value.get('metadata',{}).get('namespace'):
                self.existing.append(value)
                relative=path.relative_to(admitted_root/'reviewed-render/roebel-staging')
                group=relative.parts[0]
                owner={'web':'roebel-staging-web-workload','public-mecky':'roebel-staging-public-mecky-workload','reviewed-public-knowledge':'roebel-staging-reviewed-public-knowledge-workload','tracer-data-plane':'roebel-tracer-data-plane','workbench-baseline':'roebel-staging-workbench-baseline','staging-participant-gateway':'roebel-staging-participant-gateway'}[group]
                if 'workbench-ingress' in relative.parts:owner='roebel-staging-participant-workbench-ingress'
                self.existing_flux[resource_path(core.target(value))]=owner
        self.secret_uid=None
        self.preservation=None
        self.evidence={}

    def require_exact(self, observed, desired):
        core._require(normalize(observed)==normalize(desired), 'Case Kubernetes semantic drift')

    def get(self,target):
        path=resource_path(target)
        core._require(path in self.allowed and self.allowed[path]['target']==target, 'Case target outside reviewed inventory')
        return self.transport.request('GET',path,None)

    def create(self,desired):
        key=resource_path(core.target(desired))
        core._require(key in self.allowed,'Case creation outside reviewed inventory')
        expected=copy.deepcopy(self.allowed[key]['desired'])
        nonce=desired.get('metadata',{}).get('annotations',{}).get(core.NONCE)
        core._require(isinstance(nonce,str) and core.re.fullmatch('[0-9a-f]{64}',nonce),'Case creation nonce missing')
        expected['metadata'].setdefault('annotations',{})[core.NONCE]=nonce
        core._require(desired==expected,'Case create differs from pinned object')
        return self.transport.request('POST',resource_path(core.target(desired),True),desired)

    def _get(self,path):
        value=self.transport.request('GET',path,None)
        core._require(isinstance(value,dict),'required Kubernetes observation missing')
        return value

    def _ready(self,obj):
        core._require(not obj['metadata'].get('deletionTimestamp'),'terminating runtime object')
        core._require(obj['metadata']['generation']==obj.get('status',{}).get('observedGeneration'),'unobserved runtime generation')
        core._require(any(c.get('type')=='Ready' and c.get('status')=='True' for c in obj.get('status',{}).get('conditions',[])),'runtime not ready')

    def verify_preconditions(self,plan,*,require_secret=True):
        core._require(plan==self.plan,'Case precondition plan drift')
        cluster=self._get('/api/v1/namespaces/kube-system')
        core._require(cluster['metadata']['uid']==CLUSTER_UID,'wrong cluster')
        namespaces={}
        for name in (NAMESPACE,FLUX):
            ns=self._get('/api/v1/namespaces/'+name)
            core._require(ns.get('status',{}).get('phase')=='Active' and not ns['metadata'].get('deletionTimestamp') and ns['metadata'].get('labels',{}).get('kubernetes.io/metadata.name')==name,'required namespace identity/phase drift')
            namespaces[name]={'uid':ns['metadata']['uid'],'labels':ns['metadata']['labels']}
        source=self._get(f'/apis/source.toolkit.fluxcd.io/v1/namespaces/{FLUX}/gitrepositories/roebel-staging-operations')
        self._ready(source)
        core._require(source['status']['artifact']['revision']=='main@sha1:'+self.revision and not source['spec'].get('suspend',False),'Operations source drift')
        core._require(source['spec'].get('url')=='https://github.com/GiraeffleAeffle/roebel-staging-operations.git' and source['spec'].get('ref')=={'branch':'main'},'Operations source identity drift')
        binding=self.plan['review']['existingStorage']
        claim=binding['claim']
        pvc=self._get(f"/api/v1/namespaces/{claim['pvcNamespace']}/persistentvolumeclaims/{claim['pvcName']}")
        pv=self._get('/api/v1/persistentvolumes/'+claim['pvName'])
        core._require(pvc['metadata']['uid']==claim['pvcUid'] and pv['metadata']['uid']==binding['volumeUid'],'retained volume identity drift')
        core._require(pvc['status']['phase']=='Bound' and pv['status']['phase']=='Bound','retained volume unbound')
        core._require(pvc['spec']['volumeName']==claim['pvName'] and pv['spec']['claimRef']['uid']==claim['pvcUid'],'retained claim reference drift')
        core._require(pv['spec']['persistentVolumeReclaimPolicy']=='Retain','retained volume policy drift')
        for obj in (pvc,pv):
            core._require(not obj['metadata'].get('deletionTimestamp') and obj['spec']['accessModes']==['ReadWriteOncePod'] and obj['spec']['volumeMode']=='Filesystem' and obj['spec']['storageClassName']=='hcloud-volumes','retained storage shape drift')
        core._require(pvc['spec']['resources']['requests']['storage']=='10Gi' and pv['spec']['capacity']['storage']=='10Gi','retained storage capacity drift')
        if require_secret:
            secret_ref=self.plan['review']['separateCredentialProvisioning']
            secret=self._get(f"/api/v1/namespaces/{secret_ref['namespace']}/secrets/{secret_ref['name']}")
            core._require(secret.get('type')=='Opaque' and secret.get('immutable') is True and set(secret.get('data',{}))=={secret_ref['key']},'private configuration Secret shape drift')
            raw=base64.b64decode(secret['data'][secret_ref['key']],validate=True)
            core._require(len(raw)<=262144 and 'sha256:'+hashlib.sha256(raw).hexdigest()==secret_ref['configurationSha256'],'private configuration checksum mismatch')
            if self.secret_uid is None:self.secret_uid=secret['metadata']['uid']
            core._require(self.secret_uid==secret['metadata']['uid'],'private configuration Secret UID drift')
            del raw,secret
        # Verify actual workloads against the admitted render, not a baseline
        # captured from possibly drifted live state.
        existing_uids={}
        for desired in self.existing:
            path=resource_path(core.target(desired));live=self._get(path)
            existing_uids[path]=live['metadata']['uid']
            labels=live.get('metadata',{}).get('labels',{})
            for key,expected in [('kustomize.toolkit.fluxcd.io/name',self.existing_flux[path]),('kustomize.toolkit.fluxcd.io/namespace',FLUX)]:
                if key in labels:
                    core._require(labels[key]==expected,'existing workload Flux owner drift')
                    labels.pop(key)
            if not labels:live.get('metadata',{}).pop('labels',None)
            self.require_exact(live,desired)
            if desired['kind']!='Deployment':continue
            status=live.get('status',{})
            replicas=desired['spec']['replicas']
            core._require(status.get('observedGeneration')==live['metadata']['generation'] and all(status.get(k,0)==replicas for k in ('updatedReplicas','readyReplicas','availableReplicas')),'existing workload not ready')
        tracer_claim=self._get(f'/api/v1/namespaces/{NAMESPACE}/persistentvolumeclaims/roebel-tracer-postgres-data-v1')
        tracer_volume=self._get('/api/v1/persistentvolumes/'+tracer_claim['spec']['volumeName'])
        core._require(tracer_claim['metadata']['uid']=='d1c0ae47-37fc-43a8-8f2b-43fe7ca1a504' and tracer_volume['metadata']['uid']=='fdc96282-7d83-4f18-a463-3a3b9998cbe7','tracer retained storage identity drift')
        core._require(tracer_volume['spec']['persistentVolumeReclaimPolicy']=='Retain' and tracer_volume['spec']['claimRef']['uid']==tracer_claim['metadata']['uid'],'tracer retained storage binding drift')
        # Preserve the exact running tracer Pod and restart history. The live
        # activation boundary also binds desired render, network and workloads.
        pods=self._get(f'/api/v1/namespaces/{NAMESPACE}/pods')['items']
        postgres=[p for p in pods if p['metadata']['uid']==POSTGRES_UID]
        core._require(len(postgres)==1 and not postgres[0]['metadata'].get('deletionTimestamp'),'tracer Pod identity changed')
        core._require(postgres[0]['status']['phase']=='Running' and all(c['restartCount']==0 and c['ready'] for c in postgres[0]['status']['containerStatuses']),'tracer readiness/restart drift')
        preserved={
            'sourceUid':source['metadata']['uid'],'existingObjectUids':existing_uids,'namespaces':namespaces,
            'pvcUid':pvc['metadata']['uid'], 'pvUid':pv['metadata']['uid'],
            'pvcSpec':pvc['spec'],'pvSpec':pv['spec'],
            'postgresUid':POSTGRES_UID,'postgresSpec':postgres[0]['spec'],
            'tracerClaim':tracer_claim['spec'],'tracerVolume':tracer_volume['spec'],
        }
        if self.preservation is None: self.preservation=preserved
        core._require(self.preservation==preserved,'protected runtime preservation drift')

    def _pod(self,owned):
        deployment=self.get(owned['target'])
        core._require(deployment and deployment['metadata']['uid']==owned['uid'],'owned Deployment UID drift')
        desired=copy.deepcopy(self.allowed[resource_path(owned['target'])]['desired'])
        desired['metadata'].setdefault('annotations',{})[core.NONCE]=deployment.get('metadata',{}).get('annotations',{}).get(core.NONCE)
        core._require(core.canonical_sha256(desired)==owned['desiredSha256'],'owned deployment nonce/spec binding drift')
        self.require_exact(deployment,desired)
        status=deployment.get('status',{})
        if status.get('observedGeneration')!=deployment['metadata']['generation'] or any(status.get(k,0)!=1 for k in ('replicas','readyReplicas','updatedReplicas','availableReplicas')):
            return None
        replicasets=self._get(f'/apis/apps/v1/namespaces/{NAMESPACE}/replicasets')['items']
        owners={r['metadata']['uid'] for r in replicasets if any(o.get('uid')==owned['uid'] and o.get('controller') is True for o in r['metadata'].get('ownerReferences',[]))}
        pods=self._get(f'/api/v1/namespaces/{NAMESPACE}/pods')['items']
        matching=[p for p in pods if any(o.get('uid') in owners and o.get('controller') is True for o in p['metadata'].get('ownerReferences',[]))]
        if len(matching)!=1 or matching[0]['metadata'].get('deletionTimestamp'): return None
        pod=matching[0]
        if pod['status'].get('phase')!='Running' or not any(c.get('type')=='Ready' and c.get('status')=='True' for c in pod['status'].get('conditions',[])): return None
        expected=desired['spec']['template']['spec']
        # Compare complete pod intent using the same strict default normalization,
        # removing only the ReplicaSet's generated hash label from metadata.
        actual=copy.deepcopy(pod['spec']); actual.pop('nodeName',None)
        _default(actual,'priority',0)
        _default(actual,'preemptionPolicy','PreemptLowerPriority')
        default_tolerations=[{'key':'node.kubernetes.io/not-ready','operator':'Exists','effect':'NoExecute','tolerationSeconds':300}, {'key':'node.kubernetes.io/unreachable','operator':'Exists','effect':'NoExecute','tolerationSeconds':300}]
        _default(actual,'tolerations',default_tolerations)
        synthetic=copy.deepcopy(desired); synthetic['spec']['template']['spec']=actual
        self.require_exact(synthetic,desired)
        statuses=pod['status'].get('containerStatuses',[])
        core._require(len(statuses)==1 and statuses[0]['name']=='runtime' and statuses[0]['ready'],'runtime status mismatch')
        expected_image=expected['containers'][0]['image']
        core._require(statuses[0]['imageID'].endswith(expected_image.split('@')[1]),'running image digest mismatch')
        return pod

    def _wait(self,read,description):
        deadline=self.clock()+180
        while self.clock()<deadline:
            value=read()
            if value: return value
            self.pause(2)
        raise core.BootstrapStopped(description+' timed out')

    def verify_control_restart(self,owned,plan):
        self.verify_preconditions(plan)
        before=self._wait(lambda:self._pod(owned),'control startup')
        status=before['status']['containerStatuses'][0]
        old_count,old_id=status['restartCount'],status['containerID']
        uid=before['metadata']['uid']
        self.transport.exec_pod(NAMESPACE,before['metadata']['name'],uid,'runtime',
            ['node','-e',"process.kill(1, 'SIGTERM')"])
        def restarted():
            pod=self._pod(owned)
            if not pod:return None
            core._require(pod['metadata']['uid']==uid,'Pod replaced during restart verification')
            current=pod['status']['containerStatuses'][0]
            if current['restartCount']==old_count:return None
            core._require(current['restartCount']==old_count+1 and current['containerID']!=old_id and current.get('lastState',{}).get('terminated',{}).get('exitCode')==0,'control restart was not clean')
            return pod
        after=self._wait(restarted,'control clean restart')
        self.verify_preconditions(plan)
        self.evidence['controlRestart']={'podUid':uid,'beforeContainerId':old_id,'afterContainerId':after['status']['containerStatuses'][0]['containerID'],'exitCode':0,'restartCount':old_count+1}
        return copy.deepcopy(self.evidence['controlRestart'])

    def verify_public(self,owned,plan):
        pod=self._wait(lambda:self._pod(owned),'public replay readiness')
        self.verify_preconditions(plan)
        self.evidence['publicReady']={'podUid':pod['metadata']['uid'],'imageId':pod['status']['containerStatuses'][0]['imageID']}
        return copy.deepcopy(self.evidence['publicReady'])


    def verify_active_render(self,plan):
        self.verify_preconditions(plan)
        root=self.root/'reviewed-render/roebel-staging/case-runtime'
        for name in ('resources.json','kustomization.yaml'):
            current=root/name
            proposed=self.root/'proposals/synthetic-case-runtime'/name
            core._require(current.is_file() and not current.is_symlink() and current.read_bytes()==proposed.read_bytes(),'Case Flux render not admitted at this source revision')
        # A clean checkout, verified by the invocation boundary, binds this
        # render to the exact source revision required again immediately below.

    def without_case_flux_labels(self,observed):
        observed=copy.deepcopy(observed)
        labels=observed.get('metadata',{}).get('labels',{})
        for key,value in [('kustomize.toolkit.fluxcd.io/name','roebel-case-runtime'),('kustomize.toolkit.fluxcd.io/namespace',FLUX)]:
            if key in labels:
                core._require(labels[key]==value,'foreign Flux ownership label')
                labels.pop(key)
        if not labels:observed.get('metadata',{}).pop('labels',None)
        return observed

    def verify_flux_ready(self,owned,records):
        expected=copy.deepcopy(self.allowed[resource_path(owned['target'])]['desired'])
        expected['spec']['suspend']=False
        def reconciled():
            live=self.get(owned['target'])
            core._require(live and live['metadata']['uid']==owned['uid'],'Flux UID drift')
            self.require_exact(live,expected)
            status=live.get('status',{})
            if status.get('observedGeneration')!=live['metadata']['generation'] or status.get('lastAppliedRevision')!='main@sha1:'+self.revision:
                return None
            return live if any(c.get('type')=='Ready' and c.get('status')=='True' for c in status.get('conditions',[])) else None
        self._wait(reconciled,'Case Flux reconciliation')
        for item,record in zip(self.plan['objects'],records,strict=True):
            observed=self.get(item['target'])
            core._require(observed and observed['metadata']['uid']==record['uid'],'Flux handover changed owned UID')
            desired=copy.deepcopy(item['desired'])
            if desired['kind']=='Kustomization':desired['spec']['suspend']=False
            observed=self.without_case_flux_labels(observed)
            self.require_exact(observed,desired)
        self.verify_preconditions(self.plan)


class KubectlTransport:
    """Use an already bound Runner and kubeconfig snapshot from protected transport.

    The caller retains snapshot lifetime and executable binding. Request bodies
    travel on stdin; server errors are reduced to fixed, credential-free errors.
    """
    def __init__(self,runner,snapshot,plan):
        self.runner,self.snapshot=runner,snapshot
        self.targets={resource_path(o["target"]):o["target"] for o in plan["objects"]}
        self.secret_ref=plan["review"]["separateCredentialProvisioning"]

    def request(self,method,path,payload):
        core._require(isinstance(path,str) and path.startswith(('/api/','/apis/')) and all(c not in path for c in ('?','#','..','\n')),'invalid API path')
        args=['kubectl','--kubeconfig',str(self.snapshot.path),'--request-timeout=20s']
        if method=='GET':
            # Retry only an observed, transient TLS failure on a read. Writes
            # retain their single-send outcome and durable recovery boundary.
            for attempt in range(3):
                result=self.runner.run(args+['get','--raw',path],timeout=25)
                if result.code==0 or not any(error in result.err for error in ('TLS handshake timeout','context deadline exceeded')) or attempt==2:break
                time.sleep(0.25*(attempt+1))
            if result.code and result.err.startswith('Error from server (NotFound):'):return None
        elif method=='POST':
            if payload.get('kind')=='Secret':
                ref=self.secret_ref
                core._require(path==f"/api/v1/namespaces/{ref['namespace']}/secrets" and payload.get('metadata',{}).get('name')==ref['name'],'Secret provisioning target outside reviewed reference')
                core._require(payload.get('immutable') is True and payload.get('type')=='Opaque' and set(payload.get('data',{}))=={ref['key']},'Secret provisioning shape invalid')
                core._require('sha256:'+hashlib.sha256(base64.b64decode(payload['data'][ref['key']],validate=True)).hexdigest()==ref['configurationSha256'],'Secret provisioning bytes not pinned')
            else:
                target=core.target(payload)
                core._require(self.targets.get(resource_path(target))==target and path==resource_path(target,True),'POST target outside Case inventory')
            result=self.runner.run(args+['create','--raw',path,'-f','-'],input_text=json.dumps(payload,separators=(',',':')),timeout=25)
            if result.code and result.err.startswith('Error from server (AlreadyExists):'):
                raise core.CreateConflict('create conflict')
        else:
            raise core.BootstrapStopped('API method outside bootstrap transport')
        core._require(result.code==0,'Kubernetes request failed or outcome unresolved')
        core._require(len(result.out)<=4*1024*1024,'Kubernetes response exceeds bound')
        try:return json.loads(result.out)
        except (ValueError,TypeError):raise core.BootstrapStopped('Kubernetes response invalid') from None

    def exec_pod(self,namespace,name,uid,container,argv):
        core._require(namespace==NAMESPACE and container=='runtime' and argv==['node','-e',"process.kill(1, 'SIGTERM')"],'exec operation outside clean restart check')
        path=f'/api/v1/namespaces/{namespace}/pods/{name}'
        before=self.request('GET',path,None)
        core._require(before and before['metadata']['uid']==uid and not before['metadata'].get('deletionTimestamp'),'exec Pod identity drift')
        result=self.runner.run(['kubectl','--kubeconfig',str(self.snapshot.path),'--request-timeout=20s','exec','-n',namespace,name,'-c',container,'--',*argv],timeout=25)
        # Exec may lose its stream when PID1 exits. Do not resend. The caller
        # requires exactly one successful termination/restart before advancing.
        after=self.request('GET',path,None)
        core._require(after and after['metadata']['uid']==uid,'exec Pod replaced')

    def exec_case_request(self,name,uid,component,bundle=None):
        from . import case_runtime_saved_adoption as saved
        core._require(component in {'control','public'},'Case request component invalid')
        core._require((component=='public' and bundle is None) or (component=='control' and isinstance(bundle,bytes) and hashlib.sha256(bundle).hexdigest()==saved.BUNDLE_SHA256),'Case request payload outside saved adoption')
        path=f'/api/v1/namespaces/{NAMESPACE}/pods/{name}'
        before=self.request('GET',path,None)
        service_account='roebel-case-steward-control' if component=='control' else 'roebel-case-public-binding'
        core._require(before and before['metadata']['uid']==uid and before['spec']['serviceAccountName']==service_account and not before['metadata'].get('deletionTimestamp'),'Case request Pod identity mismatch')
        script=saved.ADMIT_JS if component=='control' else saved.READ_JS
        command=['kubectl','--kubeconfig',str(self.snapshot.path),'--request-timeout=20s','exec','-n',NAMESPACE,name,'-c','runtime']
        if bundle is not None:command.append('-i')
        result=self.runner.run(command+['--','node','--experimental-strip-types','--input-type=module','-e',script],input_text=bundle.decode() if bundle is not None else None,timeout=25)
        after=self.request('GET',path,None)
        core._require(after and after['metadata']['uid']==uid,'Case request Pod replaced')
        core._require(result.code==0 and len(result.out)<=32768,'Case request outcome unavailable; do not blindly resend')
        try:return json.loads(result.out)
        except (TypeError,ValueError):raise core.BootstrapStopped('Case response JSON invalid') from None

    def patch_owned(self,target,uid,version,operations):
        core._require(target['kind'] in {k for _,k in KINDS},'patch kind outside Case inventory')
        path=resource_path(target)
        core._require(self.targets.get(path)==target,'patch target outside Case inventory')
        nonce_path='/metadata/annotations/stadtstack.io~1case-bootstrap-nonce'
        nonce_patch=(len(operations)==2 and operations[0].get('op')=='test' and operations[0].get('path')==nonce_path and isinstance(operations[0].get('value'),str) and core.re.fullmatch('[0-9a-f]{64}',operations[0]['value']) and operations[1]=={'op':'remove','path':nonce_path})
        activate_patch=(target['kind']=='Kustomization' and operations==[{'op':'test','path':'/spec/suspend','value':True},{'op':'replace','path':'/spec/suspend','value':False}])
        core._require(nonce_patch or activate_patch,'patch operation outside exact handover')
        tests=[{'op':'test','path':'/metadata/uid','value':uid},{'op':'test','path':'/metadata/resourceVersion','value':version}]
        core._require(all(o['path'] in {'/metadata/annotations/stadtstack.io~1case-bootstrap-nonce','/spec/suspend'} for o in operations),'patch path outside ownership handover')
        result=self.runner.run(['kubectl','--kubeconfig',str(self.snapshot.path),'--request-timeout=20s','patch',target['kind'].lower(),target['name'],'-n',target['namespace'],'--type=json','-p',json.dumps(tests+operations,separators=(',',':')),'-o','json'],timeout=25)
        core._require(result.code==0,'owned patch outcome unresolved')
        try:return json.loads(result.out)
        except (ValueError,TypeError):raise core.BootstrapStopped('owned patch response invalid') from None
