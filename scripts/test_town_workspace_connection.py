"""Offline acceptance of the proposed connection; no admission hook or live writes."""
import copy
import importlib.util
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('workspace_proposal', ROOT/'scripts/town_workspace_connection.py')
policy = importlib.util.module_from_spec(spec); spec.loader.exec_module(policy)


def require(condition, message):
    if not condition: raise ValueError(message)


def file_set(root):
    return {str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() and '.git' not in p.parts and '__pycache__' not in p.parts}


def changed(a, b):
    files = file_set(a) | file_set(b)
    return {p for p in files if not (a/p).exists() or not (b/p).exists() or (a/p).read_bytes() != (b/p).read_bytes()}


V = SimpleNamespace(require=require, load_json=lambda p:json.loads(p.read_text()), changed_repository_files=changed)


def activate(root, stage):
    data=policy.bundle(V,root)
    for path, raw in policy.expected_files(data,stage).items(): (root/path).write_text(raw)
    (root/policy.STATE).write_text(json.dumps({'schemaVersion':'roebel_town_workspace_state_v1','stage':stage},indent=2)+'\n')


class WorkspaceRolloutTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base=Path(self.temporary.name)/'base'
        shutil.copytree(ROOT,self.base,ignore=shutil.ignore_patterns('.git','__pycache__','*.pyc'))
        self.data=policy.bundle(V,self.base)

    def candidate(self, stage):
        path=Path(self.temporary.name)/stage
        shutil.copytree(self.base,path)
        activate(path,stage)
        return path

    def test_preparation_preserves_every_existing_runtime_file(self):
        self.assertEqual(policy.verify(V,self.base)['stage'],'prepared')

    def test_login_then_review_are_complete_forward_transitions(self):
        login=self.candidate('login'); review=self.candidate('review')
        self.assertTrue(policy.verify_transition(V,login,self.base))
        self.assertTrue(policy.verify_transition(V,review,login))

    def test_cannot_skip_identity_subject_gate_or_roll_back_stage(self):
        login=self.candidate('login');review=self.candidate('review')
        for a,b in [(review,self.base),(login,review),(self.base,login)]:
            with self.assertRaisesRegex(ValueError,'exactly one'):policy.verify_transition(V,a,b)

    def test_partial_rollout_fails_closed(self):
        login=self.candidate('login')
        target=policy.ROOT+'web/ingress.json'
        (login/target).write_bytes((self.base/target).read_bytes())
        with self.assertRaisesRegex(ValueError,'stage file mismatch'):policy.verify(V,login)

    def test_unrelated_runtime_change_cannot_ride_with_activation(self):
        login=self.candidate('login')
        path=login/(policy.ROOT+'tracer-data-plane/postgres-deployment.json')
        path.write_text(path.read_text()+'\n')
        with self.assertRaisesRegex(ValueError,'unrelated files'):policy.verify_transition(V,login,self.base)

    def test_candidate_cannot_change_pinned_role_or_migration(self):
        for name in ['flux-bootstrap.json','workspace-sessions.sql','identity-state.sql']:
            path=self.base/(policy.PROPOSAL+name); original=path.read_bytes();path.write_bytes(original+b'\n')
            with self.assertRaisesRegex(ValueError,'pinned input changed'):policy.verify(V,self.base)
            path.write_bytes(original)

    def test_candidate_cannot_redefine_the_successor_bundle(self):
        path=self.base/policy.ROLLOUT; data=json.loads(path.read_text());data['secretValuesIncluded']=True;path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError,'independent pin'):policy.verify(V,self.base)

    def test_identity_has_one_replica_recreate_and_private_secret_references(self):
        resources=json.loads((self.base/(policy.ROOT+'identity/resources.json')).read_text())['items']
        deploy=next(o for o in resources if o['kind']=='Deployment');ps=deploy['spec']['template']['spec'];c=ps['containers'][0]
        self.assertEqual(deploy['spec']['replicas'],1);self.assertEqual(deploy['spec']['strategy'],{'type':'Recreate'})
        self.assertFalse(ps['automountServiceAccountToken']);self.assertTrue(c['securityContext']['readOnlyRootFilesystem'])
        self.assertNotIn('volumes',ps);self.assertNotIn('envFrom',c)
        private={e['name']:e for e in c['env'] if 'valueFrom' in e}
        self.assertEqual(set(private),{'COOKIE_KEYS','JWKS_JSON','WEB_CLIENT_SECRET','STAGING_IDENTITY_DATABASE_KEY','STAGING_ALLOWED_WALLETS'})
        self.assertTrue(all(e['valueFrom']['secretKeyRef']['name']=='roebel-staging-identity-v1' for e in private.values()))
        self.assertTrue(all(o['kind'] not in ['Secret','PersistentVolumeClaim'] for o in resources))

    def test_identity_database_network_is_reciprocal_and_rpc_is_one_ip(self):
        resources=json.loads((self.base/(policy.ROOT+'identity/resources.json')).read_text())['items']
        deploy=next(o for o in resources if o['kind']=='Deployment');labels=deploy['spec']['selector']['matchLabels']
        np=next(o for o in resources if o['kind']=='NetworkPolicy' and o['metadata']['name']=='roebel-id-staging')
        reciprocal=next(o for o in resources if o['kind']=='NetworkPolicy' and o['metadata']['name']!='roebel-id-staging')
        pg=next(r for r in np['spec']['egress'] if r['ports']==[{'port':3000,'protocol':'TCP'}])
        self.assertEqual(pg['to'][0]['podSelector'],reciprocal['spec']['podSelector'])
        self.assertEqual(reciprocal['spec']['ingress'][0]['from'][0]['podSelector']['matchLabels'],labels)
        ips=[t['ipBlock']['cidr'] for r in np['spec']['egress'] for t in r['to'] if 'ipBlock' in t]
        self.assertEqual(ips,['34.111.230.52/32'])

    def test_flux_has_no_secret_create_delete_or_wildcard_rights(self):
        objects=json.loads((self.base/(policy.PROPOSAL+'flux-bootstrap.json')).read_text())['items']
        for role in [o for o in objects if o['kind']=='Role']:
            for r in role['rules']:
                self.assertNotIn('secrets',r['resources']);self.assertNotIn('*',str(r));self.assertNotIn('create',r['verbs']);self.assertNotIn('delete',r['verbs'])
                if 'resourceNames' not in r:self.assertEqual(r['verbs'],['list']);self.assertIn(r['resources'],[['pods'],['replicasets']])
        k=next(o for o in objects if o['kind']=='Kustomization')
        self.assertTrue(k['spec']['suspend']);self.assertFalse(k['spec']['prune'])
        self.assertEqual(k['metadata']['labels'],{'stadtstack.io/flux-tenant':'roebel-staging'})

    def test_review_only_adds_service_port_and_exact_inbound_policy(self):
        key=policy.ROOT+'case-runtime/resources.json'
        before=json.loads((self.base/key).read_text());after=json.loads(self.data['stages']['review']['files'][key])
        added=after['items'].pop();self.assertEqual(added['kind'],'NetworkPolicy')
        self.assertEqual(added['metadata']['name'],'roebel-case-steward-control-allow-workspace-review')
        service=next(o for o in after['items'] if o['kind']=='Service' and o['metadata']['name']=='roebel-case-steward-control')
        self.assertEqual(service['spec']['ports'].pop(),{'name':'admin-review','port':18090,'protocol':'TCP','targetPort':18090})
        self.assertEqual(after,before)

    def test_review_mount_is_readonly_and_subject_gate_is_explicit(self):
        review=json.loads(self.data['stages']['review']['files'][policy.ROOT+'web/deployment.json'])
        ps=review['spec']['template']['spec'];c=ps['containers'][0]
        mount=next(m for m in c['volumeMounts'] if m['name']=='town-workspace-review')
        self.assertTrue(mount['readOnly']); self.assertIn('verified-subject-and-unexpired-explicit-review-grants',self.data['activationGates'])
        self.assertEqual(self.data['stages']['login']['boundary']['reviewEnabled'],False)

    def test_web_workspace_methods_are_closed(self):
        # Evaluate the exact HAProxy conditions for each route/method pair,
        # including negative HEAD/DELETE and neighboring-path probes.
        def status(rules,method,path):
            for line in rules.splitlines():
                m=re.fullmatch(r'http-request deny deny_status (\d+) (if|unless) (.*)',line)
                conditions=re.findall(r'(!?)\{ (method|path|path_beg|path_reg) (.*?) \}',m[3])
                values=[]
                for neg,kind,raw in conditions:
                    match=method in raw.split() if kind=='method' else (path in raw.split() if kind=='path' else (any(path.startswith(x) for x in raw.split()) if kind=='path_beg' else bool(re.search(raw,path))))
                    values.append(not match if neg else match)
                match=all(values)
                if (match if m[2]=='if' else not match):return int(m[1])
            return 200
        for stage in ['login','review']:
            ingress=json.loads(self.data['stages'][stage]['files'][policy.ROOT+'web/ingress.json'])
            rules=ingress['metadata']['annotations']['haproxy-ingress.github.io/config-backend-early']
            for route in self.data['stages'][stage]['boundary']['routes']:
                for method in ['GET','HEAD','POST','PUT','DELETE','OPTIONS']:
                    self.assertEqual(status(rules,method,route['path'])==200,method in route['methods'],(stage,method,route))
            self.assertEqual(status(rules,'GET','/api/workspace/files'),404)
            self.assertEqual(status(rules,'POST','/api/chat/mecky'),200)
            self.assertEqual(status(rules,'GET','/api/stadtstack/case-bindings/by-discussion/'+'a'*64),200)
