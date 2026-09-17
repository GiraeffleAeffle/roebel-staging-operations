"""Offline acceptance of the proposed connection; no admission hook or live writes."""
import copy
import importlib.util
import hashlib
import subprocess
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
spec = importlib.util.spec_from_file_location('workspace_comment_policy', ROOT/'scripts/comment_mecky_rollout.py')
comment_policy = importlib.util.module_from_spec(spec); spec.loader.exec_module(comment_policy)


def require(condition, message):
    if not condition: raise ValueError(message)


def file_set(root):
    return {str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() and '.git' not in p.parts and '__pycache__' not in p.parts}


def changed(a, b):
    files = file_set(a) | file_set(b)
    return {p for p in files if not (a/p).exists() or not (b/p).exists() or (a/p).read_bytes() != (b/p).read_bytes()}


V = SimpleNamespace(require=require, load_json=lambda p:json.loads(p.read_text()), changed_repository_files=changed,
                    COMMENT_MECKY=comment_policy)


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
        if comment_policy.enabled(self.base):
            contract_path = self.base / 'policy/repository-contract.json'
            workbench = json.loads(contract_path.read_text())['workbenchImagePromotionBoundary']
            for path in comment_policy.TRANSITION_FILES - {str(comment_policy.RECORD_PATH)}:
                (self.base/path).write_bytes(subprocess.check_output(['git','-C',str(ROOT),'show',
                    '0282b120facf75b174be4b20422d74827af95410:'+path]))
            (self.base/comment_policy.RECORD_PATH).unlink()
            contract = json.loads(contract_path.read_text())
            contract['workbenchImagePromotionBoundary'] = workbench
            contract_path.write_text(json.dumps(contract, indent=2) + '\n')
        self.data=policy.bundle(V,self.base)
        # Identity was introduced by preparation, so predecessorFiles does not
        # restore it. Rebuild the historical fixture from the published blob;
        # copying the active demo roster into earlier stages invalidates them.
        relative = policy.ROOT + 'identity/resources.json'
        raw = subprocess.check_output([
            'git', '-C', str(ROOT), 'show',
            'c96ceb92fc302ea296b2d6240a156b336eff8eb8:' + relative,
        ])
        self.assertEqual('sha256:' + hashlib.sha256(raw).hexdigest(),
                         self.data['proposalFiles'][relative])
        (self.base / relative).write_bytes(raw)
        # Every stage is tested from its pinned prepared predecessor, even
        # when the repository's current render has already advanced.
        for relative, expected in self.data['predecessorFiles'].items():
            path = self.base / relative
            if 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raw = subprocess.check_output([
                    'git', '-C', str(ROOT), 'show',
                    self.data['operationsPredecessor'] + ':' + relative,
                ])
                self.assertEqual('sha256:' + hashlib.sha256(raw).hexdigest(), expected)
                path.write_bytes(raw)
        activate(self.base, 'prepared')

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

    def test_both_stages_pass_the_complete_protected_admission_verifier(self):
        spec = importlib.util.spec_from_file_location('workspace_integration_verifier', ROOT/'scripts/verify-reviewed-render.py')
        verifier = importlib.util.module_from_spec(spec); spec.loader.exec_module(verifier)
        before = verifier.verify_tree(self.base)
        for stage in ['login', 'review', 'brief', 'multi-case', 'demo-login']:
            after = verifier.verify_tree(self.candidate(stage))
            verifier.verify_transition(after, before)
            before = after

    def buergerrat_access_transition(self):
        before = Path(self.temporary.name) / 'access-before'
        shutil.copytree(ROOT, before, ignore=shutil.ignore_patterns('.git', '__pycache__', '*.pyc'))
        paths = set(self.data['stages']['buergerrat-access']['files']) | {policy.STATE}
        for path in paths:
            (before / path).write_bytes(subprocess.check_output([
                'git', '-C', str(ROOT), 'show', '3234b888b7fdf968e688d33603453c0c4e500604:' + path,
            ]))
        after = Path(self.temporary.name) / 'access-after'
        shutil.copytree(before, after)
        for path, raw in self.data['stages']['buergerrat-access']['files'].items():
            (after / path).write_text(raw)
        (after / policy.STATE).write_text(json.dumps({
            'schemaVersion': 'roebel_town_workspace_state_v1', 'stage': 'buergerrat-access',
        }, indent=2) + '\n')
        return before, after

    def test_buergerrat_access_passes_complete_admission_without_image_or_network_changes(self):
        before, after = self.buergerrat_access_transition()
        spec = importlib.util.spec_from_file_location('access_verifier', ROOT/'scripts/verify-reviewed-render.py')
        verifier = importlib.util.module_from_spec(spec); spec.loader.exec_module(verifier)
        verifier.verify_transition(verifier.verify_tree(after), verifier.verify_tree(before))
        self.assertEqual(changed(after, before), set(self.data['stages']['buergerrat-access']['files']) | {policy.STATE})
        for name in ('web/deployment.json', 'public-mecky/deployment.json'):
            old = json.loads((before/(policy.ROOT+name)).read_text())['spec']['template']['spec']['containers'][0]
            new = json.loads((after/(policy.ROOT+name)).read_text())['spec']['template']['spec']['containers'][0]
            self.assertEqual(old['image'], new['image'])
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            policy.verify_transition(V, before, after)

    def test_buergerrat_access_rejects_changed_secret_config_pin_or_mecky_case(self):
        before, after = self.buergerrat_access_transition()
        spec = importlib.util.spec_from_file_location('access_negative_verifier', ROOT/'scripts/verify-reviewed-render.py')
        verifier = importlib.util.module_from_spec(spec); spec.loader.exec_module(verifier)
        interface = verifier.citizen_status_interface()
        path=after/(policy.ROOT+'case-runtime/resources.json');original=path.read_bytes()
        for replacement in ('roebel-case-steward-other-runtime-v1', '0'*64):
            value=json.loads(original)
            control=next(o for o in value['items'] if o['kind']=='Deployment' and o['metadata']['name']=='roebel-case-steward-control')
            env=control['spec']['template']['spec']['initContainers'][0]['env']
            if replacement.startswith('roebel-'):env[0]['valueFrom']['secretKeyRef']['name']=replacement
            else:env[1]['value']=replacement
            path.write_text(json.dumps(value,indent=2)+'\n')
            with self.assertRaisesRegex(verifier.VerificationError, 'stage file mismatch'):
                policy.verify_transition(interface,after,before)
        path.write_bytes(original)
        path=after/(policy.ROOT+'public-mecky/deployment.json');original=path.read_bytes();value=json.loads(original)
        env=next(e for e in value['spec']['template']['spec']['containers'][0]['env'] if e['name']=='MECKY_SYNTHETIC_BRIEF_CONFIG')
        config=json.loads(env['value']);config['additionalBindings'][0]['caseId']=config['caseId'];env['value']=json.dumps(config)
        path.write_text(json.dumps(value,indent=2)+'\n')
        with self.assertRaisesRegex(verifier.VerificationError, 'deployment changed'):
            policy.verify_transition(interface,after,before)

    def discussion_context_transition(self):
        before = Path(self.temporary.name) / 'context-before'
        shutil.copytree(ROOT, before, ignore=shutil.ignore_patterns('.git', '__pycache__', '*.pyc'))
        # Restore only this rollout's live predecessor; retain today's policy.
        paths = set(self.data['stages']['discussion-context']['files']) | set(self.data['stages']['buergerrat-access']['files']) | {policy.STATE}
        for path in paths:
            (before / path).write_bytes(subprocess.check_output([
                'git', '-C', str(ROOT), 'show',
                'a19e23df47e3818e1c7981d1cadf229299644556:' + path,
            ]))
        after = Path(self.temporary.name) / 'context-after'
        shutil.copytree(before, after)
        for path, raw in self.data['stages']['discussion-context']['files'].items():
            (after / path).write_text(raw)
        (after / policy.STATE).write_text(json.dumps({
            'schemaVersion': 'roebel_town_workspace_state_v1', 'stage': 'discussion-context',
        }, indent=2) + '\n')
        return before, after

    def test_discussion_context_passes_complete_admission_and_preserves_other_resources(self):
        before, after = self.discussion_context_transition()
        spec = importlib.util.spec_from_file_location('context_verifier', ROOT / 'scripts/verify-reviewed-render.py')
        verifier = importlib.util.module_from_spec(spec); spec.loader.exec_module(verifier)
        verifier.verify_transition(verifier.verify_tree(after), verifier.verify_tree(before))
        self.assertEqual(changed(after, before), policy.RELEASE_RECORDS | policy.RELEASE_DEPLOYMENTS | {policy.STATE})
        read = lambda root: json.loads((root / (policy.ROOT + 'public-mecky/deployment.json')).read_text())
        old = read(before)['spec']['template']['spec']['containers'][0]['env']
        current = read(after)['spec']['template']['spec']['containers'][0]['env']
        pair = current[-4:-2]
        self.assertEqual(pair, [
            {'name': 'MECKY_PUBLIC_APP_BASE_URL', 'value': 'http://roebel-web-presentation.stadtstack-roebel-web-preview.svc.cluster.local:8080'},
            {'name': 'MECKY_PUBLIC_APP_ORIGIN', 'value': 'https://roebel-web.staging.agentcart.eu'},
        ])
        self.assertEqual(current[:-4] + current[-2:], old)
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            policy.verify_transition(V, before, after)
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            policy.verify_transition(V, after, self.candidate('multi-case'))

    def test_discussion_context_rejects_changed_origin_partial_pair_and_other_env(self):
        before, after = self.discussion_context_transition()
        spec = importlib.util.spec_from_file_location('context_negative_verifier', ROOT / 'scripts/verify-reviewed-render.py')
        verifier = importlib.util.module_from_spec(spec); spec.loader.exec_module(verifier)
        path = after / (policy.ROOT + 'public-mecky/deployment.json')
        original = json.loads(path.read_text())
        for mutation in ('origin', 'partial', 'extra', 'reordered'):
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(original)
                env = value['spec']['template']['spec']['containers'][0]['env']
                if mutation == 'origin': env[-3]['value'] = 'https://example.invalid'
                if mutation == 'partial': del env[-4]
                if mutation == 'extra': env.insert(-2, {'name': 'UNREVIEWED', 'value': 'true'})
                if mutation == 'reordered': env[-4:-2] = list(reversed(env[-4:-2]))
                path.write_text(json.dumps(value, indent=2) + '\n')
                with self.assertRaisesRegex(verifier.VerificationError, 'outside reviewed release fields'):
                    policy.verify_transition(verifier, after, before)

    def test_demo_login_changes_only_allowlist_source_and_cannot_skip_or_regress(self):
        before = self.candidate('multi-case'); after = self.candidate('demo-login')
        self.assertTrue(policy.verify_transition(V, after, before))
        path = policy.ROOT + 'identity/resources.json'
        self.assertEqual(changed(after, before), {policy.STATE, path})
        previous = json.loads((before/path).read_text())
        current = json.loads((after/path).read_text())
        deployment = next(o for o in current['items'] if o['kind'] == 'Deployment')
        env = deployment['spec']['template']['spec']['containers'][0]['env']
        roster = next(e for e in env if e['name'] == 'STAGING_ALLOWED_WALLETS')
        self.assertEqual(roster['valueFrom']['secretKeyRef'], {
            'name': 'roebel-staging-demo-login-v1', 'key': 'allowed-wallets', 'optional': False})
        roster['valueFrom']['secretKeyRef']['name'] = 'roebel-staging-identity-v1'
        self.assertEqual(current, previous)
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            policy.verify_transition(V, before, after)
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            policy.verify_transition(V, after, self.candidate('brief'))
        # Repointing a signing key is not part of login admission, even when the
        # Deployment otherwise has the admitted account-list reference.
        current = json.loads((after/path).read_text())
        deployment = next(o for o in current['items'] if o['kind'] == 'Deployment')
        key = next(e for e in deployment['spec']['template']['spec']['containers'][0]['env'] if e['name'] == 'JWKS_JSON')
        key['valueFrom']['secretKeyRef']['name'] = 'unreviewed-signing-keys'
        (after/path).write_text(json.dumps(current, indent=2)+'\n')
        with self.assertRaisesRegex(ValueError, 'pinned input changed'):
            policy.verify_transition(V, after, before)

    def test_multi_case_stage_only_advances_the_control_image_and_binding(self):
        before = self.candidate('brief'); after = self.candidate('multi-case')
        self.assertTrue(policy.verify_transition(V, after, before))
        self.assertEqual(changed(after, before), {policy.STATE, policy.ROOT+'case-runtime/resources.json'})
        read = lambda root: json.loads((root/(policy.ROOT+'case-runtime/resources.json')).read_text())['items']
        old, new = read(before), read(after)
        identify = lambda obj: (obj['kind'], obj['metadata']['name'])
        old_by_id = {identify(o):o for o in old}; new_by_id = {identify(o):o for o in new}
        self.assertEqual(set(new_by_id)-set(old_by_id), {('ConfigMap','roebel-case-steward-multicase-reviewed-v1')})
        for key, value in old_by_id.items():
            if key != ('Deployment','roebel-case-steward-control'): self.assertEqual(value, new_by_id[key])
        key = ('Deployment','roebel-case-steward-control')
        previous = old_by_id[key]; restored = copy.deepcopy(new_by_id[key])
        a = previous['spec']['template']['spec']; b = restored['spec']['template']['spec']
        for field in ('containers','initContainers'): b[field][0]['image'] = a[field][0]['image']
        next(e for e in b['containers'][0]['env'] if e['name']=='STADTSTACK_CASE_CONTROL_BINDING_SHA256')['value'] = next(e['value'] for e in a['containers'][0]['env'] if e['name']=='STADTSTACK_CASE_CONTROL_BINDING_SHA256')
        next(v for v in b['volumes'] if v['name']=='reviewed')['configMap']['name'] = next(v['configMap']['name'] for v in a['volumes'] if v['name']=='reviewed')
        self.assertEqual(restored, previous)
        with self.assertRaisesRegex(ValueError, 'exactly one'): policy.verify_transition(V, before, after)
        (after/'README.md').write_text((after/'README.md').read_text()+'\nUnrelated change\n')
        with self.assertRaisesRegex(ValueError, 'unrelated files'): policy.verify_transition(V, after, before)

    def test_brief_keeps_runtime_shape_pinned_but_does_not_freeze_release_fields(self):
        brief=self.candidate('brief')
        path=brief/(policy.ROOT+'web/deployment.json')
        original=json.loads(path.read_text());changed=copy.deepcopy(original)
        changed['spec']['template']['spec']['containers'][0]['image']='ghcr.io/giraeffleaeffle/roebel-web-staging@sha256:'+'7'*64
        path.write_text(json.dumps(changed,indent=2)+'\n')
        # The workspace shape checker delegates only release validation; the
        # complete verifier still rejects an image without its matching head.
        self.assertEqual(policy.verify(V,brief)['stage'],'brief')
        spec=importlib.util.spec_from_file_location('brief_release_verifier',ROOT/'scripts/verify-reviewed-render.py')
        verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier)
        with self.assertRaisesRegex(verifier.VerificationError,'image binding invalid'):verifier.verify_tree(brief)
        review=self.candidate('review')
        with self.assertRaisesRegex(ValueError,'exact published release'):policy.verify_transition(V,brief,review)
        changed['spec']['template']['spec']['containers'][0]['env'].append({'name':'UNREVIEWED_ORIGIN','value':'https://example.invalid'})
        path.write_text(json.dumps(changed,indent=2)+'\n')
        with self.assertRaisesRegex(ValueError,'outside reviewed release fields'):policy.verify(V,brief)

    def test_brief_uses_one_new_binding_map_and_preserves_all_roles_and_storage(self):
        review=self.candidate('review');brief=self.candidate('brief')
        before=json.loads((review/(policy.ROOT+'case-runtime/resources.json')).read_text())['items']
        after=json.loads((brief/(policy.ROOT+'case-runtime/resources.json')).read_text())['items']
        identify=lambda o:(o['kind'],o['metadata']['name'])
        old={identify(o):o for o in before};new={identify(o):o for o in after}
        self.assertEqual(set(new)-set(old),{('ConfigMap','roebel-case-steward-brief-reviewed-v1')})
        for key,value in old.items():
            if key!=('Deployment','roebel-case-steward-control'):self.assertEqual(new[key],value)
        a=old[('Deployment','roebel-case-steward-control')]['spec']['template']['spec']
        b=new[('Deployment','roebel-case-steward-control')]['spec']['template']['spec']
        self.assertEqual(a['securityContext'],b['securityContext'])
        self.assertEqual([x for x in a['volumes'] if x['name']!='reviewed'],[x for x in b['volumes'] if x['name']!='reviewed'])
        self.assertEqual(a['initContainers'][0]['env'],b['initContainers'][0]['env'])

    def test_brief_reader_accepts_only_the_complete_fixed_pair(self):
        brief = self.candidate('brief')
        path = brief / (policy.ROOT + 'public-mecky/deployment.json')
        original = json.loads(path.read_text())
        def write(extra):
            value = copy.deepcopy(original)
            value['spec']['template']['spec']['containers'][0]['env'].extend(extra)
            path.write_text(json.dumps(value))
        write(policy.BRIEF_READER_ENV)
        self.assertEqual(policy.verify(V, brief)['stage'], 'brief')
        wrong_config = copy.deepcopy(policy.BRIEF_READER_ENV)
        config = json.loads(wrong_config[1]['value'])
        config['publicOrigin'] = 'https://example.invalid'
        wrong_config[1]['value'] = json.dumps(config, sort_keys=True, separators=(',', ':'))
        for extra in [policy.BRIEF_READER_ENV[:1], policy.BRIEF_READER_ENV[1:],
                      policy.BRIEF_READER_ENV * 2, list(reversed(policy.BRIEF_READER_ENV)),
                      wrong_config, policy.BRIEF_READER_ENV + [{'name': 'UNREVIEWED', 'value': 'true'}]]:
            with self.subTest(extra=extra):
                write(extra)
                with self.assertRaisesRegex(ValueError, 'outside reviewed release fields'):
                    policy.verify(V, brief)

    def test_brief_reader_does_not_relax_the_web_deployment(self):
        brief = self.candidate('brief')
        path = brief / (policy.ROOT + 'web/deployment.json')
        value = json.loads(path.read_text())
        value['spec']['template']['spec']['containers'][0]['env'].extend(policy.BRIEF_READER_ENV)
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'outside reviewed release fields'):
            policy.verify(V, brief)

    def test_reader_activation_requires_the_initial_release_and_keeps_cas_validation(self):
        before = self.candidate('brief')
        after = Path(self.temporary.name) / 'reader'
        shutil.copytree(before, after)
        path = after / (policy.ROOT + 'public-mecky/deployment.json')
        value = json.loads(path.read_text())
        value['spec']['template']['spec']['containers'][0]['env'].extend(policy.BRIEF_READER_ENV)
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'only its reviewed Release Set'):
            policy.verify_transition(V, after, before)
        for relative in (policy.RELEASE_RECORDS | policy.RELEASE_DEPLOYMENTS) - {str(path.relative_to(after))}:
            with (after / relative).open('a') as file: file.write('\n')
        with self.assertRaisesRegex(ValueError, 'exact initial transport release'):
            policy.verify_transition(V, after, before)
        head_path = after / (policy.ROOT + 'head.json')
        head = copy.deepcopy(policy.BRIEF_READER_INITIAL_HEAD)
        head_path.write_text(json.dumps(head))
        # False deliberately delegates to the full verifier; this partial
        # release fixture cannot become an admission success through this hook.
        self.assertFalse(policy.verify_transition(V, after, before))
        spec = importlib.util.spec_from_file_location('reader_cas_verifier', ROOT/'scripts/verify-reviewed-render.py')
        verifier = importlib.util.module_from_spec(spec); spec.loader.exec_module(verifier)
        with self.assertRaises(verifier.VerificationError): verifier.verify(after, before)
        with self.assertRaisesRegex(ValueError, 'cannot regress'):
            policy.verify_transition(V, before, after)
        with (after / 'README.md').open('a') as file: file.write('\nUnrelated change\n')
        with self.assertRaisesRegex(ValueError, 'only its reviewed Release Set'):
            policy.verify_transition(V, after, before)

    def test_steady_state_cannot_replace_the_protected_workspace_implementation(self):
        candidate = Path(self.temporary.name)/'tampered'
        shutil.copytree(self.base, candidate)
        with (candidate/'scripts/town_workspace_connection.py').open('a') as file:
            file.write('\n# candidate replacement\n')
        with self.assertRaisesRegex(ValueError, 'protected rollout inputs'):
            policy.verify_transition(V, candidate, self.base)

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
