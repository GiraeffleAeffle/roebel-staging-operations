"""Admission and request-boundary tests for the signed comment successor."""
import copy
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('comment_test_verifier', ROOT / 'scripts/verify-reviewed-render.py')
v = importlib.util.module_from_spec(spec); spec.loader.exec_module(v)
c = v.COMMENT_MECKY


class CommentRolloutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='roebel-comment-tests-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.base = Path(cls.temp.name) / 'base'
        shutil.copytree(ROOT, cls.base, ignore=shutil.ignore_patterns('.git', '__pycache__', '*.pyc'))
        # This test describes the fixed pre-comment transition, including after
        # its desired state has subsequently reached main.
        import subprocess
        if v.TOWN_WORKSPACE.stage(v, cls.base) == 'buergerrat-access':
            data = v.TOWN_WORKSPACE.bundle(v, cls.base)
            for path in set(data['stages']['buergerrat-access']['files']) | {v.TOWN_WORKSPACE.STATE}:
                (cls.base / path).write_bytes(subprocess.check_output([
                    'git', '-C', str(ROOT), 'show', '3234b888b7fdf968e688d33603453c0c4e500604:' + path,
                ]))
        contract_path = cls.base / 'policy/repository-contract.json'
        workbench = json.loads(contract_path.read_text())['workbenchImagePromotionBoundary']
        for path in c.TRANSITION_FILES - {str(c.RECORD_PATH)}:
            (cls.base / path).write_bytes(subprocess.check_output(['git', '-C', str(ROOT), 'show',
                '0282b120facf75b174be4b20422d74827af95410:' + path]))
        for name in ('head.json', 'live-preconditions.json', 'web/deployment.json', 'public-mecky/deployment.json'):
            path = str(Path(v.RENDER_ROOT) / name)
            (cls.base / path).write_bytes(subprocess.check_output(['git', '-C', str(ROOT), 'show',
                '0282b120facf75b174be4b20422d74827af95410:' + path]))
        (cls.base / c.RECORD_PATH).unlink(missing_ok=True)
        if v.TOWN_WORKSPACE.stage(v, cls.base) == 'discussion-context':
            (cls.base / v.TOWN_WORKSPACE.STATE).write_text(json.dumps({
                'schemaVersion': 'roebel_town_workspace_state_v1', 'stage': 'demo-login',
            }, indent=2) + '\n')
        contract = json.loads(contract_path.read_text())
        contract['workbenchImagePromotionBoundary'] = workbench
        contract_path.write_text(json.dumps(contract, indent=2) + '\n')
        cls.before = v.verify_tree(cls.base)
        cls.files = c.activation_files(v, cls.base, cls.before)

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='roebel-comment-candidate-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        shutil.copytree(self.base, self.root, dirs_exist_ok=True)
        for path, raw in self.files.items():
            (self.root / path).write_text(raw)

    def test_complete_transition_and_steady_state_preserve_case_storage_and_roles(self):
        after = v.verify_tree(self.root)
        v.verify_transition(after, self.before)
        self.assertTrue(after['commentMecky'])
        self.assertTrue(after['citizenEligibilityStatus'])
        self.assertEqual(v.changed_repository_files(self.root, self.base), c.TRANSITION_FILES)
        for key in ('head', 'objects', 'deployments', 'tracerDataPlane', 'signedNostr', 'webIdentityContractSet'):
            self.assertEqual(after[key], self.before[key], key)

    def test_exact_post_and_options_route_keep_get_head_and_rate_limit(self):
        gateway = c.resources(v, self.before['stagingParticipantGatewayPolicy'], True)
        old = self.before['stagingParticipantGateway']
        key = 'haproxy-ingress.github.io/config-backend-early'
        a = old['ingress']['metadata']['annotations'][key].splitlines()
        b = gateway['ingress']['metadata']['annotations'][key].splitlines()
        self.assertEqual(a[3:], b[3:])
        self.assertTrue(all(len(line.split()) < 64 for line in b))
        # Evaluate HAProxy's path/path_beg ACLs independently of the generator.
        def admitted(method, path):
            for line in b[:6]:
                if 'deny_status 429' in line: continue
                tail = re.split(r' (if|unless) ', line, maxsplit=1)
                conditions = []
                for negated, kind, values in re.findall(r'(!?)\{ (method|path|path_beg) ([^}]+) \}', tail[2]):
                    values = values.split()
                    match = method in values if kind == 'method' else (path in values if kind == 'path' else any(path.startswith(x) for x in values))
                    conditions.append(not match if negated else match)
                condition = all(conditions)
                if (condition if tail[1] == 'if' else not condition): return False
            return True
        self.assertTrue(admitted('POST', c.ROUTE))
        self.assertTrue(admitted('OPTIONS', c.ROUTE))
        for method in ('GET', 'HEAD', 'PUT', 'DELETE'):
            self.assertFalse(admitted(method, c.ROUTE))
        for suffix in ('/', '/other', '-extra'):
            self.assertFalse(admitted('POST', c.ROUTE + suffix))
        for path in v.PARTICIPANT_POLICY.POST_ROUTES:
            self.assertTrue(admitted('POST', path), path)
        self.assertEqual(old['ingress']['spec'], gateway['ingress']['spec'])
        for name in ('serviceAccount', 'service', 'networkPolicy', 'workbenchIngressNetworkPolicy'):
            self.assertEqual(old[name], gateway[name])

    def test_no_new_secrets_or_runtime_privileges(self):
        old = copy.deepcopy(self.before['stagingParticipantGateway']['deployment'])
        new = json.loads(self.files[str(Path(v.PARTICIPANT_GATEWAY_ROOT) / 'deployment.json')])
        container = old['spec']['template']['spec']['containers'][0]
        container['image'] = new['spec']['template']['spec']['containers'][0]['image']
        for item in container['env']:
            for suffix, field in (('SOURCE_REVISION', 'sourceRevision'), ('MANIFEST_DIGEST', 'manifestDigest')):
                if item['name'] == 'ROEBEL_STAGING_PARTICIPANT_GATEWAY_' + suffix:
                    item['value'] = c.RELEASE[field]
        self.assertEqual(old, new)

    def test_partial_activation_is_rejected_for_each_file(self):
        for path in c.TRANSITION_FILES:
            target = self.root / path; raw = target.read_bytes()
            with self.subTest(path=path):
                if (self.base / path).exists(): target.write_bytes((self.base / path).read_bytes())
                else: target.unlink()
                with self.assertRaises(v.VerificationError): v.verify_tree(self.root)
                target.write_bytes(raw)

    def test_changed_route_image_or_authority_is_rejected(self):
        for filename, mutate in (
            ('ingress', lambda o: o['metadata']['annotations'].update({'haproxy-ingress.github.io/config-backend-early': ''})),
            ('deployment', lambda o: o['spec']['template']['spec']['containers'][0].update(image='unreviewed:latest')),
            ('runtime-pin', lambda o: o.update(commentMeckyMigrationSha256='sha256:' + '0'*64)),
        ):
            path = self.root / v.PARTICIPANT_GATEWAY_ROOT / (filename + '.json')
            raw = path.read_bytes(); value = json.loads(raw); mutate(value); path.write_text(json.dumps(value))
            with self.subTest(filename=filename), self.assertRaises(v.VerificationError): v.verify_tree(self.root)
            path.write_bytes(raw)
        policy = self.root / c.POLICY_PATH
        value = json.loads(policy.read_text()); value['authority']['rolesAssigned'] = True; policy.write_text(json.dumps(value))
        with self.assertRaisesRegex(v.VerificationError, 'comment policy drift'): v.verify_tree(self.root)

    def test_unrelated_change_and_reverse_transition_are_rejected(self):
        after = v.verify_tree(self.root)
        with self.assertRaisesRegex(v.VerificationError, 'rollback requires separate'):
            v.verify_transition(self.before, after)
        (self.root / 'README.md').write_text('unrelated change\n')
        with self.assertRaisesRegex(v.VerificationError, 'file set drift'):
            v.verify_transition(v.verify_tree(self.root), self.before)

    def test_policy_cannot_be_replaced_during_activation(self):
        path = self.root / 'scripts/comment_mecky_rollout.py'
        path.write_text(path.read_text() + '\n# altered candidate policy\n')
        with self.assertRaisesRegex(v.VerificationError, 'protected policy files'):
            v.verify_transition(v.verify_tree(self.root), self.before)

    def test_sql_binding_is_atomic_and_deactivation_retains_data(self):
        sql = c.migration_sql(v, self.base)
        self.assertEqual(len(re.findall(r'^begin;$', sql, re.M)), 1)
        self.assertEqual(len(re.findall(r'^commit;$', sql, re.M)), 1)
        self.assertIn("set local lock_timeout = '5s';", sql)
        self.assertIn('COMMENT_FUNCTION_CATALOG_MISMATCH', sql)
        self.assertLess(sql.index('COMMENT_FUNCTION_CATALOG_MISMATCH'), sql.rindex('commit;'))
        off = c.deactivation_sql().lower()
        self.assertNotRegex(off, r'\b(drop|truncate|delete|insert|update|grant)\b')
        self.assertEqual(off.count('revoke all on function'), 2)
        path = self.base / c.ROOT / c.SQL_FILE; raw = path.read_bytes()
        try:
            path.write_bytes(raw + b'\n')
            with self.assertRaisesRegex(v.VerificationError, 'source artifact drift'): c.migration_sql(v, self.base)
        finally: path.write_bytes(raw)


if __name__ == '__main__': unittest.main()
