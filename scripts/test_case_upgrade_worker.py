import json
from pathlib import Path
import shutil
import tempfile
import unittest
from .case_upgrade_worker import compile_worker, NAME, MULTI_CASE_NAME, PROGRAMS
from . import town_workspace_connection as workspace
from .case_runtime_bootstrap import _verifier


class UpgradeWorkerTests(unittest.TestCase):
    def test_current_confirmed_case_uses_the_exact_second_worker_and_cannot_repeat_after_activation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)/'brief'
            shutil.copytree(Path(__file__).resolve().parents[1], root, ignore=shutil.ignore_patterns('.git','__pycache__','*.pyc'))
            interface = _verifier().citizen_status_interface()
            data = workspace.bundle(interface, root)
            case_path = workspace.ROOT+'case-runtime/resources.json'
            (root/case_path).write_text(workspace.expected_files(data,'brief')[case_path])
            (root/workspace.STATE).write_text(json.dumps({'schemaVersion':'roebel_town_workspace_state_v1','stage':'brief'},indent=2)+'\n')
            worker = compile_worker(root)
            spec = worker['pod']['spec']; policy = json.loads(worker['configMap']['data']['upgrade-policy.json'])
            self.assertEqual(worker['pod']['metadata']['name'], MULTI_CASE_NAME)
            self.assertEqual(policy['expected']['head']['caseVersion'], 28)
            self.assertEqual(spec['containers'][0]['image'].split('@')[1], policy['targetBinding']['releaseDigest'])
            self.assertFalse(spec['automountServiceAccountToken'])
            self.assertEqual(spec['containers'][0]['securityContext']['capabilities'], {'drop':['ALL']})
            self.assertEqual(worker['networkPolicy']['spec']['ingress'], [])
            self.assertEqual(worker['networkPolicy']['spec']['egress'], [])
            self.assertEqual([v['persistentVolumeClaim']['claimName'] for v in spec['volumes'] if 'persistentVolumeClaim' in v], ['roebel-case-steward-review-state-v1'])
            self.assertEqual([v['secret']['secretName'] for v in spec['volumes'] if 'secret' in v], ['roebel-case-steward-review-runtime-v1'])
            self.assertEqual(next(v['configMap']['name'] for v in spec['volumes'] if 'configMap' in v), MULTI_CASE_NAME)
            (root/case_path).write_text(data['stages']['multi-case']['files'][case_path])
            (root/workspace.STATE).write_text(json.dumps({'schemaVersion':'roebel_town_workspace_state_v1','stage':'multi-case'},indent=2)+'\n')
            with self.assertRaisesRegex(RuntimeError, 'exact review or Brief predecessor'): compile_worker(root)

    def test_worker_is_offline_uses_only_current_volume_and_existing_configuration(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)/'review'
        shutil.copytree(Path(__file__).resolve().parents[1], root, ignore=shutil.ignore_patterns('.git','__pycache__','*.pyc'))
        # The upgrade worker predates the comment gateway; restore that fixed
        # predecessor before selecting its historical Workspace review stage.
        comment = _verifier().COMMENT_MECKY
        if comment.enabled(root):
            import subprocess
            for path in comment.TRANSITION_FILES - {str(comment.RECORD_PATH)}:
                (root/path).write_bytes(subprocess.check_output(['git','-C',str(Path(__file__).resolve().parents[1]),
                    'show','0282b120facf75b174be4b20422d74827af95410:'+path]))
            (root/comment.RECORD_PATH).unlink()
        data=workspace.bundle(_verifier().citizen_status_interface(),root)
        for path, raw in workspace.expected_files(data,'review').items(): (root/path).write_text(raw)
        (root/workspace.STATE).write_text(json.dumps({'schemaVersion':'roebel_town_workspace_state_v1','stage':'review'},indent=2)+'\n')
        worker = compile_worker(root)
        spec = worker['pod']['spec']
        self.assertFalse(spec['automountServiceAccountToken'])
        self.assertEqual(spec['restartPolicy'], 'Never')
        self.assertEqual(len(spec['containers']), 1)
        self.assertNotIn('ports', spec['containers'][0])
        self.assertEqual(spec['containers'][0]['securityContext']['capabilities'], {'drop': ['ALL']})
        self.assertEqual([v['persistentVolumeClaim']['claimName'] for v in spec['volumes'] if 'persistentVolumeClaim' in v], ['roebel-case-steward-review-state-v1'])
        self.assertEqual([v['secret']['secretName'] for v in spec['volumes'] if 'secret' in v], ['roebel-case-steward-review-runtime-v1'])
        self.assertEqual(worker['networkPolicy']['spec']['egress'], [])
        self.assertEqual(worker['networkPolicy']['spec']['ingress'], [])
        self.assertTrue(worker['configMap']['immutable'])
        self.assertEqual(set(worker['configMap']['data']), set(PROGRAMS) | {'entry.mjs', 'upgrade-policy.json'})
        policy = json.loads(worker['configMap']['data']['upgrade-policy.json'])
        self.assertEqual(policy['expected']['head']['caseVersion'], 27)
        self.assertEqual(spec['containers'][0]['image'].split('@')[1], policy['targetBinding']['releaseDigest'])
        self.assertEqual(worker['pod']['metadata']['name'], NAME)
        self.assertEqual(spec['containers'][0]['env'][1]['valueFrom']['fieldRef']['fieldPath'], 'metadata.uid')


if __name__ == '__main__':
    unittest.main()
