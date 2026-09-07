"""Full coordinator/adapter ownership handover and uncertain-patch recovery."""
import json
import unittest
from . import test_case_runtime_kubernetes as fixtures
from . import test_case_runtime_bootstrap as bootfixtures
from . import case_runtime_bootstrap as core
from . import case_runtime_handover as handover


class HandoverTests(unittest.TestCase):
    setUpClass=classmethod(bootfixtures.CaseBootstrapTests.setUpClass.__func__)
    environment=bootfixtures.CaseBootstrapTests.environment
    adapter_environment=fixtures.KubernetesTests.adapter_environment

    def setup_bootstrap(self):
        sink,_=self.environment();adapter,api=self.adapter_environment()
        core.run_bootstrap(self.root,adapter=adapter,sink=sink)
        receipt=json.loads(sink.path.read_text())
        # Active render admission is a separate boundary tested by its verifier;
        # this rehearsal exercises API ownership changes, not Git activation.
        adapter.verify_active_render=lambda plan:adapter.verify_preconditions(plan)
        return adapter,api,receipt

    def test_complete_handover_keeps_all_created_uids(self):
        adapter,api,receipt=self.setup_bootstrap();sink,_=self.environment()
        result=handover.run_handover(adapter.plan,receipt,adapter=adapter,sink=sink)
        self.assertEqual(result['status'],'flux-ready')
        self.assertEqual(result['removed'],list(range(19)))
        self.assertTrue(result['fluxReady'])
        self.assertEqual(len([c for c in api.calls if c[0]=='POST']),19)

    def test_lost_patch_response_at_every_boundary_resumes_without_duplicate_mutation(self):
        for boundary in range(20):
            with self.subTest(boundary=boundary):
                adapter,api,receipt=self.setup_bootstrap();sink,_=self.environment()
                original=api.patch_owned;calls=[]
                def uncertain(*args):
                    result=original(*args);calls.append(args)
                    if len(calls)==boundary+1:raise TimeoutError('sensitive API error')
                    return result
                api.patch_owned=uncertain
                with self.assertRaises(handover.HandoverStopped):handover.run_handover(adapter.plan,receipt,adapter=adapter,sink=sink)
                prior=json.loads(sink.path.read_text());next_sink,_=self.environment()
                result=handover.run_handover(adapter.plan,receipt,adapter=adapter,sink=next_sink,prior_receipt=prior)
                self.assertEqual(result['status'],'flux-ready')
                self.assertEqual(len(calls),20)
                self.assertNotIn('sensitive API error',sink.path.read_text())

    def test_foreign_uid_and_unjournaled_nonce_removal_never_patch(self):
        for fault in ('uid','nonce'):
            with self.subTest(fault=fault):
                adapter,api,receipt=self.setup_bootstrap();sink,_=self.environment()
                item=adapter.plan['objects'][0]
                obj=api.objects[fixtures.kube.resource_path(item['target'])]
                if fault=='uid':obj['metadata']['uid']='replacement'
                else:obj['metadata']['annotations'].pop(core.NONCE)
                api.patch_owned=lambda *args:self.fail('unowned object was patched')
                with self.assertRaises(handover.HandoverStopped):handover.run_handover(adapter.plan,receipt,adapter=adapter,sink=sink)
