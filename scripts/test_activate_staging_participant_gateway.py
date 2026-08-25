import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("activation", Path(__file__).with_name("activate-staging-participant-gateway.py"))
MODULE = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(MODULE)

class ActivationPlanTests(unittest.TestCase):
    def test_plan_is_create_only_and_network_policy_first(self):
        plan = MODULE.plan({"status": "approved-separate-review", **{key: {} for key in ("publication", "egress", "fluxBootstrap", "applicationBootstrap", "secretMaterialization", "databaseVaultPreflight", "gnosisChainCheck", "dnsTlsEvidence", "activationTransaction", "rollback")}}, "a" * 40)
        self.assertEqual(plan["createOrder"], ["NetworkPolicy", "ServiceAccount", "Service", "Deployment", "Ingress"])
        self.assertEqual(plan["mode"], "verify-plan-only")
    def test_plan_blocks_unapproved_evidence(self):
        with self.assertRaisesRegex(ValueError, "activation blocked"):
            MODULE.plan({}, "a" * 40)
    def test_plan_rejects_partial_evidence(self):
        with self.assertRaisesRegex(ValueError, "incomplete"):
            MODULE.plan({"status": "approved-separate-review"}, "a" * 40)
