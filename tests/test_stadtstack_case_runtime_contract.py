from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = ROOT / "scripts" / "verify-stadtstack-case-runtime-contract.py"
SPEC = importlib.util.spec_from_file_location("case_runtime_contract_verifier", VERIFIER_PATH)
assert SPEC and SPEC.loader
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class StadtstackCaseRuntimeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = VERIFIER.load_json(
            ROOT / VERIFIER.CONTRACT_RELATIVE_PATH
        )

    def verify(self, contract: dict) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract_dir = root / VERIFIER.CONTRACT_RELATIVE_PATH.parent
            contract_dir.mkdir(parents=True)
            (root / VERIFIER.CONTRACT_RELATIVE_PATH).write_text(
                json.dumps(contract), encoding="utf-8"
            )
            return VERIFIER.verify_contract(root)

    @staticmethod
    def set_path(contract: dict, path: str, value: object) -> None:
        parts = path.split(".")
        current: object = contract
        for part in parts[:-1]:
            assert isinstance(current, dict)
            current = current[part]
        assert isinstance(current, dict)
        current[parts[-1]] = value

    def test_reviewed_contract_is_blocked_and_inert(self) -> None:
        self.assertEqual(VERIFIER.verify_contract(ROOT), [])
        self.assertEqual(self.contract["mode"], "inert_review_only")
        self.assertFalse(self.contract["reconciliationAllowed"])
        self.assertFalse(self.contract["fluxKustomizationAllowed"])
        self.assertEqual(self.contract["allowedKinds"], [])
        gate = self.contract["recoveryActivationGate"]
        self.assertEqual(
            gate["schemaVersion"],
            "stadtstack_case_recovery_evidence_inventory_v1",
        )
        self.assertEqual(gate["status"], "blocked")
        self.assertEqual(
            gate["policy"]["maxAgeSeconds"],
            86400,
        )
        self.assertEqual(gate["policy"]["maxRtoSeconds"], 14400)

    def test_nested_shapes_mirror_policy_catalog_and_attestation_modules(self) -> None:
        gate = self.contract["recoveryActivationGate"]
        self.assertEqual(
            gate["policy"]["schemaVersion"],
            "staging_case_recovery_policy_v1",
        )
        self.assertEqual(
            gate["catalog"]["schemaVersion"],
            "case_backup_catalog_locator_v1",
        )
        self.assertEqual(
            gate["attestation"]["schemaVersion"],
            "staging_case_recovery_attestation_v1",
        )
        self.assertEqual(
            gate["policy"]["signer"],
            {
                "algorithm": "Ed25519",
                "purpose": "staging_case_recovery_attestation",
                "status": "active",
                "keyId": None,
                "keyVersion": None,
                "spkiDerBase64url": None,
                "spkiSha256": None,
                "activeFromUtc": None,
                "activeUntilUtc": None,
            },
        )
        self.assertEqual(
            set(gate["attestation"]["restoreReport"]),
            {
                "restoreReportChecksum",
                "verifierReleaseDigest",
                "restoredDatabaseByteLength",
                "restoredDatabaseSha256",
                "integrity",
                "recoveryEvidenceChecksum",
                "caseCount",
                "outboxCursor",
                "headsAggregateChecksum",
                "publicProjectionChecksum",
                "isolatedRestore",
                "startedAtUtc",
                "completedAtUtc",
                "rtoSeconds",
            },
        )

    def test_every_live_fact_is_null_and_missing_evidence_is_exact(self) -> None:
        gate = self.contract["recoveryActivationGate"]
        self.assertEqual(gate["missingEvidence"], VERIFIER.EXPECTED_MISSING_EVIDENCE)
        actual_nulls = [
            path
            for path in VERIFIER._null_paths(self.contract)
            if not path.startswith("recoveryActivationGate.missingEvidence[")
        ]
        self.assertEqual(actual_nulls, VERIFIER.EXPECTED_MISSING_EVIDENCE)
        self.assertIsNone(self.contract["restoreVerifierReleaseDigest"])
        self.assertIsNone(gate["policy"]["restoreVerifierReleaseDigest"])
        self.assertIsNone(gate["attestation"]["restoreReport"]["verifierReleaseDigest"])

    def test_placeholder_live_value_is_rejected(self) -> None:
        for path in VERIFIER.EXPECTED_MISSING_EVIDENCE:
            changed = copy.deepcopy(self.contract)
            self.set_path(changed, path, "placeholder")
            self.assertTrue(
                self.verify(changed),
                msg=f"placeholder accepted at {path}",
            )

    def test_recovery_cannot_become_ready_or_reconcilable(self) -> None:
        changed = copy.deepcopy(self.contract)
        changed["recoveryActivationGate"]["status"] = "ready"
        self.assertTrue(self.verify(changed))

        changed = copy.deepcopy(self.contract)
        changed["reconciliationAllowed"] = True
        self.assertTrue(self.verify(changed))

        changed = copy.deepcopy(self.contract)
        changed["fluxKustomizationAllowed"] = True
        self.assertTrue(self.verify(changed))

    def test_no_kubernetes_or_external_activation_resources_are_present(self) -> None:
        resources = self.contract["activationResources"]
        self.assertEqual(
            resources,
            {
                "kubernetesObjects": [],
                "bucketCredentials": [],
                "jobs": [],
                "pvcs": [],
                "deployments": [],
                "secrets": [],
                "fluxObjects": [],
            },
        )
        for resource_type in resources:
            changed = copy.deepcopy(self.contract)
            changed["activationResources"][resource_type] = [{"name": "forbidden"}]
            self.assertTrue(
                self.verify(changed),
                msg=f"activation resource accepted in {resource_type}",
            )

    def test_binding_and_restore_verifier_pins_are_independent_and_missing(self) -> None:
        gate = self.contract["recoveryActivationGate"]
        self.assertIsNone(gate["policy"]["controlDeploymentBindingChecksum"])
        self.assertIsNone(self.contract["restoreVerifierReleaseDigest"])
        self.assertIsNone(gate["policy"]["restoreVerifierReleaseDigest"])
        self.assertIsNone(gate["attestation"]["restoreReport"]["verifierReleaseDigest"])
        self.assertIn(
            "recoveryActivationGate.policy.controlDeploymentBindingChecksum",
            gate["missingEvidence"],
        )
        self.assertIn("restoreVerifierReleaseDigest", gate["missingEvidence"])
        self.assertIn(
            "recoveryActivationGate.policy.restoreVerifierReleaseDigest",
            gate["missingEvidence"],
        )
        self.assertIn(
            "recoveryActivationGate.attestation.restoreReport.verifierReleaseDigest",
            gate["missingEvidence"],
        )

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text(
                '{"schemaVersion": 1, "schemaVersion": 2}',
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                VERIFIER.load_json(path)


if __name__ == "__main__":
    unittest.main()
