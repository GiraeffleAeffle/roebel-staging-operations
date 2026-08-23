from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VERIFIER = load_module(
    "stadtstack_case_recovery_composition_verifier",
    ROOT / "scripts/verify-stadtstack-case-recovery-composition-contract.py",
)
REVIEW_VERIFIER = load_module(
    "protected_reviewed_render_verifier",
    ROOT / "scripts/verify-reviewed-render.py",
)


class StadtstackCaseRecoveryCompositionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = VERIFIER.load_json(ROOT / VERIFIER.CONTRACT_RELATIVE_PATH)

    def verify(self, contract: dict) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract_path = root / VERIFIER.CONTRACT_RELATIVE_PATH
            contract_path.parent.mkdir(parents=True)
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            return VERIFIER.verify_contract(root)

    def test_contract_is_valid_inert_and_closed(self) -> None:
        self.assertEqual(VERIFIER.verify_contract(ROOT), [])
        self.assertEqual(self.contract["schemaVersion"], "stadtstack_case_recovery_composition_contract_v2")
        self.assertEqual(self.contract["mode"], "inert_review_only")
        self.assertEqual(self.contract["status"], "inert_review_only")
        self.assertFalse(self.contract["reconciliationAllowed"])
        self.assertFalse(self.contract["fluxHandoffAllowed"])
        self.assertEqual(self.contract["allowedKinds"], [])
        self.assertEqual(self.contract["forbiddenResources"]["kubernetesObjects"], [])
        self.assertEqual(self.contract["forbiddenResources"]["fluxObjects"], [])
        self.assertEqual(self.contract["forbiddenSecrets"]["credentialValues"], [])

    def test_current_v2_protocols_are_pinned(self) -> None:
        protocols = self.contract["protocols"]
        self.assertEqual(protocols["shutdownSeal"]["schemaVersion"], "case_shutdown_seal_v2")
        self.assertEqual(protocols["recoveryAttestation"]["schemaVersion"], "staging_case_recovery_attestation_v2")
        self.assertEqual(protocols["recoveryGate"]["schemaVersion"], "staging_case_recovery_gate_v2")
        self.assertEqual(protocols["deploymentClaim"]["schemaVersion"], "case_durable_deployment_claim_v1")
        self.assertEqual(protocols["bootstrap"]["schemaVersion"], "case_store_bootstrap_v1")
        self.assertEqual(protocols["openEpoch"]["schemaVersion"], "case_open_epoch_v1")
        self.assertEqual(protocols["recoveryMarker"]["schemaVersion"], "case_recovery_activation_v2")
        self.assertEqual(
            [stage["stage"] for stage in self.contract["stages"]],
            [
                "source_quiesce",
                "encrypted_bundle",
                "fresh_target",
                "isolated_restore_verifier",
                "restored_slots",
                "flux_handoff",
            ],
        )

    def test_all_live_evidence_is_explicitly_null_and_enumerated(self) -> None:
        nulls = VERIFIER._null_paths(
            {key: value for key, value in self.contract.items() if key != "missingEvidence"}
        )
        self.assertEqual(self.contract["missingEvidence"], nulls)
        self.assertTrue(nulls)
        self.assertIsNone(self.contract["liveEvidence"]["source"]["pvc"]["uid"])
        self.assertIsNone(self.contract["liveEvidence"]["target"]["pvc"]["uid"])

    def test_duplicate_json_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / VERIFIER.CONTRACT_RELATIVE_PATH
            path.parent.mkdir(parents=True)
            path.write_text('{"schemaVersion":"a","schemaVersion":"b"}\n', encoding="utf-8")
            errors = VERIFIER.verify_contract(root)
        self.assertTrue(any("duplicate JSON key" in error for error in errors))

    def test_old_attestation_protocol_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.contract)
        candidate["protocols"]["recoveryAttestation"]["schemaVersion"] = "staging_case_recovery_attestation_v1"
        errors = self.verify(candidate)
        self.assertTrue(any("protocols.recoveryAttestation drift" in error for error in errors))

    def test_resource_document_is_rejected(self) -> None:
        candidate = copy.deepcopy(self.contract)
        candidate["stages"][0]["evidence"]["apiVersion"] = None
        errors = self.verify(candidate)
        self.assertTrue(any("forbidden resource field" in error for error in errors))

    def test_flux_object_and_secret_payload_are_rejected(self) -> None:
        candidate = copy.deepcopy(self.contract)
        candidate["forbiddenResources"]["fluxObjects"] = [{"kind": "Kustomization"}]
        errors = self.verify(candidate)
        self.assertTrue(any("forbidden resource field" in error for error in errors))

        candidate = copy.deepcopy(self.contract)
        candidate["stages"][3]["evidence"]["token"] = "not-a-token"
        errors = self.verify(candidate)
        self.assertTrue(any("forbidden secret field" in error for error in errors))

    def test_live_checksum_format_and_non_null_value_are_rejected(self) -> None:
        candidate = copy.deepcopy(self.contract)
        candidate["liveEvidence"]["source"]["claimChecksum"] = "not-a-checksum"
        errors = self.verify(candidate)
        self.assertTrue(any("liveEvidence.source.claimChecksum format invalid" in error for error in errors))

        candidate = copy.deepcopy(self.contract)
        candidate["liveEvidence"]["source"]["claimChecksum"] = "sha256:" + ("a" * 64)
        errors = self.verify(candidate)
        self.assertTrue(any("must remain null" in error for error in errors))

    def test_cross_binding_and_distinct_target_requirements_are_checked(self) -> None:
        candidate = copy.deepcopy(self.contract)
        candidate["stages"][1]["bundle"]["sourceClaim"]["claimChecksum"] = "sha256:" + ("a" * 64)
        errors = self.verify(candidate)
        self.assertTrue(any("must remain null" in error for error in errors))
        candidate = copy.deepcopy(self.contract)
        source = candidate["liveEvidence"]["source"]["pvc"]
        target = candidate["liveEvidence"]["target"]["pvc"]
        source["uid"] = "00000000-0000-0000-0000-000000000001"
        target["uid"] = source["uid"]
        errors = self.verify(candidate)
        self.assertTrue(any("must remain null" in error for error in errors))

    def test_protected_base_verifier_rejects_composition_policy_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "candidate"
            shutil.copytree(
                ROOT,
                candidate,
                ignore=shutil.ignore_patterns(".git", "__pycache__"),
            )
            contract_path = candidate / VERIFIER.CONTRACT_RELATIVE_PATH
            value = json.loads(contract_path.read_text(encoding="utf-8"))
            value["stages"][0]["evidence"]["forgedField"] = None
            contract_path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(REVIEW_VERIFIER.VerificationError, "Case recovery composition contract verification failed"):
                REVIEW_VERIFIER.verify(candidate, ROOT)


if __name__ == "__main__":
    unittest.main()
