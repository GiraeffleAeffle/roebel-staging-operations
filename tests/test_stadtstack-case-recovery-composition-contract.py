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
        cls.image_inventory = VERIFIER.load_json(ROOT / VERIFIER.IMAGE_RESOURCE_INVENTORY_RELATIVE_PATH)

    def verify(self, contract: dict) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract_path = root / VERIFIER.CONTRACT_RELATIVE_PATH
            contract_path.parent.mkdir(parents=True)
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            inventory_path = root / VERIFIER.IMAGE_RESOURCE_INVENTORY_RELATIVE_PATH
            inventory_path.parent.mkdir(parents=True, exist_ok=True)
            inventory_path.write_text(json.dumps(self.image_inventory), encoding="utf-8")
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

    def test_image_resource_inventory_reference_is_exact_and_checksum_bound(self) -> None:
        reference = self.contract["imageResourceInventory"]
        self.assertEqual(reference["schemaVersion"], "stadtstack_case_image_resource_inventory_contract_v1")
        self.assertEqual(reference["contractPath"], VERIFIER.IMAGE_RESOURCE_INVENTORY_RELATIVE_PATH.as_posix())
        self.assertIsNone(reference["inventoryChecksum"])
        self.assertEqual(reference["inventoryChecksum"], self.image_inventory["inventoryChecksum"])
        self.assertEqual(
            self.contract["stages"][5]["handoffReceipt"]["resourceInventoryChecksum"],
            reference["inventoryChecksum"],
        )

        candidate = copy.deepcopy(self.contract)
        candidate["imageResourceInventory"]["contractPath"] = "contracts/other.json"
        errors = self.verify(candidate)
        self.assertTrue(any("imageResourceInventory.contractPath drift" in error for error in errors))

    def test_current_v2_protocols_are_pinned(self) -> None:
        protocols = self.contract["protocols"]
        self.assertEqual(protocols["shutdownSeal"]["schemaVersion"], "case_shutdown_seal_v2")
        self.assertEqual(protocols["recoveryAttestation"]["schemaVersion"], "staging_case_recovery_attestation_v2")
        self.assertEqual(protocols["recoveryPolicy"]["schemaVersion"], "staging_case_recovery_policy_v1")
        self.assertEqual(protocols["backupCatalog"]["schemaVersion"], "case_backup_catalog_locator_v1")
        self.assertEqual(protocols["recoveryGate"]["schemaVersion"], "staging_case_recovery_gate_v2")
        self.assertFalse(protocols["recoveryGate"]["serializableChecksum"])
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
                "recovery_activation",
            ],
        )

    def test_recovery_marker_cannot_coexist_with_ordinary_start_receipts(self) -> None:
        restore = self.contract["stages"][3]
        self.assertEqual(
            restore["protocolRefs"],
            ["recoveryPolicy", "backupCatalog", "recoveryAttestation"],
        )
        self.assertNotIn("bootstrapChecksum", restore["evidence"])
        self.assertNotIn("openEpochChecksum", restore["evidence"])
        self.assertNotIn("recoveryMarkerChecksum", restore["evidence"])
        self.assertNotIn("bootstrapReceiptForbidden", restore["requirements"])
        self.assertNotIn("openEpochReceiptForbidden", restore["requirements"])
        self.assertNotIn("bootstrapChecksum", self.contract["liveEvidence"]["restore"])
        self.assertNotIn("openEpochChecksum", self.contract["liveEvidence"]["restore"])
        activation = self.contract["stages"][6]
        self.assertTrue(activation["requirements"]["ownerLockRequired"])
        self.assertTrue(activation["requirements"]["exactRenewedRecoveryGateRequired"])
        self.assertTrue(activation["requirements"]["reviewedHandoffReceiptRequired"])
        self.assertTrue(activation["requirements"]["recoveryMarkerRequired"])
        self.assertTrue(activation["requirements"]["sourceToTargetClaimRotationRequired"])
        self.assertTrue(activation["requirements"]["bootstrapReceiptForbidden"])
        self.assertTrue(activation["requirements"]["openEpochReceiptForbidden"])
        self.assertTrue(activation["requirements"]["preBindFreshnessRequired"])
        self.assertTrue(activation["requirements"]["nonSealingAbortRequired"])
        self.assertIn("handoffReceiptChecksum", activation["evidence"])
        self.assertIsNone(activation["evidence"]["handoffReceiptChecksum"])

        candidate = copy.deepcopy(self.contract)
        candidate["stages"][6]["protocolRefs"].append("bootstrap")
        errors = self.verify(candidate)
        self.assertTrue(any("protocolRefs drift" in error for error in errors))

    def test_public_slot_has_no_storage_or_authority_surfaces(self) -> None:
        requirements = self.contract["stages"][4]["requirements"]
        self.assertNotIn("publicSlotMustReferenceTarget", requirements)
        self.assertTrue(requirements["publicSlotMustBePvcPvSecretRbacFree"])
        self.assertTrue(requirements["publicSlotMustReferenceControlPrivateOutbox"])
        self.assertEqual(requirements["publicSlotForbiddenSurfaces"], ["pvc", "pv", "secret", "rbac"])
        public = self.contract["stages"][4]["slots"]["public"]
        self.assertEqual(
            set(public),
            {"controlPrivateOutboxBindingChecksum", "controlSlotReferenceChecksum", "referenceChecksum"},
        )
        self.assertNotIn("targetPvcUid", public)
        self.assertNotIn("targetPvName", public)
        self.assertNotIn("targetClaimChecksum", public)

    def test_bundle_pins_three_independent_locators(self) -> None:
        bundle = self.contract["stages"][1]["bundle"]
        self.assertEqual(
            set(bundle) - {"database", "sourceClaim", "sourceSeal", "bundleChecksum"},
            {"catalogLocator", "completionReceiptLocator", "encryptedManifestLocator"},
        )
        self.assertEqual(
            set(bundle["catalogLocator"]),
            {"bucket", "key", "objectVersion", "checksum"},
        )
        self.assertEqual(
            set(bundle["completionReceiptLocator"]),
            {"bucket", "key", "objectVersion", "checksum", "keyVersion"},
        )
        self.assertEqual(
            set(bundle["encryptedManifestLocator"]),
            {"bucket", "key", "objectVersion", "checksum"},
        )

        candidate = copy.deepcopy(self.contract)
        candidate["stages"][1]["bundle"]["completionReceiptLocator"]["objectVersion"] = "v1"
        errors = self.verify(candidate)
        self.assertTrue(any("completionReceiptLocator.objectVersion must remain null" in error for error in errors))

    def test_restore_verifier_evidence_and_boundary_requirements_are_pinned(self) -> None:
        restore = self.contract["stages"][3]
        self.assertEqual(
            set(restore["evidence"]),
            {
                "recoveryPolicyChecksum",
                "recoveryAttestationChecksum",
                "restoreReportChecksum",
                "restoreVerifierImageDigest",
                "restoreVerifierProvenanceSha256",
                "restoreVerifierSpdxSbomSha256",
                "verifiedDatabaseSha256",
                "verifiedSchemaChecksum",
            },
        )
        self.assertTrue(restore["requirements"]["immutableRestoreVerifierRequired"])
        self.assertFalse(restore["requirements"]["sourceWriteMountAllowed"])
        self.assertFalse(restore["requirements"]["publicIngressAllowed"])
        self.assertFalse(restore["requirements"]["userFacingEndpointAllowed"])

    def test_flux_handoff_requires_review_revision_and_inventory_checksum(self) -> None:
        handoff = self.contract["stages"][5]
        self.assertTrue(handoff["requirements"]["reviewedOperationsRevisionRequired"])
        self.assertTrue(handoff["requirements"]["exactResourceInventoryChecksumRequired"])
        self.assertEqual(handoff["handoffReceipt"]["canonicalEncoding"], "canonical-json")
        self.assertEqual(
            handoff["handoffReceipt"]["checksumCovers"],
            VERIFIER.HANDOFF_CHECKSUM_COVERS,
        )
        self.assertEqual(
            set(handoff["handoffReceipt"])
            - {"schemaVersion", "status", "canonicalEncoding", "checksumCovers"},
            {
                "operationsRevision",
                "resourceInventoryChecksum",
                "sourceClaimChecksum",
                "targetClaimChecksum",
                "targetPvcUid",
                "targetPvName",
                "releaseDigest",
                "recoveryPolicyChecksum",
                "recoveryAttestationChecksum",
                "receiptChecksum",
            },
        )
        self.assertFalse(handoff["requirements"]["fluxObjectAllowed"])

        candidate = copy.deepcopy(self.contract)
        candidate["stages"][5]["handoffReceipt"]["checksumCovers"].remove("sourceClaimChecksum")
        errors = self.verify(candidate)
        self.assertTrue(any("handoffReceipt.checksumCovers drift" in error for error in errors))

    def test_source_quiesce_requires_maintenance_window_and_exact_binding(self) -> None:
        source = self.contract["stages"][0]
        self.assertTrue(source["requirements"]["maintenanceWindowRequired"])
        self.assertTrue(source["requirements"]["exactSourceControlBindingRequired"])
        self.assertEqual(
            set(source["evidence"]),
            {
                "maintenanceStartedAtUtc",
                "maintenanceCompletedAtUtc",
                "sourceControlDeploymentBindingChecksum",
                "sourceClaimChecksum",
                "sourcePvcUid",
                "sourcePvName",
                "sourceSealChecksum",
                "quiesceReceiptChecksum",
            },
        )

        candidate = copy.deepcopy(self.contract)
        candidate["stages"][0]["evidence"]["maintenanceStartedAtUtc"] = "2026-08-23T00:00:00.000Z"
        errors = self.verify(candidate)
        self.assertTrue(any("maintenanceStartedAtUtc must remain null" in error for error in errors))

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

    def test_protected_base_verifier_rejects_recovery_boundary_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "candidate"
            shutil.copytree(
                ROOT,
                candidate,
                ignore=shutil.ignore_patterns(".git", "__pycache__"),
            )
            contract_path = candidate / VERIFIER.CONTRACT_RELATIVE_PATH
            value = json.loads(contract_path.read_text(encoding="utf-8"))
            value["stages"][4]["requirements"]["publicSlotMustBePvcPvSecretRbacFree"] = False
            contract_path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(REVIEW_VERIFIER.VerificationError, "Case recovery composition contract verification failed"):
                REVIEW_VERIFIER.verify(candidate, ROOT)


if __name__ == "__main__":
    unittest.main()
