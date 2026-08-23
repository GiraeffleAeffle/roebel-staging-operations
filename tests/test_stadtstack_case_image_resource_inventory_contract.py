from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = ROOT / "scripts" / "verify-stadtstack-case-image-resource-inventory-contract.py"
SPEC = importlib.util.spec_from_file_location("case_image_resource_inventory_verifier", VERIFIER_PATH)
assert SPEC and SPEC.loader
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class StadtstackCaseImageResourceInventoryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = VERIFIER.load_json(ROOT / VERIFIER.CONTRACT_RELATIVE_PATH)

    def verify(self, contract: dict) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract_path = root / VERIFIER.CONTRACT_RELATIVE_PATH
            contract_path.parent.mkdir(parents=True)
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            topology_path = root / VERIFIER.TOPOLOGY_CONTRACT_RELATIVE_PATH
            topology_path.parent.mkdir(parents=True)
            topology_path.write_text(
                (ROOT / VERIFIER.TOPOLOGY_CONTRACT_RELATIVE_PATH).read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            return VERIFIER.verify_contract(root)

    def test_contract_is_valid_inert_and_closed(self) -> None:
        self.assertEqual(VERIFIER.verify_contract(ROOT), [])
        self.assertEqual(self.contract["schemaVersion"], "stadtstack_case_image_resource_inventory_contract_v1")
        self.assertEqual(self.contract["mode"], "inert_review_only")
        self.assertEqual(self.contract["status"], "inert_review_only")
        self.assertFalse(self.contract["reconciliationAllowed"])
        self.assertFalse(self.contract["fluxHandoffAllowed"])
        self.assertEqual(self.contract["allowedKinds"], [])
        self.assertEqual(self.contract["protectedPolicyBootstrap"], VERIFIER.PROTECTED_POLICY_BOOTSTRAP)
        self.assertFalse(self.contract["protectedPolicyBootstrap"]["activationBeforePushVerificationAllowed"])
        self.assertEqual(self.contract["forbiddenResources"]["kubernetesObjects"], [])
        self.assertEqual(self.contract["forbiddenResources"]["fluxObjects"], [])
        self.assertEqual(self.contract["forbiddenSecrets"]["credentialValues"], [])

    def test_release_set_vocabulary_is_pinned(self) -> None:
        vocabulary = self.contract["releaseSetVocabulary"]
        self.assertEqual(vocabulary["schemaVersion"], "stadtstack_case_release_set_candidate_v1")
        self.assertEqual(vocabulary["vocabularyDerivedFrom"], "roebel_staging_release_set_candidate_v1")
        self.assertEqual(vocabulary["sourceRepository"], "GiraeffleAeffle/stadtstack")
        self.assertEqual(vocabulary["sourceRevision"]["length"], 40)
        self.assertTrue(vocabulary["sourceRevision"]["exact"])
        self.assertEqual(vocabulary["digests"]["algorithm"], "sha256")
        self.assertTrue(vocabulary["digests"]["immutable"])
        self.assertEqual(vocabulary["provenance"]["issuer"], "https://token.actions.githubusercontent.com")
        self.assertIn("stadtstack/.github/workflows/case-staging-publish.yml", vocabulary["provenance"]["publisherIdentity"])
        self.assertEqual(vocabulary["provenance"]["predicateType"], "https://slsa.dev/provenance/v1")
        self.assertEqual(vocabulary["provenance"]["subjectDigestField"], "manifestDigest")
        self.assertEqual(vocabulary["provenance"]["sourceBinding"]["repository"], "GiraeffleAeffle/stadtstack")
        self.assertEqual(vocabulary["provenance"]["sourceBinding"]["gitRef"], "refs/heads/main")
        self.assertTrue(vocabulary["provenance"]["sourceBinding"]["revisionMustEqualComponentSourceRevision"])
        self.assertEqual(vocabulary["sbom"]["format"], "SPDX-2.3")
        self.assertEqual(vocabulary["sbom"]["subjectDigestField"], "manifestDigest")
        self.assertEqual(vocabulary["checksums"]["encoding"], "canonical-json")
        receipt = vocabulary["anonymousDigestPullReceipt"]
        self.assertEqual(receipt["schemaVersion"], "stadtstack_case_anonymous_digest_pull_receipt_v1")
        self.assertEqual(receipt["canonicalEncoding"], "canonical-json")
        self.assertEqual(receipt["authContext"], "clean-empty-auth-config")
        self.assertEqual(receipt["authConfigCanonicalJson"], '{"auths":{}}')
        self.assertEqual(
            receipt["authConfigCanonicalSha256"],
            "sha256:ec21c035eccb78eb5ca20ec95628eb351633621e09a130ac8d7e663714d40c7a",
        )
        self.assertEqual(receipt["resolverIdentity"], "oras-resolve-anonymous")
        self.assertEqual(receipt["bindings"], ["component", "imageRepository", "manifestDigest", "sourceRevision"])
        self.assertTrue(receipt["resolvedManifestDigestMustEqualManifestDigest"])
        self.assertNotIn("receiptDigest", receipt["receiptDigest"]["covers"])

        changed = copy.deepcopy(self.contract)
        changed["releaseSetVocabulary"]["provenance"]["issuer"] = "https://example.invalid"
        self.assertTrue(self.verify(changed))

        changed = copy.deepcopy(self.contract)
        changed["releaseSetVocabulary"]["provenance"]["sourceBinding"]["gitRef"] = "refs/heads/other"
        self.assertTrue(self.verify(changed))

    def test_components_are_ordered_and_have_distinct_image_policy(self) -> None:
        self.assertEqual(
            [item["component"] for item in self.contract["components"]],
            ["case-steward-control", "case-public-binding", "case-restore-verifier"],
        )
        control = self.contract["components"][0]
        public = self.contract["components"][1]
        restore = self.contract["components"][2]
        self.assertEqual(
            {
                control["releaseSetPolicy"]["imageRepository"],
                public["releaseSetPolicy"]["imageRepository"],
                restore["releaseSetPolicy"]["imageRepository"],
            },
            {
                "ghcr.io/giraeffleaeffle/stadtstack-case-steward-control",
                "ghcr.io/giraeffleaeffle/stadtstack-case-public-binding",
                "ghcr.io/giraeffleaeffle/stadtstack-case-restore-verifier",
            },
        )
        self.assertTrue(self.contract["releaseSetVocabulary"]["imageBinding"]["allComponentRepositoriesMustDiffer"])
        self.assertTrue(self.contract["releaseSetVocabulary"]["imageBinding"]["allComponentManifestDigestsMustDiffer"])
        self.assertEqual(control["releaseSetPolicy"]["imageRepositoryMustDifferFrom"], "case-public-binding")
        self.assertEqual(public["releaseSetPolicy"]["imageRepositoryMustDifferFrom"], "case-steward-control")
        self.assertTrue(control["releaseSetPolicy"]["immutableImageManifestRequired"])
        self.assertTrue(public["releaseSetPolicy"]["immutableConfigDigestRequired"])
        for component in (control, public, restore):
            self.assertTrue(component["releaseSetPolicy"]["publicPackageVisibilityRequired"])
            self.assertTrue(component["releaseSetPolicy"]["anonymousDigestPullRequired"])
        self.assertTrue(self.contract["releaseSetVocabulary"]["imageBinding"]["controlAndPublicRepositoriesMustDiffer"])
        self.assertTrue(self.contract["releaseSetVocabulary"]["imageBinding"]["controlAndPublicManifestDigestsMustDiffer"])

        changed = copy.deepcopy(self.contract)
        changed["components"][0], changed["components"][1] = changed["components"][1], changed["components"][0]
        self.assertTrue(self.verify(changed))

    def test_control_public_and_restore_logical_boundaries_are_explicit(self) -> None:
        control = self.contract["components"][0]["logicalResourceInventory"]
        self.assertTrue(control["oneWriterRequired"])
        self.assertTrue(control["futureExistingPvcOnly"])
        self.assertTrue(control["privateOutboxRequired"])
        self.assertFalse(control["publicIngressAllowed"])
        self.assertTrue(control["preexistingRuntimeSecretReferenceAllowed"])
        self.assertEqual(control["preexistingRuntimeSecretUsage"], "container_env_valueFrom_only")
        self.assertEqual(control["allowedPreexistingRuntimeSecretReferenceNames"], ["roebel-case-steward-control-runtime"])
        self.assertFalse(control["imagePullSecretsAllowed"])
        self.assertFalse(control["secretObjectCreationAllowed"])
        self.assertFalse(control["credentialMaterialIncluded"])
        self.assertEqual(control["topologyContractBinding"]["canonicalJsonChecksum"], VERIFIER.TOPOLOGY_CONTRACT_CANONICAL_CHECKSUM)

        public = self.contract["components"][1]["logicalResourceInventory"]
        for field in ("pvcAllowed", "pvAllowed", "secretAllowed", "tokenAllowed", "rbacAllowed"):
            self.assertFalse(public[field])
        self.assertTrue(public["exactControlChecksumReferencesOnly"])
        self.assertFalse(public["imagePullSecretsAllowed"])
        self.assertEqual(
            public["allowedChecksumReferenceNames"],
            [
                "case-steward-control.slotChecksum",
                "case-steward-control.privateOutboxChecksum",
            ],
        )

        restore = self.contract["components"][2]["logicalResourceInventory"]
        self.assertTrue(restore["isolated"])
        self.assertTrue(restore["operatorInvokedOnly"])
        self.assertFalse(restore["sourceWriteAllowed"])
        self.assertFalse(restore["publicIngressAllowed"])
        self.assertFalse(restore["userFacingEndpointAllowed"])
        self.assertFalse(restore["fluxManaged"])
        self.assertFalse(restore["imagePullSecretsAllowed"])

        changed = copy.deepcopy(self.contract)
        changed["components"][1]["logicalResourceInventory"]["rbacAllowed"] = True
        self.assertTrue(self.verify(changed))

    def test_control_runtime_secret_reference_is_exactly_topology_bound(self) -> None:
        topology = VERIFIER.load_json(ROOT / VERIFIER.TOPOLOGY_CONTRACT_RELATIVE_PATH)
        control = self.contract["components"][0]["logicalResourceInventory"]
        self.assertEqual(
            topology["futureWorkloads"]["control"]["preexistingSecretRefs"],
            control["allowedPreexistingRuntimeSecretReferenceNames"],
        )
        self.assertEqual(
            topology["futureWorkloads"]["control"]["preexistingSecretRefUsage"],
            {"roebel-case-steward-control-runtime": control["preexistingRuntimeSecretUsage"]},
        )
        self.assertFalse(topology["invariants"]["imagePullSecretsAllowed"])
        self.assertTrue(
            all(
                topology["futureWorkloads"][workload]["imagePullSecretsAllowed"] is False
                for workload in ("control", "public")
            )
        )

        changed = copy.deepcopy(self.contract)
        changed["components"][0]["logicalResourceInventory"]["allowedPreexistingRuntimeSecretReferenceNames"] = ["another-runtime"]
        self.assertTrue(self.verify(changed))

    def test_live_evidence_and_flux_handoff_are_null_and_enumerated(self) -> None:
        live = self.contract["liveEvidence"]
        self.assertIsNone(self.contract["inventoryChecksum"])
        self.assertEqual(len(live["components"]), 3)
        for component in live["components"]:
            for key, value in component.items():
                if key == "component":
                    continue
                if isinstance(value, dict):
                    self.assertTrue(all(child is None for child in value.values()))
                else:
                    self.assertIsNone(value)
        self.assertTrue(all(value is None for value in live["resourceInventory"].values()))
        self.assertEqual(
            set(live["fluxHandoff"]),
            {
                "namespace",
                "reconcilerIdentity",
                "sourceRevision",
                "sourcePath",
                "resourceNameAllowlistChecksum",
                "resourceInventoryChecksum",
                "rbacReceiptChecksum",
            },
        )
        self.assertTrue(all(value is None for value in live["fluxHandoff"].values()))
        expected = VERIFIER._null_paths({key: value for key, value in self.contract.items() if key != "missingEvidence"})
        self.assertEqual(self.contract["missingEvidence"], expected)
        self.assertIn("inventoryChecksum", self.contract["missingEvidence"])
        self.assertIn("liveEvidence.fluxHandoff.resourceInventoryChecksum", self.contract["missingEvidence"])

        changed = copy.deepcopy(self.contract)
        changed["inventoryChecksum"] = "sha256:" + "a" * 64
        self.assertTrue(self.verify(changed))

    def test_inventory_checksum_policy_covers_authority_and_release_payload(self) -> None:
        self.assertEqual(self.contract["inventoryChecksumPolicy"], VERIFIER.INVENTORY_CHECKSUM_POLICY)
        self.assertEqual(self.contract["inventoryChecksumPolicy"]["encoding"], "canonical-json")
        self.assertIn("reconciliationAllowed", self.contract["inventoryChecksumPolicy"]["covers"])
        self.assertIn("protectedPolicyBootstrap", self.contract["inventoryChecksumPolicy"]["covers"])
        self.assertIn("forbiddenResources", self.contract["inventoryChecksumPolicy"]["covers"])
        self.assertIn("forbiddenSecrets", self.contract["inventoryChecksumPolicy"]["covers"])
        self.assertIn("liveEvidence.components", self.contract["inventoryChecksumPolicy"]["covers"])
        self.assertIn("liveEvidence.resourceInventory", self.contract["inventoryChecksumPolicy"]["covers"])
        self.assertNotIn("liveEvidence.fluxHandoff", self.contract["inventoryChecksumPolicy"]["covers"])

        changed = copy.deepcopy(self.contract)
        changed["inventoryChecksumPolicy"]["covers"].remove("reconciliationAllowed")
        errors = self.verify(changed)
        self.assertTrue(any("inventory checksum policy drift" in error for error in errors))

    def test_provenance_claim_fields_are_required_live_evidence(self) -> None:
        for index, component in enumerate(self.contract["liveEvidence"]["components"]):
            self.assertIsNone(component["attestedSourceRepository"])
            self.assertIsNone(component["attestedSourceRevision"])
            self.assertIsNone(component["attestedGitRef"])
            self.assertIsNone(component["packageVisibility"])
            self.assertTrue(all(value is None for value in component["anonymousDigestPullReceipt"].values()))
            self.assertIn(f"liveEvidence.components[{index}].attestedSourceRepository", self.contract["missingEvidence"])
            self.assertIn(f"liveEvidence.components[{index}].attestedSourceRevision", self.contract["missingEvidence"])
            self.assertIn(f"liveEvidence.components[{index}].attestedGitRef", self.contract["missingEvidence"])

        changed = copy.deepcopy(self.contract)
        changed["liveEvidence"]["components"][0]["attestedSourceRevision"] = "a" * 40
        self.assertTrue(self.verify(changed))

    def test_public_visibility_and_anonymous_digest_pull_are_required_and_unfulfilled(self) -> None:
        for index, component in enumerate(self.contract["liveEvidence"]["components"]):
            self.assertIn(f"liveEvidence.components[{index}].packageVisibility", self.contract["missingEvidence"])
            for field in component["anonymousDigestPullReceipt"]:
                self.assertIn(
                    f"liveEvidence.components[{index}].anonymousDigestPullReceipt.{field}",
                    self.contract["missingEvidence"],
                )

        changed = copy.deepcopy(self.contract)
        changed["components"][0]["releaseSetPolicy"]["publicPackageVisibilityRequired"] = False
        self.assertTrue(self.verify(changed))

        changed = copy.deepcopy(self.contract)
        changed["liveEvidence"]["components"][0]["packageVisibility"] = "public"
        self.assertTrue(self.verify(changed))

        changed = copy.deepcopy(self.contract)
        changed["liveEvidence"]["components"][0]["packageVisibility"] = "private"
        self.assertTrue(self.verify(changed))

        changed = copy.deepcopy(self.contract)
        changed["liveEvidence"]["components"][0]["anonymousDigestPullReceipt"]["authContext"] = "ambient-auth"
        self.assertTrue(self.verify(changed))

    def test_future_anonymous_pull_receipt_rejects_every_binding_drift(self) -> None:
        component = {
            "component": "case-steward-control",
            "imageRepository": "ghcr.io/giraeffleaeffle/stadtstack-case-steward-control",
            "manifestDigest": "sha256:" + "a" * 64,
            "sourceRevision": "b" * 40,
        }
        receipt = {
            "schemaVersion": "stadtstack_case_anonymous_digest_pull_receipt_v1",
            "canonicalEncoding": "canonical-json",
            **component,
            "authContext": "clean-empty-auth-config",
            "authConfigCanonicalSha256": "sha256:ec21c035eccb78eb5ca20ec95628eb351633621e09a130ac8d7e663714d40c7a",
            "resolverIdentity": "oras-resolve-anonymous",
            "resolvedManifestDigest": component["manifestDigest"],
            "receiptDigest": None,
        }
        covers = VERIFIER.RELEASE_SET_VOCABULARY["anonymousDigestPullReceipt"]["receiptDigest"]["covers"]
        receipt["receiptDigest"] = VERIFIER._canonical_checksum({field: receipt[field] for field in covers})
        VERIFIER.verify_populated_anonymous_digest_pull_receipt(component, receipt)

        mutations = {
            "component": "case-public-binding",
            "imageRepository": "ghcr.io/giraeffleaeffle/stadtstack-case-public-binding",
            "manifestDigest": "sha256:" + "c" * 64,
            "sourceRevision": "d" * 40,
            "authContext": "ambient-auth",
            "authConfigCanonicalSha256": "sha256:" + "0" * 64,
            "resolverIdentity": "authenticated-client",
            "resolvedManifestDigest": "sha256:" + "e" * 64,
            "receiptDigest": "sha256:" + "f" * 64,
        }
        for field, value in mutations.items():
            changed = copy.deepcopy(receipt)
            changed[field] = value
            with self.assertRaisesRegex(
                VERIFIER.VerificationError,
                "(?:binding drift|authContext drift|authConfigCanonicalSha256 drift|resolverIdentity drift)",
            ):
                VERIFIER.verify_populated_anonymous_digest_pull_receipt(component, changed)

    def test_image_pull_secrets_are_forbidden_for_every_component(self) -> None:
        for index in range(3):
            changed = copy.deepcopy(self.contract)
            changed["components"][index]["logicalResourceInventory"]["imagePullSecretsAllowed"] = True
            self.assertTrue(self.verify(changed))

    def test_effects_are_all_false(self) -> None:
        self.assertEqual(self.contract["effects"], VERIFIER.EFFECTS)
        changed = copy.deepcopy(self.contract)
        changed["effects"]["networkCall"] = True
        self.assertTrue(self.verify(changed))

    def test_every_live_field_rejects_a_placeholder(self) -> None:
        for path in self.contract["missingEvidence"]:
            changed = copy.deepcopy(self.contract)
            parts = path.split(".")
            current: object = changed
            for part in parts[:-1]:
                if "[" in part:
                    name, index = part[:-1].split("[")
                    assert isinstance(current, dict)
                    current = current[name][int(index)]
                else:
                    assert isinstance(current, dict)
                    current = current[part]
            last = parts[-1]
            assert isinstance(current, dict)
            current[last] = "placeholder"
            self.assertTrue(self.verify(changed), msg=f"placeholder accepted at {path}")

    def test_duplicate_json_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / VERIFIER.CONTRACT_RELATIVE_PATH
            path.parent.mkdir(parents=True)
            path.write_text('{"schemaVersion":"a","schemaVersion":"b"}\n', encoding="utf-8")
            errors = VERIFIER.verify_contract(root)
        self.assertTrue(any("duplicate JSON key" in error for error in errors))

    def test_symlink_contract_is_rejected_as_non_regular(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / VERIFIER.CONTRACT_RELATIVE_PATH
            path.parent.mkdir(parents=True)
            source = root / "source.json"
            source.write_text(json.dumps(self.contract), encoding="utf-8")
            path.symlink_to(source)
            errors = VERIFIER.verify_contract(root)
        self.assertTrue(any("not a regular file" in error for error in errors))

    def test_directory_at_contract_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / VERIFIER.CONTRACT_RELATIVE_PATH).mkdir(parents=True)
            errors = VERIFIER.verify_contract(root)
        self.assertTrue(any("not a regular file" in error for error in errors))

    def test_recursive_forbidden_resource_key_is_rejected(self) -> None:
        changed = copy.deepcopy(self.contract)
        changed["components"][0]["nested"] = {"list": [{"spec": {}}]}
        errors = self.verify(changed)
        self.assertTrue(any("forbidden resource field" in error for error in errors))

    def test_recursive_forbidden_secret_key_is_rejected(self) -> None:
        changed = copy.deepcopy(self.contract)
        changed["components"][1]["nested"] = {"list": [{"token": "not-a-token"}]}
        errors = self.verify(changed)
        self.assertTrue(any("forbidden secret field" in error for error in errors))

    def test_secret_shaped_value_is_rejected_recursively(self) -> None:
        changed = copy.deepcopy(self.contract)
        changed["components"][2]["nested"] = {"list": [{"note": "ghp_not-a-real-token"}]}
        errors = self.verify(changed)
        self.assertTrue(any("secret-shaped value" in error for error in errors))

    def test_resource_and_secret_inventory_cannot_be_populated(self) -> None:
        changed = copy.deepcopy(self.contract)
        changed["forbiddenResources"]["documents"] = [{"name": "deployment"}]
        self.assertTrue(self.verify(changed))

        changed = copy.deepcopy(self.contract)
        changed["forbiddenSecrets"]["secretReferences"] = ["future-secret"]
        self.assertTrue(self.verify(changed))

    def test_allowed_kind_cannot_be_added(self) -> None:
        changed = copy.deepcopy(self.contract)
        changed["allowedKinds"] = ["Deployment"]
        self.assertTrue(self.verify(changed))

    def test_flux_handoff_fields_cannot_be_filled_or_flux_object_added(self) -> None:
        changed = copy.deepcopy(self.contract)
        changed["liveEvidence"]["fluxHandoff"]["namespace"] = "stadtstack-roebel-staging-lab"
        self.assertTrue(self.verify(changed))

        changed = copy.deepcopy(self.contract)
        changed["liveEvidence"]["fluxHandoff"]["kustomization"] = None
        self.assertTrue(self.verify(changed))


if __name__ == "__main__":
    unittest.main()
