#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "case_staging_topology_verifier", ROOT / "scripts/verify-case-staging-topology.py"
)
assert SPEC and SPEC.loader
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)

REVIEWED_SPEC = importlib.util.spec_from_file_location(
    "reviewed_render_verifier", ROOT / "scripts/verify-reviewed-render.py"
)
assert REVIEWED_SPEC and REVIEWED_SPEC.loader
REVIEWED = importlib.util.module_from_spec(REVIEWED_SPEC)
REVIEWED_SPEC.loader.exec_module(REVIEWED)


class CaseStagingTopologyVerifierTests(unittest.TestCase):
    def candidate(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temp = tempfile.TemporaryDirectory()
        destination = Path(temp.name) / "candidate"
        shutil.copytree(ROOT, destination, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        return temp, destination

    def load(self, candidate: Path, name: str) -> tuple[Path, dict]:
        path = candidate / "case-staging-topology" / name
        return path, json.loads(path.read_text())

    def write(self, path: Path, value: dict) -> None:
        path.write_text(json.dumps(value, indent=2) + "\n")

    def test_seed_is_an_inert_runtime_gate(self) -> None:
        result = VERIFIER.verify(ROOT)
        self.assertEqual(result["status"], "passed")
        self.assertFalse(result["reconciliationAllowed"])
        self.assertFalse(result["fluxKustomizationAllowed"])
        self.assertFalse(result["effects"]["clusterMutation"])
        self.assertFalse(result["effects"]["workloadDefinition"])
        contract = json.loads((ROOT / "case-staging-topology/contract.json").read_text())
        self.assertEqual(contract["controlDeploymentPreflight"]["status"], "blocked")
        self.assertEqual(contract["controlDeploymentPreflight"]["schemaVersion"], "staging_case_control_deployment_binding_v1")
        self.assertEqual(contract["allowedKinds"], ["NetworkPolicy", "Service", "ServiceAccount"])
        self.assertFalse(contract["invariants"]["pvcObjectsAllowed"])
        self.assertFalse(contract["invariants"]["workloadDefinitionAllowed"])
        binding = contract["controlDeploymentPreflight"]["binding"]
        self.assertEqual(binding["workloadName"], "roebel-case-steward-control")
        self.assertEqual(binding["deployment"]["strategy"], "Recreate")
        self.assertEqual([listener["id"] for listener in binding["listeners"]], ["admission", "private-outbox", "probe"])
        self.assertIsNone(contract["controlDeploymentPreflight"]["expectedBindingChecksum"])
        self.assertIsNone(binding["releaseDigest"])
        self.assertIsNone(binding["operationsTopologyChecksum"])
        self.assertIsNone(binding["bindingChecksum"])

    def test_control_preflight_rejects_placeholders_and_missing_evidence_drift(self) -> None:
        mutations = (
            lambda value: value["controlDeploymentPreflight"]["binding"]["storage"].update({"pvcUid": "TBD"}),
            lambda value: value["controlDeploymentPreflight"]["binding"].update({"releaseDigest": "pending"}),
            lambda value: value["controlDeploymentPreflight"].update({"expectedBindingChecksum": "pending"}),
            lambda value: value["controlDeploymentPreflight"]["missingEvidence"].pop(),
            lambda value: value["controlDeploymentPreflight"].update({"status": "ready"}),
        )
        for mutator in mutations:
            temp, candidate = self.candidate()
            self.addCleanup(temp.cleanup)
            path, contract = self.load(candidate, "contract.json")
            mutator(contract)
            self.write(path, contract)
            with self.assertRaisesRegex(VERIFIER.VerificationError, "(?:placeholder|missing evidence|must stay blocked|runtime gate contract drift)"):
                VERIFIER.verify(candidate)

    def test_public_workload_cannot_receive_control_storage_preflight(self) -> None:
        for field, value in (
            ("controlDeploymentPreflight", {"status": "blocked"}),
            ("storage", {"pvc": None}),
            ("stateMount", {"rootPath": "/var/lib/stadtstack/case-control"}),
        ):
            temp, candidate = self.candidate()
            self.addCleanup(temp.cleanup)
            path, contract = self.load(candidate, "contract.json")
            contract["futureWorkloads"]["public"][field] = value
            self.write(path, contract)
            with self.assertRaisesRegex(VERIFIER.VerificationError, "public workload cannot carry"):
                VERIFIER.verify(candidate)

    def test_control_and_public_service_accounts_cannot_mount_a_token(self) -> None:
        for name in (
            "roebel-case-steward-control-serviceaccount.json",
            "roebel-case-public-binding-serviceaccount.json",
        ):
            temp, candidate = self.candidate()
            self.addCleanup(temp.cleanup)
            path, value = self.load(candidate, name)
            value["automountServiceAccountToken"] = True
            self.write(path, value)
            with self.assertRaisesRegex(VERIFIER.VerificationError, "ServiceAccount drift"):
                VERIFIER.verify(candidate)

    def test_public_contract_cannot_gain_secret_pvc_token_or_rbac_access(self) -> None:
        for field, value in (
            ("preexistingSecretRefs", ["unexpected"]),
            ("preexistingPersistentVolumeClaimRefs", ["unexpected"]),
            ("forbiddenReferences", ["Secret"]),
        ):
            temp, candidate = self.candidate()
            self.addCleanup(temp.cleanup)
            path, contract = self.load(candidate, "contract.json")
            contract["futureWorkloads"]["public"][field] = value
            self.write(path, contract)
            with self.assertRaisesRegex(VERIFIER.VerificationError, "runtime gate contract drift"):
                VERIFIER.verify(candidate)

    def test_contract_rejects_tag_image_and_production_token_adapter(self) -> None:
        for mutator in (
            lambda value: value["futureWorkloads"]["control"]["image"].update({"value": "ghcr.io/example/control:latest"}),
            lambda value: value["futureWorkloads"]["control"]["tokenAdapter"].update({"environment": "production"}),
        ):
            temp, candidate = self.candidate()
            self.addCleanup(temp.cleanup)
            path, contract = self.load(candidate, "contract.json")
            mutator(contract)
            self.write(path, contract)
            with self.assertRaisesRegex(VERIFIER.VerificationError, "runtime gate contract drift"):
                VERIFIER.verify(candidate)

    def test_services_are_exactly_three_civic_ports_and_no_probe_service(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        (candidate / "case-staging-topology/roebel-case-public-probe-service.json").write_text(
            '{"apiVersion":"v1","kind":"Service"}\n'
        )
        with self.assertRaisesRegex(VERIFIER.VerificationError, "file set drift"):
            VERIFIER.verify(candidate)

    def test_service_cannot_widen_civic_port_or_selector(self) -> None:
        for mutator in (
            lambda value: value["spec"]["ports"][0].update({"port": 18088, "targetPort": 18088}),
            lambda value: value["spec"]["selector"].update({"app.kubernetes.io/name": "anything"}),
        ):
            temp, candidate = self.candidate()
            self.addCleanup(temp.cleanup)
            path, value = self.load(candidate, "roebel-case-steward-control-service.json")
            mutator(value)
            self.write(path, value)
            with self.assertRaisesRegex(VERIFIER.VerificationError, "Service drift"):
                VERIFIER.verify(candidate)

    def test_admission_and_outbox_cannot_cross_over(self) -> None:
        for name, path_to_port in (
            ("roebel-case-steward-control-allow-private-outbox-from-public-networkpolicy.json", ["spec", "ingress", 0, "ports", 0]),
            ("roebel-case-public-binding-allow-private-outbox-and-dns-egress-networkpolicy.json", ["spec", "egress", 1, "ports", 0]),
        ):
            temp, candidate = self.candidate()
            self.addCleanup(temp.cleanup)
            path, value = self.load(candidate, name)
            cursor = value
            for part in path_to_port:
                cursor = cursor[part]
            cursor["port"] = 18085
            self.write(path, value)
            with self.assertRaisesRegex(VERIFIER.VerificationError, "NetworkPolicy drift"):
                VERIFIER.verify(candidate)

    def test_network_policies_cannot_widen_egress_or_web_ingress(self) -> None:
        mutations = (
            ("roebel-case-public-binding-allow-private-outbox-and-dns-egress-networkpolicy.json", lambda value: value["spec"]["egress"].append({})),
            ("roebel-case-public-binding-allow-roebel-web-ingress-networkpolicy.json", lambda value: value["spec"]["ingress"][0]["from"][0]["namespaceSelector"]["matchLabels"].clear()),
        )
        for name, mutate in mutations:
            temp, candidate = self.candidate()
            self.addCleanup(temp.cleanup)
            path, value = self.load(candidate, name)
            mutate(value)
            self.write(path, value)
            with self.assertRaisesRegex(VERIFIER.VerificationError, "NetworkPolicy drift"):
                VERIFIER.verify(candidate)

    def test_flux_reference_or_automatic_promotion_mutation_is_rejected(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        (candidate / "case-staging-topology/future-flux-kustomization.json").write_text(
            '{"apiVersion":"kustomize.toolkit.fluxcd.io/v1","kind":"Kustomization"}\n'
        )
        with self.assertRaisesRegex(VERIFIER.VerificationError, "file set drift"):
            VERIFIER.verify(candidate)

        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        path, service = self.load(candidate, "roebel-case-public-binding-service.json")
        path.write_text(json.dumps(service, indent=4) + "\n")
        valid_candidate = REVIEWED.verify_tree(candidate)
        valid_base = REVIEWED.verify_tree(ROOT)
        with self.assertRaisesRegex(REVIEWED.VerificationError, "promotion changed protected policy file"):
            REVIEWED.verify_transition(valid_candidate, valid_base)

    def test_duplicate_json_key_is_rejected(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        path = candidate / "case-staging-topology/contract.json"
        path.write_text('{"schemaVersion":"x","schemaVersion":"y"}\n')
        with self.assertRaisesRegex(VERIFIER.VerificationError, "duplicate JSON key"):
            VERIFIER.verify(candidate)


if __name__ == "__main__":
    unittest.main()
