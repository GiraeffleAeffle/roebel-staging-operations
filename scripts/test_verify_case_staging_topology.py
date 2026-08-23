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


class CaseStagingTopologyVerifierTests(unittest.TestCase):
    def candidate(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temp = tempfile.TemporaryDirectory()
        destination = Path(temp.name) / "candidate"
        shutil.copytree(ROOT, destination, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        return temp, destination

    def test_seed_is_an_inert_topology_contract(self) -> None:
        result = VERIFIER.verify(ROOT)
        self.assertEqual(result["status"], "passed")
        self.assertFalse(result["effects"]["clusterMutation"])
        self.assertFalse(result["effects"]["liveBind"])
        self.assertFalse(result["effects"]["workloadDefinition"])

    def test_service_account_cannot_mount_a_token(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        path = candidate / "case-staging-topology/roebel-case-steward-control-serviceaccount.json"
        value = json.loads(path.read_text())
        value["automountServiceAccountToken"] = True
        path.write_text(json.dumps(value, indent=2) + "\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "ServiceAccount drift"):
            VERIFIER.verify(candidate)

    def test_service_cannot_be_exposed_outside_cluster(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        path = candidate / "case-staging-topology/roebel-case-public-binding-service.json"
        value = json.loads(path.read_text())
        value["spec"]["type"] = "LoadBalancer"
        path.write_text(json.dumps(value, indent=2) + "\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "Service drift"):
            VERIFIER.verify(candidate)

    def test_network_policy_cannot_allow_any_traffic_before_composition(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        path = candidate / "case-staging-topology/roebel-case-public-binding-default-deny-networkpolicy.json"
        value = json.loads(path.read_text())
        value["spec"]["ingress"] = [{}]
        path.write_text(json.dumps(value, indent=2) + "\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "default-deny NetworkPolicy drift"):
            VERIFIER.verify(candidate)

    def test_closed_world_contract_cannot_allow_a_workload_kind(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        path = candidate / "case-staging-topology/contract.json"
        value = json.loads(path.read_text())
        value["allowedKinds"].append("Deployment")
        path.write_text(json.dumps(value, indent=2) + "\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "topology contract drift"):
            VERIFIER.verify(candidate)

    def test_unreviewed_workload_or_storage_file_is_rejected(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        (candidate / "case-staging-topology/case-deployment.json").write_text(
            '{"apiVersion":"apps/v1","kind":"Deployment"}\n'
        )
        with self.assertRaisesRegex(VERIFIER.VerificationError, "file set drift"):
            VERIFIER.verify(candidate)

    def test_duplicate_json_key_is_rejected(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        path = candidate / "case-staging-topology/contract.json"
        path.write_text('{"schemaVersion":"x","schemaVersion":"y"}\n')
        with self.assertRaisesRegex(VERIFIER.VerificationError, "duplicate JSON key"):
            VERIFIER.verify(candidate)


if __name__ == "__main__":
    unittest.main()
