#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "staging_participant_gateway_policy_under_test",
    ROOT / "scripts/staging_participant_gateway_policy.py",
)
assert SPEC is not None and SPEC.loader is not None
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


def ready_policy() -> dict:
    value = POLICY.activation_policy_descriptor()
    pins = value["productPins"]
    pins["sourceRevision"] = "a" * 40
    pins["sourceTreeSha256"] = "sha256:" + "b" * 64
    pins["imageManifestDigest"] = "sha256:" + "c" * 64
    pins["workflowSha256"] = "sha256:" + "d" * 64
    pins["migration"]["sha256"] = "sha256:" + "e" * 64
    pins["databaseSchemaSha256"] = "sha256:" + "f" * 64
    pins["deactivation"]["sha256"] = "sha256:" + "1" * 64
    value["endpoints"]["supabase"]["ipv4Cidrs"] = ["192.0.2.25/32"]
    value["activationReady"] = True
    return value


def all_keys(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from all_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from all_keys(child)


class StaticPolicyTests(unittest.TestCase):
    def test_committed_descriptor_is_exact_and_inert(self):
        committed = json.loads((ROOT / POLICY.POLICY_PATH).read_text())
        self.assertEqual(committed, POLICY.activation_policy_descriptor())
        self.assertFalse(committed["activationReady"])
        self.assertEqual(
            POLICY.activation_blockers(committed),
            (
                "productPins.sourceRevision",
                "productPins.sourceTreeSha256",
                "productPins.imageManifestDigest",
                "productPins.workflowSha256",
                "productPins.migration.sha256",
                "productPins.databaseSchemaSha256",
                "productPins.deactivation.sha256",
                "endpoints.supabase.ipv4Cidrs",
            ),
        )
        with self.assertRaisesRegex(POLICY.PolicyError, "activation blocked"):
            POLICY.assert_activation_ready(committed)

    def test_static_descriptor_contains_no_caller_or_live_evidence(self):
        keys = set(all_keys(POLICY.activation_policy_descriptor()))
        self.assertTrue(
            set(POLICY.trusted_live_facts_contract()["forbiddenInStaticPolicy"]).isdisjoint(keys),
        )
        self.assertNotIn("activationEvidence", keys)
        self.assertNotIn("callerEvidence", keys)
        self.assertFalse(POLICY.activation_policy_descriptor()["network"]["conflictScan"]["staticInventoryHashes"])

    def test_route_and_rate_limit_boundary_is_exact(self):
        value = POLICY.activation_policy_descriptor()
        self.assertEqual(tuple(route["path"] for route in value["httpBoundary"]["routes"]), POLICY.ROUTES)
        self.assertEqual(len(POLICY.ROUTES), 6)
        self.assertEqual(value["httpBoundary"]["routes"][0]["methods"], ["GET", "OPTIONS"])
        self.assertTrue(all(route["methods"] == ["POST", "OPTIONS"] for route in value["httpBoundary"]["routes"][1:]))
        self.assertEqual(
            value["httpBoundary"]["haproxyRateLimit"],
            {
                "aggregateClaimAllowed": False,
                "key": "source-ip",
                "requests": 30,
                "scope": "per-controller-replica",
                "sharedAcrossReplicas": False,
                "windowSeconds": 60,
            },
        )

    def test_two_suspended_flux_identities_are_separate_and_exact(self):
        gateway = POLICY.gateway_flux_objects()
        reciprocal = POLICY.workbench_ingress_flux_objects()
        self.assertTrue(gateway["kustomization"]["spec"]["suspend"])
        self.assertTrue(reciprocal["kustomization"]["spec"]["suspend"])
        self.assertEqual(gateway["role"]["metadata"]["namespace"], POLICY.GATEWAY_NAMESPACE)
        self.assertEqual(reciprocal["role"]["metadata"]["namespace"], POLICY.WORKBENCH_NAMESPACE)
        self.assertNotEqual(
            gateway["kustomization"]["metadata"]["name"],
            reciprocal["kustomization"]["metadata"]["name"],
        )
        self.assertEqual(
            reciprocal["kustomization"]["spec"]["path"],
            "./" + POLICY.WORKBENCH_INGRESS_ROOT,
        )
        self.assertFalse(POLICY.expected_shared_flux_source_projection()["spec"]["suspend"])

    def test_reciprocal_network_policy_is_additive_and_does_not_adopt_workbench_policy(self):
        policy = POLICY.expected_workbench_ingress_network_policy()
        self.assertEqual(policy["metadata"]["name"], POLICY.WORKBENCH_INGRESS_POLICY_NAME)
        self.assertNotEqual(policy["metadata"]["name"], POLICY.WORKBENCH_NAME)
        self.assertEqual(policy["spec"]["podSelector"]["matchLabels"], POLICY.WORKBENCH_SELECTOR)
        self.assertEqual(
            policy["spec"]["ingress"],
            [{
                "from": [{
                    "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": POLICY.GATEWAY_NAMESPACE}},
                    "podSelector": {"matchLabels": POLICY.GATEWAY_LABELS},
                }],
                "ports": [{"port": POLICY.WORKBENCH_PORT, "protocol": "TCP"}],
            }],
        )
        preserved = POLICY.activation_policy_descriptor()["preservation"]["existingWorkbenchNetworkPolicy"]
        self.assertEqual(preserved["target"]["name"], POLICY.WORKBENCH_NAME)
        self.assertEqual(preserved["mutation"], "forbidden")
        self.assertEqual(preserved["adoption"], "forbidden")

    def test_definite_conflict_is_never_discoverable_or_adoptable(self):
        transaction = POLICY.activation_policy_descriptor()["gitOps"]["activationTransaction"]
        self.assertEqual(transaction["adoption"], "forbidden")
        self.assertEqual(
            transaction["createOutcomes"]["http-409-already-exists"],
            {"discoveryAllowed": False, "hardFailure": True, "ownedByTransaction": False},
        )
        uncertain = transaction["createOutcomes"]["transport-uncertain-after-send"]
        self.assertTrue(uncertain["discoveryAllowed"])
        self.assertTrue(uncertain["exactSemanticMatchRequired"])
        self.assertTrue(uncertain["uidResourceVersionReceiptRequired"])
        self.assertTrue(uncertain["rollbackRequired"])

    def test_normalizer_drops_server_identity_but_retains_security_semantics(self):
        desired = POLICY.expected_workbench_ingress_network_policy()
        live = copy.deepcopy(desired)
        live["metadata"].update({
            "uid": "00000000-0000-4000-8000-000000000001",
            "resourceVersion": "123",
            "generation": 2,
            "managedFields": [{"manager": "controller"}],
        })
        live["status"] = {"conditions": []}
        self.assertTrue(POLICY.semantically_equal(live, desired))
        widened = copy.deepcopy(live)
        widened["spec"]["ingress"][0]["from"].append({"namespaceSelector": {}})
        self.assertFalse(POLICY.semantically_equal(widened, desired))

    def test_normalizer_accepts_only_the_known_flux_controller_finalizer(self):
        desired = POLICY.gateway_flux_objects(suspended=True)["kustomization"]
        live = copy.deepcopy(desired)
        live["metadata"]["finalizers"] = ["finalizers.fluxcd.io"]
        self.assertTrue(POLICY.semantically_equal(live, desired))
        live["metadata"]["finalizers"].append("example.test/unreviewed")
        self.assertFalse(POLICY.semantically_equal(live, desired))

    def test_create_result_binding_rejects_409_and_owns_only_exact_observed_object(self):
        desired = POLICY.expected_workbench_ingress_network_policy()
        observed = copy.deepcopy(desired)
        observed["metadata"]["uid"] = "00000000-0000-4000-8000-000000000001"
        observed["metadata"]["resourceVersion"] = "123"
        with self.assertRaisesRegex(POLICY.PolicyError, "adoption forbidden"):
            POLICY.bind_create_result(
                outcome="http-409-already-exists",
                observed=observed,
                desired=desired,
                label="reciprocal policy",
            )
        receipt = POLICY.bind_create_result(
            outcome="transport-uncertain-after-send",
            observed=observed,
            desired=desired,
            label="reciprocal policy",
        )
        self.assertTrue(receipt["discoveredAfterTransportUncertainty"])
        self.assertTrue(receipt["rollbackOwned"])
        self.assertEqual(receipt["uid"], observed["metadata"]["uid"])
        widened = copy.deepcopy(observed)
        widened["spec"]["ingress"][0]["from"].append({"namespaceSelector": {}})
        with self.assertRaisesRegex(POLICY.PolicyError, "semantic drift"):
            POLICY.bind_create_result(
                outcome="transport-uncertain-after-send",
                observed=widened,
                desired=desired,
                label="reciprocal policy",
            )

    def test_ready_policy_produces_complete_two_path_render_without_live_facts(self):
        value = ready_policy()
        with mock.patch.object(POLICY, "STATIC_ACTIVATION_POLICY", value):
            resources = POLICY.expected_gateway_resources()
        self.assertEqual(set(resources), {
            "runtimePin",
            "networkPolicy",
            "serviceAccount",
            "service",
            "deployment",
            "ingress",
            "kustomization",
            "workbenchIngressNetworkPolicy",
            "workbenchIngressKustomization",
        })
        env = {
            item["name"]: item
            for item in resources["deployment"]["spec"]["template"]["spec"]["containers"][0]["env"]
        }
        self.assertEqual(
            env["ROEBEL_STAGING_PARTICIPANT_GATEWAY_MECKY_PUBKEY"]["valueFrom"]["secretKeyRef"]["key"],
            "mecky-pubkey",
        )
        self.assertEqual(
            env["ROEBEL_STAGING_PARTICIPANT_GATEWAY_PRIVATE_WORKBENCH_URL"]["value"],
            "http://e2e-workbench.stadtstack-roebel-staging-lab.svc.cluster.local:18083/",
        )
        self.assertNotIn("activationEvidence", resources["runtimePin"])


if __name__ == "__main__":
    unittest.main()
