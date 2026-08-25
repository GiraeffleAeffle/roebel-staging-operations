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
    value["clusterIdentity"] = {
        "apiOrigin": "https://api.staging.example:6443",
        "caCertificateSha256": "sha256:" + "2" * 64,
        "apiServerSpkiSha256": "sha256:" + "3" * 64,
        "kubeSystemNamespaceUid": "00000000-0000-4000-8000-000000000001",
    }
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
    def test_committed_descriptor_is_exact_and_activation_ready(self):
        committed = json.loads((ROOT / POLICY.POLICY_PATH).read_text())
        self.assertEqual(committed, POLICY.activation_policy_descriptor())
        self.assertTrue(committed["activationReady"])
        self.assertEqual(POLICY.activation_blockers(committed), ())
        self.assertEqual(
            committed["clusterIdentity"],
            {
                "apiOrigin": "https://10.255.240.11:6443",
                "caCertificateSha256": "sha256:42fd39869882e3c25a1f37c090542d215ceb0f60a7d68f5603fb9a0583afee28",
                "apiServerSpkiSha256": "sha256:1507430795ee7c9cbeea9133dd3b1a809a500de5bcc4dd8e400163ac9471186a",
                "kubeSystemNamespaceUid": "7bc769bc-e860-4d54-a0d5-d426f3a52420",
            },
        )
        self.assertEqual(
            committed["endpoints"]["supabase"]["ipv4Cidrs"],
            ["104.18.38.10/32", "172.64.149.246/32"],
        )
        self.assertEqual(POLICY.assert_activation_ready(committed), committed)

    def test_static_descriptor_contains_no_caller_or_live_evidence(self):
        keys = set(all_keys(POLICY.activation_policy_descriptor()))
        self.assertTrue(
            set(POLICY.trusted_live_facts_contract()["forbiddenInStaticPolicy"]).isdisjoint(keys),
        )
        self.assertNotIn("activationEvidence", keys)
        self.assertNotIn("callerEvidence", keys)
        self.assertFalse(POLICY.activation_policy_descriptor()["network"]["conflictScan"]["staticInventoryHashes"])
        pins = POLICY.activation_policy_descriptor()["productPins"]
        self.assertEqual(pins["sourceTreeHashSemantics"], "sha256-of-git-ls-tree-rz-full-tree-raw-bytes")
        self.assertEqual(pins["workflowHashSemantics"], "sha256-of-raw-git-blob-bytes-at-source-revision")

    def test_route_and_rate_limit_boundary_is_exact(self):
        value = POLICY.activation_policy_descriptor()
        self.assertEqual(tuple(route["path"] for route in value["httpBoundary"]["routes"]), POLICY.ROUTES)
        self.assertEqual(len(POLICY.ROUTES), 6)
        self.assertEqual(value["httpBoundary"]["routes"][0]["methods"], ["GET", "OPTIONS"])
        self.assertTrue(all(route["methods"] == ["POST", "OPTIONS"] for route in value["httpBoundary"]["routes"][1:]))
        self.assertEqual(value["httpBoundary"]["expectations"], list(POLICY.ROUTE_EXPECTATIONS))
        self.assertEqual(len(value["httpBoundary"]["expectations"]), 25)
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
        uncertain = transaction["createOutcomes"]["post-send-uncertain-discovered"]
        self.assertTrue(uncertain["discoveryAllowed"])
        self.assertTrue(uncertain["exactSemanticMatchRequired"])
        self.assertTrue(uncertain["operationNonceRequired"])
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
        nonce = "9" * 64
        desired = POLICY.with_operation_nonce(POLICY.expected_workbench_ingress_network_policy(), nonce)
        observed = copy.deepcopy(desired)
        observed["metadata"]["uid"] = "00000000-0000-4000-8000-000000000001"
        observed["metadata"]["resourceVersion"] = "123"
        with self.assertRaisesRegex(POLICY.PolicyError, "adoption forbidden"):
            POLICY.bind_create_result(
                outcome="http-409-already-exists",
                observed=observed,
                desired=desired,
                label="reciprocal policy",
                operation_nonce=nonce,
            )
        receipt = POLICY.bind_create_result(
            outcome="post-send-uncertain-discovered",
            observed=observed,
            desired=desired,
            label="reciprocal policy",
            operation_nonce=nonce,
        )
        self.assertTrue(receipt["discoveredAfterPostSendUncertainty"])
        self.assertEqual(receipt["operationNonce"], nonce)
        self.assertTrue(receipt["rollbackOwned"])
        self.assertEqual(receipt["uid"], observed["metadata"]["uid"])
        widened = copy.deepcopy(observed)
        widened["spec"]["ingress"][0]["from"].append({"namespaceSelector": {}})
        with self.assertRaisesRegex(POLICY.PolicyError, "semantic drift"):
            POLICY.bind_create_result(
                outcome="post-send-uncertain-discovered",
                observed=widened,
                desired=desired,
                label="reciprocal policy",
                operation_nonce=nonce,
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
        literal_pins = {
            "ROEBEL_STAGING_PARTICIPANT_GATEWAY_SOURCE_REVISION": value["productPins"]["sourceRevision"],
            "ROEBEL_STAGING_PARTICIPANT_GATEWAY_MANIFEST_DIGEST": value["productPins"]["imageManifestDigest"],
            "ROEBEL_STAGING_PARTICIPANT_GATEWAY_MIGRATION_SHA256": value["productPins"]["migration"]["sha256"],
            "ROEBEL_STAGING_PARTICIPANT_GATEWAY_DATABASE_SCHEMA_SHA256": value["productPins"]["databaseSchemaSha256"],
        }
        for name, expected in literal_pins.items():
            self.assertEqual(env[name], {"name": name, "value": expected})
            self.assertNotIn("valueFrom", env[name])
        self.assertNotIn("activationEvidence", resources["runtimePin"])


if __name__ == "__main__":
    unittest.main()
