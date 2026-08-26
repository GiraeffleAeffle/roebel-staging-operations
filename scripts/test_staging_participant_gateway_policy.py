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
    return POLICY.approved_next_activation_policy_descriptor()


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
                "clusterIdentity.apiOrigin",
                "clusterIdentity.caCertificateSha256",
                "clusterIdentity.apiServerSpkiSha256",
                "clusterIdentity.kubeSystemNamespaceUid",
                "endpoints.supabase.ipv4Cidrs",
            ),
        )
        with self.assertRaisesRegex(POLICY.PolicyError, "activation blocked"):
            POLICY.assert_activation_ready(committed)

    def test_only_exact_one_way_ready_transition_is_approved(self):
        current = POLICY.activation_policy_descriptor()
        approved = ready_policy()
        self.assertEqual(
            POLICY.validate_activation_policy_transition(current, approved),
            approved,
        )
        self.assertTrue(approved["activationReady"])
        self.assertEqual(POLICY.activation_blockers(approved), ())
        self.assertEqual(
            approved["clusterIdentity"],
            {
                "apiOrigin": "https://10.255.240.11:6443",
                "caCertificateSha256": "sha256:42fd39869882e3c25a1f37c090542d215ceb0f60a7d68f5603fb9a0583afee28",
                "apiServerSpkiSha256": "sha256:1507430795ee7c9cbeea9133dd3b1a809a500de5bcc4dd8e400163ac9471186a",
                "kubeSystemNamespaceUid": "7bc769bc-e860-4d54-a0d5-d426f3a52420",
            },
        )
        self.assertEqual(
            approved["endpoints"]["supabase"]["ipv4Cidrs"],
            ["104.18.38.10/32", "172.64.149.246/32"],
        )

    def test_ready_transition_rejects_every_partial_reverse_reordered_or_widened_shape(self):
        current = POLICY.activation_policy_descriptor()
        approved = ready_policy()
        mutations = []
        for key in approved["clusterIdentity"]:
            partial = copy.deepcopy(approved)
            partial["clusterIdentity"][key] = None
            mutations.append((f"partial-{key}", partial))
        partial_cidrs = copy.deepcopy(approved)
        partial_cidrs["endpoints"]["supabase"]["ipv4Cidrs"] = ["104.18.38.10/32"]
        mutations.append(("partial-cidrs", partial_cidrs))
        reordered = copy.deepcopy(approved)
        reordered["endpoints"]["supabase"]["ipv4Cidrs"].reverse()
        mutations.append(("reordered-cidrs", reordered))
        widened = copy.deepcopy(approved)
        widened["endpoints"]["supabase"]["ipv4Cidrs"].append("192.0.2.1/32")
        mutations.append(("widened-cidrs", widened))
        authority_widened = copy.deepcopy(approved)
        authority_widened["authority"]["civicAuthority"] = "municipal"
        mutations.append(("widened-authority", authority_widened))
        extra = copy.deepcopy(approved)
        extra["callerEvidence"] = {"trusted": True}
        mutations.append(("extra-field", extra))
        wrong_ready = copy.deepcopy(approved)
        wrong_ready["activationReady"] = False
        mutations.append(("derived-ready-tamper", wrong_ready))
        for label, candidate in mutations:
            with self.subTest(label=label):
                with self.assertRaisesRegex(POLICY.PolicyError, "transition candidate drift"):
                    POLICY.validate_activation_policy_transition(current, candidate)
        with self.assertRaisesRegex(POLICY.PolicyError, "transition base drift"):
            POLICY.validate_activation_policy_transition(approved, current)
        with self.assertRaisesRegex(POLICY.PolicyError, "transition candidate drift"):
            POLICY.validate_activation_policy_transition(current, current)

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

    def test_trusted_facts_contract_is_bound_to_the_same_exact_ready_successor(self):
        current = POLICY.activation_policy_descriptor()
        approved = ready_policy()
        contract = POLICY.trusted_live_facts_contract()
        self.assertEqual(
            contract["policyBinding"],
            POLICY.activation_policy_sha256(approved),
        )
        self.assertNotEqual(
            contract["policyBinding"],
            POLICY.activation_policy_sha256(current),
        )
        self.assertEqual(
            POLICY.trusted_live_facts_contract(approved),
            contract,
        )
        self.assertEqual(
            contract["schemaVersion"],
            "roebel_staging_participant_gateway_trusted_live_facts_v2",
        )
        with self.assertRaisesRegex(POLICY.PolicyError, "activation blocked"):
            POLICY.trusted_live_facts_contract(current)

    def test_route_and_rate_limit_boundary_is_exact(self):
        value = POLICY.activation_policy_descriptor()
        self.assertEqual(tuple(route["path"] for route in value["httpBoundary"]["routes"]), POLICY.ROUTES)
        self.assertEqual(len(POLICY.ROUTES), 8)
        self.assertEqual(
            POLICY.POST_ROUTES[-2:],
            (
                "/api/staging-participant/v1/promote-source-post",
                "/api/staging-participant/v1/sign-topic-suggestion",
            ),
        )
        self.assertEqual(value["httpBoundary"]["routes"][0]["methods"], ["GET", "OPTIONS"])
        self.assertTrue(all(route["methods"] == ["POST", "OPTIONS"] for route in value["httpBoundary"]["routes"][1:]))
        self.assertEqual(value["httpBoundary"]["expectations"], list(POLICY.ROUTE_EXPECTATIONS))
        self.assertEqual(len(value["httpBoundary"]["expectations"]), 31)
        for path in POLICY.POST_ROUTES[-2:]:
            self.assertIn(
                {"case": "preflight", "method": "OPTIONS", "path": path, "status": 204},
                value["httpBoundary"]["expectations"],
            )
            self.assertIn(
                {"case": "unauthenticated-post", "method": "POST", "path": path, "status": 401},
                value["httpBoundary"]["expectations"],
            )
            self.assertIn(
                {"case": "method-denied", "method": "GET", "path": path, "status": 405},
                value["httpBoundary"]["expectations"],
            )
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

    def test_dormant_flux_bootstrap_contract_is_exact_create_only_and_receipt_bound(self):
        contract = POLICY.activation_policy_descriptor()["gitOps"]["dormantBootstrap"]
        self.assertEqual(
            contract["objectOrder"],
            [
                "gateway.serviceAccount",
                "workbenchIngress.serviceAccount",
                "gateway.role",
                "workbenchIngress.role",
                "gateway.roleBinding",
                "workbenchIngress.roleBinding",
                "gateway.kustomization",
                "workbenchIngress.kustomization",
            ],
        )
        self.assertEqual(contract["initialState"], "all-eight-exact-names-absent")
        self.assertEqual(contract["successState"], "all-eight-exact-uids-present-both-kustomizations-suspended")
        self.assertEqual(contract["adoption"], "forbidden")
        self.assertEqual(contract["definite409"], "hard-failure-never-discover-never-adopt")
        self.assertEqual(contract["operationNonce"]["annotation"], POLICY.DORMANT_BOOTSTRAP_NONCE_ANNOTATION)
        self.assertEqual(
            contract["operationNonce"]["removalIntent"],
            "exact-uid-intent-durably-receipted-before-cas",
        )
        self.assertTrue(contract["laterActivationReceiptRequired"])
        self.assertEqual(contract["receiptSchemaVersion"], POLICY.DORMANT_BOOTSTRAP_RECEIPT_SCHEMA)
        self.assertEqual(contract["sharedSourceMutation"], "forbidden")
        self.assertEqual(contract["secretAccess"], "forbidden")

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
            "ROEBEL_STAGING_PARTICIPANT_GATEWAY_TOPIC_TRACER_MIGRATION_SHA256": value["productPins"]["topicTracerMigration"]["sha256"],
            "ROEBEL_STAGING_PARTICIPANT_GATEWAY_TOPIC_TRACER_DATABASE_SCHEMA_SHA256": value["productPins"]["topicTracerDatabaseSchemaSha256"],
            "ROEBEL_STAGING_PARTICIPANT_GATEWAY_MUNICIPALITY_ID": value["runtime"]["topicPolicy"]["municipalityId"],
            "ROEBEL_STAGING_PARTICIPANT_GATEWAY_SOURCE_CONVERSATION_TOPIC": value["runtime"]["topicPolicy"]["sourceConversationTopic"],
            "ROEBEL_STAGING_PARTICIPANT_GATEWAY_TOPIC_POLICY_VERSION": value["runtime"]["topicPolicy"]["policyVersion"],
        }
        for name, expected in literal_pins.items():
            self.assertEqual(env[name], {"name": name, "value": expected})
            self.assertNotIn("valueFrom", env[name])
        self.assertNotIn("activationEvidence", resources["runtimePin"])
        self.assertEqual(
            resources["runtimePin"],
            POLICY.expected_runtime_pin(value),
        )
        self.assertEqual(
            resources["runtimePin"]["schemaVersion"],
            "roebel_staging_participant_gateway_runtime_pin_v3",
        )


if __name__ == "__main__":
    unittest.main()
