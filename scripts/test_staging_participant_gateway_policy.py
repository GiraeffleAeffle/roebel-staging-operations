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
    def test_committed_descriptor_is_an_exact_approved_state(self):
        committed = json.loads((ROOT / POLICY.POLICY_PATH).read_text())
        inert = POLICY.activation_policy_descriptor()
        ready = ready_policy()
        self.assertIn(committed, (inert, ready))
        self.assertTrue(committed["activationReady"])
        self.assertEqual(POLICY.activation_blockers(committed), ())
        self.assertEqual(POLICY.assert_activation_ready(committed), committed)

    def test_only_exact_one_way_ready_transition_is_approved(self):
        current = POLICY.activation_policy_descriptor()
        approved = ready_policy()
        self.assertEqual(
            POLICY.validate_activation_policy_transition(current, approved),
            approved,
        )
        self.assertTrue(approved["activationReady"])
        self.assertTrue(current["activationReady"])
        self.assertEqual(POLICY.activation_blockers(approved), ())
        self.assertEqual(POLICY.activation_blockers(current), ())
        self.assertEqual(
            current["schemaVersion"],
            "roebel_staging_participant_gateway_activation_policy_v4",
        )
        self.assertEqual(
            approved["schemaVersion"],
            "roebel_staging_participant_gateway_activation_policy_v5",
        )
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
            approved["endpoints"]["supabase"],
            {
                "externalIngress": False,
                "internalOrigin": (
                    "http://roebel-tracer-postgrest."
                    "stadtstack-roebel-staging-lab.svc.cluster.local:3000"
                ),
                "port": 3000,
                "service": {
                    "apiVersion": "v1",
                    "kind": "Service",
                    "name": "roebel-tracer-postgrest",
                    "namespace": "stadtstack-roebel-staging-lab",
                },
                "transport": "cluster-http",
            },
        )

    def test_ready_transition_rejects_every_partial_reverse_reordered_or_widened_shape(self):
        current = POLICY.activation_policy_descriptor()
        approved = ready_policy()
        mutations = []
        for key in approved["clusterIdentity"]:
            partial = copy.deepcopy(approved)
            partial["clusterIdentity"][key] = None
            mutations.append((f"partial-{key}", partial))
        external_origin = copy.deepcopy(approved)
        external_origin["endpoints"]["supabase"]["internalOrigin"] = "https://example.invalid"
        mutations.append(("external-origin", external_origin))
        external_ingress = copy.deepcopy(approved)
        external_ingress["endpoints"]["supabase"]["externalIngress"] = True
        mutations.append(("external-ingress", external_ingress))
        wrong_service = copy.deepcopy(approved)
        wrong_service["endpoints"]["supabase"]["service"]["name"] = "other-postgrest"
        mutations.append(("wrong-service", wrong_service))
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
        current_contract = POLICY.trusted_live_facts_contract(current)
        self.assertEqual(
            current_contract["policyBinding"],
            POLICY.activation_policy_sha256(current),
        )
        self.assertNotEqual(current_contract["policyBinding"], contract["policyBinding"])

    def test_route_and_rate_limit_boundary_is_exact(self):
        value = ready_policy()
        self.assertEqual(
            tuple(route["path"] for route in value["httpBoundary"]["routes"]),
            POLICY.ROUTES,
        )
        self.assertEqual(len(POLICY.ROUTES), 11)
        self.assertEqual(
            POLICY.POST_ROUTES[-3:],
            (
                "/api/staging-participant/v1/citizen-adoption/challenge",
                "/api/staging-participant/v1/citizen-adoption/eligibility",
                "/api/staging-participant/v1/citizen-adoption/adoptions",
            ),
        )
        self.assertEqual(value["httpBoundary"]["routes"][0]["methods"], ["GET", "OPTIONS"])
        self.assertTrue(all(
            route["methods"] == ["POST", "OPTIONS"]
            for route in value["httpBoundary"]["routes"][1:]
        ))
        self.assertEqual(
            value["httpBoundary"]["dynamicGetPrefixes"],
            list(POLICY.DYNAMIC_GET_PREFIXES),
        )
        self.assertEqual(
            value["httpBoundary"]["routeProbeSamples"],
            list(POLICY.PUBLIC_GET_ROUTES),
        )
        self.assertEqual(
            value["httpBoundary"]["additionalIngressPrefixes"],
            ["/api/civic/v1/eligibility/status"],
        )
        self.assertEqual(value["httpBoundary"]["expectations"], list(POLICY.ROUTE_EXPECTATIONS))
        self.assertEqual(value["httpBoundary"]["timeoutsSeconds"]["kubernetesRequest"], 30)
        self.assertEqual(value["httpBoundary"]["timeoutsSeconds"]["routeRequest"], 10)
        self.assertEqual(len(value["httpBoundary"]["expectations"]), 46)
        for path in POLICY.POST_ROUTES[-3:]:
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
        self.assertIn(
            {
                "case": "public-adoption-absent",
                "method": "GET",
                "path": POLICY.CITIZEN_ADOPTION_PUBLIC_READ_SAMPLE,
                "status": 404,
            },
            value["httpBoundary"]["expectations"],
        )
        self.assertIn(
            {
                "case": "eligibility-status-reserved",
                "method": "GET",
                "path": POLICY.CITIZEN_ELIGIBILITY_STATUS_SAMPLE,
                "status": 503,
            },
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
        # Flux applies and proves its revision; application readiness remains
        # the protected runner's job so the narrow Role needs no discovery
        # permission for ReplicaSets.
        active_gateway = POLICY.gateway_flux_objects(suspended=False)
        active_reciprocal = POLICY.workbench_ingress_flux_objects(suspended=False)
        for flux in (gateway, reciprocal, active_gateway, active_reciprocal):
            self.assertFalse(flux["kustomization"]["spec"]["wait"])
            self.assertNotIn("healthChecks", flux["kustomization"]["spec"])
        self.assertFalse(active_gateway["kustomization"]["spec"]["suspend"])
        self.assertFalse(active_reciprocal["kustomization"]["spec"]["suspend"])
        self.assertFalse(any(
            "replicasets" in rule.get("resources", [])
            for owner in (gateway, reciprocal)
            for rule in owner["role"]["rules"]
        ))
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

    def test_participant_secret_materializer_is_descriptor_bound_and_receipt_owned(self):
        contract = POLICY.activation_policy_descriptor()["runtime"]["secretMaterializer"]
        self.assertEqual(contract, POLICY.secret_materializer_contract())
        self.assertEqual(contract["runner"], POLICY.SECRET_MATERIALIZER_RUNNER)
        self.assertEqual(contract["inputTransport"], "owned-private-inherited-descriptors-only")
        self.assertEqual(contract["createOrder"], ["config", "runtime"])
        self.assertEqual(contract["initialState"], "both-exact-secret-names-absent")
        self.assertEqual(contract["adoption"], "forbidden")
        self.assertFalse(contract["receiptContainsValues"])
        self.assertEqual(contract["receiptSchemaVersion"], POLICY.SECRET_MATERIALIZATION_RECEIPT_SCHEMA)
        self.assertEqual(contract["teardownReceiptSchemaVersion"], POLICY.SECRET_TEARDOWN_RECEIPT_SCHEMA)
        self.assertEqual(contract["teardown"]["deleteOrder"], ["runtime", "config"])
        self.assertTrue(contract["teardown"]["uidResourceVersionPreconditions"])
        self.assertEqual(len(contract["teardown"]["requiredAbsentTargets"]), 8)

    def test_gateway_ingress_policy_matches_the_exact_hostnetwork_controller_sources(self):
        value = ready_policy()
        cidrs = [
            "10.42.0.10/32", "10.42.0.11/32", "10.42.0.12/32",
            "10.244.0.0/32", "10.244.1.0/32", "10.244.2.0/32",
            "10.244.0.1/32", "10.244.1.1/32", "10.244.2.1/32",
        ]
        self.assertEqual(value["network"]["gatewayIngressHostNetworkSourceCidrs"], cidrs)
        network_policy = POLICY.expected_gateway_resources(value)["networkPolicy"]
        self.assertEqual(
            network_policy["spec"]["ingress"],
            [{
                "from": [
                    {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "ingress-system"}}},
                    *[{"ipBlock": {"cidr": cidr}} for cidr in cidrs],
                ],
                "ports": [{"port": POLICY.GATEWAY_PORT, "protocol": "TCP"}],
            }],
        )
        for label, mutate in (
            ("omitted", lambda items: items.pop()),
            ("widened", lambda items: items.append("10.42.0.0/16")),
            ("reordered", lambda items: items.reverse()),
        ):
            changed = copy.deepcopy(value)
            mutate(changed["network"]["gatewayIngressHostNetworkSourceCidrs"])
            with self.subTest(label=label), self.assertRaises(POLICY.PolicyError):
                POLICY.validate_activation_policy(changed)

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

    def test_civic_projection_workbench_ingress_adds_only_the_exact_web_presentation(self):
        policy = POLICY.expected_workbench_ingress_network_policy(
            include_web_presentation=True,
        )
        self.assertEqual(
            policy["spec"]["ingress"][0]["from"],
            [
                {
                    "namespaceSelector": {
                        "matchLabels": {
                            "kubernetes.io/metadata.name": POLICY.GATEWAY_NAMESPACE,
                        },
                    },
                    "podSelector": {"matchLabels": POLICY.GATEWAY_LABELS},
                },
                {
                    "namespaceSelector": {
                        "matchLabels": {
                            "kubernetes.io/metadata.name": POLICY.GATEWAY_NAMESPACE,
                        },
                    },
                    "podSelector": {
                        "matchLabels": POLICY.WEB_PRESENTATION_LABELS,
                    },
                },
            ],
        )

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

    def test_networkpolicy_normalizer_accepts_only_empty_rule_slice_omission(self):
        desired = POLICY.expected_workbench_ingress_network_policy()
        desired["spec"]["policyTypes"] = ["Ingress", "Egress"]
        desired["spec"]["egress"] = []
        live = copy.deepcopy(desired)
        live["spec"].pop("egress")
        self.assertTrue(POLICY.semantically_equal(live, desired))
        widened = copy.deepcopy(live)
        widened["spec"]["policyTypes"].remove("Egress")
        self.assertFalse(POLICY.semantically_equal(widened, desired))
        widened = copy.deepcopy(live)
        widened["spec"]["egress"] = [{"to": [{"namespaceSelector": {}}]}]
        self.assertFalse(POLICY.semantically_equal(widened, desired))

    def test_normalizer_accepts_only_the_known_flux_controller_finalizer(self):
        desired = POLICY.gateway_flux_objects(suspended=True)["kustomization"]
        live = copy.deepcopy(desired)
        live["metadata"]["finalizers"] = ["finalizers.fluxcd.io"]
        self.assertTrue(POLICY.semantically_equal(live, desired))
        live["metadata"]["finalizers"].append("example.test/unreviewed")
        self.assertFalse(POLICY.semantically_equal(live, desired))

    def test_deployment_normalizer_accepts_only_matching_defaulted_service_account_alias(self):
        desired = POLICY.expected_gateway_resources(ready_policy())["deployment"]
        service_account_name = desired["spec"]["template"]["spec"]["serviceAccountName"]
        live = copy.deepcopy(desired)
        live["spec"]["template"]["spec"]["serviceAccount"] = service_account_name
        self.assertTrue(POLICY.semantically_equal(live, desired))
        for label, value in (
            ("mismatch", "different-service-account"),
            ("wrong-type", [service_account_name]),
            ("empty", ""),
        ):
            widened = copy.deepcopy(live)
            widened["spec"]["template"]["spec"]["serviceAccount"] = value
            with self.subTest(label=label):
                self.assertFalse(POLICY.semantically_equal(widened, desired))
        alias_only = copy.deepcopy(live)
        alias_only["spec"]["template"]["spec"].pop("serviceAccountName")
        self.assertFalse(POLICY.semantically_equal(alias_only, desired))

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
            "ROEBEL_STAGING_PARTICIPANT_GATEWAY_CITIZEN_ADOPTION_POLICY_VERSION": value["runtime"]["citizenAdoption"]["policyVersion"],
            "ROEBEL_STAGING_PARTICIPANT_GATEWAY_ELIGIBILITY_ISSUER_KEY_ID": value["runtime"]["citizenAdoption"]["eligibilityIssuer"]["keyId"],
            "ROEBEL_STAGING_PARTICIPANT_GATEWAY_ELIGIBILITY_ISSUER_PUBLIC_KEY": value["runtime"]["citizenAdoption"]["eligibilityIssuer"]["publicKey"],
            "ROEBEL_STAGING_PARTICIPANT_GATEWAY_CITIZEN_NFT_ADDRESS": value["runtime"]["citizenAdoption"]["citizenNft"]["address"],
            "ROEBEL_STAGING_PARTICIPANT_GATEWAY_CITIZEN_NFT_RUNTIME_CODE_HASH": value["runtime"]["citizenAdoption"]["citizenNft"]["runtimeCodeHash"],
            "ROEBEL_STAGING_PARTICIPANT_GATEWAY_CITIZEN_ADOPTION_MIGRATION_SHA256": value["productPins"]["citizenAdoptionMigration"]["sha256"],
            "ROEBEL_STAGING_PARTICIPANT_GATEWAY_CITIZEN_ADOPTION_DATABASE_SCHEMA_SHA256": value["productPins"]["citizenAdoptionDatabaseSchemaSha256"],
        }
        for name, expected in literal_pins.items():
            self.assertEqual(env[name], {"name": name, "value": expected})
            self.assertNotIn("valueFrom", env[name])
        issuer_secret = env[
            "ROEBEL_STAGING_PARTICIPANT_GATEWAY_ELIGIBILITY_ISSUER_PRIVATE_KEY_HEX"
        ]["valueFrom"]["secretKeyRef"]
        self.assertEqual(
            issuer_secret,
            {
                "key": "private-key-hex",
                "name": "roebel-staging-participant-gateway-eligibility-issuer",
                "optional": False,
            },
        )
        container = resources["deployment"]["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(
            container["readinessProbe"],
            {
                "failureThreshold": 3,
                "httpGet": {"path": "/status", "port": "http", "scheme": "HTTP"},
                "periodSeconds": 10,
                "successThreshold": 1,
                "timeoutSeconds": 3,
            },
        )
        self.assertIn("tcpSocket", container["livenessProbe"])
        self.assertIn("tcpSocket", container["startupProbe"])
        self.assertNotIn("activationEvidence", resources["runtimePin"])
        self.assertEqual(
            resources["runtimePin"],
            POLICY.expected_runtime_pin(value),
        )
        self.assertEqual(
            resources["runtimePin"]["schemaVersion"],
            "roebel_staging_participant_gateway_runtime_pin_v4",
        )
        self.assertEqual(
            resources["runtimePin"]["citizenAdoption"],
            value["runtime"]["citizenAdoption"],
        )


if __name__ == "__main__":
    unittest.main()
