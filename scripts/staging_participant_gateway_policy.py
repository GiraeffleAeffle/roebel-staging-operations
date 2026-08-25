#!/usr/bin/env python3
"""Protected static policy for the Röbel staging participant gateway.

This module is the shared seam between protected admission and the local
activation runner.  Git contains product intent, exact identities and empty
immutable publication/database slots.  It never contains live Kubernetes
UIDs, resource versions, controller status, DNS observations or caller-supplied
evidence.  Those facts belong to a short-lived runner receipt validated
against this policy after the policy is activation-ready.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any


POLICY_SCHEMA = "roebel_staging_participant_gateway_activation_policy_v4"
TRUSTED_LIVE_FACTS_SCHEMA = "roebel_staging_participant_gateway_trusted_live_facts_v1"
POLICY_PATH = "policy/staging-participant-gateway-activation-policy.json"
GATEWAY_ROOT = "reviewed-render/roebel-staging/staging-participant-gateway"
WORKBENCH_INGRESS_ROOT = f"{GATEWAY_ROOT}/workbench-ingress"

GATEWAY_RENDER_FILES = (
    f"{GATEWAY_ROOT}/networkpolicy.json",
    f"{GATEWAY_ROOT}/serviceaccount.json",
    f"{GATEWAY_ROOT}/service.json",
    f"{GATEWAY_ROOT}/deployment.json",
    f"{GATEWAY_ROOT}/ingress.json",
    f"{GATEWAY_ROOT}/kustomization.yaml",
    f"{GATEWAY_ROOT}/runtime-pin.json",
)
WORKBENCH_INGRESS_RENDER_FILES = (
    f"{WORKBENCH_INGRESS_ROOT}/networkpolicy.json",
    f"{WORKBENCH_INGRESS_ROOT}/kustomization.yaml",
)
ALL_RENDER_FILES = GATEWAY_RENDER_FILES + WORKBENCH_INGRESS_RENDER_FILES

GATEWAY_NAME = "roebel-staging-participant-gateway"
GATEWAY_NAMESPACE = "stadtstack-roebel-web-preview"
GATEWAY_PORT = 18085
WORKBENCH_NAMESPACE = "stadtstack-roebel-staging-lab"
WORKBENCH_NAME = "e2e-workbench"
WORKBENCH_PORT = 18083
WORKBENCH_INGRESS_POLICY_NAME = "roebel-staging-participant-workbench-ingress"
FLUX_NAMESPACE = "flux-roebel-staging"
FLUX_SOURCE_NAME = "roebel-staging-operations"

GATEWAY_LABELS = {
    "app.kubernetes.io/component": "staging-participant-gateway",
    "app.kubernetes.io/name": GATEWAY_NAME,
    "app.kubernetes.io/part-of": "stadtstack",
    "stadtstack.io/authority": "none",
    "stadtstack.io/civic-authority": "none",
    "stadtstack.io/environment": "staging",
}
WORKBENCH_SELECTOR = {
    "app.kubernetes.io/component": "e2e-workbench",
    "app.kubernetes.io/name": WORKBENCH_NAME,
    "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
}
WORKBENCH_INGRESS_POLICY_LABELS = {
    "app.kubernetes.io/component": "staging-participant-workbench-ingress",
    "app.kubernetes.io/name": WORKBENCH_INGRESS_POLICY_NAME,
    "app.kubernetes.io/part-of": "stadtstack",
    "stadtstack.io/authority": "none",
    "stadtstack.io/civic-authority": "none",
    "stadtstack.io/environment": "staging",
    "stadtstack.io/gitops-owner": "participant-workbench-ingress",
}

ROUTES = (
    "/api/staging-participant/v1/status",
    "/api/staging-participant/v1/challenge",
    "/api/staging-participant/v1/session",
    "/api/staging-participant/v1/posts",
    "/api/staging-participant/v1/comments",
    "/api/staging-participant/v1/nostr-post",
)
POST_ROUTES = ROUTES[1:]

SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
RFC3339_UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


class PolicyError(ValueError):
    """Raised when static policy or runner facts widen the boundary."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode()).hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyError(message)


def _target(api_version: str, kind: str, name: str, namespace: str) -> dict[str, str]:
    return {
        "apiVersion": api_version,
        "kind": kind,
        "name": name,
        "namespace": namespace,
    }


def _static_descriptor() -> dict[str, Any]:
    gateway_reconciler = "roebel-staging-participant-gateway-reconciler"
    workbench_reconciler = "roebel-staging-participant-workbench-ingress-reconciler"
    return {
        "schemaVersion": POLICY_SCHEMA,
        "activationReady": False,
        "authority": {
            "environment": "staging",
            "civicAuthority": "none",
            "municipalPublication": False,
            "citizenVerification": False,
            "proposalMutation": False,
            "voteMutation": False,
            "treasuryMutation": False,
        },
        "repositories": {
            "operations": {
                "url": "https://github.com/GiraeffleAeffle/roebel-staging-operations.git",
                "protectedRef": "refs/heads/main",
                "fluxSource": _target(
                    "source.toolkit.fluxcd.io/v1",
                    "GitRepository",
                    FLUX_SOURCE_NAME,
                    FLUX_NAMESPACE,
                ),
            },
            "product": {
                "url": "https://github.com/GiraeffleAeffle/Roebel-App.git",
                "protectedRef": "refs/heads/main",
            },
        },
        "productPins": {
            "sourceRevision": None,
            "sourceTreeSha256": None,
            "imageRepository": "ghcr.io/giraeffleaeffle/roebel-staging-participant-gateway",
            "imageManifestDigest": None,
            "workflowIdentity": (
                "https://github.com/GiraeffleAeffle/Roebel-App/"
                ".github/workflows/staging-participant-gateway-publish.yml@refs/heads/main"
            ),
            "workflowSha256": None,
            "migration": {
                "path": "supabase/migrations/20260825_staging_participant_gateway.sql",
                "sha256": None,
            },
            "databaseSchemaSha256": None,
            "deactivation": {
                "path": "supabase/staging_participant_gateway_deactivate.sql",
                "sha256": None,
            },
        },
        "endpoints": {
            "browserOrigin": "https://roebel-web.staging.agentcart.eu",
            "gnosis": {
                "httpsOrigin": "https://rpc.gnosischain.com",
                "chainId": 100,
                "port": 443,
                "ipv4Cidrs": ["34.111.230.52/32"],
            },
            "supabase": {
                "httpsOrigin": "https://vdlksxpihmoumebjpeix.supabase.co",
                "projectRef": "vdlksxpihmoumebjpeix",
                "port": 443,
                "ipv4Cidrs": [],
            },
            "workbench": {
                "url": (
                    "http://e2e-workbench.stadtstack-roebel-staging-lab."
                    "svc.cluster.local:18083/"
                ),
                "service": _target("v1", "Service", WORKBENCH_NAME, WORKBENCH_NAMESPACE),
                "port": WORKBENCH_PORT,
                "admissionHeader": {"name": "x-stadtstack-e2e", "value": "1"},
            },
        },
        "httpBoundary": {
            "host": "roebel-web.staging.agentcart.eu",
            "prefix": "/api/staging-participant/v1",
            "routes": [
                {"path": ROUTES[0], "methods": ["GET", "OPTIONS"]},
                *[{"path": path, "methods": ["POST", "OPTIONS"]} for path in POST_ROUTES],
            ],
            "expectations": [
                {"method": "GET", "path": ROUTES[0], "status": 200},
                *[{"method": "OPTIONS", "path": path, "status": 204} for path in ROUTES],
                {"method": "POST", "path": ROUTES[0], "status": 405},
                *[{"method": "GET", "path": path, "status": 405} for path in POST_ROUTES],
                {"method": "HEAD", "path": ROUTES[0], "status": 405},
                {"method": "DELETE", "path": ROUTES[0], "status": 405},
            ],
            "haproxyRateLimit": {
                "requests": 30,
                "windowSeconds": 60,
                "key": "source-ip",
                "scope": "per-controller-replica",
                "sharedAcrossReplicas": False,
                "aggregateClaimAllowed": False,
            },
            "timeoutsSeconds": {
                "kubernetesRequest": 10,
                "routeRequest": 10,
                "routeMatrixTotal": 120,
                "deploymentRollout": 120,
                "fluxReady": 120,
                "rollback": 120,
            },
        },
        "runtime": {
            "replicas": 1,
            "deploymentStrategy": "Recreate",
            "serviceAccountToken": False,
            "containerPort": GATEWAY_PORT,
            "secretReferences": {
                "config": {
                    "name": "roebel-staging-participant-gateway-config",
                    "namespace": GATEWAY_NAMESPACE,
                    "keys": ["allowed-wallets", "invite-sha256", "mecky-pubkey"],
                },
                "runtime": {
                    "name": "roebel-staging-participant-gateway-runtime",
                    "namespace": GATEWAY_NAMESPACE,
                    "keys": ["session-key", "supabase-anon-key", "supabase-rpc-secret"],
                },
            },
        },
        "render": {
            "gateway": {
                "root": GATEWAY_ROOT,
                "files": list(GATEWAY_RENDER_FILES),
                "objects": [
                    _target("networking.k8s.io/v1", "NetworkPolicy", GATEWAY_NAME, GATEWAY_NAMESPACE),
                    _target("v1", "ServiceAccount", GATEWAY_NAME, GATEWAY_NAMESPACE),
                    _target("v1", "Service", GATEWAY_NAME, GATEWAY_NAMESPACE),
                    _target("apps/v1", "Deployment", GATEWAY_NAME, GATEWAY_NAMESPACE),
                    _target("networking.k8s.io/v1", "Ingress", GATEWAY_NAME, GATEWAY_NAMESPACE),
                ],
            },
            "workbenchIngress": {
                "root": WORKBENCH_INGRESS_ROOT,
                "files": list(WORKBENCH_INGRESS_RENDER_FILES),
                "objects": [
                    _target(
                        "networking.k8s.io/v1",
                        "NetworkPolicy",
                        WORKBENCH_INGRESS_POLICY_NAME,
                        WORKBENCH_NAMESPACE,
                    ),
                ],
            },
            "createOrder": [
                "gateway.networkPolicy",
                "workbenchIngress.networkPolicy",
                "gateway.serviceAccount",
                "gateway.service",
                "gateway.deployment",
                "gateway.ingress-after-health",
            ],
        },
        "gitOps": {
            "sharedSourceOwnership": "read-only-never-adopted",
            "reconcilers": {
                "gateway": {
                    "kustomization": _target(
                        "kustomize.toolkit.fluxcd.io/v1",
                        "Kustomization",
                        GATEWAY_NAME,
                        FLUX_NAMESPACE,
                    ),
                    "serviceAccount": _target("v1", "ServiceAccount", gateway_reconciler, FLUX_NAMESPACE),
                    "role": _target("rbac.authorization.k8s.io/v1", "Role", gateway_reconciler, GATEWAY_NAMESPACE),
                    "roleBinding": _target("rbac.authorization.k8s.io/v1", "RoleBinding", gateway_reconciler, GATEWAY_NAMESPACE),
                    "path": f"./{GATEWAY_ROOT}",
                    "targetNamespace": GATEWAY_NAMESPACE,
                    "resourceNames": [GATEWAY_NAME],
                },
                "workbenchIngress": {
                    "kustomization": _target(
                        "kustomize.toolkit.fluxcd.io/v1",
                        "Kustomization",
                        WORKBENCH_INGRESS_POLICY_NAME,
                        FLUX_NAMESPACE,
                    ),
                    "serviceAccount": _target("v1", "ServiceAccount", workbench_reconciler, FLUX_NAMESPACE),
                    "role": _target("rbac.authorization.k8s.io/v1", "Role", workbench_reconciler, WORKBENCH_NAMESPACE),
                    "roleBinding": _target("rbac.authorization.k8s.io/v1", "RoleBinding", workbench_reconciler, WORKBENCH_NAMESPACE),
                    "path": f"./{WORKBENCH_INGRESS_ROOT}",
                    "targetNamespace": WORKBENCH_NAMESPACE,
                    "resourceNames": [WORKBENCH_INGRESS_POLICY_NAME],
                },
            },
            "activationTransaction": {
                "initialState": "both-suspended",
                "unsuspend": "compare-and-swap-both-or-rollback",
                "failureState": "both-suspended",
                "prune": False,
                "force": False,
                "deletionPolicy": "Orphan",
                "adoption": "forbidden",
                "createOutcomes": {
                    "http-201-created": {
                        "discoveryAllowed": False,
                        "ownedByTransaction": True,
                    },
                    "http-409-already-exists": {
                        "discoveryAllowed": False,
                        "hardFailure": True,
                        "ownedByTransaction": False,
                    },
                    "transport-uncertain-after-send": {
                        "discoveryAllowed": True,
                        "exactSemanticMatchRequired": True,
                        "uidResourceVersionReceiptRequired": True,
                        "ownedByTransaction": True,
                        "rollbackRequired": True,
                    },
                },
            },
        },
        "network": {
            "gatewayPodSelector": GATEWAY_LABELS,
            "workbenchPodSelector": WORKBENCH_SELECTOR,
            "gatewayIngressNamespaceSelector": {
                "kubernetes.io/metadata.name": "ingress-system",
            },
            "dnsPodSelector": {"k8s-app": "kube-dns"},
            "dnsNamespaceSelector": {"kubernetes.io/metadata.name": "kube-system"},
            "reciprocalPort": WORKBENCH_PORT,
            "conflictScan": {
                "families": [
                    "networking.k8s.io/NetworkPolicy",
                    "cilium.io/CiliumNetworkPolicy",
                    "cilium.io/CiliumClusterwideNetworkPolicy",
                ],
                "scope": "fresh-runner-selector-overlap-scan",
                "staticInventoryHashes": False,
            },
        },
        "preservation": {
            "webIngress": {
                "target": _target(
                    "networking.k8s.io/v1",
                    "Ingress",
                    "roebel-web-presentation",
                    GATEWAY_NAMESPACE,
                ),
                "mutation": "forbidden",
                "adoption": "forbidden",
                "prePostByteEqualityRequired": True,
            },
            "existingWorkbenchNetworkPolicy": {
                "target": _target(
                    "networking.k8s.io/v1",
                    "NetworkPolicy",
                    WORKBENCH_NAME,
                    WORKBENCH_NAMESPACE,
                ),
                "mutation": "forbidden",
                "adoption": "forbidden",
                "prePostByteEqualityRequired": True,
            },
        },
        "rollback": {
            "firstStep": "delete-exact-owned-participant-ingress-uid",
            "secondStep": "cas-suspend-both-participant-kustomizations",
            "applicationObjects": "delete-only-exact-transaction-owned-uids-in-reverse-create-order",
            "database": "run-only-policy-pinned-deactivation-after-schema-binding",
            "preserve": [
                "shared-flux-source",
                "web-ingress",
                "existing-workbench-network-policy",
                "secrets",
                "unrelated-network-policy-families",
            ],
            "requiredPostconditions": [
                "both-participant-kustomizations-suspended",
                "all-transaction-owned-objects-absent-or-restored",
                "web-ingress-byte-identical",
                "existing-workbench-network-policy-byte-identical",
                "no-civic-authority-effects",
            ],
        },
        "trustedFactsReceiptSchemaVersion": TRUSTED_LIVE_FACTS_SCHEMA,
    }


STATIC_ACTIVATION_POLICY = _static_descriptor()


def activation_policy_descriptor() -> dict[str, Any]:
    """Return a defensive copy of the exact protected static descriptor."""
    return copy.deepcopy(STATIC_ACTIVATION_POLICY)


def activation_policy_sha256(policy: dict[str, Any] | None = None) -> str:
    return canonical_sha256(STATIC_ACTIVATION_POLICY if policy is None else policy)


def activation_blockers(policy: dict[str, Any] | None = None) -> tuple[str, ...]:
    """Return every intentionally unfilled immutable activation slot."""
    value = STATIC_ACTIVATION_POLICY if policy is None else policy
    pins = value["productPins"]
    slots = {
        "productPins.sourceRevision": pins["sourceRevision"],
        "productPins.sourceTreeSha256": pins["sourceTreeSha256"],
        "productPins.imageManifestDigest": pins["imageManifestDigest"],
        "productPins.workflowSha256": pins["workflowSha256"],
        "productPins.migration.sha256": pins["migration"]["sha256"],
        "productPins.databaseSchemaSha256": pins["databaseSchemaSha256"],
        "productPins.deactivation.sha256": pins["deactivation"]["sha256"],
    }
    blockers = [name for name, slot in slots.items() if slot is None]
    for endpoint in ("gnosis", "supabase"):
        if not value["endpoints"][endpoint]["ipv4Cidrs"]:
            blockers.append(f"endpoints.{endpoint}.ipv4Cidrs")
    return tuple(blockers)


def expected_runtime_pin(policy: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the deterministic render pin; it never carries live evidence."""
    value = assert_activation_ready(policy)
    pins = value["productPins"]
    return {
        "schemaVersion": "roebel_staging_participant_gateway_runtime_pin_v2",
        "component": "staging-participant-gateway",
        "sourceRevision": pins["sourceRevision"],
        "sourceTreeSha256": pins["sourceTreeSha256"],
        "imageRepository": pins["imageRepository"],
        "manifestDigest": pins["imageManifestDigest"],
        "workflowIdentity": pins["workflowIdentity"],
        "workflowSha256": pins["workflowSha256"],
        "migrationSha256": pins["migration"]["sha256"],
        "databaseSchemaSha256": pins["databaseSchemaSha256"],
        "deactivationSha256": pins["deactivation"]["sha256"],
        "activationPolicySha256": activation_policy_sha256(value),
    }


def validate_activation_policy(value: Any) -> dict[str, Any]:
    _require(isinstance(value, dict), "participant activation policy must be an object")
    _require(value == STATIC_ACTIVATION_POLICY, "participant activation policy drift")
    blockers = activation_blockers(value)
    _require(
        value["activationReady"] is (len(blockers) == 0),
        "participant activationReady does not match immutable slots",
    )
    _validate_static_semantics(value)
    return copy.deepcopy(value)


def assert_activation_ready(policy: dict[str, Any] | None = None) -> dict[str, Any]:
    value = validate_activation_policy(STATIC_ACTIVATION_POLICY if policy is None else policy)
    blockers = activation_blockers(value)
    _require(not blockers and value["activationReady"] is True, "participant activation blocked: protected product, database and endpoint pins are incomplete")
    return value


def _validate_static_semantics(value: dict[str, Any]) -> None:
    pins = value["productPins"]
    _require(
        value["authority"] == {
            "environment": "staging",
            "civicAuthority": "none",
            "municipalPublication": False,
            "citizenVerification": False,
            "proposalMutation": False,
            "voteMutation": False,
            "treasuryMutation": False,
        },
        "participant authority boundary drift",
    )
    _require(
        value["repositories"] == {
            "operations": {
                "url": "https://github.com/GiraeffleAeffle/roebel-staging-operations.git",
                "protectedRef": "refs/heads/main",
                "fluxSource": _target(
                    "source.toolkit.fluxcd.io/v1",
                    "GitRepository",
                    FLUX_SOURCE_NAME,
                    FLUX_NAMESPACE,
                ),
            },
            "product": {
                "url": "https://github.com/GiraeffleAeffle/Roebel-App.git",
                "protectedRef": "refs/heads/main",
            },
        },
        "participant repository/ref boundary drift",
    )
    _require(
        pins["imageRepository"]
        == "ghcr.io/giraeffleaeffle/roebel-staging-participant-gateway"
        and pins["workflowIdentity"]
        == (
            "https://github.com/GiraeffleAeffle/Roebel-App/"
            ".github/workflows/staging-participant-gateway-publish.yml@refs/heads/main"
        )
        and pins["migration"]["path"]
        == "supabase/migrations/20260825_staging_participant_gateway.sql"
        and pins["deactivation"]["path"]
        == "supabase/staging_participant_gateway_deactivate.sql",
        "participant product publication/database identity drift",
    )
    for key in ("sourceTreeSha256", "imageManifestDigest", "workflowSha256", "databaseSchemaSha256"):
        slot = pins[key]
        _require(slot is None or bool(SHA256.fullmatch(slot)), f"participant {key} invalid")
    _require(pins["sourceRevision"] is None or bool(REVISION.fullmatch(pins["sourceRevision"])), "participant sourceRevision invalid")
    for nested in (pins["migration"], pins["deactivation"]):
        _require(nested["sha256"] is None or bool(SHA256.fullmatch(nested["sha256"])), "participant SQL hash invalid")
    _require([route["path"] for route in value["httpBoundary"]["routes"]] == list(ROUTES), "participant route order drift")
    _require(len(value["httpBoundary"]["routes"]) == 6, "participant gateway must expose exactly six routes")
    _require(
        value["httpBoundary"]["host"] == "roebel-web.staging.agentcart.eu"
        and value["httpBoundary"]["prefix"] == "/api/staging-participant/v1"
        and value["httpBoundary"]["routes"][0]["methods"] == ["GET", "OPTIONS"]
        and all(route["methods"] == ["POST", "OPTIONS"] for route in value["httpBoundary"]["routes"][1:]),
        "participant method/path boundary drift",
    )
    rate = value["httpBoundary"]["haproxyRateLimit"]
    _require(rate == {
        "requests": 30,
        "windowSeconds": 60,
        "key": "source-ip",
        "scope": "per-controller-replica",
        "sharedAcrossReplicas": False,
        "aggregateClaimAllowed": False,
    }, "participant HAProxy rate-limit truth drift")
    for endpoint_name in ("gnosis", "supabase"):
        for cidr in value["endpoints"][endpoint_name]["ipv4Cidrs"]:
            network = ipaddress.ip_network(cidr, strict=True)
            _require(network.version == 4 and network.prefixlen == 32, "participant endpoint CIDR must be IPv4 /32")
    endpoints = value["endpoints"]
    _require(
        endpoints["browserOrigin"] == "https://roebel-web.staging.agentcart.eu"
        and endpoints["gnosis"]["httpsOrigin"] == "https://rpc.gnosischain.com"
        and endpoints["gnosis"]["chainId"] == 100
        and endpoints["gnosis"]["port"] == 443
        and endpoints["supabase"]["httpsOrigin"]
        == "https://vdlksxpihmoumebjpeix.supabase.co"
        and endpoints["supabase"]["projectRef"] == "vdlksxpihmoumebjpeix"
        and endpoints["supabase"]["port"] == 443
        and endpoints["workbench"]["url"]
        == "http://e2e-workbench.stadtstack-roebel-staging-lab.svc.cluster.local:18083/"
        and endpoints["workbench"]["service"]
        == _target("v1", "Service", WORKBENCH_NAME, WORKBENCH_NAMESPACE)
        and endpoints["workbench"]["port"] == WORKBENCH_PORT
        and endpoints["workbench"]["admissionHeader"]
        == {"name": "x-stadtstack-e2e", "value": "1"},
        "participant endpoint identity drift",
    )
    _require(
        value["runtime"]["secretReferences"]["config"]["name"]
        == "roebel-staging-participant-gateway-config"
        and value["runtime"]["secretReferences"]["config"]["namespace"]
        == GATEWAY_NAMESPACE
        and value["runtime"]["secretReferences"]["runtime"]["name"]
        == "roebel-staging-participant-gateway-runtime"
        and value["runtime"]["secretReferences"]["runtime"]["namespace"]
        == GATEWAY_NAMESPACE,
        "participant Secret identity drift",
    )
    _require(
        value["runtime"]["secretReferences"]["config"]["keys"]
        == ["allowed-wallets", "invite-sha256", "mecky-pubkey"],
        "participant config Secret keyset drift",
    )
    _require(
        value["runtime"]["secretReferences"]["runtime"]["keys"]
        == ["session-key", "supabase-anon-key", "supabase-rpc-secret"],
        "participant runtime Secret keyset drift",
    )
    _require(
        tuple(value["render"]["gateway"]["files"]) == GATEWAY_RENDER_FILES
        and tuple(value["render"]["workbenchIngress"]["files"]) == WORKBENCH_INGRESS_RENDER_FILES,
        "participant render inventory drift",
    )
    reconcilers = value["gitOps"]["reconcilers"]
    _require(
        set(reconcilers) == {"gateway", "workbenchIngress"}
        and reconcilers["gateway"]["path"] == f"./{GATEWAY_ROOT}"
        and reconcilers["gateway"]["targetNamespace"] == GATEWAY_NAMESPACE
        and reconcilers["workbenchIngress"]["path"] == f"./{WORKBENCH_INGRESS_ROOT}"
        and reconcilers["workbenchIngress"]["targetNamespace"] == WORKBENCH_NAMESPACE,
        "participant Flux ownership boundary drift",
    )
    _require(
        value["network"]["gatewayPodSelector"] == GATEWAY_LABELS
        and value["network"]["workbenchPodSelector"] == WORKBENCH_SELECTOR
        and value["network"]["conflictScan"] == {
            "families": [
                "networking.k8s.io/NetworkPolicy",
                "cilium.io/CiliumNetworkPolicy",
                "cilium.io/CiliumClusterwideNetworkPolicy",
            ],
            "scope": "fresh-runner-selector-overlap-scan",
            "staticInventoryHashes": False,
        },
        "participant additive policy conflict-scan boundary drift",
    )
    _require(value["preservation"]["webIngress"]["mutation"] == "forbidden", "Web Ingress mutation permitted")
    _require(value["preservation"]["existingWorkbenchNetworkPolicy"]["adoption"] == "forbidden", "existing workbench policy adoption permitted")
    outcomes = value["gitOps"]["activationTransaction"]["createOutcomes"]
    _require(
        outcomes["http-409-already-exists"]
        == {"discoveryAllowed": False, "hardFailure": True, "ownedByTransaction": False},
        "participant definite 409 must fail without adoption",
    )
    uncertain = outcomes["transport-uncertain-after-send"]
    _require(
        uncertain["discoveryAllowed"] is True
        and uncertain["exactSemanticMatchRequired"] is True
        and uncertain["uidResourceVersionReceiptRequired"] is True
        and uncertain["rollbackRequired"] is True,
        "participant uncertain-create recovery boundary drift",
    )


def gateway_flux_objects(*, suspended: bool = True) -> dict[str, dict[str, Any]]:
    return _flux_objects("gateway", suspended=suspended)


def workbench_ingress_flux_objects(*, suspended: bool = True) -> dict[str, dict[str, Any]]:
    return _flux_objects("workbenchIngress", suspended=suspended)


def _flux_objects(owner: str, *, suspended: bool) -> dict[str, dict[str, Any]]:
    policy = validate_activation_policy(STATIC_ACTIVATION_POLICY)
    item = policy["gitOps"]["reconcilers"][owner]
    target_namespace = item["targetNamespace"]
    sa_name = item["serviceAccount"]["name"]
    labels = {
        "app.kubernetes.io/part-of": "stadtstack",
        "stadtstack.io/authority": "none",
        "stadtstack.io/civic-authority": "none",
        "stadtstack.io/environment": "staging",
        "stadtstack.io/flux-tenant": "roebel-staging",
        "stadtstack.io/gitops-owner": "participant-gateway" if owner == "gateway" else "participant-workbench-ingress",
    }
    if owner == "gateway":
        rules = [
            {"apiGroups": [""], "resourceNames": [GATEWAY_NAME], "resources": ["serviceaccounts", "services"], "verbs": ["get", "patch", "update"]},
            {"apiGroups": ["apps"], "resourceNames": [GATEWAY_NAME], "resources": ["deployments"], "verbs": ["get", "patch", "update"]},
            {"apiGroups": ["networking.k8s.io"], "resourceNames": [GATEWAY_NAME], "resources": ["networkpolicies", "ingresses"], "verbs": ["get", "patch", "update"]},
        ]
        health_checks = [{"apiVersion": "apps/v1", "kind": "Deployment", "name": GATEWAY_NAME, "namespace": GATEWAY_NAMESPACE}]
    else:
        rules = [
            {"apiGroups": ["networking.k8s.io"], "resourceNames": [WORKBENCH_INGRESS_POLICY_NAME], "resources": ["networkpolicies"], "verbs": ["get", "patch", "update"]},
        ]
        health_checks = []
    service_account = {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {"labels": labels, "name": sa_name, "namespace": FLUX_NAMESPACE},
        "automountServiceAccountToken": False,
    }
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"labels": labels, "name": item["role"]["name"], "namespace": target_namespace},
        "rules": rules,
    }
    role_binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {"labels": labels, "name": item["roleBinding"]["name"], "namespace": target_namespace},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": item["role"]["name"]},
        "subjects": [{"kind": "ServiceAccount", "name": sa_name, "namespace": FLUX_NAMESPACE}],
    }
    kustomization = {
        "apiVersion": "kustomize.toolkit.fluxcd.io/v1",
        "kind": "Kustomization",
        "metadata": {"labels": labels, "name": item["kustomization"]["name"], "namespace": FLUX_NAMESPACE},
        "spec": {
            "deletionPolicy": "Orphan",
            "dependsOn": [],
            "force": False,
            "healthChecks": health_checks,
            "interval": "5m",
            "path": item["path"],
            "prune": False,
            "retryInterval": "30s",
            "serviceAccountName": sa_name,
            "sourceRef": {"kind": "GitRepository", "name": FLUX_SOURCE_NAME, "namespace": FLUX_NAMESPACE},
            "suspend": suspended,
            "targetNamespace": target_namespace,
            "timeout": "2m",
            "wait": True,
        },
    }
    return {
        "kustomization": kustomization,
        "serviceAccount": service_account,
        "role": role,
        "roleBinding": role_binding,
    }


def expected_workbench_ingress_network_policy() -> dict[str, Any]:
    validate_activation_policy(STATIC_ACTIVATION_POLICY)
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "labels": WORKBENCH_INGRESS_POLICY_LABELS,
            "name": WORKBENCH_INGRESS_POLICY_NAME,
            "namespace": WORKBENCH_NAMESPACE,
        },
        "spec": {
            "ingress": [{
                "from": [{
                    "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": GATEWAY_NAMESPACE}},
                    "podSelector": {"matchLabels": GATEWAY_LABELS},
                }],
                "ports": [{"port": WORKBENCH_PORT, "protocol": "TCP"}],
            }],
            "podSelector": {"matchLabels": WORKBENCH_SELECTOR},
            "policyTypes": ["Ingress"],
        },
    }


def expected_shared_flux_source_projection() -> dict[str, Any]:
    """The participant transaction observes, but never owns, this source."""
    return {
        "apiVersion": "source.toolkit.fluxcd.io/v1",
        "kind": "GitRepository",
        "metadata": {
            "labels": {"stadtstack.io/flux-tenant": "roebel-staging"},
            "name": FLUX_SOURCE_NAME,
            "namespace": FLUX_NAMESPACE,
        },
        "spec": {
            "interval": "1m",
            "ref": {"branch": "main"},
            "suspend": False,
            "timeout": "30s",
            "url": "https://github.com/GiraeffleAeffle/roebel-staging-operations.git",
        },
    }


def _secret_env(name: str, reference: dict[str, Any], key: str) -> dict[str, Any]:
    return {
        "name": name,
        "valueFrom": {
            "secretKeyRef": {
                "key": key,
                "name": reference["name"],
                "optional": False,
            },
        },
    }


def expected_gateway_ingress(policy: dict[str, Any] | None = None) -> dict[str, Any]:
    value = assert_activation_ready(policy)
    boundary = value["httpBoundary"]
    paths = [route["path"] for route in boundary["routes"]]
    post_paths = [route["path"] for route in boundary["routes"] if "POST" in route["methods"]]
    early = "\n".join([
        "http-request deny deny_status 405 if { method POST } "
        + " ".join(f"!{{ path {path} }}" for path in post_paths),
        "http-request deny deny_status 405 if { method OPTIONS } "
        + " ".join(f"!{{ path {path} }}" for path in paths),
        "http-request deny deny_status 405 if { method HEAD }",
        f"http-request deny deny_status 405 if {{ method GET }} !{{ path {paths[0]} }}",
        "http-request deny deny_status 405 unless { method GET HEAD POST OPTIONS }",
        "http-request deny deny_status 404 "
        + " ".join(f"!{{ path {path} }}" for path in paths),
        "stick-table type ip size 10k expire 60s store http_req_rate(1m)",
        "http-request track-sc0 src",
        "http-request deny deny_status 429 if { sc_http_req_rate(0) gt 30 }",
    ])
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {
            "annotations": {"haproxy-ingress.github.io/config-backend-early": early},
            "labels": GATEWAY_LABELS,
            "name": GATEWAY_NAME,
            "namespace": GATEWAY_NAMESPACE,
        },
        "spec": {
            "ingressClassName": "haproxy",
            "rules": [{
                "host": boundary["host"],
                "http": {"paths": [{
                    "backend": {"service": {"name": GATEWAY_NAME, "port": {"name": "http"}}},
                    "path": boundary["prefix"],
                    "pathType": "Prefix",
                }]},
            }],
            "tls": [{
                "hosts": [boundary["host"]],
                "secretName": "roebel-web-presentation-tls",
            }],
        },
    }


def expected_gateway_resources(policy: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build the exact two-path render from protected policy only."""
    value = assert_activation_ready(policy)
    runtime_pin = expected_runtime_pin(value)
    endpoints = value["endpoints"]
    refs = value["runtime"]["secretReferences"]
    pod_security = {
        "fsGroup": 65532,
        "runAsGroup": 65532,
        "runAsNonRoot": True,
        "runAsUser": 65532,
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    container_security = {
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
        "readOnlyRootFilesystem": True,
    }

    def tcp_probe(threshold: int, period: int) -> dict[str, Any]:
        return {
            "failureThreshold": threshold,
            "periodSeconds": period,
            "successThreshold": 1,
            "tcpSocket": {"port": "http"},
            "timeoutSeconds": 3,
        }

    environment = [
        {"name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY", "value": "enabled"},
        {"name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_HOST", "value": "0.0.0.0"},
        {"name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_PORT", "value": str(GATEWAY_PORT)},
        {"name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_ORIGIN", "value": endpoints["browserOrigin"]},
        _secret_env("ROEBEL_STAGING_PARTICIPANT_GATEWAY_INVITE_SHA256", refs["config"], "invite-sha256"),
        _secret_env("ROEBEL_STAGING_PARTICIPANT_GATEWAY_ALLOWED_WALLETS", refs["config"], "allowed-wallets"),
        _secret_env("ROEBEL_STAGING_PARTICIPANT_GATEWAY_SESSION_KEY", refs["runtime"], "session-key"),
        {"name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_GNOSIS_RPC_URL", "value": endpoints["gnosis"]["httpsOrigin"]},
        {"name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_SUPABASE_URL", "value": endpoints["supabase"]["httpsOrigin"]},
        _secret_env("ROEBEL_STAGING_PARTICIPANT_GATEWAY_SUPABASE_ANON_KEY", refs["runtime"], "supabase-anon-key"),
        _secret_env("ROEBEL_STAGING_PARTICIPANT_GATEWAY_SUPABASE_RPC_SECRET", refs["runtime"], "supabase-rpc-secret"),
        _secret_env("ROEBEL_STAGING_PARTICIPANT_GATEWAY_MECKY_PUBKEY", refs["config"], "mecky-pubkey"),
        {"name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_PRIVATE_WORKBENCH_URL", "value": endpoints["workbench"]["url"]},
        {
            "name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_PRIVATE_WORKBENCH_ADMISSION_HEADER",
            "value": (
                endpoints["workbench"]["admissionHeader"]["name"]
                + ":"
                + endpoints["workbench"]["admissionHeader"]["value"]
            ),
        },
        {
            "name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_SOURCE_REVISION",
            "value": value["productPins"]["sourceRevision"],
        },
        {
            "name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_MANIFEST_DIGEST",
            "value": value["productPins"]["imageManifestDigest"],
        },
        {
            "name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_MIGRATION_SHA256",
            "value": value["productPins"]["migration"]["sha256"],
        },
        {
            "name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_DATABASE_SCHEMA_SHA256",
            "value": value["productPins"]["databaseSchemaSha256"],
        },
    ]
    deployment = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"labels": GATEWAY_LABELS, "name": GATEWAY_NAME, "namespace": GATEWAY_NAMESPACE},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": GATEWAY_LABELS},
            "strategy": {"type": "Recreate"},
            "template": {
                "metadata": {"labels": GATEWAY_LABELS},
                "spec": {
                    "automountServiceAccountToken": False,
                    "restartPolicy": "Always",
                    "serviceAccountName": GATEWAY_NAME,
                    "securityContext": pod_security,
                    "volumes": [{"emptyDir": {"sizeLimit": "64Mi"}, "name": "tmp"}],
                    "containers": [{
                        "env": environment,
                        "image": runtime_pin["imageRepository"] + "@" + runtime_pin["manifestDigest"],
                        "imagePullPolicy": "IfNotPresent",
                        "name": "staging-participant-gateway",
                        "ports": [{"containerPort": GATEWAY_PORT, "name": "http", "protocol": "TCP"}],
                        "readinessProbe": tcp_probe(3, 10),
                        "livenessProbe": tcp_probe(3, 20),
                        "startupProbe": tcp_probe(30, 2),
                        "resources": {
                            "limits": {"cpu": "200m", "memory": "128Mi"},
                            "requests": {"cpu": "50m", "memory": "64Mi"},
                        },
                        "securityContext": container_security,
                        "volumeMounts": [{"mountPath": "/tmp", "name": "tmp"}],
                    }],
                },
            },
        },
    }
    service = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"labels": GATEWAY_LABELS, "name": GATEWAY_NAME, "namespace": GATEWAY_NAMESPACE},
        "spec": {
            "ports": [{"name": "http", "port": GATEWAY_PORT, "protocol": "TCP", "targetPort": "http"}],
            "selector": GATEWAY_LABELS,
            "type": "ClusterIP",
        },
    }
    network_policy = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"labels": GATEWAY_LABELS, "name": GATEWAY_NAME, "namespace": GATEWAY_NAMESPACE},
        "spec": {
            "podSelector": {"matchLabels": GATEWAY_LABELS},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [{
                "from": [{
                    "namespaceSelector": {"matchLabels": value["network"]["gatewayIngressNamespaceSelector"]},
                }],
                "ports": [{"port": GATEWAY_PORT, "protocol": "TCP"}],
            }],
            "egress": [
                {
                    "to": [{
                        "namespaceSelector": {"matchLabels": value["network"]["dnsNamespaceSelector"]},
                        "podSelector": {"matchLabels": value["network"]["dnsPodSelector"]},
                    }],
                    "ports": [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}],
                },
                *[
                    {"to": [{"ipBlock": {"cidr": cidr}}], "ports": [{"port": 443, "protocol": "TCP"}]}
                    for endpoint in (endpoints["gnosis"], endpoints["supabase"])
                    for cidr in endpoint["ipv4Cidrs"]
                ],
                {
                    "to": [{
                        "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": WORKBENCH_NAMESPACE}},
                        "podSelector": {"matchLabels": WORKBENCH_SELECTOR},
                    }],
                    "ports": [{"port": WORKBENCH_PORT, "protocol": "TCP"}],
                },
            ],
        },
    }
    service_account = {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {"labels": GATEWAY_LABELS, "name": GATEWAY_NAME, "namespace": GATEWAY_NAMESPACE},
        "automountServiceAccountToken": False,
    }
    gateway_kustomization = (
        "apiVersion: kustomize.config.k8s.io/v1beta1\n"
        "kind: Kustomization\n"
        "resources:\n"
        "  - networkpolicy.json\n"
        "  - serviceaccount.json\n"
        "  - service.json\n"
        "  - deployment.json\n"
        "  - ingress.json\n"
    )
    return {
        "runtimePin": runtime_pin,
        "networkPolicy": network_policy,
        "serviceAccount": service_account,
        "service": service,
        "deployment": deployment,
        "ingress": expected_gateway_ingress(value),
        "kustomization": gateway_kustomization,
        "workbenchIngressNetworkPolicy": expected_workbench_ingress_network_policy(),
        "workbenchIngressKustomization": (
            "apiVersion: kustomize.config.k8s.io/v1beta1\n"
            "kind: Kustomization\n"
            "resources:\n"
            "  - networkpolicy.json\n"
        ),
    }


def trusted_live_facts_contract() -> dict[str, Any]:
    """Describe runner-owned facts without placing any fact in static policy."""
    return {
        "schemaVersion": TRUSTED_LIVE_FACTS_SCHEMA,
        "authority": "protected-local-runner-only",
        "transport": "out-of-band-receipt",
        "maximumAgeSeconds": 300,
        "policyBinding": activation_policy_sha256(),
        "requiredSections": [
            "clusterBinding",
            "protectedRevision",
            "publication",
            "database",
            "endpoints",
            "secretMaterialization",
            "networkPolicyConflictScan",
            "objectCreateResults",
            "semanticObjects",
            "haproxy",
            "routeMatrix",
            "fluxTransaction",
            "preservation",
            "rollback",
        ],
        "forbiddenInStaticPolicy": [
            "uid",
            "resourceVersion",
            "observedAt",
            "validUntil",
            "liveObject",
            "controllerStatus",
            "dnsAnswers",
            "tlsCertificate",
        ],
        "semanticComparison": {
            "normalizer": "normalize_kubernetes_object_v1",
            "comparison": "exact-after-known-server-default-removal",
            "fullLiveObjectHashAsAuthority": False,
        },
    }


def normalize_kubernetes_object(value: Any) -> dict[str, Any]:
    """Remove only server identity/status and documented Kubernetes defaults.

    Security-relevant fields are retained, so adding an ingress source, egress
    destination, RBAC verb, environment value or container privilege remains a
    semantic mismatch.  The result deliberately excludes UID/RV/status and can
    therefore be compared across fresh API reads without policy self-approval.
    """
    _require(isinstance(value, dict), "Kubernetes object must be an object")
    result = copy.deepcopy(value)
    metadata = result.get("metadata")
    _require(isinstance(metadata, dict), "Kubernetes object metadata missing")
    for key in ("creationTimestamp", "generation", "managedFields", "resourceVersion", "selfLink", "uid"):
        metadata.pop(key, None)
    annotations = metadata.get("annotations")
    if isinstance(annotations, dict):
        annotations.pop("kubectl.kubernetes.io/last-applied-configuration", None)
        if not annotations:
            metadata.pop("annotations", None)
    result.pop("status", None)

    kind = result.get("kind")
    # Flux adds this one controller finalizer even to suspended source and
    # Kustomization objects. It is not caller intent and neither participant
    # rollback nor teardown owns these bootstrap identities. Unknown or extra
    # finalizers remain security-relevant and therefore remain in semantics.
    if kind in {"GitRepository", "Kustomization"} and metadata.get("finalizers") == ["finalizers.fluxcd.io"]:
        metadata.pop("finalizers")
    spec = result.get("spec")
    if isinstance(spec, dict) and kind == "Service":
        for key in (
            "allocateLoadBalancerNodePorts", "clusterIP", "clusterIPs", "healthCheckNodePort",
            "internalTrafficPolicy", "ipFamilies", "ipFamilyPolicy", "sessionAffinity",
            "sessionAffinityConfig", "trafficDistribution",
        ):
            spec.pop(key, None)
        for port in spec.get("ports", []):
            if isinstance(port, dict):
                port.pop("nodePort", None)
    if isinstance(spec, dict) and kind == "Deployment":
        if spec.get("paused") is False:
            spec.pop("paused")
        if spec.get("progressDeadlineSeconds") == 600:
            spec.pop("progressDeadlineSeconds")
        if spec.get("revisionHistoryLimit") == 10:
            spec.pop("revisionHistoryLimit")
        template_spec = spec.get("template", {}).get("spec", {})
        if isinstance(template_spec, dict):
            defaults = {
                "dnsPolicy": "ClusterFirst",
                "enableServiceLinks": True,
                "restartPolicy": "Always",
                "schedulerName": "default-scheduler",
                "terminationGracePeriodSeconds": 30,
            }
            for key, default in defaults.items():
                if template_spec.get(key) == default:
                    template_spec.pop(key)
            for container in template_spec.get("containers", []):
                if not isinstance(container, dict):
                    continue
                if container.get("terminationMessagePath") == "/dev/termination-log":
                    container.pop("terminationMessagePath")
                if container.get("terminationMessagePolicy") == "File":
                    container.pop("terminationMessagePolicy")
    if kind == "ServiceAccount":
        result.pop("secrets", None)
        if isinstance(spec, dict) and not spec:
            result.pop("spec", None)
    return result


def semantic_sha256(value: Any) -> str:
    return canonical_sha256(normalize_kubernetes_object(value))


def semantically_equal(live: Any, desired: Any) -> bool:
    return normalize_kubernetes_object(live) == normalize_kubernetes_object(desired)


def require_semantically_equal(live: Any, desired: Any, label: str) -> dict[str, Any]:
    normalized_live = normalize_kubernetes_object(live)
    normalized_desired = normalize_kubernetes_object(desired)
    _require(normalized_live == normalized_desired, f"{label} semantic drift")
    return normalized_live


def bind_create_result(
    *,
    outcome: str,
    observed: Any | None,
    desired: Any,
    label: str,
) -> dict[str, Any]:
    """Turn one trusted create result into a rollback-safe receipt projection.

    A definite conflict is never recoverable. A successful create and a
    transport-uncertain create both require the exact protected semantics plus
    a live UID/resourceVersion; only the latter represents discovery.
    """
    outcomes = validate_activation_policy(STATIC_ACTIVATION_POLICY)["gitOps"][
        "activationTransaction"
    ]["createOutcomes"]
    _require(outcome in outcomes, f"{label} create outcome invalid")
    if outcome == "http-409-already-exists":
        raise PolicyError(f"{label} create conflict: adoption forbidden")
    _require(observed is not None, f"{label} create result missing observed object")
    normalized = require_semantically_equal(observed, desired, label)
    metadata = observed.get("metadata")
    _require(isinstance(metadata, dict), f"{label} create metadata missing")
    uid = metadata.get("uid")
    resource_version = metadata.get("resourceVersion")
    _require(isinstance(uid, str) and bool(uid), f"{label} create UID missing")
    _require(
        isinstance(resource_version, str) and resource_version.isdigit(),
        f"{label} create resourceVersion invalid",
    )
    desired_metadata = normalized.get("metadata", {})
    return {
        "outcome": outcome,
        "discoveredAfterTransportUncertainty": outcome == "transport-uncertain-after-send",
        "target": {
            "apiVersion": normalized.get("apiVersion"),
            "kind": normalized.get("kind"),
            "name": desired_metadata.get("name"),
            "namespace": desired_metadata.get("namespace"),
        },
        "uid": uid,
        "resourceVersion": resource_version,
        "semanticSha256": canonical_sha256(normalized),
        "rollbackOwned": True,
    }


def validate_trusted_live_facts(value: Any, *, now: datetime | None = None) -> dict[str, Any]:
    """Validate the runner receipt envelope; section semantics stay runner-owned.

    This function intentionally cannot make an incomplete static policy ready.
    Once the protected slots are filled, it enforces a short validity window,
    exact policy binding and a closed section set.  Individual sections are
    compared to the static descriptor with the helpers above by the executor.
    """
    policy = assert_activation_ready()
    _require(isinstance(value, dict), "trusted live facts must be an object")
    contract = trusted_live_facts_contract()
    required = {
        "schemaVersion", "policySha256", "collectedAt", "validUntil", "maxAgeSeconds",
        *contract["requiredSections"],
    }
    _require(set(value) == required, "trusted live facts field set drift")
    _require(value["schemaVersion"] == TRUSTED_LIVE_FACTS_SCHEMA, "trusted live facts schema drift")
    _require(value["policySha256"] == activation_policy_sha256(policy), "trusted live facts policy binding drift")
    _require(value["maxAgeSeconds"] == 300, "trusted live facts freshness window drift")
    _require(isinstance(value["protectedRevision"], str) and bool(REVISION.fullmatch(value["protectedRevision"])), "trusted live facts revision invalid")
    collected = _utc(value["collectedAt"], "trusted live facts collectedAt")
    valid_until = _utc(value["validUntil"], "trusted live facts validUntil")
    _require(0 < (valid_until - collected).total_seconds() <= 300, "trusted live facts validity interval invalid")
    current = datetime.now(timezone.utc) if now is None else now
    _require(current.tzinfo is not None and current.utcoffset() is not None, "trusted live facts verification clock must be aware")
    current = current.astimezone(timezone.utc)
    _require(collected <= current <= valid_until, "trusted live facts are future-dated or expired")
    for section in contract["requiredSections"]:
        if section == "protectedRevision":
            continue
        _require(
            isinstance(value[section], (dict, list)) and bool(value[section]),
            f"trusted live facts {section} must be a non-empty structured receipt",
        )
    return copy.deepcopy(value)


def _utc(value: Any, label: str) -> datetime:
    _require(isinstance(value, str) and bool(RFC3339_UTC.fullmatch(value)), f"{label} must be RFC3339 UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise PolicyError(f"{label} invalid") from exc
