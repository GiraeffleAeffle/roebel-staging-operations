#!/usr/bin/env python3
"""Fail-closed verifier for the public Röbel staging reviewed render.

For pull requests this exact script is loaded from the protected base branch
and receives the candidate checkout only as data. The candidate therefore
cannot weaken its own admission policy.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
IMMUTABLE_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

HEAD_SCHEMA = "roebel_staging_release_set_head_v1"
RENDER_SCHEMA = "roebel_staging_reviewed_render_v1"
RENDER_ROOT = "reviewed-render/roebel-staging"
COMPONENT_ORDER = ("public-mecky", "roebel-web-staging")
COMPONENTS = {
    "public-mecky": {
        "directory": "public-mecky",
        "repository": "ghcr.io/giraeffleaeffle/public-mecky",
        "namespace": "stadtstack-roebel-staging-lab",
        "name": "public-mecky",
        "container": "public-mecky",
    },
    "roebel-web-staging": {
        "directory": "web",
        "repository": "ghcr.io/giraeffleaeffle/roebel-web-staging",
        "namespace": "stadtstack-roebel-web-preview",
        "name": "roebel-web-presentation",
        "container": "web",
    },
}

EXPECTED_FILES = {
    ".github/CODEOWNERS",
    ".github/workflows/automatic-promotion.yml",
    ".github/workflows/reviewed-render-admission.yml",
    ".gitignore",
    "LICENSE",
    "README.md",
    "policy/repository-contract.json",
    "scripts/render-release-set-promotion.py",
    "scripts/test_automatic_promotion_workflow.py",
    "scripts/test_render_release_set_promotion.py",
    "scripts/test_verify_reviewed_render.py",
    "scripts/verify-reviewed-render.py",
    f"{RENDER_ROOT}/head.json",
    f"{RENDER_ROOT}/integrity.json",
    f"{RENDER_ROOT}/live-preconditions.json",
    f"{RENDER_ROOT}/network-boundary-migration.json",
    f"{RENDER_ROOT}/public-mecky/deployment.json",
    f"{RENDER_ROOT}/public-mecky/kustomization.yaml",
    f"{RENDER_ROOT}/public-mecky/networkpolicy.json",
    f"{RENDER_ROOT}/public-mecky/service.json",
    f"{RENDER_ROOT}/web/deployment.json",
    f"{RENDER_ROOT}/web/ingress.json",
    f"{RENDER_ROOT}/web/kustomization.yaml",
    f"{RENDER_ROOT}/web/networkpolicy.json",
}

ALLOWED_PATCH_PATHS = {
    "/metadata/annotations/stadtstack.io~1source-revision",
    "/metadata/annotations/stadtstack.io~1release-set-sha256",
    "/spec/template/metadata/annotations/stadtstack.io~1source-revision",
    "/spec/template/spec/containers/0/image",
    "/spec/template/spec/containers/0/imagePullPolicy",
}


class VerificationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(), object_pairs_hook=object_pairs)


def closed(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    require(set(value) == keys, f"{label} keys mismatch")
    return value


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def iter_keys(value: Any):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from iter_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_keys(child)


def repository_files(root: Path) -> set[str]:
    files: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] == ".git":
            continue
        require(not path.is_symlink(), f"symlink forbidden: {relative}")
        if path.is_file():
            require(path.is_file(), f"non-regular file forbidden: {relative}")
            files.add(str(relative))
    return files


def verify_contract(root: Path) -> dict[str, Any]:
    contract = load_json(root / "policy/repository-contract.json")
    require(contract == {
        "schemaVersion": "roebel_staging_operations_repository_v1",
        "repository": "GiraeffleAeffle/roebel-staging-operations",
        "visibility": "public",
        "defaultBranch": "main",
        "environment": "roebel-staging",
        "reviewedRenderRoot": RENDER_ROOT,
        "componentOrder": list(COMPONENT_ORDER),
        "components": [
            {"component": component, **COMPONENTS[component]}
            for component in COMPONENT_ORDER
        ],
        "schemas": {"head": HEAD_SCHEMA, "reviewedRender": RENDER_SCHEMA},
        "publicMetadataBoundary": {
            "allowedKinds": ["Deployment", "Ingress", "Service", "NetworkPolicy"],
            "secretObjectsAllowed": False,
            "secretValuesAllowed": False,
            "secretReferencesAllowed": True,
            "personalDataAllowed": False,
            "civicRecordsAllowed": False,
            "runtimeStatusAllowed": False,
        },
        "promotionBoundary": {
            "pullRequestMayChangeOnlyReviewedRender": True,
            "completePreviousHeadRequired": True,
            "immutableDigestRequired": True,
            "imagePullPolicy": "IfNotPresent",
            "noOpPromotionAllowed": False,
        },
        "requiredBranchProtection": {
            "requiredStatusChecks": ["reviewed-render-admission"],
            "requiredApprovingReviewCount": 1,
            "dismissStaleReviews": True,
            "requireCodeOwnerReviews": True,
            "requireConversationResolution": True,
            "requireLinearHistory": True,
            "allowForcePushes": False,
            "allowDeletions": False,
        },
    }, "repository contract drift")
    return contract


def verify_head(value: Any, label: str) -> dict[str, Any]:
    head = closed(value, {"schemaVersion", "promotionRevision", "releaseSetDigest", "components"}, label)
    require(head["schemaVersion"] == HEAD_SCHEMA, f"{label} schema drift")
    require(isinstance(head["promotionRevision"], str) and REVISION.fullmatch(head["promotionRevision"]), f"{label} promotion revision invalid")
    require(isinstance(head["releaseSetDigest"], str) and SHA256.fullmatch(head["releaseSetDigest"]), f"{label} release digest invalid")
    require(isinstance(head["components"], list) and len(head["components"]) == 2, f"{label} component count invalid")
    parsed = []
    for index, component in enumerate(head["components"]):
        item = closed(component, {"component", "sourceRevision", "manifestDigest"}, f"{label}.components[{index}]")
        require(item["component"] == COMPONENT_ORDER[index], f"{label} component order invalid")
        require(isinstance(item["sourceRevision"], str) and REVISION.fullmatch(item["sourceRevision"]), f"{label} source revision invalid")
        require(isinstance(item["manifestDigest"], str) and SHA256.fullmatch(item["manifestDigest"]), f"{label} manifest digest invalid")
        parsed.append(item)
    return head


def component_map(head: dict[str, Any]) -> dict[str, dict[str, str]]:
    return {item["component"]: item for item in head["components"]}


def verify_deployment(root: Path, component: str, head: dict[str, Any]) -> dict[str, Any]:
    policy = COMPONENTS[component]
    path = root / RENDER_ROOT / policy["directory"] / "deployment.json"
    deployment = load_json(path)
    require(isinstance(deployment, dict), f"{component} Deployment must be an object")
    require(deployment.get("apiVersion") == "apps/v1" and deployment.get("kind") == "Deployment", f"{component} object kind invalid")
    require(set(deployment) == {"apiVersion", "kind", "metadata", "spec"}, f"{component} top-level shape invalid")
    metadata = deployment.get("metadata")
    require(isinstance(metadata, dict), f"{component} metadata invalid")
    require(metadata.get("namespace") == policy["namespace"] and metadata.get("name") == policy["name"], f"{component} identity invalid")
    require(not ({"uid", "resourceVersion", "managedFields", "creationTimestamp"} & set(metadata)), f"{component} runtime metadata forbidden")
    require("status" not in deployment, f"{component} runtime status forbidden")
    annotations = metadata.get("annotations")
    require(isinstance(annotations, dict), f"{component} annotations invalid")
    record = component_map(head)[component]
    require(annotations.get("stadtstack.io/source-revision") == record["sourceRevision"], f"{component} source annotation mismatch")
    require(annotations.get("stadtstack.io/release-set-sha256") == head["releaseSetDigest"], f"{component} release annotation mismatch")
    try:
        containers = deployment["spec"]["template"]["spec"]["containers"]
        pod_annotations = deployment["spec"]["template"]["metadata"]["annotations"]
    except (KeyError, TypeError):
        raise VerificationError(f"{component} Pod template invalid") from None
    require(isinstance(containers, list), f"{component} containers invalid")
    primary = [container for container in containers if isinstance(container, dict) and container.get("name") == policy["container"]]
    require(len(primary) == 1, f"{component} primary container invalid")
    expected_image = f"{policy['repository']}@{record['manifestDigest']}"
    require(primary[0].get("image") == expected_image, f"{component} image binding invalid")
    require(primary[0].get("imagePullPolicy") == "IfNotPresent", f"{component} pull policy invalid")
    require(isinstance(pod_annotations, dict) and pod_annotations.get("stadtstack.io/source-revision") == record["sourceRevision"], f"{component} Pod source annotation mismatch")

    keys = set(iter_keys(deployment))
    require(not ({"data", "stringData", "binaryData"} & keys), f"{component} Secret payload-shaped field forbidden")
    serialized = json.dumps(deployment, sort_keys=True)
    for forbidden in ("BEGIN PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", "AGE-SECRET-KEY-", "ghp_", "github_pat_"):
        require(forbidden not in serialized, f"{component} secret-shaped content forbidden")
    for container in containers:
        if not isinstance(container, dict):
            continue
        for env in container.get("env", []):
            if not isinstance(env, dict):
                continue
            name = env.get("name", "")
            if isinstance(name, str) and re.search(r"(?:SECRET|TOKEN|PASSWORD|API_KEY)$", name):
                require("value" not in env and "valueFrom" in env, f"{component} literal secret-shaped environment value forbidden: {name}")
    env = primary[0].get("env", [])
    require(isinstance(env, list), f"{component} environment invalid")
    names = [item.get("name") for item in env if isinstance(item, dict)]
    require(len(names) == len(env) and len(names) == len(set(names)), f"{component} environment names invalid or repeated")
    by_name = {item["name"]: item for item in env}
    if component == "public-mecky":
        expected_chat = {
            "STADTSTACK_E2E_MODE": "synthetic-reviewed",
            "STADTSTACK_E2E_SYNTHETIC_EVIDENCE_ALLOWED": "true",
            "MECKY_CHAT_PORT": "18084",
            "MECKY_CHAT_BIND_HOST": "0.0.0.0",
            "MECKY_CHAT_PER_MINUTE": "10",
            "MECKY_CHAT_PER_DAY": "100",
        }
        for name, value in expected_chat.items():
            require(by_name.get(name) == {"name": name, "value": value}, f"public-mecky {name} binding invalid")
        require(primary[0].get("ports") == [{"containerPort": 18084, "name": "mecky-chat", "protocol": "TCP"}], "public-mecky chat port invalid")
        expected_probe = {
            "failureThreshold": 3,
            "httpGet": {"path": "/healthz", "port": "mecky-chat", "scheme": "HTTP"},
            "periodSeconds": 10,
            "successThreshold": 1,
            "timeoutSeconds": 3,
        }
        require(primary[0].get("readinessProbe") == expected_probe, "public-mecky readiness probe invalid")
        require(primary[0].get("livenessProbe") == {**expected_probe, "periodSeconds": 20}, "public-mecky liveness probe invalid")
        require(primary[0].get("startupProbe") == {**expected_probe, "failureThreshold": 30, "periodSeconds": 2}, "public-mecky startup probe invalid")
    else:
        require(by_name.get("PUBLIC_MECKY_CHAT_URL") == {
            "name": "PUBLIC_MECKY_CHAT_URL",
            "value": "http://public-mecky.stadtstack-roebel-staging-lab.svc.cluster.local:18084",
        }, "Web Public Mecky URL invalid")
    return deployment


def verify_public_mecky_service(root: Path) -> dict[str, Any]:
    service = load_json(root / RENDER_ROOT / "public-mecky/service.json")
    require(service == {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "labels": {
                "app.kubernetes.io/component": "public-mecky",
                "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
                "stadtstack.io/authority": "none",
            },
            "name": "public-mecky",
            "namespace": "stadtstack-roebel-staging-lab",
        },
        "spec": {
            "ports": [{"name": "mecky-chat", "port": 18084, "protocol": "TCP", "targetPort": "mecky-chat"}],
            "selector": {
                "app.kubernetes.io/component": "public-mecky",
                "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
            },
            "type": "ClusterIP",
        },
    }, "Public Mecky Service drift")
    return service


def verify_public_mecky_network_policy(root: Path) -> dict[str, Any]:
    policy = load_json(root / RENDER_ROOT / "public-mecky/networkpolicy.json")
    require(policy == {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "labels": {
                "app.kubernetes.io/component": "public-mecky",
                "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
                "stadtstack.io/authority": "none",
            },
            "name": "public-mecky-chat-from-web",
            "namespace": "stadtstack-roebel-staging-lab",
        },
        "spec": {
            "ingress": [{
                "from": [{
                    "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "stadtstack-roebel-web-preview"}},
                    "podSelector": {"matchLabels": {"app.kubernetes.io/name": "roebel-web-presentation"}},
                }],
                "ports": [{"port": 18084, "protocol": "TCP"}],
            }],
            "podSelector": {"matchLabels": {
                "app.kubernetes.io/component": "public-mecky",
                "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
            }},
            "policyTypes": ["Ingress"],
        },
    }, "Public Mecky NetworkPolicy drift")
    return policy


def verify_web_network_policy(root: Path) -> dict[str, Any]:
    policy = load_json(root / RENDER_ROOT / "web/networkpolicy.json")
    require(policy == {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "labels": {
                "app.kubernetes.io/component": "readonly-presentation",
                "app.kubernetes.io/name": "roebel-web-presentation",
                "app.kubernetes.io/part-of": "stadtstack",
                "stadtstack.io/authority": "none",
            },
            "name": "roebel-web-presentation",
            "namespace": "stadtstack-roebel-web-preview",
        },
        "spec": {
            "egress": [
                {
                    "to": [{
                        "namespaceSelector": {
                            "matchLabels": {
                                "kubernetes.io/metadata.name": "kube-system"
                            }
                        },
                        "podSelector": {
                            "matchLabels": {"k8s-app": "kube-dns"}
                        },
                    }],
                    "ports": [
                        {"port": 53, "protocol": "UDP"},
                        {"port": 53, "protocol": "TCP"},
                    ],
                },
                {
                    "to": [{"ipBlock": {"cidr": "77.42.11.9/32"}}],
                    "ports": [{"port": 443, "protocol": "TCP"}],
                },
                {
                    "to": [{
                        "namespaceSelector": {
                            "matchLabels": {
                                "kubernetes.io/metadata.name": "stadtstack-roebel-staging-lab"
                            }
                        },
                        "podSelector": {
                            "matchLabels": {
                                "app.kubernetes.io/component": "public-mecky",
                                "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
                            }
                        },
                    }],
                    "ports": [{"port": 18084, "protocol": "TCP"}],
                },
            ],
            "ingress": [{
                "from": [
                    {"namespaceSelector": {
                        "matchLabels": {
                            "kubernetes.io/metadata.name": "ingress-system"
                        }
                    }},
                    {"ipBlock": {"cidr": "10.42.0.10/32"}},
                    {"ipBlock": {"cidr": "10.42.0.11/32"}},
                    {"ipBlock": {"cidr": "10.42.0.12/32"}},
                    {"ipBlock": {"cidr": "10.244.0.0/32"}},
                    {"ipBlock": {"cidr": "10.244.1.0/32"}},
                    {"ipBlock": {"cidr": "10.244.2.0/32"}},
                    {"ipBlock": {"cidr": "10.244.0.1/32"}},
                    {"ipBlock": {"cidr": "10.244.1.1/32"}},
                    {"ipBlock": {"cidr": "10.244.2.1/32"}},
                ],
                "ports": [{"port": 8080, "protocol": "TCP"}],
            }],
            "podSelector": {
                "matchLabels": {"app.kubernetes.io/name": "roebel-web-presentation"}
            },
            "policyTypes": ["Ingress", "Egress"],
        },
    }, "Web NetworkPolicy drift")
    return policy


def verify_web_ingress(root: Path) -> dict[str, Any]:
    ingress = load_json(root / RENDER_ROOT / "web/ingress.json")
    require(ingress == {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {
            "annotations": {
                "haproxy-ingress.github.io/config-backend": (
                    "http-response set-header X-Stadtstack-Public-Boundary roebel-web-readonly-presentation\n"
                    "http-response set-header X-Robots-Tag noindex,nofollow,noarchive\n"
                    "http-response set-header X-Frame-Options DENY\n"
                    "http-response set-header X-Content-Type-Options nosniff\n"
                    "http-response set-header Referrer-Policy no-referrer\n"
                    "http-response set-header Content-Security-Policy \"default-src 'self'; base-uri 'none'; form-action 'none'; object-src 'none'; frame-ancestors 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data: blob: https:; connect-src 'self' https://roebel-stadtstack.agentcart.eu; worker-src 'self' blob:;\""
                ),
                "haproxy-ingress.github.io/config-backend-early": (
                    "http-request deny deny_status 405 if { method POST } !{ path /api/chat/mecky }\n"
                    "http-request deny deny_status 405 unless { method GET HEAD POST }\n"
                    "http-request deny deny_status 404 if { path_beg /api } !{ path_beg /api/public-feed/ } !{ path /api/notifications/unread-count } !{ path /api/chat/mecky }"
                ),
            },
            "labels": {
                "app.kubernetes.io/component": "readonly-presentation",
                "app.kubernetes.io/name": "roebel-web-presentation",
                "app.kubernetes.io/part-of": "stadtstack",
                "stadtstack.io/authority": "none",
            },
            "name": "roebel-web-presentation",
            "namespace": "stadtstack-roebel-web-preview",
        },
        "spec": {
            "ingressClassName": "haproxy",
            "rules": [{
                "host": "roebel-web.staging.agentcart.eu",
                "http": {
                    "paths": [
                        {
                            "backend": {"service": {
                                "name": "roebel-supabase-read-gateway",
                                "port": {"name": "http"},
                            }},
                            "path": "/supabase-read",
                            "pathType": "Prefix",
                        },
                        {
                            "backend": {"service": {
                                "name": "roebel-web-presentation",
                                "port": {"name": "http"},
                            }},
                            "path": "/",
                            "pathType": "Prefix",
                        },
                    ]
                },
            }],
            "tls": [{
                "hosts": ["roebel-web.staging.agentcart.eu"],
                "secretName": "roebel-web-presentation-tls",
            }],
        },
    }, "Web Ingress drift")
    return ingress


def verify_network_boundary_migration(
    root: Path,
    web_network_policy: dict[str, Any],
    web_ingress: dict[str, Any],
) -> dict[str, Any]:
    migration = load_json(root / RENDER_ROOT / "network-boundary-migration.json")
    expected = {
        "authority": "none",
        "boundary": {
            "ingress": {
                "allowedMethods": ["GET", "HEAD", "POST"],
                "exactPostPath": "/api/chat/mecky",
                "otherApiPaths": "404_except_public_feed_notifications_and_exact_mecky_path",
                "otherMethods": "405",
                "otherPostPaths": "405",
                "resource": {
                    "kind": "Ingress",
                    "name": "roebel-web-presentation",
                    "namespace": "stadtstack-roebel-web-preview",
                },
            },
            "webEgress": {
                "destinationNamespace": "stadtstack-roebel-staging-lab",
                "destinationPodLabels": {
                    "app.kubernetes.io/component": "public-mecky",
                    "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
                },
                "port": 18084,
                "protocol": "TCP",
                "resource": {
                    "kind": "NetworkPolicy",
                    "name": "roebel-web-presentation",
                    "namespace": "stadtstack-roebel-web-preview",
                },
            },
        },
        "effects": {
            "civicMutation": False,
            "clusterMutation": False,
            "secretRead": False,
            "secretWrite": False,
        },
        "objects": [
            {
                "kind": "NetworkPolicy",
                "name": "roebel-web-presentation",
                "namespace": "stadtstack-roebel-web-preview",
                "sha256": digest(web_network_policy),
            },
            {
                "kind": "Ingress",
                "name": "roebel-web-presentation",
                "namespace": "stadtstack-roebel-web-preview",
                "sha256": digest(web_ingress),
            },
        ],
        "rbacBootstrap": {
            "createAllowed": False,
            "deleteAllowed": False,
            "listAllowed": False,
            "required": True,
            "roleNamespace": "stadtstack-roebel-web-preview",
            "serviceAccount": {
                "name": "roebel-web-reconciler",
                "namespace": "flux-roebel-staging",
            },
            "watchAllowed": False,
            "rules": [
                {
                    "apiGroups": ["networking.k8s.io"],
                    "resourceNames": ["roebel-web-presentation"],
                    "resources": ["networkpolicies"],
                    "verbs": ["get", "patch", "update"],
                },
                {
                    "apiGroups": ["networking.k8s.io"],
                    "resourceNames": ["roebel-web-presentation"],
                    "resources": ["ingresses"],
                    "verbs": ["get", "patch", "update"],
                },
            ],
            "liveMutationPerformed": False,
        },
        "schemaVersion": "roebel_staging_network_boundary_bootstrap_v1",
        "status": "local_candidate_ready_for_one_time_policy_bootstrap",
    }
    require(migration == expected, "network-boundary migration receipt drift")
    return migration


def verify_kustomizations(root: Path) -> None:
    public_expected = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - deployment.json\n  - service.json\n  - networkpolicy.json\n"
    web_expected = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - deployment.json\n  - networkpolicy.json\n  - ingress.json\n"
    require((root / RENDER_ROOT / "public-mecky/kustomization.yaml").read_text() == public_expected, "public-mecky Flux path widened")
    require((root / RENDER_ROOT / "web/kustomization.yaml").read_text() == web_expected, "roebel-web-staging Flux path widened")


def expected_patch_value(component: str, path: str, head: dict[str, Any]) -> str:
    record = component_map(head)[component]
    if path in {
        "/metadata/annotations/stadtstack.io~1source-revision",
        "/spec/template/metadata/annotations/stadtstack.io~1source-revision",
    }:
        return record["sourceRevision"]
    if path == "/metadata/annotations/stadtstack.io~1release-set-sha256":
        return head["releaseSetDigest"]
    if path == "/spec/template/spec/containers/0/image":
        return f"{COMPONENTS[component]['repository']}@{record['manifestDigest']}"
    if path == "/spec/template/spec/containers/0/imagePullPolicy":
        return "IfNotPresent"
    raise VerificationError("unreachable patch path")


def verify_live_preconditions(root: Path, head: dict[str, Any]) -> dict[str, Any]:
    value = load_json(root / RENDER_ROOT / "live-preconditions.json")
    record = closed(value, {"previousEnvironmentHead", "requiredLivePreconditions", "patches"}, "live-preconditions")
    previous = verify_head(record["previousEnvironmentHead"], "previousEnvironmentHead")
    require(isinstance(record["requiredLivePreconditions"], list) and len(record["requiredLivePreconditions"]) == 2, "live precondition count invalid")
    require(isinstance(record["patches"], list) and len(record["patches"]) == 2, "patch count invalid")
    for index, component in enumerate(COMPONENT_ORDER):
        policy = COMPONENTS[component]
        precondition = closed(record["requiredLivePreconditions"][index], {"component", "currentImage", "resourceVersion", "target", "uid"}, f"precondition[{index}]")
        require(precondition["component"] == component, "precondition component order invalid")
        require(isinstance(precondition["currentImage"], str) and IMMUTABLE_IMAGE.fullmatch(precondition["currentImage"]), "precondition current image invalid")
        require(isinstance(precondition["resourceVersion"], str) and precondition["resourceVersion"].isdigit(), "precondition resourceVersion invalid")
        require(isinstance(precondition["uid"], str) and UUID.fullmatch(precondition["uid"]), "precondition uid invalid")
        expected_target = {"apiVersion": "apps/v1", "kind": "Deployment", "name": policy["name"], "namespace": policy["namespace"]}
        require(precondition["target"] == expected_target, "precondition target invalid")

        patch = closed(record["patches"][index], {"component", "operations", "target"}, f"patch[{index}]")
        require(patch["component"] == component and patch["target"] == expected_target, "patch target invalid")
        require(isinstance(patch["operations"], list), "patch operations invalid")
        seen: set[str] = set()
        for operation in patch["operations"]:
            item = closed(operation, {"op", "path", "value"}, f"{component} patch operation")
            require(item["op"] in {"add", "replace"}, "patch operation invalid")
            require(item["path"] in ALLOWED_PATCH_PATHS and item["path"] not in seen, "patch path invalid or repeated")
            require(item["value"] == expected_patch_value(component, item["path"], head), "patch value invalid")
            seen.add(item["path"])
    return {"previous": previous, "preconditions": record["requiredLivePreconditions"], "patches": record["patches"]}


def verify_tree(root: Path) -> dict[str, Any]:
    root = root.resolve()
    require(root.is_dir(), "repository root missing")
    require(repository_files(root) == EXPECTED_FILES, "repository file set drift")
    verify_contract(root)
    head = verify_head(load_json(root / RENDER_ROOT / "head.json"), "head")
    integrity = closed(load_json(root / RENDER_ROOT / "integrity.json"), {"schemaVersion", "releaseSetDigest", "desiredRenderSha256", "networkBoundaryMigrationSha256"}, "integrity")
    require(integrity["schemaVersion"] == RENDER_SCHEMA, "integrity schema drift")
    require(integrity["releaseSetDigest"] == head["releaseSetDigest"], "integrity release binding invalid")
    require(isinstance(integrity["desiredRenderSha256"], str) and SHA256.fullmatch(integrity["desiredRenderSha256"]), "integrity checksum invalid")
    deployments = {component: verify_deployment(root, component, head) for component in COMPONENT_ORDER}
    service = verify_public_mecky_service(root)
    network_policy = verify_public_mecky_network_policy(root)
    web_network_policy = verify_web_network_policy(root)
    web_ingress = verify_web_ingress(root)
    migration = verify_network_boundary_migration(root, web_network_policy, web_ingress)
    objects = [
        deployments["public-mecky"],
        service,
        network_policy,
        deployments["roebel-web-staging"],
        web_network_policy,
        web_ingress,
    ]
    require(integrity["desiredRenderSha256"] == digest({"nextEnvironmentHead": head, "objects": objects}), "reviewed render checksum mismatch")
    require(integrity["networkBoundaryMigrationSha256"] == digest(migration), "network-boundary migration checksum mismatch")
    verify_kustomizations(root)
    live = verify_live_preconditions(root, head)
    return {"root": root, "head": head, "integrity": integrity, "objects": objects, "deployments": deployments, "migration": migration, "live": live}


def verify_transition(candidate: dict[str, Any], base: dict[str, Any]) -> None:
    candidate_root: Path = candidate["root"]
    base_root: Path = base["root"]
    for relative in EXPECTED_FILES:
        if not relative.startswith(RENDER_ROOT + "/"):
            require((candidate_root / relative).read_bytes() == (base_root / relative).read_bytes(), f"promotion changed protected policy file: {relative}")
    for relative in (
        f"{RENDER_ROOT}/network-boundary-migration.json",
        f"{RENDER_ROOT}/web/ingress.json",
        f"{RENDER_ROOT}/web/networkpolicy.json",
    ):
        require((candidate_root / relative).read_bytes() == (base_root / relative).read_bytes(), f"promotion changed protected network boundary: {relative}")

    previous = candidate["live"]["previous"]
    require(previous == base["head"], "candidate previous head does not equal protected base head")
    require(candidate["head"] != base["head"], "no-op promotion forbidden")
    base_components = component_map(base["head"])
    candidate_components = component_map(candidate["head"])
    changed = []
    for component in COMPONENT_ORDER:
        if candidate_components[component] == base_components[component]:
            continue
        changed.append(component)
    require(changed, "promotion must change at least one component")
    require(any(candidate_components[component]["sourceRevision"] == candidate["head"]["promotionRevision"] for component in changed), "promotion revision is not bound to a changed component")
    base_images = {
        component: next(container for container in base["deployments"][component]["spec"]["template"]["spec"]["containers"] if container.get("name") == COMPONENTS[component]["container"])["image"]
        for component in COMPONENT_ORDER
    }
    for index, component in enumerate(COMPONENT_ORDER):
        require(candidate["live"]["preconditions"][index]["currentImage"] == base_images[component], f"{component} live CAS image does not equal protected base image")


def verify(root: Path, base_root: Path | None = None) -> dict[str, Any]:
    candidate = verify_tree(root)
    if base_root is not None:
        base = verify_tree(base_root)
        verify_transition(candidate, base)
    return {
        "schemaVersion": "roebel_staging_operations_verification_v1",
        "status": "passed",
        "repository": "GiraeffleAeffle/roebel-staging-operations",
        "environment": "roebel-staging",
        "releaseSetDigest": candidate["head"]["releaseSetDigest"],
        "desiredRenderSha256": candidate["integrity"]["desiredRenderSha256"],
        "components": [
            {
                "component": item["component"],
                "sourceRevision": item["sourceRevision"],
                "manifestDigest": item["manifestDigest"],
            }
            for item in candidate["head"]["components"]
        ],
        "baseTransitionVerified": base_root is not None,
        "effects": {
            "secretRead": False,
            "secretWrite": False,
            "clusterMutation": False,
            "civicMutation": False,
        },
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--base-root", type=Path)
    args = parser.parse_args(argv)
    try:
        result = verify(args.root, args.base_root)
    except (OSError, json.JSONDecodeError, KeyError, TypeError, VerificationError) as error:
        print(f"reviewed-render verification failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
