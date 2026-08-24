#!/usr/bin/env python3
"""Fail-closed verifier for the public Röbel staging reviewed render.

For pull requests this exact script is loaded from the protected base branch
and receives the candidate checkout only as data. The candidate therefore
cannot weaken its own admission policy.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
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

# The current render remains the default admission shape.  The reviewed
# knowledge runtime is deliberately a second, closed shape: a promotion may
# either contain the complete current render or the complete future render,
# never a mixture of the two.  The future values below are policy-level
# identities; the source revision and image digest are bound by runtime-pin in
# the later render PR.
REVIEWED_PUBLIC_KNOWLEDGE_FILES = {
    f"{RENDER_ROOT}/reviewed-public-knowledge/deployment.json",
    f"{RENDER_ROOT}/reviewed-public-knowledge/service.json",
    f"{RENDER_ROOT}/reviewed-public-knowledge/networkpolicy.json",
    f"{RENDER_ROOT}/reviewed-public-knowledge/kustomization.yaml",
    f"{RENDER_ROOT}/reviewed-public-knowledge/runtime-pin.json",
}
REVIEWED_PUBLIC_KNOWLEDGE_NAMESPACE = "stadtstack-roebel-staging-lab"
REVIEWED_PUBLIC_KNOWLEDGE_NAME = "reviewed-public-knowledge"
REVIEWED_PUBLIC_KNOWLEDGE_IMAGE = "ghcr.io/giraeffleaeffle/stadtstack-reviewed-public-knowledge-runtime"
REVIEWED_PUBLIC_KNOWLEDGE_WORKFLOW = (
    "https://github.com/GiraeffleAeffle/stadtstack/"
    ".github/workflows/reviewed-knowledge-runtime-publish.yml@refs/heads/main"
)
REVIEWED_PUBLIC_KNOWLEDGE_BASE_URL = (
    "http://reviewed-public-knowledge.stadtstack-roebel-staging-lab."
    "svc.cluster.local:18080"
)
REVIEWED_PUBLIC_KNOWLEDGE_SOURCE_KINDS = "local_news,ratsinformation"
REVIEWED_PUBLIC_KNOWLEDGE_LABELS = {
    "app.kubernetes.io/component": "reviewed-public-knowledge",
    "app.kubernetes.io/name": "reviewed-public-knowledge",
    "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
    "stadtstack.io/authority": "none",
}
REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_SOURCE_REVISION = "642e2741d2fd3cb867c0e1c315f04ef8e29d787b"
REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_SOURCE_TAG = (
    "source-642e2741d2fd3cb867c0e1c315f04ef8e29d787b"
)
REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_IMAGE_DIGEST = (
    "sha256:7846fee172cfdad286773fa56c939d716ae32604cd0e47833f72536aa6a5c1dc"
)
REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_SLSA_DIGEST = (
    "sha256:5d7f4a80f77bc0b1c7e036303325bf68f4bbb6e8a4dbeaaa839abf7abd330aab"
)
REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_SPDX_DIGEST = (
    "sha256:052b53e71548f978fd00d22eb9dd20089dd58b05f6b9cc39590f3d8f25740bc4"
)
REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_AUTH_DIGEST = (
    "sha256:ec21c035eccb78eb5ca20ec95628eb351633621e09a130ac8d7e663714d40c7a"
)
REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_RECEIPT_DIGEST = (
    "sha256:21a4c33b36db0831fa65375f6e7af812b87502986d97d5a45e7eb8b19108b04f"
)
LEGACY_SYNTHETIC_EVIDENCE_ENV_NAMES = {
    "STADTSTACK_E2E_MODE",
    "STADTSTACK_E2E_SYNTHETIC_EVIDENCE_ALLOWED",
    "STADTSTACK_E2E_REVIEWED_EVIDENCE",
    "STADTSTACK_E2E_REVIEWED_EVIDENCE_SHA256",
}
PUBLIC_MECKY_LABELS = {
    "app.kubernetes.io/component": "public-mecky",
    "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
}
PUBLIC_MECKY_NETWORK_POLICY_LABELS = {
    **PUBLIC_MECKY_LABELS,
    "stadtstack.io/authority": "none",
}
PUBLIC_MECKY_REVIEWED_EGRESS_DESTINATION_LABELS = {
    "app.kubernetes.io/component": "reviewed-public-knowledge",
    "app.kubernetes.io/name": "reviewed-public-knowledge",
    "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
    "stadtstack.io/authority": "none",
}

EXPECTED_FILES = {
    ".github/CODEOWNERS",
    ".github/workflows/automatic-promotion.yml",
    ".github/workflows/reviewed-render-admission.yml",
    ".gitignore",
    "LICENSE",
    "README.md",
    "contracts/stadtstack-case-image-resource-inventory-contract.json",
    "contracts/stadtstack-case-recovery-composition-contract.json",
    "contracts/stadtstack-case-runtime-contract.json",
    "policy/repository-contract.json",
    "scripts/render-release-set-promotion.py",
    "scripts/test_automatic_promotion_workflow.py",
    "scripts/test_verify_case_staging_topology.py",
    "scripts/test_render_release_set_promotion.py",
    "scripts/test_verify_reviewed_render.py",
    "scripts/verify-stadtstack-case-runtime-contract.py",
    "scripts/verify-case-staging-topology.py",
    "scripts/verify-reviewed-render.py",
    "scripts/verify-stadtstack-case-image-resource-inventory-contract.py",
    "scripts/verify-stadtstack-case-recovery-composition-contract.py",
    "tests/test_stadtstack_case_image_resource_inventory_contract.py",
    "tests/test_stadtstack_case_runtime_contract.py",
    "tests/test_stadtstack-case-recovery-composition-contract.py",
    "case-staging-topology/contract.json",
    "case-staging-topology/roebel-case-public-binding-default-deny-networkpolicy.json",
    "case-staging-topology/roebel-case-public-binding-allow-private-outbox-and-dns-egress-networkpolicy.json",
    "case-staging-topology/roebel-case-public-binding-allow-roebel-web-ingress-networkpolicy.json",
    "case-staging-topology/roebel-case-public-binding-service.json",
    "case-staging-topology/roebel-case-public-binding-serviceaccount.json",
    "case-staging-topology/roebel-case-steward-control-allow-private-outbox-from-public-networkpolicy.json",
    "case-staging-topology/roebel-case-steward-control-default-deny-networkpolicy.json",
    "case-staging-topology/roebel-case-steward-control-private-outbox-service.json",
    "case-staging-topology/roebel-case-steward-control-service.json",
    "case-staging-topology/roebel-case-steward-control-serviceaccount.json",
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

FUTURE_EXPECTED_FILES = EXPECTED_FILES | REVIEWED_PUBLIC_KNOWLEDGE_FILES

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


def verify_repository_file_set(root: Path) -> str:
    """Admit exactly one whole render shape and report which shape it is."""
    actual = repository_files(root)
    if actual == EXPECTED_FILES:
        return "current"
    if actual == FUTURE_EXPECTED_FILES:
        return "reviewed-public-knowledge"
    missing_current = sorted(EXPECTED_FILES - actual)
    unexpected = sorted(actual - EXPECTED_FILES)
    raise VerificationError(
        "repository file set drift "
        f"(missing={missing_current!r}, unexpected={unexpected!r})"
    )


def verify_case_staging_topology_with_protected_policy(root: Path) -> None:
    """Validate candidate topology data with the verifier beside this script.

    On pull_request_target this module is executed from the protected base
    checkout.  Resolving the sibling by ``__file__`` is therefore deliberate:
    candidate topology is data only and cannot select or execute its own
    policy module.
    """
    verifier_path = Path(__file__).with_name("verify-case-staging-topology.py")
    spec = importlib.util.spec_from_file_location("protected_case_topology_verifier", verifier_path)
    require(spec is not None and spec.loader is not None, "protected Case topology verifier unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        module.verify(root)
    except module.VerificationError as error:
        raise VerificationError(f"Case staging topology verification failed: {error}") from error


def verify_case_runtime_contract_with_protected_policy(root: Path) -> None:
    """Validate the candidate recovery inventory with protected-base policy."""
    verifier_path = Path(__file__).with_name("verify-stadtstack-case-runtime-contract.py")
    spec = importlib.util.spec_from_file_location("protected_case_runtime_contract_verifier", verifier_path)
    require(spec is not None and spec.loader is not None, "protected Case runtime contract verifier unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    errors = module.verify_contract(root)
    require(errors == [], f"Case runtime contract verification failed: {errors!r}")


def verify_case_recovery_composition_contract_with_protected_policy(root: Path) -> None:
    """Validate the inert recovery composition with protected-base policy."""
    verifier_path = Path(__file__).with_name("verify-stadtstack-case-recovery-composition-contract.py")
    spec = importlib.util.spec_from_file_location("protected_case_recovery_composition_verifier", verifier_path)
    require(spec is not None and spec.loader is not None, "protected Case recovery composition verifier unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    errors = module.verify_contract(root)
    require(errors == [], f"Case recovery composition contract verification failed: {errors!r}")


def verify_case_image_resource_inventory_contract_with_protected_policy(root: Path) -> None:
    """Validate the inert image/resource inventory with protected-base policy."""
    verifier_path = Path(__file__).with_name("verify-stadtstack-case-image-resource-inventory-contract.py")
    spec = importlib.util.spec_from_file_location("protected_case_image_resource_inventory_verifier", verifier_path)
    require(spec is not None and spec.loader is not None, "protected Case image/resource inventory verifier unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    errors = module.verify_contract(root)
    require(errors == [], f"Case image/resource inventory contract verification failed: {errors!r}")


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
            "allowedKinds": ["Deployment", "Ingress", "Service", "NetworkPolicy", "ServiceAccount"],
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


def verify_reviewed_public_knowledge_runtime_pin(value: Any) -> dict[str, Any]:
    pin = closed(
        value,
        {
            "schemaVersion",
            "component",
            "sourceRevision",
            "sourceTag",
            "imageRepository",
            "manifestDigest",
            "workflowIdentity",
            "slsaProvenance",
            "spdxSbom",
            "anonymousPublicPullReceipt",
            "authorityBinding",
            "deploymentEffect",
        },
        "reviewed-public-knowledge runtime-pin",
    )
    require(pin["schemaVersion"] == "stadtstack_reviewed_public_knowledge_runtime_pin_v1", "reviewed runtime-pin schema drift")
    require(pin["component"] == "reviewed-public-knowledge-runtime", "reviewed runtime-pin component invalid")
    require(isinstance(pin["sourceRevision"], str) and REVISION.fullmatch(pin["sourceRevision"]), "reviewed runtime source revision invalid")
    require(pin["sourceTag"] == f"source-{pin['sourceRevision']}", "reviewed runtime source tag invalid")
    require(pin["imageRepository"] == REVIEWED_PUBLIC_KNOWLEDGE_IMAGE, "reviewed runtime image repository invalid")
    require(isinstance(pin["manifestDigest"], str) and SHA256.fullmatch(pin["manifestDigest"]), "reviewed runtime manifest digest invalid")
    require(pin["workflowIdentity"] == REVIEWED_PUBLIC_KNOWLEDGE_WORKFLOW, "reviewed runtime workflow identity invalid")
    require(pin["sourceRevision"] == REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_SOURCE_REVISION, "reviewed runtime first-tracer source revision drift")
    require(pin["sourceTag"] == REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_SOURCE_TAG, "reviewed runtime first-tracer source tag drift")
    require(pin["manifestDigest"] == REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_IMAGE_DIGEST, "reviewed runtime first-tracer image digest drift")

    provenance = closed(
        pin["slsaProvenance"],
        {"issuer", "publisherIdentity", "predicateType", "repository", "gitRef", "sourceRevision", "subjectDigest", "attestationDigest"},
        "reviewed runtime SLSA provenance",
    )
    require(provenance["issuer"] == "https://token.actions.githubusercontent.com", "reviewed runtime provenance issuer invalid")
    require(provenance["publisherIdentity"] == REVIEWED_PUBLIC_KNOWLEDGE_WORKFLOW, "reviewed runtime provenance publisher invalid")
    require(provenance["predicateType"] == "https://slsa.dev/provenance/v1", "reviewed runtime provenance predicate invalid")
    require(provenance["repository"] == "GiraeffleAeffle/stadtstack", "reviewed runtime provenance repository invalid")
    require(provenance["gitRef"] == "refs/heads/main", "reviewed runtime provenance ref invalid")
    require(provenance["sourceRevision"] == pin["sourceRevision"], "reviewed runtime provenance revision invalid")
    require(provenance["subjectDigest"] == pin["manifestDigest"], "reviewed runtime provenance subject invalid")
    require(provenance["attestationDigest"] == REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_SLSA_DIGEST, "reviewed runtime first-tracer SLSA attestation drift")

    sbom = closed(
        pin["spdxSbom"],
        {"format", "predicateType", "repository", "gitRef", "sourceRevision", "subjectDigest", "attestationDigest"},
        "reviewed runtime SPDX SBOM",
    )
    require(sbom["format"] == "SPDX-2.3", "reviewed runtime SBOM format invalid")
    require(sbom["predicateType"] == "https://spdx.dev/Document/v2.3", "reviewed runtime SBOM predicate invalid")
    require(sbom["repository"] == "GiraeffleAeffle/stadtstack", "reviewed runtime SBOM repository invalid")
    require(sbom["gitRef"] == "refs/heads/main", "reviewed runtime SBOM ref invalid")
    require(sbom["sourceRevision"] == pin["sourceRevision"], "reviewed runtime SBOM revision invalid")
    require(sbom["subjectDigest"] == pin["manifestDigest"], "reviewed runtime SBOM subject invalid")
    require(sbom["attestationDigest"] == REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_SPDX_DIGEST, "reviewed runtime first-tracer SPDX attestation drift")

    receipt = closed(
        pin["anonymousPublicPullReceipt"],
        {
            "schemaVersion",
            "canonicalEncoding",
            "component",
            "imageRepository",
            "manifestDigest",
            "sourceRevision",
            "packageVisibility",
            "authContext",
            "authConfigCanonicalSha256",
            "resolverIdentity",
            "resolvedManifestDigest",
            "receiptDigest",
        },
        "reviewed runtime anonymous-public receipt",
    )
    require(receipt["schemaVersion"] == "stadtstack_reviewed_public_knowledge_anonymous_digest_pull_receipt_v1", "reviewed runtime receipt schema drift")
    require(receipt["canonicalEncoding"] == "canonical-json", "reviewed runtime receipt encoding invalid")
    require(receipt["component"] == pin["component"], "reviewed runtime receipt component invalid")
    require(receipt["imageRepository"] == pin["imageRepository"], "reviewed runtime receipt image invalid")
    require(receipt["manifestDigest"] == pin["manifestDigest"], "reviewed runtime receipt manifest invalid")
    require(receipt["sourceRevision"] == pin["sourceRevision"], "reviewed runtime receipt revision invalid")
    require(receipt["packageVisibility"] == "public", "reviewed runtime package visibility invalid")
    require(receipt["authContext"] == "clean-empty-auth-config", "reviewed runtime anonymous auth context invalid")
    require(receipt["authConfigCanonicalSha256"] == REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_AUTH_DIGEST, "reviewed runtime first-tracer anonymous auth drift")
    require(receipt["resolverIdentity"] == "oras-resolve-anonymous", "reviewed runtime resolver identity invalid")
    require(receipt["resolvedManifestDigest"] == pin["manifestDigest"], "reviewed runtime resolved digest invalid")
    require(receipt["receiptDigest"] == REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_RECEIPT_DIGEST, "reviewed runtime first-tracer receipt digest drift")
    require(pin["authorityBinding"] == "none", "reviewed runtime authority binding invalid")
    require(pin["deploymentEffect"] is False, "reviewed runtime deployment effect invalid")
    return pin


def verify_reviewed_public_knowledge_deployment(value: Any, runtime_pin: dict[str, Any]) -> dict[str, Any]:
    deployment = closed(value, {"apiVersion", "kind", "metadata", "spec"}, "reviewed-public-knowledge Deployment")
    require(deployment["apiVersion"] == "apps/v1" and deployment["kind"] == "Deployment", "reviewed runtime Deployment kind invalid")
    metadata = closed(deployment["metadata"], {"labels", "name", "namespace"}, "reviewed runtime Deployment metadata")
    require(metadata["name"] == REVIEWED_PUBLIC_KNOWLEDGE_NAME and metadata["namespace"] == REVIEWED_PUBLIC_KNOWLEDGE_NAMESPACE, "reviewed runtime Deployment identity invalid")
    require(metadata["labels"] == REVIEWED_PUBLIC_KNOWLEDGE_LABELS, "reviewed runtime Deployment labels invalid")
    spec = closed(
        deployment["spec"],
        {"replicas", "selector", "template"},
        "reviewed runtime Deployment spec",
    )
    require(spec["replicas"] == 1, "reviewed runtime replicas invalid")
    require(spec["selector"] == {"matchLabels": REVIEWED_PUBLIC_KNOWLEDGE_LABELS}, "reviewed runtime selector invalid")
    template = closed(spec["template"], {"metadata", "spec"}, "reviewed runtime Pod template")
    template_metadata = closed(template["metadata"], {"labels"}, "reviewed runtime Pod metadata")
    require(template_metadata["labels"] == REVIEWED_PUBLIC_KNOWLEDGE_LABELS, "reviewed runtime Pod labels invalid")
    pod = closed(
        template["spec"],
        {"automountServiceAccountToken", "containers", "restartPolicy", "securityContext"},
        "reviewed runtime Pod spec",
    )
    require(pod["automountServiceAccountToken"] is False, "reviewed runtime ServiceAccount token must be disabled")
    require(pod["restartPolicy"] == "Always", "reviewed runtime restart policy invalid")
    require(pod["securityContext"] == {
        "fsGroup": 65532,
        "runAsGroup": 65532,
        "runAsNonRoot": True,
        "runAsUser": 65532,
        "seccompProfile": {"type": "RuntimeDefault"},
    }, "reviewed runtime Pod security context invalid")
    containers = pod["containers"]
    require(isinstance(containers, list) and len(containers) == 1 and isinstance(containers[0], dict), "reviewed runtime container set invalid")
    container = containers[0]
    require(set(container) <= {"env", "image", "imagePullPolicy", "livenessProbe", "name", "ports", "readinessProbe", "securityContext", "startupProbe"}, "reviewed runtime container fields widened")
    require(container.get("name") == "reviewed-public-knowledge", "reviewed runtime container name invalid")
    require(container.get("image") == f"{runtime_pin['imageRepository']}@{runtime_pin['manifestDigest']}", "reviewed runtime immutable image binding invalid")
    require(container.get("imagePullPolicy") == "IfNotPresent", "reviewed runtime pull policy invalid")
    require(container.get("env") == [], "reviewed runtime must not accept mutable environment configuration")
    require(container.get("ports") == [{"containerPort": 8080, "name": "http", "protocol": "TCP"}], "reviewed runtime port invalid")
    require(container.get("securityContext") == {
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
        "readOnlyRootFilesystem": True,
    }, "reviewed runtime container security context invalid")

    def tcp_probe(failure_threshold: int, period_seconds: int) -> dict[str, Any]:
        return {
            "failureThreshold": failure_threshold,
            "periodSeconds": period_seconds,
            "successThreshold": 1,
            "tcpSocket": {"port": "http"},
            "timeoutSeconds": 3,
        }

    require(container.get("readinessProbe") == tcp_probe(3, 10), "reviewed runtime readiness probe must be non-HTTP")
    require(container.get("livenessProbe") == tcp_probe(3, 20), "reviewed runtime liveness probe must be non-HTTP")
    require(container.get("startupProbe") == tcp_probe(30, 2), "reviewed runtime startup probe must be non-HTTP")
    return deployment


def verify_reviewed_public_knowledge_service(value: Any) -> dict[str, Any]:
    service = closed(value, {"apiVersion", "kind", "metadata", "spec"}, "reviewed-public-knowledge Service")
    require(service["apiVersion"] == "v1" and service["kind"] == "Service", "reviewed runtime Service kind invalid")
    metadata = closed(service["metadata"], {"labels", "name", "namespace"}, "reviewed runtime Service metadata")
    require(metadata["name"] == REVIEWED_PUBLIC_KNOWLEDGE_NAME and metadata["namespace"] == REVIEWED_PUBLIC_KNOWLEDGE_NAMESPACE, "reviewed runtime Service identity invalid")
    require(metadata["labels"] == REVIEWED_PUBLIC_KNOWLEDGE_LABELS, "reviewed runtime Service labels invalid")
    require(service["spec"] == {
        "ports": [{"name": "http", "port": 18080, "protocol": "TCP", "targetPort": "http"}],
        "selector": REVIEWED_PUBLIC_KNOWLEDGE_LABELS,
        "type": "ClusterIP",
    }, "reviewed runtime Service boundary invalid")
    return service


def verify_reviewed_public_knowledge_network_policy(value: Any) -> dict[str, Any]:
    policy = closed(value, {"apiVersion", "kind", "metadata", "spec"}, "reviewed-public-knowledge NetworkPolicy")
    require(policy["apiVersion"] == "networking.k8s.io/v1" and policy["kind"] == "NetworkPolicy", "reviewed runtime NetworkPolicy kind invalid")
    metadata = closed(policy["metadata"], {"labels", "name", "namespace"}, "reviewed runtime NetworkPolicy metadata")
    require(metadata["name"] == REVIEWED_PUBLIC_KNOWLEDGE_NAME and metadata["namespace"] == REVIEWED_PUBLIC_KNOWLEDGE_NAMESPACE, "reviewed runtime NetworkPolicy identity invalid")
    require(metadata["labels"] == REVIEWED_PUBLIC_KNOWLEDGE_LABELS, "reviewed runtime NetworkPolicy labels invalid")
    require(policy["spec"] == {
        "egress": [],
        "ingress": [{
            "from": [{
                "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": REVIEWED_PUBLIC_KNOWLEDGE_NAMESPACE}},
                "podSelector": {"matchLabels": {
                    "app.kubernetes.io/component": "public-mecky",
                    "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
                }},
            }],
            "ports": [{"port": 8080, "protocol": "TCP"}],
        }],
        "podSelector": {"matchLabels": REVIEWED_PUBLIC_KNOWLEDGE_LABELS},
        "policyTypes": ["Ingress", "Egress"],
    }, "reviewed runtime NetworkPolicy boundary invalid")
    return policy


def verify_reviewed_public_knowledge_kustomization(root: Path) -> str:
    expected = (
        "apiVersion: kustomize.config.k8s.io/v1beta1\n"
        "kind: Kustomization\n"
        "resources:\n"
        "  - deployment.json\n"
        "  - service.json\n"
        "  - networkpolicy.json\n"
    )
    value = (root / f"{RENDER_ROOT}/reviewed-public-knowledge/kustomization.yaml").read_text()
    require(value == expected, "reviewed runtime Flux path widened or ingress added")
    return value


def verify_reviewed_public_knowledge(root: Path) -> dict[str, Any]:
    runtime_pin = verify_reviewed_public_knowledge_runtime_pin(load_json(root / f"{RENDER_ROOT}/reviewed-public-knowledge/runtime-pin.json"))
    deployment = verify_reviewed_public_knowledge_deployment(load_json(root / f"{RENDER_ROOT}/reviewed-public-knowledge/deployment.json"), runtime_pin)
    service = verify_reviewed_public_knowledge_service(load_json(root / f"{RENDER_ROOT}/reviewed-public-knowledge/service.json"))
    network_policy = verify_reviewed_public_knowledge_network_policy(load_json(root / f"{RENDER_ROOT}/reviewed-public-knowledge/networkpolicy.json"))
    kustomization = verify_reviewed_public_knowledge_kustomization(root)
    return {
        "deployment": deployment,
        "service": service,
        "networkPolicy": network_policy,
        "kustomization": kustomization,
        "runtimePin": runtime_pin,
    }


def verify_deployment(root: Path, component: str, head: dict[str, Any], reviewed_knowledge: bool = False) -> dict[str, Any]:
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
            "MECKY_CHAT_PORT": "18084",
            "MECKY_CHAT_BIND_HOST": "0.0.0.0",
            "MECKY_CHAT_PER_MINUTE": "10",
            "MECKY_CHAT_PER_DAY": "100",
        }
        if not reviewed_knowledge:
            expected_chat.update({
                "STADTSTACK_E2E_MODE": "synthetic-reviewed",
                "STADTSTACK_E2E_SYNTHETIC_EVIDENCE_ALLOWED": "true",
            })
        else:
            for forbidden in LEGACY_SYNTHETIC_EVIDENCE_ENV_NAMES:
                require(forbidden not in by_name, f"public-mecky legacy synthetic evidence field present: {forbidden}")
            require(by_name.get("STADTSTACK_PUBLIC_BASE_URL") == {
                "name": "STADTSTACK_PUBLIC_BASE_URL",
                "value": REVIEWED_PUBLIC_KNOWLEDGE_BASE_URL,
            }, "public-mecky reviewed knowledge base URL invalid")
            require(by_name.get("MECKY_REVIEWED_SOURCE_KINDS") == {
                "name": "MECKY_REVIEWED_SOURCE_KINDS",
                "value": REVIEWED_PUBLIC_KNOWLEDGE_SOURCE_KINDS,
            }, "public-mecky reviewed source ordering invalid")
            for item in env:
                value_from = item.get("valueFrom", {}) if isinstance(item, dict) else {}
                config_map = value_from.get("configMapKeyRef", {}) if isinstance(value_from, dict) else {}
                require(config_map.get("name") != "reviewed-evidence", "public-mecky legacy synthetic evidence ConfigMap present")
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


def expected_public_mecky_network_policy(reviewed_egress: bool) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "ingress": [{
            "from": [{
                "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "stadtstack-roebel-web-preview"}},
                "podSelector": {"matchLabels": {"app.kubernetes.io/name": "roebel-web-presentation"}},
            }],
            "ports": [{"port": 18084, "protocol": "TCP"}],
        }],
        "podSelector": {"matchLabels": PUBLIC_MECKY_LABELS},
        "policyTypes": ["Ingress"],
    }
    if reviewed_egress:
        spec = {
            "egress": [{
                "to": [{
                    "namespaceSelector": {"matchLabels": {
                        "kubernetes.io/metadata.name": REVIEWED_PUBLIC_KNOWLEDGE_NAMESPACE,
                    }},
                    "podSelector": {"matchLabels": PUBLIC_MECKY_REVIEWED_EGRESS_DESTINATION_LABELS},
                }],
                "ports": [{"port": 8080, "protocol": "TCP"}],
            }],
            **spec,
            "policyTypes": ["Ingress", "Egress"],
        }
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "labels": PUBLIC_MECKY_NETWORK_POLICY_LABELS,
            "name": "public-mecky-chat-from-web",
            "namespace": "stadtstack-roebel-staging-lab",
        },
        "spec": spec,
    }


def verify_public_mecky_network_policy(
    root: Path,
    reviewed_knowledge: bool,
) -> tuple[dict[str, Any], bool]:
    policy = load_json(root / RENDER_ROOT / "public-mecky/networkpolicy.json")
    legacy = expected_public_mecky_network_policy(False)
    reviewed = expected_public_mecky_network_policy(True)
    require(policy in (legacy, reviewed), "Public Mecky NetworkPolicy drift")
    reviewed_egress = policy == reviewed
    require(
        not reviewed_egress or reviewed_knowledge,
        "Public Mecky reviewed-runtime egress requires the complete reviewed runtime render",
    )
    return policy, reviewed_egress


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
    render_file_set = verify_repository_file_set(root)
    verify_contract(root)
    verify_case_staging_topology_with_protected_policy(root)
    verify_case_runtime_contract_with_protected_policy(root)
    verify_case_recovery_composition_contract_with_protected_policy(root)
    verify_case_image_resource_inventory_contract_with_protected_policy(root)
    head = verify_head(load_json(root / RENDER_ROOT / "head.json"), "head")
    integrity = closed(load_json(root / RENDER_ROOT / "integrity.json"), {"schemaVersion", "releaseSetDigest", "desiredRenderSha256", "networkBoundaryMigrationSha256"}, "integrity")
    require(integrity["schemaVersion"] == RENDER_SCHEMA, "integrity schema drift")
    require(integrity["releaseSetDigest"] == head["releaseSetDigest"], "integrity release binding invalid")
    require(isinstance(integrity["desiredRenderSha256"], str) and SHA256.fullmatch(integrity["desiredRenderSha256"]), "integrity checksum invalid")
    reviewed_knowledge = render_file_set == "reviewed-public-knowledge"
    deployments = {component: verify_deployment(root, component, head, reviewed_knowledge) for component in COMPONENT_ORDER}
    service = verify_public_mecky_service(root)
    network_policy, public_mecky_reviewed_egress = verify_public_mecky_network_policy(
        root,
        reviewed_knowledge,
    )
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
    checksum_payload: dict[str, Any] = {"nextEnvironmentHead": head, "objects": objects}
    reviewed_objects = None
    if reviewed_knowledge:
        reviewed_objects = verify_reviewed_public_knowledge(root)
        checksum_payload["reviewedPublicKnowledge"] = reviewed_objects
    require(integrity["desiredRenderSha256"] == digest(checksum_payload), "reviewed render checksum mismatch")
    require(integrity["networkBoundaryMigrationSha256"] == digest(migration), "network-boundary migration checksum mismatch")
    verify_kustomizations(root)
    live = verify_live_preconditions(root, head)
    return {
        "root": root,
        "head": head,
        "integrity": integrity,
        "objects": objects,
        "deployments": deployments,
        "migration": migration,
        "live": live,
        "renderFileSet": render_file_set,
        "publicMeckyReviewedEgress": public_mecky_reviewed_egress,
        "reviewedPublicKnowledge": reviewed_objects,
    }


def verify_transition(candidate: dict[str, Any], base: dict[str, Any]) -> None:
    candidate_root: Path = candidate["root"]
    base_root: Path = base["root"]
    require(
        not (base["renderFileSet"] == "reviewed-public-knowledge" and candidate["renderFileSet"] == "current"),
        "reviewed-public-knowledge render set cannot regress to the legacy set",
    )
    require(
        not (base["publicMeckyReviewedEgress"] and not candidate["publicMeckyReviewedEgress"]),
        "Public Mecky reviewed-runtime egress cannot regress",
    )

    if base["renderFileSet"] == "current" and candidate["renderFileSet"] == "reviewed-public-knowledge":
        require(candidate["head"] == base["head"], "reviewed-public-knowledge activation must preserve the Release Set head")
        allowed_existing_changes = {
            f"{RENDER_ROOT}/integrity.json",
            f"{RENDER_ROOT}/public-mecky/deployment.json",
        }
        for relative in EXPECTED_FILES:
            if relative in allowed_existing_changes:
                continue
            require(
                (candidate_root / relative).read_bytes() == (base_root / relative).read_bytes(),
                f"reviewed-public-knowledge activation changed existing file: {relative}",
            )

        expected_public = copy.deepcopy(base["deployments"]["public-mecky"])
        expected_env = []
        base_env = expected_public["spec"]["template"]["spec"]["containers"][0]["env"]
        base_names = [item["name"] for item in base_env]
        require(LEGACY_SYNTHETIC_EVIDENCE_ENV_NAMES <= set(base_names), "protected base lacks the complete legacy synthetic environment")
        require("MECKY_REVIEWED_SOURCE_KINDS" not in base_names, "protected base already contains reviewed source ordering")
        for item in base_env:
            if item["name"] in LEGACY_SYNTHETIC_EVIDENCE_ENV_NAMES:
                continue
            transformed = copy.deepcopy(item)
            if transformed["name"] == "STADTSTACK_PUBLIC_BASE_URL":
                transformed["value"] = REVIEWED_PUBLIC_KNOWLEDGE_BASE_URL
            expected_env.append(transformed)
        expected_env.append({
            "name": "MECKY_REVIEWED_SOURCE_KINDS",
            "value": REVIEWED_PUBLIC_KNOWLEDGE_SOURCE_KINDS,
        })
        expected_public["spec"]["template"]["spec"]["containers"][0]["env"] = expected_env
        require(
            candidate["deployments"]["public-mecky"] == expected_public,
            "reviewed-public-knowledge activation Public Mecky transformation drift",
        )
        return

    if (
        base["renderFileSet"] == "reviewed-public-knowledge"
        and candidate["renderFileSet"] == "reviewed-public-knowledge"
        and candidate["head"] == base["head"]
        and not base["publicMeckyReviewedEgress"]
        and candidate["publicMeckyReviewedEgress"]
    ):
        allowed_changes = {
            f"{RENDER_ROOT}/integrity.json",
            f"{RENDER_ROOT}/public-mecky/networkpolicy.json",
            "scripts/render-release-set-promotion.py",
            "scripts/test_verify_reviewed_render.py",
            "scripts/verify-reviewed-render.py",
        }
        for relative in FUTURE_EXPECTED_FILES:
            if relative in allowed_changes:
                continue
            require(
                (candidate_root / relative).read_bytes() == (base_root / relative).read_bytes(),
                f"reviewed-runtime egress activation changed unrelated file: {relative}",
            )
        return

    require(
        candidate["publicMeckyReviewedEgress"] == base["publicMeckyReviewedEgress"],
        "Public Mecky reviewed-runtime egress must be a standalone exact transition",
    )

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
    for component in changed:
        require(
            candidate_components[component]["sourceRevision"]
            == candidate["head"]["promotionRevision"],
            f"{component} changed component must bind to the promotion revision",
        )
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
        "renderFileSet": candidate["renderFileSet"],
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
