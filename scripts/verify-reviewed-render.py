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
import ipaddress
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
IMMUTABLE_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
RFC3339_UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


def load_participant_gateway_policy_module():
    """Load policy beside this protected verifier, never from candidate data."""
    path = Path(__file__).with_name("staging_participant_gateway_policy.py")
    spec = importlib.util.spec_from_file_location("protected_participant_gateway_policy", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("protected participant gateway policy unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PARTICIPANT_POLICY = load_participant_gateway_policy_module()

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
    ".github/workflows/staging-participant-gateway-activation.yml",
    ".gitignore",
    "LICENSE",
    "README.md",
    "contracts/stadtstack-case-image-resource-inventory-contract.json",
    "contracts/stadtstack-case-recovery-composition-contract.json",
    "contracts/stadtstack-case-runtime-contract.json",
    "policy/repository-contract.json",
    "policy/staging-participant-gateway-activation-policy.json",
    "scripts/render-release-set-promotion.py",
    "scripts/activate-staging-participant-gateway.py",
    "scripts/staging_participant_gateway_policy.py",
    "scripts/test_automatic_promotion_workflow.py",
    "scripts/test_activate_staging_participant_gateway.py",
    "scripts/test_staging_participant_gateway_policy.py",
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

# The participant gateway is deliberately a fourth, independently pinned
# staging capability.  It is never folded into the normal Web/Mecky release
# set: the gateway has a writer capability while the public Web must remain
# read-only.  The complete subtree is admitted only alongside the reviewed
# public-knowledge runtime, and may later be composed with (but never hidden
# inside) the signed-Nostr tracer.
PARTICIPANT_GATEWAY_ROOT = PARTICIPANT_POLICY.GATEWAY_ROOT
PARTICIPANT_GATEWAY_FILES = set(PARTICIPANT_POLICY.ALL_RENDER_FILES)
PARTICIPANT_GATEWAY_EXPECTED_FILES = FUTURE_EXPECTED_FILES | PARTICIPANT_GATEWAY_FILES
PARTICIPANT_GATEWAY_NAME = PARTICIPANT_POLICY.GATEWAY_NAME
PARTICIPANT_GATEWAY_NAMESPACE = PARTICIPANT_POLICY.GATEWAY_NAMESPACE
PARTICIPANT_GATEWAY_PORT = PARTICIPANT_POLICY.GATEWAY_PORT
PARTICIPANT_GATEWAY_IMAGE = PARTICIPANT_POLICY.STATIC_ACTIVATION_POLICY["productPins"]["imageRepository"]
PARTICIPANT_GATEWAY_WORKFLOW = PARTICIPANT_POLICY.STATIC_ACTIVATION_POLICY["productPins"]["workflowIdentity"]
PARTICIPANT_GATEWAY_ORIGIN = PARTICIPANT_POLICY.STATIC_ACTIVATION_POLICY["endpoints"]["browserOrigin"]
PARTICIPANT_GATEWAY_LABELS = PARTICIPANT_POLICY.GATEWAY_LABELS
PARTICIPANT_GATEWAY_CONFIG_SECRET = PARTICIPANT_POLICY.STATIC_ACTIVATION_POLICY["runtime"]["secretReferences"]["config"]["name"]
PARTICIPANT_GATEWAY_RUNTIME_SECRET = PARTICIPANT_POLICY.STATIC_ACTIVATION_POLICY["runtime"]["secretReferences"]["runtime"]["name"]
PARTICIPANT_GATEWAY_FLUX_NAMESPACE = PARTICIPANT_POLICY.FLUX_NAMESPACE
PARTICIPANT_GATEWAY_FLUX_SOURCE_NAME = PARTICIPANT_POLICY.FLUX_SOURCE_NAME
PARTICIPANT_GATEWAY_FLUX_KUSTOMIZATION = "roebel-staging-participant-gateway"
PARTICIPANT_GATEWAY_FLUX_SERVICE_ACCOUNT = "roebel-staging-participant-gateway-reconciler"
PARTICIPANT_GATEWAY_FLUX_ROLE = "roebel-staging-participant-gateway-reconciler"
PARTICIPANT_GATEWAY_FLUX_ROLE_BINDING = "roebel-staging-participant-gateway-reconciler"
PARTICIPANT_GATEWAY_WEB_FLUX_KUSTOMIZATION = "roebel-web-presentation"
PARTICIPANT_GATEWAY_WEB_FLUX_SERVICE_ACCOUNT = "roebel-web-reconciler"
PARTICIPANT_GATEWAY_DNS_TLS_EVIDENCE_SCHEMA = "roebel_staging_participant_gateway_dns_tls_evidence_v1"
PARTICIPANT_GATEWAY_ACTIVATION_RECEIPT_SCHEMA = "roebel_staging_participant_gateway_activation_receipt_v1"
PARTICIPANT_GATEWAY_ANONYMOUS_EMPTY_AUTH_CONFIG_SHA256 = (
    "sha256:e58c7564b64e92c6c8ebc3cb296e644b4f2409ace8882621e888924c0c598753"
)
# This deliberately inert, policy-owned template is the only permitted
# activation operation.  It is hashed into the approved evidence; a render PR
# cannot replace it with a different command or use its own receipt as proof.
PARTICIPANT_GATEWAY_VERIFICATION_TIME_OVERRIDE: datetime | None = None

def participant_gateway_activation_script_sha256() -> str:
    """Bind policy evidence to the committed guarded planner bytes."""
    return bytes_digest(Path(__file__).with_name("activate-staging-participant-gateway.py").read_bytes())


# Signed Nostr is a third, closed render shape layered on the already-admitted
# reviewed-public-knowledge render.  The files are deliberately not present in
# this policy/bootstrap change: a later activation must add all sixteen in one
# reviewed transaction, never stage one workload or relay independently.
SIGNED_NOSTR_ROOT = f"{RENDER_ROOT}/signed-nostr"
SIGNED_NOSTR_RUNTIME_PIN = f"{SIGNED_NOSTR_ROOT}/runtime-pin.json"
SIGNED_NOSTR_COMPONENTS = ("workbench", "citizen-relay", "agent-relay")
SIGNED_NOSTR_COMPONENT_FILES = {
    f"{SIGNED_NOSTR_ROOT}/{component}/{kind}"
    for component in SIGNED_NOSTR_COMPONENTS
    for kind in ("deployment.json", "service.json", "networkpolicy.json", "kustomization.yaml")
}
SIGNED_NOSTR_GNOSIS_PROXY_FILES = {
    f"{SIGNED_NOSTR_ROOT}/workbench/gnosis-proxy-deployment.json",
    f"{SIGNED_NOSTR_ROOT}/workbench/gnosis-proxy-service.json",
    f"{SIGNED_NOSTR_ROOT}/workbench/gnosis-proxy-networkpolicy.json",
}
SIGNED_NOSTR_FILES = (
    SIGNED_NOSTR_COMPONENT_FILES
    | SIGNED_NOSTR_GNOSIS_PROXY_FILES
    | {SIGNED_NOSTR_RUNTIME_PIN}
)
SIGNED_NOSTR_EXPECTED_FILES = FUTURE_EXPECTED_FILES | SIGNED_NOSTR_FILES
SIGNED_NOSTR_PARTICIPANT_GATEWAY_EXPECTED_FILES = SIGNED_NOSTR_EXPECTED_FILES | PARTICIPANT_GATEWAY_FILES
SIGNED_NOSTR_MUTABLE_EXISTING_FILES = {
    f"{RENDER_ROOT}/integrity.json",
    f"{RENDER_ROOT}/web/ingress.json",
    f"{RENDER_ROOT}/public-mecky/networkpolicy.json",
    f"{RENDER_ROOT}/network-boundary-migration.json",
}
SIGNED_NOSTR_NAMESPACE = "stadtstack-roebel-staging-lab"
SIGNED_NOSTR_WEB_NAMESPACE = "stadtstack-roebel-web-preview"
SIGNED_NOSTR_WORKFLOW = (
    "https://github.com/GiraeffleAeffle/Roebel-App/"
    ".github/workflows/roebel-e2e-runtime-publish.yml@refs/heads/main"
)
SIGNED_NOSTR_IMAGES = {
    "workbench": "ghcr.io/giraeffleaeffle/roebel-e2e-workbench",
    "citizen-relay": "ghcr.io/giraeffleaeffle/roebel-staging-relay",
    "agent-relay": "ghcr.io/giraeffleaeffle/roebel-staging-relay",
}
SIGNED_NOSTR_NAMES = {
    "workbench": "roebel-staging-workbench",
    "citizen-relay": "citizen-relay",
    "agent-relay": "agent-relay",
}
SIGNED_NOSTR_PORTS = {"workbench": 18083, "citizen-relay": 18081, "agent-relay": 18081}
SIGNED_NOSTR_GNOSIS_PROXY_NAME = "gnosis-private-rpc"
SIGNED_NOSTR_GNOSIS_PROXY_PORT = 8545
SIGNED_NOSTR_GNOSIS_UPSTREAM_HOST = "rpc.gnosischain.com"
SIGNED_NOSTR_GNOSIS_UPSTREAM_PORT = 443
SIGNED_NOSTR_GNOSIS_UPSTREAM_IPV4_CIDR = "34.111.230.52/32"
SIGNED_NOSTR_GNOSIS_ALLOWED_METHODS = (
    "eth_blockNumber",
    "eth_call",
    "eth_chainId",
    "eth_getCode",
)
SIGNED_NOSTR_FLUX_NAMESPACE = "flux-roebel-staging"
SIGNED_NOSTR_FLUX_SOURCE_NAME = "roebel-staging-operations"
SIGNED_NOSTR_PUBLISHER_COMPONENT_ORDER = ("roebel-e2e-workbench", "roebel-staging-relay")
SIGNED_NOSTR_ANONYMOUS_DIGEST_PULL_RECEIPT_SCHEMA = (
    "roebel_signed_nostr_anonymous_digest_pull_receipt_v1"
)
SIGNED_NOSTR_CLEAN_EMPTY_AUTH_CONFIG_SHA256 = (
    "sha256:ec21c035eccb78eb5ca20ec95628eb351633621e09a130ac8d7e663714d40c7a"
)
SIGNED_NOSTR_ACTIVATION_EVIDENCE_SCHEMA = "roebel_signed_nostr_activation_evidence_v1"
SIGNED_NOSTR_BOOTSTRAP_RECEIPT_SCHEMA = "roebel_signed_nostr_bootstrap_cas_receipt_v1"
SIGNED_NOSTR_LIVE_RECHECK_SCHEMA = "roebel_signed_nostr_activation_live_recheck_v1"
SIGNED_NOSTR_ROLLBACK_CONTRACT_SCHEMA = "roebel_signed_nostr_live_rollback_contract_v1"
SIGNED_NOSTR_DEACTIVATION_EVIDENCE_SCHEMA = "roebel_signed_nostr_deactivation_evidence_v1"
SIGNED_NOSTR_DNS_TLS_EVIDENCE_SCHEMA = "roebel_signed_nostr_dns_tls_evidence_v1"
SIGNED_NOSTR_ACTIVATION_COMPONENT_ORDER = SIGNED_NOSTR_PUBLISHER_COMPONENT_ORDER
SIGNED_NOSTR_FLUX_BINDING_ORDER = ("workbench", "citizen-relay", "agent-relay")
SIGNED_NOSTR_FLUX_PATHS = {
    "workbench": f"./{SIGNED_NOSTR_ROOT}/workbench",
    "citizen-relay": f"./{SIGNED_NOSTR_ROOT}/citizen-relay",
    "agent-relay": f"./{SIGNED_NOSTR_ROOT}/agent-relay",
}
SIGNED_NOSTR_FLUX_NAMESPACES = {
    "workbench": SIGNED_NOSTR_WEB_NAMESPACE,
    "citizen-relay": SIGNED_NOSTR_NAMESPACE,
    "agent-relay": SIGNED_NOSTR_NAMESPACE,
}
SIGNED_NOSTR_FLUX_KUSTOMIZATION_NAMES = {
    component: f"roebel-staging-signed-nostr-{component}"
    for component in SIGNED_NOSTR_FLUX_BINDING_ORDER
}
SIGNED_NOSTR_FLUX_SERVICE_ACCOUNT_NAMES = {
    component: f"roebel-signed-nostr-{component}-reconciler"
    for component in SIGNED_NOSTR_FLUX_BINDING_ORDER
}

# This policy constrains the prospective Gnosis address and Flux identities but
# deliberately contains no actual live receipt. A later, separately reviewed
# policy may set this constant to exactly one complete closed evidence record.
# It is intentionally None in this commit, which blocks every signed-Nostr
# render even if the candidate contains a well-formed record.
SIGNED_NOSTR_APPROVED_ACTIVATION_EVIDENCE: None | dict[str, Any] = None

# Deactivation is an independently reviewed live operation.  A future policy
# change must pin one completed teardown receipt here before a signed-Nostr
# render may be removed.  Keeping this closed prevents a Git-only rollback from
# silently orphaning active workloads or Flux identities.
SIGNED_NOSTR_APPROVED_DEACTIVATION_EVIDENCE: None | dict[str, Any] = None

# Tests may replace this protected-module value with one explicit UTC instant.
# Candidate data has no way to select the clock.  Production admission always
# uses the verifier host's current UTC time.
SIGNED_NOSTR_VERIFICATION_TIME_OVERRIDE: datetime | None = None

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


def bytes_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def utc_timestamp(value: Any, label: str) -> datetime:
    require(isinstance(value, str) and RFC3339_UTC.fullmatch(value), f"{label} timestamp invalid")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise VerificationError(f"{label} timestamp invalid") from error


def duration_seconds(start: datetime, end: datetime) -> int:
    return int((end - start).total_seconds())


def signed_nostr_verification_time() -> datetime:
    value = SIGNED_NOSTR_VERIFICATION_TIME_OVERRIDE
    if value is None:
        return datetime.now(timezone.utc).replace(microsecond=0)
    require(
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() == timezone.utc.utcoffset(value),
        "signed-Nostr verification clock override must be UTC",
    )
    return value.replace(microsecond=0)


def participant_gateway_verification_time() -> datetime:
    value = PARTICIPANT_GATEWAY_VERIFICATION_TIME_OVERRIDE
    if value is None:
        return datetime.now(timezone.utc).replace(microsecond=0)
    require(
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() == timezone.utc.utcoffset(value),
        "participant gateway verification clock override must be UTC",
    )
    return value.replace(microsecond=0)


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
        # The verifier is itself imported by the test suite.  Interpreter
        # bytecode is neither reviewed render input nor a repository artifact.
        if "__pycache__" in relative.parts or relative.suffix == ".pyc":
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
    if actual == PARTICIPANT_GATEWAY_EXPECTED_FILES:
        return "reviewed-public-knowledge-participant-gateway"
    if actual == SIGNED_NOSTR_EXPECTED_FILES:
        return "signed-nostr"
    if actual == SIGNED_NOSTR_PARTICIPANT_GATEWAY_EXPECTED_FILES:
        return "signed-nostr-participant-gateway"
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


def verify_participant_gateway_static_policy(root: Path, render_file_set: str) -> dict[str, Any]:
    """Treat candidate JSON as data under the protected sibling module."""
    try:
        value = PARTICIPANT_POLICY.validate_activation_policy(
            load_json(root / PARTICIPANT_POLICY.POLICY_PATH),
        )
        if render_file_set in {
            "reviewed-public-knowledge-participant-gateway",
            "signed-nostr-participant-gateway",
        }:
            PARTICIPANT_POLICY.assert_activation_ready(value)
        return value
    except PARTICIPANT_POLICY.PolicyError as error:
        raise VerificationError(str(error)) from error


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
        "signedNostrBoundary": {
            "activationEvidence": "pending-separate-review",
            "components": ["workbench", "citizen-relay", "agent-relay"],
            "normalReleaseSetPromotionMayChange": False,
            "publisherPinCanonicalChecksumRequired": True,
            "publisherPinSchema": "roebel_e2e_runtime_pin_v1",
            "renderRoot": SIGNED_NOSTR_ROOT,
            "runtimePin": SIGNED_NOSTR_RUNTIME_PIN,
            "schemaVersion": "roebel_signed_nostr_activation_render_pin_v1",
        },
        "stagingParticipantGatewayBoundary": {
            "activationPolicy": PARTICIPANT_POLICY.POLICY_PATH,
            "activationReady": True,
            "component": "staging-participant-gateway",
            "exactGatewayPaths": list(PARTICIPANT_POLICY.ROUTES),
            "methodPathMatrix": {
                "GET": [PARTICIPANT_POLICY.ROUTES[0]],
                "OPTIONS": list(PARTICIPANT_POLICY.ROUTES),
                "POST": list(PARTICIPANT_POLICY.POST_ROUTES),
            },
            "normalReleaseSetPromotionMayChange": False,
            "renderRoot": PARTICIPANT_GATEWAY_ROOT,
            "runtimePin": f"{PARTICIPANT_GATEWAY_ROOT}/runtime-pin.json",
            "schemaVersion": "roebel_staging_participant_gateway_runtime_pin_v2",
            "singleReplicaRequired": True,
            "trustedLiveFacts": "protected-local-runner-out-of-band-only",
            "workbenchIngressRenderRoot": PARTICIPANT_POLICY.WORKBENCH_INGRESS_ROOT,
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


def signed_nostr_labels(component: str) -> dict[str, str]:
    require(component in SIGNED_NOSTR_COMPONENTS, "signed-Nostr component invalid")
    return {
        "app.kubernetes.io/component": f"signed-nostr-{component}",
        "app.kubernetes.io/name": SIGNED_NOSTR_NAMES[component],
        "app.kubernetes.io/part-of": "roebel-signed-nostr-staging",
        "stadtstack.io/authority": "none",
    }


def signed_nostr_namespace(component: str) -> str:
    return SIGNED_NOSTR_WEB_NAMESPACE if component == "workbench" else SIGNED_NOSTR_NAMESPACE


def signed_nostr_pod_security_context() -> dict[str, Any]:
    return {
        "fsGroup": 65532,
        "runAsGroup": 65532,
        "runAsNonRoot": True,
        "runAsUser": 65532,
        "seccompProfile": {"type": "RuntimeDefault"},
    }


def signed_nostr_container_security_context() -> dict[str, Any]:
    return {
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
        "readOnlyRootFilesystem": True,
    }


def signed_nostr_gnosis_private_proxy_labels(name: str = SIGNED_NOSTR_GNOSIS_PROXY_NAME) -> dict[str, str]:
    return {
        "app.kubernetes.io/component": "gnosis-rpc-private-proxy",
        "app.kubernetes.io/name": name,
        "app.kubernetes.io/part-of": "roebel-signed-nostr-staging",
        "stadtstack.io/authority": "none",
    }


def expected_signed_nostr_gnosis_private_proxy_service() -> dict[str, Any]:
    """The only proxy shape a future activation record may claim.

    This is a ClusterIP service in the workbench namespace.  It deliberately
    contains no public address, external name, load balancer, IP block, or
    secret value.  The later protected exact-record constant selects the one
    real object; this function constrains its materialized shape first.
    """
    labels = signed_nostr_gnosis_private_proxy_labels()
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"labels": labels, "name": SIGNED_NOSTR_GNOSIS_PROXY_NAME, "namespace": SIGNED_NOSTR_WEB_NAMESPACE},
        "spec": {
            "ports": [{"name": "http", "port": SIGNED_NOSTR_GNOSIS_PROXY_PORT, "protocol": "TCP", "targetPort": "http"}],
            "selector": labels,
            "type": "ClusterIP",
        },
    }


def expected_signed_nostr_gnosis_private_proxy_deployment(image: str) -> dict[str, Any]:
    labels = signed_nostr_gnosis_private_proxy_labels()
    environment = [
        {"name": "ROEBEL_RUNTIME_ROLE", "value": "gnosis-rpc-proxy"},
        {"name": "GNOSIS_PROXY_BIND_HOST", "value": "0.0.0.0"},
        {"name": "GNOSIS_PROXY_PORT", "value": str(SIGNED_NOSTR_GNOSIS_PROXY_PORT)},
        {"name": "GNOSIS_PROXY_UPSTREAM_URL", "value": f"https://{SIGNED_NOSTR_GNOSIS_UPSTREAM_HOST}"},
        {"name": "GNOSIS_PROXY_EXPECTED_CHAIN_ID", "value": "0x64"},
        {"name": "GNOSIS_PROXY_ALLOWED_METHODS", "value": ",".join(SIGNED_NOSTR_GNOSIS_ALLOWED_METHODS)},
        {"name": "GNOSIS_PROXY_MAX_BODY_BYTES", "value": "131072"},
        {"name": "GNOSIS_PROXY_UPSTREAM_TIMEOUT_MS", "value": "5000"},
        {"name": "GNOSIS_PROXY_MAX_CONCURRENT", "value": "16"},
    ]
    container = {
        "env": environment,
        "image": image,
        "imagePullPolicy": "IfNotPresent",
        "livenessProbe": {"failureThreshold": 3, "httpGet": {"path": "/healthz", "port": "http", "scheme": "HTTP"}, "periodSeconds": 20, "successThreshold": 1, "timeoutSeconds": 3},
        "name": SIGNED_NOSTR_GNOSIS_PROXY_NAME,
        "ports": [{"containerPort": SIGNED_NOSTR_GNOSIS_PROXY_PORT, "name": "http", "protocol": "TCP"}],
        "readinessProbe": {"failureThreshold": 3, "httpGet": {"path": "/readyz", "port": "http", "scheme": "HTTP"}, "periodSeconds": 10, "successThreshold": 1, "timeoutSeconds": 6},
        "resources": {"limits": {"cpu": "150m", "ephemeral-storage": "64Mi", "memory": "96Mi"}, "requests": {"cpu": "10m", "ephemeral-storage": "32Mi", "memory": "32Mi"}},
        "securityContext": signed_nostr_container_security_context(),
        "startupProbe": {"failureThreshold": 30, "httpGet": {"path": "/readyz", "port": "http", "scheme": "HTTP"}, "periodSeconds": 2, "successThreshold": 1, "timeoutSeconds": 6},
    }
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"labels": labels, "name": SIGNED_NOSTR_GNOSIS_PROXY_NAME, "namespace": SIGNED_NOSTR_WEB_NAMESPACE},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": labels},
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "automountServiceAccountToken": False,
                    "containers": [container],
                    "restartPolicy": "Always",
                    "securityContext": signed_nostr_pod_security_context(),
                },
            },
        },
    }


def expected_signed_nostr_gnosis_private_proxy_network_policy() -> dict[str, Any]:
    labels = signed_nostr_gnosis_private_proxy_labels()
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"labels": labels, "name": SIGNED_NOSTR_GNOSIS_PROXY_NAME, "namespace": SIGNED_NOSTR_WEB_NAMESPACE},
        "spec": {
            "egress": [
                {
                    "to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}, "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}],
                    "ports": [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}],
                },
                {
                    "to": [{"ipBlock": {"cidr": SIGNED_NOSTR_GNOSIS_UPSTREAM_IPV4_CIDR}}],
                    "ports": [{"port": SIGNED_NOSTR_GNOSIS_UPSTREAM_PORT, "protocol": "TCP"}],
                },
            ],
            "ingress": [{
                "from": [{"podSelector": {"matchLabels": signed_nostr_labels("workbench")}}],
                "ports": [{"port": SIGNED_NOSTR_GNOSIS_PROXY_PORT, "protocol": "TCP"}],
            }],
            "podSelector": {"matchLabels": labels},
            "policyTypes": ["Ingress", "Egress"],
        },
    }


def expected_signed_nostr_workbench_network_policy() -> dict[str, Any]:
    """Canonical workbench policy with one private Gnosis hop."""
    workbench_labels = signed_nostr_labels("workbench")
    dns_egress = {
        "to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}, "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}],
        "ports": [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}],
    }
    relay_egress = [{
        "to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": SIGNED_NOSTR_NAMESPACE}}, "podSelector": {"matchLabels": signed_nostr_labels(relay)}}],
        "ports": [{"port": 18081, "protocol": "TCP"}],
    } for relay in ("citizen-relay", "agent-relay")]
    egress = [
        dns_egress,
        *relay_egress,
        {
            "to": [{"podSelector": {"matchLabels": signed_nostr_gnosis_private_proxy_labels()}}],
            "ports": [{"port": SIGNED_NOSTR_GNOSIS_PROXY_PORT, "protocol": "TCP"}],
        },
    ]
    return {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"labels": workbench_labels, "name": SIGNED_NOSTR_NAMES["workbench"], "namespace": SIGNED_NOSTR_WEB_NAMESPACE},
        "spec": {
            "egress": egress,
            "ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "ingress-system"}}}], "ports": [{"port": 18083, "protocol": "TCP"}]}],
            "podSelector": {"matchLabels": workbench_labels}, "policyTypes": ["Ingress", "Egress"],
        },
    }


def signed_nostr_flux_labels(component: str) -> dict[str, str]:
    require(component in SIGNED_NOSTR_FLUX_BINDING_ORDER, "signed-Nostr Flux component invalid")
    return {
        "app.kubernetes.io/component": f"signed-nostr-{component}-reconciler",
        "app.kubernetes.io/part-of": "roebel-signed-nostr-staging",
        "stadtstack.io/authority": "none",
    }


def signed_nostr_flux_resource_names(component: str) -> list[str]:
    names = [SIGNED_NOSTR_NAMES[component]]
    if component == "workbench":
        names.append(SIGNED_NOSTR_GNOSIS_PROXY_NAME)
    return sorted(names)


def expected_signed_nostr_flux_objects(
    component: str,
    *,
    suspended: bool = True,
) -> dict[str, dict[str, Any]]:
    target_namespace = SIGNED_NOSTR_FLUX_NAMESPACES[component]
    labels = signed_nostr_flux_labels(component)
    kustomization_name = SIGNED_NOSTR_FLUX_KUSTOMIZATION_NAMES[component]
    service_account_name = SIGNED_NOSTR_FLUX_SERVICE_ACCOUNT_NAMES[component]
    resource_names = signed_nostr_flux_resource_names(component)
    health_checks = [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "name": name,
            "namespace": target_namespace,
        }
        for name in resource_names
    ]
    kustomization_spec: dict[str, Any] = {
        "deletionPolicy": "Orphan",
        "force": False,
        "healthChecks": health_checks,
        "interval": "1m",
        "path": SIGNED_NOSTR_FLUX_PATHS[component],
        "prune": False,
        "retryInterval": "30s",
        "serviceAccountName": service_account_name,
        "sourceRef": {
            "kind": "GitRepository",
            "name": SIGNED_NOSTR_FLUX_SOURCE_NAME,
            "namespace": SIGNED_NOSTR_FLUX_NAMESPACE,
        },
        # The one-time administrator bootstrap may create only this suspended
        # object.  A separately bound CAS/live recheck is required before the
        # exact same object may be unsuspended.
        "suspend": suspended,
        "targetNamespace": target_namespace,
        "timeout": "2m",
        "wait": True,
    }
    if component == "workbench":
        kustomization_spec["dependsOn"] = [
            {"name": SIGNED_NOSTR_FLUX_KUSTOMIZATION_NAMES[relay]}
            for relay in ("citizen-relay", "agent-relay")
        ]
    kustomization = {
        "apiVersion": "kustomize.toolkit.fluxcd.io/v1",
        "kind": "Kustomization",
        "metadata": {
            "labels": labels,
            "name": kustomization_name,
            "namespace": SIGNED_NOSTR_FLUX_NAMESPACE,
        },
        "spec": kustomization_spec,
    }
    service_account = {
        "apiVersion": "v1",
        "automountServiceAccountToken": False,
        "kind": "ServiceAccount",
        "metadata": {
            "labels": labels,
            "name": service_account_name,
            "namespace": SIGNED_NOSTR_FLUX_NAMESPACE,
        },
    }
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {
            "labels": labels,
            "name": service_account_name,
            "namespace": target_namespace,
        },
        "rules": [
            {
                "apiGroups": ["apps"],
                "resourceNames": resource_names,
                "resources": ["deployments"],
                "verbs": ["get", "patch", "update"],
            },
            {
                "apiGroups": [""],
                "resourceNames": resource_names,
                "resources": ["services"],
                "verbs": ["get", "patch", "update"],
            },
            {
                "apiGroups": ["networking.k8s.io"],
                "resourceNames": resource_names,
                "resources": ["networkpolicies"],
                "verbs": ["get", "patch", "update"],
            },
        ],
    }
    role_binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {
            "labels": labels,
            "name": service_account_name,
            "namespace": target_namespace,
        },
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": service_account_name,
        },
        "subjects": [{
            "kind": "ServiceAccount",
            "name": service_account_name,
            "namespace": SIGNED_NOSTR_FLUX_NAMESPACE,
        }],
    }
    return {
        "kustomization": kustomization,
        "serviceAccount": service_account,
        "role": role,
        "roleBinding": role_binding,
    }


def signed_nostr_object_target(value: dict[str, Any]) -> dict[str, str]:
    metadata = value["metadata"]
    return {
        "apiVersion": value["apiVersion"],
        "kind": value["kind"],
        "name": metadata["name"],
        "namespace": metadata["namespace"],
    }


def expected_signed_nostr_managed_objects(
    publisher_pin: dict[str, Any],
    *,
    suspended_flux: bool,
) -> list[dict[str, Any]]:
    """Return every exact live object owned by the signed-Nostr tracer.

    The ordering is part of the evidence contract.  Runtime and Flux identity
    objects share this one inventory so bootstrap, activation and teardown can
    never silently disagree about ownership.
    """
    images = {entry["component"]: entry for entry in publisher_pin["components"]}
    resources = expected_signed_nostr_resources({"images": images})
    managed: list[dict[str, Any]] = []

    runtime_keys = (
        ("deployment", "deployment"),
        ("service", "service"),
        ("networkpolicy", "networkPolicy"),
    )
    for component in SIGNED_NOSTR_COMPONENTS:
        for object_id, key in runtime_keys:
            value = resources[component][key]
            managed.append({
                "objectId": f"runtime/{component}/{object_id}",
                "class": "runtime",
                "object": value,
            })
        if component == "workbench":
            for object_id, key in (
                ("gnosis-proxy-deployment", "gnosisProxyDeployment"),
                ("gnosis-proxy-service", "gnosisProxyService"),
                ("gnosis-proxy-networkpolicy", "gnosisProxyNetworkPolicy"),
            ):
                value = resources[component][key]
                managed.append({
                    "objectId": f"runtime/{component}/{object_id}",
                    "class": "runtime",
                    "object": value,
                })

    for component in SIGNED_NOSTR_FLUX_BINDING_ORDER:
        flux = expected_signed_nostr_flux_objects(component, suspended=suspended_flux)
        for key in ("kustomization", "serviceAccount", "role", "roleBinding"):
            managed.append({
                "objectId": f"flux/{component}/{key}",
                "class": "flux-identity",
                "object": flux[key],
            })
    return managed


def verify_signed_nostr_live_preconditions(
    value: Any,
    managed: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    require(isinstance(value, list) and len(value) == len(managed), "signed-Nostr live precondition count invalid")
    parsed: list[dict[str, Any]] = []
    for index, (item, expected) in enumerate(zip(value, managed, strict=True)):
        precondition = closed(
            item,
            {
                "objectId",
                "target",
                "desiredObjectDigest",
                "state",
                "uid",
                "resourceVersion",
                "currentObjectDigest",
            },
            f"signed-Nostr live precondition[{index}]",
        )
        require(precondition["objectId"] == expected["objectId"], "signed-Nostr live precondition object order invalid")
        require(precondition["target"] == signed_nostr_object_target(expected["object"]), "signed-Nostr live precondition target invalid")
        desired_digest = digest(expected["object"])
        require(precondition["desiredObjectDigest"] == desired_digest, "signed-Nostr live precondition desired digest invalid")
        if precondition["state"] == "absent":
            require(
                precondition["uid"] is None
                and precondition["resourceVersion"] is None
                and precondition["currentObjectDigest"] is None,
                "signed-Nostr absent precondition must not claim live identity",
            )
        else:
            require(precondition["state"] == "present-exact", "signed-Nostr live precondition state invalid")
            require(isinstance(precondition["uid"], str) and UUID.fullmatch(precondition["uid"]), "signed-Nostr live precondition UID invalid")
            require(isinstance(precondition["resourceVersion"], str) and precondition["resourceVersion"].isdigit(), "signed-Nostr live precondition resourceVersion invalid")
            require(precondition["currentObjectDigest"] == desired_digest, "signed-Nostr present object is not exact and may not be adopted")
        parsed.append(precondition)
    return parsed


def verify_signed_nostr_bootstrap_receipt(
    value: Any,
    preconditions: list[dict[str, Any]],
    managed: list[dict[str, Any]],
) -> dict[str, Any]:
    receipt = closed(
        value,
        {
            "schemaVersion",
            "canonicalEncoding",
            "status",
            "operationId",
            "observedAt",
            "validUntil",
            "maxAgeSeconds",
            "preconditionsCanonicalSha256",
            "postconditions",
            "postconditionsCanonicalSha256",
            "kustomizationsInitiallySuspended",
            "authority",
            "effects",
        },
        "signed-Nostr one-time bootstrap receipt",
    )
    require(receipt["schemaVersion"] == SIGNED_NOSTR_BOOTSTRAP_RECEIPT_SCHEMA, "signed-Nostr bootstrap receipt schema invalid")
    require(receipt["canonicalEncoding"] == "canonical-json", "signed-Nostr bootstrap receipt encoding invalid")
    require(receipt["status"] == "completed-exact-cas", "signed-Nostr bootstrap receipt status invalid")
    require(isinstance(receipt["operationId"], str) and UUID.fullmatch(receipt["operationId"]), "signed-Nostr bootstrap operation id invalid")
    observed = utc_timestamp(receipt["observedAt"], "signed-Nostr bootstrap observedAt")
    valid_until = utc_timestamp(receipt["validUntil"], "signed-Nostr bootstrap validUntil")
    require(receipt["maxAgeSeconds"] == 300, "signed-Nostr bootstrap freshness budget invalid")
    require(0 < duration_seconds(observed, valid_until) <= receipt["maxAgeSeconds"], "signed-Nostr bootstrap receipt stale")
    require(receipt["preconditionsCanonicalSha256"] == digest(preconditions), "signed-Nostr bootstrap precondition checksum invalid")
    require(receipt["kustomizationsInitiallySuspended"] is True, "signed-Nostr bootstrap Kustomizations must start suspended")
    require(receipt["authority"] == "one-time-cluster-admin-exact-targets", "signed-Nostr bootstrap authority invalid")
    require(receipt["effects"] == {
        "clusterMutation": True,
        "civicMutation": False,
        "secretRead": False,
        "secretWrite": False,
        "wildcardAuthority": False,
        "ssaPatchUsedForAbsentTargets": False,
        "absenceGuardSource": "atomic-post-create-http-409-no-adopt",
        "presentGuardSource": "uid-resourceVersion-bound-no-op",
    }, "signed-Nostr bootstrap effects invalid")

    postconditions = receipt["postconditions"]
    require(isinstance(postconditions, list) and len(postconditions) == len(managed), "signed-Nostr bootstrap postcondition count invalid")
    for index, (postcondition_value, precondition, expected) in enumerate(zip(postconditions, preconditions, managed, strict=True)):
        postcondition = closed(
            postcondition_value,
            {
                "objectId",
                "target",
                "uid",
                "resourceVersion",
                "objectDigest",
                "action",
                "apiOperation",
                "requiredUid",
                "requiredResourceVersion",
                "conflictPolicy",
                "apiOutcome",
            },
            f"signed-Nostr bootstrap postcondition[{index}]",
        )
        require(postcondition["objectId"] == expected["objectId"], "signed-Nostr bootstrap postcondition object order invalid")
        require(postcondition["target"] == signed_nostr_object_target(expected["object"]), "signed-Nostr bootstrap postcondition target invalid")
        require(isinstance(postcondition["uid"], str) and UUID.fullmatch(postcondition["uid"]), "signed-Nostr bootstrap postcondition UID invalid")
        require(isinstance(postcondition["resourceVersion"], str) and postcondition["resourceVersion"].isdigit(), "signed-Nostr bootstrap postcondition resourceVersion invalid")
        require(postcondition["objectDigest"] == digest(expected["object"]), "signed-Nostr bootstrap postcondition object drift")
        if precondition["state"] == "absent":
            require(
                postcondition["action"] == "created-by-atomic-post-after-verified-absence"
                and postcondition["apiOperation"] == "POST-create"
                and postcondition["requiredUid"] is None
                and postcondition["requiredResourceVersion"] is None
                and postcondition["conflictPolicy"] == "fail-on-http-409-no-adopt"
                and postcondition["apiOutcome"] == "http-201-created",
                "signed-Nostr absent bootstrap is not atomic create-only",
            )
        else:
            require(
                postcondition["action"] == "retained-exact-owned-object-no-op"
                and postcondition["apiOperation"] == "none"
                and postcondition["requiredUid"] == precondition["uid"]
                and postcondition["requiredResourceVersion"] == precondition["resourceVersion"]
                and postcondition["conflictPolicy"] == "fail-on-uid-or-resourceVersion-mismatch-no-adopt"
                and postcondition["apiOutcome"] == "unchanged-after-atomic-precondition-recheck",
                "signed-Nostr present bootstrap CAS receipt invalid",
            )
            require(postcondition["uid"] == precondition["uid"], "signed-Nostr bootstrap adopted a different UID")
            require(
                postcondition["resourceVersion"] == precondition["resourceVersion"],
                "signed-Nostr bootstrap retained object resourceVersion drift",
            )
    require(receipt["postconditionsCanonicalSha256"] == digest(postconditions), "signed-Nostr bootstrap postcondition checksum invalid")
    return receipt


def verify_signed_nostr_dns_tls_evidence(value: Any, label: str) -> dict[str, Any]:
    evidence = closed(
        value,
        {
            "schemaVersion",
            "canonicalEncoding",
            "resolverIdentity",
            "resolutionMethod",
            "queriedHost",
            "queriedPort",
            "observedAt",
            "validUntil",
            "maxAgeSeconds",
            "addresses",
            "tlsCertificate",
        },
        label,
    )
    require(evidence["schemaVersion"] == SIGNED_NOSTR_DNS_TLS_EVIDENCE_SCHEMA, f"{label} schema invalid")
    require(evidence["canonicalEncoding"] == "canonical-json", f"{label} encoding invalid")
    require(evidence["resolverIdentity"] == "reviewed-doh-resolver", f"{label} resolver invalid")
    require(evidence["resolutionMethod"] == "dns-over-https-a-and-aaaa", f"{label} method invalid")
    require(evidence["queriedHost"] == SIGNED_NOSTR_GNOSIS_UPSTREAM_HOST, f"{label} host invalid")
    require(evidence["queriedPort"] == SIGNED_NOSTR_GNOSIS_UPSTREAM_PORT, f"{label} port invalid")
    observed = utc_timestamp(evidence["observedAt"], f"{label} observedAt")
    valid_until = utc_timestamp(evidence["validUntil"], f"{label} validUntil")
    require(evidence["maxAgeSeconds"] == 300, f"{label} freshness budget invalid")
    require(0 < duration_seconds(observed, valid_until) <= evidence["maxAgeSeconds"], f"{label} stale")

    addresses = closed(evidence["addresses"], {"a", "aaaa"}, f"{label} addresses")
    require(isinstance(addresses["a"], list) and isinstance(addresses["aaaa"], list), f"{label} address sets invalid")
    for family, address_set in ((4, addresses["a"]), (6, addresses["aaaa"])):
        require(all(isinstance(address, str) for address in address_set), f"{label} address set contains a non-string")
        require(address_set == sorted(set(address_set)), f"{label} {'A' if family == 4 else 'AAAA'} set must be sorted and unique")
        for address in address_set:
            try:
                valid = isinstance(address, str) and ipaddress.ip_address(address).version == family
            except ValueError:
                valid = False
            require(valid, f"{label} {'A' if family == 4 else 'AAAA'} address invalid")
    pinned = str(ipaddress.ip_network(SIGNED_NOSTR_GNOSIS_UPSTREAM_IPV4_CIDR, strict=True).network_address)
    require(addresses == {"a": [pinned], "aaaa": []}, f"{label} full resolution set does not equal the fail-closed /32")

    certificate = closed(
        evidence["tlsCertificate"],
        {"serverName", "issuer", "certificateSha256", "notBefore", "notAfter"},
        f"{label} TLS certificate",
    )
    require(certificate["serverName"] == SIGNED_NOSTR_GNOSIS_UPSTREAM_HOST, f"{label} TLS server name invalid")
    require(isinstance(certificate["issuer"], str) and certificate["issuer"].strip() == certificate["issuer"] and certificate["issuer"], f"{label} TLS issuer invalid")
    require(isinstance(certificate["certificateSha256"], str) and SHA256.fullmatch(certificate["certificateSha256"]), f"{label} TLS fingerprint invalid")
    not_before = utc_timestamp(certificate["notBefore"], f"{label} certificate notBefore")
    not_after = utc_timestamp(certificate["notAfter"], f"{label} certificate notAfter")
    require(not_before <= observed <= valid_until < not_after, f"{label} certificate is not valid for the complete evidence window")
    return evidence


def dns_tls_binding(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "resolverIdentity": value["resolverIdentity"],
        "resolutionMethod": value["resolutionMethod"],
        "queriedHost": value["queriedHost"],
        "queriedPort": value["queriedPort"],
        "addresses": value["addresses"],
        "tlsCertificate": value["tlsCertificate"],
    }


def rollback_boundary_digest_record(rollback: dict[str, Any]) -> dict[str, str]:
    return {
        "integritySha256": rollback["integritySha256"],
        "webIngressSha256": rollback["webIngressSha256"],
        "publicMeckyNetworkPolicySha256": rollback["publicMeckyNetworkPolicySha256"],
        "boundaryReceiptSha256": rollback["boundaryReceiptSha256"],
    }


def verify_signed_nostr_activation_live_recheck(
    value: Any,
    bootstrap: dict[str, Any],
    rollback: dict[str, Any],
    initial_dns_tls: dict[str, Any],
) -> dict[str, Any]:
    receipt = closed(
        value,
        {
            "schemaVersion",
            "canonicalEncoding",
            "status",
            "checkedAt",
            "validUntil",
            "maxAgeSeconds",
            "bootstrapReceiptCanonicalSha256",
            "objectStates",
            "objectStatesCanonicalSha256",
            "boundaryState",
            "dnsTlsRecheck",
        },
        "signed-Nostr activation live recheck",
    )
    require(receipt["schemaVersion"] == SIGNED_NOSTR_LIVE_RECHECK_SCHEMA, "signed-Nostr activation live recheck schema invalid")
    require(receipt["canonicalEncoding"] == "canonical-json", "signed-Nostr activation live recheck encoding invalid")
    require(receipt["status"] == "passed-no-drift", "signed-Nostr activation live recheck status invalid")
    checked = utc_timestamp(receipt["checkedAt"], "signed-Nostr activation live recheck checkedAt")
    valid_until = utc_timestamp(receipt["validUntil"], "signed-Nostr activation live recheck validUntil")
    require(receipt["maxAgeSeconds"] == 300, "signed-Nostr activation live recheck freshness budget invalid")
    require(0 < duration_seconds(checked, valid_until) <= receipt["maxAgeSeconds"], "signed-Nostr activation live recheck stale")
    require(receipt["bootstrapReceiptCanonicalSha256"] == digest(bootstrap), "signed-Nostr activation live recheck bootstrap binding invalid")
    require(receipt["objectStates"] == bootstrap["postconditions"], "signed-Nostr activation live object ownership drift")
    require(receipt["objectStatesCanonicalSha256"] == digest(receipt["objectStates"]), "signed-Nostr activation live state checksum invalid")
    require(receipt["boundaryState"] == rollback_boundary_digest_record(rollback), "signed-Nostr activation boundary live recheck drift")
    dns_recheck = verify_signed_nostr_dns_tls_evidence(receipt["dnsTlsRecheck"], "signed-Nostr activation DNS/TLS recheck")
    require(utc_timestamp(dns_recheck["observedAt"], "signed-Nostr activation DNS/TLS observedAt") == checked, "signed-Nostr DNS/TLS recheck is not activation-time evidence")
    require(utc_timestamp(dns_recheck["validUntil"], "signed-Nostr activation DNS/TLS validUntil") >= valid_until, "signed-Nostr DNS/TLS recheck expires before activation receipt")
    require(dns_tls_binding(dns_recheck) == dns_tls_binding(initial_dns_tls), "signed-Nostr activation DNS/TLS recheck changed resolution or certificate")
    return receipt


def verify_signed_nostr_reconcile_activation(
    value: Any,
    live_recheck: dict[str, Any],
    bootstrap: dict[str, Any],
    managed_suspended: list[dict[str, Any]],
    managed_active: list[dict[str, Any]],
) -> dict[str, Any]:
    receipt = closed(
        value,
        {
            "schemaVersion",
            "canonicalEncoding",
            "status",
            "operationId",
            "completedAt",
            "liveRecheckCanonicalSha256",
            "unsuspensions",
            "unsuspensionsCanonicalSha256",
            "effects",
        },
        "signed-Nostr reconcile activation receipt",
    )
    require(receipt["schemaVersion"] == "roebel_signed_nostr_reconcile_activation_receipt_v1", "signed-Nostr reconcile activation schema invalid")
    require(receipt["canonicalEncoding"] == "canonical-json", "signed-Nostr reconcile activation encoding invalid")
    require(receipt["status"] == "completed-after-live-recheck", "signed-Nostr reconcile activation status invalid")
    require(isinstance(receipt["operationId"], str) and UUID.fullmatch(receipt["operationId"]), "signed-Nostr reconcile activation operation id invalid")
    completed = utc_timestamp(receipt["completedAt"], "signed-Nostr reconcile activation completedAt")
    checked = utc_timestamp(live_recheck["checkedAt"], "signed-Nostr activation live recheck checkedAt")
    valid_until = utc_timestamp(live_recheck["validUntil"], "signed-Nostr activation live recheck validUntil")
    require(checked <= completed <= valid_until, "signed-Nostr reconcile activation occurred outside the live-preflight window")
    require(receipt["liveRecheckCanonicalSha256"] == digest(live_recheck), "signed-Nostr reconcile activation live-recheck binding invalid")
    require(receipt["effects"] == {
        "clusterMutation": True,
        "civicMutation": False,
        "secretRead": False,
        "secretWrite": False,
        "onlySuspendFieldChanged": True,
    }, "signed-Nostr reconcile activation effects invalid")

    suspended_by_id = {entry["objectId"]: entry for entry in managed_suspended}
    active_by_id = {entry["objectId"]: entry for entry in managed_active}
    post_by_id = {entry["objectId"]: entry for entry in bootstrap["postconditions"]}
    expected_ids = [f"flux/{component}/kustomization" for component in SIGNED_NOSTR_FLUX_BINDING_ORDER]
    unsuspensions = receipt["unsuspensions"]
    require(isinstance(unsuspensions, list) and len(unsuspensions) == len(expected_ids), "signed-Nostr reconcile activation count invalid")
    for index, (item, object_id) in enumerate(zip(unsuspensions, expected_ids, strict=True)):
        change = closed(
            item,
            {
                "objectId",
                "target",
                "requiredUid",
                "requiredResourceVersion",
                "beforeObjectDigest",
                "patch",
                "postResourceVersion",
                "afterObjectDigest",
            },
            f"signed-Nostr reconcile activation[{index}]",
        )
        before = suspended_by_id[object_id]["object"]
        after = active_by_id[object_id]["object"]
        live = post_by_id[object_id]
        require(change["objectId"] == object_id, "signed-Nostr reconcile activation object order invalid")
        require(change["target"] == signed_nostr_object_target(before), "signed-Nostr reconcile activation target invalid")
        require(change["requiredUid"] == live["uid"], "signed-Nostr reconcile activation UID drift")
        require(change["requiredResourceVersion"] == live["resourceVersion"], "signed-Nostr reconcile activation resourceVersion drift")
        require(change["beforeObjectDigest"] == digest(before) == live["objectDigest"], "signed-Nostr reconcile activation before digest invalid")
        require(change["patch"] == {"op": "replace", "path": "/spec/suspend", "expected": True, "value": False}, "signed-Nostr reconcile activation patch widened")
        require(isinstance(change["postResourceVersion"], str) and change["postResourceVersion"].isdigit(), "signed-Nostr reconcile activation post resourceVersion invalid")
        require(int(change["postResourceVersion"]) > int(change["requiredResourceVersion"]), "signed-Nostr reconcile activation resourceVersion did not advance")
        require(change["afterObjectDigest"] == digest(after), "signed-Nostr reconcile activation after digest invalid")
    require(receipt["unsuspensionsCanonicalSha256"] == digest(unsuspensions), "signed-Nostr reconcile activation checksum invalid")
    return receipt


def verify_signed_nostr_activation_admission_freshness(
    activation_evidence: dict[str, Any],
) -> None:
    """Require one current, coherently ordered activation preflight.

    Shape validation remains timeless so an already-active render can still be
    verified by later routine promotions.  This current-time check is invoked
    only for the reviewed-public-knowledge -> signed-Nostr transition that
    grants deployment authority.
    """
    lifecycle = activation_evidence["lifecycle"]
    bootstrap = lifecycle["bootstrapReceipt"]
    live_recheck = lifecycle["activationLiveRecheck"]
    reconcile = lifecycle["reconcileActivationReceipt"]
    initial_dns = activation_evidence["gnosisRpcEgress"]["upstream"]["dnsTlsEvidence"]
    now = signed_nostr_verification_time()
    bootstrap_observed = utc_timestamp(bootstrap["observedAt"], "signed-Nostr bootstrap observedAt")
    initial_dns_observed = utc_timestamp(initial_dns["observedAt"], "signed-Nostr reviewed DNS/TLS observedAt")
    checked = utc_timestamp(live_recheck["checkedAt"], "signed-Nostr activation live recheck checkedAt")
    completed = utc_timestamp(reconcile["completedAt"], "signed-Nostr reconcile activation completedAt")
    valid_until = utc_timestamp(live_recheck["validUntil"], "signed-Nostr activation live recheck validUntil")
    require(bootstrap_observed <= checked, "signed-Nostr activation live recheck predates bootstrap")
    require(initial_dns_observed <= checked, "signed-Nostr activation live recheck predates reviewed DNS/TLS evidence")
    require(
        checked <= completed <= now <= valid_until,
        "signed-Nostr activation evidence is future-dated or outside the current five-minute preflight",
    )


def expected_signed_nostr_rollback_contract(
    managed_suspended: list[dict[str, Any]],
    bootstrap: dict[str, Any],
    reconcile: dict[str, Any],
    rollback: dict[str, Any],
) -> dict[str, Any]:
    post_by_id = {entry["objectId"]: entry for entry in bootstrap["postconditions"]}
    active_kustomizations = {entry["objectId"]: entry for entry in reconcile["unsuspensions"]}
    runtime_targets: list[dict[str, Any]] = []
    identity_targets: list[dict[str, Any]] = []
    for entry in managed_suspended:
        object_id = entry["objectId"]
        post = post_by_id[object_id]
        target = signed_nostr_object_target(entry["object"])
        if entry["class"] == "runtime":
            runtime_targets.append({
                "objectId": object_id,
                "target": target,
                "requiredUid": post["uid"],
                "requiredObjectDigest": post["objectDigest"],
                "action": "scale-zero-then-delete" if target["kind"] == "Deployment" else "delete",
                "onUidMismatch": "stop-for-adoption-review",
            })
        else:
            current_digest = (
                active_kustomizations[object_id]["afterObjectDigest"]
                if object_id in active_kustomizations
                else post["objectDigest"]
            )
            identity_targets.append({
                "objectId": object_id,
                "target": target,
                "requiredUid": post["uid"],
                "requiredObjectDigest": current_digest,
                "postSuspendObjectDigest": post["objectDigest"] if target["kind"] == "Kustomization" else None,
                "action": "suspend-then-delete" if target["kind"] == "Kustomization" else "delete",
                "onUidMismatch": "stop-for-adoption-review",
            })
    return {
        "schemaVersion": SIGNED_NOSTR_ROLLBACK_CONTRACT_SCHEMA,
        "canonicalEncoding": "canonical-json",
        "sequence": [
            "suspend-exact-reconcilers",
            "restore-four-public-boundary-bytes",
            "scale-and-delete-exact-runtime-uids",
            "delete-exact-flux-rbac-uids",
            "verify-boundary-and-total-absence",
        ],
        "deleteAuthority": "one-time-cluster-admin-exact-targets",
        "routineReconcilerDeleteAllowed": False,
        "boundaryBaseline": rollback_boundary_digest_record(rollback),
        "runtimeTargets": runtime_targets,
        "identityTargets": identity_targets,
        "absenceVerificationTargets": [signed_nostr_object_target(entry["object"]) for entry in managed_suspended],
        "uidMismatchPolicy": "fail-closed-no-delete-no-adopt",
        "completionReceiptSchema": SIGNED_NOSTR_DEACTIVATION_EVIDENCE_SCHEMA,
        "civicAuthority": "none",
    }


def deactivation_step_payload(
    sequence: int,
    action: str,
    target: dict[str, Any] | None,
    required_uid: str | None,
    before_digest: str | None,
    result: str,
) -> dict[str, Any]:
    return {
        "sequence": sequence,
        "action": action,
        "target": target,
        "requiredUid": required_uid,
        "beforeObjectDigest": before_digest,
        "result": result,
    }


def expected_signed_nostr_deactivation_steps(contract: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    sequence = 1
    for target in contract["identityTargets"]:
        if target["target"]["kind"] != "Kustomization":
            continue
        payload = deactivation_step_payload(
            sequence,
            "suspend-exact-reconciler",
            target["target"],
            target["requiredUid"],
            target["requiredObjectDigest"],
            "suspended-and-verified",
        )
        steps.append({**payload, "receiptDigest": digest(payload)})
        sequence += 1
    payload = deactivation_step_payload(
        sequence,
        "restore-four-public-boundary-bytes",
        None,
        None,
        digest(contract["boundaryBaseline"]),
        "restored-and-verified",
    )
    steps.append({**payload, "receiptDigest": digest(payload)})
    sequence += 1
    for target in contract["runtimeTargets"]:
        payload = deactivation_step_payload(
            sequence,
            target["action"],
            target["target"],
            target["requiredUid"],
            target["requiredObjectDigest"],
            "absent-and-verified",
        )
        steps.append({**payload, "receiptDigest": digest(payload)})
        sequence += 1
    # Kustomizations are removed first after workloads are gone; RoleBindings,
    # Roles and ServiceAccounts then lose authority in deterministic order.
    identity_order = {"Kustomization": 0, "RoleBinding": 1, "Role": 2, "ServiceAccount": 3}
    for target in sorted(
        contract["identityTargets"],
        key=lambda item: (identity_order[item["target"]["kind"]], item["objectId"]),
    ):
        payload = deactivation_step_payload(
            sequence,
            "delete-exact-flux-identity",
            target["target"],
            target["requiredUid"],
            target["postSuspendObjectDigest"] or target["requiredObjectDigest"],
            "absent-and-verified",
        )
        steps.append({**payload, "receiptDigest": digest(payload)})
        sequence += 1
    return steps


def verify_signed_nostr_deactivation_evidence(
    value: Any,
    activation_evidence: dict[str, Any],
    rollback_contract: dict[str, Any],
) -> dict[str, Any]:
    receipt = closed(
        value,
        {
            "schemaVersion",
            "canonicalEncoding",
            "status",
            "startedAt",
            "completedAt",
            "validUntil",
            "maxAgeSeconds",
            "activationEvidenceCanonicalSha256",
            "rollbackContractCanonicalSha256",
            "stepReceipts",
            "boundaryVerification",
            "absenceVerification",
            "effects",
        },
        "signed-Nostr deactivation evidence",
    )
    require(receipt["schemaVersion"] == SIGNED_NOSTR_DEACTIVATION_EVIDENCE_SCHEMA, "signed-Nostr deactivation evidence schema invalid")
    require(receipt["canonicalEncoding"] == "canonical-json", "signed-Nostr deactivation encoding invalid")
    require(receipt["status"] == "completed-and-verified", "signed-Nostr deactivation status invalid")
    started = utc_timestamp(receipt["startedAt"], "signed-Nostr deactivation startedAt")
    completed = utc_timestamp(receipt["completedAt"], "signed-Nostr deactivation completedAt")
    valid_until = utc_timestamp(receipt["validUntil"], "signed-Nostr deactivation validUntil")
    now = signed_nostr_verification_time()
    require(0 <= duration_seconds(started, completed) <= 900, "signed-Nostr deactivation duration invalid")
    require(receipt["maxAgeSeconds"] == 300, "signed-Nostr deactivation freshness budget invalid")
    require(
        0 < duration_seconds(completed, valid_until) <= receipt["maxAgeSeconds"],
        "signed-Nostr deactivation validity window invalid",
    )
    require(
        started <= completed <= now <= valid_until,
        "signed-Nostr deactivation evidence is future-dated, expired, or replayed",
    )
    require(receipt["activationEvidenceCanonicalSha256"] == digest(activation_evidence), "signed-Nostr deactivation activation binding invalid")
    require(receipt["rollbackContractCanonicalSha256"] == digest(rollback_contract), "signed-Nostr deactivation contract binding invalid")
    require(receipt["stepReceipts"] == expected_signed_nostr_deactivation_steps(rollback_contract), "signed-Nostr deactivation step receipt set incomplete or drifted")
    require(receipt["boundaryVerification"] == {
        "verifiedAt": receipt["completedAt"],
        "status": "exact-baseline-restored",
        **rollback_contract["boundaryBaseline"],
    }, "signed-Nostr deactivation boundary verification invalid")
    require(receipt["absenceVerification"] == {
        "verifiedAt": receipt["completedAt"],
        "status": "all-exact-targets-absent",
        "targets": rollback_contract["absenceVerificationTargets"],
    }, "signed-Nostr deactivation absence verification invalid")
    require(receipt["effects"] == {
        "clusterMutation": True,
        "civicMutation": False,
        "secretRead": False,
        "secretWrite": False,
        "uidMismatchObserved": False,
        "unrelatedObjectMutation": False,
    }, "signed-Nostr deactivation effects invalid")
    return receipt


def verify_signed_nostr_runtime_pin(value: Any) -> dict[str, Any]:
    pin = closed(
        value,
        {
            "schemaVersion",
            "publisherPin",
            "publisherPinCanonicalSha256",
            "activationEvidence",
            "rollback",
        },
        "signed-Nostr runtime-pin",
    )
    require(pin["schemaVersion"] == "roebel_signed_nostr_activation_render_pin_v1", "signed-Nostr runtime-pin schema invalid")
    publisher = closed(
        pin["publisherPin"],
        {"schemaVersion", "sourceRevision", "components", "civicAuthority", "deploymentEffect"},
        "signed-Nostr publisher pin",
    )
    require(publisher["schemaVersion"] == "roebel_e2e_runtime_pin_v1", "signed-Nostr publisher pin schema invalid")
    require(isinstance(publisher["sourceRevision"], str) and REVISION.fullmatch(publisher["sourceRevision"]), "signed-Nostr source revision invalid")
    require(publisher["civicAuthority"] == "none" and publisher["deploymentEffect"] is False, "signed-Nostr authority binding invalid")
    require(
        pin["publisherPinCanonicalSha256"] == digest(publisher),
        "signed-Nostr publisher pin canonical checksum invalid",
    )
    rollback = closed(
        pin["rollback"],
        {"fromRender", "integritySha256", "webIngressSha256", "publicMeckyNetworkPolicySha256", "boundaryReceiptSha256"},
        "signed-Nostr rollback record",
    )
    require(rollback["fromRender"] == "reviewed-public-knowledge", "signed-Nostr rollback base invalid")
    for field in ("integritySha256", "webIngressSha256", "publicMeckyNetworkPolicySha256", "boundaryReceiptSha256"):
        require(isinstance(rollback[field], str) and SHA256.fullmatch(rollback[field]), f"signed-Nostr rollback {field} invalid")
    evidence = pin["activationEvidence"]
    if evidence == {
        "status": "pending-separate-review",
        "gnosisRpcEgress": None,
        "fluxIdentity": None,
        "anonymousDigestPullReceipts": None,
    }:
        # A temporary, explicitly closed placeholder is the only activation
        # evidence accepted by this bootstrap.  A later full record is parsed
        # below, but still cannot activate until it equals the protected
        # approved-policy constant.
        pass
    else:
        verify_signed_nostr_activation_evidence(
            evidence,
            publisher,
            pin["publisherPinCanonicalSha256"],
            rollback,
        )
    require(isinstance(publisher["components"], list) and len(publisher["components"]) == 2, "signed-Nostr runtime pin component count invalid")
    parsed: dict[str, dict[str, str]] = {}
    for index, entry in enumerate(publisher["components"]):
        component = closed(entry, {"component", "image", "manifestDigest", "provenance", "sbomAttestation", "workflowIdentity"}, f"signed-Nostr pin component[{index}]")
        expected = SIGNED_NOSTR_PUBLISHER_COMPONENT_ORDER[index]
        require(component["component"] == expected, "signed-Nostr runtime pin component order invalid")
        expected_image = SIGNED_NOSTR_IMAGES["workbench" if expected == "roebel-e2e-workbench" else "citizen-relay"]
        require(component["image"] == expected_image, "signed-Nostr runtime pin image repository invalid")
        require(isinstance(component["manifestDigest"], str) and SHA256.fullmatch(component["manifestDigest"]), "signed-Nostr runtime pin digest invalid")
        require(component["workflowIdentity"] == SIGNED_NOSTR_WORKFLOW, "signed-Nostr component workflow identity invalid")
        for key in ("provenance", "sbomAttestation"):
            proof = closed(component[key], {"id", "url"}, f"signed-Nostr {key}")
            require(isinstance(proof["id"], str) and proof["id"], f"signed-Nostr {key} id invalid")
            require(isinstance(proof["url"], str) and proof["url"].startswith("https://github.com/GiraeffleAeffle/Roebel-App/"), f"signed-Nostr {key} URL invalid")
        parsed[expected] = component
    return {"pin": pin, "publisherPin": publisher, "images": parsed}


def verify_signed_nostr_attestation_receipt(
    value: Any,
    publisher_receipt: dict[str, Any],
    manifest_digest: str,
    label: str,
) -> dict[str, str]:
    receipt = closed(
        value,
        {"receiptId", "receiptUrl", "attestationDigest", "subjectDigest"},
        label,
    )
    require(receipt["receiptId"] == publisher_receipt["id"], f"{label} id binding invalid")
    require(receipt["receiptUrl"] == publisher_receipt["url"], f"{label} URL binding invalid")
    require(isinstance(receipt["attestationDigest"], str) and SHA256.fullmatch(receipt["attestationDigest"]), f"{label} digest invalid")
    require(receipt["subjectDigest"] == manifest_digest, f"{label} subject binding invalid")
    return receipt


def verify_signed_nostr_object_receipt(
    value: Any,
    expected_object: dict[str, Any],
    label: str,
) -> dict[str, Any]:
    receipt = closed(value, {"object", "objectDigest"}, label)
    require(receipt["object"] == expected_object, f"{label} object invalid")
    require(
        isinstance(receipt["objectDigest"], str) and SHA256.fullmatch(receipt["objectDigest"]),
        f"{label} digest invalid",
    )
    require(receipt["objectDigest"] == digest(expected_object), f"{label} digest binding invalid")
    return receipt


def verify_signed_nostr_activation_evidence(
    value: Any,
    publisher_pin: dict[str, Any],
    publisher_pin_canonical_sha256: str,
    rollback_record: dict[str, Any],
) -> dict[str, Any]:
    """Validate the complete future activation record without authorizing it.

    The shape is deliberately closed.  The policy constant below performs the
    separate approval step: validation alone never turns a candidate record
    into authority to materialise the runtime.
    """
    evidence = closed(
        value,
        {
            "schemaVersion",
            "canonicalEncoding",
            "status",
            "publisherPinCanonicalSha256",
            "publisherSourceRevision",
            "publisherWorkflowIdentity",
            "components",
            "fluxBindings",
            "gnosisRpcEgress",
            "anonymousDigestPullReceipts",
            "lifecycle",
        },
        "signed-Nostr activation evidence",
    )
    require(evidence["schemaVersion"] == SIGNED_NOSTR_ACTIVATION_EVIDENCE_SCHEMA, "signed-Nostr activation evidence schema invalid")
    require(evidence["canonicalEncoding"] == "canonical-json", "signed-Nostr activation evidence canonical encoding invalid")
    require(evidence["status"] == "reviewed", "signed-Nostr activation evidence status invalid")
    require(evidence["publisherPinCanonicalSha256"] == publisher_pin_canonical_sha256, "signed-Nostr activation evidence publisher checksum binding invalid")
    require(evidence["publisherSourceRevision"] == publisher_pin["sourceRevision"], "signed-Nostr activation evidence source binding invalid")
    require(evidence["publisherWorkflowIdentity"] == SIGNED_NOSTR_WORKFLOW, "signed-Nostr activation evidence workflow binding invalid")

    require(isinstance(evidence["components"], list) and len(evidence["components"]) == 2, "signed-Nostr activation evidence component count invalid")
    publisher_components = {entry["component"]: entry for entry in publisher_pin["components"]}
    attestation_digests: set[str] = set()
    attestation_ids: set[str] = set()
    for index, item in enumerate(evidence["components"]):
        component = closed(
            item,
            {"component", "imageRepository", "manifestDigest", "provenance", "sbomAttestation"},
            f"signed-Nostr activation component[{index}]",
        )
        expected_name = SIGNED_NOSTR_ACTIVATION_COMPONENT_ORDER[index]
        require(component["component"] == expected_name, "signed-Nostr activation component order invalid")
        publisher_component = publisher_components[expected_name]
        require(component["imageRepository"] == publisher_component["image"], "signed-Nostr activation component image binding invalid")
        require(component["manifestDigest"] == publisher_component["manifestDigest"], "signed-Nostr activation component manifest binding invalid")
        provenance = verify_signed_nostr_attestation_receipt(component["provenance"], publisher_component["provenance"], publisher_component["manifestDigest"], f"signed-Nostr activation component[{index}] provenance")
        sbom = verify_signed_nostr_attestation_receipt(component["sbomAttestation"], publisher_component["sbomAttestation"], publisher_component["manifestDigest"], f"signed-Nostr activation component[{index}] SBOM")
        require(provenance["receiptId"] != sbom["receiptId"], "signed-Nostr activation component provenance/SBOM receipt id reused")
        require(provenance["attestationDigest"] != sbom["attestationDigest"], "signed-Nostr activation component provenance/SBOM digest reused")
        for receipt in (provenance, sbom):
            require(receipt["attestationDigest"] not in attestation_digests, "signed-Nostr activation attestation digest reused")
            require(receipt["receiptId"] not in attestation_ids, "signed-Nostr activation attestation receipt id reused")
            attestation_digests.add(receipt["attestationDigest"])
            attestation_ids.add(receipt["receiptId"])

    require(isinstance(evidence["fluxBindings"], list) and len(evidence["fluxBindings"]) == 3, "signed-Nostr Flux binding count invalid")
    for index, item in enumerate(evidence["fluxBindings"]):
        binding = closed(
            item,
            {"component", "kustomization", "serviceAccount", "role", "roleBinding"},
            f"signed-Nostr Flux binding[{index}]",
        )
        expected_component = SIGNED_NOSTR_FLUX_BINDING_ORDER[index]
        require(binding["component"] == expected_component, "signed-Nostr Flux binding component order invalid")
        expected_flux = expected_signed_nostr_flux_objects(expected_component)
        for kind in ("serviceAccount", "role", "roleBinding"):
            verify_signed_nostr_object_receipt(
                binding[kind],
                expected_flux[kind],
                f"signed-Nostr Flux binding[{index}] {kind}",
            )
        verify_signed_nostr_object_receipt(
            binding["kustomization"],
            expected_flux["kustomization"],
            f"signed-Nostr Flux binding[{index}] Kustomization",
        )

    gnosis = closed(
        evidence["gnosisRpcEgress"],
        {"chainId", "upstream", "privateProxy", "workbenchNetworkPolicy"},
        "signed-Nostr Gnosis RPC egress evidence",
    )
    require(gnosis["chainId"] == 100, "signed-Nostr Gnosis chain id invalid")
    upstream = closed(gnosis["upstream"], {"scheme", "host", "port", "pinnedIpv4Cidr", "allowedMethods", "dnsTlsEvidence"}, "signed-Nostr Gnosis upstream evidence")
    require({key: upstream[key] for key in ("scheme", "host", "port", "pinnedIpv4Cidr", "allowedMethods")} == {
        "scheme": "https",
        "host": SIGNED_NOSTR_GNOSIS_UPSTREAM_HOST,
        "port": SIGNED_NOSTR_GNOSIS_UPSTREAM_PORT,
        "pinnedIpv4Cidr": SIGNED_NOSTR_GNOSIS_UPSTREAM_IPV4_CIDR,
        "allowedMethods": list(SIGNED_NOSTR_GNOSIS_ALLOWED_METHODS),
    }, "signed-Nostr Gnosis upstream invalid")
    initial_dns_tls = verify_signed_nostr_dns_tls_evidence(
        upstream["dnsTlsEvidence"],
        "signed-Nostr reviewed DNS/TLS evidence",
    )
    private_proxy = closed(
        gnosis["privateProxy"],
        {"name", "namespace", "port", "runtimeRole", "deployment", "service", "networkPolicy"},
        "signed-Nostr Gnosis private proxy evidence",
    )
    require(private_proxy["name"] == SIGNED_NOSTR_GNOSIS_PROXY_NAME, "signed-Nostr Gnosis private proxy name invalid")
    require(private_proxy["namespace"] == SIGNED_NOSTR_WEB_NAMESPACE, "signed-Nostr Gnosis private proxy namespace invalid")
    require(private_proxy["port"] == SIGNED_NOSTR_GNOSIS_PROXY_PORT, "signed-Nostr Gnosis private proxy port invalid")
    require(private_proxy["runtimeRole"] == "gnosis-rpc-proxy", "signed-Nostr Gnosis private proxy runtime role invalid")
    workbench_publisher = publisher_components["roebel-e2e-workbench"]
    workbench_image = f"{workbench_publisher['image']}@{workbench_publisher['manifestDigest']}"
    verify_signed_nostr_object_receipt(private_proxy["deployment"], expected_signed_nostr_gnosis_private_proxy_deployment(workbench_image), "signed-Nostr Gnosis private proxy Deployment")
    verify_signed_nostr_object_receipt(private_proxy["service"], expected_signed_nostr_gnosis_private_proxy_service(), "signed-Nostr Gnosis private proxy Service")
    verify_signed_nostr_object_receipt(private_proxy["networkPolicy"], expected_signed_nostr_gnosis_private_proxy_network_policy(), "signed-Nostr Gnosis private proxy NetworkPolicy")
    verify_signed_nostr_object_receipt(gnosis["workbenchNetworkPolicy"], expected_signed_nostr_workbench_network_policy(), "signed-Nostr workbench NetworkPolicy")

    verify_signed_nostr_anonymous_digest_pull_receipts(
        evidence["anonymousDigestPullReceipts"],
        publisher_pin,
        publisher_pin_canonical_sha256,
    )

    managed_suspended = expected_signed_nostr_managed_objects(
        publisher_pin,
        suspended_flux=True,
    )
    managed_active = expected_signed_nostr_managed_objects(
        publisher_pin,
        suspended_flux=False,
    )
    lifecycle = closed(
        evidence["lifecycle"],
        {
            "livePreconditions",
            "bootstrapReceipt",
            "activationLiveRecheck",
            "reconcileActivationReceipt",
            "rollbackContract",
        },
        "signed-Nostr lifecycle evidence",
    )
    preconditions = verify_signed_nostr_live_preconditions(
        lifecycle["livePreconditions"],
        managed_suspended,
    )
    bootstrap = verify_signed_nostr_bootstrap_receipt(
        lifecycle["bootstrapReceipt"],
        preconditions,
        managed_suspended,
    )
    live_recheck = verify_signed_nostr_activation_live_recheck(
        lifecycle["activationLiveRecheck"],
        bootstrap,
        rollback_record,
        initial_dns_tls,
    )
    reconcile = verify_signed_nostr_reconcile_activation(
        lifecycle["reconcileActivationReceipt"],
        live_recheck,
        bootstrap,
        managed_suspended,
        managed_active,
    )
    require(
        lifecycle["rollbackContract"]
        == expected_signed_nostr_rollback_contract(
            managed_suspended,
            bootstrap,
            reconcile,
            rollback_record,
        ),
        "signed-Nostr rollback contract incomplete or drifted",
    )
    return evidence


def verify_signed_nostr_anonymous_digest_pull_receipts(
    value: Any,
    publisher_pin: dict[str, Any],
    publisher_pin_canonical_sha256: str,
) -> None:
    require(isinstance(value, list) and len(value) == 2, "signed-Nostr anonymous digest receipt count invalid")
    require(
        [entry["component"] for entry in publisher_pin["components"]] == list(SIGNED_NOSTR_PUBLISHER_COMPONENT_ORDER),
        "signed-Nostr publisher component order invalid",
    )
    publisher_components = {entry["component"]: entry for entry in publisher_pin["components"]}
    expected = {
        "roebel-e2e-workbench": "ghcr.io/giraeffleaeffle/roebel-e2e-workbench",
        "roebel-staging-relay": "ghcr.io/giraeffleaeffle/roebel-staging-relay",
    }
    seen: set[str] = set()
    for index, value_item in enumerate(value):
        receipt = closed(
            value_item,
            {
                "schemaVersion",
                "canonicalEncoding",
                "publisherPinCanonicalSha256",
                "component",
                "imageRepository",
                "manifestDigest",
                "sourceRevision",
                "authContext",
                "authConfigCanonicalSha256",
                "resolverIdentity",
                "resolvedManifestDigest",
                "receiptDigest",
            },
            f"signed-Nostr anonymous digest receipt[{index}]",
        )
        require(
            receipt["schemaVersion"] == SIGNED_NOSTR_ANONYMOUS_DIGEST_PULL_RECEIPT_SCHEMA,
            "signed-Nostr anonymous digest receipt schema invalid",
        )
        require(
            receipt["canonicalEncoding"] == "canonical-json",
            "signed-Nostr anonymous digest receipt canonical encoding invalid",
        )
        require(
            receipt["publisherPinCanonicalSha256"] == publisher_pin_canonical_sha256,
            "signed-Nostr anonymous digest receipt publisher checksum binding invalid",
        )
        component = receipt["component"]
        require(
            component == SIGNED_NOSTR_PUBLISHER_COMPONENT_ORDER[index],
            "signed-Nostr anonymous digest receipt component order invalid",
        )
        require(component in expected and component not in seen, "signed-Nostr anonymous digest receipt component invalid")
        seen.add(component)
        publisher = publisher_components[component]
        require(receipt["imageRepository"] == expected[component] == publisher["image"], "signed-Nostr anonymous digest receipt image invalid")
        require(receipt["manifestDigest"] == publisher["manifestDigest"], "signed-Nostr anonymous digest receipt manifest binding invalid")
        require(receipt["sourceRevision"] == publisher_pin["sourceRevision"], "signed-Nostr anonymous digest receipt source binding invalid")
        require(receipt["authContext"] == "clean-empty-auth-config", "signed-Nostr anonymous digest receipt auth context invalid")
        require(
            receipt["authConfigCanonicalSha256"] == SIGNED_NOSTR_CLEAN_EMPTY_AUTH_CONFIG_SHA256,
            "signed-Nostr anonymous digest receipt auth hash invalid",
        )
        require(receipt["resolverIdentity"] == "oras-resolve-anonymous", "signed-Nostr anonymous digest receipt resolver invalid")
        require(receipt["resolvedManifestDigest"] == publisher["manifestDigest"], "signed-Nostr anonymous digest receipt resolved digest invalid")
        require(
            receipt["receiptDigest"] == digest({key: item for key, item in receipt.items() if key != "receiptDigest"}),
            "signed-Nostr anonymous digest receipt checksum invalid",
        )
    require(seen == set(expected), "signed-Nostr anonymous digest receipt component set invalid")


def signed_nostr_runtime_image(component: str, runtime_pin: dict[str, Any]) -> str:
    source_component = "roebel-e2e-workbench" if component == "workbench" else "roebel-staging-relay"
    record = runtime_pin["images"][source_component]
    return f"{record['image']}@{record['manifestDigest']}"


def signed_nostr_relay_environment(component: str) -> list[dict[str, Any]]:
    base = [
        {"name": "RELAY_NAME", "value": component},
        {"name": "RELAY_PORT", "value": "18081"},
        {"name": "RELAY_BIND_HOST", "value": "0.0.0.0"},
        {"name": "RELAY_WEBSOCKET_PATH", "value": f"/{component}"},
        {"name": "RELAY_EVENT_STORE", "value": "/relay/events.ndjson"},
        {"name": "RELAY_MAX_EVENT_STORE_BYTES", "value": "67108864"},
        {"name": "RELAY_MAX_EVENT_COUNT", "value": "50000"},
        {
            "name": "RELAY_ALLOWED_PUBKEYS",
            "valueFrom": {"secretKeyRef": {"key": "MECKY_PUBKEY", "name": "roebel-signed-nostr-runtime", "optional": False}},
        },
    ]
    if component == "citizen-relay":
        base.extend([
            {"name": "RELAY_ADMISSION_STORE", "value": "/relay/admissions.ndjson"},
            {"name": "RELAY_MAX_ADMISSION_STORE_BYTES", "value": "16777216"},
            {"name": "RELAY_MAX_ADMISSION_COUNT", "value": "10000"},
            {
                "name": "RELAY_ADMISSION_TOKEN",
                "valueFrom": {"secretKeyRef": {"key": "CITIZEN_RELAY_ADMISSION_TOKEN", "name": "roebel-signed-nostr-runtime", "optional": False}},
            },
        ])
    return base


def expected_signed_nostr_resources(runtime_pin: dict[str, Any]) -> dict[str, Any]:
    """Return the whole future runtime shape without materialising manifests.

    The renderer remains unavailable while the evidence gate below is pending;
    this function exists so the protected verifier can constrain that later
    review to one exact topology rather than accepting arbitrary YAML.
    """
    resources: dict[str, Any] = {}
    for component in SIGNED_NOSTR_COMPONENTS:
        labels = signed_nostr_labels(component)
        namespace = signed_nostr_namespace(component)
        port = SIGNED_NOSTR_PORTS[component]
        if component == "workbench":
            environment = [
                {"name": "WORKBENCH_MODE", "value": "public-signed-only"},
                {"name": "WORKBENCH_PORT", "value": "18083"},
                {"name": "WORKBENCH_BIND_HOST", "value": "0.0.0.0"},
                {"name": "CITIZEN_RELAY_URL", "value": "ws://citizen-relay.stadtstack-roebel-staging-lab.svc.cluster.local:18081"},
                {"name": "AGENT_RELAY_URL", "value": "ws://agent-relay.stadtstack-roebel-staging-lab.svc.cluster.local:18081"},
                {"name": "GNOSIS_RPC_URL", "value": f"http://{SIGNED_NOSTR_GNOSIS_PROXY_NAME}.{SIGNED_NOSTR_WEB_NAMESPACE}.svc.cluster.local:{SIGNED_NOSTR_GNOSIS_PROXY_PORT}"},
                {"name": "MECKY_PUBKEY", "valueFrom": {"secretKeyRef": {"key": "MECKY_PUBKEY", "name": "roebel-signed-nostr-runtime", "optional": False}}},
                {"name": "CITIZEN_RELAY_ADMISSION_TOKEN", "valueFrom": {"secretKeyRef": {"key": "CITIZEN_RELAY_ADMISSION_TOKEN", "name": "roebel-signed-nostr-runtime", "optional": False}}},
            ]
            pod_extra: dict[str, Any] = {}
            container_extra: dict[str, Any] = {}
        else:
            environment = signed_nostr_relay_environment(component)
            pod_extra = {"volumes": [{"emptyDir": {"sizeLimit": "128Mi"}, "name": "relay-store"}]}
            container_extra = {"volumeMounts": [{"mountPath": "/relay", "name": "relay-store"}]}
        container = {
            "env": environment,
            "image": signed_nostr_runtime_image(component, runtime_pin),
            "imagePullPolicy": "IfNotPresent",
            "livenessProbe": {"failureThreshold": 3, "periodSeconds": 20, "successThreshold": 1, "tcpSocket": {"port": "http"}, "timeoutSeconds": 3},
            "name": SIGNED_NOSTR_NAMES[component],
            "ports": [{"containerPort": port, "name": "http", "protocol": "TCP"}],
            "readinessProbe": {"failureThreshold": 3, "periodSeconds": 10, "successThreshold": 1, "tcpSocket": {"port": "http"}, "timeoutSeconds": 3},
            "resources": {"limits": {"cpu": "250m", "ephemeral-storage": "128Mi", "memory": "112Mi"}, "requests": {"cpu": "10m", "ephemeral-storage": "64Mi", "memory": "32Mi"}},
            "securityContext": signed_nostr_container_security_context(),
            "startupProbe": {"failureThreshold": 30, "periodSeconds": 2, "successThreshold": 1, "tcpSocket": {"port": "http"}, "timeoutSeconds": 3},
            **container_extra,
        }
        deployment = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"labels": labels, "name": SIGNED_NOSTR_NAMES[component], "namespace": namespace},
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": labels},
                "template": {
                    "metadata": {"labels": labels},
                    "spec": {
                        "automountServiceAccountToken": False,
                        "containers": [container],
                        "restartPolicy": "Always",
                        "securityContext": signed_nostr_pod_security_context(),
                        **pod_extra,
                    },
                },
            },
        }
        service = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"labels": labels, "name": SIGNED_NOSTR_NAMES[component], "namespace": namespace},
            "spec": {"ports": [{"name": "http", "port": port, "protocol": "TCP", "targetPort": "http"}], "selector": labels, "type": "ClusterIP"},
        }
        resources[component] = {"deployment": deployment, "service": service}

    workbench_labels = signed_nostr_labels("workbench")
    relay_from = [
        {
            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": SIGNED_NOSTR_WEB_NAMESPACE}},
            "podSelector": {"matchLabels": workbench_labels},
        },
        {
            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": SIGNED_NOSTR_NAMESPACE}},
            "podSelector": {"matchLabels": PUBLIC_MECKY_LABELS},
        },
    ]
    workbench_image = signed_nostr_runtime_image("workbench", runtime_pin)
    resources["workbench"]["networkPolicy"] = expected_signed_nostr_workbench_network_policy()
    resources["workbench"]["gnosisProxyDeployment"] = expected_signed_nostr_gnosis_private_proxy_deployment(workbench_image)
    resources["workbench"]["gnosisProxyService"] = expected_signed_nostr_gnosis_private_proxy_service()
    resources["workbench"]["gnosisProxyNetworkPolicy"] = expected_signed_nostr_gnosis_private_proxy_network_policy()
    for relay in ("citizen-relay", "agent-relay"):
        labels = signed_nostr_labels(relay)
        resources[relay]["networkPolicy"] = {
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"labels": labels, "name": SIGNED_NOSTR_NAMES[relay], "namespace": SIGNED_NOSTR_NAMESPACE},
            "spec": {"egress": [], "ingress": [{"from": relay_from, "ports": [{"port": 18081, "protocol": "TCP"}]}], "podSelector": {"matchLabels": labels}, "policyTypes": ["Ingress", "Egress"]},
        }
    for component in SIGNED_NOSTR_COMPONENTS:
        extra = ""
        if component == "workbench":
            extra = (
                "  - gnosis-proxy-deployment.json\n"
                "  - gnosis-proxy-service.json\n"
                "  - gnosis-proxy-networkpolicy.json\n"
            )
        resources[component]["kustomization"] = (
            "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n"
            "  - deployment.json\n  - service.json\n  - networkpolicy.json\n"
            + extra
        )
    return resources


def expected_public_mecky_network_policy(reviewed_egress: bool, signed_nostr: bool = False) -> dict[str, Any]:
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
    if signed_nostr:
        require(reviewed_egress, "signed-Nostr Public Mecky policy requires reviewed knowledge egress")
        spec = {
            **spec,
            "egress": [
                *spec["egress"],
                *[
                    {
                        "to": [{
                            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": SIGNED_NOSTR_NAMESPACE}},
                            "podSelector": {"matchLabels": signed_nostr_labels(relay)},
                        }],
                        "ports": [{"port": 18081, "protocol": "TCP"}],
                    }
                    for relay in ("citizen-relay", "agent-relay")
                ],
            ],
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


def verify_signed_nostr(root: Path) -> dict[str, Any]:
    runtime_pin = verify_signed_nostr_runtime_pin(load_json(root / SIGNED_NOSTR_RUNTIME_PIN))
    expected = expected_signed_nostr_resources(runtime_pin)
    actual: dict[str, Any] = {}
    for component in SIGNED_NOSTR_COMPONENTS:
        component_root = root / SIGNED_NOSTR_ROOT / component
        deployment = load_json(component_root / "deployment.json")
        service = load_json(component_root / "service.json")
        network_policy = load_json(component_root / "networkpolicy.json")
        kustomization = (component_root / "kustomization.yaml").read_text()
        require(deployment == expected[component]["deployment"], f"signed-Nostr {component} Deployment drift")
        require(service == expected[component]["service"], f"signed-Nostr {component} Service drift")
        require(network_policy == expected[component]["networkPolicy"], f"signed-Nostr {component} NetworkPolicy drift")
        require(kustomization == expected[component]["kustomization"], f"signed-Nostr {component} Flux path widened")
        actual[component] = {
            "deployment": deployment,
            "service": service,
            "networkPolicy": network_policy,
            "kustomization": kustomization,
        }
        if component == "workbench":
            proxy_deployment = load_json(component_root / "gnosis-proxy-deployment.json")
            proxy_service = load_json(component_root / "gnosis-proxy-service.json")
            proxy_policy = load_json(component_root / "gnosis-proxy-networkpolicy.json")
            require(proxy_deployment == expected[component]["gnosisProxyDeployment"], "signed-Nostr Gnosis proxy Deployment drift")
            require(proxy_service == expected[component]["gnosisProxyService"], "signed-Nostr Gnosis proxy Service drift")
            require(proxy_policy == expected[component]["gnosisProxyNetworkPolicy"], "signed-Nostr Gnosis proxy NetworkPolicy drift")
            actual[component]["gnosisProxyDeployment"] = proxy_deployment
            actual[component]["gnosisProxyService"] = proxy_service
            actual[component]["gnosisProxyNetworkPolicy"] = proxy_policy
    # Both relay Deployment images bind to the one relay digest from the pin;
    # this prevents a citizen/agent mixed build from entering staging.
    citizen_image = actual["citizen-relay"]["deployment"]["spec"]["template"]["spec"]["containers"][0]["image"]
    agent_image = actual["agent-relay"]["deployment"]["spec"]["template"]["spec"]["containers"][0]["image"]
    require(citizen_image == agent_image, "signed-Nostr relays must share one immutable digest")
    approved = SIGNED_NOSTR_APPROVED_ACTIVATION_EVIDENCE
    require(
        approved is not None,
        "signed-Nostr activation blocked: complete Gnosis, Flux, provenance, and anonymous-pull evidence require separate review",
    )
    require(
        runtime_pin["pin"]["activationEvidence"] == approved,
        "signed-Nostr activation evidence does not equal the exact approved policy record",
    )
    verify_signed_nostr_activation_evidence(
        approved,
        runtime_pin["publisherPin"],
        runtime_pin["pin"]["publisherPinCanonicalSha256"],
        runtime_pin["pin"]["rollback"],
    )
    return {"runtimePin": runtime_pin["pin"], "components": actual}


def verify_public_mecky_network_policy(
    root: Path,
    reviewed_knowledge: bool,
    signed_nostr: bool,
) -> tuple[dict[str, Any], bool]:
    policy = load_json(root / RENDER_ROOT / "public-mecky/networkpolicy.json")
    legacy = expected_public_mecky_network_policy(False)
    reviewed = expected_public_mecky_network_policy(True)
    signed = expected_public_mecky_network_policy(True, True)
    require(policy in (legacy, reviewed, signed), "Public Mecky NetworkPolicy drift")
    reviewed_egress = policy == reviewed
    signed_egress = policy == signed
    require(
        not reviewed_egress or reviewed_knowledge,
        "Public Mecky reviewed-runtime egress requires the complete reviewed runtime render",
    )
    require(not signed_egress or signed_nostr, "Public Mecky relay egress requires the complete signed-Nostr render")
    require(not signed_nostr or signed_egress, "signed-Nostr render requires exact Public Mecky relay egress")
    return policy, reviewed_egress or signed_egress


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


def participant_gateway_secret_env(name: str, secret: str, key: str) -> dict[str, Any]:
    return {
        "name": name,
        "valueFrom": {"secretKeyRef": {"key": key, "name": secret, "optional": False}},
    }


def participant_gateway_target(kind: str, name: str, namespace: str) -> dict[str, str]:
    api_versions = {
        "Deployment": "apps/v1",
        "Ingress": "networking.k8s.io/v1",
        "GitRepository": "source.toolkit.fluxcd.io/v1",
        "Kustomization": "kustomize.toolkit.fluxcd.io/v1",
        "NetworkPolicy": "networking.k8s.io/v1",
        "Role": "rbac.authorization.k8s.io/v1",
        "RoleBinding": "rbac.authorization.k8s.io/v1",
        "Secret": "v1",
        "Service": "v1",
        "ServiceAccount": "v1",
    }
    api_version = api_versions.get(kind)
    require(api_version is not None, f"participant gateway target kind invalid: {kind}")
    return {"apiVersion": api_version, "kind": kind, "name": name, "namespace": namespace}


def expected_participant_gateway_flux_objects(*, suspended: bool = True) -> dict[str, dict[str, Any]]:
    return PARTICIPANT_POLICY.gateway_flux_objects(suspended=suspended)


def expected_participant_workbench_ingress_flux_objects(
    *, suspended: bool = True,
) -> dict[str, dict[str, Any]]:
    return PARTICIPANT_POLICY.workbench_ingress_flux_objects(suspended=suspended)


def _legacy_expected_participant_gateway_flux_objects(*, suspended: bool = True) -> dict[str, dict[str, Any]]:
    labels = {**PARTICIPANT_GATEWAY_LABELS, "stadtstack.io/gitops-owner": "participant-gateway", "stadtstack.io/flux-tenant": "roebel-staging"}
    service_account = {
        "apiVersion": "v1", "kind": "ServiceAccount",
        # Flux resolves spec.serviceAccountName in the Kustomization namespace,
        # never in targetNamespace.  The application workload ServiceAccount is
        # separately rendered in the target namespace.
        "metadata": {"labels": labels, "name": PARTICIPANT_GATEWAY_FLUX_SERVICE_ACCOUNT, "namespace": PARTICIPANT_GATEWAY_FLUX_NAMESPACE},
        "automountServiceAccountToken": False,
    }
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"labels": labels, "name": PARTICIPANT_GATEWAY_FLUX_ROLE, "namespace": PARTICIPANT_GATEWAY_NAMESPACE},
        "rules": [
            {"apiGroups": [""], "resourceNames": [PARTICIPANT_GATEWAY_NAME], "resources": ["serviceaccounts", "services"], "verbs": ["get", "patch", "update"]},
            {"apiGroups": ["apps"], "resourceNames": [PARTICIPANT_GATEWAY_NAME], "resources": ["deployments"], "verbs": ["get", "patch", "update"]},
            {"apiGroups": ["networking.k8s.io"], "resourceNames": [PARTICIPANT_GATEWAY_NAME], "resources": ["networkpolicies"], "verbs": ["get", "patch", "update"]},
            {"apiGroups": ["networking.k8s.io"], "resourceNames": [PARTICIPANT_GATEWAY_NAME], "resources": ["ingresses"], "verbs": ["get", "patch", "update"]},
        ],
    }
    role_binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"labels": labels, "name": PARTICIPANT_GATEWAY_FLUX_ROLE_BINDING, "namespace": PARTICIPANT_GATEWAY_NAMESPACE},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": PARTICIPANT_GATEWAY_FLUX_ROLE},
        "subjects": [{"kind": "ServiceAccount", "name": PARTICIPANT_GATEWAY_FLUX_SERVICE_ACCOUNT, "namespace": PARTICIPANT_GATEWAY_FLUX_NAMESPACE}],
    }
    kustomization = {
        "apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization",
        "metadata": {"labels": labels, "name": PARTICIPANT_GATEWAY_FLUX_KUSTOMIZATION, "namespace": PARTICIPANT_GATEWAY_FLUX_NAMESPACE},
        "spec": {
            "deletionPolicy": "Orphan", "dependsOn": [], "force": False,
            "healthChecks": [{"apiVersion": "apps/v1", "kind": "Deployment", "name": PARTICIPANT_GATEWAY_NAME, "namespace": PARTICIPANT_GATEWAY_NAMESPACE}],
            "interval": "5m", "path": f"./{PARTICIPANT_GATEWAY_ROOT}",
            "prune": False, "retryInterval": "30s", "serviceAccountName": PARTICIPANT_GATEWAY_FLUX_SERVICE_ACCOUNT,
            "sourceRef": {"kind": "GitRepository", "name": PARTICIPANT_GATEWAY_FLUX_SOURCE_NAME, "namespace": PARTICIPANT_GATEWAY_FLUX_NAMESPACE},
            "timeout": "2m", "wait": True,
            # The policy bootstrap must not point an active controller at an
            # absent render path.  A separately receipt-bound CAS unsuspend is
            # the only later activation transition.
            "suspend": suspended, "targetNamespace": PARTICIPANT_GATEWAY_NAMESPACE,
        },
    }
    return {"kustomization": kustomization, "serviceAccount": service_account, "role": role, "roleBinding": role_binding}


def expected_participant_gateway_flux_source() -> dict[str, Any]:
    """Return the immutable projection of the shared, active Flux source.

    The participant boundary owns only its dedicated Kustomization.  It may
    never suspend, patch, or adopt this shared GitRepository.
    """
    return PARTICIPANT_POLICY.expected_shared_flux_source_projection()


def verify_participant_gateway_dns_tls_evidence(value: Any, endpoint: dict[str, Any], label: str) -> dict[str, Any]:
    evidence = closed(value, {"schemaVersion", "canonicalEncoding", "resolverIdentity", "resolutionMethod", "queriedHost", "queriedPort", "observedAt", "validUntil", "maxAgeSeconds", "addresses", "tlsCertificate"}, label)
    require(evidence["schemaVersion"] == PARTICIPANT_GATEWAY_DNS_TLS_EVIDENCE_SCHEMA, f"{label} schema invalid")
    require(evidence["canonicalEncoding"] == "canonical-json" and evidence["resolverIdentity"] == "reviewed-doh-resolver" and evidence["resolutionMethod"] == "dns-over-https-a-and-aaaa", f"{label} resolver identity invalid")
    origin = urlparse(endpoint["httpsOrigin"])
    require(evidence["queriedHost"] == origin.hostname and evidence["queriedPort"] == 443, f"{label} endpoint binding invalid")
    observed, valid_until = utc_timestamp(evidence["observedAt"], f"{label} observedAt"), utc_timestamp(evidence["validUntil"], f"{label} validUntil")
    require(evidence["maxAgeSeconds"] == 300 and 0 < duration_seconds(observed, valid_until) <= 300, f"{label} freshness window invalid")
    addresses = closed(evidence["addresses"], {"a", "aaaa"}, f"{label} addresses")
    expected_a = [str(ipaddress.ip_network(cidr, strict=True).network_address) for cidr in endpoint["ipv4Cidrs"]]
    require(addresses == {"a": expected_a, "aaaa": []}, f"{label} DNS answer does not equal reviewed /32 set")
    certificate = closed(evidence["tlsCertificate"], {"serverName", "issuer", "certificateSha256", "notBefore", "notAfter"}, f"{label} certificate")
    require(certificate["serverName"] == origin.hostname and isinstance(certificate["issuer"], str) and certificate["issuer"], f"{label} TLS identity invalid")
    require(isinstance(certificate["certificateSha256"], str) and SHA256.fullmatch(certificate["certificateSha256"]), f"{label} TLS digest invalid")
    require(utc_timestamp(certificate["notBefore"], f"{label} notBefore") <= observed <= valid_until < utc_timestamp(certificate["notAfter"], f"{label} notAfter"), f"{label} TLS validity invalid")
    return evidence


def participant_gateway_dns_tls_binding(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "resolverIdentity": value["resolverIdentity"],
        "resolutionMethod": value["resolutionMethod"],
        "queriedHost": value["queriedHost"],
        "queriedPort": value["queriedPort"],
        "addresses": value["addresses"],
        "tlsCertificate": value["tlsCertificate"],
    }


def verify_participant_gateway_flux_bootstrap(value: Any, operations_revision: str) -> dict[str, Any]:
    """Validate the one-time *suspended* Flux identity bootstrap.

    This is deliberately an evidence record, not a manifest.  The protected
    constant must bind its four exact objects and prove they were absent at
    collection time.  In particular it cannot authorise the participant
    reconciler to take ownership of the existing Web Ingress.
    """
    bootstrap = closed(
        value,
        {"objects", "resourceAbsenceReceipts", "bootstrapReceipt", "sourceReceipt", "webIngressReconciler"},
        "participant gateway Flux bootstrap",
    )
    expected = expected_participant_gateway_flux_objects(suspended=True)
    order = ("kustomization", "serviceAccount", "role", "roleBinding")
    objects = bootstrap["objects"]
    require(isinstance(objects, list) and len(objects) == len(order), "participant gateway Flux object count invalid")
    for object_id, value_item in zip(order, objects, strict=True):
        item = closed(value_item, {"objectId", "target", "object", "objectCanonicalSha256"}, f"participant gateway Flux {object_id}")
        require(item["objectId"] == object_id, "participant gateway Flux object order invalid")
        require(item["target"] == participant_gateway_target(
            expected[object_id]["kind"], expected[object_id]["metadata"]["name"], expected[object_id]["metadata"]["namespace"],
        ), "participant gateway Flux target invalid")
        require(item["object"] == expected[object_id], "participant gateway Flux object widened or drifted")
        require(item["objectCanonicalSha256"] == digest(expected[object_id]), "participant gateway Flux object digest invalid")

    receipts = bootstrap["resourceAbsenceReceipts"]
    require(isinstance(receipts, list) and len(receipts) == len(order), "participant gateway absence receipt count invalid")
    for object_id, value_item in zip(order, receipts, strict=True):
        expected_object = expected[object_id]
        item = closed(
            value_item,
            {"objectId", "target", "desiredObjectDigest", "state", "uid", "resourceVersion", "currentObjectDigest", "observedAt", "validUntil", "maxAgeSeconds", "apiOutcome", "receiptCanonicalSha256"},
            f"participant gateway absence receipt {object_id}",
        )
        require(item["objectId"] == object_id, "participant gateway absence receipt order invalid")
        require(item["target"] == participant_gateway_target(
            expected_object["kind"], expected_object["metadata"]["name"], expected_object["metadata"]["namespace"],
        ), "participant gateway absence receipt target invalid")
        require(item["desiredObjectDigest"] == digest(expected_object), "participant gateway absence desired object digest invalid")
        require(
            item["state"] == "absent" and item["uid"] is None and item["resourceVersion"] is None and item["currentObjectDigest"] is None,
            "participant gateway bootstrap must prove resource absence without adoption",
        )
        observed = utc_timestamp(item["observedAt"], f"participant gateway absence {object_id} observedAt")
        valid_until = utc_timestamp(item["validUntil"], f"participant gateway absence {object_id} validUntil")
        require(item["maxAgeSeconds"] == 300 and 0 < duration_seconds(observed, valid_until) <= 300, "participant gateway absence receipt freshness invalid")
        require(item["apiOutcome"] == "http-404-not-found", "participant gateway absence receipt API outcome invalid")
        canonical = {key: item[key] for key in item if key != "receiptCanonicalSha256"}
        require(item["receiptCanonicalSha256"] == digest(canonical), "participant gateway absence receipt digest invalid")

    receipt = closed(
        bootstrap["bootstrapReceipt"],
        {"status", "operationId", "completedAt", "validUntil", "maxAgeSeconds", "postconditions", "postconditionsCanonicalSha256"},
        "participant gateway suspended Flux bootstrap receipt",
    )
    require(receipt["status"] == "completed-suspended-create-only", "participant gateway bootstrap receipt status invalid")
    require(isinstance(receipt["operationId"], str) and UUID.fullmatch(receipt["operationId"]), "participant gateway bootstrap operation id invalid")
    completed = utc_timestamp(receipt["completedAt"], "participant gateway bootstrap completedAt")
    valid_until = utc_timestamp(receipt["validUntil"], "participant gateway bootstrap validUntil")
    require(receipt["maxAgeSeconds"] == 300 and 0 < duration_seconds(completed, valid_until) <= 300, "participant gateway bootstrap receipt freshness invalid")
    postconditions = receipt["postconditions"]
    require(isinstance(postconditions, list) and len(postconditions) == len(order), "participant gateway bootstrap postcondition count invalid")
    for object_id, value_item in zip(order, postconditions, strict=True):
        expected_object = expected[object_id]
        item = closed(
            value_item,
            {"objectId", "target", "uid", "resourceVersion", "objectCanonicalSha256", "apiOperation", "apiOutcome", "conflictPolicy"},
            f"participant gateway bootstrap postcondition {object_id}",
        )
        require(item["objectId"] == object_id, "participant gateway bootstrap postcondition order invalid")
        require(item["target"] == participant_gateway_target(expected_object["kind"], expected_object["metadata"]["name"], expected_object["metadata"]["namespace"]), "participant gateway bootstrap postcondition target invalid")
        require(isinstance(item["uid"], str) and UUID.fullmatch(item["uid"]), "participant gateway bootstrap postcondition UID invalid")
        require(isinstance(item["resourceVersion"], str) and item["resourceVersion"].isdigit(), "participant gateway bootstrap postcondition resourceVersion invalid")
        require(item["objectCanonicalSha256"] == digest(expected_object), "participant gateway bootstrap postcondition object drift")
        require(item["apiOperation"] == "POST-create" and item["apiOutcome"] == "http-201-created" and item["conflictPolicy"] == "fail-on-http-409-no-adopt", "participant gateway bootstrap postcondition not create-only")
    require(receipt["postconditionsCanonicalSha256"] == digest(postconditions), "participant gateway bootstrap postcondition checksum invalid")

    source = closed(bootstrap["sourceReceipt"], {"target", "uid", "resourceVersion", "liveObject", "liveObjectCanonicalSha256", "lastAppliedRevision"}, "participant gateway Flux GitRepository source receipt")
    require(source["target"] == participant_gateway_target("GitRepository", PARTICIPANT_GATEWAY_FLUX_SOURCE_NAME, PARTICIPANT_GATEWAY_FLUX_NAMESPACE), "participant gateway Flux source target invalid")
    require(isinstance(source["uid"], str) and UUID.fullmatch(source["uid"]) and isinstance(source["resourceVersion"], str) and source["resourceVersion"].isdigit(), "participant gateway Flux source identity invalid")
    expected_source = expected_participant_gateway_flux_source()
    require(source["liveObject"] == expected_source and source["liveObjectCanonicalSha256"] == digest(expected_source), "participant gateway Flux source URL/ref/verification drift")
    require(source["lastAppliedRevision"] == operations_revision, "participant gateway Flux source revision invalid")

    web = closed(bootstrap["webIngressReconciler"], {"kustomization", "serviceAccount"}, "participant gateway Web reconciler binding")
    expected_web_kustomization = participant_gateway_target("Kustomization", PARTICIPANT_GATEWAY_WEB_FLUX_KUSTOMIZATION, PARTICIPANT_GATEWAY_FLUX_NAMESPACE)
    expected_web_sa = participant_gateway_target("ServiceAccount", PARTICIPANT_GATEWAY_WEB_FLUX_SERVICE_ACCOUNT, PARTICIPANT_GATEWAY_FLUX_NAMESPACE)
    for key, target in (("kustomization", expected_web_kustomization), ("serviceAccount", expected_web_sa)):
        record = closed(web[key], {"target", "uid", "resourceVersion", "liveObjectSha256"}, f"participant gateway Web reconciler {key}")
        require(record["target"] == target, f"participant gateway Web reconciler {key} target invalid")
        require(isinstance(record["uid"], str) and UUID.fullmatch(record["uid"]), f"participant gateway Web reconciler {key} UID invalid")
        require(isinstance(record["resourceVersion"], str) and record["resourceVersion"].isdigit(), f"participant gateway Web reconciler {key} resourceVersion invalid")
        require(isinstance(record["liveObjectSha256"], str) and SHA256.fullmatch(record["liveObjectSha256"]), f"participant gateway Web reconciler {key} digest invalid")
    return bootstrap


def verify_participant_gateway_activation_transaction(value: Any, flux_bootstrap: dict[str, Any]) -> dict[str, Any]:
    """Check the pre-approved dormant-to-active transaction template.

    A postcondition cannot be known until the CAS patch happens.  It is audit
    output, never candidate-controlled activation evidence; only this
    protected precondition/template is admitted in the policy merge.
    """
    transaction = closed(
        value,
        {"scriptSha256", "receiptSchemaVersion", "precondition", "patch", "postconditionTemplate"},
        "participant gateway activation transaction",
    )
    suspended = expected_participant_gateway_flux_objects(suspended=True)["kustomization"]
    active = expected_participant_gateway_flux_objects(suspended=False)["kustomization"]
    postcondition = flux_bootstrap["bootstrapReceipt"]["postconditions"][0]
    require(transaction["scriptSha256"] == participant_gateway_activation_script_sha256(), "participant gateway activation script drift")
    require(transaction["receiptSchemaVersion"] == PARTICIPANT_GATEWAY_ACTIVATION_RECEIPT_SCHEMA, "participant gateway activation receipt schema invalid")
    precondition = closed(transaction["precondition"], {"target", "requiredUid", "requiredResourceVersion", "beforeObjectDigest"}, "participant gateway activation transaction precondition")
    require(precondition["target"] == participant_gateway_target("Kustomization", PARTICIPANT_GATEWAY_FLUX_KUSTOMIZATION, PARTICIPANT_GATEWAY_FLUX_NAMESPACE), "participant gateway activation target invalid")
    require(precondition["requiredUid"] == postcondition["uid"] and precondition["requiredResourceVersion"] == postcondition["resourceVersion"], "participant gateway activation CAS binding invalid")
    require(precondition["beforeObjectDigest"] == digest(suspended) == postcondition["objectCanonicalSha256"], "participant gateway activation before object invalid")
    require(transaction["patch"] == {"op": "replace", "path": "/spec/suspend", "expected": True, "value": False}, "participant gateway activation patch widened")
    require(transaction["postconditionTemplate"] == {
        "target": participant_gateway_target("Kustomization", PARTICIPANT_GATEWAY_FLUX_KUSTOMIZATION, PARTICIPANT_GATEWAY_FLUX_NAMESPACE),
        "requiredUid": postcondition["uid"],
        "requiredResourceVersion": postcondition["resourceVersion"],
        "beforeObjectDigest": digest(suspended),
        "afterObjectDigest": digest(active),
        "apiOperation": "PATCH-json-cas",
        "apiOutcome": "http-200-re-read-exact-active",
    }, "participant gateway activation postcondition template drift")
    return transaction


def verify_participant_gateway_activation_postcondition_receipt(value: Any, transaction: dict[str, Any]) -> dict[str, Any]:
    """Validate audit output from the protected activation script, if supplied."""
    receipt = closed(
        value,
        {"schemaVersion", "target", "requiredUid", "requiredResourceVersion", "beforeObjectDigest", "postResourceVersion", "afterObjectDigest", "apiOperation", "apiOutcome", "completedAt"},
        "participant gateway activation postcondition receipt",
    )
    template = transaction["postconditionTemplate"]
    require(receipt["schemaVersion"] == PARTICIPANT_GATEWAY_ACTIVATION_RECEIPT_SCHEMA, "participant gateway activation audit schema invalid")
    for key in ("target", "requiredUid", "requiredResourceVersion", "beforeObjectDigest", "afterObjectDigest", "apiOperation", "apiOutcome"):
        require(receipt[key] == template[key], f"participant gateway activation audit {key} drift")
    require(isinstance(receipt["postResourceVersion"], str) and receipt["postResourceVersion"].isdigit() and int(receipt["postResourceVersion"]) > int(receipt["requiredResourceVersion"]), "participant gateway activation audit post resourceVersion invalid")
    utc_timestamp(receipt["completedAt"], "participant gateway activation audit completedAt")
    return receipt


def verify_participant_gateway_ingress_cas(value: Any, rollback: dict[str, Any], label: str) -> dict[str, Any]:
    record = closed(
        value,
        {"target", "uid", "resourceVersion", "liveObjectSha256", "observedAt", "validUntil", "maxAgeSeconds", "apiOutcome"},
        label,
    )
    require(record["target"] == participant_gateway_target("Ingress", PARTICIPANT_GATEWAY_NAME, PARTICIPANT_GATEWAY_NAMESPACE), f"{label} target invalid")
    require(isinstance(record["uid"], str) and UUID.fullmatch(record["uid"]), f"{label} UID invalid")
    require(isinstance(record["resourceVersion"], str) and record["resourceVersion"].isdigit(), f"{label} resourceVersion invalid")
    require(record["liveObjectSha256"] == rollback["participantIngressSha256"], f"{label} live bytes do not match participant rollback baseline")
    observed = utc_timestamp(record["observedAt"], f"{label} observedAt")
    valid_until = utc_timestamp(record["validUntil"], f"{label} validUntil")
    require(record["maxAgeSeconds"] == 300 and 0 < duration_seconds(observed, valid_until) <= 300, f"{label} freshness invalid")
    require(record["apiOutcome"] == "http-200-exact-live-bytes", f"{label} API outcome invalid")
    return record


def verify_participant_gateway_secret_materialization(value: Any, label: str) -> dict[str, Any]:
    materialization = closed(value, {"config", "runtime"}, label)
    expected = {
        "config": (PARTICIPANT_GATEWAY_CONFIG_SECRET, ["allowed-wallets", "invite-sha256", "mecky-pubkey"]),
        "runtime": (PARTICIPANT_GATEWAY_RUNTIME_SECRET, ["session-key", "supabase-anon-key", "supabase-rpc-secret"]),
    }
    for name, (secret_name, keys) in expected.items():
        record = closed(
            materialization[name],
            {"target", "uid", "resourceVersion", "keySet", "state", "semanticChecks", "materializedAt", "validUntil", "maxAgeSeconds", "vaultArm", "receiptCanonicalSha256"},
            f"{label} {name} Secret",
        )
        require(record["target"] == participant_gateway_target("Secret", secret_name, PARTICIPANT_GATEWAY_NAMESPACE), f"{label} {name} Secret target invalid")
        require(isinstance(record["uid"], str) and UUID.fullmatch(record["uid"]), f"{label} {name} Secret UID invalid")
        require(isinstance(record["resourceVersion"], str) and record["resourceVersion"].isdigit(), f"{label} {name} Secret resourceVersion invalid")
        require(record["keySet"] == keys and record["state"] == "present-exact-keyset", f"{label} {name} Secret key set invalid")
        expected_semantics = (
            {"inviteSha256Is64LowerHex": True, "meckyPubkeyIs64LowerHex": True, "walletAllowListNonEmptyNormalized": True}
            if name == "config" else
            {"sessionHmacKeyAtLeast32Bytes": True, "sessionHmacKeyHighEntropy": True, "stagingSupabaseAnonCredentialValid": True, "stagingRpcSecretAccepted": True}
        )
        require(record["semanticChecks"] == expected_semantics, f"{label} {name} Secret semantic preflight invalid")
        observed = utc_timestamp(record["materializedAt"], f"{label} {name} Secret materializedAt")
        valid_until = utc_timestamp(record["validUntil"], f"{label} {name} Secret validUntil")
        require(record["maxAgeSeconds"] == 300 and 0 < duration_seconds(observed, valid_until) <= 300, f"{label} {name} Secret freshness invalid")
        require(record["vaultArm"] == "roebel_staging_participant_environment_arm=staging-only", f"{label} {name} Secret Vault arm invalid")
        canonical = {key: record[key] for key in record if key != "receiptCanonicalSha256"}
        require(record["receiptCanonicalSha256"] == digest(canonical), f"{label} {name} Secret receipt invalid")
    return materialization


def verify_participant_gateway_database_preflight(value: Any, label: str) -> dict[str, Any]:
    preflight = closed(
        value,
        {"databaseProject", "environment", "vaultArm", "migrationSha256", "schemaSha256", "observedAt", "validUntil", "maxAgeSeconds", "apiOutcome", "receiptCanonicalSha256"},
        label,
    )
    require(isinstance(preflight["databaseProject"], str) and re.fullmatch(r"[a-z0-9]{20}", preflight["databaseProject"]), f"{label} database project invalid")
    require(preflight["environment"] == "staging" and preflight["vaultArm"] == "roebel_staging_participant_environment_arm=staging-only", f"{label} staging/Vault binding invalid")
    for key in ("migrationSha256", "schemaSha256"):
        require(isinstance(preflight[key], str) and SHA256.fullmatch(preflight[key]), f"{label} {key} invalid")
    observed = utc_timestamp(preflight["observedAt"], f"{label} observedAt")
    valid_until = utc_timestamp(preflight["validUntil"], f"{label} validUntil")
    require(preflight["maxAgeSeconds"] == 300 and 0 < duration_seconds(observed, valid_until) <= 300, f"{label} freshness invalid")
    require(preflight["apiOutcome"] == "staging-schema-and-vault-arm-exact", f"{label} API outcome invalid")
    canonical = {key: preflight[key] for key in preflight if key != "receiptCanonicalSha256"}
    require(preflight["receiptCanonicalSha256"] == digest(canonical), f"{label} receipt invalid")
    return preflight


def verify_participant_gateway_gnosis_chain(value: Any, origin: str, label: str) -> dict[str, Any]:
    receipt = closed(value, {"httpsOrigin", "request", "response", "observedAt", "validUntil", "maxAgeSeconds", "receiptCanonicalSha256"}, label)
    require(receipt["httpsOrigin"] == origin, f"{label} origin invalid")
    require(receipt["request"] == {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}, f"{label} request invalid")
    require(receipt["response"] == {"jsonrpc": "2.0", "id": 1, "result": "0x64"}, f"{label} must prove Gnosis eth_chainId 0x64")
    observed = utc_timestamp(receipt["observedAt"], f"{label} observedAt")
    valid_until = utc_timestamp(receipt["validUntil"], f"{label} validUntil")
    require(receipt["maxAgeSeconds"] == 300 and 0 < duration_seconds(observed, valid_until) <= 300, f"{label} freshness invalid")
    canonical = {key: receipt[key] for key in receipt if key != "receiptCanonicalSha256"}
    require(receipt["receiptCanonicalSha256"] == digest(canonical), f"{label} receipt invalid")
    return receipt


def verify_participant_gateway_application_bootstrap(value: Any, runtime_pin: dict[str, Any]) -> dict[str, Any]:
    """Prove the application objects were create-only in safe order.

    The dormant Flux Kustomization never gets authority to create or adopt an
    absent application object.  A privileged, reviewed bootstrap instead uses
    one atomic POST per exact object and records the UID/RV/bytes Flux must
    later observe unchanged.
    """
    bootstrap = closed(value, {"resourceAbsenceReceipts", "postconditions", "postconditionsCanonicalSha256", "healthBeforeIngress"}, "participant gateway application bootstrap")
    resources = expected_participant_gateway_resources(runtime_pin)
    # NetworkPolicy must exist before any matching Pod. The dedicated Ingress
    # is the last create-only object and may appear only after the internal
    # Service/Deployment health receipt. The existing Web Ingress is not part
    # of this transaction and cannot be adopted or changed.
    order = (
        ("networkPolicy", "networkPolicy"),
        ("serviceAccount", "serviceAccount"),
        ("service", "service"),
        ("deployment", "deployment"),
        ("ingress", "ingress"),
    )
    for field in ("resourceAbsenceReceipts", "postconditions"):
        require(isinstance(bootstrap[field], list) and len(bootstrap[field]) == len(order), f"participant gateway application {field} count invalid")
    for (object_id, resource_key), absence_value, post_value in zip(order, bootstrap["resourceAbsenceReceipts"], bootstrap["postconditions"], strict=True):
        expected = resources[resource_key]
        target = participant_gateway_target(expected["kind"], expected["metadata"]["name"], expected["metadata"]["namespace"])
        absence = closed(
            absence_value,
            {"objectId", "target", "desiredObjectDigest", "state", "uid", "resourceVersion", "currentObjectDigest", "observedAt", "validUntil", "maxAgeSeconds", "apiOutcome", "receiptCanonicalSha256"},
            f"participant gateway application absence {object_id}",
        )
        require(absence["objectId"] == object_id and absence["target"] == target and absence["desiredObjectDigest"] == digest(expected), "participant gateway application absence target/digest invalid")
        require(absence["state"] == "absent" and absence["uid"] is None and absence["resourceVersion"] is None and absence["currentObjectDigest"] is None and absence["apiOutcome"] == "http-404-not-found", "participant gateway application absence must be exact no-adopt")
        observed = utc_timestamp(absence["observedAt"], f"participant gateway application absence {object_id} observedAt")
        valid_until = utc_timestamp(absence["validUntil"], f"participant gateway application absence {object_id} validUntil")
        require(absence["maxAgeSeconds"] == 300 and 0 < duration_seconds(observed, valid_until) <= 300, "participant gateway application absence freshness invalid")
        require(absence["receiptCanonicalSha256"] == digest({key: absence[key] for key in absence if key != "receiptCanonicalSha256"}), "participant gateway application absence digest invalid")
        post_keys = {"objectId", "target", "uid", "resourceVersion", "objectCanonicalSha256", "apiOperation", "apiOutcome", "conflictPolicy"}
        if object_id == "ingress":
            post_keys.add("createdAt")
        post = closed(post_value, post_keys, f"participant gateway application postcondition {object_id}")
        require(post["objectId"] == object_id and post["target"] == target, "participant gateway application postcondition target invalid")
        require(isinstance(post["uid"], str) and UUID.fullmatch(post["uid"]), "participant gateway application postcondition UID invalid")
        require(isinstance(post["resourceVersion"], str) and post["resourceVersion"].isdigit(), "participant gateway application postcondition resourceVersion invalid")
        require(post["objectCanonicalSha256"] == digest(expected), "participant gateway application postcondition object drift")
        require(post["apiOperation"] == "POST-create" and post["apiOutcome"] == "http-201-created" and post["conflictPolicy"] == "fail-on-http-409-no-adopt", "participant gateway application postcondition not create-only")
    require(bootstrap["postconditionsCanonicalSha256"] == digest(bootstrap["postconditions"]), "participant gateway application postcondition checksum invalid")
    health = closed(
        bootstrap["healthBeforeIngress"],
        {"target", "deploymentUid", "deploymentResourceVersion", "serviceTarget", "statusPath", "observedAt", "validUntil", "maxAgeSeconds", "apiOutcome", "receiptCanonicalSha256"},
        "participant gateway pre-Ingress health receipt",
    )
    deployment_post = bootstrap["postconditions"][3]
    require(health["target"] == deployment_post["target"] and health["deploymentUid"] == deployment_post["uid"] and health["deploymentResourceVersion"] == deployment_post["resourceVersion"], "participant gateway pre-Ingress health deployment binding invalid")
    require(health["serviceTarget"] == participant_gateway_target("Service", PARTICIPANT_GATEWAY_NAME, PARTICIPANT_GATEWAY_NAMESPACE), "participant gateway pre-Ingress health Service target invalid")
    require(health["statusPath"] == "/api/staging-participant/v1/status" and health["apiOutcome"] == "http-200-internal-status", "participant gateway pre-Ingress health outcome invalid")
    observed = utc_timestamp(health["observedAt"], "participant gateway pre-Ingress health observedAt")
    valid_until = utc_timestamp(health["validUntil"], "participant gateway pre-Ingress health validUntil")
    require(health["maxAgeSeconds"] == 300 and 0 < duration_seconds(observed, valid_until) <= 300, "participant gateway pre-Ingress health freshness invalid")
    require(health["receiptCanonicalSha256"] == digest({key: health[key] for key in health if key != "receiptCanonicalSha256"}), "participant gateway pre-Ingress health receipt invalid")
    ingress_post = bootstrap["postconditions"][4]
    require(utc_timestamp(health["observedAt"], "participant gateway pre-Ingress health observedAt") <= utc_timestamp(ingress_post["createdAt"], "participant gateway Ingress createdAt"), "participant gateway Ingress precedes health")
    return bootstrap


def verify_participant_gateway_publication_receipt(value: Any, runtime_pin: dict[str, Any], predicate_type: str, label: str) -> dict[str, Any]:
    receipt = closed(value, {"receiptId", "receiptUrl", "subjectImage", "subjectDigest", "sourceRevision", "workflowIdentity", "runner", "predicateType", "attestationDigest", "verifiedAt", "verification", "canonicalReceiptSha256"}, label)
    require(isinstance(receipt["receiptId"], str) and receipt["receiptId"].isdigit(), f"{label} receipt id invalid")
    require(receipt["receiptUrl"] == f"https://github.com/GiraeffleAeffle/Roebel-App/actions/runs/{receipt['receiptId']}", f"{label} receipt URL invalid")
    require(receipt["subjectImage"] == runtime_pin["imageRepository"] and receipt["subjectDigest"] == runtime_pin["manifestDigest"], f"{label} image subject invalid")
    require(receipt["sourceRevision"] == runtime_pin["sourceRevision"] and receipt["workflowIdentity"] == runtime_pin["workflowIdentity"], f"{label} source/workflow binding invalid")
    require(receipt["runner"] == "github-hosted", f"{label} runner invalid")
    require(receipt["predicateType"] == predicate_type, f"{label} predicate type invalid")
    require(isinstance(receipt["attestationDigest"], str) and SHA256.fullmatch(receipt["attestationDigest"]) and receipt["attestationDigest"] != "sha256:" + "0" * 64, f"{label} attestation digest invalid")
    utc_timestamp(receipt["verifiedAt"], f"{label} verifiedAt")
    require(receipt["verification"] == {"tool": "gh", "command": "attestation-verify", "result": "verified", "subjectDigest": runtime_pin["manifestDigest"]}, f"{label} must contain a successful attestation verification receipt")
    require(receipt["canonicalReceiptSha256"] == digest({key: receipt[key] for key in receipt if key != "canonicalReceiptSha256"}), f"{label} canonical receipt digest invalid")
    return receipt


def verify_participant_gateway_anonymous_pull_receipt(value: Any, runtime_pin: dict[str, Any]) -> dict[str, Any]:
    receipt = closed(value, {"subjectImage", "subjectDigest", "pullMode", "tool", "toolVersion", "resolverIdentity", "authContext", "authConfigSha256", "descriptor", "observedAt", "receiptCanonicalSha256"}, "participant gateway anonymous digest pull receipt")
    require(receipt["subjectImage"] == runtime_pin["imageRepository"] and receipt["subjectDigest"] == runtime_pin["manifestDigest"], "participant gateway anonymous pull subject invalid")
    require(receipt["pullMode"] == "anonymous-digest-pull", "participant gateway anonymous pull mode invalid")
    require(receipt["tool"] == "oras" and isinstance(receipt["toolVersion"], str) and receipt["toolVersion"], "participant gateway anonymous pull tool invalid")
    require(receipt["resolverIdentity"] == "oras-resolve-anonymous" and receipt["authContext"] == "isolated-empty-auth-config", "participant gateway anonymous pull identity invalid")
    require(receipt["authConfigSha256"] == PARTICIPANT_GATEWAY_ANONYMOUS_EMPTY_AUTH_CONFIG_SHA256, "participant gateway anonymous pull must pin the reviewed empty auth config")
    descriptor = closed(receipt["descriptor"], {"mediaType", "digest", "size"}, "participant gateway anonymous pull descriptor")
    require(descriptor["mediaType"] == "application/vnd.oci.image.manifest.v1+json" and descriptor["digest"] == runtime_pin["manifestDigest"] and isinstance(descriptor["size"], int) and descriptor["size"] > 0, "participant gateway anonymous pull descriptor invalid")
    utc_timestamp(receipt["observedAt"], "participant gateway anonymous pull observedAt")
    require(receipt["receiptCanonicalSha256"] == digest({key: receipt[key] for key in receipt if key != "receiptCanonicalSha256"}), "participant gateway anonymous pull receipt digest invalid")
    return receipt


def verify_participant_gateway_network_policy_inventory(value: Any) -> dict[str, Any]:
    """Require a complete, non-widening K8s and Cilium policy inventory.

    The participant policy is additive only.  A blanket selector in either
    API family would make the narrow Gateway NetworkPolicy impossible to
    reason about, so the activation bundle must record all three inventories
    and prove every selected policy has an exact matchLabels selector.
    """
    inventory = closed(
        value,
        {"schemaVersion", "namespace", "capturedAt", "validUntil", "maxAgeSeconds", "kubernetesNetworkPolicies", "ciliumNetworkPolicies", "ciliumClusterwideNetworkPolicies", "selectorWidening", "receiptCanonicalSha256"},
        "participant gateway network policy inventory",
    )
    require(inventory["schemaVersion"] == "roebel_staging_participant_gateway_network_policy_inventory_v1", "participant gateway network policy inventory schema invalid")
    require(inventory["namespace"] == PARTICIPANT_GATEWAY_NAMESPACE, "participant gateway network policy inventory namespace invalid")
    captured = utc_timestamp(inventory["capturedAt"], "participant gateway network policy inventory capturedAt")
    valid_until = utc_timestamp(inventory["validUntil"], "participant gateway network policy inventory validUntil")
    require(inventory["maxAgeSeconds"] == 300 and 0 < duration_seconds(captured, valid_until) <= 300, "participant gateway network policy inventory freshness invalid")
    require(inventory["selectorWidening"] is False, "participant gateway network policy selector widening observed")
    for family in ("kubernetesNetworkPolicies", "ciliumNetworkPolicies", "ciliumClusterwideNetworkPolicies"):
        records = inventory[family]
        require(isinstance(records, list), f"participant gateway {family} inventory invalid")
        seen: set[tuple[str, str, str]] = set()
        for index, record_value in enumerate(records):
            record = closed(record_value, {"target", "uid", "resourceVersion", "objectCanonicalSha256", "podSelector"}, f"participant gateway {family}[{index}]")
            target = closed(record["target"], {"apiVersion", "kind", "name", "namespace"}, f"participant gateway {family}[{index}] target")
            require(target["namespace"] in {PARTICIPANT_GATEWAY_NAMESPACE, ""}, f"participant gateway {family} target namespace invalid")
            require(isinstance(target["kind"], str) and target["kind"].endswith("NetworkPolicy"), f"participant gateway {family} target kind invalid")
            key = (target["apiVersion"], target["kind"], target["name"])
            require(key not in seen, f"participant gateway {family} duplicate policy inventory target")
            seen.add(key)
            require(isinstance(record["uid"], str) and UUID.fullmatch(record["uid"]), f"participant gateway {family} UID invalid")
            require(isinstance(record["resourceVersion"], str) and record["resourceVersion"].isdigit(), f"participant gateway {family} resourceVersion invalid")
            require(isinstance(record["objectCanonicalSha256"], str) and SHA256.fullmatch(record["objectCanonicalSha256"]), f"participant gateway {family} object digest invalid")
            selector = closed(record["podSelector"], {"matchLabels"}, f"participant gateway {family} pod selector")
            require(isinstance(selector["matchLabels"], dict) and selector["matchLabels"], f"participant gateway {family} has a broad or empty pod selector")
    require(inventory["receiptCanonicalSha256"] == digest({key: inventory[key] for key in inventory if key != "receiptCanonicalSha256"}), "participant gateway network policy inventory receipt invalid")
    return inventory


def verify_participant_gateway_activation_evidence(value: Any, runtime_pin: dict[str, Any]) -> dict[str, Any]:
    del value, runtime_pin
    raise VerificationError(
        "candidate-embedded participant activation evidence is forbidden; "
        "trusted live facts are runner-owned and out-of-band",
    )


def _legacy_verify_participant_gateway_activation_evidence(value: Any, runtime_pin: dict[str, Any]) -> dict[str, Any]:
    evidence = closed(
        value,
        {
            "schemaVersion", "status", "operationsRevision", "sourceRevision", "imageRepository", "manifestDigest",
            "workflowIdentity", "publication", "egress", "networkPolicyInventory", "fluxBootstrap", "applicationBootstrap", "ingressCas", "secretMaterialization",
            "databaseVaultPreflight", "gnosisChainCheck", "dnsTlsEvidence", "activationLiveRecheck", "activationTransaction", "rollback",
        },
        "staging participant gateway activation evidence",
    )
    require(evidence["schemaVersion"] == "roebel_staging_participant_gateway_activation_evidence_v1", "participant gateway evidence schema invalid")
    require(evidence["status"] == "approved-separate-review", "participant gateway evidence status invalid")
    require(isinstance(evidence["operationsRevision"], str) and REVISION.fullmatch(evidence["operationsRevision"]), "participant gateway operations revision invalid")
    require(evidence["sourceRevision"] == runtime_pin["sourceRevision"], "participant gateway evidence source revision invalid")
    require(evidence["imageRepository"] == runtime_pin["imageRepository"], "participant gateway evidence image repository invalid")
    require(evidence["manifestDigest"] == runtime_pin["manifestDigest"], "participant gateway evidence image digest invalid")
    require(evidence["workflowIdentity"] == runtime_pin["workflowIdentity"], "participant gateway evidence workflow invalid")
    publication = closed(evidence["publication"], {"slsaProvenance", "spdxSbom", "anonymousPull"}, "participant gateway publication evidence")
    verify_participant_gateway_publication_receipt(publication["slsaProvenance"], runtime_pin, "https://slsa.dev/provenance/v1", "participant gateway SLSA provenance")
    verify_participant_gateway_publication_receipt(publication["spdxSbom"], runtime_pin, "https://spdx.dev/Document", "participant gateway SPDX SBOM")
    verify_participant_gateway_anonymous_pull_receipt(publication["anonymousPull"], runtime_pin)
    verify_participant_gateway_network_policy_inventory(evidence["networkPolicyInventory"])
    egress = closed(evidence["egress"], {"gnosis", "supabase"}, "participant gateway egress evidence")
    for name in ("gnosis", "supabase"):
        endpoint = closed(egress[name], {"httpsOrigin", "ipv4Cidrs", "port"}, f"participant gateway {name} egress")
        parsed_origin = urlparse(endpoint["httpsOrigin"])
        require(
            parsed_origin.scheme == "https" and parsed_origin.hostname and parsed_origin.port in {None, 443}
            and not parsed_origin.username and not parsed_origin.password and parsed_origin.path in {"", "/"}
            and not parsed_origin.params and not parsed_origin.query and not parsed_origin.fragment,
            f"participant gateway {name} HTTPS origin invalid",
        )
        require(endpoint["httpsOrigin"] == f"https://{parsed_origin.hostname}", f"participant gateway {name} origin must be a canonical literal HTTPS origin")
        require(endpoint["port"] == 443, f"participant gateway {name} port invalid")
        cidrs = endpoint["ipv4Cidrs"]
        require(isinstance(cidrs, list) and 1 <= len(cidrs) <= 8 and cidrs == sorted(set(cidrs)), f"participant gateway {name} CIDR set invalid")
        for cidr in cidrs:
            try:
                parsed = ipaddress.ip_network(cidr, strict=True)
            except ValueError:
                parsed = None
            require(parsed is not None and parsed.version == 4 and parsed.prefixlen == 32, f"participant gateway {name} CIDR must be an exact IPv4 /32")
    flux = verify_participant_gateway_flux_bootstrap(evidence["fluxBootstrap"], evidence["operationsRevision"])
    rollback = closed(evidence["rollback"], {"previousIngressSha256", "participantIngressSha256", "deactivationSqlSha256"}, "participant gateway rollback evidence")
    require(isinstance(rollback["previousIngressSha256"], str) and SHA256.fullmatch(rollback["previousIngressSha256"]), "participant gateway rollback ingress invalid")
    require(rollback["participantIngressSha256"] == digest(expected_participant_gateway_ingress()), "participant gateway rollback dedicated Ingress bytes invalid")
    require(isinstance(rollback["deactivationSqlSha256"], str) and SHA256.fullmatch(rollback["deactivationSqlSha256"]), "participant gateway rollback SQL invalid")
    application = verify_participant_gateway_application_bootstrap(evidence["applicationBootstrap"], runtime_pin)
    ingress = verify_participant_gateway_ingress_cas(evidence["ingressCas"], rollback, "participant gateway Ingress CAS")
    secrets = verify_participant_gateway_secret_materialization(evidence["secretMaterialization"], "participant gateway Secret materialization")
    database = verify_participant_gateway_database_preflight(evidence["databaseVaultPreflight"], "participant gateway database/Vault preflight")
    chain = verify_participant_gateway_gnosis_chain(evidence["gnosisChainCheck"], egress["gnosis"]["httpsOrigin"], "participant gateway Gnosis chain check")
    initial_dns = closed(evidence["dnsTlsEvidence"], {"gnosis", "supabase"}, "participant gateway DNS/TLS evidence")
    initial_dns = {
        name: verify_participant_gateway_dns_tls_evidence(initial_dns[name], egress[name], f"participant gateway {name} DNS/TLS evidence")
        for name in ("gnosis", "supabase")
    }
    recheck = closed(
        evidence["activationLiveRecheck"],
        {"checkedAt", "validUntil", "maxAgeSeconds", "sharedSourceRebind", "fluxKustomizationCas", "applicationStates", "ingressCas", "secretMaterialization", "databaseVaultPreflight", "gnosisChainCheck", "dnsTlsEvidence"},
        "participant gateway activation live recheck",
    )
    checked = utc_timestamp(recheck["checkedAt"], "participant gateway activation live recheck checkedAt")
    valid_until = utc_timestamp(recheck["validUntil"], "participant gateway activation live recheck validUntil")
    require(recheck["maxAgeSeconds"] == 300 and 0 < duration_seconds(checked, valid_until) <= 300, "participant gateway activation live recheck freshness invalid")
    source_rebind = closed(recheck["sharedSourceRebind"], {"target", "uid", "resourceVersion", "liveObjectCanonicalSha256", "artifactRevision", "observedAt", "validUntil", "maxAgeSeconds", "apiOutcome"}, "participant gateway activation shared Flux source rebind")
    source = flux["sourceReceipt"]
    require(source_rebind["target"] == source["target"] and source_rebind["uid"] == source["uid"], "participant gateway activation shared Flux source identity drift")
    require(isinstance(source_rebind["resourceVersion"], str) and source_rebind["resourceVersion"].isdigit() and int(source_rebind["resourceVersion"]) >= int(source["resourceVersion"]), "participant gateway activation shared Flux source resourceVersion invalid")
    require(source_rebind["liveObjectCanonicalSha256"] == source["liveObjectCanonicalSha256"], "participant gateway activation shared Flux source spec drift")
    require(source_rebind["artifactRevision"] == evidence["operationsRevision"], "participant gateway activation shared Flux source is not rebound to the exact protected render revision")
    require(source_rebind["apiOutcome"] == "http-200-active-source-exact-artifact", "participant gateway activation shared Flux source rebind outcome invalid")
    source_observed = utc_timestamp(source_rebind["observedAt"], "participant gateway activation shared Flux source observedAt")
    source_valid = utc_timestamp(source_rebind["validUntil"], "participant gateway activation shared Flux source validUntil")
    require(source_rebind["maxAgeSeconds"] == 300 and source_observed <= checked <= source_valid, "participant gateway activation shared Flux source freshness invalid")
    kustomization_cas = closed(recheck["fluxKustomizationCas"], {"target", "uid", "resourceVersion", "liveObjectSha256", "observedAt", "validUntil", "maxAgeSeconds", "apiOutcome"}, "participant gateway activation Flux Kustomization CAS")
    flux_kustomization = flux["bootstrapReceipt"]["postconditions"][0]
    require(kustomization_cas["target"] == flux_kustomization["target"] and kustomization_cas["uid"] == flux_kustomization["uid"] and kustomization_cas["resourceVersion"] == flux_kustomization["resourceVersion"] and kustomization_cas["liveObjectSha256"] == flux_kustomization["objectCanonicalSha256"], "participant gateway activation Flux Kustomization CAS drift")
    require(kustomization_cas["apiOutcome"] == "http-200-exact-suspended-bytes", "participant gateway activation Flux Kustomization CAS outcome invalid")
    covers_kustomization_observed = utc_timestamp(kustomization_cas["observedAt"], "participant gateway activation Flux Kustomization observedAt")
    covers_kustomization_valid = utc_timestamp(kustomization_cas["validUntil"], "participant gateway activation Flux Kustomization validUntil")
    require(kustomization_cas["maxAgeSeconds"] == 300 and covers_kustomization_observed <= checked <= covers_kustomization_valid, "participant gateway activation Flux Kustomization CAS freshness invalid")
    require(recheck["applicationStates"] == application["postconditions"], "participant gateway activation application ownership drift")
    recheck_ingress = verify_participant_gateway_ingress_cas(recheck["ingressCas"], rollback, "participant gateway activation Ingress CAS")
    recheck_secrets = verify_participant_gateway_secret_materialization(recheck["secretMaterialization"], "participant gateway activation Secret materialization")
    recheck_database = verify_participant_gateway_database_preflight(recheck["databaseVaultPreflight"], "participant gateway activation database/Vault preflight")
    recheck_chain = verify_participant_gateway_gnosis_chain(recheck["gnosisChainCheck"], egress["gnosis"]["httpsOrigin"], "participant gateway activation Gnosis chain check")
    recheck_dns_value = closed(recheck["dnsTlsEvidence"], {"gnosis", "supabase"}, "participant gateway activation DNS/TLS recheck")
    for name in ("gnosis", "supabase"):
        current = verify_participant_gateway_dns_tls_evidence(recheck_dns_value[name], egress[name], f"participant gateway activation {name} DNS/TLS")
        require(participant_gateway_dns_tls_binding(current) == participant_gateway_dns_tls_binding(initial_dns[name]), f"participant gateway activation {name} DNS/TLS binding drift")
    def covers_checked(observed_at: str, receipt_valid_until: str, receipt_label: str) -> None:
        require(
            utc_timestamp(observed_at, f"{receipt_label} observed") <= checked <= utc_timestamp(receipt_valid_until, f"{receipt_label} validUntil"),
            f"{receipt_label} does not cover activation recheck time",
        )

    covers_checked(recheck_ingress["observedAt"], recheck_ingress["validUntil"], "participant gateway activation Ingress CAS")
    for name in ("config", "runtime"):
        covers_checked(recheck_secrets[name]["materializedAt"], recheck_secrets[name]["validUntil"], f"participant gateway activation {name} Secret")
        require(
            {key: recheck_secrets[name][key] for key in ("target", "uid", "resourceVersion", "keySet", "state", "vaultArm")}
            == {key: secrets[name][key] for key in ("target", "uid", "resourceVersion", "keySet", "state", "vaultArm")},
            f"participant gateway activation {name} Secret identity drift",
        )
    covers_checked(recheck_database["observedAt"], recheck_database["validUntil"], "participant gateway activation database/Vault preflight")
    require(
        {key: recheck_database[key] for key in ("databaseProject", "environment", "vaultArm", "migrationSha256", "schemaSha256", "apiOutcome")}
        == {key: database[key] for key in ("databaseProject", "environment", "vaultArm", "migrationSha256", "schemaSha256", "apiOutcome")},
        "participant gateway activation database/Vault binding drift",
    )
    covers_checked(recheck_chain["observedAt"], recheck_chain["validUntil"], "participant gateway activation Gnosis chain check")
    require(
        {key: recheck_chain[key] for key in ("httpsOrigin", "request", "response")}
        == {key: chain[key] for key in ("httpsOrigin", "request", "response")},
        "participant gateway activation Gnosis chain binding drift",
    )
    require(
        {key: recheck_ingress[key] for key in ("target", "uid", "resourceVersion", "liveObjectSha256", "apiOutcome")}
        == {key: ingress[key] for key in ("target", "uid", "resourceVersion", "liveObjectSha256", "apiOutcome")},
        "participant gateway activation Ingress CAS identity drift",
    )
    for name in ("gnosis", "supabase"):
        covers_checked(recheck_dns_value[name]["observedAt"], recheck_dns_value[name]["validUntil"], f"participant gateway activation {name} DNS/TLS")
    require(checked >= utc_timestamp(flux["resourceAbsenceReceipts"][0]["observedAt"], "participant gateway Flux absence observedAt"), "participant gateway activation recheck predates Flux absence evidence")
    verify_participant_gateway_activation_transaction(evidence["activationTransaction"], flux)
    return evidence


def verify_participant_gateway_activation_rollback_baseline(
    activation_evidence: dict[str, Any],
    protected_base_root: Path,
) -> None:
    """Bind the gateway teardown plan to the protected pre-activation ingress.

    The activation candidate cannot choose this baseline: in pull-request
    admission ``protected_base_root`` is the protected base checkout.  The
    structural evidence validation has already checked the field shape; this
    function establishes the byte-for-byte CAS binding.
    """
    expected = bytes_digest(
        (protected_base_root / RENDER_ROOT / "web/ingress.json").read_bytes(),
    )
    require(
        activation_evidence["rollback"]["previousIngressSha256"] == expected,
        "participant gateway activation rollback ingress baseline drift",
    )


def verify_participant_gateway_activation_admission_freshness(
    activation_evidence: dict[str, Any],
) -> None:
    """Require activation to happen within the one reviewed preflight window.

    The policy constant is immutable once bootstrapped, so it must contain the
    read-only evidence.  This clock check runs only on the transition that
    grants rendering authority; routine promotions remain reproducible after
    the receipt expires.
    """
    now = participant_gateway_verification_time()
    recheck = activation_evidence["activationLiveRecheck"]
    checked = utc_timestamp(recheck["checkedAt"], "participant gateway activation live recheck checkedAt")
    valid_until = utc_timestamp(recheck["validUntil"], "participant gateway activation live recheck validUntil")
    require(
        checked <= now <= valid_until,
        "participant gateway activation evidence is future-dated or outside the current five-minute preflight",
    )


def verify_participant_gateway_runtime_pin(value: Any) -> dict[str, Any]:
    try:
        expected = PARTICIPANT_POLICY.expected_runtime_pin()
    except PARTICIPANT_POLICY.PolicyError as error:
        raise VerificationError(str(error)) from error
    require(value == expected, "staging participant gateway runtime pin drift")
    require("activationEvidence" not in value, "participant runtime pin may not carry live activation evidence")
    return copy.deepcopy(expected)


def participant_gateway_ingress_sources() -> list[dict[str, Any]]:
    return [
        {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "ingress-system"}}},
        *[{"ipBlock": {"cidr": cidr}} for cidr in (
            "10.42.0.10/32", "10.42.0.11/32", "10.42.0.12/32",
            "10.244.0.0/32", "10.244.1.0/32", "10.244.2.0/32",
            "10.244.0.1/32", "10.244.1.1/32", "10.244.2.1/32",
        )],
    ]


def expected_participant_gateway_ingress() -> dict[str, Any]:
    try:
        return PARTICIPANT_POLICY.expected_gateway_ingress()
    except PARTICIPANT_POLICY.PolicyError as error:
        raise VerificationError(str(error)) from error


def expected_participant_gateway_resources(runtime_pin: dict[str, Any]) -> dict[str, Any]:
    """Compatibility adapter to the single protected policy module."""
    try:
        expected = PARTICIPANT_POLICY.expected_gateway_resources()
    except PARTICIPANT_POLICY.PolicyError as error:
        raise VerificationError(str(error)) from error
    require(runtime_pin == expected["runtimePin"], "participant runtime pin differs from protected policy")
    return {
        "deployment": expected["deployment"],
        "service": expected["service"],
        "networkPolicy": expected["networkPolicy"],
        "serviceAccount": expected["serviceAccount"],
        "ingress": expected["ingress"],
        "kustomization": expected["kustomization"],
        "workbenchIngressNetworkPolicy": expected["workbenchIngressNetworkPolicy"],
        "workbenchIngressKustomization": expected["workbenchIngressKustomization"],
    }


def _legacy_expected_participant_gateway_resources(runtime_pin: dict[str, Any]) -> dict[str, Any]:
    evidence = runtime_pin["activationEvidence"]
    egress = evidence["egress"]
    pod_security = {
        "fsGroup": 65532, "runAsGroup": 65532, "runAsNonRoot": True,
        "runAsUser": 65532, "seccompProfile": {"type": "RuntimeDefault"},
    }
    container_security = {
        "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
        "readOnlyRootFilesystem": True,
    }
    tcp_probe = lambda threshold, period: {
        "failureThreshold": threshold, "periodSeconds": period, "successThreshold": 1,
        "tcpSocket": {"port": "http"}, "timeoutSeconds": 3,
    }
    environment = [
        {"name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY", "value": "enabled"},
        {"name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_HOST", "value": "0.0.0.0"},
        {"name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_PORT", "value": str(PARTICIPANT_GATEWAY_PORT)},
        {"name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_ORIGIN", "value": PARTICIPANT_GATEWAY_ORIGIN},
        participant_gateway_secret_env("ROEBEL_STAGING_PARTICIPANT_GATEWAY_INVITE_SHA256", PARTICIPANT_GATEWAY_CONFIG_SECRET, "invite-sha256"),
        participant_gateway_secret_env("ROEBEL_STAGING_PARTICIPANT_GATEWAY_ALLOWED_WALLETS", PARTICIPANT_GATEWAY_CONFIG_SECRET, "allowed-wallets"),
        participant_gateway_secret_env("ROEBEL_STAGING_PARTICIPANT_GATEWAY_SESSION_KEY", PARTICIPANT_GATEWAY_RUNTIME_SECRET, "session-key"),
        # Origins are reviewed policy data, not credentials.  Keeping them
        # literal binds the Deployment and its NetworkPolicy to exactly the
        # DNS/TLS evidence above; Secrets retain only secret material.
        {"name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_GNOSIS_RPC_URL", "value": egress["gnosis"]["httpsOrigin"]},
        {"name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_SUPABASE_URL", "value": egress["supabase"]["httpsOrigin"]},
        participant_gateway_secret_env("ROEBEL_STAGING_PARTICIPANT_GATEWAY_SUPABASE_ANON_KEY", PARTICIPANT_GATEWAY_RUNTIME_SECRET, "supabase-anon-key"),
        participant_gateway_secret_env("ROEBEL_STAGING_PARTICIPANT_GATEWAY_SUPABASE_RPC_SECRET", PARTICIPANT_GATEWAY_RUNTIME_SECRET, "supabase-rpc-secret"),
    ]
    deployment = {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"labels": PARTICIPANT_GATEWAY_LABELS, "name": PARTICIPANT_GATEWAY_NAME, "namespace": PARTICIPANT_GATEWAY_NAMESPACE},
        "spec": {
            "replicas": 1, "selector": {"matchLabels": PARTICIPANT_GATEWAY_LABELS},
            "strategy": {"type": "Recreate"},
            "template": {
                "metadata": {"labels": PARTICIPANT_GATEWAY_LABELS},
                "spec": {
                    "automountServiceAccountToken": False, "restartPolicy": "Always",
                    "serviceAccountName": PARTICIPANT_GATEWAY_NAME, "securityContext": pod_security,
                    "volumes": [{"emptyDir": {"sizeLimit": "64Mi"}, "name": "tmp"}],
                    "containers": [{
                        "env": environment,
                        "image": f"{runtime_pin['imageRepository']}@{runtime_pin['manifestDigest']}",
                        "imagePullPolicy": "IfNotPresent", "name": "staging-participant-gateway",
                        "ports": [{"containerPort": PARTICIPANT_GATEWAY_PORT, "name": "http", "protocol": "TCP"}],
                        "readinessProbe": tcp_probe(3, 10), "livenessProbe": tcp_probe(3, 20), "startupProbe": tcp_probe(30, 2),
                        "resources": {"limits": {"cpu": "200m", "memory": "128Mi"}, "requests": {"cpu": "50m", "memory": "64Mi"}},
                        "securityContext": container_security,
                        "volumeMounts": [{"mountPath": "/tmp", "name": "tmp"}],
                    }],
                },
            },
        },
    }
    service = {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"labels": PARTICIPANT_GATEWAY_LABELS, "name": PARTICIPANT_GATEWAY_NAME, "namespace": PARTICIPANT_GATEWAY_NAMESPACE},
        "spec": {"ports": [{"name": "http", "port": PARTICIPANT_GATEWAY_PORT, "protocol": "TCP", "targetPort": "http"}], "selector": PARTICIPANT_GATEWAY_LABELS, "type": "ClusterIP"},
    }
    network_policy = {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"labels": PARTICIPANT_GATEWAY_LABELS, "name": PARTICIPANT_GATEWAY_NAME, "namespace": PARTICIPANT_GATEWAY_NAMESPACE},
        "spec": {
            "podSelector": {"matchLabels": PARTICIPANT_GATEWAY_LABELS}, "policyTypes": ["Ingress", "Egress"],
            "ingress": [{"from": participant_gateway_ingress_sources(), "ports": [{"port": PARTICIPANT_GATEWAY_PORT, "protocol": "TCP"}]}],
            "egress": [
                {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}, "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}], "ports": [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}]},
                *[{"to": [{"ipBlock": {"cidr": cidr}}], "ports": [{"port": 443, "protocol": "TCP"}]} for endpoint in (egress["gnosis"], egress["supabase"]) for cidr in endpoint["ipv4Cidrs"]],
            ],
        },
    }
    service_account = {
        "apiVersion": "v1", "kind": "ServiceAccount",
        "metadata": {"labels": PARTICIPANT_GATEWAY_LABELS, "name": PARTICIPANT_GATEWAY_NAME, "namespace": PARTICIPANT_GATEWAY_NAMESPACE},
        "automountServiceAccountToken": False,
    }
    kustomization = (
        "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n"
        "  - serviceaccount.json\n  - deployment.json\n  - service.json\n  - networkpolicy.json\n  - ingress.json\n"
    )
    return {"deployment": deployment, "service": service, "networkPolicy": network_policy, "serviceAccount": service_account, "ingress": expected_participant_gateway_ingress(), "kustomization": kustomization}


def verify_participant_gateway(root: Path) -> dict[str, Any]:
    runtime_pin = verify_participant_gateway_runtime_pin(load_json(root / PARTICIPANT_GATEWAY_ROOT / "runtime-pin.json"))
    expected = expected_participant_gateway_resources(runtime_pin)
    actual = {
        "deployment": load_json(root / PARTICIPANT_GATEWAY_ROOT / "deployment.json"),
        "service": load_json(root / PARTICIPANT_GATEWAY_ROOT / "service.json"),
        "networkPolicy": load_json(root / PARTICIPANT_GATEWAY_ROOT / "networkpolicy.json"),
        "serviceAccount": load_json(root / PARTICIPANT_GATEWAY_ROOT / "serviceaccount.json"),
        "ingress": load_json(root / PARTICIPANT_GATEWAY_ROOT / "ingress.json"),
        "kustomization": (root / PARTICIPANT_GATEWAY_ROOT / "kustomization.yaml").read_text(),
        "workbenchIngressNetworkPolicy": load_json(
            root / PARTICIPANT_POLICY.WORKBENCH_INGRESS_ROOT / "networkpolicy.json",
        ),
        "workbenchIngressKustomization": (
            root / PARTICIPANT_POLICY.WORKBENCH_INGRESS_ROOT / "kustomization.yaml"
        ).read_text(),
    }
    require(actual == expected, "staging participant gateway resource drift")
    return {"runtimePin": runtime_pin, **actual}


def expected_web_ingress(signed_nostr: bool, participant_gateway: bool = False) -> dict[str, Any]:
    # Participant routing is a separate, longer-prefix Ingress.  Keep this
    # compatibility parameter inert so every existing Web byte stays fixed.
    participant_gateway = False
    early = (
        "http-request deny deny_status 405 if { method POST } !{ path /api/chat/mecky }\n"
        "http-request deny deny_status 405 unless { method GET HEAD POST }\n"
        "http-request deny deny_status 404 if { path_beg /api } !{ path_beg /api/public-feed/ } !{ path /api/notifications/unread-count } !{ path /api/chat/mecky }"
    )
    paths = [
        {
            "backend": {"service": {
                "name": "roebel-supabase-read-gateway",
                "port": {"name": "http"},
            }},
            "path": "/supabase-read",
            "pathType": "Prefix",
        },
    ]
    if signed_nostr:
        early = (
            "http-request deny deny_status 405 if { method POST } !{ path /api/chat/mecky } !{ path /stadtstack-test/api/session/admit } !{ path /stadtstack-test/api/signed-event }\n"
            "http-request deny deny_status 405 unless { method GET HEAD POST }\n"
            "http-request deny deny_status 404 if { path_beg /api } !{ path_beg /api/public-feed/ } !{ path /api/notifications/unread-count } !{ path /api/chat/mecky }\n"
            "http-request deny deny_status 404 if { path_beg /stadtstack-test } !{ path /stadtstack-test/healthz } !{ path /stadtstack-test/api/config } !{ path /stadtstack-test/api/feed } !{ path /stadtstack-test/api/thread } !{ path /stadtstack-test/api/conversation } !{ path /stadtstack-test/api/session/admit } !{ path /stadtstack-test/api/signed-event }"
        )
        paths.append({
            "backend": {"service": {
                "name": "roebel-staging-workbench",
                "port": {"name": "http"},
            }},
            "path": "/stadtstack-test",
            "pathType": "Prefix",
        })
    if participant_gateway:
        participant_paths = (
            "/api/staging-participant/v1/status",
            "/api/staging-participant/v1/challenge",
            "/api/staging-participant/v1/session",
            "/api/staging-participant/v1/posts",
            "/api/staging-participant/v1/comments",
        )
        post_paths = participant_paths[1:]
        early_lines = early.split("\n")
        early_lines[0] += " " + " ".join(f"!{{ path {path} }}" for path in post_paths)
        early_lines.insert(
            1,
            "http-request deny deny_status 405 if { method OPTIONS } "
            + " ".join(f"!{{ path {path} }}" for path in participant_paths),
        )
        early_lines.insert(
            2,
            "http-request deny deny_status 405 if { path_beg /api/staging-participant/v1/ } { method HEAD }",
        )
        early_lines.insert(
            3,
            "http-request deny deny_status 405 if { method GET } { path_beg /api/staging-participant/v1/ } !{ path /api/staging-participant/v1/status }",
        )
        early_lines[4] = "http-request deny deny_status 405 unless { method GET HEAD POST OPTIONS }"
        api_line = next(
            index
            for index, line in enumerate(early_lines)
            if line.startswith("http-request deny deny_status 404 if { path_beg /api } ")
        )
        early_lines[api_line] += " !{ path_beg /api/staging-participant/v1/ }"
        participant_guard = (
            "http-request deny deny_status 404 if { path_beg /api/staging-participant/v1/ } "
            + " ".join(f"!{{ path {path} }}" for path in participant_paths)
        )
        early_lines.insert(api_line + 1, participant_guard)
        early_lines.extend([
            "stick-table type ip size 10k expire 60s store http_req_rate(1m)",
            "http-request track-sc0 src if { path_beg /api/staging-participant/v1/ }",
            "http-request deny deny_status 429 if { path_beg /api/staging-participant/v1/ } { sc_http_req_rate(0) gt 30 }",
        ])
        early = "\n".join(early_lines)
        paths.append({
            "backend": {"service": {
                "name": PARTICIPANT_GATEWAY_NAME,
                "port": {"name": "http"},
            }},
            "path": "/api/staging-participant/v1",
            "pathType": "Prefix",
        })
    paths.append({
        "backend": {"service": {
            "name": "roebel-web-presentation",
            "port": {"name": "http"},
        }},
        "path": "/",
        "pathType": "Prefix",
    })
    return {
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
                    "http-response set-header Content-Security-Policy \"default-src 'self'; base-uri 'none'; form-action 'none'; object-src 'none'; frame-ancestors 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data: blob: https:; connect-src 'self' https://roebel-stadtstack.agentcart.eu https://embedded-wallet.thirdweb.com https://api.thirdweb.com https://100.rpc.thirdweb.com; frame-src https://embedded-wallet.thirdweb.com; worker-src 'self' blob:;\""
                ),
                "haproxy-ingress.github.io/config-backend-early": early,
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
                    "paths": paths
                },
            }],
            "tls": [{
                "hosts": ["roebel-web.staging.agentcart.eu"],
                "secretName": "roebel-web-presentation-tls",
            }],
        },
    }


def verify_web_ingress(root: Path, signed_nostr: bool, participant_gateway: bool = False) -> dict[str, Any]:
    ingress = load_json(root / RENDER_ROOT / "web/ingress.json")
    require(ingress == expected_web_ingress(signed_nostr, participant_gateway), "Web Ingress drift")
    return ingress


def verify_network_boundary_migration(
    root: Path,
    web_network_policy: dict[str, Any],
    web_ingress: dict[str, Any],
    public_mecky_network_policy: dict[str, Any],
    signed_nostr: bool,
    participant_gateway: bool = False,
    participant_gateway_objects: dict[str, Any] | None = None,
) -> dict[str, Any]:
    migration = load_json(root / RENDER_ROOT / "network-boundary-migration.json")
    if participant_gateway:
        require(participant_gateway_objects is not None, "participant gateway boundary objects unavailable")
        ingress_paths = list(PARTICIPANT_POLICY.ROUTES)
        gateway_flux = expected_participant_gateway_flux_objects()
        workbench_flux = expected_participant_workbench_ingress_flux_objects()
        objects = [
            {"kind": "NetworkPolicy", "name": "roebel-web-presentation", "namespace": PARTICIPANT_GATEWAY_NAMESPACE, "sha256": digest(web_network_policy)},
            {"kind": "Ingress", "name": "roebel-web-presentation", "namespace": PARTICIPANT_GATEWAY_NAMESPACE, "sha256": digest(web_ingress)},
            {"kind": "ServiceAccount", "name": PARTICIPANT_GATEWAY_NAME, "namespace": PARTICIPANT_GATEWAY_NAMESPACE, "sha256": digest(participant_gateway_objects["serviceAccount"])},
            {"kind": "Deployment", "name": PARTICIPANT_GATEWAY_NAME, "namespace": PARTICIPANT_GATEWAY_NAMESPACE, "sha256": digest(participant_gateway_objects["deployment"])},
            {"kind": "Service", "name": PARTICIPANT_GATEWAY_NAME, "namespace": PARTICIPANT_GATEWAY_NAMESPACE, "sha256": digest(participant_gateway_objects["service"])},
            {"kind": "NetworkPolicy", "name": PARTICIPANT_GATEWAY_NAME, "namespace": PARTICIPANT_GATEWAY_NAMESPACE, "sha256": digest(participant_gateway_objects["networkPolicy"])},
            {"kind": "Ingress", "name": PARTICIPANT_GATEWAY_NAME, "namespace": PARTICIPANT_GATEWAY_NAMESPACE, "sha256": digest(participant_gateway_objects["ingress"])},
            {"kind": "NetworkPolicy", "name": PARTICIPANT_POLICY.WORKBENCH_INGRESS_POLICY_NAME, "namespace": PARTICIPANT_POLICY.WORKBENCH_NAMESPACE, "sha256": digest(participant_gateway_objects["workbenchIngressNetworkPolicy"])},
        ]
        expected = {
            "authority": "none",
            "boundary": {
                "ingress": {
                    "allowedMethods": ["GET", "POST", "OPTIONS"],
                    "exactGatewayPaths": ingress_paths,
                    "exactPostPaths": ingress_paths[1:],
                    "gatewayMethodPathMatrix": {
                        "GET": [ingress_paths[0]],
                        "OPTIONS": ingress_paths,
                        "POST": ingress_paths[1:],
                    },
                    "rateLimit": {
                        "aggregateClaimAllowed": False,
                        "requestsPerMinutePerSourceIp": 30,
                        "scope": "gateway-paths-only-per-controller-replica",
                    },
                    "resource": {"kind": "Ingress", "name": PARTICIPANT_GATEWAY_NAME, "namespace": PARTICIPANT_GATEWAY_NAMESPACE},
                },
                "participantGateway": {
                    "namespace": PARTICIPANT_GATEWAY_NAMESPACE,
                    "name": PARTICIPANT_GATEWAY_NAME,
                    "replicas": 1,
                    "serviceAccountToken": False,
                    "writerAuthority": "fixed-staging-rpcs-only",
                    "civicAuthority": "none",
                    "egress": "dns-plus-policy-pinned-gnosis-supabase-and-exact-workbench-only",
                },
                "workbenchIngress": {
                    "name": PARTICIPANT_POLICY.WORKBENCH_INGRESS_POLICY_NAME,
                    "namespace": PARTICIPANT_POLICY.WORKBENCH_NAMESPACE,
                    "port": PARTICIPANT_POLICY.WORKBENCH_PORT,
                    "existingPolicyMutation": "forbidden",
                    "source": {
                        "namespace": PARTICIPANT_GATEWAY_NAMESPACE,
                        "podSelector": PARTICIPANT_GATEWAY_LABELS,
                    },
                },
                "signedNostr": "retained-exact" if signed_nostr else "not-present",
            },
            "effects": {"civicMutation": False, "clusterMutation": False, "secretRead": False, "secretWrite": False},
            "objects": objects,
            "rbacBootstrap": {
                "required": True,
                "transaction": "cas-unsuspend-both-or-suspend-both",
                "reconcilers": [
                    {
                        "kustomization": gateway_flux["kustomization"]["metadata"],
                        "roleNamespace": gateway_flux["role"]["metadata"]["namespace"],
                        "rules": gateway_flux["role"]["rules"],
                        "serviceAccount": gateway_flux["serviceAccount"]["metadata"],
                    },
                    {
                        "kustomization": workbench_flux["kustomization"]["metadata"],
                        "roleNamespace": workbench_flux["role"]["metadata"]["namespace"],
                        "rules": workbench_flux["role"]["rules"],
                        "serviceAccount": workbench_flux["serviceAccount"]["metadata"],
                    },
                ],
                "liveMutationPerformed": False,
            },
            "schemaVersion": "roebel_staging_participant_gateway_boundary_v1",
            "status": "approved-for-exact-staging-activation",
        }
        require(migration == expected, "participant gateway network-boundary receipt drift")
        return migration
    if signed_nostr:
        expected_signed_nostr = {
            "authority": "none",
            "boundary": {
                "ingress": {
                    "allowedMethods": ["GET", "HEAD", "POST"],
                    "exactPostPaths": [
                        "/api/chat/mecky",
                        "/stadtstack-test/api/session/admit",
                        "/stadtstack-test/api/signed-event",
                    ],
                    "readOnlyPrefix": "/stadtstack-test",
                    "resource": {"kind": "Ingress", "name": "roebel-web-presentation", "namespace": SIGNED_NOSTR_WEB_NAMESPACE},
                },
                "publicMeckyRelayEgress": {
                    "destinationNamespace": SIGNED_NOSTR_NAMESPACE,
                    "destinationPorts": [18081],
                    "relays": ["citizen-relay", "agent-relay"],
                    "resource": {"kind": "NetworkPolicy", "name": "public-mecky-chat-from-web", "namespace": SIGNED_NOSTR_NAMESPACE},
                },
                "relays": {
                    "ingress": "workbench-only",
                    "ingressClass": "none",
                    "namespace": SIGNED_NOSTR_NAMESPACE,
                    "persistentVolume": False,
                    "emptyDirSizeLimit": "128Mi",
                    "combinedPersistedBudgetBytes": 83886080,
                },
            },
            "evidence": {
                "gnosisRpcEgress": None,
                "fluxIdentity": None,
                "status": "pending-separate-review",
            },
            "effects": {"civicMutation": False, "clusterMutation": False, "secretRead": False, "secretWrite": False},
            "objects": [
                {"kind": "NetworkPolicy", "name": "public-mecky-chat-from-web", "namespace": SIGNED_NOSTR_NAMESPACE, "sha256": digest(public_mecky_network_policy)},
                {"kind": "Ingress", "name": "roebel-web-presentation", "namespace": SIGNED_NOSTR_WEB_NAMESPACE, "sha256": digest(web_ingress)},
            ],
            "rbacBootstrap": {
                "createAllowed": False,
                "deleteAllowed": False,
                "listAllowed": False,
                "required": True,
                "roleNamespace": SIGNED_NOSTR_WEB_NAMESPACE,
                "serviceAccount": {"name": "roebel-web-reconciler", "namespace": "flux-roebel-staging"},
                "watchAllowed": False,
                "rules": [
                    {"apiGroups": ["networking.k8s.io"], "resourceNames": ["roebel-web-presentation"], "resources": ["networkpolicies"], "verbs": ["get", "patch", "update"]},
                    {"apiGroups": ["networking.k8s.io"], "resourceNames": ["roebel-web-presentation"], "resources": ["ingresses"], "verbs": ["get", "patch", "update"]},
                ],
                "liveMutationPerformed": False,
            },
            "schemaVersion": "roebel_staging_signed_nostr_boundary_v1",
            "status": "blocked_pending_separately_reviewed_signed_nostr_evidence",
        }
        require(migration == expected_signed_nostr, "signed-Nostr network-boundary receipt drift")
        return migration
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


def verify_kustomizations(root: Path, signed_nostr: bool, participant_gateway: bool = False) -> None:
    public_expected = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - deployment.json\n  - service.json\n  - networkpolicy.json\n"
    web_expected = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - deployment.json\n  - networkpolicy.json\n  - ingress.json\n"
    require((root / RENDER_ROOT / "public-mecky/kustomization.yaml").read_text() == public_expected, "public-mecky Flux path widened")
    require((root / RENDER_ROOT / "web/kustomization.yaml").read_text() == web_expected, "roebel-web-staging Flux path widened")
    if signed_nostr:
        for component in SIGNED_NOSTR_COMPONENTS:
            extra = ""
            if component == "workbench":
                extra = "  - gnosis-proxy-deployment.json\n  - gnosis-proxy-service.json\n  - gnosis-proxy-networkpolicy.json\n"
            expected = (
                "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n"
                "  - deployment.json\n  - service.json\n  - networkpolicy.json\n"
                + extra
            )
            require(
                (root / SIGNED_NOSTR_ROOT / component / "kustomization.yaml").read_text() == expected,
                f"signed-Nostr {component} Flux path widened",
            )
    if participant_gateway:
        expected = (
            "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n"
            "  - networkpolicy.json\n  - serviceaccount.json\n  - service.json\n  - deployment.json\n  - ingress.json\n"
        )
        require(
            (root / PARTICIPANT_GATEWAY_ROOT / "kustomization.yaml").read_text() == expected,
            "staging participant gateway Flux path widened",
        )
        reciprocal_expected = (
            "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n"
            "  - networkpolicy.json\n"
        )
        require(
            (root / PARTICIPANT_POLICY.WORKBENCH_INGRESS_ROOT / "kustomization.yaml").read_text()
            == reciprocal_expected,
            "staging participant reciprocal workbench Flux path widened",
        )


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
    participant_policy = verify_participant_gateway_static_policy(root, render_file_set)
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
    reviewed_knowledge = render_file_set in {
        "reviewed-public-knowledge", "reviewed-public-knowledge-participant-gateway",
        "signed-nostr", "signed-nostr-participant-gateway",
    }
    signed_nostr = render_file_set in {"signed-nostr", "signed-nostr-participant-gateway"}
    participant_gateway = render_file_set in {
        "reviewed-public-knowledge-participant-gateway", "signed-nostr-participant-gateway",
    }
    deployments = {component: verify_deployment(root, component, head, reviewed_knowledge) for component in COMPONENT_ORDER}
    service = verify_public_mecky_service(root)
    network_policy, public_mecky_reviewed_egress = verify_public_mecky_network_policy(
        root,
        reviewed_knowledge,
        signed_nostr,
    )
    web_network_policy = verify_web_network_policy(root)
    participant_gateway_objects = verify_participant_gateway(root) if participant_gateway else None
    web_ingress = verify_web_ingress(root, signed_nostr, participant_gateway)
    migration = verify_network_boundary_migration(
        root, web_network_policy, web_ingress, network_policy, signed_nostr,
        participant_gateway, participant_gateway_objects,
    )
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
    signed_nostr_objects = None
    if signed_nostr:
        signed_nostr_objects = verify_signed_nostr(root)
        checksum_payload["signedNostr"] = signed_nostr_objects
    if participant_gateway:
        checksum_payload["stagingParticipantGateway"] = participant_gateway_objects
    require(integrity["desiredRenderSha256"] == digest(checksum_payload), "reviewed render checksum mismatch")
    require(integrity["networkBoundaryMigrationSha256"] == digest(migration), "network-boundary migration checksum mismatch")
    verify_kustomizations(root, signed_nostr, participant_gateway)
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
        "signedNostr": signed_nostr_objects,
        "stagingParticipantGateway": participant_gateway_objects,
        "stagingParticipantGatewayPolicy": participant_policy,
    }


def verify_transition(candidate: dict[str, Any], base: dict[str, Any]) -> None:
    candidate_root: Path = candidate["root"]
    base_root: Path = base["root"]
    base_participant_gateway = base["renderFileSet"] in {
        "reviewed-public-knowledge-participant-gateway", "signed-nostr-participant-gateway",
    }
    candidate_participant_gateway = candidate["renderFileSet"] in {
        "reviewed-public-knowledge-participant-gateway", "signed-nostr-participant-gateway",
    }
    require(
        not (base["renderFileSet"] == "reviewed-public-knowledge" and candidate["renderFileSet"] == "current"),
        "reviewed-public-knowledge render set cannot regress to the legacy set",
    )
    require(
        not (base["renderFileSet"] == "signed-nostr" and candidate["renderFileSet"] == "current"),
        "signed-Nostr rollback must retain the reviewed-public-knowledge render",
    )
    require(
        not (base["publicMeckyReviewedEgress"] and not candidate["publicMeckyReviewedEgress"]),
        "Public Mecky reviewed-runtime egress cannot regress",
    )
    require(
        not (base_participant_gateway and not candidate_participant_gateway),
        "participant gateway deactivation is blocked pending separately reviewed exact teardown evidence",
    )

    if candidate_participant_gateway and not base_participant_gateway:
        require(
            base["renderFileSet"] in {"reviewed-public-knowledge", "signed-nostr"},
            "participant gateway activation requires the reviewed public-knowledge render",
        )
        require(
            not (
                base["renderFileSet"] == "reviewed-public-knowledge"
                and candidate["renderFileSet"] == "signed-nostr-participant-gateway"
            ),
            "participant gateway and signed-Nostr activation must be separate reviewed transitions",
        )
        require(candidate["head"] == base["head"], "participant gateway activation must preserve the Release Set head")
        require(
            candidate["stagingParticipantGatewayPolicy"]["activationReady"] is True,
            "participant gateway activation policy is not ready",
        )
        allowed_existing_changes = {
            f"{RENDER_ROOT}/integrity.json",
            f"{RENDER_ROOT}/network-boundary-migration.json",
        }
        protected = SIGNED_NOSTR_EXPECTED_FILES if base["renderFileSet"] == "signed-nostr" else FUTURE_EXPECTED_FILES
        for relative in protected:
            if relative in allowed_existing_changes:
                continue
            require(
                (candidate_root / relative).read_bytes() == (base_root / relative).read_bytes(),
                f"participant gateway activation changed existing file: {relative}",
            )
        return

    if (
        base["renderFileSet"] in {"reviewed-public-knowledge", "reviewed-public-knowledge-participant-gateway"}
        and candidate["renderFileSet"] in {"signed-nostr", "signed-nostr-participant-gateway"}
    ):
        require(candidate["head"] == base["head"], "signed-Nostr activation must preserve the Release Set head")
        verify_signed_nostr_activation_admission_freshness(
            candidate["signedNostr"]["runtimePin"]["activationEvidence"],
        )
        protected = PARTICIPANT_GATEWAY_EXPECTED_FILES if base_participant_gateway else FUTURE_EXPECTED_FILES
        for relative in protected:
            if relative in SIGNED_NOSTR_MUTABLE_EXISTING_FILES:
                continue
            require(
                (candidate_root / relative).read_bytes() == (base_root / relative).read_bytes(),
                f"signed-Nostr activation changed existing file: {relative}",
            )
        rollback = candidate["signedNostr"]["runtimePin"]["rollback"]
        expected_rollback = {
            "integritySha256": bytes_digest((base_root / f"{RENDER_ROOT}/integrity.json").read_bytes()),
            "webIngressSha256": bytes_digest((base_root / f"{RENDER_ROOT}/web/ingress.json").read_bytes()),
            "publicMeckyNetworkPolicySha256": bytes_digest((base_root / f"{RENDER_ROOT}/public-mecky/networkpolicy.json").read_bytes()),
            "boundaryReceiptSha256": bytes_digest((base_root / f"{RENDER_ROOT}/network-boundary-migration.json").read_bytes()),
        }
        require(
            {field: rollback[field] for field in expected_rollback} == expected_rollback,
            "signed-Nostr activation rollback baseline drift",
        )
        return

    require(
        not (
            base["renderFileSet"] == "signed-nostr-participant-gateway"
            and candidate["renderFileSet"] != "signed-nostr-participant-gateway"
        ),
        "combined signed-Nostr/participant gateway deactivation blocked pending separately reviewed exact teardown evidence",
    )

    if base["renderFileSet"] == "signed-nostr" and candidate["renderFileSet"] == "reviewed-public-knowledge":
        require(candidate["head"] == base["head"], "signed-Nostr rollback must preserve the Release Set head")
        activation_evidence = base["signedNostr"]["runtimePin"]["activationEvidence"]
        rollback_contract = activation_evidence["lifecycle"]["rollbackContract"]
        approved_deactivation = SIGNED_NOSTR_APPROVED_DEACTIVATION_EVIDENCE
        require(
            approved_deactivation is not None,
            "signed-Nostr deactivation blocked: completed exact-UID live teardown evidence requires separate review",
        )
        verify_signed_nostr_deactivation_evidence(
            approved_deactivation,
            activation_evidence,
            rollback_contract,
        )
        for relative in FUTURE_EXPECTED_FILES:
            if relative in SIGNED_NOSTR_MUTABLE_EXISTING_FILES:
                continue
            require(
                (candidate_root / relative).read_bytes() == (base_root / relative).read_bytes(),
                f"signed-Nostr rollback changed existing file: {relative}",
            )
        rollback = base["signedNostr"]["runtimePin"]["rollback"]
        expected_rollback = {
            "integritySha256": bytes_digest((candidate_root / f"{RENDER_ROOT}/integrity.json").read_bytes()),
            "webIngressSha256": bytes_digest((candidate_root / f"{RENDER_ROOT}/web/ingress.json").read_bytes()),
            "publicMeckyNetworkPolicySha256": bytes_digest((candidate_root / f"{RENDER_ROOT}/public-mecky/networkpolicy.json").read_bytes()),
            "boundaryReceiptSha256": bytes_digest((candidate_root / f"{RENDER_ROOT}/network-boundary-migration.json").read_bytes()),
        }
        require(
            {field: rollback[field] for field in expected_rollback} == expected_rollback,
            "signed-Nostr rollback did not restore the exact prior boundary",
        )
        return

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
    if base["renderFileSet"] in {"signed-nostr", "signed-nostr-participant-gateway"}:
        for relative in SIGNED_NOSTR_FILES:
            require(
                (candidate_root / relative).read_bytes() == (base_root / relative).read_bytes(),
                f"routine promotion changed signed-Nostr runtime file: {relative}",
            )
    if base_participant_gateway:
        for relative in PARTICIPANT_GATEWAY_FILES:
            require(
                (candidate_root / relative).read_bytes() == (base_root / relative).read_bytes(),
                f"routine promotion changed staging participant gateway runtime file: {relative}",
            )
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
