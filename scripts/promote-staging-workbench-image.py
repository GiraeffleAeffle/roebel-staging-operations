#!/usr/bin/env python3
"""One-time, CAS-bound promotion of the public E2E workbench image.

This runner owns exactly one existing Deployment public-mode transition.  It
does not adopt a name, apply a manifest, touch a Secret, or change the
Service or NetworkPolicy which make the workbench reachable.  The live path
is bounded to one preflight, one JSON Patch, and (when a known postcondition
fails) one CAS rollback patch.  A lost mutation response is classified with
one GET; there is deliberately no blind mutation retry.

The module is dependency-free so the wrapper can execute the protected bytes
with ``python3 -I``.  Tests inject a narrow Kubernetes-like object instead of
contacting a cluster.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import http.client
import ipaddress
import json
import os
import re
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "roebel_staging_workbench_image_promotion_v1"
JOURNAL_SCHEMA = "roebel_staging_workbench_image_promotion_journal_v1"
RECEIPT_SCHEMA = "roebel_staging_workbench_image_promotion_receipt_v1"

WORKBENCH_NAMESPACE = "stadtstack-roebel-staging-lab"
WORKBENCH_NAME = "e2e-workbench"
WORKBENCH_DEPLOYMENT_UID = "f7e99fb3-842d-469b-9196-cd1c6dfe10bb"
WORKBENCH_CONTAINER_NAME = "e2e-workbench"
OWNER_LABEL_KEY = "stadtstack.io/owner"
OWNER_LABEL_VALUE = "stadtstack-operations-private"
WORKBENCH_MODE_ENV_NAME = "WORKBENCH_MODE"
WORKBENCH_MODE_ENV_VALUE = "public-signed-only"
# These four fixture-only inputs are the only environment entries admitted
# for removal.  Every other entry remains byte-for-byte in its original list
# position, including SecretKeyRef references (whose values are never read).
FORBIDDEN_PUBLIC_MODE_ENV_NAMES = (
    "CASE_STEWARD_TOKEN",
    "STADTSTACK_CONTROL_BASE_URL",
    "STADTSTACK_PUBLIC_BASE_URL",
    "SYNTHETIC_CITIZENS_JSON",
)
FORBIDDEN_PUBLIC_MODE_ENV_SET = frozenset(FORBIDDEN_PUBLIC_MODE_ENV_NAMES)
# These fixture values can contain credential-like material and are therefore
# admitted in the old Deployment only as a value-free Secret reference. The
# reference itself is journaled for exact rollback; the Secret is never read.
PUBLIC_MODE_SECRET_REF_ENV_NAMES = frozenset({
    "CASE_STEWARD_TOKEN",
    "CITIZEN_RELAY_ADMISSION_TOKEN",
    "SYNTHETIC_CITIZENS_JSON",
})

OLD_IMAGE = (
    "registry.agentcart.eu/civic/roebel-staging-workbench@"
    "sha256:1a7f53a4dc367c8170ca7021de622f6517784d8acabdfba6c06272e500a337dc"
)
TARGET_IMAGE = (
    "ghcr.io/giraeffleaeffle/roebel-e2e-workbench@"
    "sha256:2158831bd76865db483ca6a8dc211e7d5c3de51d0113613fc0a22a4ca27fc6ce"
)
TARGET_DIGEST = TARGET_IMAGE.rsplit("@", 1)[1]
SOURCE_REVISION = "36ac41d7049df815aaebbe4301c098a0ec7e4101"
ARTIFACT_PIN_RECEIPT_SHA256 = "sha256:08d2b65bb57434ba6f35d8083f32b22f43010e1222544a8ce074e208f95efd9b"
PROTECTED_PATHS = (
    "scripts/run-staging-participant-gateway-live.py",
    "scripts/promote-staging-workbench-image.py",
    "scripts/verify-reviewed-render.py",
    "policy/repository-contract.json",
)

SERVICE_NAME = "e2e-workbench"
NETWORK_POLICY_NAME = "e2e-workbench"
SERVICE_TARGET = {
    "apiVersion": "v1",
    "kind": "Service",
    "namespace": WORKBENCH_NAMESPACE,
    "name": SERVICE_NAME,
}
NETWORK_POLICY_TARGET = {
    "apiVersion": "networking.k8s.io/v1",
    "kind": "NetworkPolicy",
    "namespace": WORKBENCH_NAMESPACE,
    "name": NETWORK_POLICY_NAME,
}
DEPLOYMENT_TARGET = {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "namespace": WORKBENCH_NAMESPACE,
    "name": WORKBENCH_NAME,
}

PROBE_CONFIG_PATH = "/stadtstack-test/api/config"
PROBE_FEED_PATH = "/stadtstack-test/api/feed?profile=public"
PUBLIC_CONFIG_SCHEMA = "roebel_e2e_workbench_config_v1"
PUBLIC_FEED_SCHEMA = "roebel_staging_mixed_feed_v1"
# Functional verification uses the exact public staging origin exercised by a
# participant browser.  It is fixed in the protected runner and is never a
# caller-selected destination.
WORKBENCH_PUBLIC_HOSTNAME = "roebel-web.staging.agentcart.eu"
WORKBENCH_PUBLIC_PORT = 443
WORKBENCH_PUBLIC_ORIGIN = f"https://{WORKBENCH_PUBLIC_HOSTNAME}"
WORKBENCH_PROBE_TIMEOUT_SECONDS = 15
WORKBENCH_PROBE_MAX_BODY_BYTES = 8 * 1024 * 1024
# The Service identity and port remain independently verified against the
# target Pod and EndpointSlice before any public functional probe is trusted.
WORKBENCH_SERVICE_PORT = 18083
WORKBENCH_SERVICE_PORT_NAME = "http"
WORKBENCH_PROBE_PATHS = (PROBE_CONFIG_PATH, PROBE_FEED_PATH)
_PROBE_BINDING_DESCRIPTOR = json.dumps(
    {
        "transport": "python-stdlib-direct-https",
        "origin": WORKBENCH_PUBLIC_ORIGIN,
        "hostname": WORKBENCH_PUBLIC_HOSTNAME,
        "port": WORKBENCH_PUBLIC_PORT,
        "method": "GET",
        "expectedStatus": 200,
        "tlsVerification": "default-ca-and-hostname",
        "environmentProxyUse": False,
        "redirectsFollowed": False,
        "timeoutSeconds": WORKBENCH_PROBE_TIMEOUT_SECONDS,
        "maxBodyBytes": WORKBENCH_PROBE_MAX_BODY_BYTES,
        "allowedPaths": list(WORKBENCH_PROBE_PATHS),
    },
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
)
WORKBENCH_PROBE_BINDING_SHA256 = "sha256:" + hashlib.sha256(_PROBE_BINDING_DESCRIPTOR.encode("ascii")).hexdigest()
ENDPOINT_SLICE_LABEL = "kubernetes.io/service-name"

CONFIG_KEYS = frozenset({"schemaVersion", "personas", "meckyPubkey", "mode", "authorityBinding"})
PERSONA_KEYS = frozenset({"id", "name", "publicKey"})
FEED_KEYS = frozenset({"schemaVersion", "posts", "authorityBinding"})
ORDINARY_POST_KEYS = frozenset({
    "id", "entryType", "event", "author", "content", "createdAt", "replyCount",
    "meckyMentioned", "meckyAnswered", "promotedDiscussionId", "promotedTopicId",
    "sourceAppPostId", "synthetic",
})
TOPIC_POST_KEYS = frozenset({
    "id", "entryType", "author", "content", "createdAt", "replyCount", "meckyMentioned",
    "meckyAnswered", "suggestionSigned", "caseBinding", "sourceConversation", "topicId",
    "topicTitle", "synthetic", "lastActivityAt", "discussionCount", "discussionIds",
    "discussions", "sourcePostIds", "activityCount",
})
TOPIC_DISCUSSION_KEYS = frozenset({
    "id", "author", "content", "createdAt", "replyCount", "meckyMentioned", "meckyAnswered",
    "suggestionSigned", "caseBinding", "sourceConversation", "synthetic",
})
AUTHOR_KEYS = frozenset({"name", "kind", "pubkey", "synthetic"})
NOSTR_EVENT_KEYS = frozenset({"id", "pubkey", "created_at", "kind", "tags", "content", "sig"})
CASE_BINDING_KEYS = frozenset({"municipalityId", "sourceCaseId", "canonicalCaseId"})
CONVERSATION_KEYS = frozenset({
    "sourceAppPostId", "sourceAppCommentId", "mentionId", "replyId", "receiptId", "mentionAuthor", "evidenceRefs",
})
EVIDENCE_REF_KEYS = frozenset({"digest", "url"})
FORBIDDEN_PROVENANCE_VALUES = frozenset({
    "demo", "demo-data", "fixture", "seed", "seeded", "synthetic", "synthetic-fixture", "test-fixture", "isolated-fixture",
})

KUBECTL_BIN = Path("/Users/max/.local/bin/kubectl-v1.36.0")
KUBECTL_SHA256 = "sha256:4bcf268eacdc1d2df74e37d86f639f27ca7dea3ae185b7b452b73b9fb5ddc14e"

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._:/-]+@sha256:[0-9a-f]{64}$")
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_ERROR_CHARS = 320
KUBECTL_REQUEST_TIMEOUT_SECONDS = 30
KUBECTL_PROCESS_TIMEOUT_SECONDS = 40
ROLLOUT_TIMEOUT_SECONDS = 120
ROLLOUT_REQUEST_GRACE_SECONDS = 5
ROLLOUT_PROCESS_GRACE_SECONDS = 10

# This one field is deliberately allowed in a value-free receipt.  It is an
# effect flag, not a credential or a credential reference.  Keeping the
# exception explicit prevents the recursive guard below from turning a safe
# audit fact into a secret-shaped field while still rejecting all other
# secret/token/password-looking keys.
SAFE_VALUE_FREE_KEYS = {"secretvaluesread"}


class PromotionError(RuntimeError):
    """A fail-closed precondition, postcondition, or persistence failure."""


class TransportUncertain(PromotionError):
    """The runner cannot prove whether a requested operation reached the API."""


class PostconditionFailure(PromotionError):
    """The API state was observed, but it is not the reviewed state."""


class PromotionInterrupted(PromotionError):
    """Operator termination converted into a rollback-visible exception."""

    def __init__(self, signum: int) -> None:
        self.signum = signum
        super().__init__(f"workbench promotion interrupted by signal {signum}")


class FinalizationError(PromotionError):
    """Durable receipt/journal finalization failed after workload processing."""

    def __init__(self, stage: str, *, receipt_may_have_committed: bool, journal_may_have_committed: bool, cause: Exception) -> None:
        super().__init__(f"finalization failed at {stage}: {_bounded_error(cause)}")
        self.stage = stage
        self.receipt_may_have_committed = receipt_may_have_committed
        self.journal_may_have_committed = journal_may_have_committed


TRANSACTION_SIGNALS = (signal.SIGINT, signal.SIGTERM)


def install_transaction_signal_handlers() -> dict[int, Any]:
    """Make the first operator signal enter normal transaction recovery."""
    previous: dict[int, Any] = {}

    def interrupt(received: int, _frame: Any) -> None:
        raise PromotionInterrupted(received)

    try:
        for signum in TRANSACTION_SIGNALS:
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, interrupt)
    except (OSError, ValueError) as error:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        raise PromotionError("live promotion requires controllable signal handlers") from error
    return previous


def defer_transaction_signals() -> None:
    """Prevent a second signal from interrupting rollback or finalization."""
    for signum in TRANSACTION_SIGNALS:
        signal.signal(signum, signal.SIG_IGN)


def restore_transaction_signal_handlers(previous: dict[int, Any]) -> None:
    for signum, handler in previous.items():
        signal.signal(signum, handler)


def require(condition: bool, message: str, error: type[PromotionError] = PromotionError) -> None:
    if not condition:
        raise error(message)


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def bytes_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(raw: bytes | str, label: str) -> Any:
    try:
        return json.loads(raw, object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, PromotionError) as error:
        raise PromotionError(f"{label} is not valid JSON") from error


def parse_object(raw: bytes | str, label: str) -> dict[str, Any]:
    value = parse_json(raw, label)
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return value


def _bounded_error(value: Any) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return " ".join(str(value).split())[:MAX_ERROR_CHARS]


def _reject_secret_shaped(value: Any, path: str = "$") -> None:
    """Reject accidental credential material in value-free durable records."""
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = str(key).lower().replace("_", "").replace("-", "")
            if lowered in SAFE_VALUE_FREE_KEYS:
                require(isinstance(child, bool), f"value-free effect flag at {path}.{key} must be boolean")
            elif lowered == "valuefrom":
                # A rollback journal may retain Kubernetes references so it
                # can restore the exact old env list after a process restart.
                # References are safe only as a closed, value-free object;
                # literal secret material or arbitrary nested fields remain
                # rejected.  The referenced Secret value is never read.
                require(isinstance(child, dict) and len(child) == 1, f"environment reference shape invalid at {path}.{key}")
                reference_kind, reference = next(iter(child.items()))
                normalized_kind = str(reference_kind).lower().replace("_", "").replace("-", "")
                require(normalized_kind == "secretkeyref", f"environment reference kind invalid at {path}.{key}")
                require(isinstance(reference, dict), f"environment reference value invalid at {path}.{key}")
                allowed = {"name", "key", "optional"}
                require(set(reference) <= allowed and {"name", "key"} <= set(reference), f"environment reference fields invalid at {path}.{key}")
                require(isinstance(reference["name"], str) and bool(reference["name"]), f"environment reference name invalid at {path}.{key}")
                require(isinstance(reference["key"], str) and bool(reference["key"]), f"environment reference key invalid at {path}.{key}")
                if "optional" in reference:
                    require(isinstance(reference["optional"], bool), f"environment reference optional invalid at {path}.{key}")
                continue
            require(
                lowered in SAFE_VALUE_FREE_KEYS
                or not any(token in lowered for token in ("secret", "password", "privatekey", "apikey", "token")),
                f"value-free record contains credential-shaped field at {path}.{key}",
            )
            _reject_secret_shaped(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_shaped(child, f"{path}[{index}]")


def _read_private_regular(path: Path, label: str, *, max_bytes: int = MAX_FILE_BYTES) -> bytes:
    selected = Path(path).absolute()
    info = os.lstat(selected)
    require(stat.S_ISREG(info.st_mode) and not selected.is_symlink(), f"{label} must be a regular non-symlink file")
    require(info.st_size > 0 and info.st_size <= max_bytes, f"{label} exceeds the bounded size")
    with selected.open("rb") as stream:
        raw = stream.read(max_bytes + 1)
    require(len(raw) == info.st_size, f"{label} changed while reading")
    return raw


def _validate_uuid(value: Any, label: str) -> str:
    require(isinstance(value, str) and UUID_RE.fullmatch(value) is not None, f"{label} UUID invalid")
    return value


def _validate_resource_version(value: Any, label: str) -> str:
    require(isinstance(value, str) and value.isdigit() and int(value) >= 0, f"{label} resourceVersion invalid")
    return value


def _metadata(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    metadata = value.get("metadata")
    require(isinstance(metadata, dict), f"{label} metadata absent")
    return metadata


def identity(value: dict[str, Any], label: str) -> dict[str, str]:
    metadata = _metadata(value, label)
    require(isinstance(value.get("apiVersion"), str), f"{label} apiVersion absent")
    require(isinstance(value.get("kind"), str), f"{label} kind absent")
    require(isinstance(metadata.get("namespace"), str), f"{label} namespace absent")
    require(isinstance(metadata.get("name"), str), f"{label} name absent")
    return {
        "apiVersion": value["apiVersion"],
        "kind": value["kind"],
        "namespace": metadata["namespace"],
        "name": metadata["name"],
    }


def _without_server_fields(value: Any) -> Any:
    result = copy.deepcopy(value)
    if isinstance(result, dict):
        metadata = result.get("metadata")
        if isinstance(metadata, dict):
            for key in (
                "creationTimestamp",
                "deletionGracePeriodSeconds",
                "deletionTimestamp",
                "generation",
                "managedFields",
                "resourceVersion",
                "selfLink",
                "uid",
            ):
                metadata.pop(key, None)
        result.pop("status", None)
    return result


def spec_digest(value: dict[str, Any]) -> str:
    spec = value.get("spec")
    require(isinstance(spec, dict), "Kubernetes object spec absent")
    return digest(spec)


IMAGE_PLACEHOLDER = "__REVIEWED_WORKBENCH_IMAGE__"


def _containers(value: dict[str, Any], label: str) -> list[dict[str, Any]]:
    spec = value.get("spec")
    require(isinstance(spec, dict), f"{label} spec absent")
    template = spec.get("template")
    require(isinstance(template, dict), f"{label} pod template absent")
    template_spec = template.get("spec")
    require(isinstance(template_spec, dict), f"{label} pod template spec absent")
    containers = template_spec.get("containers")
    require(isinstance(containers, list) and containers, f"{label} containers absent")
    require(all(isinstance(item, dict) for item in containers), f"{label} container entry invalid")
    return containers


def container_index(value: dict[str, Any], name: str = WORKBENCH_CONTAINER_NAME) -> int:
    containers = _containers(value, "workbench Deployment")
    matches = [index for index, item in enumerate(containers) if item.get("name") == name]
    require(len(matches) == 1, f"workbench Deployment must have exactly one {name} container")
    return matches[0]


def _container_path(index: int, field: str) -> str:
    return f"/spec/template/spec/containers/{index}/{field}"


def _container_env(value: dict[str, Any], label: str = "workbench Deployment") -> list[dict[str, Any]]:
    """Return the named container's environment without reading Secret values."""
    container = _containers(value, label)[container_index(value)]
    env = container.get("env")
    require(isinstance(env, list), f"{label} environment list absent")
    require(
        all(isinstance(item, dict) and isinstance(item.get("name"), str) and bool(item["name"]) for item in env),
        f"{label} environment entry invalid",
    )
    return env


def _public_mode_source_env(value: dict[str, Any], label: str = "workbench Deployment") -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Validate the exact old fixture environment and return removal indexes."""
    env = _container_env(value, label)
    return _public_mode_source_entries(env, label)


def _public_mode_source_entries(env: list[dict[str, Any]], label: str) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Validate a stored old environment without reading referenced Secrets."""
    require(isinstance(env, list), f"{label} environment list absent")
    require(
        all(isinstance(item, dict) and isinstance(item.get("name"), str) and bool(item["name"]) for item in env),
        f"{label} environment entry invalid",
    )
    mode_entries = [item for item in env if item.get("name") == WORKBENCH_MODE_ENV_NAME]
    require(not mode_entries, f"{label} already has {WORKBENCH_MODE_ENV_NAME}")
    indexes: dict[str, int] = {}
    for name in FORBIDDEN_PUBLIC_MODE_ENV_NAMES:
        matches = [index for index, item in enumerate(env) if item.get("name") == name]
        require(len(matches) == 1, f"{label} must contain exactly one {name}")
        indexes[name] = matches[0]
    for name in FORBIDDEN_PUBLIC_MODE_ENV_NAMES:
        if name in PUBLIC_MODE_SECRET_REF_ENV_NAMES:
            entry = env[indexes[name]]
            require(
                "value" not in entry
                and isinstance(entry.get("valueFrom"), dict)
                and set(entry["valueFrom"]) == {"secretKeyRef"},
                f"{label} literal credential environment value forbidden: {name}",
            )
    return env, indexes


def _public_mode_target_env(value: dict[str, Any], label: str = "workbench Deployment") -> list[dict[str, Any]]:
    """Validate the target's fixture-free public environment."""
    env = _container_env(value, label)
    require(
        not any(item.get("name") in FORBIDDEN_PUBLIC_MODE_ENV_SET for item in env),
        f"{label} contains forbidden public-mode environment entries",
    )
    mode_entries = [item for item in env if item.get("name") == WORKBENCH_MODE_ENV_NAME]
    require(len(mode_entries) == 1, f"{label} must contain exactly one {WORKBENCH_MODE_ENV_NAME}")
    require(
        mode_entries[0] == {"name": WORKBENCH_MODE_ENV_NAME, "value": WORKBENCH_MODE_ENV_VALUE},
        f"{label} {WORKBENCH_MODE_ENV_NAME} value drift",
    )
    return env


def _normalized_public_mode_env(env: Any) -> Any:
    if not isinstance(env, list):
        return env
    return [
        copy.deepcopy(item)
        for item in env
        if not isinstance(item, dict)
        or item.get("name") not in FORBIDDEN_PUBLIC_MODE_ENV_SET | {WORKBENCH_MODE_ENV_NAME}
    ]


def normalized_deployment_spec(value: dict[str, Any], *, index: int | None = None) -> dict[str, Any]:
    result = copy.deepcopy(value.get("spec"))
    require(isinstance(result, dict), "workbench Deployment spec absent")
    if index is None:
        index = container_index(value)
    containers = result.get("template", {}).get("spec", {}).get("containers")
    require(isinstance(containers, list) and 0 <= index < len(containers), "workbench container index invalid")
    require(isinstance(containers[index], dict), "workbench container invalid")
    containers[index] = copy.deepcopy(containers[index])
    containers[index]["image"] = IMAGE_PLACEHOLDER
    # The normalized digest is the transition invariant: image, the four
    # removed fixture entries, and the newly appended public-mode marker are
    # deliberately omitted.  Any other field, reference, or list ordering
    # remains part of the digest and therefore cannot drift silently.
    if "env" in containers[index]:
        containers[index]["env"] = _normalized_public_mode_env(containers[index]["env"])
    return result


def normalized_spec_digest(value: dict[str, Any], *, index: int | None = None) -> str:
    return digest(normalized_deployment_spec(value, index=index))


def spec_equal_except_image(before: dict[str, Any], after: dict[str, Any], *, index: int | None = None) -> bool:
    """Compare specs after removing only the reviewed public-mode delta."""
    if index is None:
        index = container_index(before)
    try:
        return normalized_deployment_spec(before, index=index) == normalized_deployment_spec(after, index=index)
    except PromotionError:
        return False


def _owner_label(value: dict[str, Any], label: str) -> str:
    metadata = _metadata(value, label)
    labels = metadata.get("labels")
    require(isinstance(labels, dict), f"{label} labels absent")
    owner = labels.get(OWNER_LABEL_KEY)
    require(owner == OWNER_LABEL_VALUE, f"{label} owner label drift")
    return owner


def _no_owner_refs(value: dict[str, Any], label: str) -> None:
    metadata = _metadata(value, label)
    require(not metadata.get("ownerReferences"), f"{label} ownerReferences must be absent")


def validate_artifact_pin(
    path: Path,
    *,
    expected_receipt_sha256: str = ARTIFACT_PIN_RECEIPT_SHA256,
    expected_source_revision: str = SOURCE_REVISION,
) -> dict[str, Any]:
    """Bind the immutable reviewed pin receipt before Kubernetes contact."""
    require(SHA256_RE.fullmatch(expected_receipt_sha256) is not None, "artifact receipt checksum policy invalid")
    require(REVISION_RE.fullmatch(expected_source_revision) is not None, "artifact source revision policy invalid")
    raw = _read_private_regular(path, "artifact pin receipt")
    observed_sha256 = bytes_digest(raw)
    require(observed_sha256 == expected_receipt_sha256, "artifact pin receipt checksum drift")
    value = parse_object(raw, "artifact pin receipt")
    require(value.get("schemaVersion") == "roebel_e2e_runtime_pin_v1", "artifact pin schema drift")
    require(value.get("sourceRevision") == expected_source_revision, "artifact pin source revision drift")
    require(value.get("civicAuthority") == "none", "artifact pin civic authority widened")
    require(value.get("deploymentEffect") is False, "artifact pin deployment effect widened")
    components = value.get("components")
    require(isinstance(components, list) and components, "artifact pin component list absent")
    selected = [item for item in components if isinstance(item, dict) and item.get("component") == "roebel-e2e-workbench"]
    require(len(selected) == 1, "artifact pin workbench component missing or duplicated")
    component = selected[0]
    require(component.get("image") == TARGET_IMAGE.split("@", 1)[0], "artifact pin repository drift")
    require(component.get("manifestDigest") == TARGET_DIGEST, "artifact pin manifest digest drift")
    provenance = component.get("provenance")
    sbom = component.get("sbomAttestation")
    workflow = component.get("workflowIdentity")
    require(isinstance(provenance, dict) and isinstance(provenance.get("url"), str), "artifact provenance binding absent")
    require(isinstance(sbom, dict) and isinstance(sbom.get("url"), str), "artifact SBOM binding absent")
    require(isinstance(workflow, str) and workflow.endswith("/.github/workflows/roebel-e2e-runtime-publish.yml@refs/heads/main"), "artifact workflow binding drift")
    return {
        "receiptSha256": observed_sha256,
        "sourceRevision": expected_source_revision,
        "component": "roebel-e2e-workbench",
        "repository": component["image"],
        "manifestDigest": component["manifestDigest"],
        "image": TARGET_IMAGE,
        "civicAuthority": "none",
        "deploymentEffect": False,
    }


def _public_mode_patch_test_operations(deployment: dict[str, Any], *, expected_image: str) -> tuple[list[dict[str, Any]], int]:
    metadata = _metadata(deployment, "workbench Deployment")
    uid = _validate_uuid(metadata.get("uid"), "workbench Deployment")
    resource_version = _validate_resource_version(metadata.get("resourceVersion"), "workbench Deployment")
    require(uid == WORKBENCH_DEPLOYMENT_UID, "workbench Deployment UID drift")
    index = container_index(deployment)
    containers = _containers(deployment, "workbench Deployment")
    require(containers[index].get("image") == expected_image, "workbench Deployment image drift")
    _owner_label(deployment, "workbench Deployment")
    path_name = _container_path(index, "name")
    path_image = _container_path(index, "image")
    return [
        {"op": "test", "path": "/metadata/uid", "value": WORKBENCH_DEPLOYMENT_UID},
        {"op": "test", "path": "/metadata/resourceVersion", "value": resource_version},
        {"op": "test", "path": "/metadata/labels/stadtstack.io~1owner", "value": OWNER_LABEL_VALUE},
        {"op": "test", "path": path_name, "value": WORKBENCH_CONTAINER_NAME},
        {"op": "test", "path": path_image, "value": expected_image},
    ], index


def _validate_public_mode_patch_shape(operations: list[dict[str, Any]]) -> None:
    """Enforce the closed JSON-Patch grammar at the transport boundary."""
    require(isinstance(operations, list), "workbench Deployment patch must be a list")
    require(len(operations) == 11, "workbench Deployment public-mode patch shape widened")
    require(all(isinstance(item, dict) for item in operations), "workbench Deployment patch entry invalid")
    require([item.get("op") for item in operations[:5]] == ["test"] * 5, "workbench Deployment CAS tests widened")
    require(all(set(item) == {"op", "path", "value"} for item in operations[:5]), "workbench Deployment CAS test fields widened")
    image_path = operations[5].get("path") if len(operations) > 5 and isinstance(operations[5], dict) else None
    match = re.fullmatch(r"/spec/template/spec/containers/(\d+)/image", image_path or "")
    require(match is not None, "workbench Deployment image path widened")
    container_prefix = f"/spec/template/spec/containers/{match.group(1)}"
    require(
        {item.get("path") for item in operations[:5]}
        == {
            "/metadata/uid",
            "/metadata/resourceVersion",
            "/metadata/labels/stadtstack.io~1owner",
            f"{container_prefix}/name",
            image_path,
        },
        "workbench Deployment CAS test paths widened",
    )
    image_operation = operations[5]
    require(
        set(image_operation) == {"op", "path", "value"}
        and
        image_operation.get("op") == "replace"
        and image_operation.get("path") == image_path
        and image_operation.get("value") in {OLD_IMAGE, TARGET_IMAGE},
        "workbench Deployment image transition widened",
    )
    transition = operations[6:]
    env_paths = [item.get("path") for item in transition]
    require(all(isinstance(path, str) for path in env_paths), "workbench Deployment environment patch path invalid")
    env_prefix = f"{container_prefix}/env/"

    def env_index(path: Any) -> int:
        require(isinstance(path, str) and path.startswith(env_prefix), "workbench Deployment environment patch path invalid")
        suffix = path[len(env_prefix):]
        require(re.fullmatch(r"[0-9]+", suffix) is not None, "workbench Deployment environment index invalid")
        return int(suffix)

    if image_operation["value"] == TARGET_IMAGE:
        removals = transition[:4]
        require(
            all(set(item) == {"op", "path"} and item.get("op") == "remove" for item in removals),
            "workbench Deployment fixture removal shape widened",
        )
        indexes = [env_index(item["path"]) for item in removals]
        require(indexes == sorted(indexes, reverse=True) and len(set(indexes)) == 4, "workbench Deployment fixture removal order drift")
        require(
            set(transition[4]) == {"op", "path", "value"}
            and
            transition[4]
            == {"op": "add", "path": f"{env_prefix}-", "value": {"name": WORKBENCH_MODE_ENV_NAME, "value": WORKBENCH_MODE_ENV_VALUE}},
            "workbench Deployment public mode addition drift",
        )
    else:
        require(
            set(transition[0]) == {"op", "path"}
            and transition[0].get("op") == "remove",
            "workbench Deployment public mode removal drift",
        )
        env_index(transition[0]["path"])
        require(
            all(set(item) == {"op", "path", "value"} and item.get("op") == "add" for item in transition[1:]),
            "workbench Deployment fixture restoration shape widened",
        )
        indexes = [env_index(item["path"]) for item in transition[1:]]
        require(indexes == sorted(indexes) and len(set(indexes)) == 4, "workbench Deployment fixture restoration order drift")
        require(
            all(isinstance(item.get("value"), dict) and item["value"].get("name") in FORBIDDEN_PUBLIC_MODE_ENV_SET for item in transition[1:]),
            "workbench Deployment fixture restoration names drift",
        )


def build_image_patch(deployment: dict[str, Any], *, image: str = TARGET_IMAGE) -> list[dict[str, Any]]:
    """Build the exact public-mode Deployment transition patch."""
    require(image == TARGET_IMAGE, "workbench Deployment target image drift")
    env, indexes = _public_mode_source_env(deployment)
    tests, index = _public_mode_patch_test_operations(deployment, expected_image=OLD_IMAGE)
    require(index == container_index(deployment), "workbench container index drift")
    env_path = _container_path(index, "env")
    operations = tests + [{"op": "replace", "path": _container_path(index, "image"), "value": TARGET_IMAGE}]
    operations.extend(
        {"op": "remove", "path": f"{env_path}/{env_index}"}
        for env_index in sorted(indexes.values(), reverse=True)
    )
    operations.append(
        {"op": "add", "path": f"{env_path}/-", "value": {"name": WORKBENCH_MODE_ENV_NAME, "value": WORKBENCH_MODE_ENV_VALUE}}
    )
    # The transport adapter only accepts the fixed-container path; reject an
    # unexpected container position before any caller can send this patch.
    _validate_public_mode_patch_shape(operations)
    return operations


def build_public_mode_patch(deployment: dict[str, Any], *, image: str = TARGET_IMAGE) -> list[dict[str, Any]]:
    """Named alias making the transition intent explicit to callers/tests."""
    return build_image_patch(deployment, image=image)


def build_rollback_patch(deployment: dict[str, Any], *, before: dict[str, Any]) -> list[dict[str, Any]]:
    """Build an exact inverse restoring the complete old environment order."""
    env, indexes = _public_mode_source_env(before)
    current_env = _public_mode_target_env(deployment)
    tests, index = _public_mode_patch_test_operations(deployment, expected_image=TARGET_IMAGE)
    before_index = container_index(before)
    require(index == before_index, "workbench rollback container index drift")
    expected_target_env = [
        copy.deepcopy(item)
        for item in env
        if item.get("name") not in FORBIDDEN_PUBLIC_MODE_ENV_SET
    ] + [{"name": WORKBENCH_MODE_ENV_NAME, "value": WORKBENCH_MODE_ENV_VALUE}]
    require(current_env == expected_target_env, "workbench rollback public environment drift", PostconditionFailure)
    env_path = _container_path(index, "env")
    mode_index = len(current_env) - 1
    operations = tests + [{"op": "replace", "path": _container_path(index, "image"), "value": OLD_IMAGE}]
    operations.append({"op": "remove", "path": f"{env_path}/{mode_index}"})
    operations.extend(
        {"op": "add", "path": f"{env_path}/{env_index}", "value": copy.deepcopy(env[env_index])}
        for env_index in sorted(indexes.values())
    )
    _validate_public_mode_patch_shape(operations)
    return operations


def _validate_target(value: dict[str, Any], expected: dict[str, str], label: str) -> None:
    require(identity(value, label) == expected, f"{label} target drift")


def validate_workbench_deployment(value: Any, *, expected_image: str, label: str = "workbench Deployment") -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} absent")
    _validate_target(value, DEPLOYMENT_TARGET, label)
    metadata = _metadata(value, label)
    uid = _validate_uuid(metadata.get("uid"), label)
    require(uid == WORKBENCH_DEPLOYMENT_UID, f"{label} UID drift")
    resource_version = _validate_resource_version(metadata.get("resourceVersion"), label)
    _owner_label(value, label)
    _no_owner_refs(value, label)
    require(isinstance(expected_image, str) and IMAGE_RE.fullmatch(expected_image) is not None, "expected workbench image invalid")
    index = container_index(value)
    containers = _containers(value, label)
    require(containers[index].get("image") == expected_image, f"{label} image drift")
    require(isinstance(containers[index].get("name"), str), f"{label} container name absent")
    spec = value.get("spec")
    require(isinstance(spec, dict), f"{label} spec absent")
    replicas = spec.get("replicas", 1)
    require(isinstance(replicas, int) and replicas >= 1, f"{label} replicas invalid")
    selector = spec.get("selector", {}).get("matchLabels") if isinstance(spec.get("selector"), dict) else None
    require(isinstance(selector, dict) and selector and all(isinstance(k, str) and isinstance(v, str) for k, v in selector.items()), f"{label} selector invalid")
    ports = containers[index].get("ports")
    require(
        isinstance(ports, list)
        and len(ports) == 1
        and ports[0].get("name") == WORKBENCH_SERVICE_PORT_NAME
        and ports[0].get("containerPort") == WORKBENCH_SERVICE_PORT
        and ports[0].get("protocol", "TCP") == "TCP",
        f"{label} container port drift",
    )
    if expected_image == TARGET_IMAGE:
        _public_mode_target_env(value, label)
    return {
        "uid": uid,
        "resourceVersion": resource_version,
        "index": index,
        "containerName": WORKBENCH_CONTAINER_NAME,
        "image": expected_image,
        "replicas": replicas,
        "selector": copy.deepcopy(selector),
        "containerPort": {"name": WORKBENCH_SERVICE_PORT_NAME, "port": WORKBENCH_SERVICE_PORT, "protocol": "TCP"},
        "specSha256": spec_digest(value),
        "normalizedSpecSha256": normalized_spec_digest(value, index=index),
    }


def validate_service_or_network_policy(value: Any, expected: dict[str, str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} absent")
    _validate_target(value, expected, label)
    metadata = _metadata(value, label)
    uid = _validate_uuid(metadata.get("uid"), label)
    _no_owner_refs(value, label)
    spec = value.get("spec")
    require(isinstance(spec, dict), f"{label} spec absent")
    return {"target": copy.deepcopy(expected), "uid": uid, "specSha256": digest(spec)}


def validate_service_routing(service: dict[str, Any], deployment_facts: dict[str, Any]) -> dict[str, Any]:
    """Bind the exact live Service selector and numeric port to the Deployment."""
    spec = service.get("spec")
    require(isinstance(spec, dict), "workbench Service spec absent", PostconditionFailure)
    ports = spec.get("ports")
    require(
        spec.get("selector") == deployment_facts["selector"]
        and isinstance(ports, list)
        and len(ports) == 1
        and set(ports[0]) <= {"name", "port", "protocol", "targetPort"}
        and ports[0].get("name") == WORKBENCH_SERVICE_PORT_NAME
        and ports[0].get("port") == WORKBENCH_SERVICE_PORT
        and ports[0].get("targetPort") == WORKBENCH_SERVICE_PORT
        and ports[0].get("protocol", "TCP") == "TCP",
        "workbench Service selector/port/targetPort drift",
        PostconditionFailure,
    )
    return {
        "selector": copy.deepcopy(deployment_facts["selector"]),
        "servicePort": WORKBENCH_SERVICE_PORT,
        "targetPort": WORKBENCH_SERVICE_PORT,
        "containerPort": copy.deepcopy(deployment_facts["containerPort"]),
    }


def validate_endpoint_slices(value: Any, pod_proof: dict[str, Any]) -> dict[str, Any]:
    """Require Service backends to be the exact promoted Pod UIDs and IPs."""
    require(isinstance(value, list) and value, "workbench EndpointSlice set absent", PostconditionFailure)
    expected = {
        item["uid"]: {"name": item["name"], "addresses": set(item["podIPs"])}
        for item in pod_proof["pods"]
    }
    observed: dict[str, dict[str, Any]] = {}
    observed_families: set[tuple[str, str]] = set()
    observed_addresses: set[str] = set()
    slice_uids: list[str] = []
    address_types: set[str] = set()
    for item in value:
        require(isinstance(item, dict) and item.get("apiVersion") == "discovery.k8s.io/v1" and item.get("kind") == "EndpointSlice", "workbench EndpointSlice identity drift", PostconditionFailure)
        metadata = _metadata(item, "workbench EndpointSlice")
        require(
            metadata.get("namespace") == WORKBENCH_NAMESPACE
            and metadata.get("labels", {}).get(ENDPOINT_SLICE_LABEL) == SERVICE_NAME,
            "workbench EndpointSlice Service binding drift",
            PostconditionFailure,
        )
        slice_uid = _validate_uuid(metadata.get("uid"), "workbench EndpointSlice")
        require(slice_uid not in slice_uids, "workbench EndpointSlice UID duplicated", PostconditionFailure)
        slice_uids.append(slice_uid)
        address_type = item.get("addressType")
        require(address_type in {"IPv4", "IPv6"}, "workbench EndpointSlice addressType drift", PostconditionFailure)
        address_types.add(address_type)
        ports = item.get("ports")
        require(
            isinstance(ports, list)
            and len(ports) == 1
            and ports[0].get("name") == WORKBENCH_SERVICE_PORT_NAME
            and ports[0].get("port") == WORKBENCH_SERVICE_PORT
            and ports[0].get("protocol", "TCP") == "TCP",
            "workbench EndpointSlice port drift",
            PostconditionFailure,
        )
        endpoints = item.get("endpoints")
        require(isinstance(endpoints, list) and endpoints, "workbench EndpointSlice endpoints absent", PostconditionFailure)
        for endpoint in endpoints:
            target = endpoint.get("targetRef") if isinstance(endpoint, dict) else None
            require(
                isinstance(target, dict)
                and target.get("apiVersion", "v1") == "v1"
                and target.get("kind") == "Pod"
                and target.get("namespace") == WORKBENCH_NAMESPACE
                and endpoint.get("conditions", {}).get("ready") is True,
                "workbench EndpointSlice target drift",
                PostconditionFailure,
            )
            uid = _validate_uuid(target.get("uid"), "workbench EndpointSlice Pod target")
            name = target.get("name")
            require(uid in expected and expected[uid]["name"] == name, "workbench EndpointSlice backend Pod UID drift", PostconditionFailure)
            addresses = endpoint.get("addresses")
            require(
                isinstance(addresses, list)
                and addresses
                and len(addresses) == len(set(addresses))
                and all(isinstance(address, str) for address in addresses),
                "workbench EndpointSlice addresses invalid",
                PostconditionFailure,
            )
            family_addresses: set[str] = set()
            for address in addresses:
                try:
                    parsed = ipaddress.ip_address(address)
                except ValueError as exc:
                    raise PostconditionFailure("workbench EndpointSlice address invalid") from exc
                require(str(parsed) == address, "workbench EndpointSlice address is not canonical", PostconditionFailure)
                require((parsed.version == 4) == (address_type == "IPv4"), "workbench EndpointSlice address family drift", PostconditionFailure)
                require(address not in observed_addresses, "workbench EndpointSlice address duplicated", PostconditionFailure)
                family_addresses.add(address); observed_addresses.add(address)
            expected_family = {
                address for address in expected[uid]["addresses"]
                if (ipaddress.ip_address(address).version == 4) == (address_type == "IPv4")
            }
            require(
                expected_family
                and family_addresses == expected_family
                and (uid, address_type) not in observed_families,
                "workbench EndpointSlice backend Pod address drift",
                PostconditionFailure,
            )
            observed_families.add((uid, address_type))
            observed.setdefault(uid, {"name": name, "addresses": set()})["addresses"].update(family_addresses)
    require(
        set(observed) == set(expected)
        and all(observed[uid]["name"] == expected[uid]["name"] and observed[uid]["addresses"] == expected[uid]["addresses"] for uid in expected),
        "workbench EndpointSlice backend set drift",
        PostconditionFailure,
    )
    return {
        "endpointSliceUids": sorted(slice_uids),
        "addressTypes": sorted(address_types),
        "podTargets": [
            {"uid": uid, "name": observed[uid]["name"], "addresses": sorted(observed[uid]["addresses"])}
            for uid in sorted(observed)
        ],
    }


def _pod_ready_image_proof(pods: Any, expected_image: str, replicas: int, label: str) -> dict[str, Any]:
    require(isinstance(pods, list), f"{label} pod list invalid")
    require(len(pods) == replicas, f"{label} pod replica count drift")
    expected_digest = expected_image.rsplit("@", 1)[1]
    result: list[dict[str, Any]] = []
    for pod in pods:
        require(isinstance(pod, dict), f"{label} pod entry invalid")
        pod_meta = _metadata(pod, f"{label} pod")
        require(pod.get("apiVersion") == "v1" and pod.get("kind") == "Pod", f"{label} pod identity invalid")
        require(pod_meta.get("namespace") == WORKBENCH_NAMESPACE, f"{label} pod namespace drift")
        pod_name = pod_meta.get("name")
        require(isinstance(pod_name, str) and pod_name, f"{label} pod name invalid")
        pod_uid = _validate_uuid(pod_meta.get("uid"), f"{label} pod")
        status = pod.get("status")
        require(isinstance(status, dict), f"{label} pod status absent")
        pod_ip = status.get("podIP")
        pod_ips = status.get("podIPs")
        require(
            isinstance(pod_ip, str)
            and isinstance(pod_ips, list)
            and pod_ips
            and all(isinstance(item, dict) and set(item) == {"ip"} and isinstance(item["ip"], str) for item in pod_ips),
            f"{label} pod IP status invalid",
        )
        addresses = [item["ip"] for item in pod_ips]
        require(addresses[0] == pod_ip and len(addresses) == len(set(addresses)), f"{label} pod IP set drift")
        try:
            parsed_addresses = [ipaddress.ip_address(address) for address in addresses]
        except ValueError as exc:
            raise PostconditionFailure(f"{label} pod IP invalid") from exc
        require(all(str(parsed) == address for parsed, address in zip(parsed_addresses, addresses)), f"{label} pod IP is not canonical")
        statuses = status.get("containerStatuses")
        require(isinstance(statuses, list), f"{label} pod container statuses absent")
        matches = [item for item in statuses if isinstance(item, dict) and item.get("name") == WORKBENCH_CONTAINER_NAME]
        require(len(matches) == 1, f"{label} pod workbench container status absent")
        container_status = matches[0]
        require(container_status.get("ready") is True, f"{label} pod is not ready")
        image_id = container_status.get("imageID")
        require(isinstance(image_id, str) and image_id.endswith("@" + expected_digest), f"{label} pod imageID drift")
        result.append({"name": pod_name, "uid": pod_uid, "imageId": image_id, "ready": True, "podIPs": addresses})
    return {"expectedImage": expected_image, "readyPodCount": len(result), "pods": sorted(result, key=lambda item: str(item["name"]))}


def _closed_object(value: Any, keys: frozenset[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object", PostconditionFailure)
    require(frozenset(value) == keys, f"{label} key set drift", PostconditionFailure)
    return value


def _nonnegative_integer(value: Any, label: str) -> int:
    require(isinstance(value, int) and not isinstance(value, bool) and value >= 0, f"{label} must be a non-negative integer", PostconditionFailure)
    return value


def _nonempty_string(value: Any, label: str) -> str:
    require(isinstance(value, str) and bool(value) and value == value.strip(), f"{label} must be a non-empty string", PostconditionFailure)
    return value


def _optional_nonempty_string(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _nonempty_string(value, label)


def _reject_provenance_markers(value: Any, path: str = "$") -> None:
    """Reject fixture/demo provenance instead of trusting a single boolean."""
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if normalized == "synthetic":
                require(child is False, f"{path}.{key} synthetic marker is not false", PostconditionFailure)
            else:
                require(
                    normalized not in {"fixture", "fixtureid", "demodata", "seed", "seeded", "issynthetic", "testfixture", "sourcefixture"},
                    f"{path}.{key} contains fixture/demo provenance",
                    PostconditionFailure,
                )
            _reject_provenance_markers(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_provenance_markers(child, f"{path}[{index}]")
    elif isinstance(value, str):
        require(value.strip().lower() not in FORBIDDEN_PROVENANCE_VALUES, f"{path} contains fixture/demo provenance", PostconditionFailure)


def _validate_author(value: Any, label: str) -> None:
    author = _closed_object(value, AUTHOR_KEYS, label)
    _nonempty_string(author["name"], f"{label} name")
    require(author["kind"] in {"citizen", "mecky"}, f"{label} kind invalid", PostconditionFailure)
    require(isinstance(author["pubkey"], str) and re.fullmatch(r"[0-9a-f]{64}", author["pubkey"]) is not None, f"{label} pubkey invalid", PostconditionFailure)
    require(author["synthetic"] is False, f"{label} synthetic provenance present", PostconditionFailure)


def _validate_event(value: Any, label: str) -> None:
    event = _closed_object(value, NOSTR_EVENT_KEYS, label)
    require(isinstance(event["id"], str) and re.fullmatch(r"[0-9a-f]{64}", event["id"]) is not None, f"{label} id invalid", PostconditionFailure)
    require(isinstance(event["pubkey"], str) and re.fullmatch(r"[0-9a-f]{64}", event["pubkey"]) is not None, f"{label} pubkey invalid", PostconditionFailure)
    _nonnegative_integer(event["created_at"], f"{label} created_at")
    _nonnegative_integer(event["kind"], f"{label} kind")
    _nonempty_string(event["content"], f"{label} content")
    require(isinstance(event["sig"], str) and re.fullmatch(r"[0-9a-f]{128}", event["sig"]) is not None, f"{label} signature invalid", PostconditionFailure)
    tags = event["tags"]
    require(isinstance(tags, list), f"{label} tags invalid", PostconditionFailure)
    for index, tag in enumerate(tags):
        require(isinstance(tag, list) and all(isinstance(item, str) for item in tag), f"{label} tag {index} invalid", PostconditionFailure)
        _reject_provenance_markers(tag, f"{label}.tags[{index}]")


def _validate_case_binding(value: Any, label: str) -> None:
    if value is None:
        return
    binding = _closed_object(value, CASE_BINDING_KEYS, label)
    for key, child in binding.items():
        _nonempty_string(child, f"{label}.{key}")


def _validate_conversation(value: Any, label: str) -> None:
    if value is None:
        return
    conversation = _closed_object(value, CONVERSATION_KEYS, label)
    _nonempty_string(conversation["sourceAppPostId"], f"{label}.sourceAppPostId")
    _optional_nonempty_string(conversation["sourceAppCommentId"], f"{label}.sourceAppCommentId")
    for key in ("mentionId", "replyId"):
        require(isinstance(conversation[key], str) and re.fullmatch(r"[0-9a-f]{64}", conversation[key]) is not None, f"{label}.{key} invalid", PostconditionFailure)
    require(isinstance(conversation["receiptId"], str) and re.fullmatch(r"urn:stadtstack:mecky-answer:[0-9a-f]{64}", conversation["receiptId"]) is not None, f"{label}.receiptId invalid", PostconditionFailure)
    _validate_author(conversation["mentionAuthor"], f"{label}.mentionAuthor")
    refs = conversation["evidenceRefs"]
    require(isinstance(refs, list) and 1 <= len(refs) <= 3, f"{label}.evidenceRefs invalid", PostconditionFailure)
    for index, reference in enumerate(refs):
        ref = _closed_object(reference, EVIDENCE_REF_KEYS, f"{label}.evidenceRefs[{index}]")
        require(isinstance(ref["digest"], str) and SHA256_RE.fullmatch(ref["digest"]) is not None, f"{label}.evidenceRefs[{index}] digest invalid", PostconditionFailure)
        parsed = urllib.parse.urlsplit(ref["url"]) if isinstance(ref["url"], str) else None
        require(parsed is not None and parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password, f"{label}.evidenceRefs[{index}] URL invalid", PostconditionFailure)


def _validate_common_feed_record(value: dict[str, Any], label: str) -> None:
    require(isinstance(value["id"], str) and re.fullmatch(r"[0-9a-f]{64}", value["id"]) is not None, f"{label} id invalid", PostconditionFailure)
    _validate_author(value["author"], f"{label}.author")
    _nonempty_string(value["content"], f"{label}.content")
    _nonempty_string(value["createdAt"], f"{label}.createdAt")
    _nonnegative_integer(value["replyCount"], f"{label}.replyCount")
    for key in ("meckyMentioned", "meckyAnswered", "synthetic"):
        require(value[key] is False, f"{label}.{key} synthetic/public marker drift", PostconditionFailure)


def _validate_feed_post(value: Any, index: int) -> None:
    require(isinstance(value, dict), f"workbench feed post {index} invalid", PostconditionFailure)
    entry_type = value.get("entryType")
    label = f"workbench feed post {index}"
    if entry_type == "post":
        post = _closed_object(value, ORDINARY_POST_KEYS, label)
        _validate_common_feed_record(post, label)
        _validate_event(post["event"], f"{label}.event")
        for key in ("promotedDiscussionId", "promotedTopicId", "sourceAppPostId"):
            _optional_nonempty_string(post[key], f"{label}.{key}")
        return
    require(entry_type == "topic", f"{label} entryType invalid", PostconditionFailure)
    topic = _closed_object(value, TOPIC_POST_KEYS, label)
    _validate_common_feed_record(topic, label)
    _validate_case_binding(topic["caseBinding"], f"{label}.caseBinding")
    _validate_conversation(topic["sourceConversation"], f"{label}.sourceConversation")
    _nonempty_string(topic["topicId"], f"{label}.topicId")
    _nonempty_string(topic["topicTitle"], f"{label}.topicTitle")
    _nonempty_string(topic["lastActivityAt"], f"{label}.lastActivityAt")
    _nonnegative_integer(topic["discussionCount"], f"{label}.discussionCount")
    _nonnegative_integer(topic["activityCount"], f"{label}.activityCount")
    require(topic["suggestionSigned"] is False or topic["suggestionSigned"] is True, f"{label}.suggestionSigned invalid", PostconditionFailure)
    discussion_ids = topic["discussionIds"]
    require(isinstance(discussion_ids, list) and all(isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item) is not None for item in discussion_ids), f"{label}.discussionIds invalid", PostconditionFailure)
    require(len(set(discussion_ids)) == len(discussion_ids), f"{label}.discussionIds duplicated", PostconditionFailure)
    discussions = topic["discussions"]
    require(isinstance(discussions, list) and len(discussions) == topic["discussionCount"], f"{label}.discussions/count drift", PostconditionFailure)
    for discussion_index, discussion_value in enumerate(discussions):
        discussion = _closed_object(discussion_value, TOPIC_DISCUSSION_KEYS, f"{label}.discussions[{discussion_index}]")
        _validate_common_feed_record(discussion, f"{label}.discussions[{discussion_index}]")
        _validate_case_binding(discussion["caseBinding"], f"{label}.discussions[{discussion_index}].caseBinding")
        _validate_conversation(discussion["sourceConversation"], f"{label}.discussions[{discussion_index}].sourceConversation")
        require(discussion["suggestionSigned"] is False or discussion["suggestionSigned"] is True, f"{label}.discussions[{discussion_index}].suggestionSigned invalid", PostconditionFailure)
    source_ids = topic["sourcePostIds"]
    require(isinstance(source_ids, list) and all(isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item) is not None for item in source_ids), f"{label}.sourcePostIds invalid", PostconditionFailure)
    require(len(set(source_ids)) == len(source_ids), f"{label}.sourcePostIds duplicated", PostconditionFailure)


def validate_config_probe(value: Any) -> dict[str, Any]:
    _reject_secret_shaped(value)
    _reject_provenance_markers(value)
    config = _closed_object(value, CONFIG_KEYS, "workbench config probe")
    require(config.get("schemaVersion") == PUBLIC_CONFIG_SCHEMA, "workbench config probe schema drift", PostconditionFailure)
    require(config.get("mode") == "public-signed-only", "workbench config probe mode drift", PostconditionFailure)
    require(config.get("authorityBinding") == "none", "workbench config probe authority drift", PostconditionFailure)
    personas = config.get("personas")
    require(personas == [], "workbench config probe contains synthetic personas", PostconditionFailure)
    mecky_pubkey = config.get("meckyPubkey")
    require(isinstance(mecky_pubkey, str) and re.fullmatch(r"[0-9a-f]{64}", mecky_pubkey) is not None, "workbench config probe identity invalid", PostconditionFailure)
    return {
        "schemaVersion": PUBLIC_CONFIG_SCHEMA,
        "mode": "public-signed-only",
        "authorityBinding": "none",
        "personas": [],
        "meckyPubkeyPresent": True,
    }


def validate_feed_probe(value: Any) -> dict[str, Any]:
    _reject_secret_shaped(value)
    _reject_provenance_markers(value)
    feed = _closed_object(value, FEED_KEYS, "workbench feed probe")
    require(feed.get("schemaVersion") == PUBLIC_FEED_SCHEMA, "workbench feed probe schema drift", PostconditionFailure)
    require(feed.get("authorityBinding") == "none", "workbench feed probe authority drift", PostconditionFailure)
    posts = feed.get("posts")
    require(isinstance(posts, list), "workbench feed probe posts invalid", PostconditionFailure)
    for index, post in enumerate(posts):
        _validate_feed_post(post, index)
    return {
        "schemaVersion": PUBLIC_FEED_SCHEMA,
        "authorityBinding": "none",
        "postCount": len(posts),
        "syntheticRecords": False,
    }


def _probe(kube: Any, path: str) -> Any:
    try:
        result = kube.probe_get(path)
    except PromotionError:
        raise
    except Exception as error:
        raise TransportUncertain(f"GET probe failed for {path}: {_bounded_error(error)}") from error
    if isinstance(result, tuple) and len(result) == 2:
        status, payload = result
        require(status == 200, f"GET probe {path} returned HTTP {status}", PostconditionFailure)
        result = payload
    return result


def validate_rollout_deployment(value: dict[str, Any], expected_image: str, replicas: int, index: int) -> dict[str, Any]:
    validated = validate_workbench_deployment(value, expected_image=expected_image, label="post-rollout workbench Deployment")
    require(validated["replicas"] == replicas, "post-rollout replica policy drift", PostconditionFailure)
    status = value.get("status")
    require(isinstance(status, dict), "post-rollout Deployment status absent", PostconditionFailure)
    for key in ("readyReplicas", "updatedReplicas", "availableReplicas"):
        require(status.get(key) == replicas, f"post-rollout {key} drift", PostconditionFailure)
    require(status.get("observedGeneration") == value.get("metadata", {}).get("generation"), "post-rollout generation not observed", PostconditionFailure)
    return validated


def _classify_patch_state(value: Any, before: dict[str, Any], *, target_image: str) -> str:
    """Classify one lost PATCH response without attempting a second mutation."""
    if value is None:
        return "absent"
    try:
        before_index = container_index(before)
        current = validate_workbench_deployment(value, expected_image=target_image, label="uncertain patch classification")
        if current["uid"] == WORKBENCH_DEPLOYMENT_UID and spec_equal_except_image(before, value, index=before_index):
            return "applied"
    except Exception:
        pass
    if target_image != OLD_IMAGE:
        try:
            current = validate_workbench_deployment(value, expected_image=OLD_IMAGE, label="uncertain patch classification")
            if current["uid"] == WORKBENCH_DEPLOYMENT_UID and spec_equal_except_image(before, value, index=container_index(before)):
                return "not-applied"
        except Exception:
            pass
    return "ambiguous"


def _classify_rollback_state(value: Any, before: dict[str, Any]) -> str:
    """Classify one lost rollback response; never infer success by name."""
    if value is None:
        return "absent"
    try:
        current = validate_workbench_deployment(value, expected_image=OLD_IMAGE, label="uncertain rollback classification")
        if (
            current["uid"] == WORKBENCH_DEPLOYMENT_UID
            and spec_digest(value) == spec_digest(before)
        ):
            return "rolled-back"
    except Exception:
        pass
    return "ambiguous"


def _failure_code(error: Exception) -> str:
    text = str(error).lower()
    if "probe" in text:
        return "functional_probe_failed"
    if "rollout" in text or "ready" in text or "imageid" in text:
        return "rollout_or_image_proof_failed"
    if "service" in text or "networkpolicy" in text or "preserv" in text:
        return "preservation_proof_failed"
    if "resourceversion" in text or "cas" in text:
        return "cas_failed"
    return "postcondition_failed"


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def validate_protected_binding(revision: Any, hashes: Any) -> tuple[str, dict[str, str]]:
    require(isinstance(revision, str) and REVISION_RE.fullmatch(revision) is not None, "protected revision invalid")
    require(
        isinstance(hashes, dict)
        and set(hashes) == set(PROTECTED_PATHS)
        and all(isinstance(value, str) and SHA256_RE.fullmatch(value) is not None for value in hashes.values()),
        "protected Git blob closure drift",
    )
    return revision, dict(sorted(hashes.items()))


def _event(state: dict[str, Any], operation: str, stage: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    events = state.setdefault("events", [])
    previous = events[-1].get("entrySha256") if events else None
    value: dict[str, Any] = {
        "sequence": len(events) + 1,
        "operation": operation,
        "stage": stage,
        "previousEntrySha256": previous,
    }
    if details:
        value.update(copy.deepcopy(details))
    value["entrySha256"] = digest(value)
    events.append(value)
    return value


def _initial_journal(pin: dict[str, Any], operation_id: str, protected_revision: str, protected_hashes: dict[str, str]) -> dict[str, Any]:
    return {
        "schemaVersion": JOURNAL_SCHEMA,
        "status": "preflight",
        "operationId": operation_id,
        "protectedRevision": protected_revision,
        "protectedGitBlobSha256": copy.deepcopy(protected_hashes),
        "artifact": {
            "receiptSha256": pin["receiptSha256"],
            "sourceRevision": pin["sourceRevision"],
            "component": pin["component"],
            "manifestDigest": pin["manifestDigest"],
            "image": pin["image"],
        },
        "target": copy.deepcopy(DEPLOYMENT_TARGET),
        "events": [],
    }


def _journal_commit(journal: Any, state: dict[str, Any], operation: str, stage: str, details: dict[str, Any] | None = None) -> None:
    _event(state, operation, stage, details)
    journal.commit(state)


def _receipt_base(
    pin: dict[str, Any],
    operation_id: str,
    *,
    mode: str,
    protected_revision: str,
    protected_hashes: dict[str, str],
) -> dict[str, Any]:
    return {
        "schemaVersion": RECEIPT_SCHEMA,
        "status": "reserved",
        "mode": mode,
        "operation": {"operationId": operation_id},
        "protectedRevision": protected_revision,
        "protectedGitBlobSha256": copy.deepcopy(protected_hashes),
        # Bind every functional proof to the exact public staging origin. The
        # destination is protected source, never caller input; backend identity
        # remains a separate Pod/Service/EndpointSlice postcondition.
        "probeBinding": {
            "kind": "fixed-public-https-origin",
            "transport": "python-stdlib-direct-https",
            "origin": WORKBENCH_PUBLIC_ORIGIN,
            "hostname": WORKBENCH_PUBLIC_HOSTNAME,
            "port": WORKBENCH_PUBLIC_PORT,
            "method": "GET",
            "expectedStatus": 200,
            "tlsVerification": "default-ca-and-hostname",
            "environmentProxyUse": False,
            "redirectsFollowed": False,
            "timeoutSeconds": WORKBENCH_PROBE_TIMEOUT_SECONDS,
            "maxBodyBytes": WORKBENCH_PROBE_MAX_BODY_BYTES,
            "allowedPaths": list(WORKBENCH_PROBE_PATHS),
            "bindingSha256": WORKBENCH_PROBE_BINDING_SHA256,
        },
        "artifact": {
            "receiptSha256": pin["receiptSha256"],
            "sourceRevision": pin["sourceRevision"],
            "component": pin["component"],
            "manifestDigest": pin["manifestDigest"],
            "image": pin["image"],
        },
        "target": copy.deepcopy(DEPLOYMENT_TARGET),
        "deployment": {
            "uid": WORKBENCH_DEPLOYMENT_UID,
            "container": WORKBENCH_CONTAINER_NAME,
            "oldImage": OLD_IMAGE,
            "targetImage": TARGET_IMAGE,
            "environmentTransition": {
                "added": {"name": WORKBENCH_MODE_ENV_NAME, "value": WORKBENCH_MODE_ENV_VALUE},
                "removedNames": list(FORBIDDEN_PUBLIC_MODE_ENV_NAMES),
            },
            "beforeResourceVersion": None,
            "afterResourceVersion": None,
            "beforeSpecSha256": None,
            "beforeNormalizedSpecSha256": None,
            "afterSpecSha256": None,
            "afterNormalizedSpecSha256": None,
        },
        "preservation": {
            "service": None,
            "networkPolicy": None,
            "unchanged": False,
        },
        "rollout": None,
        "backendBinding": None,
        "probes": None,
        "patch": {"requestSha256": None, "rollbackRequestSha256": None},
        "rollback": None,
        "effects": {
            "clusterMutation": False,
            "deploymentImageChanged": False,
            "rollbackApplied": False,
            "serviceChanged": False,
            "networkPolicyChanged": False,
            "secretValuesRead": False,
            "civicAuthorityEffects": False,
        },
    }


def _commit_receipt(receipt_sink: Any, receipt: dict[str, Any]) -> None:
    _reject_secret_shaped(receipt)
    receipt_sink.commit(receipt)


class MemoryJournal:
    """Deterministic journal sink for tests and injected callers."""

    def __init__(self) -> None:
        self.state: dict[str, Any] | None = None
        self.commits: list[dict[str, Any]] = []

    def load(self) -> dict[str, Any] | None:
        return copy.deepcopy(self.state)

    def commit(self, value: dict[str, Any]) -> None:
        _reject_secret_shaped(value)
        self.state = copy.deepcopy(value)
        self.commits.append(copy.deepcopy(value))


class MemoryReceipt:
    """Deterministic immutable receipt sink for tests."""

    def __init__(self) -> None:
        self.value: dict[str, Any] | None = None

    def commit(self, value: dict[str, Any]) -> None:
        require(self.value is None, "receipt is immutable")
        _reject_secret_shaped(value)
        final = copy.deepcopy(value)
        final["canonicalSha256"] = digest(value)
        self.value = final


def _ensure_private_parent(path: Path, label: str) -> Path:
    # Refuse symlink traversal for both the destination and every existing
    # parent component.  A realpath-only check would silently follow a
    # pre-existing link before the owner-only checks below.
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        candidate = current / component
        try:
            info = os.lstat(candidate)
        except FileNotFoundError:
            current = candidate
            continue
        require(not stat.S_ISLNK(info.st_mode), f"{label} path contains symlink: {candidate}")
        current = candidate
    resolved = absolute
    parent = resolved.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = os.lstat(parent)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) & 0o077 == 0, f"{label} parent is not private")
    return resolved


class JsonJournal:
    """Owner-only, fsynced, checksum-bound atomic journal."""

    MAX_BYTES = 1024 * 1024

    def __init__(self, path: Path) -> None:
        self.path = _ensure_private_parent(Path(path), "journal")
        if self.path.exists() or self.path.is_symlink():
            info = os.lstat(self.path)
            require(
                stat.S_ISREG(info.st_mode)
                and not self.path.is_symlink()
                and info.st_uid == os.geteuid()
                and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600
                and 0 < info.st_size <= self.MAX_BYTES,
                "existing journal must be a bounded private owned file",
            )
            return
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.path, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
        self._fsync_parent()

    def load(self) -> dict[str, Any] | None:
        info = os.lstat(self.path)
        require(
            stat.S_ISREG(info.st_mode)
            and not self.path.is_symlink()
            and info.st_uid == os.geteuid()
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_size <= self.MAX_BYTES,
            "journal identity changed",
        )
        if info.st_size == 0:
            return None
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.path, flags)
        try:
            opened = os.fstat(fd)
            raw = os.pread(fd, opened.st_size + 1, 0)
            after = os.fstat(fd)
        finally:
            os.close(fd)
        require(
            len(raw) == opened.st_size
            and (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            "journal changed while loading",
        )
        value = parse_object(raw, "promotion journal")
        checksum = value.pop("journalSha256", None)
        require(isinstance(checksum, str) and checksum == digest(value), "promotion journal checksum drift")
        return value

    def _fsync_parent(self) -> None:
        fd = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def commit(self, value: dict[str, Any]) -> None:
        _reject_secret_shaped(value)
        final = copy.deepcopy(value)
        final["journalSha256"] = digest(value)
        encoded = (canonical(final) + "\n").encode("utf-8")
        require(len(encoded) <= self.MAX_BYTES, "journal exceeds bound")
        current = os.lstat(self.path)
        require(stat.S_ISREG(current.st_mode) and stat.S_IMODE(current.st_mode) == 0o600, "journal identity changed")
        fd, name = tempfile.mkstemp(prefix=".workbench-promotion-journal-", dir=self.path.parent)
        temporary = Path(name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                fd = -1
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600, follow_symlinks=False)
            self._fsync_parent()
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


class JsonReceipt:
    """Owner-only, fsynced immutable canonical receipt sink."""

    MAX_BYTES = 1024 * 1024

    def __init__(self, path: Path, *, allow_existing_empty: bool = False) -> None:
        self.path = _ensure_private_parent(Path(path), "receipt")
        if self.path.exists() or self.path.is_symlink():
            info = os.lstat(self.path)
            require(
                allow_existing_empty
                and stat.S_ISREG(info.st_mode)
                and not self.path.is_symlink()
                and info.st_uid == os.geteuid()
                and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_size == 0,
                "existing receipt is not the exact empty restart reservation",
            )
        else:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(self.path, flags, 0o600)
            try:
                os.fchmod(fd, 0o600)
                os.fsync(fd)
            finally:
                os.close(fd)
            fd = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        self.value: dict[str, Any] | None = None

    def commit(self, value: dict[str, Any]) -> None:
        require(self.value is None, "receipt is immutable")
        _reject_secret_shaped(value)
        final = copy.deepcopy(value)
        final["canonicalSha256"] = digest(value)
        encoded = (canonical(final) + "\n").encode("utf-8")
        require(len(encoded) <= self.MAX_BYTES, "receipt exceeds bound")
        fd, name = tempfile.mkstemp(prefix=".workbench-promotion-receipt-", dir=self.path.parent)
        temporary = Path(name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                fd = -1
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600, follow_symlinks=False)
            parent_fd = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            self.value = final
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


class KubernetesAdapter:
    """Exact kubectl transport; GETs are bounded, mutations are never retried."""

    def __init__(self, kubeconfig: str, *, kubectl: Path = KUBECTL_BIN) -> None:
        selected = Path(kubeconfig).absolute()
        info = os.lstat(selected)
        require(stat.S_ISREG(info.st_mode) and not selected.is_symlink(), "kubeconfig must be a regular file")
        require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) & 0o077 == 0, "kubeconfig must be owner-only")
        executable = os.lstat(kubectl)
        require(stat.S_ISREG(executable.st_mode) and not kubectl.is_symlink() and os.access(kubectl, os.X_OK), "kubectl executable invalid")
        require(bytes_digest(kubectl.read_bytes()) == KUBECTL_SHA256, "kubectl executable digest drift")
        self.kubeconfig = str(selected)
        self.kubectl = Path(kubectl)

    def _run(
        self,
        args: list[str],
        *,
        input_text: str | None = None,
        timeout: float = KUBECTL_PROCESS_TIMEOUT_SECONDS,
        request_timeout_seconds: int = KUBECTL_REQUEST_TIMEOUT_SECONDS,
    ) -> subprocess.CompletedProcess[str]:
        require(
            isinstance(request_timeout_seconds, int)
            and not isinstance(request_timeout_seconds, bool)
            and request_timeout_seconds > 0
            and request_timeout_seconds < timeout,
            "kubectl request timeout must be positive and shorter than its process bound",
        )
        environment = {
            key: value
            for key, value in os.environ.items()
            if key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy", "kubeconfig", "pythonpath"}
        }
        environment.update({"NO_PROXY": "*", "no_proxy": "*"})
        return subprocess.run(
            [
                str(self.kubectl),
                "--kubeconfig",
                self.kubeconfig,
                f"--request-timeout={request_timeout_seconds}s",
                *args,
            ],
            env=environment,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )

    @staticmethod
    def _kind(value: dict[str, str]) -> str:
        return {
            "Deployment": "deployment",
            "Service": "service",
            "NetworkPolicy": "networkpolicy",
        }.get(value["kind"], value["kind"].lower())

    def get(self, target: dict[str, str]) -> dict[str, Any] | None:
        allowed = {canonical(DEPLOYMENT_TARGET), canonical(SERVICE_TARGET), canonical(NETWORK_POLICY_TARGET)}
        require(canonical(target) in allowed, "GET target outside workbench promotion scope")
        result = self._run(["-n", target["namespace"], "get", self._kind(target), target["name"], "-o", "json"])
        if result.returncode != 0:
            lowered = (result.stderr + "\n" + result.stdout).lower()
            if "notfound" in lowered or "not found" in lowered or re.search(r"\b404\b", lowered):
                return None
            raise TransportUncertain(f"GET {target['kind']}/{target['name']} failed: {_bounded_error(result.stderr)}")
        return parse_object(result.stdout, f"GET {target['kind']}/{target['name']}")

    def get_pods(self, namespace: str, selector: dict[str, str]) -> list[dict[str, Any]]:
        require(namespace == WORKBENCH_NAMESPACE, "pod GET namespace outside workbench scope")
        require(selector and all(isinstance(k, str) and isinstance(v, str) for k, v in selector.items()), "pod selector invalid")
        selector_text = ",".join(f"{key}={value}" for key, value in sorted(selector.items()))
        result = self._run(["-n", namespace, "get", "pods", "-l", selector_text, "-o", "json"])
        if result.returncode != 0:
            raise TransportUncertain(f"GET workbench pods failed: {_bounded_error(result.stderr)}")
        value = parse_object(result.stdout, "GET workbench pods")
        items = value.get("items")
        require(isinstance(items, list), "GET workbench pods items invalid")
        return items

    def get_endpoint_slices(self, namespace: str, service_name: str) -> list[dict[str, Any]]:
        require(namespace == WORKBENCH_NAMESPACE and service_name == SERVICE_NAME, "EndpointSlice GET outside workbench Service scope")
        result = self._run([
            "-n", namespace, "get", "endpointslices",
            "-l", f"{ENDPOINT_SLICE_LABEL}={SERVICE_NAME}", "-o", "json",
        ])
        if result.returncode != 0:
            raise TransportUncertain(f"GET workbench EndpointSlices failed: {_bounded_error(result.stderr)}")
        value = parse_object(result.stdout, "GET workbench EndpointSlices")
        items = value.get("items")
        require(isinstance(items, list), "GET workbench EndpointSlices items invalid")
        return items

    def patch(self, target: dict[str, str], operations: list[dict[str, Any]]) -> dict[str, Any]:
        require(target == DEPLOYMENT_TARGET, "patch target outside workbench Deployment scope")
        _validate_public_mode_patch_shape(operations)
        result = self._run(
            ["-n", target["namespace"], "patch", "deployment", target["name"], "--type=json", "-p", canonical(operations), "-o", "json"],
        )
        if result.returncode != 0:
            raise TransportUncertain(f"PATCH workbench Deployment outcome uncertain: {_bounded_error(result.stderr)}")
        return parse_object(result.stdout, "PATCH workbench Deployment")

    def rollout_status(self, target: dict[str, str], timeout_seconds: int = ROLLOUT_TIMEOUT_SECONDS) -> None:
        require(target == DEPLOYMENT_TARGET, "rollout target outside workbench scope")
        require(
            isinstance(timeout_seconds, int)
            and not isinstance(timeout_seconds, bool)
            and 0 < timeout_seconds <= ROLLOUT_TIMEOUT_SECONDS,
            "rollout timeout outside protected bound",
        )
        result = self._run(
            ["-n", target["namespace"], "rollout", "status", f"deployment/{target['name']}", f"--timeout={timeout_seconds}s"],
            timeout=timeout_seconds + ROLLOUT_PROCESS_GRACE_SECONDS,
            request_timeout_seconds=timeout_seconds + ROLLOUT_REQUEST_GRACE_SECONDS,
        )
        if result.returncode != 0:
            raise PostconditionFailure(f"workbench rollout did not complete: {_bounded_error(result.stderr)}")

    def probe_get(self, path: str) -> dict[str, Any]:
        require(path in WORKBENCH_PROBE_PATHS, "probe path outside workbench promotion scope")
        context = getattr(self, "_probe_tls_context", None)
        if context is None:
            context = ssl.create_default_context()
            self._probe_tls_context = context
        require(
            context.check_hostname is True and context.verify_mode == ssl.CERT_REQUIRED,
            "functional probe TLS verification disabled",
        )
        connection: http.client.HTTPSConnection | None = None
        try:
            connection = http.client.HTTPSConnection(
                WORKBENCH_PUBLIC_HOSTNAME,
                WORKBENCH_PUBLIC_PORT,
                timeout=WORKBENCH_PROBE_TIMEOUT_SECONDS,
                context=context,
            )
            connection.request(
                "GET",
                path,
                headers={"Accept": "application/json", "Connection": "close"},
            )
            response = connection.getresponse()
            require(response.status == 200, f"GET probe {path} returned HTTP {response.status}", PostconditionFailure)
            raw = response.read(WORKBENCH_PROBE_MAX_BODY_BYTES + 1)
        except PromotionError:
            raise
        except (OSError, TimeoutError, http.client.HTTPException, ssl.SSLError) as error:
            raise TransportUncertain(f"GET probe {path} transport failed: {_bounded_error(error)}") from error
        finally:
            if connection is not None:
                connection.close()
        require(len(raw) <= WORKBENCH_PROBE_MAX_BODY_BYTES, "GET probe response exceeds bound", PostconditionFailure)
        return parse_object(raw, f"GET probe {path}")


def _get(kube: Any, target: dict[str, str], label: str) -> dict[str, Any]:
    try:
        value = kube.get(target)
    except PromotionError:
        raise
    except Exception as error:
        raise TransportUncertain(f"GET {label} failed: {_bounded_error(error)}") from error
    require(value is not None, f"GET {label} returned NotFound", PostconditionFailure)
    require(isinstance(value, dict), f"GET {label} returned invalid object", PostconditionFailure)
    return value


def _preflight(kube: Any, pin: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    deployment = _get(kube, DEPLOYMENT_TARGET, "workbench Deployment")
    service = _get(kube, SERVICE_TARGET, "workbench Service")
    network_policy = _get(kube, NETWORK_POLICY_TARGET, "workbench NetworkPolicy")
    deployment_facts = validate_workbench_deployment(deployment, expected_image=OLD_IMAGE)
    require(deployment_facts["containerName"] == WORKBENCH_CONTAINER_NAME, "workbench container name drift")
    _public_mode_source_env(deployment)
    require(pin["image"] == TARGET_IMAGE and pin["manifestDigest"] == TARGET_DIGEST, "artifact pin target drift")
    service_facts = validate_service_or_network_policy(service, SERVICE_TARGET, "workbench Service")
    policy_facts = validate_service_or_network_policy(network_policy, NETWORK_POLICY_TARGET, "workbench NetworkPolicy")
    service_routing = validate_service_routing(service, deployment_facts)
    return deployment, service, network_policy, {
        "deployment": deployment_facts,
        "service": service_facts,
        "serviceRouting": service_routing,
        "networkPolicy": policy_facts,
    }


def _record_preflight(receipt: dict[str, Any], facts: dict[str, Any]) -> None:
    deployment = facts["deployment"]
    receipt["deployment"].update({
        "beforeResourceVersion": deployment["resourceVersion"],
        "beforeSpecSha256": deployment["specSha256"],
        "beforeNormalizedSpecSha256": deployment["normalizedSpecSha256"],
    })
    receipt["preservation"]["service"] = copy.deepcopy(facts["service"])
    receipt["preservation"]["networkPolicy"] = copy.deepcopy(facts["networkPolicy"])


def _record_after(receipt: dict[str, Any], facts: dict[str, Any], *, field: str = "after") -> None:
    receipt["deployment"].update({
        "afterResourceVersion": facts["resourceVersion"],
        "afterSpecSha256": facts["specSha256"],
        "afterNormalizedSpecSha256": facts["normalizedSpecSha256"],
    })


def _verify_preservation(kube: Any, receipt: dict[str, Any]) -> None:
    service = _get(kube, SERVICE_TARGET, "post-promotion workbench Service")
    policy = _get(kube, NETWORK_POLICY_TARGET, "post-promotion workbench NetworkPolicy")
    service_facts = validate_service_or_network_policy(service, SERVICE_TARGET, "post-promotion workbench Service")
    policy_facts = validate_service_or_network_policy(policy, NETWORK_POLICY_TARGET, "post-promotion workbench NetworkPolicy")
    require(service_facts == receipt["preservation"]["service"], "workbench Service UID/spec changed", PostconditionFailure)
    require(policy_facts == receipt["preservation"]["networkPolicy"], "workbench NetworkPolicy UID/spec changed", PostconditionFailure)
    receipt["preservation"]["unchanged"] = True


def _verify_live_target(kube: Any, before: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
    index = container_index(before)
    deployment = _get(kube, DEPLOYMENT_TARGET, "post-promotion workbench Deployment")
    facts = validate_workbench_deployment(deployment, expected_image=TARGET_IMAGE, label="post-promotion workbench Deployment")
    require(spec_equal_except_image(before, deployment, index=index), "post-promotion Deployment spec changed outside image", PostconditionFailure)
    require(facts["normalizedSpecSha256"] == receipt["deployment"]["beforeNormalizedSpecSha256"], "post-promotion normalized spec digest drift", PostconditionFailure)
    _record_after(receipt, facts)
    try:
        kube.rollout_status(DEPLOYMENT_TARGET, ROLLOUT_TIMEOUT_SECONDS)
    except PromotionError:
        raise
    except Exception as error:
        raise PostconditionFailure(f"workbench rollout verification failed: {_bounded_error(error)}") from error
    rolled = _get(kube, DEPLOYMENT_TARGET, "post-rollout workbench Deployment")
    rollout_facts = validate_rollout_deployment(rolled, TARGET_IMAGE, facts["replicas"], index)
    require(spec_equal_except_image(before, rolled, index=index), "post-rollout Deployment spec changed outside image", PostconditionFailure)
    require(rollout_facts["normalizedSpecSha256"] == receipt["deployment"]["beforeNormalizedSpecSha256"], "post-rollout normalized spec digest drift", PostconditionFailure)
    pods = kube.get_pods(WORKBENCH_NAMESPACE, rollout_facts["selector"])
    pod_proof = _pod_ready_image_proof(pods, TARGET_IMAGE, facts["replicas"], "post-rollout workbench")
    service = _get(kube, SERVICE_TARGET, "post-rollout workbench Service backend")
    service_routing = validate_service_routing(service, rollout_facts)
    endpoint_proof = validate_endpoint_slices(kube.get_endpoint_slices(WORKBENCH_NAMESPACE, SERVICE_NAME), pod_proof)
    receipt["backendBinding"] = service_routing | endpoint_proof
    config = validate_config_probe(_probe(kube, PROBE_CONFIG_PATH))
    feed = validate_feed_probe(_probe(kube, PROBE_FEED_PATH))
    receipt["rollout"] = {
        "deploymentUid": rollout_facts["uid"],
        "resourceVersion": rollout_facts["resourceVersion"],
        "replicas": facts["replicas"],
        "readyReplicas": facts["replicas"],
        "podImageProof": pod_proof,
    }
    receipt["probes"] = {"config": config, "feed": feed, "methods": {"config": "GET", "feed": "GET"}}
    _verify_preservation(kube, receipt)
    return rollout_facts


def _safe_rollback(kube: Any, before: dict[str, Any], receipt: dict[str, Any], journal: Any, state: dict[str, Any]) -> tuple[str, str | None]:
    """Rollback only an observed exact target with one CAS patch."""
    defer_transaction_signals()
    current = _get(kube, DEPLOYMENT_TARGET, "rollback workbench Deployment")
    index = container_index(before)
    require(spec_equal_except_image(before, current, index=index), "rollback Deployment spec drift", PostconditionFailure)
    require(validate_workbench_deployment(current, expected_image=TARGET_IMAGE, label="rollback workbench Deployment")["uid"] == WORKBENCH_DEPLOYMENT_UID, "rollback Deployment identity drift", PostconditionFailure)
    patch = build_rollback_patch(current, before=before)
    receipt["patch"]["rollbackRequestSha256"] = digest(patch)
    _journal_commit(journal, state, "rollback-deployment-image", "intent", {"requestSha256": digest(patch), "target": copy.deepcopy(DEPLOYMENT_TARGET)})
    try:
        response = kube.patch(DEPLOYMENT_TARGET, patch)
    except Exception as error:
        try:
            classified = _classify_rollback_state(kube.get(DEPLOYMENT_TARGET), before)
        except Exception as discovery_error:
            classified = "ambiguous"
            error = TransportUncertain(f"rollback outcome unresolved: {_bounded_error(discovery_error)}")
        _journal_commit(journal, state, "rollback-deployment-image", "uncertain", {"classification": classified})
        return "rollback-incomplete", classified
    _journal_commit(journal, state, "rollback-deployment-image", "after", {"response": "accepted"})
    # The inverse JSON Patch has reached the API.  Record this effect before
    # rollout verification so an interrupted/failed rollout cannot be
    # mistaken for a mutation-free outcome.
    receipt["effects"]["rollbackApplied"] = True
    require(isinstance(response, dict), "rollback response invalid", PostconditionFailure)
    rolled = _get(kube, DEPLOYMENT_TARGET, "post-rollback workbench Deployment")
    facts = validate_workbench_deployment(rolled, expected_image=OLD_IMAGE, label="post-rollback workbench Deployment")
    require(spec_digest(rolled) == spec_digest(before), "post-rollback Deployment spec drift", PostconditionFailure)
    receipt["deployment"]["afterResourceVersion"] = facts["resourceVersion"]
    receipt["deployment"]["afterSpecSha256"] = facts["specSha256"]
    receipt["deployment"]["afterNormalizedSpecSha256"] = facts["normalizedSpecSha256"]
    try:
        kube.rollout_status(DEPLOYMENT_TARGET, ROLLOUT_TIMEOUT_SECONDS)
        pods = kube.get_pods(WORKBENCH_NAMESPACE, facts["selector"])
        receipt["rollback"] = {
            "status": "rolled-back",
            "deploymentUid": facts["uid"],
            "resourceVersion": facts["resourceVersion"],
            "podImageProof": _pod_ready_image_proof(pods, OLD_IMAGE, facts["replicas"], "post-rollback workbench"),
        }
        _verify_preservation(kube, receipt)
    except Exception as error:
        receipt["rollback"] = {"status": "rollback-verification-failed", "failureCode": _failure_code(error)}
        return "rollback-incomplete", None
    return "rolled-back", None


def _finalize(journal: Any, state: dict[str, Any], receipt_sink: Any, receipt: dict[str, Any], status: str) -> dict[str, Any]:
    """Persist the terminal outcome without hiding sink uncertainty.

    A receipt sink is an immutable boundary.  Once its commit starts, a
    raised exception cannot prove whether the bytes reached durable storage;
    the same is true for the terminal journal append.  Callers therefore
    must treat ``FinalizationError`` as a recovery state and must never feed
    it back into workload rollback logic.
    """
    receipt["status"] = status
    receipt["completedAt"] = _now()
    state["status"] = "finalizing"
    try:
        _journal_commit(journal, state, "transaction", "finalizing", {"receiptStatus": status})
    except Exception as error:
        raise FinalizationError(
            "journal-finalizing",
            receipt_may_have_committed=False,
            journal_may_have_committed=True,
            cause=error,
        ) from error
    try:
        _commit_receipt(receipt_sink, receipt)
    except Exception as error:
        # A sink may have written and then lost its response.  Never retry an
        # immutable receipt and never rollback a workload after this point.
        raise FinalizationError(
            "receipt",
            receipt_may_have_committed=True,
            journal_may_have_committed=True,
            cause=error,
        ) from error
    state["status"] = status
    try:
        _journal_commit(journal, state, "transaction", "completed", {"receiptStatus": status})
    except Exception as error:
        raise FinalizationError(
            "journal-terminal",
            receipt_may_have_committed=True,
            journal_may_have_committed=True,
            cause=error,
        ) from error
    return receipt


def _finalization_incomplete(
    journal: Any,
    state: dict[str, Any],
    result: dict[str, Any],
    error: FinalizationError,
) -> dict[str, Any]:
    """Return a value-free recovery receipt after durable persistence fails.

    This function intentionally does not call any Kubernetes method.  The
    workload outcome has already been decided; only a best-effort journal
    marker is attempted so an operator can reconcile the receipt/journal
    pair.  In particular, it never retries a receipt and never rolls back.
    """
    result["status"] = "finalization-incomplete"
    result["failure"] = {"failureCode": "finalization_failed"}
    recovery = {
        "status": "recovery-required",
        "stage": error.stage,
        "receiptMayHaveCommitted": error.receipt_may_have_committed,
        "journalMayHaveCommitted": error.journal_may_have_committed,
        "recoveryJournalRecorded": False,
    }
    result["finalization"] = recovery
    state["status"] = "finalization-incomplete"
    try:
        _journal_commit(
            journal,
            state,
            "transaction",
            "recovery-needed",
            {
                "failureStage": error.stage,
                "receiptMayHaveCommitted": error.receipt_may_have_committed,
                "journalMayHaveCommitted": error.journal_may_have_committed,
            },
        )
        recovery["recoveryJournalRecorded"] = True
    except Exception:
        # This is intentionally terminal.  We cannot make a second blind
        # persistence attempt or infer the state of a failed sink.
        pass
    return result


def _finalize_without_rollback(
    journal: Any,
    state: dict[str, Any],
    receipt_sink: Any,
    receipt: dict[str, Any],
    status: str,
) -> dict[str, Any]:
    """Finalize a workload result while keeping sink failures out of rollback."""
    try:
        return _finalize(journal, state, receipt_sink, receipt, status)
    except FinalizationError as error:
        return _finalization_incomplete(journal, state, receipt, error)


def validate_resume_journal(
    state: Any,
    pin: dict[str, Any],
    protected_revision: str,
    protected_hashes: dict[str, str],
) -> dict[str, Any]:
    """Bind one nonterminal same-path journal before recovery cluster GETs."""
    require(isinstance(state, dict), "promotion resume journal absent")
    require(
        set(state) == {
            "schemaVersion", "status", "operationId", "protectedRevision",
            "protectedGitBlobSha256", "artifact", "target", "events", "before",
        }
        and state.get("schemaVersion") == JOURNAL_SCHEMA
        and state.get("status") == "preflight"
        and state.get("protectedRevision") == protected_revision
        and state.get("protectedGitBlobSha256") == protected_hashes
        and state.get("target") == DEPLOYMENT_TARGET,
        "promotion resume journal binding drift",
    )
    operation_id = _validate_uuid(state.get("operationId"), "promotion resume operation")
    expected_artifact = {
        "receiptSha256": pin["receiptSha256"],
        "sourceRevision": pin["sourceRevision"],
        "component": pin["component"],
        "manifestDigest": pin["manifestDigest"],
        "image": pin["image"],
    }
    require(state.get("artifact") == expected_artifact, "promotion resume artifact drift")
    before = state.get("before")
    require(
        isinstance(before, dict)
        and set(before) == {"deploymentUid", "resourceVersion", "specSha256", "normalizedSpecSha256", "environment", "service", "serviceRouting", "networkPolicy"}
        and before.get("deploymentUid") == WORKBENCH_DEPLOYMENT_UID
        and isinstance(before.get("resourceVersion"), str)
        and before["resourceVersion"].isdigit()
        and all(isinstance(before.get(key), str) and SHA256_RE.fullmatch(before[key]) for key in ("specSha256", "normalizedSpecSha256"))
        and isinstance(before.get("environment"), dict)
        and set(before["environment"]) == {"containerIndex", "entries"}
        and isinstance(before["environment"].get("containerIndex"), int)
        and not isinstance(before["environment"].get("containerIndex"), bool)
        and isinstance(before["environment"].get("entries"), list)
        and isinstance(before.get("service"), dict)
        and isinstance(before.get("serviceRouting"), dict)
        and isinstance(before.get("networkPolicy"), dict),
        "promotion resume preflight binding drift",
    )
    require(before["environment"]["containerIndex"] >= 0, "promotion resume container index invalid")
    _public_mode_source_entries(before["environment"]["entries"], "promotion resume environment")
    events = state.get("events")
    require(isinstance(events, list) and events, "promotion resume journal events absent")
    previous: str | None = None
    grammar: list[tuple[str, str]] = []
    rollback_required = False
    for sequence, event in enumerate(events, start=1):
        require(isinstance(event, dict), "promotion resume event invalid")
        entry = dict(event); checksum = entry.pop("entrySha256", None)
        require(
            event.get("sequence") == sequence
            and event.get("previousEntrySha256") == previous
            and isinstance(checksum, str)
            and checksum == digest(entry),
            "promotion resume event hash drift",
        )
        previous = checksum
        operation_name, stage = event.get("operation"), event.get("stage")
        grammar.append((operation_name, stage))
        base = {"sequence", "operation", "stage", "previousEntrySha256", "entrySha256"}
        details = {key: value for key, value in event.items() if key not in base}
        if (operation_name, stage) == ("preflight", "after"):
            require(details == {"deploymentResourceVersion": before["resourceVersion"]}, "promotion resume preflight event drift")
        elif (operation_name, stage) == ("patch-deployment-image", "intent"):
            require(
                set(details) == {"requestSha256", "target"}
                and details["target"] == DEPLOYMENT_TARGET
                and isinstance(details["requestSha256"], str)
                and SHA256_RE.fullmatch(details["requestSha256"]),
                "promotion resume patch intent drift",
            )
        elif (operation_name, stage) == ("patch-deployment-image", "after"):
            require(details == {"response": "accepted"}, "promotion resume patch response drift")
        elif (operation_name, stage) in {("patch-deployment-image", "classified"), ("patch-deployment-image", "uncertain")}:
            allowed = {"applied", "not-applied", "absent", "ambiguous"} if stage == "classified" else {"ambiguous"}
            require(details.get("classification") in allowed and set(details) == {"classification"}, "promotion resume patch classification drift")
        elif (operation_name, stage) == ("resume", "before"):
            require(details == {"operationId": operation_id}, "promotion resume-before event drift")
        elif (operation_name, stage) == ("resume", "classified"):
            require(
                details.get("operationId") == operation_id
                and details.get("classification") in {"target-image", "old-image", "ambiguous"}
                and set(details) == {"operationId", "classification"},
                "promotion resume classification event drift",
            )
        elif (operation_name, stage) == ("postconditions", "after"):
            require(details == {"status": "verified"}, "promotion resume postcondition event drift")
        elif (operation_name, stage) == ("rollback-deployment-image", "intent"):
            require(
                set(details) == {"requestSha256", "target"}
                and details["target"] == DEPLOYMENT_TARGET
                and isinstance(details["requestSha256"], str)
                and SHA256_RE.fullmatch(details["requestSha256"]),
                "promotion resume rollback intent drift",
            )
            rollback_required = True
        elif (operation_name, stage) == ("rollback-deployment-image", "after"):
            require(details == {"response": "accepted"}, "promotion resume rollback response drift")
            rollback_required = True
        elif (operation_name, stage) == ("rollback-deployment-image", "uncertain"):
            require(
                details.get("classification") in {"rolled-back", "absent", "ambiguous"}
                and set(details) == {"classification"},
                "promotion resume rollback classification drift",
            )
            rollback_required = True
        else:
            raise PromotionError("promotion resume journal operation drift")
    require(
        grammar[:2] == [("preflight", "after"), ("patch-deployment-image", "intent")]
        and grammar.count(("preflight", "after")) == 1
        and grammar.count(("patch-deployment-image", "intent")) == 1
        and not any(item[0] == "transaction" for item in grammar),
        "promotion resume journal grammar drift",
    )
    patch_outcomes = [index for index, item in enumerate(grammar) if item[0] == "patch-deployment-image" and item[1] != "intent"]
    require(len(patch_outcomes) <= 1 and (not patch_outcomes or patch_outcomes[0] == 2), "promotion resume patch outcome ordering drift")
    rollback_intents = [index for index, item in enumerate(grammar) if item == ("rollback-deployment-image", "intent")]
    rollback_outcomes = [index for index, item in enumerate(grammar) if item[0] == "rollback-deployment-image" and item[1] != "intent"]
    require(
        len(rollback_intents) <= 1
        and len(rollback_outcomes) <= 1
        and (not rollback_outcomes or (rollback_intents and rollback_outcomes[0] == rollback_intents[0] + 1)),
        "promotion resume rollback ordering drift",
    )
    for index, item in enumerate(grammar):
        if item == ("resume", "classified"):
            require(index > 0 and grammar[index - 1] == ("resume", "before"), "promotion resume classification ordering drift")
    patch_intent = events[1]
    return {
        "operationId": operation_id,
        "before": copy.deepcopy(before),
        "events": copy.deepcopy(events),
        "patchRequestSha256": patch_intent["requestSha256"],
        "rollbackRequired": rollback_required,
    }


def _resume_transaction(
    *,
    kube: Any,
    pin: dict[str, Any],
    receipt: Any,
    journal: Any,
    state: dict[str, Any],
    protected_revision: str,
    protected_hashes: dict[str, str],
) -> dict[str, Any]:
    bound = validate_resume_journal(state, pin, protected_revision, protected_hashes)
    operation_id = bound["operationId"]
    before_facts = bound["before"]
    result = _receipt_base(
        pin,
        operation_id,
        mode="live",
        protected_revision=protected_revision,
        protected_hashes=protected_hashes,
    )
    result["deployment"].update({
        "beforeResourceVersion": before_facts["resourceVersion"],
        "beforeSpecSha256": before_facts["specSha256"],
        "beforeNormalizedSpecSha256": before_facts["normalizedSpecSha256"],
    })
    result["preservation"]["service"] = copy.deepcopy(before_facts["service"])
    result["preservation"]["networkPolicy"] = copy.deepcopy(before_facts["networkPolicy"])
    result["patch"]["requestSha256"] = bound["patchRequestSha256"]
    defer_transaction_signals()
    _journal_commit(journal, state, "resume", "before", {"operationId": operation_id})
    current = _get(kube, DEPLOYMENT_TARGET, "promotion resume Deployment")
    classification = "ambiguous"
    reconstructed_before: dict[str, Any] | None = None
    try:
        current_facts = validate_workbench_deployment(current, expected_image=TARGET_IMAGE, label="promotion resume Deployment")
        require(current_facts["normalizedSpecSha256"] == before_facts["normalizedSpecSha256"], "promotion resume Deployment spec drift", PostconditionFailure)
        reconstructed_before = copy.deepcopy(current)
        require(
            before_facts["environment"]["containerIndex"] == current_facts["index"],
            "promotion resume container index drift",
            PostconditionFailure,
        )
        reconstructed_before["spec"]["template"]["spec"]["containers"][current_facts["index"]]["image"] = OLD_IMAGE
        reconstructed_before["spec"]["template"]["spec"]["containers"][current_facts["index"]]["env"] = copy.deepcopy(before_facts["environment"]["entries"])
        require(spec_digest(reconstructed_before) == before_facts["specSha256"], "promotion resume before-spec reconstruction drift", PostconditionFailure)
        classification = "target-image"
    except Exception:
        try:
            old_facts = validate_workbench_deployment(current, expected_image=OLD_IMAGE, label="promotion resume Deployment")
            require(
                old_facts["normalizedSpecSha256"] == before_facts["normalizedSpecSha256"]
                and old_facts["specSha256"] == before_facts["specSha256"],
                "promotion resume old Deployment spec drift",
                PostconditionFailure,
            )
            reconstructed_before = copy.deepcopy(current)
            classification = "old-image"
        except Exception:
            classification = "ambiguous"
    _journal_commit(journal, state, "resume", "classified", {"operationId": operation_id, "classification": classification})
    if classification == "ambiguous" or reconstructed_before is None:
        result["failure"] = {"failureCode": "resume_state_ambiguous"}
        result["uncertainOutcome"] = {"classification": classification, "discovery": "single-get"}
        return _finalize_without_rollback(journal, state, receipt, result, "uncertain")
    if classification == "old-image":
        service = _get(kube, SERVICE_TARGET, "promotion resume Service")
        policy = _get(kube, NETWORK_POLICY_TARGET, "promotion resume NetworkPolicy")
        require(validate_service_or_network_policy(service, SERVICE_TARGET, "promotion resume Service") == before_facts["service"], "promotion resume Service drift", PostconditionFailure)
        require(validate_service_routing(service, old_facts) == before_facts["serviceRouting"], "promotion resume Service routing drift", PostconditionFailure)
        require(validate_service_or_network_policy(policy, NETWORK_POLICY_TARGET, "promotion resume NetworkPolicy") == before_facts["networkPolicy"], "promotion resume NetworkPolicy drift", PostconditionFailure)
        result["preservation"]["unchanged"] = True
        result["rollback"] = {"status": "already-old-image", "resourceVersion": old_facts["resourceVersion"]}
        result["failure"] = {"failureCode": "interrupted_before_or_rolled_back"}
        return _finalize_without_rollback(journal, state, receipt, result, "rolled-back")
    result["effects"]["clusterMutation"] = True
    result["effects"]["deploymentImageChanged"] = True
    if bound["rollbackRequired"]:
        result["failure"] = {"failureCode": "interrupted_during_rollback"}
        try:
            rollback_status, rollback_classification = _safe_rollback(kube, reconstructed_before, result, journal, state)
        except Exception as rollback_error:
            result["rollback"] = {"status": "rollback-incomplete", "failureCode": _failure_code(rollback_error)}
            return _finalize_without_rollback(journal, state, receipt, result, "rollback-incomplete")
        if rollback_status == "rolled-back":
            return _finalize_without_rollback(journal, state, receipt, result, "rolled-back")
        result["rollback"] = result.get("rollback") or {"status": rollback_status, "classification": rollback_classification}
        return _finalize_without_rollback(journal, state, receipt, result, "rollback-incomplete")
    try:
        _verify_live_target(kube, reconstructed_before, result)
        _journal_commit(journal, state, "postconditions", "after", {"status": "verified"})
        return _finalize_without_rollback(journal, state, receipt, result, "completed")
    except Exception as error:
        result["failure"] = {"failureCode": _failure_code(error)}
        try:
            rollback_status, rollback_classification = _safe_rollback(kube, reconstructed_before, result, journal, state)
        except Exception as rollback_error:
            result["rollback"] = {"status": "rollback-incomplete", "failureCode": _failure_code(rollback_error)}
            return _finalize_without_rollback(journal, state, receipt, result, "rollback-incomplete")
        if rollback_status == "rolled-back":
            return _finalize_without_rollback(journal, state, receipt, result, "rolled-back")
        result["rollback"] = result.get("rollback") or {"status": rollback_status, "classification": rollback_classification}
        return _finalize_without_rollback(journal, state, receipt, result, "rollback-incomplete")


def _run_transaction(
    *,
    kube: Any,
    artifact_pin: Path,
    receipt: Any,
    journal: Any,
    dry_run: bool = False,
    operation_id: str | None = None,
    artifact_receipt_sha256: str = ARTIFACT_PIN_RECEIPT_SHA256,
    source_revision: str = SOURCE_REVISION,
    protected_revision: str,
    protected_hashes: dict[str, str],
) -> dict[str, Any]:
    """Execute the bounded promotion with injectable sinks and transport."""
    pin = validate_artifact_pin(
        artifact_pin,
        expected_receipt_sha256=artifact_receipt_sha256,
        expected_source_revision=source_revision,
    )
    protected_revision, protected_hashes = validate_protected_binding(protected_revision, protected_hashes)
    existing = journal.load()
    if existing is not None:
        require(not dry_run, "promotion journal resume is live-only")
        return _resume_transaction(
            kube=kube,
            pin=pin,
            receipt=receipt,
            journal=journal,
            state=existing,
            protected_revision=protected_revision,
            protected_hashes=protected_hashes,
        )
    operation_id = operation_id or str(uuid.uuid4())
    _validate_uuid(operation_id, "promotion operation")
    state = _initial_journal(pin, operation_id, protected_revision, protected_hashes)
    journal.commit(state)  # intent exists before the first Kubernetes mutation
    result = _receipt_base(
        pin,
        operation_id,
        mode="dry-run" if dry_run else "live",
        protected_revision=protected_revision,
        protected_hashes=protected_hashes,
    )
    try:
        before, _service, _policy, facts = _preflight(kube, pin)
        _record_preflight(result, facts)
        state["before"] = {
            "deploymentUid": facts["deployment"]["uid"],
            "resourceVersion": facts["deployment"]["resourceVersion"],
            "specSha256": facts["deployment"]["specSha256"],
            "normalizedSpecSha256": facts["deployment"]["normalizedSpecSha256"],
            "environment": {
                "containerIndex": facts["deployment"]["index"],
                "entries": copy.deepcopy(_container_env(before)),
            },
            "service": facts["service"],
            "serviceRouting": facts["serviceRouting"],
            "networkPolicy": facts["networkPolicy"],
        }
        _journal_commit(journal, state, "preflight", "after", {"deploymentResourceVersion": facts["deployment"]["resourceVersion"]})
    except Exception as error:
        defer_transaction_signals()
        result["failure"] = {"failureCode": _failure_code(error)}
        result["effects"]["civicAuthorityEffects"] = False
        return _finalize_without_rollback(journal, state, receipt, result, "preflight-failed")
    if dry_run:
        defer_transaction_signals()
        result["effects"]["clusterMutation"] = False
        result["preservation"]["unchanged"] = True
        return _finalize_without_rollback(journal, state, receipt, result, "dry-run")

    patch = build_image_patch(before)
    result["patch"]["requestSha256"] = digest(patch)
    _journal_commit(journal, state, "patch-deployment-image", "intent", {"requestSha256": digest(patch), "target": copy.deepcopy(DEPLOYMENT_TARGET)})
    result["effects"]["clusterMutation"] = True
    patch_response: dict[str, Any] | None = None
    try:
        patch_response = kube.patch(DEPLOYMENT_TARGET, patch)
        _journal_commit(journal, state, "patch-deployment-image", "after", {"response": "accepted"})
    except Exception as error:
        # Once a mutation response is lost (including an operator signal),
        # reconciliation and any rollback/finalization must not be interrupted
        # by a second signal.
        defer_transaction_signals()
        interrupted = isinstance(error, PromotionInterrupted)
        # Exactly one discovery GET after a lost mutation response.  The
        # classification is recorded; no patch retry is ever attempted.
        try:
            discovered = kube.get(DEPLOYMENT_TARGET)
            classification = _classify_patch_state(discovered, before, target_image=TARGET_IMAGE)
        except Exception as discovery_error:
            classification = "ambiguous"
            discovery_error_text = _bounded_error(discovery_error)
            _journal_commit(journal, state, "patch-deployment-image", "uncertain", {"classification": classification})
            result["failure"] = {"failureCode": "mutation_outcome_unresolved"}
            result["uncertainOutcome"] = {"classification": classification, "discovery": "single-get"}
            return _finalize_without_rollback(journal, state, receipt, result, "uncertain")
        _journal_commit(journal, state, "patch-deployment-image", "classified", {"classification": classification})
        result["uncertainOutcome"] = {"classification": classification, "discovery": "single-get"}
        if classification == "applied":
            patch_response = discovered
            if interrupted:
                result["effects"]["deploymentImageChanged"] = True
                result["failure"] = {"failureCode": "operator_interrupted"}
                try:
                    rollback_status, rollback_classification = _safe_rollback(kube, before, result, journal, state)
                except Exception as rollback_error:
                    result["rollback"] = {"status": "rollback-incomplete", "failureCode": _failure_code(rollback_error)}
                    return _finalize_without_rollback(journal, state, receipt, result, "rollback-incomplete")
                if rollback_status == "rolled-back":
                    return _finalize_without_rollback(journal, state, receipt, result, "rolled-back")
                result["rollback"] = result.get("rollback") or {"status": rollback_status, "classification": rollback_classification}
                return _finalize_without_rollback(journal, state, receipt, result, "rollback-incomplete")
        elif classification == "not-applied":
            result["failure"] = {"failureCode": "operator_interrupted" if interrupted else "mutation_not_applied"}
            if interrupted:
                defer_transaction_signals()
            return _finalize_without_rollback(journal, state, receipt, result, "not-applied")
        else:
            result["failure"] = {"failureCode": "mutation_outcome_ambiguous"}
            return _finalize_without_rollback(journal, state, receipt, result, "uncertain")
    try:
        require(isinstance(patch_response, dict), "accepted patch response invalid", TransportUncertain)
        result["effects"]["deploymentImageChanged"] = True
        _verify_live_target(kube, before, result)
        defer_transaction_signals()
        _journal_commit(journal, state, "postconditions", "after", {"status": "verified"})
        return _finalize_without_rollback(journal, state, receipt, result, "completed")
    except PostconditionFailure as error:
        defer_transaction_signals()
        result["failure"] = {"failureCode": _failure_code(error)}
        try:
            rollback_status, classification = _safe_rollback(kube, before, result, journal, state)
        except Exception as rollback_error:
            # A changed spec/identity means the inverse patch cannot be
            # proven safe.  Do not guess and do not mutate a drifted object.
            result["rollback"] = {"status": "rollback-incomplete", "failureCode": _failure_code(rollback_error)}
            return _finalize_without_rollback(journal, state, receipt, result, "rollback-incomplete")
        if rollback_status == "rolled-back":
            result["effects"]["deploymentImageChanged"] = True
            return _finalize_without_rollback(journal, state, receipt, result, "rolled-back")
        result["rollback"] = result.get("rollback") or {"status": rollback_status, "classification": classification}
        return _finalize_without_rollback(journal, state, receipt, result, "rollback-incomplete")
    except TransportUncertain as error:
        defer_transaction_signals()
        result["failure"] = {"failureCode": "postcondition_outcome_unresolved"}
        result["uncertainOutcome"] = {"classification": "postcondition-unresolved", "discovery": "single-get-only-for-mutation"}
        return _finalize_without_rollback(journal, state, receipt, result, "uncertain")
    except Exception as error:
        defer_transaction_signals()
        result["failure"] = {"failureCode": _failure_code(error)}
        try:
            rollback_status, classification = _safe_rollback(kube, before, result, journal, state)
        except Exception as rollback_error:
            result["rollback"] = {"status": "rollback-incomplete", "failureCode": _failure_code(rollback_error)}
            return _finalize_without_rollback(journal, state, receipt, result, "rollback-incomplete")
        if rollback_status == "rolled-back":
            return _finalize_without_rollback(journal, state, receipt, result, "rolled-back")
        result["rollback"] = result.get("rollback") or {"status": rollback_status, "classification": classification}
        return _finalize_without_rollback(journal, state, receipt, result, "rollback-incomplete")


def run(
    *,
    kube: Any,
    artifact_pin: Path,
    receipt: Any,
    journal: Any,
    dry_run: bool = False,
    operation_id: str | None = None,
    artifact_receipt_sha256: str = ARTIFACT_PIN_RECEIPT_SHA256,
    source_revision: str = SOURCE_REVISION,
    protected_revision: str,
    protected_hashes: dict[str, str],
) -> dict[str, Any]:
    """Install transaction signal handling around the bounded promotion."""
    previous = install_transaction_signal_handlers()
    try:
        return _run_transaction(
            kube=kube,
            artifact_pin=artifact_pin,
            receipt=receipt,
            journal=journal,
            dry_run=dry_run,
            operation_id=operation_id,
            artifact_receipt_sha256=artifact_receipt_sha256,
            source_revision=source_revision,
            protected_revision=protected_revision,
            protected_hashes=protected_hashes,
        )
    finally:
        restore_transaction_signal_handlers(previous)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-pin", required=True, type=Path)
    parser.add_argument("--kubeconfig", required=False)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--journal", type=Path)
    parser.add_argument("--protected-revision", required=True)
    parser.add_argument("--protected-hashes", required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    require(args.dry_run or args.kubeconfig, "live promotion requires --kubeconfig")
    journal_path = args.journal or args.receipt.with_name(args.receipt.name + ".journal")
    require(args.receipt.absolute() != journal_path.absolute(), "promotion receipt and journal paths must be distinct")
    receipt_exists = args.receipt.exists() or args.receipt.is_symlink()
    journal_exists = journal_path.exists() or journal_path.is_symlink()
    require(receipt_exists == journal_exists, "promotion restart requires both reserved output paths")
    journal = JsonJournal(journal_path)
    protected_hashes = parse_object(args.protected_hashes, "protected Git blob hashes")
    pin = validate_artifact_pin(args.artifact_pin)
    protected_revision, protected_hashes = validate_protected_binding(args.protected_revision, protected_hashes)
    existing_journal = journal.load()
    if existing_journal is not None:
        validate_resume_journal(existing_journal, pin, protected_revision, protected_hashes)
        require(receipt_exists, "promotion restart receipt reservation absent")
    else:
        require(not receipt_exists, "pre-existing receipt requires an exact nonterminal journal")
    receipt = JsonReceipt(args.receipt, allow_existing_empty=existing_journal is not None)
    kube = None
    if args.kubeconfig:
        kube = KubernetesAdapter(args.kubeconfig)
    else:
        require(args.dry_run, "live promotion requires Kubernetes transport")
    # Dry-run still preflights a supplied cluster.  A fully effect-free
    # admission render should use the ordinary protected verifier in CI.
    require(kube is not None, "promotion preflight requires Kubernetes transport")
    result = run(
        kube=kube,
        artifact_pin=args.artifact_pin,
        receipt=receipt,
        journal=journal,
        dry_run=args.dry_run,
        protected_revision=protected_revision,
        protected_hashes=protected_hashes,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") in {"completed", "dry-run"} else 1


if __name__ == "__main__":
    if not (sys.flags.isolated and sys.flags.safe_path):
        print("workbench image promotion blocked: invoke with python3 -I", file=sys.stderr)
        raise SystemExit(2)
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (PromotionError, OSError, subprocess.SubprocessError) as error:
        print(f"workbench image promotion blocked: {_bounded_error(error)}", file=sys.stderr)
        raise SystemExit(1) from error
