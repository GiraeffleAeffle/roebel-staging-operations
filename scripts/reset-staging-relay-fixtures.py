#!/usr/bin/env python3
"""One-shot, fail-closed reset of the two Röbel staging relay fixture stores.

The protected runner gates the legacy workbench to GET/HEAD, quiesces the
exact public-Mecky Flux workload, recreates citizen-relay then agent-relay,
restarts Mecky, proves its sole signed kind-0 identity event, and restores the
gate and Flux suspension.  It never reads a Kubernetes Secret, never retries
a mutation, and never claims civic authority.  A durable hash-linked intent
precedes every mutation; an interrupted attempt is inspected, not resumed.
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
from typing import Any, Callable


SCHEMA_VERSION = "roebel_staging_relay_fixture_reset_v2"
JOURNAL_SCHEMA = "roebel_staging_relay_fixture_reset_journal_v2"
RECEIPT_SCHEMA = "roebel_staging_relay_fixture_reset_receipt_v2"

NAMESPACE = "stadtstack-roebel-staging-lab"
WEB_NAMESPACE = "stadtstack-roebel-web-preview"
FLUX_NAMESPACE = "flux-roebel-staging"
COMPONENT_ORDER = ("citizen-relay", "agent-relay")
DEPLOYMENT_UIDS = {
    "citizen-relay": "86b9aada-2b27-428b-9c98-27376b965f58",
    "agent-relay": "d62fbb00-feed-40aa-ba72-180bfd80c4e7",
}

SOURCE_REVISION = "36ac41d7049df815aaebbe4301c098a0ec7e4101"
ARTIFACT_PIN_RECEIPT_SHA256 = "sha256:08d2b65bb57434ba6f35d8083f32b22f43010e1222544a8ce074e208f95efd9b"
RELAY_REPOSITORY = "ghcr.io/giraeffleaeffle/roebel-staging-relay"
RELAY_DIGEST = "sha256:6def2f468e3fad47cf17c0287a9215bbdc299b0d7d3b7fc58927b2f2169650ad"
RELAY_IMAGE = f"{RELAY_REPOSITORY}@{RELAY_DIGEST}"
PUBLISHER_WORKFLOW = (
    "https://github.com/GiraeffleAeffle/Roebel-App/"
    ".github/workflows/roebel-e2e-runtime-publish.yml@refs/heads/main"
)

PROTECTED_PATHS = (
    "scripts/run-staging-participant-gateway-live.py",
    "scripts/reset-staging-relay-fixtures.py",
    "scripts/verify-reviewed-render.py",
    "policy/repository-contract.json",
)

KUBECTL_BIN = Path("/Users/max/.local/bin/kubectl-v1.36.0")
KUBECTL_SHA256 = "sha256:4bcf268eacdc1d2df74e37d86f639f27ca7dea3ae185b7b452b73b9fb5ddc14e"

RELAY_PORT = 18081
RELAY_PORT_NAME = "http"
RELAY_VOLUME_NAME = "relay-store"
RELAY_MOUNT_PATH = "/relay"
RELAY_EMPTYDIR_SIZE = "128Mi"
ENDPOINT_SLICE_LABEL = "kubernetes.io/service-name"
WORKBENCH_SERVICE_NAME = "e2e-workbench"
WORKBENCH_SERVICE_PORT = 18083
PUBLIC_ORIGIN_HOST = "roebel-web.staging.agentcart.eu"
PUBLIC_ORIGIN = f"https://{PUBLIC_ORIGIN_HOST}"
WORKBENCH_PREFIX = "/stadtstack-test"
WORKBENCH_FEED_PATH = f"{WORKBENCH_PREFIX}/api/feed"
WORKBENCH_CONFIG_PATH = f"{WORKBENCH_PREFIX}/api/config"
WORKBENCH_GATE_PROBE_PATH = f"{WORKBENCH_PREFIX}/api/reset-gate-probe"
WORKBENCH_FEED_SCHEMA = "roebel_staging_mixed_feed_v1"
WORKBENCH_CONFIG_SCHEMA = "roebel_e2e_workbench_config_v1"
PUBLIC_HTTPS_TIMEOUT_SECONDS = 15

WORKBENCH_INGRESS_NAME = "stadtstack-test-workbench"
WORKBENCH_INGRESS_UID = "02cc55b5-30c5-46dd-b819-727e53c58806"
WORKBENCH_INGRESS_GENERATION = 1
WORKBENCH_INGRESS_ANNOTATION = "haproxy-ingress.github.io/config-backend-early"
WORKBENCH_INGRESS_OPEN = (
    "http-request deny deny_status 405 unless { method GET HEAD POST }\n"
    "http-request deny deny_status 404 unless { path_beg /stadtstack-test }"
)
WORKBENCH_INGRESS_GATED = (
    "http-request deny deny_status 405 unless { method GET HEAD }\n"
    "http-request deny deny_status 404 unless { path_beg /stadtstack-test }"
)

PUBLIC_MECKY_NAME = "public-mecky"
PUBLIC_MECKY_UID = "96987f99-0fb7-4149-a5e7-f0b7c469ab75"
PUBLIC_MECKY_IMAGE = "ghcr.io/giraeffleaeffle/public-mecky@sha256:aa66c9b8bb75989e1c47b628845523fa345a944b0a1a82bd17863f96c1f128e4"
PUBLIC_MECKY_PORT = 18084
PUBLIC_MECKY_PORT_NAME = "mecky-chat"
PUBLIC_MECKY_LABELS = {
    "app.kubernetes.io/component": "public-mecky",
    "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
}
PUBLIC_MECKY_KUSTOMIZATION = "roebel-staging-public-mecky-workload"
PUBLIC_MECKY_KUSTOMIZATION_UID = "4d49b8eb-c84b-442a-a96e-26c94f24177a"
EXPECTED_MECKY_PUBKEY_SHA256 = "sha256:e3f9abfd377f323afd82cb225630ce96030b544fda7829f4d312b7350980225d"
EXPECTED_MECKY_NAME = "Mecky · E2E"
EXPECTED_MECKY_TAG = ["netizen_agent", "mecky", "roebel-e2e"]

PARTICIPANT_GATEWAY_NAME = "roebel-staging-participant-gateway"
PARTICIPANT_WORKBENCH_INGRESS_NAME = "roebel-staging-participant-workbench-ingress"
PARTICIPANT_KUSTOMIZATIONS = (
    {
        "apiVersion": "kustomize.toolkit.fluxcd.io/v1",
        "kind": "Kustomization",
        "namespace": FLUX_NAMESPACE,
        "name": PARTICIPANT_GATEWAY_NAME,
    },
    {
        "apiVersion": "kustomize.toolkit.fluxcd.io/v1",
        "kind": "Kustomization",
        "namespace": FLUX_NAMESPACE,
        "name": PARTICIPANT_WORKBENCH_INGRESS_NAME,
    },
)
PARTICIPANT_RUNTIME_TARGETS = (
    {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "namespace": WEB_NAMESPACE,
        "name": PARTICIPANT_GATEWAY_NAME,
    },
    {
        "apiVersion": "v1",
        "kind": "Service",
        "namespace": WEB_NAMESPACE,
        "name": PARTICIPANT_GATEWAY_NAME,
    },
    {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "namespace": WEB_NAMESPACE,
        "name": PARTICIPANT_GATEWAY_NAME,
    },
    {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "namespace": WEB_NAMESPACE,
        "name": PARTICIPANT_GATEWAY_NAME,
    },
    {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "namespace": WEB_NAMESPACE,
        "name": PARTICIPANT_GATEWAY_NAME,
    },
    {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "namespace": NAMESPACE,
        "name": PARTICIPANT_WORKBENCH_INGRESS_NAME,
    },
)

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
MAX_FILE_BYTES = 8 * 1024 * 1024
PUBLIC_HTTPS_MAX_BODY_BYTES = MAX_FILE_BYTES
MAX_ERROR_CHARS = 320
DEFAULT_REPLACEMENT_TIMEOUT_SECONDS = 120
DEFAULT_QUIET_OBSERVATIONS = 3
DEFAULT_QUIET_INTERVAL_SECONDS = 1.0

LIVE_EXECUTION_ENABLED = True


class RelayResetError(RuntimeError):
    """A fail-closed validation, persistence, or transaction failure."""


class TransportUncertain(RelayResetError):
    """A request outcome or read-only transport result cannot be proven."""


class PostconditionFailure(RelayResetError):
    """Cluster state was observed but does not satisfy the reviewed contract."""


class RelayResetInterrupted(RelayResetError):
    def __init__(self, signum: int) -> None:
        self.signum = signum
        super().__init__(f"relay reset interrupted by signal {signum}")


def require(condition: bool, message: str, error: type[RelayResetError] = RelayResetError) -> None:
    if not condition:
        raise error(message)


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def bytes_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _bounded_error(value: Any) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return " ".join(str(value).split())[:MAX_ERROR_CHARS]


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(raw: bytes | str, label: str) -> Any:
    try:
        return json.loads(raw, object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, RelayResetError) as error:
        raise RelayResetError(f"{label} is not valid JSON") from error


def parse_object(raw: bytes | str, label: str) -> dict[str, Any]:
    value = parse_json(raw, label)
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return value


def _validate_uuid(value: Any, label: str) -> str:
    require(isinstance(value, str) and UUID_RE.fullmatch(value) is not None, f"{label} UUID invalid")
    return value


def _validate_resource_version(value: Any, label: str) -> str:
    require(isinstance(value, str) and value.isdigit() and int(value) > 0, f"{label} resourceVersion invalid")
    return value


def _validate_generation(value: Any, label: str) -> int:
    require(isinstance(value, int) and not isinstance(value, bool) and value > 0, f"{label} generation invalid")
    return value


def _metadata(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    metadata = value.get("metadata")
    require(isinstance(metadata, dict), f"{label} metadata absent")
    return metadata


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_private_regular(path: Path, label: str, *, max_bytes: int = MAX_FILE_BYTES) -> bytes:
    selected = Path(path).absolute()
    info = os.lstat(selected)
    require(
        stat.S_ISREG(info.st_mode)
        and not selected.is_symlink()
        and info.st_uid == os.geteuid()
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) & 0o077 == 0,
        f"{label} must be an owner-only regular non-symlink file",
    )
    require(0 < info.st_size <= max_bytes, f"{label} exceeds the bounded size")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(selected, flags)
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
        f"{label} changed while reading",
    )
    return raw


def _secret_reference(value: Any, path: str) -> None:
    require(isinstance(value, dict), f"Secret reference at {path} invalid")
    require(set(value) == {"name", "key", "optional"}, f"Secret reference fields at {path} invalid")
    require(isinstance(value["name"], str) and value["name"], f"Secret reference name at {path} invalid")
    require(isinstance(value["key"], str) and value["key"], f"Secret reference key at {path} invalid")
    require(value["optional"] is False, f"Secret reference optional policy at {path} invalid")


def _reject_secret_values(value: Any, path: str = "$") -> None:
    """Allow value-free references while refusing accidentally captured data."""
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower().replace("_", "").replace("-", "")
            require(normalized not in {"data", "stringdata"}, f"value-free record contains data at {path}.{key}")
            if normalized == "secretkeyref":
                _secret_reference(child, f"{path}.{key}")
                continue
            if normalized in {"secretvaluesread", "civicauthorityeffects", "secretread", "secretwrite"}:
                require(isinstance(child, bool), f"effect flag at {path}.{key} must be boolean")
            _reject_secret_values(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_values(child, f"{path}[{index}]")


def _project_value_free_evidence(value: Any) -> Any:
    """Remove mutation-only full specs while retaining their validated digest."""
    if isinstance(value, dict):
        result = {key: _project_value_free_evidence(child) for key, child in value.items()}
        if "spec" in result and "specSha256" in result:
            result.pop("spec")
        return result
    if isinstance(value, list):
        return [_project_value_free_evidence(child) for child in value]
    return copy.deepcopy(value)


def validate_artifact_pin(path: Path) -> dict[str, Any]:
    raw = _read_private_regular(path, "artifact pin receipt")
    observed = bytes_digest(raw)
    require(observed == ARTIFACT_PIN_RECEIPT_SHA256, "artifact pin receipt checksum drift")
    value = parse_object(raw, "artifact pin receipt")
    require(
        set(value) == {"schemaVersion", "sourceRevision", "components", "civicAuthority", "deploymentEffect"},
        "artifact pin fields drift",
    )
    require(value["schemaVersion"] == "roebel_e2e_runtime_pin_v1", "artifact pin schema drift")
    require(value["sourceRevision"] == SOURCE_REVISION, "artifact pin source revision drift")
    require(value["civicAuthority"] == "none", "artifact pin civic authority widened")
    require(value["deploymentEffect"] is False, "artifact pin deployment effect widened")
    components = value["components"]
    require(isinstance(components, list) and len(components) == 2, "artifact pin component closure drift")
    selected = [item for item in components if isinstance(item, dict) and item.get("component") == "roebel-staging-relay"]
    require(len(selected) == 1, "artifact pin relay component missing or duplicated")
    component = selected[0]
    require(
        set(component) == {"component", "image", "manifestDigest", "provenance", "sbomAttestation", "workflowIdentity"},
        "artifact pin relay fields drift",
    )
    require(component["image"] == RELAY_REPOSITORY, "artifact pin relay repository drift")
    require(component["manifestDigest"] == RELAY_DIGEST, "artifact pin relay digest drift")
    require(component["workflowIdentity"] == PUBLISHER_WORKFLOW, "artifact pin relay workflow drift")
    for key in ("provenance", "sbomAttestation"):
        attestation = component[key]
        require(
            isinstance(attestation, dict)
            and set(attestation) == {"id", "url"}
            and isinstance(attestation["id"], str)
            and bool(attestation["id"])
            and isinstance(attestation["url"], str)
            and attestation["url"].startswith("https://github.com/"),
            f"artifact pin {key} binding absent",
        )
    return {
        "receiptSha256": observed,
        "sourceRevision": SOURCE_REVISION,
        "component": "roebel-staging-relay",
        "repository": RELAY_REPOSITORY,
        "manifestDigest": RELAY_DIGEST,
        "image": RELAY_IMAGE,
        "civicAuthority": "none",
        "deploymentEffect": False,
    }


def validate_protected_binding(revision: Any, hashes: Any) -> tuple[str, dict[str, str]]:
    require(isinstance(revision, str) and REVISION_RE.fullmatch(revision) is not None, "protected revision invalid")
    require(
        isinstance(hashes, dict)
        and set(hashes) == set(PROTECTED_PATHS)
        and all(isinstance(value, str) and SHA256_RE.fullmatch(value) is not None for value in hashes.values()),
        "protected Git blob closure drift",
    )
    return revision, dict(sorted(hashes.items()))


def relay_labels(component: str) -> dict[str, str]:
    require(component in COMPONENT_ORDER, "relay component outside reset scope")
    return {
        "app.kubernetes.io/component": f"signed-nostr-{component}",
        "app.kubernetes.io/name": component,
        "app.kubernetes.io/part-of": "roebel-signed-nostr-staging",
        "stadtstack.io/authority": "none",
    }


def _target(api_version: str, kind: str, name: str, namespace: str = NAMESPACE) -> dict[str, str]:
    return {"apiVersion": api_version, "kind": kind, "namespace": namespace, "name": name}


def deployment_target(component: str) -> dict[str, str]:
    return _target("apps/v1", "Deployment", component)


def service_target(component: str) -> dict[str, str]:
    return _target("v1", "Service", component)


def network_policy_target(component: str) -> dict[str, str]:
    return _target("networking.k8s.io/v1", "NetworkPolicy", component)


def workbench_ingress_target() -> dict[str, str]:
    return _target("networking.k8s.io/v1", "Ingress", WORKBENCH_INGRESS_NAME)


def public_mecky_deployment_target() -> dict[str, str]:
    return _target("apps/v1", "Deployment", PUBLIC_MECKY_NAME)


def public_mecky_service_target() -> dict[str, str]:
    return _target("v1", "Service", PUBLIC_MECKY_NAME)


def public_mecky_kustomization_target() -> dict[str, str]:
    return _target(
        "kustomize.toolkit.fluxcd.io/v1",
        "Kustomization",
        PUBLIC_MECKY_KUSTOMIZATION,
        FLUX_NAMESPACE,
    )


ALLOWED_GET_TARGETS = tuple(
    [target for component in COMPONENT_ORDER for target in (
        deployment_target(component), service_target(component), network_policy_target(component)
    )]
    + [workbench_ingress_target(), public_mecky_deployment_target(), public_mecky_service_target(), public_mecky_kustomization_target()]
    + list(PARTICIPANT_RUNTIME_TARGETS)
    + list(PARTICIPANT_KUSTOMIZATIONS)
)


def _validate_target(value: Any, target: dict[str, str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    metadata = _metadata(value, label)
    require(value.get("apiVersion") == target["apiVersion"], f"{label} apiVersion drift")
    require(value.get("kind") == target["kind"], f"{label} kind drift")
    require(metadata.get("namespace") == target["namespace"], f"{label} namespace drift")
    require(metadata.get("name") == target["name"], f"{label} name drift")
    return value


def _validate_labels(value: dict[str, Any], component: str, label: str) -> None:
    labels = _metadata(value, label).get("labels")
    require(isinstance(labels, dict), f"{label} labels absent")
    for key, expected in relay_labels(component).items():
        require(labels.get(key) == expected, f"{label} ownership label drift: {key}")


def _relay_environment(component: str) -> list[dict[str, Any]]:
    value: list[dict[str, Any]] = [
        {"name": "RELAY_NAME", "value": component},
        {"name": "RELAY_PORT", "value": str(RELAY_PORT)},
        {"name": "RELAY_BIND_HOST", "value": "0.0.0.0"},
        {"name": "RELAY_WEBSOCKET_PATH", "value": f"/{component}"},
        {"name": "RELAY_EVENT_STORE", "value": "/relay/events.ndjson"},
        {"name": "RELAY_MAX_EVENT_STORE_BYTES", "value": "67108864"},
        {"name": "RELAY_MAX_EVENT_COUNT", "value": "50000"},
        {
            "name": "RELAY_ALLOWED_PUBKEYS",
            "valueFrom": {
                "secretKeyRef": {
                    "key": "MECKY_PUBKEY",
                    "name": "roebel-signed-nostr-runtime",
                    "optional": False,
                }
            },
        },
    ]
    if component == "citizen-relay":
        value.extend([
            {"name": "RELAY_ADMISSION_STORE", "value": "/relay/admissions.ndjson"},
            {"name": "RELAY_MAX_ADMISSION_STORE_BYTES", "value": "16777216"},
            {"name": "RELAY_MAX_ADMISSION_COUNT", "value": "10000"},
            {
                "name": "RELAY_ADMISSION_TOKEN",
                "valueFrom": {
                    "secretKeyRef": {
                        "key": "CITIZEN_RELAY_ADMISSION_TOKEN",
                        "name": "roebel-signed-nostr-runtime",
                        "optional": False,
                    }
                },
            },
        ])
    return value


def validate_deployment(value: Any, component: str) -> dict[str, Any]:
    label = f"{component} Deployment"
    deployment = _validate_target(value, deployment_target(component), label)
    metadata = _metadata(deployment, label)
    uid = _validate_uuid(metadata.get("uid"), label)
    resource_version = _validate_resource_version(metadata.get("resourceVersion"), label)
    generation = _validate_generation(metadata.get("generation"), label)
    require(uid == DEPLOYMENT_UIDS[component], f"{label} UID drift")
    require(not metadata.get("ownerReferences"), f"{label} ownerReferences must be absent")
    _validate_labels(deployment, component, label)
    spec = deployment.get("spec")
    require(isinstance(spec, dict), f"{label} spec absent")
    require(spec.get("replicas") == 1, f"{label} replicas drift")
    require(spec.get("selector") == {"matchLabels": relay_labels(component)}, f"{label} selector drift")
    template = spec.get("template")
    require(isinstance(template, dict), f"{label} template absent")
    template_metadata = template.get("metadata")
    require(isinstance(template_metadata, dict) and template_metadata.get("labels") == relay_labels(component), f"{label} template labels drift")
    pod_spec = template.get("spec")
    require(isinstance(pod_spec, dict), f"{label} Pod spec absent")
    require(pod_spec.get("automountServiceAccountToken") is False, f"{label} service-account token widened")
    require(pod_spec.get("volumes") == [{"emptyDir": {"sizeLimit": RELAY_EMPTYDIR_SIZE}, "name": RELAY_VOLUME_NAME}], f"{label} /relay emptyDir drift")
    require(not pod_spec.get("initContainers") and not pod_spec.get("ephemeralContainers"), f"{label} auxiliary container drift")
    containers = pod_spec.get("containers")
    require(isinstance(containers, list) and len(containers) == 1 and isinstance(containers[0], dict), f"{label} container closure drift")
    container = containers[0]
    require(container.get("name") == component, f"{label} container name drift")
    require(container.get("image") == RELAY_IMAGE, f"{label} image drift")
    require(container.get("imagePullPolicy") == "IfNotPresent", f"{label} image pull policy drift")
    require(container.get("volumeMounts") == [{"mountPath": RELAY_MOUNT_PATH, "name": RELAY_VOLUME_NAME}], f"{label} /relay mount drift")
    require(container.get("env") == _relay_environment(component), f"{label} environment drift")
    require(container.get("ports") == [{"containerPort": RELAY_PORT, "name": RELAY_PORT_NAME, "protocol": "TCP"}], f"{label} port drift")
    status = deployment.get("status")
    require(isinstance(status, dict), f"{label} status absent")
    require(status.get("observedGeneration") == metadata.get("generation"), f"{label} generation not observed")
    require(status.get("readyReplicas") == 1 and status.get("availableReplicas") == 1, f"{label} not ready")
    return {
        "uid": uid,
        "resourceVersion": resource_version,
        "generation": generation,
        "spec": copy.deepcopy(spec),
        "specSha256": digest(spec),
    }


def _without_server_fields(value: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(value)
    metadata = result.get("metadata")
    if isinstance(metadata, dict):
        for key in (
            "creationTimestamp", "deletionGracePeriodSeconds", "deletionTimestamp",
            "generation", "managedFields", "resourceVersion", "selfLink", "uid",
        ):
            metadata.pop(key, None)
    result.pop("status", None)
    return result


def validate_service(value: Any, component: str) -> dict[str, Any]:
    label = f"{component} Service"
    service = _validate_target(value, service_target(component), label)
    metadata = _metadata(service, label)
    _validate_labels(service, component, label)
    require(not metadata.get("ownerReferences"), f"{label} ownerReferences must be absent")
    uid = _validate_uuid(metadata.get("uid"), label)
    resource_version = _validate_resource_version(metadata.get("resourceVersion"), label)
    spec = service.get("spec")
    require(isinstance(spec, dict), f"{label} spec absent")
    require(spec.get("selector") == relay_labels(component), f"{label} selector drift")
    require(spec.get("type") == "ClusterIP", f"{label} type drift")
    require(spec.get("ports") == [{"name": RELAY_PORT_NAME, "port": RELAY_PORT, "protocol": "TCP", "targetPort": RELAY_PORT_NAME}], f"{label} port drift")
    snapshot = _without_server_fields(service)
    return {
        "uid": uid,
        "resourceVersion": resource_version,
        "object": snapshot,
        "objectSha256": digest(snapshot),
    }


def validate_network_policy(value: Any, component: str) -> dict[str, Any]:
    label = f"{component} NetworkPolicy"
    policy = _validate_target(value, network_policy_target(component), label)
    metadata = _metadata(policy, label)
    _validate_labels(policy, component, label)
    require(not metadata.get("ownerReferences"), f"{label} ownerReferences must be absent")
    uid = _validate_uuid(metadata.get("uid"), label)
    resource_version = _validate_resource_version(metadata.get("resourceVersion"), label)
    generation = _validate_generation(metadata.get("generation"), label)
    spec = policy.get("spec")
    require(isinstance(spec, dict), f"{label} spec absent")
    require(spec.get("podSelector") == {"matchLabels": relay_labels(component)}, f"{label} selector drift")
    require(spec.get("policyTypes") == ["Ingress", "Egress"], f"{label} policy types drift")
    require(spec.get("egress") == [], f"{label} egress widened")
    snapshot = _without_server_fields(policy)
    return {
        "uid": uid,
        "resourceVersion": resource_version,
        "generation": generation,
        "object": snapshot,
        "objectSha256": digest(snapshot),
    }


def validate_network_policy_inventory(value: Any) -> list[dict[str, Any]]:
    require(isinstance(value, list) and value, "namespace NetworkPolicy inventory absent")
    records: list[dict[str, Any]] = []
    names: set[str] = set()
    for index, item in enumerate(value):
        label = f"namespace NetworkPolicy[{index}]"
        require(isinstance(item, dict) and item.get("apiVersion") == "networking.k8s.io/v1" and item.get("kind") == "NetworkPolicy", f"{label} type drift")
        metadata = _metadata(item, label)
        require(metadata.get("namespace") == NAMESPACE, f"{label} namespace drift")
        name = metadata.get("name")
        require(isinstance(name, str) and DNS_LABEL_RE.fullmatch(name) is not None and name not in names, f"{label} name invalid or duplicated")
        names.add(name)
        uid = _validate_uuid(metadata.get("uid"), label)
        generation = _validate_generation(metadata.get("generation"), label)
        spec = item.get("spec")
        require(isinstance(spec, dict), f"{label} spec absent")
        normalized = _without_server_fields(item)
        records.append({"name": name, "uid": uid, "generation": generation, "object": normalized, "objectSha256": digest(normalized)})
    return sorted(records, key=lambda item: item["name"])


def validate_workbench_ingress(value: Any, *, expected_policy: str) -> dict[str, Any]:
    label = "workbench write-gate Ingress"
    ingress = _validate_target(value, workbench_ingress_target(), label)
    metadata = _metadata(ingress, label)
    require(_validate_uuid(metadata.get("uid"), label) == WORKBENCH_INGRESS_UID, f"{label} UID drift")
    resource_version = _validate_resource_version(metadata.get("resourceVersion"), label)
    require(_validate_generation(metadata.get("generation"), label) == WORKBENCH_INGRESS_GENERATION, f"{label} generation drift")
    annotations = metadata.get("annotations")
    require(isinstance(annotations, dict) and annotations.get(WORKBENCH_INGRESS_ANNOTATION) == expected_policy, f"{label} policy drift")
    spec = ingress.get("spec")
    require(isinstance(spec, dict), f"{label} spec absent")
    normalized = _without_server_fields(ingress)
    return {
        "uid": WORKBENCH_INGRESS_UID,
        "resourceVersion": resource_version,
        "generation": WORKBENCH_INGRESS_GENERATION,
        "policy": expected_policy,
        "object": normalized,
        "objectSha256": digest(normalized),
        "specSha256": digest(spec),
    }


def ingress_patch(current: dict[str, Any], old: str, new: str) -> list[dict[str, Any]]:
    require(old in {WORKBENCH_INGRESS_OPEN, WORKBENCH_INGRESS_GATED}, "Ingress old policy outside reset scope")
    require(new in {WORKBENCH_INGRESS_OPEN, WORKBENCH_INGRESS_GATED} and new != old, "Ingress new policy outside reset scope")
    return [
        {"op": "test", "path": "/metadata/uid", "value": WORKBENCH_INGRESS_UID},
        {"op": "test", "path": "/metadata/resourceVersion", "value": _validate_resource_version(current.get("resourceVersion"), "Ingress CAS")},
        {"op": "test", "path": "/metadata/generation", "value": WORKBENCH_INGRESS_GENERATION},
        {"op": "test", "path": "/spec", "value": copy.deepcopy(current["object"]["spec"])},
        {"op": "test", "path": "/metadata/annotations/" + WORKBENCH_INGRESS_ANNOTATION.replace("~", "~0").replace("/", "~1"), "value": old},
        {"op": "replace", "path": "/metadata/annotations/" + WORKBENCH_INGRESS_ANNOTATION.replace("~", "~0").replace("/", "~1"), "value": new},
    ]


def validate_public_mecky_deployment(value: Any, *, replicas: int) -> dict[str, Any]:
    label = "public-mecky Deployment"
    target = public_mecky_deployment_target()
    deployment = _validate_target(value, target, label)
    metadata = _metadata(deployment, label)
    uid = _validate_uuid(metadata.get("uid"), label)
    require(uid == PUBLIC_MECKY_UID, f"{label} UID drift")
    resource_version = _validate_resource_version(metadata.get("resourceVersion"), label)
    generation = _validate_generation(metadata.get("generation"), label)
    spec = deployment.get("spec")
    require(isinstance(spec, dict) and spec.get("replicas") == replicas, f"{label} replicas drift")
    require(spec.get("selector") == {"matchLabels": PUBLIC_MECKY_LABELS}, f"{label} selector drift")
    template = spec.get("template")
    require(isinstance(template, dict) and isinstance(template.get("metadata"), dict), f"{label} template absent")
    labels = template["metadata"].get("labels")
    require(isinstance(labels, dict) and all(labels.get(key) == expected for key, expected in PUBLIC_MECKY_LABELS.items()), f"{label} template labels drift")
    pod_spec = template.get("spec")
    require(isinstance(pod_spec, dict) and pod_spec.get("automountServiceAccountToken") is False, f"{label} Pod security boundary drift")
    containers = pod_spec.get("containers")
    require(isinstance(containers, list) and len(containers) == 1 and isinstance(containers[0], dict), f"{label} container closure drift")
    container = containers[0]
    require(container.get("name") == PUBLIC_MECKY_NAME and container.get("image") == PUBLIC_MECKY_IMAGE, f"{label} image drift")
    require(container.get("ports") == [{"containerPort": PUBLIC_MECKY_PORT, "name": PUBLIC_MECKY_PORT_NAME, "protocol": "TCP"}], f"{label} port drift")
    status = deployment.get("status")
    require(isinstance(status, dict) and status.get("observedGeneration") == generation, f"{label} generation not observed")
    if replicas == 1:
        require(status.get("readyReplicas") == 1 and status.get("availableReplicas") == 1, f"{label} not ready")
    else:
        require(status.get("replicas", 0) == 0 and status.get("readyReplicas", 0) == 0 and status.get("availableReplicas", 0) == 0, f"{label} did not scale to zero")
    return {
        "uid": uid,
        "resourceVersion": resource_version,
        "generation": generation,
        "replicas": replicas,
        "spec": copy.deepcopy(spec),
        "specSha256": digest(spec),
    }


def deployment_replicas_patch(current: dict[str, Any], old: int, new: int) -> list[dict[str, Any]]:
    require((old, new) in {(1, 0), (0, 1)}, "public-mecky replicas transition outside reset scope")
    return [
        {"op": "test", "path": "/metadata/uid", "value": PUBLIC_MECKY_UID},
        {"op": "test", "path": "/metadata/resourceVersion", "value": _validate_resource_version(current.get("resourceVersion"), "public-mecky Deployment CAS")},
        {"op": "test", "path": "/spec", "value": copy.deepcopy(current["spec"])},
        {"op": "test", "path": "/spec/replicas", "value": old},
        {"op": "replace", "path": "/spec/replicas", "value": new},
    ]


def validate_public_mecky_service(value: Any) -> dict[str, Any]:
    label = "public-mecky Service"
    service = _validate_target(value, public_mecky_service_target(), label)
    metadata = _metadata(service, label)
    uid = _validate_uuid(metadata.get("uid"), label)
    _validate_resource_version(metadata.get("resourceVersion"), label)
    spec = service.get("spec")
    require(isinstance(spec, dict), f"{label} spec absent")
    require(spec.get("selector") == PUBLIC_MECKY_LABELS, f"{label} selector drift")
    require(spec.get("type") == "ClusterIP", f"{label} type drift")
    require(spec.get("ports") == [{"name": PUBLIC_MECKY_PORT_NAME, "port": PUBLIC_MECKY_PORT, "protocol": "TCP", "targetPort": PUBLIC_MECKY_PORT_NAME}], f"{label} ports drift")
    normalized = _without_server_fields(service)
    return {"uid": uid, "object": normalized, "objectSha256": digest(normalized)}


def validate_public_mecky_kustomization(value: Any, *, suspended: bool) -> dict[str, Any]:
    label = "public-mecky Flux Kustomization"
    item = _validate_target(value, public_mecky_kustomization_target(), label)
    metadata = _metadata(item, label)
    uid = _validate_uuid(metadata.get("uid"), label)
    require(uid == PUBLIC_MECKY_KUSTOMIZATION_UID, f"{label} UID drift")
    resource_version = _validate_resource_version(metadata.get("resourceVersion"), label)
    generation = _validate_generation(metadata.get("generation"), label)
    spec = item.get("spec")
    require(isinstance(spec, dict), f"{label} spec absent")
    explicit = "suspend" in spec
    require((spec.get("suspend") is True) if suspended else (spec.get("suspend") in {None, False}), f"{label} suspension drift")
    if not suspended:
        conditions = item.get("status", {}).get("conditions")
        require(isinstance(conditions, list) and any(isinstance(entry, dict) and entry.get("type") == "Ready" and entry.get("status") == "True" and entry.get("observedGeneration") == generation for entry in conditions), f"{label} Ready proof absent")
    return {
        "uid": uid,
        "resourceVersion": resource_version,
        "generation": generation,
        "suspended": suspended,
        "suspendExplicit": explicit,
        "spec": copy.deepcopy(spec),
        "specSha256": digest(spec),
    }


def kustomization_suspend_patch(current: dict[str, Any], old: bool, new: bool) -> list[dict[str, Any]]:
    require((old, new) in {(False, True), (True, False)}, "Kustomization suspension transition outside reset scope")
    patch = [
        {"op": "test", "path": "/metadata/uid", "value": PUBLIC_MECKY_KUSTOMIZATION_UID},
        {"op": "test", "path": "/metadata/resourceVersion", "value": _validate_resource_version(current.get("resourceVersion"), "Kustomization CAS")},
        {"op": "test", "path": "/spec", "value": copy.deepcopy(current["spec"])},
    ]
    explicit = current.get("suspendExplicit") is True
    if old is False and new is True:
        patch.append({"op": "replace" if explicit else "add", "path": "/spec/suspend", "value": True})
    else:
        patch.append({"op": "replace", "path": "/spec/suspend", "value": False})
    return patch


def kustomization_restore_patch(current: dict[str, Any], original: dict[str, Any]) -> list[dict[str, Any]]:
    require(current.get("suspended") is True and original.get("suspended") is False, "Kustomization restore state invalid")
    patch = [
        {"op": "test", "path": "/metadata/uid", "value": PUBLIC_MECKY_KUSTOMIZATION_UID},
        {"op": "test", "path": "/metadata/resourceVersion", "value": _validate_resource_version(current.get("resourceVersion"), "Kustomization restore CAS")},
        {"op": "test", "path": "/spec", "value": copy.deepcopy(current["spec"])},
    ]
    if original.get("suspendExplicit") is True:
        patch.append({"op": "replace", "path": "/spec/suspend", "value": False})
    else:
        patch.append({"op": "remove", "path": "/spec/suspend"})
    return patch


def _controller_reference(value: dict[str, Any], label: str) -> dict[str, Any]:
    references = _metadata(value, label).get("ownerReferences")
    require(isinstance(references, list), f"{label} ownerReferences absent")
    selected = [item for item in references if isinstance(item, dict) and item.get("controller") is True]
    require(len(selected) == 1, f"{label} must have exactly one controller")
    reference = selected[0]
    _validate_uuid(reference.get("uid"), f"{label} controller")
    return reference


def validate_ready_owned_pod(pods: Any, replica_sets: Any, component: str) -> dict[str, Any]:
    label = f"{component} Pod"
    require(isinstance(pods, list) and len(pods) == 1 and isinstance(pods[0], dict), f"exactly one {label} required")
    pod = pods[0]
    require(pod.get("apiVersion") == "v1" and pod.get("kind") == "Pod", f"{label} type drift")
    metadata = _metadata(pod, label)
    require(metadata.get("namespace") == NAMESPACE, f"{label} namespace drift")
    name = metadata.get("name")
    require(isinstance(name, str) and DNS_LABEL_RE.fullmatch(name) is not None and name.startswith(f"{component}-"), f"{label} name drift")
    require(metadata.get("deletionTimestamp") is None, f"{label} is terminating")
    uid = _validate_uuid(metadata.get("uid"), label)
    resource_version = _validate_resource_version(metadata.get("resourceVersion"), label)
    labels = metadata.get("labels")
    require(isinstance(labels, dict), f"{label} labels absent")
    for key, expected in relay_labels(component).items():
        require(labels.get(key) == expected, f"{label} label drift: {key}")
    pod_owner = _controller_reference(pod, label)
    require(pod_owner.get("apiVersion") == "apps/v1" and pod_owner.get("kind") == "ReplicaSet", f"{label} controller kind drift")
    require(isinstance(replica_sets, list), f"{component} ReplicaSet list invalid")
    matches = [
        item for item in replica_sets
        if isinstance(item, dict) and _metadata(item, f"{component} ReplicaSet candidate").get("uid") == pod_owner["uid"]
    ]
    require(len(matches) == 1, f"{label} owning ReplicaSet absent or duplicated")
    replica_set = matches[0]
    rs_metadata = _metadata(replica_set, f"{component} ReplicaSet")
    require(rs_metadata.get("namespace") == NAMESPACE and rs_metadata.get("name") == pod_owner.get("name"), f"{label} ReplicaSet identity drift")
    deployment_owner = _controller_reference(replica_set, f"{component} ReplicaSet")
    require(
        deployment_owner.get("apiVersion") == "apps/v1"
        and deployment_owner.get("kind") == "Deployment"
        and deployment_owner.get("name") == component
        and deployment_owner.get("uid") == DEPLOYMENT_UIDS[component],
        f"{label} is not owned by the exact Deployment",
    )
    status = pod.get("status")
    require(isinstance(status, dict) and status.get("phase") == "Running", f"{label} not Running")
    conditions = status.get("conditions")
    require(
        isinstance(conditions, list)
        and any(isinstance(item, dict) and item.get("type") == "Ready" and item.get("status") == "True" for item in conditions),
        f"{label} Ready condition absent",
    )
    statuses = status.get("containerStatuses")
    require(isinstance(statuses, list) and len(statuses) == 1 and isinstance(statuses[0], dict), f"{label} container status drift")
    container_status = statuses[0]
    require(container_status.get("name") == component and container_status.get("ready") is True, f"{label} container not ready")
    image_id = container_status.get("imageID")
    require(isinstance(image_id, str) and RELAY_DIGEST in image_id, f"{label} imageID drift")
    addresses = []
    pod_ips = status.get("podIPs")
    if isinstance(pod_ips, list):
        for item in pod_ips:
            if isinstance(item, dict) and isinstance(item.get("ip"), str):
                addresses.append(item["ip"])
    if not addresses and isinstance(status.get("podIP"), str):
        addresses.append(status["podIP"])
    require(addresses and len(addresses) == len(set(addresses)), f"{label} addresses absent or duplicated")
    for address in addresses:
        try:
            ipaddress.ip_address(address)
        except ValueError as error:
            raise PostconditionFailure(f"{label} address invalid") from error
    return {
        "name": name,
        "uid": uid,
        "resourceVersion": resource_version,
        "replicaSetUid": pod_owner["uid"],
        "addresses": sorted(addresses),
        "ready": True,
        "imageDigest": RELAY_DIGEST,
    }


def validate_public_mecky_ready_pod(pods: Any, replica_sets: Any) -> dict[str, Any]:
    label = "public-mecky Pod"
    require(isinstance(pods, list) and len(pods) == 1 and isinstance(pods[0], dict), f"exactly one {label} required")
    pod = pods[0]
    require(pod.get("apiVersion") == "v1" and pod.get("kind") == "Pod", f"{label} type drift")
    metadata = _metadata(pod, label)
    require(metadata.get("namespace") == NAMESPACE, f"{label} namespace drift")
    name = metadata.get("name")
    require(isinstance(name, str) and DNS_LABEL_RE.fullmatch(name) is not None and name.startswith("public-mecky-"), f"{label} name drift")
    require(metadata.get("deletionTimestamp") is None, f"{label} is terminating")
    uid = _validate_uuid(metadata.get("uid"), label)
    resource_version = _validate_resource_version(metadata.get("resourceVersion"), label)
    labels = metadata.get("labels")
    require(isinstance(labels, dict) and all(labels.get(key) == expected for key, expected in PUBLIC_MECKY_LABELS.items()), f"{label} labels drift")
    pod_owner = _controller_reference(pod, label)
    require(pod_owner.get("apiVersion") == "apps/v1" and pod_owner.get("kind") == "ReplicaSet", f"{label} controller kind drift")
    matches = [item for item in replica_sets if isinstance(item, dict) and _metadata(item, "public-mecky ReplicaSet candidate").get("uid") == pod_owner.get("uid")]
    require(len(matches) == 1, f"{label} owning ReplicaSet absent or duplicated")
    rs = matches[0]
    rs_metadata = _metadata(rs, "public-mecky ReplicaSet")
    require(rs_metadata.get("namespace") == NAMESPACE and rs_metadata.get("name") == pod_owner.get("name"), f"{label} ReplicaSet identity drift")
    owner = _controller_reference(rs, "public-mecky ReplicaSet")
    require(owner.get("apiVersion") == "apps/v1" and owner.get("kind") == "Deployment" and owner.get("name") == PUBLIC_MECKY_NAME and owner.get("uid") == PUBLIC_MECKY_UID, f"{label} exact Deployment ownership absent")
    status = pod.get("status")
    require(isinstance(status, dict) and status.get("phase") == "Running", f"{label} not Running")
    require(any(isinstance(item, dict) and item.get("type") == "Ready" and item.get("status") == "True" for item in status.get("conditions", [])), f"{label} Ready condition absent")
    statuses = status.get("containerStatuses")
    require(isinstance(statuses, list) and len(statuses) == 1 and statuses[0].get("name") == PUBLIC_MECKY_NAME and statuses[0].get("ready") is True, f"{label} container not ready")
    image_id = statuses[0].get("imageID")
    require(isinstance(image_id, str) and PUBLIC_MECKY_IMAGE.split("@", 1)[1] in image_id, f"{label} imageID drift")
    addresses = [entry.get("ip") for entry in status.get("podIPs", []) if isinstance(entry, dict) and isinstance(entry.get("ip"), str)]
    if not addresses and isinstance(status.get("podIP"), str):
        addresses = [status["podIP"]]
    require(addresses and len(addresses) == len(set(addresses)), f"{label} addresses absent or duplicated")
    for address in addresses:
        try:
            ipaddress.ip_address(address)
        except ValueError as error:
            raise PostconditionFailure(f"{label} address invalid") from error
    return {
        "name": name,
        "uid": uid,
        "resourceVersion": resource_version,
        "replicaSetUid": pod_owner["uid"],
        "addresses": sorted(addresses),
        "ready": True,
        "imageDigest": PUBLIC_MECKY_IMAGE.split("@", 1)[1],
    }


def validate_endpoint_slices(value: Any, component: str, pod: dict[str, Any]) -> dict[str, Any]:
    require(component in (*COMPONENT_ORDER, PUBLIC_MECKY_NAME), "EndpointSlice component outside reset scope")
    require(isinstance(value, list) and value, f"{component} EndpointSlices absent")
    port_name = PUBLIC_MECKY_PORT_NAME if component == PUBLIC_MECKY_NAME else RELAY_PORT_NAME
    port = PUBLIC_MECKY_PORT if component == PUBLIC_MECKY_NAME else RELAY_PORT
    ready: list[dict[str, Any]] = []
    slice_uids: list[str] = []
    for index, item in enumerate(value):
        label = f"{component} EndpointSlice[{index}]"
        require(isinstance(item, dict), f"{label} invalid")
        require(item.get("apiVersion") == "discovery.k8s.io/v1" and item.get("kind") == "EndpointSlice", f"{label} type drift")
        metadata = _metadata(item, label)
        require(metadata.get("namespace") == NAMESPACE, f"{label} namespace drift")
        labels = metadata.get("labels")
        require(isinstance(labels, dict) and labels.get(ENDPOINT_SLICE_LABEL) == component, f"{label} Service binding drift")
        slice_uids.append(_validate_uuid(metadata.get("uid"), label))
        ports = item.get("ports")
        require(
            isinstance(ports, list)
            and len(ports) == 1
            and isinstance(ports[0], dict)
            and ports[0].get("name") == port_name
            and ports[0].get("port") == port
            and ports[0].get("protocol") == "TCP",
            f"{label} port drift",
        )
        endpoints = item.get("endpoints")
        require(isinstance(endpoints, list), f"{label} endpoints invalid")
        for endpoint in endpoints:
            require(isinstance(endpoint, dict), f"{label} endpoint invalid")
            if endpoint.get("conditions", {}).get("ready") is not True:
                continue
            ready.append(endpoint)
    require(len(ready) == 1, f"{component} must have exactly one ready Service endpoint")
    endpoint = ready[0]
    target = endpoint.get("targetRef")
    require(
        isinstance(target, dict)
        and target.get("apiVersion") == "v1"
        and target.get("kind") == "Pod"
        and target.get("namespace") == NAMESPACE
        and target.get("name") == pod["name"]
        and target.get("uid") == pod["uid"],
        f"{component} EndpointSlice target is not the replacement Pod",
    )
    addresses = endpoint.get("addresses")
    require(isinstance(addresses, list) and sorted(addresses) == pod["addresses"], f"{component} EndpointSlice addresses drift")
    return {
        "service": component,
        "podUid": pod["uid"],
        "podName": pod["name"],
        "addresses": copy.deepcopy(pod["addresses"]),
        "endpointSliceUids": sorted(slice_uids),
        "port": port,
        "ready": True,
    }


def validate_relay_health(value: Any, component: str, *, empty: bool) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == {"ok", "identityVerified", "events"}, f"{component} health fields drift")
    require(value["ok"] is True and value["identityVerified"] is True, f"{component} health identity drift")
    events = value["events"]
    require(isinstance(events, int) and not isinstance(events, bool) and events >= 0, f"{component} health event count invalid")
    require(events == 0 if empty else events > 0, f"{component} event store {'not empty' if empty else 'fixture-empty'}")
    return {"component": component, "identityVerified": True, "events": events, "empty": events == 0}


def validate_relay_inventory(value: Any, component: str, *, empty: bool, profile: bool = False) -> dict[str, Any]:
    allowed = {"health", "eventStore", "admissionStore", "profile"}
    require(isinstance(value, dict) and set(value) == allowed, f"{component} relay inventory fields drift")
    health = validate_relay_health(value["health"], component, empty=empty if not profile else False)
    event_store = value["eventStore"]
    require(isinstance(event_store, dict) and set(event_store) == {"present", "bytes", "records"}, f"{component} event-store inventory drift")
    require(isinstance(event_store["present"], bool), f"{component} event-store presence invalid")
    for key in ("bytes", "records"):
        require(isinstance(event_store[key], int) and not isinstance(event_store[key], bool) and event_store[key] >= 0, f"{component} event-store {key} invalid")
    if empty:
        require(event_store["bytes"] == 0 and event_store["records"] == 0 and health["events"] == 0, f"{component} event store not empty", PostconditionFailure)
    admission = value["admissionStore"]
    require(isinstance(admission, dict) and set(admission) == {"applicable", "present", "bytes", "records"}, f"{component} admission-store inventory drift")
    require(admission["applicable"] is (component == "citizen-relay"), f"{component} admission-store applicability drift")
    require(isinstance(admission["present"], bool), f"{component} admission-store presence invalid")
    require(isinstance(admission["bytes"], int) and admission["bytes"] >= 0 and isinstance(admission["records"], int) and admission["records"] >= 0, f"{component} admission-store counts invalid")
    if component == "citizen-relay":
        require(admission["bytes"] == 0 and admission["records"] == 0, "citizen admission store is not absent/zero", PostconditionFailure)
    else:
        require(admission == {"applicable": False, "present": False, "bytes": 0, "records": 0}, "agent admission-store inventory widened")
    profile_value = value["profile"]
    if profile:
        expected_fields = {
            "kind0Count", "kind1Count", "validKind0Count", "expectedAuthorHash",
            "eventIdVerified", "signatureVerified", "bot", "identityVerified",
            "aboutNonempty", "agentTagVerified",
        }
        require(isinstance(profile_value, dict) and set(profile_value) == expected_fields, "Mecky profile proof fields drift")
        require(profile_value["kind0Count"] == 1 and profile_value["kind1Count"] == 0 and profile_value["validKind0Count"] == 1, "Mecky profile event cardinality drift", PostconditionFailure)
        for key in expected_fields - {"kind0Count", "kind1Count", "validKind0Count"}:
            require(profile_value[key] is True, f"Mecky profile proof failed: {key}", PostconditionFailure)
        require(health["events"] == 1 and event_store["records"] == 1 and event_store["bytes"] > 0, "agent relay physical profile inventory drift", PostconditionFailure)
    else:
        require(profile_value is None, f"{component} unexpected profile output")
    return {
        "health": health,
        "eventStore": copy.deepcopy(event_store),
        "admissionStore": copy.deepcopy(admission),
        "profile": copy.deepcopy(profile_value),
        "valueFree": True,
    }


def _walk_synthetic(value: Any, found: list[bool]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower().replace("_", "").replace("-", "") in {"synthetic", "issynthetic"}:
                require(child is True, "workbench feed contains a non-synthetic marker", PostconditionFailure)
                found.append(True)
            _walk_synthetic(child, found)
    elif isinstance(value, list):
        for child in value:
            _walk_synthetic(child, found)


def validate_workbench_feed(value: Any, *, empty: bool) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == {"schemaVersion", "posts", "authorityBinding"}, "workbench feed fields drift")
    require(value["schemaVersion"] == WORKBENCH_FEED_SCHEMA, "workbench feed schema drift")
    require(value["authorityBinding"] == "none", "workbench feed authority widened")
    posts = value["posts"]
    require(isinstance(posts, list) and len(posts) <= 500, "workbench feed posts invalid")
    if empty:
        require(posts == [], "workbench feed is not empty after relay replacement", PostconditionFailure)
        return {"postCount": 0, "allSynthetic": True, "canonicalSha256": digest(value)}
    require(posts, "workbench fixture feed is empty")
    found: list[bool] = []
    for index, post in enumerate(posts):
        require(isinstance(post, dict) and post.get("synthetic") is True, f"workbench feed post[{index}] is not synthetic")
        _walk_synthetic(post, found)
    require(len(found) >= len(posts), "workbench feed synthetic provenance absent")
    return {"postCount": len(posts), "allSynthetic": True, "canonicalSha256": digest(value)}


def validate_workbench_config(value: Any) -> dict[str, Any]:
    require(isinstance(value, dict), "workbench config invalid")
    require(value.get("schemaVersion") == WORKBENCH_CONFIG_SCHEMA, "workbench config schema drift")
    require(value.get("authorityBinding") == "none", "workbench config authority widened")
    personas = value.get("personas")
    require(isinstance(personas, list), "workbench config personas invalid")
    public_key = value.get("meckyPubkey")
    require(isinstance(public_key, str) and re.fullmatch(r"[0-9a-f]{64}", public_key) is not None, "workbench Mecky pubkey invalid")
    require("sha256:" + hashlib.sha256(public_key.encode("ascii")).hexdigest() == EXPECTED_MECKY_PUBKEY_SHA256, "workbench Mecky pubkey binding drift")
    return {
        "schemaVersion": WORKBENCH_CONFIG_SCHEMA,
        "authorityBinding": "none",
        "mode": value.get("mode") if isinstance(value.get("mode"), str) else "legacy-unlabelled",
        "personaCount": len(personas),
        "meckyPubkeyHashVerified": True,
        "canonicalSha256": digest(value),
    }


def delete_options(pod: dict[str, Any]) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "DeleteOptions",
        "preconditions": {
            "uid": _validate_uuid(pod.get("uid"), "Pod delete precondition"),
            "resourceVersion": _validate_resource_version(pod.get("resourceVersion"), "Pod delete precondition"),
        },
    }


def delete_request(component: str, pod: dict[str, Any]) -> dict[str, Any]:
    require(component in COMPONENT_ORDER, "Pod delete component outside reset scope")
    name = pod.get("name")
    require(isinstance(name, str) and DNS_LABEL_RE.fullmatch(name) is not None, "Pod delete name invalid")
    body = delete_options(pod)
    path = f"/api/v1/namespaces/{NAMESPACE}/pods/{urllib.parse.quote(name, safe='')}"
    return {"method": "DELETE", "path": path, "body": body}


def _event(state: dict[str, Any], operation: str, stage: str, details: dict[str, Any] | None = None) -> None:
    events = state.setdefault("events", [])
    previous = events[-1].get("entrySha256") if events else None
    entry: dict[str, Any] = {
        "sequence": len(events) + 1,
        "operation": operation,
        "stage": stage,
        "previousEntrySha256": previous,
    }
    if details:
        entry.update(copy.deepcopy(details))
    entry["entrySha256"] = digest(entry)
    events.append(entry)


class MemoryJournal:
    def __init__(self) -> None:
        self.state: dict[str, Any] | None = None
        self.commits: list[dict[str, Any]] = []

    def load(self) -> dict[str, Any] | None:
        return copy.deepcopy(self.state)

    def commit(self, value: dict[str, Any]) -> None:
        _reject_secret_values(value)
        self.state = copy.deepcopy(value)
        self.commits.append(copy.deepcopy(value))


class MemoryReceipt:
    def __init__(self) -> None:
        self.value: dict[str, Any] | None = None

    def commit(self, value: dict[str, Any]) -> None:
        require(self.value is None, "receipt is immutable")
        _reject_secret_values(value)
        final = copy.deepcopy(value)
        final["canonicalSha256"] = digest(value)
        self.value = final


def _ensure_private_parent(path: Path, label: str) -> Path:
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
    parent = absolute.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = os.lstat(parent)
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) & 0o077 == 0,
        f"{label} parent is not private",
    )
    return absolute


class JsonJournal:
    MAX_BYTES = 2 * 1024 * 1024

    def __init__(self, path: Path) -> None:
        self.path = _ensure_private_parent(path, "journal")
        require(not self.path.exists() and not self.path.is_symlink(), "relay reset journal must be absent; resume is forbidden")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.path, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
        self._fsync_parent()

    def _fsync_parent(self) -> None:
        fd = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def load(self) -> dict[str, Any] | None:
        info = os.lstat(self.path)
        require(
            stat.S_ISREG(info.st_mode)
            and not self.path.is_symlink()
            and info.st_uid == os.geteuid()
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_size <= self.MAX_BYTES,
            "relay reset journal identity changed",
        )
        require(info.st_size == 0, "relay reset journal resume is forbidden")
        return None

    def commit(self, value: dict[str, Any]) -> None:
        _reject_secret_values(value)
        final = copy.deepcopy(value)
        final["journalSha256"] = digest(value)
        encoded = (canonical(final) + "\n").encode("utf-8")
        require(len(encoded) <= self.MAX_BYTES, "relay reset journal exceeds bound")
        current = os.lstat(self.path)
        require(stat.S_ISREG(current.st_mode) and stat.S_IMODE(current.st_mode) == 0o600, "relay reset journal identity changed")
        fd, name = tempfile.mkstemp(prefix=".relay-reset-journal-", dir=self.path.parent)
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
    MAX_BYTES = 2 * 1024 * 1024

    def __init__(self, path: Path) -> None:
        self.path = _ensure_private_parent(path, "receipt")
        require(not self.path.exists() and not self.path.is_symlink(), "relay reset receipt must be absent")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.path, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
        parent_fd = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        self.value: dict[str, Any] | None = None

    def commit(self, value: dict[str, Any]) -> None:
        require(self.value is None, "receipt is immutable")
        _reject_secret_values(value)
        final = copy.deepcopy(value)
        final["canonicalSha256"] = digest(value)
        encoded = (canonical(final) + "\n").encode("utf-8")
        require(len(encoded) <= self.MAX_BYTES, "relay reset receipt exceeds bound")
        fd, name = tempfile.mkstemp(prefix=".relay-reset-receipt-", dir=self.path.parent)
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


class PublicHttpsAdapter:
    """Exact-origin HTTPS probe with verified TLS, no proxy, redirects, or caller URL."""

    ALLOWED = {
        ("GET", WORKBENCH_CONFIG_PATH),
        ("GET", WORKBENCH_FEED_PATH),
        ("POST", WORKBENCH_GATE_PROBE_PATH),
    }

    def _request(self, method: str, path: str) -> tuple[int, bytes]:
        require((method, path) in self.ALLOWED, "public HTTPS probe outside relay reset scope")
        context = ssl.create_default_context()
        require(context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname is True, "public HTTPS TLS verification disabled")
        connection = http.client.HTTPSConnection(
            PUBLIC_ORIGIN_HOST,
            443,
            timeout=PUBLIC_HTTPS_TIMEOUT_SECONDS,
            context=context,
        )
        try:
            connection.request(method, path, body=b"" if method == "POST" else None, headers={"Accept": "application/json", "Connection": "close"})
            response = connection.getresponse()
            body = response.read(PUBLIC_HTTPS_MAX_BODY_BYTES + 1)
            require(len(body) <= PUBLIC_HTTPS_MAX_BODY_BYTES, "public HTTPS response exceeds bound")
            return response.status, body
        except (OSError, ssl.SSLError, http.client.HTTPException) as error:
            raise TransportUncertain(f"public HTTPS {method} {path} failed: {_bounded_error(error)}") from error
        finally:
            connection.close()

    def get_workbench(self, path: str) -> dict[str, Any]:
        require(path in {WORKBENCH_CONFIG_PATH, WORKBENCH_FEED_PATH}, "workbench GET path outside relay reset scope")
        status, body = self._request("GET", path)
        require(status == 200, f"public HTTPS GET {path} returned {status}", PostconditionFailure)
        return parse_object(body, f"public HTTPS GET {path}")

    def probe_gate(self) -> int:
        status, body = self._request("POST", WORKBENCH_GATE_PROBE_PATH)
        require(len(body) <= 4096, "write-gate probe body exceeds bound")
        return status


def _relay_inventory_script(component: str, *, profile: bool) -> str:
    require(component in COMPONENT_ORDER, "relay inventory component outside reset scope")
    require(profile is (component == "agent-relay") or profile is False, "profile inventory outside agent relay")
    # This descriptor-fixed script never prints file contents.  The profile
    # branch is replaced below by the full cryptographic checker; both branches
    # emit the same closed, value-free record.
    applicable = "true" if component == "citizen-relay" else "false"
    expected_name = "Röbel E2E Bürger-Relay" if component == "citizen-relay" else "Röbel E2E Mecky-Relay"
    profile_json = "null"
    script = (
        "'use strict';const fs=require('fs'),http=require('http');"
        "const stat=(p,a)=>{if(!a)return {applicable:false,present:false,bytes:0,records:0};"
        "if(!fs.existsSync(p))return {applicable:true,present:false,bytes:0,records:0};"
        "const n=fs.statSync(p).size;return {applicable:true,present:true,bytes:n,records:n===0?0:-1}};"
        "const event=()=>{const p='/relay/events.ndjson';if(!fs.existsSync(p))return {present:false,bytes:0,records:0};"
        "const n=fs.statSync(p).size;return {present:true,bytes:n,records:n===0?0:-1}};"
        "const q=http.get({host:'127.0.0.1',port:18081,path:'/healthz',timeout:3000},r=>{"
        "let b='';r.setEncoding('utf8');r.on('data',c=>{b+=c;if(b.length>4096)q.destroy(new Error('bounded'))});"
        "r.on('end',()=>{if(r.statusCode!==200)throw new Error('health');const h=JSON.parse(b),e=event(),"
        "v=h&&Object.keys(h).sort().join(',')==='events,name,ok'&&h.name===__EXPECTED__;"
        "if(e.records<0)e.records=Number.isSafeInteger(h.events)?h.events:0;console.log(JSON.stringify({health:{ok:h.ok===true,identityVerified:v,events:Number.isSafeInteger(h.events)&&h.events>=0?h.events:0},eventStore:e,"
        "admissionStore:stat('/relay/admissions.ndjson',__APPLICABLE__),profile:__PROFILE__}))});"
        "q.on('timeout',()=>q.destroy(new Error('timeout')));q.on('error',()=>process.exit(2));"
    )
    return script.replace("__APPLICABLE__", applicable).replace("__PROFILE__", profile_json).replace("__EXPECTED__", json.dumps(expected_name, ensure_ascii=True))


RELAY_INVENTORY_SCRIPTS = {
    component: _relay_inventory_script(component, profile=False)
    for component in COMPONENT_ORDER
}

# Fixed, dependency-free NIP-01/BIP340 verification performed inside the
# agent-relay Pod.  Only counts and booleans leave the Pod; no event, content,
# author key, signature, or Secret value is printed.
MECKY_PROFILE_SCRIPT = r'''const fs=require("fs"),http=require("http"),crypto=require("crypto");
const PATH="/relay/events.ndjson",MAX=67108864,PH="e3f9abfd377f323afd82cb225630ce96030b544fda7829f4d312b7350980225d",NAME="Mecky · E2E",ABOUT="KI-Assistent von Röbel/Müritz E2E. Antwortet, wenn man ihn erwähnt.",TAG=["netizen_agent","mecky","roebel-e2e"];
const H=x=>crypto.createHash("sha256").update(x).digest(),P=2n**256n-2n**32n-977n,N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n,mod=x=>(x%P+P)%P;
const pow=(x,n)=>{let r=1n;for(x=mod(x);n;n>>=1n,x=mod(x*x))if(n&1n)r=mod(r*x);return r};
const dbl=a=>{let[X,Y,Z]=a;if(!Z||!Y)return[0n,1n,0n];let y=mod(Y*Y),s=mod(4n*X*y),m=mod(3n*X*X),x=mod(m*m-2n*s);return[x,mod(m*(s-x)-8n*y*y),mod(2n*Y*Z)]};
const add=(a,b)=>{let[X,Y,Z]=a,[x,y,z]=b;if(!Z)return b;if(!z)return a;let Z2=mod(Z*Z),z2=mod(z*z),u=mod(X*z2),v=mod(x*Z2),s=mod(Y*z*z2),t=mod(y*Z*Z2);if(u===v)return s===t?dbl(a):[0n,1n,0n];let h=mod(v-u),i=mod(4n*h*h),j=mod(h*i),r=mod(2n*(t-s)),q=mod(u*i),X3=mod(r*r-j-2n*q);return[X3,mod(r*(q-X3)-2n*s*j),mod(((Z+z)*(Z+z)-Z2-z2)*h)]};
const mul=(k,p)=>{let r=[0n,1n,0n];for(;k;k>>=1n,p=dbl(p))if(k&1n)r=add(r,p);return r},BI=b=>BigInt("0x"+Buffer.from(b).toString("hex"));
const tagged=(tag,b)=>{const t=H(Buffer.from(tag,"utf8"));return H(Buffer.concat([t,t,b]))},G=[0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n,0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n,1n];
const schnorr=(sig,msg,pk)=>{try{const r=BI(sig.subarray(0,32)),s=BI(sig.subarray(32)),x=BI(pk);if(r>=P||s>=N||x>=P)return false;const c=mod(x*x*x+7n);let y=pow(c,(P+1n)/4n);if(mod(y*y)!==c)return false;if(y&1n)y=P-y;const e=BI(tagged("BIP0340/challenge",Buffer.concat([sig.subarray(0,32),pk,msg])))%N,R=add(mul(s,G),mul(N-e,[x,y,1n]));if(!R[2])return false;const z=pow(R[2],P-2n),xx=mod(R[0]*z*z),yy=mod(R[1]*z*z*z);return !(yy&1n)&&xx===r}catch{return false}};
const health=()=>new Promise((resolve,reject)=>{const q=http.get({host:"127.0.0.1",port:18081,path:"/healthz",method:"GET",agent:false,timeout:3000},r=>{let n=0,a=[];r.on("data",c=>{n+=c.length;if(n>4096)q.destroy(new Error("bounded"));else a.push(c)});r.on("end",()=>{try{resolve({status:r.statusCode,body:JSON.parse(Buffer.concat(a).toString("utf8"))})}catch(e){reject(e)}})});q.on("timeout",()=>q.destroy(new Error("timeout")));q.on("error",reject)});
const p={kind0Count:0,kind1Count:0,validKind0Count:0,expectedAuthorHash:false,eventIdVerified:false,signatureVerified:false,bot:false,identityVerified:false,aboutNonempty:false,agentTagVerified:false};
(async()=>{let raw=Buffer.alloc(0),events=[],present=false,stable=false;try{const st=fs.statSync(PATH);if(!st.isFile()||st.size>MAX)throw 0;present=true;raw=fs.readFileSync(PATH);if(raw.length>MAX)throw 0;let text=new TextDecoder("utf-8",{fatal:true}).decode(raw);if(text.endsWith("\n"))text=text.slice(0,-1);const lines=text===""?[]:text.split("\n");if(lines.length>50000||lines.some(x=>x===""||x.includes("\r")))throw 0;events=lines.map(JSON.parse);stable=H(raw).equals(H(fs.readFileSync(PATH)))}catch{}p.kind0Count=events.filter(e=>e&&e.kind===0).length;p.kind1Count=events.filter(e=>e&&e.kind===1).length;
if(events.length===1&&p.kind0Count===1){const e=events[0],h64=/^[0-9a-f]{64}$/,h128=/^[0-9a-f]{128}$/;const shape=e&&typeof e==="object"&&!Array.isArray(e)&&Object.keys(e).sort().join(",")==="content,created_at,id,kind,pubkey,sig,tags"&&h64.test(e.id)&&h64.test(e.pubkey)&&h128.test(e.sig)&&Number.isSafeInteger(e.created_at)&&e.created_at>=0&&typeof e.content==="string"&&Array.isArray(e.tags)&&e.tags.every(t=>Array.isArray(t)&&t.length<=32&&t.every(x=>typeof x==="string"));if(shape){p.expectedAuthorHash=H(Buffer.from(e.pubkey,"utf8")).toString("hex")===PH;try{const c=JSON.parse(e.content);const exact=c&&typeof c==="object"&&!Array.isArray(c)&&Object.keys(c).sort().join(",")==="about,bot,name";p.bot=exact&&c.bot===true;p.identityVerified=p.bot&&c.name===NAME;p.aboutNonempty=c.about===ABOUT}catch{}p.agentTagVerified=e.tags.length===1&&JSON.stringify(e.tags[0])===JSON.stringify(TAG);const msg=H(Buffer.from(JSON.stringify([0,e.pubkey,e.created_at,e.kind,e.tags,e.content]),"utf8"));p.eventIdVerified=msg.toString("hex")===e.id;p.signatureVerified=p.eventIdVerified&&schnorr(Buffer.from(e.sig,"hex"),msg,Buffer.from(e.pubkey,"hex"));p.validKind0Count=Object.entries(p).filter(([k])=>!k.endsWith("Count")).every(([,v])=>v===true)?1:0}}
let healthBody={ok:false,name:"",events:-1};try{const response=await health();if(response.status===200&&response.body&&Object.keys(response.body).sort().join(",")==="events,name,ok")healthBody=response.body}catch{}const healthOut={ok:healthBody.ok===true,identityVerified:healthBody.name==="Röbel E2E Mecky-Relay",events:Number.isSafeInteger(healthBody.events)&&healthBody.events>=0?healthBody.events:0};const eventStore={present,bytes:raw.length,records:events.length};if(!stable){p.validKind0Count=0;p.signatureVerified=false}process.stdout.write(JSON.stringify({health:healthOut,eventStore,admissionStore:{applicable:false,present:false,bytes:0,records:0},profile:p})+"\n")})().catch(()=>process.stdout.write(JSON.stringify({health:{ok:false,identityVerified:false,events:0},eventStore:{present:false,bytes:0,records:0},admissionStore:{applicable:false,present:false,bytes:0,records:0},profile:p})+"\n"));'''


class KubernetesAdapter:
    """Pinned kubectl transport exposing only the reviewed fixed capabilities."""

    def __init__(self, kubeconfig: str, *, kubectl: Path = KUBECTL_BIN) -> None:
        selected = Path(kubeconfig).absolute()
        info = os.lstat(selected)
        require(
            stat.S_ISREG(info.st_mode)
            and not selected.is_symlink()
            and info.st_uid == os.geteuid()
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) & 0o077 == 0,
            "kubeconfig must be an owner-only regular file",
        )
        executable = os.lstat(kubectl)
        require(
            stat.S_ISREG(executable.st_mode)
            and not Path(kubectl).is_symlink()
            and os.access(kubectl, os.X_OK),
            "kubectl executable invalid",
        )
        require(bytes_digest(Path(kubectl).read_bytes()) == KUBECTL_SHA256, "kubectl executable digest drift")
        self.kubeconfig = str(selected)
        self.kubectl = Path(kubectl)
        self.read_only_exec_requests = 0

    def _run(
        self,
        args: list[str],
        *,
        input_text: str | None = None,
        timeout: float = 40,
    ) -> subprocess.CompletedProcess[str]:
        environment = {
            key: value
            for key, value in os.environ.items()
            if key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy", "kubeconfig", "pythonpath"}
        }
        environment.update({"NO_PROXY": "*", "no_proxy": "*"})
        return subprocess.run(
            [str(self.kubectl), "--kubeconfig", self.kubeconfig, "--request-timeout=30s", *args],
            env=environment,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )

    @staticmethod
    def _kind(target: dict[str, str]) -> str:
        return {
            "Deployment": "deployment.apps",
            "Service": "service",
            "ServiceAccount": "serviceaccount",
            "NetworkPolicy": "networkpolicy.networking.k8s.io",
            "Ingress": "ingress.networking.k8s.io",
            "Kustomization": "kustomization.kustomize.toolkit.fluxcd.io",
        }.get(target["kind"], target["kind"].lower())

    def get(self, target: dict[str, str]) -> dict[str, Any] | None:
        require(canonical(target) in {canonical(item) for item in ALLOWED_GET_TARGETS}, "GET target outside relay reset scope")
        result = self._run(["-n", target["namespace"], "get", self._kind(target), target["name"], "-o", "json"])
        if result.returncode != 0:
            message = _bounded_error(result.stderr or result.stdout)
            lowered = message.lower()
            if "notfound" in lowered or "not found" in lowered or re.search(r"\b404\b", lowered):
                return None
            raise TransportUncertain(f"GET {target['kind']}/{target['name']} failed: {message}")
        return parse_object(result.stdout, f"GET {target['kind']}/{target['name']}")

    def get_pods(self, component: str) -> list[dict[str, Any]]:
        require(component in (*COMPONENT_ORDER, PUBLIC_MECKY_NAME), "Pod list component outside relay reset scope")
        labels = PUBLIC_MECKY_LABELS if component == PUBLIC_MECKY_NAME else relay_labels(component)
        selector = ",".join(f"{key}={value}" for key, value in sorted(labels.items()))
        result = self._run(["-n", NAMESPACE, "get", "pods", "-l", selector, "-o", "json"])
        if result.returncode != 0:
            raise TransportUncertain(f"GET {component} Pods failed: {_bounded_error(result.stderr)}")
        value = parse_object(result.stdout, f"GET {component} Pods")
        require(isinstance(value.get("items"), list), f"GET {component} Pods items invalid")
        return value["items"]

    def get_replica_sets(self, component: str) -> list[dict[str, Any]]:
        require(component in (*COMPONENT_ORDER, PUBLIC_MECKY_NAME), "ReplicaSet list component outside relay reset scope")
        labels = PUBLIC_MECKY_LABELS if component == PUBLIC_MECKY_NAME else relay_labels(component)
        selector = ",".join(f"{key}={value}" for key, value in sorted(labels.items()))
        result = self._run(["-n", NAMESPACE, "get", "replicasets.apps", "-l", selector, "-o", "json"])
        if result.returncode != 0:
            raise TransportUncertain(f"GET {component} ReplicaSets failed: {_bounded_error(result.stderr)}")
        value = parse_object(result.stdout, f"GET {component} ReplicaSets")
        require(isinstance(value.get("items"), list), f"GET {component} ReplicaSets items invalid")
        return value["items"]

    def get_endpoint_slices(self, component: str) -> list[dict[str, Any]]:
        require(component in (*COMPONENT_ORDER, PUBLIC_MECKY_NAME), "EndpointSlice target outside relay reset scope")
        result = self._run([
            "-n", NAMESPACE, "get", "endpointslices.discovery.k8s.io",
            "-l", f"{ENDPOINT_SLICE_LABEL}={component}", "-o", "json",
        ])
        if result.returncode != 0:
            raise TransportUncertain(f"GET {component} EndpointSlices failed: {_bounded_error(result.stderr)}")
        value = parse_object(result.stdout, f"GET {component} EndpointSlices")
        require(isinstance(value.get("items"), list), f"GET {component} EndpointSlices items invalid")
        return value["items"]

    def get_network_policies(self) -> list[dict[str, Any]]:
        result = self._run(["-n", NAMESPACE, "get", "networkpolicies.networking.k8s.io", "-o", "json"])
        if result.returncode != 0:
            raise TransportUncertain(f"GET namespace NetworkPolicies failed: {_bounded_error(result.stderr or result.stdout)}")
        value = parse_object(result.stdout, "GET namespace NetworkPolicies")
        require(isinstance(value.get("items"), list), "GET namespace NetworkPolicies items invalid")
        return value["items"]

    def inspect_relay(self, component: str, pod_name: str, *, profile: bool = False) -> dict[str, Any]:
        require(component in COMPONENT_ORDER, "relay exec component outside reset scope")
        require(isinstance(pod_name, str) and DNS_LABEL_RE.fullmatch(pod_name) is not None and pod_name.startswith(f"{component}-"), "relay exec Pod outside reset scope")
        require(profile is (component == "agent-relay") or profile is False, "profile exec outside agent relay")
        script = MECKY_PROFILE_SCRIPT if profile else RELAY_INVENTORY_SCRIPTS[component]
        self.read_only_exec_requests += 1
        result = self._run(["-n", NAMESPACE, "exec", pod_name, "-c", component, "--", "/usr/local/bin/node", "-e", script], timeout=15)
        if result.returncode != 0:
            raise TransportUncertain(f"fixed {component} inventory exec failed: {_bounded_error(result.stderr or result.stdout)}")
        require(result.stderr == "", f"fixed {component} inventory exec emitted stderr")
        require(len(result.stdout.encode("utf-8")) <= 4096, f"fixed {component} inventory output exceeds bound")
        return parse_object(result.stdout, f"fixed {component} inventory")

    @staticmethod
    def _patch_shape(operations: Any, *, target: str) -> None:
        require(isinstance(operations, list) and all(isinstance(item, dict) for item in operations), f"{target} JSON Patch invalid")
        require(all(set(item) <= {"op", "path", "value"} and item.get("op") in {"test", "add", "replace", "remove"} for item in operations), f"{target} JSON Patch widened")

    def patch_ingress(self, operations: list[dict[str, Any]]) -> dict[str, Any]:
        self._patch_shape(operations, target="Ingress")
        annotation_path = "/metadata/annotations/" + WORKBENCH_INGRESS_ANNOTATION.replace("~", "~0").replace("/", "~1")
        require(len(operations) == 6 and [item.get("op") for item in operations] == ["test", "test", "test", "test", "test", "replace"], "Ingress patch shape widened")
        require([item.get("path") for item in operations] == ["/metadata/uid", "/metadata/resourceVersion", "/metadata/generation", "/spec", annotation_path, annotation_path], "Ingress patch paths widened")
        require(operations[-1].get("value") in {WORKBENCH_INGRESS_OPEN, WORKBENCH_INGRESS_GATED}, "Ingress patch value widened")
        result = self._run(["-n", NAMESPACE, "patch", "ingress", WORKBENCH_INGRESS_NAME, "--type=json", "-p", canonical(operations), "-o", "json"])
        if result.returncode != 0:
            raise TransportUncertain(f"PATCH workbench Ingress outcome uncertain: {_bounded_error(result.stderr or result.stdout)}")
        return parse_object(result.stdout, "PATCH workbench Ingress")

    def patch_public_mecky_kustomization(self, operations: list[dict[str, Any]]) -> dict[str, Any]:
        self._patch_shape(operations, target="Kustomization")
        require(
            len(operations) == 4
            and [item.get("op") for item in operations[:3]] == ["test", "test", "test"]
            and [item.get("path") for item in operations[:3]] == ["/metadata/uid", "/metadata/resourceVersion", "/spec"]
            and operations[0].get("value") == PUBLIC_MECKY_KUSTOMIZATION_UID
            and isinstance(operations[1].get("value"), str)
            and isinstance(operations[2].get("value"), dict)
            and operations[-1].get("path") == "/spec/suspend"
            and (
                (operations[-1].get("op") in {"add", "replace"} and isinstance(operations[-1].get("value"), bool))
                or (operations[-1] == {"op": "remove", "path": "/spec/suspend"})
            ),
            "Kustomization patch shape widened",
        )
        result = self._run(["-n", FLUX_NAMESPACE, "patch", "kustomization", PUBLIC_MECKY_KUSTOMIZATION, "--type=json", "-p", canonical(operations), "-o", "json"])
        if result.returncode != 0:
            raise TransportUncertain(f"PATCH public-mecky Kustomization outcome uncertain: {_bounded_error(result.stderr or result.stdout)}")
        return parse_object(result.stdout, "PATCH public-mecky Kustomization")

    def patch_public_mecky_deployment(self, operations: list[dict[str, Any]]) -> dict[str, Any]:
        self._patch_shape(operations, target="public-mecky Deployment")
        require(
            len(operations) == 5
            and [item.get("op") for item in operations] == ["test", "test", "test", "test", "replace"]
            and [item.get("path") for item in operations] == ["/metadata/uid", "/metadata/resourceVersion", "/spec", "/spec/replicas", "/spec/replicas"]
            and operations[0].get("value") == PUBLIC_MECKY_UID
            and isinstance(operations[1].get("value"), str)
            and isinstance(operations[2].get("value"), dict)
            and (operations[3].get("value"), operations[4].get("value")) in {(1, 0), (0, 1)},
            "public-mecky Deployment patch shape widened",
        )
        result = self._run(["-n", NAMESPACE, "patch", "deployment", PUBLIC_MECKY_NAME, "--type=json", "-p", canonical(operations), "-o", "json"])
        if result.returncode != 0:
            raise TransportUncertain(f"PATCH public-mecky Deployment outcome uncertain: {_bounded_error(result.stderr or result.stdout)}")
        return parse_object(result.stdout, "PATCH public-mecky Deployment")

    def delete_pod(self, component: str, pod_name: str, options: dict[str, Any]) -> dict[str, Any]:
        require(component in COMPONENT_ORDER, "Pod DELETE component outside relay reset scope")
        require(isinstance(pod_name, str) and DNS_LABEL_RE.fullmatch(pod_name) is not None and pod_name.startswith(f"{component}-"), "Pod DELETE name outside relay reset scope")
        require(isinstance(options, dict), "Pod DeleteOptions must be an object")
        require(options == {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": options.get("preconditions")}, "Pod DeleteOptions fields widened")
        preconditions = options.get("preconditions")
        require(isinstance(preconditions, dict) and set(preconditions) == {"uid", "resourceVersion"}, "Pod DeleteOptions preconditions drift")
        _validate_uuid(preconditions["uid"], "Pod DeleteOptions")
        _validate_resource_version(preconditions["resourceVersion"], "Pod DeleteOptions")
        raw_path = f"/api/v1/namespaces/{NAMESPACE}/pods/{urllib.parse.quote(pod_name, safe='')}"
        result = self._run(["delete", "--raw", raw_path, "-f", "-"], input_text=canonical(options))
        if result.returncode != 0:
            raise TransportUncertain(f"DELETE Pod/{pod_name} outcome uncertain: {_bounded_error(result.stderr or result.stdout)}")
        return parse_object(result.stdout, f"DELETE Pod/{pod_name}")


def _get_required(kube: Any, target: dict[str, str], label: str) -> dict[str, Any]:
    try:
        value = kube.get(target)
    except RelayResetError:
        raise
    except Exception as error:
        raise TransportUncertain(f"GET {label} failed: {_bounded_error(error)}") from error
    require(value is not None and isinstance(value, dict), f"GET {label} returned NotFound", PostconditionFailure)
    return value


def _participant_inactive_proof(kube: Any) -> dict[str, Any]:
    absent: list[dict[str, str]] = []
    for target in PARTICIPANT_RUNTIME_TARGETS:
        try:
            value = kube.get(target)
        except RelayResetError:
            raise
        except Exception as error:
            raise TransportUncertain(f"GET participant target failed: {_bounded_error(error)}") from error
        require(value is None, f"participant gateway activation resource present: {target['kind']}/{target['name']}")
        absent.append(copy.deepcopy(target))
    flux: list[dict[str, Any]] = []
    for target in PARTICIPANT_KUSTOMIZATIONS:
        try:
            value = kube.get(target)
        except RelayResetError:
            raise
        except Exception as error:
            raise TransportUncertain(f"GET participant Kustomization failed: {_bounded_error(error)}") from error
        if value is None:
            flux.append({"target": copy.deepcopy(target), "state": "absent"})
            continue
        _validate_target(value, target, f"participant Kustomization {target['name']}")
        metadata = _metadata(value, f"participant Kustomization {target['name']}")
        uid = _validate_uuid(metadata.get("uid"), f"participant Kustomization {target['name']}")
        resource_version = _validate_resource_version(metadata.get("resourceVersion"), f"participant Kustomization {target['name']}")
        spec = value.get("spec")
        require(isinstance(spec, dict) and spec.get("suspend") is True, f"participant Kustomization active: {target['name']}")
        flux.append({"target": copy.deepcopy(target), "state": "suspended", "uid": uid, "resourceVersion": resource_version, "specSha256": digest(spec)})
    return {
        "status": "no-active-participant-gateway",
        "runtimeTargets": absent,
        "fluxReconcilers": flux,
        "secretValuesRead": False,
    }


def _delete_discovery(kube: Any, component: str, before_pod: dict[str, Any]) -> str:
    """Perform one read-only classification after a lost DELETE response."""
    try:
        pods = kube.get_pods(component)
    except Exception:
        return "ambiguous"
    if not isinstance(pods, list):
        return "ambiguous"
    uids = [
        _metadata(item, f"{component} discovery Pod").get("uid")
        for item in pods
        if isinstance(item, dict)
    ]
    if before_pod["uid"] not in uids:
        return "old-pod-absent"
    if len(pods) == 1:
        metadata = _metadata(pods[0], f"{component} discovery Pod")
        if metadata.get("uid") == before_pod["uid"] and metadata.get("deletionTimestamp") is None:
            return "old-pod-still-present"
    return "ambiguous"


def _same_ingress_except_policy(current: dict[str, Any], expected: dict[str, Any], policy: str) -> bool:
    candidate = copy.deepcopy(current["object"])
    baseline = copy.deepcopy(expected["object"])
    for value in (candidate, baseline):
        value.get("metadata", {}).get("annotations", {}).pop(WORKBENCH_INGRESS_ANNOTATION, None)
    return candidate == baseline and current["specSha256"] == expected["specSha256"] and current["policy"] == policy


def _public_summary(public: Any, *, empty: bool) -> dict[str, Any]:
    config = validate_workbench_config(public.get_workbench(WORKBENCH_CONFIG_PATH))
    feed = validate_workbench_feed(public.get_workbench(WORKBENCH_FEED_PATH), empty=empty)
    return {"config": config, "feed": feed}


def _relay_runtime_snapshot(kube: Any, component: str, *, empty: bool) -> tuple[dict[str, Any], dict[str, Any]]:
    deployment = validate_deployment(_get_required(kube, deployment_target(component), f"{component} Deployment"), component)
    service = validate_service(_get_required(kube, service_target(component), f"{component} Service"), component)
    pod = validate_ready_owned_pod(kube.get_pods(component), kube.get_replica_sets(component), component)
    endpoint = validate_endpoint_slices(kube.get_endpoint_slices(component), component, pod)
    inventory = validate_relay_inventory(kube.inspect_relay(component, pod["name"], profile=False), component, empty=empty)
    return {"deployment": deployment, "service": service}, {"pod": pod, "endpointSlice": endpoint, "inventory": inventory}


def _public_mecky_snapshot(kube: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    deployment = validate_public_mecky_deployment(_get_required(kube, public_mecky_deployment_target(), "public-mecky Deployment"), replicas=1)
    service = validate_public_mecky_service(_get_required(kube, public_mecky_service_target(), "public-mecky Service"))
    kustomization = validate_public_mecky_kustomization(_get_required(kube, public_mecky_kustomization_target(), "public-mecky Kustomization"), suspended=False)
    pod = validate_public_mecky_ready_pod(kube.get_pods(PUBLIC_MECKY_NAME), kube.get_replica_sets(PUBLIC_MECKY_NAME))
    endpoint = validate_endpoint_slices(kube.get_endpoint_slices(PUBLIC_MECKY_NAME), PUBLIC_MECKY_NAME, pod)
    return {"deployment": deployment, "service": service, "kustomization": kustomization}, {"pod": pod, "endpointSlice": endpoint}


def _preflight_v2(kube: Any, public: Any) -> dict[str, Any]:
    participant = _participant_inactive_proof(kube)
    ingress = validate_workbench_ingress(_get_required(kube, workbench_ingress_target(), "workbench Ingress"), expected_policy=WORKBENCH_INGRESS_OPEN)
    require(public.probe_gate() == 404, "open workbench gate probe did not reach the application", PostconditionFailure)
    workbench = _public_summary(public, empty=False)
    policies = validate_network_policy_inventory(kube.get_network_policies())
    resources: dict[str, Any] = {}
    runtime: dict[str, Any] = {}
    for component in COMPONENT_ORDER:
        resources[component], runtime[component] = _relay_runtime_snapshot(kube, component, empty=False)
    mecky, mecky_runtime = _public_mecky_snapshot(kube)
    require(runtime["citizen-relay"]["inventory"]["admissionStore"]["bytes"] == 0, "citizen admissions are not zero", PostconditionFailure)
    return {
        "resources": resources,
        "runtime": runtime,
        "networkPolicies": policies,
        "workbench": workbench,
        "ingress": ingress,
        "publicMecky": mecky,
        "publicMeckyRuntime": mecky_runtime,
        "participantAdmissionBoundary": {
            **participant,
            "realAdmissionObserved": False,
            "writeIngressQuiescent": False,
            "admissionStoreZeroProven": True,
            "proofScope": "participant-runtime-absence;synthetic-feed;citizen-admissions-file-zero",
            "admissionStoreContentRead": False,
        },
    }


def _verify_gate(kube: Any, public: Any, before: dict[str, Any], *, expected_policy: str, probe_status: int, feed_empty: bool | None) -> dict[str, Any]:
    current = validate_workbench_ingress(_get_required(kube, workbench_ingress_target(), "workbench Ingress gate verification"), expected_policy=expected_policy)
    require(_same_ingress_except_policy(current, before["ingress"], expected_policy), "workbench Ingress changed outside exact gate annotation", PostconditionFailure)
    require(public.probe_gate() == probe_status, f"workbench gate enforcement did not return {probe_status}", PostconditionFailure)
    if feed_empty is None:
        config = validate_workbench_config(public.get_workbench(WORKBENCH_CONFIG_PATH))
        raw_feed = public.get_workbench(WORKBENCH_FEED_PATH)
        posts = raw_feed.get("posts") if isinstance(raw_feed, dict) else None
        feed = validate_workbench_feed(raw_feed, empty=isinstance(posts, list) and not posts)
        summary = {"config": config, "feed": feed}
    else:
        summary = _public_summary(public, empty=feed_empty)
    require(summary["config"] == before["workbench"]["config"], "workbench config changed while gating", PostconditionFailure)
    return {"ingress": current, "public": summary, "probeStatus": probe_status}


def _quiet_gate_observations(
    kube: Any,
    public: Any,
    before: dict[str, Any],
    *,
    count: int,
    interval_seconds: float,
    sleep_fn: Callable[[float], None],
) -> list[dict[str, Any]]:
    require(count == DEFAULT_QUIET_OBSERVATIONS, "quiet observation count drift")
    require(interval_seconds == DEFAULT_QUIET_INTERVAL_SECONDS, "quiet observation interval drift")
    observations: list[dict[str, Any]] = []
    baseline: dict[str, Any] | None = None
    for index in range(count):
        gate = _verify_gate(kube, public, before, expected_policy=WORKBENCH_INGRESS_GATED, probe_status=405, feed_empty=False)
        relays: dict[str, Any] = {}
        for component in COMPONENT_ORDER:
            pod = before["runtime"][component]["pod"]
            inventory = validate_relay_inventory(kube.inspect_relay(component, pod["name"], profile=False), component, empty=False)
            relays[component] = inventory
        value = {
            "feedSha256": gate["public"]["feed"]["canonicalSha256"],
            "ingressObjectSha256": gate["ingress"]["objectSha256"],
            "relayInventorySha256": digest(relays),
            "admissionStoreZero": relays["citizen-relay"]["admissionStore"]["bytes"] == 0,
        }
        require(value["admissionStoreZero"] is True, "citizen admission store changed during quiet window", PostconditionFailure)
        if baseline is None:
            baseline = value
        else:
            require(value == baseline, "gated quiet observation drift", PostconditionFailure)
        observations.append(value)
        if index + 1 < count:
            sleep_fn(interval_seconds)
    return observations


def _wait_relay_replacement_v2(
    kube: Any,
    component: str,
    before_pod: dict[str, Any],
    *,
    timeout_seconds: float,
    sleep_fn: Callable[[float], None],
    monotonic_fn: Callable[[], float],
) -> dict[str, Any]:
    deadline = monotonic_fn() + timeout_seconds
    while True:
        try:
            pod = validate_ready_owned_pod(kube.get_pods(component), kube.get_replica_sets(component), component)
            require(pod["uid"] != before_pod["uid"], f"{component} Pod UID did not change", PostconditionFailure)
            endpoint = validate_endpoint_slices(kube.get_endpoint_slices(component), component, pod)
            inventory = validate_relay_inventory(kube.inspect_relay(component, pod["name"], profile=False), component, empty=True)
            return {"pod": pod, "endpointSlice": endpoint, "inventory": inventory}
        except (PostconditionFailure, TransportUncertain, RelayResetError):
            if monotonic_fn() >= deadline:
                raise PostconditionFailure(f"{component} replacement did not become ready, bound, and empty")
            sleep_fn(min(1.0, max(0.0, deadline - monotonic_fn())))


def _wait_public_mecky_zero(
    kube: Any,
    *,
    timeout_seconds: float,
    sleep_fn: Callable[[float], None],
    monotonic_fn: Callable[[], float],
) -> dict[str, Any]:
    deadline = monotonic_fn() + timeout_seconds
    while True:
        try:
            deployment = validate_public_mecky_deployment(_get_required(kube, public_mecky_deployment_target(), "public-mecky zero Deployment"), replicas=0)
            require(kube.get_pods(PUBLIC_MECKY_NAME) == [], "public-mecky Pod still present at zero", PostconditionFailure)
            return deployment
        except (PostconditionFailure, TransportUncertain, RelayResetError):
            if monotonic_fn() >= deadline:
                raise PostconditionFailure("public-mecky did not scale to zero")
            sleep_fn(min(1.0, max(0.0, deadline - monotonic_fn())))


def _wait_public_mecky_ready(
    kube: Any,
    old_pod_uid: str,
    *,
    timeout_seconds: float,
    sleep_fn: Callable[[float], None],
    monotonic_fn: Callable[[], float],
) -> dict[str, Any]:
    deadline = monotonic_fn() + timeout_seconds
    while True:
        try:
            deployment = validate_public_mecky_deployment(_get_required(kube, public_mecky_deployment_target(), "public-mecky restored Deployment"), replicas=1)
            pod = validate_public_mecky_ready_pod(kube.get_pods(PUBLIC_MECKY_NAME), kube.get_replica_sets(PUBLIC_MECKY_NAME))
            require(pod["uid"] != old_pod_uid, "public-mecky Pod UID did not change", PostconditionFailure)
            endpoint = validate_endpoint_slices(kube.get_endpoint_slices(PUBLIC_MECKY_NAME), PUBLIC_MECKY_NAME, pod)
            agent_pod = validate_ready_owned_pod(kube.get_pods("agent-relay"), kube.get_replica_sets("agent-relay"), "agent-relay")
            profile = validate_relay_inventory(kube.inspect_relay("agent-relay", agent_pod["name"], profile=True), "agent-relay", empty=False, profile=True)
            return {"deployment": deployment, "pod": pod, "endpointSlice": endpoint, "profile": profile["profile"], "agentInventory": profile}
        except (PostconditionFailure, TransportUncertain, RelayResetError):
            if monotonic_fn() >= deadline:
                raise PostconditionFailure("public-mecky did not restart and publish the exact profile")
            sleep_fn(min(1.0, max(0.0, deadline - monotonic_fn())))


def _classify_ingress(kube: Any, desired: str, before: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    try:
        current = validate_workbench_ingress(_get_required(kube, workbench_ingress_target(), "Ingress classification"), expected_policy=desired)
        if _same_ingress_except_policy(current, before["ingress"], desired):
            return "desired-observed", current
    except Exception:
        pass
    return "ambiguous", None


def _classify_kustomization(kube: Any, suspended: bool, baseline: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    try:
        value = _validate_target(_get_required(kube, public_mecky_kustomization_target(), "Kustomization classification"), public_mecky_kustomization_target(), "Kustomization classification")
        metadata = _metadata(value, "Kustomization classification")
        current = {
            "uid": _validate_uuid(metadata.get("uid"), "Kustomization classification"),
            "resourceVersion": _validate_resource_version(metadata.get("resourceVersion"), "Kustomization classification"),
            "generation": _validate_generation(metadata.get("generation"), "Kustomization classification"),
            "suspended": suspended,
            "suspendExplicit": "suspend" in value.get("spec", {}),
            "spec": copy.deepcopy(value.get("spec")),
        }
        require(isinstance(current["spec"], dict), "Kustomization classification spec absent")
        expected = copy.deepcopy(baseline["spec"])
        observed = copy.deepcopy(current["spec"])
        if suspended:
            expected["suspend"] = True
        if observed != expected or current["uid"] != baseline["uid"]:
            return "ambiguous", None
        return "desired-observed", current
    except Exception:
        return "ambiguous", None


def _classify_mecky_replicas(kube: Any, replicas: int, baseline: dict[str, Any], *, source_replicas: int | None = None) -> tuple[str, dict[str, Any] | None]:
    try:
        value = _validate_target(_get_required(kube, public_mecky_deployment_target(), "Deployment classification"), public_mecky_deployment_target(), "Deployment classification")
        metadata = _metadata(value, "Deployment classification")
        uid = _validate_uuid(metadata.get("uid"), "Deployment classification")
        resource_version = _validate_resource_version(metadata.get("resourceVersion"), "Deployment classification")
        spec = value.get("spec")
        require(isinstance(spec, dict), "Deployment classification spec absent")
        current = {"uid": uid, "resourceVersion": resource_version, "spec": copy.deepcopy(spec), "replicas": replicas}
        expected = copy.deepcopy(baseline["spec"])
        expected["replicas"] = replicas
        if current["uid"] == baseline["uid"] and current["spec"] == expected:
            return "desired-observed", current
        if source_replicas is not None:
            source = copy.deepcopy(baseline["spec"])
            source["replicas"] = source_replicas
            if current["uid"] == baseline["uid"] and current["spec"] == source:
                return "source-observed", current
        return "ambiguous", None
    except Exception:
        return "ambiguous", None


def _wait_kustomization_restored(
    kube: Any,
    baseline: dict[str, Any],
    *,
    timeout_seconds: float,
    sleep_fn: Callable[[float], None],
    monotonic_fn: Callable[[], float],
) -> dict[str, Any]:
    deadline = monotonic_fn() + timeout_seconds
    while True:
        try:
            current = validate_public_mecky_kustomization(_get_required(kube, public_mecky_kustomization_target(), "restored public-mecky Kustomization"), suspended=False)
            require(current["uid"] == baseline["uid"] and current["spec"] == baseline["spec"], "restored Kustomization spec drift", PostconditionFailure)
            return current
        except (PostconditionFailure, TransportUncertain, RelayResetError):
            if monotonic_fn() >= deadline:
                raise PostconditionFailure("public-mecky Kustomization restore did not become Ready")
            sleep_fn(min(1.0, max(0.0, deadline - monotonic_fn())))


def _same_spec_identity(current: dict[str, Any], before: dict[str, Any]) -> bool:
    return (
        current["uid"] == before["uid"]
        and current["generation"] >= before["generation"]
        and current["spec"] == before["spec"]
        and current["specSha256"] == before["specSha256"]
    )


def _final_preservation(kube: Any, public: Any, before: dict[str, Any]) -> dict[str, Any]:
    resources: dict[str, Any] = {}
    runtime: dict[str, Any] = {}
    for component in COMPONENT_ORDER:
        if component == "citizen-relay":
            resource, running = _relay_runtime_snapshot(kube, component, empty=True)
        else:
            deployment = validate_deployment(_get_required(kube, deployment_target(component), f"{component} Deployment"), component)
            service = validate_service(_get_required(kube, service_target(component), f"{component} Service"), component)
            pod = validate_ready_owned_pod(kube.get_pods(component), kube.get_replica_sets(component), component)
            endpoint = validate_endpoint_slices(kube.get_endpoint_slices(component), component, pod)
            inventory = validate_relay_inventory(kube.inspect_relay(component, pod["name"], profile=True), component, empty=False, profile=True)
            resource = {"deployment": deployment, "service": service}
            running = {"pod": pod, "endpointSlice": endpoint, "inventory": inventory}
        expected = before["resources"][component]
        require(_same_spec_identity(resource["deployment"], expected["deployment"]), f"{component} Deployment changed", PostconditionFailure)
        require(resource["service"]["uid"] == expected["service"]["uid"] and resource["service"]["object"] == expected["service"]["object"], f"{component} Service changed", PostconditionFailure)
        resources[component] = resource
        runtime[component] = running
    policies = validate_network_policy_inventory(kube.get_network_policies())
    require(policies == before["networkPolicies"], "namespace NetworkPolicy inventory changed", PostconditionFailure)
    mecky, mecky_runtime = _public_mecky_snapshot(kube)
    require(_same_spec_identity(mecky["deployment"], before["publicMecky"]["deployment"]), "public-mecky Deployment changed outside temporary replicas", PostconditionFailure)
    require(mecky["service"] == before["publicMecky"]["service"], "public-mecky Service changed", PostconditionFailure)
    require(mecky["kustomization"]["uid"] == before["publicMecky"]["kustomization"]["uid"] and mecky["kustomization"]["spec"] == before["publicMecky"]["kustomization"]["spec"], "public-mecky Kustomization not restored", PostconditionFailure)
    ingress = validate_workbench_ingress(_get_required(kube, workbench_ingress_target(), "restored workbench Ingress"), expected_policy=WORKBENCH_INGRESS_OPEN)
    require(ingress["object"] == before["ingress"]["object"], "workbench Ingress not exactly restored", PostconditionFailure)
    participant = _participant_inactive_proof(kube)
    require(participant == {key: before["participantAdmissionBoundary"][key] for key in participant}, "participant inactive boundary changed", PostconditionFailure)
    require(public.probe_gate() == 404, "restored workbench POST probe did not reach application", PostconditionFailure)
    first = _public_summary(public, empty=True)
    second = _public_summary(public, empty=True)
    require(first == second and first["config"] == before["workbench"]["config"], "restored public feed/config observations drift", PostconditionFailure)
    return {
        "resources": resources,
        "runtime": runtime,
        "networkPolicies": policies,
        "publicMecky": mecky,
        "publicMeckyRuntime": mecky_runtime,
        "ingress": ingress,
        "participantGateway": participant,
        "feed": first["feed"],
        "feedObservations": [first["feed"], second["feed"]],
        "exact": True,
    }


def _initial_journal(pin: dict[str, Any], operation_id: str, revision: str, hashes: dict[str, str]) -> dict[str, Any]:
    return {
        "schemaVersion": JOURNAL_SCHEMA,
        "status": "preflight",
        "operationId": operation_id,
        "protectedRevision": revision,
        "protectedGitBlobSha256": copy.deepcopy(hashes),
        "artifact": copy.deepcopy(pin),
        "namespace": NAMESPACE,
        "sequence": [
            "gate-workbench", "suspend-public-mecky", "scale-public-mecky-zero",
            "delete-citizen-relay", "delete-agent-relay", "scale-public-mecky-one",
            "restore-public-mecky-flux", "restore-workbench-gate",
        ],
        "before": None,
        "gate": None,
        "meckyLifecycle": None,
        "resets": [],
        "after": None,
        "restoration": None,
        "events": [],
    }


def _receipt_base(pin: dict[str, Any], operation_id: str, revision: str, hashes: dict[str, str]) -> dict[str, Any]:
    return {
        "schemaVersion": RECEIPT_SCHEMA,
        "status": "reserved",
        "operationId": operation_id,
        "protectedRevision": revision,
        "protectedGitBlobSha256": copy.deepcopy(hashes),
        "artifact": copy.deepcopy(pin),
        "mode": "live-one-shot",
        "namespace": NAMESPACE,
        "sequence": [
            "gate-workbench", "suspend-public-mecky", "scale-public-mecky-zero",
            "delete-citizen-relay", "delete-agent-relay", "scale-public-mecky-one",
            "restore-public-mecky-flux", "restore-workbench-gate",
        ],
        "before": None,
        "gate": {"applied": False, "quietObservations": [], "restored": False},
        "meckyLifecycle": {
            "fluxSuspended": False,
            "scaledToZero": False,
            "scaledToOne": False,
            "profile": None,
            "fluxRestored": False,
        },
        "resets": [],
        "after": None,
        "restoration": {
            "required": False,
            "scaleUp": {"attempted": False, "proven": False},
            "flux": {"attempted": False, "proven": False},
            "ingress": {"attempted": False, "proven": False},
            "complete": False,
        },
        "uncertainOutcome": None,
        "failure": None,
        "authority": {
            "civicAuthority": "none",
            "municipalDecision": False,
            "voteMutation": False,
            "treasuryMutation": False,
        },
        "effects": {
            "clusterMutationAttempted": False,
            "ingressPatchRequests": 0,
            "kustomizationPatchRequests": 0,
            "deploymentPatchRequests": 0,
            "podDeleteRequests": 0,
            "readOnlyExecRequests": 0,
            "secretValuesRead": False,
            "eventContentsEmitted": False,
            "publicKeysEmitted": False,
            "civicAuthorityEffects": False,
            "admissionStoreContentRead": False,
            "dataRollbackPossible": False,
            "automaticMutationRetry": False,
        },
    }


def _failure_code(error: Exception) -> str:
    if isinstance(error, TransportUncertain):
        return "transport_uncertain"
    if isinstance(error, PostconditionFailure):
        return "postcondition_failed"
    if isinstance(error, RelayResetInterrupted):
        return "operator_interrupted"
    return "precondition_failed"


def _journal_commit(journal: Any, state: dict[str, Any], operation: str, stage: str, details: dict[str, Any] | None = None) -> None:
    _event(state, operation, stage, details)
    journal.commit(state)


def _finalize(
    journal: Any,
    state: dict[str, Any],
    receipt_sink: Any,
    receipt: dict[str, Any],
    status: str,
) -> dict[str, Any]:
    receipt["status"] = status
    receipt["completedAt"] = _now()
    state["status"] = status
    _event(state, "transaction", "final", {"status": status})
    journal.commit(state)
    _reject_secret_values(receipt)
    request_sha = digest(receipt)
    _journal_commit(journal, state, "receipt", "intent", {"requestSha256": request_sha, "status": status})
    try:
        receipt_sink.commit(receipt)
    except Exception as error:
        state["status"] = "finalization-uncertain"
        try:
            _journal_commit(journal, state, "receipt", "uncertain", {"requestSha256": request_sha})
        finally:
            raise RelayResetError(f"relay reset receipt finalization uncertain: {_bounded_error(error)}") from error
    _journal_commit(journal, state, "receipt", "after", {"requestSha256": request_sha, "status": status})
    return receipt


def _execute_live_transaction(
    *,
    kube: Any,
    public: Any,
    artifact_pin: Path,
    receipt: Any,
    journal: Any,
    protected_revision: str,
    protected_hashes: dict[str, str],
    operation_id: str | None = None,
    replacement_timeout_seconds: float = DEFAULT_REPLACEMENT_TIMEOUT_SECONDS,
    sleep_fn: Callable[[float], None] = time.sleep,
    monotonic_fn: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Execute the reviewed one-shot transaction and mandatory restorations."""
    pin = validate_artifact_pin(artifact_pin)
    revision, hashes = validate_protected_binding(protected_revision, protected_hashes)
    require(isinstance(replacement_timeout_seconds, (int, float)) and 0 < replacement_timeout_seconds <= 300, "replacement timeout invalid")
    require(journal.load() is None, "relay reset journal resume is forbidden; inspect and start a newly reviewed operation")
    operation_id = operation_id or str(uuid.uuid4())
    _validate_uuid(operation_id, "relay reset operation")
    state = _initial_journal(pin, operation_id, revision, hashes)
    journal.commit(state)
    result = _receipt_base(pin, operation_id, revision, hashes)
    before: dict[str, Any] | None = None
    stage = "preflight"
    primary_error: Exception | None = None
    gate_active = False
    gate_outcome_unknown = False
    flux_suspended = False
    flux_outcome_unknown = False
    mecky_scaled_down = False
    mecky_ready = False
    mecky_outcome_unknown = False
    scale_up_attempted = False
    destructive_started = False
    old_mecky_pod_uid: str | None = None

    try:
        before = _preflight_v2(kube, public)
        old_mecky_pod_uid = before["publicMeckyRuntime"]["pod"]["uid"]
        mecky_ready = True
        result["before"] = _project_value_free_evidence(before)
        state["before"] = _project_value_free_evidence(before)
        _journal_commit(journal, state, "preflight", "after", {
            "snapshotSha256": digest(before),
            "feedSha256": before["workbench"]["feed"]["canonicalSha256"],
            "admissionStoreZero": True,
            "participantInactive": True,
        })
    except Exception as error:
        result["failure"] = {"failureCode": _failure_code(error), "stage": "preflight"}
        result["effects"]["readOnlyExecRequests"] = getattr(kube, "read_only_exec_requests", 0)
        return _finalize(journal, state, receipt, result, "preflight-failed")

    try:
        # 1. Gate the only public write surface admitted by this transaction.
        stage = "gate-workbench"
        gate_patch = ingress_patch(before["ingress"], WORKBENCH_INGRESS_OPEN, WORKBENCH_INGRESS_GATED)
        gate_sha = digest(gate_patch)
        _journal_commit(journal, state, stage, "intent", {"target": workbench_ingress_target(), "requestSha256": gate_sha, "transition": "GET-HEAD-POST-to-GET-HEAD"})
        result["effects"]["clusterMutationAttempted"] = True
        result["effects"]["ingressPatchRequests"] += 1
        try:
            response = validate_workbench_ingress(kube.patch_ingress(gate_patch), expected_policy=WORKBENCH_INGRESS_GATED)
            require(_same_ingress_except_policy(response, before["ingress"], WORKBENCH_INGRESS_GATED), "Ingress gate response changed another field", PostconditionFailure)
            gate_active = True
            _journal_commit(journal, state, stage, "after", {"requestSha256": gate_sha, "desiredStateObserved": True})
        except Exception as error:
            classification, observed = _classify_ingress(kube, WORKBENCH_INGRESS_GATED, before)
            _journal_commit(journal, state, stage, "classified", {"requestSha256": gate_sha, "classification": classification, "mutationRetried": False})
            if classification != "desired-observed" or observed is None:
                gate_outcome_unknown = True
                raise TransportUncertain("workbench Ingress gate outcome unproven") from error
            gate_active = True
        result["gate"]["applied"] = True
        result["restoration"]["required"] = True
        state["gate"] = copy.deepcopy(result["gate"])
        result["gate"]["quietObservations"] = _quiet_gate_observations(
            kube, public, before,
            count=DEFAULT_QUIET_OBSERVATIONS,
            interval_seconds=DEFAULT_QUIET_INTERVAL_SECONDS,
            sleep_fn=sleep_fn,
        )

        # 2. Suspend Flux before changing its managed Deployment.
        stage = "suspend-public-mecky"
        current_flux = validate_public_mecky_kustomization(_get_required(kube, public_mecky_kustomization_target(), "public-mecky Kustomization before suspend"), suspended=False)
        require(current_flux["uid"] == before["publicMecky"]["kustomization"]["uid"] and current_flux["spec"] == before["publicMecky"]["kustomization"]["spec"], "public-mecky Kustomization drifted after preflight", PostconditionFailure)
        suspend_patch = kustomization_suspend_patch(current_flux, False, True)
        suspend_sha = digest(suspend_patch)
        _journal_commit(journal, state, stage, "intent", {"target": public_mecky_kustomization_target(), "requestSha256": suspend_sha, "transition": "false-to-true"})
        result["effects"]["kustomizationPatchRequests"] += 1
        try:
            suspended_response = validate_public_mecky_kustomization(kube.patch_public_mecky_kustomization(suspend_patch), suspended=True)
            expected_suspended_spec = copy.deepcopy(before["publicMecky"]["kustomization"]["spec"])
            expected_suspended_spec["suspend"] = True
            require(suspended_response["spec"] == expected_suspended_spec, "public-mecky Kustomization suspend response widened", PostconditionFailure)
            flux_suspended = True
            _journal_commit(journal, state, stage, "after", {"requestSha256": suspend_sha, "desiredStateObserved": True})
        except Exception as error:
            classification, observed = _classify_kustomization(kube, True, before["publicMecky"]["kustomization"])
            _journal_commit(journal, state, stage, "classified", {"requestSha256": suspend_sha, "classification": classification, "mutationRetried": False})
            if classification != "desired-observed" or observed is None:
                flux_outcome_unknown = True
                raise TransportUncertain("public-mecky Kustomization suspend outcome unproven") from error
            flux_suspended = True
        result["meckyLifecycle"]["fluxSuspended"] = True

        # 3. Scale the exact workload to zero and prove no selected Pod remains.
        stage = "scale-public-mecky-zero"
        _verify_gate(kube, public, before, expected_policy=WORKBENCH_INGRESS_GATED, probe_status=405, feed_empty=False)
        current_deployment = validate_public_mecky_deployment(_get_required(kube, public_mecky_deployment_target(), "public-mecky Deployment before scale-down"), replicas=1)
        require(current_deployment["uid"] == before["publicMecky"]["deployment"]["uid"] and current_deployment["spec"] == before["publicMecky"]["deployment"]["spec"], "public-mecky Deployment drifted after preflight", PostconditionFailure)
        down_patch = deployment_replicas_patch(current_deployment, 1, 0)
        down_sha = digest(down_patch)
        _journal_commit(journal, state, stage, "intent", {"target": public_mecky_deployment_target(), "requestSha256": down_sha, "transition": "1-to-0"})
        result["effects"]["deploymentPatchRequests"] += 1
        mecky_ready = False
        try:
            response = kube.patch_public_mecky_deployment(down_patch)
            require(_metadata(response, "public-mecky scale-down response").get("uid") == PUBLIC_MECKY_UID and response.get("spec", {}).get("replicas") == 0, "public-mecky scale-down response drift", TransportUncertain)
            expected_down_spec = copy.deepcopy(before["publicMecky"]["deployment"]["spec"])
            expected_down_spec["replicas"] = 0
            require(response.get("spec") == expected_down_spec, "public-mecky scale-down response widened", PostconditionFailure)
            mecky_scaled_down = True
            _journal_commit(journal, state, stage, "after", {"requestSha256": down_sha, "requestAccepted": True})
        except Exception as error:
            classification, observed = _classify_mecky_replicas(kube, 0, before["publicMecky"]["deployment"], source_replicas=1)
            _journal_commit(journal, state, stage, "classified", {"requestSha256": down_sha, "classification": classification, "mutationRetried": False})
            if classification == "source-observed":
                mecky_ready = True
                raise TransportUncertain("public-mecky scale-down request did not apply") from error
            if classification != "desired-observed" or observed is None:
                mecky_outcome_unknown = True
                raise TransportUncertain("public-mecky scale-down outcome unproven") from error
            mecky_scaled_down = True
        zero = _wait_public_mecky_zero(kube, timeout_seconds=replacement_timeout_seconds, sleep_fn=sleep_fn, monotonic_fn=monotonic_fn)
        result["meckyLifecycle"]["scaledToZero"] = True
        _journal_commit(journal, state, "wait-public-mecky-zero", "after", {"deploymentSha256": zero["specSha256"], "selectedPodCount": 0})

        # 4. Destructive relay recreation, citizen first and fully proven before agent.
        for component in COMPONENT_ORDER:
            stage = f"delete-{component}-pod"
            _verify_gate(
                kube, public, before,
                expected_policy=WORKBENCH_INGRESS_GATED,
                probe_status=405,
                feed_empty=False if component == "citizen-relay" else None,
            )
            before_pod = before["runtime"][component]["pod"]
            request = delete_request(component, before_pod)
            request_sha = digest(request)
            _journal_commit(journal, state, stage, "intent", {
                "target": {"apiVersion": "v1", "kind": "Pod", "namespace": NAMESPACE, "name": before_pod["name"]},
                "uid": before_pod["uid"], "resourceVersion": before_pod["resourceVersion"], "requestSha256": request_sha,
            })
            destructive_started = True
            result["effects"]["podDeleteRequests"] += 1
            try:
                response = kube.delete_pod(component, before_pod["name"], request["body"])
                require(isinstance(response, dict), f"DELETE {component} response invalid", TransportUncertain)
                _journal_commit(journal, state, stage, "after", {"requestSha256": request_sha, "requestAccepted": True})
            except Exception as error:
                classification = _delete_discovery(kube, component, before_pod)
                _journal_commit(journal, state, stage, "classified", {"requestSha256": request_sha, "classification": classification, "mutationRetried": False})
                if classification != "old-pod-absent":
                    raise TransportUncertain(f"{component} Pod deletion outcome unproven") from error
            replacement = _wait_relay_replacement_v2(
                kube, component, before_pod,
                timeout_seconds=replacement_timeout_seconds,
                sleep_fn=sleep_fn,
                monotonic_fn=monotonic_fn,
            )
            reset = {
                "component": component,
                "oldPodUid": before_pod["uid"],
                "newPodUid": replacement["pod"]["uid"],
                "endpointBindingSha256": digest(replacement["endpointSlice"]),
                "eventStoreEmpty": True,
                "admissionStoreReset": component == "citizen-relay",
                "requestSha256": request_sha,
            }
            result["resets"].append(reset)
            state["resets"] = copy.deepcopy(result["resets"])
            _journal_commit(journal, state, f"wait-{component}-replacement", "after", reset)

        # 5. Bring up a fresh Mecky and prove the exact cryptographic profile.
        stage = "scale-public-mecky-one"
        _verify_gate(kube, public, before, expected_policy=WORKBENCH_INGRESS_GATED, probe_status=405, feed_empty=True)
        zero_current = validate_public_mecky_deployment(_get_required(kube, public_mecky_deployment_target(), "public-mecky Deployment before scale-up"), replicas=0)
        expected_zero_spec = copy.deepcopy(before["publicMecky"]["deployment"]["spec"])
        expected_zero_spec["replicas"] = 0
        require(zero_current["spec"] == expected_zero_spec, "public-mecky zero Deployment drifted", PostconditionFailure)
        up_patch = deployment_replicas_patch(zero_current, 0, 1)
        up_sha = digest(up_patch)
        _journal_commit(journal, state, stage, "intent", {"target": public_mecky_deployment_target(), "requestSha256": up_sha, "transition": "0-to-1"})
        result["effects"]["deploymentPatchRequests"] += 1
        scale_up_attempted = True
        try:
            response = kube.patch_public_mecky_deployment(up_patch)
            require(_metadata(response, "public-mecky scale-up response").get("uid") == PUBLIC_MECKY_UID and response.get("spec", {}).get("replicas") == 1, "public-mecky scale-up response drift", TransportUncertain)
            require(response.get("spec") == before["publicMecky"]["deployment"]["spec"], "public-mecky scale-up response widened", PostconditionFailure)
            mecky_scaled_down = False
            _journal_commit(journal, state, stage, "after", {"requestSha256": up_sha, "requestAccepted": True})
        except Exception as error:
            classification, observed = _classify_mecky_replicas(kube, 1, before["publicMecky"]["deployment"], source_replicas=0)
            _journal_commit(journal, state, stage, "classified", {"requestSha256": up_sha, "classification": classification, "mutationRetried": False})
            if classification == "source-observed":
                raise TransportUncertain("public-mecky scale-up request did not apply") from error
            if classification != "desired-observed" or observed is None:
                mecky_outcome_unknown = True
                raise TransportUncertain("public-mecky scale-up outcome unproven") from error
            mecky_scaled_down = False
        ready = _wait_public_mecky_ready(
            kube, old_mecky_pod_uid,
            timeout_seconds=replacement_timeout_seconds,
            sleep_fn=sleep_fn,
            monotonic_fn=monotonic_fn,
        )
        mecky_ready = True
        mecky_scaled_down = False
        result["meckyLifecycle"]["scaledToOne"] = True
        result["meckyLifecycle"]["profile"] = copy.deepcopy(ready["profile"])
        _journal_commit(journal, state, "wait-public-mecky-profile", "after", {"newPodUid": ready["pod"]["uid"], "profileProofSha256": digest(ready["profile"]), "kind0Count": 1, "kind1Count": 0})
    except Exception as error:
        primary_error = error
        result["failure"] = {"failureCode": _failure_code(error), "stage": stage}

    # Restoration coordinator: one attempt per outstanding mutation, in the
    # only safe order.  Never let an error bypass the public gate restoration.
    result["restoration"]["required"] = (
        gate_active or flux_suspended or mecky_scaled_down
        or gate_outcome_unknown or flux_outcome_unknown or mecky_outcome_unknown
    )
    if mecky_scaled_down and not scale_up_attempted:
        result["restoration"]["scaleUp"]["attempted"] = True
        stage_restore = "restore-public-mecky-scale"
        try:
            current = validate_public_mecky_deployment(_get_required(kube, public_mecky_deployment_target(), "public-mecky restoration Deployment"), replicas=0)
            expected_zero_spec = copy.deepcopy(before["publicMecky"]["deployment"]["spec"])
            expected_zero_spec["replicas"] = 0
            require(current["spec"] == expected_zero_spec, "public-mecky restoration Deployment drifted", PostconditionFailure)
            operations = deployment_replicas_patch(current, 0, 1)
            request_sha = digest(operations)
            _journal_commit(journal, state, stage_restore, "intent", {"target": public_mecky_deployment_target(), "requestSha256": request_sha, "transition": "0-to-1"})
            result["effects"]["deploymentPatchRequests"] += 1
            try:
                response = kube.patch_public_mecky_deployment(operations)
                require(_metadata(response, "public-mecky restoration response").get("uid") == PUBLIC_MECKY_UID and response.get("spec", {}).get("replicas") == 1, "public-mecky restoration response drift", TransportUncertain)
                require(response.get("spec") == before["publicMecky"]["deployment"]["spec"], "public-mecky restoration response widened", PostconditionFailure)
                _journal_commit(journal, state, stage_restore, "after", {"requestSha256": request_sha, "requestAccepted": True})
            except Exception as error:
                classification, observed = _classify_mecky_replicas(kube, 1, before["publicMecky"]["deployment"], source_replicas=0)
                _journal_commit(journal, state, stage_restore, "classified", {"requestSha256": request_sha, "classification": classification, "mutationRetried": False})
                if classification != "desired-observed" or observed is None:
                    mecky_outcome_unknown = classification == "ambiguous"
                    raise TransportUncertain("public-mecky restoration scale outcome unproven") from error
                mecky_scaled_down = False
            ready = _wait_public_mecky_ready(kube, old_mecky_pod_uid or "", timeout_seconds=replacement_timeout_seconds, sleep_fn=sleep_fn, monotonic_fn=monotonic_fn)
            mecky_ready = True
            mecky_scaled_down = False
            result["meckyLifecycle"]["scaledToOne"] = True
            result["meckyLifecycle"]["profile"] = copy.deepcopy(ready["profile"])
            result["restoration"]["scaleUp"]["proven"] = True
        except Exception as error:
            _journal_commit(journal, state, stage_restore, "uncertain", {"classification": "scale-up-or-profile-unproven", "mutationRetried": False})
            if primary_error is None:
                primary_error = error
                result["failure"] = {"failureCode": _failure_code(error), "stage": stage_restore}
    elif mecky_ready:
        result["restoration"]["scaleUp"] = {"attempted": False, "proven": True}

    if flux_suspended and mecky_ready:
        result["restoration"]["flux"]["attempted"] = True
        stage_restore = "restore-public-mecky-flux"
        try:
            current = validate_public_mecky_kustomization(_get_required(kube, public_mecky_kustomization_target(), "public-mecky Kustomization restoration"), suspended=True)
            expected_suspended_spec = copy.deepcopy(before["publicMecky"]["kustomization"]["spec"])
            expected_suspended_spec["suspend"] = True
            require(current["spec"] == expected_suspended_spec, "public-mecky suspended Kustomization drifted", PostconditionFailure)
            operations = kustomization_restore_patch(current, before["publicMecky"]["kustomization"])
            request_sha = digest(operations)
            _journal_commit(journal, state, stage_restore, "intent", {"target": public_mecky_kustomization_target(), "requestSha256": request_sha, "transition": "true-to-original-false"})
            result["effects"]["kustomizationPatchRequests"] += 1
            try:
                response_value = _validate_target(kube.patch_public_mecky_kustomization(operations), public_mecky_kustomization_target(), "Kustomization restore response")
                require(response_value.get("spec") == before["publicMecky"]["kustomization"]["spec"], "Kustomization restore response spec drift", PostconditionFailure)
                _journal_commit(journal, state, stage_restore, "after", {"requestSha256": request_sha, "desiredStateObserved": True})
            except Exception as error:
                classification, observed = _classify_kustomization(kube, False, before["publicMecky"]["kustomization"])
                _journal_commit(journal, state, stage_restore, "classified", {"requestSha256": request_sha, "classification": classification, "mutationRetried": False})
                if classification != "desired-observed" or observed is None or observed["spec"] != before["publicMecky"]["kustomization"]["spec"]:
                    flux_outcome_unknown = True
                    raise TransportUncertain("public-mecky Flux restoration outcome unproven") from error
            _wait_kustomization_restored(kube, before["publicMecky"]["kustomization"], timeout_seconds=replacement_timeout_seconds, sleep_fn=sleep_fn, monotonic_fn=monotonic_fn)
            flux_suspended = False
            result["meckyLifecycle"]["fluxRestored"] = True
            result["restoration"]["flux"]["proven"] = True
        except Exception as error:
            _journal_commit(journal, state, stage_restore, "uncertain", {"classification": "flux-restore-unproven", "mutationRetried": False})
            if primary_error is None:
                primary_error = error
                result["failure"] = {"failureCode": _failure_code(error), "stage": stage_restore}

    if gate_active:
        result["restoration"]["ingress"]["attempted"] = True
        stage_restore = "restore-workbench-gate"
        try:
            current = validate_workbench_ingress(_get_required(kube, workbench_ingress_target(), "workbench Ingress restoration"), expected_policy=WORKBENCH_INGRESS_GATED)
            operations = ingress_patch(current, WORKBENCH_INGRESS_GATED, WORKBENCH_INGRESS_OPEN)
            request_sha = digest(operations)
            _journal_commit(journal, state, stage_restore, "intent", {"target": workbench_ingress_target(), "requestSha256": request_sha, "transition": "GET-HEAD-to-GET-HEAD-POST"})
            result["effects"]["ingressPatchRequests"] += 1
            try:
                response = validate_workbench_ingress(kube.patch_ingress(operations), expected_policy=WORKBENCH_INGRESS_OPEN)
                require(response["object"] == before["ingress"]["object"], "Ingress restore response not exact", PostconditionFailure)
                _journal_commit(journal, state, stage_restore, "after", {"requestSha256": request_sha, "desiredStateObserved": True})
            except Exception as error:
                classification, observed = _classify_ingress(kube, WORKBENCH_INGRESS_OPEN, before)
                _journal_commit(journal, state, stage_restore, "classified", {"requestSha256": request_sha, "classification": classification, "mutationRetried": False})
                if classification != "desired-observed" or observed is None:
                    gate_outcome_unknown = True
                    raise TransportUncertain("workbench Ingress restoration outcome unproven") from error
            require(public.probe_gate() == 404, "restored workbench write route not publicly proven", PostconditionFailure)
            gate_active = False
            result["gate"]["restored"] = True
            result["restoration"]["ingress"]["proven"] = True
        except Exception as error:
            _journal_commit(journal, state, stage_restore, "uncertain", {"classification": "ingress-restore-unproven", "mutationRetried": False})
            if primary_error is None:
                primary_error = error
                result["failure"] = {"failureCode": _failure_code(error), "stage": stage_restore}
        if result["restoration"]["ingress"]["proven"]:
            try:
                restored_config = validate_workbench_config(public.get_workbench(WORKBENCH_CONFIG_PATH))
                require(restored_config == before["workbench"]["config"], "restored workbench config drift", PostconditionFailure)
                raw_feed = public.get_workbench(WORKBENCH_FEED_PATH)
                posts = raw_feed.get("posts") if isinstance(raw_feed, dict) else None
                validate_workbench_feed(raw_feed, empty=isinstance(posts, list) and not posts)
            except Exception as error:
                _journal_commit(journal, state, "restored-public-reads", "failed", {"gateStillRestored": True})
                if primary_error is None:
                    primary_error = error
                    result["failure"] = {"failureCode": _failure_code(error), "stage": "restored-public-reads"}

    restoration_complete = (
        (not gate_active) and (not flux_suspended) and (not mecky_scaled_down)
        and (not gate_outcome_unknown) and (not flux_outcome_unknown) and (not mecky_outcome_unknown)
    )
    result["restoration"]["complete"] = restoration_complete
    state["gate"] = copy.deepcopy(result["gate"])
    state["meckyLifecycle"] = copy.deepcopy(result["meckyLifecycle"])
    state["restoration"] = copy.deepcopy(result["restoration"])

    if primary_error is None and restoration_complete:
        try:
            after = _final_preservation(kube, public, before)
            result["after"] = _project_value_free_evidence(after)
            state["after"] = _project_value_free_evidence(after)
            _journal_commit(journal, state, "postconditions", "after", {"snapshotSha256": digest(after), "preservationExact": True, "emptyFeedObservations": 2})
        except Exception as error:
            primary_error = error
            result["failure"] = {"failureCode": _failure_code(error), "stage": "postconditions"}

    result["effects"]["readOnlyExecRequests"] = getattr(kube, "read_only_exec_requests", 0)
    state["resets"] = copy.deepcopy(result["resets"])
    if primary_error is None and restoration_complete and result["after"] is not None:
        return _finalize(journal, state, receipt, result, "completed")

    uncertain = destructive_started or not restoration_complete or isinstance(primary_error, TransportUncertain)
    if uncertain:
        result["uncertainOutcome"] = {
            "stage": result["failure"]["stage"] if result["failure"] else "restoration",
            "dataRollbackPossible": False,
            "mutationRetried": False,
            "manualInspectionRequired": True,
        }
    return _finalize(journal, state, receipt, result, "uncertain" if uncertain else "failed-restored")


def _run_transaction(
    *,
    kube: Any,
    public: Any,
    artifact_pin: Path,
    receipt: Any,
    journal: Any,
    protected_revision: str,
    protected_hashes: dict[str, str],
    operation_id: str | None = None,
    replacement_timeout_seconds: float = DEFAULT_REPLACEMENT_TIMEOUT_SECONDS,
    sleep_fn: Callable[[float], None] = time.sleep,
    monotonic_fn: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    require(LIVE_EXECUTION_ENABLED, "relay fixture reset live execution disabled")
    return _execute_live_transaction(
        kube=kube,
        public=public,
        artifact_pin=artifact_pin,
        receipt=receipt,
        journal=journal,
        protected_revision=protected_revision,
        protected_hashes=protected_hashes,
        operation_id=operation_id,
        replacement_timeout_seconds=replacement_timeout_seconds,
        sleep_fn=sleep_fn,
        monotonic_fn=monotonic_fn,
    )


TRANSACTION_SIGNALS = (signal.SIGINT, signal.SIGTERM)


def run(
    *,
    kube: Any,
    public: Any,
    artifact_pin: Path,
    receipt: Any,
    journal: Any,
    protected_revision: str,
    protected_hashes: dict[str, str],
    operation_id: str | None = None,
    replacement_timeout_seconds: float = DEFAULT_REPLACEMENT_TIMEOUT_SECONDS,
    sleep_fn: Callable[[float], None] = time.sleep,
    monotonic_fn: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    previous: dict[int, Any] = {}

    def interrupt(received: int, _frame: Any) -> None:
        raise RelayResetInterrupted(received)

    try:
        for signum in TRANSACTION_SIGNALS:
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, interrupt)
        return _run_transaction(
            kube=kube,
            public=public,
            artifact_pin=artifact_pin,
            receipt=receipt,
            journal=journal,
            protected_revision=protected_revision,
            protected_hashes=protected_hashes,
            operation_id=operation_id,
            replacement_timeout_seconds=replacement_timeout_seconds,
            sleep_fn=sleep_fn,
            monotonic_fn=monotonic_fn,
        )
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-pin", required=True, type=Path)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--journal", required=True, type=Path)
    parser.add_argument("--protected-revision", required=True)
    parser.add_argument("--protected-hashes", required=True)
    args = parser.parse_args(argv)
    require(LIVE_EXECUTION_ENABLED, "relay fixture reset live execution disabled")
    require(args.receipt.absolute() != args.journal.absolute(), "relay reset receipt and journal paths must be distinct")
    require(not args.receipt.exists() and not args.receipt.is_symlink(), "relay reset receipt must be absent")
    require(not args.journal.exists() and not args.journal.is_symlink(), "relay reset journal must be absent; resume is forbidden")
    protected_hashes = parse_object(args.protected_hashes, "protected Git blob hashes")
    validate_protected_binding(args.protected_revision, protected_hashes)
    validate_artifact_pin(args.artifact_pin)
    receipt = JsonReceipt(args.receipt)
    journal = JsonJournal(args.journal)
    kube = KubernetesAdapter(args.kubeconfig)
    public = PublicHttpsAdapter()
    result = run(
        kube=kube,
        public=public,
        artifact_pin=args.artifact_pin,
        receipt=receipt,
        journal=journal,
        protected_revision=args.protected_revision,
        protected_hashes=protected_hashes,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") == "completed" else 1


if __name__ == "__main__":
    if not (sys.flags.isolated and sys.flags.safe_path):
        print("staging relay fixture reset blocked: invoke with python3 -I", file=sys.stderr)
        raise SystemExit(2)
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (RelayResetError, OSError, subprocess.SubprocessError) as error:
        print(f"staging relay fixture reset blocked: {_bounded_error(error)}", file=sys.stderr)
        raise SystemExit(1) from error
