"""Protected, one-time GitOps handover for the existing E2E workbench policy.

The workbench is an existing synthetic test workload.  This module deliberately
does not own that workload, its Service, or any Secret.  It only hands the
existing NetworkPolicy to a new, suspended Flux Kustomization and changes the
old private-owner label to the public Operations owner.  The handover is
receipt-bound to the exact object UID and the exact pre-handover API response;
there is no name-only adoption path.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "roebel_staging_workbench_baseline_handover_v1"
PLAN_SCHEMA = "roebel_staging_workbench_baseline_handover_plan_v1"
RECEIPT_SCHEMA = "roebel_staging_workbench_baseline_handover_receipt_v1"
JOURNAL_SCHEMA = "roebel_staging_workbench_baseline_journal_v1"
JOURNAL_DEFAULT_SUFFIX = ".journal"
JOURNAL_DURABILITY = "fsync-temp-write-atomic-rename-owner-only"
JOURNAL_RECOVERY = "receipt-first-finalize-else-suspend-rollback"
JOURNAL_FINALIZATION = "journal-finalizing-before-receipt-then-terminal-state"
ROLLBACK_PENDING_STATUS = "pending"
FINAL_RECEIPT_STATUSES = {
    "completed",
    "rolled-back",
    "rollback-incomplete",
    "recovered-rolled-back",
    "recovered-rollback-incomplete",
}

BASELINE_ROOT = "reviewed-render/roebel-staging/workbench-baseline"
NETWORK_POLICY_PATH = f"{BASELINE_ROOT}/networkpolicy.json"
KUSTOMIZATION_PATH = f"{BASELINE_ROOT}/kustomization.yaml"
WORKBENCH_NAMESPACE = "stadtstack-roebel-staging-lab"
WORKBENCH_NAME = "e2e-workbench"
FLUX_NAMESPACE = "flux-roebel-staging"
FLUX_NAME = "roebel-staging-workbench-baseline"
RECONCILER_NAME = "roebel-staging-workbench-baseline-reconciler"
SOURCE_NAME = "roebel-staging-operations"
SOURCE_URL = "https://github.com/GiraeffleAeffle/roebel-staging-operations.git"

BASELINE_UID = "298b0f92-0d6b-4563-b141-f93aa8c8fd8f"
# This is the exact canonical API response digest retained by the participant
# bootstrap receipt.  It intentionally includes the pre-handover API identity
# so a stale or replaced policy cannot be adopted by this one-time operation.
BASELINE_BEFORE_DIGEST = "sha256:21c582036f38a54649b771a6dec1ba599ca859029a1c32246ef8aee6a00359c5"
OLD_OWNER = "stadtstack-operations-private"
NEW_OWNER = "roebel-staging-operations"
SSA_ANNOTATION = "kustomize.toolkit.fluxcd.io/ssa"
SSA_MODE = "Override"
FLUX_INVENTORY_NAME_LABEL = "kustomize.toolkit.fluxcd.io/name"
FLUX_INVENTORY_NAMESPACE_LABEL = "kustomize.toolkit.fluxcd.io/namespace"
FLUX_INVENTORY_LABELS = {
    FLUX_INVENTORY_NAME_LABEL: FLUX_NAME,
    FLUX_INVENTORY_NAMESPACE_LABEL: FLUX_NAMESPACE,
}
FLUX_READY_TIMEOUT_SECONDS = 120
FLUX_READY_POLL_SECONDS = 1
FLUX_DELETE_TIMEOUT_SECONDS = 30
FLUX_DELETE_POLL_SECONDS = 1
HANDOVER_OPERATION_ANNOTATION = "stadtstack.io/workbench-handover-operation"

REVISION = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

GIT_BIN = Path("/usr/bin/git")
KUBECTL_BIN = Path("/Users/max/.local/bin/kubectl-v1.36.0")

# These are the exact bytes which affect the protected handover.  The receipt
# records a SHA-256 for every one at the checked-out Git revision.
PROTECTED_PATHS = (
    "scripts/handover-staging-workbench-baseline.py",
    "scripts/workbench_baseline_handover.py",
    "scripts/verify-reviewed-render.py",
    "policy/repository-contract.json",
    NETWORK_POLICY_PATH,
    KUSTOMIZATION_PATH,
)


class HandoverError(RuntimeError):
    """A fail-closed precondition, mutation, or rollback failure."""


class Conflict(HandoverError):
    pass


class HandoverSignal(HandoverError):
    """An operator signal routed through the ordinary rollback path."""

    def __init__(self, signum: int) -> None:
        super().__init__(f"handover interrupted by signal {signum}")
        self.signum = signum


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HandoverError(message)


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value).encode()).hexdigest()


def bytes_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _json_object(raw: str | bytes, label: str) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, f"{label}: duplicate JSON key {key}")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError, HandoverError) as exc:
        raise HandoverError(f"{label}: invalid JSON") from exc
    require(isinstance(value, dict), f"{label}: JSON object required")
    return value


def _workbench_selector() -> dict[str, str]:
    return {
        "app.kubernetes.io/component": "e2e-workbench",
        "app.kubernetes.io/part-of": WORKBENCH_NAMESPACE,
    }


def _baseline_spec() -> dict[str, Any]:
    namespace = WORKBENCH_NAMESPACE
    return {
        "egress": [
            {
                "ports": [
                    {"port": 53, "protocol": "UDP"},
                    {"port": 53, "protocol": "TCP"},
                ],
                "to": [{
                    "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
                    "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
                }],
            },
            {
                "ports": [{"port": 18081, "protocol": "TCP"}],
                "to": [{"podSelector": {"matchLabels": {
                    "app.kubernetes.io/component": "citizen-relay",
                    "app.kubernetes.io/part-of": namespace,
                }}}],
            },
            {
                "ports": [{"port": 18081, "protocol": "TCP"}],
                "to": [{"podSelector": {"matchLabels": {
                    "app.kubernetes.io/component": "agent-relay",
                    "app.kubernetes.io/part-of": namespace,
                }}}],
            },
            {
                "ports": [
                    {"port": 18080, "protocol": "TCP"},
                    {"port": 18081, "protocol": "TCP"},
                ],
                "to": [{"podSelector": {"matchLabels": {
                    "app.kubernetes.io/component": "stadtstack-runtime",
                    "app.kubernetes.io/part-of": namespace,
                }}}],
            },
            {
                "ports": [{"port": 443, "protocol": "TCP"}],
                "to": [{"ipBlock": {"cidr": "34.111.230.52/32"}}],
            },
        ],
        "podSelector": {"matchLabels": _workbench_selector()},
        "policyTypes": ["Ingress", "Egress"],
    }


def expected_before_network_policy() -> dict[str, Any]:
    """Return the server-field-free predecessor of the live policy."""
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "labels": {
                **_workbench_selector(),
                "stadtstack.io/authority": "none",
                "stadtstack.io/owner": OLD_OWNER,
                "stadtstack.io/purpose": "workbench-baseline",
            },
            "name": WORKBENCH_NAME,
            "namespace": WORKBENCH_NAMESPACE,
        },
        "spec": _baseline_spec(),
    }


def expected_network_policy() -> dict[str, Any]:
    """Return the reviewed post-handover policy render."""
    value = expected_before_network_policy()
    value["metadata"]["labels"]["stadtstack.io/owner"] = NEW_OWNER
    value["metadata"]["annotations"] = {SSA_ANNOTATION: SSA_MODE}
    return value


FLUX_LABELS = {
    "app.kubernetes.io/component": "workbench-baseline",
    "app.kubernetes.io/name": FLUX_NAME,
    "app.kubernetes.io/part-of": "stadtstack",
    "stadtstack.io/authority": "none",
    "stadtstack.io/civic-authority": "none",
    "stadtstack.io/environment": "staging",
    "stadtstack.io/flux-tenant": "roebel-staging",
    "stadtstack.io/gitops-owner": "workbench-baseline",
}


def expected_flux_objects(*, suspended: bool = True) -> dict[str, dict[str, Any]]:
    """Return only the four bootstrap identities owned by this handover."""
    service_account = {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {
            "labels": copy.deepcopy(FLUX_LABELS),
            "name": RECONCILER_NAME,
            "namespace": FLUX_NAMESPACE,
        },
        "automountServiceAccountToken": False,
    }
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {
            "labels": copy.deepcopy(FLUX_LABELS),
            "name": RECONCILER_NAME,
            "namespace": WORKBENCH_NAMESPACE,
        },
        "rules": [{
            "apiGroups": ["networking.k8s.io"],
            "resourceNames": [WORKBENCH_NAME],
            "resources": ["networkpolicies"],
            "verbs": ["get", "patch", "update"],
        }],
    }
    role_binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {
            "labels": copy.deepcopy(FLUX_LABELS),
            "name": RECONCILER_NAME,
            "namespace": WORKBENCH_NAMESPACE,
        },
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": RECONCILER_NAME,
        },
        "subjects": [{
            "kind": "ServiceAccount",
            "name": RECONCILER_NAME,
            "namespace": FLUX_NAMESPACE,
        }],
    }
    kustomization = {
        "apiVersion": "kustomize.toolkit.fluxcd.io/v1",
        "kind": "Kustomization",
        "metadata": {
            "labels": copy.deepcopy(FLUX_LABELS),
            "name": FLUX_NAME,
            "namespace": FLUX_NAMESPACE,
        },
        "spec": {
            "deletionPolicy": "Orphan",
            "dependsOn": [],
            "force": False,
            "healthChecks": [],
            "interval": "5m",
            "path": f"./{BASELINE_ROOT}",
            "prune": False,
            "retryInterval": "30s",
            "serviceAccountName": RECONCILER_NAME,
            "sourceRef": {
                "kind": "GitRepository",
                "name": SOURCE_NAME,
                "namespace": FLUX_NAMESPACE,
            },
            "suspend": suspended,
            "targetNamespace": WORKBENCH_NAMESPACE,
            "timeout": "2m",
            "wait": True,
        },
    }
    return {
        "serviceAccount": service_account,
        "role": role,
        "roleBinding": role_binding,
        "kustomization": kustomization,
    }


def expected_kustomization_text() -> str:
    return (
        "apiVersion: kustomize.config.k8s.io/v1beta1\n"
        "kind: Kustomization\n"
        "resources:\n"
        "  - networkpolicy.json\n"
    )


def _server_fields(value: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(value)
    metadata = result.get("metadata")
    require(isinstance(metadata, dict), "Kubernetes object metadata absent")
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
    if not metadata.get("annotations"):
        metadata.pop("annotations", None)
    result.pop("status", None)
    return result


def _flux_server_fields(value: dict[str, Any]) -> dict[str, Any]:
    """Normalize only documented Flux controller metadata.

    Flux adds its finalizer to a Kustomization after creation.  It is
    controller-owned metadata, not a desired-state input.  Inventory labels on
    a reconciled managed resource are deliberately *not* removed here: they
    are part of the post-reconcile proof and are admitted only by the exact
    inventory projection below.
    """
    result = _server_fields(value)
    if result.get("kind") in {"GitRepository", "Kustomization"}:
        metadata = result["metadata"]
        if metadata.get("finalizers") == ["finalizers.fluxcd.io"]:
            metadata.pop("finalizers")
    return result


def validate_network_policy(value: Any, *, final: bool) -> dict[str, Any]:
    require(isinstance(value, dict), "workbench baseline NetworkPolicy must be an object")
    expected = expected_network_policy() if final else expected_before_network_policy()
    require(_server_fields(value) == expected, "workbench baseline NetworkPolicy semantic drift")
    return copy.deepcopy(expected)


def expected_reconciled_network_policy() -> dict[str, Any]:
    """Return the exact policy after Flux inventory bookkeeping.

    Kustomize-controller adds these two labels to managed resources.  They
    are the only metadata additions admitted after the handover's explicit
    SSA Override marker; policy spec and all non-inventory labels stay exact.
    """
    value = expected_network_policy()
    value["metadata"]["labels"].update(copy.deepcopy(FLUX_INVENTORY_LABELS))
    return value


def validate_reconciled_network_policy(value: Any) -> dict[str, Any]:
    require(isinstance(value, dict), "reconciled workbench NetworkPolicy must be an object")
    expected = expected_reconciled_network_policy()
    require(_server_fields(value) == expected, "reconciled workbench NetworkPolicy metadata drift")
    require(value.get("spec") == expected["spec"], "reconciled workbench NetworkPolicy spec drift")
    require(value["metadata"]["labels"].get(FLUX_INVENTORY_NAME_LABEL) == FLUX_NAME, "Flux inventory name label drift")
    require(value["metadata"]["labels"].get(FLUX_INVENTORY_NAMESPACE_LABEL) == FLUX_NAMESPACE, "Flux inventory namespace label drift")
    return copy.deepcopy(expected)


def validate_kustomization_text(value: str) -> str:
    require(value == expected_kustomization_text(), "workbench baseline Kustomization path widened")
    return value


def validate_render(root: Path) -> dict[str, Any]:
    policy = validate_network_policy(_json_object((root / NETWORK_POLICY_PATH).read_bytes(), NETWORK_POLICY_PATH), final=True)
    kustomization = validate_kustomization_text((root / KUSTOMIZATION_PATH).read_text())
    return {"networkPolicy": policy, "kustomization": kustomization}


def target(value: dict[str, Any]) -> dict[str, str]:
    metadata = value.get("metadata", {})
    require(isinstance(metadata, dict), "managed object metadata absent")
    return {
        "apiVersion": value["apiVersion"],
        "kind": value["kind"],
        "name": metadata["name"],
        "namespace": metadata["namespace"],
    }


def object_order() -> tuple[str, ...]:
    return ("serviceAccount", "role", "roleBinding", "kustomization")


def validate_flux_objects(objects: dict[str, dict[str, Any]], *, suspended: bool) -> None:
    expected = expected_flux_objects(suspended=suspended)
    require(set(objects) == set(expected), "workbench baseline Flux object set drift")
    for name in object_order():
        require(_flux_server_fields(objects[name]) == expected[name], f"workbench baseline Flux {name} drift")


def expected_source_projection() -> dict[str, Any]:
    """The shared Operations GitRepository this transaction only observes."""
    return {
        "apiVersion": "source.toolkit.fluxcd.io/v1",
        "kind": "GitRepository",
        "metadata": {
            "labels": {"stadtstack.io/flux-tenant": "roebel-staging"},
            "name": SOURCE_NAME,
            "namespace": FLUX_NAMESPACE,
        },
        "spec": {
            "interval": "1m",
            "ref": {"branch": "main"},
            "suspend": False,
            "timeout": "30s",
            "url": SOURCE_URL,
        },
    }


def source_target() -> dict[str, str]:
    return target(expected_source_projection())


def validate_source(value: Any, protected_revision: str) -> dict[str, Any]:
    require(isinstance(value, dict), "shared Flux source absent")
    require(_flux_server_fields(value) == expected_source_projection(), "shared Flux source projection drift")
    uid, resource_version = _identity_metadata(value, "shared Flux source")
    metadata = value["metadata"]
    generation = metadata.get("generation")
    require(isinstance(generation, int) and generation > 0, "shared Flux source generation invalid")
    status = value.get("status")
    require(isinstance(status, dict), "shared Flux source status absent")
    expected_revision = f"main@sha1:{revision(protected_revision)}"
    require(status.get("artifact", {}).get("revision") == expected_revision, "shared Flux source artifact revision drift")
    require(status.get("observedGeneration") == generation, "shared Flux source generation not observed")
    ready = next((condition for condition in status.get("conditions", []) if condition.get("type") == "Ready"), None)
    require(isinstance(ready, dict) and ready.get("status") == "True", "shared Flux source not Ready")
    if "observedGeneration" in ready:
        require(ready["observedGeneration"] == generation, "shared Flux source Ready generation drift")
    return {
        "uid": uid,
        "resourceVersion": resource_version,
        "generation": generation,
        "observedGeneration": status["observedGeneration"],
        "artifactRevision": expected_revision,
        "ready": True,
    }


def validate_flux_ready(value: Any, uid: str, protected_revision: str) -> dict[str, Any]:
    require(isinstance(value, dict), "workbench baseline Kustomization absent")
    actual_uid, resource_version = _identity_metadata(value, "workbench baseline Kustomization")
    require(actual_uid == uid, "workbench baseline Kustomization UID changed")
    require(_flux_server_fields(value) == expected_flux_objects(suspended=False)["kustomization"], "workbench baseline Kustomization semantic drift")
    metadata = value["metadata"]
    generation = metadata.get("generation")
    require(isinstance(generation, int) and generation > 0, "workbench baseline Kustomization generation invalid")
    require(value["spec"].get("suspend") is False, "workbench baseline Kustomization remains suspended")
    status = value.get("status")
    require(isinstance(status, dict), "workbench baseline Kustomization status absent")
    require(status.get("observedGeneration") == generation, "workbench baseline Kustomization observedGeneration drift")
    ready = next((condition for condition in status.get("conditions", []) if condition.get("type") == "Ready"), None)
    require(isinstance(ready, dict) and ready.get("status") == "True", "workbench baseline Kustomization not Ready")
    if "observedGeneration" in ready:
        require(ready["observedGeneration"] == generation, "workbench baseline Kustomization Ready generation drift")
    expected_revision = f"main@sha1:{revision(protected_revision)}"
    require(status.get("lastAppliedRevision") == expected_revision, "workbench baseline Kustomization applied revision drift")
    if status.get("lastAttemptedRevision") is not None:
        require(status["lastAttemptedRevision"] == expected_revision, "workbench baseline Kustomization attempted revision drift")
    return {
        "uid": actual_uid,
        "resourceVersion": resource_version,
        "generation": generation,
        "observedGeneration": status["observedGeneration"],
        "lastAppliedRevision": expected_revision,
        "ready": True,
    }


def validate_flux_suspended(value: Any, uid: str) -> dict[str, Any]:
    require(isinstance(value, dict), "workbench baseline Kustomization absent during rollback")
    actual_uid, resource_version = _identity_metadata(value, "rollback workbench baseline Kustomization")
    require(actual_uid == uid, "rollback Kustomization UID changed")
    require(_flux_server_fields(value) == expected_flux_objects(suspended=True)["kustomization"], "rollback Kustomization semantic drift")
    require(value["spec"].get("suspend") is True, "rollback Kustomization was not suspended")
    return {"uid": actual_uid, "resourceVersion": resource_version, "suspend": True}


def _wait_for(
    read: Any,
    check: Any,
    *,
    label: str,
    timeout_seconds: float | None = None,
) -> dict[str, Any]:
    if timeout_seconds is None:
        timeout_seconds = FLUX_READY_TIMEOUT_SECONDS
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    last_error: Exception | None = None
    while True:
        try:
            value = read()
            return check(value)
        except Exception as error:
            last_error = error
            if time.monotonic() >= deadline:
                raise HandoverError(f"{label} did not reach the required state: {last_error}") from error
            time.sleep(min(FLUX_READY_POLL_SECONDS, max(0.0, deadline - time.monotonic())))


def wait_for_source(kube: Any, protected_revision: str) -> dict[str, Any]:
    return _wait_for(
        lambda: kube.get(source_target()),
        lambda value: validate_source(value, protected_revision),
        label="shared Flux source",
    )


def wait_for_flux_ready(kube: Any, identity: dict[str, str], uid: str, protected_revision: str) -> dict[str, Any]:
    return _wait_for(
        lambda: kube.get(identity),
        lambda value: validate_flux_ready(value, uid, protected_revision),
        label="workbench baseline Flux Kustomization",
    )


def wait_for_absent(kube: Any, identity: dict[str, str], *, label: str) -> None:
    """Boundedly prove an asynchronous Kubernetes DELETE has completed.

    A successful DELETE response may leave a resource in ``Terminating``
    state.  Callers must not remove a controller's RBAC until this exact
    identity is observed absent; a timeout is deliberately surfaced as an
    incomplete rollback and leaves the journal recoverable.
    """
    deadline = time.monotonic() + max(0.0, FLUX_DELETE_TIMEOUT_SECONDS)
    while True:
        current = kube.get(identity)
        if current is None:
            return
        if time.monotonic() >= deadline:
            raise HandoverError(f"{label} deletion did not reach absent state before timeout")
        time.sleep(min(FLUX_DELETE_POLL_SECONDS, max(0.0, deadline - time.monotonic())))


def _allowed_read_targets() -> tuple[dict[str, str], ...]:
    objects = expected_flux_objects(suspended=True)
    return (target(expected_before_network_policy()), source_target(), *(target(objects[name]) for name in object_order()))


def _allowed_mutation_target(identity: dict[str, str], *, action: str) -> None:
    allowed = {canonical(item) for item in _allowed_read_targets()}
    require(canonical(identity) in allowed, f"{action} target outside protected handover scope")
    baseline = target(expected_before_network_policy())
    kustomization = target(expected_flux_objects(suspended=True)["kustomization"])
    if action == "patch":
        require(identity != source_target(), "patch target outside protected handover scope")
    elif action == "delete":
        require(identity != baseline and identity != source_target(), "delete target outside transaction-owned Flux scope")


def _operation_marker_path() -> str:
    return "/metadata/annotations/" + HANDOVER_OPERATION_ANNOTATION.replace("~", "~0").replace("/", "~1")


def _marked_object(desired: dict[str, Any], operation_marker: str) -> dict[str, Any]:
    require(UUID.fullmatch(operation_marker) is not None, "handover operation marker invalid")
    value = copy.deepcopy(desired)
    metadata = value.get("metadata")
    require(isinstance(metadata, dict), "transaction object metadata absent")
    annotations = metadata.setdefault("annotations", {})
    require(isinstance(annotations, dict) and HANDOVER_OPERATION_ANNOTATION not in annotations, "transaction marker collision")
    annotations[HANDOVER_OPERATION_ANNOTATION] = operation_marker
    return value


def _marker_remove_patch(uid: str, resource_version: str, operation_marker: str) -> list[dict[str, Any]]:
    return [
        {"op": "test", "path": "/metadata/uid", "value": uid},
        {"op": "test", "path": "/metadata/resourceVersion", "value": resource_version},
        {"op": "test", "path": _operation_marker_path(), "value": operation_marker},
        {"op": "remove", "path": _operation_marker_path()},
    ]


def trusted_git(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[Any]:
    info = os.lstat(GIT_BIN)
    require(
        stat.S_ISREG(info.st_mode)
        and not GIT_BIN.is_symlink()
        and info.st_uid == 0
        and stat.S_IMODE(info.st_mode) & 0o022 == 0
        and os.access(GIT_BIN, os.X_OK),
        "trusted Git executable metadata invalid",
    )
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "HOME": "/dev/null",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    return subprocess.run([str(GIT_BIN), "--no-replace-objects", *args], env=environment, **kwargs)


ROOT = Path(__file__).resolve().parent.parent


def revision(value: Any) -> str:
    require(isinstance(value, str) and REVISION.fullmatch(value) is not None, "protected revision must be 40 lowercase hex")
    return value


def git_blob(rev: str, path: str) -> bytes:
    revision(rev)
    result = trusted_git(["-C", str(ROOT), "show", f"{rev}:{path}"], capture_output=True, check=False, timeout=10)
    require(result.returncode == 0, f"protected Git blob unavailable: {path}")
    return result.stdout


def protected_checkout(rev: str) -> dict[str, str]:
    head = trusted_git(["-C", str(ROOT), "rev-parse", "HEAD"], text=True, capture_output=True, check=False)
    require(head.returncode == 0 and head.stdout.strip() == rev, "checked-out revision is not the expected protected revision")
    hashes: dict[str, str] = {}
    for path in PROTECTED_PATHS:
        local = ROOT / path
        require(local.is_file() and not local.is_symlink(), f"protected handover file missing: {path}")
        expected = git_blob(rev, path)
        require(local.read_bytes() == expected, f"protected handover file differs from exact Git blob: {path}")
        hashes[path] = bytes_digest(expected)
    return dict(sorted(hashes.items()))


def build_plan(protected_revision: str, protected_file_hashes: dict[str, str], *, render: dict[str, Any] | None = None) -> dict[str, Any]:
    rev = revision(protected_revision)
    require(set(protected_file_hashes) == set(PROTECTED_PATHS), "protected handover blob set incomplete")
    require(all(isinstance(value, str) and SHA256.fullmatch(value) for value in protected_file_hashes.values()), "protected handover blob digest invalid")
    if render is None:
        render = {"networkPolicy": expected_network_policy(), "kustomization": expected_kustomization_text()}
    require(render["networkPolicy"] == expected_network_policy(), "protected baseline NetworkPolicy render drift")
    validate_kustomization_text(render["kustomization"])
    objects = expected_flux_objects(suspended=True)
    validate_flux_objects(objects, suspended=True)
    return {
        "schemaVersion": PLAN_SCHEMA,
        "protectedRevision": rev,
        "protectedFileSha256": dict(sorted(protected_file_hashes.items())),
        "baseline": {
            "target": target(expected_before_network_policy()),
            "uid": BASELINE_UID,
            "beforeDigest": BASELINE_BEFORE_DIGEST,
            "previousOwner": OLD_OWNER,
            "nextOwner": NEW_OWNER,
            "ssaAnnotation": {"name": SSA_ANNOTATION, "value": SSA_MODE},
            "networkPolicySemanticDigest": digest(expected_network_policy()),
        },
        "adoption": {
            "mode": "flux-ssa-override",
            "annotation": SSA_ANNOTATION,
            "value": SSA_MODE,
            "reconciliation": "cas-unsuspend-and-prove-ready",
            "sourceRevisionBinding": "main@sha1:<protectedRevision>",
            "readyProof": "observedGeneration-current-source-revision-ready-true",
            "inventoryMetadata": copy.deepcopy(FLUX_INVENTORY_LABELS),
        },
        "objects": [
            {
                "objectId": name,
                "target": target(objects[name]),
                "object": copy.deepcopy(objects[name]),
                "objectSemanticDigest": digest(objects[name]),
            }
            for name in object_order()
        ],
        "mutations": {
            "existingNetworkPolicy": "owner-label-and-flux-ssa-annotation-only-before-reconcile;inventory-labels-approved-after-reconcile",
            "existingWorkbenchDeployment": "forbidden",
            "existingWorkbenchService": "forbidden",
            "secretAccess": "forbidden",
            "civicAuthorityEffects": False,
        },
    }


def load_context(protected_revision: str) -> dict[str, Any]:
    rev = revision(protected_revision)
    hashes = protected_checkout(rev)
    render_policy = _json_object(git_blob(rev, NETWORK_POLICY_PATH), NETWORK_POLICY_PATH)
    render = {
        "networkPolicy": validate_network_policy(render_policy, final=True),
        "kustomization": git_blob(rev, KUSTOMIZATION_PATH).decode("utf-8"),
    }
    return {"revision": rev, "hashes": hashes, "render": render, "plan": build_plan(rev, hashes, render=render)}


SAFE_METADATA_KEYS = {
    # This is a Kubernetes ServiceAccount safety setting, not a credential.
    # It contains the word ``token`` but is deliberately a documented boolean
    # in the protected Flux object set.
    "automountserviceaccounttoken",
    "secretaccess",
    "secretobjectsallowed",
    "secretvaluesallowed",
    "secretreferencesallowed",
}
SAFE_METADATA_STRING_VALUES = {
    # Plan/receipt boundary statements are intentionally value-free.  The
    # literal is a documented capability denial, never a credential.
    "secretaccess": {"forbidden"},
    "secretobjectsallowed": {"forbidden"},
    "secretvaluesallowed": {"forbidden"},
    "secretreferencesallowed": {"forbidden"},
}
SECRET_KEY_MARKERS = (
    "apikey",
    "clientsecret",
    "authorization",
    "sessionkey",
    "token",
    "password",
    "privatekey",
    "secret",
    "secretvalue",
)


def _reject_secret_shaped(value: Any) -> None:
    """Reject nested credential-shaped keys while allowing safe booleans.

    Receipts and journals may describe a *boundary* such as ``secretAccess``
    or ``secretReferencesAllowed``.  Those documented metadata fields are
    allowed only as booleans; actual credential-bearing key variants are
    rejected recursively without scanning ordinary text values.
    """
    def walk(current: Any) -> None:
        if isinstance(current, dict):
            for key, child in current.items():
                require(isinstance(key, str), "secret-shaped receipt key invalid")
                normalized = re.sub(r"[^a-z0-9]", "", key.lower())
                if normalized in SAFE_METADATA_KEYS:
                    require(
                        isinstance(child, bool)
                        or (isinstance(child, str) and child in SAFE_METADATA_STRING_VALUES.get(normalized, set())),
                        f"safe metadata key {key} must be a documented boolean or capability denial",
                    )
                else:
                    require(normalized not in {"data", "stringdata"}, f"secret-shaped receipt key forbidden: {key}")
                    require(not any(marker in normalized for marker in SECRET_KEY_MARKERS), f"secret-shaped receipt key forbidden: {key}")
                walk(child)
        elif isinstance(current, list):
            for child in current:
                walk(child)

    walk(value)


def _absolute_no_symlink_path(path: Path, label: str) -> Path:
    """Return an absolute path only after rejecting symlink components."""
    absolute = Path(os.path.abspath(os.fspath(path)))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            continue
        require(not stat.S_ISLNK(info.st_mode), f"{label} path component is a symlink: {current}")
    return absolute


def _read_receipt_file(path: Path, *, max_bytes: int = 1024 * 1024) -> dict[str, Any]:
    """Read one owner-only receipt with a bounded, no-follow open."""
    path = _absolute_no_symlink_path(path, "receipt")
    info = os.lstat(path)
    require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode), "existing receipt is not a regular file")
    require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600, "existing receipt ownership or mode invalid")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        require(opened.st_dev == info.st_dev and opened.st_ino == info.st_ino, "receipt identity changed while opening")
        raw = os.read(fd, max_bytes + 1)
    finally:
        os.close(fd)
    require(len(raw) <= max_bytes, "receipt exceeds bounded size")
    parsed = _json_object(raw, "existing handover receipt")
    checksum = parsed.pop("canonicalSha256", None)
    require(isinstance(checksum, str) and SHA256.fullmatch(checksum) and checksum == digest(parsed), "existing handover receipt checksum invalid")
    _reject_secret_shaped(parsed)
    parsed["canonicalSha256"] = checksum
    return parsed


def _read_journal_file(path: Path, *, max_bytes: int = 1024 * 1024) -> tuple[dict[str, Any], os.stat_result]:
    """Read one checksum-bound journal and return its observed identity."""
    path = _absolute_no_symlink_path(path, "journal")
    info = os.lstat(path)
    require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode), "existing journal is not a regular file")
    require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600, "existing journal ownership or mode invalid")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        require(opened.st_dev == info.st_dev and opened.st_ino == info.st_ino, "journal identity changed while opening")
        raw = os.read(fd, max_bytes + 1)
    finally:
        os.close(fd)
    require(len(raw) <= max_bytes, "journal exceeds bounded size")
    parsed = _json_object(raw, "handover journal")
    checksum = parsed.pop("journalSha256", None)
    require(isinstance(checksum, str) and SHA256.fullmatch(checksum) and checksum == digest(parsed), "journal checksum invalid")
    _reject_secret_shaped(parsed)
    parsed["journalSha256"] = checksum
    return parsed, info


class MemoryReceiptSink:
    """Small sink used by tests and dry-run callers."""

    def __init__(self) -> None:
        self.values: list[dict[str, Any]] = []

    def load(self) -> dict[str, Any] | None:
        return copy.deepcopy(self.values[-1]) if self.values else None

    def commit(self, value: dict[str, Any]) -> None:
        _reject_secret_shaped(value)
        require(len(canonical(value).encode()) <= ReceiptSink.MAX_BYTES, "receipt exceeds bounded size")
        self.values.append(copy.deepcopy(value))


class ReceiptSink:
    """Non-overwriting, owner-only, durably replaced receipt file."""

    MAX_BYTES = 1024 * 1024

    def __init__(self, path: Path, *, allow_existing_completed: bool = False) -> None:
        resolved = _absolute_no_symlink_path(Path(path), "receipt")
        resolved.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _absolute_no_symlink_path(resolved.parent, "receipt parent")
        parent = os.lstat(resolved.parent)
        require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and stat.S_IMODE(parent.st_mode) & 0o022 == 0, "receipt parent must be private and owned")
        try:
            existing = os.lstat(resolved)
        except FileNotFoundError:
            existing = None
        info: os.stat_result
        fd: int | None = None
        if existing is not None:
            require(
                stat.S_ISREG(existing.st_mode)
                and not resolved.is_symlink()
                and existing.st_uid == os.geteuid()
                and stat.S_IMODE(existing.st_mode) == 0o600,
                "existing receipt reservation invalid",
            )
            # A zero-length file is the reservation left by a process that
            # died before its first durable receipt.  Reuse that reservation
            # for crash recovery; a non-empty final receipt is immutable and
            # means this one-time operation must not be rerun.
            if existing.st_size != 0:
                if not allow_existing_completed:
                    raise FileExistsError(resolved)
                parsed = _read_receipt_file(resolved, max_bytes=self.MAX_BYTES)
                require(parsed.get("status") in FINAL_RECEIPT_STATUSES, "existing handover receipt is not a finalized transaction")
                self.existing = parsed
                info = existing
            else:
                self.existing = None
            if existing.st_size == 0:
                fd = os.open(resolved, os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0))
        else:
            fd = os.open(resolved, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            self.existing = None
        if fd is not None:
            try:
                os.fchmod(fd, 0o600)
                os.fsync(fd)
                info = os.fstat(fd)
            finally:
                os.close(fd)
        directory = os.open(resolved.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        self.path = resolved
        self.device = info.st_dev
        self.inode = info.st_ino

    def load(self) -> dict[str, Any] | None:
        _absolute_no_symlink_path(self.path, "receipt")
        try:
            info = os.lstat(self.path)
        except FileNotFoundError:
            return None
        if info.st_size == 0:
            return None
        parsed = _read_receipt_file(self.path, max_bytes=self.MAX_BYTES)
        self.existing = parsed
        self.device = info.st_dev
        self.inode = info.st_ino
        return copy.deepcopy(parsed)

    def commit(self, value: dict[str, Any]) -> None:
        # Always observe the committed path before deciding whether a later
        # write is legal.  This closes the post-os.replace/re-entry window in
        # which the process that replaced the file did not update its cache.
        require(self.load() is None, "completed receipt is immutable")
        _absolute_no_symlink_path(self.path, "receipt")
        require(isinstance(value, dict) and "canonicalSha256" not in value, "receipt payload invalid")
        _reject_secret_shaped(value)
        final = copy.deepcopy(value)
        final["canonicalSha256"] = digest(value)
        encoded = (canonical(final) + "\n").encode()
        require(len(encoded) <= self.MAX_BYTES, "receipt exceeds bounded size")
        current = os.lstat(self.path)
        require(
            stat.S_ISREG(current.st_mode)
            and current.st_dev == self.device
            and current.st_ino == self.inode
            and stat.S_IMODE(current.st_mode) == 0o600,
            "reserved receipt target identity changed",
        )
        fd, name = tempfile.mkstemp(prefix=".workbench-handover-", dir=self.path.parent)
        temporary = Path(name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600, follow_symlinks=False)
            replaced = os.lstat(self.path)
            require(
                stat.S_ISREG(replaced.st_mode) and stat.S_IMODE(replaced.st_mode) == 0o600,
                "committed receipt mode drift",
            )
            self.device, self.inode = replaced.st_dev, replaced.st_ino
            self.existing = copy.deepcopy(final)
            directory = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


class MemoryJournalSink:
    """In-memory journal used by deterministic tests and injected callers."""

    def __init__(self, state: dict[str, Any] | None = None) -> None:
        self.state = copy.deepcopy(state)
        self.values: list[dict[str, Any]] = []

    def load(self) -> dict[str, Any] | None:
        return copy.deepcopy(self.state)

    def commit(self, value: dict[str, Any]) -> None:
        _reject_secret_shaped(value)
        require(len(canonical(value).encode()) <= JournalSink.MAX_BYTES, "journal exceeds bounded size")
        self.state = copy.deepcopy(value)
        self.values.append(copy.deepcopy(value))


class JournalSink:
    """Owner-only, checksum-bound, fsynced atomic in-progress journal.

    The path is reserved before Kubernetes contact.  A zero-length reservation
    is reusable after process death, while a non-empty journal is loaded and
    recovered rather than silently starting a second transaction.
    """

    MAX_BYTES = 1024 * 1024

    def __init__(self, path: Path) -> None:
        resolved = _absolute_no_symlink_path(Path(path), "journal")
        resolved.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _absolute_no_symlink_path(resolved.parent, "journal parent")
        parent = os.lstat(resolved.parent)
        require(
            stat.S_ISDIR(parent.st_mode)
            and parent.st_uid == os.geteuid()
            and stat.S_IMODE(parent.st_mode) & 0o022 == 0,
            "journal parent must be private and owned",
        )
        try:
            existing = os.lstat(resolved)
        except FileNotFoundError:
            existing = None
        self.path = resolved
        self.state: dict[str, Any] | None = None
        if existing is None:
            fd = os.open(resolved, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                os.fchmod(fd, 0o600)
                os.fsync(fd)
                existing = os.fstat(fd)
            finally:
                os.close(fd)
        else:
            require(
                stat.S_ISREG(existing.st_mode)
                and not resolved.is_symlink()
                and existing.st_uid == os.geteuid()
                and stat.S_IMODE(existing.st_mode) == 0o600
                and existing.st_size <= self.MAX_BYTES,
                "existing journal reservation invalid",
            )
            if existing.st_size:
                parsed, _observed = _read_journal_file(resolved, max_bytes=self.MAX_BYTES)
                parsed.pop("journalSha256", None)
                self.state = parsed
        self.device = existing.st_dev
        self.inode = existing.st_ino
        directory = os.open(resolved.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def load(self) -> dict[str, Any] | None:
        _absolute_no_symlink_path(self.path, "journal")
        try:
            info = os.lstat(self.path)
        except FileNotFoundError:
            self.state = None
            return None
        if info.st_size == 0:
            self.state = None
            return None
        parsed, observed = _read_journal_file(self.path, max_bytes=self.MAX_BYTES)
        parsed.pop("journalSha256", None)
        self.state = parsed
        self.device = observed.st_dev
        self.inode = observed.st_ino
        return copy.deepcopy(parsed)

    def commit(self, value: dict[str, Any]) -> None:
        require(isinstance(value, dict) and "journalSha256" not in value, "journal payload invalid")
        _reject_secret_shaped(value)
        _absolute_no_symlink_path(self.path, "journal")
        final = copy.deepcopy(value)
        final["journalSha256"] = digest(value)
        current = os.lstat(self.path)
        require(
            stat.S_ISREG(current.st_mode)
            and current.st_dev == self.device
            and current.st_ino == self.inode
            and stat.S_IMODE(current.st_mode) == 0o600,
            "reserved journal target identity changed",
        )
        fd, name = tempfile.mkstemp(prefix=".workbench-journal-", dir=self.path.parent)
        temporary = Path(name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                encoded = (canonical(final) + "\n").encode()
                require(len(encoded) <= self.MAX_BYTES, "journal exceeds bounded size")
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600, follow_symlinks=False)
            replaced = os.lstat(self.path)
            require(stat.S_ISREG(replaced.st_mode) and stat.S_IMODE(replaced.st_mode) == 0o600, "committed journal mode drift")
            self.device, self.inode = replaced.st_dev, replaced.st_ino
            self.state = copy.deepcopy(value)
            directory = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def _sink_file_identity(sink: Any, label: str) -> tuple[Path, tuple[int, int]] | None:
    """Open and bind one durable sink path without following an alias.

    The pairwise guard below runs before the first Kubernetes read.  It still
    opens each path and compares the resulting descriptor identity with both
    the path and the sink's reservation identity, so a rename/hard-link race
    between lexical validation and opening fails closed rather than allowing
    two logical journals to share one inode.
    """
    raw_path = getattr(sink, "path", None)
    if raw_path is None:
        return None
    path = _absolute_no_symlink_path(Path(raw_path), label)
    try:
        path_info = os.lstat(path)
    except FileNotFoundError as error:
        raise HandoverError(f"{label} path disappeared before Kubernetes contact") from error
    require(
        stat.S_ISREG(path_info.st_mode) and not stat.S_ISLNK(path_info.st_mode),
        f"{label} target must be a regular file",
    )
    expected_device = getattr(sink, "device", None)
    expected_inode = getattr(sink, "inode", None)
    require(
        isinstance(expected_device, int) and isinstance(expected_inode, int),
        f"{label} reservation identity unavailable",
    )
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        latest = os.lstat(path)
        require(
            opened.st_dev == latest.st_dev and opened.st_ino == latest.st_ino,
            f"{label} path identity changed while opening",
        )
    finally:
        os.close(fd)
    require(
        opened.st_dev == expected_device and opened.st_ino == expected_inode,
        f"{label} reservation identity changed before Kubernetes contact",
    )
    return path, (opened.st_dev, opened.st_ino)


def _validate_sink_separation(receipt_sink: Any, journal_sink: Any) -> None:
    """Reject path and inode aliases before any Kubernetes contact."""
    receipt_raw = getattr(receipt_sink, "path", None)
    journal_raw = getattr(journal_sink, "path", None)
    if receipt_raw is None or journal_raw is None:
        return
    receipt_path = _absolute_no_symlink_path(Path(receipt_raw), "receipt")
    journal_path = _absolute_no_symlink_path(Path(journal_raw), "journal")
    normalized_receipt = os.path.normcase(os.path.normpath(os.fspath(receipt_path)))
    normalized_journal = os.path.normcase(os.path.normpath(os.fspath(journal_path)))
    require(normalized_receipt != normalized_journal, "receipt and journal paths must be distinct")
    receipt_identity = _sink_file_identity(receipt_sink, "receipt")
    journal_identity = _sink_file_identity(journal_sink, "journal")
    require(receipt_identity is not None and journal_identity is not None, "receipt/journal sink identity unavailable")
    require(receipt_identity[1] != journal_identity[1], "receipt and journal inode aliases are forbidden")


def _journal_initial_state(
    plan: dict[str, Any],
    *,
    operation_id: str,
    operation_marker: str,
    before: dict[str, Any],
) -> dict[str, Any]:
    uid, resource_version = _identity_metadata(before, "journal baseline")
    state: dict[str, Any] = {
        "schemaVersion": JOURNAL_SCHEMA,
        "status": "in-progress",
        "mode": "live",
        "operationId": operation_id,
        "operationMarker": operation_marker,
        "protectedRevision": plan["protectedRevision"],
        "protectedFileSha256": copy.deepcopy(plan["protectedFileSha256"]),
        "baseline": {
            "target": copy.deepcopy(plan["baseline"]["target"]),
            "uid": uid,
            "resourceVersion": resource_version,
            "objectDigest": digest(before),
            "object": copy.deepcopy(before),
            "semantic": copy.deepcopy(expected_before_network_policy()),
        },
        "createdObjects": [],
        "events": [],
        "rollback": None,
    }
    _journal_event(state, "reserved", "transaction", {"operationId": operation_id})
    return state


def _journal_event(state: dict[str, Any], stage: str, operation: str, details: dict[str, Any]) -> dict[str, Any]:
    previous = state["events"][-1]["entrySha256"] if state["events"] else None
    entry: dict[str, Any] = {
        "sequence": len(state["events"]) + 1,
        "stage": stage,
        "operation": operation,
        "previousEntrySha256": previous,
    }
    entry.update(copy.deepcopy(details))
    entry["entrySha256"] = digest(entry)
    state["events"].append(entry)
    return entry


def _journal_rehash(entry: dict[str, Any]) -> None:
    entry.pop("entrySha256", None)
    entry["entrySha256"] = digest(entry)


def _journal_mutation_before(journal: Any, state: dict[str, Any], operation: str, target_value: dict[str, str], request: Any) -> dict[str, Any]:
    event = _journal_event(
        state,
        "before",
        operation,
        {
            "target": copy.deepcopy(target_value),
            "request": copy.deepcopy(request),
            "requestDigest": digest(request),
        },
    )
    journal.commit(state)
    return event


def _journal_mutation_after(journal: Any, state: dict[str, Any], event: dict[str, Any], result: Any) -> None:
    event["stage"] = "after"
    event["result"] = copy.deepcopy(result)
    _journal_rehash(event)
    journal.commit(state)


def _journal_mutation_uncertain(journal: Any, state: dict[str, Any], event: dict[str, Any], error: Exception) -> None:
    event["stage"] = "uncertain"
    event["error"] = str(error)[:320]
    _journal_rehash(event)
    journal.commit(state)


def _journal_validate_state(plan: dict[str, Any], state: dict[str, Any]) -> None:
    require(isinstance(state, dict), "handover journal must be an object")
    require(state.get("schemaVersion") == JOURNAL_SCHEMA, "handover journal schema invalid")
    journal_status = state.get("status")
    require(
        journal_status in {"in-progress", "reserved", "finalizing", "completed", "rollback-finalizing", *ROLLBACK_RECEIPT_STATUSES},
        "handover journal status invalid",
    )
    require(state.get("protectedRevision") == plan["protectedRevision"], "handover journal protected revision drift")
    require(state.get("protectedFileSha256") == plan["protectedFileSha256"], "handover journal protected file drift")
    operation_id = state.get("operationId")
    operation_marker = state.get("operationMarker")
    require(isinstance(operation_id, str) and UUID.fullmatch(operation_id), "handover journal operation ID invalid")
    require(isinstance(operation_marker, str) and UUID.fullmatch(operation_marker), "handover journal operation marker invalid")
    baseline = state.get("baseline")
    require(isinstance(baseline, dict), "handover journal baseline absent")
    require(baseline.get("target") == plan["baseline"]["target"], "handover journal baseline target drift")
    original = baseline.get("object")
    require(isinstance(original, dict), "handover journal original NetworkPolicy absent")
    uid, resource_version = _identity_metadata(original, "handover journal original NetworkPolicy")
    require(uid == BASELINE_UID and resource_version == baseline.get("resourceVersion"), "handover journal original NetworkPolicy identity drift")
    require(baseline.get("uid") == BASELINE_UID, "handover journal baseline UID drift")
    require(baseline.get("objectDigest") == BASELINE_BEFORE_DIGEST and digest(original) == BASELINE_BEFORE_DIGEST, "handover journal baseline digest drift")
    require(_server_fields(original) == expected_before_network_policy(), "handover journal original NetworkPolicy semantic drift")
    require(baseline.get("semantic") == expected_before_network_policy(), "handover journal baseline semantic projection drift")
    rollback = state.get("rollback")
    if journal_status in {"rollback-finalizing", *ROLLBACK_RECEIPT_STATUSES}:
        require(isinstance(rollback, dict), "handover journal rollback proof absent")
        rollback_status = rollback.get("status")
        require(
            rollback_status in {*ROLLBACK_RECEIPT_STATUSES, ROLLBACK_PENDING_STATUS},
            "handover journal rollback proof status invalid",
        )
        if journal_status in ROLLBACK_RECEIPT_STATUSES:
            require(rollback_status == journal_status, "handover journal rollback status drift")
        else:
            # ``rollback-finalizing`` is also the durable retry state for an
            # exact owned Kustomization whose asynchronous delete has not yet
            # reached absence.  It must not be turned into an immutable
            # incomplete receipt while the same UID can still be retried.
            if rollback_status == ROLLBACK_PENDING_STATUS:
                pending = rollback.get("pendingObjectIds")
                require(
                    isinstance(pending, list)
                    and pending == ["kustomization"],
                    "handover journal pending rollback inventory invalid",
                )
    else:
        require(rollback is None or isinstance(rollback, dict), "handover journal rollback field invalid")
    expected_objects = expected_flux_objects(suspended=True)
    records = state.get("createdObjects")
    require(isinstance(records, list), "handover journal created object inventory invalid")
    seen: set[str] = set()
    for record in records:
        require(isinstance(record, dict), "handover journal created object record invalid")
        name = record.get("objectId")
        require(name in object_order() and name not in seen, "handover journal created object identity invalid")
        seen.add(name)
        require(record.get("target") == target(expected_objects[name]), f"handover journal {name} target drift")
        require(record.get("desired") == expected_objects[name], f"handover journal {name} desired drift")
        marked = record.get("markedDesired")
        require(isinstance(marked, dict), f"handover journal {name} marked desired absent")
        require(_created_semantics(_without_operation_marker(marked), name) == expected_objects[name], f"handover journal {name} marked desired drift")
        annotations = marked.get("metadata", {}).get("annotations", {})
        require(annotations == {HANDOVER_OPERATION_ANNOTATION: operation_marker}, f"handover journal {name} operation marker drift")
        uid = record.get("uid")
        resource_version = record.get("resourceVersion")
        require(isinstance(uid, str) and UUID.fullmatch(uid), f"handover journal {name} UID invalid")
        require(isinstance(resource_version, str) and resource_version.isdigit(), f"handover journal {name} resourceVersion invalid")
        require(isinstance(record.get("markerRemoved"), bool), f"handover journal {name} marker state invalid")
        require(record.get("apiOutcome") in {"http-201-created", "post-send-uncertain-discovered", "recovered-created", "recovered-created-marker-bound"}, f"handover journal {name} create outcome invalid")
    events = state.get("events")
    require(isinstance(events, list) and events, "handover journal event chain absent")
    previous = None
    for index, event in enumerate(events, start=1):
        require(isinstance(event, dict), "handover journal event invalid")
        entry = copy.deepcopy(event)
        checksum = entry.pop("entrySha256", None)
        require(
            event.get("sequence") == index
            and event.get("previousEntrySha256") == previous
            and isinstance(checksum, str)
            and SHA256.fullmatch(checksum)
            and checksum == digest(entry),
            "handover journal event chain invalid",
        )
        if "request" in event:
            require(event.get("requestDigest") == digest(event["request"]), "handover journal request digest invalid")
        previous = checksum


def _created_semantics(value: dict[str, Any], name: str) -> dict[str, Any]:
    return _flux_server_fields(value) if name == "kustomization" else _server_fields(value)


def _marked_semantics(value: dict[str, Any], name: str) -> dict[str, Any]:
    return _created_semantics(value, name)


def _without_operation_marker(value: dict[str, Any]) -> dict[str, Any]:
    unmarked = copy.deepcopy(value)
    annotations = unmarked.get("metadata", {}).get("annotations")
    if isinstance(annotations, dict):
        annotations.pop(HANDOVER_OPERATION_ANNOTATION, None)
        if not annotations:
            unmarked["metadata"].pop("annotations", None)
    return unmarked


def _exact_marked_candidate(value: Any, name: str, desired: dict[str, Any], operation_marker: str) -> tuple[str, str]:
    require(isinstance(value, dict), f"{name} create outcome object absent")
    identity = target(value)
    require(identity == target(desired), f"{name} create outcome target drift")
    uid, resource_version = _identity_metadata(value, f"{name} create outcome")
    annotations = value.get("metadata", {}).get("annotations", {})
    require(annotations == {HANDOVER_OPERATION_ANNOTATION: operation_marker}, f"{name} create outcome is not this transaction's marker")
    marked_desired = _marked_object(desired, operation_marker)
    require(_marked_semantics(value, name) == _marked_semantics(marked_desired, name), f"{name} create outcome semantic drift")
    return uid, resource_version


def _static_candidate(
    value: Any,
    name: str,
    desired: dict[str, Any],
    *,
    expected_uid: str | None = None,
) -> tuple[str, str]:
    require(isinstance(value, dict), f"{name} static object absent")
    uid, resource_version = _identity_metadata(value, f"{name} static object")
    if expected_uid is not None:
        require(uid == expected_uid, f"{name} static object UID changed; recovery/adoption forbidden")
    require(_created_semantics(value, name) == _created_semantics(desired, name), f"{name} static object semantic drift")
    return uid, resource_version


def _receipt_created_record(name: str, identity: dict[str, str], desired: dict[str, Any], marked: dict[str, Any], uid: str, resource_version: str, marker_removed: bool) -> dict[str, Any]:
    return {
        "objectId": name,
        "target": copy.deepcopy(identity),
        "uid": uid,
        "resourceVersion": resource_version,
        "objectSemanticDigest": digest(_created_semantics(desired, name)),
        "apiOperation": "POST-create",
        "apiOutcome": "http-201-created" if not marker_removed else "http-201-created-marker-removed",
        "operationMarker": marked["metadata"]["annotations"][HANDOVER_OPERATION_ANNOTATION],
        "markerRemoved": marker_removed,
        "rollbackOwned": True,
    }


class KubernetesAdapter:
    """Narrow kubectl adapter; all resource names come from the protected plan."""

    def __init__(self, kubeconfig: str, *, kubectl: Path = KUBECTL_BIN) -> None:
        require(isinstance(kubeconfig, str) and kubeconfig, "handover requires explicit kubeconfig")
        kubeconfig_input = Path(kubeconfig)
        kubeconfig_info = os.lstat(kubeconfig_input)
        kubeconfig_path = Path(os.path.realpath(os.path.abspath(kubeconfig_input)))
        require(
            stat.S_ISREG(kubeconfig_info.st_mode)
            and not kubeconfig_input.is_symlink()
            and kubeconfig_info.st_uid == os.geteuid()
            and stat.S_IMODE(kubeconfig_info.st_mode) & 0o077 == 0,
            "kubeconfig must be an owned private regular file",
        )
        info = os.lstat(kubectl)
        require(stat.S_ISREG(info.st_mode) and not kubectl.is_symlink() and os.access(kubectl, os.X_OK), "kubectl executable invalid")
        self.kubeconfig = str(kubeconfig_path)
        self.kubectl = kubectl

    def _run(self, args: list[str], *, input_text: str | None = None) -> tuple[int, str, str]:
        command = [str(self.kubectl), "--kubeconfig", self.kubeconfig, "--request-timeout=30s", *args]
        environment = {
            key: value
            for key, value in os.environ.items()
            if key.upper() not in {
                "ALL_PROXY",
                "FTP_PROXY",
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "NO_PROXY",
                "all_proxy",
                "ftp_proxy",
                "http_proxy",
                "https_proxy",
                "no_proxy",
            }
        }
        environment.update({"NO_PROXY": "*", "no_proxy": "*"})
        result = subprocess.run(
            command,
            env=environment,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=40,
            check=False,
        )
        return result.returncode, result.stdout, result.stderr

    @staticmethod
    def _args(value: dict[str, str], action: str) -> list[str]:
        return ["-n", value["namespace"], action, value["kind"].lower(), value["name"]]

    def get(self, value: dict[str, str]) -> dict[str, Any] | None:
        require(any(value == allowed for allowed in _allowed_read_targets()), "GET target outside protected handover scope")
        code, out, err = self._run(self._args(value, "get") + ["-o", "json"])
        if code != 0 and re.search(r"notfound|not found|404", err, re.I):
            return None
        require(code == 0, f"GET failed for {value['kind']}/{value['name']}: {err.strip()}")
        return _json_object(out, f"GET {value['kind']}/{value['name']}")

    def create(self, value: dict[str, Any]) -> dict[str, Any]:
        identity = target(value)
        require(identity != target(expected_before_network_policy()) and identity != source_target(), "create target outside transaction-owned Flux scope")
        desired = expected_flux_objects(suspended=True)
        matching = next((desired[name] for name in object_order() if target(desired[name]) == identity), None)
        require(matching is not None, "create target outside transaction-owned Flux scope")
        marked = copy.deepcopy(value)
        annotations = marked.get("metadata", {}).get("annotations", {})
        require(
            isinstance(annotations, dict)
            and set(annotations) == {HANDOVER_OPERATION_ANNOTATION}
            and isinstance(annotations[HANDOVER_OPERATION_ANNOTATION], str)
            and UUID.fullmatch(annotations[HANDOVER_OPERATION_ANNOTATION]) is not None
            and _flux_server_fields(marked) == _flux_server_fields(_marked_object(matching, annotations[HANDOVER_OPERATION_ANNOTATION])),
            "create object differs from protected Flux object or marker",
        )
        code, out, err = self._run(["-n", identity["namespace"], "create", "-f", "-", "-o", "json"], input_text=canonical(value))
        if code != 0 and ("alreadyexists" in err.lower() or re.search(r"\b409\b", err)):
            raise Conflict(f"{identity['kind']}/{identity['name']} already exists; adoption forbidden")
        require(code == 0, f"create failed for {identity['kind']}/{identity['name']}: {err.strip()}")
        return _json_object(out, f"create {identity['kind']}/{identity['name']}")

    def patch(self, identity: dict[str, str], operations: list[dict[str, Any]]) -> dict[str, Any]:
        _allowed_mutation_target(identity, action="patch")
        baseline = target(expected_before_network_policy())
        kustomization = target(expected_flux_objects(suspended=True)["kustomization"])
        if identity not in (baseline, kustomization):
            require(
                len(operations) == 4
                and [operation.get("op") for operation in operations] == ["test", "test", "test", "remove"]
                and operations[2].get("path") == _operation_marker_path()
                and isinstance(operations[2].get("value"), str)
                and UUID.fullmatch(operations[2]["value"]) is not None
                and operations[3].get("path") == _operation_marker_path(),
                "patch outside protected transaction-marker removal scope",
            )
        code, out, err = self._run(self._args(identity, "patch") + ["--type=json", "-p", canonical(operations), "-o", "json"])
        require(code == 0, f"patch failed for {identity['kind']}/{identity['name']}: {err.strip()}")
        return _json_object(out, f"patch {identity['kind']}/{identity['name']}")

    @staticmethod
    def _raw_delete_path(identity: dict[str, str]) -> str:
        api_version = identity["apiVersion"]
        plural = {
            ("v1", "ServiceAccount"): "serviceaccounts",
            ("rbac.authorization.k8s.io/v1", "Role"): "roles",
            ("rbac.authorization.k8s.io/v1", "RoleBinding"): "rolebindings",
            ("kustomize.toolkit.fluxcd.io/v1", "Kustomization"): "kustomizations",
        }.get((api_version, identity["kind"]))
        require(plural is not None, "delete target API kind outside protected scope")
        prefix = "/api/v1" if api_version == "v1" else f"/apis/{api_version}"
        return f"{prefix}/namespaces/{identity['namespace']}/{plural}/{identity['name']}"

    def delete(self, identity: dict[str, str], *, uid: str, resource_version: str) -> None:
        _allowed_mutation_target(identity, action="delete")
        require(UUID.fullmatch(uid) is not None, "delete UID precondition invalid")
        require(isinstance(resource_version, str) and resource_version.isdigit(), "delete resourceVersion precondition invalid")
        payload = {
            "apiVersion": "v1",
            "kind": "DeleteOptions",
            "preconditions": {"uid": uid, "resourceVersion": resource_version},
        }
        code, _out, err = self._run(
            ["delete", "--raw", self._raw_delete_path(identity), "-f", "-"],
            input_text=canonical(payload),
        )
        if code != 0 and re.search(r"notfound|not found|404", err, re.I):
            return
        require(code == 0, f"delete failed for {identity['kind']}/{identity['name']}: {err.strip()}")


def _identity_metadata(value: dict[str, Any], label: str) -> tuple[str, str]:
    metadata = value.get("metadata", {})
    uid = metadata.get("uid")
    resource_version = metadata.get("resourceVersion")
    require(isinstance(uid, str) and UUID.fullmatch(uid), f"{label} UID invalid")
    require(isinstance(resource_version, str) and resource_version.isdigit(), f"{label} resourceVersion invalid")
    return uid, resource_version


def _owned_created(
    kube: Any,
    identity: dict[str, str],
    uid: str,
    desired: dict[str, Any],
    label: str,
    *,
    acceptable: tuple[dict[str, Any], ...] = (),
) -> str:
    current = kube.get(identity)
    if current is None:
        return "already-absent"
    current_uid, current_resource_version = _identity_metadata(current, label)
    require(current_uid == uid, f"{label} UID replacement; deletion forbidden")
    candidates = (desired, *acceptable)
    if current.get("kind") in {"GitRepository", "Kustomization"}:
        current_semantics = _flux_server_fields(current)
        expected_semantics = tuple(_flux_server_fields(item) for item in candidates)
    else:
        current_semantics = _server_fields(current)
        expected_semantics = tuple(_server_fields(item) for item in candidates)
    require(current_semantics in expected_semantics, f"{label} semantic drift; deletion forbidden")
    kube.delete(identity, uid=current_uid, resource_version=current_resource_version)
    wait_for_absent(kube, identity, label=label)
    return "deleted"


def _classify_kustomization_delete_failure(
    kube: Any,
    record: dict[str, Any],
    error: Exception,
) -> str:
    """Classify a Kustomization delete timeout without adopting a name.

    A terminating Kustomization with the journaled UID and unchanged Flux
    semantics is safe to retry on re-entry.  A replacement, semantic drift,
    or an API authorization failure is terminal and must produce an explicit
    incomplete receipt instead.  The extra GET is proof-only; it never
    changes the journaled UID.
    """
    if "deletion did not reach absent state before timeout" not in str(error).lower():
        return "terminal"
    identity = record["target"]
    try:
        current = kube.get(identity)
    except Exception:
        return "terminal"
    if current is None:
        return "absent"
    try:
        current_uid, _resource_version = _identity_metadata(current, "rollback Kustomization delete retry")
        require(current_uid == record["uid"], "rollback Kustomization UID replacement; refusing retry")
        allowed = (
            _created_semantics(record["desired"], "kustomization"),
            _created_semantics(record["markedDesired"], "kustomization"),
            _flux_server_fields(expected_flux_objects(suspended=False)["kustomization"]),
        )
        require(_created_semantics(current, "kustomization") in allowed, "rollback Kustomization semantic drift; refusing retry")
    except Exception:
        return "terminal"
    return "pending"


def _baseline_patch(resource_version: str) -> list[dict[str, Any]]:
    return [
        {"op": "test", "path": "/metadata/uid", "value": BASELINE_UID},
        {"op": "test", "path": "/metadata/resourceVersion", "value": resource_version},
        {"op": "test", "path": "/metadata/labels/stadtstack.io~1owner", "value": OLD_OWNER},
        {"op": "replace", "path": "/metadata/labels/stadtstack.io~1owner", "value": NEW_OWNER},
        {"op": "add", "path": "/metadata/annotations", "value": {SSA_ANNOTATION: SSA_MODE}},
    ]


def _baseline_rollback_patch(resource_version: str, *, reconciled: bool) -> list[dict[str, Any]]:
    operations = [
        {"op": "test", "path": "/metadata/uid", "value": BASELINE_UID},
        {"op": "test", "path": "/metadata/resourceVersion", "value": resource_version},
        {"op": "test", "path": "/metadata/labels/stadtstack.io~1owner", "value": NEW_OWNER},
        {"op": "test", "path": "/metadata/annotations/kustomize.toolkit.fluxcd.io~1ssa", "value": SSA_MODE},
    ]
    if reconciled:
        operations.extend([
            {"op": "test", "path": f"/metadata/labels/{FLUX_INVENTORY_NAME_LABEL.replace('/', '~1')}", "value": FLUX_NAME},
            {"op": "test", "path": f"/metadata/labels/{FLUX_INVENTORY_NAMESPACE_LABEL.replace('/', '~1')}", "value": FLUX_NAMESPACE},
            {"op": "remove", "path": f"/metadata/labels/{FLUX_INVENTORY_NAME_LABEL.replace('/', '~1')}"},
            {"op": "remove", "path": f"/metadata/labels/{FLUX_INVENTORY_NAMESPACE_LABEL.replace('/', '~1')}"},
        ])
    operations.extend([
        {"op": "replace", "path": "/metadata/labels/stadtstack.io~1owner", "value": OLD_OWNER},
        {"op": "remove", "path": "/metadata/annotations/kustomize.toolkit.fluxcd.io~1ssa"},
        {"op": "remove", "path": "/metadata/annotations"},
    ])
    return operations


def _unsuspend_patch(uid: str, resource_version: str) -> list[dict[str, Any]]:
    return [
        {"op": "test", "path": "/metadata/uid", "value": uid},
        {"op": "test", "path": "/metadata/resourceVersion", "value": resource_version},
        {"op": "test", "path": "/spec/suspend", "value": True},
        {"op": "replace", "path": "/spec/suspend", "value": False},
    ]


def _suspend_patch(uid: str, resource_version: str) -> list[dict[str, Any]]:
    return [
        {"op": "test", "path": "/metadata/uid", "value": uid},
        {"op": "test", "path": "/metadata/resourceVersion", "value": resource_version},
        {"op": "test", "path": "/spec/suspend", "value": False},
        {"op": "replace", "path": "/spec/suspend", "value": True},
    ]


def _receipt_base(plan: dict[str, Any], mode: str) -> dict[str, Any]:
    return {
        "schemaVersion": RECEIPT_SCHEMA,
        "status": "reserved",
        "mode": mode,
        "protectedRevision": plan["protectedRevision"],
        "protectedFileSha256": copy.deepcopy(plan["protectedFileSha256"]),
        "baseline": copy.deepcopy(plan["baseline"]),
        "adoption": copy.deepcopy(plan["adoption"]),
        "objects": [],
        "flux": {
            "sourceBefore": None,
            "sourceAfter": None,
            "casUnsuspend": None,
            "ready": None,
            "networkPolicyReconciled": None,
        },
        "rollback": None,
        "effects": {
            "networkPolicySpecChanged": False,
            "networkPolicySemanticLabelsChanged": False,
            "networkPolicyOwnerLabelChanged": False,
            "fluxSsaOverrideAdded": False,
            "kustomizationUnsuspended": False,
            "fluxReady": False,
            "networkPolicyReconciled": False,
            "existingDeploymentChanged": False,
            "existingServiceChanged": False,
            "secretAccess": False,
            "civicAuthorityEffects": False,
        },
    }


def _journal_result(value: dict[str, Any], name: str) -> dict[str, Any]:
    uid, resource_version = _identity_metadata(value, f"{name} mutation result")
    return {
        "uid": uid,
        "resourceVersion": resource_version,
        "semanticDigest": digest(_created_semantics(value, name)) if name in object_order() else digest(_server_fields(value)),
    }


def _journal_add_created(
    state: dict[str, Any],
    *,
    name: str,
    identity: dict[str, str],
    desired: dict[str, Any],
    marked: dict[str, Any],
    uid: str,
    resource_version: str,
    marker_removed: bool,
    api_outcome: str = "http-201-created",
) -> dict[str, Any]:
    record = {
        "objectId": name,
        "target": copy.deepcopy(identity),
        "uid": uid,
        "resourceVersion": resource_version,
        "desired": copy.deepcopy(desired),
        "markedDesired": copy.deepcopy(marked),
        "markerRemoved": marker_removed,
        "apiOutcome": api_outcome,
    }
    for existing in state["createdObjects"]:
        if existing.get("objectId") == name:
            existing.clear()
            existing.update(copy.deepcopy(record))
            return existing
    state["createdObjects"].append(record)
    return state["createdObjects"][-1]


def _journal_update_created(
    state: dict[str, Any],
    *,
    name: str,
    uid: str,
    resource_version: str,
    marker_removed: bool,
) -> dict[str, Any]:
    for record in state["createdObjects"]:
        if record.get("objectId") == name:
            require(record.get("uid") == uid, f"handover journal {name} UID replacement; refusing adoption")
            record["uid"] = uid
            record["resourceVersion"] = resource_version
            record["markerRemoved"] = marker_removed
            return record
    raise HandoverError(f"handover journal {name} created record absent")


def _receipt_record_from_journal(record: dict[str, Any]) -> dict[str, Any]:
    name = record["objectId"]
    desired = record["desired"]
    return {
        "objectId": name,
        "target": copy.deepcopy(record["target"]),
        "uid": record["uid"],
        "resourceVersion": record["resourceVersion"],
        "objectSemanticDigest": digest(_created_semantics(desired, name)),
        "apiOperation": "POST-create",
        "apiOutcome": record.get("apiOutcome") or ("recovered-created" if record.get("markerRemoved") else "recovered-created-marker-bound"),
        "operationMarker": record["markedDesired"]["metadata"]["annotations"][HANDOVER_OPERATION_ANNOTATION],
        "markerRemoved": bool(record.get("markerRemoved")),
        "rollbackOwned": True,
        "recovered": True,
    }


def _recover_marker_removals(*, kube: Any, journal: Any, state: dict[str, Any]) -> None:
    """Reconcile a lost marker-removal response without UID adoption.

    The journal records the UID observed before the PATCH.  A same-name object
    with a different UID is a replacement, never the result of our request;
    it must therefore fail closed rather than being copied into the journal.
    """
    records = {record["objectId"]: record for record in state.get("createdObjects", [])}
    for name, record in records.items():
        if record.get("markerRemoved") is True:
            continue
        marker_event = next(
            (
                event
                for event in reversed(state.get("events", []))
                if event.get("operation") == f"remove-marker.{name}"
                and event.get("stage") in {"before", "uncertain"}
            ),
            None,
        )
        if marker_event is None:
            continue
        identity = record["target"]
        current = kube.get(identity)
        if current is None:
            continue
        desired = record["desired"]
        annotations = current.get("metadata", {}).get("annotations", {})
        if HANDOVER_OPERATION_ANNOTATION in annotations:
            require(
                annotations == {HANDOVER_OPERATION_ANNOTATION: state["operationMarker"]},
                f"recovery {name} marker state ambiguous",
            )
            # The durable ``before`` event is the marker-removal intent.  A
            # process can die after that journal write and before sending the
            # PATCH, so the exact marked object is still ours and remains
            # rollback-owned.  Validate its full marked semantics *before*
            # trying the unmarked candidate path; the latter intentionally
            # rejects the marker and would turn this safe state into a false
            # ambiguity.
            marked_uid, _marked_rv = _exact_marked_candidate(
                current,
                name,
                desired,
                state["operationMarker"],
            )
            require(marked_uid == record["uid"], f"recovery {name} marker UID changed")
            # The marker is still present; rollback can safely delete the
            # exact marked UID, so no synthetic PATCH is attempted.
            continue
        current_uid, current_rv = _static_candidate(current, name, desired, expected_uid=record["uid"])
        _journal_update_created(
            state,
            name=name,
            uid=current_uid,
            resource_version=current_rv,
            marker_removed=True,
        )
        journal.commit(state)


def _receipt_from_sink(sink: Any) -> dict[str, Any] | None:
    """Read a previously durable receipt without making it mutable."""
    loader = getattr(sink, "load", None)
    value = loader() if callable(loader) else None
    if value is None and isinstance(getattr(sink, "values", None), list) and sink.values:
        value = sink.values[-1]
    return copy.deepcopy(value) if isinstance(value, dict) else None


def _validate_completed_receipt_identity(plan: dict[str, Any], state: dict[str, Any], receipt: dict[str, Any]) -> None:
    """Bind a completed receipt to this exact journal and protected plan."""
    require(receipt.get("schemaVersion") == RECEIPT_SCHEMA, "completed handover receipt schema drift")
    require(receipt.get("status") == "completed", "completed handover receipt status invalid")
    require(receipt.get("mode") == "live", "completed handover receipt mode invalid")
    require(receipt.get("protectedRevision") == plan["protectedRevision"], "completed handover receipt protected revision drift")
    require(receipt.get("protectedFileSha256") == plan["protectedFileSha256"], "completed handover receipt protected file drift")
    operation = receipt.get("operation")
    require(isinstance(operation, dict), "completed handover receipt operation absent")
    require(operation.get("operationId") == state.get("operationId"), "completed handover receipt operation ID drift")
    require(operation.get("operationMarker") == state.get("operationMarker"), "completed handover receipt operation marker drift")
    baseline = receipt.get("baseline")
    require(isinstance(baseline, dict), "completed handover receipt baseline absent")
    require(baseline.get("uid") == BASELINE_UID, "completed handover receipt baseline UID drift")
    require(baseline.get("beforeObjectDigest") == BASELINE_BEFORE_DIGEST, "completed handover receipt baseline digest drift")
    receipt_objects = receipt.get("objects")
    require(isinstance(receipt_objects, list), "completed handover receipt object inventory invalid")
    receipt_by_name = {item.get("objectId"): item for item in receipt_objects if isinstance(item, dict)}
    require(set(receipt_by_name) == set(object_order()) and len(receipt_by_name) == len(object_order()), "completed handover receipt object inventory drift")
    journal_by_name = {item["objectId"]: item for item in state.get("createdObjects", [])}
    require(set(journal_by_name) == set(object_order()), "completed handover journal object inventory incomplete")
    for name in object_order():
        receipt_record = receipt_by_name[name]
        journal_record = journal_by_name[name]
        require(receipt_record.get("target") == journal_record.get("target"), f"completed handover receipt {name} target drift")
        require(receipt_record.get("uid") == journal_record.get("uid"), f"completed handover receipt {name} UID drift")
        require(receipt_record.get("markerRemoved") is True and journal_record.get("markerRemoved") is True, f"completed handover receipt {name} marker state invalid")
        require(receipt_record.get("operationMarker") == state.get("operationMarker"), f"completed handover receipt {name} marker drift")


def _verify_completed_live_postconditions(*, plan: dict[str, Any], state: dict[str, Any], receipt: dict[str, Any], kube: Any) -> dict[str, Any]:
    """Prove a receipt already committed before a journal-final write is live."""
    source = wait_for_source(kube, plan["protectedRevision"])
    source_before = state.get("sourceBefore")
    if isinstance(source_before, dict):
        require(source["uid"] == source_before.get("uid"), "completed handover shared Flux source UID drift")
    source_after = state.get("sourceAfter")
    if isinstance(source_after, dict):
        require(source["uid"] == source_after.get("uid"), "completed handover source-after UID drift")

    records = {record["objectId"]: record for record in state["createdObjects"]}
    kustomization_record = records["kustomization"]
    kustomization = kube.get(kustomization_record["target"])
    require(kustomization is not None, "completed handover Kustomization absent")
    ready = validate_flux_ready(kustomization, kustomization_record["uid"], plan["protectedRevision"])

    baseline = kube.get(state["baseline"]["target"])
    require(baseline is not None, "completed handover NetworkPolicy absent")
    baseline_uid, baseline_rv = _identity_metadata(baseline, "completed handover NetworkPolicy")
    require(baseline_uid == BASELINE_UID, "completed handover NetworkPolicy UID drift")
    validate_reconciled_network_policy(baseline)

    for name in object_order():
        record = records[name]
        current = kube.get(record["target"])
        require(current is not None, f"completed handover {name} absent")
        current_uid, _current_rv = _identity_metadata(current, f"completed handover {name}")
        require(current_uid == record["uid"], f"completed handover {name} UID drift")
        if name == "kustomization":
            require(_flux_server_fields(current) == expected_flux_objects(suspended=False)["kustomization"], "completed handover Kustomization semantic drift")
        else:
            require(_server_fields(current) == _server_fields(record["desired"]), f"completed handover {name} semantic drift")
    return {
        "source": source,
        "ready": ready,
        "networkPolicy": {
            "uid": baseline_uid,
            "resourceVersion": baseline_rv,
            "semanticDigest": digest(_server_fields(baseline)),
            "specDigest": digest(baseline["spec"]),
        },
    }


def _finalize_completed_receipt(*, plan: dict[str, Any], state: dict[str, Any], receipt: dict[str, Any], kube: Any, journal: Any) -> dict[str, Any]:
    """Complete the journal after a receipt-first crash, without new mutations."""
    _journal_validate_state(plan, state)
    require(state.get("status") in {"in-progress", "reserved", "finalizing", "completed"}, "completed handover journal status invalid")
    _validate_completed_receipt_identity(plan, state, receipt)
    proof = _verify_completed_live_postconditions(plan=plan, state=state, receipt=receipt, kube=kube)
    state["status"] = "completed"
    state["completedAt"] = receipt.get("completedAt", _now())
    state["finalizedFromReceipt"] = True
    state["finalizationProof"] = proof
    journal.commit(state)
    return receipt


ROLLBACK_RECEIPT_STATUSES = {
    "rolled-back",
    "rollback-incomplete",
    "recovered-rolled-back",
    "recovered-rollback-incomplete",
}


def _validate_rollback_receipt_identity(plan: dict[str, Any], state: dict[str, Any], receipt: dict[str, Any]) -> None:
    """Bind a rollback receipt to the exact journal and protected baseline."""
    require(receipt.get("schemaVersion") == RECEIPT_SCHEMA, "rollback receipt schema drift")
    require(receipt.get("status") in ROLLBACK_RECEIPT_STATUSES, "rollback receipt status invalid")
    require(receipt.get("mode") == "live", "rollback receipt mode invalid")
    require(receipt.get("protectedRevision") == plan["protectedRevision"], "rollback receipt protected revision drift")
    require(receipt.get("protectedFileSha256") == plan["protectedFileSha256"], "rollback receipt protected file drift")
    operation = receipt.get("operation")
    if operation is not None:
        require(isinstance(operation, dict), "rollback receipt operation invalid")
        require(operation.get("operationId") == state.get("operationId"), "rollback receipt operation ID drift")
        require(operation.get("operationMarker") == state.get("operationMarker"), "rollback receipt operation marker drift")
    else:
        require(receipt.get("recoveredOperationId") == state.get("operationId"), "rollback receipt recovered operation ID drift")
    baseline = receipt.get("baseline")
    require(isinstance(baseline, dict), "rollback receipt baseline absent")
    require(baseline.get("uid") == BASELINE_UID, "rollback receipt baseline UID drift")
    require(baseline.get("beforeObjectDigest") == BASELINE_BEFORE_DIGEST, "rollback receipt baseline digest drift")
    rollback = receipt.get("rollback")
    require(isinstance(rollback, dict), "rollback receipt rollback proof absent")
    require(rollback.get("status") == receipt.get("status"), "rollback receipt status/proof drift")
    require(rollback.get("suspendFirst") is True, "rollback receipt suspend-first proof absent")
    records = {record["objectId"]: record for record in state.get("createdObjects", [])}
    receipt_objects = receipt.get("objects")
    require(isinstance(receipt_objects, list), "rollback receipt object inventory invalid")
    receipt_by_name = {item.get("objectId"): item for item in receipt_objects if isinstance(item, dict)}
    require(set(receipt_by_name) == set(records) and len(receipt_by_name) == len(records), "rollback receipt object inventory drift")
    for name, record in records.items():
        item = receipt_by_name[name]
        require(item.get("target") == record.get("target"), f"rollback receipt {name} target drift")
        require(item.get("uid") == record.get("uid"), f"rollback receipt {name} UID drift")
        require(item.get("operationMarker") == state.get("operationMarker"), f"rollback receipt {name} marker drift")


def _verify_rollback_live_postconditions(*, plan: dict[str, Any], state: dict[str, Any], receipt: dict[str, Any], kube: Any) -> dict[str, Any]:
    """Prove a rollback receipt before finalizing its journal.

    A complete rollback requires the original NetworkPolicy and absence of all
    transaction-owned Flux objects.  An incomplete rollback is allowed to
    retain a precisely identified replacement/terminating object, but it must
    never be upgraded to a complete claim.
    """
    complete_claim = receipt["status"] in {"rolled-back", "recovered-rolled-back"}
    baseline = kube.get(state["baseline"]["target"])
    if baseline is None:
        require(not complete_claim, "complete rollback receipt NetworkPolicy absent")
        return {
            "networkPolicy": {"uid": None, "resourceVersion": None, "restored": False},
            "fluxObjectsAbsent": [],
            "fluxObjectsPresent": sorted(record["objectId"] for record in state.get("createdObjects", [])),
            "complete": False,
        }
    baseline_uid, baseline_rv = _identity_metadata(baseline, "rollback receipt NetworkPolicy")
    if baseline_uid != BASELINE_UID:
        require(not complete_claim, "rollback receipt NetworkPolicy UID drift")
        return {
            "networkPolicy": {"uid": baseline_uid, "resourceVersion": baseline_rv, "restored": False},
            "fluxObjectsAbsent": [],
            "fluxObjectsPresent": sorted(record["objectId"] for record in state.get("createdObjects", [])),
            "complete": False,
        }
    restored = _server_fields(baseline) == expected_before_network_policy()
    require(restored or not complete_claim, "rollback receipt NetworkPolicy predecessor drift")
    records = {record["objectId"]: record for record in state.get("createdObjects", [])}
    absent: list[str] = []
    present: list[str] = []
    for name, record in records.items():
        current = kube.get(record["target"])
        if current is None:
            absent.append(name)
            continue
        present.append(name)
        current_uid, _current_rv = _identity_metadata(current, f"rollback receipt {name}")
        if current_uid == record["uid"]:
            allowed_semantics = [
                _created_semantics(record["desired"], name),
                _created_semantics(record["markedDesired"], name),
            ]
            if name == "kustomization":
                allowed_semantics.append(_flux_server_fields(expected_flux_objects(suspended=False)["kustomization"]))
            require(
                _created_semantics(current, name) in allowed_semantics,
                f"rollback receipt {name} surviving object drift",
            )
    if complete_claim:
        require(not present, "complete rollback receipt has surviving Flux object")
        require(receipt["rollback"].get("restoredPriorOwnerAndSsa") is True, "complete rollback predecessor proof absent")
    return {
        "networkPolicy": {"uid": baseline_uid, "resourceVersion": baseline_rv, "restored": restored},
        "fluxObjectsAbsent": sorted(absent),
        "fluxObjectsPresent": sorted(present),
        "complete": not present,
    }


def _finalize_rollback_receipt(*, plan: dict[str, Any], state: dict[str, Any], receipt: dict[str, Any], kube: Any, journal: Any) -> dict[str, Any]:
    """Finalize a receipt-first rollback without starting another operation."""
    _journal_validate_state(plan, state)
    require(
        state.get("status") in {"rollback-finalizing", *ROLLBACK_RECEIPT_STATUSES},
        "rollback journal status invalid",
    )
    _validate_rollback_receipt_identity(plan, state, receipt)
    proof = _verify_rollback_live_postconditions(plan=plan, state=state, receipt=receipt, kube=kube)
    state["status"] = receipt["status"]
    state["rollback"]["status"] = receipt["status"]
    state["rollbackFinalizedAt"] = receipt.get("completedAt", _now())
    state["rollbackFinalizationProof"] = proof
    state["finalizedFromReceipt"] = True
    journal.commit(state)
    return receipt


def _rollback_receipt_from_state(plan: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    """Deterministically reconstruct a receipt from a durable rollback state."""
    rollback = state.get("rollback")
    require(isinstance(rollback, dict), "rollback journal proof absent")
    journal_status = rollback.get("status")
    require(journal_status in ROLLBACK_RECEIPT_STATUSES, "rollback journal proof status invalid")
    require(
        state.get("status") == journal_status
        or state.get("status") == "rollback-finalizing",
        "rollback journal status/proof drift",
    )
    # A terminal rollback journal reached during the original invocation can
    # be left in ``rollback-finalizing`` by a process crash before its receipt
    # write.  Its reconstructed receipt is a recovered result, while a
    # journal already terminal before re-entry retains its original status.
    status = journal_status
    if state.get("status") == "rollback-finalizing" and not status.startswith("recovered-"):
        status = f"recovered-{status}"
    receipt = _receipt_base(plan, "live")
    receipt["status"] = status
    receipt["operation"] = {
        "operationId": state["operationId"],
        "operationMarker": state["operationMarker"],
        "markerAnnotation": HANDOVER_OPERATION_ANNOTATION,
    }
    receipt["recoveredOperationId"] = state["operationId"]
    receipt["recoveredFromJournal"] = True
    receipt["baseline"]["beforeObjectDigest"] = state["baseline"]["objectDigest"]
    receipt["baseline"]["beforeResourceVersion"] = state["baseline"]["resourceVersion"]
    receipt["objects"] = [_receipt_record_from_journal(record) for record in state.get("createdObjects", [])]
    receipt["rollback"] = copy.deepcopy(rollback)
    receipt["rollback"]["status"] = status
    receipt["rollback"]["kustomizationUnsuspended"] = any(
        event.get("operation") == "unsuspend-kustomization" and event.get("stage") in {"after", "uncertain"}
        for event in state.get("events", [])
    )
    receipt["completedAt"] = state.get("rollbackFinalizedAt") or state.get("completedAt") or _now()
    return receipt


def _rollback_attempt_receipt_from_state(plan: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    """Build the mutable receipt envelope used while retrying pending cleanup."""
    receipt = _receipt_base(plan, "live")
    receipt["operation"] = {
        "operationId": state["operationId"],
        "operationMarker": state["operationMarker"],
        "markerAnnotation": HANDOVER_OPERATION_ANNOTATION,
    }
    receipt["recoveredOperationId"] = state["operationId"]
    receipt["recoveredFromJournal"] = True
    receipt["baseline"]["beforeObjectDigest"] = state["baseline"]["objectDigest"]
    receipt["baseline"]["beforeResourceVersion"] = state["baseline"]["resourceVersion"]
    receipt["objects"] = [_receipt_record_from_journal(record) for record in state.get("createdObjects", [])]
    receipt["rollback"] = copy.deepcopy(state.get("rollback"))
    return receipt


def _prepare_rollback_receipt(*, plan: dict[str, Any], state: dict[str, Any], receipt: dict[str, Any], kube: Any, journal: Any) -> None:
    """Bind a live rollback proof before its receipt becomes durable.

    A complete claim that cannot be proven is downgraded to the explicit
    incomplete status before writing the receipt.  This prevents a transient
    post-delete race from producing a false success claim.
    """
    try:
        proof = _verify_rollback_live_postconditions(plan=plan, state=state, receipt=receipt, kube=kube)
    except Exception as error:
        if receipt.get("status") in {"rolled-back", "recovered-rolled-back"}:
            incomplete_status = "recovered-rollback-incomplete" if receipt["status"].startswith("recovered-") else "rollback-incomplete"
            receipt["status"] = incomplete_status
            state["rollback"]["status"] = incomplete_status
            state["rollback"].setdefault("errors", []).append(f"rollback live proof unavailable: {error}")
            state["status"] = "rollback-finalizing"
            receipt["rollback"] = copy.deepcopy(state["rollback"])
            receipt["rollback"]["kustomizationUnsuspended"] = any(
                event.get("operation") == "unsuspend-kustomization" and event.get("stage") in {"after", "uncertain"}
                for event in state.get("events", [])
            )
            journal.commit(state)
            return
        raise
    state["rollbackPreReceiptProof"] = proof
    journal.commit(state)


def _install_signal_handlers() -> tuple[dict[int, Any], dict[str, bool]]:
    state = {"rollbackActive": False}
    previous: dict[int, Any] = {}

    def handler(signum: int, _frame: Any) -> None:
        if state["rollbackActive"]:
            return
        raise HandoverSignal(signum)

    for signum in (signal.SIGINT, signal.SIGTERM):
        previous[signum] = signal.getsignal(signum)
        signal.signal(signum, handler)
    return previous, state


def _restore_signal_handlers(previous: dict[int, Any]) -> None:
    for signum, handler in previous.items():
        signal.signal(signum, handler)


def _rollback_transaction(
    *,
    kube: Any,
    journal: Any,
    state: dict[str, Any],
    receipt: dict[str, Any],
    recovered: bool,
) -> str:
    """Suspend first, restore the predecessor, then delete exact owned UIDs."""
    rollback_errors: list[str] = []
    deleted_object_ids: list[str] = []
    already_absent_object_ids: list[str] = []
    restored_prior = False
    pending_object_ids: list[str] = []

    records = {record["objectId"]: record for record in state.get("createdObjects", [])}
    kustomization_record = records.get("kustomization")
    suspension_proven = kustomization_record is None
    kustomization_absent_proven = kustomization_record is None
    if kustomization_record is not None:
        identity = kustomization_record["target"]
        try:
            current = kube.get(identity)
            if current is not None:
                current_uid, current_rv = _identity_metadata(current, "rollback workbench baseline Kustomization")
                require(current_uid == kustomization_record["uid"], "rollback Kustomization UID replacement; refusing mutation")
                if current.get("spec", {}).get("suspend") is False:
                    patch = _suspend_patch(current_uid, current_rv)
                    event = _journal_mutation_before(journal, state, "rollback.suspend-kustomization", identity, patch)
                    try:
                        suspended = kube.patch(identity, patch)
                    except Exception as error:
                        _journal_mutation_uncertain(journal, state, event, error)
                        raise
                    _journal_mutation_after(journal, state, event, _journal_result(suspended, "kustomization"))
                    current = suspended
                validate_flux_suspended(current, kustomization_record["uid"])
                suspension_proven = True
            else:
                # An already-absent transaction-owned controller cannot be
                # resumed; absence is safe and the later delete is a no-op.
                already_absent_object_ids.append("kustomization")
                suspension_proven = True
                kustomization_absent_proven = True
        except Exception as rollback_error:
            rollback_errors.append(str(rollback_error))
            suspension_proven = False

    baseline_target = state["baseline"]["target"]
    if suspension_proven:
        try:
            current = kube.get(baseline_target)
            require(current is not None, "rollback workbench NetworkPolicy absent or replaced")
            current_uid, current_rv = _identity_metadata(current, "rollback workbench NetworkPolicy")
            require(current_uid == BASELINE_UID, "rollback workbench NetworkPolicy UID replacement; refusing mutation")
            current_semantics = _server_fields(current)
            if current_semantics == expected_before_network_policy():
                restored_prior = True
            else:
                reconciled = current_semantics == expected_reconciled_network_policy()
                require(reconciled or current_semantics == expected_network_policy(), "rollback workbench NetworkPolicy drift; refusing mutation")
                patch = _baseline_rollback_patch(current_rv, reconciled=reconciled)
                event = _journal_mutation_before(journal, state, "rollback.restore-networkpolicy", baseline_target, patch)
                try:
                    restored = kube.patch(baseline_target, patch)
                except Exception as error:
                    _journal_mutation_uncertain(journal, state, event, error)
                    raise
                _journal_mutation_after(journal, state, event, _journal_result(restored, "networkPolicy"))
                require(_identity_metadata(restored, "restored workbench NetworkPolicy")[0] == BASELINE_UID and _server_fields(restored) == expected_before_network_policy(), "restored workbench NetworkPolicy semantic drift")
                restored_prior = True
        except Exception as rollback_error:
            rollback_errors.append(str(rollback_error))
    else:
        rollback_errors.append("rollback suspended-state proof unavailable; NetworkPolicy restore and Flux deletion skipped")

    deletion_order = reversed(object_order()) if suspension_proven else ()
    for name in deletion_order:
        record = records.get(name)
        if record is None:
            continue
        # The Kustomization owns the reconciliation loop.  Never remove its
        # RBAC while the controller object is still present or terminating.
        # The Kustomization is first in reversed(object_order()); a failed or
        # timed-out proof therefore stops the deletion transaction here.
        if name != "kustomization" and not kustomization_absent_proven:
            rollback_errors.append(f"{name} deletion deferred until Kustomization absence is proven")
            continue
        identity = record["target"]
        try:
            current = kube.get(identity)
            if current is None:
                if name not in already_absent_object_ids:
                    already_absent_object_ids.append(name)
                if name == "kustomization":
                    kustomization_absent_proven = True
                continue
            current_uid, current_rv = _identity_metadata(current, f"rollback {name}")
            delete_options = {
                "apiVersion": "v1",
                "kind": "DeleteOptions",
                "preconditions": {"uid": current_uid, "resourceVersion": current_rv},
            }
            event = _journal_mutation_before(journal, state, f"rollback.delete.{name}", identity, delete_options)
            try:
                outcome = _owned_created(
                    kube,
                    identity,
                    record["uid"],
                    record["desired"],
                    f"rollback {name}",
                    acceptable=(record["markedDesired"], expected_flux_objects(suspended=False)["kustomization"]) if name == "kustomization" else (record["markedDesired"],),
                )
            except Exception as error:
                _journal_mutation_uncertain(journal, state, event, error)
                raise
            _journal_mutation_after(journal, state, event, {"outcome": outcome, "uid": current_uid, "resourceVersion": current_rv})
            if outcome == "present":
                rollback_errors.append(f"{name} remains present after delete")
            elif outcome == "deleted":
                deleted_object_ids.append(name)
                if name == "kustomization":
                    kustomization_absent_proven = True
            else:
                already_absent_object_ids.append(name)
                if name == "kustomization":
                    kustomization_absent_proven = True
        except Exception as rollback_error:
            delete_state = "terminal"
            if name == "kustomization":
                delete_state = _classify_kustomization_delete_failure(kube, record, rollback_error)
                if delete_state == "pending":
                    pending_object_ids.append(name)
                elif delete_state == "absent":
                    # The DELETE may have committed while the wait response
                    # was lost.  Treat a fresh proof of absence as success
                    # and allow the dependent RBAC cleanup to proceed.
                    kustomization_absent_proven = True
                else:
                    rollback_errors.append(str(rollback_error))
            else:
                rollback_errors.append(str(rollback_error))
            if name == "kustomization":
                if delete_state != "absent":
                    kustomization_absent_proven = False
                    # No RBAC deletion is safe while the Kustomization's
                    # asynchronous deletion remains unproven.
                    break

    if pending_object_ids and not rollback_errors:
        # Keep the journal in its pre-receipt phase.  There is deliberately no
        # terminal receipt yet: re-entry must retry the exact UID-bound delete
        # after the controller finalizer clears.
        status = ROLLBACK_PENDING_STATUS
    else:
        status = "rolled-back" if not rollback_errors else "rollback-incomplete"
    receipt_status = f"recovered-{status}" if recovered else status
    # Persist a rollback-finalizing marker before the receipt.  If the process
    # dies after this write, re-entry can finish the receipt deterministically;
    # if the receipt write is lost, the journal still names the exact cleanup
    # proof and never looks like a fresh transaction.
    state["status"] = "rollback-finalizing"
    state["rollback"] = {
        "status": ROLLBACK_PENDING_STATUS if status == ROLLBACK_PENDING_STATUS else receipt_status,
        "suspendFirst": True,
        "restoredPriorOwnerAndSsa": restored_prior,
        "existingNetworkPolicyDeleted": False,
        "deletedObjectIds": sorted(set(deleted_object_ids)),
        "alreadyAbsentObjectIds": sorted(set(already_absent_object_ids)),
        "pendingObjectIds": sorted(set(pending_object_ids)),
        "errors": rollback_errors,
    }
    try:
        journal.commit(state)
    except Exception as journal_error:
        rollback_errors.append(f"rollback journal persistence failed: {journal_error}")
        status = "rollback-incomplete"
        receipt_status = f"recovered-{status}" if recovered else status
        state["status"] = "rollback-finalizing"
        state["rollback"]["status"] = receipt_status
        state["rollback"]["errors"] = rollback_errors
    if status == ROLLBACK_PENDING_STATUS:
        # Leave the mutable envelope uncommitted.  The durable state above is
        # the sole recovery record until Kustomization absence is proven.
        receipt["status"] = ROLLBACK_PENDING_STATUS
        receipt["rollback"] = copy.deepcopy(state["rollback"])
        receipt["completedAt"] = _now()
        return ROLLBACK_PENDING_STATUS
    receipt["status"] = receipt_status
    # A failure can occur after the journal records a create but before the
    # ordinary success-path receipt inventory append.  Keep the rollback
    # receipt's object set exactly aligned with the durable journal.
    receipt_object_ids = {
        item.get("objectId") for item in receipt.get("objects", []) if isinstance(item, dict)
    }
    for record in state.get("createdObjects", []):
        if record.get("objectId") not in receipt_object_ids:
            receipt.setdefault("objects", []).append(_receipt_record_from_journal(record))
    receipt["rollback"] = copy.deepcopy(state["rollback"])
    receipt["rollback"]["kustomizationUnsuspended"] = any(
        event.get("operation") == "unsuspend-kustomization" and event.get("stage") in {"after", "uncertain"}
        for event in state.get("events", [])
    )
    receipt["completedAt"] = _now()
    return receipt_status


def _recover_existing_journal(*, plan: dict[str, Any], kube: Any, journal: Any, sink: Any, signal_state: dict[str, bool] | None = None) -> dict[str, Any]:
    state = journal.load()
    require(state is not None, "handover journal state absent")
    _journal_validate_state(plan, state)
    status = state.get("status")
    if status == "rollback-finalizing":
        rollback = state.get("rollback")
        require(isinstance(rollback, dict), "rollback journal proof absent")
        rollback_status = rollback.get("status")
        if rollback_status == ROLLBACK_PENDING_STATUS:
            # An exact owned Kustomization may still be terminating.  Retry
            # only that durable transaction, with the journaled UID as the
            # ownership boundary; no new create or adoption phase is allowed.
            receipt = _rollback_attempt_receipt_from_state(plan, state)
            receipt["failure"] = "recovered pending Kustomization deletion"
            if signal_state is not None:
                signal_state["rollbackActive"] = True
            retry_status = _rollback_transaction(
                kube=kube,
                journal=journal,
                state=state,
                receipt=receipt,
                recovered=True,
            )
            if retry_status == ROLLBACK_PENDING_STATUS:
                raise HandoverError("rollback remains pending: Kustomization deletion has not reached absence")
            _prepare_rollback_receipt(plan=plan, state=state, receipt=receipt, kube=kube, journal=journal)
            _commit_receipt(sink, receipt)
            return _finalize_rollback_receipt(plan=plan, state=state, receipt=receipt, kube=kube, journal=journal)
        require(rollback_status in ROLLBACK_RECEIPT_STATUSES, "rollback journal proof status invalid")
        # A process may have died after the rollback journal's pre-receipt
        # state was committed.  Reconstruct and prove the terminal receipt
        # without replaying any live mutations.
        receipt = _rollback_receipt_from_state(plan, state)
        _validate_rollback_receipt_identity(plan, state, receipt)
        _verify_rollback_live_postconditions(plan=plan, state=state, receipt=receipt, kube=kube)
        _commit_receipt(sink, receipt)
        return _finalize_rollback_receipt(plan=plan, state=state, receipt=receipt, kube=kube, journal=journal)
    if status in ROLLBACK_RECEIPT_STATUSES:
        # A process can die after the rollback journal commit but before its
        # receipt.  The durable proof is already final; synthesize exactly one
        # receipt, validate the live predecessor/absence boundary, and finish
        # the journal without replaying mutations.
        receipt = _rollback_receipt_from_state(plan, state)
        _validate_rollback_receipt_identity(plan, state, receipt)
        try:
            _verify_rollback_live_postconditions(plan=plan, state=state, receipt=receipt, kube=kube)
            _commit_receipt(sink, receipt)
            return _finalize_rollback_receipt(plan=plan, state=state, receipt=receipt, kube=kube, journal=journal)
        except Exception:
            # Do not claim a recovered rollback when its live proof or receipt
            # persistence is unavailable.  Leave the finalized journal and
            # let the next invocation retry the same deterministic proof.
            raise
    require(status in {"in-progress", "reserved", "finalizing", "rollback-finalizing"}, "handover journal is already finalized; refusing a second transaction")
    receipt = _receipt_base(plan, "live")
    receipt["operation"] = {
        "operationId": state["operationId"],
        "operationMarker": state["operationMarker"],
        "markerAnnotation": HANDOVER_OPERATION_ANNOTATION,
    }
    receipt["recoveredOperationId"] = state["operationId"]
    receipt["recoveredFromJournal"] = True
    receipt["baseline"]["beforeObjectDigest"] = state["baseline"]["objectDigest"]
    receipt["baseline"]["beforeResourceVersion"] = state["baseline"]["resourceVersion"]

    try:
        # A process may have died after the server committed a marked create
        # but before the after-journal write.  Rediscover only the exact
        # marker and protected semantic object; a same-name static object is
        # never adopted.
        known = {record["objectId"]: record for record in state["createdObjects"]}
        expected = expected_flux_objects(suspended=True)
        for event in state["events"]:
            operation = event.get("operation", "")
            if not operation.startswith("create."):
                continue
            name = operation.split(".", 1)[1]
            if name in known or event.get("stage") not in {"before", "uncertain"}:
                continue
            marked = event.get("request")
            if not isinstance(marked, dict):
                continue
            identity = event.get("target")
            if identity != target(expected[name]):
                raise HandoverError(f"recovery {name} create target drift")
            current = kube.get(identity)
            if current is None:
                continue
            try:
                uid, resource_version = _exact_marked_candidate(current, name, expected[name], state["operationMarker"])
            except Exception as error:
                raise HandoverError(f"recovery {name} create outcome is not transaction-owned: {error}") from error
            record = _journal_add_created(
                state,
                name=name,
                identity=identity,
                desired=expected[name],
                marked=marked,
                uid=uid,
                resource_version=resource_version,
                marker_removed=False,
                api_outcome="recovered-created-marker-bound",
            )
            known[name] = record
            journal.commit(state)

        _recover_marker_removals(kube=kube, journal=journal, state=state)

        for record in state["createdObjects"]:
            receipt["objects"].append(_receipt_record_from_journal(record))
        rollback_status = _rollback_transaction(kube=kube, journal=journal, state=state, receipt=receipt, recovered=True)
        if rollback_status == ROLLBACK_PENDING_STATUS:
            raise HandoverError("rollback remains pending: Kustomization deletion has not reached absence")
    except HandoverSignal:
        # Recovery is itself a live transaction.  Once interrupted, suppress
        # further signals and execute the same suspend-first rollback again;
        # the journal remains the durable source for a later re-entry.
        if signal_state is not None:
            signal_state["rollbackActive"] = True
        rollback_status = _rollback_transaction(kube=kube, journal=journal, state=state, receipt=receipt, recovered=True)
        if rollback_status == ROLLBACK_PENDING_STATUS:
            raise HandoverError("rollback remains pending: Kustomization deletion has not reached absence")
    if signal_state is not None:
        signal_state["rollbackActive"] = True
    _prepare_rollback_receipt(plan=plan, state=state, receipt=receipt, kube=kube, journal=journal)
    try:
        _commit_receipt(sink, receipt)
    except Exception:
        # The journal already proves whether cleanup completed.  A receipt
        # persistence failure must never turn an incomplete cleanup into a
        # success claim.
        raise
    return _finalize_rollback_receipt(plan=plan, state=state, receipt=receipt, kube=kube, journal=journal)


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _commit_receipt(sink: Any, receipt: dict[str, Any]) -> None:
    sink.commit(receipt)


def run(
    plan: dict[str, Any],
    *,
    mode: str,
    kube: Any | None = None,
    sink: Any | None = None,
    journal: Any | None = None,
) -> dict[str, Any]:
    """Run one exact handover transaction with durable crash recovery."""
    require(mode in {"dry-run", "live"}, "handover mode invalid")
    require(plan.get("schemaVersion") == PLAN_SCHEMA, "handover plan schema invalid")
    validate_flux_objects({item["objectId"]: item["object"] for item in plan["objects"]}, suspended=True)
    if sink is None:
        sink = MemoryReceiptSink()
    receipt = _receipt_base(plan, mode)
    if mode == "dry-run":
        receipt.update({
            "status": "dry-run",
            "plan": copy.deepcopy(plan),
            "completedAt": _now(),
        })
        _commit_receipt(sink, receipt)
        return receipt

    require(kube is not None, "live handover requires Kubernetes adapter")
    if journal is None:
        journal = MemoryJournalSink()
    # Reserve and validate both durable paths before the first Kubernetes
    # contact.  Memory sinks intentionally have no path and remain useful for
    # deterministic tests/injected callers.
    _validate_sink_separation(sink, journal)
    prior_journal = journal.load()
    # Journal loading is deliberately done before Kubernetes contact, but it
    # is still filesystem I/O.  Re-check both path and descriptor identities
    # immediately before selecting a live recovery/preflight branch.
    _validate_sink_separation(sink, journal)
    if prior_journal is not None:
        previous_handlers, signal_state = _install_signal_handlers()
        try:
            prior_receipt = _receipt_from_sink(sink)
            if prior_receipt is not None and prior_receipt.get("status") == "completed":
                # A completed receipt is immutable.  Never overwrite it with a
                # rollback receipt if its finalization proof fails; leave the
                # journal pending and require an operator to inspect the exact
                # live drift instead.
                try:
                    return _finalize_completed_receipt(
                        plan=plan,
                        state=prior_journal,
                        receipt=prior_receipt,
                        kube=kube,
                        journal=journal,
                    )
                except Exception as finalization_error:
                    raise HandoverError(f"completed handover journal finalization proof failed: {finalization_error}") from finalization_error
            if prior_receipt is not None and prior_receipt.get("status") in ROLLBACK_RECEIPT_STATUSES:
                try:
                    return _finalize_rollback_receipt(
                        plan=plan,
                        state=prior_journal,
                        receipt=prior_receipt,
                        kube=kube,
                        journal=journal,
                    )
                except Exception as finalization_error:
                    raise HandoverError(f"rollback handover journal finalization proof failed: {finalization_error}") from finalization_error
            return _recover_existing_journal(plan=plan, kube=kube, journal=journal, sink=sink, signal_state=signal_state)
        finally:
            _restore_signal_handlers(previous_handlers)
    existing_receipt = _receipt_from_sink(sink)
    require(existing_receipt is None, "completed handover receipt exists without its journal; refusing a second transaction")

    baseline_target = plan["baseline"]["target"]
    desired_objects = {item["objectId"]: item["object"] for item in plan["objects"]}
    source_before: dict[str, Any] | None = None
    receipt_durable = False
    try:
        _validate_sink_separation(sink, journal)
        before = kube.get(baseline_target)
        require(before is not None, "existing workbench NetworkPolicy absent; adoption forbidden")
        uid, before_resource_version = _identity_metadata(before, "existing workbench NetworkPolicy")
        require(uid == BASELINE_UID, "existing workbench NetworkPolicy UID drift; adoption forbidden")
        require(digest(before) == BASELINE_BEFORE_DIGEST, "existing workbench NetworkPolicy exact baseline digest drift")
        require(_server_fields(before) == expected_before_network_policy(), "existing workbench NetworkPolicy semantic baseline drift")
        receipt["baseline"]["beforeObjectDigest"] = digest(before)
        receipt["baseline"]["beforeResourceVersion"] = before_resource_version
        source_before = wait_for_source(kube, plan["protectedRevision"])
        receipt["flux"]["sourceBefore"] = copy.deepcopy(source_before)

        absent: dict[str, dict[str, str]] = {}
        for name in object_order():
            identity = target(desired_objects[name])
            absent[name] = identity
            require(kube.get(identity) is None, f"{name} already exists; adoption forbidden")
    except Exception as error:
        receipt.update({
            "status": "blocked",
            "failure": str(error),
            "completedAt": _now(),
            "rollback": {
                "status": "not-started",
                "restoredPriorOwnerAndSsa": False,
                "existingNetworkPolicyDeleted": False,
                "deletedObjectIds": [],
                "alreadyAbsentObjectIds": [],
                "errors": [],
                "failure": str(error),
            },
        })
        try:
            _commit_receipt(sink, receipt)
        except Exception:
            pass
        raise HandoverError(f"workbench baseline handover blocked: {error}") from error

    operation_id = str(uuid.uuid4())
    operation_marker = str(uuid.uuid4())
    receipt["operation"] = {"operationId": operation_id, "operationMarker": operation_marker, "markerAnnotation": HANDOVER_OPERATION_ANNOTATION}
    state = _journal_initial_state(plan, operation_id=operation_id, operation_marker=operation_marker, before=before)
    state["sourceBefore"] = copy.deepcopy(source_before)
    journal.commit(state)
    previous_handlers, signal_state = _install_signal_handlers()
    try:
        for name in object_order():
            desired = desired_objects[name]
            identity = absent[name]
            marked = _marked_object(desired, operation_marker)
            event = _journal_mutation_before(journal, state, f"create.{name}", identity, marked)
            observed: dict[str, Any] | None = None
            create_outcome = "http-201-created"
            try:
                observed = kube.create(marked)
                uid, resource_version = _exact_marked_candidate(observed, name, desired, operation_marker)
            except Exception as error:
                # A create response can be lost after the API server commits.
                # Re-read the exact target and adopt it only when the unique
                # transaction marker, UID, and complete protected semantics
                # prove that it is this request.  A same-name static object is
                # never adopted.
                try:
                    candidate = kube.get(identity)
                except Exception as discovery_error:
                    _journal_mutation_uncertain(journal, state, event, discovery_error)
                    raise HandoverError(f"{name} create outcome unresolved") from error
                if candidate is None:
                    _journal_mutation_uncertain(journal, state, event, error)
                    raise HandoverError(f"{name} create outcome unresolved") from error
                try:
                    uid, resource_version = _exact_marked_candidate(candidate, name, desired, operation_marker)
                except Exception as ownership_error:
                    _journal_mutation_uncertain(journal, state, event, ownership_error)
                    raise HandoverError(f"{name} create outcome is not transaction-owned") from error
                observed = candidate
                create_outcome = "post-send-uncertain-discovered"
            _journal_add_created(
                state,
                name=name,
                identity=identity,
                desired=desired,
                marked=marked,
                uid=uid,
                resource_version=resource_version,
                marker_removed=False,
                api_outcome=create_outcome,
            )
            _journal_mutation_after(journal, state, event, _journal_result(observed, name))
            receipt["objects"].append(_receipt_created_record(name, identity, desired, marked, uid, resource_version, False) | {"apiOutcome": create_outcome})

            marker_patch = _marker_remove_patch(uid, resource_version, operation_marker)
            marker_event = _journal_mutation_before(journal, state, f"remove-marker.{name}", identity, marker_patch)
            try:
                marker_removed = kube.patch(identity, marker_patch)
                removed_uid, removed_rv = _static_candidate(marker_removed, name, desired, expected_uid=uid)
            except Exception as error:
                try:
                    candidate = kube.get(identity)
                except Exception as discovery_error:
                    _journal_mutation_uncertain(journal, state, marker_event, discovery_error)
                    raise HandoverError(f"{name} marker removal outcome unresolved") from error
                try:
                    removed_uid, removed_rv = _static_candidate(candidate, name, desired, expected_uid=uid)
                    require(HANDOVER_OPERATION_ANNOTATION not in candidate.get("metadata", {}).get("annotations", {}), f"{name} marker removal outcome ambiguous")
                except Exception as ownership_error:
                    _journal_mutation_uncertain(journal, state, marker_event, ownership_error)
                    raise HandoverError(f"{name} marker removal outcome unresolved") from error
                marker_removed = candidate
            _journal_update_created(state, name=name, uid=removed_uid, resource_version=removed_rv, marker_removed=True)
            _journal_mutation_after(journal, state, marker_event, _journal_result(marker_removed, name))
            for record in receipt["objects"]:
                if record["objectId"] == name:
                    record["uid"] = removed_uid
                    record["resourceVersion"] = removed_rv
                    record["postMarkerResourceVersion"] = removed_rv
                    record["markerRemoved"] = True

        baseline_patch = _baseline_patch(before_resource_version)
        baseline_event = _journal_mutation_before(journal, state, "patch-networkpolicy", baseline_target, baseline_patch)
        try:
            changed = kube.patch(baseline_target, baseline_patch)
        except Exception as error:
            _journal_mutation_uncertain(journal, state, baseline_event, error)
            raise
        _journal_mutation_after(journal, state, baseline_event, _journal_result(changed, "networkPolicy"))
        changed_uid, changed_rv = _identity_metadata(changed, "adopted workbench NetworkPolicy")
        require(changed_uid == BASELINE_UID, "adopted workbench NetworkPolicy UID changed")
        require(_server_fields(changed) == expected_network_policy(), "adopted workbench NetworkPolicy semantic drift")
        receipt["effects"]["networkPolicyOwnerLabelChanged"] = True
        receipt["effects"]["fluxSsaOverrideAdded"] = True
        receipt["baseline"]["afterResourceVersion"] = changed_rv
        receipt["baseline"]["afterSemanticDigest"] = digest(_server_fields(changed))

        kustomization_identity = absent["kustomization"]
        kustomization = kube.get(kustomization_identity)
        require(kustomization is not None, "workbench baseline Kustomization disappeared before activation")
        kustomization_uid, kustomization_rv = _identity_metadata(kustomization, "workbench baseline Kustomization")
        validate_flux_suspended(kustomization, kustomization_uid)
        unsuspend_patch = _unsuspend_patch(kustomization_uid, kustomization_rv)
        unsuspend_event = _journal_mutation_before(journal, state, "unsuspend-kustomization", kustomization_identity, unsuspend_patch)
        try:
            activated = kube.patch(kustomization_identity, unsuspend_patch)
        except Exception as error:
            _journal_mutation_uncertain(journal, state, unsuspend_event, error)
            raise
        _journal_mutation_after(journal, state, unsuspend_event, _journal_result(activated, "kustomization"))
        activated_uid, activated_rv = _identity_metadata(activated, "unsuspended workbench baseline Kustomization")
        require(activated_uid == kustomization_uid and int(activated_rv) > int(kustomization_rv), "Kustomization CAS unsuspend identity drift")
        require(_flux_server_fields(activated) == expected_flux_objects(suspended=False)["kustomization"], "Kustomization CAS unsuspend semantic drift")
        require(activated["spec"].get("suspend") is False, "Kustomization CAS unsuspend did not take effect")
        receipt["effects"]["kustomizationUnsuspended"] = True
        receipt["flux"]["casUnsuspend"] = {
            "uid": activated_uid,
            "beforeResourceVersion": kustomization_rv,
            "afterResourceVersion": activated_rv,
            "suspendBefore": True,
            "suspendAfter": False,
        }

        ready = wait_for_flux_ready(kube, kustomization_identity, kustomization_uid, plan["protectedRevision"])
        receipt["flux"]["ready"] = copy.deepcopy(ready)
        receipt["effects"]["fluxReady"] = True
        source_after = wait_for_source(kube, plan["protectedRevision"])
        require(source_before is not None and source_after["uid"] == source_before["uid"], "shared Flux source UID changed during handover")
        receipt["flux"]["sourceAfter"] = copy.deepcopy(source_after)
        state["sourceAfter"] = copy.deepcopy(source_after)
        journal.commit(state)

        after = kube.get(baseline_target)
        require(after is not None and _identity_metadata(after, "final workbench NetworkPolicy")[0] == BASELINE_UID, "final workbench NetworkPolicy absent or replaced")
        validate_reconciled_network_policy(after)
        after_uid, reconciled_rv = _identity_metadata(after, "reconciled workbench NetworkPolicy")
        receipt["flux"]["networkPolicyReconciled"] = {
            "uid": after_uid,
            "resourceVersion": reconciled_rv,
            "semanticDigest": digest(_server_fields(after)),
            "specDigest": digest(after["spec"]),
            "inventoryLabels": copy.deepcopy(FLUX_INVENTORY_LABELS),
            "reconciled": True,
        }
        receipt["effects"]["networkPolicyReconciled"] = True
        receipt["baseline"]["reconciledResourceVersion"] = reconciled_rv
        receipt["baseline"]["reconciledSemanticDigest"] = digest(_server_fields(after))

        for name in object_order():
            record = next(item for item in state["createdObjects"] if item["objectId"] == name)
            observed = kube.get(record["target"])
            require(observed is not None, f"{name} disappeared before handover receipt")
            live_uid, live_rv = _identity_metadata(observed, name)
            if name == "kustomization":
                require(live_uid == record["uid"] and _flux_server_fields(observed) == expected_flux_objects(suspended=False)["kustomization"], f"{name} postcondition drift")
            else:
                require(live_uid == record["uid"] and _server_fields(observed) == _server_fields(record["desired"]), f"{name} postcondition drift")
            for receipt_record in receipt["objects"]:
                if receipt_record["objectId"] == name:
                    receipt_record["postResourceVersion"] = live_rv
        receipt.update({"status": "completed", "completedAt": _now()})
        # Two-phase finalization: the journal first records that the receipt
        # is being committed.  A process death before the receipt write is
        # recovered as an unreceipted transaction; a death after the receipt
        # write can prove and finalize the journal without another mutation.
        state["status"] = "finalizing"
        state["finalizingAt"] = _now()
        journal.commit(state)
        _commit_receipt(sink, receipt)
        receipt_durable = True
        state["status"] = "completed"
        state["completedAt"] = receipt["completedAt"]
        journal.commit(state)
        return receipt
    except Exception as error:
        if not receipt_durable:
            # A storage backend may throw after its atomic replace.  Re-read
            # its immutable value before deciding to roll back; otherwise a
            # durable success receipt could be mistaken for an unreceipted
            # transaction.
            persisted = _receipt_from_sink(sink)
            if persisted is not None and persisted.get("status") == "completed":
                try:
                    _validate_completed_receipt_identity(plan, state, persisted)
                except Exception:
                    persisted = None
                receipt_durable = persisted is not None
        if receipt_durable:
            # The receipt is already the durable user-visible success record;
            # do not mutate live state merely because the final journal write
            # was lost.  Re-entry will prove the exact postconditions and
            # finish the journal.
            raise HandoverError(f"completed handover receipt durable; journal finalization pending: {error}") from error
        signal_state["rollbackActive"] = True
        receipt["failure"] = str(error)
        status = _rollback_transaction(kube=kube, journal=journal, state=state, receipt=receipt, recovered=False)
        if status == ROLLBACK_PENDING_STATUS:
            # Keep only the durable rollback-finalizing journal.  Committing a
            # terminal incomplete receipt here would make a retry impossible
            # even though the exact Kustomization UID is still safely owned.
            raise HandoverError(
                "workbench baseline handover rollback pending: "
                "Kustomization deletion has not reached absence"
            ) from error
        _prepare_rollback_receipt(plan=plan, state=state, receipt=receipt, kube=kube, journal=journal)
        status = receipt["status"]
        try:
            _commit_receipt(sink, receipt)
        except Exception as receipt_error:
            raise HandoverError(f"workbench baseline handover {status}; receipt persistence failed: {receipt_error}") from error
        try:
            _finalize_rollback_receipt(
                plan=plan,
                state=state,
                receipt=receipt,
                kube=kube,
                journal=journal,
            )
        except Exception as journal_error:
            raise HandoverError(f"workbench baseline handover {status}; rollback journal finalization pending: {journal_error}") from error
        raise HandoverError(f"workbench baseline handover {status}: {error}") from error
    finally:
        _restore_signal_handlers(previous_handlers)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--expected-protected-revision", required=True)
    parser.add_argument("--kubeconfig")
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--journal", help="private durable journal path; defaults to <receipt>.journal")
    args = parser.parse_args(argv)
    context = load_context(args.expected_protected_revision)
    if args.dry_run:
        sink = ReceiptSink(Path(args.receipt))
        result = run(context["plan"], mode="dry-run", sink=sink)
    else:
        require(args.kubeconfig, "live handover requires --kubeconfig")
        receipt_path = Path(args.receipt)
        journal_path = Path(args.journal) if args.journal else receipt_path.with_name(receipt_path.name + JOURNAL_DEFAULT_SUFFIX)
        # Load the journal first so a durable completed receipt can safely
        # finish a receipt-first crash window on re-entry.  ReceiptSink keeps
        # completed receipts immutable and only exposes them for proof.
        journal = JournalSink(journal_path)
        sink = ReceiptSink(receipt_path, allow_existing_completed=True)
        result = run(context["plan"], mode="live", kube=KubernetesAdapter(args.kubeconfig), sink=sink, journal=journal)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    if not (sys.flags.isolated and sys.flags.safe_path):
        print("workbench handover blocked: invoke with python3 -I", file=sys.stderr)
        raise SystemExit(2)
    try:
        raise SystemExit(main(sys.argv[1:]))
    except HandoverError as error:
        print(f"workbench handover blocked: {error}", file=sys.stderr)
        raise SystemExit(1) from error
