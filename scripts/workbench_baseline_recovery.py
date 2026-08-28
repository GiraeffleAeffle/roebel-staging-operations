"""One-shot, delete-only recovery for the failed G0 workbench transaction.

This is intentionally a different transaction from the handover implementation.
It never creates, patches, applies, lists, reads Secrets, or changes the
existing NetworkPolicy.  It can remove only the four exact Flux identities
created by the failed, evidence-bound attempt, after proving every identity,
semantic projection, marker, and predecessor/source precondition.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "roebel_staging_workbench_baseline_recovery_v1"
JOURNAL_SCHEMA = "roebel_staging_workbench_baseline_recovery_journal_v1"
RECEIPT_SCHEMA = "roebel_staging_workbench_baseline_recovery_receipt_v1"
ORIGIN_REVISION = "3be9405c6bfd6b4caf0423b137f969aab3bef323"
ORIGIN_JOURNAL_FILE_SHA256 = "sha256:70015e2728bf8e30491862687c3b507aa3d4d03e4f91b72cafb84ae3dcba30c0"
ORIGIN_JOURNAL_EMBEDDED_SHA256 = "sha256:cd15195c7d1ce3209f65ab6b579d6c5926db4e730272e64da8894a9fc19d7a18"
ATTEMPT_RECEIPT_SHA256 = "sha256:55a7cfac98cdb40aa49a46a00abbd47d8305cff4d001f8984c57a0c964d51ee9"
INSPECTION_SHA256 = "sha256:d7a94d4e27c18317ede34f6700a7c4a27081133bd7f881e46d5bd30466430755"
TERMINAL_RECOVERY_REVISION = "18b1780be9b2e1d8bad05e27f81f11d9b104ab06"
TERMINAL_RECOVERY_JOURNAL_FILE_SHA256 = "sha256:d6e16407761ecbf2d6ce29aab48f10f4420770a7b97b393b53b9753152f5f604"
TERMINAL_RECOVERY_JOURNAL_CANONICAL_SHA256 = "sha256:cdeab725635754bb4a220bc915e4ff69a46246b6336ca954681d7ff6e7497613"
TERMINAL_FINALIZATION_PARENT_REVISION = "9f7a7a1e96065e849a8b7a9879de1fadb9ec6e2f"
OPERATION_ID = "b6b52abc-4b28-4db0-b4ef-74041f41d7c6"
OPERATION_MARKER = "77157c24-d1d0-4cb8-850b-538f380c16fd"
BASELINE_UID = "298b0f92-0d6b-4563-b141-f93aa8c8fd8f"
BASELINE_DIGEST = "sha256:21c582036f38a54649b771a6dec1ba599ca859029a1c32246ef8aee6a00359c5"
WORKBENCH_NAMESPACE = "stadtstack-roebel-staging-lab"
WORKBENCH_NAME = "e2e-workbench"
FLUX_NAMESPACE = "flux-roebel-staging"
FLUX_NAME = "roebel-staging-workbench-baseline"
RECONCILER_NAME = "roebel-staging-workbench-baseline-reconciler"
SOURCE_NAME = "roebel-staging-operations"
SOURCE_UID = "0de8a05d-550f-429c-93c5-9b8c76b0bf9b"
BASELINE_ROOT = "reviewed-render/roebel-staging/workbench-baseline"
KUBECTL_BIN = Path("/Users/max/.local/bin/kubectl-v1.36.0")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
MARKER_ANNOTATION = "stadtstack.io/workbench-handover-operation"
FINALIZER = "finalizers.fluxcd.io"
OBJECT_ORDER = ("kustomization", "roleBinding", "role", "serviceAccount")
OBJECT_UIDS = {
    "kustomization": "d251a65f-b322-44a5-8e03-76ca268e72be",
    "roleBinding": "d7e8ec85-3fad-41ff-873b-4b8920c7b8df",
    "role": "2ca77559-34dc-4573-85e3-2c41242eab12",
    "serviceAccount": "c0829ad9-ab20-43a0-9c84-a122098864f0",
}
MARKER_REMAINS = frozenset({"kustomization"})
GET_MAX_ATTEMPTS = 3
GET_RETRY_DELAYS_SECONDS = (0.25, 0.75)
GET_TLS_HANDSHAKE_TIMEOUT = "net/http: TLS handshake timeout"
GET_ERROR_MAX_CHARS = 320


class RecoveryError(RuntimeError):
    """A closed recovery precondition, mutation, or output failure."""


def require(value: bool, message: str) -> None:
    if not value:
        raise RecoveryError(message)


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value).encode()).hexdigest()


def bytes_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _bounded_get_error(value: Any) -> str:
    """Normalize and cap a kubectl GET error before it enters a receipt."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return " ".join(str(value).split())[:GET_ERROR_MAX_CHARS]


def _normalized_get_transport_error(value: Any) -> str:
    """Return only the exact kubectl client transport error token."""
    normalized = _bounded_get_error(value)
    prefix = "Unable to connect to the server: "
    if normalized.startswith(prefix):
        normalized = normalized[len(prefix):]
    return normalized


def _is_retryable_get_transport_failure(code: int, out: Any, err: Any) -> bool:
    return code != 0 and not out and _normalized_get_transport_error(err) == GET_TLS_HANDSHAKE_TIMEOUT


def _json_object(raw: bytes, label: str) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            require(key not in value, f"{label}: duplicate JSON key")
            value[key] = item
        return value
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError, RecoveryError) as error:
        raise RecoveryError(f"{label}: invalid JSON") from error
    require(isinstance(value, dict), f"{label}: JSON object required")
    return value


def _labels() -> dict[str, str]:
    return {
        "app.kubernetes.io/component": "workbench-baseline",
        "app.kubernetes.io/name": FLUX_NAME,
        "app.kubernetes.io/part-of": "stadtstack",
        "stadtstack.io/authority": "none",
        "stadtstack.io/civic-authority": "none",
        "stadtstack.io/environment": "staging",
        "stadtstack.io/flux-tenant": "roebel-staging",
        "stadtstack.io/gitops-owner": "workbench-baseline",
    }


def expected_objects() -> dict[str, dict[str, Any]]:
    service_account = {
        "apiVersion": "v1", "kind": "ServiceAccount",
        "metadata": {"labels": _labels(), "name": RECONCILER_NAME, "namespace": FLUX_NAMESPACE},
        "automountServiceAccountToken": False,
    }
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"labels": _labels(), "name": RECONCILER_NAME, "namespace": WORKBENCH_NAMESPACE},
        "rules": [{"apiGroups": ["networking.k8s.io"], "resourceNames": [WORKBENCH_NAME], "resources": ["networkpolicies"], "verbs": ["get", "patch", "update"]}],
    }
    role_binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"labels": _labels(), "name": RECONCILER_NAME, "namespace": WORKBENCH_NAMESPACE},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": RECONCILER_NAME},
        "subjects": [{"kind": "ServiceAccount", "name": RECONCILER_NAME, "namespace": FLUX_NAMESPACE}],
    }
    kustomization = {
        "apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization",
        "metadata": {"labels": _labels(), "name": FLUX_NAME, "namespace": FLUX_NAMESPACE},
        "spec": {
            "deletionPolicy": "Orphan", "dependsOn": [], "force": False, "healthChecks": [],
            "interval": "5m", "path": f"./{BASELINE_ROOT}", "prune": False,
            "retryInterval": "30s", "serviceAccountName": RECONCILER_NAME,
            "sourceRef": {"kind": "GitRepository", "name": SOURCE_NAME, "namespace": FLUX_NAMESPACE},
            "suspend": True, "targetNamespace": WORKBENCH_NAMESPACE, "timeout": "2m", "wait": True,
        },
    }
    return {"kustomization": kustomization, "roleBinding": role_binding, "role": role, "serviceAccount": service_account}


def expected_source() -> dict[str, Any]:
    return {
        "apiVersion": "source.toolkit.fluxcd.io/v1", "kind": "GitRepository",
        "metadata": {"labels": {"stadtstack.io/flux-tenant": "roebel-staging"}, "name": SOURCE_NAME, "namespace": FLUX_NAMESPACE},
        "spec": {"interval": "1m", "ref": {"branch": "main"}, "suspend": False, "timeout": "30s", "url": "https://github.com/GiraeffleAeffle/roebel-staging-operations.git"},
    }


def expected_baseline() -> dict[str, Any]:
    return {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": WORKBENCH_NAME, "namespace": WORKBENCH_NAMESPACE},
    }


def target(value: dict[str, Any]) -> dict[str, str]:
    metadata = value.get("metadata")
    require(isinstance(metadata, dict), "object metadata absent")
    return {"apiVersion": value["apiVersion"], "kind": value["kind"], "namespace": metadata["namespace"], "name": metadata["name"]}


def _identity(value: Any, label: str) -> tuple[str, str]:
    require(isinstance(value, dict), f"{label} object absent")
    metadata = value.get("metadata")
    require(isinstance(metadata, dict), f"{label} metadata absent")
    uid, resource_version = metadata.get("uid"), metadata.get("resourceVersion")
    require(isinstance(uid, str) and UUID.fullmatch(uid), f"{label} UID invalid")
    require(isinstance(resource_version, str) and resource_version.isdigit(), f"{label} resourceVersion invalid")
    return uid, resource_version


def _server_fields(value: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(value)
    metadata = result.get("metadata")
    require(isinstance(metadata, dict), "Kubernetes object metadata absent")
    for key in ("creationTimestamp", "deletionGracePeriodSeconds", "deletionTimestamp", "generation", "managedFields", "resourceVersion", "selfLink", "uid"):
        metadata.pop(key, None)
    if not metadata.get("annotations"):
        metadata.pop("annotations", None)
    result.pop("status", None)
    return result


def _flux_server_fields(value: dict[str, Any]) -> dict[str, Any]:
    result = _server_fields(value)
    if result.get("kind") in {"Kustomization", "GitRepository"} and result["metadata"].get("finalizers") == [FINALIZER]:
        result["metadata"].pop("finalizers")
    return result


def source_target() -> dict[str, str]:
    return target(expected_source())


def baseline_target() -> dict[str, str]:
    return target(expected_baseline())


def _marker_annotations(name: str) -> dict[str, str] | None:
    return {MARKER_ANNOTATION: OPERATION_MARKER} if name in MARKER_REMAINS else None


def _validate_origin_inputs(origin_journal: bytes, attempt_receipt: bytes, inspection: bytes) -> dict[str, str]:
    require(bytes_digest(origin_journal) == ORIGIN_JOURNAL_FILE_SHA256, "origin journal file checksum drift")
    require(bytes_digest(attempt_receipt) == ATTEMPT_RECEIPT_SHA256, "attempt receipt checksum drift")
    require(bytes_digest(inspection) == INSPECTION_SHA256, "inspection checksum drift")
    origin = _json_object(origin_journal, "origin journal")
    require(origin.get("journalSha256") == ORIGIN_JOURNAL_EMBEDDED_SHA256, "origin journal embedded checksum drift")
    require(origin.get("protectedRevision") == ORIGIN_REVISION, "origin journal revision drift")
    require(origin.get("operationId") == OPERATION_ID and origin.get("operationMarker") == OPERATION_MARKER, "origin journal operation binding drift")
    baseline = origin.get("baseline")
    require(isinstance(baseline, dict) and baseline.get("uid") == BASELINE_UID and baseline.get("objectDigest") == BASELINE_DIGEST, "origin journal baseline binding drift")
    records = origin.get("createdObjects")
    require(isinstance(records, list), "origin journal created-object inventory absent")
    by_name = {item.get("objectId"): item for item in records if isinstance(item, dict)}
    require(set(by_name) == set(OBJECT_ORDER) and len(by_name) == len(records), "origin journal created-object set drift")
    for name in OBJECT_ORDER:
        item = by_name[name]
        desired = expected_objects()[name]
        marked = copy.deepcopy(desired); marked["metadata"]["annotations"] = {MARKER_ANNOTATION: OPERATION_MARKER}
        require(item.get("target") == target(desired), f"origin journal {name} target drift")
        require(item.get("desired") == desired and item.get("markedDesired") == marked, f"origin journal {name} desired projection drift")
        require(item.get("uid") == OBJECT_UIDS[name], f"origin journal {name} UID drift")
        require(item.get("markerRemoved") is (name not in MARKER_REMAINS), f"origin journal {name} marker-removal state drift")
    _validate_inspection_projection(_json_object(inspection, "read-only inspection"))
    return {"originJournalSha256": bytes_digest(origin_journal), "attemptReceiptSha256": bytes_digest(attempt_receipt), "inspectionSha256": bytes_digest(inspection)}


def _validate_source(value: Any, revision: str) -> dict[str, Any]:
    require(
        isinstance(value, dict) and value.get("metadata", {}).get("finalizers") == [FINALIZER],
        "shared Flux source finalizer drift",
    )
    require(_flux_server_fields(value) == expected_source(), "shared Flux source semantic drift")
    uid, _resource_version = _identity(value, "shared Flux source")
    require(uid == SOURCE_UID, "shared Flux source UID drift")
    status = value.get("status")
    require(isinstance(status, dict), "shared Flux source status absent")
    require(status.get("artifact", {}).get("revision") == f"main@sha1:{revision}", "shared Flux source revision drift")
    require(status.get("observedGeneration") == value.get("metadata", {}).get("generation"), "shared Flux source generation drift")
    ready = next((item for item in status.get("conditions", []) if isinstance(item, dict) and item.get("type") == "Ready"), None)
    require(isinstance(ready, dict) and ready.get("status") == "True", "shared Flux source not Ready")
    generation = value.get("metadata", {}).get("generation")
    require(isinstance(generation, int) and generation >= 1, "shared Flux source generation invalid")
    return {"uid": uid, "revision": f"main@sha1:{revision}", "generation": generation}


def _validate_baseline(value: Any) -> dict[str, Any]:
    require(isinstance(value, dict) and target(value) == baseline_target(), "baseline target drift")
    uid, rv = _identity(value, "baseline")
    require(uid == BASELINE_UID, "baseline UID drift")
    require(digest(value) == BASELINE_DIGEST, "baseline digest drift")
    return {"uid": uid, "resourceVersion": rv, "digest": BASELINE_DIGEST}


def _validate_object(name: str, value: Any, *, expected_uid: str) -> dict[str, Any]:
    desired = expected_objects()[name]
    require(isinstance(value, dict) and target(value) == target(desired), f"{name} target drift")
    uid, rv = _identity(value, name)
    require(uid == expected_uid, f"{name} UID replacement; deletion forbidden")
    annotations = value.get("metadata", {}).get("annotations")
    require(annotations == _marker_annotations(name), f"{name} transaction marker state drift")
    semantic = _flux_server_fields(value) if name == "kustomization" else _server_fields(value)
    expected = _flux_server_fields(desired) if name == "kustomization" else _server_fields(desired)
    if name in MARKER_REMAINS:
        expected["metadata"]["annotations"] = _marker_annotations(name)
    require(semantic == expected, f"{name} semantic drift; deletion forbidden")
    if name == "kustomization":
        require(value.get("metadata", {}).get("finalizers") == [FINALIZER], "Kustomization finalizer drift")
        require(value.get("spec", {}).get("suspend") is True, "Kustomization must remain suspended")
    return {"uid": uid, "resourceVersion": rv}


def _validate_inspection_projection(inspection: dict[str, Any]) -> None:
    """Bind the independently captured, read-only G0 object projection."""
    require(
        inspection.get("schemaVersion") == "stadtstack_workbench_read_only_inspection_v1"
        and inspection.get("containsSecretMaterial") is False
        and inspection.get("mutationAttempted") is False,
        "read-only inspection boundary drift",
    )
    values = inspection.get("objects")
    expected_keys = {"kustomization", "networkPolicy", "role", "roleBinding", "serviceAccount", "source"}
    require(isinstance(values, dict) and set(values) == expected_keys, "read-only inspection inventory drift")
    _validate_baseline(values["networkPolicy"])
    _validate_source(values["source"], ORIGIN_REVISION)
    for name in OBJECT_ORDER:
        _validate_object(name, values[name], expected_uid=OBJECT_UIDS[name])
    require(
        inspection.get("proof") == {
            "kustomizationNormalizedDiffPaths": ["$.metadata.annotations"],
            "networkPolicyCanonicalSha256": BASELINE_DIGEST,
        },
        "read-only inspection proof drift",
    )


def _event(state: dict[str, Any], stage: str, operation: str, details: dict[str, Any]) -> dict[str, Any]:
    previous = state["events"][-1]["entrySha256"] if state["events"] else None
    event: dict[str, Any] = {"sequence": len(state["events"]) + 1, "stage": stage, "operation": operation, "previousEntrySha256": previous}
    event.update(copy.deepcopy(details)); event["entrySha256"] = digest(event); state["events"].append(event)
    return event


def _rehash(event: dict[str, Any]) -> None:
    event.pop("entrySha256", None); event["entrySha256"] = digest(event)


class MemoryJournal:
    def __init__(self, state: dict[str, Any] | None = None) -> None: self.state = copy.deepcopy(state); self.values: list[dict[str, Any]] = []
    def load(self) -> dict[str, Any] | None: return copy.deepcopy(self.state)
    def commit(self, value: dict[str, Any]) -> None: self.state = copy.deepcopy(value); self.values.append(copy.deepcopy(value))


class MemoryReceipt:
    def __init__(self) -> None: self.value: dict[str, Any] | None = None
    def commit(self, value: dict[str, Any]) -> None:
        require(self.value is None, "recovery receipt is immutable")
        self.value = copy.deepcopy(value)


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _private_parent(path: Path, label: str) -> Path:
    """Return an owner-only canonical parent and reject a symlinked output."""
    provided = Path(path)
    try:
        final_info = os.lstat(provided)
    except FileNotFoundError:
        pass
    else:
        require(not stat.S_ISLNK(final_info.st_mode), f"{label} path cannot be a symlink")
    # macOS exposes /var as a system symlink to /private/var.  Resolve parent
    # aliases once, then verify each component of the canonical target path.
    # A pre-existing final component was rejected above, so this never blesses
    # a symlinked output file.
    selected = Path(os.path.realpath(os.path.abspath(provided)))
    require(selected.is_absolute(), f"{label} path invalid")
    current = Path(selected.anchor)
    for part in selected.parts[1:-1]:
        current /= part
        info = os.lstat(current)
        require(stat.S_ISDIR(info.st_mode) and not current.is_symlink(), f"{label} parent contains a symlink or non-directory")
    info = os.lstat(selected.parent)
    require(
        stat.S_ISDIR(info.st_mode)
        and not selected.parent.is_symlink()
        and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) & 0o077 == 0,
        f"{label} parent must be private and owned",
    )
    return selected


def _private_file_identity(path: Path, label: str, *, allow_empty: bool) -> tuple[int, int, int]:
    info = os.lstat(path)
    require(
        stat.S_ISREG(info.st_mode)
        and not path.is_symlink()
        and info.st_uid == os.geteuid()
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o600
        and (allow_empty or info.st_size > 0),
        f"{label} file invalid",
    )
    return info.st_dev, info.st_ino, info.st_size


def _reserve_private_output(path: Path, label: str, *, allow_existing: bool) -> tuple[Path, tuple[int, int, int]]:
    selected = _private_parent(path, label)
    try:
        identity = _private_file_identity(selected, label, allow_empty=True)
    except FileNotFoundError:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(selected, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
        _fsync_directory(selected.parent)
        identity = _private_file_identity(selected, label, allow_empty=True)
    else:
        require(allow_existing, f"{label} is already reserved or completed")
    return selected, identity


def _read_private(path: Path, label: str, maximum: int) -> bytes:
    _private_parent(path, label)
    before = _private_file_identity(path, label, allow_empty=False)
    require(before[2] <= maximum, f"{label} size invalid")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        require((opened.st_dev, opened.st_ino, opened.st_size) == before, f"{label} identity changed while opening")
        raw = os.pread(fd, opened.st_size + 1, 0)
        after = os.fstat(fd)
        require(len(raw) == opened.st_size and (after.st_dev, after.st_ino, after.st_size) == before, f"{label} changed while reading")
        return raw
    finally:
        os.close(fd)


def _decode_checksummed(raw: bytes, label: str, checksum_key: str) -> dict[str, Any]:
    value = _json_object(raw, label)
    checksum = value.pop(checksum_key, None)
    require(isinstance(checksum, str) and SHA256.fullmatch(checksum) and checksum == digest(value), f"{label} checksum drift")
    return value


def _atomic_private_json(
    path: Path,
    expected_identity: tuple[int, int, int],
    value: dict[str, Any],
    checksum_key: str,
    maximum: int,
) -> tuple[int, int, int]:
    """Atomically replace exactly the reserved owner-only path and fsync it."""
    require(checksum_key not in value, "output checksum key collision")
    final = copy.deepcopy(value)
    final[checksum_key] = digest(value)
    raw = (canonical(final) + "\n").encode()
    require(len(raw) <= maximum, "output too large")
    require(_private_file_identity(path, "recovery output", allow_empty=True) == expected_identity, "reserved output identity changed")
    fd, temporary_name = tempfile.mkstemp(prefix=".workbench-recovery-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            fd = -1
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        temp_identity = _private_file_identity(temporary, "recovery temporary output", allow_empty=False)
        require(temp_identity[2] == len(raw), "recovery temporary output size drift")
        os.replace(temporary, path)
        os.chmod(path, 0o600, follow_symlinks=False)
        _fsync_directory(path.parent)
        return _private_file_identity(path, "recovery output", allow_empty=False)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


class JsonJournal:
    MAX_BYTES = 1024 * 1024
    def __init__(self, path: Path) -> None:
        self.path, self.identity = _reserve_private_output(path, "recovery journal", allow_existing=True)
    def load(self) -> dict[str, Any] | None:
        current = _private_file_identity(self.path, "recovery journal", allow_empty=True)
        require(current == self.identity, "recovery journal reservation identity changed")
        if current[2] == 0:
            return None
        return _decode_checksummed(_read_private(self.path, "recovery journal", self.MAX_BYTES), "recovery journal", "journalSha256")
    def raw_sha256(self) -> str:
        current = _private_file_identity(self.path, "recovery journal", allow_empty=False)
        require(current == self.identity, "recovery journal reservation identity changed")
        return bytes_digest(_read_private(self.path, "recovery journal", self.MAX_BYTES))
    def commit(self, value: dict[str, Any]) -> None:
        self.identity = _atomic_private_json(self.path, self.identity, value, "journalSha256", self.MAX_BYTES)


class JsonReceipt:
    MAX_BYTES = 1024 * 1024
    def __init__(self, path: Path) -> None:
        self.path, self.identity = _reserve_private_output(path, "recovery receipt", allow_existing=False)
        require(self.identity[2] == 0, "recovery receipt is already completed")
        self.committed = False
    def commit(self, value: dict[str, Any]) -> None:
        require(not self.committed and self.identity[2] == 0, "recovery receipt is immutable")
        self.identity = _atomic_private_json(self.path, self.identity, value, "canonicalSha256", self.MAX_BYTES)
        self.committed = True


def _private_path(path: Path, label: str, *, allow_missing: bool) -> Path:
    selected = _private_parent(path, label)
    try:
        _private_file_identity(selected, label, allow_empty=True)
    except FileNotFoundError:
        if not allow_missing:
            raise RecoveryError(f"{label} absent")
    return selected


def _validate_output_separation(journal: Any, receipt: Any) -> None:
    """Reject same-path and inode aliases before the first Kubernetes GET."""
    journal_path, receipt_path = getattr(journal, "path", None), getattr(receipt, "path", None)
    if journal_path is None or receipt_path is None:
        return
    journal_selected = _private_parent(Path(journal_path), "recovery journal")
    receipt_selected = _private_parent(Path(receipt_path), "recovery receipt")
    require(os.path.normcase(os.path.normpath(os.fspath(journal_selected))) != os.path.normcase(os.path.normpath(os.fspath(receipt_selected))), "recovery receipt and journal paths must be distinct")
    journal_identity = _private_file_identity(journal_selected, "recovery journal", allow_empty=True)
    receipt_identity = _private_file_identity(receipt_selected, "recovery receipt", allow_empty=True)
    require(journal_identity[:2] != receipt_identity[:2], "recovery receipt and journal inode aliases are forbidden")


class KubernetesAdapter:
    """Closed GET with bounded transport retry plus preconditioned DELETE."""
    def __init__(self, kubeconfig: Path, *, kubectl: Path | None = None) -> None:
        self.kubeconfig = _private_path(kubeconfig, "kubeconfig", allow_missing=False)
        self.kubectl = KUBECTL_BIN if kubectl is None else kubectl
    def _run(self, arguments: list[str], *, input_text: str | None = None) -> tuple[int, str, str]:
        command = [str(self.kubectl), "--kubeconfig", str(self.kubeconfig), "--request-timeout=30s", *arguments]
        result = subprocess.run(command, input=input_text, text=True, capture_output=True, timeout=40, check=False, env={"PATH": "/usr/bin:/bin", "NO_PROXY": "*", "no_proxy": "*"})
        return result.returncode, result.stdout, result.stderr
    def get(self, identity: dict[str, str]) -> dict[str, Any] | None:
        require(identity in _allowed_targets(), "GET target outside recovery scope")
        arguments = ["-n", identity["namespace"], "get", identity["kind"].lower(), identity["name"], "-o", "json"]
        for attempt in range(GET_MAX_ATTEMPTS):
            try:
                code, out, err = self._run(arguments)
            except subprocess.TimeoutExpired as error:
                if attempt + 1 < GET_MAX_ATTEMPTS:
                    time.sleep(GET_RETRY_DELAYS_SECONDS[attempt])
                    continue
                raise RecoveryError(
                    f"GET failed after {GET_MAX_ATTEMPTS} attempts for {identity['kind']}/{identity['name']}: command timeout"
                ) from error
            if code != 0 and re.search(r"notfound|not found|404", err, re.I): return None
            if _is_retryable_get_transport_failure(code, out, err):
                if attempt + 1 < GET_MAX_ATTEMPTS:
                    time.sleep(GET_RETRY_DELAYS_SECONDS[attempt])
                    continue
                raise RecoveryError(
                    f"GET failed after {GET_MAX_ATTEMPTS} attempts for {identity['kind']}/{identity['name']}: {_bounded_get_error(err)}"
                )
            require(code == 0, f"GET failed for {identity['kind']}/{identity['name']}: {_bounded_get_error(err)}")
            return _json_object(out.encode(), f"GET {identity['kind']}/{identity['name']}")
        raise AssertionError("unreachable GET retry loop")
    def delete(self, identity: dict[str, str], *, uid: str, resource_version: str) -> None:
        require(identity in _delete_targets(), "DELETE target outside recovery scope")
        require(UUID.fullmatch(uid) is not None and isinstance(resource_version, str) and resource_version.isdigit(), "DELETE preconditions invalid")
        plural = {("v1", "ServiceAccount"): "serviceaccounts", ("rbac.authorization.k8s.io/v1", "Role"): "roles", ("rbac.authorization.k8s.io/v1", "RoleBinding"): "rolebindings", ("kustomize.toolkit.fluxcd.io/v1", "Kustomization"): "kustomizations"}.get((identity["apiVersion"], identity["kind"]))
        require(plural is not None, "DELETE API target outside recovery scope")
        prefix = "/api/v1" if identity["apiVersion"] == "v1" else f"/apis/{identity['apiVersion']}"
        payload = canonical(_delete_options(uid, resource_version))
        code, _out, err = self._run(["delete", "--raw", f"{prefix}/namespaces/{identity['namespace']}/{plural}/{identity['name']}", "-f", "-"], input_text=payload)
        if code != 0 and re.search(r"notfound|not found|404", err, re.I): return
        require(code == 0, f"DELETE failed for {identity['kind']}/{identity['name']}: {err.strip()}")


def _delete_options(uid: str, resource_version: str) -> dict[str, Any]:
    require(UUID.fullmatch(uid) is not None and isinstance(resource_version, str) and resource_version.isdigit(), "DELETE preconditions invalid")
    return {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid, "resourceVersion": resource_version}}


def _allowed_targets() -> tuple[dict[str, str], ...]:
    objects = expected_objects()
    return (baseline_target(), source_target(), *(target(objects[name]) for name in OBJECT_ORDER))


def _delete_targets() -> tuple[dict[str, str], ...]:
    objects = expected_objects(); return tuple(target(objects[name]) for name in OBJECT_ORDER)


def _initial_state(revision: str, evidence: dict[str, str], baseline: dict[str, Any], source: dict[str, Any], objects: dict[str, dict[str, Any]]) -> dict[str, Any]:
    inventory = {
        name: {"uid": objects[name]["uid"], "resourceVersion": objects[name]["resourceVersion"], "status": "present"}
        for name in OBJECT_ORDER
    }
    state: dict[str, Any] = {"schemaVersion": JOURNAL_SCHEMA, "status": "in-progress", "protectedRevision": revision, "originRevision": ORIGIN_REVISION, "operationId": OPERATION_ID, "operationMarker": OPERATION_MARKER, "evidence": evidence, "baseline": baseline, "source": source, "objects": inventory, "finalAbsence": None, "events": []}
    _event(state, "before", "preflight", {"baselineDigest": baseline["digest"], "sourceUid": source["uid"]}); return state


def _validate_state(state: dict[str, Any], revision: str, evidence: dict[str, str]) -> None:
    require(state.get("schemaVersion") == JOURNAL_SCHEMA and state.get("protectedRevision") == revision, "recovery journal revision/schema drift")
    require(state.get("originRevision") == ORIGIN_REVISION and state.get("operationId") == OPERATION_ID and state.get("operationMarker") == OPERATION_MARKER, "recovery journal origin binding drift")
    require(state.get("evidence") == evidence, "recovery journal evidence drift")
    objects = state.get("objects"); require(isinstance(objects, dict) and set(objects) == set(OBJECT_ORDER), "recovery journal object set drift")
    for name in OBJECT_ORDER:
        record = objects[name]
        require(record.get("uid") == OBJECT_UIDS[name] and record.get("status") in {"present", "delete-intent", "delete-uncertain", "absent"}, f"recovery journal {name} state drift")
    previous = None
    for index, event in enumerate(state.get("events", []), start=1):
        entry = copy.deepcopy(event); checksum = entry.pop("entrySha256", None)
        require(event.get("sequence") == index and event.get("previousEntrySha256") == previous and checksum == digest(entry), "recovery journal hash chain drift")
        previous = checksum


def _preflight(
    kube: Any,
    revision: str,
    *,
    already_absent: set[str] | None = None,
    delete_uncertain: set[str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, dict[str, Any]]]:
    baseline = _validate_baseline(kube.get(baseline_target()))
    source = _validate_source(kube.get(source_target()), revision)
    values: dict[str, dict[str, Any]] = {}
    absent, uncertain = already_absent or set(), delete_uncertain or set()
    for name in OBJECT_ORDER:
        current = kube.get(target(expected_objects()[name]))
        if name in absent:
            require(current is None, f"recovery {name} reappeared after proven absence")
            continue
        if name in uncertain and current is None:
            continue
        values[name] = _validate_object(name, current, expected_uid=OBJECT_UIDS[name])
    return baseline, source, values


def run(
    *,
    kube: Any,
    revision: str,
    origin_journal: bytes,
    attempt_receipt: bytes,
    inspection: bytes,
    journal: Any,
    receipt: Any,
    terminal_finalize: bool = False,
) -> dict[str, Any]:
    require(REVISION.fullmatch(revision) is not None, "protected revision invalid")
    require(isinstance(terminal_finalize, bool), "terminal-finalization mode invalid")
    _validate_output_separation(journal, receipt)
    evidence = _validate_origin_inputs(origin_journal, attempt_receipt, inspection)
    state = journal.load()
    if terminal_finalize:
        require(isinstance(state, dict), "terminal-finalization mode requires the exact existing journal")
        require(state.get("status") == "completed", "terminal-finalization mode requires a completed journal")
        require(state.get("protectedRevision") == TERMINAL_RECOVERY_REVISION, "terminal-finalization journal revision drift")
        baseline, source, final_absence, journal_file_sha256 = _reprove_pinned_terminal_cleanup(
            kube, state, revision, evidence, journal
        )
        result = _completed_terminal_finalization_receipt(
            revision=revision,
            evidence=evidence,
            baseline=baseline,
            source=source,
            state=state,
            final_absence=final_absence,
            journal_file_sha256=journal_file_sha256,
        )
        receipt.commit(result)
        return result
    if state is None:
        baseline, source, objects = _preflight(kube, revision)
        state = _initial_state(revision, evidence, baseline, source, objects); journal.commit(state)
    elif state.get("status") == "completed":
        require(state.get("protectedRevision") == revision, "prior terminal journal requires explicit terminal-finalization mode")
        baseline, source, final_absence = _reprove_terminal_cleanup(kube, state, revision, evidence)
        result = _completed_receipt(revision=revision, evidence=evidence, baseline=baseline, source=source, state=state, final_absence=final_absence)
        receipt.commit(result)
        return result
    else:
        _validate_state(state, revision, evidence)
        require(state.get("status") in {"in-progress", "pending"}, "recovery journal already terminal")
        # Re-entry re-proves every survivor before continuing; nothing is
        # adopted by name from a previous attempt.
        absent = {name for name in OBJECT_ORDER if state["objects"][name].get("status") == "absent"}
        uncertain = {name for name in OBJECT_ORDER if state["objects"][name].get("status") in {"delete-intent", "delete-uncertain"}}
        baseline, source, objects = _preflight(kube, revision, already_absent=absent, delete_uncertain=uncertain)
        require(baseline == state["baseline"] and source == state["source"], "recovery predecessor/source drift on resume")
        for name in OBJECT_ORDER:
            record = state["objects"][name]
            if record.get("status") == "absent" or name not in objects:
                continue
            require(objects[name]["uid"] == record["uid"], f"recovery {name} UID drift on resume")
        state["status"] = "in-progress"; _event(state, "before", "resume", {"revision": revision}); journal.commit(state)

    for name in OBJECT_ORDER:
        record = state["objects"][name]
        if record.get("status") == "absent": continue
        identity = target(expected_objects()[name]); current = kube.get(identity)
        if current is None:
            record["status"] = "absent"; _event(state, "after", f"delete.{name}", {"result": "already-absent", "uid": record["uid"]}); journal.commit(state); continue
        proof = _validate_object(name, current, expected_uid=record["uid"])
        options = _delete_options(proof["uid"], proof["resourceVersion"])
        payload = canonical(options)
        record["status"] = "delete-intent"
        event = _event(state, "before", f"delete.{name}", {"target": identity, "uid": proof["uid"], "resourceVersion": proof["resourceVersion"], "verb": "DELETE", "deleteOptions": options, "deletePayload": payload, "deletePayloadSha256": bytes_digest(payload.encode())}); journal.commit(state)
        try:
            kube.delete(identity, uid=proof["uid"], resource_version=proof["resourceVersion"])
            after = kube.get(identity)
        except Exception as error:
            event["stage"] = "uncertain"; event["error"] = str(error)[:320]; _rehash(event); record["status"] = "delete-uncertain"; state["status"] = "pending"; journal.commit(state)
            result = {"schemaVersion": RECEIPT_SCHEMA, "status": "pending", "protectedRevision": revision, "effects": _effects(False), "failure": str(error)[:320]}; receipt.commit(result); raise RecoveryError(f"{name} delete pending; resume only with this journal") from error
        if after is not None:
            try: _validate_object(name, after, expected_uid=record["uid"])
            except Exception as error:
                event["stage"] = "uncertain"; event["error"] = str(error)[:320]; _rehash(event); record["status"] = "delete-uncertain"; state["status"] = "pending"; journal.commit(state)
                result = {"schemaVersion": RECEIPT_SCHEMA, "status": "pending", "protectedRevision": revision, "effects": _effects(False), "failure": str(error)[:320]}; receipt.commit(result); raise RecoveryError(f"{name} delete pending; resume only with this journal") from error
            event["stage"] = "uncertain"; event["error"] = "DELETE accepted but exact object remains"; _rehash(event); record["status"] = "delete-uncertain"; state["status"] = "pending"; journal.commit(state)
            result = {"schemaVersion": RECEIPT_SCHEMA, "status": "pending", "protectedRevision": revision, "effects": _effects(False), "failure": f"{name} deletion not yet absent"}; receipt.commit(result); raise RecoveryError(f"{name} delete pending; resume only with this journal")
        record["status"] = "absent"; event["stage"] = "after"; event["result"] = {"absent": True, "uid": proof["uid"]}; _rehash(event); journal.commit(state)

    final_absence: dict[str, Any] = {}
    for name in OBJECT_ORDER:
        identity = target(expected_objects()[name])
        require(kube.get(identity) is None, f"recovery {name} reappeared after deletion")
        final_absence[name] = {"target": identity, "uid": state["objects"][name]["uid"], "absent": True}
    state["finalAbsence"] = final_absence
    baseline = _validate_baseline(kube.get(baseline_target())); source = _validate_source(kube.get(source_target()), revision)
    require(baseline == state["baseline"] and source == state["source"], "baseline/source changed during recovery")
    state["status"] = "completed"; _event(state, "after", "complete", {"baselineDigest": baseline["digest"], "sourceUid": source["uid"]}); journal.commit(state)
    result = _completed_receipt(revision=revision, evidence=evidence, baseline=baseline, source=source, state=state, final_absence=final_absence)
    receipt.commit(result); return result


def _effects(cleanup_complete: bool) -> dict[str, Any]:
    return {"getOnlyPreflight": True, "deleteOnlyMutation": True, "create": False, "patch": False, "apply": False, "list": False, "secretAccess": False, "civicAuthorityEffects": False, "baselineChanged": False, "sharedSourceChanged": False, "cleanupComplete": cleanup_complete}


def _terminal_journal_binding(state: dict[str, Any]) -> dict[str, Any]:
    events = state.get("events")
    require(state.get("status") == "completed" and isinstance(events, list) and events, "terminal recovery journal absent")
    terminal = events[-1]
    require(isinstance(terminal, dict) and terminal.get("operation") == "complete", "terminal recovery journal event drift")
    terminal_hash = terminal.get("entrySha256")
    require(isinstance(terminal_hash, str) and SHA256.fullmatch(terminal_hash), "terminal recovery journal hash absent")
    return {"schemaVersion": JOURNAL_SCHEMA, "status": "completed", "eventCount": len(events), "terminalEntrySha256": terminal_hash, "terminalJournalSha256": digest(state)}


def _reprove_terminal_cleanup(kube: Any, state: dict[str, Any], revision: str, evidence: dict[str, str]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Re-open only the receipt-finalization window after durable cleanup."""
    _validate_state(state, revision, evidence)
    require(state.get("status") == "completed", "recovery journal is not terminal")
    final_absence = state.get("finalAbsence")
    require(isinstance(final_absence, dict) and set(final_absence) == set(OBJECT_ORDER), "terminal final-absence proof drift")
    for name in OBJECT_ORDER:
        identity = target(expected_objects()[name])
        require(final_absence[name] == {"target": identity, "uid": OBJECT_UIDS[name], "absent": True}, f"terminal {name} absence proof drift")
        require(state["objects"][name].get("status") == "absent", f"terminal {name} state drift")
        require(kube.get(identity) is None, f"terminal {name} reappeared; receipt finalization forbidden")
    baseline = _validate_baseline(kube.get(baseline_target()))
    source = _validate_source(kube.get(source_target()), revision)
    require(baseline == state.get("baseline") and source == state.get("source"), "terminal baseline/source drift")
    _terminal_journal_binding(state)
    return baseline, source, copy.deepcopy(final_absence)


def _reprove_pinned_terminal_cleanup(
    kube: Any,
    state: dict[str, Any],
    revision: str,
    evidence: dict[str, str],
    journal: Any,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]:
    """Finalize only the exact historical terminal journal with GETs."""
    require(revision != TERMINAL_RECOVERY_REVISION, "terminal finalization revision did not advance")
    _validate_state(state, TERMINAL_RECOVERY_REVISION, evidence)
    require(state.get("status") == "completed", "recovery journal is not terminal")
    require(digest(state) == TERMINAL_RECOVERY_JOURNAL_CANONICAL_SHA256, "terminal recovery journal canonical checksum drift")
    raw_sha256 = getattr(journal, "raw_sha256", None)
    require(callable(raw_sha256), "terminal recovery journal raw binding unavailable")
    journal_file_sha256 = raw_sha256()
    require(journal_file_sha256 == TERMINAL_RECOVERY_JOURNAL_FILE_SHA256, "terminal recovery journal file checksum drift")

    final_absence = state.get("finalAbsence")
    require(isinstance(final_absence, dict) and set(final_absence) == set(OBJECT_ORDER), "terminal final-absence proof drift")
    for name in OBJECT_ORDER:
        identity = target(expected_objects()[name])
        require(final_absence[name] == {"target": identity, "uid": OBJECT_UIDS[name], "absent": True}, f"terminal {name} absence proof drift")
        require(state["objects"][name].get("status") == "absent", f"terminal {name} state drift")
        require(kube.get(identity) is None, f"terminal {name} reappeared; receipt finalization forbidden")

    baseline = _validate_baseline(kube.get(baseline_target()))
    require(baseline == state.get("baseline"), "terminal baseline drift")
    source = _validate_source(kube.get(source_target()), revision)
    source_at_recovery = state.get("source")
    require(
        isinstance(source_at_recovery, dict)
        and source["uid"] == source_at_recovery.get("uid")
        and source["generation"] == source_at_recovery.get("generation"),
        "terminal shared source identity/generation drift",
    )
    _terminal_journal_binding(state)
    return baseline, source, copy.deepcopy(final_absence), journal_file_sha256


def _completed_receipt(*, revision: str, evidence: dict[str, str], baseline: dict[str, Any], source: dict[str, Any], state: dict[str, Any], final_absence: dict[str, Any]) -> dict[str, Any]:
    return {"schemaVersion": RECEIPT_SCHEMA, "status": "completed", "protectedRevision": revision, "originRevision": ORIGIN_REVISION, "operationId": OPERATION_ID, "operationMarker": OPERATION_MARKER, "evidence": evidence, "baseline": baseline, "source": source, "objects": copy.deepcopy(state["objects"]), "finalAbsence": copy.deepcopy(final_absence), "journal": _terminal_journal_binding(state), "effects": _effects(True)}


def _completed_terminal_finalization_receipt(
    *,
    revision: str,
    evidence: dict[str, str],
    baseline: dict[str, Any],
    source: dict[str, Any],
    state: dict[str, Any],
    final_absence: dict[str, Any],
    journal_file_sha256: str,
) -> dict[str, Any]:
    journal_binding = _terminal_journal_binding(state) | {
        "protectedRevision": TERMINAL_RECOVERY_REVISION,
        "terminalJournalFileSha256": journal_file_sha256,
    }
    effects = _effects(True) | {
        "historicalDeleteOnlyRecovery": True,
        "deleteOnlyMutation": False,
        "getOnlyFinalization": True,
        "clusterMutationCount": 0,
        "newDeletes": 0,
    }
    return {
        "schemaVersion": RECEIPT_SCHEMA,
        "status": "completed",
        "protectedRevision": revision,
        "finalizedAgainstRevision": revision,
        "finalizationParentRevision": TERMINAL_FINALIZATION_PARENT_REVISION,
        "terminalRecoveryRevision": TERMINAL_RECOVERY_REVISION,
        "originRevision": ORIGIN_REVISION,
        "operationId": OPERATION_ID,
        "operationMarker": OPERATION_MARKER,
        "evidence": evidence,
        "baseline": baseline,
        "source": source,
        "sourceAtRecovery": copy.deepcopy(state["source"]),
        "sourceAtFinalization": copy.deepcopy(source),
        "objects": copy.deepcopy(state["objects"]),
        "finalAbsence": copy.deepcopy(final_absence),
        "journal": journal_binding,
        "effects": effects,
    }


def _read_fd(fd: int, label: str) -> bytes:
    info = os.fstat(fd); require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 1024 * 1024, f"{label} fd invalid")
    raw = os.pread(fd, info.st_size + 1, 0); require(len(raw) == info.st_size, f"{label} fd size drift"); return raw


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-protected-revision", required=True)
    parser.add_argument("--kubeconfig", required=True, type=Path)
    parser.add_argument("--origin-journal-fd", required=True, type=int)
    parser.add_argument("--attempt-receipt-fd", required=True, type=int)
    parser.add_argument("--inspection-fd", required=True, type=int)
    parser.add_argument("--recovery-journal", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--terminal-finalize", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    journal = JsonJournal(args.recovery_journal)
    receipt = JsonReceipt(args.receipt)
    _validate_output_separation(journal, receipt)
    origin_journal = _read_fd(args.origin_journal_fd, "origin journal")
    attempt_receipt = _read_fd(args.attempt_receipt_fd, "attempt receipt")
    inspection = _read_fd(args.inspection_fd, "inspection")
    result = run(
        kube=KubernetesAdapter(args.kubeconfig),
        revision=args.expected_protected_revision,
        origin_journal=origin_journal,
        attempt_receipt=attempt_receipt,
        inspection=inspection,
        journal=journal,
        receipt=receipt,
        terminal_finalize=args.terminal_finalize,
    )
    print(canonical({"status": result["status"], "protectedRevision": result["protectedRevision"], "civicAuthorityEffects": False}))
    return 0


if __name__ == "__main__":
    try: raise SystemExit(main())
    except RecoveryError as error: raise SystemExit(f"workbench recovery blocked: {error}")
