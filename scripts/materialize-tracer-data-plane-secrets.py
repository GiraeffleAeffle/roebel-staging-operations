#!/usr/bin/env python3
"""Create the three value-free-bound Secrets for the ephemeral tracer plane.

The related credentials are generated together in memory.  No plaintext
bundle is accepted or written.  Existing Secrets are never adopted.  A failed
transaction deletes only exact UIDs/resourceVersions created by this run.
"""

from __future__ import annotations

import sys as _bootstrap_sys

if __name__ == "__main__" and not (
    _bootstrap_sys.flags.isolated and _bootstrap_sys.flags.safe_path
):
    print("tracer Secret materializer blocked: invoke with python3 -I", file=_bootstrap_sys.stderr)
    raise SystemExit(2)

import argparse
import base64
import hashlib
import hmac
import importlib.util
import json
import os
import re
import secrets
import signal
import stat
import subprocess
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
SELF_PATH = "scripts/materialize-tracer-data-plane-secrets.py"
CORE_PATH = "scripts/activate-staging-participant-gateway.py"
TRACER_POLICY_PATH = "scripts/tracer_data_plane_policy.py"
PARTICIPANT_POLICY_PATH = "scripts/staging_participant_gateway_policy.py"
PARTICIPANT_POLICY_JSON = "policy/staging-participant-gateway-activation-policy.json"
CONTRACT_PATH = "policy/repository-contract.json"
RUNTIME_PIN_PATH = "reviewed-render/roebel-staging/tracer-data-plane/runtime-pin.json"
PROTECTED_PATHS = (
    SELF_PATH,
    CORE_PATH,
    TRACER_POLICY_PATH,
    PARTICIPANT_POLICY_PATH,
    PARTICIPANT_POLICY_JSON,
    CONTRACT_PATH,
    RUNTIME_PIN_PATH,
)

NONCE_ANNOTATION = "stadtstack.io/tracer-secret-materialization-nonce"
RECEIPT_SCHEMA = "roebel_tracer_data_plane_secret_materialization_receipt_v1"
TEARDOWN_RECEIPT_SCHEMA = "roebel_tracer_data_plane_secret_teardown_receipt_v1"
JOURNAL_SCHEMA = "roebel_tracer_data_plane_secret_materialization_journal_v1"
REVISION = re.compile(r"^[0-9a-f]{40}$")
UID = re.compile(r"^[0-9a-f-]{16,64}$")
SECRET_LABELS = {
    "app.kubernetes.io/part-of": "stadtstack",
    "stadtstack.io/authority": "none",
    "stadtstack.io/civic-authority": "none",
    "stadtstack.io/environment": "staging",
    "stadtstack.io/secret-owner": "tracer-data-plane-materializer",
}


class MaterializationError(RuntimeError):
    pass


class MaterializationInterrupted(MaterializationError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise MaterializationError(message)


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(path))


def require_distinct_paths(*paths: Path) -> None:
    selected = [absolute_path(path) for path in paths]
    require(len(set(selected)) == len(selected), "receipt and journal paths must be distinct")
    existing = [path for path in selected if path.exists()]
    for index, left in enumerate(existing):
        for right in existing[index + 1 :]:
            require(not os.path.samefile(left, right), "receipt and journal paths must not alias")


def reserve_receipt(path: Path) -> dict[str, Any]:
    """Reserve the immutable receipt inode before the first cluster mutation."""
    selected = absolute_path(path)
    require(not selected.exists(), "receipt path already exists")
    selected.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(selected, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        info = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(selected.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return {
        "absolutePath": str(selected),
        "pathSha256": sha256_bytes(str(selected).encode("utf-8")),
        "device": info.st_dev,
        "inode": info.st_ino,
    }


def read_reserved_receipt(path: Path, reservation: dict[str, Any]) -> bytes:
    selected = absolute_path(path)
    require(
        set(reservation) == {"absolutePath", "pathSha256", "device", "inode"}
        and reservation.get("absolutePath") == str(selected)
        and reservation.get("pathSha256") == sha256_bytes(str(selected).encode("utf-8"))
        and type(reservation.get("device")) is int
        and type(reservation.get("inode")) is int,
        "receipt reservation binding drift",
    )
    info = os.lstat(selected)
    require(
        stat.S_ISREG(info.st_mode)
        and not selected.is_symlink()
        and info.st_uid == os.geteuid()
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_dev == reservation["device"]
        and info.st_ino == reservation["inode"]
        and info.st_size <= 8 * 1024 * 1024,
        "receipt reservation inode drift",
    )
    raw = selected.read_bytes()
    require(len(raw) == info.st_size, "reserved receipt changed while reading")
    return raw


def commit_reserved_receipt(path: Path, reservation: dict[str, Any], value: dict[str, Any]) -> None:
    selected = absolute_path(path)
    require(read_reserved_receipt(selected, reservation) == b"", "reserved receipt is not empty")
    flags = os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(selected, flags)
    try:
        info = os.fstat(descriptor)
        require(
            info.st_dev == reservation["device"]
            and info.st_ino == reservation["inode"]
            and info.st_size == 0,
            "receipt reservation changed before commit",
        )
        pending = memoryview((json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        while pending:
            written = os.write(descriptor, pending)
            require(written > 0, "reserved receipt short write")
            pending = pending[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(selected.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def load_module(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"module unavailable: {path}")
    module = importlib.util.module_from_spec(spec)
    _bootstrap_sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if _bootstrap_sys.modules.get(name) is module:
            _bootstrap_sys.modules.pop(name, None)
        raise
    return module


def bind_checkout(expected_revision: str) -> dict[str, str]:
    require(REVISION.fullmatch(expected_revision) is not None, "expected revision must be 40 lowercase hex")
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
    head = subprocess.run(
        ["/usr/bin/git", "--no-replace-objects", "-C", str(ROOT), "rev-parse", "HEAD"],
        capture_output=True,
        check=False,
        text=True,
        env=environment,
        timeout=10,
    )
    require(head.returncode == 0 and head.stdout.strip() == expected_revision, "checkout is not expected protected revision")
    hashes: dict[str, str] = {}
    for relative in PROTECTED_PATHS:
        local = ROOT / relative
        info = os.lstat(local)
        require(stat.S_ISREG(info.st_mode) and not local.is_symlink(), f"protected file invalid: {relative}")
        blob = subprocess.run(
            ["/usr/bin/git", "--no-replace-objects", "-C", str(ROOT), "show", f"{expected_revision}:{relative}"],
            capture_output=True,
            check=False,
            env=environment,
            timeout=10,
        )
        require(blob.returncode == 0 and local.read_bytes() == blob.stdout, f"protected file drift: {relative}")
        hashes[relative] = sha256_bytes(blob.stdout)
    return dict(sorted(hashes.items()))


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def anon_jwt(jwt_secret: str, *, now: int) -> tuple[str, int]:
    require(re.fullmatch(r"[0-9a-f]{64}", jwt_secret) is not None, "JWT secret shape invalid")
    expiration = now + 365 * 24 * 60 * 60
    header = b64url(canonical({"alg": "HS256", "typ": "JWT"}).encode("ascii"))
    payload = b64url(canonical({"exp": expiration, "iat": now, "role": "anon"}).encode("ascii"))
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = b64url(hmac.new(jwt_secret.encode("ascii"), signing_input, hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}", expiration


def generate_bundle(policy: Any, *, now: int | None = None) -> tuple[dict[str, dict[str, bytes]], dict[str, int]]:
    timestamp = int(time.time()) if now is None else now
    postgres_password = secrets.token_hex(32)
    authenticator_password = secrets.token_hex(32)
    jwt_secret = secrets.token_hex(32)
    pgsodium_root_key = secrets.token_hex(32)
    rpc_secret = secrets.token_hex(48)
    token, expiration = anon_jwt(jwt_secret, now=timestamp)
    database_uri = (
        "postgres://authenticator:"
        + authenticator_password
        + "@roebel-tracer-postgres.stadtstack-roebel-staging-lab.svc.cluster.local:5432/postgres"
    )
    values = {
        "dataPlane": {
            "anon-jwt": token.encode("ascii"),
            "authenticator-password": authenticator_password.encode("ascii"),
            "environment-arm": b"staging-only",
            "jwt-secret": jwt_secret.encode("ascii"),
            "pgsodium-root-key": pgsodium_root_key.encode("ascii"),
            "postgres-password": postgres_password.encode("ascii"),
            "postgrest-db-uri": database_uri.encode("ascii"),
            "rpc-secret": rpc_secret.encode("ascii"),
        },
        "webFeed": {"supabase-anon-key": token.encode("ascii")},
        "participantPostgrest": {
            "supabase-anon-key": token.encode("ascii"),
            "supabase-rpc-secret": rpc_secret.encode("ascii"),
        },
    }
    references = policy.secret_materialization_contract()["secrets"]
    require(set(values) == set(references), "generated Secret set drift")
    for label, reference in references.items():
        require(set(values[label]) == set(reference["keys"]), f"generated Secret keyset drift: {label}")
    require(expiration - timestamp >= 30 * 24 * 60 * 60, "anon JWT has less than 30 days remaining")
    return values, {"iat": timestamp, "exp": expiration}


def secret_manifest(reference: dict[str, Any], values: dict[str, bytes], nonce: str) -> dict[str, Any]:
    require(re.fullmatch(r"[0-9a-f]{64}", nonce) is not None, "ownership nonce invalid")
    require(set(values) == set(reference["keys"]), "Secret value keyset drift")
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "annotations": {NONCE_ANNOTATION: nonce},
            "labels": dict(SECRET_LABELS),
            "name": reference["name"],
            "namespace": reference["namespace"],
        },
        "type": "Opaque",
        "data": {
            key: base64.b64encode(values[key]).decode("ascii")
            for key in reference["keys"]
        },
    }


def projection_template() -> str:
    labels = "".join(
        '{{index .metadata.labels "' + key + '"}}{{"\\n"}}'
        for key in SECRET_LABELS
    )
    return (
        '{{.metadata.uid}}{{"\\n"}}{{.metadata.resourceVersion}}{{"\\n"}}'
        '{{index .metadata.annotations "' + NONCE_ANNOTATION + '"}}{{"\\n"}}'
        '{{.type}}{{"\\n"}}' + labels
        + '{{range $k,$v := .data}}{{$k}}{{"\\n"}}{{end}}'
    )


def not_found(result: Any) -> bool:
    text = (result.out + "\n" + result.err).lower()
    return result.code != 0 and ("notfound" in text or re.search(r"\b404\b", text) is not None)


def read_projection(core: Any, runner: Any, kubeconfig: str, label: str, reference: dict[str, Any]) -> dict[str, Any] | None:
    result = runner.run([
        "kubectl", "--kubeconfig", kubeconfig, "-n", reference["namespace"],
        "get", "secret", reference["name"], "-o", f"go-template={projection_template()}",
    ])
    if not_found(result):
        return None
    require(result.code == 0, f"Secret projection failed: {label}")
    lines = result.out.splitlines()
    label_count = len(SECRET_LABELS)
    require(len(lines) >= 4 + label_count, f"Secret projection incomplete: {label}")
    uid, resource_version, nonce, secret_type, *tail = lines
    observed_labels = tail[:label_count]
    keys = tail[label_count:]
    require(UID.fullmatch(uid) is not None, f"Secret UID invalid: {label}")
    require(resource_version.isdigit(), f"Secret resourceVersion invalid: {label}")
    require(re.fullmatch(r"[0-9a-f]{64}", nonce) is not None, f"Secret ownership nonce invalid: {label}")
    require(
        secret_type == "Opaque"
        and observed_labels == list(SECRET_LABELS.values())
        and sorted(keys) == sorted(reference["keys"]),
        f"Secret labels/keyset/type drift: {label}",
    )
    return {
        "target": {"apiVersion": "v1", "kind": "Secret", "name": reference["name"], "namespace": reference["namespace"]},
        "uid": uid,
        "resourceVersion": resource_version,
        "keySet": sorted(keys),
        "ownershipNonce": nonce,
        "valuesRead": False,
    }


def create_secret(core: Any, runner: Any, kubeconfig: str, label: str, reference: dict[str, Any], values: dict[str, bytes], nonce: str) -> dict[str, Any]:
    manifest = secret_manifest(reference, values, nonce)
    result = runner.run(
        [
            "kubectl", "--kubeconfig", kubeconfig, "-n", reference["namespace"],
            "create", "-f", "-", "-o", f"go-template={projection_template()}",
        ],
        input_text=canonical(manifest),
        timeout=30,
    )
    text = (result.out + "\n" + result.err).lower()
    require("alreadyexists" not in text and re.search(r"\b409\b", text) is None, f"Secret {label} exists; adoption forbidden")
    observed = read_projection(core, runner, kubeconfig, label, reference)
    require(observed is not None and observed["ownershipNonce"] == nonce, f"Secret {label} create outcome unresolved")
    observed["createOutcome"] = (
        "create-response-and-exact-live-projection"
        if result.code == 0
        else "nonzero-post-send-exact-same-nonce-live-projection"
    )
    return observed


def api_path(reference: dict[str, Any]) -> str:
    return f"/api/v1/namespaces/{reference['namespace']}/secrets/{reference['name']}"


def delete_owned(core: Any, runner: Any, snapshot: Any, kubeconfig: str, label: str, reference: dict[str, Any], owned: dict[str, Any]) -> None:
    current = read_projection(core, runner, kubeconfig, label, reference)
    if current is None:
        return
    for key in ("uid", "resourceVersion", "ownershipNonce", "keySet"):
        require(current[key] == owned[key], f"Secret rollback ownership drift: {label}.{key}")
    payload = canonical({
        "apiVersion": "v1",
        "kind": "DeleteOptions",
        "preconditions": {"uid": current["uid"], "resourceVersion": current["resourceVersion"]},
    })
    core.raw_delete(snapshot, api_path(reference), payload, 15)
    require(read_projection(core, runner, kubeconfig, label, reference) is None, f"Secret rollback incomplete: {label}")


def recover_nonce_owned(core: Any, runner: Any, kubeconfig: str, contract: dict[str, Any], nonce: str, created: dict[str, dict[str, Any]]) -> None:
    for label in contract["createOrder"]:
        if label in created:
            continue
        observed = read_projection(core, runner, kubeconfig, label, contract["secrets"][label])
        if observed is not None and observed.get("ownershipNonce") == nonce:
            observed["createOutcome"] = "rollback-entry-exact-same-nonce-live-projection"
            created[label] = observed


def write_receipt(path: Path, value: dict[str, Any]) -> None:
    selected = Path(os.path.abspath(path))
    require(not selected.exists(), "receipt path already exists")
    selected.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(selected, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
        pending = memoryview(raw)
        while pending:
            pending = pending[os.write(descriptor, pending):]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(selected.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def write_journal(path: Path, value: dict[str, Any]) -> None:
    selected = Path(os.path.abspath(path))
    selected.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = selected.parent / f".{selected.name}.{secrets.token_hex(16)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        pending = memoryview((json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        while pending:
            pending = pending[os.write(descriptor, pending):]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, selected)
        directory = os.open(selected.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        info = os.lstat(selected)
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600, "materialization journal durability drift")
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


class SignalGuard:
    """Convert the first termination signal to abort; ignore repeats in cleanup."""

    def __init__(self) -> None:
        self.original: dict[int, Any] = {}
        self.observed: list[int] = []

    def install(self) -> None:
        def handler(signum: int, _frame: Any) -> None:
            self.observed.append(signum)
            self.defer()
            raise MaterializationInterrupted(f"operator signal {signum}")

        for item in (signal.SIGINT, signal.SIGTERM):
            self.original[item] = signal.getsignal(item)
            signal.signal(item, handler)

    def defer(self) -> None:
        for item in (signal.SIGINT, signal.SIGTERM):
            signal.signal(item, signal.SIG_IGN)

    def restore(self) -> None:
        for item, handler in self.original.items():
            signal.signal(item, handler)


def plan(policy: Any, expected_revision: str) -> dict[str, Any]:
    contract = policy.secret_materialization_contract()
    return {
        "schemaVersion": RECEIPT_SCHEMA,
        "mode": "plan",
        "protectedRevision": expected_revision,
        "clusterMutation": False,
        "secretValuesGenerated": False,
        "secretValuesPrinted": False,
        "createOrder": contract["createOrder"],
        "secrets": contract["secrets"],
        "adoption": "forbidden",
        "civicAuthorityEffects": False,
    }


def validate_secret_record(
    label: str,
    record: Any,
    reference: dict[str, Any],
    *,
    operation_nonce: str | None = None,
) -> dict[str, Any]:
    require(
        isinstance(record, dict)
        and set(record) == {
            "target", "uid", "resourceVersion", "keySet", "ownershipNonce",
            "valuesRead", "createOutcome",
        }
        and record.get("target")
        == {
            "apiVersion": "v1", "kind": "Secret",
            "name": reference["name"], "namespace": reference["namespace"],
        }
        and isinstance(record.get("uid"), str)
        and UID.fullmatch(record["uid"]) is not None
        and isinstance(record.get("resourceVersion"), str)
        and record["resourceVersion"].isdigit()
        and record.get("keySet") == sorted(reference["keys"])
        and isinstance(record.get("ownershipNonce"), str)
        and re.fullmatch(r"[0-9a-f]{64}", record["ownershipNonce"]) is not None
        and (operation_nonce is None or record["ownershipNonce"] == operation_nonce)
        and record.get("valuesRead") is False
        and record.get("createOutcome") in {
            "create-response-and-exact-live-projection",
            "nonzero-post-send-exact-same-nonce-live-projection",
            "rollback-entry-exact-same-nonce-live-projection",
        },
        f"Secret receipt record drift: {label}",
    )
    return record


def load_source_receipt(
    path: Path,
    contract: dict[str, Any],
    current_hashes: dict[str, str],
    expected_revision: str,
) -> dict[str, Any]:
    selected = Path(os.path.abspath(path))
    info = os.lstat(selected)
    require(
        stat.S_ISREG(info.st_mode)
        and not selected.is_symlink()
        and info.st_uid == os.geteuid()
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o600
        and 0 < info.st_size <= 8 * 1024 * 1024,
        "source materialization receipt must be an owned 0600 regular file",
    )
    raw = selected.read_bytes()
    require(len(raw) == info.st_size, "source materialization receipt changed while reading")
    value = json.loads(raw)
    require(
        isinstance(value, dict)
        and value.get("schemaVersion") == RECEIPT_SCHEMA
        and value.get("status") == "materialized"
        and value.get("protectedRevision") == expected_revision
        and value.get("receiptContainsValues") is False
        and value.get("civicAuthorityEffects") is False,
        "source materialization receipt status/value boundary drift",
    )
    require(value.get("protectedFileSha256") == current_hashes, "source materialization receipt protected file closure drift")
    operation_nonce = value.get("operationNonce")
    require(isinstance(operation_nonce, str) and re.fullmatch(r"[0-9a-f]{64}", operation_nonce) is not None, "source materialization receipt nonce drift")
    require(value.get("createOrder") == contract["createOrder"], "source materialization receipt create order drift")
    records = value.get("secretRecords")
    require(isinstance(records, dict) and set(records) == set(contract["secrets"]), "source materialization receipt Secret set drift")
    for label, reference in contract["secrets"].items():
        validate_secret_record(label, records[label], reference, operation_nonce=operation_nonce)
    value["fileSha256"] = sha256_bytes(raw)
    return value


def validate_terminal_receipt(
    value: Any,
    contract: dict[str, Any],
    expected_revision: str,
    hashes: dict[str, str],
    nonce: str,
) -> dict[str, Any]:
    require(isinstance(value, dict), "reserved receipt must contain a JSON object")
    require(
        value.get("schemaVersion") == RECEIPT_SCHEMA
        and value.get("status") in {"materialized", "rolled-back", "recovered-rolled-back"}
        and value.get("protectedRevision") == expected_revision
        and value.get("protectedFileSha256") == hashes
        and value.get("operationNonce") == nonce
        and value.get("receiptContainsValues") is False
        and value.get("civicAuthorityEffects") is False,
        "reserved materialization receipt terminal binding drift",
    )
    records = value.get("secretRecords")
    require(isinstance(records, dict) and set(records) <= set(contract["secrets"]), "reserved materialization receipt Secret set drift")
    if value["status"] == "materialized":
        require(set(records) == set(contract["secrets"]), "committed materialization receipt Secret set incomplete")
    for label, record in records.items():
        validate_secret_record(label, record, contract["secrets"][label], operation_nonce=nonce)
    return value


def target_cli(kind: str) -> str:
    return {
        "ConfigMap": "configmap",
        "Deployment": "deployment.apps",
        "Kustomization": "kustomization.kustomize.toolkit.fluxcd.io",
        "NetworkPolicy": "networkpolicy.networking.k8s.io",
        "Role": "role.rbac.authorization.k8s.io",
        "RoleBinding": "rolebinding.rbac.authorization.k8s.io",
        "Service": "service",
        "ServiceAccount": "serviceaccount",
    }[kind]


def require_target_absent(runner: Any, kubeconfig: str, target: dict[str, str]) -> dict[str, Any]:
    result = runner.run([
        "kubectl", "--kubeconfig", kubeconfig, "-n", target["namespace"],
        "get", target_cli(target["kind"]), target["name"], "-o", "name",
    ])
    require(not_found(result), f"Secret teardown blocked until {target['kind']}/{target['name']} is absent")
    return dict(target) | {"absent": True}


def deployment_secret_references(value: dict[str, Any]) -> set[str]:
    pod = value.get("spec", {}).get("template", {}).get("spec", {})
    result: set[str] = set()
    for container in [*pod.get("initContainers", []), *pod.get("containers", [])]:
        for item in container.get("env", []):
            reference = item.get("valueFrom", {}).get("secretKeyRef", {})
            if isinstance(reference.get("name"), str):
                result.add(reference["name"])
        for item in container.get("envFrom", []):
            reference = item.get("secretRef", {})
            if isinstance(reference.get("name"), str):
                result.add(reference["name"])
    for volume in pod.get("volumes", []):
        secret_name = volume.get("secret", {}).get("secretName")
        if isinstance(secret_name, str):
            result.add(secret_name)
        for source in volume.get("projected", {}).get("sources", []):
            name = source.get("secret", {}).get("name")
            if isinstance(name, str):
                result.add(name)
    return result


def require_consumer_unreferenced(core: Any, runner: Any, kubeconfig: str, descriptor: dict[str, str]) -> dict[str, Any]:
    result = runner.run([
        "kubectl", "--kubeconfig", kubeconfig, "-n", descriptor["namespace"],
        "get", "deployment.apps", descriptor["name"], "-o", "json",
    ])
    if not_found(result):
        return {key: descriptor[key] for key in ("apiVersion", "kind", "name", "namespace", "secretName")} | {"absent": True, "referenced": False}
    require(result.code == 0, f"consumer Deployment read failed: {descriptor['name']}")
    value = core.obj(result.out, f"consumer Deployment {descriptor['name']}")
    references = deployment_secret_references(value)
    require(descriptor["secretName"] not in references, f"Secret teardown blocked: {descriptor['name']} still references {descriptor['secretName']}")
    return {key: descriptor[key] for key in ("apiVersion", "kind", "name", "namespace", "secretName")} | {"absent": False, "referenced": False}


def teardown(expected_revision: str, kubeconfig: str, source_receipt_path: Path, receipt_path: Path) -> dict[str, Any]:
    require_distinct_paths(source_receipt_path, receipt_path)
    hashes = bind_checkout(expected_revision)
    tracer = load_module(ROOT / TRACER_POLICY_PATH, f"tracer_policy_teardown_{expected_revision}")
    participant = load_module(ROOT / PARTICIPANT_POLICY_PATH, f"participant_policy_teardown_{expected_revision}")
    core = load_module(ROOT / CORE_PATH, f"participant_core_teardown_{expected_revision}")
    core.POLICY = participant
    descriptor = participant.assert_activation_ready(json.loads((ROOT / PARTICIPANT_POLICY_JSON).read_text()))
    contract = tracer.secret_materialization_contract()
    source = load_source_receipt(source_receipt_path, contract, hashes, expected_revision)
    runner = core.Runner()
    snapshot = core.snapshot_kubeconfig_v4(kubeconfig, runner)
    guard = SignalGuard()
    guard.install()
    deleted: list[dict[str, Any]] = []
    try:
        cluster = core.cluster_binding_v4(runner, snapshot, descriptor)
        absent = [
            require_target_absent(runner, str(snapshot.path), target)
            for target in contract["teardown"]["requiredAbsentTargets"]
        ]
        consumers = [
            require_consumer_unreferenced(core, runner, str(snapshot.path), consumer)
            for consumer in contract["teardown"]["requiredUnreferencedConsumers"]
        ]
        try:
            for label in contract["teardown"]["deleteOrder"]:
                reference = contract["secrets"][label]
                before = read_projection(core, runner, str(snapshot.path), label, reference)
                if before is None:
                    deleted.append({"label": label, "target": source["secretRecords"][label]["target"], "alreadyAbsent": True, "absent": True})
                    continue
                delete_owned(core, runner, snapshot, str(snapshot.path), label, reference, source["secretRecords"][label])
                deleted.append({"label": label, "target": source["secretRecords"][label]["target"], "alreadyAbsent": False, "uid": before["uid"], "deleteResourceVersion": before["resourceVersion"], "absent": True})
        except BaseException:
            guard.defer()
            raise
        receipt = {
            "schemaVersion": TEARDOWN_RECEIPT_SCHEMA,
            "status": "torn-down",
            "protectedRevision": expected_revision,
            "protectedFileSha256": hashes,
            "sourceMaterializationReceiptFileSha256": source["fileSha256"],
            "clusterBinding": cluster,
            "requiredAbsentTargets": absent,
            "requiredUnreferencedConsumers": consumers,
            "deleteOrder": contract["teardown"]["deleteOrder"],
            "deleted": deleted,
            "receiptContainsValues": False,
            "civicAuthorityEffects": False,
            "signalsDeferredDuringCommit": list(guard.observed),
        }
        guard.defer()
        write_receipt(receipt_path, receipt)
        return receipt
    finally:
        guard.restore()
        snapshot.close()


def recover_from_journal(
    expected_revision: str,
    kubeconfig: str,
    journal_path: Path,
    receipt_path: Path,
) -> dict[str, Any]:
    require_distinct_paths(journal_path, receipt_path)
    hashes = bind_checkout(expected_revision)
    tracer = load_module(ROOT / TRACER_POLICY_PATH, f"tracer_policy_recovery_{expected_revision}")
    participant = load_module(ROOT / PARTICIPANT_POLICY_PATH, f"participant_policy_recovery_{expected_revision}")
    core = load_module(ROOT / CORE_PATH, f"participant_core_recovery_{expected_revision}")
    core.POLICY = participant
    descriptor = participant.assert_activation_ready(json.loads((ROOT / PARTICIPANT_POLICY_JSON).read_text()))
    contract = tracer.secret_materialization_contract()
    selected = Path(os.path.abspath(journal_path))
    info = os.lstat(selected)
    require(
        stat.S_ISREG(info.st_mode)
        and not selected.is_symlink()
        and info.st_uid == os.geteuid()
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o600
        and 0 < info.st_size <= 8 * 1024 * 1024,
        "materialization recovery journal must be an owned 0600 regular file",
    )
    journal = json.loads(selected.read_text())
    require(
        isinstance(journal, dict)
        and journal.get("schemaVersion") == JOURNAL_SCHEMA
        and journal.get("status") in {"in-progress", "committed", "rolled-back"}
        and journal.get("protectedRevision") == expected_revision
        and journal.get("protectedFileSha256") == hashes
        and journal.get("createOrder") == contract["createOrder"]
        and journal.get("secretValuesIncluded") is False
        and journal.get("civicAuthorityEffects") is False,
        "materialization recovery journal boundary drift",
    )
    nonce = journal.get("operationNonce")
    require(isinstance(nonce, str) and re.fullmatch(r"[0-9a-f]{64}", nonce) is not None, "materialization recovery nonce invalid")
    reservation = journal.get("receiptReservation")
    committed = read_reserved_receipt(receipt_path, reservation)
    if committed:
        terminal = validate_terminal_receipt(
            json.loads(committed), contract, expected_revision, hashes, nonce,
        )
        journal["status"] = "committed" if terminal["status"] == "materialized" else "rolled-back"
        journal["phase"] = "terminal-receipt-observed-without-cluster-mutation"
        journal["terminalReceiptSha256"] = sha256_bytes(committed)
        write_journal(journal_path, journal)
        return terminal
    created = journal.get("secretRecords")
    require(isinstance(created, dict) and set(created) <= set(contract["secrets"]), "materialization recovery record set drift")
    created = dict(created)
    for label, record in created.items():
        validate_secret_record(label, record, contract["secrets"][label], operation_nonce=nonce)
    runner = core.Runner()
    snapshot = core.snapshot_kubeconfig_v4(kubeconfig, runner)
    guard = SignalGuard()
    guard.install()
    deleted = list(journal.get("rollbackDeleted", []))
    require(all(label in contract["createOrder"] for label in deleted), "materialization recovery deleted set drift")
    try:
        cluster = core.cluster_binding_v4(runner, snapshot, descriptor)
        recover_nonce_owned(core, runner, str(snapshot.path), contract, nonce, created)
        # Complete the read-only ownership/absence audit before the first
        # suspension or delete.  A foreign exact-name object must not be
        # discovered only after an earlier owned object has been removed.
        for label in contract["createOrder"]:
            observed = read_projection(core, runner, str(snapshot.path), label, contract["secrets"][label])
            if label not in created:
                require(observed is None, f"unowned Secret blocks materialization recovery: {label}")
                continue
            validate_secret_record(label, created[label], contract["secrets"][label], operation_nonce=nonce)
            if observed is not None:
                for field in ("target", "uid", "resourceVersion", "keySet", "ownershipNonce", "valuesRead"):
                    require(observed.get(field) == created[label].get(field), f"materialization recovery ownership drift: {label}.{field}")
        guard.defer()
        journal["secretRecords"] = created
        journal["phase"] = "explicit-recovery-entry"
        write_journal(journal_path, journal)
        for label in reversed(contract["createOrder"]):
            if label not in created:
                require(
                    read_projection(core, runner, str(snapshot.path), label, contract["secrets"][label]) is None,
                    f"unowned Secret blocks materialization recovery: {label}",
                )
                continue
            delete_owned(
                core,
                runner,
                snapshot,
                str(snapshot.path),
                label,
                contract["secrets"][label],
                created[label],
            )
            if label not in deleted:
                deleted.append(label)
            journal["rollbackDeleted"] = list(deleted)
            journal["phase"] = f"explicit-recovery-deleted:{label}"
            write_journal(journal_path, journal)
        journal["status"] = "rolled-back"
        journal["phase"] = "explicit-recovery-complete"
        write_journal(journal_path, journal)
        receipt = {
            "schemaVersion": RECEIPT_SCHEMA,
            "status": "recovered-rolled-back",
            "protectedRevision": expected_revision,
            "protectedFileSha256": hashes,
            "operationNonce": nonce,
            "clusterBinding": cluster,
            "createOrder": contract["createOrder"],
            "secretRecords": created,
            "rollbackDeleted": deleted,
            "receiptContainsValues": False,
            "civicAuthorityEffects": False,
        }
        commit_reserved_receipt(receipt_path, reservation, receipt)
        return receipt
    finally:
        guard.restore()
        snapshot.close()


def materialize(
    expected_revision: str,
    kubeconfig: str,
    receipt_path: Path,
    journal_path: Path,
) -> dict[str, Any]:
    require_distinct_paths(receipt_path, journal_path)
    hashes = bind_checkout(expected_revision)
    tracer = load_module(ROOT / TRACER_POLICY_PATH, f"tracer_policy_{expected_revision}")
    participant = load_module(ROOT / PARTICIPANT_POLICY_PATH, f"participant_policy_{expected_revision}")
    core = load_module(ROOT / CORE_PATH, f"participant_core_{expected_revision}")
    core.POLICY = participant
    descriptor = json.loads((ROOT / PARTICIPANT_POLICY_JSON).read_text())
    descriptor = participant.assert_activation_ready(descriptor)
    contract = tracer.secret_materialization_contract()
    require(contract["receiptSchemaVersion"] == RECEIPT_SCHEMA, "materializer receipt schema drift")
    runner = core.Runner()
    snapshot = core.snapshot_kubeconfig_v4(kubeconfig, runner)
    created: dict[str, dict[str, Any]] = {}
    guard = SignalGuard()
    guard.install()
    try:
        cluster = core.cluster_binding_v4(runner, snapshot, descriptor)
        for label in contract["createOrder"]:
            require(read_projection(core, runner, str(snapshot.path), label, contract["secrets"][label]) is None, f"Secret {label} already exists; adoption forbidden")
        values, token_window = generate_bundle(tracer)
        nonce = secrets.token_hex(32)
        require(not journal_path.exists(), "materialization journal path already exists")
        reservation = reserve_receipt(receipt_path)
        journal = {
            "schemaVersion": JOURNAL_SCHEMA,
            "status": "in-progress",
            "phase": "reserved-before-first-mutation",
            "protectedRevision": expected_revision,
            "protectedFileSha256": hashes,
            "operationNonce": nonce,
            "receiptReservation": reservation,
            "createOrder": contract["createOrder"],
            "secretRecords": {},
            "rollbackDeleted": [],
            "secretValuesIncluded": False,
            "civicAuthorityEffects": False,
        }
        write_journal(journal_path, journal)
        try:
            for label in contract["createOrder"]:
                created[label] = create_secret(
                    core,
                    runner,
                    str(snapshot.path),
                    label,
                    contract["secrets"][label],
                    values[label],
                    nonce,
                )
                journal["phase"] = f"created:{label}"
                journal["secretRecords"] = created
                write_journal(journal_path, journal)
        except BaseException as error:
            guard.defer()
            recover_nonce_owned(core, runner, str(snapshot.path), contract, nonce, created)
            for label in contract["createOrder"]:
                observed = read_projection(core, runner, str(snapshot.path), label, contract["secrets"][label])
                if label not in created:
                    require(observed is None, f"unowned Secret blocks materialization rollback: {label}")
                    continue
                validate_secret_record(label, created[label], contract["secrets"][label], operation_nonce=nonce)
                if observed is not None:
                    for field in ("target", "uid", "resourceVersion", "keySet", "ownershipNonce", "valuesRead"):
                        require(observed.get(field) == created[label].get(field), f"materialization rollback ownership drift: {label}.{field}")
            journal["phase"] = "rollback-entry"
            journal["secretRecords"] = created
            write_journal(journal_path, journal)
            for label in reversed(contract["createOrder"]):
                if label in created:
                    delete_owned(core, runner, snapshot, str(snapshot.path), label, contract["secrets"][label], created[label])
                    journal["rollbackDeleted"].append(label)
                    journal["phase"] = f"rollback-deleted:{label}"
                    write_journal(journal_path, journal)
            journal["status"] = "rolled-back"
            journal["phase"] = "rollback-complete"
            write_journal(journal_path, journal)
            rollback_receipt = {
                "schemaVersion": RECEIPT_SCHEMA,
                "status": "rolled-back",
                "protectedRevision": expected_revision,
                "protectedFileSha256": hashes,
                "operationNonce": nonce,
                "createOrder": contract["createOrder"],
                "secretRecords": created,
                "rollbackDeleted": list(journal["rollbackDeleted"]),
                "failureType": type(error).__name__,
                "receiptContainsValues": False,
                "civicAuthorityEffects": False,
            }
            commit_reserved_receipt(receipt_path, reservation, rollback_receipt)
            raise
        receipt = {
            "schemaVersion": RECEIPT_SCHEMA,
            "status": "materialized",
            "protectedRevision": expected_revision,
            "protectedFileSha256": hashes,
            "operationNonce": nonce,
            "clusterBinding": cluster,
            "createOrder": contract["createOrder"],
            "secretRecords": created,
            "anonJwt": {
                "iat": token_window["iat"],
                "exp": token_window["exp"],
                "minimumRemainingDaysAtCreation": 30,
                "valueIncluded": False,
            },
            "sharedValueBindingsVerified": contract["sharedValueBindings"],
            "receiptContainsValues": False,
            "civicAuthorityEffects": False,
            "signalsDeferredDuringCommit": list(guard.observed),
        }
        # The durable receipt is the commit point.  Signals are deferred
        # before its first byte so a post-commit signal cannot enter the
        # rollback branch and invalidate an immutable success receipt.  A
        # commit I/O failure is deliberately not followed by cluster writes:
        # recovery can roll back an empty reservation, while a partial receipt
        # is ambiguous and therefore blocks recovery.
        journal["phase"] = "materialized-before-receipt-commit"
        journal["secretRecords"] = created
        write_journal(journal_path, journal)
        guard.defer()
        commit_reserved_receipt(receipt_path, reservation, receipt)
        return receipt
    finally:
        guard.restore()
        snapshot.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-revision", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--live", action="store_true")
    mode.add_argument("--teardown", action="store_true")
    mode.add_argument("--recover-journal", type=Path)
    parser.add_argument("--kubeconfig")
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--source-materialization-receipt", type=Path)
    parser.add_argument("--journal", type=Path)
    args = parser.parse_args()
    tracer = load_module(ROOT / TRACER_POLICY_PATH, "tracer_policy_plan")
    if not args.live and not args.teardown and args.recover_journal is None:
        require(
            args.kubeconfig is None
            and args.receipt is None
            and args.source_materialization_receipt is None
            and args.journal is None,
            "plan mode accepts no live arguments",
        )
        print(json.dumps(plan(tracer, args.expected_revision), indent=2, sort_keys=True))
        return 0
    require(args.kubeconfig is not None and args.receipt is not None, "live mode requires --kubeconfig and --receipt")
    if args.recover_journal is not None:
        require(
            args.source_materialization_receipt is None and args.journal is None,
            "recovery accepts only its source journal",
        )
        result = recover_from_journal(
            args.expected_revision,
            args.kubeconfig,
            args.recover_journal,
            args.receipt,
        )
    elif args.teardown:
        require(args.source_materialization_receipt is not None, "teardown requires --source-materialization-receipt")
        require(args.journal is None, "teardown accepts no materialization journal")
        result = teardown(
            args.expected_revision,
            args.kubeconfig,
            args.source_materialization_receipt,
            args.receipt,
        )
    else:
        require(
            args.source_materialization_receipt is None and args.journal is not None,
            "materialization requires --journal and accepts no source receipt",
        )
        result = materialize(args.expected_revision, args.kubeconfig, args.receipt, args.journal)
    print(json.dumps({
        "schemaVersion": result["schemaVersion"],
        "status": result["status"],
        "protectedRevision": result["protectedRevision"],
        "receipt": str(args.receipt),
        "secretValuesPrinted": False,
        "civicAuthorityEffects": False,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (MaterializationError, OSError, ValueError) as error:
        print(f"tracer Secret materialization failed: {error}", file=_bootstrap_sys.stderr)
        raise SystemExit(2)
