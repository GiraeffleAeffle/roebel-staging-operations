#!/usr/bin/env python3
"""Exact create/adopt-by-Flux transaction for the ephemeral tracer plane.

The runner creates the eight reviewed application objects itself, so the
dormant Flux Role needs only exact-name get/patch/update.  It then creates four
namespace-scoped Flux/RBAC objects, removes its temporary ownership nonces,
unsuspends the single Kustomization, and proves the two Services have ready
EndpointSlices.  Any failure suspends Flux and deletes only exact UIDs created
by this operation; the separately receipt-owned Secrets remain available for
a retry or explicit teardown.
"""

from __future__ import annotations

import sys as _bootstrap_sys

if __name__ == "__main__" and not (
    _bootstrap_sys.flags.isolated and _bootstrap_sys.flags.safe_path
):
    print("tracer data-plane runner blocked: invoke with python3 -I", file=_bootstrap_sys.stderr)
    raise SystemExit(2)

import argparse
import copy
import hashlib
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
SELF_PATH = "scripts/run-tracer-data-plane-live.py"
CORE_PATH = "scripts/activate-staging-participant-gateway.py"
TRACER_POLICY_PATH = "scripts/tracer_data_plane_policy.py"
PARTICIPANT_POLICY_PATH = "scripts/staging_participant_gateway_policy.py"
PARTICIPANT_POLICY_JSON = "policy/staging-participant-gateway-activation-policy.json"
MATERIALIZER_PATH = "scripts/materialize-tracer-data-plane-secrets.py"
CONTRACT_PATH = "policy/repository-contract.json"
NONCE_ANNOTATION = "stadtstack.io/tracer-data-plane-activation-nonce"
RECEIPT_SCHEMA = "roebel_tracer_data_plane_activation_receipt_v1"
JOURNAL_SCHEMA = "roebel_tracer_data_plane_activation_journal_v1"
REVISION = re.compile(r"^[0-9a-f]{40}$")


class ActivationError(RuntimeError):
    pass


class ActivationInterrupted(ActivationError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ActivationError(message)


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(path))


def require_distinct_paths(*paths: Path) -> None:
    selected = [absolute_path(path) for path in paths]
    require(len(set(selected)) == len(selected), "Secret receipt, activation receipt, and journal paths must be distinct")
    existing = [path for path in selected if path.exists()]
    for index, left in enumerate(existing):
        for right in existing[index + 1 :]:
            require(not os.path.samefile(left, right), "receipt and journal paths must not alias")


def reserve_receipt(path: Path) -> dict[str, Any]:
    selected = absolute_path(path)
    require(not selected.exists(), "activation receipt path already exists")
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
        isinstance(reservation, dict)
        and set(reservation) == {"absolutePath", "pathSha256", "device", "inode"}
        and reservation.get("absolutePath") == str(selected)
        and reservation.get("pathSha256") == sha256_bytes(str(selected).encode("utf-8"))
        and type(reservation.get("device")) is int
        and type(reservation.get("inode")) is int,
        "activation receipt reservation binding drift",
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
        "activation receipt reservation inode drift",
    )
    raw = selected.read_bytes()
    require(len(raw) == info.st_size, "reserved activation receipt changed while reading")
    return raw


def commit_reserved_receipt(path: Path, reservation: dict[str, Any], value: dict[str, Any]) -> None:
    selected = absolute_path(path)
    require(read_reserved_receipt(selected, reservation) == b"", "reserved activation receipt is not empty")
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
            "activation receipt reservation changed before commit",
        )
        pending = memoryview((json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        while pending:
            written = os.write(descriptor, pending)
            require(written > 0, "activation receipt short write")
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


def protected_paths(tracer: Any) -> tuple[str, ...]:
    return tuple(dict.fromkeys((
        SELF_PATH,
        CORE_PATH,
        TRACER_POLICY_PATH,
        PARTICIPANT_POLICY_PATH,
        PARTICIPANT_POLICY_JSON,
        MATERIALIZER_PATH,
        CONTRACT_PATH,
        *sorted(tracer.expected_files()),
    )))


def bind_checkout(expected_revision: str, tracer: Any) -> dict[str, str]:
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
    result: dict[str, str] = {}
    for relative in protected_paths(tracer):
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
        result[relative] = tracer.bytes_sha256(blob.stdout)
    return dict(sorted(result.items()))


def read_private_json(path: Path, label: str) -> dict[str, Any]:
    selected = Path(os.path.abspath(path))
    info = os.lstat(selected)
    require(
        stat.S_ISREG(info.st_mode)
        and not selected.is_symlink()
        and info.st_uid == os.geteuid()
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o600
        and 0 < info.st_size <= 8 * 1024 * 1024,
        f"{label} must be an owned 0600 regular file",
    )
    raw = selected.read_bytes()
    require(len(raw) == info.st_size, f"{label} changed while reading")
    value = json.loads(raw)
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return value


def require_semantic(core: Any, observed: dict[str, Any], desired: dict[str, Any], label: str) -> None:
    """Use the protected server-default normalizer shared with participant activation."""
    try:
        core.POLICY.require_semantically_equal(observed, desired, label)
    except core.POLICY.PolicyError as error:
        raise ActivationError(str(error)) from error


def with_nonce(value: dict[str, Any], nonce: str) -> dict[str, Any]:
    result = copy.deepcopy(value)
    annotations = result.setdefault("metadata", {}).setdefault("annotations", {})
    require(NONCE_ANNOTATION not in annotations, "desired object already has activation nonce")
    annotations[NONCE_ANNOTATION] = nonce
    return result


def kind_cli(kind: str) -> str:
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


def get_optional(core: Any, runner: Any, kubeconfig: str, desired: dict[str, Any]) -> dict[str, Any] | None:
    metadata = desired["metadata"]
    response = runner.run([
        "kubectl", "--kubeconfig", kubeconfig, "-n", metadata["namespace"],
        "get", kind_cli(desired["kind"]), metadata["name"], "-o", "json",
    ])
    text = (response.out + "\n" + response.err).lower()
    if response.code != 0 and ("notfound" in text or re.search(r"\b404\b", text)):
        return None
    require(response.code == 0, f"GET failed: {desired['kind']}/{metadata['name']}")
    value = core.obj(response.out, f"{desired['kind']}/{metadata['name']}")
    return value


def bind_observed(core: Any, desired: dict[str, Any], observed: dict[str, Any], nonce: str, label: str) -> dict[str, Any]:
    nonce_desired = with_nonce(desired, nonce)
    require_semantic(core, observed, nonce_desired, label)
    metadata = observed.get("metadata", {})
    require(isinstance(metadata.get("uid"), str) and metadata["uid"], f"{label} UID absent")
    require(isinstance(metadata.get("resourceVersion"), str) and metadata["resourceVersion"].isdigit(), f"{label} resourceVersion absent")
    return {
        "target": {
            "apiVersion": desired["apiVersion"],
            "kind": desired["kind"],
            "namespace": desired["metadata"]["namespace"],
            "name": desired["metadata"]["name"],
        },
        "uid": metadata["uid"],
        "resourceVersion": metadata["resourceVersion"],
        "ownershipNonce": nonce,
        "temporaryNonceRemoved": False,
    }


def create_object(core: Any, runner: Any, kubeconfig: str, label: str, desired: dict[str, Any], nonce: str) -> dict[str, Any]:
    body = with_nonce(desired, nonce)
    metadata = desired["metadata"]
    response = runner.run(
        [
            "kubectl", "--kubeconfig", kubeconfig, "-n", metadata["namespace"],
            "create", "-f", "-", "-o", "json",
        ],
        input_text=canonical(body),
        timeout=30,
    )
    text = (response.out + "\n" + response.err).lower()
    require("alreadyexists" not in text and re.search(r"\b409\b", text) is None, f"{label} exists; adoption forbidden")
    observed = get_optional(core, runner, kubeconfig, desired)
    require(observed is not None, f"{label} create outcome unresolved")
    return bind_observed(core, desired, observed, nonce, label)


def remove_nonce(core: Any, runner: Any, kubeconfig: str, label: str, desired: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    current = get_optional(core, runner, kubeconfig, desired)
    require(current is not None and current["metadata"].get("uid") == record["uid"], f"{label} identity drift before nonce removal")
    require_semantic(core, current, with_nonce(desired, record["ownershipNonce"]), label)
    resource_version = current["metadata"].get("resourceVersion")
    annotation_path = "/metadata/annotations/" + NONCE_ANNOTATION.replace("~", "~0").replace("/", "~1")
    patch = [
        {"op": "test", "path": "/metadata/uid", "value": record["uid"]},
        {"op": "test", "path": "/metadata/resourceVersion", "value": resource_version},
        {"op": "test", "path": annotation_path, "value": record["ownershipNonce"]},
        {"op": "remove", "path": annotation_path},
    ]
    metadata = desired["metadata"]
    response = runner.run([
        "kubectl", "--kubeconfig", kubeconfig, "-n", metadata["namespace"],
        "patch", kind_cli(desired["kind"]), metadata["name"], "--type=json", "-p", canonical(patch), "-o", "json",
    ])
    require(response.code == 0, f"{label} nonce-removal CAS failed")
    observed = core.obj(response.out, f"{label} nonce-removal response")
    require(observed.get("metadata", {}).get("uid") == record["uid"], f"{label} UID changed")
    require_semantic(core, observed, desired, label)
    result = copy.deepcopy(record)
    result["resourceVersion"] = observed["metadata"]["resourceVersion"]
    result["temporaryNonceRemoved"] = True
    return result


def resource_path(desired: dict[str, Any]) -> str:
    kind = desired["kind"]
    namespace = desired["metadata"]["namespace"]
    name = desired["metadata"]["name"]
    api, plural = {
        "ConfigMap": ("v1", "configmaps"),
        "Deployment": ("apps/v1", "deployments"),
        "Kustomization": ("kustomize.toolkit.fluxcd.io/v1", "kustomizations"),
        "NetworkPolicy": ("networking.k8s.io/v1", "networkpolicies"),
        "Role": ("rbac.authorization.k8s.io/v1", "roles"),
        "RoleBinding": ("rbac.authorization.k8s.io/v1", "rolebindings"),
        "Service": ("v1", "services"),
        "ServiceAccount": ("v1", "serviceaccounts"),
    }[kind]
    prefix = "/api" if api == "v1" else "/apis"
    return f"{prefix}/{api}/namespaces/{namespace}/{plural}/{name}"


def delete_owned(core: Any, runner: Any, snapshot: Any, kubeconfig: str, label: str, desired: dict[str, Any], record: dict[str, Any]) -> None:
    current = get_optional(core, runner, kubeconfig, desired)
    if current is None:
        return
    require(current.get("metadata", {}).get("uid") == record["uid"], f"rollback UID drift: {label}")
    if record.get("temporaryNonceRemoved"):
        require_semantic(core, current, desired, f"rollback {label}")
    else:
        try:
            require_semantic(core, current, with_nonce(desired, record["ownershipNonce"]), f"rollback nonce {label}")
        except ActivationError:
            # The nonce-removal CAS response or following journal update may
            # have been lost.  Exact receipt UID plus exact nonce-free desired
            # semantics is the sole alternate ownership proof.
            require_semantic(core, current, desired, f"rollback post-nonce {label}")
    rv = current["metadata"].get("resourceVersion")
    require(isinstance(rv, str) and rv.isdigit(), f"rollback resourceVersion absent: {label}")
    options: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": "DeleteOptions",
        "preconditions": {"uid": record["uid"], "resourceVersion": rv},
    }
    if desired["kind"] == "Deployment":
        options["propagationPolicy"] = "Foreground"
    core.raw_delete(snapshot, resource_path(desired), canonical(options), 15)
    deadline = time.monotonic() + 120
    while get_optional(core, runner, kubeconfig, desired) is not None:
        require(time.monotonic() < deadline, f"rollback absence timeout: {label}")
        time.sleep(0.2)


def recover_nonce_owned(core: Any, runner: Any, kubeconfig: str, desired_objects: dict[str, dict[str, Any]], nonce: str, records: dict[str, dict[str, Any]]) -> None:
    for label, desired in desired_objects.items():
        if label in records:
            continue
        current = get_optional(core, runner, kubeconfig, desired)
        if current is None:
            continue
        annotations = current.get("metadata", {}).get("annotations", {})
        if isinstance(annotations, dict) and annotations.get(NONCE_ANNOTATION) == nonce:
            records[label] = bind_observed(core, desired, current, nonce, f"recovered {label}")


def validate_object_record(
    label: str,
    record: Any,
    desired: dict[str, Any],
    nonce: str,
) -> dict[str, Any]:
    require(
        isinstance(record, dict)
        and set(record) == {
            "target", "uid", "resourceVersion", "ownershipNonce",
            "temporaryNonceRemoved",
        }
        and record.get("target")
        == {
            "apiVersion": desired["apiVersion"],
            "kind": desired["kind"],
            "namespace": desired["metadata"]["namespace"],
            "name": desired["metadata"]["name"],
        }
        and isinstance(record.get("uid"), str)
        and bool(record["uid"])
        and isinstance(record.get("resourceVersion"), str)
        and record["resourceVersion"].isdigit()
        and record.get("ownershipNonce") == nonce
        and type(record.get("temporaryNonceRemoved")) is bool,
        f"activation ownership record drift: {label}",
    )
    return record


def recovery_preflight(
    core: Any,
    runner: Any,
    kubeconfig: str,
    desired_objects: dict[str, dict[str, Any]],
    nonce: str,
    records: dict[str, dict[str, Any]],
) -> None:
    """Audit every exact-name target before the first recovery mutation."""
    recover_nonce_owned(core, runner, kubeconfig, desired_objects, nonce, records)
    for label, desired in desired_objects.items():
        current = get_optional(core, runner, kubeconfig, desired)
        if label not in records:
            require(current is None, f"unowned tracer target blocks recovery: {label}")
            continue
        record = validate_object_record(label, records[label], desired, nonce)
        if current is None:
            continue
        require(current.get("metadata", {}).get("uid") == record["uid"], f"recovery UID drift: {label}")
        candidates = [with_nonce(desired, nonce), desired]
        if desired["kind"] == "Kustomization" and current.get("spec", {}).get("suspend") is False:
            active = copy.deepcopy(desired)
            active.setdefault("spec", {})["suspend"] = False
            candidates.extend((with_nonce(active, nonce), active))
        errors: list[str] = []
        for candidate in candidates:
            try:
                require_semantic(core, current, candidate, f"recovery {label}")
                break
            except ActivationError as error:
                errors.append(str(error))
        else:
            raise ActivationError(f"recovery semantic ownership drift: {label}: {'; '.join(errors)}")


def validate_terminal_activation_receipt(
    value: Any,
    expected_revision: str,
    hashes: dict[str, str],
    nonce: str,
    desired: dict[str, dict[str, Any]],
    create_order: list[str],
) -> dict[str, Any]:
    require(isinstance(value, dict), "reserved activation receipt must contain a JSON object")
    require(
        value.get("schemaVersion") == RECEIPT_SCHEMA
        and value.get("status") in {"activated", "rolled-back", "recovered-rolled-back"}
        and value.get("protectedRevision") == expected_revision
        and value.get("protectedFileSha256") == hashes
        and value.get("operationNonce") == nonce
        and value.get("secretValuesRead") is False
        and value.get("civicAuthorityEffects") is False,
        "reserved activation receipt terminal binding drift",
    )
    records = value.get("objectRecords")
    require(isinstance(records, dict) and set(records) <= set(create_order), "reserved activation receipt object set drift")
    if value["status"] == "activated":
        require(value.get("createOrder") == create_order and set(records) == set(create_order), "committed activation receipt object set incomplete")
    for label, record in records.items():
        validate_object_record(label, record, desired[label], nonce)
    return value


def validate_secret_receipt(receipt: dict[str, Any], expected_revision: str, tracer: Any) -> dict[str, Any]:
    contract = tracer.secret_materialization_contract()
    require(receipt.get("schemaVersion") == contract["receiptSchemaVersion"] and receipt.get("status") == "materialized", "tracer Secret receipt status drift")
    require(receipt.get("protectedRevision") == expected_revision, "tracer Secret receipt revision drift")
    require(receipt.get("receiptContainsValues") is False and receipt.get("civicAuthorityEffects") is False, "tracer Secret receipt authority/value drift")
    require(receipt.get("sharedValueBindingsVerified") == contract["sharedValueBindings"], "tracer Secret shared binding drift")
    window = receipt.get("anonJwt", {})
    require(
        type(window.get("iat")) is int
        and type(window.get("exp")) is int
        and window["exp"] >= int(time.time()) + 30 * 24 * 60 * 60
        and window.get("valueIncluded") is False,
        "tracer anon JWT has less than 30 days remaining",
    )
    records = receipt.get("secretRecords")
    require(isinstance(records, dict) and set(records) == set(contract["secrets"]), "tracer Secret receipt set drift")
    return records


def bind_live_secrets(materializer: Any, core: Any, runner: Any, kubeconfig: str, tracer: Any, records: dict[str, Any]) -> dict[str, Any]:
    contract = tracer.secret_materialization_contract()
    result: dict[str, Any] = {}
    for label, reference in contract["secrets"].items():
        observed = materializer.read_projection(core, runner, kubeconfig, label, reference)
        require(observed is not None, f"tracer Secret absent: {label}")
        for key in ("target", "uid", "resourceVersion", "keySet", "ownershipNonce", "valuesRead"):
            require(observed.get(key) == records[label].get(key), f"tracer Secret identity drift: {label}.{key}")
        result[label] = observed
    return result


def verify_shared_source(core: Any, runner: Any, kubeconfig: str, tracer: Any, operations_revision: str) -> dict[str, Any]:
    desired = {
        "apiVersion": "source.toolkit.fluxcd.io/v1",
        "kind": "GitRepository",
        "metadata": {"name": tracer.FLUX_SOURCE_NAME, "namespace": tracer.FLUX_NAMESPACE},
    }
    source = get_optional(core, runner, kubeconfig, desired)
    require(source is not None, "shared Flux source absent")
    spec = source.get("spec", {})
    require(
        spec.get("url") == "https://github.com/GiraeffleAeffle/roebel-staging-operations.git"
        and spec.get("ref") == {"branch": "main"}
        and spec.get("suspend") is not True,
        "shared Flux source identity drift",
    )
    expected = f"main@sha1:{operations_revision}"
    status = source.get("status", {})
    require(status.get("artifact", {}).get("revision") == expected, "shared Flux source is not at protected operations revision")
    ready = next((item for item in status.get("conditions", []) if item.get("type") == "Ready"), None)
    require(isinstance(ready, dict) and ready.get("status") == "True", "shared Flux source not Ready")
    return {"revision": expected, "ready": True, "mutation": False}


def unsuspend(core: Any, runner: Any, kubeconfig: str, tracer: Any, record: dict[str, Any]) -> dict[str, Any]:
    desired = tracer.dormant_flux_objects(suspended=True)["kustomization"]
    current = get_optional(core, runner, kubeconfig, desired)
    require(current is not None and current["metadata"].get("uid") == record["uid"], "tracer Kustomization identity drift")
    require_semantic(core, current, desired, "tracer Kustomization dormant")
    patch = canonical({"metadata": {"resourceVersion": current["metadata"]["resourceVersion"]}, "spec": {"suspend": False}})
    metadata = desired["metadata"]
    response = runner.run([
        "kubectl", "--kubeconfig", kubeconfig, "-n", metadata["namespace"],
        "patch", "kustomization", metadata["name"], "--type=merge", "-p", patch, "-o", "json",
    ])
    require(response.code == 0, "tracer Kustomization unsuspend CAS failed")
    after = core.obj(response.out, "tracer Kustomization unsuspend response")
    require(after.get("metadata", {}).get("uid") == record["uid"] and after.get("spec", {}).get("suspend") is False, "tracer Kustomization unsuspend ambiguous")
    return after


def wait_ready(core: Any, runner: Any, kubeconfig: str, tracer: Any, operations_revision: str, kustomization_uid: str) -> dict[str, Any]:
    target = tracer.dormant_flux_objects(suspended=False)["kustomization"]
    response = runner.run([
        "kubectl", "--kubeconfig", kubeconfig, "-n", target["metadata"]["namespace"],
        "wait", "--for=condition=Ready", f"kustomization/{target['metadata']['name']}", "--timeout=300s",
    ], timeout=305)
    require(response.code == 0, "tracer Flux readiness timeout")
    live = get_optional(core, runner, kubeconfig, target)
    require(live is not None and live["metadata"].get("uid") == kustomization_uid, "tracer Flux identity changed")
    expected_revision = f"main@sha1:{operations_revision}"
    status = live.get("status", {})
    require(status.get("lastAppliedRevision") == expected_revision, "tracer Flux applied revision drift")
    for deployment in (tracer.POSTGRES_NAME, tracer.POSTGREST_NAME):
        rollout = runner.run([
            "kubectl", "--kubeconfig", kubeconfig, "-n", tracer.NAMESPACE,
            "rollout", "status", f"deployment/{deployment}", "--timeout=300s",
        ], timeout=305)
        require(rollout.code == 0, f"tracer Deployment readiness timeout: {deployment}")
    return {"uid": kustomization_uid, "lastAppliedRevision": expected_revision, "ready": True}


def service_binding(core: Any, runner: Any, kubeconfig: str, tracer: Any, service: dict[str, Any]) -> dict[str, Any]:
    live = get_optional(core, runner, kubeconfig, service)
    require(live is not None, f"tracer Service absent: {service['metadata']['name']}")
    require_semantic(core, live, service, f"Service {service['metadata']['name']}")
    name = service["metadata"]["name"]
    listing = runner.run([
        "kubectl", "--kubeconfig", kubeconfig, "-n", tracer.NAMESPACE,
        "get", "endpointslices.discovery.k8s.io", "-l", f"kubernetes.io/service-name={name}", "-o", "json",
    ])
    require(listing.code == 0, f"EndpointSlice query failed: {name}")
    value = core.obj(listing.out, f"EndpointSlices {name}")
    items = value.get("items", [])
    ready_addresses: list[str] = []
    expected_port = service["spec"]["ports"][0]["port"]
    for item in items:
        ports = item.get("ports", [])
        if not any(port.get("port") == expected_port for port in ports):
            continue
        for endpoint in item.get("endpoints", []):
            if endpoint.get("conditions", {}).get("ready") is True:
                ready_addresses.extend(endpoint.get("addresses", []))
    require(ready_addresses, f"no ready EndpointSlice addresses: {name}")
    return {"serviceUid": live["metadata"]["uid"], "port": expected_port, "readyEndpointAddresses": sorted(set(ready_addresses))}


def suspend_if_active(core: Any, runner: Any, kubeconfig: str, tracer: Any, record: dict[str, Any] | None) -> None:
    if record is None:
        return
    desired = tracer.dormant_flux_objects(suspended=True)["kustomization"]
    current = get_optional(core, runner, kubeconfig, desired)
    if current is None:
        return
    require(current.get("metadata", {}).get("uid") == record["uid"], "rollback Kustomization UID drift")
    if current.get("spec", {}).get("suspend") is True:
        return
    patch = canonical({"metadata": {"resourceVersion": current["metadata"]["resourceVersion"]}, "spec": {"suspend": True}})
    response = runner.run([
        "kubectl", "--kubeconfig", kubeconfig, "-n", desired["metadata"]["namespace"],
        "patch", "kustomization", desired["metadata"]["name"], "--type=merge", "-p", patch, "-o", "json",
    ])
    require(response.code == 0, "rollback could not suspend tracer Flux")


def write_receipt(path: Path, value: dict[str, Any]) -> None:
    selected = Path(os.path.abspath(path))
    require(not selected.exists(), "activation receipt path already exists")
    selected.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(selected, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        pending = memoryview((json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"))
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
    """Durably replace a value-free owner-only recovery journal."""
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
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600, "activation journal durability drift")
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


class SignalGuard:
    def __init__(self) -> None:
        self.original: dict[int, Any] = {}
        self.observed: list[int] = []

    def install(self) -> None:
        def handler(signum: int, _frame: Any) -> None:
            self.observed.append(signum)
            for item in (signal.SIGINT, signal.SIGTERM):
                signal.signal(item, signal.SIG_IGN)
            raise ActivationInterrupted(f"operator signal {signum}")
        for item in (signal.SIGINT, signal.SIGTERM):
            self.original[item] = signal.getsignal(item)
            signal.signal(item, handler)

    def defer(self) -> None:
        for item in (signal.SIGINT, signal.SIGTERM):
            signal.signal(item, signal.SIG_IGN)

    def restore(self) -> None:
        for item, handler in self.original.items():
            signal.signal(item, handler)


def recover_from_journal(
    expected_revision: str,
    kubeconfig: str,
    journal_path: Path,
    receipt_path: Path,
) -> dict[str, Any]:
    """Rollback an interrupted transaction using only its durable ownership journal."""
    require_distinct_paths(journal_path, receipt_path)
    tracer = load_module(ROOT / TRACER_POLICY_PATH, f"tracer_policy_recovery_{expected_revision}")
    hashes = bind_checkout(expected_revision, tracer)
    tracer.verify_render(ROOT)
    participant = load_module(ROOT / PARTICIPANT_POLICY_PATH, f"participant_policy_recovery_{expected_revision}")
    core = load_module(ROOT / CORE_PATH, f"participant_core_recovery_{expected_revision}")
    core.POLICY = participant
    descriptor = participant.assert_activation_ready(json.loads((ROOT / PARTICIPANT_POLICY_JSON).read_text()))
    journal = read_private_json(journal_path, "tracer activation recovery journal")
    require(
        journal.get("schemaVersion") == JOURNAL_SCHEMA
        and journal.get("status") in {"in-progress", "committed", "rolled-back"}
        and journal.get("protectedRevision") == expected_revision
        and journal.get("protectedFileSha256") == hashes
        and journal.get("secretValuesIncluded") is False
        and journal.get("civicAuthorityEffects") is False,
        "tracer activation recovery journal boundary drift",
    )
    nonce = journal.get("operationNonce")
    require(isinstance(nonce, str) and re.fullmatch(r"[0-9a-f]{64}", nonce) is not None, "recovery journal nonce invalid")
    application = tracer.expected_application_objects(ROOT)
    flux = tracer.dormant_flux_objects(suspended=True)
    desired: dict[str, dict[str, Any]] = {
        **{f"application.{label}": value for label, value in application.items()},
        **{f"flux.{label}": value for label, value in flux.items()},
    }
    create_order = [
        *(f"application.{label}" for label in tracer.application_object_order()),
        *(f"flux.{label}" for label in tracer.dormant_flux_contract()["objectOrder"]),
    ]
    require(journal.get("createOrder") == create_order and list(desired) == create_order, "recovery journal create order drift")
    records = journal.get("objectRecords")
    require(isinstance(records, dict) and set(records) <= set(create_order), "recovery journal object record set drift")
    records = copy.deepcopy(records)
    for label, record in records.items():
        validate_object_record(label, record, desired[label], nonce)
    reservation = journal.get("receiptReservation")
    committed = read_reserved_receipt(receipt_path, reservation)
    if committed:
        terminal = validate_terminal_activation_receipt(
            json.loads(committed), expected_revision, hashes, nonce, desired, create_order,
        )
        journal["status"] = "committed" if terminal["status"] == "activated" else "rolled-back"
        journal["phase"] = "terminal-receipt-observed-without-cluster-mutation"
        journal["terminalReceiptSha256"] = sha256_bytes(committed)
        write_journal(journal_path, journal)
        return terminal
    runner = core.Runner()
    snapshot = core.snapshot_kubeconfig_v4(kubeconfig, runner)
    guard = SignalGuard()
    guard.install()
    deleted = list(journal.get("rollbackDeleted", []))
    require(all(label in create_order for label in deleted), "recovery journal deleted set drift")
    try:
        cluster = core.cluster_binding_v4(runner, snapshot, descriptor)
        recovery_preflight(core, runner, str(snapshot.path), desired, nonce, records)
        guard.defer()
        journal["objectRecords"] = copy.deepcopy(records)
        journal["phase"] = "explicit-recovery-entry"
        write_journal(journal_path, journal)
        suspend_if_active(core, runner, str(snapshot.path), tracer, records.get("flux.kustomization"))
        for label in reversed(create_order):
            if label not in records:
                require(get_optional(core, runner, str(snapshot.path), desired[label]) is None, f"unowned tracer target blocks recovery: {label}")
                continue
            delete_owned(core, runner, snapshot, str(snapshot.path), label, desired[label], records[label])
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
            "createOrder": create_order,
            "objectRecords": records,
            "rollbackDeleted": deleted,
            "secretMaterializationRetainedForRetry": True,
            "secretValuesRead": False,
            "civicAuthorityEffects": False,
        }
        commit_reserved_receipt(receipt_path, reservation, receipt)
        return receipt
    finally:
        guard.restore()
        snapshot.close()


def activate(
    expected_revision: str,
    kubeconfig: str,
    secret_receipt_path: Path,
    receipt_path: Path,
    journal_path: Path,
) -> dict[str, Any]:
    require_distinct_paths(secret_receipt_path, receipt_path, journal_path)
    tracer = load_module(ROOT / TRACER_POLICY_PATH, f"tracer_policy_{expected_revision}")
    hashes = bind_checkout(expected_revision, tracer)
    tracer.verify_render(ROOT)
    require(tracer.runtime_pin()["activationReady"] is True, "tracer data plane is not activation-ready")
    participant = load_module(ROOT / PARTICIPANT_POLICY_PATH, f"participant_policy_{expected_revision}")
    core = load_module(ROOT / CORE_PATH, f"participant_core_{expected_revision}")
    materializer = load_module(ROOT / MATERIALIZER_PATH, f"tracer_materializer_{expected_revision}")
    core.POLICY = participant
    descriptor = participant.assert_activation_ready(json.loads((ROOT / PARTICIPANT_POLICY_JSON).read_text()))
    secret_receipt = read_private_json(secret_receipt_path, "tracer Secret materialization receipt")
    secret_records = validate_secret_receipt(secret_receipt, expected_revision, tracer)
    secret_nonce = secret_receipt.get("operationNonce")
    require(isinstance(secret_nonce, str) and re.fullmatch(r"[0-9a-f]{64}", secret_nonce) is not None, "tracer Secret receipt nonce drift")
    for label, reference in tracer.secret_materialization_contract()["secrets"].items():
        materializer.validate_secret_record(label, secret_records[label], reference, operation_nonce=secret_nonce)
    application = tracer.expected_application_objects(ROOT)
    flux = tracer.dormant_flux_objects(suspended=True)
    desired: dict[str, dict[str, Any]] = {
        **{f"application.{label}": value for label, value in application.items()},
        **{f"flux.{label}": value for label, value in flux.items()},
    }
    create_order = [
        *(f"application.{label}" for label in tracer.application_object_order()),
        *(f"flux.{label}" for label in tracer.dormant_flux_contract()["objectOrder"]),
    ]
    require(list(desired) == create_order, "tracer transaction create order drift")
    runner = core.Runner()
    snapshot = core.snapshot_kubeconfig_v4(kubeconfig, runner)
    records: dict[str, dict[str, Any]] = {}
    nonce = secrets.token_hex(32)
    guard = SignalGuard()
    guard.install()
    try:
        cluster = core.cluster_binding_v4(runner, snapshot, descriptor)
        live_secrets = bind_live_secrets(materializer, core, runner, str(snapshot.path), tracer, secret_records)
        source = verify_shared_source(core, runner, str(snapshot.path), tracer, expected_revision)
        for label in create_order:
            require(get_optional(core, runner, str(snapshot.path), desired[label]) is None, f"tracer target already exists; adoption forbidden: {label}")
        require(not journal_path.exists(), "activation journal path already exists")
        reservation = reserve_receipt(receipt_path)
        journal = {
            "schemaVersion": JOURNAL_SCHEMA,
            "status": "in-progress",
            "phase": "reserved-before-first-mutation",
            "protectedRevision": expected_revision,
            "protectedFileSha256": hashes,
            "operationNonce": nonce,
            "receiptReservation": reservation,
            "createOrder": create_order,
            "objectRecords": {},
            "rollbackDeleted": [],
            "secretMaterializationReceiptSha256": tracer.bytes_sha256(secret_receipt_path.read_bytes()),
            "secretValuesIncluded": False,
            "civicAuthorityEffects": False,
        }
        write_journal(journal_path, journal)
        commit_started = False
        try:
            for label in create_order:
                records[label] = create_object(core, runner, str(snapshot.path), label, desired[label], nonce)
                journal["phase"] = f"created:{label}"
                journal["objectRecords"] = copy.deepcopy(records)
                write_journal(journal_path, journal)
            for label in create_order:
                records[label] = remove_nonce(core, runner, str(snapshot.path), label, desired[label], records[label])
                journal["phase"] = f"nonce-removed:{label}"
                journal["objectRecords"] = copy.deepcopy(records)
                write_journal(journal_path, journal)
            unsuspend(core, runner, str(snapshot.path), tracer, records["flux.kustomization"])
            journal["phase"] = "flux-unsuspended"
            journal["objectRecords"] = copy.deepcopy(records)
            write_journal(journal_path, journal)
            ready = wait_ready(core, runner, str(snapshot.path), tracer, expected_revision, records["flux.kustomization"]["uid"])
            endpoints = {
                "postgres": service_binding(core, runner, str(snapshot.path), tracer, tracer.expected_postgres_service()),
                "postgrest": service_binding(core, runner, str(snapshot.path), tracer, tracer.expected_postgrest_service()),
            }
            receipt = {
                "schemaVersion": RECEIPT_SCHEMA,
                "status": "activated",
                "protectedRevision": expected_revision,
                "operationNonce": nonce,
                "productSourceRevision": tracer.PRODUCT_SOURCE_REVISION,
                "protectedFileSha256": hashes,
                "clusterBinding": cluster,
                "sharedFluxSource": source,
                "secretMaterializationReceiptSha256": tracer.bytes_sha256(secret_receipt_path.read_bytes()),
                "secretRecords": live_secrets,
                "createOrder": create_order,
                "objectRecords": records,
                "flux": ready,
                "serviceBindings": endpoints,
                "failureRollback": "exact-operation-owned-uids-only",
                "secretValuesRead": False,
                "civicAuthorityEffects": False,
                "signalsDeferredDuringFinalization": guard.observed,
                "functionalHttpRpcProof": {
                    "status": "pending-participant-gateway-protected-preflight",
                    "secretValuesRead": False,
                },
            }
            journal["phase"] = "activation-ready-before-receipt-commit"
            journal["objectRecords"] = copy.deepcopy(records)
            write_journal(journal_path, journal)
            # Receipt durability is the commit point.  Defer signals before
            # the first byte so a post-commit signal cannot enter rollback.
            guard.defer()
            commit_started = True
            commit_reserved_receipt(receipt_path, reservation, receipt)
            return receipt
        except BaseException as error:
            if commit_started:
                # Empty reservations can be recovered; a partial write is
                # ambiguous and must block rather than trigger cluster writes.
                raise
            guard.defer()
            recovery_preflight(core, runner, str(snapshot.path), desired, nonce, records)
            journal["phase"] = "rollback-entry"
            journal["objectRecords"] = copy.deepcopy(records)
            write_journal(journal_path, journal)
            suspend_if_active(core, runner, str(snapshot.path), tracer, records.get("flux.kustomization"))
            for label in reversed(create_order):
                if label in records:
                    delete_owned(core, runner, snapshot, str(snapshot.path), label, desired[label], records[label])
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
                "createOrder": create_order,
                "objectRecords": records,
                "rollbackDeleted": list(journal["rollbackDeleted"]),
                "failureType": type(error).__name__,
                "failureRollback": "exact-operation-owned-uids-only",
                "secretMaterializationRetainedForRetry": True,
                "secretValuesRead": False,
                "civicAuthorityEffects": False,
            }
            commit_reserved_receipt(receipt_path, reservation, rollback_receipt)
            raise
    finally:
        guard.restore()
        snapshot.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-revision", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--live", action="store_true")
    mode.add_argument("--recover-journal", type=Path)
    parser.add_argument("--kubeconfig")
    parser.add_argument("--secret-receipt", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--journal", type=Path)
    args = parser.parse_args()
    if args.recover_journal is not None:
        require(
            args.kubeconfig is not None
            and args.receipt is not None
            and args.secret_receipt is None
            and args.journal is None,
            "tracer recovery requires kubeconfig and output receipt only",
        )
        result = recover_from_journal(
            args.expected_revision,
            args.kubeconfig,
            args.recover_journal,
            args.receipt,
        )
        print(json.dumps({
            "schemaVersion": result["schemaVersion"],
            "status": result["status"],
            "protectedRevision": result["protectedRevision"],
            "receipt": str(args.receipt),
            "secretValuesRead": False,
            "civicAuthorityEffects": False,
        }, indent=2, sort_keys=True))
        return 0
    require(
        args.kubeconfig is not None
        and args.secret_receipt is not None
        and args.receipt is not None
        and args.journal is not None,
        "tracer activation requires kubeconfig, Secret receipt, output receipt, and recovery journal",
    )
    result = activate(args.expected_revision, args.kubeconfig, args.secret_receipt, args.receipt, args.journal)
    print(json.dumps({
        "schemaVersion": result["schemaVersion"],
        "status": result["status"],
        "protectedRevision": result["protectedRevision"],
        "receipt": str(args.receipt),
        "secretValuesRead": False,
        "civicAuthorityEffects": False,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ActivationError, OSError, ValueError) as error:
        print(f"tracer data-plane activation failed: {error}", file=_bootstrap_sys.stderr)
        raise SystemExit(2)
