#!/usr/bin/env python3
"""Exact, receipt-bound Secret materializer for the staging participant gateway.

Secret values enter only through inherited private file descriptors.  This
runner can create exactly the two policy-owned Secrets, or delete those exact
UID/resourceVersion pairs after the participant runtime is fully deactivated.
It never emits Secret values, accepts caller-selected object identities, or
adopts an existing object.
"""
from __future__ import annotations

import sys as _bootstrap_sys
if __name__ == "__main__" and not (_bootstrap_sys.flags.isolated and _bootstrap_sys.flags.safe_path):
    print("participant Secret materializer blocked: invoke with python3 -I", file=_bootstrap_sys.stderr)
    raise SystemExit(2)

import argparse
import base64
import copy
import hashlib
import http.client
import json
import os
import re
import secrets
import ssl
import stat
import subprocess
import sys
import types
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
SELF_PATH = "scripts/materialize-staging-participant-gateway-secrets.py"
CORE_RUNNER_PATH = "scripts/activate-staging-participant-gateway.py"
POLICY_MODULE_PATH = "scripts/staging_participant_gateway_policy.py"
POLICY_PATH = "policy/staging-participant-gateway-activation-policy.json"
LIVE_WRAPPER_PATH = "scripts/run-staging-participant-gateway-live.py"
REPOSITORY_CONTRACT_PATH = "policy/repository-contract.json"
PROTECTED_PATHS = (
    SELF_PATH,
    CORE_RUNNER_PATH,
    POLICY_MODULE_PATH,
    POLICY_PATH,
    LIVE_WRAPPER_PATH,
    REPOSITORY_CONTRACT_PATH,
)

NAMESPACE = "stadtstack-roebel-web-preview"
CONFIG_NAME = "roebel-staging-participant-gateway-config"
RUNTIME_NAME = "roebel-staging-participant-gateway-runtime"
CONFIG_KEYS = ("allowed-wallets", "invite-sha256", "mecky-pubkey")
RUNTIME_KEYS = ("session-key", "supabase-anon-key", "supabase-rpc-secret")
CREATE_ORDER = ("config", "runtime")
DELETE_ORDER = tuple(reversed(CREATE_ORDER))
NONCE_ANNOTATION = "stadtstack.io/participant-secret-materialization-nonce"
MATERIALIZATION_RECEIPT_SCHEMA = "roebel_staging_participant_secret_materialization_receipt_v1"
TEARDOWN_RECEIPT_SCHEMA = "roebel_staging_participant_secret_teardown_receipt_v1"
MAX_INPUT_BYTES = 256 * 1024
REVISION = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
UID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
KEY = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
GIT_BIN = Path("/usr/bin/git")

CORE: Any = None
POLICY: Any = None


class MaterializationError(RuntimeError):
    pass


class PostSendUncertainError(MaterializationError):
    pass


def require(value: bool, message: str) -> None:
    if not value:
        raise MaterializationError(message)


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def bytes_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def revision(value: Any) -> str:
    require(isinstance(value, str) and REVISION.fullmatch(value) is not None, "protected revision must be lowercase SHA-1")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def json_object(raw: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (TypeError, ValueError) as exc:
        raise MaterializationError(f"{label} is invalid or duplicate-key JSON") from exc
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return value


def _git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "HOME": "/dev/null",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


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
    return subprocess.run([str(GIT_BIN), "--no-replace-objects", *args], env=_git_environment(), **kwargs)


def git_blob(rev: str, path: str) -> bytes:
    result = trusted_git(
        ["-C", str(ROOT), "show", f"{rev}:{path}"],
        capture_output=True,
        check=False,
        timeout=10,
    )
    require(result.returncode == 0, f"protected Git blob unavailable: {path}")
    return result.stdout


def bind_protected_checkout(rev: str) -> tuple[dict[str, str], dict[str, bytes]]:
    head = trusted_git(["-C", str(ROOT), "rev-parse", "HEAD"], text=True, capture_output=True, check=False)
    require(head.returncode == 0 and head.stdout.strip() == rev, "checkout is not the expected protected revision")
    hashes: dict[str, str] = {}
    blobs: dict[str, bytes] = {}
    for path in PROTECTED_PATHS:
        local = ROOT / path
        info = os.lstat(local)
        require(stat.S_ISREG(info.st_mode) and not local.is_symlink(), f"protected file is not a regular Git blob: {path}")
        expected = git_blob(rev, path)
        require(local.read_bytes() == expected, f"protected file differs from exact Git blob: {path}")
        hashes[path] = bytes_digest(expected)
        blobs[path] = expected
    return dict(sorted(hashes.items())), blobs


def _compile_module(source: bytes, name: str, filename: str) -> Any:
    require(isinstance(source, bytes) and source, f"protected {name} source absent")
    module = types.ModuleType(name)
    module.__file__ = filename
    module.__package__ = ""
    sys.modules[name] = module
    try:
        exec(compile(source, filename, "exec", dont_inherit=True), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def load_protected_runtime(rev: str) -> tuple[dict[str, str], dict[str, Any]]:
    global CORE, POLICY
    hashes, blobs = bind_protected_checkout(rev)
    CORE = _compile_module(blobs[CORE_RUNNER_PATH], f"participant_secret_core_{rev}", str(ROOT / CORE_RUNNER_PATH))
    POLICY = _compile_module(blobs[POLICY_MODULE_PATH], f"participant_secret_policy_{rev}", str(ROOT / POLICY_MODULE_PATH))
    CORE.POLICY = POLICY
    raw_policy = blobs[POLICY_PATH]
    policy = json_object(raw_policy.decode("utf-8"), "participant activation policy")
    try:
        policy = POLICY.assert_activation_ready(policy)
    except POLICY.PolicyError as exc:
        raise MaterializationError(str(exc)) from exc
    bind_policy_identity(policy)
    return hashes, policy


def _target(kind: str, name: str, namespace: str) -> dict[str, str]:
    api_version = {
        "Secret": "v1",
        "ServiceAccount": "v1",
        "Service": "v1",
        "Deployment": "apps/v1",
        "Ingress": "networking.k8s.io/v1",
        "NetworkPolicy": "networking.k8s.io/v1",
        "Kustomization": "kustomize.toolkit.fluxcd.io/v1",
    }[kind]
    return {"apiVersion": api_version, "kind": kind, "name": name, "namespace": namespace}


def expected_secret_references() -> dict[str, dict[str, Any]]:
    return {
        "config": {"name": CONFIG_NAME, "namespace": NAMESPACE, "keys": list(CONFIG_KEYS)},
        "runtime": {"name": RUNTIME_NAME, "namespace": NAMESPACE, "keys": list(RUNTIME_KEYS)},
    }


def bind_policy_identity(policy: dict[str, Any]) -> None:
    require(policy["runtime"]["secretReferences"] == expected_secret_references(), "participant Secret identity/keyset drift")
    contract = policy["runtime"].get("secretMaterializer")
    expected_targets = [
        _target("NetworkPolicy", "roebel-staging-participant-gateway", NAMESPACE),
        _target("ServiceAccount", "roebel-staging-participant-gateway", NAMESPACE),
        _target("Service", "roebel-staging-participant-gateway", NAMESPACE),
        _target("Deployment", "roebel-staging-participant-gateway", NAMESPACE),
        _target("Ingress", "roebel-staging-participant-gateway", NAMESPACE),
        _target("NetworkPolicy", "roebel-staging-participant-workbench-ingress", "stadtstack-roebel-staging-lab"),
        _target("Kustomization", "roebel-staging-participant-gateway", "flux-roebel-staging"),
        _target("Kustomization", "roebel-staging-participant-workbench-ingress", "flux-roebel-staging"),
    ]
    require(
        contract == {
            "runner": SELF_PATH,
            "receiptSchemaVersion": MATERIALIZATION_RECEIPT_SCHEMA,
            "teardownReceiptSchemaVersion": TEARDOWN_RECEIPT_SCHEMA,
            "inputTransport": "owned-private-inherited-descriptors-only",
            "createOrder": list(CREATE_ORDER),
            "initialState": "both-exact-secret-names-absent",
            "adoption": "forbidden",
            "receiptContainsValues": False,
            "teardown": {
                "sourceReceiptRequired": True,
                "deleteOrder": list(DELETE_ORDER),
                "uidResourceVersionPreconditions": True,
                "requiredAbsentTargets": expected_targets,
            },
        },
        "participant Secret materializer policy drift",
    )


def _descriptor_bytes(fd: int, label: str) -> bytes:
    require(isinstance(fd, int) and fd >= 3, f"{label} descriptor invalid")
    info = os.fstat(fd)
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.geteuid()
        and info.st_nlink in {0, 1}
        and stat.S_IMODE(info.st_mode) == 0o600
        and 0 < info.st_size <= MAX_INPUT_BYTES,
        f"{label} descriptor must be a bounded owned 0600 regular file",
    )
    raw = os.pread(fd, info.st_size + 1, 0)
    after = os.fstat(fd)
    require(
        len(raw) == info.st_size
        and (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
        f"{label} descriptor changed or read incomplete",
    )
    return raw


def parse_private_env_descriptor(fd: int, label: str, expected_keys: tuple[str, ...]) -> dict[str, bytes]:
    raw = _descriptor_bytes(fd, label)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MaterializationError(f"{label} must be UTF-8") from exc
    values: dict[str, bytes] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        require("=" in line, f"{label} line {line_number} has no assignment")
        key, value = line.split("=", 1)
        require(KEY.fullmatch(key) is not None, f"{label} line {line_number} key invalid")
        require(key not in values, f"{label} contains a duplicate key")
        require(value != "" and "\x00" not in value, f"{label} contains an empty or invalid value")
        values[key] = value.encode("utf-8")
    require(set(values) == set(expected_keys), f"{label} keyset differs from protected policy")
    return {key: values[key] for key in expected_keys}


def _secret_template() -> str:
    return (
        '{{.metadata.uid}}{{"\\n"}}{{.metadata.resourceVersion}}{{"\\n"}}'
        '{{index .metadata.annotations "' + NONCE_ANNOTATION + '"}}{{"\\n"}}'
        '{{.type}}{{"\\n"}}{{range $k,$v := .data}}{{$k}}{{"\\n"}}{{end}}'
    )


def _not_found(result: Any) -> bool:
    combined = (result.out + "\n" + result.err).lower()
    return result.code != 0 and re.search(r"error from server \(\s*notfound\s*\)", combined) is not None


def _already_exists(result: Any) -> bool:
    combined = (result.out + "\n" + result.err).lower()
    return result.code != 0 and ("alreadyexists" in combined or re.search(r"\b409\b", combined) is not None)


def parse_secret_projection(raw: str, reference: dict[str, Any], label: str) -> dict[str, Any]:
    lines = raw.splitlines()
    require(len(lines) >= 4, f"{label} projection metadata absent")
    uid, resource_version, nonce, secret_type, *keys = lines
    require(UID.fullmatch(uid) is not None, f"{label} UID invalid")
    require(resource_version.isdigit(), f"{label} resourceVersion invalid")
    require(re.fullmatch(r"[0-9a-f]{64}", nonce) is not None, f"{label} ownership nonce invalid")
    require(secret_type == "Opaque", f"{label} type drift")
    require(sorted(keys) == sorted(reference["keys"]), f"{label} keyset drift")
    return {
        "target": _target("Secret", reference["name"], reference["namespace"]),
        "uid": uid,
        "resourceVersion": resource_version,
        "keySet": sorted(keys),
        "ownershipNonce": nonce,
        "valuesRead": False,
    }


def secret_projection(runner: Any, kubeconfig: str, reference: dict[str, Any], label: str) -> dict[str, Any] | None:
    result = runner.run(
        [
            "kubectl", "--kubeconfig", kubeconfig, "-n", reference["namespace"],
            "get", "secret", reference["name"], "-o", f"go-template={_secret_template()}",
        ]
    )
    if _not_found(result):
        return None
    require(result.code == 0, f"{label} projection read failed")
    return parse_secret_projection(result.out, reference, label)


def _secret_manifest(reference: dict[str, Any], values: dict[str, bytes], nonce: str) -> dict[str, Any]:
    require(set(values) == set(reference["keys"]), "internal Secret value keyset drift")
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "annotations": {NONCE_ANNOTATION: nonce},
            "labels": {
                "app.kubernetes.io/component": "staging-participant-gateway",
                "app.kubernetes.io/part-of": "stadtstack",
                "stadtstack.io/authority": "none",
                "stadtstack.io/civic-authority": "none",
                "stadtstack.io/environment": "staging",
                "stadtstack.io/secret-owner": "participant-secret-materializer",
            },
            "name": reference["name"],
            "namespace": reference["namespace"],
        },
        "type": "Opaque",
        "data": {key: base64.b64encode(values[key]).decode("ascii") for key in reference["keys"]},
    }


def create_secret(
    runner: Any,
    kubeconfig: str,
    label: str,
    reference: dict[str, Any],
    values: dict[str, bytes],
    nonce: str,
) -> dict[str, Any]:
    manifest = _secret_manifest(reference, values, nonce)
    result = runner.run(
        [
            "kubectl", "--kubeconfig", kubeconfig, "-n", reference["namespace"],
            "create", "-f", "-", "-o", f"go-template={_secret_template()}",
        ],
        input_text=canonical(manifest),
        timeout=30,
    )
    if _already_exists(result):
        raise MaterializationError(f"Secret {label} create conflict; adoption forbidden")
    observed: dict[str, Any] | None = None
    if result.code == 0:
        try:
            observed = parse_secret_projection(result.out, reference, f"created Secret {label}")
        except MaterializationError:
            observed = None
    if observed is None:
        discovered = secret_projection(runner, kubeconfig, reference, f"uncertain Secret {label}")
        if discovered is None or discovered["ownershipNonce"] != nonce:
            raise PostSendUncertainError(f"Secret {label} post-send create outcome unresolved")
        observed = discovered
    require(observed["ownershipNonce"] == nonce, f"Secret {label} ownership nonce drift")
    return observed


def _raw_delete_secret(snapshot: Any, reference: dict[str, Any], uid: str, resource_version: str, timeout: int = 15) -> None:
    require(reference in expected_secret_references().values(), "Secret delete reference outside closed policy")
    payload_value = {
        "apiVersion": "v1",
        "kind": "DeleteOptions",
        "preconditions": {"uid": uid, "resourceVersion": resource_version},
    }
    payload = canonical(payload_value)
    resource_path = f"/api/v1/namespaces/{reference['namespace']}/secrets/{reference['name']}"
    allowed_paths = {
        f"/api/v1/namespaces/{NAMESPACE}/secrets/{CONFIG_NAME}",
        f"/api/v1/namespaces/{NAMESPACE}/secrets/{RUNTIME_NAME}",
    }
    require(resource_path in allowed_paths, "Secret delete path outside closed policy")
    context = ssl.create_default_context(cadata=snapshot.ca_pem.decode("ascii"))
    if snapshot.client_certificate_path is not None or snapshot.client_key_path is not None:
        require(snapshot.client_certificate_path is not None and snapshot.client_key_path is not None, "Kubernetes client certificate snapshot incomplete")
        context.load_cert_chain(str(snapshot.client_certificate_path), str(snapshot.client_key_path))
    raw = CORE._api_tcp_transport_v4(snapshot, timeout)
    secured: ssl.SSLSocket | None = None
    try:
        secured = context.wrap_socket(raw, server_hostname=snapshot.tls_server_name)
        host = f"[{snapshot.hostname}]" if ":" in snapshot.hostname else snapshot.hostname
        authority = host if snapshot.port == 443 else f"{host}:{snapshot.port}"
        body = payload.encode("ascii")
        headers = [
            f"DELETE {resource_path} HTTP/1.1",
            f"Host: {authority}",
            "Accept: application/json",
            "Content-Type: application/json",
            f"Content-Length: {len(body)}",
            "Connection: close",
        ]
        if snapshot.bearer_token is not None:
            headers.append(f"Authorization: Bearer {snapshot.bearer_token}")
        secured.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body)
        response = http.client.HTTPResponse(secured)
        response.begin()
        response_body = response.read(1024 * 1024 + 1)
        require(len(response_body) <= 1024 * 1024, "Kubernetes Secret DELETE response exceeds 1 MiB")
        require(200 <= response.status < 300 or response.status == 404, f"Kubernetes Secret DELETE rejected: HTTP {response.status}")
    finally:
        if secured is not None:
            try:
                secured.close()
            except OSError:
                pass
        else:
            try:
                raw.close()
            except OSError:
                pass


def delete_owned_secret(
    runner: Any,
    kubeconfig: str,
    snapshot: Any,
    label: str,
    reference: dict[str, Any],
    ownership: dict[str, Any],
) -> dict[str, Any]:
    current = secret_projection(runner, kubeconfig, reference, f"teardown Secret {label}")
    if current is None:
        return {"target": _target("Secret", reference["name"], reference["namespace"]), "absent": True, "alreadyAbsent": True}
    for key in ("target", "uid", "resourceVersion", "keySet", "ownershipNonce"):
        require(current.get(key) == ownership.get(key), f"Secret {label} teardown ownership {key} drift")
    _raw_delete_secret(snapshot, reference, current["uid"], current["resourceVersion"])
    require(secret_projection(runner, kubeconfig, reference, f"deleted Secret {label}") is None, f"Secret {label} remains after delete")
    return {
        "target": current["target"],
        "uid": current["uid"],
        "deleteResourceVersion": current["resourceVersion"],
        "absent": True,
        "alreadyAbsent": False,
    }


def _kind_cli(kind: str) -> str:
    return {
        "NetworkPolicy": "networkpolicy.networking.k8s.io",
        "ServiceAccount": "serviceaccount",
        "Service": "service",
        "Deployment": "deployment.apps",
        "Ingress": "ingress.networking.k8s.io",
        "Kustomization": "kustomization.kustomize.toolkit.fluxcd.io",
    }[kind]


def require_deactivated(runner: Any, kubeconfig: str, policy: dict[str, Any]) -> list[dict[str, Any]]:
    targets = policy["runtime"]["secretMaterializer"]["teardown"]["requiredAbsentTargets"]
    checked: list[dict[str, Any]] = []
    for target in targets:
        result = runner.run([
            "kubectl", "--kubeconfig", kubeconfig, "-n", target["namespace"], "get",
            _kind_cli(target["kind"]), target["name"], "-o", "name",
        ])
        require(_not_found(result), f"participant Secret teardown blocked until {target['kind']}/{target['name']} is absent")
        checked.append(copy.deepcopy(target) | {"absent": True})
    return checked


def _materialization_unsigned(
    rev: str,
    policy: dict[str, Any],
    runner_hashes: dict[str, str],
    created: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schemaVersion": MATERIALIZATION_RECEIPT_SCHEMA,
        "status": "materialized",
        "protectedRevision": rev,
        "activationPolicySha256": POLICY.activation_policy_sha256(policy),
        "protectedRunnerFileSha256": runner_hashes,
        "createOrder": list(CREATE_ORDER),
        "secrets": {label: copy.deepcopy(created[label]) for label in CREATE_ORDER},
        "inputTransport": "owned-private-inherited-descriptors-only",
        "valuesInReceipt": False,
        "civicAuthorityEffects": False,
    }


def bind_materialization_receipt(
    receipt: dict[str, Any],
    policy: dict[str, Any],
    rev: str,
    runner_hashes: dict[str, str],
) -> dict[str, Any]:
    require(isinstance(receipt, dict), "Secret materialization receipt must be an object")
    checksum = receipt.get("canonicalSha256")
    require(isinstance(checksum, str) and SHA256.fullmatch(checksum) is not None, "Secret materialization receipt checksum invalid")
    unsigned = {key: copy.deepcopy(value) for key, value in receipt.items() if key != "canonicalSha256"}
    require(digest(unsigned) == checksum, "Secret materialization receipt checksum mismatch")
    require(
        set(unsigned) == {
            "schemaVersion", "status", "protectedRevision", "activationPolicySha256",
            "protectedRunnerFileSha256", "createOrder", "secrets", "inputTransport",
            "valuesInReceipt", "civicAuthorityEffects",
        }
        and unsigned["schemaVersion"] == MATERIALIZATION_RECEIPT_SCHEMA
        and unsigned["status"] == "materialized"
        and unsigned["protectedRevision"] == rev
        and unsigned["activationPolicySha256"] == POLICY.activation_policy_sha256(policy)
        and unsigned["protectedRunnerFileSha256"] == runner_hashes
        and unsigned["createOrder"] == list(CREATE_ORDER)
        and unsigned["inputTransport"] == "owned-private-inherited-descriptors-only"
        and unsigned["valuesInReceipt"] is False
        and unsigned["civicAuthorityEffects"] is False,
        "Secret materialization receipt field or identity drift",
    )
    require(isinstance(unsigned["secrets"], dict) and set(unsigned["secrets"]) == set(CREATE_ORDER), "Secret materialization receipt inventory drift")
    refs = policy["runtime"]["secretReferences"]
    for label in CREATE_ORDER:
        record = unsigned["secrets"][label]
        require(isinstance(record, dict) and set(record) == {"target", "uid", "resourceVersion", "keySet", "ownershipNonce", "valuesRead"}, f"Secret {label} receipt field drift")
        require(record["target"] == _target("Secret", refs[label]["name"], refs[label]["namespace"]), f"Secret {label} receipt target drift")
        require(isinstance(record["uid"], str) and UID.fullmatch(record["uid"]) is not None and isinstance(record["resourceVersion"], str) and record["resourceVersion"].isdigit(), f"Secret {label} receipt identity invalid")
        require(record["keySet"] == sorted(refs[label]["keys"]), f"Secret {label} receipt keyset drift")
        require(re.fullmatch(r"[0-9a-f]{64}", record["ownershipNonce"]) is not None and record["valuesRead"] is False, f"Secret {label} receipt ownership drift")
    return {
        "status": "materialized",
        "protectedRevision": rev,
        "receiptSha256": checksum,
        "secretUids": {label: unsigned["secrets"][label]["uid"] for label in CREATE_ORDER},
        # Value-free records let a later activation continuation perform a
        # fresh UID/key-set/resourceVersion check without rereading or
        # rematerializing any Secret value.
        "secretRecords": {
            label: {
                "target": copy.deepcopy(unsigned["secrets"][label]["target"]),
                "uid": unsigned["secrets"][label]["uid"],
                "resourceVersion": unsigned["secrets"][label]["resourceVersion"],
                "keySet": copy.deepcopy(unsigned["secrets"][label]["keySet"]),
                "valuesRead": False,
            }
            for label in CREATE_ORDER
        },
        "civicAuthorityEffects": False,
    }


def bind_teardown_receipt(
    receipt: dict[str, Any],
    policy: dict[str, Any],
    rev: str,
    runner_hashes: dict[str, str],
) -> dict[str, Any]:
    require(isinstance(receipt, dict), "Secret teardown receipt must be an object")
    checksum = receipt.get("canonicalSha256")
    require(isinstance(checksum, str) and digest({key: copy.deepcopy(value) for key, value in receipt.items() if key != "canonicalSha256"}) == checksum, "Secret teardown receipt checksum mismatch")
    require(
        set(receipt) == {
            "schemaVersion", "status", "protectedRevision", "activationPolicySha256",
            "protectedRunnerFileSha256", "sourceMaterializationReceiptSha256",
            "deactivationPreconditions", "deleteOrder", "deleted", "valuesRead",
            "civicAuthorityEffects", "canonicalSha256",
        }
        and receipt.get("activationPolicySha256") == POLICY.activation_policy_sha256(policy)
        and receipt.get("schemaVersion") == TEARDOWN_RECEIPT_SCHEMA
        and receipt.get("status") == "torn-down"
        and receipt.get("protectedRevision") == rev
        and receipt.get("protectedRunnerFileSha256") == runner_hashes
        and receipt.get("deleteOrder") == list(DELETE_ORDER)
        and receipt.get("valuesRead") is False
        and receipt.get("civicAuthorityEffects") is False,
        "Secret teardown receipt field or identity drift",
    )
    require(isinstance(receipt.get("sourceMaterializationReceiptSha256"), str) and SHA256.fullmatch(receipt["sourceMaterializationReceiptSha256"]) is not None, "Secret teardown source receipt binding invalid")
    deleted = receipt.get("deleted")
    require(isinstance(deleted, list) and len(deleted) == len(DELETE_ORDER), "Secret teardown delete receipt drift")
    refs = policy["runtime"]["secretReferences"]
    for label, record in zip(DELETE_ORDER, deleted, strict=True):
        expected_target = _target("Secret", refs[label]["name"], refs[label]["namespace"])
        require(isinstance(record, dict) and record.get("target") == expected_target, f"Secret {label} teardown receipt target drift")
        if record.get("alreadyAbsent") is True:
            require(
                set(record) == {"target", "absent", "alreadyAbsent"}
                and record.get("absent") is True,
                f"Secret {label} already-absent receipt field drift",
            )
        else:
            require(
                set(record) == {"target", "uid", "deleteResourceVersion", "absent", "alreadyAbsent"}
                and record.get("alreadyAbsent") is False
                and record.get("absent") is True
                and isinstance(record.get("uid"), str)
                and UID.fullmatch(record["uid"]) is not None
                and isinstance(record.get("deleteResourceVersion"), str)
                and record["deleteResourceVersion"].isdigit(),
                f"Secret {label} deleted receipt identity drift",
            )
    require(
        receipt.get("deactivationPreconditions")
        == [copy.deepcopy(target) | {"absent": True} for target in policy["runtime"]["secretMaterializer"]["teardown"]["requiredAbsentTargets"]],
        "Secret teardown deactivation preconditions drift",
    )
    return {
        "status": "torn-down",
        "protectedRevision": rev,
        "receiptSha256": checksum,
        "teardownOfReceiptSha256": receipt["sourceMaterializationReceiptSha256"],
        "civicAuthorityEffects": False,
    }


def materialize(
    policy: dict[str, Any],
    rev: str,
    kubeconfig: str,
    config_values: dict[str, bytes],
    runtime_values: dict[str, bytes],
    sink: Any,
    runner_hashes: dict[str, str],
    runner: Any | None = None,
) -> dict[str, Any]:
    active_runner = CORE.Runner() if runner is None else runner
    snapshot = None
    signal_handlers: dict[int, Any] | None = None
    created: dict[str, dict[str, Any]] = {}
    unresolved_create_outcomes: list[str] = []
    refs = policy["runtime"]["secretReferences"]
    try:
        signal_handlers = CORE.install_transaction_signal_handlers_v4()
        snapshot = CORE.snapshot_kubeconfig_v4(kubeconfig, active_runner)
        for label in CREATE_ORDER:
            require(secret_projection(active_runner, str(snapshot.path), refs[label], f"preflight Secret {label}") is None, f"Secret {label} already exists; adoption forbidden")
        value_sets = {"config": config_values, "runtime": runtime_values}
        for label in CREATE_ORDER:
            nonce = secrets.token_hex(32)
            try:
                created[label] = create_secret(active_runner, str(snapshot.path), label, refs[label], value_sets[label], nonce)
            except PostSendUncertainError:
                unresolved_create_outcomes.append(label)
                raise
            confirmed = secret_projection(active_runner, str(snapshot.path), refs[label], f"confirmed Secret {label}")
            require(confirmed == created[label], f"Secret {label} changed after create")
        success = _materialization_unsigned(rev, policy, runner_hashes, created)
        CORE.defer_transaction_signals_v4()
        sink.commit(success)
        return success
    except BaseException as exc:
        if signal_handlers is not None:
            CORE.defer_transaction_signals_v4()
        rollback: list[dict[str, Any]] = []
        rollback_errors: list[dict[str, str]] = [
            {"secret": label, "failureType": "PostSendUncertainError"}
            for label in unresolved_create_outcomes
        ]
        if snapshot is not None:
            for label in DELETE_ORDER:
                if label not in created:
                    continue
                try:
                    rollback.append(delete_owned_secret(active_runner, str(snapshot.path), snapshot, label, refs[label], created[label]))
                except BaseException as rollback_error:
                    rollback_errors.append({"secret": label, "failureType": type(rollback_error).__name__})
        failure = {
            "schemaVersion": MATERIALIZATION_RECEIPT_SCHEMA,
            "status": "rolled-back" if not rollback_errors else "rollback-incomplete",
            "protectedRevision": rev,
            "activationPolicySha256": POLICY.activation_policy_sha256(policy),
            "protectedRunnerFileSha256": runner_hashes,
            "failureType": type(exc).__name__,
            "created": {label: copy.deepcopy(value) for label, value in created.items()},
            "unresolvedCreateOutcomes": list(unresolved_create_outcomes),
            "rollback": rollback,
            "rollbackErrors": rollback_errors,
            "valuesInReceipt": False,
            "civicAuthorityEffects": False,
        }
        sink.commit(failure)
        raise MaterializationError(f"Secret materialization {failure['status']}: {type(exc).__name__}") from exc
    finally:
        if snapshot is not None:
            snapshot.close()
        if signal_handlers is not None:
            CORE.restore_transaction_signal_handlers_v4(signal_handlers)


def teardown(
    policy: dict[str, Any],
    rev: str,
    kubeconfig: str,
    source_receipt: dict[str, Any],
    sink: Any,
    runner_hashes: dict[str, str],
    runner: Any | None = None,
) -> dict[str, Any]:
    projection = bind_materialization_receipt(source_receipt, policy, rev, runner_hashes)
    active_runner = CORE.Runner() if runner is None else runner
    snapshot = None
    signal_handlers: dict[int, Any] | None = None
    deleted: list[dict[str, Any]] = []
    refs = policy["runtime"]["secretReferences"]
    try:
        signal_handlers = CORE.install_transaction_signal_handlers_v4()
        snapshot = CORE.snapshot_kubeconfig_v4(kubeconfig, active_runner)
        absent = require_deactivated(active_runner, str(snapshot.path), policy)
        for label in DELETE_ORDER:
            deleted.append(delete_owned_secret(active_runner, str(snapshot.path), snapshot, label, refs[label], source_receipt["secrets"][label]))
        require(
            require_deactivated(active_runner, str(snapshot.path), policy) == absent,
            "participant deactivation boundary changed during Secret teardown",
        )
        success = {
            "schemaVersion": TEARDOWN_RECEIPT_SCHEMA,
            "status": "torn-down",
            "protectedRevision": rev,
            "activationPolicySha256": POLICY.activation_policy_sha256(policy),
            "protectedRunnerFileSha256": runner_hashes,
            "sourceMaterializationReceiptSha256": projection["receiptSha256"],
            "deactivationPreconditions": absent,
            "deleteOrder": list(DELETE_ORDER),
            "deleted": deleted,
            "valuesRead": False,
            "civicAuthorityEffects": False,
        }
        CORE.defer_transaction_signals_v4()
        sink.commit(success)
        return success
    except BaseException as exc:
        if signal_handlers is not None:
            CORE.defer_transaction_signals_v4()
        failure = {
            "schemaVersion": TEARDOWN_RECEIPT_SCHEMA,
            "status": "teardown-incomplete",
            "protectedRevision": rev,
            "protectedRunnerFileSha256": runner_hashes,
            "sourceMaterializationReceiptSha256": projection["receiptSha256"],
            "failureType": type(exc).__name__,
            "deleted": deleted,
            "valuesRead": False,
            "civicAuthorityEffects": False,
        }
        sink.commit(failure)
        raise MaterializationError(f"Secret teardown incomplete: {type(exc).__name__}") from exc
    finally:
        if snapshot is not None:
            snapshot.close()
        if signal_handlers is not None:
            CORE.restore_transaction_signal_handlers_v4(signal_handlers)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-protected-revision", required=True)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--materialize", action="store_true")
    modes.add_argument("--teardown", action="store_true")
    modes.add_argument("--verify-materialization-receipt-fd", type=int)
    modes.add_argument("--verify-teardown-receipt-fd", type=int)
    parser.add_argument("--kubeconfig")
    parser.add_argument("--config-input-fd", type=int)
    parser.add_argument("--runtime-input-fd", type=int)
    parser.add_argument("--source-materialization-receipt-fd", type=int)
    parser.add_argument("--receipt", type=Path, default=Path("participant-secret-materialization-receipt.json"))
    args = parser.parse_args(argv)
    if args.materialize:
        require(args.kubeconfig is not None and args.config_input_fd is not None and args.runtime_input_fd is not None, "materialization requires kubeconfig and both private input descriptors")
        require(args.source_materialization_receipt_fd is None, "materialization accepts no source receipt")
    elif args.teardown:
        require(args.kubeconfig is not None and args.source_materialization_receipt_fd is not None, "teardown requires kubeconfig and source materialization receipt descriptor")
        require(args.config_input_fd is None and args.runtime_input_fd is None, "teardown accepts no Secret input descriptors")
    else:
        require(args.kubeconfig is None and args.config_input_fd is None and args.runtime_input_fd is None and args.source_materialization_receipt_fd is None, "receipt verification accepts no kubeconfig or Secret inputs")
    return args


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        require(sys.flags.isolated == 1 and bool(sys.flags.safe_path), "runner requires python3 -I isolated safe-path mode")
        os.environ.pop("PYTHONPATH", None)
        rev = revision(args.expected_protected_revision)
        runner_hashes, policy = load_protected_runtime(rev)
        if args.verify_materialization_receipt_fd is not None:
            receipt = CORE.load_owned_receipt_fd_v4(args.verify_materialization_receipt_fd, "Secret materialization receipt")
            print(canonical(bind_materialization_receipt(receipt, policy, rev, runner_hashes)))
            return 0
        if args.verify_teardown_receipt_fd is not None:
            receipt = CORE.load_owned_receipt_fd_v4(args.verify_teardown_receipt_fd, "Secret teardown receipt")
            print(canonical(bind_teardown_receipt(receipt, policy, rev, runner_hashes)))
            return 0
        sink = CORE.ReceiptSink.reserve(args.receipt)
        if args.materialize:
            config_values = parse_private_env_descriptor(args.config_input_fd, "participant config input", CONFIG_KEYS)
            runtime_values = parse_private_env_descriptor(args.runtime_input_fd, "participant runtime input", RUNTIME_KEYS)
            result = materialize(policy, rev, args.kubeconfig, config_values, runtime_values, sink, runner_hashes)
        else:
            source = CORE.load_owned_receipt_fd_v4(args.source_materialization_receipt_fd, "Secret materialization receipt")
            result = teardown(policy, rev, args.kubeconfig, source, sink, runner_hashes)
        print(canonical(result))
        return 0
    except (MaterializationError, OSError, json.JSONDecodeError) as exc:
        print(f"participant Secret materializer blocked: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
