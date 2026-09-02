#!/usr/bin/env python3
"""Create-only materializer for the Röbel staging eligibility issuer Secret."""

from __future__ import annotations

import sys as _bootstrap_sys

if __name__ == "__main__" and not (
    _bootstrap_sys.flags.isolated and _bootstrap_sys.flags.safe_path
):
    print(
        "eligibility issuer materializer blocked: invoke with python3 -I",
        file=_bootstrap_sys.stderr,
    )
    raise SystemExit(2)

import argparse
import base64
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
SELF_PATH = "scripts/materialize-staging-participant-eligibility-issuer.py"
POLICY_PATH = "policy/staging-participant-eligibility-issuer-materialization-policy.json"
CORE_RUNNER_PATH = "scripts/activate-staging-participant-gateway.py"
PROTECTED_PATHS = (SELF_PATH, POLICY_PATH, CORE_RUNNER_PATH)
POLICY_SCHEMA = "roebel_staging_participant_eligibility_issuer_materialization_policy_v2"
RECEIPT_SCHEMA = (
    "roebel_staging_participant_eligibility_issuer_materialization_receipt_v1"
)
JOURNAL_SCHEMA = (
    "roebel_staging_participant_eligibility_issuer_materialization_journal_v1"
)
NAMESPACE = "stadtstack-roebel-web-preview"
SECRET_NAME = "roebel-staging-participant-gateway-eligibility-issuer"
SECRET_KEY = "private-key-hex"
KEY_ID = "roebel-staging-citizen-eligibility-2026-09"
EXPECTED_PUBLIC_KEY = "376c539caae987f6b764aa1c74ba52869058fab421495459a8e6e8274d6270a8"
EXPECTED_PRIVATE_KEY_COMMITMENT = (
    "sha256:416aa283ad44c8b58915f0a855f33af3289ffc844baf32b89dd1d94e2c917dbc"
)
KEY_ID_ANNOTATION = "stadtstack.io/eligibility-issuer-key-id"
PUBLIC_KEY_ANNOTATION = "stadtstack.io/eligibility-issuer-public-key"
NONCE_ANNOTATION = "stadtstack.io/eligibility-issuer-materialization-nonce"
CONTENT_CONTRACT_ANNOTATION = (
    "stadtstack.io/eligibility-issuer-content-contract-sha256"
)
KEYSET_ANNOTATION = "stadtstack.io/eligibility-issuer-keyset-sha256"
PARTIAL_OBJECT_METADATA_ACCEPT = (
    "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1"
)
SECRET_API_PATH = (
    "/api/v1/namespaces/stadtstack-roebel-web-preview/secrets/"
    "roebel-staging-participant-gateway-eligibility-issuer"
)
MAX_METADATA_RESPONSE_BYTES = 256 * 1024
GIT_BIN = Path("/usr/bin/git")


class MaterializationError(RuntimeError):
    """Raised when the closed issuer materialization boundary is not proven."""


class ExistingObjectError(MaterializationError):
    """Raised when create-only semantics prove that the target pre-existed."""


class AtomicallyPublishedReceipt(MaterializationError):
    """Signals that the reserved empty inode became a complete staged inode."""


_FIELD = 2**255 - 19
_D = (-121665 * pow(121666, _FIELD - 2, _FIELD)) % _FIELD
_BASE_Y = (4 * pow(5, _FIELD - 2, _FIELD)) % _FIELD


def _recover_x(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _FIELD - 2, _FIELD) % _FIELD
    x = pow(xx, (_FIELD + 3) // 8, _FIELD)
    if (x * x - xx) % _FIELD:
        x = x * pow(2, (_FIELD - 1) // 4, _FIELD) % _FIELD
    if x & 1:
        x = _FIELD - x
    return x


_BASE = (_recover_x(_BASE_Y), _BASE_Y)
_IDENTITY = (0, 1)
_PRIVATE_KEY_HEX = re.compile(rb"^[0-9a-f]{64}$")
_PUBLIC_KEY_HEX = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_NONCE = re.compile(r"^[0-9a-f]{64}$")
_UID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

SECRET_LABELS = {
    "app.kubernetes.io/component": "staging-participant-gateway",
    "app.kubernetes.io/part-of": "stadtstack",
    "stadtstack.io/authority": "none",
    "stadtstack.io/civic-authority": "none",
    "stadtstack.io/environment": "staging",
    "stadtstack.io/secret-owner": "eligibility-issuer-materializer",
}
CLUSTER_IDENTITY_KEYS = (
    "apiOrigin",
    "caCertificateSha256",
    "apiServerSpkiSha256",
    "kubeSystemNamespaceUid",
)


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


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


def _trusted_git(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[Any]:
    info = os.lstat(GIT_BIN)
    if not (
        stat.S_ISREG(info.st_mode)
        and not GIT_BIN.is_symlink()
        and info.st_uid == 0
        and stat.S_IMODE(info.st_mode) & 0o022 == 0
        and os.access(GIT_BIN, os.X_OK)
    ):
        raise MaterializationError("trusted Git executable metadata invalid")
    return subprocess.run(
        [str(GIT_BIN), "--no-replace-objects", *args],
        env=_git_environment(),
        **kwargs,
    )


def _git_blob(revision: str, path: str) -> bytes:
    result = _trusted_git(
        ["-C", str(ROOT), "show", f"{revision}:{path}"],
        capture_output=True,
        check=False,
        timeout=10,
    )
    if result.returncode != 0:
        raise MaterializationError(f"protected Git blob unavailable: {path}")
    return result.stdout


def bind_protected_checkout(
    revision: str,
) -> tuple[dict[str, str], dict[str, bytes]]:
    if _REVISION.fullmatch(revision) is None:
        raise MaterializationError("expected protected revision must be 40 lowercase hex")
    head = _trusted_git(
        ["-C", str(ROOT), "rev-parse", "HEAD"],
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )
    if head.returncode != 0 or head.stdout.strip() != revision:
        raise MaterializationError("checkout is not the expected protected revision")
    blobs: dict[str, bytes] = {}
    hashes: dict[str, str] = {}
    for path in PROTECTED_PATHS:
        local = ROOT / path
        info = os.lstat(local)
        expected = _git_blob(revision, path)
        if not (
            stat.S_ISREG(info.st_mode)
            and not local.is_symlink()
            and local.read_bytes() == expected
        ):
            raise MaterializationError(f"protected file differs from exact Git blob: {path}")
        blobs[path] = expected
        hashes[path] = sha256(expected)
    return dict(sorted(hashes.items())), blobs


def _compile_core(source: bytes, revision: str) -> Any:
    name = f"eligibility_issuer_materializer_core_{revision}"
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / CORE_RUNNER_PATH)
    module.__package__ = ""
    sys.modules[name] = module
    try:
        exec(
            compile(source, module.__file__, "exec", dont_inherit=True),
            module.__dict__,
        )
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def load_protected_runtime(
    revision: str,
) -> tuple[Any, dict[str, Any], dict[str, str]]:
    hashes, blobs = bind_protected_checkout(revision)
    core = _compile_core(blobs[CORE_RUNNER_PATH], revision)
    return core, load_policy(blobs[POLICY_PATH]), hashes


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MaterializationError("issuer policy contains a duplicate JSON key")
        result[key] = value
    return result


def load_policy(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise MaterializationError("issuer policy is not exact JSON") from exc
    expected = {
        "schemaVersion": POLICY_SCHEMA,
        "authority": {
            "environment": "staging",
            "civicAuthority": "none",
            "citizenVerification": False,
            "municipalPublication": False,
            "proposalMutation": False,
            "voteMutation": False,
            "treasuryMutation": False,
        },
        "algorithm": "Ed25519",
        "keyId": KEY_ID,
        "clusterIdentity": {
            "apiOrigin": "https://10.255.240.11:6443",
            "caCertificateSha256": "sha256:42fd39869882e3c25a1f37c090542d215ceb0f60a7d68f5603fb9a0583afee28",
            "apiServerSpkiSha256": "sha256:1507430795ee7c9cbeea9133dd3b1a809a500de5bcc4dd8e400163ac9471186a",
            "kubeSystemNamespaceUid": "7bc769bc-e860-4d54-a0d5-d426f3a52420",
        },
        "httpBoundary": {"timeoutsSeconds": {"routeRequest": 15}},
        "target": {
            "apiVersion": "v1",
            "kind": "Secret",
            "namespace": NAMESPACE,
            "name": SECRET_NAME,
            "type": "Opaque",
            "key": SECRET_KEY,
            "immutable": True,
        },
        "input": {
            "transport": "owned-private-inherited-descriptor-only",
            "encoding": "exact-lowercase-64-hex-no-newline",
            "decodedBytes": 32,
            "sha256Commitment": EXPECTED_PRIVATE_KEY_COMMITMENT,
        },
        "publicKey": {
            "derivation": "RFC8032-Ed25519-private-seed-to-public-key",
            "encoding": "lowercase-64-hex",
            "expected": EXPECTED_PUBLIC_KEY,
        },
        "materialization": {
            "operation": "create-only",
            "initialState": "exact-target-absent",
            "existingObject": "reject-no-adopt-no-recreate",
            "operationNonceAnnotation": NONCE_ANNOTATION,
            "dryRun": "server-before-create",
            "readSecretValues": False,
            "metadataOnlyRead": {
                "representation": "PartialObjectMetadata",
                "accept": PARTIAL_OBJECT_METADATA_ACCEPT,
                "apiPath": SECRET_API_PATH,
            },
            "metadataCommitments": {
                "contentContractAnnotation": CONTENT_CONTRACT_ANNOTATION,
                "contentContractFields": [
                    "target",
                    "input.sha256Commitment",
                    "keyId",
                    "publicKey.expected",
                ],
                "keySetAnnotation": KEYSET_ANNOTATION,
                "keySet": [SECRET_KEY],
            },
            "delete": False,
            "patch": False,
            "replace": False,
            "durableJournal": {
                "schemaVersion": JOURNAL_SCHEMA,
                "reservation": "durable-before-create",
                "recovery": "same-protected-journal-and-operation-nonce-only",
                "postSendUncertain": "exact-live-projection-same-operation-nonce-only",
                "genericAdoption": False,
            },
        },
        "receipt": {
            "schemaVersion": RECEIPT_SCHEMA,
            "status": "materialized",
            "requiredFields": [
                "schemaVersion",
                "status",
                "protectedRevision",
                "protectedFileSha256",
                "policy",
                "clusterBinding",
                "target",
                "uid",
                "resourceVersion",
                "operationNonce",
                "keyId",
                "publicKey",
                "privateKeyCommitmentSha256",
                "keySet",
                "labels",
                "annotations",
                "createOutcome",
                "valuesRead",
                "receiptContainsValues",
                "authority",
            ],
            "verifyMode": "owned-private-inherited-descriptor",
            "containsPrivateKey": False,
            "containsSecretValue": False,
        },
    }
    if value != expected:
        raise MaterializationError("issuer materialization policy drift")
    return value


def _add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    product = _D * x1 * x2 * y1 * y2
    return (
        (x1 * y2 + x2 * y1) * pow(1 + product, _FIELD - 2, _FIELD) % _FIELD,
        (y1 * y2 + x1 * x2) * pow(1 - product, _FIELD - 2, _FIELD) % _FIELD,
    )


def _scalar_multiply(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    result = _IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        scalar >>= 1
    return result


def ed25519_public_key(private_seed: bytes) -> bytes:
    """Derive the RFC 8032 public key from a 32-byte Ed25519 private seed."""
    if not isinstance(private_seed, bytes) or len(private_seed) != 32:
        raise MaterializationError("issuer private key must decode to exactly 32 bytes")
    expanded = bytearray(hashlib.sha512(private_seed).digest())
    scalar = int.from_bytes(expanded[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    x, y = _scalar_multiply(_BASE, scalar)
    encoded = y | ((x & 1) << 255)
    return encoded.to_bytes(32, "little")


def read_private_key_fd(fd: int) -> bytes:
    """Read one exact Ed25519 seed from an inherited private descriptor."""
    if not isinstance(fd, int) or fd < 3:
        raise MaterializationError("issuer private-key descriptor invalid")
    try:
        os.set_inheritable(fd, False)
        info = os.fstat(fd)
        if not (
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.geteuid()
            and info.st_nlink in {0, 1}
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_size == 64
        ):
            raise MaterializationError(
                "issuer private-key descriptor must be an owned 0600 regular file of exactly 64 bytes"
            )
        raw = os.pread(fd, 65, 0)
        after = os.fstat(fd)
        if not (
            len(raw) == 64
            and (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            and _PRIVATE_KEY_HEX.fullmatch(raw) is not None
        ):
            raise MaterializationError(
                "issuer private key must be exactly 64 lowercase hexadecimal characters"
            )
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    return bytes.fromhex(raw.decode("ascii"))


def canonical_private_key_hex(private_seed: bytes) -> bytes:
    if not isinstance(private_seed, bytes) or len(private_seed) != 32:
        raise MaterializationError("issuer private key must decode to exactly 32 bytes")
    return private_seed.hex().encode("ascii")


def private_key_commitment(private_seed: bytes) -> str:
    return sha256(canonical_private_key_hex(private_seed))


def content_contract_commitment() -> str:
    return sha256(
        canonical(
            {
                "target": {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "namespace": NAMESPACE,
                    "name": SECRET_NAME,
                    "type": "Opaque",
                    "key": SECRET_KEY,
                    "immutable": True,
                },
                "privateKeyCommitmentSha256": EXPECTED_PRIVATE_KEY_COMMITMENT,
                "keyId": KEY_ID,
                "publicKey": EXPECTED_PUBLIC_KEY,
            }
        ).encode("ascii")
    )


def keyset_commitment() -> str:
    return sha256(canonical([SECRET_KEY]).encode("ascii"))


def exact_secret_annotations(
    public_key: str, operation_nonce: str
) -> dict[str, str]:
    return {
        NONCE_ANNOTATION: operation_nonce,
        KEY_ID_ANNOTATION: KEY_ID,
        PUBLIC_KEY_ANNOTATION: public_key,
        CONTENT_CONTRACT_ANNOTATION: content_contract_commitment(),
        KEYSET_ANNOTATION: keyset_commitment(),
    }


def _projection_template(*, include_identity: bool) -> str:
    identity = (
        '{{.metadata.uid}}{{"\\n"}}'
        '{{.metadata.resourceVersion}}{{"\\n"}}'
        if include_identity
        else '{{"\\n"}}{{"\\n"}}'
    )
    labels = "".join(
        '{{index .metadata.labels "' + key + '"}}{{"\\n"}}'
        for key in sorted(SECRET_LABELS)
    )
    label_keys = '{{range $k,$v := .metadata.labels}}{{$k}}{{"\\n"}}{{end}}'
    annotations = "".join(
        '{{index .metadata.annotations "' + key + '"}}{{"\\n"}}'
        for key in sorted(
            {
                NONCE_ANNOTATION,
                KEY_ID_ANNOTATION,
                PUBLIC_KEY_ANNOTATION,
                CONTENT_CONTRACT_ANNOTATION,
                KEYSET_ANNOTATION,
            }
        )
    )
    annotation_keys = (
        '{{range $k,$v := .metadata.annotations}}{{$k}}{{"\\n"}}{{end}}'
    )
    return (
        identity
        + '{{.metadata.namespace}}{{"\\n"}}'
        '{{.metadata.name}}{{"\\n"}}'
        + labels
        + label_keys
        + annotations
        + annotation_keys
    )


def _manifest(
    private_seed: bytes, public_key: str, operation_nonce: str
) -> dict[str, Any]:
    if not (
        len(private_seed) == 32
        and _PUBLIC_KEY_HEX.fullmatch(public_key) is not None
        and _NONCE.fullmatch(operation_nonce) is not None
    ):
        raise MaterializationError("issuer key material shape invalid")
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": SECRET_NAME,
            "namespace": NAMESPACE,
            "annotations": exact_secret_annotations(public_key, operation_nonce),
            "labels": dict(SECRET_LABELS),
        },
        "type": "Opaque",
        "immutable": True,
        "data": {
            SECRET_KEY: base64.b64encode(
                canonical_private_key_hex(private_seed)
            ).decode("ascii")
        },
    }


def _already_exists(result: Any) -> bool:
    combined = f"{result.out}\n{result.err}".lower()
    return result.code != 0 and (
        "alreadyexists" in combined or re.search(r"\b409\b", combined) is not None
    )


def _parse_projection(
    raw: str,
    public_key: str,
    operation_nonce: str,
    label: str,
    *,
    require_identity: bool,
) -> dict[str, Any]:
    lines = raw.splitlines()
    expected_annotations = exact_secret_annotations(public_key, operation_nonce)
    expected_tail = [
        NAMESPACE,
        SECRET_NAME,
        *(SECRET_LABELS[key] for key in sorted(SECRET_LABELS)),
        *sorted(SECRET_LABELS),
        *(expected_annotations[key] for key in sorted(expected_annotations)),
        *sorted(expected_annotations),
    ]
    if len(lines) != 2 + len(expected_tail):
        raise MaterializationError(f"{label} exact target projection mismatch")
    uid, resource_version, *tail = lines
    if not (
        tail == expected_tail
        and (
            (not require_identity and uid == "" and resource_version == "")
            or (
                require_identity
                and _UID.fullmatch(uid) is not None
                and resource_version.isdigit()
            )
        )
    ):
        raise MaterializationError(f"{label} exact target projection mismatch")
    return {
        "target": {
            "apiVersion": "v1",
            "kind": "Secret",
            "namespace": NAMESPACE,
            "name": SECRET_NAME,
        },
        "uid": uid,
        "resourceVersion": resource_version,
        "operationNonce": operation_nonce,
        "type": "Opaque",
        "immutable": True,
        "keySet": [SECRET_KEY],
        "labels": dict(SECRET_LABELS),
        "annotations": expected_annotations,
        "valuesRead": False,
    }


def _kubectl(kubeconfig: str) -> list[str]:
    if not isinstance(kubeconfig, str) or not kubeconfig.startswith("/"):
        raise MaterializationError("private kubeconfig snapshot path invalid")
    return ["kubectl", "--kubeconfig", kubeconfig, "-n", NAMESPACE]


def _parse_partial_object_metadata(
    value: Any,
    public_key: str,
    operation_nonce: str,
) -> dict[str, Any] | None:
    expected_annotations = exact_secret_annotations(public_key, operation_nonce)
    metadata = value.get("metadata") if isinstance(value, dict) else None
    if not (
        isinstance(value, dict)
        and set(value) == {"apiVersion", "kind", "metadata"}
        and value.get("apiVersion") == "meta.k8s.io/v1"
        and value.get("kind") == "PartialObjectMetadata"
        and isinstance(metadata, dict)
        and metadata.get("namespace") == NAMESPACE
        and metadata.get("name") == SECRET_NAME
        and isinstance(metadata.get("uid"), str)
        and _UID.fullmatch(metadata["uid"]) is not None
        and isinstance(metadata.get("resourceVersion"), str)
        and metadata["resourceVersion"].isdigit()
        and metadata.get("labels") == SECRET_LABELS
        and metadata.get("annotations") == expected_annotations
    ):
        raise MaterializationError(
            "eligibility issuer PartialObjectMetadata projection mismatch"
        )
    return {
        "target": {
            "apiVersion": "v1",
            "kind": "Secret",
            "namespace": NAMESPACE,
            "name": SECRET_NAME,
        },
        "uid": metadata["uid"],
        "resourceVersion": metadata["resourceVersion"],
        "operationNonce": operation_nonce,
        "type": "Opaque",
        "immutable": True,
        "keySet": [SECRET_KEY],
        "labels": dict(SECRET_LABELS),
        "annotations": expected_annotations,
        "valuesRead": False,
    }


def partial_object_metadata_get(
    core: Any,
    snapshot: Any,
    policy: dict[str, Any],
    public_key: str,
    operation_nonce: str,
) -> dict[str, Any] | None:
    """Read only Kubernetes PartialObjectMetadata for the exact Secret."""
    boundary = policy["materialization"]["metadataOnlyRead"]
    if boundary != {
        "representation": "PartialObjectMetadata",
        "accept": PARTIAL_OBJECT_METADATA_ACCEPT,
        "apiPath": SECRET_API_PATH,
    }:
        raise MaterializationError("eligibility issuer metadata-only policy drift")
    timeout = policy["httpBoundary"]["timeoutsSeconds"]["routeRequest"]
    context = ssl.create_default_context(cadata=snapshot.ca_pem.decode("ascii"))
    if snapshot.client_certificate_path is not None or snapshot.client_key_path is not None:
        if not (
            snapshot.client_certificate_path is not None
            and snapshot.client_key_path is not None
        ):
            raise MaterializationError(
                "eligibility issuer Kubernetes client certificate snapshot incomplete"
            )
        context.load_cert_chain(
            str(snapshot.client_certificate_path), str(snapshot.client_key_path)
        )
    raw = core._api_tcp_transport_v4(snapshot, timeout)
    secured = None
    try:
        secured = context.wrap_socket(
            raw, server_hostname=snapshot.tls_server_name
        )
        host = f"[{snapshot.hostname}]" if ":" in snapshot.hostname else snapshot.hostname
        authority = host if snapshot.port == 443 else f"{host}:{snapshot.port}"
        headers = [
            f"GET {SECRET_API_PATH} HTTP/1.1",
            f"Host: {authority}",
            f"Accept: {PARTIAL_OBJECT_METADATA_ACCEPT}",
            "Connection: close",
        ]
        if snapshot.bearer_token is not None:
            headers.append(f"Authorization: Bearer {snapshot.bearer_token}")
        secured.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
        response = http.client.HTTPResponse(secured)
        response.begin()
        if response.status == 404:
            return None
        if response.status != 200:
            raise MaterializationError(
                "eligibility issuer metadata-only Kubernetes GET rejected"
            )
        content_type = response.getheader("Content-Type", "")
        if content_type.split(";", 1)[0].strip().lower() != "application/json":
            raise MaterializationError(
                "eligibility issuer metadata-only response type invalid"
            )
        if response.getheader("Content-Encoding") is not None:
            raise MaterializationError(
                "eligibility issuer metadata-only response encoding forbidden"
            )
        content_length = response.getheader("Content-Length")
        if content_length is not None and not (
            content_length.isdigit()
            and int(content_length) <= MAX_METADATA_RESPONSE_BYTES
        ):
            raise MaterializationError(
                "eligibility issuer metadata-only response length invalid"
            )
        body = response.read(MAX_METADATA_RESPONSE_BYTES + 1)
        if (
            len(body) > MAX_METADATA_RESPONSE_BYTES
            or (
                content_length is not None
                and len(body) != int(content_length)
            )
        ):
            raise MaterializationError(
                "eligibility issuer metadata-only response length mismatch"
            )
        try:
            document = json.loads(body, object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, ValueError, TypeError) as exc:
            raise MaterializationError(
                "eligibility issuer metadata-only response invalid"
            ) from exc
        return _parse_partial_object_metadata(
            document, public_key, operation_nonce
        )
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


def validate_secret_record(
    record: Any, public_key: str, operation_nonce: str
) -> dict[str, Any]:
    expected_keys = {
        "target",
        "uid",
        "resourceVersion",
        "operationNonce",
        "type",
        "immutable",
        "keySet",
        "labels",
        "annotations",
        "valuesRead",
        "createOutcome",
    }
    if not (
        isinstance(record, dict)
        and set(record) == expected_keys
        and record.get("target")
        == {
            "apiVersion": "v1",
            "kind": "Secret",
            "namespace": NAMESPACE,
            "name": SECRET_NAME,
        }
        and isinstance(record.get("uid"), str)
        and _UID.fullmatch(record["uid"]) is not None
        and isinstance(record.get("resourceVersion"), str)
        and record["resourceVersion"].isdigit()
        and isinstance(operation_nonce, str)
        and _NONCE.fullmatch(operation_nonce) is not None
        and record.get("operationNonce") == operation_nonce
        and record.get("type") == "Opaque"
        and record.get("immutable") is True
        and record.get("keySet") == [SECRET_KEY]
        and record.get("labels") == SECRET_LABELS
        and record.get("annotations")
        == exact_secret_annotations(public_key, operation_nonce)
        and record.get("valuesRead") is False
        and record.get("createOutcome")
        in {
            "create-response-and-exact-live-projection",
            "nonzero-post-send-exact-same-journal-nonce-live-projection",
            "recovered-exact-same-journal-nonce-live-projection",
        }
    ):
        raise MaterializationError("eligibility issuer Secret record drift")
    return json.loads(canonical(record))


def server_dry_run(
    private_seed: bytes,
    public_key: str,
    operation_nonce: str,
    runner: Any,
    kubeconfig: str,
) -> None:
    manifest = canonical(_manifest(private_seed, public_key, operation_nonce))
    result = runner.run(
        [
            *_kubectl(kubeconfig),
            "create",
            "-f",
            "-",
            "--dry-run=server",
            "-o",
            f"go-template={_projection_template(include_identity=False)}",
        ],
        input_text=manifest,
        timeout=30,
    )
    if _already_exists(result):
        raise ExistingObjectError(
            "eligibility issuer Secret already exists; adoption and recreation forbidden"
        )
    if result.code != 0:
        raise MaterializationError("eligibility issuer server dry-run failed")
    _parse_projection(
        result.out,
        public_key,
        operation_nonce,
        "server dry-run",
        require_identity=False,
    )


def create_and_observe(
    private_seed: bytes,
    public_key: str,
    operation_nonce: str,
    runner: Any,
    kubeconfig: str,
    core: Any,
    snapshot: Any,
    policy: dict[str, Any],
) -> dict[str, Any]:
    manifest = canonical(_manifest(private_seed, public_key, operation_nonce))
    result = runner.run(
        [
            *_kubectl(kubeconfig),
            "create",
            "-f",
            "-",
            "-o",
            f"go-template={_projection_template(include_identity=True)}",
        ],
        input_text=manifest,
        timeout=30,
    )
    if _already_exists(result):
        raise ExistingObjectError(
            "eligibility issuer Secret create conflict; adoption forbidden"
        )
    response: dict[str, Any] | None = None
    if result.code == 0:
        response = _parse_projection(
            result.out,
            public_key,
            operation_nonce,
            "created Secret",
            require_identity=True,
        )
    live = partial_object_metadata_get(
        core, snapshot, policy, public_key, operation_nonce
    )
    if live is None:
        if _already_exists(result):
            raise MaterializationError(
                "eligibility issuer Secret create conflict; adoption forbidden"
            )
        raise MaterializationError(
            "eligibility issuer Secret create outcome unresolved; recovery journal retained"
        )
    if response is not None and response != live:
        raise MaterializationError("eligibility issuer create/live projection drift")
    live["createOutcome"] = (
        "create-response-and-exact-live-projection"
        if result.code == 0
        else "nonzero-post-send-exact-same-journal-nonce-live-projection"
    )
    return validate_secret_record(live, public_key, operation_nonce)


def policy_binding(policy: dict[str, Any]) -> dict[str, str]:
    return {
        "schemaVersion": POLICY_SCHEMA,
        "sha256": sha256(canonical(policy).encode("ascii")),
    }


def bind_protected_identity(
    protected_revision: str, protected_hashes: Any
) -> dict[str, str]:
    if not (
        isinstance(protected_revision, str)
        and _REVISION.fullmatch(protected_revision) is not None
        and isinstance(protected_hashes, dict)
        and set(protected_hashes) == set(PROTECTED_PATHS)
        and all(
            isinstance(value, str) and _SHA256.fullmatch(value) is not None
            for value in protected_hashes.values()
        )
    ):
        raise MaterializationError("eligibility issuer protected file closure drift")
    return dict(sorted(protected_hashes.items()))


def bind_cluster_binding(
    policy: dict[str, Any], cluster: Any
) -> dict[str, Any]:
    required = {
        "apiOrigin",
        "caCertificateSha256",
        "apiServerSpkiSha256",
        "kubeSystemNamespaceUid",
        "kubeSystemNamespaceResourceVersion",
        "credentialsIncluded",
        "kubeconfigPathIncluded",
    }
    expected = policy["clusterIdentity"]
    if not (
        isinstance(cluster, dict)
        and set(cluster) == required
        and all(cluster.get(key) == expected[key] for key in expected)
        and isinstance(cluster.get("kubeSystemNamespaceResourceVersion"), str)
        and cluster["kubeSystemNamespaceResourceVersion"].isdigit()
        and cluster.get("credentialsIncluded") is False
        and cluster.get("kubeconfigPathIncluded") is False
    ):
        raise MaterializationError("eligibility issuer cluster binding drift")
    return json.loads(canonical(cluster))


def require_same_cluster_identity(
    left: dict[str, Any], right: dict[str, Any]
) -> None:
    if any(left.get(key) != right.get(key) for key in CLUSTER_IDENTITY_KEYS):
        raise MaterializationError("eligibility issuer recovery cluster identity drift")


def build_receipt(
    policy: dict[str, Any],
    protected_revision: str,
    protected_hashes: dict[str, str],
    cluster: dict[str, Any],
    record: dict[str, Any],
) -> dict[str, Any]:
    policy = load_policy(canonical(policy).encode("ascii"))
    protected_hashes = bind_protected_identity(
        protected_revision, protected_hashes
    )
    public_key = policy["publicKey"]["expected"]
    nonce = record.get("operationNonce") if isinstance(record, dict) else ""
    record = validate_secret_record(record, public_key, nonce)
    receipt = {
        "schemaVersion": RECEIPT_SCHEMA,
        "status": "materialized",
        "protectedRevision": protected_revision,
        "protectedFileSha256": dict(sorted(protected_hashes.items())),
        "policy": policy_binding(policy),
        "clusterBinding": bind_cluster_binding(policy, cluster),
        "target": json.loads(canonical(policy["target"])),
        "uid": record["uid"],
        "resourceVersion": record["resourceVersion"],
        "operationNonce": record["operationNonce"],
        "keyId": KEY_ID,
        "publicKey": public_key,
        "privateKeyCommitmentSha256": policy["input"]["sha256Commitment"],
        "keySet": record["keySet"],
        "labels": record["labels"],
        "annotations": record["annotations"],
        "createOutcome": record["createOutcome"],
        "valuesRead": False,
        "receiptContainsValues": False,
        "authority": json.loads(canonical(policy["authority"])),
    }
    return bind_receipt(
        policy, receipt, protected_revision, protected_hashes
    )


def bind_receipt(
    policy: dict[str, Any],
    receipt: Any,
    protected_revision: str,
    protected_hashes: dict[str, str],
) -> dict[str, Any]:
    policy = load_policy(canonical(policy).encode("ascii"))
    protected_hashes = bind_protected_identity(
        protected_revision, protected_hashes
    )
    required = set(policy["receipt"]["requiredFields"])
    if not (
        isinstance(receipt, dict)
        and set(receipt) == required
        and receipt.get("schemaVersion") == RECEIPT_SCHEMA
        and receipt.get("status") == "materialized"
        and receipt.get("protectedRevision") == protected_revision
        and receipt.get("protectedFileSha256")
        == dict(sorted(protected_hashes.items()))
        and receipt.get("policy") == policy_binding(policy)
        and receipt.get("target") == policy["target"]
        and receipt.get("keyId") == KEY_ID
        and receipt.get("publicKey") == policy["publicKey"]["expected"]
        and receipt.get("privateKeyCommitmentSha256")
        == policy["input"]["sha256Commitment"]
        and receipt.get("valuesRead") is False
        and receipt.get("receiptContainsValues") is False
        and receipt.get("authority") == policy["authority"]
        and isinstance(receipt.get("uid"), str)
        and _UID.fullmatch(receipt["uid"]) is not None
        and isinstance(receipt.get("resourceVersion"), str)
        and receipt["resourceVersion"].isdigit()
        and isinstance(receipt.get("operationNonce"), str)
        and _NONCE.fullmatch(receipt["operationNonce"]) is not None
        and receipt.get("keySet") == [SECRET_KEY]
        and receipt.get("labels") == SECRET_LABELS
        and receipt.get("annotations")
        == exact_secret_annotations(
            policy["publicKey"]["expected"], receipt["operationNonce"]
        )
        and receipt.get("createOutcome")
        in {
            "create-response-and-exact-live-projection",
            "nonzero-post-send-exact-same-journal-nonce-live-projection",
            "recovered-exact-same-journal-nonce-live-projection",
        }
    ):
        raise MaterializationError("eligibility issuer receipt field or policy drift")
    bind_cluster_binding(policy, receipt["clusterBinding"])
    return json.loads(canonical(receipt))


class ReceiptSink:
    """Pre-reserved, non-overwriting receipt with the exact public field set."""

    def __init__(self, path: Path, device: int, inode: int):
        self.path, self.device, self.inode = path, device, inode

    def reservation(self) -> dict[str, Any]:
        return {
            "absolutePath": str(self.path),
            "pathSha256": sha256(str(self.path).encode("utf-8")),
            "device": self.device,
            "inode": self.inode,
        }

    @classmethod
    def reserve(cls, selected: Path) -> "ReceiptSink":
        requested = Path(os.path.abspath(selected))
        if requested.exists() or requested.is_symlink():
            raise MaterializationError("eligibility issuer receipt path already exists")
        path = Path(os.path.realpath(requested.parent)) / requested.name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent = os.lstat(path.parent)
        if not (
            path.parent.resolve() == path.parent
            and stat.S_ISDIR(parent.st_mode)
            and parent.st_uid == os.geteuid()
            and stat.S_IMODE(parent.st_mode) & 0o022 == 0
        ):
            raise MaterializationError(
                "eligibility issuer receipt parent must be owned and non-writable"
            )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.fsync(fd)
            info = os.fstat(fd)
        finally:
            os.close(fd)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return cls(path, info.st_dev, info.st_ino)

    @classmethod
    def from_reservation(
        cls, selected: Path, reservation: Any
    ) -> "ReceiptSink":
        requested = Path(os.path.abspath(selected))
        if requested.is_symlink():
            raise MaterializationError("eligibility issuer receipt path is a symlink")
        path = Path(os.path.realpath(requested.parent)) / requested.name
        if not (
            isinstance(reservation, dict)
            and set(reservation)
            == {"absolutePath", "pathSha256", "device", "inode"}
            and reservation.get("absolutePath") == str(path)
            and reservation.get("pathSha256")
            == sha256(str(path).encode("utf-8"))
            and type(reservation.get("device")) is int
            and type(reservation.get("inode")) is int
        ):
            raise MaterializationError(
                "eligibility issuer receipt reservation binding drift"
            )
        current = os.lstat(path)
        if (
            stat.S_ISREG(current.st_mode)
            and not path.is_symlink()
            and current.st_uid == os.geteuid()
            and current.st_nlink == 1
            and stat.S_IMODE(current.st_mode) == 0o600
            and current.st_size > 0
            and current.st_size <= 8 * 1024 * 1024
            and (
                current.st_dev != reservation["device"]
                or current.st_ino != reservation["inode"]
            )
        ):
            raise AtomicallyPublishedReceipt(
                "eligibility issuer receipt inode replaced by staged publication"
            )
        sink = cls(path, reservation["device"], reservation["inode"])
        sink.read()
        return sink

    def read(self) -> bytes:
        current = os.lstat(self.path)
        if not (
            stat.S_ISREG(current.st_mode)
            and not self.path.is_symlink()
            and current.st_uid == os.geteuid()
            and current.st_nlink == 1
            and stat.S_IMODE(current.st_mode) == 0o600
            and current.st_dev == self.device
            and current.st_ino == self.inode
            and current.st_size <= 8 * 1024 * 1024
        ):
            raise MaterializationError("eligibility issuer receipt reservation drift")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(self.path, flags)
        try:
            opened = os.fstat(fd)
            if not (
                opened.st_dev == self.device
                and opened.st_ino == self.inode
                and opened.st_size == current.st_size
            ):
                raise MaterializationError("eligibility issuer receipt inode drift")
            raw = os.read(fd, 8 * 1024 * 1024 + 1)
        finally:
            os.close(fd)
        if len(raw) != current.st_size:
            raise MaterializationError("eligibility issuer receipt changed while reading")
        return raw

    def commit(
        self,
        policy: dict[str, Any],
        receipt: dict[str, Any],
        protected_revision: str,
        protected_hashes: dict[str, str],
    ) -> None:
        public_receipt = bind_receipt(
            policy, receipt, protected_revision, protected_hashes
        )
        raw = (json.dumps(public_receipt, indent=2, sort_keys=True) + "\n").encode(
            "ascii"
        )
        if self.read() != b"":
            raise MaterializationError("eligibility issuer receipt reservation drift")
        staged = self.path.parent / (
            f".{self.path.name}.{secrets.token_hex(16)}.receipt-stage"
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(staged, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            pending = memoryview(raw)
            while pending:
                written = os.write(fd, pending)
                if written <= 0:
                    raise MaterializationError("eligibility issuer receipt short write")
                pending = pending[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            staged_info = os.lstat(staged)
            if not (
                stat.S_ISREG(staged_info.st_mode)
                and not staged.is_symlink()
                and staged_info.st_uid == os.geteuid()
                and staged_info.st_nlink == 1
                and stat.S_IMODE(staged_info.st_mode) == 0o600
                and staged_info.st_size == len(raw)
            ):
                raise MaterializationError(
                    "eligibility issuer staged receipt drift"
                )
            if self.read() != b"":
                raise MaterializationError(
                    "eligibility issuer receipt reservation drift"
                )
            os.replace(staged, self.path)
            published = os.lstat(self.path)
            self.device, self.inode = published.st_dev, published.st_ino
            directory = os.open(
                self.path.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            if self.read() != raw:
                raise MaterializationError(
                    "eligibility issuer published receipt drift"
                )
        finally:
            try:
                staged.unlink()
            except FileNotFoundError:
                pass


def require_distinct_paths(*paths: Path) -> None:
    selected = [Path(os.path.realpath(Path(os.path.abspath(path)))) for path in paths]
    if len(set(selected)) != len(selected):
        raise MaterializationError("eligibility issuer receipt and journal must differ")
    existing = [path for path in selected if path.exists()]
    for index, left in enumerate(existing):
        for right in existing[index + 1 :]:
            if os.path.samefile(left, right):
                raise MaterializationError(
                    "eligibility issuer receipt and journal must not alias"
                )


def bind_journal(
    policy: dict[str, Any],
    journal: Any,
    protected_revision: str,
    protected_hashes: dict[str, str],
) -> dict[str, Any]:
    policy = load_policy(canonical(policy).encode("ascii"))
    protected_hashes = bind_protected_identity(
        protected_revision, protected_hashes
    )
    required = {
        "schemaVersion",
        "status",
        "phase",
        "protectedRevision",
        "protectedFileSha256",
        "policy",
        "clusterBinding",
        "operationNonce",
        "receiptReservation",
        "target",
        "keyId",
        "publicKey",
        "privateKeyCommitmentSha256",
        "secretRecord",
        "secretValuesIncluded",
        "civicAuthorityEffects",
    }
    phases = {
        "reserved-before-create",
        "create-attempting",
        "create-observed",
        "materialized-before-receipt-commit",
        "create-conflict",
        "terminal-receipt-observed",
        "committed",
    }
    reservation = journal.get("receiptReservation") if isinstance(journal, dict) else None
    reservation_path = (
        reservation.get("absolutePath") if isinstance(reservation, dict) else None
    )
    reservation_valid = (
        isinstance(reservation, dict)
        and set(reservation) == {"absolutePath", "pathSha256", "device", "inode"}
        and isinstance(reservation_path, str)
        and reservation_path.startswith("/")
        and str(
            Path(
                os.path.realpath(Path(os.path.abspath(reservation_path)))
            )
        )
        == reservation_path
        and reservation.get("pathSha256")
        == sha256(reservation_path.encode("utf-8"))
        and type(reservation.get("device")) is int
        and reservation["device"] >= 0
        and type(reservation.get("inode")) is int
        and reservation["inode"] > 0
    )
    if not (
        isinstance(journal, dict)
        and set(journal) == required
        and journal.get("schemaVersion") == JOURNAL_SCHEMA
        and journal.get("status") in {"in-progress", "blocked", "committed"}
        and journal.get("phase") in phases
        and reservation_valid
        and journal.get("protectedRevision") == protected_revision
        and journal.get("protectedFileSha256")
        == dict(sorted(protected_hashes.items()))
        and journal.get("policy") == policy_binding(policy)
        and journal.get("target") == policy["target"]
        and journal.get("keyId") == KEY_ID
        and journal.get("publicKey") == policy["publicKey"]["expected"]
        and journal.get("privateKeyCommitmentSha256")
        == policy["input"]["sha256Commitment"]
        and isinstance(journal.get("operationNonce"), str)
        and _NONCE.fullmatch(journal["operationNonce"]) is not None
        and journal.get("secretValuesIncluded") is False
        and journal.get("civicAuthorityEffects") is False
    ):
        raise MaterializationError("eligibility issuer recovery journal boundary drift")
    bind_cluster_binding(policy, journal["clusterBinding"])
    record = journal.get("secretRecord")
    if record is not None:
        validate_secret_record(
            record, journal["publicKey"], journal["operationNonce"]
        )
    expected_state = {
        "reserved-before-create": ("in-progress", False),
        "create-attempting": ("in-progress", False),
        "create-observed": ("in-progress", True),
        "materialized-before-receipt-commit": ("in-progress", True),
        "create-conflict": ("blocked", False),
        "terminal-receipt-observed": ("committed", True),
        "committed": ("committed", True),
    }[journal["phase"]]
    if (journal["status"], record is not None) != expected_state:
        raise MaterializationError("eligibility issuer recovery journal phase drift")
    return json.loads(canonical(journal))


def reserve_journal(path: Path) -> Path:
    requested = Path(os.path.abspath(path))
    if requested.exists() or requested.is_symlink():
        raise MaterializationError("eligibility issuer journal path already exists")
    selected = Path(os.path.realpath(requested.parent)) / requested.name
    selected.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent = os.lstat(selected.parent)
    if not (
        stat.S_ISDIR(parent.st_mode)
        and parent.st_uid == os.geteuid()
        and stat.S_IMODE(parent.st_mode) & 0o022 == 0
    ):
        raise MaterializationError("eligibility issuer journal parent is not private")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(selected, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(
        selected.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return selected


def write_journal(
    path: Path,
    policy: dict[str, Any],
    journal: dict[str, Any],
    protected_revision: str,
    protected_hashes: dict[str, str],
) -> None:
    value = bind_journal(
        policy, journal, protected_revision, protected_hashes
    )
    requested = Path(os.path.abspath(path))
    if requested.is_symlink():
        raise MaterializationError("eligibility issuer journal path is a symlink")
    selected = Path(os.path.realpath(requested.parent)) / requested.name
    if not selected.exists() or selected.is_symlink():
        raise MaterializationError("eligibility issuer journal was not reserved")
    parent = os.lstat(selected.parent)
    current = os.lstat(selected)
    if not (
        stat.S_ISDIR(parent.st_mode)
        and parent.st_uid == os.geteuid()
        and stat.S_IMODE(parent.st_mode) & 0o022 == 0
        and stat.S_ISREG(current.st_mode)
        and current.st_uid == os.geteuid()
        and current.st_nlink == 1
        and stat.S_IMODE(current.st_mode) == 0o600
    ):
        raise MaterializationError("eligibility issuer journal parent is not private")
    temporary = selected.parent / f".{selected.name}.{secrets.token_hex(16)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(temporary, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        pending = memoryview(
            (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("ascii")
        )
        while pending:
            written = os.write(fd, pending)
            if written <= 0:
                raise MaterializationError("eligibility issuer journal short write")
            pending = pending[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(temporary, selected)
        directory = os.open(
            selected.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        info = os.lstat(selected)
        if not (
            stat.S_ISREG(info.st_mode)
            and not selected.is_symlink()
            and info.st_uid == os.geteuid()
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600
        ):
            raise MaterializationError("eligibility issuer journal durability drift")
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _read_owned_path_bytes(
    path: Path,
    label: str,
    *,
    allow_empty: bool,
) -> bytes:
    requested = Path(os.path.abspath(path))
    selected_parent = Path(os.path.realpath(requested.parent))
    parent = os.lstat(selected_parent)
    if not (
        stat.S_ISDIR(parent.st_mode)
        and parent.st_uid == os.geteuid()
        and stat.S_IMODE(parent.st_mode) & 0o022 == 0
    ):
        raise MaterializationError(f"{label} parent directory is not private")
    parent_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        parent_flags |= os.O_NOFOLLOW
    parent_fd = os.open(selected_parent, parent_flags)
    opened_parent = os.fstat(parent_fd)
    if not (
        opened_parent.st_dev == parent.st_dev
        and opened_parent.st_ino == parent.st_ino
        and stat.S_ISDIR(opened_parent.st_mode)
    ):
        os.close(parent_fd)
        raise MaterializationError(f"{label} parent directory changed")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(requested.name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise MaterializationError(f"{label} open failed") from exc
    finally:
        os.close(parent_fd)
    try:
        info = os.fstat(fd)
        if not (
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.geteuid()
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600
            and (allow_empty or info.st_size > 0)
            and info.st_size <= 8 * 1024 * 1024
        ):
            raise MaterializationError(
                f"{label} must be an owned 0600 regular file"
            )
        remaining = info.st_size + 1
        chunks: list[bytes] = []
        while remaining > 0:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(fd)
        if not (
            len(raw) == info.st_size
            and (
                info.st_dev,
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            )
        ):
            raise MaterializationError(f"{label} changed while reading")
        return raw
    finally:
        os.close(fd)


def load_journal(path: Path) -> dict[str, Any]:
    raw = _read_owned_path_bytes(
        path, "eligibility issuer recovery journal", allow_empty=False
    )
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (ValueError, UnicodeDecodeError) as exc:
        raise MaterializationError("eligibility issuer recovery journal invalid") from exc
    if not isinstance(value, dict):
        raise MaterializationError("eligibility issuer recovery journal invalid")
    return value


def new_journal(
    policy: dict[str, Any],
    protected_revision: str,
    protected_hashes: dict[str, str],
    cluster: dict[str, Any],
    operation_nonce: str,
    reservation: dict[str, Any],
) -> dict[str, Any]:
    value = {
        "schemaVersion": JOURNAL_SCHEMA,
        "status": "in-progress",
        "phase": "reserved-before-create",
        "protectedRevision": protected_revision,
        "protectedFileSha256": dict(sorted(protected_hashes.items())),
        "policy": policy_binding(policy),
        "clusterBinding": bind_cluster_binding(policy, cluster),
        "operationNonce": operation_nonce,
        "receiptReservation": json.loads(canonical(reservation)),
        "target": json.loads(canonical(policy["target"])),
        "keyId": KEY_ID,
        "publicKey": policy["publicKey"]["expected"],
        "privateKeyCommitmentSha256": policy["input"]["sha256Commitment"],
        "secretRecord": None,
        "secretValuesIncluded": False,
        "civicAuthorityEffects": False,
    }
    return bind_journal(policy, value, protected_revision, protected_hashes)


def record_from_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "target": {
            "apiVersion": "v1",
            "kind": "Secret",
            "namespace": receipt["target"]["namespace"],
            "name": receipt["target"]["name"],
        },
        "uid": receipt["uid"],
        "resourceVersion": receipt["resourceVersion"],
        "operationNonce": receipt["operationNonce"],
        "type": receipt["target"]["type"],
        "immutable": receipt["target"]["immutable"],
        "keySet": receipt["keySet"],
        "labels": receipt["labels"],
        "annotations": receipt["annotations"],
        "valuesRead": receipt["valuesRead"],
        "createOutcome": receipt["createOutcome"],
    }


def receipt_projection(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": receipt["schemaVersion"],
        "status": receipt["status"],
        "protectedRevision": receipt["protectedRevision"],
        "protectedFileSha256": receipt["protectedFileSha256"],
        "policy": receipt["policy"],
        "clusterBinding": receipt["clusterBinding"],
        "target": receipt["target"],
        "uid": receipt["uid"],
        "resourceVersion": receipt["resourceVersion"],
        "operationNonce": receipt["operationNonce"],
        "keyId": receipt["keyId"],
        "publicKey": receipt["publicKey"],
        "privateKeyCommitmentSha256": receipt["privateKeyCommitmentSha256"],
        "valuesRead": False,
        "receiptContainsValues": False,
        "authority": receipt["authority"],
        "canonicalReceiptSha256": sha256(canonical(receipt).encode("ascii")),
    }


def _load_owned_json_fd(fd: int, label: str) -> dict[str, Any]:
    if not isinstance(fd, int) or fd < 3:
        raise MaterializationError(f"{label} descriptor invalid")
    info = os.fstat(fd)
    if not (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.geteuid()
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o600
        and 0 < info.st_size <= 8 * 1024 * 1024
    ):
        raise MaterializationError(f"{label} must be an owned 0600 regular file")
    raw = os.pread(fd, info.st_size + 1, 0)
    after = os.fstat(fd)
    if not (
        len(raw) == info.st_size
        and (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    ):
        raise MaterializationError(f"{label} changed while reading")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (ValueError, UnicodeDecodeError) as exc:
        raise MaterializationError(f"{label} invalid") from exc
    if not isinstance(value, dict):
        raise MaterializationError(f"{label} invalid")
    return value


def materialize_live(
    protected_revision: str,
    kubeconfig: str,
    private_key_fd: int,
    receipt_path: Path,
    journal_path: Path,
) -> dict[str, Any]:
    require_distinct_paths(receipt_path, journal_path)
    core, policy, hashes = load_protected_runtime(protected_revision)
    private_seed = read_private_key_fd(private_key_fd)
    public_key = ed25519_public_key(private_seed).hex()
    if not (
        public_key == policy["publicKey"]["expected"]
        and private_key_commitment(private_seed)
        == policy["input"]["sha256Commitment"]
    ):
        raise MaterializationError(
            "issuer private key does not match protected public identity"
        )
    runner = core.Runner()
    snapshot = None
    signal_handlers = None
    try:
        signal_handlers = core.install_transaction_signal_handlers_v4()
        snapshot = core.snapshot_kubeconfig_v4(kubeconfig, runner)
        cluster = bind_cluster_binding(
            policy, core.cluster_binding_v4(runner, snapshot, policy)
        )
        operation_nonce = secrets.token_hex(32)
        server_dry_run(
            private_seed,
            public_key,
            operation_nonce,
            runner,
            str(snapshot.path),
        )
        reserve_journal(journal_path)
        sink = ReceiptSink.reserve(receipt_path)
        journal = new_journal(
            policy,
            protected_revision,
            hashes,
            cluster,
            operation_nonce,
            sink.reservation(),
        )
        write_journal(journal_path, policy, journal, protected_revision, hashes)
        before_create = bind_cluster_binding(
            policy, core.cluster_binding_v4(runner, snapshot, policy)
        )
        require_same_cluster_identity(cluster, before_create)
        journal["clusterBinding"] = before_create
        journal["phase"] = "create-attempting"
        write_journal(journal_path, policy, journal, protected_revision, hashes)
        try:
            record = create_and_observe(
                private_seed,
                public_key,
                operation_nonce,
                runner,
                str(snapshot.path),
                core,
                snapshot,
                policy,
            )
        except ExistingObjectError:
            journal["status"] = "blocked"
            journal["phase"] = "create-conflict"
            write_journal(
                journal_path, policy, journal, protected_revision, hashes
            )
            raise
        journal["phase"] = "create-observed"
        journal["secretRecord"] = record
        write_journal(journal_path, policy, journal, protected_revision, hashes)
        receipt = build_receipt(
            policy, protected_revision, hashes, before_create, record
        )
        journal["phase"] = "materialized-before-receipt-commit"
        write_journal(journal_path, policy, journal, protected_revision, hashes)
        core.defer_transaction_signals_v4()
        sink.commit(policy, receipt, protected_revision, hashes)
        journal["status"] = "committed"
        journal["phase"] = "committed"
        write_journal(journal_path, policy, journal, protected_revision, hashes)
        return receipt
    finally:
        if snapshot is not None:
            snapshot.close()
        if signal_handlers is not None:
            core.restore_transaction_signal_handlers_v4(signal_handlers)


def _bind_committed_receipt_bytes(
    raw: bytes,
    policy: dict[str, Any],
    protected_revision: str,
    hashes: dict[str, str],
    journal: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (ValueError, UnicodeDecodeError) as exc:
        raise MaterializationError(
            "eligibility issuer reserved receipt is partial or invalid"
        ) from exc
    receipt = bind_receipt(policy, value, protected_revision, hashes)
    if receipt["operationNonce"] != journal["operationNonce"]:
        raise MaterializationError("eligibility issuer receipt/journal nonce drift")
    require_same_cluster_identity(
        journal["clusterBinding"], receipt["clusterBinding"]
    )
    record = record_from_receipt(receipt)
    validate_secret_record(record, journal["publicKey"], journal["operationNonce"])
    if journal["secretRecord"] is not None and journal["secretRecord"] != record:
        raise MaterializationError("eligibility issuer receipt/journal record drift")
    return receipt, record


def _load_exact_atomically_published_receipt(
    receipt_path: Path,
    policy: dict[str, Any],
    protected_revision: str,
    hashes: dict[str, str],
    journal: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    requested = Path(os.path.abspath(receipt_path))
    selected = Path(os.path.realpath(requested.parent)) / requested.name
    reservation = journal["receiptReservation"]
    if not (
        str(selected) == reservation["absolutePath"]
        and sha256(str(selected).encode("utf-8")) == reservation["pathSha256"]
    ):
        raise MaterializationError(
            "eligibility issuer published receipt path differs from journal"
        )
    raw = _read_owned_path_bytes(
        selected,
        "eligibility issuer atomically published receipt",
        allow_empty=False,
    )
    return _bind_committed_receipt_bytes(
        raw, policy, protected_revision, hashes, journal
    )


def recover_from_journal(
    protected_revision: str,
    kubeconfig: str,
    receipt_path: Path,
    journal_path: Path,
) -> dict[str, Any]:
    require_distinct_paths(receipt_path, journal_path)
    core, policy, hashes = load_protected_runtime(protected_revision)
    journal = bind_journal(
        policy, load_journal(journal_path), protected_revision, hashes
    )
    if journal["status"] == "blocked":
        raise MaterializationError(
            "eligibility issuer journal records a create conflict; recovery and adoption forbidden"
        )
    if journal["phase"] == "reserved-before-create":
        raise MaterializationError(
            "eligibility issuer journal records no authorized create attempt"
        )
    try:
        sink = ReceiptSink.from_reservation(
            receipt_path, journal["receiptReservation"]
        )
    except AtomicallyPublishedReceipt:
        receipt, record = _load_exact_atomically_published_receipt(
            receipt_path, policy, protected_revision, hashes, journal
        )
        journal["secretRecord"] = record
        journal["status"] = "committed"
        journal["phase"] = "terminal-receipt-observed"
        write_journal(journal_path, policy, journal, protected_revision, hashes)
        return receipt
    committed = sink.read()
    if committed:
        receipt, record = _bind_committed_receipt_bytes(
            committed, policy, protected_revision, hashes, journal
        )
        journal["secretRecord"] = record
        journal["status"] = "committed"
        journal["phase"] = "terminal-receipt-observed"
        write_journal(journal_path, policy, journal, protected_revision, hashes)
        return receipt

    runner = core.Runner()
    snapshot = None
    signal_handlers = None
    try:
        signal_handlers = core.install_transaction_signal_handlers_v4()
        snapshot = core.snapshot_kubeconfig_v4(kubeconfig, runner)
        cluster = bind_cluster_binding(
            policy, core.cluster_binding_v4(runner, snapshot, policy)
        )
        require_same_cluster_identity(journal["clusterBinding"], cluster)
        live = partial_object_metadata_get(
            core,
            snapshot,
            policy,
            journal["publicKey"],
            journal["operationNonce"],
        )
        if live is None:
            raise MaterializationError(
                "eligibility issuer recovery found no same-journal Secret"
            )
        if journal["secretRecord"] is None:
            live["createOutcome"] = (
                "recovered-exact-same-journal-nonce-live-projection"
            )
            record = validate_secret_record(
                live, journal["publicKey"], journal["operationNonce"]
            )
        else:
            record = journal["secretRecord"]
            comparable = dict(live)
            comparable["createOutcome"] = record["createOutcome"]
            if comparable != record:
                raise MaterializationError(
                    "eligibility issuer recovery live projection drift"
                )
        journal["secretRecord"] = record
        journal["phase"] = "create-observed"
        write_journal(journal_path, policy, journal, protected_revision, hashes)
        receipt = build_receipt(
            policy, protected_revision, hashes, cluster, record
        )
        journal["phase"] = "materialized-before-receipt-commit"
        write_journal(journal_path, policy, journal, protected_revision, hashes)
        core.defer_transaction_signals_v4()
        sink.commit(policy, receipt, protected_revision, hashes)
        journal["status"] = "committed"
        journal["phase"] = "committed"
        write_journal(journal_path, policy, journal, protected_revision, hashes)
        return receipt
    finally:
        if snapshot is not None:
            snapshot.close()
        if signal_handlers is not None:
            core.restore_transaction_signal_handlers_v4(signal_handlers)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-protected-revision", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--materialize", action="store_true")
    mode.add_argument("--recover-journal", type=Path)
    mode.add_argument("--verify-receipt-fd", type=int)
    parser.add_argument("--kubeconfig")
    parser.add_argument("--private-key-fd", type=int)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--journal", type=Path)
    args = parser.parse_args(argv)
    if args.materialize:
        if not (
            args.kubeconfig is not None
            and args.private_key_fd is not None
            and args.receipt is not None
            and args.journal is not None
        ):
            raise MaterializationError(
                "materialization requires kubeconfig, private-key FD, receipt and journal"
            )
    elif args.recover_journal is not None:
        if not (
            args.kubeconfig is not None
            and args.receipt is not None
            and args.private_key_fd is None
            and args.journal is None
        ):
            raise MaterializationError(
                "recovery accepts only kubeconfig, receipt and its source journal"
            )
    elif not (
        args.kubeconfig is None
        and args.private_key_fd is None
        and args.receipt is None
        and args.journal is None
    ):
        raise MaterializationError("receipt verification accepts no live arguments")
    return args


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        if not (sys.flags.isolated and sys.flags.safe_path):
            raise MaterializationError(
                "runner requires python3 -I isolated safe-path mode"
            )
        os.environ.pop("PYTHONPATH", None)
        if args.materialize:
            receipt = materialize_live(
                args.expected_protected_revision,
                args.kubeconfig,
                args.private_key_fd,
                args.receipt,
                args.journal,
            )
        elif args.recover_journal is not None:
            receipt = recover_from_journal(
                args.expected_protected_revision,
                args.kubeconfig,
                args.receipt,
                args.recover_journal,
            )
        else:
            _core, policy, hashes = load_protected_runtime(
                args.expected_protected_revision
            )
            receipt = bind_receipt(
                policy,
                _load_owned_json_fd(
                    args.verify_receipt_fd, "eligibility issuer receipt"
                ),
                args.expected_protected_revision,
                hashes,
            )
        print(canonical(receipt_projection(receipt)))
        return 0
    except MaterializationError as exc:
        print(f"eligibility issuer materializer blocked: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # Fail closed without echoing third-party diagnostics.
        print(
            "eligibility issuer materializer blocked: " + type(exc).__name__,
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
