"""Deep, policy-owned dormant Flux bootstrap transaction.

The public interface is deliberately small: :func:`build_plan` derives the
only eight desired objects from the protected policy module, :func:`run`
executes or recovers that fixed transaction through an injected Kubernetes
adapter, and :func:`bind_success_receipt` binds the later activation runner to
the exact stable UIDs established here.
"""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import stat
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any


PLAN_SCHEMA = "roebel_staging_participant_flux_bootstrap_plan_v1"
RECEIPT_SCHEMA = "roebel_staging_participant_flux_bootstrap_receipt_v1"
NONCE_ANNOTATION = "stadtstack.io/participant-flux-bootstrap-nonce"
REVISION = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
NONCE = re.compile(r"[0-9a-f]{64}")

CREATE_ORDER = (
    "gateway.serviceAccount",
    "workbenchIngress.serviceAccount",
    "gateway.role",
    "workbenchIngress.role",
    "gateway.roleBinding",
    "workbenchIngress.roleBinding",
    "gateway.kustomization",
    "workbenchIngress.kustomization",
)


class BootstrapError(RuntimeError):
    pass


class DefiniteConflict(BootstrapError):
    pass


class UncertainCreate(BootstrapError):
    def __init__(self, logical_name: str):
        self.logical_name = logical_name
        super().__init__(f"{logical_name}: post-send create outcome unresolved")


class RawResult:
    def __init__(self, code: int = 0, out: str = "", err: str = ""):
        self.code = code
        self.out = out
        self.err = err


class ReceiptSink:
    """Pre-reserved, non-overwriting and durably replaced receipt file."""

    def __init__(self, path: Path, device: int, inode: int):
        self.path = path
        self.device = device
        self.inode = inode

    @classmethod
    def reserve(cls, path: Path) -> "ReceiptSink":
        resolved = Path(os.path.realpath(os.path.abspath(path)))
        parent = resolved.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent_info = os.lstat(parent)
        _require(
            parent.resolve() == parent
            and stat.S_ISDIR(parent_info.st_mode)
            and parent_info.st_uid == os.geteuid()
            and stat.S_IMODE(parent_info.st_mode) & 0o022 == 0,
            "receipt parent must be an owned non-writable real directory",
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(resolved, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.fsync(fd)
            info = os.fstat(fd)
        finally:
            os.close(fd)
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return cls(resolved, info.st_dev, info.st_ino)

    def commit(self, value: dict[str, Any]) -> None:
        _require(isinstance(value, dict) and "canonicalSha256" not in value, "receipt payload invalid")
        _reject_secret_shaped(value)
        final = copy.deepcopy(value)
        final["canonicalSha256"] = canonical_sha256(value)
        current = os.lstat(self.path)
        _require(
            stat.S_ISREG(current.st_mode)
            and current.st_dev == self.device
            and current.st_ino == self.inode,
            "reserved receipt target identity changed",
        )
        fd, raw_name = tempfile.mkstemp(prefix=".participant-flux-bootstrap-", dir=self.path.parent)
        temporary = Path(raw_name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=True) as stream:
                stream.write((canonical(final) + "\n").encode())
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            replaced = os.lstat(self.path)
            _require(stat.S_ISREG(replaced.st_mode) and stat.S_IMODE(replaced.st_mode) == 0o600, "committed receipt mode drift")
            self.device, self.inode = replaced.st_dev, replaced.st_ino
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


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise BootstrapError(message)


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value).encode()).hexdigest()


def _reject_secret_shaped(value: Any) -> None:
    encoded = canonical(value).lower()
    _require(
        not any(
            marker in encoded
            for marker in ('"data"', '"stringdata"', '"token"', '"password"', '"privatekey"')
        ),
        "secret-shaped receipt value forbidden",
    )


def _target(value: dict[str, Any]) -> dict[str, str]:
    metadata = value["metadata"]
    return {
        "apiVersion": value["apiVersion"],
        "kind": value["kind"],
        "namespace": metadata["namespace"],
        "name": metadata["name"],
    }


def target_of(value: dict[str, Any]) -> dict[str, str]:
    return _target(value)


def _json_object(raw: str, label: str) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (json.JSONDecodeError, ValueError) as exc:
        raise BootstrapError(f"{label}: invalid or duplicate-key JSON") from exc
    _require(isinstance(value, dict), f"{label}: JSON object required")
    return value


def _with_nonce(desired: dict[str, Any], nonce: str) -> dict[str, Any]:
    _require(NONCE.fullmatch(nonce) is not None, "bootstrap nonce invalid")
    value = copy.deepcopy(desired)
    metadata = value.get("metadata")
    _require(isinstance(metadata, dict), "bootstrap object metadata absent")
    annotations = metadata.setdefault("annotations", {})
    _require(isinstance(annotations, dict) and NONCE_ANNOTATION not in annotations, "bootstrap nonce annotation collision")
    annotations[NONCE_ANNOTATION] = nonce
    return value


def _metadata_identity(value: dict[str, Any], label: str) -> tuple[str, str]:
    metadata = value.get("metadata", {})
    uid, resource_version = metadata.get("uid"), metadata.get("resourceVersion")
    _require(isinstance(uid, str) and uid, f"{label} UID absent")
    _require(isinstance(resource_version, str) and resource_version.isdigit(), f"{label} resourceVersion invalid")
    return uid, resource_version


def _bind_created(
    *,
    policy_module: Any,
    kube: Any,
    item: dict[str, Any],
    desired_with_nonce: dict[str, Any],
    nonce: str,
    response: RawResult,
) -> tuple[dict[str, Any], str]:
    logical_name = item["logicalName"]
    lowered = (response.out + "\n" + response.err).lower()
    if response.code != 0 and ("alreadyexists" in lowered or re.search(r"\b409\b", lowered)):
        raise DefiniteConflict(f"{logical_name}: create conflict; adoption forbidden")

    observed: dict[str, Any] | None = None
    outcome = "http-201-created"
    if response.code == 0:
        try:
            candidate = _json_object(response.out, f"created {logical_name}")
            policy_module.require_semantically_equal(candidate, desired_with_nonce, logical_name)
            observed = candidate
        except (BootstrapError, policy_module.PolicyError):
            observed = None
    if observed is None:
        outcome = "post-send-uncertain-discovered"
        discovered = kube.get(item["target"])
        if discovered is None:
            raise UncertainCreate(logical_name)
        annotations = discovered.get("metadata", {}).get("annotations", {})
        if not isinstance(annotations, dict) or annotations.get(NONCE_ANNOTATION) != nonce:
            raise UncertainCreate(logical_name)
        try:
            policy_module.require_semantically_equal(discovered, desired_with_nonce, logical_name)
        except policy_module.PolicyError as exc:
            raise UncertainCreate(logical_name) from exc
        observed = discovered
    annotations = observed.get("metadata", {}).get("annotations", {})
    _require(isinstance(annotations, dict) and annotations.get(NONCE_ANNOTATION) == nonce, f"{logical_name} nonce ownership mismatch")
    uid, resource_version = _metadata_identity(observed, logical_name)
    return observed, outcome


def _desired_objects(policy_module: Any) -> dict[str, dict[str, Any]]:
    gateway = policy_module.gateway_flux_objects(suspended=True)
    workbench = policy_module.workbench_ingress_flux_objects(suspended=True)
    return {
        "gateway.serviceAccount": gateway["serviceAccount"],
        "workbenchIngress.serviceAccount": workbench["serviceAccount"],
        "gateway.role": gateway["role"],
        "workbenchIngress.role": workbench["role"],
        "gateway.roleBinding": gateway["roleBinding"],
        "workbenchIngress.roleBinding": workbench["roleBinding"],
        "gateway.kustomization": gateway["kustomization"],
        "workbenchIngress.kustomization": workbench["kustomization"],
    }


def build_plan(
    policy_module: Any,
    policy: dict[str, Any],
    protected_revision: str,
    protected_file_hashes: dict[str, str],
) -> dict[str, Any]:
    """Derive the complete dormant bootstrap plan from protected policy only."""
    _require(isinstance(protected_revision, str) and REVISION.fullmatch(protected_revision) is not None, "protected revision invalid")
    try:
        validated = policy_module.validate_activation_policy(policy)
    except policy_module.PolicyError as exc:
        raise BootstrapError(str(exc)) from exc
    _require(
        getattr(policy_module, "DORMANT_BOOTSTRAP_NONCE_ANNOTATION", None) == NONCE_ANNOTATION
        and getattr(policy_module, "DORMANT_BOOTSTRAP_RECEIPT_SCHEMA", None) == RECEIPT_SCHEMA
        and tuple(getattr(policy_module, "DORMANT_BOOTSTRAP_OBJECT_ORDER", ())) == CREATE_ORDER
        and validated["gitOps"]["dormantBootstrap"]["objectOrder"] == list(CREATE_ORDER),
        "protected dormant Flux bootstrap contract drift",
    )
    blockers = list(policy_module.activation_blockers(validated))
    _require(
        isinstance(protected_file_hashes, dict)
        and protected_file_hashes
        and all(isinstance(path, str) and isinstance(value, str) and SHA256.fullmatch(value) for path, value in protected_file_hashes.items()),
        "protected file hash set invalid",
    )
    desired = _desired_objects(policy_module)
    _require(tuple(desired) == CREATE_ORDER, "dormant Flux object order drift")
    objects = []
    for logical_name in CREATE_ORDER:
        value = copy.deepcopy(desired[logical_name])
        if value["kind"] == "Kustomization":
            _require(value.get("spec", {}).get("suspend") is True, f"{logical_name} must be suspended")
        objects.append(
            {
                "logicalName": logical_name,
                "target": _target(value),
                "desired": value,
                "desiredSemanticSha256": policy_module.semantic_sha256(value),
            },
        )
    return {
        "schemaVersion": PLAN_SCHEMA,
        "status": "blocked-policy-incomplete" if blockers else "ready-no-cluster-plan",
        "protectedRevision": protected_revision,
        "activationReady": validated["activationReady"] is True and not blockers,
        "blockers": blockers,
        "activationPolicySha256": policy_module.activation_policy_sha256(validated),
        "protectedFileSha256": dict(sorted(protected_file_hashes.items())),
        "objects": objects,
        "sharedSourceMutation": "forbidden",
        "secretAccess": "forbidden",
        "applicationMutation": False,
        "civicAuthorityEffects": False,
        "kubernetesContacted": False,
    }


def _journal(state: dict[str, Any], phase: str, logical_name: str | None = None) -> None:
    previous = state["journal"][-1]["entrySha256"] if state["journal"] else None
    entry: dict[str, Any] = {
        "sequence": len(state["journal"]) + 1,
        "phase": phase,
        "previousEntrySha256": previous,
    }
    if logical_name is not None:
        entry["logicalName"] = logical_name
    entry["entrySha256"] = canonical_sha256(entry)
    state["journal"].append(entry)


def _receipt_state(plan: dict[str, Any], nonce: str) -> dict[str, Any]:
    state = {
        "schemaVersion": RECEIPT_SCHEMA,
        "status": "reserved",
        "mode": "live",
        "protectedRevision": plan["protectedRevision"],
        "activationPolicySha256": plan["activationPolicySha256"],
        "protectedFileSha256": copy.deepcopy(plan["protectedFileSha256"]),
        "operation": {
            "operationId": str(uuid.uuid4()),
            "operationNonce": nonce,
            "nonceAnnotation": NONCE_ANNOTATION,
        },
        "plan": [
            {
                "logicalName": item["logicalName"],
                "target": copy.deepcopy(item["target"]),
                "desiredSemanticSha256": item["desiredSemanticSha256"],
            }
            for item in plan["objects"]
        ],
        "preflight": None,
        "objectCreateResults": [],
        "postconditions": None,
        "rollback": None,
        "journal": [],
        "effects": {
            "applicationMutation": False,
            "secretRead": False,
            "secretWrite": False,
            "sharedSourceMutation": False,
            "webIngressMutation": False,
            "existingWorkbenchNetworkPolicyMutation": False,
            "civicAuthorityEffects": False,
        },
    }
    _journal(state, "reserved")
    return state


def _closed_receipt_payload(receipt: dict[str, Any]) -> tuple[dict[str, Any], str]:
    _require(isinstance(receipt, dict), "bootstrap receipt must be an object")
    payload = copy.deepcopy(receipt)
    checksum = payload.pop("canonicalSha256", None)
    _require(isinstance(checksum, str) and SHA256.fullmatch(checksum) is not None, "bootstrap receipt checksum invalid")
    _require(canonical_sha256(payload) == checksum, "bootstrap receipt checksum mismatch")
    _reject_secret_shaped(payload)
    return payload, checksum


def load_receipt(path: Path) -> dict[str, Any]:
    """Read one operator-selected receipt without following or racing links."""
    resolved = Path(os.path.abspath(path))
    info = os.lstat(resolved)
    _require(
        stat.S_ISREG(info.st_mode)
        and not resolved.is_symlink()
        and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_size <= 1024 * 1024,
        "bootstrap receipt must be an owned 0600 regular non-symlink file under 1 MiB",
    )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(resolved, flags)
    try:
        opened = os.fstat(fd)
        _require(
            opened.st_dev == info.st_dev
            and opened.st_ino == info.st_ino
            and opened.st_size == info.st_size,
            "bootstrap receipt identity changed while opening",
        )
        raw = os.read(fd, 1024 * 1024 + 1)
    finally:
        os.close(fd)
    _require(len(raw) <= 1024 * 1024, "bootstrap receipt exceeds 1 MiB")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BootstrapError("bootstrap receipt must be UTF-8 JSON") from exc
    value = _json_object(text, "bootstrap receipt")
    _closed_receipt_payload(value)
    return value


def _validate_journal(journal: Any) -> None:
    _require(isinstance(journal, list) and journal, "bootstrap receipt journal invalid")
    previous = None
    for index, raw in enumerate(journal, start=1):
        _require(isinstance(raw, dict), "bootstrap receipt journal entry invalid")
        entry = copy.deepcopy(raw)
        digest = entry.pop("entrySha256", None)
        _require(
            entry.get("sequence") == index
            and entry.get("previousEntrySha256") == previous
            and isinstance(digest, str)
            and SHA256.fullmatch(digest) is not None
            and canonical_sha256(entry) == digest,
            "bootstrap receipt journal chain invalid",
        )
        previous = digest


def _journal_contains(journal: list[dict[str, Any]], phase: str, logical_name: str) -> bool:
    return any(
        entry.get("phase") == phase and entry.get("logicalName") == logical_name
        for entry in journal
    )


def _validate_receipt_plan_binding(plan: dict[str, Any], payload: dict[str, Any]) -> None:
    expected_plan = [
        {
            "logicalName": item["logicalName"],
            "target": item["target"],
            "desiredSemanticSha256": item["desiredSemanticSha256"],
        }
        for item in plan["objects"]
    ]
    _require(payload.get("schemaVersion") == RECEIPT_SCHEMA, "bootstrap receipt schema drift")
    _require(payload.get("protectedRevision") == plan["protectedRevision"], "bootstrap receipt protected revision drift")
    _require(payload.get("activationPolicySha256") == plan["activationPolicySha256"], "bootstrap receipt policy drift")
    _require(payload.get("protectedFileSha256") == plan["protectedFileSha256"], "bootstrap receipt protected file drift")
    _require(payload.get("plan") == expected_plan, "bootstrap receipt exact eight-object plan drift")
    operation = payload.get("operation")
    _require(
        isinstance(operation, dict)
        and isinstance(operation.get("operationId"), str)
        and operation.get("nonceAnnotation") == NONCE_ANNOTATION
        and isinstance(operation.get("operationNonce"), str)
        and NONCE.fullmatch(operation["operationNonce"]) is not None,
        "bootstrap receipt operation binding invalid",
    )
    effects = payload.get("effects")
    _require(
        effects
        == {
            "applicationMutation": False,
            "secretRead": False,
            "secretWrite": False,
            "sharedSourceMutation": False,
            "webIngressMutation": False,
            "existingWorkbenchNetworkPolicyMutation": False,
            "civicAuthorityEffects": False,
        },
        "bootstrap receipt authority effects drift",
    )
    _validate_journal(payload.get("journal"))


def bind_success_receipt(plan: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
    """Bind later activation to the exact dormant identities from one receipt."""
    payload, checksum = _closed_receipt_payload(receipt)
    _validate_receipt_plan_binding(plan, payload)
    _require(payload.get("mode") == "live" and payload.get("status") == "dormant-ready", "bootstrap success receipt not dormant-ready")
    _require(payload.get("rollback") is None, "bootstrap success receipt unexpectedly rolled back")
    records = payload.get("objectCreateResults")
    postconditions = payload.get("postconditions")
    _require(isinstance(records, list) and len(records) == len(plan["objects"]), "bootstrap success create result count drift")
    _require(
        isinstance(postconditions, dict)
        and postconditions.get("bothKustomizationsSuspended") is True
        and isinstance(postconditions.get("objects"), list)
        and len(postconditions["objects"]) == len(plan["objects"]),
        "bootstrap success postconditions invalid",
    )
    bound: list[dict[str, Any]] = []
    seen_uids: set[str] = set()
    for item, record, post in zip(plan["objects"], records, postconditions["objects"], strict=True):
        _require(
            isinstance(record, dict)
            and record.get("logicalName") == item["logicalName"]
            and record.get("target") == item["target"]
            and record.get("desiredSemanticSha256") == item["desiredSemanticSha256"]
            and record.get("nonceRemovalState") == "removed"
            and record.get("temporaryNonceRemoved") is True
            and record.get("rollbackOwned") is True,
            f"bootstrap success create binding drift: {item['logicalName']}",
        )
        _require(
            all(
                _journal_contains(payload["journal"], phase, item["logicalName"])
                for phase in ("object-created", "nonce-removal-intent", "nonce-removed")
            ),
            f"bootstrap success nonce journal drift: {item['logicalName']}",
        )
        uid = record.get("uid")
        resource_version = record.get("postNonceRemovalResourceVersion")
        _require(
            isinstance(uid, str)
            and uid
            and uid not in seen_uids
            and isinstance(resource_version, str)
            and resource_version.isdigit(),
            f"bootstrap success identity invalid: {item['logicalName']}",
        )
        seen_uids.add(uid)
        _require(
            isinstance(post, dict)
            and post.get("logicalName") == item["logicalName"]
            and post.get("target") == item["target"]
            and post.get("uid") == uid
            and post.get("desiredSemanticSha256") == item["desiredSemanticSha256"]
            and isinstance(post.get("resourceVersion"), str)
            and post["resourceVersion"].isdigit()
            and int(post["resourceVersion"]) >= int(resource_version),
            f"bootstrap success postcondition binding drift: {item['logicalName']}",
        )
        bound.append({
            "logicalName": item["logicalName"],
            "target": copy.deepcopy(item["target"]),
            "uid": uid,
            "resourceVersion": post["resourceVersion"],
            "desiredSemanticSha256": item["desiredSemanticSha256"],
        })
    return {
        "schemaVersion": RECEIPT_SCHEMA,
        "status": "dormant-ready",
        "receiptSha256": checksum,
        "protectedRevision": plan["protectedRevision"],
        "activationPolicySha256": plan["activationPolicySha256"],
        "objects": bound,
        "bothKustomizationsSuspended": True,
    }


def run(
    plan: dict[str, Any],
    *,
    mode: str,
    kube: Any,
    sink: Any,
    policy_module: Any,
    prior_receipt: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute or recover the fixed bootstrap transaction through one adapter."""
    _require(mode in {"live", "recover"}, "bootstrap mode invalid")
    _require(plan.get("schemaVersion") == PLAN_SCHEMA and plan.get("activationReady") is True and not plan.get("blockers"), "dormant Flux bootstrap blocked: activation policy incomplete")
    if mode == "recover":
        _require(prior_receipt is not None, "recovery receipt required")
        return _recover(plan, kube=kube, sink=sink, policy_module=policy_module, receipt=prior_receipt)

    nonce = secrets.token_hex(32)
    _require(NONCE.fullmatch(nonce) is not None, "runner CSPRNG bootstrap nonce invalid")
    state = _receipt_state(plan, nonce)
    sink.commit(state)

    before = kube.preflight(plan)
    absence = []
    for item in plan["objects"]:
        found = kube.get(item["target"])
        _require(found is None, f"dormant Flux bootstrap target already exists; adoption forbidden: {item['logicalName']}")
        absence.append({"logicalName": item["logicalName"], "target": copy.deepcopy(item["target"]), "state": "absent", "apiOutcome": "http-404-not-found"})
    state["preflight"] = {"allEightAbsent": True, "objects": absence, **copy.deepcopy(before)}
    state["status"] = "creating"
    _journal(state, "all-eight-absent")
    sink.commit(state)

    created: list[dict[str, Any]] = []
    try:
        for item in plan["objects"]:
            desired_with_nonce = _with_nonce(item["desired"], nonce)
            response = kube.create(desired_with_nonce)
            observed, outcome = _bind_created(
                policy_module=policy_module,
                kube=kube,
                item=item,
                desired_with_nonce=desired_with_nonce,
                nonce=nonce,
                response=response,
            )
            uid, resource_version = _metadata_identity(observed, item["logicalName"])
            record = {
                "logicalName": item["logicalName"],
                "target": copy.deepcopy(item["target"]),
                "desiredSemanticSha256": item["desiredSemanticSha256"],
                "outcome": outcome,
                "uid": uid,
                "createdResourceVersion": resource_version,
                "postNonceRemovalResourceVersion": None,
                "nonceRemovalState": "not-started",
                "temporaryNonceRemoved": False,
                "rollbackOwned": True,
            }
            created.append(record)
            state["objectCreateResults"].append(record)
            _journal(state, "object-created", item["logicalName"])
            sink.commit(state)

        state["status"] = "removing-nonces"
        for item, record in zip(plan["objects"], created, strict=True):
            # Persist the exact UID-bound intent before sending the CAS.  If
            # the API accepts the patch but its response (or the following
            # receipt write) is lost, recovery may then distinguish that
            # state from an unrelated actor stripping our nonce.
            record["nonceRemovalState"] = "intent-durable"
            _journal(state, "nonce-removal-intent", item["logicalName"])
            sink.commit(state)
            after = kube.remove_nonce(
                item["desired"],
                record["uid"],
                record["createdResourceVersion"],
                nonce,
            )
            uid, resource_version = _metadata_identity(after, item["logicalName"])
            _require(uid == record["uid"], f"{item['logicalName']} UID changed during nonce removal")
            policy_module.require_semantically_equal(after, item["desired"], f"{item['logicalName']} post-nonce")
            record["postNonceRemovalResourceVersion"] = resource_version
            record["nonceRemovalState"] = "removed"
            record["temporaryNonceRemoved"] = True
            _journal(state, "nonce-removed", item["logicalName"])
            sink.commit(state)

        final = kube.final_checks(plan, before)
        post_objects = []
        for item, record in zip(plan["objects"], created, strict=True):
            live = kube.get(item["target"])
            _require(live is not None, f"{item['logicalName']} missing after bootstrap")
            policy_module.require_semantically_equal(live, item["desired"], f"{item['logicalName']} final")
            uid, resource_version = _metadata_identity(live, item["logicalName"])
            _require(uid == record["uid"], f"{item['logicalName']} final UID drift")
            post_objects.append({
                "logicalName": item["logicalName"],
                "target": copy.deepcopy(item["target"]),
                "uid": uid,
                "resourceVersion": resource_version,
                "desiredSemanticSha256": item["desiredSemanticSha256"],
            })
        state["postconditions"] = {
            "objects": post_objects,
            "bothKustomizationsSuspended": all(
                item["desired"].get("spec", {}).get("suspend") is True
                for item in plan["objects"]
                if item["target"]["kind"] == "Kustomization"
            ),
            "finalChecks": copy.deepcopy(final),
        }
        state["status"] = "dormant-ready"
        _journal(state, "dormant-ready")
        sink.commit(state)
        return state
    except Exception as exc:
        begin_rollback = getattr(kube, "begin_rollback", None)
        if callable(begin_rollback):
            try:
                begin_rollback()
            except Exception as rollback_guard_exc:
                state["rollback"] = {
                    "status": "incomplete",
                    "errors": [f"rollback signal guard: {rollback_guard_exc}"],
                    "allEightAbsentQuiet": False,
                }
                state["status"] = "rollback-incomplete"
                _journal(state, state["status"])
                sink.commit(state)
                raise BootstrapError("bootstrap rollback-incomplete: rollback signal guard unavailable") from exc
        unresolved = (
            [f"post-send create outcome unresolved: {exc.logical_name}"]
            if isinstance(exc, UncertainCreate)
            else None
        )
        rollback = _rollback(
            plan,
            kube=kube,
            policy_module=policy_module,
            nonce=nonce,
            created=created,
            before=before,
            initial_errors=unresolved,
        )
        state["rollback"] = rollback
        state["status"] = "rolled-back" if rollback["status"] == "complete" else "rollback-incomplete"
        _journal(state, state["status"])
        try:
            sink.commit(state)
        except Exception as receipt_exc:
            raise BootstrapError(
                f"bootstrap {state['status']}; rollback receipt persistence failed: {receipt_exc}"
            ) from exc
        raise BootstrapError(f"bootstrap {state['status']}: {exc}") from exc


def _rollback(
    plan: dict[str, Any],
    *,
    kube: Any,
    policy_module: Any,
    nonce: str,
    created: list[dict[str, Any]],
    before: dict[str, Any],
    initial_errors: list[str] | None = None,
) -> dict[str, Any]:
    """Delete only exact UIDs proved to belong to this operation nonce."""
    desired_by_name = {item["logicalName"]: item for item in plan["objects"]}
    reverse_created = list(reversed(created))
    ordered = [item for item in reverse_created if item["target"]["kind"] == "Kustomization"]
    ordered.extend(item for item in reverse_created if item["target"]["kind"] != "Kustomization")
    deletions: list[dict[str, Any]] = []
    errors: list[str] = list(initial_errors or [])
    for record in ordered:
        logical_name = record["logicalName"]
        item = desired_by_name[logical_name]
        try:
            current = kube.get(record["target"])
            if current is None:
                deletions.append({"logicalName": logical_name, "uid": record["uid"], "state": "already-absent"})
                continue
            uid, resource_version = _metadata_identity(current, f"rollback {logical_name}")
            _require(uid == record["uid"], f"{logical_name} rollback UID replacement; deletion forbidden")
            annotations = current.get("metadata", {}).get("annotations", {})
            has_nonce = isinstance(annotations, dict) and annotations.get(NONCE_ANNOTATION) == nonce
            if has_nonce:
                expected = _with_nonce(item["desired"], nonce)
            else:
                _require(
                    record.get("nonceRemovalState") in {"intent-durable", "removed"},
                    f"{logical_name} lacks nonce without durable removal intent; deletion forbidden",
                )
                expected = item["desired"]
            policy_module.require_semantically_equal(current, expected, f"rollback {logical_name}")
            kube.delete(record["target"], uid, resource_version)
            deletions.append({
                "logicalName": logical_name,
                "uid": uid,
                "deleteResourceVersion": resource_version,
                "state": "delete-requested",
            })
        except Exception as rollback_exc:
            errors.append(f"{logical_name}: {rollback_exc}")

    all_absent = False
    try:
        all_absent = bool(kube.wait_all_absent([item["target"] for item in plan["objects"]]))
        _require(all_absent, "all eight dormant Flux names did not remain absent for the quiet interval")
    except Exception as rollback_exc:
        errors.append(f"absence: {rollback_exc}")
    final_checks: dict[str, Any] | None = None
    try:
        final_checks = kube.final_checks(plan, before)
    except Exception as rollback_exc:
        errors.append(f"preservation: {rollback_exc}")
    both_kustomizations_absent = False
    try:
        both_kustomizations_absent = all(
            kube.get(item["target"]) is None
            for item in plan["objects"]
            if item["target"]["kind"] == "Kustomization"
        )
    except Exception as rollback_exc:
        errors.append(f"kustomization absence: {rollback_exc}")
    return {
        "status": "complete" if not errors and all_absent else "incomplete",
        "deletionOrder": [item["logicalName"] for item in ordered],
        "deleted": deletions,
        "allEightAbsentQuiet": all_absent,
        "bothKustomizationsAbsent": both_kustomizations_absent,
        "finalChecks": copy.deepcopy(final_checks),
        "errors": errors,
        "foreignOrReplacementObjectsDeleted": False,
    }


def _recover(
    plan: dict[str, Any],
    *,
    kube: Any,
    sink: Any,
    policy_module: Any,
    receipt: dict[str, Any],
) -> dict[str, Any]:
    payload, checksum = _closed_receipt_payload(receipt)
    _validate_receipt_plan_binding(plan, payload)
    _require(payload.get("status") != "dormant-ready", "successful dormant bootstrap must not be recovered as rollback")
    _require(payload.get("mode") == "live", "only interrupted live bootstrap receipts are recoverable")
    nonce = payload["operation"]["operationNonce"]
    state = copy.deepcopy(payload)
    state["mode"] = "recover"
    state["status"] = "recovering"
    state["recoveryOfReceiptSha256"] = checksum
    state["rollback"] = None
    _journal(state, "recovery-reserved")
    sink.commit(state)

    before = kube.preflight(plan)
    receipt_records = {
        record.get("logicalName"): record
        for record in payload.get("objectCreateResults", [])
        if isinstance(record, dict) and isinstance(record.get("logicalName"), str)
    }
    recovered: list[dict[str, Any]] = []
    errors: list[str] = []
    for item in plan["objects"]:
        logical_name = item["logicalName"]
        try:
            current = kube.get(item["target"])
            if current is None:
                continue
            uid, resource_version = _metadata_identity(current, f"recovery {logical_name}")
            annotations = current.get("metadata", {}).get("annotations", {})
            has_nonce = isinstance(annotations, dict) and annotations.get(NONCE_ANNOTATION) == nonce
            if has_nonce:
                policy_module.require_semantically_equal(
                    current,
                    _with_nonce(item["desired"], nonce),
                    f"recovery {logical_name}",
                )
                nonce_removed = False
            else:
                record = receipt_records.get(logical_name)
                _require(
                    isinstance(record, dict)
                    and record.get("target") == item["target"]
                    and record.get("uid") == uid
                    and record.get("desiredSemanticSha256") == item["desiredSemanticSha256"]
                    and record.get("rollbackOwned") is True
                    and record.get("nonceRemovalState") in {"intent-durable", "removed"},
                    f"{logical_name} lacks this operation nonce and durable UID/removal-intent ownership",
                )
                _require(
                    _journal_contains(payload["journal"], "nonce-removal-intent", logical_name),
                    f"{logical_name} lacks durable nonce-removal-intent journal proof",
                )
                policy_module.require_semantically_equal(current, item["desired"], f"recovery {logical_name}")
                nonce_removed = True
            recovered.append({
                "logicalName": logical_name,
                "target": copy.deepcopy(item["target"]),
                "desiredSemanticSha256": item["desiredSemanticSha256"],
                "outcome": "recovery-discovered",
                "uid": uid,
                "createdResourceVersion": resource_version,
                "postNonceRemovalResourceVersion": resource_version if nonce_removed else None,
                "nonceRemovalState": "removed" if nonce_removed else "not-started",
                "temporaryNonceRemoved": nonce_removed,
                "rollbackOwned": True,
            })
        except Exception as recovery_exc:
            errors.append(f"{logical_name}: {recovery_exc}")

    state["recoveryDiscoveredObjects"] = copy.deepcopy(recovered)
    begin_rollback = getattr(kube, "begin_rollback", None)
    if callable(begin_rollback):
        begin_rollback()
    rollback = _rollback(
        plan,
        kube=kube,
        policy_module=policy_module,
        nonce=nonce,
        created=recovered,
        before=before,
        initial_errors=errors,
    )
    state["rollback"] = rollback
    state["status"] = "recovered-rolled-back" if rollback["status"] == "complete" else "recovery-incomplete"
    _journal(state, state["status"])
    sink.commit(state)
    return state
