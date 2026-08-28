"""Pure, GET-only bridge for one archived dormant Participant receipt.

The live runner supplies Git-verified plans and a deliberately tiny Kubernetes
adapter exposing only ``get_exact``.  This module never opens a kubeconfig,
invokes a command, reads a Secret, or mutates cluster state.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any, Callable


ARCHIVE_REVISION = "08c4171573bb138845a9160e747f6ac56a3c754e"
HANDOVER_RECEIPT_SCHEMA = "roebel_staging_participant_dormant_receipt_handover_v1"
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
MAX_RECEIPT_BYTES = 1024 * 1024


class HandoverError(RuntimeError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise HandoverError(message)


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def bytes_sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _json_object(raw: bytes, label: str) -> dict[str, Any]:
    _require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_RECEIPT_BYTES, f"{label} size invalid")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HandoverError(f"{label} must be UTF-8 JSON") from exc

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            _require(key not in result, f"{label} contains duplicate JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(text, object_pairs_hook=pairs)
    except json.JSONDecodeError as exc:
        raise HandoverError(f"{label} is not JSON") from exc
    _require(isinstance(value, dict), f"{label} must be an object")
    return value


def _closed_payload(value: dict[str, Any], label: str) -> tuple[dict[str, Any], str]:
    payload = copy.deepcopy(value)
    checksum = payload.pop("canonicalSha256", None)
    _require(isinstance(checksum, str) and SHA256.fullmatch(checksum) is not None, f"{label} checksum invalid")
    _require(canonical_sha256(payload) == checksum, f"{label} checksum mismatch")
    encoded = canonical(payload).lower()
    _require(
        not any(token in encoded for token in ('"data"', '"stringdata"', '"token"', '"password"', '"privatekey"')),
        f"{label} contains secret-shaped material",
    )
    return payload, checksum


def _plan_projection(plan: dict[str, Any]) -> dict[str, Any]:
    objects = plan.get("objects")
    _require(isinstance(objects, list) and len(objects) == 8, "participant plan must contain eight objects")
    projected: list[dict[str, Any]] = []
    seen_logical: set[str] = set()
    seen_targets: set[tuple[str, str, str, str]] = set()
    for item in objects:
        _require(
            isinstance(item, dict)
            and isinstance(item.get("logicalName"), str)
            and isinstance(item.get("target"), dict)
            and isinstance(item.get("desiredSemanticSha256"), str)
            and SHA256.fullmatch(item["desiredSemanticSha256"]) is not None,
            "participant plan object invalid",
        )
        target = item["target"]
        _require(set(target) == {"apiVersion", "kind", "namespace", "name"}, "participant plan target is not closed")
        _require(all(isinstance(target[key], str) and target[key] for key in target), "participant plan target is invalid")
        target_key = (target["apiVersion"], target["kind"], target["namespace"], target["name"])
        _require(item["logicalName"] not in seen_logical, "participant plan logical name is duplicated")
        _require(target_key not in seen_targets, "participant plan target is duplicated")
        seen_logical.add(item["logicalName"])
        seen_targets.add(target_key)
        projected.append({
            "logicalName": item["logicalName"],
            "target": {key: target[key] for key in ("apiVersion", "kind", "namespace", "name")},
            "desiredSemanticSha256": item["desiredSemanticSha256"],
        })
    policy_sha = plan.get("activationPolicySha256")
    _require(isinstance(policy_sha, str) and SHA256.fullmatch(policy_sha) is not None, "participant policy checksum invalid")
    return {"activationPolicySha256": policy_sha, "objects": projected}


def _current_compatibility_drift_is_explicitly_bound(contract: dict[str, Any]) -> bool:
    """Allow unrelated current files only under the reviewed contract flag."""
    boundary = contract.get("stagingParticipantGatewayBoundary", contract)
    return isinstance(boundary, dict) and boundary.get("archivedDormantReceiptHandover", {}).get(
        "currentCompatibility",
    ) == "ordered-eight-object-plan-only"


def _normalized_archived_receipt(
    receipt: dict[str, Any],
    archived_plan: dict[str, Any],
    archived_projection: dict[str, Any],
) -> dict[str, Any]:
    """Normalize only a v1 receipt accepted by its historical protected binder."""
    _require(receipt.get("protectedRevision") == ARCHIVE_REVISION, "archived receipt revision drift")
    _require(receipt.get("status") == "dormant-ready", "archived receipt is not dormant-ready")
    _require(
        isinstance(archived_projection, dict)
        and archived_projection.get("status") == "dormant-ready"
        and archived_projection.get("protectedRevision") == ARCHIVE_REVISION,
        "archived binder projection invalid",
    )
    objects = archived_projection.get("objects")
    preflight = receipt.get("preflight")
    postconditions = receipt.get("postconditions")
    _require(isinstance(preflight, dict) and isinstance(postconditions, dict), "archived v1 receipt proofs absent")
    source = preflight.get("sharedSource")
    preservation = preflight.get("preservation")
    final_checks = postconditions.get("finalChecks")
    _require(
        isinstance(source, dict)
        and isinstance(preservation, dict)
        and isinstance(final_checks, dict)
        and final_checks.get("sharedSource", {}).get("uid") == source.get("uid")
        and isinstance(final_checks.get("preservation"), dict),
        "archived v1 final proof drift",
    )
    normalized_preservation: dict[str, Any] = {}
    for label, before in preservation.items():
        after = final_checks["preservation"].get(label)
        _require(
            isinstance(before, dict)
            and isinstance(after, dict)
            and before.get("target") == after.get("target")
            and before.get("beforeCanonicalSha256") == after.get("afterCanonicalSha256")
            and after.get("byteIdenticalCanonicalJson") is True,
            f"archived preservation proof drift: {label}",
        )
        normalized_preservation[label] = {
            "target": copy.deepcopy(before["target"]),
            "canonicalSha256": before["beforeCanonicalSha256"],
        }
    _require(
        isinstance(source, dict)
        and isinstance(source.get("uid"), str)
        and bool(source["uid"])
        and source.get("artifactRevision") == f"main@sha1:{ARCHIVE_REVISION}"
        and isinstance(source.get("semanticSha256"), str)
        and SHA256.fullmatch(source["semanticSha256"]) is not None,
        "archived shared source binding invalid",
    )
    _require(isinstance(objects, list) and len(objects) == 8, "archived dormant object set invalid")
    projected_plan = _plan_projection(archived_plan)["objects"]
    normalized_objects: list[dict[str, Any]] = []
    for expected, observed in zip(projected_plan, objects, strict=True):
        _require(
            isinstance(observed, dict)
            and observed.get("logicalName") == expected["logicalName"]
            and observed.get("target") == expected["target"]
            and observed.get("desiredSemanticSha256") == expected["desiredSemanticSha256"]
            and isinstance(observed.get("uid"), str)
            and bool(observed["uid"])
            and isinstance(observed.get("resourceVersion"), str)
            and observed["resourceVersion"].isdigit(),
            f"archived dormant identity invalid: {expected['logicalName']}",
        )
        normalized_objects.append(copy.deepcopy(observed))
    _require(
        isinstance(normalized_preservation, dict)
        and set(normalized_preservation) == {"webIngress", "existingWorkbenchNetworkPolicy"},
        "archived preservation set invalid",
    )
    for label, value in normalized_preservation.items():
        _require(
            isinstance(value, dict)
            and isinstance(value.get("target"), dict)
            and isinstance(value.get("canonicalSha256"), str)
            and SHA256.fullmatch(value["canonicalSha256"]) is not None,
            f"archived preservation binding invalid: {label}",
        )
    return {
        "sharedSource": {
            "uid": source["uid"],
            "artifactRevision": source["artifactRevision"],
            "semanticSha256": source.get("semanticSha256"),
        },
        "objects": normalized_objects,
        "preservation": normalized_preservation,
    }


def build_archived_binding(
    *,
    archived_receipt_raw: bytes,
    archive_revision: str,
    current_revision: str,
    archived_plan: dict[str, Any],
    current_plan: dict[str, Any],
    archived_artifacts: dict[str, str],
    current_artifacts: dict[str, str],
    archived_participant_contract: dict[str, Any],
    current_participant_contract: dict[str, Any],
    archived_projection: dict[str, Any] | None = None,
    expected_archived_raw_sha256: str | None = None,
    expected_archived_canonical_sha256: str | None = None,
) -> dict[str, Any]:
    _require(archive_revision == ARCHIVE_REVISION, "archived revision is not the protected one-time origin")
    _require(isinstance(current_revision, str) and REVISION.fullmatch(current_revision) is not None, "current revision invalid")
    _require(current_revision != ARCHIVE_REVISION, "handover revision did not advance")
    receipt = _json_object(archived_receipt_raw, "archived bootstrap receipt")
    _payload, receipt_checksum = _closed_payload(receipt, "archived bootstrap receipt")
    raw_checksum = bytes_sha256(archived_receipt_raw)
    if expected_archived_raw_sha256 is not None:
        _require(raw_checksum == expected_archived_raw_sha256, "archived receipt raw checksum drift")
    if expected_archived_canonical_sha256 is not None:
        _require(receipt_checksum == expected_archived_canonical_sha256, "archived receipt canonical checksum drift")
    archived_projection_plan = _plan_projection(archived_plan)
    current_projection_plan = _plan_projection(current_plan)
    _require(
        archived_projection_plan == current_projection_plan,
        "participant policy or eight-object plan changed across handover",
    )
    allow_current_compatibility_drift = _current_compatibility_drift_is_explicitly_bound(current_participant_contract)
    _require(
        isinstance(archived_artifacts, dict)
        and archived_artifacts
        and isinstance(current_artifacts, dict)
        and current_artifacts
        and all(isinstance(path, str) and isinstance(value, str) and SHA256.fullmatch(value) for path, value in archived_artifacts.items())
        and all(isinstance(path, str) and isinstance(value, str) and SHA256.fullmatch(value) for path, value in current_artifacts.items())
        and (archived_artifacts == current_artifacts or allow_current_compatibility_drift),
        "participant compatibility artifact drift",
    )
    _require(
        isinstance(archived_participant_contract, dict)
        and isinstance(current_participant_contract, dict)
        and bool(archived_participant_contract)
        and bool(current_participant_contract)
        and (archived_participant_contract == current_participant_contract or allow_current_compatibility_drift),
        "participant repository-contract projection drift",
    )
    _require(isinstance(archived_projection, dict), "historical archived receipt binder projection required")
    normalized = _normalized_archived_receipt(receipt, archived_plan, archived_projection)
    current_objects = current_plan.get("objects")
    _require(isinstance(current_objects, list) and len(current_objects) == 8, "current desired object set invalid")
    expected_source_semantic = current_plan.get("expectedSharedSourceSemanticSha256")
    _require(
        isinstance(expected_source_semantic, str)
        and SHA256.fullmatch(expected_source_semantic) is not None
        and normalized["sharedSource"]["semanticSha256"] == expected_source_semantic,
        "shared source semantics changed across handover",
    )
    return {
        "archivedRevision": ARCHIVE_REVISION,
        "currentRevision": current_revision,
        "activationPolicySha256": current_projection_plan["activationPolicySha256"],
        "archivedReceiptRawSha256": raw_checksum,
        "archivedReceiptCanonicalSha256": receipt_checksum,
        "compatibilityArtifacts": copy.deepcopy(dict(sorted(current_artifacts.items()))),
        "participantContractSha256": canonical_sha256(current_participant_contract),
        "sourceTarget": copy.deepcopy(current_plan["sharedSource"]),
        "expectedSharedSource": copy.deepcopy(current_plan.get("expectedSharedSource")),
        "expectedSharedSourceSemanticSha256": expected_source_semantic,
        "sharedSource": normalized["sharedSource"],
        "objects": [
            normalized["objects"][index] | {"desired": copy.deepcopy(current_objects[index]["desired"])}
            for index in range(8)
        ],
        "preservation": normalized["preservation"],
    }


def _default_semantic_equal(observed: dict[str, Any], desired: dict[str, Any], label: str) -> None:
    def normalize(value: dict[str, Any]) -> dict[str, Any]:
        result = copy.deepcopy(value)
        result.pop("status", None)
        metadata = result.get("metadata", {})
        for key in ("uid", "resourceVersion", "generation", "creationTimestamp", "managedFields"):
            metadata.pop(key, None)
        return result
    _require(normalize(observed) == normalize(desired), f"{label} semantic drift")


def _ready_source(value: dict[str, Any], binding: dict[str, Any]) -> None:
    metadata, status = value.get("metadata", {}), value.get("status", {})
    _require(metadata.get("uid") == binding["sharedSource"]["uid"], "shared source UID changed across bootstrap handover")
    _require(value.get("spec", {}).get("suspend") is not True, "shared source is suspended")
    _require(status.get("artifact", {}).get("revision") == f"main@sha1:{binding['currentRevision']}", "shared source revision drift")
    _require(status.get("observedGeneration") == metadata.get("generation"), "shared source generation not observed")
    ready = next((item for item in status.get("conditions", []) if item.get("type") == "Ready"), None)
    _require(isinstance(ready, dict) and ready.get("status") == "True", "shared source is not Ready")
    if "observedGeneration" in ready:
        _require(ready["observedGeneration"] == metadata.get("generation"), "shared source Ready generation drift")


def run_get_only_handover(
    *,
    binding: dict[str, Any],
    kube: Any,
    receipt: Any,
    cluster_binding: dict[str, Any],
    require_semantically_equal: Callable[[dict[str, Any], dict[str, Any], str], None] | None = None,
    canonical_object_sha256: Callable[[dict[str, Any]], str] | None = None,
    semantic_object_sha256: Callable[[dict[str, Any]], str] | None = None,
) -> dict[str, Any]:
    semantic_equal = require_semantically_equal or _default_semantic_equal
    def default_object_sha(value: dict[str, Any]) -> str:
        # Unit fixtures can carry a precomputed canonical identity without
        # teaching this pure module Kubernetes' full runtime metadata shape.
        fixture = value.get("spec", {}).get("canonicalSha256Fixture")
        return fixture if isinstance(fixture, str) and SHA256.fullmatch(fixture) else canonical_sha256(value)
    object_sha = canonical_object_sha256 or default_object_sha
    semantic_sha = semantic_object_sha256 or default_object_sha
    expected_cluster_fields = {
        "apiOrigin", "caCertificateSha256", "apiServerSpkiSha256",
        "kubeSystemNamespaceUid", "kubeSystemNamespaceResourceVersion",
        "credentialsIncluded", "kubeconfigPathIncluded",
    }
    _require(
        isinstance(cluster_binding, dict)
        and set(cluster_binding) == expected_cluster_fields
        and isinstance(cluster_binding.get("kubeSystemNamespaceResourceVersion"), str)
        and cluster_binding["kubeSystemNamespaceResourceVersion"].isdigit()
        and cluster_binding.get("credentialsIncluded") is False
        and cluster_binding.get("kubeconfigPathIncluded") is False,
        "protected cluster binding invalid",
    )
    source = kube.get_exact(binding["sourceTarget"])
    _ready_source(source, binding)
    expected_source = binding.get("expectedSharedSource")
    if isinstance(expected_source, dict):
        semantic_equal(source, expected_source, "shared Flux source")

    live_objects: list[dict[str, Any]] = []
    for archived in binding["objects"]:
        live = kube.get_exact(archived["target"])
        metadata = live.get("metadata", {})
        _require(metadata.get("uid") == archived["uid"], f"dormant UID drift: {archived['logicalName']}")
        resource_version = metadata.get("resourceVersion")
        _require(
            isinstance(resource_version, str)
            and resource_version.isdigit()
            and int(resource_version) >= int(archived["resourceVersion"]),
            f"dormant resourceVersion drift: {archived['logicalName']}",
        )
        semantic_equal(live, archived["desired"], f"dormant {archived['logicalName']}")
        if archived["target"]["kind"] == "Kustomization":
            _require(live.get("spec", {}).get("suspend") is True, f"dormant Kustomization unsuspended: {archived['logicalName']}")
        live_objects.append({
            "logicalName": archived["logicalName"],
            "target": copy.deepcopy(archived["target"]),
            "uid": archived["uid"],
            "resourceVersion": resource_version,
            "desiredSemanticSha256": archived["desiredSemanticSha256"],
        })

    preserved: dict[str, Any] = {}
    for label in ("webIngress", "existingWorkbenchNetworkPolicy"):
        expected = binding["preservation"][label]
        live = kube.get_exact(expected["target"])
        observed_sha = object_sha(live)
        _require(observed_sha == expected["canonicalSha256"], f"preserved object changed: {label}")
        preserved[label] = {
            "target": copy.deepcopy(expected["target"]),
            "canonicalSha256": observed_sha,
            "unchangedFromArchivedBootstrap": True,
        }

    payload = {
        "schemaVersion": HANDOVER_RECEIPT_SCHEMA,
        "status": "dormant-ready-revalidated",
        "archivedRevision": binding["archivedRevision"],
        "currentRevision": binding["currentRevision"],
        "activationPolicySha256": binding["activationPolicySha256"],
        "archivedReceipt": {
            "rawSha256": binding["archivedReceiptRawSha256"],
            "canonicalSha256": binding["archivedReceiptCanonicalSha256"],
        },
        "compatibilityArtifacts": copy.deepcopy(binding["compatibilityArtifacts"]),
        "participantContractSha256": binding["participantContractSha256"],
        "clusterBinding": copy.deepcopy(cluster_binding),
        "sharedSource": {
            "uid": binding["sharedSource"]["uid"],
            "resourceVersion": source.get("metadata", {}).get("resourceVersion"),
            "artifactRevision": f"main@sha1:{binding['currentRevision']}",
            "semanticSha256": semantic_sha(source),
        },
        "objects": live_objects,
        "bothKustomizationsSuspended": True,
        "preservation": preserved,
        "effects": {"verbs": ["GET"], "kubernetesGetCount": 12, "resourceGetCount": 11, "clusterMutationCount": 0, "secretReads": False, "civicAuthorityEffects": False},
        "civicAuthorityEffects": False,
    }
    payload["canonicalSha256"] = canonical_sha256(payload)
    receipt.commit(payload)
    return payload


def bind_handover_receipt(binding: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
    payload, checksum = _closed_payload(receipt, "dormant handover receipt")
    expected_fields = {
        "schemaVersion", "status", "archivedRevision", "currentRevision", "activationPolicySha256",
        "archivedReceipt", "compatibilityArtifacts", "participantContractSha256", "clusterBinding", "sharedSource",
        "objects", "bothKustomizationsSuspended", "preservation", "effects", "civicAuthorityEffects",
    }
    _require(set(payload) == expected_fields, "dormant handover receipt field set drift")
    _require(
        payload["schemaVersion"] == HANDOVER_RECEIPT_SCHEMA
        and payload["status"] == "dormant-ready-revalidated"
        and payload["archivedRevision"] == binding["archivedRevision"]
        and payload["currentRevision"] == binding["currentRevision"]
        and payload["activationPolicySha256"] == binding["activationPolicySha256"]
        and payload["archivedReceipt"] == {
            "rawSha256": binding["archivedReceiptRawSha256"],
            "canonicalSha256": binding["archivedReceiptCanonicalSha256"],
        }
        and payload["compatibilityArtifacts"] == binding["compatibilityArtifacts"]
        and payload["participantContractSha256"] == binding["participantContractSha256"]
        and payload["bothKustomizationsSuspended"] is True
        and payload["effects"] == {"verbs": ["GET"], "kubernetesGetCount": 12, "resourceGetCount": 11, "clusterMutationCount": 0, "secretReads": False, "civicAuthorityEffects": False}
        and payload["civicAuthorityEffects"] is False,
        "dormant handover receipt provenance drift",
    )
    expected_objects = binding["objects"]
    _require(isinstance(payload["objects"], list) and len(payload["objects"]) == len(expected_objects), "handover object set drift")
    seen_uids: set[str] = set()
    seen_targets: set[tuple[str, str, str, str]] = set()
    for expected, observed in zip(expected_objects, payload["objects"], strict=True):
        _require(
            isinstance(observed, dict)
            and set(observed) == {"logicalName", "target", "uid", "resourceVersion", "desiredSemanticSha256"}
            and observed.get("logicalName") == expected["logicalName"]
            and observed.get("target") == expected["target"]
            and observed.get("uid") == expected["uid"]
            and observed.get("desiredSemanticSha256") == expected["desiredSemanticSha256"]
            and isinstance(observed.get("resourceVersion"), str)
            and observed["resourceVersion"].isdigit()
            and int(observed["resourceVersion"]) >= int(expected["resourceVersion"]),
            f"handover object identity drift: {expected['logicalName']}",
        )
        target_value = observed["target"]
        target_key = tuple(target_value[key] for key in ("apiVersion", "kind", "namespace", "name"))
        _require(observed["uid"] not in seen_uids, "handover object UID is duplicated")
        _require(target_key not in seen_targets, "handover object target is duplicated")
        seen_uids.add(observed["uid"])
        seen_targets.add(target_key)
    source = payload["sharedSource"]
    _require(
        isinstance(source, dict)
        and set(source) == {"uid", "resourceVersion", "artifactRevision", "semanticSha256"}
        and source.get("uid") == binding["sharedSource"]["uid"]
        and isinstance(source.get("resourceVersion"), str)
        and source["resourceVersion"].isdigit()
        and payload["sharedSource"].get("artifactRevision") == f"main@sha1:{binding['currentRevision']}"
        and payload["sharedSource"].get("semanticSha256") == binding["expectedSharedSourceSemanticSha256"]
        and isinstance(payload["clusterBinding"], dict)
        and set(payload["clusterBinding"]) == {
            "apiOrigin", "caCertificateSha256", "apiServerSpkiSha256",
            "kubeSystemNamespaceUid", "kubeSystemNamespaceResourceVersion",
            "credentialsIncluded", "kubeconfigPathIncluded",
        }
        and isinstance(payload["clusterBinding"].get("kubeSystemNamespaceResourceVersion"), str)
        and payload["clusterBinding"]["kubeSystemNamespaceResourceVersion"].isdigit()
        and payload["clusterBinding"].get("credentialsIncluded") is False
        and payload["clusterBinding"].get("kubeconfigPathIncluded") is False
        and set(payload["preservation"]) == set(binding["preservation"])
        and all(
            isinstance(payload["preservation"][label], dict)
            and set(payload["preservation"][label]) == {"target", "canonicalSha256", "unchangedFromArchivedBootstrap"}
            and payload["preservation"][label].get("target") == binding["preservation"][label]["target"]
            and payload["preservation"][label].get("canonicalSha256") == binding["preservation"][label]["canonicalSha256"]
            and payload["preservation"][label].get("unchangedFromArchivedBootstrap") is True
            for label in binding["preservation"]
        ),
        "handover source or preservation drift",
    )
    return {
        "status": "dormant-ready",
        "receiptSha256": checksum,
        "receiptProvenance": {
            "mode": "archived-v1+get-only-handover",
            "archivedRawSha256": payload["archivedReceipt"]["rawSha256"],
            "archivedCanonicalSha256": payload["archivedReceipt"]["canonicalSha256"],
            "handoverCanonicalSha256": checksum,
            "handoverEffects": copy.deepcopy(payload["effects"]),
        },
        "protectedRevision": binding["currentRevision"],
        "activationPolicySha256": binding["activationPolicySha256"],
        "clusterBinding": copy.deepcopy(payload["clusterBinding"]),
        "sharedSource": copy.deepcopy(payload["sharedSource"]),
        "objects": copy.deepcopy(payload["objects"]),
        "preservation": {
            label: {
                "target": copy.deepcopy(value["target"]),
                "canonicalSha256": value["canonicalSha256"],
            }
            for label, value in payload["preservation"].items()
        },
        "bothKustomizationsSuspended": True,
        "handover": copy.deepcopy(payload["archivedReceipt"]),
        "civicAuthorityEffects": False,
    }


class ReceiptSink:
    def __init__(self, path: Path, device: int, inode: int):
        self.path, self.device, self.inode = path, device, inode

    @classmethod
    def reserve(cls, path: Path) -> "ReceiptSink":
        selected = Path(os.path.abspath(path))
        parent = selected.parent.resolve()
        info = os.lstat(parent)
        _require(
            selected.parent == parent
            and stat.S_ISDIR(info.st_mode)
            and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) & 0o022 == 0,
            "receipt parent must be private and owned",
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(selected, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.fsync(fd)
            created = os.fstat(fd)
        finally:
            os.close(fd)
        parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        return cls(selected, created.st_dev, created.st_ino)

    def commit(self, value: dict[str, Any]) -> None:
        current = os.lstat(self.path)
        _require(
            stat.S_ISREG(current.st_mode)
            and not self.path.is_symlink()
            and current.st_uid == os.geteuid()
            and current.st_nlink == 1
            and stat.S_IMODE(current.st_mode) == 0o600
            and (current.st_dev, current.st_ino) == (self.device, self.inode),
            "reserved handover receipt identity changed",
        )
        raw = (canonical(value) + "\n").encode("utf-8")
        _require(len(raw) <= MAX_RECEIPT_BYTES, "handover receipt exceeds size bound")
        fd, temporary = tempfile.mkstemp(prefix=".participant-handover-", dir=self.path.parent)
        try:
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(raw):
                written = os.write(fd, raw[offset:])
                _require(written > 0, "handover receipt write made no progress")
                offset += written
            os.fsync(fd)
            os.close(fd)
            fd = -1
            os.replace(temporary, self.path)
            committed = os.lstat(self.path)
            _require(
                stat.S_ISREG(committed.st_mode)
                and committed.st_uid == os.geteuid()
                and committed.st_nlink == 1
                and stat.S_IMODE(committed.st_mode) == 0o600,
                "committed handover receipt metadata drift",
            )
            parent_fd = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            self.device, self.inode = committed.st_dev, committed.st_ino
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
