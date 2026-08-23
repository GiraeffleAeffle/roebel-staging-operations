#!/usr/bin/env python3
"""Verify the inert, closed-world Stadtstack recovery composition contract.

This verifier is deliberately data-only.  It does not contact Kubernetes,
Flux, an object store, a database, a signer, or any runtime Secret.  The
contract records the exact future recovery ceremony while every live fact is
still absent.  It therefore cannot itself activate, restore, reconcile, or
publish anything.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


CONTRACT_RELATIVE_PATH = Path("contracts/stadtstack-case-recovery-composition-contract.json")

SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
KUBE_UID = UUID
IDENTIFIER = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")

PROTOCOLS = {
    "shutdownSeal": {
        "schemaVersion": "case_shutdown_seal_v2",
        "canonicalEncoding": "canonical-json",
        "mode": "0600",
    },
    "recoveryAttestation": {
        "schemaVersion": "staging_case_recovery_attestation_v2",
        "canonicalEncoding": "canonical-json",
    },
    "recoveryGate": {
        "schemaVersion": "staging_case_recovery_gate_v2",
        "capability": "opaque-data-free-gate",
    },
    "deploymentClaim": {
        "schemaVersion": "case_durable_deployment_claim_v1",
        "canonicalEncoding": "canonical-json",
    },
    "bootstrap": {
        "schemaVersion": "case_store_bootstrap_v1",
        "canonicalEncoding": "canonical-json",
    },
    "openEpoch": {
        "schemaVersion": "case_open_epoch_v1",
        "canonicalEncoding": "canonical-json",
    },
    "recoveryMarker": {
        "schemaVersion": "case_recovery_activation_v2",
        "canonicalEncoding": "canonical-json",
    },
}

STAGE_ORDER = (
    "source_quiesce",
    "encrypted_bundle",
    "fresh_target",
    "isolated_restore_verifier",
    "restored_slots",
    "flux_handoff",
)

STAGE_PROTOCOL_REFS = {
    "source_quiesce": ["shutdownSeal", "deploymentClaim", "recoveryGate"],
    "encrypted_bundle": ["deploymentClaim", "shutdownSeal", "recoveryAttestation"],
    "fresh_target": ["deploymentClaim", "recoveryAttestation"],
    "isolated_restore_verifier": ["recoveryGate", "recoveryAttestation", "recoveryMarker", "bootstrap", "openEpoch"],
    "restored_slots": ["deploymentClaim", "recoveryAttestation"],
    "flux_handoff": ["recoveryGate", "recoveryAttestation", "deploymentClaim", "shutdownSeal"],
}

FORBIDDEN_KEYS = {
    "apiVersion",
    "kind",
    "metadata",
    "spec",
    "data",
    "stringData",
    "binaryData",
    "containers",
    "volumes",
    "volumeMounts",
    "serviceAccountName",
    "roleRef",
    "subjects",
    "rules",
    "resourceNames",
    "resources",
    "verbs",
    "kustomization",
    "helmRelease",
    "gitRepository",
    "sourceRef",
    "secretRef",
}

FORBIDDEN_SECRET_KEYS = {
    "credential",
    "credentials",
    "token",
    "password",
    "privateKey",
    "apiKey",
    "clientSecret",
    "authorization",
    "accessKey",
    "secretKey",
}

SECRET_PATTERNS = (
    "BEGIN PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "AGE-SECRET-KEY-",
    "ghp_",
    "github_pat_",
    "Bearer ",
)


class VerificationError(RuntimeError):
    """Raised when a candidate contract is not admitted."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(value, dict):
        raise VerificationError("contract root must be an object")
    return value


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _closed(value: Any, keys: set[str], path: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{path} must be an object")
    _require(set(value) == keys, f"{path} keys mismatch")
    return value


def _null_paths(value: Any, prefix: str = "") -> list[str]:
    if value is None:
        return [prefix]
    if isinstance(value, dict):
        paths: list[str] = []
        for key, child in value.items():
            child_prefix = f"{prefix}.{key}" if prefix else key
            paths.extend(_null_paths(child, child_prefix))
        return paths
    if isinstance(value, list):
        paths: list[str] = []
        for index, child in enumerate(value):
            paths.extend(_null_paths(child, f"{prefix}[{index}]"))
        return paths
    return []


def _scan_forbidden(value: Any, path: str = "contract") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in FORBIDDEN_KEYS:
                raise VerificationError(f"forbidden resource field: {path}.{key}")
            if key in FORBIDDEN_SECRET_KEYS:
                raise VerificationError(f"forbidden secret field: {path}.{key}")
            _scan_forbidden(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _scan_forbidden(child, f"{path}[{index}]")
    elif isinstance(value, str):
        for marker in SECRET_PATTERNS:
            if marker in value:
                raise VerificationError(f"forbidden secret-shaped value at {path}")


def _optional_checksum(value: Any, path: str) -> None:
    if value is not None:
        _require(isinstance(value, str) and SHA256.fullmatch(value) is not None, f"{path} format invalid")
        raise VerificationError(f"{path} must remain null in inert_review_only mode")


def _optional_uid(value: Any, path: str) -> None:
    if value is not None:
        _require(isinstance(value, str) and KUBE_UID.fullmatch(value) is not None, f"{path} format invalid")
        raise VerificationError(f"{path} must remain null in inert_review_only mode")


def _optional_identifier(value: Any, path: str) -> None:
    if value is not None:
        _require(isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None, f"{path} format invalid")
        raise VerificationError(f"{path} must remain null in inert_review_only mode")


def _optional_positive_integer(value: Any, path: str) -> None:
    if value is not None:
        _require(isinstance(value, int) and not isinstance(value, bool) and value > 0, f"{path} format invalid")
        raise VerificationError(f"{path} must remain null in inert_review_only mode")


def _verify_pvc(value: Any, path: str) -> None:
    pvc = _closed(value, {"namespace", "name", "uid"}, path)
    _optional_identifier(pvc["namespace"], f"{path}.namespace")
    _optional_identifier(pvc["name"], f"{path}.name")
    _optional_uid(pvc["uid"], f"{path}.uid")


def _verify_protocols(value: Any) -> None:
    protocols = _closed(value, set(PROTOCOLS), "protocols")
    for name, expected in PROTOCOLS.items():
        _require(protocols[name] == expected, f"protocols.{name} drift")


def _verify_stage(value: Any, index: int) -> None:
    stage = _closed(value, {"stage", "status", "protocolRefs", "requirements"} | ({"evidence"} if STAGE_ORDER[index] in {"source_quiesce", "isolated_restore_verifier"} else set()) | ({"bundle"} if STAGE_ORDER[index] == "encrypted_bundle" else set()) | ({"target"} if STAGE_ORDER[index] == "fresh_target" else set()) | ({"slots"} if STAGE_ORDER[index] == "restored_slots" else set()) | ({"handoffReceipt"} if STAGE_ORDER[index] == "flux_handoff" else set()), f"stages[{index}]")
    expected_name = STAGE_ORDER[index]
    _require(stage["stage"] == expected_name, f"stages[{index}].stage order invalid")
    _require(stage["status"] == "inert_review_only", f"stages[{index}].status invalid")
    _require(stage["protocolRefs"] == STAGE_PROTOCOL_REFS[expected_name], f"stages[{index}].protocolRefs drift")
    _require(isinstance(stage["requirements"], dict), f"stages[{index}].requirements must be an object")
    _require(all(isinstance(item, bool) or isinstance(item, str) for item in stage["requirements"].values()), f"stages[{index}].requirements format invalid")

    if expected_name == "source_quiesce":
        _closed(stage["evidence"], {"sourceClaimChecksum", "sourcePvcUid", "sourcePvName", "sourceSealChecksum", "quiesceReceiptChecksum"}, f"stages[{index}].evidence")
        _optional_checksum(stage["evidence"]["sourceClaimChecksum"], f"stages[{index}].evidence.sourceClaimChecksum")
        _optional_uid(stage["evidence"]["sourcePvcUid"], f"stages[{index}].evidence.sourcePvcUid")
        _optional_identifier(stage["evidence"]["sourcePvName"], f"stages[{index}].evidence.sourcePvName")
        _optional_checksum(stage["evidence"]["sourceSealChecksum"], f"stages[{index}].evidence.sourceSealChecksum")
        _optional_checksum(stage["evidence"]["quiesceReceiptChecksum"], f"stages[{index}].evidence.quiesceReceiptChecksum")
    elif expected_name == "encrypted_bundle":
        bundle = _closed(stage["bundle"], {"database", "sourceClaim", "sourceSeal", "encryptedManifest", "bundleChecksum"}, f"stages[{index}].bundle")
        database = _closed(bundle["database"], {"encoding", "basename", "byteLength", "sha256"}, f"stages[{index}].bundle.database")
        _require(database["encoding"] == "exact-sqlite-bytes", f"stages[{index}].bundle.database.encoding drift")
        _optional_identifier(database["basename"], f"stages[{index}].bundle.database.basename")
        _optional_positive_integer(database["byteLength"], f"stages[{index}].bundle.database.byteLength")
        _optional_checksum(database["sha256"], f"stages[{index}].bundle.database.sha256")
        source_claim = _closed(bundle["sourceClaim"], {"schemaVersion", "encoding", "claimChecksum"}, f"stages[{index}].bundle.sourceClaim")
        _require(source_claim == {"schemaVersion": "case_durable_deployment_claim_v1", "encoding": "canonical-json", "claimChecksum": source_claim["claimChecksum"]}, f"stages[{index}].bundle.sourceClaim drift")
        _optional_checksum(source_claim["claimChecksum"], f"stages[{index}].bundle.sourceClaim.claimChecksum")
        source_seal = _closed(bundle["sourceSeal"], {"schemaVersion", "encoding", "mode", "sealChecksum"}, f"stages[{index}].bundle.sourceSeal")
        _require(source_seal["schemaVersion"] == "case_shutdown_seal_v2" and source_seal["encoding"] == "canonical-json" and source_seal["mode"] == "0600", f"stages[{index}].bundle.sourceSeal drift")
        _optional_checksum(source_seal["sealChecksum"], f"stages[{index}].bundle.sourceSeal.sealChecksum")
        manifest = _closed(bundle["encryptedManifest"], {"locator", "manifestChecksum"}, f"stages[{index}].bundle.encryptedManifest")
        locator = _closed(manifest["locator"], {"bucket", "key", "objectVersion", "checksum", "keyVersion"}, f"stages[{index}].bundle.encryptedManifest.locator")
        for field in ("bucket", "key", "objectVersion", "keyVersion"):
            _require(locator[field] is None, f"stages[{index}].bundle.encryptedManifest.locator.{field} must remain null")
        _optional_checksum(locator["checksum"], f"stages[{index}].bundle.encryptedManifest.locator.checksum")
        _optional_checksum(manifest["manifestChecksum"], f"stages[{index}].bundle.encryptedManifest.manifestChecksum")
        _optional_checksum(bundle["bundleChecksum"], f"stages[{index}].bundle.bundleChecksum")
    elif expected_name == "fresh_target":
        target = _closed(stage["target"], {"deploymentClaim"}, f"stages[{index}].target")
        claim = _closed(target["deploymentClaim"], {"schemaVersion", "claimChecksum", "releaseDigest", "controlDeploymentBindingChecksum", "pvc", "pvName", "storageClass"}, f"stages[{index}].target.deploymentClaim")
        _require(claim["schemaVersion"] == "case_durable_deployment_claim_v1", f"stages[{index}].target.deploymentClaim.schemaVersion drift")
        _optional_checksum(claim["claimChecksum"], f"stages[{index}].target.deploymentClaim.claimChecksum")
        _optional_checksum(claim["releaseDigest"], f"stages[{index}].target.deploymentClaim.releaseDigest")
        _optional_checksum(claim["controlDeploymentBindingChecksum"], f"stages[{index}].target.deploymentClaim.controlDeploymentBindingChecksum")
        _verify_pvc(claim["pvc"], f"stages[{index}].target.deploymentClaim.pvc")
        _optional_identifier(claim["pvName"], f"stages[{index}].target.deploymentClaim.pvName")
        _optional_identifier(claim["storageClass"], f"stages[{index}].target.deploymentClaim.storageClass")
    elif expected_name == "isolated_restore_verifier":
        evidence = _closed(stage["evidence"], {"recoveryGateChecksum", "recoveryAttestationChecksum", "restoreReportChecksum", "recoveryMarkerChecksum", "bootstrapChecksum", "openEpochChecksum", "verifiedDatabaseSha256", "verifiedSchemaChecksum"}, f"stages[{index}].evidence")
        for field in evidence:
            _optional_checksum(evidence[field], f"stages[{index}].evidence.{field}")
    elif expected_name == "restored_slots":
        slots = _closed(stage["slots"], {"control", "public"}, f"stages[{index}].slots")
        for slot_name in ("control", "public"):
            slot = _closed(slots[slot_name], {"targetClaimChecksum", "targetPvcUid", "targetPvName", "releaseDigest", "referenceChecksum"}, f"stages[{index}].slots.{slot_name}")
            _optional_checksum(slot["targetClaimChecksum"], f"stages[{index}].slots.{slot_name}.targetClaimChecksum")
            _optional_uid(slot["targetPvcUid"], f"stages[{index}].slots.{slot_name}.targetPvcUid")
            _optional_identifier(slot["targetPvName"], f"stages[{index}].slots.{slot_name}.targetPvName")
            _optional_checksum(slot["releaseDigest"], f"stages[{index}].slots.{slot_name}.releaseDigest")
            _optional_checksum(slot["referenceChecksum"], f"stages[{index}].slots.{slot_name}.referenceChecksum")
    else:
        receipt = _closed(stage["handoffReceipt"], {"schemaVersion", "status", "targetClaimChecksum", "targetPvcUid", "targetPvName", "releaseDigest", "recoveryAttestationChecksum", "receiptChecksum"}, f"stages[{index}].handoffReceipt")
        _require(receipt["schemaVersion"] == "stadtstack_case_recovery_handoff_receipt_v1", f"stages[{index}].handoffReceipt.schemaVersion drift")
        _require(receipt["status"] == "inert_review_only", f"stages[{index}].handoffReceipt.status invalid")
        _optional_checksum(receipt["targetClaimChecksum"], f"stages[{index}].handoffReceipt.targetClaimChecksum")
        _optional_uid(receipt["targetPvcUid"], f"stages[{index}].handoffReceipt.targetPvcUid")
        _optional_identifier(receipt["targetPvName"], f"stages[{index}].handoffReceipt.targetPvName")
        _optional_checksum(receipt["releaseDigest"], f"stages[{index}].handoffReceipt.releaseDigest")
        _optional_checksum(receipt["recoveryAttestationChecksum"], f"stages[{index}].handoffReceipt.recoveryAttestationChecksum")
        _optional_checksum(receipt["receiptChecksum"], f"stages[{index}].handoffReceipt.receiptChecksum")


def _verify_live_evidence(value: Any) -> None:
    live = _closed(value, {"source", "bundle", "target", "restore", "slots", "fluxHandoff"}, "liveEvidence")
    source = _closed(live["source"], {"claimChecksum", "pvc", "pvName", "releaseDigest", "sealChecksum"}, "liveEvidence.source")
    _optional_checksum(source["claimChecksum"], "liveEvidence.source.claimChecksum")
    _verify_pvc(source["pvc"], "liveEvidence.source.pvc")
    _optional_identifier(source["pvName"], "liveEvidence.source.pvName")
    _optional_checksum(source["releaseDigest"], "liveEvidence.source.releaseDigest")
    _optional_checksum(source["sealChecksum"], "liveEvidence.source.sealChecksum")
    bundle = _closed(live["bundle"], {"databaseBasename", "databaseByteLength", "databaseSha256", "sourceClaimChecksum", "sourceSealChecksum", "locatorChecksum", "bundleChecksum"}, "liveEvidence.bundle")
    _optional_identifier(bundle["databaseBasename"], "liveEvidence.bundle.databaseBasename")
    _optional_positive_integer(bundle["databaseByteLength"], "liveEvidence.bundle.databaseByteLength")
    for field in ("databaseSha256", "sourceClaimChecksum", "sourceSealChecksum", "locatorChecksum", "bundleChecksum"):
        _optional_checksum(bundle[field], f"liveEvidence.bundle.{field}")
    target = _closed(live["target"], {"claimChecksum", "pvc", "pvName", "storageClass", "releaseDigest"}, "liveEvidence.target")
    _optional_checksum(target["claimChecksum"], "liveEvidence.target.claimChecksum")
    _verify_pvc(target["pvc"], "liveEvidence.target.pvc")
    _optional_identifier(target["pvName"], "liveEvidence.target.pvName")
    _optional_identifier(target["storageClass"], "liveEvidence.target.storageClass")
    _optional_checksum(target["releaseDigest"], "liveEvidence.target.releaseDigest")
    restore = _closed(live["restore"], {"recoveryGateChecksum", "recoveryAttestationChecksum", "restoreReportChecksum", "recoveryMarkerChecksum", "bootstrapChecksum", "openEpochChecksum", "databaseSha256", "schemaChecksum"}, "liveEvidence.restore")
    for field in restore:
        _optional_checksum(restore[field], f"liveEvidence.restore.{field}")
    slots = _closed(live["slots"], {"controlReferenceChecksum", "publicReferenceChecksum"}, "liveEvidence.slots")
    _optional_checksum(slots["controlReferenceChecksum"], "liveEvidence.slots.controlReferenceChecksum")
    _optional_checksum(slots["publicReferenceChecksum"], "liveEvidence.slots.publicReferenceChecksum")
    handoff = _closed(live["fluxHandoff"], {"receiptChecksum"}, "liveEvidence.fluxHandoff")
    _optional_checksum(handoff["receiptChecksum"], "liveEvidence.fluxHandoff.receiptChecksum")
    if source["pvc"]["uid"] is not None and target["pvc"]["uid"] is not None:
        _require(source["pvc"]["uid"] != target["pvc"]["uid"], "source and target PVC UID must be distinct")


def _verify_cross_bindings(contract: dict[str, Any]) -> None:
    stages = {stage["stage"]: stage for stage in contract["stages"]}
    live = contract["liveEvidence"]
    source = stages["source_quiesce"]["evidence"]
    _require(source["sourceClaimChecksum"] == live["source"]["claimChecksum"], "source claim checksum binding drift")
    _require(source["sourcePvcUid"] == live["source"]["pvc"]["uid"], "source PVC binding drift")
    _require(source["sourcePvName"] == live["source"]["pvName"], "source PV binding drift")
    _require(source["sourceSealChecksum"] == live["source"]["sealChecksum"], "source seal binding drift")

    bundle = stages["encrypted_bundle"]["bundle"]
    _require(bundle["database"]["sha256"] == live["bundle"]["databaseSha256"], "bundle database checksum binding drift")
    _require(bundle["sourceClaim"]["claimChecksum"] == live["bundle"]["sourceClaimChecksum"], "bundle source claim binding drift")
    _require(bundle["sourceSeal"]["sealChecksum"] == live["bundle"]["sourceSealChecksum"], "bundle source seal binding drift")
    _require(bundle["encryptedManifest"]["locator"]["checksum"] == live["bundle"]["locatorChecksum"], "bundle locator binding drift")
    _require(bundle["bundleChecksum"] == live["bundle"]["bundleChecksum"], "bundle checksum binding drift")
    _require(bundle["sourceClaim"]["claimChecksum"] == live["source"]["claimChecksum"], "bundle must contain exact source claim")
    _require(bundle["sourceSeal"]["sealChecksum"] == live["source"]["sealChecksum"], "bundle must contain exact source seal")

    target = stages["fresh_target"]["target"]["deploymentClaim"]
    _require(target["claimChecksum"] == live["target"]["claimChecksum"], "target claim checksum binding drift")
    _require(target["pvc"] == live["target"]["pvc"], "target PVC binding drift")
    _require(target["pvName"] == live["target"]["pvName"], "target PV binding drift")
    _require(target["storageClass"] == live["target"]["storageClass"], "target StorageClass binding drift")
    _require(target["releaseDigest"] == live["target"]["releaseDigest"], "target release binding drift")

    restore = stages["isolated_restore_verifier"]["evidence"]
    for field in ("recoveryGateChecksum", "recoveryAttestationChecksum", "restoreReportChecksum", "recoveryMarkerChecksum", "bootstrapChecksum", "openEpochChecksum"):
        _require(restore[field] == live["restore"][field], f"restore {field} binding drift")
    _require(restore["verifiedDatabaseSha256"] == live["restore"]["databaseSha256"], "restore database binding drift")
    _require(restore["verifiedSchemaChecksum"] == live["restore"]["schemaChecksum"], "restore schema binding drift")
    slots = stages["restored_slots"]["slots"]
    _require(slots["control"]["referenceChecksum"] == live["slots"]["controlReferenceChecksum"], "control slot binding drift")
    _require(slots["public"]["referenceChecksum"] == live["slots"]["publicReferenceChecksum"], "public slot binding drift")
    for slot_name in ("control", "public"):
        _require(slots[slot_name]["targetClaimChecksum"] == live["target"]["claimChecksum"], f"{slot_name} slot target claim binding drift")
        _require(slots[slot_name]["targetPvcUid"] == live["target"]["pvc"]["uid"], f"{slot_name} slot target PVC binding drift")
        _require(slots[slot_name]["targetPvName"] == live["target"]["pvName"], f"{slot_name} slot target PV binding drift")
        _require(slots[slot_name]["releaseDigest"] == live["target"]["releaseDigest"], f"{slot_name} slot release binding drift")
    receipt = stages["flux_handoff"]["handoffReceipt"]
    _require(receipt["receiptChecksum"] == live["fluxHandoff"]["receiptChecksum"], "handoff receipt binding drift")
    _require(receipt["targetClaimChecksum"] == live["target"]["claimChecksum"], "handoff target claim binding drift")
    _require(receipt["targetPvcUid"] == live["target"]["pvc"]["uid"], "handoff target PVC binding drift")
    _require(receipt["targetPvName"] == live["target"]["pvName"], "handoff target PV binding drift")
    _require(receipt["releaseDigest"] == live["target"]["releaseDigest"], "handoff release binding drift")
    _require(receipt["recoveryAttestationChecksum"] == live["restore"]["recoveryAttestationChecksum"], "handoff attestation binding drift")


def verify_contract(root: Path) -> list[str]:
    try:
        contract = load_json(root / CONTRACT_RELATIVE_PATH)
        _scan_forbidden(contract)
        _closed(
            contract,
            {
                "schemaVersion", "mode", "status", "deploymentEnvironment", "municipalityId",
                "reconciliationAllowed", "fluxHandoffAllowed", "allowedKinds", "forbiddenResources",
                "forbiddenSecrets", "protocols", "stages", "liveEvidence", "effects", "missingEvidence",
            },
            "contract",
        )
        _require(contract["schemaVersion"] == "stadtstack_case_recovery_composition_contract_v2", "schemaVersion drift")
        _require(contract["mode"] == "inert_review_only" and contract["status"] == "inert_review_only", "contract must remain inert_review_only")
        _require(contract["deploymentEnvironment"] == "staging" and contract["municipalityId"] == "roebel-mueritz", "scope drift")
        _require(contract["reconciliationAllowed"] is False and contract["fluxHandoffAllowed"] is False, "activation flags must remain false")
        _require(contract["allowedKinds"] == [], "allowedKinds must remain empty")
        _require(contract["forbiddenResources"] == {"documents": [], "apiVersions": [], "kinds": [], "kubernetesObjects": [], "fluxObjects": []}, "forbidden resource inventory must remain empty")
        _require(contract["forbiddenSecrets"] == {"credentialValues": [], "secretObjects": [], "secretReferences": []}, "forbidden secret inventory must remain empty")
        _verify_protocols(contract["protocols"])
        _require(isinstance(contract["stages"], list) and len(contract["stages"]) == len(STAGE_ORDER), "stage count invalid")
        for index, stage in enumerate(contract["stages"]):
            _verify_stage(stage, index)
        _verify_live_evidence(contract["liveEvidence"])
        _verify_cross_bindings(contract)
        _require(contract["effects"] == {"secretRead": False, "secretWrite": False, "clusterMutation": False, "civicMutation": False, "treasuryMutation": False, "fluxReconciliation": False}, "effects must remain false")
        expected_missing = _null_paths({key: value for key, value in contract.items() if key != "missingEvidence"})
        _require(contract["missingEvidence"] == expected_missing, "missingEvidence does not exactly enumerate null evidence")
        return []
    except (OSError, json.JSONDecodeError, KeyError, TypeError, VerificationError) as error:
        return [str(error)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args()
    errors = verify_contract(args.root.resolve())
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("OK: inert Stadtstack case recovery composition contract is closed and review-only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
