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
from datetime import datetime
from pathlib import Path
from typing import Any


CONTRACT_RELATIVE_PATH = Path("contracts/stadtstack-case-recovery-composition-contract.json")
IMAGE_RESOURCE_INVENTORY_RELATIVE_PATH = Path("contracts/stadtstack-case-image-resource-inventory-contract.json")

SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
KUBE_UID = UUID
IDENTIFIER = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")

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
    "recoveryPolicy": {
        "schemaVersion": "staging_case_recovery_policy_v1",
        "canonicalEncoding": "canonical-json",
    },
    "backupCatalog": {
        "schemaVersion": "case_backup_catalog_locator_v1",
        "canonicalEncoding": "canonical-json",
    },
    "recoveryGate": {
        "schemaVersion": "staging_case_recovery_gate_v2",
        "capability": "opaque-data-free-gate",
        "serializableChecksum": False,
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
    "recovery_activation",
)

STAGE_PROTOCOL_REFS = {
    "source_quiesce": ["shutdownSeal", "deploymentClaim"],
    "encrypted_bundle": ["deploymentClaim", "shutdownSeal", "backupCatalog"],
    "fresh_target": ["deploymentClaim", "recoveryPolicy"],
    "isolated_restore_verifier": ["recoveryPolicy", "backupCatalog", "recoveryAttestation"],
    "recovery_activation": ["recoveryGate", "recoveryAttestation", "deploymentClaim", "recoveryMarker"],
    "restored_slots": ["deploymentClaim", "recoveryAttestation"],
    "flux_handoff": ["recoveryGate", "recoveryAttestation", "deploymentClaim", "shutdownSeal"],
}

STAGE_REQUIREMENTS = {
    "source_quiesce": {
        "databaseOwnerMustStop": True,
        "walCheckpoint": "TRUNCATE",
        "existingDurableClaimRequired": True,
        "canonicalShutdownSealRequired": True,
        "maintenanceWindowRequired": True,
        "exactSourceControlBindingRequired": True,
        "liveMutationAllowed": False,
    },
    "encrypted_bundle": {
        "encryptionRequired": True,
        "canonicalDatabaseRequired": True,
        "canonicalSourceClaimRequired": True,
        "canonicalV2SealRequired": True,
        "pinnedLocatorRequired": True,
        "credentialMaterialIncluded": False,
    },
    "fresh_target": {
        "freshTargetRequired": True,
        "targetMustBeDistinctFromSource": True,
        "targetClaimMustBeNew": True,
        "storageClassMustBePinned": True,
        "sourceVolumeReuseAllowed": False,
        "liveMutationAllowed": False,
    },
    "isolated_restore_verifier": {
        "isolatedRestoreRequired": True,
        "sourceMustNotBeMounted": True,
        "exactDatabaseRequired": True,
        "createOnRestoreForbidden": True,
        "exactSchemaRequired": True,
        "baselineDominanceRequired": True,
        "recoveryPolicyRequired": True,
        "backupCatalogRequired": True,
        "recoveryAttestationRequired": True,
        "immutableRestoreVerifierRequired": True,
        "sourceWriteMountAllowed": False,
        "publicIngressAllowed": False,
        "userFacingEndpointAllowed": False,
        "credentialMaterialIncluded": False,
    },
    "recovery_activation": {
        "ownerLockRequired": True,
        "exactRenewedRecoveryGateRequired": True,
        "reviewedHandoffReceiptRequired": True,
        "recoveryMarkerRequired": True,
        "sourceToTargetClaimRotationRequired": True,
        "bootstrapReceiptForbidden": True,
        "openEpochReceiptForbidden": True,
        "preBindFreshnessRequired": True,
        "nonSealingAbortRequired": True,
        "liveMutationAllowed": False,
    },
    "restored_slots": {
        "controlSlotMustReferenceTarget": True,
        "publicSlotMustBePvcPvSecretRbacFree": True,
        "publicSlotMustReferenceControlPrivateOutbox": True,
        "publicSlotForbiddenSurfaces": ["pvc", "pv", "secret", "rbac"],
        "publicAuthority": "none",
        "sameCaseBindingLineRequired": True,
        "liveMutationAllowed": False,
    },
    "flux_handoff": {
        "exactReceiptRequired": True,
        "reviewedOperationsRevisionRequired": True,
        "exactResourceInventoryChecksumRequired": True,
        "fluxObjectAllowed": False,
        "reconciliationAllowed": False,
        "liveMutationAllowed": False,
    },
}

HANDOFF_CHECKSUM_COVERS = [
    "schemaVersion",
    "status",
    "canonicalEncoding",
    "operationsRevision",
    "resourceInventoryChecksum",
    "sourceClaimChecksum",
    "targetClaimChecksum",
    "targetPvcUid",
    "targetPvName",
    "releaseDigest",
    "recoveryPolicyChecksum",
    "recoveryAttestationChecksum",
]

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


def _optional_revision(value: Any, path: str) -> None:
    if value is not None:
        _require(isinstance(value, str) and REVISION.fullmatch(value) is not None, f"{path} format invalid")
        raise VerificationError(f"{path} must remain null in inert_review_only mode")


def _optional_timestamp(value: Any, path: str) -> None:
    if value is not None:
        _require(isinstance(value, str) and UTC.fullmatch(value) is not None, f"{path} format invalid")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise VerificationError(f"{path} format invalid") from None
        _require(parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z") == value, f"{path} format invalid")
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


def _verify_image_resource_inventory_reference(root: Path, value: Any) -> None:
    reference = _closed(value, {"schemaVersion", "contractPath", "inventoryChecksum"}, "imageResourceInventory")
    _require(
        reference["schemaVersion"] == "stadtstack_case_image_resource_inventory_contract_v1",
        "imageResourceInventory.schemaVersion drift",
    )
    _require(
        reference["contractPath"] == IMAGE_RESOURCE_INVENTORY_RELATIVE_PATH.as_posix(),
        "imageResourceInventory.contractPath drift",
    )
    _optional_checksum(reference["inventoryChecksum"], "imageResourceInventory.inventoryChecksum")
    inventory = load_json(root / IMAGE_RESOURCE_INVENTORY_RELATIVE_PATH)
    _require(
        inventory.get("schemaVersion") == reference["schemaVersion"],
        "image resource inventory schema binding drift",
    )
    _require(
        inventory.get("inventoryChecksum") == reference["inventoryChecksum"],
        "image resource inventory checksum binding drift",
    )


def _verify_locator(value: Any, path: str, with_key_version: bool) -> None:
    fields = {"bucket", "key", "objectVersion", "checksum"}
    if with_key_version:
        fields.add("keyVersion")
    locator = _closed(value, fields, path)
    for field in ("bucket", "key", "objectVersion"):
        _require(locator[field] is None, f"{path}.{field} must remain null")
    _optional_checksum(locator["checksum"], f"{path}.checksum")
    if with_key_version:
        _require(locator["keyVersion"] is None, f"{path}.keyVersion must remain null")


def _verify_stage(value: Any, index: int) -> None:
    stage = _closed(value, {"stage", "status", "protocolRefs", "requirements"} | ({"evidence"} if STAGE_ORDER[index] in {"source_quiesce", "isolated_restore_verifier", "recovery_activation"} else set()) | ({"bundle"} if STAGE_ORDER[index] == "encrypted_bundle" else set()) | ({"target"} if STAGE_ORDER[index] == "fresh_target" else set()) | ({"slots"} if STAGE_ORDER[index] == "restored_slots" else set()) | ({"handoffReceipt"} if STAGE_ORDER[index] == "flux_handoff" else set()), f"stages[{index}]")
    expected_name = STAGE_ORDER[index]
    _require(stage["stage"] == expected_name, f"stages[{index}].stage order invalid")
    _require(stage["status"] == "inert_review_only", f"stages[{index}].status invalid")
    _require(stage["protocolRefs"] == STAGE_PROTOCOL_REFS[expected_name], f"stages[{index}].protocolRefs drift")
    _require(stage["requirements"] == STAGE_REQUIREMENTS[expected_name], f"stages[{index}].requirements drift")

    if expected_name == "source_quiesce":
        _closed(stage["evidence"], {"maintenanceStartedAtUtc", "maintenanceCompletedAtUtc", "sourceControlDeploymentBindingChecksum", "sourceClaimChecksum", "sourcePvcUid", "sourcePvName", "sourceSealChecksum", "quiesceReceiptChecksum"}, f"stages[{index}].evidence")
        _optional_timestamp(stage["evidence"]["maintenanceStartedAtUtc"], f"stages[{index}].evidence.maintenanceStartedAtUtc")
        _optional_timestamp(stage["evidence"]["maintenanceCompletedAtUtc"], f"stages[{index}].evidence.maintenanceCompletedAtUtc")
        _optional_checksum(stage["evidence"]["sourceControlDeploymentBindingChecksum"], f"stages[{index}].evidence.sourceControlDeploymentBindingChecksum")
        _optional_checksum(stage["evidence"]["sourceClaimChecksum"], f"stages[{index}].evidence.sourceClaimChecksum")
        _optional_uid(stage["evidence"]["sourcePvcUid"], f"stages[{index}].evidence.sourcePvcUid")
        _optional_identifier(stage["evidence"]["sourcePvName"], f"stages[{index}].evidence.sourcePvName")
        _optional_checksum(stage["evidence"]["sourceSealChecksum"], f"stages[{index}].evidence.sourceSealChecksum")
        _optional_checksum(stage["evidence"]["quiesceReceiptChecksum"], f"stages[{index}].evidence.quiesceReceiptChecksum")
    elif expected_name == "encrypted_bundle":
        bundle = _closed(stage["bundle"], {"database", "sourceClaim", "sourceSeal", "catalogLocator", "completionReceiptLocator", "encryptedManifestLocator", "bundleChecksum"}, f"stages[{index}].bundle")
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
        _verify_locator(bundle["catalogLocator"], f"stages[{index}].bundle.catalogLocator", False)
        _verify_locator(bundle["completionReceiptLocator"], f"stages[{index}].bundle.completionReceiptLocator", True)
        _verify_locator(bundle["encryptedManifestLocator"], f"stages[{index}].bundle.encryptedManifestLocator", False)
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
        evidence = _closed(stage["evidence"], {"recoveryPolicyChecksum", "recoveryAttestationChecksum", "restoreReportChecksum", "restoreVerifierImageDigest", "restoreVerifierProvenanceSha256", "restoreVerifierSpdxSbomSha256", "verifiedDatabaseSha256", "verifiedSchemaChecksum"}, f"stages[{index}].evidence")
        for field in evidence:
            _optional_checksum(evidence[field], f"stages[{index}].evidence.{field}")
    elif expected_name == "recovery_activation":
        evidence = _closed(stage["evidence"], {"ownerLockReceiptChecksum", "recoveryPolicyChecksum", "recoveryAttestationChecksum", "handoffReceiptChecksum", "recoveryMarkerChecksum", "sourceClaimChecksum", "targetClaimChecksum", "claimRotationReceiptChecksum", "preBindFreshnessReceiptChecksum"}, f"stages[{index}].evidence")
        for field in evidence:
            _optional_checksum(evidence[field], f"stages[{index}].evidence.{field}")
    elif expected_name == "restored_slots":
        slots = _closed(stage["slots"], {"control", "public"}, f"stages[{index}].slots")
        control = _closed(slots["control"], {"targetClaimChecksum", "targetPvcUid", "targetPvName", "releaseDigest", "controlPrivateOutboxBindingChecksum", "referenceChecksum"}, f"stages[{index}].slots.control")
        for field in ("targetClaimChecksum", "releaseDigest", "controlPrivateOutboxBindingChecksum", "referenceChecksum"):
            _optional_checksum(control[field], f"stages[{index}].slots.control.{field}")
        _optional_uid(control["targetPvcUid"], f"stages[{index}].slots.control.targetPvcUid")
        _optional_identifier(control["targetPvName"], f"stages[{index}].slots.control.targetPvName")

        public = _closed(slots["public"], {"controlPrivateOutboxBindingChecksum", "controlSlotReferenceChecksum", "referenceChecksum"}, f"stages[{index}].slots.public")
        for field in ("controlPrivateOutboxBindingChecksum", "controlSlotReferenceChecksum", "referenceChecksum"):
            _optional_checksum(public[field], f"stages[{index}].slots.public.{field}")
    elif expected_name == "flux_handoff":
        receipt = _closed(stage["handoffReceipt"], {"schemaVersion", "status", "canonicalEncoding", "checksumCovers", "operationsRevision", "resourceInventoryChecksum", "sourceClaimChecksum", "targetClaimChecksum", "targetPvcUid", "targetPvName", "releaseDigest", "recoveryPolicyChecksum", "recoveryAttestationChecksum", "receiptChecksum"}, f"stages[{index}].handoffReceipt")
        _require(receipt["schemaVersion"] == "stadtstack_case_recovery_handoff_receipt_v1", f"stages[{index}].handoffReceipt.schemaVersion drift")
        _require(receipt["status"] == "inert_review_only", f"stages[{index}].handoffReceipt.status invalid")
        _require(receipt["canonicalEncoding"] == "canonical-json", f"stages[{index}].handoffReceipt.canonicalEncoding drift")
        _require(receipt["checksumCovers"] == HANDOFF_CHECKSUM_COVERS, f"stages[{index}].handoffReceipt.checksumCovers drift")
        _optional_revision(receipt["operationsRevision"], f"stages[{index}].handoffReceipt.operationsRevision")
        _optional_checksum(receipt["resourceInventoryChecksum"], f"stages[{index}].handoffReceipt.resourceInventoryChecksum")
        _optional_checksum(receipt["sourceClaimChecksum"], f"stages[{index}].handoffReceipt.sourceClaimChecksum")
        _optional_checksum(receipt["targetClaimChecksum"], f"stages[{index}].handoffReceipt.targetClaimChecksum")
        _optional_uid(receipt["targetPvcUid"], f"stages[{index}].handoffReceipt.targetPvcUid")
        _optional_identifier(receipt["targetPvName"], f"stages[{index}].handoffReceipt.targetPvName")
        _optional_checksum(receipt["releaseDigest"], f"stages[{index}].handoffReceipt.releaseDigest")
        _optional_checksum(receipt["recoveryPolicyChecksum"], f"stages[{index}].handoffReceipt.recoveryPolicyChecksum")
        _optional_checksum(receipt["recoveryAttestationChecksum"], f"stages[{index}].handoffReceipt.recoveryAttestationChecksum")
        _optional_checksum(receipt["receiptChecksum"], f"stages[{index}].handoffReceipt.receiptChecksum")


def _verify_live_evidence(value: Any) -> None:
    live = _closed(value, {"source", "bundle", "target", "restore", "recoveryActivation", "slots", "fluxHandoff"}, "liveEvidence")
    source = _closed(live["source"], {"maintenanceStartedAtUtc", "maintenanceCompletedAtUtc", "sourceControlDeploymentBindingChecksum", "claimChecksum", "pvc", "pvName", "releaseDigest", "sealChecksum"}, "liveEvidence.source")
    _optional_timestamp(source["maintenanceStartedAtUtc"], "liveEvidence.source.maintenanceStartedAtUtc")
    _optional_timestamp(source["maintenanceCompletedAtUtc"], "liveEvidence.source.maintenanceCompletedAtUtc")
    _optional_checksum(source["sourceControlDeploymentBindingChecksum"], "liveEvidence.source.sourceControlDeploymentBindingChecksum")
    _optional_checksum(source["claimChecksum"], "liveEvidence.source.claimChecksum")
    _verify_pvc(source["pvc"], "liveEvidence.source.pvc")
    _optional_identifier(source["pvName"], "liveEvidence.source.pvName")
    _optional_checksum(source["releaseDigest"], "liveEvidence.source.releaseDigest")
    _optional_checksum(source["sealChecksum"], "liveEvidence.source.sealChecksum")
    bundle = _closed(live["bundle"], {"databaseBasename", "databaseByteLength", "databaseSha256", "sourceClaimChecksum", "sourceSealChecksum", "catalogLocator", "completionReceiptLocator", "encryptedManifestLocator", "bundleChecksum"}, "liveEvidence.bundle")
    _optional_identifier(bundle["databaseBasename"], "liveEvidence.bundle.databaseBasename")
    _optional_positive_integer(bundle["databaseByteLength"], "liveEvidence.bundle.databaseByteLength")
    for field in ("databaseSha256", "sourceClaimChecksum", "sourceSealChecksum", "bundleChecksum"):
        _optional_checksum(bundle[field], f"liveEvidence.bundle.{field}")
    _verify_locator(bundle["catalogLocator"], "liveEvidence.bundle.catalogLocator", False)
    _verify_locator(bundle["completionReceiptLocator"], "liveEvidence.bundle.completionReceiptLocator", True)
    _verify_locator(bundle["encryptedManifestLocator"], "liveEvidence.bundle.encryptedManifestLocator", False)
    target = _closed(live["target"], {"claimChecksum", "pvc", "pvName", "storageClass", "releaseDigest"}, "liveEvidence.target")
    _optional_checksum(target["claimChecksum"], "liveEvidence.target.claimChecksum")
    _verify_pvc(target["pvc"], "liveEvidence.target.pvc")
    _optional_identifier(target["pvName"], "liveEvidence.target.pvName")
    _optional_identifier(target["storageClass"], "liveEvidence.target.storageClass")
    _optional_checksum(target["releaseDigest"], "liveEvidence.target.releaseDigest")
    restore = _closed(live["restore"], {"recoveryPolicyChecksum", "recoveryAttestationChecksum", "restoreReportChecksum", "restoreVerifierImageDigest", "restoreVerifierProvenanceSha256", "restoreVerifierSpdxSbomSha256", "databaseSha256", "schemaChecksum"}, "liveEvidence.restore")
    for field in restore:
        _optional_checksum(restore[field], f"liveEvidence.restore.{field}")
    activation = _closed(live["recoveryActivation"], {"ownerLockReceiptChecksum", "recoveryPolicyChecksum", "recoveryAttestationChecksum", "handoffReceiptChecksum", "recoveryMarkerChecksum", "sourceClaimChecksum", "targetClaimChecksum", "claimRotationReceiptChecksum", "preBindFreshnessReceiptChecksum"}, "liveEvidence.recoveryActivation")
    for field in activation:
        _optional_checksum(activation[field], f"liveEvidence.recoveryActivation.{field}")
    slots = _closed(live["slots"], {"controlReferenceChecksum", "controlPrivateOutboxBindingChecksum", "publicControlSlotReferenceChecksum", "publicControlPrivateOutboxBindingChecksum", "publicReferenceChecksum"}, "liveEvidence.slots")
    _optional_checksum(slots["controlReferenceChecksum"], "liveEvidence.slots.controlReferenceChecksum")
    _optional_checksum(slots["controlPrivateOutboxBindingChecksum"], "liveEvidence.slots.controlPrivateOutboxBindingChecksum")
    _optional_checksum(slots["publicControlSlotReferenceChecksum"], "liveEvidence.slots.publicControlSlotReferenceChecksum")
    _optional_checksum(slots["publicControlPrivateOutboxBindingChecksum"], "liveEvidence.slots.publicControlPrivateOutboxBindingChecksum")
    _optional_checksum(slots["publicReferenceChecksum"], "liveEvidence.slots.publicReferenceChecksum")
    handoff = _closed(live["fluxHandoff"], {"operationsRevision", "resourceInventoryChecksum", "receiptChecksum"}, "liveEvidence.fluxHandoff")
    _optional_revision(handoff["operationsRevision"], "liveEvidence.fluxHandoff.operationsRevision")
    _optional_checksum(handoff["resourceInventoryChecksum"], "liveEvidence.fluxHandoff.resourceInventoryChecksum")
    _optional_checksum(handoff["receiptChecksum"], "liveEvidence.fluxHandoff.receiptChecksum")
    if source["pvc"]["uid"] is not None and target["pvc"]["uid"] is not None:
        _require(source["pvc"]["uid"] != target["pvc"]["uid"], "source and target PVC UID must be distinct")


def _verify_cross_bindings(contract: dict[str, Any]) -> None:
    stages = {stage["stage"]: stage for stage in contract["stages"]}
    live = contract["liveEvidence"]
    source = stages["source_quiesce"]["evidence"]
    _require(source["maintenanceStartedAtUtc"] == live["source"]["maintenanceStartedAtUtc"], "source maintenance start binding drift")
    _require(source["maintenanceCompletedAtUtc"] == live["source"]["maintenanceCompletedAtUtc"], "source maintenance completion binding drift")
    _require(source["sourceControlDeploymentBindingChecksum"] == live["source"]["sourceControlDeploymentBindingChecksum"], "source control binding drift")
    _require(source["sourceClaimChecksum"] == live["source"]["claimChecksum"], "source claim checksum binding drift")
    _require(source["sourcePvcUid"] == live["source"]["pvc"]["uid"], "source PVC binding drift")
    _require(source["sourcePvName"] == live["source"]["pvName"], "source PV binding drift")
    _require(source["sourceSealChecksum"] == live["source"]["sealChecksum"], "source seal binding drift")

    bundle = stages["encrypted_bundle"]["bundle"]
    _require(bundle["database"]["sha256"] == live["bundle"]["databaseSha256"], "bundle database checksum binding drift")
    _require(bundle["sourceClaim"]["claimChecksum"] == live["bundle"]["sourceClaimChecksum"], "bundle source claim binding drift")
    _require(bundle["sourceSeal"]["sealChecksum"] == live["bundle"]["sourceSealChecksum"], "bundle source seal binding drift")
    for locator_name in ("catalogLocator", "completionReceiptLocator", "encryptedManifestLocator"):
        _require(bundle[locator_name] == live["bundle"][locator_name], f"bundle {locator_name} binding drift")
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
    for field in ("recoveryPolicyChecksum", "recoveryAttestationChecksum", "restoreReportChecksum", "restoreVerifierImageDigest", "restoreVerifierProvenanceSha256", "restoreVerifierSpdxSbomSha256"):
        _require(restore[field] == live["restore"][field], f"restore {field} binding drift")
    _require(restore["verifiedDatabaseSha256"] == live["restore"]["databaseSha256"], "restore database binding drift")
    _require(restore["verifiedSchemaChecksum"] == live["restore"]["schemaChecksum"], "restore schema binding drift")
    activation = stages["recovery_activation"]["evidence"]
    for field in activation:
        _require(activation[field] == live["recoveryActivation"][field], f"recovery activation {field} binding drift")
    _require(activation["recoveryPolicyChecksum"] == live["restore"]["recoveryPolicyChecksum"], "activation policy binding drift")
    _require(activation["recoveryAttestationChecksum"] == live["restore"]["recoveryAttestationChecksum"], "activation attestation binding drift")
    _require(activation["sourceClaimChecksum"] == live["source"]["claimChecksum"], "activation source claim binding drift")
    _require(activation["targetClaimChecksum"] == live["target"]["claimChecksum"], "activation target claim binding drift")
    slots = stages["restored_slots"]["slots"]
    _require(slots["control"]["referenceChecksum"] == live["slots"]["controlReferenceChecksum"], "control slot binding drift")
    _require(slots["control"]["controlPrivateOutboxBindingChecksum"] == live["slots"]["controlPrivateOutboxBindingChecksum"], "control private outbox binding drift")
    _require(slots["public"]["referenceChecksum"] == live["slots"]["publicReferenceChecksum"], "public slot binding drift")
    _require(slots["public"]["controlPrivateOutboxBindingChecksum"] == live["slots"]["publicControlPrivateOutboxBindingChecksum"], "public control private outbox binding drift")
    _require(slots["public"]["controlSlotReferenceChecksum"] == live["slots"]["publicControlSlotReferenceChecksum"], "public control slot reference drift")
    _require(slots["public"]["controlPrivateOutboxBindingChecksum"] == slots["control"]["controlPrivateOutboxBindingChecksum"], "public slot must reference exact control private outbox")
    _require(slots["public"]["controlSlotReferenceChecksum"] == slots["control"]["referenceChecksum"], "public slot must reference exact control slot")
    _require(slots["control"]["targetClaimChecksum"] == live["target"]["claimChecksum"], "control slot target claim binding drift")
    _require(slots["control"]["targetPvcUid"] == live["target"]["pvc"]["uid"], "control slot target PVC binding drift")
    _require(slots["control"]["targetPvName"] == live["target"]["pvName"], "control slot target PV binding drift")
    _require(slots["control"]["releaseDigest"] == live["target"]["releaseDigest"], "control slot release binding drift")
    receipt = stages["flux_handoff"]["handoffReceipt"]
    _require(receipt["operationsRevision"] == live["fluxHandoff"]["operationsRevision"], "handoff Operations revision binding drift")
    _require(receipt["resourceInventoryChecksum"] == live["fluxHandoff"]["resourceInventoryChecksum"], "handoff resource inventory binding drift")
    _require(receipt["resourceInventoryChecksum"] == contract["imageResourceInventory"]["inventoryChecksum"], "handoff image resource inventory binding drift")
    _require(receipt["receiptChecksum"] == live["fluxHandoff"]["receiptChecksum"], "handoff receipt binding drift")
    _require(receipt["sourceClaimChecksum"] == live["source"]["claimChecksum"], "handoff source claim binding drift")
    _require(receipt["targetClaimChecksum"] == live["target"]["claimChecksum"], "handoff target claim binding drift")
    _require(receipt["targetPvcUid"] == live["target"]["pvc"]["uid"], "handoff target PVC binding drift")
    _require(receipt["targetPvName"] == live["target"]["pvName"], "handoff target PV binding drift")
    _require(receipt["releaseDigest"] == live["target"]["releaseDigest"], "handoff release binding drift")
    _require(receipt["recoveryPolicyChecksum"] == live["restore"]["recoveryPolicyChecksum"], "handoff recovery policy binding drift")
    _require(receipt["recoveryAttestationChecksum"] == live["restore"]["recoveryAttestationChecksum"], "handoff attestation binding drift")
    _require(activation["handoffReceiptChecksum"] == receipt["receiptChecksum"], "activation handoff receipt binding drift")


def verify_contract(root: Path) -> list[str]:
    try:
        contract = load_json(root / CONTRACT_RELATIVE_PATH)
        _scan_forbidden(contract)
        _closed(
            contract,
            {
                "schemaVersion", "mode", "status", "deploymentEnvironment", "municipalityId",
                "reconciliationAllowed", "fluxHandoffAllowed", "allowedKinds", "forbiddenResources",
                "forbiddenSecrets", "protocols", "imageResourceInventory", "stages", "liveEvidence", "effects", "missingEvidence",
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
        _verify_image_resource_inventory_reference(root, contract["imageResourceInventory"])
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
