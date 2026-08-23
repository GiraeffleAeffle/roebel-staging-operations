#!/usr/bin/env python3
"""Verify the closed-world, still-inert recovery activation contract.

This is a policy verifier, not an activation controller. It does not contact
Kubernetes, Flux, an object store, or a signer. The nested policy, catalog and
attestation records intentionally mirror the application recovery module, but
all live evidence remains absent until a separately reviewed ceremony exists.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


CONTRACT_RELATIVE_PATH = Path("contracts/stadtstack-case-runtime-contract.json")


EXPECTED_MISSING_EVIDENCE = [
    "restoreVerifierReleaseDigest",
    "recoveryActivationGate.policy.storeId",
    "recoveryActivationGate.policy.sourcePvc.namespace",
    "recoveryActivationGate.policy.sourcePvc.name",
    "recoveryActivationGate.policy.sourcePvc.uid",
    "recoveryActivationGate.policy.targetPvc.namespace",
    "recoveryActivationGate.policy.targetPvc.name",
    "recoveryActivationGate.policy.targetPvc.uid",
    "recoveryActivationGate.policy.targetPvName",
    "recoveryActivationGate.policy.recoveryOperationId",
    "recoveryActivationGate.policy.controlDeploymentBindingChecksum",
    "recoveryActivationGate.policy.catalogLocatorChecksum",
    "recoveryActivationGate.policy.restoreVerifierReleaseDigest",
    "recoveryActivationGate.policy.signer.keyId",
    "recoveryActivationGate.policy.signer.keyVersion",
    "recoveryActivationGate.policy.signer.spkiDerBase64url",
    "recoveryActivationGate.policy.signer.spkiSha256",
    "recoveryActivationGate.policy.signer.activeFromUtc",
    "recoveryActivationGate.policy.signer.activeUntilUtc",
    "recoveryActivationGate.policy.policyChecksum",
    "recoveryActivationGate.catalog.municipalityId",
    "recoveryActivationGate.catalog.storeId",
    "recoveryActivationGate.catalog.recoveryOperationId",
    "recoveryActivationGate.catalog.casGeneration",
    "recoveryActivationGate.catalog.backupId",
    "recoveryActivationGate.catalog.completionReceipt.bucket",
    "recoveryActivationGate.catalog.completionReceipt.key",
    "recoveryActivationGate.catalog.completionReceipt.objectVersion",
    "recoveryActivationGate.catalog.completionReceipt.checksum",
    "recoveryActivationGate.catalog.completionReceipt.keyVersion",
    "recoveryActivationGate.catalog.encryptedManifest.bucket",
    "recoveryActivationGate.catalog.encryptedManifest.key",
    "recoveryActivationGate.catalog.encryptedManifest.objectVersion",
    "recoveryActivationGate.catalog.encryptedManifest.checksum",
    "recoveryActivationGate.catalog.retentionUntilUtc",
    "recoveryActivationGate.catalog.locatorChecksum",
    "recoveryActivationGate.attestation.municipalityId",
    "recoveryActivationGate.attestation.storeId",
    "recoveryActivationGate.attestation.recoveryOperationId",
    "recoveryActivationGate.attestation.policyChecksum",
    "recoveryActivationGate.attestation.controlDeploymentBindingChecksum",
    "recoveryActivationGate.attestation.catalogLocatorChecksum",
    "recoveryActivationGate.attestation.casGeneration",
    "recoveryActivationGate.attestation.backupId",
    "recoveryActivationGate.attestation.completionReceipt.bucket",
    "recoveryActivationGate.attestation.completionReceipt.key",
    "recoveryActivationGate.attestation.completionReceipt.objectVersion",
    "recoveryActivationGate.attestation.completionReceipt.checksum",
    "recoveryActivationGate.attestation.completionReceipt.keyVersion",
    "recoveryActivationGate.attestation.encryptedManifest.bucket",
    "recoveryActivationGate.attestation.encryptedManifest.key",
    "recoveryActivationGate.attestation.encryptedManifest.objectVersion",
    "recoveryActivationGate.attestation.encryptedManifest.checksum",
    "recoveryActivationGate.attestation.sourcePvcUid",
    "recoveryActivationGate.attestation.targetPvcUid",
    "recoveryActivationGate.attestation.targetPvName",
    "recoveryActivationGate.attestation.seal.sealChecksum",
    "recoveryActivationGate.attestation.seal.closedAtUtc",
    "recoveryActivationGate.attestation.seal.databaseSchemaVersion",
    "recoveryActivationGate.attestation.seal.configFingerprint",
    "recoveryActivationGate.attestation.seal.sourceReleaseDigest",
    "recoveryActivationGate.attestation.seal.databaseBasename",
    "recoveryActivationGate.attestation.seal.databaseByteLength",
    "recoveryActivationGate.attestation.seal.databaseSha256",
    "recoveryActivationGate.attestation.seal.recoveryEvidenceChecksum",
    "recoveryActivationGate.attestation.seal.caseCount",
    "recoveryActivationGate.attestation.seal.outboxCursor",
    "recoveryActivationGate.attestation.seal.headsAggregateChecksum",
    "recoveryActivationGate.attestation.seal.publicProjectionChecksum",
    "recoveryActivationGate.attestation.restoreReport.restoreReportChecksum",
    "recoveryActivationGate.attestation.restoreReport.verifierReleaseDigest",
    "recoveryActivationGate.attestation.restoreReport.restoredDatabaseByteLength",
    "recoveryActivationGate.attestation.restoreReport.restoredDatabaseSha256",
    "recoveryActivationGate.attestation.restoreReport.integrity",
    "recoveryActivationGate.attestation.restoreReport.recoveryEvidenceChecksum",
    "recoveryActivationGate.attestation.restoreReport.caseCount",
    "recoveryActivationGate.attestation.restoreReport.outboxCursor",
    "recoveryActivationGate.attestation.restoreReport.headsAggregateChecksum",
    "recoveryActivationGate.attestation.restoreReport.publicProjectionChecksum",
    "recoveryActivationGate.attestation.restoreReport.isolatedRestore",
    "recoveryActivationGate.attestation.restoreReport.startedAtUtc",
    "recoveryActivationGate.attestation.restoreReport.completedAtUtc",
    "recoveryActivationGate.attestation.restoreReport.rtoSeconds",
    "recoveryActivationGate.attestation.issuedAtUtc",
    "recoveryActivationGate.attestation.expiresAtUtc",
    "recoveryActivationGate.attestation.signerKeyId",
    "recoveryActivationGate.attestation.signerKeyVersion",
    "recoveryActivationGate.attestation.attestationChecksum",
    "recoveryActivationGate.attestation.signature",
]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle, object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(value, dict):
        raise ValueError("contract root must be an object")
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


def _require_keys(errors: list[str], value: Any, expected: set[str], path: str) -> None:
    if not isinstance(value, dict):
        errors.append(f"{path} must be an object")
        return
    actual = set(value)
    if actual != expected:
        errors.append(f"{path} keys differ: expected {sorted(expected)}, got {sorted(actual)}")


def _require_equal(errors: list[str], value: Any, expected: Any, path: str) -> None:
    if value != expected:
        errors.append(f"{path} must equal {expected!r}; got {value!r}")


def _require_null(errors: list[str], value: Any, path: str) -> None:
    if value is not None:
        errors.append(f"{path} must remain null until live evidence exists")


def _verify_object_locator(errors: list[str], value: Any, path: str, with_key_version: bool) -> None:
    fields = {"bucket", "key", "objectVersion", "checksum"}
    if with_key_version:
        fields.add("keyVersion")
    _require_keys(errors, value, fields, path)


def verify_contract(root: Path) -> list[str]:
    errors: list[str] = []
    try:
        contract = load_json(root / CONTRACT_RELATIVE_PATH)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [f"cannot load {CONTRACT_RELATIVE_PATH}: {exc}"]

    _require_keys(
        errors,
        contract,
        {
            "schemaVersion",
            "mode",
            "reconciliationAllowed",
            "fluxKustomizationAllowed",
            "allowedKinds",
            "otherKindsAllowed",
            "invariants",
            "activationResources",
            "restoreVerifierReleaseDigest",
            "recoveryActivationGate",
        },
        "contract",
    )
    _require_equal(errors, contract.get("schemaVersion"), "stadtstack_case_runtime_contract_v1", "schemaVersion")
    _require_equal(errors, contract.get("mode"), "inert_review_only", "mode")
    _require_equal(errors, contract.get("reconciliationAllowed"), False, "reconciliationAllowed")
    _require_equal(errors, contract.get("fluxKustomizationAllowed"), False, "fluxKustomizationAllowed")
    _require_equal(errors, contract.get("allowedKinds"), [], "allowedKinds")
    _require_equal(errors, contract.get("otherKindsAllowed"), False, "otherKindsAllowed")
    _require_null(errors, contract.get("restoreVerifierReleaseDigest"), "restoreVerifierReleaseDigest")
    _require_equal(
        errors,
        contract.get("invariants"),
        {
            "kubernetesResourcesAllowed": False,
            "bucketCredentialsAllowed": False,
            "jobsAllowed": False,
            "pvcsAllowed": False,
            "deploymentsAllowed": False,
            "secretsAllowed": False,
            "fluxActivationAllowed": False,
            "recoveryActivationAllowed": False,
        },
        "invariants",
    )
    _require_equal(
        errors,
        contract.get("activationResources"),
        {
            "kubernetesObjects": [],
            "bucketCredentials": [],
            "jobs": [],
            "pvcs": [],
            "deployments": [],
            "secrets": [],
            "fluxObjects": [],
        },
        "activationResources",
    )

    gate = contract.get("recoveryActivationGate")
    _require_keys(errors, gate, {"schemaVersion", "status", "policy", "catalog", "attestation", "missingEvidence"}, "recoveryActivationGate")
    if not isinstance(gate, dict):
        return errors
    _require_equal(errors, gate.get("schemaVersion"), "stadtstack_case_recovery_evidence_inventory_v1", "recoveryActivationGate.schemaVersion")
    _require_equal(errors, gate.get("status"), "blocked", "recoveryActivationGate.status")

    policy = gate.get("policy")
    _require_keys(
        errors,
        policy,
        {
            "schemaVersion", "deploymentEnvironment", "municipalityId", "storeId", "sourcePvc", "targetPvc", "targetPvName",
            "recoveryOperationId", "controlDeploymentBindingChecksum", "catalogLocatorChecksum", "restoreVerifierReleaseDigest",
            "signer", "maxAgeSeconds", "maxRtoSeconds", "policyChecksum",
        },
        "recoveryActivationGate.policy",
    )
    if isinstance(policy, dict):
        _require_equal(errors, policy.get("schemaVersion"), "staging_case_recovery_policy_v1", "recoveryActivationGate.policy.schemaVersion")
        _require_equal(errors, policy.get("deploymentEnvironment"), "staging", "recoveryActivationGate.policy.deploymentEnvironment")
        _require_equal(errors, policy.get("municipalityId"), "roebel-mueritz", "recoveryActivationGate.policy.municipalityId")
        _require_equal(errors, policy.get("maxAgeSeconds"), 86400, "recoveryActivationGate.policy.maxAgeSeconds")
        _require_equal(errors, policy.get("maxRtoSeconds"), 14400, "recoveryActivationGate.policy.maxRtoSeconds")
        _require_keys(errors, policy.get("sourcePvc"), {"namespace", "name", "uid"}, "recoveryActivationGate.policy.sourcePvc")
        _require_keys(errors, policy.get("targetPvc"), {"namespace", "name", "uid"}, "recoveryActivationGate.policy.targetPvc")
        _require_keys(
            errors,
            policy.get("signer"),
            {"algorithm", "purpose", "status", "keyId", "keyVersion", "spkiDerBase64url", "spkiSha256", "activeFromUtc", "activeUntilUtc"},
            "recoveryActivationGate.policy.signer",
        )
        signer = policy.get("signer")
        if isinstance(signer, dict):
            _require_equal(errors, signer.get("algorithm"), "Ed25519", "recoveryActivationGate.policy.signer.algorithm")
            _require_equal(errors, signer.get("purpose"), "staging_case_recovery_attestation", "recoveryActivationGate.policy.signer.purpose")
            _require_equal(errors, signer.get("status"), "active", "recoveryActivationGate.policy.signer.status")

    catalog = gate.get("catalog")
    _require_keys(
        errors,
        catalog,
        {
            "schemaVersion", "deploymentEnvironment", "municipalityId", "storeId", "recoveryOperationId", "casGeneration", "backupId",
            "completionReceipt", "encryptedManifest", "retentionUntilUtc", "locatorChecksum",
        },
        "recoveryActivationGate.catalog",
    )
    if isinstance(catalog, dict):
        _require_equal(errors, catalog.get("schemaVersion"), "case_backup_catalog_locator_v1", "recoveryActivationGate.catalog.schemaVersion")
        _require_equal(errors, catalog.get("deploymentEnvironment"), "staging", "recoveryActivationGate.catalog.deploymentEnvironment")
        _verify_object_locator(errors, catalog.get("completionReceipt"), "recoveryActivationGate.catalog.completionReceipt", True)
        _verify_object_locator(errors, catalog.get("encryptedManifest"), "recoveryActivationGate.catalog.encryptedManifest", False)

    attestation = gate.get("attestation")
    _require_keys(
        errors,
        attestation,
        {
            "schemaVersion", "deploymentEnvironment", "municipalityId", "storeId", "recoveryOperationId", "policyChecksum",
            "controlDeploymentBindingChecksum", "catalogLocatorChecksum", "casGeneration", "backupId", "completionReceipt", "encryptedManifest",
            "sourcePvcUid", "targetPvcUid", "targetPvName", "seal", "restoreReport", "issuedAtUtc", "expiresAtUtc", "signerKeyId",
            "signerKeyVersion", "signatureAlgorithm", "attestationChecksum", "signature",
        },
        "recoveryActivationGate.attestation",
    )
    if isinstance(attestation, dict):
        _require_equal(errors, attestation.get("schemaVersion"), "staging_case_recovery_attestation_v1", "recoveryActivationGate.attestation.schemaVersion")
        _require_equal(errors, attestation.get("deploymentEnvironment"), "staging", "recoveryActivationGate.attestation.deploymentEnvironment")
        _require_equal(errors, attestation.get("signatureAlgorithm"), "Ed25519", "recoveryActivationGate.attestation.signatureAlgorithm")
        _verify_object_locator(errors, attestation.get("completionReceipt"), "recoveryActivationGate.attestation.completionReceipt", True)
        _verify_object_locator(errors, attestation.get("encryptedManifest"), "recoveryActivationGate.attestation.encryptedManifest", False)
        _require_keys(
            errors,
            attestation.get("seal"),
            {
                "sealChecksum", "closedAtUtc", "databaseSchemaVersion", "configFingerprint", "sourceReleaseDigest", "databaseBasename",
                "databaseByteLength", "databaseSha256", "recoveryEvidenceChecksum", "caseCount", "outboxCursor", "headsAggregateChecksum",
                "publicProjectionChecksum",
            },
            "recoveryActivationGate.attestation.seal",
        )
        _require_keys(
            errors,
            attestation.get("restoreReport"),
            {
                "restoreReportChecksum", "verifierReleaseDigest", "restoredDatabaseByteLength", "restoredDatabaseSha256", "integrity",
                "recoveryEvidenceChecksum", "caseCount", "outboxCursor", "headsAggregateChecksum", "publicProjectionChecksum",
                "isolatedRestore", "startedAtUtc", "completedAtUtc", "rtoSeconds",
            },
            "recoveryActivationGate.attestation.restoreReport",
        )

    actual_nulls = [path for path in _null_paths(contract) if not path.startswith("recoveryActivationGate.missingEvidence[")]
    if actual_nulls != EXPECTED_MISSING_EVIDENCE:
        errors.append(
            "missingEvidence does not exactly enumerate null evidence: "
            f"expected {EXPECTED_MISSING_EVIDENCE!r}, got {actual_nulls!r}"
        )
    _require_equal(errors, gate.get("missingEvidence"), EXPECTED_MISSING_EVIDENCE, "recoveryActivationGate.missingEvidence")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args()
    errors = verify_contract(args.root.resolve())
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("OK: inert Stadtstack case recovery activation contract is blocked and closed-world")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
