#!/usr/bin/env python3
"""Verify the inert, closed-world image/resource inventory contract.

This verifier is deliberately local and data-only.  It reads one regular JSON
file and never contacts Kubernetes, Flux, GitHub, a registry, an object store,
an image builder, a signer, or a running application.  The contract describes
the future release and logical resource boundaries while every live value is
still absent.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


CONTRACT_RELATIVE_PATH = Path("contracts/stadtstack-case-image-resource-inventory-contract.json")
TOPOLOGY_CONTRACT_RELATIVE_PATH = Path("case-staging-topology/contract.json")
TOPOLOGY_CONTRACT_CANONICAL_CHECKSUM = "sha256:31314eaf064f3a11d9c93ed399378e3807a2686b4916033637cbcc73c07b6584"

REVISION = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
IMAGE_REPOSITORY = re.compile(r"^ghcr\.io/[a-z0-9][a-z0-9./-]*$")

COMPONENT_ORDER = (
    "case-steward-control",
    "case-public-binding",
    "case-restore-verifier",
)

RELEASE_SET_VOCABULARY = {
    "schemaVersion": "stadtstack_case_release_set_candidate_v1",
    "vocabularyDerivedFrom": "roebel_staging_release_set_candidate_v1",
    "sourceRepository": "GiraeffleAeffle/stadtstack",
    "sourceRevision": {
        "encoding": "lowercase-hex",
        "length": 40,
        "exact": True,
    },
    "digests": {
        "algorithm": "sha256",
        "format": "sha256:<64 lowercase hex>",
        "immutable": True,
        "requiredWhenPopulated": ["manifestDigest", "configDigest", "layerDigests"],
    },
    "provenance": {
        "issuer": "https://token.actions.githubusercontent.com",
        "publisherIdentity": "https://github.com/GiraeffleAeffle/stadtstack/.github/workflows/case-staging-publish.yml@refs/heads/main",
        "predicateType": "https://slsa.dev/provenance/v1",
        "canonicalEncoding": "canonical-json",
        "subjectDigestField": "manifestDigest",
        "sourceBinding": {
            "repository": "GiraeffleAeffle/stadtstack",
            "gitRef": "refs/heads/main",
            "repositoryClaimRequired": True,
            "revisionClaimRequired": True,
            "revisionMustEqualComponentSourceRevision": True,
            "gitRefClaimRequired": True,
        },
    },
    "sbom": {
        "format": "SPDX-2.3",
        "identity": "https://spdx.dev/spdx/v2.3",
        "canonicalEncoding": "canonical-json",
        "subjectDigestField": "manifestDigest",
    },
    "checksums": {
        "algorithm": "sha256",
        "encoding": "canonical-json",
        "requiredWhenPopulated": True,
    },
    "anonymousDigestPullReceipt": {
        "schemaVersion": "stadtstack_case_anonymous_digest_pull_receipt_v1",
        "canonicalEncoding": "canonical-json",
        "authContext": "clean-empty-auth-config",
        "authConfigCanonicalJson": "{\"auths\":{}}",
        "authConfigCanonicalSha256": "sha256:ec21c035eccb78eb5ca20ec95628eb351633621e09a130ac8d7e663714d40c7a",
        "resolverIdentity": "oras-resolve-anonymous",
        "imageReferenceFormat": "<imageRepository>@<manifestDigest>",
        "bindings": ["component", "imageRepository", "manifestDigest", "sourceRevision"],
        "resolvedManifestDigestMustEqualManifestDigest": True,
        "receiptDigest": {
            "algorithm": "sha256",
            "encoding": "canonical-json",
            "covers": [
                "schemaVersion",
                "canonicalEncoding",
                "component",
                "imageRepository",
                "manifestDigest",
                "sourceRevision",
                "authContext",
                "authConfigCanonicalSha256",
                "resolverIdentity",
                "resolvedManifestDigest",
            ],
        },
    },
    "imageBinding": {
        "repositoryRequiredWhenPopulated": True,
        "manifestDigestRequiredWhenRepositoryPopulated": True,
        "allComponentRepositoriesMustDiffer": True,
        "allComponentManifestDigestsMustDiffer": True,
        "controlAndPublicRepositoriesMustDiffer": True,
        "controlAndPublicManifestDigestsMustDiffer": True,
    },
}

INVENTORY_CHECKSUM_POLICY = {
    "algorithm": "sha256",
    "encoding": "canonical-json",
    "covers": [
        "schemaVersion",
        "mode",
        "status",
        "deploymentEnvironment",
        "municipalityId",
        "reconciliationAllowed",
        "fluxHandoffAllowed",
        "allowedKinds",
        "protectedPolicyBootstrap",
        "forbiddenResources",
        "forbiddenSecrets",
        "releaseSetVocabulary",
        "components",
        "liveEvidence.components",
        "liveEvidence.resourceInventory",
        "effects",
    ],
}

COMPONENTS = [
    {
        "component": "case-steward-control",
        "order": 1,
        "releaseSetPolicy": {
            "imageRepository": "ghcr.io/giraeffleaeffle/stadtstack-case-steward-control",
            "sourceRevisionFormat": "exact-40-lowercase-hex",
            "immutableImageManifestRequired": True,
            "immutableConfigDigestRequired": True,
            "immutableLayerDigestsRequired": True,
            "slsaProvenanceV1Required": True,
            "spdx23Required": True,
            "canonicalJsonChecksumsRequired": True,
            "publicPackageVisibilityRequired": True,
            "anonymousDigestPullRequired": True,
            "imageRepositoryMustDifferFrom": "case-public-binding",
        },
        "logicalResourceInventory": {
            "representation": "logical_only",
            "oneWriterRequired": True,
            "futureExistingPvcOnly": True,
            "privateOutboxRequired": True,
            "publicIngressAllowed": False,
            "publicAuthority": "none",
            "preexistingRuntimeSecretReferenceAllowed": True,
            "preexistingRuntimeSecretUsage": "container_env_valueFrom_only",
            "allowedPreexistingRuntimeSecretReferenceNames": [
                "roebel-case-steward-control-runtime",
            ],
            "imagePullSecretsAllowed": False,
            "secretObjectCreationAllowed": False,
            "credentialMaterialIncluded": False,
            "topologyContractBinding": {
                "contractPath": "case-staging-topology/contract.json",
                "canonicalJsonChecksum": TOPOLOGY_CONTRACT_CANONICAL_CHECKSUM,
                "allowlistPath": "futureWorkloads.control.preexistingSecretRefs",
            },
        },
    },
    {
        "component": "case-public-binding",
        "order": 2,
        "releaseSetPolicy": {
            "imageRepository": "ghcr.io/giraeffleaeffle/stadtstack-case-public-binding",
            "sourceRevisionFormat": "exact-40-lowercase-hex",
            "immutableImageManifestRequired": True,
            "immutableConfigDigestRequired": True,
            "immutableLayerDigestsRequired": True,
            "slsaProvenanceV1Required": True,
            "spdx23Required": True,
            "canonicalJsonChecksumsRequired": True,
            "publicPackageVisibilityRequired": True,
            "anonymousDigestPullRequired": True,
            "imageRepositoryMustDifferFrom": "case-steward-control",
        },
        "logicalResourceInventory": {
            "representation": "logical_only",
            "pvcAllowed": False,
            "pvAllowed": False,
            "secretAllowed": False,
            "tokenAllowed": False,
            "rbacAllowed": False,
            "exactControlChecksumReferencesOnly": True,
            "allowedChecksumReferenceNames": [
                "case-steward-control.slotChecksum",
                "case-steward-control.privateOutboxChecksum",
            ],
            "publicAuthority": "none",
            "imagePullSecretsAllowed": False,
            "secretOrCredentialReferencesAllowed": False,
        },
    },
    {
        "component": "case-restore-verifier",
        "order": 3,
        "releaseSetPolicy": {
            "imageRepository": "ghcr.io/giraeffleaeffle/stadtstack-case-restore-verifier",
            "sourceRevisionFormat": "exact-40-lowercase-hex",
            "immutableImageManifestRequired": True,
            "immutableConfigDigestRequired": True,
            "immutableLayerDigestsRequired": True,
            "slsaProvenanceV1Required": True,
            "spdx23Required": True,
            "canonicalJsonChecksumsRequired": True,
            "publicPackageVisibilityRequired": True,
            "anonymousDigestPullRequired": True,
        },
        "logicalResourceInventory": {
            "representation": "logical_only",
            "isolated": True,
            "operatorInvokedOnly": True,
            "sourceWriteAllowed": False,
            "publicIngressAllowed": False,
            "userFacingEndpointAllowed": False,
            "fluxManaged": False,
            "imagePullSecretsAllowed": False,
            "secretOrCredentialReferencesAllowed": False,
        },
    },
]

FORBIDDEN_RESOURCE_KEYS = {
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
    "secret",
}

SECRET_PATTERNS = (
    "BEGIN PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "AGE-SECRET-KEY-",
    "ghp_",
    "github_pat_",
    "Bearer ",
)

EFFECTS = {
    "secretRead": False,
    "secretWrite": False,
    "clusterMutation": False,
    "networkCall": False,
    "imagePull": False,
    "fluxReconciliation": False,
    "civicMutation": False,
    "treasuryMutation": False,
}

PROTECTED_POLICY_BOOTSTRAP = {
    "required": True,
    "reason": "protected_base_lacks_case_image_inventory_policy_v1",
    "mechanism": "one_time_exact_commit_administrator_merge",
    "administratorEnforcementRestorationRequired": True,
    "postMergePushVerificationRequired": True,
    "activationBeforePushVerificationAllowed": False,
    "subsequentProtectedBaseAdmissionRequired": True,
}


class VerificationError(RuntimeError):
    """Raised when the candidate contract is not admitted."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    _require(path.is_file() and not path.is_symlink(), f"contract is not a regular file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except OSError as error:
        raise VerificationError(f"cannot read contract: {error}") from error
    except json.JSONDecodeError as error:
        raise VerificationError(f"invalid JSON: {error}") from error
    _require(isinstance(value, dict), "contract root must be an object")
    return value


def _closed(value: Any, keys: set[str], path: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{path} must be an object")
    _require(set(value) == keys, f"{path} keys mismatch")
    return value


def _canonical_checksum(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


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


def _assert_all_null(value: Any, path: str) -> None:
    if value is None:
        return
    if isinstance(value, dict):
        for key, child in value.items():
            _assert_all_null(child, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _assert_all_null(child, f"{path}[{index}]")
        return
    raise VerificationError(f"{path} must remain null in inert_review_only mode")


def _scan_forbidden(value: Any, path: str = "contract") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in FORBIDDEN_RESOURCE_KEYS:
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


def _optional_revision(value: Any, path: str) -> None:
    if value is None:
        return
    _require(isinstance(value, str) and REVISION.fullmatch(value) is not None, f"{path} format invalid")
    raise VerificationError(f"{path} must remain null in inert_review_only mode")


def _optional_digest(value: Any, path: str) -> None:
    if value is None:
        return
    _require(isinstance(value, str) and DIGEST.fullmatch(value) is not None, f"{path} format invalid")
    raise VerificationError(f"{path} must remain null in inert_review_only mode")


def _optional_repository(value: Any, path: str) -> None:
    if value is None:
        return
    _require(isinstance(value, str) and IMAGE_REPOSITORY.fullmatch(value) is not None, f"{path} format invalid")
    raise VerificationError(f"{path} must remain null in inert_review_only mode")


def _optional_string(value: Any, path: str) -> None:
    if value is None:
        return
    _require(isinstance(value, str) and value != "", f"{path} format invalid")
    raise VerificationError(f"{path} must remain null in inert_review_only mode")


def _optional_exact_string(value: Any, expected: str, path: str) -> None:
    if value is None:
        return
    _require(value == expected, f"{path} format invalid")
    raise VerificationError(f"{path} must remain null in inert_review_only mode")


def verify_populated_anonymous_digest_pull_receipt(
    component_evidence: dict[str, Any], receipt_value: Any, path: str = "anonymousDigestPullReceipt"
) -> None:
    """Pin the exact receipt semantics a later non-inert admission must use."""

    receipt = _closed(
        receipt_value,
        {
            "schemaVersion",
            "canonicalEncoding",
            "component",
            "imageRepository",
            "manifestDigest",
            "sourceRevision",
            "authContext",
            "authConfigCanonicalSha256",
            "resolverIdentity",
            "resolvedManifestDigest",
            "receiptDigest",
        },
        path,
    )
    policy = RELEASE_SET_VOCABULARY["anonymousDigestPullReceipt"]
    _require(
        "sha256:" + hashlib.sha256(policy["authConfigCanonicalJson"].encode("utf-8")).hexdigest()
        == policy["authConfigCanonicalSha256"],
        f"{path} clean auth-config checksum drift",
    )
    _require(receipt["schemaVersion"] == policy["schemaVersion"], f"{path}.schemaVersion drift")
    _require(receipt["canonicalEncoding"] == policy["canonicalEncoding"], f"{path}.canonicalEncoding drift")
    _require(receipt["component"] == component_evidence.get("component"), f"{path}.component binding drift")
    _require(
        receipt["imageRepository"] == component_evidence.get("imageRepository"),
        f"{path}.imageRepository binding drift",
    )
    _require(receipt["manifestDigest"] == component_evidence.get("manifestDigest"), f"{path}.manifestDigest binding drift")
    _require(receipt["sourceRevision"] == component_evidence.get("sourceRevision"), f"{path}.sourceRevision binding drift")
    _require(receipt["authContext"] == policy["authContext"], f"{path}.authContext drift")
    _require(
        receipt["authConfigCanonicalSha256"] == policy["authConfigCanonicalSha256"],
        f"{path}.authConfigCanonicalSha256 drift",
    )
    _require(receipt["resolverIdentity"] == policy["resolverIdentity"], f"{path}.resolverIdentity drift")
    _require(
        receipt["resolvedManifestDigest"] == component_evidence.get("manifestDigest"),
        f"{path}.resolvedManifestDigest binding drift",
    )
    _require(
        isinstance(receipt["component"], str) and receipt["component"] in COMPONENT_ORDER,
        f"{path}.component invalid",
    )
    _require(
        isinstance(receipt["imageRepository"], str) and IMAGE_REPOSITORY.fullmatch(receipt["imageRepository"]),
        f"{path}.imageRepository invalid",
    )
    _require(
        isinstance(receipt["manifestDigest"], str) and DIGEST.fullmatch(receipt["manifestDigest"]),
        f"{path}.manifestDigest invalid",
    )
    _require(
        isinstance(receipt["sourceRevision"], str) and REVISION.fullmatch(receipt["sourceRevision"]),
        f"{path}.sourceRevision invalid",
    )
    digest_policy = policy["receiptDigest"]
    payload = {field: receipt[field] for field in digest_policy["covers"]}
    _require(receipt["receiptDigest"] == _canonical_checksum(payload), f"{path}.receiptDigest binding drift")


def _verify_component_live_evidence(value: Any, index: int) -> None:
    path = f"liveEvidence.components[{index}]"
    item = _closed(
        value,
        {
            "component",
            "sourceRevision",
            "attestedSourceRepository",
            "attestedSourceRevision",
            "attestedGitRef",
            "imageRepository",
            "manifestDigest",
            "configDigest",
            "layerDigests",
            "provenanceAttestationDigest",
            "sbomArtifactDigest",
            "packageVisibility",
            "anonymousDigestPullReceipt",
            "canonicalChecksums",
        },
        path,
    )
    _require(item["component"] == COMPONENT_ORDER[index], f"{path}.component order invalid")
    _optional_revision(item["sourceRevision"], f"{path}.sourceRevision")
    _optional_string(item["attestedSourceRepository"], f"{path}.attestedSourceRepository")
    _optional_revision(item["attestedSourceRevision"], f"{path}.attestedSourceRevision")
    _optional_string(item["attestedGitRef"], f"{path}.attestedGitRef")
    _optional_repository(item["imageRepository"], f"{path}.imageRepository")
    for field in ("manifestDigest", "configDigest", "provenanceAttestationDigest", "sbomArtifactDigest"):
        _optional_digest(item[field], f"{path}.{field}")
    _optional_exact_string(item["packageVisibility"], "public", f"{path}.packageVisibility")
    receipt = _closed(
        item["anonymousDigestPullReceipt"],
        {
            "schemaVersion",
            "canonicalEncoding",
            "component",
            "imageRepository",
            "manifestDigest",
            "sourceRevision",
            "authContext",
            "authConfigCanonicalSha256",
            "resolverIdentity",
            "resolvedManifestDigest",
            "receiptDigest",
        },
        f"{path}.anonymousDigestPullReceipt",
    )
    _assert_all_null(receipt, f"{path}.anonymousDigestPullReceipt")
    if item["layerDigests"] is not None:
        _require(isinstance(item["layerDigests"], list) and item["layerDigests"], f"{path}.layerDigests format invalid")
        for layer_index, digest in enumerate(item["layerDigests"]):
            _require(isinstance(digest, str) and DIGEST.fullmatch(digest) is not None, f"{path}.layerDigests[{layer_index}] format invalid")
        raise VerificationError(f"{path}.layerDigests must remain null in inert_review_only mode")
    checksums = _closed(
        item["canonicalChecksums"],
        {"manifest", "config", "layers", "provenance", "sbom", "releaseSet"},
        f"{path}.canonicalChecksums",
    )
    for field, value in checksums.items():
        _optional_digest(value, f"{path}.canonicalChecksums.{field}")


def _verify_live_evidence(value: Any) -> None:
    live = _closed(value, {"components", "resourceInventory", "fluxHandoff"}, "liveEvidence")
    _require(isinstance(live["components"], list) and len(live["components"]) == len(COMPONENT_ORDER), "liveEvidence.components shape invalid")
    for index, component in enumerate(live["components"]):
        _verify_component_live_evidence(component, index)

    inventory = _closed(
        live["resourceInventory"],
        {
            "controlSlotChecksum",
            "controlPrivateOutboxChecksum",
            "publicControlSlotReferenceChecksum",
            "publicControlPrivateOutboxReferenceChecksum",
            "restoreVerifierChecksum",
        },
        "liveEvidence.resourceInventory",
    )
    for field, value in inventory.items():
        _optional_digest(value, f"liveEvidence.resourceInventory.{field}")

    handoff = _closed(
        live["fluxHandoff"],
        {
            "namespace",
            "reconcilerIdentity",
            "sourceRevision",
            "sourcePath",
            "resourceNameAllowlistChecksum",
            "resourceInventoryChecksum",
            "rbacReceiptChecksum",
        },
        "liveEvidence.fluxHandoff",
    )
    _optional_string(handoff["namespace"], "liveEvidence.fluxHandoff.namespace")
    _optional_string(handoff["reconcilerIdentity"], "liveEvidence.fluxHandoff.reconcilerIdentity")
    _optional_revision(handoff["sourceRevision"], "liveEvidence.fluxHandoff.sourceRevision")
    _optional_string(handoff["sourcePath"], "liveEvidence.fluxHandoff.sourcePath")
    _optional_digest(handoff["resourceNameAllowlistChecksum"], "liveEvidence.fluxHandoff.resourceNameAllowlistChecksum")
    _optional_digest(handoff["resourceInventoryChecksum"], "liveEvidence.fluxHandoff.resourceInventoryChecksum")
    _optional_digest(handoff["rbacReceiptChecksum"], "liveEvidence.fluxHandoff.rbacReceiptChecksum")

def verify_contract(root: Path) -> list[str]:
    try:
        contract = load_json(root / CONTRACT_RELATIVE_PATH)
        _scan_forbidden(contract)
        _closed(
            contract,
            {
                "schemaVersion",
                "mode",
                "status",
                "deploymentEnvironment",
                "municipalityId",
                "reconciliationAllowed",
                "fluxHandoffAllowed",
                "allowedKinds",
                "protectedPolicyBootstrap",
                "forbiddenResources",
                "forbiddenSecrets",
                "releaseSetVocabulary",
                "components",
                "inventoryChecksumPolicy",
                "inventoryChecksum",
                "liveEvidence",
                "effects",
                "missingEvidence",
            },
            "contract",
        )
        _require(contract["schemaVersion"] == "stadtstack_case_image_resource_inventory_contract_v1", "schemaVersion drift")
        _require(contract["mode"] == "inert_review_only" and contract["status"] == "inert_review_only", "contract must remain inert_review_only")
        _require(contract["deploymentEnvironment"] == "staging" and contract["municipalityId"] == "roebel-mueritz", "scope drift")
        _require(contract["reconciliationAllowed"] is False and contract["fluxHandoffAllowed"] is False, "activation flags must remain false")
        _require(contract["allowedKinds"] == [], "allowedKinds must remain empty")
        _require(contract["protectedPolicyBootstrap"] == PROTECTED_POLICY_BOOTSTRAP, "protected policy bootstrap boundary drift")
        _require(
            contract["forbiddenResources"] == {
                "documents": [],
                "apiVersions": [],
                "kinds": [],
                "kubernetesObjects": [],
                "fluxObjects": [],
            },
            "forbidden resource inventory must remain empty",
        )
        _require(
            contract["forbiddenSecrets"] == {
                "credentialValues": [],
                "secretObjects": [],
                "secretReferences": [],
            },
            "forbidden secret inventory must remain empty",
        )
        _require(contract["releaseSetVocabulary"] == RELEASE_SET_VOCABULARY, "Release Set vocabulary drift")
        _require(contract["components"] == COMPONENTS, "ordered component inventory drift")
        topology = load_json(root / TOPOLOGY_CONTRACT_RELATIVE_PATH)
        _require(_canonical_checksum(topology) == TOPOLOGY_CONTRACT_CANONICAL_CHECKSUM, "topology contract checksum drift")
        _require(
            topology.get("futureWorkloads", {}).get("control", {}).get("preexistingSecretRefs")
            == COMPONENTS[0]["logicalResourceInventory"]["allowedPreexistingRuntimeSecretReferenceNames"],
            "control runtime Secret allowlist drift",
        )
        _require(
            topology.get("futureWorkloads", {}).get("control", {}).get("preexistingSecretRefUsage")
            == {
                "roebel-case-steward-control-runtime": COMPONENTS[0]["logicalResourceInventory"][
                    "preexistingRuntimeSecretUsage"
                ]
            },
            "control runtime Secret usage drift",
        )
        _require(
            topology.get("invariants", {}).get("imagePullSecretsAllowed") is False
            and all(
                topology.get("futureWorkloads", {}).get(workload, {}).get("imagePullSecretsAllowed") is False
                for workload in ("control", "public")
            )
            and all(component["logicalResourceInventory"]["imagePullSecretsAllowed"] is False for component in COMPONENTS),
            "Case imagePullSecret boundary drift",
        )
        _require(contract["inventoryChecksumPolicy"] == INVENTORY_CHECKSUM_POLICY, "inventory checksum policy drift")
        _optional_digest(contract["inventoryChecksum"], "inventoryChecksum")
        _verify_live_evidence(contract["liveEvidence"])
        _require(contract["effects"] == EFFECTS, "effects must remain false")

        nulls = _null_paths({key: value for key, value in contract.items() if key != "missingEvidence"})
        _require(
            nulls and all(path == "inventoryChecksum" or path.startswith("liveEvidence.") for path in nulls),
            "null evidence escaped liveEvidence/inventoryChecksum",
        )
        _require(contract["missingEvidence"] == nulls, "missingEvidence does not exactly enumerate null evidence")
        return []
    except (OSError, TypeError, KeyError, VerificationError) as error:
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
    print("OK: inert Stadtstack case image/resource inventory contract is closed and review-only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
