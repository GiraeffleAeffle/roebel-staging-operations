#!/usr/bin/env python3
"""Assemble the one reviewed synthetic CitizenNFT handoff from trusted inputs.

The GitHub workflow independently obtains every input.  This module is kept
network-free so protected tests can prove the closed schemas, immutable pins
and exact handoff file set before candidate renderer code sees any bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


REVISION = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")

SOURCE_REVISION = "1b004dc0a1b156baf639fcdd54ab5a1b5501a575"
GATEWAY_RUN_ID = "33659908416"
GATEWAY_COMPONENT = "staging-participant-gateway"
GATEWAY_IMAGE = "ghcr.io/giraeffleaeffle/roebel-staging-participant-gateway"
GATEWAY_MANIFEST = "sha256:c2920003a6e514d56c662731877e665d518b1a22bc921cd3d58c60c77651d7e2"
GATEWAY_SOURCE_TREE = "sha256:827fea9741a90f9d2eede3bea2074687cd464ad496de33dac441dce7c2f84f15"
GATEWAY_WORKFLOW_SHA256 = "sha256:6c4c09517f53e18a301630cecb341f9996ba74eaa1dc1126ef735eb1c6460ac3"
GATEWAY_SIGNER = (
    "https://github.com/GiraeffleAeffle/Roebel-App/"
    ".github/workflows/staging-participant-gateway-publish.yml@refs/heads/main"
)
ISSUER = "https://token.actions.githubusercontent.com"

SOURCE_RECEIPT_SHA256 = "sha256:ab6a46795950551ba89409c533e263b1719e985995b0a404535c8d39fa6b36ea"
RELEASE_PINS_SHA256 = "sha256:0a67871be71addc5c650f3b674b3e5e6bbe1b2e9d0785119c31cb0ed1ef04653"
PUBLICATION_RECEIPT_SHA256 = "sha256:aaa4d4dbbec0129326e2ffd6dee1756d245c86ebbbc81494fb31bf2189cf4f97"
SBOM_SHA256 = "sha256:8256bdaf67cc55468d67a39733932397fce9d7b3ece2bf9a65bcad01c345e700"

MIGRATION_FILENAME = "76-staging-synthetic-citizen-adoption.sql"
MIGRATION_SOURCE_PATH = "supabase/migrations/20260902_staging_synthetic_citizen_adoption.sql"
MIGRATION_SHA256 = "sha256:992e56a65af74b32e35d2211ac57714f32e2e72e4fb82ea59afeb7dbbcefb282"
DATABASE_SCHEMA_SHA256 = "sha256:bcaa0b098a99b145e5111c17e29e5e7d9e9eb0840ee27643b3c26db34118bd66"
POLICY_VERSION = "roebel-test-citizen-nft-v2-staging-2026-09"

# These are the exact real gateway, topic and municipal-adoption bindings in
# the protected v4 predecessor.  The synthetic lane may only append its two
# pins; it may not relabel or replace the real civic eligibility path.
REAL_RELEASE_PINS = {
    "migrationSha256": "sha256:ad050047a71bf2cc82361c16169627dc0a0a66a7982db804b1612624f0f97eab",
    "databaseSchemaSha256": "sha256:a540591c718d4b2c74f56fe7310baf5b522ac6541384223a5263079e207f3d5d",
    "deactivationSha256": "sha256:777926a55e3f3b57f515d774d03999a646ddca07a06ec98d0202733276f6fdd5",
    "topicTracerMigrationSha256": "sha256:739cbcb189e3b12913ebf28dae74c931eab3cfae514e476bea4071092aef242e",
    "topicTracerDatabaseSchemaSha256": "sha256:298ef4a02f5f299afd157210a1074f179b08478c683bad3ed36430eb013854eb",
    "citizenAdoptionMigrationSha256": "sha256:35e12ecc7e54e76f8e12b17e828970bc2d3bd4393f14f58fe9604dd00d398a2d",
    "citizenAdoptionDatabaseSchemaSha256": "sha256:79fea3feb09029e6138c7675fa0b877c3367390bec012b07e052c55103de7c9c",
}


class HandoffError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HandoffError(message)


def closed(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == keys, f"{label} shape invalid")
    return value


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def load_bytes(path: Path, label: str) -> bytes:
    require(path.is_file() and not path.is_symlink(), f"{label} is not a regular file")
    return path.read_bytes()


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        return json.loads(load_bytes(path, label))
    except json.JSONDecodeError as error:
        raise HandoffError(f"{label} JSON invalid") from error


def canonical_candidate(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode()


def write_json(path: Path, value: dict[str, Any]) -> None:
    with tempfile.NamedTemporaryFile("w", dir=path.parent, prefix=f".{path.name}.", delete=False) as output:
        # Candidate key order is part of the v1/v2 payload digest contract.
        # Keep the explicit construction order used by the protected renderer.
        json.dump(value, output, indent=2)
        output.write("\n")
        temporary = Path(output.name)
    os.replace(temporary, path)


def assert_digest(value: Any, label: str) -> str:
    require(isinstance(value, str) and DIGEST.fullmatch(value) is not None, f"{label} invalid")
    return value


def assert_file_set(root: Path, expected: set[str], label: str) -> None:
    require(root.is_dir() and not root.is_symlink(), f"{label} root invalid")
    for path in root.rglob("*"):
        require(not path.is_symlink(), f"{label} contains a symlink")
    actual = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}
    require(actual == expected, f"{label} file set invalid")


def base_handoff_files(candidate: dict[str, Any]) -> set[str]:
    components = candidate.get("components")
    require(isinstance(components, list) and len(components) == 2, "v1 candidate components invalid")
    expected = {"previous-head.json", "release-set.candidate.json"}
    for component in components:
        require(isinstance(component, dict), "v1 candidate component invalid")
        name = component.get("component")
        manifest = assert_digest(component.get("manifestDigest"), "v1 component manifest")
        require(name in {"public-mecky", "roebel-web-staging"}, "v1 component identity invalid")
        bundle = f"sha256-{manifest.removeprefix('sha256:')}.jsonl"
        expected.update({
            f"evidence/{name}.component-evidence.json",
            f"bundles/provenance/{name}/{bundle}",
            f"bundles/sbom/{name}/{bundle}",
        })
    return expected


def validate_release_pins(path: Path) -> dict[str, Any]:
    raw = load_bytes(path, "gateway release pins")
    require(digest_bytes(raw) == RELEASE_PINS_SHA256, "gateway release-pins file checksum invalid")
    pins = closed(
        json.loads(raw),
        {"schemaVersion", *REAL_RELEASE_PINS, "syntheticCitizenAdoptionMigrationSha256", "syntheticCitizenAdoptionDatabaseSchemaSha256"},
        "gateway release pins",
    )
    require(pins["schemaVersion"] == "roebel_staging_participant_gateway_release_pins_v4", "gateway release-pins schema invalid")
    require({key: pins[key] for key in REAL_RELEASE_PINS} == REAL_RELEASE_PINS, "real gateway or citizen-adoption pin drift")
    require(pins["syntheticCitizenAdoptionMigrationSha256"] == MIGRATION_SHA256, "synthetic migration pin invalid")
    require(pins["syntheticCitizenAdoptionDatabaseSchemaSha256"] == DATABASE_SCHEMA_SHA256, "synthetic schema pin invalid")
    return pins


def validate_source_receipt(path: Path, release_pins: dict[str, Any]) -> dict[str, Any]:
    raw = load_bytes(path, "gateway source receipt")
    require(digest_bytes(raw) == SOURCE_RECEIPT_SHA256, "gateway source-receipt file checksum invalid")
    receipt = closed(
        json.loads(raw),
        {
            "schemaVersion", "sourceRevision", "component", "importName", "podReference",
            "manifestDigest", "configDigest", "layerDigests", "user", "entrypoint",
            "releasePinsSha256", "topicTracerMigrationSha256", "topicTracerDatabaseSchemaSha256",
            "citizenAdoptionMigrationSha256", "citizenAdoptionDatabaseSchemaSha256",
            "syntheticCitizenAdoptionMigrationSha256", "syntheticCitizenAdoptionDatabaseSchemaSha256",
        },
        "gateway source receipt",
    )
    require(receipt["schemaVersion"] == "roebel_staging_service_oci_receipt_v1", "gateway source-receipt schema invalid")
    require(receipt["sourceRevision"] == SOURCE_REVISION and receipt["component"] == GATEWAY_COMPONENT, "gateway source identity invalid")
    require(receipt["manifestDigest"] == GATEWAY_MANIFEST, "gateway manifest pin invalid")
    require(receipt["releasePinsSha256"] == RELEASE_PINS_SHA256, "gateway release-pins receipt binding invalid")
    require(receipt["importName"] == f"stadtstack.local/roebel-staging-lab/{GATEWAY_COMPONENT}:source-{SOURCE_REVISION}", "gateway import identity invalid")
    require(receipt["podReference"] == f"stadtstack.local/roebel-staging-lab/{GATEWAY_COMPONENT}@{GATEWAY_MANIFEST}", "gateway Pod identity invalid")
    require(receipt["user"] == "65532:65532" and receipt["entrypoint"] == ["node", "/app/staging-participant-gateway.cjs"], "gateway runtime identity invalid")
    assert_digest(receipt["configDigest"], "gateway configDigest")
    require(isinstance(receipt["layerDigests"], list) and receipt["layerDigests"], "gateway layers invalid")
    for layer in receipt["layerDigests"]:
        assert_digest(layer, "gateway layer")
    for field in (
        "topicTracerMigrationSha256", "topicTracerDatabaseSchemaSha256",
        "citizenAdoptionMigrationSha256", "citizenAdoptionDatabaseSchemaSha256",
        "syntheticCitizenAdoptionMigrationSha256", "syntheticCitizenAdoptionDatabaseSchemaSha256",
    ):
        require(receipt[field] == release_pins[field], f"gateway {field} receipt drift")
    return receipt


def validate_publication_receipt(path: Path, source_receipt: Path, sbom: Path) -> dict[str, Any]:
    raw = load_bytes(path, "gateway publication receipt")
    require(digest_bytes(raw) == PUBLICATION_RECEIPT_SHA256, "gateway publication-receipt file checksum invalid")
    receipt = closed(
        json.loads(raw),
        {
            "schemaVersion", "component", "sourceRevision", "image", "tag", "manifestDigest",
            "archiveSha256", "sourceReceiptSha256", "sbomSha256", *REAL_RELEASE_PINS,
            "syntheticCitizenAdoptionMigrationSha256", "syntheticCitizenAdoptionDatabaseSchemaSha256",
            "provenance", "sbomAttestation", "workflowIdentity", "runId", "civicAuthority", "deploymentEffect",
        },
        "gateway publication receipt",
    )
    require(receipt["schemaVersion"] == "roebel_staging_publication_receipt_v4", "gateway publication schema invalid")
    require(receipt["component"] == GATEWAY_COMPONENT and receipt["sourceRevision"] == SOURCE_REVISION, "gateway publication source invalid")
    require(receipt["image"] == GATEWAY_IMAGE and receipt["tag"] == f"source-{SOURCE_REVISION}" and receipt["manifestDigest"] == GATEWAY_MANIFEST, "gateway publication image invalid")
    require(receipt["workflowIdentity"] == GATEWAY_SIGNER and receipt["runId"] == GATEWAY_RUN_ID, "gateway publication workflow invalid")
    require(receipt["civicAuthority"] == "none" and receipt["deploymentEffect"] is False, "gateway publication authority boundary invalid")
    require(receipt["sourceReceiptSha256"] == digest_bytes(load_bytes(source_receipt, "gateway source receipt")), "publication source-receipt binding invalid")
    require(receipt["sbomSha256"] == SBOM_SHA256 == digest_bytes(load_bytes(sbom, "gateway SPDX document")), "publication SBOM binding invalid")
    require({key: receipt[key] for key in REAL_RELEASE_PINS} == REAL_RELEASE_PINS, "publication real-adoption pin drift")
    require(receipt["syntheticCitizenAdoptionMigrationSha256"] == MIGRATION_SHA256 and receipt["syntheticCitizenAdoptionDatabaseSchemaSha256"] == DATABASE_SCHEMA_SHA256, "publication synthetic pin drift")
    for key in ("provenance", "sbomAttestation"):
        item = closed(receipt[key], {"id", "url"}, f"gateway {key}")
        require(isinstance(item["id"], str) and item["id"].isdigit(), f"gateway {key} id invalid")
        require(item["url"] == f"https://github.com/GiraeffleAeffle/Roebel-App/attestations/{item['id']}", f"gateway {key} URL invalid")
    return receipt


def assemble(
    handoff_root: Path,
    source_receipt_path: Path,
    publication_receipt_path: Path,
    release_pins_path: Path,
    sbom_path: Path,
    source_tree_sha256: str,
    workflow_sha256: str,
) -> dict[str, Any]:
    require(source_tree_sha256 == GATEWAY_SOURCE_TREE, "gateway source-tree checksum invalid")
    require(workflow_sha256 == GATEWAY_WORKFLOW_SHA256, "gateway workflow checksum invalid")
    candidate_path = handoff_root / "release-set.candidate.json"
    candidate = load_json(candidate_path, "v1 candidate")
    require(candidate.get("schemaVersion") == "roebel_staging_release_set_candidate_v1", "v1 candidate schema invalid")
    require(candidate.get("promotionRevision") == SOURCE_REVISION, "v1 candidate promotion revision invalid")
    expected_v1 = base_handoff_files(candidate)
    bundle_name = f"sha256-{GATEWAY_MANIFEST.removeprefix('sha256:')}.jsonl"
    preassembled = expected_v1 | {
        f"artifacts/{MIGRATION_FILENAME}",
        f"bundles/provenance/{GATEWAY_COMPONENT}/{bundle_name}",
        f"bundles/sbom/{GATEWAY_COMPONENT}/{bundle_name}",
    }
    assert_file_set(handoff_root, preassembled, "preassembled handoff")

    release_pins = validate_release_pins(release_pins_path)
    source_receipt = validate_source_receipt(source_receipt_path, release_pins)
    validate_publication_receipt(publication_receipt_path, source_receipt_path, sbom_path)

    migration_path = handoff_root / "artifacts" / MIGRATION_FILENAME
    require(digest_bytes(load_bytes(migration_path, "synthetic migration")) == MIGRATION_SHA256, "synthetic migration artifact checksum invalid")

    provenance_path = handoff_root / "bundles" / "provenance" / GATEWAY_COMPONENT / bundle_name
    sbom_bundle_path = handoff_root / "bundles" / "sbom" / GATEWAY_COMPONENT / bundle_name
    provenance_digest = digest_bytes(load_bytes(provenance_path, "gateway provenance bundle"))
    load_bytes(sbom_bundle_path, "gateway SBOM bundle")
    sbom_digest = digest_bytes(load_bytes(sbom_path, "gateway SPDX document"))

    gateway = {
        "component": GATEWAY_COMPONENT,
        "sourceRevision": SOURCE_REVISION,
        "sourceTreeSha256": GATEWAY_SOURCE_TREE,
        "workflowSha256": GATEWAY_WORKFLOW_SHA256,
        "manifestDigest": GATEWAY_MANIFEST,
        "configDigest": source_receipt["configDigest"],
        "layerDigests": source_receipt["layerDigests"],
        "provenance": {
            "issuer": ISSUER,
            "identity": GATEWAY_SIGNER,
            "predicateType": "https://slsa.dev/provenance/v1",
            "attestationDigest": provenance_digest,
        },
        "sbom": {
            "format": "SPDX-2.3",
            "identity": "https://spdx.dev/spdx/v2.3",
            "artifactDigest": sbom_digest,
        },
    }
    synthetic = {
        "schemaVersion": "roebel_staging_synthetic_citizen_pass_release_v1",
        "environment": "staging",
        "testOnly": True,
        "authorityBinding": "none",
        "policyVersion": POLICY_VERSION,
        "testCitizenNft": {
            "chainId": 100,
            "address": "0x0be374808a567c9088ac8208b90a4239432b3220",
            "runtimeCodeKeccak256": "0x481949efe62483d881190ec16e7ac6ffd796b0e601ea952507fa6eee1986bafb",
        },
        "gateway": gateway,
        "migration": {
            "configMapFilename": MIGRATION_FILENAME,
            "path": MIGRATION_SOURCE_PATH,
            "sha256": MIGRATION_SHA256,
            "databaseSchemaSha256": DATABASE_SCHEMA_SHA256,
        },
    }
    payload = {
        "schemaVersion": "roebel_staging_release_set_candidate_v2",
        "promotionRevision": candidate["promotionRevision"],
        "expectedPreviousHead": candidate["expectedPreviousHead"],
        "components": candidate["components"],
        "syntheticCitizenPass": synthetic,
    }
    result = {**payload, "candidatePayloadDigest": digest_bytes(canonical_candidate(payload))}
    write_json(candidate_path, result)

    evidence_path = handoff_root / "evidence" / f"{GATEWAY_COMPONENT}.component-evidence.json"
    write_json(evidence_path, {
        "schemaVersion": "roebel_staging_component_evidence_v1",
        "component": GATEWAY_COMPONENT,
        "sourceRevision": SOURCE_REVISION,
        "sourceTreeSha256": GATEWAY_SOURCE_TREE,
        "workflowSha256": GATEWAY_WORKFLOW_SHA256,
        "manifestDigest": GATEWAY_MANIFEST,
        "provenance": {**gateway["provenance"], "subjectDigest": GATEWAY_MANIFEST},
        "sbom": {**gateway["sbom"], "subjectDigest": GATEWAY_MANIFEST},
    })
    expected_v2 = expected_v1 | {
        f"artifacts/{MIGRATION_FILENAME}",
        f"evidence/{GATEWAY_COMPONENT}.component-evidence.json",
        f"bundles/provenance/{GATEWAY_COMPONENT}/{bundle_name}",
        f"bundles/sbom/{GATEWAY_COMPONENT}/{bundle_name}",
    }
    assert_file_set(handoff_root, expected_v2, "assembled v2 handoff")
    return result


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--handoff-root", type=Path, required=True)
    parser.add_argument("--source-receipt", type=Path, required=True)
    parser.add_argument("--publication-receipt", type=Path, required=True)
    parser.add_argument("--release-pins", type=Path, required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--source-tree-sha256", required=True)
    parser.add_argument("--workflow-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        result = assemble(
            args.handoff_root.resolve(), args.source_receipt.resolve(),
            args.publication_receipt.resolve(), args.release_pins.resolve(),
            args.sbom.resolve(), args.source_tree_sha256, args.workflow_sha256,
        )
    except (OSError, KeyError, TypeError, json.JSONDecodeError, HandoffError) as error:
        print(f"synthetic CitizenNFT handoff failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({
        "schemaVersion": "roebel_staging_synthetic_citizen_pass_handoff_v1",
        "promotionRevision": result["promotionRevision"],
        "candidatePayloadDigest": result["candidatePayloadDigest"],
        "effect": "none",
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
