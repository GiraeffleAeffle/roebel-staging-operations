#!/usr/bin/env python3
"""Render one immutable Röbel Release Set into the protected Flux tree.

This module is effect-free. It accepts the publisher's value-free candidate
and evidence bundle and compares the complete previous head. Legacy v1 keeps
the five-field release transform; the closed v2 schema composes that release
with the separately typed staging-only citizen-pass gateway and ephemeral SQL
transition. It never contacts GitHub or Kubernetes.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
COMPONENT_ORDER = ("public-mecky", "roebel-web-staging")
POLICY = {
    "public-mecky": {
        "directory": "public-mecky",
        "repository": "ghcr.io/giraeffleaeffle/public-mecky",
        "container": "public-mecky",
        "namespace": "stadtstack-roebel-staging-lab",
        "name": "public-mecky",
    },
    "roebel-web-staging": {
        "directory": "web",
        "repository": "ghcr.io/giraeffleaeffle/roebel-web-staging",
        "container": "web",
        "namespace": "stadtstack-roebel-web-preview",
        "name": "roebel-web-presentation",
    },
}
SIGNER = "https://github.com/GiraeffleAeffle/Roebel-App/.github/workflows/roebel-staging-publish.yml@refs/heads/main"
PARTICIPANT_GATEWAY_SIGNER = (
    "https://github.com/GiraeffleAeffle/Roebel-App/"
    ".github/workflows/staging-participant-gateway-publish.yml@refs/heads/main"
)
ISSUER = "https://token.actions.githubusercontent.com"
RENDER_ROOT = Path("reviewed-render/roebel-staging")
PARTICIPANT_GATEWAY_ROOT = RENDER_ROOT / "staging-participant-gateway"
TRACER_DATA_PLANE_ROOT = RENDER_ROOT / "tracer-data-plane"
WEB_IDENTITY_CONTRACT_SET_ENV = [
    {
        "name": "ROEBEL_PUBLIC_IDENTITY_CONTRACT_SET",
        "value": "gnosis-staging-test-v1",
    },
    {
        "name": "ROEBEL_PUBLIC_ATTESTER_NFT_ADDRESS",
        "value": "0x5983F6300bCE3D9C1336a858Bd73F259bB8330F3",
    },
    {
        "name": "ROEBEL_PUBLIC_CITIZEN_NFT_ADDRESS",
        "value": "0x0Be374808A567c9088aC8208B90a4239432B3220",
    },
]
WEB_IDENTITY_CONTRACT_SET_ENV_NAMES = {
    item["name"] for item in WEB_IDENTITY_CONTRACT_SET_ENV
}
WEB_IDENTITY_CONTRACT_SET_ANNOTATIONS = {
    "stadtstack.io/identity-contract-set": "gnosis-staging-test-v1",
    "stadtstack.io/identity-contract-authority": "none",
    "stadtstack.io/identity-contract-set-sha256": (
        "sha256:af51165b7854caf2058ca7c645d74d8c8717d738ec879e806ecb860da1cae131"
    ),
    "stadtstack.io/identity-attester-runtime-code-keccak256": (
        "0x3c12a034ea9c2749c786497b5d50dcfaa4eff84860819d788517145a2276ee51"
    ),
    "stadtstack.io/identity-citizen-runtime-code-keccak256": (
        "0x481949efe62483d881190ec16e7ac6ffd796b0e601ea952507fa6eee1986bafb"
    ),
}
SYNTHETIC_CITIZEN_PASS_POLICY_VERSION = (
    "roebel-test-citizen-nft-v2-staging-2026-09"
)
SYNTHETIC_CITIZEN_PASS_SOURCE_REVISION = (
    "1b004dc0a1b156baf639fcdd54ab5a1b5501a575"
)
SYNTHETIC_CITIZEN_PASS_GATEWAY_SOURCE_TREE_SHA256 = (
    "sha256:827fea9741a90f9d2eede3bea2074687cd464ad496de33dac441dce7c2f84f15"
)
SYNTHETIC_CITIZEN_PASS_GATEWAY_MANIFEST_DIGEST = (
    "sha256:c2920003a6e514d56c662731877e665d518b1a22bc921cd3d58c60c77651d7e2"
)
SYNTHETIC_CITIZEN_PASS_GATEWAY_WORKFLOW_SHA256 = (
    "sha256:6c4c09517f53e18a301630cecb341f9996ba74eaa1dc1126ef735eb1c6460ac3"
)
SYNTHETIC_CITIZEN_ADOPTION_MIGRATION_SHA256 = (
    "sha256:992e56a65af74b32e35d2211ac57714f32e2e72e4fb82ea59afeb7dbbcefb282"
)
SYNTHETIC_CITIZEN_ADOPTION_DATABASE_SCHEMA_SHA256 = (
    "sha256:bcaa0b098a99b145e5111c17e29e5e7d9e9eb0840ee27643b3c26db34118bd66"
)
SYNTHETIC_CITIZEN_ADOPTION_FILENAME = (
    "76-staging-synthetic-citizen-adoption.sql"
)
SYNTHETIC_CITIZEN_ADOPTION_SOURCE_PATH = (
    "supabase/migrations/20260902_staging_synthetic_citizen_adoption.sql"
)
SYNTHETIC_CITIZEN_PASS_ENV = [
    {
        "name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_SYNTHETIC_CITIZEN_ADOPTION",
        "value": "enabled",
    },
    {
        "name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_SYNTHETIC_CITIZEN_ADOPTION_POLICY_VERSION",
        "value": SYNTHETIC_CITIZEN_PASS_POLICY_VERSION,
    },
    {
        "name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_TEST_CITIZEN_NFT_ADDRESS",
        "value": "0x0be374808a567c9088ac8208b90a4239432b3220",
    },
    {
        "name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_TEST_CITIZEN_NFT_RUNTIME_CODE_KECCAK256",
        "value": "0x481949efe62483d881190ec16e7ac6ffd796b0e601ea952507fa6eee1986bafb",
    },
    {
        "name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_SYNTHETIC_CITIZEN_ADOPTION_MIGRATION_SHA256",
        "value": SYNTHETIC_CITIZEN_ADOPTION_MIGRATION_SHA256,
    },
    {
        "name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_SYNTHETIC_CITIZEN_ADOPTION_DATABASE_SCHEMA_SHA256",
        "value": SYNTHETIC_CITIZEN_ADOPTION_DATABASE_SCHEMA_SHA256,
    },
]
SYNTHETIC_CITIZEN_PASS_ENV_NAMES = {
    item["name"] for item in SYNTHETIC_CITIZEN_PASS_ENV
}
SYNTHETIC_CITIZEN_PASS_POST_ROUTES = (
    "/api/staging-participant/v1/synthetic-citizen-adoption/challenge",
    "/api/staging-participant/v1/synthetic-citizen-adoption/tracers",
)
SYNTHETIC_CITIZEN_PASS_DYNAMIC_GET_PREFIX = (
    "/api/staging-participant/v1/synthetic-citizen-adoption/by-suggestion/"
)
SYNTHETIC_CITIZEN_PASS_TRANSITION_PATH = (
    RENDER_ROOT / "synthetic-citizen-pass-transition.json"
)
SYNTHETIC_CITIZEN_PASS_EXISTING_PATHS = (
    "policy/repository-contract.json",
    str(RENDER_ROOT / "head.json"),
    str(RENDER_ROOT / "integrity.json"),
    str(RENDER_ROOT / "live-preconditions.json"),
    str(RENDER_ROOT / "network-boundary-migration.json"),
    str(RENDER_ROOT / "public-mecky/deployment.json"),
    str(RENDER_ROOT / "web/deployment.json"),
    str(PARTICIPANT_GATEWAY_ROOT / "runtime-pin.json"),
    str(PARTICIPANT_GATEWAY_ROOT / "deployment.json"),
    str(PARTICIPANT_GATEWAY_ROOT / "ingress.json"),
    str(TRACER_DATA_PLANE_ROOT / "runtime-pin.json"),
    str(TRACER_DATA_PLANE_ROOT / "postgres-deployment.json"),
    str(TRACER_DATA_PLANE_ROOT / "kustomization.yaml"),
    str(TRACER_DATA_PLANE_ROOT / "bootstrap/zz-roebel-tracer.sh"),
)


def load_tracer_data_plane_module():
    path = Path(__file__).with_name("tracer_data_plane_policy.py")
    spec = importlib.util.spec_from_file_location(
        "promotion_tracer_data_plane_policy",
        path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("tracer data-plane policy unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TRACER_DATA_PLANE = load_tracer_data_plane_module()


class PromotionError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PromotionError(message)


def pairs(pairs_value: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs_value:
        require(key not in result, f"duplicate key: {key}")
        result[key] = value
    return result


def load(path: Path) -> Any:
    require(path.is_file() and not path.is_symlink(), f"input is not a regular file: {path}")
    return json.loads(path.read_text(), object_pairs_hook=pairs)


def read_text(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), f"input is not a regular file: {path}")
    return path.read_text()


def closed(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == expected, f"{label} shape invalid")
    return value


def canonical_candidate_payload(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode()


def canonical_render(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, prefix=f".{path.name}.", delete=False) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = Path(output.name)
    os.replace(temporary, path)


def write_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=f".{path.name}.", delete=False) as output:
        output.write(value)
        temporary = Path(output.name)
    os.replace(temporary, path)


def validate_head(value: Any, label: str) -> dict[str, Any]:
    head = closed(value, {"schemaVersion", "promotionRevision", "releaseSetDigest", "components"}, label)
    require(head["schemaVersion"] == "roebel_staging_release_set_head_v1", f"{label} schema invalid")
    require(isinstance(head["promotionRevision"], str) and REVISION.fullmatch(head["promotionRevision"]), f"{label} revision invalid")
    require(isinstance(head["releaseSetDigest"], str) and DIGEST.fullmatch(head["releaseSetDigest"]), f"{label} digest invalid")
    require(isinstance(head["components"], list) and len(head["components"]) == 2, f"{label} components invalid")
    for index, component_name in enumerate(COMPONENT_ORDER):
        component = closed(head["components"][index], {"component", "sourceRevision", "manifestDigest"}, f"{label} component")
        require(component["component"] == component_name, f"{label} component order invalid")
        require(isinstance(component["sourceRevision"], str) and REVISION.fullmatch(component["sourceRevision"]), f"{label} component revision invalid")
        require(isinstance(component["manifestDigest"], str) and DIGEST.fullmatch(component["manifestDigest"]), f"{label} component digest invalid")
    return head


def synthetic_citizen_pass_boundary() -> dict[str, Any]:
    return {
        "schemaVersion": "roebel_staging_synthetic_citizen_pass_boundary_v1",
        "environment": "staging",
        "testOnly": True,
        "authorityBinding": "none",
        "policyVersion": SYNTHETIC_CITIZEN_PASS_POLICY_VERSION,
        "testCitizenNft": {
            "chainId": 100,
            "address": "0x0be374808a567c9088ac8208b90a4239432b3220",
            "runtimeCodeKeccak256": (
                "0x481949efe62483d881190ec16e7ac6ffd796b0e601ea952507fa6eee1986bafb"
            ),
        },
        "migrationSha256": SYNTHETIC_CITIZEN_ADOPTION_MIGRATION_SHA256,
        "databaseSchemaSha256": SYNTHETIC_CITIZEN_ADOPTION_DATABASE_SCHEMA_SHA256,
        "realCitizenEligibility": False,
        "civicCaseCreated": False,
        "administrativeEndorsement": False,
        "bindingVote": False,
        "treasuryEffect": False,
        "paymentEffect": False,
        "rollback": "restore-exact-predecessor-bytes-and-remove-76-artifact",
    }


def validate_synthetic_citizen_pass(value: Any, promotion_revision: str) -> dict[str, Any]:
    bundle = closed(
        value,
        {
            "schemaVersion",
            "environment",
            "testOnly",
            "authorityBinding",
            "policyVersion",
            "testCitizenNft",
            "gateway",
            "migration",
        },
        "synthetic citizen pass",
    )
    require(
        bundle["schemaVersion"]
        == "roebel_staging_synthetic_citizen_pass_release_v1",
        "synthetic citizen pass schema invalid",
    )
    require(
        bundle["environment"] == "staging"
        and bundle["testOnly"] is True
        and bundle["authorityBinding"] == "none",
        "synthetic citizen pass authority boundary invalid",
    )
    require(
        bundle["policyVersion"] == SYNTHETIC_CITIZEN_PASS_POLICY_VERSION,
        "synthetic citizen pass policy version invalid",
    )
    require(
        bundle["testCitizenNft"]
        == synthetic_citizen_pass_boundary()["testCitizenNft"],
        "synthetic citizen pass test CitizenNFT binding invalid",
    )
    migration = closed(
        bundle["migration"],
        {"configMapFilename", "path", "sha256", "databaseSchemaSha256"},
        "synthetic citizen pass migration",
    )
    require(
        migration
        == {
            "configMapFilename": SYNTHETIC_CITIZEN_ADOPTION_FILENAME,
            "path": SYNTHETIC_CITIZEN_ADOPTION_SOURCE_PATH,
            "sha256": SYNTHETIC_CITIZEN_ADOPTION_MIGRATION_SHA256,
            "databaseSchemaSha256": (
                SYNTHETIC_CITIZEN_ADOPTION_DATABASE_SCHEMA_SHA256
            ),
        },
        "synthetic citizen pass migration binding invalid",
    )
    gateway = closed(
        bundle["gateway"],
        {
            "component",
            "sourceRevision",
            "sourceTreeSha256",
            "workflowSha256",
            "manifestDigest",
            "configDigest",
            "layerDigests",
            "provenance",
            "sbom",
        },
        "synthetic participant gateway release",
    )
    require(
        gateway["component"] == "staging-participant-gateway",
        "synthetic participant gateway component invalid",
    )
    require(
        promotion_revision == SYNTHETIC_CITIZEN_PASS_SOURCE_REVISION
        and gateway["sourceRevision"] == SYNTHETIC_CITIZEN_PASS_SOURCE_REVISION,
        "synthetic participant gateway source must equal the promotion revision",
    )
    for field in ("sourceTreeSha256", "workflowSha256", "manifestDigest", "configDigest"):
        require(
            isinstance(gateway[field], str) and DIGEST.fullmatch(gateway[field]),
            f"synthetic participant gateway {field} invalid",
        )
    require(
        gateway["sourceTreeSha256"]
        == SYNTHETIC_CITIZEN_PASS_GATEWAY_SOURCE_TREE_SHA256
        and gateway["workflowSha256"]
        == SYNTHETIC_CITIZEN_PASS_GATEWAY_WORKFLOW_SHA256
        and gateway["manifestDigest"]
        == SYNTHETIC_CITIZEN_PASS_GATEWAY_MANIFEST_DIGEST,
        "synthetic participant gateway protected publication binding invalid",
    )
    require(
        isinstance(gateway["layerDigests"], list)
        and gateway["layerDigests"]
        and all(
            isinstance(item, str) and DIGEST.fullmatch(item)
            for item in gateway["layerDigests"]
        ),
        "synthetic participant gateway layer digest invalid",
    )
    provenance = closed(
        gateway["provenance"],
        {"issuer", "identity", "predicateType", "attestationDigest"},
        "synthetic participant gateway provenance",
    )
    require(
        provenance["issuer"] == ISSUER
        and provenance["identity"] == PARTICIPANT_GATEWAY_SIGNER
        and provenance["predicateType"] == "https://slsa.dev/provenance/v1"
        and isinstance(provenance["attestationDigest"], str)
        and DIGEST.fullmatch(provenance["attestationDigest"]),
        "synthetic participant gateway provenance invalid",
    )
    sbom = closed(
        gateway["sbom"],
        {"format", "identity", "artifactDigest"},
        "synthetic participant gateway sbom",
    )
    require(
        sbom["format"] == "SPDX-2.3"
        and sbom["identity"] == "https://spdx.dev/spdx/v2.3"
        and isinstance(sbom["artifactDigest"], str)
        and DIGEST.fullmatch(sbom["artifactDigest"]),
        "synthetic participant gateway sbom invalid",
    )
    return bundle


def validate_candidate(value: Any, current_head: dict[str, Any]) -> dict[str, Any]:
    require(isinstance(value, dict), "candidate shape invalid")
    schema_version = value.get("schemaVersion")
    require(
        schema_version in {
            "roebel_staging_release_set_candidate_v1",
            "roebel_staging_release_set_candidate_v2",
        },
        "candidate schema invalid",
    )
    keys = {
        "schemaVersion",
        "promotionRevision",
        "expectedPreviousHead",
        "components",
        "candidatePayloadDigest",
    }
    if schema_version == "roebel_staging_release_set_candidate_v2":
        keys.add("syntheticCitizenPass")
    candidate = closed(
        value,
        keys,
        "candidate",
    )
    require(isinstance(candidate["promotionRevision"], str) and REVISION.fullmatch(candidate["promotionRevision"]), "candidate revision invalid")
    expected_head = validate_head(
        {"schemaVersion": "roebel_staging_release_set_head_v1", **candidate["expectedPreviousHead"]},
        "expected previous head",
    )
    require(expected_head == current_head, "candidate previous head is stale")
    require(isinstance(candidate["components"], list) and len(candidate["components"]) == 2, "candidate components invalid")
    previous_components = {
        component["component"]: component for component in expected_head["components"]
    }

    for index, component_name in enumerate(COMPONENT_ORDER):
        component = closed(
            candidate["components"][index],
            {"component", "sourceRevision", "manifestDigest", "configDigest", "layerDigests", "provenance", "sbom"},
            f"candidate {component_name}",
        )
        require(component["component"] == component_name, "candidate component order invalid")
        require(isinstance(component["sourceRevision"], str) and REVISION.fullmatch(component["sourceRevision"]), "component revision invalid")
        for field in ("manifestDigest", "configDigest"):
            require(isinstance(component[field], str) and DIGEST.fullmatch(component[field]), f"component {field} invalid")
        require(isinstance(component["layerDigests"], list) and component["layerDigests"], "component layers invalid")
        require(all(isinstance(item, str) and DIGEST.fullmatch(item) for item in component["layerDigests"]), "component layer digest invalid")
        provenance = closed(component["provenance"], {"issuer", "identity", "predicateType", "attestationDigest"}, "candidate provenance")
        require(provenance["issuer"] == ISSUER and provenance["identity"] == SIGNER, "candidate provenance identity invalid")
        require(provenance["predicateType"] == "https://slsa.dev/provenance/v1", "candidate provenance type invalid")
        require(isinstance(provenance["attestationDigest"], str) and DIGEST.fullmatch(provenance["attestationDigest"]), "candidate attestation digest invalid")
        sbom = closed(component["sbom"], {"format", "identity", "artifactDigest"}, "candidate sbom")
        require(sbom["format"] == "SPDX-2.3" and sbom["identity"] == "https://spdx.dev/spdx/v2.3", "candidate sbom identity invalid")
        require(isinstance(sbom["artifactDigest"], str) and DIGEST.fullmatch(sbom["artifactDigest"]), "candidate sbom digest invalid")

        # A release-set can reuse an unchanged component, but only from the
        # complete head that this candidate compare-and-swaps.  This permits
        # affected-component publishing without turning the handoff into a
        # historical image-selection mechanism.
        previous = previous_components[component_name]
        if component["sourceRevision"] != candidate["promotionRevision"]:
            require(
                component["sourceRevision"] == previous["sourceRevision"]
                and component["manifestDigest"] == previous["manifestDigest"],
                f"{component_name} non-promotion component must exactly reuse the expected previous head",
            )

    synthetic = None
    if schema_version == "roebel_staging_release_set_candidate_v2":
        synthetic = validate_synthetic_citizen_pass(
            candidate["syntheticCitizenPass"],
            candidate["promotionRevision"],
        )
        web = candidate["components"][COMPONENT_ORDER.index("roebel-web-staging")]
        require(
            web["sourceRevision"] == candidate["promotionRevision"],
            "synthetic citizen pass requires the promoted Web component",
        )

    payload = {
        "schemaVersion": candidate["schemaVersion"],
        "promotionRevision": candidate["promotionRevision"],
        "expectedPreviousHead": candidate["expectedPreviousHead"],
        "components": candidate["components"],
    }
    if synthetic is not None:
        payload["syntheticCitizenPass"] = synthetic
    require(candidate["candidatePayloadDigest"] == digest_bytes(canonical_candidate_payload(payload)), "candidate payload digest invalid")
    require(any(item["sourceRevision"] == candidate["promotionRevision"] for item in candidate["components"]), "candidate is a no-op")
    return candidate


def validate_component_evidence(
    component: dict[str, Any],
    evidence_root: Path,
    signer: str,
    *,
    source_tree: bool = False,
) -> None:
    name = component["component"]
    evidence_keys = {
        "schemaVersion",
        "component",
        "sourceRevision",
        "manifestDigest",
        "provenance",
        "sbom",
    }
    if source_tree:
        evidence_keys.add("sourceTreeSha256")
        evidence_keys.add("workflowSha256")
    evidence = closed(
        load(evidence_root / "evidence" / f"{name}.component-evidence.json"),
        evidence_keys,
        f"{name} evidence",
    )
    require(evidence["schemaVersion"] == "roebel_staging_component_evidence_v1", "evidence schema invalid")
    require(evidence["component"] == name and evidence["sourceRevision"] == component["sourceRevision"], "evidence component binding invalid")
    require(evidence["manifestDigest"] == component["manifestDigest"], "evidence manifest binding invalid")
    if source_tree:
        require(
            evidence["sourceTreeSha256"] == component["sourceTreeSha256"],
            "evidence source-tree binding invalid",
        )
        require(
            evidence["workflowSha256"] == component["workflowSha256"],
            "evidence workflow binding invalid",
        )
    provenance = closed(evidence["provenance"], {"issuer", "identity", "predicateType", "subjectDigest", "attestationDigest"}, "evidence provenance")
    require(provenance["issuer"] == ISSUER and provenance["identity"] == signer, "evidence provenance identity invalid")
    require(provenance["predicateType"] == "https://slsa.dev/provenance/v1", "evidence provenance type invalid")
    require(provenance["subjectDigest"] == component["manifestDigest"], "evidence provenance subject invalid")
    require(provenance["attestationDigest"] == component["provenance"]["attestationDigest"], "evidence provenance digest invalid")
    bundle = evidence_root / "bundles" / "provenance" / name / f"sha256-{component['manifestDigest'].removeprefix('sha256:')}.jsonl"
    require(bundle.is_file() and not bundle.is_symlink(), "provenance bundle missing")
    require(digest_bytes(bundle.read_bytes()) == provenance["attestationDigest"], "provenance bundle checksum invalid")
    sbom = closed(evidence["sbom"], {"format", "identity", "subjectDigest", "artifactDigest"}, "evidence sbom")
    require(sbom["format"] == "SPDX-2.3" and sbom["identity"] == "https://spdx.dev/spdx/v2.3", "evidence sbom identity invalid")
    require(sbom["subjectDigest"] == component["manifestDigest"], "evidence sbom subject invalid")
    require(sbom["artifactDigest"] == component["sbom"]["artifactDigest"], "evidence sbom digest invalid")
    sbom_bundle = evidence_root / "bundles" / "sbom" / name / f"sha256-{component['manifestDigest'].removeprefix('sha256:')}.jsonl"
    require(sbom_bundle.is_file() and not sbom_bundle.is_symlink() and sbom_bundle.stat().st_size > 0, "sbom bundle missing")


def validate_evidence(candidate: dict[str, Any], evidence_root: Path) -> None:
    for component in candidate["components"]:
        validate_component_evidence(component, evidence_root, SIGNER)
    synthetic = candidate.get("syntheticCitizenPass")
    if synthetic is None:
        return
    gateway = synthetic["gateway"]
    validate_component_evidence(
        gateway,
        evidence_root,
        PARTICIPANT_GATEWAY_SIGNER,
        source_tree=True,
    )
    migration = evidence_root / "artifacts" / SYNTHETIC_CITIZEN_ADOPTION_FILENAME
    require(
        migration.is_file() and not migration.is_symlink(),
        "synthetic citizen adoption migration artifact missing",
    )
    require(
        digest_bytes(migration.read_bytes())
        == SYNTHETIC_CITIZEN_ADOPTION_MIGRATION_SHA256,
        "synthetic citizen adoption migration checksum invalid",
    )


def primary_container(deployment: dict[str, Any], component: str) -> dict[str, Any]:
    containers = deployment["spec"]["template"]["spec"]["containers"]
    found = [item for item in containers if item.get("name") == POLICY[component]["container"]]
    require(len(found) == 1, f"{component} primary container invalid")
    return found[0]


def activate_web_identity_contract_set(deployment: dict[str, Any]) -> None:
    """Add the exact selector on its first Web promotion; preserve it thereafter."""
    template = deployment["spec"]["template"]
    container = primary_container(deployment, "roebel-web-staging")
    environment = container["env"]
    by_name = {item.get("name"): item for item in environment}
    require(
        len(by_name) == len(environment),
        "Web identity contract set environment names invalid or repeated",
    )
    present_names = WEB_IDENTITY_CONTRACT_SET_ENV_NAMES & set(by_name)
    annotations = template.setdefault("metadata", {}).setdefault("annotations", {})
    present_annotations = (
        set(WEB_IDENTITY_CONTRACT_SET_ANNOTATIONS) & set(annotations)
    )
    if present_names or present_annotations:
        require(
            present_names == WEB_IDENTITY_CONTRACT_SET_ENV_NAMES,
            "Web identity contract set predecessor is partial",
        )
        require(
            [by_name[item["name"]] for item in WEB_IDENTITY_CONTRACT_SET_ENV]
            == WEB_IDENTITY_CONTRACT_SET_ENV,
            "Web identity contract set predecessor address binding drift",
        )
        require(
            {
                name: annotations[name]
                for name in WEB_IDENTITY_CONTRACT_SET_ANNOTATIONS
                if name in annotations
            }
            == WEB_IDENTITY_CONTRACT_SET_ANNOTATIONS,
            "Web identity contract set predecessor evidence drift",
        )
        return
    names = [item["name"] for item in environment]
    insertion = names.index("ROEBEL_PUBLIC_GNOSIS_BUNDLER_URL")
    environment[insertion:insertion] = copy.deepcopy(
        WEB_IDENTITY_CONTRACT_SET_ENV,
    )
    annotations.update(copy.deepcopy(WEB_IDENTITY_CONTRACT_SET_ANNOTATIONS))


def synthetic_gateway_runtime_pin(
    predecessor: dict[str, Any],
    gateway: dict[str, Any],
) -> dict[str, Any]:
    require(
        predecessor.get("schemaVersion")
        == "roebel_staging_participant_gateway_runtime_pin_v4",
        "synthetic participant gateway requires the v4 predecessor",
    )
    require(
        not any(key.startswith("syntheticCitizen") for key in predecessor),
        "synthetic participant gateway predecessor already contains capability",
    )
    value = copy.deepcopy(predecessor)
    value["schemaVersion"] = "roebel_staging_participant_gateway_runtime_pin_v5"
    value["sourceRevision"] = gateway["sourceRevision"]
    value["sourceTreeSha256"] = gateway["sourceTreeSha256"]
    value["workflowSha256"] = gateway["workflowSha256"]
    value["manifestDigest"] = gateway["manifestDigest"]
    value["syntheticCitizenAdoptionMigrationSha256"] = (
        SYNTHETIC_CITIZEN_ADOPTION_MIGRATION_SHA256
    )
    value["syntheticCitizenAdoptionDatabaseSchemaSha256"] = (
        SYNTHETIC_CITIZEN_ADOPTION_DATABASE_SCHEMA_SHA256
    )
    value["syntheticCitizenAdoption"] = synthetic_citizen_pass_boundary()
    return value


def synthetic_gateway_deployment(
    predecessor: dict[str, Any],
    runtime_pin: dict[str, Any],
) -> dict[str, Any]:
    value = copy.deepcopy(predecessor)
    container = value["spec"]["template"]["spec"]["containers"][0]
    environment = container["env"]
    by_name = {item.get("name"): item for item in environment}
    require(
        len(by_name) == len(environment),
        "participant gateway environment names invalid or repeated",
    )
    require(
        not (SYNTHETIC_CITIZEN_PASS_ENV_NAMES & set(by_name)),
        "synthetic participant gateway predecessor environment is partial",
    )
    by_name["ROEBEL_STAGING_PARTICIPANT_GATEWAY_SOURCE_REVISION"]["value"] = (
        runtime_pin["sourceRevision"]
    )
    by_name["ROEBEL_STAGING_PARTICIPANT_GATEWAY_MANIFEST_DIGEST"]["value"] = (
        runtime_pin["manifestDigest"]
    )
    container["image"] = (
        runtime_pin["imageRepository"] + "@" + runtime_pin["manifestDigest"]
    )
    environment.extend(copy.deepcopy(SYNTHETIC_CITIZEN_PASS_ENV))
    return value


def synthetic_repository_contract(predecessor: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(predecessor)
    value["ephemeralTracerDataPlaneBoundary"] = (
        TRACER_DATA_PLANE.contract_boundary(
            TRACER_DATA_PLANE.SYNTHETIC_PRODUCT_ARTIFACTS,
        )
    )
    gateway = value["stagingParticipantGatewayBoundary"]
    require(
        "syntheticCitizenAdoption" not in gateway
        and gateway["schemaVersion"]
        == "roebel_staging_participant_gateway_runtime_pin_v4",
        "synthetic repository contract predecessor drift",
    )
    for route in SYNTHETIC_CITIZEN_PASS_POST_ROUTES:
        require(route not in gateway["exactGatewayPaths"], "synthetic route already present")
        gateway["exactGatewayPaths"].append(route)
        gateway["methodPathMatrix"]["OPTIONS"].append(route)
        gateway["methodPathMatrix"]["POST"].append(route)
    require(
        SYNTHETIC_CITIZEN_PASS_DYNAMIC_GET_PREFIX
        not in gateway["dynamicGetPrefixes"],
        "synthetic dynamic route already present",
    )
    gateway["dynamicGetPrefixes"].append(
        SYNTHETIC_CITIZEN_PASS_DYNAMIC_GET_PREFIX,
    )
    gateway["schemaVersion"] = (
        "roebel_staging_participant_gateway_runtime_pin_v5"
    )
    gateway["syntheticCitizenAdoption"] = synthetic_citizen_pass_boundary()
    return value


def gateway_early_allowlist(
    exact_paths: list[str],
    post_paths: list[str],
    dynamic_get_prefixes: list[str],
) -> str:
    return "\n".join([
        "http-request deny deny_status 404 if "
        + " ".join([
            *(f"!{{ path {path} }}" for path in exact_paths),
            *(f"!{{ path_beg {prefix} }}" for prefix in dynamic_get_prefixes),
        ]),
        "http-request deny deny_status 405 if { method POST } "
        + " ".join(f"!{{ path {path} }}" for path in post_paths),
        "http-request deny deny_status 405 if { method OPTIONS } "
        + " ".join(f"!{{ path {path} }}" for path in exact_paths),
        "http-request deny deny_status 405 if { method HEAD }",
        "http-request deny deny_status 405 if { method GET } "
        + " ".join([
            f"!{{ path {exact_paths[0]} }}",
            *(f"!{{ path_beg {prefix} }}" for prefix in dynamic_get_prefixes),
        ]),
        "http-request deny deny_status 405 unless { method GET HEAD POST OPTIONS }",
        "stick-table type ip size 10k expire 60s store http_req_rate(1m)",
        "http-request track-sc0 src",
        "http-request deny deny_status 429 if { sc_http_req_rate(0) gt 30 }",
    ])


def synthetic_gateway_ingress(
    predecessor: dict[str, Any],
    contract: dict[str, Any],
) -> dict[str, Any]:
    value = copy.deepcopy(predecessor)
    boundary = contract["stagingParticipantGatewayBoundary"]
    value["metadata"]["annotations"][
        "haproxy-ingress.github.io/config-backend-early"
    ] = gateway_early_allowlist(
        boundary["exactGatewayPaths"],
        boundary["methodPathMatrix"]["POST"],
        boundary["dynamicGetPrefixes"],
    )
    return value


def synthetic_transition_record(
    root: Path,
    predecessor_bytes: dict[str, bytes],
    source_revision: str,
) -> dict[str, Any]:
    sql_path = str(
        TRACER_DATA_PLANE_ROOT
        / "bootstrap"
        / SYNTHETIC_CITIZEN_ADOPTION_FILENAME
    )
    return {
        "schemaVersion": "roebel_staging_synthetic_citizen_pass_transition_v1",
        "environment": "staging",
        "testOnly": True,
        "authorityBinding": "none",
        "sourceRevision": source_revision,
        "capability": synthetic_citizen_pass_boundary(),
        "forward": {
            "atomicComponents": [
                "roebel-web-staging",
                "staging-participant-gateway",
                "ephemeral-tracer-data-plane",
            ],
            "migrationPath": sql_path,
        },
        "rollback": {
            "strategy": "restore-exact-predecessor-bytes-and-remove-added-files",
            "restoreFiles": [
                {
                    "path": path,
                    "predecessorSha256": digest_bytes(predecessor_bytes[path]),
                    "successorSha256": digest_bytes((root / path).read_bytes()),
                }
                for path in sorted(predecessor_bytes)
            ],
            "removeFiles": [
                sql_path,
                str(SYNTHETIC_CITIZEN_PASS_TRANSITION_PATH),
            ],
        },
    }


def render(root: Path, candidate_path: Path, evidence_root: Path) -> dict[str, Any]:
    render_root = root / RENDER_ROOT
    current_head = validate_head(load(render_root / "head.json"), "current head")
    candidate = validate_candidate(load(candidate_path), current_head)
    validate_evidence(candidate, evidence_root)
    synthetic = candidate.get("syntheticCitizenPass")
    predecessor_bytes: dict[str, bytes] = {}
    if synthetic is not None:
        predecessor_bytes = {
            path: (root / path).read_bytes()
            for path in SYNTHETIC_CITIZEN_PASS_EXISTING_PATHS
        }
        for path in (
            TRACER_DATA_PLANE_ROOT
            / "bootstrap"
            / SYNTHETIC_CITIZEN_ADOPTION_FILENAME,
            SYNTHETIC_CITIZEN_PASS_TRANSITION_PATH,
        ):
            require(
                not (root / path).exists(),
                f"synthetic citizen pass predecessor already contains {path}",
            )
    by_component = {item["component"]: item for item in candidate["components"]}
    next_head = {
        "components": [
            {
                "component": name,
                "manifestDigest": by_component[name]["manifestDigest"],
                "sourceRevision": by_component[name]["sourceRevision"],
            }
            for name in COMPONENT_ORDER
        ],
        "promotionRevision": candidate["promotionRevision"],
        "releaseSetDigest": candidate["candidatePayloadDigest"],
        "schemaVersion": "roebel_staging_release_set_head_v1",
    }

    desired_deployments: list[dict[str, Any]] = []
    previous_preconditions = load(render_root / "live-preconditions.json")["requiredLivePreconditions"]
    preconditions: list[dict[str, Any]] = []
    patches: list[dict[str, Any]] = []
    for index, name in enumerate(COMPONENT_ORDER):
        policy = POLICY[name]
        deployment_path = render_root / policy["directory"] / "deployment.json"
        deployment = copy.deepcopy(load(deployment_path))
        current_image = primary_container(deployment, name)["image"]
        record = by_component[name]
        deployment.setdefault("metadata", {}).setdefault("annotations", {})["stadtstack.io/source-revision"] = record["sourceRevision"]
        deployment["metadata"]["annotations"]["stadtstack.io/release-set-sha256"] = next_head["releaseSetDigest"]
        deployment["spec"]["template"].setdefault("metadata", {}).setdefault("annotations", {})["stadtstack.io/source-revision"] = record["sourceRevision"]
        container = primary_container(deployment, name)
        container["image"] = f"{policy['repository']}@{record['manifestDigest']}"
        container["imagePullPolicy"] = "IfNotPresent"
        if name == "roebel-web-staging" and synthetic is not None:
            activate_web_identity_contract_set(deployment)
        desired_deployments.append(deployment)
        precondition = copy.deepcopy(previous_preconditions[index])
        require(precondition["component"] == name, "base precondition order invalid")
        precondition["currentImage"] = current_image
        preconditions.append(precondition)
        target = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "name": policy["name"],
            "namespace": policy["namespace"],
        }
        patches.append(
            {
                "component": name,
                "operations": [
                    {"op": "add", "path": "/metadata/annotations/stadtstack.io~1source-revision", "value": record["sourceRevision"]},
                    {"op": "add", "path": "/metadata/annotations/stadtstack.io~1release-set-sha256", "value": next_head["releaseSetDigest"]},
                    {"op": "replace", "path": "/spec/template/metadata/annotations/stadtstack.io~1source-revision", "value": record["sourceRevision"]},
                    {"op": "replace", "path": "/spec/template/spec/containers/0/image", "value": container["image"]},
                    {"op": "replace", "path": "/spec/template/spec/containers/0/imagePullPolicy", "value": "IfNotPresent"},
                ],
                "target": target,
            }
        )

    desired_objects = [
        desired_deployments[0],
        load(render_root / "public-mecky/service.json"),
        load(render_root / "public-mecky/networkpolicy.json"),
        desired_deployments[1],
        load(render_root / "web/networkpolicy.json"),
        load(render_root / "web/ingress.json"),
    ]
    network_boundary_migration = load(
        render_root / "network-boundary-migration.json"
    )
    participant_gateway_root = render_root / "staging-participant-gateway"
    participant_gateway_payload: dict[str, Any] | None = None
    synthetic_gateway_pin: dict[str, Any] | None = None
    synthetic_gateway_resource: dict[str, Any] | None = None
    synthetic_gateway_ingress_resource: dict[str, Any] | None = None
    synthetic_contract: dict[str, Any] | None = None
    synthetic_tracer_pin: dict[str, Any] | None = None
    synthetic_postgres: dict[str, Any] | None = None
    synthetic_kustomization: str | None = None
    synthetic_bootstrap_script: str | None = None
    synthetic_sql: bytes | None = None
    if participant_gateway_root.is_dir() and not participant_gateway_root.is_symlink():
        workbench_ingress_root = participant_gateway_root / "workbench-ingress"
        current_gateway_pin = load(participant_gateway_root / "runtime-pin.json")
        current_gateway_deployment = load(participant_gateway_root / "deployment.json")
        current_gateway_ingress = load(participant_gateway_root / "ingress.json")
        if synthetic is not None:
            synthetic_gateway_pin = synthetic_gateway_runtime_pin(
                current_gateway_pin,
                synthetic["gateway"],
            )
            synthetic_gateway_resource = synthetic_gateway_deployment(
                current_gateway_deployment,
                synthetic_gateway_pin,
            )
            current_gateway_pin = synthetic_gateway_pin
            current_gateway_deployment = synthetic_gateway_resource
            deployment_receipts = [
                item
                for item in network_boundary_migration["objects"]
                if item.get("kind") == "Deployment"
                and item.get("name") == "roebel-staging-participant-gateway"
            ]
            require(
                len(deployment_receipts) == 1,
                "participant gateway migration deployment receipt invalid",
            )
            deployment_receipts[0]["sha256"] = digest_bytes(
                canonical_render(synthetic_gateway_resource),
            )
            synthetic_contract = synthetic_repository_contract(
                load(root / "policy/repository-contract.json"),
            )
            synthetic_gateway_ingress_resource = synthetic_gateway_ingress(
                current_gateway_ingress,
                synthetic_contract,
            )
            current_gateway_ingress = synthetic_gateway_ingress_resource
            ingress_receipts = [
                item
                for item in network_boundary_migration["objects"]
                if item.get("kind") == "Ingress"
                and item.get("name") == "roebel-staging-participant-gateway"
            ]
            require(
                len(ingress_receipts) == 1,
                "participant gateway migration ingress receipt invalid",
            )
            ingress_receipts[0]["sha256"] = digest_bytes(
                canonical_render(synthetic_gateway_ingress_resource),
            )
            synthetic_sql = (
                evidence_root
                / "artifacts"
                / SYNTHETIC_CITIZEN_ADOPTION_FILENAME
            ).read_bytes()
            synthetic_tracer_pin = TRACER_DATA_PLANE.runtime_pin(
                candidate["promotionRevision"],
                TRACER_DATA_PLANE.SYNTHETIC_PRODUCT_ARTIFACTS,
            )
            synthetic_postgres = TRACER_DATA_PLANE.expected_postgres_deployment(
                TRACER_DATA_PLANE.SYNTHETIC_PRODUCT_ARTIFACTS,
            )
            synthetic_kustomization = TRACER_DATA_PLANE.kustomization_text(
                TRACER_DATA_PLANE.SYNTHETIC_PRODUCT_ARTIFACTS,
            )
            synthetic_bootstrap_script = TRACER_DATA_PLANE.bootstrap_verify_script(
                TRACER_DATA_PLANE.SYNTHETIC_PRODUCT_ARTIFACTS,
            )
        participant_gateway_payload = {
            "runtimePin": current_gateway_pin,
            "deployment": current_gateway_deployment,
            "service": load(participant_gateway_root / "service.json"),
            "networkPolicy": load(participant_gateway_root / "networkpolicy.json"),
            "serviceAccount": load(participant_gateway_root / "serviceaccount.json"),
            "ingress": current_gateway_ingress,
            "kustomization": read_text(participant_gateway_root / "kustomization.yaml"),
            "workbenchIngressNetworkPolicy": load(
                workbench_ingress_root / "networkpolicy.json"
            ),
            "workbenchIngressKustomization": read_text(
                workbench_ingress_root / "kustomization.yaml"
            ),
        }
    require(
        synthetic is None or participant_gateway_payload is not None,
        "synthetic citizen pass requires the participant gateway render",
    )
    checksum_payload: dict[str, Any] = {
        "nextEnvironmentHead": next_head,
        "objects": desired_objects,
    }
    reviewed_knowledge_root = render_root / "reviewed-public-knowledge"
    if reviewed_knowledge_root.is_dir() and not reviewed_knowledge_root.is_symlink():
        checksum_payload["reviewedPublicKnowledge"] = {
            "deployment": load(reviewed_knowledge_root / "deployment.json"),
            "service": load(reviewed_knowledge_root / "service.json"),
            "networkPolicy": load(reviewed_knowledge_root / "networkpolicy.json"),
            "kustomization": read_text(reviewed_knowledge_root / "kustomization.yaml"),
            "runtimePin": load(reviewed_knowledge_root / "runtime-pin.json"),
        }
    if participant_gateway_payload is not None:
        checksum_payload["stagingParticipantGateway"] = participant_gateway_payload
    integrity = {
        "desiredRenderSha256": digest_bytes(canonical_render(checksum_payload)),
        "networkBoundaryMigrationSha256": digest_bytes(
            canonical_render(network_boundary_migration)
        ),
        "releaseSetDigest": next_head["releaseSetDigest"],
        "schemaVersion": "roebel_staging_reviewed_render_v1",
    }
    live = {
        "patches": patches,
        "previousEnvironmentHead": current_head,
        "requiredLivePreconditions": preconditions,
    }
    write_json(render_root / "head.json", next_head)
    write_json(render_root / "integrity.json", integrity)
    write_json(render_root / "live-preconditions.json", live)
    for index, name in enumerate(COMPONENT_ORDER):
        write_json(render_root / POLICY[name]["directory"] / "deployment.json", desired_deployments[index])
    if synthetic is not None:
        require(
            synthetic_gateway_pin is not None
            and synthetic_gateway_resource is not None
            and synthetic_gateway_ingress_resource is not None
            and synthetic_contract is not None
            and synthetic_tracer_pin is not None
            and synthetic_postgres is not None
            and synthetic_kustomization is not None
            and synthetic_bootstrap_script is not None
            and synthetic_sql is not None,
            "synthetic citizen pass render composition incomplete",
        )
        write_json(root / "policy/repository-contract.json", synthetic_contract)
        write_json(
            participant_gateway_root / "runtime-pin.json",
            synthetic_gateway_pin,
        )
        write_json(
            participant_gateway_root / "deployment.json",
            synthetic_gateway_resource,
        )
        write_json(
            participant_gateway_root / "ingress.json",
            synthetic_gateway_ingress_resource,
        )
        write_json(
            root / TRACER_DATA_PLANE_ROOT / "runtime-pin.json",
            synthetic_tracer_pin,
        )
        write_json(
            root / TRACER_DATA_PLANE_ROOT / "postgres-deployment.json",
            synthetic_postgres,
        )
        write_bytes(
            root / TRACER_DATA_PLANE_ROOT / "kustomization.yaml",
            synthetic_kustomization.encode(),
        )
        write_bytes(
            root
            / TRACER_DATA_PLANE_ROOT
            / "bootstrap/zz-roebel-tracer.sh",
            synthetic_bootstrap_script.encode(),
        )
        write_bytes(
            root
            / TRACER_DATA_PLANE_ROOT
            / "bootstrap"
            / SYNTHETIC_CITIZEN_ADOPTION_FILENAME,
            synthetic_sql,
        )
        write_json(
            render_root / "network-boundary-migration.json",
            network_boundary_migration,
        )
        write_json(
            root / SYNTHETIC_CITIZEN_PASS_TRANSITION_PATH,
            synthetic_transition_record(
                root,
                predecessor_bytes,
                candidate["promotionRevision"],
            ),
        )
    return {
        "schemaVersion": (
            "roebel_staging_automatic_promotion_render_v2"
            if synthetic is not None
            else "roebel_staging_automatic_promotion_render_v1"
        ),
        "status": "rendered_effect_free",
        "promotionRevision": next_head["promotionRevision"],
        "releaseSetDigest": next_head["releaseSetDigest"],
        "changedComponents": [
            name
            for name in COMPONENT_ORDER
            if next_head["components"][COMPONENT_ORDER.index(name)]
            != current_head["components"][COMPONENT_ORDER.index(name)]
        ],
        "effects": {"clusterMutation": False, "secretRead": False, "civicMutation": False},
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = render(args.root.resolve(), args.candidate.resolve(), args.evidence_root.resolve())
    except (OSError, KeyError, IndexError, TypeError, json.JSONDecodeError, PromotionError) as error:
        print(f"automatic promotion render failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
