"""The immutable project-owned successor to the original staging identity pair.

These are protected policy values, never caller-selected configuration. The
historical v1 definitions stay in their original modules. This successor
changes only test identity checks; real eligibility and all authority, network,
Secret and storage boundaries are inherited unchanged.
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any


SOURCE_REVISION = "2961a04fb9b869bff35a411784c3fb4747eaf435"
GATEWAY_RELEASE = {
    "sourceRevision": SOURCE_REVISION,
    "sourceTreeSha256": "sha256:ff878037e84f4046757d9d51e8c712529fde19b4a5649e24329baad9391908e5",
    "workflowSha256": "sha256:57f845cd106120c365a60fcf9e80e00e5304c410f2aafd462ee8f89073dd1a61",
    "manifestDigest": "sha256:ee7fd9e8cb8dc9032ddcf7615579dfcf2ac93f3c7e0a5735c7932eed2fef1c1c",
}
MIGRATION_ARTIFACT = (
    "77-staging-synthetic-citizen-pass-v2.sql",
    "supabase/migrations/20260905_staging_synthetic_citizen_pass_v2.sql",
    "sha256:46aa0bd9efb89c837302f98a1ebd03151fc0f1828eb3212a79bc342ecc854f87",
)
DATABASE_SCHEMA_SHA256 = "sha256:c072fbc87a8fe6d4be9ef83359e919b639a5afddcef2a0dda337defad272462a"
WEB_IDENTITY = {
    "schemaVersion": "roebel_web_staging_identity_contract_set_v1",
    "profile": "gnosis-staging-test-v2",
    "chainId": 100,
    "authority": "none",
    "contracts": {
        "attesterNft": {
            "address": "0x76b558Feb869c77790431497554C9aa8797896Fa",
            "runtimeCodeKeccak256": "0x3c12a034ea9c2749c786497b5d50dcfaa4eff84860819d788517145a2276ee51",
        },
        "citizenNft": {
            "address": "0x4765cB681E8eB080B3191DD550E81eaA41907323",
            "runtimeCodeKeccak256": "0x0131b35a46839c2c50e013a5702dd1a75ab2c079890711900071d56486d1bce4",
        },
    },
}


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(
        (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
    ).hexdigest()


def web_environment() -> list[dict[str, str]]:
    return [
        {"name": "ROEBEL_PUBLIC_IDENTITY_CONTRACT_SET", "value": WEB_IDENTITY["profile"]},
        {"name": "ROEBEL_PUBLIC_ATTESTER_NFT_ADDRESS", "value": WEB_IDENTITY["contracts"]["attesterNft"]["address"]},
        {"name": "ROEBEL_PUBLIC_CITIZEN_NFT_ADDRESS", "value": WEB_IDENTITY["contracts"]["citizenNft"]["address"]},
    ]


def web_annotations() -> dict[str, str]:
    return {
        "stadtstack.io/identity-contract-set": WEB_IDENTITY["profile"],
        "stadtstack.io/identity-contract-authority": "none",
        "stadtstack.io/identity-contract-set-sha256": canonical_sha256(WEB_IDENTITY),
        "stadtstack.io/identity-attester-runtime-code-keccak256": WEB_IDENTITY["contracts"]["attesterNft"]["runtimeCodeKeccak256"],
        "stadtstack.io/identity-citizen-runtime-code-keccak256": WEB_IDENTITY["contracts"]["citizenNft"]["runtimeCodeKeccak256"],
    }


def boundary(predecessor: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(predecessor)
    citizen = WEB_IDENTITY["contracts"]["citizenNft"]
    value["testCitizenNft"] = {
        "chainId": 100,
        "address": citizen["address"].lower(),
        "runtimeCodeKeccak256": citizen["runtimeCodeKeccak256"],
    }
    value["migrationSha256"] = MIGRATION_ARTIFACT[2]
    value["databaseSchemaSha256"] = DATABASE_SCHEMA_SHA256
    value["rollback"] = "forward-only-schema-rotation-requires-reviewed-reverse-migration"
    return value


def gateway_environment(predecessor: list[dict[str, str]]) -> list[dict[str, str]]:
    value = copy.deepcopy(predecessor)
    replacements = {
        "TEST_CITIZEN_NFT_ADDRESS": WEB_IDENTITY["contracts"]["citizenNft"]["address"].lower(),
        "TEST_CITIZEN_NFT_RUNTIME_CODE_KECCAK256": WEB_IDENTITY["contracts"]["citizenNft"]["runtimeCodeKeccak256"],
        "SYNTHETIC_CITIZEN_ADOPTION_MIGRATION_SHA256": MIGRATION_ARTIFACT[2],
        "SYNTHETIC_CITIZEN_ADOPTION_DATABASE_SCHEMA_SHA256": DATABASE_SCHEMA_SHA256,
    }
    for item in value:
        suffix = item["name"].removeprefix("ROEBEL_STAGING_PARTICIPANT_GATEWAY_")
        if suffix in replacements:
            item["value"] = replacements[suffix]
    return value


def gateway_runtime_pin(predecessor: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(predecessor)
    value.update(GATEWAY_RELEASE)
    value["syntheticCitizenAdoptionMigrationSha256"] = MIGRATION_ARTIFACT[2]
    value["syntheticCitizenAdoptionDatabaseSchemaSha256"] = DATABASE_SCHEMA_SHA256
    value["syntheticCitizenAdoption"] = boundary(predecessor["syntheticCitizenAdoption"])
    return value


def rotate_reviewed_release(root, base_root, migration_path) -> dict[str, Any]:
    """Rotate a verified image release using an independently verified v1 base.

    Network-free and local-file-only. The existing publisher renderer must
    already have checked its candidate/evidence bundle. This does not apply
    SQL or restart a workload; the later guarded live runner applies SQL.
    """
    import importlib.util
    from pathlib import Path

    root, base_root, migration_path = map(Path, (root, base_root, migration_path))
    path = Path(__file__).with_name("verify-reviewed-render.py")
    spec = importlib.util.spec_from_file_location("protected_identity_rotation_verifier", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("protected rotation verifier unavailable")
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    v = verifier
    before = v.verify_tree(base_root)
    current = v.verify_tree(root)
    v.verify_transition(current, before)
    v.require(before["webIdentityContractSet"] == v.WEB_IDENTITY_CONTRACT_SET
              and current["webIdentityContractSet"] == v.WEB_IDENTITY_CONTRACT_SET,
              "rotation renderer requires the unrotated v1 identity")
    v.require(current["head"]["promotionRevision"] == SOURCE_REVISION,
              "rotation renderer requires the reviewed source revision")
    v.require(migration_path.is_file() and not migration_path.is_symlink(),
              "rotation SQL must be a regular file")
    sql = migration_path.read_bytes()
    v.require(v.bytes_digest(sql) == MIGRATION_ARTIFACT[2], "rotation SQL source checksum drift")
    v.require(not (root / v.IDENTITY_ROTATION_RECORD_PATH).exists(), "rotation record already exists")
    v.require(not (root / v.IDENTITY_ROTATION_SQL_PATH).exists(), "rotation SQL already exists")

    def write_json(relative, value):
        (root / relative).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")

    web = copy.deepcopy(current["deployments"]["roebel-web-staging"])
    by_name = {item["name"]: item for item in web["spec"]["template"]["spec"]["containers"][0]["env"]}
    for item in web_environment():
        by_name[item["name"]].update(item)
    web["spec"]["template"]["metadata"]["annotations"].update(web_annotations())
    write_json(Path(v.RENDER_ROOT) / "web/deployment.json", web)

    gateway_pin = v.expected_synthetic_citizen_pass_gateway_runtime_pin(GATEWAY_RELEASE)
    gateway = v.expected_participant_gateway_resources(gateway_pin, current["stagingParticipantGatewayPolicy"], civic_projection_route=current["stagingParticipantGateway"]["civicProjectionRoute"])
    write_json(Path(v.PARTICIPANT_GATEWAY_ROOT) / "runtime-pin.json", gateway_pin)
    write_json(Path(v.PARTICIPANT_GATEWAY_ROOT) / "deployment.json", gateway["deployment"])
    data = v.TRACER_DATA_PLANE
    artifacts = data.ROTATED_SYNTHETIC_PRODUCT_ARTIFACTS
    write_json(data.RENDER_ROOT / "runtime-pin.json", data.runtime_pin(SOURCE_REVISION, artifacts))
    write_json(data.RENDER_ROOT / "postgres-deployment.json", data.expected_postgres_deployment(artifacts))
    (root / data.RENDER_ROOT / "kustomization.yaml").write_text(data.kustomization_text(artifacts))
    (root / data.RENDER_ROOT / "bootstrap/zz-roebel-tracer.sh").write_text(data.bootstrap_verify_script(artifacts))
    (root / v.IDENTITY_ROTATION_SQL_PATH).write_bytes(sql)
    contract = v.load_json(root / "policy/repository-contract.json")
    contract["ephemeralTracerDataPlaneBoundary"] = data.contract_boundary(artifacts)
    contract["stagingParticipantGatewayBoundary"]["syntheticCitizenAdoption"] = boundary(v.synthetic_citizen_pass_boundary())
    write_json("policy/repository-contract.json", contract)

    network = copy.deepcopy(current["migration"])
    for item in network["objects"]:
        if item["kind"] == "Deployment" and item["name"] == v.PARTICIPANT_GATEWAY_NAME:
            item["sha256"] = v.digest(gateway["deployment"])
    write_json(Path(v.RENDER_ROOT) / "network-boundary-migration.json", network)
    objects = copy.deepcopy(current["objects"])
    objects[3] = web
    gateway_payload = {
        key: value for key, value in current["stagingParticipantGateway"].items()
        if key != "civicProjectionRoute"
    }
    gateway_payload["runtimePin"] = gateway_pin
    gateway_payload["deployment"] = gateway["deployment"]
    payload = {"nextEnvironmentHead": current["head"], "objects": objects,
               "stagingParticipantGateway": gateway_payload}
    if current["reviewedPublicKnowledge"] is not None:
        payload["reviewedPublicKnowledge"] = current["reviewedPublicKnowledge"]
    if current["signedNostr"] is not None:
        payload["signedNostr"] = current["signedNostr"]
    integrity = copy.deepcopy(current["integrity"])
    integrity["desiredRenderSha256"] = v.digest(payload)
    integrity["networkBoundaryMigrationSha256"] = v.digest(network)
    write_json(Path(v.RENDER_ROOT) / "integrity.json", integrity)
    write_json(v.IDENTITY_ROTATION_RECORD_PATH, v.expected_test_identity_rotation_record(root, base_root))
    return v.verify(root, base_root)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--base-root", required=True)
    parser.add_argument("--migration", required=True)
    args = parser.parse_args()
    print(json.dumps(rotate_reviewed_release(args.root, args.base_root, args.migration), indent=2))
