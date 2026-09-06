"""Pinned signed-status rollout, separate from the retained database bootstrap.

This protected module admits one exact seven-file status transition. It also
prepares desired state and SQL offline; it never contacts a cluster, reads
credentials, assigns municipal roles, or executes migrations.
"""

from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path


SCHEMA = "roebel_staging_participant_gateway_runtime_pin_v6"
ROOT = Path("policy/citizen-adoption-status")
POLICY_PATH = ROOT / "activation.json"
RECORD_PATH = Path("reviewed-render/roebel-staging/citizen-adoption-status.json")
SOURCE_REVISION = "c25cbdff5f18143257c4849d91bbee3b18166ab1"
RELEASE = {
    "sourceRevision": SOURCE_REVISION,
    "sourceTreeSha256": "sha256:9b77ec660968839429d262299797ed5fb21e7089d1ab17f9d53141a40f267df5",
    "workflowSha256": "sha256:57f845cd106120c365a60fcf9e80e00e5304c410f2aafd462ee8f89073dd1a61",
    "manifestDigest": "sha256:b69922baff63356efadd705fcecc20e0b73a90725e2402b9a641a00c7b283e73",
}
ARTIFACTS = (
    ("20260905_staging_citizen_eligibility_status_lookup.sql",
     "supabase/migrations/20260905_staging_citizen_eligibility_status_lookup.sql",
     "sha256:81ae161df079a183d4782b91b528a83100414e89e08c1287c8a4c4ad282e7689"),
    ("20260906_staging_citizen_adoption_acceptance_lookup.sql",
     "supabase/migrations/20260906_staging_citizen_adoption_acceptance_lookup.sql",
     "sha256:810e0a03bc8b9ba60271c606bcff8dcdc0d18bb53e3f0ea2d15068f4542519bb"),
    ("20260906_staging_citizen_adoption_status_readiness.sql",
     "supabase/migrations/20260906_staging_citizen_adoption_status_readiness.sql",
     "sha256:62b4974d8b52be7ba5f31c06ab1c9604ec3370bbab1443b8a95fe2ae6fc49de7"),
    ("staging-citizen-adoption-status-schema-contract-v1.json",
     "supabase/staging-citizen-adoption-status-schema-contract-v1.json",
     "sha256:85c778d6b805fbfb9c82e343cfd966b1865c15c1fad628173da247ceecff2332"),
)
LICENSE_ARTIFACT = ("LICENSE.AGPL-3.0", "LICENSE", "sha256:0d96a4ff68ad6d4b6f1f30f713b18d5184912ba8dd389f86aa7710db079abcb0")
POLICY_FILES = {
    "scripts/citizen_adoption_status.py",
    "scripts/test_citizen_adoption_status.py",
    str(POLICY_PATH),
    *(str(ROOT / filename) for filename, _, _ in (*ARTIFACTS, LICENSE_ARTIFACT)),
}
ACCEPTANCE_PREFIX = "/api/staging-participant/v1/citizen-adoption/acceptance/"
STATUS_PREFIX = "/api/civic/v1/eligibility/status/"
PUBLIC_ORIGIN = "https://roebel-web.staging.agentcart.eu"
PREFLIGHT_RPC = "staging_participant_gateway_citizen_adoption_status_preflight"
PREFLIGHT_RESPONSE = {
    "migration_id": "20260906_staging_citizen_adoption_status_readiness",
    "database_schema_sha256": ARTIFACTS[-1][2],
}
ENVIRONMENT = [
    {"name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_CITIZEN_ELIGIBILITY_STATUS", "value": "enabled"},
    {"name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_CITIZEN_ADOPTION_STATUS_MIGRATION_SHA256", "value": ARTIFACTS[2][2]},
    {"name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_CITIZEN_ADOPTION_STATUS_DATABASE_SCHEMA_SHA256", "value": ARTIFACTS[3][2]},
]
TRANSITION_FILES = {
    str(RECORD_PATH), "policy/repository-contract.json",
    "reviewed-render/roebel-staging/integrity.json",
    "reviewed-render/roebel-staging/network-boundary-migration.json",
    *(f"reviewed-render/roebel-staging/staging-participant-gateway/{name}.json"
      for name in ("runtime-pin", "deployment", "ingress")),
}


def descriptor():
    return {
        "schemaVersion": "roebel_citizen_adoption_status_activation_policy_v1",
        "source": {"repository": "https://github.com/GiraeffleAeffle/Roebel-App.git",
                   "protectedRef": "refs/heads/main", **RELEASE},
        "publication": {
            "schemaVersion": "roebel_staging_publication_receipt_v4",
            "runId": "34019534693",
            "receiptSha256": "sha256:678cbb12bfc65e4bcb823b718bb0525c57b6d86c43e9cee31eab64931f4adf1c",
            "supplementalSqlAttestedByPublication": False,
        },
        "supplementalArtifacts": [
            {"operationsPath": str(ROOT / filename), "sourcePath": source, "sha256": digest}
            for filename, source, digest in ARTIFACTS
        ],
        "sourceLicense": {"operationsPath": str(ROOT / LICENSE_ARTIFACT[0]), "sourcePath": "LICENSE", "sha256": LICENSE_ARTIFACT[2], "appliesTo": [filename for filename, _, _ in ARTIFACTS]},
        "database": {
            "namespace": "stadtstack-roebel-staging-lab",
            "deployment": "roebel-tracer-postgres",
            "claim": "roebel-tracer-postgres-data-v1",
            "migrationMode": "one-transaction-before-gateway-promotion",
            "bootstrapReplay": False, "automaticMigration": False,
            "preflightRpc": PREFLIGHT_RPC, "expectedPreflight": PREFLIGHT_RESPONSE,
            "preserve": ["retained-storage", "existing-bootstrap-bytes", "original-receipts", "real-and-test-identity-policies"],
        },
        "runtime": {
            "schemaVersion": SCHEMA, "environment": ENVIRONMENT,
            "reuseExistingIssuerSecret": True,
            "readiness": "startup-and-every-status-request-and-internal-status",
        },
        "http": {
            "acceptanceBaseUrl": PUBLIC_ORIGIN + ACCEPTANCE_PREFIX,
            "statusBaseUrl": PUBLIC_ORIGIN + STATUS_PREFIX,
            "statusNonceHeader": "x-stadtstack-status-nonce",
            "identifier": "64-lowercase-hex", "readMethod": "GET",
            "unknownIdentifierStatus": 404, "unavailableStatus": 503,
            "holderDataPublic": False,
        },
        "authority": {"binding": "none", "rolesAssigned": False,
                      "caseAdmissionActivated": False, "syntheticPassGrantsEligibility": False},
        "rollback": "restore-exact-gateway-predecessor-keep-additive-sql-and-retained-records",
    }


def enabled(root):
    return (root / RECORD_PATH).is_file()


def verify_policy(v, root):
    v.require(v.load_json(root / POLICY_PATH) == descriptor(), "citizen status activation policy drift")
    for filename, _, digest in (*ARTIFACTS, LICENSE_ARTIFACT):
        path = root / ROOT / filename
        v.require(path.is_file() and not path.is_symlink(), "citizen status artifact must be a regular file")
        v.require(v.bytes_digest(path.read_bytes()) == digest, f"citizen status source artifact drift: {filename}")


def runtime_pin(v, participant_policy=None):
    value = v.expected_synthetic_citizen_pass_gateway_runtime_pin(v.IDENTITY_ROTATION.GATEWAY_RELEASE, participant_policy)
    value.update(RELEASE)
    value.update({
        "schemaVersion": SCHEMA,
        "publicationReceiptSchemaVersion": "roebel_staging_publication_receipt_v4",
        "citizenAdoptionStatusMigrationSha256": ARTIFACTS[2][2],
        "citizenAdoptionStatusDatabaseSchemaSha256": ARTIFACTS[3][2],
        "citizenEligibilityStatus": "enabled",
    })
    return value


def resources(v, participant_policy, civic_projection_route):
    predecessor = v.expected_synthetic_citizen_pass_gateway_runtime_pin(v.IDENTITY_ROTATION.GATEWAY_RELEASE, participant_policy)
    value = v.expected_participant_gateway_resources(predecessor, participant_policy, civic_projection_route=civic_projection_route)
    container = value["deployment"]["spec"]["template"]["spec"]["containers"][0]
    container["image"] = predecessor["imageRepository"] + "@" + RELEASE["manifestDigest"]
    environment = {item["name"]: item for item in container["env"]}
    for suffix, key in (("SOURCE_REVISION", "sourceRevision"), ("MANIFEST_DIGEST", "manifestDigest")):
        environment["ROEBEL_STAGING_PARTICIPANT_GATEWAY_" + suffix]["value"] = RELEASE[key]
    container["env"].extend(copy.deepcopy(ENVIRONMENT))
    rules = v.synthetic_gateway_early_allowlist().splitlines()
    # Extend only the closed path and GET clauses. The existing POST/OPTIONS
    # restrictions and shared rate limit still apply to the proposed route.
    v.require(rules[0].startswith("http-request deny deny_status 404 if ") and rules[4].startswith("http-request deny deny_status 405 if { method GET } "), "citizen status ingress predecessor drift")
    for index in (0, 4):
        rules[index] += " !{ path_beg " + ACCEPTANCE_PREFIX + " }"
    value["ingress"]["metadata"]["annotations"]["haproxy-ingress.github.io/config-backend-early"] = "\n".join(rules)
    return value


def extend_http(value):
    value = copy.deepcopy(value)
    value["schemaVersion"] = SCHEMA
    value["dynamicGetPrefixes"].append(ACCEPTANCE_PREFIX)
    sample = ACCEPTANCE_PREFIX + "0" * 64
    value["routeProbeSamples"].append(sample)
    value["methodPathMatrix"]["GET"].append(sample)
    return value


def record(v):
    return {
        "schemaVersion": "roebel_citizen_adoption_status_desired_state_v1",
        "policy": str(POLICY_PATH), "policyCanonicalSha256": v.digest(descriptor()),
        "runtimePinCanonicalSha256": v.digest(runtime_pin(v)),
        "databasePreflightRequired": True, "liveEvidenceCommitted": False,
        "authorityBinding": "none", "caseAdmissionActivated": False,
    }


def migration_sql(v, root):
    """Return one atomic batch from exact source bytes; never replay bootstrap."""
    verify_policy(v, root)
    statements = ["\\set ON_ERROR_STOP on", "begin;", "set local lock_timeout = '5s';", "set local statement_timeout = '30s';"]
    for filename, _, _ in ARTIFACTS[:3]:
        sql = (root / ROOT / filename).read_text()
        # Only the three hash-verified source envelopes are transformed. This
        # is not a general SQL parser and must not accept caller-selected SQL.
        v.require(sql.count("\nbegin;\n") == 1 and sql.endswith("\ncommit;\n"), "citizen status migration transaction envelope drift")
        statements.append(sql.replace("\nbegin;\n", "\n", 1).removesuffix("\ncommit;\n"))
    statements.append("select public." + PREFLIGHT_RPC + "();")
    statements.extend(["notify pgrst, 'reload schema';", "commit;"])
    return "\n".join(statements) + "\n"


def prepare(v, root, base_root, product_root, publication_path):
    """Return a review proposal, without changing or admitting desired state."""
    verify_policy(v, root)
    def git(*args):
        return subprocess.check_output(["git", "-C", str(product_root), *args])
    v.require(v.bytes_digest(git("ls-tree", "-r", "-z", "--full-tree", SOURCE_REVISION)) == RELEASE["sourceTreeSha256"], "citizen status product source tree drift")
    v.require(v.bytes_digest(git("show", SOURCE_REVISION + ":.github/workflows/staging-participant-gateway-publish.yml")) == RELEASE["workflowSha256"], "citizen status product workflow drift")
    for filename, source, digest in (*ARTIFACTS, LICENSE_ARTIFACT):
        v.require(v.bytes_digest(git("show", SOURCE_REVISION + ":" + source)) == digest, "citizen status artifact source binding drift")
    v.require(not publication_path.is_symlink() and v.bytes_digest(publication_path.read_bytes()) == descriptor()["publication"]["receiptSha256"], "citizen status publication receipt drift")
    return proposal(v, root, base_root)


def activation_files(v, base_root, current):
    """The sole allowed transformation of an already verified predecessor."""
    v.require(not enabled(base_root), "citizen status already enabled")
    v.require(current["tracerDataPlane"]["persistentVolumeClaim"], "citizen status requires retained database storage")
    v.require(current["stagingParticipantGateway"]["runtimePin"] == v.expected_synthetic_citizen_pass_gateway_runtime_pin(v.IDENTITY_ROTATION.GATEWAY_RELEASE), "citizen status gateway predecessor drift")
    pin = runtime_pin(v, current["stagingParticipantGatewayPolicy"])
    gateway = resources(v, current["stagingParticipantGatewayPolicy"], current["stagingParticipantGateway"]["civicProjectionRoute"])
    proposed_files = {}
    def write(path, value):
        proposed_files[str(path)] = json.dumps(value, indent=2, sort_keys=True) + "\n"
    gateway_root = Path(v.PARTICIPANT_GATEWAY_ROOT)
    write(gateway_root / "runtime-pin.json", pin)
    for name in ("deployment", "ingress"):
        write(gateway_root / (name + ".json"), gateway[name])
    contract = v.load_json(base_root / "policy/repository-contract.json")
    http = contract["stagingParticipantGatewayBoundary"]
    extended = extend_http(http)
    extended["citizenEligibilityStatus"] = descriptor()
    contract["stagingParticipantGatewayBoundary"] = extended
    write("policy/repository-contract.json", contract)
    network = copy.deepcopy(current["migration"])
    ingress = network["boundary"]["ingress"]
    extended = extend_http({"dynamicGetPrefixes": ingress["dynamicGetPrefixes"], "routeProbeSamples": ingress["routeProbeSamples"], "methodPathMatrix": ingress["gatewayMethodPathMatrix"]})
    for key in ("dynamicGetPrefixes", "routeProbeSamples"):
        ingress[key] = extended[key]
    ingress["gatewayMethodPathMatrix"] = extended["methodPathMatrix"]
    for item in network["objects"]:
        if item["name"] == v.PARTICIPANT_GATEWAY_NAME and item["kind"] in {"Deployment", "Ingress"}:
            item["sha256"] = v.digest(gateway[item["kind"].lower()])
    write(Path(v.RENDER_ROOT) / "network-boundary-migration.json", network)
    gateway_payload = {key: value for key, value in current["stagingParticipantGateway"].items() if key != "civicProjectionRoute"}
    gateway_payload.update(gateway)
    gateway_payload["runtimePin"] = pin
    payload = {"nextEnvironmentHead": current["head"], "objects": current["objects"], "stagingParticipantGateway": gateway_payload}
    for key in ("reviewedPublicKnowledge", "signedNostr"):
        if current[key] is not None:
            payload[key] = current[key]
    integrity = copy.deepcopy(current["integrity"])
    integrity.update(desiredRenderSha256=v.digest(payload), networkBoundaryMigrationSha256=v.digest(network))
    write(Path(v.RENDER_ROOT) / "integrity.json", integrity)
    write(RECORD_PATH, record(v))
    v.require(set(proposed_files) == TRANSITION_FILES, "citizen status proposal file set drift")
    return proposed_files


def verify_state(v, root, gateway, tracer):
    active = enabled(root)
    v.require(active == bool(gateway and gateway["runtimePin"]["schemaVersion"] == SCHEMA), "citizen status record/runtime mismatch")
    if active:
        v.require(tracer["persistentVolumeClaim"], "citizen status requires retained database storage")
        v.require(v.load_json(root / RECORD_PATH) == record(v), "citizen status desired-state record drift")
    return active


def verify_transition(v, candidate, base):
    v.require(not base.get("citizenEligibilityStatus") and candidate.get("citizenEligibilityStatus"), "citizen status rollback requires separate exact predecessor admission")
    candidate_root, base_root = candidate["root"], base["root"]
    v.require(v.changed_repository_files(candidate_root, base_root) == TRANSITION_FILES, "citizen status transition changed file set drift")
    expected = activation_files(v, base_root, base)
    for path, content in expected.items():
        v.require((candidate_root / path).read_bytes() == content.encode(), f"citizen status transition bytes drift: {path}")


def proposal(v, root, base_root):
    """Build review data from a verified base and its unchanged candidate copy."""
    v.require(root.resolve() != base_root.resolve(), "citizen status candidate must be isolated from protected base")
    verify_policy(v, root)
    current = v.verify_tree(base_root)
    v.require(not v.changed_repository_files(root, base_root), "citizen status candidate differs from protected base files")
    proposed_files = activation_files(v, base_root, current)
    base_files = {path: v.bytes_digest((base_root / path).read_bytes()) for path in sorted(v.repository_files(base_root))}
    return {
        "schemaVersion": "roebel_citizen_adoption_status_review_proposal_v1",
        "status": "proposal-only",
        "operationsBaseFilesSha256": v.digest(base_files),
        "policy": descriptor(),
        "proposedFiles": proposed_files,
        "proposedFileSha256": {path: v.bytes_digest(content.encode()) for path, content in proposed_files.items()},
        "migrationSql": migration_sql(v, root),
        "deploymentEffect": False, "admissionPassed": False,
    }


def render(v, root, base_root):
    """Write the candidate checkout only, then run protected-base admission."""
    result = proposal(v, root, base_root)
    for path, content in result["proposedFiles"].items():
        (root / path).write_text(content)
    return v.verify(root, base_root)


if __name__ == "__main__":
    import argparse
    import importlib.util
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--base-root", type=Path, required=True)
    parser.add_argument("--product-root", type=Path, required=True)
    parser.add_argument("--publication-receipt", type=Path, required=True)
    parser.add_argument("--write-render", action="store_true", help="write and verify the seven files in the isolated candidate checkout")
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location("protected_status_verifier", Path(__file__).with_name("verify-reviewed-render.py"))
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    result = prepare(verifier, args.root, args.base_root, args.product_root, args.publication_receipt)
    if args.write_render:
        result["verification"] = render(verifier, args.root, args.base_root)
        result["admissionPassed"] = True
    print(json.dumps(result, indent=2))
