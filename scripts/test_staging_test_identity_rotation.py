from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shutil
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

FIXTURES = load("identity_rotation_fixture", "test_render_release_set_promotion.py")
V = FIXTURES.VERIFIER
R = FIXTURES.MODULE
I = V.IDENTITY_ROTATION


class TestIdentityRotation(unittest.TestCase):
    def setUp(self):
        self.temp, self.root, self.incoming, self.candidate = FIXTURES.AutomaticPromotionTests().synthetic_fixture()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name) / "base"
        R.render(self.root, self.candidate, self.incoming)
        shutil.rmtree(self.base)
        shutil.copytree(self.root, self.base)
        candidate = json.loads(self.candidate.read_text())
        candidate.pop("syntheticCitizenPass")
        candidate["schemaVersion"] = "roebel_staging_release_set_candidate_v1"
        head = V.load_json(self.root / V.RENDER_ROOT / "head.json")
        candidate["expectedPreviousHead"] = {key: head[key] for key in ("promotionRevision", "releaseSetDigest", "components")}
        candidate["promotionRevision"] = I.SOURCE_REVISION
        for component in candidate["components"]:
            component["sourceRevision"] = I.SOURCE_REVISION
            evidence = self.incoming / "evidence" / f"{component['component']}.component-evidence.json"
            value = json.loads(evidence.read_text())
            value["sourceRevision"] = I.SOURCE_REVISION
            evidence.write_text(json.dumps(value))
        self.write_candidate(candidate)
        R.render(self.root, self.candidate, self.incoming)
        self.sql = ROOT / "tests/fixtures/staging-synthetic-citizen-pass-v2.sql"

    def write_candidate(self, candidate):
        candidate.pop("candidatePayloadDigest", None)
        candidate["candidatePayloadDigest"] = "sha256:" + hashlib.sha256(R.canonical_candidate_payload(candidate)).hexdigest()
        self.candidate.write_text(json.dumps(candidate))

    def rotate(self):
        return I.rotate_reviewed_release(self.root, self.base, self.sql)

    def test_tracer_policy_still_compiles_from_exact_git_blob_without_local_imports(self):
        core = load("rotation_blob_compiler", "activate-staging-participant-gateway.py")
        policy = core.compile_verified_tracer_policy_module_v4(
            (ROOT / "scripts/tracer_data_plane_policy.py").read_bytes(), I.SOURCE_REVISION
        )
        self.assertEqual(policy.IDENTITY_ROTATION_ARTIFACT, I.MIGRATION_ARTIFACT)
        self.assertEqual(policy.IDENTITY_ROTATION_SOURCE_REVISION, I.SOURCE_REVISION)

    def test_complete_rotation_preserves_database_pod_and_real_eligibility(self):
        result = self.rotate()
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["baseTransitionVerified"])
        old, new = V.verify_tree(self.base), V.verify_tree(self.root)
        self.assertEqual(new["webIdentityContractSet"]["profile"], "gnosis-staging-test-v2")
        self.assertEqual(new["stagingParticipantGateway"]["runtimePin"]["citizenAdoption"], old["stagingParticipantGateway"]["runtimePin"]["citizenAdoption"])
        postgres = V.TRACER_DATA_PLANE.RENDER_ROOT / "postgres-deployment.json"
        self.assertEqual(V.load_json(self.root / postgres)["spec"]["template"], V.load_json(self.base / postgres)["spec"]["template"])
        self.assertEqual((self.root / V.SYNTHETIC_CITIZEN_ADOPTION_SQL_PATH).read_bytes(), (self.base / V.SYNTHETIC_CITIZEN_ADOPTION_SQL_PATH).read_bytes())
        self.assertEqual((self.root / V.SYNTHETIC_CITIZEN_PASS_TRANSITION_PATH).read_bytes(), (self.base / V.SYNTHETIC_CITIZEN_PASS_TRANSITION_PATH).read_bytes())
        self.assertEqual(V.changed_repository_files(self.root, self.base), V.IDENTITY_ROTATION_FILES)

    def test_unreviewed_sql_rejected_before_writes(self):
        sql = Path(self.temp.name) / "unreviewed.sql"
        sql.write_bytes(self.sql.read_bytes() + b"\n-- changed\n")
        before = V.repository_files(self.root)
        with self.assertRaisesRegex(RuntimeError, "SQL source checksum drift"):
            I.rotate_reviewed_release(self.root, self.base, sql)
        self.assertEqual(V.repository_files(self.root), before)

    def test_mixed_web_pair_rejected(self):
        self.rotate()
        path = self.root / V.RENDER_ROOT / "web/deployment.json"
        value = V.load_json(path)
        for item in value["spec"]["template"]["spec"]["containers"][0]["env"]:
            if item["name"] == "ROEBEL_PUBLIC_CITIZEN_NFT_ADDRESS":
                item["value"] = V.WEB_IDENTITY_CONTRACT_SET["contracts"]["citizenNft"]["address"]
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(V.VerificationError, "profile/address binding invalid"):
            V.verify_tree(self.root)

    def test_database_restart_annotation_rejected(self):
        self.rotate()
        path = self.root / V.TRACER_DATA_PLANE.RENDER_ROOT / "postgres-deployment.json"
        value = V.load_json(path)
        value["spec"]["template"]["metadata"]["annotations"]["stadtstack.io/bootstrap-artifacts-sha256"] = "sha256:" + "a" * 64
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(V.VerificationError, "postgres-deployment.json drift"):
            V.verify_tree(self.root)

    def test_gateway_substitution_and_real_authority_change_rejected(self):
        pin = V.expected_synthetic_citizen_pass_gateway_runtime_pin(I.GATEWAY_RELEASE)
        for field in ("sourceRevision", "manifestDigest", "workflowSha256", "sourceTreeSha256"):
            value = copy.deepcopy(pin)
            value[field] = "f" * 40 if field == "sourceRevision" else "sha256:" + "f" * 64
            with self.subTest(field=field), self.assertRaises(V.VerificationError):
                V.validate_synthetic_citizen_pass_gateway_runtime_pin(value)
        value = copy.deepcopy(pin)
        value["citizenAdoption"]["bindingVote"] = True
        with self.assertRaisesRegex(V.VerificationError, "runtime pin drift"):
            V.validate_synthetic_citizen_pass_gateway_runtime_pin(value)

    def test_partial_rotation_rejected_even_with_individually_valid_pins(self):
        self.rotate()
        path = V.TRACER_DATA_PLANE.RENDER_ROOT
        shutil.rmtree(self.root / path)
        shutil.copytree(self.base / path, self.root / path)
        with self.assertRaises(V.VerificationError):
            V.verify_tree(self.root)

    def test_duplicate_rotation_does_not_rewrite_history(self):
        self.rotate()
        record = (self.root / V.IDENTITY_ROTATION_RECORD_PATH).read_bytes()
        with self.assertRaisesRegex(RuntimeError, "requires the unrotated v1 identity"):
            self.rotate()
        self.assertEqual((self.root / V.IDENTITY_ROTATION_RECORD_PATH).read_bytes(), record)

    def test_future_ordinary_release_preserves_v2(self):
        self.rotate()
        rotated = Path(self.temp.name) / "rotated-base"
        shutil.copytree(self.root, rotated)
        head = V.load_json(rotated / V.RENDER_ROOT / "head.json")
        candidate = json.loads(self.candidate.read_text())
        candidate["promotionRevision"] = "f" * 40
        candidate["expectedPreviousHead"] = {key: head[key] for key in ("promotionRevision", "releaseSetDigest", "components")}
        for component in candidate["components"]:
            component["sourceRevision"] = "f" * 40
            evidence = self.incoming / "evidence" / f"{component['component']}.component-evidence.json"
            value = json.loads(evidence.read_text())
            value["sourceRevision"] = "f" * 40
            evidence.write_text(json.dumps(value))
        self.write_candidate(candidate)
        R.render(self.root, self.candidate, self.incoming)
        V.verify(self.root, rotated)
        self.assertEqual(V.verify_tree(self.root)["webIdentityContractSet"], I.WEB_IDENTITY)

    def test_reverse_rotation_requires_separate_admission(self):
        self.rotate()
        with self.assertRaises(V.VerificationError):
            V.verify_transition(V.verify_tree(self.base), V.verify_tree(self.root))


if __name__ == "__main__":
    unittest.main()
