"""Review proposals must not silently activate or replace retained state."""

import importlib.util
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


status = load("status_proposal_test", "citizen_adoption_status.py")
verifier = load("unchanged_status_base_verifier", "verify-reviewed-render.py")


class CitizenStatusProposalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="roebel-status-proposal-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.base = Path(cls.temporary.name) / "protected-base"
        cls.base.mkdir()
        archive = subprocess.check_output(["git", "-C", str(ROOT), "archive", status.BASE_REVISION])
        with tarfile.open(fileobj=io.BytesIO(archive)) as source:
            source.extractall(cls.base, filter="data")

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="roebel-status-input-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        shutil.copytree(ROOT / status.ROOT, self.root / status.ROOT)

    def prepare(self):
        return status.proposal(verifier, self.root, self.base)

    def test_proposal_is_read_only_and_preserves_existing_authority_and_storage(self):
        before = verifier.digest({p: verifier.bytes_digest((self.base / p).read_bytes()) for p in sorted(verifier.repository_files(self.base))})
        result = self.prepare()
        self.assertFalse(result["deploymentEffect"])
        self.assertFalse(result["admissionPassed"])
        self.assertEqual(set(result["proposedFiles"]), status.TRANSITION_FILES)
        self.assertEqual(set(result["proposedFileSha256"]), status.TRANSITION_FILES)
        self.assertEqual(before, verifier.digest({p: verifier.bytes_digest((self.base / p).read_bytes()) for p in sorted(verifier.repository_files(self.base))}))
        self.assertFalse((self.root / "reviewed-render").exists())
        path = "reviewed-render/roebel-staging/staging-participant-gateway/runtime-pin.json"
        old = json.loads((self.base / path).read_text())
        new = json.loads(result["proposedFiles"][path])
        for key in ("citizenAdoption", "syntheticCitizenAdoption", "syntheticCitizenAdoptionMigrationSha256", "syntheticCitizenAdoptionDatabaseSchemaSha256"):
            self.assertEqual(old[key], new[key], key)
        self.assertFalse(any("tracer-data-plane/" in path for path in result["proposedFiles"]))

    def test_runtime_enables_all_three_status_inputs_and_retains_readiness_and_secret_references(self):
        result = self.prepare()
        path = "reviewed-render/roebel-staging/staging-participant-gateway/deployment.json"
        old = json.loads((self.base / path).read_text())["spec"]["template"]["spec"]["containers"][0]
        new = json.loads(result["proposedFiles"][path])["spec"]["template"]["spec"]["containers"][0]
        names = [item["name"] for item in new["env"]]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(len(new["env"]), len(old["env"]) + 3)
        self.assertEqual([item for item in old["env"] if "valueFrom" in item], [item for item in new["env"] if "valueFrom" in item])
        self.assertEqual(old["readinessProbe"], new["readinessProbe"])
        self.assertEqual(new["readinessProbe"]["httpGet"]["path"], "/status")
        self.assertTrue(new["image"].endswith("@" + status.RELEASE["manifestDigest"]))
        for item in status.ENVIRONMENT:
            self.assertIn(item, new["env"])

    def test_exact_acceptance_get_reaches_gateway_without_expanding_write_methods_or_rate_limit(self):
        result = self.prepare()
        path = "reviewed-render/roebel-staging/staging-participant-gateway/ingress.json"
        old = json.loads((self.base / path).read_text())
        new = json.loads(result["proposedFiles"][path])
        key = "haproxy-ingress.github.io/config-backend-early"
        before = old["metadata"]["annotations"][key].splitlines()
        after = new["metadata"]["annotations"][key].splitlines()
        self.assertEqual(old["spec"], new["spec"])
        for index, line in enumerate(after):
            if index in (0, 4):
                self.assertIn("!{ path_beg " + status.ACCEPTANCE_PREFIX + " }", line)
            else:
                self.assertEqual(line, before[index])
            # HAProxy's fixed MAX_LINE_ARGS rejected an earlier route expansion.
            self.assertLess(len(line.split()), 64)
        self.assertNotIn(status.ACCEPTANCE_PREFIX, after[1])
        self.assertNotIn(status.ACCEPTANCE_PREFIX, after[2])
        boundary = json.loads(result["proposedFiles"]["policy/repository-contract.json"])["stagingParticipantGatewayBoundary"]
        self.assertIn(status.ACCEPTANCE_PREFIX, boundary["dynamicGetPrefixes"])
        self.assertEqual(boundary["citizenEligibilityStatus"]["http"]["statusNonceHeader"], "x-stadtstack-status-nonce")

    def test_sql_is_one_transaction_and_leaves_bootstrap_and_records_out(self):
        sql = self.prepare()["migrationSql"]
        self.assertEqual(len(re.findall(r"^begin;$", sql, re.M)), 1)
        self.assertEqual(len(re.findall(r"^commit;$", sql, re.M)), 1)
        self.assertIn("\\set ON_ERROR_STOP on\nbegin;", sql)
        self.assertIn("set local lock_timeout = '5s';", sql)
        self.assertEqual(sql.count("create function public."), 3)
        self.assertTrue(sql.endswith("notify pgrst, 'reload schema';\ncommit;\n"))
        self.assertLess(sql.index("create function public.staging_participant_gateway_get_citizen_status_holder"), sql.index("create function public." + status.PREFLIGHT_RPC))
        self.assertNotRegex(sql.lower(), r"\b(?:truncate|insert\s+into|delete\s+from|create\s+table|drop\s+table)\b")
        self.assertNotIn("71-roebel-tracer-baseline.sql", sql)

    def test_each_migration_and_schema_contract_rejects_changed_bytes(self):
        for filename, _, _ in status.ARTIFACTS:
            with self.subTest(filename=filename):
                path = self.root / status.ROOT / filename
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                with self.assertRaisesRegex(verifier.VerificationError, "artifact drift"):
                    self.prepare()
                path.write_bytes(original)

    def test_policy_cannot_enable_case_admission_or_substitute_issuer_route(self):
        for section, field, value in (("authority", "caseAdmissionActivated", True), ("http", "statusBaseUrl", "https://example.invalid/status/")):
            with self.subTest(field=field):
                policy = status.descriptor()
                policy[section][field] = value
                (self.root / status.POLICY_PATH).write_text(json.dumps(policy))
                with self.assertRaisesRegex(verifier.VerificationError, "policy drift"):
                    self.prepare()

    def test_linked_source_artifact_is_rejected(self):
        path = self.root / status.ROOT / status.ARTIFACTS[0][0]
        path.unlink()
        path.symlink_to(ROOT / status.ROOT / status.ARTIFACTS[0][0])
        with self.assertRaisesRegex(verifier.VerificationError, "regular file"):
            self.prepare()

    def test_other_base_commit_or_unrelated_edit_is_rejected(self):
        modified = self.root / "different-base"
        shutil.copytree(self.base, modified)
        (modified / "README.md").write_text("unreviewed change\n")
        with self.assertRaisesRegex(verifier.VerificationError, "base files drift"):
            status.proposal(verifier, self.root, modified)


if __name__ == "__main__":
    unittest.main()
