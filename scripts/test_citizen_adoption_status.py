"""Exercise the protected status transition and its storage/authority boundary."""

import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


status = load("status_proposal_test", "citizen_adoption_status.py")
verifier = load("protected_status_base_verifier", "verify-reviewed-render.py")


class CitizenStatusProposalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="roebel-status-proposal-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.base = Path(cls.temporary.name) / "protected-base"
        shutil.copytree(ROOT, cls.base, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        # Retain today's protected code, but bind the active-state fixture to
        # the reviewed predecessor even after a later rollout reaches main.
        predecessor = "9728b97c2d39a3d7ae4d9af439e93b55df9357ef"
        # The historical integrity file also binds the Web/Mecky release.
        historical_files = (status.TRANSITION_FILES - {str(status.RECORD_PATH)}) | {
            f"{verifier.RENDER_ROOT}/{name}"
            for name in ("head.json", "live-preconditions.json", "web/deployment.json", "web/networkpolicy.json", "web/ingress.json", "public-mecky/deployment.json")
        }
        for path in sorted(historical_files):
            (cls.base / path).write_bytes(subprocess.check_output(["git", "-C", str(ROOT), "show", predecessor + ":" + path]))
        (cls.base / status.RECORD_PATH).unlink(missing_ok=True)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="roebel-status-input-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        shutil.copytree(self.base, self.root, dirs_exist_ok=True)

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
        self.assertFalse(verifier.changed_repository_files(self.root, self.base))
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
        with self.assertRaisesRegex(verifier.VerificationError, "differs from protected base files"):
            status.proposal(verifier, self.root, modified)

    def activate(self):
        return status.render(verifier, self.root, self.base)

    def test_full_admission_and_steady_state_preserve_unrelated_files(self):
        result = self.activate()
        self.assertTrue(result["baseTransitionVerified"])
        self.assertEqual(verifier.changed_repository_files(self.root, self.base), status.TRANSITION_FILES)
        self.assertEqual(verifier.verify(self.root)["status"], "passed")
        before, after = verifier.verify_tree(self.base), verifier.verify_tree(self.root)
        for key in ("head", "live", "webIdentityContractSet", "tracerDataPlane", "workbenchBaseline", "reviewedPublicKnowledge", "signedNostr"):
            self.assertEqual(before[key], after[key], key)
        self.assertTrue(after["citizenEligibilityStatus"])
        self.assertEqual(after["stagingParticipantGateway"]["runtimePin"]["citizenAdoption"], before["stagingParticipantGateway"]["runtimePin"]["citizenAdoption"])

    def test_every_partial_transition_fails_admission(self):
        proposal = self.prepare()
        for missing in status.TRANSITION_FILES:
            with self.subTest(missing=missing):
                for path, content in proposal["proposedFiles"].items():
                    target = self.root / path
                    if path == missing:
                        if (self.base / path).exists():
                            target.write_bytes((self.base / path).read_bytes())
                        else:
                            target.unlink(missing_ok=True)
                    else:
                        target.write_text(content)
                with self.assertRaises(verifier.VerificationError):
                    verifier.verify(self.root, self.base)

    def test_candidate_policy_code_is_data_and_cannot_join_activation(self):
        self.activate()
        for relative in ("scripts/citizen_adoption_status.py", "scripts/verify-reviewed-render.py", ".github/workflows/reviewed-render-admission.yml", "README.md"):
            with self.subTest(path=relative):
                path = self.root / relative
                original = path.read_bytes()
                # This invalid Python would execute if candidate policy were
                # imported. Admission must instead reject its changed bytes.
                path.write_bytes(b"raise RuntimeError('candidate code executed')\n")
                with self.assertRaisesRegex(verifier.VerificationError, "changed.*files|file set drift"):
                    verifier.verify(self.root, self.base)
                path.write_bytes(original)

    def test_missing_policy_artifact_cannot_be_hidden_by_active_render(self):
        self.activate()
        (self.root / status.POLICY_PATH).unlink()
        with self.assertRaisesRegex(verifier.VerificationError, "repository file set drift"):
            verifier.verify(self.root, self.base)

    def test_source_pins_real_and_test_authority_remain_closed(self):
        self.activate()
        path = self.root / verifier.PARTICIPANT_GATEWAY_ROOT / "runtime-pin.json"
        original = path.read_bytes()
        for field, value in (("sourceRevision", "f" * 40), ("manifestDigest", "sha256:" + "f" * 64), ("workflowSha256", "sha256:" + "f" * 64), ("sourceTreeSha256", "sha256:" + "f" * 64), ("citizenEligibilityStatus", "disabled"), ("citizenAdoptionStatusMigrationSha256", "sha256:" + "f" * 64), ("citizenAdoptionStatusDatabaseSchemaSha256", "sha256:" + "f" * 64), ("citizenAdoption", {}), ("syntheticCitizenAdoption", {})):
            with self.subTest(field=field):
                value_pin = json.loads(original)
                value_pin[field] = value
                path.write_text(json.dumps(value_pin))
                with self.assertRaisesRegex(verifier.VerificationError, "runtime pin drift"):
                    verifier.verify(self.root, self.base)
        path.write_bytes(original)

    def test_runtime_inputs_secret_substitution_and_expanded_ingress_rejected(self):
        self.activate()
        path = self.root / verifier.PARTICIPANT_GATEWAY_ROOT / "deployment.json"
        original = path.read_bytes()
        for mode in ("partial", "duplicate", "secret"):
            with self.subTest(mode=mode):
                value = json.loads(original)
                env = value["spec"]["template"]["spec"]["containers"][0]["env"]
                if mode == "partial":
                    env.pop()
                elif mode == "duplicate":
                    env.append(env[-1])
                else:
                    next(item for item in env if "valueFrom" in item)["valueFrom"]["secretKeyRef"]["name"] = "different-secret"
                path.write_text(json.dumps(value))
                with self.assertRaisesRegex(verifier.VerificationError, "resource drift"):
                    verifier.verify(self.root, self.base)
        path.write_bytes(original)
        path = self.root / verifier.PARTICIPANT_GATEWAY_ROOT / "ingress.json"
        value = json.loads(path.read_bytes())
        key = "haproxy-ingress.github.io/config-backend-early"
        value["metadata"]["annotations"][key] += " !{ path_beg /unreviewed/ }"
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(verifier.VerificationError, "resource drift"):
            verifier.verify(self.root, self.base)

    def test_retained_database_cannot_change_during_status_rollout(self):
        self.activate()
        path = self.root / verifier.TRACER_DATA_PLANE.RENDER_ROOT / "postgres-deployment.json"
        value = json.loads(path.read_bytes())
        value["spec"]["template"]["spec"]["volumes"][0] = {"name": "data", "emptyDir": {}}
        path.write_text(json.dumps(value))
        with self.assertRaises(verifier.VerificationError):
            verifier.verify(self.root, self.base)

    def test_record_cannot_claim_live_readiness_or_case_authority(self):
        self.activate()
        path = self.root / status.RECORD_PATH
        value = json.loads(path.read_bytes())
        value["caseAdmissionActivated"] = True
        value["liveEvidenceCommitted"] = True
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(verifier.VerificationError, "desired-state record drift"):
            verifier.verify(self.root, self.base)

    def test_reactivation_reverse_and_writing_the_base_are_rejected(self):
        with self.assertRaisesRegex(verifier.VerificationError, "must be isolated"):
            status.render(verifier, self.base, self.base)
        self.activate()
        with self.assertRaisesRegex(verifier.VerificationError, "differs from protected base files"):
            self.activate()
        with self.assertRaisesRegex(verifier.VerificationError, "rollback requires separate"):
            verifier.verify(self.base, self.root)


if __name__ == "__main__":
    unittest.main()
