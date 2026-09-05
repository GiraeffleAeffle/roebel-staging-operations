#!/usr/bin/env python3
"""Admission and startup failures that could erase restored staging records."""

import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("protected_storage_test_verifier", ROOT / "scripts/verify-reviewed-render.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
data = verifier.TRACER_DATA_PLANE


def write(root, path, value):
    (root / path).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def rotate(root):
    artifacts = data.ROTATED_SYNTHETIC_PRODUCT_ARTIFACTS
    write(root, data.RENDER_ROOT / "runtime-pin.json", data.runtime_pin(data.IDENTITY_ROTATION_SOURCE_REVISION, artifacts, retained=True))
    write(root, data.RENDER_ROOT / "postgres-deployment.json", data.expected_postgres_deployment(artifacts, retained=True))
    contract = json.loads((root / "policy/repository-contract.json").read_text())
    contract["ephemeralTracerDataPlaneBoundary"] = data.contract_boundary(artifacts, retained=True)
    write(root, "policy/repository-contract.json", contract)
    write(root, data.RETAINED_RECORD_PATH, data.retained_transition_record())


class StorageContinuityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="roebel-storage-policy-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name) / "base"
        self.candidate = Path(self.temporary.name) / "candidate"
        shutil.copytree(ROOT, self.base, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        # Explicit historical predecessor makes these tests valid on both renders.
        artifacts = data.ROTATED_SYNTHETIC_PRODUCT_ARTIFACTS
        write(self.base, data.RENDER_ROOT / "runtime-pin.json", data.runtime_pin(data.IDENTITY_ROTATION_SOURCE_REVISION, artifacts))
        write(self.base, data.RENDER_ROOT / "postgres-deployment.json", data.expected_postgres_deployment(artifacts))
        contract = json.loads((self.base / "policy/repository-contract.json").read_text())
        contract["ephemeralTracerDataPlaneBoundary"] = data.contract_boundary(artifacts)
        write(self.base, "policy/repository-contract.json", contract)
        (self.base / data.RETAINED_RECORD_PATH).unlink(missing_ok=True)
        shutil.copytree(self.base, self.candidate)
        rotate(self.candidate)

    def mutate_deployment(self, mutate):
        path = data.RENDER_ROOT / "postgres-deployment.json"
        value = json.loads((self.candidate / path).read_text())
        mutate(value)
        write(self.candidate, path, value)

    def test_complete_transition_preserves_service_network_secret_and_authority_boundaries(self):
        before = verifier.verify_tree(self.base)
        after = verifier.verify_tree(self.candidate)
        verifier.verify_transition(after, before)
        self.assertTrue(after["tracerDataPlane"]["persistentVolumeClaim"])
        for file in ("postgres-service.json", "postgres-networkpolicy.json", "postgrest-networkpolicy.json", "postgrest-deployment.json"):
            self.assertEqual((self.base / data.RENDER_ROOT / file).read_bytes(), (self.candidate / data.RENDER_ROOT / file).read_bytes())
        pin = json.loads((self.candidate / data.RENDER_ROOT / "runtime-pin.json").read_text())
        self.assertFalse(pin["database"]["durableCivicRecordsAllowed"])
        self.assertEqual(pin["authority"]["civicAuthority"], "none")

    def test_missing_restore_record_is_rejected(self):
        (self.candidate / data.RETAINED_RECORD_PATH).unlink()
        with self.assertRaises((verifier.VerificationError, data.PolicyError)):
            verifier.verify_tree(self.candidate)

    def test_unrestored_claim_has_no_empty_database_startup_path(self):
        self.mutate_deployment(lambda value: value["spec"]["template"]["spec"].pop("initContainers"))
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_tree(self.candidate)

    def test_wrong_claim_cannot_be_substituted(self):
        self.mutate_deployment(lambda value: value["spec"]["template"]["spec"]["volumes"][0]["persistentVolumeClaim"].update(claimName="some-other-application"))
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_tree(self.candidate)

    def test_storage_class_capacity_and_reclaim_policy_are_closed(self):
        for field, bad in (("storageClassName", "hcloud-volumes-temporary"), ("requestedStorage", "1Ti"), ("requiredReclaimPolicy", "Delete")):
            with self.subTest(field=field):
                rotate(self.candidate)
                value = json.loads((self.candidate / data.RETAINED_RECORD_PATH).read_text())
                value["storage"][field] = bad
                write(self.candidate, data.RETAINED_RECORD_PATH, value)
                with self.assertRaises(verifier.VerificationError):
                    verifier.verify_tree(self.candidate)

    def test_marker_cannot_be_moved_away_from_restored_data(self):
        self.mutate_deployment(lambda value: value["spec"]["template"]["spec"]["containers"][0]["env"][0].update(value="/var/lib/postgresql/data"))
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_tree(self.candidate)

    def test_database_image_cannot_change_during_storage_migration(self):
        self.mutate_deployment(lambda value: value["spec"]["template"]["spec"]["containers"][0].update(image="postgres:latest"))
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_tree(self.candidate)

    def test_image_configuration_cannot_override_the_restored_data_directory(self):
        self.mutate_deployment(lambda value: value["spec"]["template"]["spec"]["containers"][0].pop("args"))
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_tree(self.candidate)

    def test_startup_guard_must_read_data_as_the_pinned_postgres_user(self):
        self.mutate_deployment(lambda value: value["spec"]["template"]["spec"]["initContainers"][0]["securityContext"].update(runAsUser=0))
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_tree(self.candidate)

    def test_deployment_selector_remains_immutable(self):
        self.mutate_deployment(lambda value: value["spec"]["selector"]["matchLabels"].update({"stadtstack.io/data-lifecycle": "renamed"}))
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_tree(self.candidate)

    def test_reverse_to_empty_directory_is_rejected(self):
        with self.assertRaisesRegex(verifier.VerificationError, "cannot return to emptyDir"):
            verifier.verify_transition(verifier.verify_tree(self.base), verifier.verify_tree(self.candidate))

    def test_unrelated_file_cannot_ride_the_storage_transition(self):
        with (self.candidate / "README.md").open("a") as stream:
            stream.write("\nUnrelated change.\n")
        with self.assertRaisesRegex(verifier.VerificationError, "changed file set drift"):
            verifier.verify_transition(verifier.verify_tree(self.candidate), verifier.verify_tree(self.base))

    def test_partial_retained_pin_is_rejected(self):
        write(self.candidate, data.RENDER_ROOT / "runtime-pin.json", data.runtime_pin(data.IDENTITY_ROTATION_SOURCE_REVISION, data.ROTATED_SYNTHETIC_PRODUCT_ARTIFACTS))
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_tree(self.candidate)

    def test_real_startup_guard_rejects_empty_and_incomplete_imports(self):
        pod = data.expected_postgres_deployment(data.ROTATED_SYNTHETIC_PRODUCT_ARTIFACTS, retained=True)["spec"]["template"]["spec"]
        volume = Path(self.temporary.name) / "claim"
        volume.mkdir()
        command = copy.deepcopy(pod["initContainers"][0]["command"])
        command[2] = command[2].replace("/var/lib/postgresql/data", str(volume))
        def status():
            return subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
        self.assertNotEqual(status(), 0)
        (volume / "pgdata/base").mkdir(parents=True)
        (volume / "pgdata/PG_VERSION").write_text("15\n")
        self.assertNotEqual(status(), 0)
        marker = volume / ".roebel-tracer-restored-v1"
        marker.write_text("incorrect\n")
        self.assertNotEqual(status(), 0)
        marker.write_text(data.RESTORE_MARKER_VALUE + "\n")
        self.assertEqual(status(), 0)


if __name__ == "__main__":
    unittest.main()
