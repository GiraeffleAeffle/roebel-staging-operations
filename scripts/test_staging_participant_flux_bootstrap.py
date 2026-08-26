from __future__ import annotations

import importlib.util
import io
import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from contextlib import redirect_stderr, redirect_stdout


ROOT = Path(__file__).resolve().parent.parent


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


POLICY = load(
    "participant_policy_for_flux_bootstrap_tests",
    ROOT / "scripts/staging_participant_gateway_policy.py",
)
BOOTSTRAP = load(
    "participant_flux_bootstrap_under_test",
    ROOT / "scripts/staging_participant_flux_bootstrap.py",
)
CLI = load(
    "participant_flux_bootstrap_cli_under_test",
    ROOT / "scripts/bootstrap-staging-participant-flux.py",
)


REVISION = "9" * 40


def close_receipt(value):
    closed = json.loads(json.dumps(value))
    closed["canonicalSha256"] = BOOTSTRAP.canonical_sha256(closed)
    return closed


class MemorySink:
    def __init__(self):
        self.values = []

    def commit(self, value):
        self.values.append(json.loads(json.dumps(value)))


class FailOnceSink(MemorySink):
    def __init__(self, fail_on_call, before_failure=None):
        super().__init__()
        self.fail_on_call = fail_on_call
        self.before_failure = before_failure
        self.calls = 0

    def commit(self, value):
        self.calls += 1
        if self.calls == self.fail_on_call:
            if self.before_failure is not None:
                self.before_failure()
            raise OSError("simulated durable receipt failure")
        super().commit(value)


class FakeKube:
    def __init__(self):
        self.objects = {}
        self.created = []
        self.deleted = []
        self.create_responses = []
        self.preflight_calls = 0

    @staticmethod
    def key(target):
        return target["kind"], target["namespace"], target["name"]

    def preflight(self, _plan):
        self.preflight_calls += 1
        return {
            "clusterBinding": {"identity": "exact"},
            "sharedSource": {"uid": "source-uid", "artifactRevision": "main@sha1:" + REVISION},
            "preservation": {"webIngress": "same", "existingWorkbenchNetworkPolicy": "same"},
        }

    def final_checks(self, _plan, before):
        return before

    def get(self, target):
        return self.objects.get(self.key(target))

    def create(self, desired):
        if self.create_responses:
            response = self.create_responses.pop(0)
            if callable(response):
                return response(self, desired)
            if response is not None:
                return response
        value = json.loads(json.dumps(desired))
        value["metadata"]["uid"] = f"uid-{len(self.created) + 1}"
        value["metadata"]["resourceVersion"] = str(10 + len(self.created))
        self.objects[self.key(BOOTSTRAP.target_of(value))] = value
        self.created.append(value)
        return BOOTSTRAP.RawResult(0, json.dumps(value), "")

    def remove_nonce(self, desired, uid, resource_version, nonce):
        target = BOOTSTRAP.target_of(desired)
        current = self.objects[self.key(target)]
        self.assert_owned(current, uid, resource_version, nonce)
        current = json.loads(json.dumps(current))
        current["metadata"]["annotations"].pop(BOOTSTRAP.NONCE_ANNOTATION)
        if not current["metadata"]["annotations"]:
            current["metadata"].pop("annotations")
        current["metadata"]["resourceVersion"] = str(int(resource_version) + 100)
        self.objects[self.key(target)] = current
        return current

    def assert_owned(self, current, uid, resource_version, nonce):
        assert current["metadata"]["uid"] == uid
        assert current["metadata"]["resourceVersion"] == resource_version
        assert current["metadata"]["annotations"][BOOTSTRAP.NONCE_ANNOTATION] == nonce

    def delete(self, target, uid, resource_version):
        current = self.get(target)
        if current is not None and current["metadata"]["uid"] == uid:
            self.objects.pop(self.key(target), None)
        self.deleted.append((target, uid, resource_version))

    def wait_all_absent(self, targets):
        return all(self.get(target) is None for target in targets)


class ParticipantFluxBootstrapTests(unittest.TestCase):
    def ready_plan(self):
        return BOOTSTRAP.build_plan(
            POLICY,
            POLICY.approved_next_activation_policy_descriptor(),
            REVISION,
            {"scripts/bootstrap-staging-participant-flux.py": "sha256:" + "a" * 64},
        )

    def test_plan_contains_only_the_exact_eight_suspended_flux_objects(self) -> None:
        plan = BOOTSTRAP.build_plan(
            POLICY,
            POLICY.approved_next_activation_policy_descriptor(),
            REVISION,
            {"scripts/bootstrap-staging-participant-flux.py": "sha256:" + "a" * 64},
        )

        self.assertEqual(
            [item["logicalName"] for item in plan["objects"]],
            [
                "gateway.serviceAccount",
                "workbenchIngress.serviceAccount",
                "gateway.role",
                "workbenchIngress.role",
                "gateway.roleBinding",
                "workbenchIngress.roleBinding",
                "gateway.kustomization",
                "workbenchIngress.kustomization",
            ],
        )
        self.assertEqual(len(plan["objects"]), 8)
        self.assertTrue(
            all(
                item["desired"].get("spec", {}).get("suspend") is True
                for item in plan["objects"]
                if item["target"]["kind"] == "Kustomization"
            ),
        )
        self.assertEqual(plan["sharedSourceMutation"], "forbidden")
        self.assertFalse(plan["civicAuthorityEffects"])

    def test_receipt_sink_is_0600_non_overwriting_and_canonically_checksummed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "receipts"
            target = parent / "bootstrap.json"
            sink = BOOTSTRAP.ReceiptSink.reserve(target)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

            sink.commit({"schemaVersion": BOOTSTRAP.RECEIPT_SCHEMA, "status": "reserved"})
            receipt = json.loads(target.read_text())
            checksum = receipt.pop("canonicalSha256")
            self.assertEqual(checksum, BOOTSTRAP.canonical_sha256(receipt))
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

            with self.assertRaises(FileExistsError):
                BOOTSTRAP.ReceiptSink.reserve(target)

    def test_receipt_loader_rejects_permissive_mode_and_duplicate_json_keys(self) -> None:
        receipt = close_receipt(BOOTSTRAP._receipt_state(self.ready_plan(), "d" * 64))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            path.write_text(json.dumps(receipt))
            path.chmod(0o600)
            self.assertEqual(BOOTSTRAP.load_receipt(path), receipt)
            path.chmod(0o644)
            with self.assertRaisesRegex(BOOTSTRAP.BootstrapError, "0600"):
                BOOTSTRAP.load_receipt(path)
            path.chmod(0o600)
            path.write_text('{"schemaVersion":"x","schemaVersion":"y"}')
            with self.assertRaisesRegex(BOOTSTRAP.BootstrapError, "duplicate-key"):
                BOOTSTRAP.load_receipt(path)

    def test_live_bootstrap_creates_exactly_eight_objects_and_leaves_both_suspended(self) -> None:
        sink = MemorySink()
        kube = FakeKube()
        receipt = BOOTSTRAP.run(
            self.ready_plan(),
            mode="live",
            kube=kube,
            sink=sink,
            policy_module=POLICY,
        )

        self.assertEqual(receipt["status"], "dormant-ready")
        self.assertEqual(len(kube.created), 8)
        self.assertEqual(kube.deleted, [])
        self.assertEqual(len(receipt["objectCreateResults"]), 8)
        self.assertTrue(all(item["temporaryNonceRemoved"] for item in receipt["objectCreateResults"]))
        self.assertTrue(receipt["postconditions"]["bothKustomizationsSuspended"])
        self.assertEqual(sink.values[-1], receipt)

    def test_any_preexisting_exact_name_blocks_before_the_first_create(self) -> None:
        plan = self.ready_plan()
        kube = FakeKube()
        occupied = json.loads(json.dumps(plan["objects"][3]["desired"]))
        occupied["metadata"].update({"uid": "foreign", "resourceVersion": "7"})
        kube.objects[kube.key(plan["objects"][3]["target"])] = occupied

        with self.assertRaisesRegex(BOOTSTRAP.BootstrapError, "adoption forbidden"):
            BOOTSTRAP.run(
                plan,
                mode="live",
                kube=kube,
                sink=MemorySink(),
                policy_module=POLICY,
            )

        self.assertEqual(kube.created, [])
        self.assertEqual(kube.deleted, [])

    def test_definite_409_is_never_adopted_and_rolls_back_prior_owned_objects(self) -> None:
        plan = self.ready_plan()
        sink = MemorySink()
        kube = FakeKube()
        kube.create_responses = [
            None,
            BOOTSTRAP.RawResult(1, "", "Error from server (AlreadyExists): 409"),
        ]

        with self.assertRaisesRegex(BOOTSTRAP.BootstrapError, "rolled-back"):
            BOOTSTRAP.run(
                plan,
                mode="live",
                kube=kube,
                sink=sink,
                policy_module=POLICY,
            )

        self.assertEqual(len(kube.created), 1)
        self.assertEqual(len(kube.deleted), 1)
        self.assertEqual(kube.deleted[0][0], plan["objects"][0]["target"])
        self.assertEqual(sink.values[-1]["status"], "rolled-back")
        self.assertEqual(sink.values[-1]["rollback"]["allEightAbsentQuiet"], True)

    def test_malformed_rc0_is_uncertain_and_owned_only_after_nonce_discovery(self) -> None:
        def create_then_lose_response(kube, desired):
            created = kube.create_responses
            kube.create_responses = []
            kube.create(desired)
            kube.create_responses = created
            return BOOTSTRAP.RawResult(0, "{malformed", "")

        sink = MemorySink()
        kube = FakeKube()
        kube.create_responses = [create_then_lose_response]
        receipt = BOOTSTRAP.run(
            self.ready_plan(),
            mode="live",
            kube=kube,
            sink=sink,
            policy_module=POLICY,
        )

        self.assertEqual(receipt["status"], "dormant-ready")
        self.assertEqual(
            receipt["objectCreateResults"][0]["outcome"],
            "post-send-uncertain-discovered",
        )

    def test_unresolved_post_send_5xx_can_never_report_complete_rollback(self) -> None:
        sink = MemorySink()
        kube = FakeKube()
        kube.create_responses = [
            BOOTSTRAP.RawResult(1, "", "Internal Server Error: 500"),
        ]

        with self.assertRaisesRegex(BOOTSTRAP.BootstrapError, "rollback-incomplete"):
            BOOTSTRAP.run(
                self.ready_plan(),
                mode="live",
                kube=kube,
                sink=sink,
                policy_module=POLICY,
            )

        self.assertEqual(kube.deleted, [])
        self.assertEqual(sink.values[-1]["status"], "rollback-incomplete")
        self.assertIn(
            "post-send create outcome unresolved: gateway.serviceAccount",
            sink.values[-1]["rollback"]["errors"],
        )

    def test_receipt_persistence_failure_after_create_rolls_back_the_exact_uid(self) -> None:
        plan = self.ready_plan()
        sink = FailOnceSink(fail_on_call=3)
        kube = FakeKube()

        with self.assertRaisesRegex(BOOTSTRAP.BootstrapError, "rolled-back"):
            BOOTSTRAP.run(
                plan,
                mode="live",
                kube=kube,
                sink=sink,
                policy_module=POLICY,
            )

        self.assertEqual(len(kube.created), 1)
        self.assertEqual(kube.deleted[0][1], "uid-1")
        self.assertEqual(sink.values[-1]["status"], "rolled-back")

    def test_lost_nonce_removal_response_rolls_back_the_durable_uid_intent(self) -> None:
        class LostNonceRemovalResponse(FakeKube):
            def remove_nonce(self, desired, uid, resource_version, nonce):
                super().remove_nonce(desired, uid, resource_version, nonce)
                raise OSError("simulated response loss after nonce-removal CAS")

        sink = MemorySink()
        kube = LostNonceRemovalResponse()

        with self.assertRaisesRegex(BOOTSTRAP.BootstrapError, "rolled-back"):
            BOOTSTRAP.run(
                self.ready_plan(),
                mode="live",
                kube=kube,
                sink=sink,
                policy_module=POLICY,
            )

        self.assertEqual(
            [target["kind"] for target, _uid, _rv in kube.deleted[:2]],
            ["Kustomization", "Kustomization"],
        )
        self.assertEqual(
            {uid for _target, uid, _rv in kube.deleted},
            {f"uid-{index}" for index in range(1, 9)},
        )
        self.assertEqual(sink.values[-1]["status"], "rolled-back")
        self.assertEqual(
            sink.values[-1]["objectCreateResults"][0]["nonceRemovalState"],
            "intent-durable",
        )

    def test_receipt_failure_after_nonce_removal_rolls_back_all_exact_uids(self) -> None:
        sink = FailOnceSink(fail_on_call=12)
        kube = FakeKube()

        with self.assertRaisesRegex(BOOTSTRAP.BootstrapError, "rolled-back"):
            BOOTSTRAP.run(
                self.ready_plan(),
                mode="live",
                kube=kube,
                sink=sink,
                policy_module=POLICY,
            )

        self.assertEqual(
            {uid for _target, uid, _rv in kube.deleted},
            {f"uid-{index}" for index in range(1, 9)},
        )
        self.assertEqual(sink.values[-1]["status"], "rolled-back")
        self.assertEqual(
            sink.values[-1]["objectCreateResults"][0]["nonceRemovalState"],
            "removed",
        )

    def test_replacement_uid_is_never_deleted_and_marks_rollback_incomplete(self) -> None:
        plan = self.ready_plan()
        kube = FakeKube()

        def replace_owned_object():
            target = plan["objects"][0]["target"]
            replacement = json.loads(json.dumps(kube.get(target)))
            replacement["metadata"]["uid"] = "foreign-replacement"
            kube.objects[kube.key(target)] = replacement

        sink = FailOnceSink(fail_on_call=3, before_failure=replace_owned_object)
        with self.assertRaisesRegex(BOOTSTRAP.BootstrapError, "rollback-incomplete"):
            BOOTSTRAP.run(
                plan,
                mode="live",
                kube=kube,
                sink=sink,
                policy_module=POLICY,
            )

        self.assertEqual(kube.deleted, [])
        self.assertEqual(sink.values[-1]["status"], "rollback-incomplete")
        self.assertTrue(any("UID replacement" in error for error in sink.values[-1]["rollback"]["errors"]))

    def test_recovery_deletes_nonce_owned_object_missing_from_interrupted_journal(self) -> None:
        plan = self.ready_plan()
        kube = FakeKube()
        nonce = "b" * 64
        desired = BOOTSTRAP._with_nonce(plan["objects"][0]["desired"], nonce)
        kube.create(desired)
        interrupted = BOOTSTRAP._receipt_state(plan, nonce)
        interrupted["status"] = "creating"
        interrupted = close_receipt(interrupted)
        sink = MemorySink()

        recovered = BOOTSTRAP.run(
            plan,
            mode="recover",
            kube=kube,
            sink=sink,
            policy_module=POLICY,
            prior_receipt=interrupted,
        )

        self.assertEqual(recovered["status"], "recovered-rolled-back")
        self.assertEqual(kube.deleted[0][1], "uid-1")
        self.assertTrue(recovered["rollback"]["allEightAbsentQuiet"])

    def test_recovery_deletes_same_uid_after_durable_intent_and_lost_nonce_response(self) -> None:
        plan = self.ready_plan()
        item = plan["objects"][0]
        nonce = "e" * 64
        kube = FakeKube()
        kube.create(BOOTSTRAP._with_nonce(item["desired"], nonce))
        created = kube.get(item["target"])
        uid = created["metadata"]["uid"]
        resource_version = created["metadata"]["resourceVersion"]

        interrupted = BOOTSTRAP._receipt_state(plan, nonce)
        interrupted["status"] = "removing-nonces"
        interrupted["objectCreateResults"].append({
            "logicalName": item["logicalName"],
            "target": item["target"],
            "desiredSemanticSha256": item["desiredSemanticSha256"],
            "outcome": "http-201-created",
            "uid": uid,
            "createdResourceVersion": resource_version,
            "postNonceRemovalResourceVersion": None,
            "nonceRemovalState": "intent-durable",
            "temporaryNonceRemoved": False,
            "rollbackOwned": True,
        })
        BOOTSTRAP._journal(interrupted, "object-created", item["logicalName"])
        BOOTSTRAP._journal(interrupted, "nonce-removal-intent", item["logicalName"])
        kube.remove_nonce(item["desired"], uid, resource_version, nonce)

        recovered = BOOTSTRAP.run(
            plan,
            mode="recover",
            kube=kube,
            sink=MemorySink(),
            policy_module=POLICY,
            prior_receipt=close_receipt(interrupted),
        )

        self.assertEqual(recovered["status"], "recovered-rolled-back")
        self.assertEqual([deleted_uid for _target, deleted_uid, _rv in kube.deleted], [uid])
        self.assertTrue(recovered["rollback"]["allEightAbsentQuiet"])

    def test_recovery_never_deletes_nonce_free_object_without_durable_removal_intent(self) -> None:
        plan = self.ready_plan()
        item = plan["objects"][0]
        nonce = "f" * 64
        kube = FakeKube()
        kube.create(BOOTSTRAP._with_nonce(item["desired"], nonce))
        created = kube.get(item["target"])
        uid = created["metadata"]["uid"]
        resource_version = created["metadata"]["resourceVersion"]

        interrupted = BOOTSTRAP._receipt_state(plan, nonce)
        interrupted["status"] = "creating"
        interrupted["objectCreateResults"].append({
            "logicalName": item["logicalName"],
            "target": item["target"],
            "desiredSemanticSha256": item["desiredSemanticSha256"],
            "outcome": "http-201-created",
            "uid": uid,
            "createdResourceVersion": resource_version,
            "postNonceRemovalResourceVersion": None,
            "nonceRemovalState": "not-started",
            "temporaryNonceRemoved": False,
            "rollbackOwned": True,
        })
        BOOTSTRAP._journal(interrupted, "object-created", item["logicalName"])
        kube.remove_nonce(item["desired"], uid, resource_version, nonce)

        recovered = BOOTSTRAP.run(
            plan,
            mode="recover",
            kube=kube,
            sink=MemorySink(),
            policy_module=POLICY,
            prior_receipt=close_receipt(interrupted),
        )

        self.assertEqual(recovered["status"], "recovery-incomplete")
        self.assertEqual(kube.deleted, [])
        self.assertIsNotNone(kube.get(item["target"]))
        self.assertTrue(
            any("durable UID/removal-intent ownership" in error for error in recovered["rollback"]["errors"]),
        )

    def test_recovery_requires_matching_durable_intent_journal_entry(self) -> None:
        plan = self.ready_plan()
        item = plan["objects"][0]
        nonce = "1" * 64
        kube = FakeKube()
        kube.create(BOOTSTRAP._with_nonce(item["desired"], nonce))
        created = kube.get(item["target"])
        uid = created["metadata"]["uid"]
        resource_version = created["metadata"]["resourceVersion"]

        interrupted = BOOTSTRAP._receipt_state(plan, nonce)
        interrupted["status"] = "removing-nonces"
        interrupted["objectCreateResults"].append({
            "logicalName": item["logicalName"],
            "target": item["target"],
            "desiredSemanticSha256": item["desiredSemanticSha256"],
            "outcome": "http-201-created",
            "uid": uid,
            "createdResourceVersion": resource_version,
            "postNonceRemovalResourceVersion": None,
            "nonceRemovalState": "intent-durable",
            "temporaryNonceRemoved": False,
            "rollbackOwned": True,
        })
        BOOTSTRAP._journal(interrupted, "object-created", item["logicalName"])
        # Deliberately omit the matching nonce-removal-intent journal entry.
        kube.remove_nonce(item["desired"], uid, resource_version, nonce)

        recovered = BOOTSTRAP.run(
            plan,
            mode="recover",
            kube=kube,
            sink=MemorySink(),
            policy_module=POLICY,
            prior_receipt=close_receipt(interrupted),
        )

        self.assertEqual(recovered["status"], "recovery-incomplete")
        self.assertEqual(kube.deleted, [])
        self.assertIsNotNone(kube.get(item["target"]))
        self.assertTrue(
            any("durable nonce-removal-intent journal proof" in error for error in recovered["rollback"]["errors"]),
        )

    def test_bad_recovery_checksum_is_rejected_before_kubernetes_contact(self) -> None:
        plan = self.ready_plan()
        kube = FakeKube()
        receipt = BOOTSTRAP._receipt_state(plan, "c" * 64)
        receipt = close_receipt(receipt)
        receipt["canonicalSha256"] = "sha256:" + "0" * 64

        with self.assertRaisesRegex(BOOTSTRAP.BootstrapError, "checksum"):
            BOOTSTRAP.run(
                plan,
                mode="recover",
                kube=kube,
                sink=MemorySink(),
                policy_module=POLICY,
                prior_receipt=receipt,
            )

        self.assertEqual(kube.preflight_calls, 0)

    def test_success_receipt_binding_returns_only_exact_stable_uids(self) -> None:
        plan = self.ready_plan()
        kube = FakeKube()
        receipt = BOOTSTRAP.run(
            plan,
            mode="live",
            kube=kube,
            sink=MemorySink(),
            policy_module=POLICY,
        )
        closed = close_receipt(receipt)

        bound = BOOTSTRAP.bind_success_receipt(plan, closed)

        self.assertEqual(bound["status"], "dormant-ready")
        self.assertEqual(len(bound["objects"]), 8)
        self.assertEqual(bound["objects"][0]["uid"], "uid-1")
        self.assertNotIn("operationNonce", json.dumps(bound))

    def test_success_receipt_binding_requires_completed_nonce_removal_state(self) -> None:
        plan = self.ready_plan()
        receipt = BOOTSTRAP.run(
            plan,
            mode="live",
            kube=FakeKube(),
            sink=MemorySink(),
            policy_module=POLICY,
        )
        receipt["objectCreateResults"][0].pop("nonceRemovalState")

        with self.assertRaisesRegex(BOOTSTRAP.BootstrapError, "success create binding drift"):
            BOOTSTRAP.bind_success_receipt(plan, close_receipt(receipt))

    def test_success_receipt_binding_requires_complete_nonce_journal(self) -> None:
        plan = self.ready_plan()
        receipt = BOOTSTRAP.run(
            plan,
            mode="live",
            kube=FakeKube(),
            sink=MemorySink(),
            policy_module=POLICY,
        )
        logical_name = plan["objects"][0]["logicalName"]
        for entry in receipt["journal"]:
            if entry.get("phase") == "nonce-removed" and entry.get("logicalName") == logical_name:
                entry["phase"] = "nonce-removal-intent"
                break
        previous = None
        for sequence, entry in enumerate(receipt["journal"], start=1):
            entry.pop("entrySha256", None)
            entry["sequence"] = sequence
            entry["previousEntrySha256"] = previous
            entry["entrySha256"] = BOOTSTRAP.canonical_sha256(entry)
            previous = entry["entrySha256"]

        with self.assertRaisesRegex(BOOTSTRAP.BootstrapError, "success nonce journal drift"):
            BOOTSTRAP.bind_success_receipt(plan, close_receipt(receipt))

    def test_inert_dry_run_writes_plan_without_constructing_kubernetes_adapter(self) -> None:
        inert_plan = BOOTSTRAP.build_plan(
            POLICY,
            POLICY.activation_policy_descriptor(),
            REVISION,
            {"scripts/bootstrap-staging-participant-flux.py": "sha256:" + "a" * 64},
        )
        context = {
            "revision": REVISION,
            "hashes": inert_plan["protectedFileSha256"],
            "policy": POLICY.activation_policy_descriptor(),
            "policyModule": POLICY,
            "bootstrapModule": BOOTSTRAP,
            "plan": inert_plan,
        }
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "dry-run.json"
            with mock.patch.object(CLI, "load_context", return_value=context), mock.patch.object(
                CLI,
                "KubernetesAdapter",
                side_effect=AssertionError("dry-run contacted Kubernetes"),
            ), mock.patch.object(CLI.sys, "flags", mock.Mock(isolated=1, safe_path=True)), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                result = CLI.main(
                    [
                        "--dry-run",
                        "--expected-protected-revision",
                        REVISION,
                        "--receipt",
                        str(receipt),
                    ],
                )
        self.assertEqual(result, 0)
        self.assertEqual(inert_plan["status"], "blocked-policy-incomplete")

    def test_inert_live_gate_fails_before_receipt_or_kubernetes_adapter(self) -> None:
        inert_plan = BOOTSTRAP.build_plan(
            POLICY,
            POLICY.activation_policy_descriptor(),
            REVISION,
            {"scripts/bootstrap-staging-participant-flux.py": "sha256:" + "a" * 64},
        )
        context = {
            "revision": REVISION,
            "hashes": inert_plan["protectedFileSha256"],
            "policy": POLICY.activation_policy_descriptor(),
            "policyModule": POLICY,
            "bootstrapModule": BOOTSTRAP,
            "plan": inert_plan,
        }
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "must-not-exist.json"
            with mock.patch.object(CLI, "load_context", return_value=context), mock.patch.object(
                CLI,
                "KubernetesAdapter",
                side_effect=AssertionError("blocked live mode contacted Kubernetes"),
            ), mock.patch.object(CLI.sys, "flags", mock.Mock(isolated=1, safe_path=True)), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                result = CLI.main(
                    [
                        "--live",
                        "--expected-protected-revision",
                        REVISION,
                        "--kubeconfig",
                        "/must/not/be/read",
                        "--receipt",
                        str(receipt),
                    ],
                )
            self.assertFalse(receipt.exists())
        self.assertEqual(result, 2)

    def test_protected_cli_and_workflow_accept_no_manifest_evidence_or_cluster_credentials(self) -> None:
        source = (ROOT / "scripts/bootstrap-staging-participant-flux.py").read_text()
        workflow = (ROOT / ".github/workflows/staging-participant-flux-bootstrap.yml").read_text()
        for forbidden in ("--manifest", "--evidence", "--target", "--allowlist", "--secret", "--proxy"):
            self.assertNotIn(forbidden, source)
        self.assertIn("env=self.activation.kubernetes_subprocess_environment_v4()", source)
        self.assertIn('modes.add_argument("--dry-run"', source)
        self.assertIn('modes.add_argument("--live"', source)
        self.assertIn('modes.add_argument("--recover"', source)
        self.assertIn("scripts/test_staging_participant_flux_bootstrap.py", workflow)
        self.assertIn("--dry-run", workflow)
        self.assertNotIn("--live", workflow)
        self.assertNotIn("kubeconfig", workflow.lower())
        self.assertNotIn("secrets.", workflow)
        self.assertNotIn("secret_materialization_v4", source)
        self.assertNotIn('["get", "secret"', source)


if __name__ == "__main__":
    unittest.main()
