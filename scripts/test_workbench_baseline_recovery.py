#!/usr/bin/env python3
"""Deterministic tests for the failed-G0 delete-only recovery."""
from __future__ import annotations

import copy
import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


PATH = Path(__file__).with_name("workbench_baseline_recovery.py")
SPEC = importlib.util.spec_from_file_location("workbench_baseline_recovery_test", PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(MODULE)
REVISION = "f" * 40


def key(identity): return (identity["apiVersion"], identity["kind"], identity["namespace"], identity["name"])


def object_live(name: str) -> dict:
    value = copy.deepcopy(MODULE.expected_objects()[name])
    metadata = {"uid": MODULE.OBJECT_UIDS[name], "resourceVersion": "100" + str(len(name)), "generation": 1, "creationTimestamp": "2026-08-27T00:00:00Z"}
    if name == "kustomization":
        metadata.update({"annotations": {MODULE.MARKER_ANNOTATION: MODULE.OPERATION_MARKER}, "finalizers": [MODULE.FINALIZER]})
    value["metadata"].update(metadata)
    if name == "kustomization": value["status"] = {"ignored": True}
    return value


def source_live(revision: str = REVISION) -> dict:
    value = copy.deepcopy(MODULE.expected_source())
    value["metadata"].update({"uid": MODULE.SOURCE_UID, "resourceVersion": "200", "generation": 1, "creationTimestamp": "2026-08-27T00:00:00Z", "finalizers": [MODULE.FINALIZER]})
    value["status"] = {"artifact": {"revision": f"main@sha1:{revision}"}, "observedGeneration": 1, "conditions": [{"type": "Ready", "status": "True", "observedGeneration": 1}]}
    return value


def baseline_live() -> dict:
    value = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": MODULE.WORKBENCH_NAME, "namespace": MODULE.WORKBENCH_NAMESPACE, "uid": MODULE.BASELINE_UID, "resourceVersion": "300", "generation": 1, "creationTimestamp": "2026-08-27T00:00:00Z"}, "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}}
    return value


def origin_journal() -> bytes:
    records = []
    for name in MODULE.OBJECT_ORDER:
        desired = copy.deepcopy(MODULE.expected_objects()[name])
        marked = copy.deepcopy(desired); marked["metadata"]["annotations"] = {MODULE.MARKER_ANNOTATION: MODULE.OPERATION_MARKER}
        records.append({"objectId": name, "target": MODULE.target(desired), "desired": desired, "uid": MODULE.OBJECT_UIDS[name], "markedDesired": marked, "markerRemoved": name != "kustomization"})
    return json.dumps({"journalSha256": "", "protectedRevision": MODULE.ORIGIN_REVISION, "operationId": MODULE.OPERATION_ID, "operationMarker": MODULE.OPERATION_MARKER, "baseline": {"uid": MODULE.BASELINE_UID, "objectDigest": ""}, "createdObjects": records}, sort_keys=True, separators=(",", ":")).encode()


class FakeKube:
    def __init__(self):
        self.objects = {key(MODULE.baseline_target()): baseline_live(), key(MODULE.source_target()): source_live()}
        for name in MODULE.OBJECT_ORDER: self.objects[key(MODULE.target(MODULE.expected_objects()[name]))] = object_live(name)
        self.gets = []; self.deletes = []; self.keep_once = None
    def get(self, identity):
        self.gets.append(copy.deepcopy(identity)); value = self.objects.get(key(identity)); return copy.deepcopy(value) if value else None
    def delete(self, identity, *, uid, resource_version):
        self.deletes.append((copy.deepcopy(identity), uid, resource_version))
        current = self.objects.get(key(identity))
        if current is None: return
        if current["metadata"]["uid"] != uid or current["metadata"]["resourceVersion"] != resource_version: raise MODULE.RecoveryError("delete CAS mismatch")
        if self.keep_once == identity["kind"]:
            self.keep_once = None; return
        self.objects.pop(key(identity))


class RecoveryTests(unittest.TestCase):
    def inputs(self, baseline):
        journal = origin_journal(); attempt = b'{"attempt":"exact"}'
        inspection = {"schemaVersion": "stadtstack_workbench_read_only_inspection_v1", "containsSecretMaterial": False, "mutationAttempted": False, "objects": {"networkPolicy": baseline, "source": source_live(MODULE.ORIGIN_REVISION), **{name: object_live(name) for name in MODULE.OBJECT_ORDER}}, "proof": {"kustomizationNormalizedDiffPaths": ["$.metadata.annotations"], "networkPolicyCanonicalSha256": MODULE.digest(baseline)}}
        inspection = json.dumps(inspection, sort_keys=True, separators=(",", ":")).encode()
        decoded = json.loads(journal); decoded["baseline"]["objectDigest"] = MODULE.digest(baseline); decoded["journalSha256"] = MODULE.digest({k: v for k, v in decoded.items() if k != "journalSha256"})
        journal = json.dumps(decoded, sort_keys=True, separators=(",", ":")).encode()
        return journal, attempt, inspection

    def patched_constants(self, journal, attempt, inspection, baseline):
        return patch.multiple(
            MODULE,
            ORIGIN_JOURNAL_FILE_SHA256=MODULE.bytes_digest(journal),
            ORIGIN_JOURNAL_EMBEDDED_SHA256=json.loads(journal)["journalSha256"],
            ATTEMPT_RECEIPT_SHA256=MODULE.bytes_digest(attempt),
            INSPECTION_SHA256=MODULE.bytes_digest(inspection),
            BASELINE_DIGEST=MODULE.digest(baseline),
        )

    def invoke(self, kube, journal_sink=None, receipt=None):
        baseline = kube.get(MODULE.baseline_target())
        assert baseline is not None
        origin, attempt, inspection = self.inputs(baseline)
        with self.patched_constants(origin, attempt, inspection, baseline):
            return MODULE.run(kube=kube, revision=REVISION, origin_journal=origin, attempt_receipt=attempt, inspection=inspection, journal=journal_sink or MODULE.MemoryJournal(), receipt=receipt or MODULE.MemoryReceipt())

    def adapter_with_runs(self, responses):
        adapter = MODULE.KubernetesAdapter.__new__(MODULE.KubernetesAdapter)
        calls = []

        def fake_run(arguments, *, input_text=None):
            calls.append((arguments, input_text))
            response = responses.pop(0)
            if isinstance(response, BaseException):
                raise response
            return response

        adapter._run = fake_run
        return adapter, calls

    def test_kubernetes_get_retries_exact_tls_transport_then_succeeds(self):
        identity = MODULE.baseline_target()
        adapter, calls = self.adapter_with_runs([
            (1, "", "Unable to connect to the server: net/http: TLS handshake timeout\n"),
            (1, "", "net/http: TLS handshake timeout"),
            (0, '{"ok":true}', ""),
        ])
        with patch.object(MODULE.time, "sleep") as sleep:
            self.assertEqual(adapter.get(identity), {"ok": True})
        self.assertEqual(len(calls), 3)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [0.25, 0.75])

    def test_kubernetes_get_surfaces_bounded_failure_after_three_exact_tls_failures(self):
        identity = MODULE.baseline_target()
        adapter, calls = self.adapter_with_runs([
            (1, "", "net/http: TLS handshake timeout") for _ in range(MODULE.GET_MAX_ATTEMPTS)
        ])
        with patch.object(MODULE.time, "sleep") as sleep:
            with self.assertRaisesRegex(MODULE.RecoveryError, "GET failed after 3 attempts"):
                adapter.get(identity)
        self.assertEqual(len(calls), MODULE.GET_MAX_ATTEMPTS)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [0.25, 0.75])

    def test_kubernetes_get_retries_timeout_expired_then_succeeds(self):
        identity = MODULE.baseline_target()
        adapter, calls = self.adapter_with_runs([
            MODULE.subprocess.TimeoutExpired(["kubectl"], 40),
            (0, '{"ok":true}', ""),
        ])
        with patch.object(MODULE.time, "sleep") as sleep:
            self.assertEqual(adapter.get(identity), {"ok": True})
        self.assertEqual(len(calls), 2)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [0.25])

    def test_kubernetes_get_does_not_retry_non_transport_failures(self):
        identity = MODULE.baseline_target()
        cases = (
            ((1, "", "Error from server (Forbidden): denied"), MODULE.RecoveryError),
            ((1, "", "Error from server (Unauthorized): denied"), MODULE.RecoveryError),
            ((0, "[]", ""), MODULE.RecoveryError),
            ((1, "", "request timed out"), MODULE.RecoveryError),
            ((1, '{"partial":true}', "net/http: TLS handshake timeout"), MODULE.RecoveryError),
            ((1, "", "net/http: TLS handshake timeout with context"), MODULE.RecoveryError),
        )
        for response, error_type in cases:
            adapter, calls = self.adapter_with_runs([response])
            with patch.object(MODULE.time, "sleep") as sleep:
                with self.assertRaises(error_type):
                    adapter.get(identity)
            self.assertEqual(len(calls), 1)
            sleep.assert_not_called()

        adapter, calls = self.adapter_with_runs([(1, "", "Error from server (NotFound): absent")])
        with patch.object(MODULE.time, "sleep") as sleep:
            self.assertIsNone(adapter.get(identity))
        self.assertEqual(len(calls), 1)
        sleep.assert_not_called()

    def test_kubernetes_get_validates_target_before_any_attempt(self):
        adapter, calls = self.adapter_with_runs([(0, '{"ok":true}', "")])
        with self.assertRaisesRegex(MODULE.RecoveryError, "outside recovery scope"):
            adapter.get({"apiVersion": "v1", "kind": "ConfigMap", "namespace": "other", "name": "not-allowed"})
        self.assertEqual(calls, [])

    def test_recovery_retries_transient_post_delete_get_without_duplicate_deletes(self):
        class RetryingKube(FakeKube):
            def __init__(self):
                super().__init__()
                self.transient_pending = False
                self.adapter = MODULE.KubernetesAdapter.__new__(MODULE.KubernetesAdapter)
                self.adapter._run = self.transport_run

            def transport_run(self, arguments, *, input_text=None):
                identity = next(
                    allowed
                    for allowed in MODULE._allowed_targets()
                    if allowed["namespace"] == arguments[1]
                    and allowed["kind"].lower() == arguments[3]
                    and allowed["name"] == arguments[4]
                )
                if self.transient_pending:
                    self.transient_pending = False
                    return 1, "", "Unable to connect to the server: net/http: TLS handshake timeout"
                value = FakeKube.get(self, identity)
                if value is None:
                    return 1, "", "Error from server (NotFound): absent"
                return 0, json.dumps(value), ""

            def get(self, identity):
                return self.adapter.get(identity)

            def delete(self, identity, *, uid, resource_version):
                super().delete(identity, uid=uid, resource_version=resource_version)
                if len(self.deletes) == 1:
                    self.transient_pending = True

        kube = RetryingKube()
        journal = MODULE.MemoryJournal()
        with patch.object(MODULE.time, "sleep") as sleep:
            result = self.invoke(kube, journal, MODULE.MemoryReceipt())
        self.assertEqual(result["status"], "completed")
        self.assertEqual([item[0]["kind"] for item in kube.deletes], ["Kustomization", "RoleBinding", "Role", "ServiceAccount"])
        self.assertEqual(len(kube.deletes), 4)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [0.25])

    def test_kubernetes_mutation_delete_remains_single_attempt(self):
        adapter = MODULE.KubernetesAdapter.__new__(MODULE.KubernetesAdapter)
        calls = []

        def fake_run(arguments, *, input_text=None):
            calls.append((arguments, input_text))
            return 0, "{}", ""

        adapter._run = fake_run
        identity = MODULE.target(MODULE.expected_objects()["serviceAccount"])
        with patch.object(MODULE.time, "sleep") as sleep:
            MODULE.KubernetesAdapter.delete(
                adapter,
                identity,
                uid=MODULE.OBJECT_UIDS["serviceAccount"],
                resource_version="17000001",
            )
        self.assertEqual(len(calls), 1)
        sleep.assert_not_called()

    def test_success_is_exact_ordered_delete_only_and_reproves_predecessors(self):
        kube = FakeKube(); journal = MODULE.MemoryJournal(); receipt = MODULE.MemoryReceipt(); result = self.invoke(kube, journal, receipt)
        self.assertEqual(result["status"], "completed")
        self.assertEqual([item[0]["kind"] for item in kube.deletes], ["Kustomization", "RoleBinding", "Role", "ServiceAccount"])
        self.assertTrue(result["effects"]["cleanupComplete"])
        self.assertFalse(result["effects"]["create"]); self.assertFalse(result["effects"]["patch"]); self.assertFalse(result["effects"]["secretAccess"])
        self.assertIsNotNone(kube.get(MODULE.baseline_target())); self.assertIsNotNone(kube.get(MODULE.source_target()))
        binding = result["journal"]
        self.assertEqual(binding["terminalJournalSha256"], MODULE.digest(journal.state))
        self.assertEqual(binding["terminalEntrySha256"], journal.state["events"][-1]["entrySha256"])
        delete_event = next(event for event in journal.state["events"] if event["operation"] == "delete.kustomization" and event["stage"] == "after")
        self.assertEqual(delete_event["deletePayloadSha256"], MODULE.bytes_digest(delete_event["deletePayload"].encode()))
        self.assertEqual(json.loads(delete_event["deletePayload"]), delete_event["deleteOptions"])

    def test_replacement_uid_blocks_before_any_delete(self):
        kube = FakeKube(); identity = MODULE.target(MODULE.expected_objects()["role"]); kube.objects[key(identity)]["metadata"]["uid"] = "00000000-0000-4000-8000-000000000099"
        with self.assertRaisesRegex(MODULE.RecoveryError, "UID replacement"):
            self.invoke(kube)
        self.assertEqual(kube.deletes, [])

    def test_semantic_drift_blocks_before_any_delete(self):
        kube = FakeKube(); identity = MODULE.target(MODULE.expected_objects()["roleBinding"]); kube.objects[key(identity)]["roleRef"]["name"] = "widened"
        with self.assertRaisesRegex(MODULE.RecoveryError, "semantic drift"):
            self.invoke(kube)
        self.assertEqual(kube.deletes, [])

    def test_source_or_baseline_drift_blocks_before_any_delete(self):
        for target_name in ("source", "baseline"):
            kube = FakeKube()
            reference = kube.get(MODULE.baseline_target())
            assert reference is not None
            origin, attempt, inspection = self.inputs(reference)
            if target_name == "source": kube.objects[key(MODULE.source_target())]["status"]["artifact"]["revision"] = "main@sha1:" + "a" * 40
            else: kube.objects[key(MODULE.baseline_target())]["spec"]["policyTypes"].append("Egress")
            with self.patched_constants(origin, attempt, inspection, reference):
                with self.assertRaises(MODULE.RecoveryError):
                    MODULE.run(kube=kube, revision=REVISION, origin_journal=origin, attempt_receipt=attempt, inspection=inspection, journal=MODULE.MemoryJournal(), receipt=MODULE.MemoryReceipt())
            self.assertEqual(kube.deletes, [])

    def test_pending_delete_resume_uses_same_journal_and_never_retries_in_one_run(self):
        kube = FakeKube(); kube.keep_once = "Role"; journal = MODULE.MemoryJournal(); first = MODULE.MemoryReceipt()
        with self.assertRaisesRegex(MODULE.RecoveryError, "pending; resume"):
            self.invoke(kube, journal, first)
        self.assertEqual(len(kube.deletes), 3); self.assertEqual(first.value["status"], "pending")
        kube.objects[key(MODULE.source_target())]["metadata"]["resourceVersion"] = "201"
        second = MODULE.MemoryReceipt(); result = self.invoke(kube, journal, second)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(kube.deletes), 5)

    def test_source_stable_proof_rejects_uid_generation_revision_or_spec_drift(self):
        for drift in ("uid", "generation", "revision", "spec"):
            kube = FakeKube(); baseline = kube.get(MODULE.baseline_target()); assert baseline is not None
            origin, attempt, inspection = self.inputs(baseline)
            source = kube.objects[key(MODULE.source_target())]
            if drift == "uid":
                source["metadata"]["uid"] = "00000000-0000-4000-8000-000000000099"
            elif drift == "generation":
                source["metadata"]["generation"] = 2
            elif drift == "revision":
                source["status"]["artifact"]["revision"] = "main@sha1:" + "a" * 40
            else:
                source["spec"]["timeout"] = "31s"
            with self.patched_constants(origin, attempt, inspection, baseline):
                with self.assertRaises(MODULE.RecoveryError):
                    MODULE.run(kube=kube, revision=REVISION, origin_journal=origin, attempt_receipt=attempt, inspection=inspection, journal=MODULE.MemoryJournal(), receipt=MODULE.MemoryReceipt())

    def test_lost_delete_response_resumes_by_proving_absence_without_a_second_delete(self):
        class ResponseLostKube(FakeKube):
            def __init__(self): super().__init__(); self.lose_once = "role"
            def delete(self, identity, *, uid, resource_version):
                super().delete(identity, uid=uid, resource_version=resource_version)
                if identity["kind"] == "Role" and self.lose_once:
                    self.lose_once = None
                    raise RuntimeError("response lost after API accepted DELETE")

        kube = ResponseLostKube(); journal = MODULE.MemoryJournal()
        with self.assertRaisesRegex(MODULE.RecoveryError, "pending; resume"):
            self.invoke(kube, journal, MODULE.MemoryReceipt())
        self.assertEqual(journal.state["objects"]["role"]["status"], "delete-uncertain")
        result = self.invoke(kube, journal, MODULE.MemoryReceipt())
        self.assertEqual(result["status"], "completed")
        self.assertEqual([item[0]["kind"] for item in kube.deletes], ["Kustomization", "RoleBinding", "Role", "ServiceAccount"])

    def test_crash_after_durable_delete_intent_resumes_by_proving_absence(self):
        class SimulatedCrash(BaseException): pass
        class CrashAfterDeleteKube(FakeKube):
            def __init__(self): super().__init__(); self.crash_once = True
            def delete(self, identity, *, uid, resource_version):
                super().delete(identity, uid=uid, resource_version=resource_version)
                if identity["kind"] == "Role" and self.crash_once:
                    self.crash_once = False
                    raise SimulatedCrash("crash after accepted delete")

        kube = CrashAfterDeleteKube(); journal = MODULE.MemoryJournal()
        with self.assertRaises(SimulatedCrash):
            self.invoke(kube, journal, MODULE.MemoryReceipt())
        self.assertEqual(journal.state["objects"]["role"]["status"], "delete-intent")
        result = self.invoke(kube, journal, MODULE.MemoryReceipt())
        self.assertEqual(result["status"], "completed")
        self.assertEqual([item[0]["kind"] for item in kube.deletes], ["Kustomization", "RoleBinding", "Role", "ServiceAccount"])
        self.assertEqual(set(result["finalAbsence"]), set(MODULE.OBJECT_ORDER))

    def test_origin_marker_removal_projection_is_bound_per_object(self):
        kube = FakeKube(); baseline = kube.get(MODULE.baseline_target()); assert baseline is not None
        origin, attempt, inspection = self.inputs(baseline)
        tampered = json.loads(origin)
        next(item for item in tampered["createdObjects"] if item["objectId"] == "role")["markerRemoved"] = False
        unsigned = {key: value for key, value in tampered.items() if key != "journalSha256"}
        tampered["journalSha256"] = MODULE.digest(unsigned)
        tampered_raw = json.dumps(tampered, sort_keys=True, separators=(",", ":")).encode()
        with self.patched_constants(tampered_raw, attempt, inspection, baseline):
            with self.assertRaisesRegex(MODULE.RecoveryError, "marker-removal state drift"):
                MODULE.run(kube=kube, revision=REVISION, origin_journal=tampered_raw, attempt_receipt=attempt, inspection=inspection, journal=MODULE.MemoryJournal(), receipt=MODULE.MemoryReceipt())

    def test_final_all_absent_proof_rejects_same_name_reappearance(self):
        class ReappearingKube(FakeKube):
            def __init__(self): super().__init__(); self.reappeared = False
            def get(self, identity):
                if len(self.deletes) == len(MODULE.OBJECT_ORDER) and identity["kind"] == "Kustomization" and not self.reappeared:
                    self.reappeared = True
                    self.objects[key(identity)] = object_live("kustomization")
                return super().get(identity)

        kube = ReappearingKube()
        with self.assertRaisesRegex(MODULE.RecoveryError, "reappeared after deletion"):
            self.invoke(kube)

    def test_terminal_journal_reentry_finalizes_new_receipt_without_another_delete(self):
        class ReceiptPersistenceFailure(MODULE.MemoryReceipt):
            def commit(self, value):
                raise OSError("receipt persistence failed after terminal journal")

        kube = FakeKube(); journal = MODULE.MemoryJournal()
        with self.assertRaisesRegex(OSError, "receipt persistence failed"):
            self.invoke(kube, journal, ReceiptPersistenceFailure())
        self.assertEqual(journal.state["status"], "completed")
        deletes_before = list(kube.deletes)
        recovered_receipt = MODULE.MemoryReceipt()
        result = self.invoke(kube, journal, recovered_receipt)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(kube.deletes, deletes_before)
        self.assertEqual(recovered_receipt.value["journal"]["terminalJournalSha256"], MODULE.digest(journal.state))

    def test_receipt_is_immutable_and_cli_surface_has_no_mutating_escape_hatches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700); receipt = MODULE.JsonReceipt(root / "receipt.json")
            receipt.commit({"schemaVersion": MODULE.RECEIPT_SCHEMA, "status": "completed"})
            with self.assertRaisesRegex(MODULE.RecoveryError, "immutable"): receipt.commit({"schemaVersion": MODULE.RECEIPT_SCHEMA, "status": "again"})
            with self.assertRaisesRegex(MODULE.RecoveryError, "already reserved or completed"):
                MODULE.JsonReceipt(root / "receipt.json")
        parser = MODULE.parse_args
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit): parser(["--expected-protected-revision", REVISION])
        for forbidden in ("patch", "create", "apply", "list"):
            self.assertFalse(hasattr(MODULE.KubernetesAdapter, forbidden))

    def test_journal_checksum_tampering_is_rejected_after_a_durable_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700); path = root / "journal.json"
            journal = MODULE.JsonJournal(path)
            journal.commit({"schemaVersion": MODULE.JOURNAL_SCHEMA, "status": "in-progress"})
            self.assertEqual(MODULE.JsonJournal(path).load()["status"], "in-progress")
            path.write_text('{"journalSha256":"sha256:' + "0" * 64 + '","status":"tampered"}\n')
            path.chmod(0o600)
            with self.assertRaisesRegex(MODULE.RecoveryError, "checksum drift"):
                MODULE.JsonJournal(path).load()

    def test_journal_reopens_latest_fsynced_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700); path = root / "journal.json"
            journal = MODULE.JsonJournal(path)
            first_identity = journal.identity
            journal.commit({"schemaVersion": MODULE.JOURNAL_SCHEMA, "sequence": 1})
            second_identity = journal.identity
            journal.commit({"schemaVersion": MODULE.JOURNAL_SCHEMA, "sequence": 2})
            self.assertNotEqual(first_identity[:2], second_identity[:2])
            reloaded = MODULE.JsonJournal(path)
            self.assertEqual(reloaded.load(), {"schemaVersion": MODULE.JOURNAL_SCHEMA, "sequence": 2})
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_receipt_journal_alias_blocks_before_any_kubernetes_contact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700); journal = MODULE.JsonJournal(root / "journal.json")

            class AliasedReceipt:
                path = journal.path
                identity = journal.identity
                def commit(self, value):
                    raise AssertionError("receipt must not be written")

            class NeverContactKube:
                def get(self, identity):
                    raise AssertionError("output alias must block before Kubernetes GET")

            with self.assertRaisesRegex(MODULE.RecoveryError, "paths must be distinct"):
                MODULE.run(
                    kube=NeverContactKube(), revision=REVISION,
                    origin_journal=b"invalid", attempt_receipt=b"invalid", inspection=b"invalid",
                    journal=journal, receipt=AliasedReceipt(),
                )


if __name__ == "__main__": unittest.main()
