#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


MODULE = load("tracer_data_plane_runner_test_subject", ROOT / "scripts/run-tracer-data-plane-live.py")
TRACER = load("tracer_data_plane_runner_policy_fixture", ROOT / "scripts/tracer_data_plane_policy.py")
KUBE_POLICY = load("tracer_data_plane_kube_semantics_fixture", ROOT / "scripts/staging_participant_gateway_policy.py")
REVISION = "a" * 40
NONCE = "b" * 64
HASHES = {path: TRACER.bytes_sha256(path.encode()) for path in MODULE.protected_paths(TRACER)}


class Result:
    def __init__(self, code: int = 0, out: str = "", err: str = "") -> None:
        self.code = code
        self.out = out
        self.err = err


def desired_objects() -> dict[str, dict]:
    application = TRACER.expected_application_objects(ROOT)
    flux = TRACER.dormant_flux_objects(suspended=True)
    return {
        **{f"application.{label}": value for label, value in application.items()},
        **{f"flux.{label}": value for label, value in flux.items()},
    }


def defaulted(value: dict, uid: str = "fixture-uid", rv: str = "17") -> dict:
    result = copy.deepcopy(value)
    metadata = result["metadata"]
    metadata.update({
        "uid": uid,
        "resourceVersion": rv,
        "creationTimestamp": "2026-08-30T00:00:00Z",
        "generation": 1,
        "managedFields": [{"manager": "kube-apiserver"}],
    })
    result["status"] = {"fixture": True}
    kind = result["kind"]
    spec = result.get("spec", {})
    if kind == "Service":
        spec.update({
            "clusterIP": "10.96.0.20",
            "clusterIPs": ["10.96.0.20"],
            "internalTrafficPolicy": "Cluster",
            "ipFamilies": ["IPv4"],
            "ipFamilyPolicy": "SingleStack",
            "sessionAffinity": "None",
        })
        for port in spec["ports"]:
            port["nodePort"] = 31000
    elif kind == "Deployment":
        metadata.setdefault("annotations", {})["deployment.kubernetes.io/revision"] = "1"
        spec.setdefault("paused", False)
        spec.setdefault("progressDeadlineSeconds", 600)
        spec.setdefault("revisionHistoryLimit", 10)
        pod = spec["template"]["spec"]
        if pod.get("serviceAccountName"):
            pod["serviceAccount"] = pod["serviceAccountName"]
        for key, value in {
            "dnsPolicy": "ClusterFirst",
            "enableServiceLinks": True,
            "restartPolicy": "Always",
            "schedulerName": "default-scheduler",
            "terminationGracePeriodSeconds": 30,
        }.items():
            pod.setdefault(key, value)
        for container in pod["containers"]:
            container.update({"terminationMessagePath": "/dev/termination-log", "terminationMessagePolicy": "File"})
    elif kind == "ServiceAccount":
        result["secrets"] = [{"name": "server-generated-token"}]
    elif kind == "Kustomization":
        metadata["finalizers"] = ["finalizers.fluxcd.io"]
    return result


def object_record(label: str, desired: dict, *, removed: bool = False, rv: str = "17") -> dict:
    return {
        "target": {
            "apiVersion": desired["apiVersion"],
            "kind": desired["kind"],
            "namespace": desired["metadata"]["namespace"],
            "name": desired["metadata"]["name"],
        },
        "uid": f"fixture-{label}-uid",
        "resourceVersion": rv,
        "ownershipNonce": NONCE,
        "temporaryNonceRemoved": removed,
    }


class ObjectRunner:
    def __init__(self) -> None:
        self.state: dict[tuple[str, str, str], dict] = {}
        self.create_code = 0
        self.create_error = ""
        self.create_nonce: str | None = None
        self.patch_codes: list[int] = []
        self.mutations: list[str] = []

    @staticmethod
    def key(value: dict) -> tuple[str, str, str]:
        return (
            MODULE.kind_cli(value["kind"]),
            value["metadata"]["namespace"],
            value["metadata"]["name"],
        )

    def run(self, command, *, input_text=None, timeout=None):
        del timeout
        namespace = command[command.index("-n") + 1]
        if "create" in command:
            body = json.loads(input_text)
            if self.create_nonce is not None:
                body["metadata"]["annotations"][MODULE.NONCE_ANNOTATION] = self.create_nonce
            observed = defaulted(body, uid="created-object-uid", rv="17")
            self.state[self.key(observed)] = observed
            self.mutations.append("create")
            return Result(self.create_code, err=self.create_error)
        if "get" in command:
            kind = command[command.index("get") + 1]
            name = command[command.index(kind) + 1]
            observed = self.state.get((kind, namespace, name))
            if observed is None:
                return Result(1, err="Error from server (NotFound): object not found")
            return Result(out=json.dumps(observed))
        if "patch" in command:
            kind = command[command.index("patch") + 1]
            name = command[command.index(kind) + 1]
            key = (kind, namespace, name)
            if key not in self.state and kind == "kustomization":
                key = ("kustomization.kustomize.toolkit.fluxcd.io", namespace, name)
            observed = self.state[key]
            payload = json.loads(command[command.index("-p") + 1])
            if isinstance(payload, list):
                observed["metadata"].get("annotations", {}).pop(MODULE.NONCE_ANNOTATION, None)
            else:
                observed["spec"]["suspend"] = payload["spec"]["suspend"]
            observed["metadata"]["resourceVersion"] = str(int(observed["metadata"]["resourceVersion"]) + 1)
            code = self.patch_codes.pop(0) if self.patch_codes else 0
            self.mutations.append("patch")
            return Result(code, out=json.dumps(observed) if code == 0 else "", err="response lost" if code else "")
        raise AssertionError(command)


class Snapshot:
    path = Path("/snapshot")

    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class NoSignals:
    observed: list[int] = []

    def install(self) -> None:
        pass

    def defer(self) -> None:
        pass

    def restore(self) -> None:
        pass


def private_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)


def activation_journal(reservation: dict, records: dict[str, dict]) -> dict:
    order = list(desired_objects())
    return {
        "schemaVersion": MODULE.JOURNAL_SCHEMA,
        "status": "in-progress",
        "phase": "fixture",
        "protectedRevision": REVISION,
        "protectedFileSha256": HASHES,
        "operationNonce": NONCE,
        "receiptReservation": reservation,
        "createOrder": order,
        "objectRecords": records,
        "rollbackDeleted": [],
        "secretMaterializationReceiptSha256": MODULE.sha256_bytes(b"secret-receipt"),
        "secretValuesIncluded": False,
        "civicAuthorityEffects": False,
    }


class TracerRunnerTests(unittest.TestCase):
    def test_recovery_revision_binding_allows_only_the_exact_direct_default_fix(self) -> None:
        same = MODULE.bind_recovery_revision(
            {"protectedRevision": REVISION, "protectedFileSha256": HASHES},
            REVISION,
            HASHES,
            TRACER,
        )
        self.assertEqual(same["mode"], "same-protected-revision")

        historical = {path: f"old:{path}" for path in HASHES}
        current = copy.deepcopy(historical)
        current[MODULE.SELF_PATH] = "new:runner"
        current[MODULE.PARTICIPANT_POLICY_PATH] = "new:normalizer"
        journal = {
            "protectedRevision": MODULE.RECOVERY_COMPATIBLE_ORIGIN_REVISION,
            "protectedFileSha256": historical,
        }
        with (
            patch.object(MODULE, "protected_hashes_at_revision", return_value=historical),
            patch.object(
                MODULE,
                "direct_successor_changed_files",
                return_value=MODULE.RECOVERY_COMPATIBLE_SUCCESSOR_FILES,
            ),
        ):
            binding = MODULE.bind_recovery_revision(
                journal,
                "c" * 40,
                current,
                TRACER,
            )
        self.assertEqual(binding["mode"], "exact-direct-default-normalizer-successor")
        self.assertEqual(
            binding["changedProtectedPaths"],
            sorted({MODULE.SELF_PATH, MODULE.PARTICIPANT_POLICY_PATH}),
        )

        with (
            patch.object(MODULE, "protected_hashes_at_revision", return_value=historical),
            patch.object(MODULE, "direct_successor_changed_files", return_value={"README.md"}),
        ):
            with self.assertRaisesRegex(MODULE.ActivationError, "successor file set drift"):
                MODULE.bind_recovery_revision(journal, "c" * 40, current, TRACER)

    def test_flux_source_kind_has_an_exact_kubectl_resource(self) -> None:
        self.assertEqual(
            MODULE.kind_cli("GitRepository"),
            "gitrepository.source.toolkit.fluxcd.io",
        )

    def test_dynamic_loader_registers_dataclass_module_during_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "dataclass_probe.py"
            source.write_text(
                "from dataclasses import dataclass\n"
                "@dataclass\n"
                "class Probe:\n"
                "    value: int\n",
            )
            name = "tracer_runner_dataclass_probe"
            sys.modules.pop(name, None)
            self.addCleanup(sys.modules.pop, name, None)
            loaded = MODULE.load_module(source, name)
            self.assertIs(sys.modules[name], loaded)
            self.assertEqual(loaded.Probe(11).value, 11)

    core = SimpleNamespace(POLICY=KUBE_POLICY, obj=lambda raw, label: json.loads(raw))

    def test_all_twelve_objects_accept_only_documented_kubernetes_defaults(self) -> None:
        desired = desired_objects()
        self.assertEqual(len(desired), 12)
        for index, (label, item) in enumerate(desired.items()):
            with self.subTest(label=label):
                nonce_desired = MODULE.with_nonce(item, NONCE)
                observed = defaulted(nonce_desired, uid=f"object-{index}-uid", rv=str(20 + index))
                bound = MODULE.bind_observed(self.core, item, observed, NONCE, label)
                self.assertEqual(bound["uid"], f"object-{index}-uid")
                self.assertFalse(bound["temporaryNonceRemoved"])

        network = desired["application.postgrestNetworkPolicy"]
        changed = defaulted(MODULE.with_nonce(network, NONCE))
        changed["spec"]["ingress"].append({"from": [{"namespaceSelector": {}}]})
        with self.assertRaisesRegex(MODULE.ActivationError, "semantic drift"):
            MODULE.bind_observed(self.core, network, changed, NONCE, "changed network")

    def test_uncertain_create_accepts_exact_same_nonce_and_rejects_adoption(self) -> None:
        item = desired_objects()["application.serviceAccount"]
        runner = ObjectRunner()
        runner.create_code = 124
        runner.create_error = "request timed out after send"
        record = MODULE.create_object(self.core, runner, "/snapshot", "serviceAccount", item, NONCE)
        self.assertEqual(record["uid"], "created-object-uid")
        self.assertEqual(record["ownershipNonce"], NONCE)

        foreign = ObjectRunner()
        foreign.create_code = 124
        foreign.create_nonce = "c" * 64
        with self.assertRaisesRegex(MODULE.ActivationError, "semantic drift"):
            MODULE.create_object(self.core, foreign, "/snapshot", "serviceAccount", item, NONCE)

        conflict = ObjectRunner()
        conflict.create_code = 1
        conflict.create_error = "AlreadyExists 409"
        with self.assertRaisesRegex(MODULE.ActivationError, "adoption forbidden"):
            MODULE.create_object(self.core, conflict, "/snapshot", "serviceAccount", item, NONCE)

    def test_lost_nonce_removal_response_is_classified_for_exact_safe_rollback(self) -> None:
        item = desired_objects()["application.serviceAccount"]
        runner = ObjectRunner()
        live = defaulted(MODULE.with_nonce(item, NONCE), uid="created-object-uid", rv="17")
        runner.state[runner.key(live)] = live
        runner.patch_codes = [124]
        record = MODULE.bind_observed(self.core, item, live, NONCE, "serviceAccount")
        with self.assertRaisesRegex(MODULE.ActivationError, "nonce-removal CAS failed"):
            MODULE.remove_nonce(self.core, runner, "/snapshot", "serviceAccount", item, record)
        self.assertNotIn(MODULE.NONCE_ANNOTATION, live["metadata"].get("annotations", {}))

        deleted = []

        def raw_delete(snapshot, path, payload, timeout):
            del snapshot, payload, timeout
            deleted.append(path)
            runner.state.clear()

        core = SimpleNamespace(POLICY=KUBE_POLICY, obj=lambda raw, label: json.loads(raw), raw_delete=raw_delete)
        with patch.object(MODULE.time, "sleep", return_value=None):
            MODULE.delete_owned(core, runner, Snapshot(), "/snapshot", "serviceAccount", item, record)
        self.assertEqual(deleted, [MODULE.resource_path(item)])

    def test_lost_unsuspend_response_is_recognized_then_resuspended(self) -> None:
        desired = {"flux.kustomization": desired_objects()["flux.kustomization"]}
        item = desired["flux.kustomization"]
        runner = ObjectRunner()
        live = defaulted(item, uid="flux-object-uid", rv="17")
        runner.state[runner.key(live)] = live
        runner.patch_codes = [124, 0]
        record = object_record("flux.kustomization", item, removed=True)
        record["uid"] = "flux-object-uid"
        with self.assertRaisesRegex(MODULE.ActivationError, "unsuspend CAS failed"):
            MODULE.unsuspend(self.core, runner, "/snapshot", TRACER, record)
        self.assertFalse(live["spec"]["suspend"])
        MODULE.recovery_preflight(self.core, runner, "/snapshot", desired, NONCE, {"flux.kustomization": record})
        MODULE.suspend_if_active(self.core, runner, "/snapshot", TRACER, record)
        self.assertTrue(live["spec"]["suspend"])
        self.assertEqual(runner.mutations, ["patch", "patch"])

    def _module_loader(self, core):
        def loader(path: Path, name: str):
            del name
            if path.name == "tracer_data_plane_policy.py":
                return TRACER
            if path.name == "staging_participant_gateway_policy.py":
                return KUBE_POLICY
            if path.name == "activate-staging-participant-gateway.py":
                return core
            raise AssertionError(path)

        return loader

    def test_committed_activation_receipt_recovery_is_zero_mutation(self) -> None:
        desired = desired_objects()
        records = {label: object_record(label, item, removed=True) for label, item in desired.items()}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt_path = root / "receipt.json"
            journal_path = root / "journal.json"
            reservation = MODULE.reserve_receipt(receipt_path)
            terminal = {
                "schemaVersion": MODULE.RECEIPT_SCHEMA,
                "status": "activated",
                "protectedRevision": REVISION,
                "protectedFileSha256": HASHES,
                "operationNonce": NONCE,
                "createOrder": list(desired),
                "objectRecords": records,
                "secretValuesRead": False,
                "civicAuthorityEffects": False,
            }
            MODULE.commit_reserved_receipt(receipt_path, reservation, terminal)
            private_json(journal_path, activation_journal(reservation, records))
            core = SimpleNamespace(Runner=Mock(side_effect=AssertionError("cluster access forbidden")))
            with (
                patch.object(MODULE, "bind_checkout", return_value=HASHES),
                patch.object(MODULE, "load_module", side_effect=self._module_loader(core)),
                patch.object(TRACER, "verify_render", return_value={}),
            ):
                recovered = MODULE.recover_from_journal(REVISION, "/kube", journal_path, receipt_path)
            self.assertEqual(recovered, terminal)
            core.Runner.assert_not_called()
            self.assertEqual(
                json.loads(journal_path.read_text())["phase"],
                "terminal-receipt-observed-without-cluster-mutation",
            )

    def test_empty_reservation_recovery_deletes_exact_twelve_owned_objects(self) -> None:
        desired = desired_objects()
        records = {label: object_record(label, item) for label, item in desired.items()}
        runner = ObjectRunner()
        for label, item in desired.items():
            observed = defaulted(MODULE.with_nonce(item, NONCE), uid=records[label]["uid"], rv=records[label]["resourceVersion"])
            runner.state[runner.key(observed)] = observed
        snapshot = Snapshot()
        deleted: list[str] = []

        def raw_delete(_snapshot, path, payload, timeout):
            del payload, timeout
            deleted.append(path)
            match = next(item for item in desired.values() if MODULE.resource_path(item) == path)
            runner.state.pop(runner.key(match))

        core = SimpleNamespace(
            POLICY=KUBE_POLICY,
            obj=lambda raw, label: json.loads(raw),
            Runner=lambda: runner,
            snapshot_kubeconfig_v4=lambda kubeconfig, selected: snapshot,
            cluster_binding_v4=lambda selected, snap, descriptor: {"fixture": "cluster"},
            raw_delete=raw_delete,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt_path = root / "receipt.json"
            journal_path = root / "journal.json"
            reservation = MODULE.reserve_receipt(receipt_path)
            private_json(journal_path, activation_journal(reservation, records))
            with (
                patch.object(MODULE, "bind_checkout", return_value=HASHES),
                patch.object(MODULE, "load_module", side_effect=self._module_loader(core)),
                patch.object(MODULE, "SignalGuard", NoSignals),
                patch.object(MODULE.time, "sleep", return_value=None),
                patch.object(TRACER, "verify_render", return_value={}),
            ):
                recovered = MODULE.recover_from_journal(REVISION, "/kube", journal_path, receipt_path)
        self.assertEqual(recovered["status"], "recovered-rolled-back")
        self.assertEqual(recovered["rollbackDeleted"], list(reversed(list(desired))))
        self.assertEqual(len(deleted), 12)
        self.assertFalse(runner.state)
        self.assertTrue(snapshot.closed)

    def test_partial_activation_receipt_blocks_before_cluster_access(self) -> None:
        desired = desired_objects()
        records = {label: object_record(label, item) for label, item in desired.items()}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt_path = root / "receipt.json"
            journal_path = root / "journal.json"
            reservation = MODULE.reserve_receipt(receipt_path)
            with receipt_path.open("wb") as stream:
                stream.write(b'{"schemaVersion":')
                stream.flush()
                os.fsync(stream.fileno())
            private_json(journal_path, activation_journal(reservation, records))
            core = SimpleNamespace(Runner=Mock(side_effect=AssertionError("cluster access forbidden")))
            with (
                patch.object(MODULE, "bind_checkout", return_value=HASHES),
                patch.object(MODULE, "load_module", side_effect=self._module_loader(core)),
                patch.object(TRACER, "verify_render", return_value={}),
                self.assertRaises(json.JSONDecodeError),
            ):
                MODULE.recover_from_journal(REVISION, "/kube", journal_path, receipt_path)
            core.Runner.assert_not_called()

    def test_recovery_preflight_rejects_uid_and_semantic_drift_before_delete(self) -> None:
        item = desired_objects()["application.postgrestNetworkPolicy"]
        record = object_record("application.postgrestNetworkPolicy", item)
        for label, mutate in (
            ("uid", lambda value: value["metadata"].update(uid="foreign-uid")),
            ("semantic", lambda value: value["spec"]["ingress"].append({"from": [{"namespaceSelector": {}}]})),
        ):
            with self.subTest(label=label):
                runner = ObjectRunner()
                observed = defaulted(MODULE.with_nonce(item, NONCE), uid=record["uid"], rv=record["resourceVersion"])
                mutate(observed)
                runner.state[runner.key(observed)] = observed
                with self.assertRaisesRegex(MODULE.ActivationError, "drift"):
                    MODULE.recovery_preflight(
                        self.core,
                        runner,
                        "/snapshot",
                        {"application.postgrestNetworkPolicy": item},
                        NONCE,
                        {"application.postgrestNetworkPolicy": record},
                    )


if __name__ == "__main__":
    unittest.main()
