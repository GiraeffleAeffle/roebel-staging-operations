#!/usr/bin/env python3

from __future__ import annotations

import base64
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


MODULE = load(
    "tracer_secret_materializer_test_subject",
    ROOT / "scripts/materialize-tracer-data-plane-secrets.py",
)
POLICY = load("tracer_secret_policy_fixture", ROOT / "scripts/tracer_data_plane_policy.py")
REVISION = "a" * 40
NONCE = "b" * 64
HASHES = {path: MODULE.sha256_bytes(path.encode()) for path in MODULE.PROTECTED_PATHS}


class Result:
    def __init__(self, code: int = 0, out: str = "", err: str = "") -> None:
        self.code = code
        self.out = out
        self.err = err


class SecretRunner:
    """Value-blind fake for the exact go-template projection used by the runner."""

    def __init__(self) -> None:
        self.state: dict[tuple[str, str], dict] = {}
        self.create_code = 0
        self.create_error = ""
        self.created_nonce: str | None = None
        self.raw_deletes: list[str] = []

    def run(self, command, *, input_text=None, timeout=None):
        del timeout
        if "create" in command:
            manifest = json.loads(input_text)
            metadata = manifest["metadata"]
            nonce = self.created_nonce or metadata["annotations"][MODULE.NONCE_ANNOTATION]
            self.state[(metadata["namespace"], metadata["name"])] = {
                "uid": "01234567-89ab-cdef-0123-456789abcdef",
                "resourceVersion": "17",
                "nonce": nonce,
                "type": manifest["type"],
                "labels": copy.deepcopy(manifest["metadata"]["labels"]),
                "keys": sorted(manifest["data"]),
            }
            return Result(self.create_code, err=self.create_error)
        if "get" in command and "secret" in command:
            namespace = command[command.index("-n") + 1]
            name = command[command.index("secret") + 1]
            observed = self.state.get((namespace, name))
            if observed is None:
                return Result(1, err="Error from server (NotFound): secrets not found")
            lines = [
                observed["uid"],
                observed["resourceVersion"],
                observed["nonce"],
                observed["type"],
                *(observed["labels"].get(key, "") for key in MODULE.SECRET_LABELS),
                *observed["keys"],
            ]
            return Result(out="\n".join(lines) + "\n")
        raise AssertionError(f"unexpected command: {command}")


def secret_record(label: str, nonce: str = NONCE, rv: str = "17") -> dict:
    reference = POLICY.secret_materialization_contract()["secrets"][label]
    return {
        "target": {
            "apiVersion": "v1",
            "kind": "Secret",
            "name": reference["name"],
            "namespace": reference["namespace"],
        },
        "uid": "01234567-89ab-cdef-0123-456789abcdef",
        "resourceVersion": rv,
        "keySet": sorted(reference["keys"]),
        "ownershipNonce": nonce,
        "valuesRead": False,
        "createOutcome": "create-response-and-exact-live-projection",
    }


def private_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)


def recovery_journal(receipt_reservation: dict, records: dict[str, dict]) -> dict:
    contract = POLICY.secret_materialization_contract()
    return {
        "schemaVersion": MODULE.JOURNAL_SCHEMA,
        "status": "in-progress",
        "phase": "fixture",
        "protectedRevision": REVISION,
        "protectedFileSha256": HASHES,
        "operationNonce": NONCE,
        "receiptReservation": receipt_reservation,
        "createOrder": contract["createOrder"],
        "secretRecords": records,
        "rollbackDeleted": [],
        "secretValuesIncluded": False,
        "civicAuthorityEffects": False,
    }


class Snapshot:
    def __init__(self) -> None:
        self.path = Path("/snapshot")
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


class MaterializerTests(unittest.TestCase):
    def test_generated_bundle_has_exact_shared_values_without_receipt_exposure(self) -> None:
        values, window = MODULE.generate_bundle(POLICY, now=1_800_000_000)
        self.assertEqual(values["dataPlane"]["anon-jwt"], values["webFeed"]["supabase-anon-key"])
        self.assertEqual(values["dataPlane"]["anon-jwt"], values["participantPostgrest"]["supabase-anon-key"])
        self.assertEqual(values["dataPlane"]["rpc-secret"], values["participantPostgrest"]["supabase-rpc-secret"])
        self.assertNotEqual(values["dataPlane"]["postgres-password"], values["dataPlane"]["authenticator-password"])
        uri = values["dataPlane"]["postgrest-db-uri"]
        self.assertIn(values["dataPlane"]["authenticator-password"], uri)
        payload = values["dataPlane"]["anon-jwt"].decode().split(".")[1]
        payload += "=" * (-len(payload) % 4)
        self.assertEqual(
            json.loads(base64.urlsafe_b64decode(payload)),
            {"exp": window["exp"], "iat": window["iat"], "role": "anon"},
        )

        records = {label: secret_record(label) for label in POLICY.secret_materialization_contract()["createOrder"]}
        receipt = {
            "schemaVersion": MODULE.RECEIPT_SCHEMA,
            "status": "materialized",
            "protectedRevision": REVISION,
            "protectedFileSha256": HASHES,
            "operationNonce": NONCE,
            "secretRecords": records,
            "anonJwt": {"iat": window["iat"], "exp": window["exp"], "valueIncluded": False},
            "sharedValueBindingsVerified": POLICY.secret_materialization_contract()["sharedValueBindings"],
            "receiptContainsValues": False,
            "civicAuthorityEffects": False,
        }
        serialized = MODULE.canonical(receipt).encode()
        for bundle in values.values():
            for value in bundle.values():
                if len(value) >= 16:
                    self.assertNotIn(value, serialized)

    def test_uncertain_create_accepts_only_exact_same_nonce_projection(self) -> None:
        reference = POLICY.secret_materialization_contract()["secrets"]["webFeed"]
        values = {"supabase-anon-key": b"not-a-real-secret"}
        runner = SecretRunner()
        runner.create_code = 124
        runner.create_error = "request timed out after send"
        record = MODULE.create_secret(None, runner, "/snapshot", "webFeed", reference, values, NONCE)
        self.assertEqual(record["ownershipNonce"], NONCE)
        self.assertEqual(record["createOutcome"], "nonzero-post-send-exact-same-nonce-live-projection")

        for observed_nonce, error in (("c" * 64, "outcome unresolved"),):
            with self.subTest(observed_nonce=observed_nonce):
                foreign = SecretRunner()
                foreign.create_code = 124
                foreign.created_nonce = observed_nonce
                with self.assertRaisesRegex(MODULE.MaterializationError, error):
                    MODULE.create_secret(None, foreign, "/snapshot", "webFeed", reference, values, NONCE)

        conflict = SecretRunner()
        conflict.create_code = 1
        conflict.create_error = "AlreadyExists 409"
        with self.assertRaisesRegex(MODULE.MaterializationError, "adoption forbidden"):
            MODULE.create_secret(None, conflict, "/snapshot", "webFeed", reference, values, NONCE)

    def test_receipt_reservation_is_0600_inode_bound_and_durable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = root / "receipt.json"
            reservation = MODULE.reserve_receipt(receipt)
            info = receipt.stat()
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            self.assertEqual(info.st_size, 0)
            MODULE.commit_reserved_receipt(receipt, reservation, {"status": "committed"})
            self.assertEqual(json.loads(receipt.read_text()), {"status": "committed"})
            with self.assertRaisesRegex(MODULE.MaterializationError, "not empty"):
                MODULE.commit_reserved_receipt(receipt, reservation, {"status": "second"})

            other = root / "other"
            other.write_bytes(b"x")
            alias = root / "alias"
            os.link(other, alias)
            with self.assertRaisesRegex(MODULE.MaterializationError, "must not alias"):
                MODULE.require_distinct_paths(other, alias)

            replacement = root / "replacement"
            replacement_reservation = MODULE.reserve_receipt(replacement)
            foreign = root / "foreign"
            foreign.write_bytes(b"")
            foreign.chmod(0o600)
            replacement.unlink()
            os.replace(foreign, replacement)
            with self.assertRaisesRegex(MODULE.MaterializationError, "inode drift"):
                MODULE.read_reserved_receipt(replacement, replacement_reservation)

    def _module_loader(self, core):
        participant = SimpleNamespace(assert_activation_ready=lambda value: value)

        def loader(path: Path, name: str):
            del name
            if path.name == "tracer_data_plane_policy.py":
                return POLICY
            if path.name == "staging_participant_gateway_policy.py":
                return participant
            if path.name == "activate-staging-participant-gateway.py":
                return core
            raise AssertionError(path)

        return loader

    def test_committed_receipt_recovery_never_contacts_the_cluster(self) -> None:
        contract = POLICY.secret_materialization_contract()
        records = {label: secret_record(label) for label in contract["createOrder"]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt_path = root / "receipt.json"
            journal_path = root / "journal.json"
            reservation = MODULE.reserve_receipt(receipt_path)
            terminal = {
                "schemaVersion": MODULE.RECEIPT_SCHEMA,
                "status": "materialized",
                "protectedRevision": REVISION,
                "protectedFileSha256": HASHES,
                "operationNonce": NONCE,
                "secretRecords": records,
                "receiptContainsValues": False,
                "civicAuthorityEffects": False,
            }
            MODULE.commit_reserved_receipt(receipt_path, reservation, terminal)
            private_json(journal_path, recovery_journal(reservation, records))
            core = SimpleNamespace(Runner=Mock(side_effect=AssertionError("cluster access forbidden")))
            with (
                patch.object(MODULE, "bind_checkout", return_value=HASHES),
                patch.object(MODULE, "load_module", side_effect=self._module_loader(core)),
            ):
                recovered = MODULE.recover_from_journal(REVISION, "/kube", journal_path, receipt_path)
            self.assertEqual(recovered, terminal)
            core.Runner.assert_not_called()
            journal = json.loads(journal_path.read_text())
            self.assertEqual(journal["phase"], "terminal-receipt-observed-without-cluster-mutation")
            self.assertEqual(journal["terminalReceiptSha256"], MODULE.sha256_bytes(receipt_path.read_bytes()))

    def test_empty_reservation_recovery_exactly_deletes_owned_bundle(self) -> None:
        contract = POLICY.secret_materialization_contract()
        records = {label: secret_record(label) for label in contract["createOrder"]}
        runner = SecretRunner()
        for label, reference in contract["secrets"].items():
            record = records[label]
            runner.state[(reference["namespace"], reference["name"])] = {
                "uid": record["uid"],
                "resourceVersion": record["resourceVersion"],
                "nonce": record["ownershipNonce"],
                "type": "Opaque",
                "labels": copy.deepcopy(MODULE.SECRET_LABELS),
                "keys": record["keySet"],
            }
        snapshot = Snapshot()

        def raw_delete(_snapshot, path, payload, timeout):
            del payload, timeout
            parts = path.split("/")
            runner.raw_deletes.append(path)
            runner.state.pop((parts[4], parts[6]))

        core = SimpleNamespace(
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
            private_json(journal_path, recovery_journal(reservation, records))
            with (
                patch.object(MODULE, "bind_checkout", return_value=HASHES),
                patch.object(MODULE, "load_module", side_effect=self._module_loader(core)),
                patch.object(MODULE, "SignalGuard", NoSignals),
            ):
                recovered = MODULE.recover_from_journal(REVISION, "/kube", journal_path, receipt_path)
        self.assertEqual(recovered["status"], "recovered-rolled-back")
        self.assertEqual(recovered["rollbackDeleted"], list(reversed(contract["createOrder"])))
        self.assertEqual(len(runner.raw_deletes), 3)
        self.assertFalse(runner.state)
        self.assertTrue(snapshot.closed)

    def test_partial_receipt_and_recovery_drift_block_before_delete(self) -> None:
        contract = POLICY.secret_materialization_contract()
        base_records = {label: secret_record(label) for label in contract["createOrder"]}

        cases = {
            "revision": ("journal", lambda journal, records, runner: journal.update(protectedRevision="f" * 40)),
            "uid": ("live", lambda journal, records, runner: runner.state[next(iter(runner.state))].update(uid="fedcba98-7654-3210-fedc-ba9876543210")),
            "resourceVersion": ("live", lambda journal, records, runner: runner.state[next(iter(runner.state))].update(resourceVersion="99")),
            "keyset": ("live", lambda journal, records, runner: runner.state[next(iter(runner.state))].update(keys=["wrong-key"])),
            "semantic-label": ("live", lambda journal, records, runner: runner.state[next(iter(runner.state))]["labels"].update({"stadtstack.io/authority": "municipal"})),
        }
        for label, (_location, mutate) in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                records = copy.deepcopy(base_records)
                runner = SecretRunner()
                for item, reference in contract["secrets"].items():
                    record = records[item]
                    runner.state[(reference["namespace"], reference["name"])] = {
                        "uid": record["uid"], "resourceVersion": record["resourceVersion"],
                        "nonce": record["ownershipNonce"], "type": "Opaque",
                        "labels": copy.deepcopy(MODULE.SECRET_LABELS), "keys": record["keySet"],
                    }
                deleted = Mock()
                core = SimpleNamespace(
                    Runner=lambda: runner,
                    snapshot_kubeconfig_v4=lambda kubeconfig, selected: Snapshot(),
                    cluster_binding_v4=lambda selected, snap, descriptor: {},
                    raw_delete=deleted,
                )
                root = Path(directory)
                receipt_path = root / "receipt.json"
                journal_path = root / "journal.json"
                reservation = MODULE.reserve_receipt(receipt_path)
                journal = recovery_journal(reservation, records)
                mutate(journal, records, runner)
                private_json(journal_path, journal)
                with (
                    patch.object(MODULE, "bind_checkout", return_value=HASHES),
                    patch.object(MODULE, "load_module", side_effect=self._module_loader(core)),
                    patch.object(MODULE, "SignalGuard", NoSignals),
                    self.assertRaises((MODULE.MaterializationError, KeyError)),
                ):
                    MODULE.recover_from_journal(REVISION, "/kube", journal_path, receipt_path)
                deleted.assert_not_called()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt_path = root / "receipt.json"
            journal_path = root / "journal.json"
            reservation = MODULE.reserve_receipt(receipt_path)
            with receipt_path.open("wb") as stream:
                stream.write(b'{"schemaVersion":')
                stream.flush()
                os.fsync(stream.fileno())
            private_json(journal_path, recovery_journal(reservation, base_records))
            core = SimpleNamespace(Runner=Mock(side_effect=AssertionError("cluster access forbidden")))
            with (
                patch.object(MODULE, "bind_checkout", return_value=HASHES),
                patch.object(MODULE, "load_module", side_effect=self._module_loader(core)),
                self.assertRaises(json.JSONDecodeError),
            ):
                MODULE.recover_from_journal(REVISION, "/kube", journal_path, receipt_path)
            core.Runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
