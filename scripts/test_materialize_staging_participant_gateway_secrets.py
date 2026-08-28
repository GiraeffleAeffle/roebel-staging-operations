from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "participant_secret_materializer_under_test",
    ROOT / "scripts/materialize-staging-participant-gateway-secrets.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

REV = "a" * 40
HASHES = {path: "sha256:" + "b" * 64 for path in MODULE.PROTECTED_PATHS}


class DummyPolicy:
    @staticmethod
    def activation_policy_sha256(_policy):
        return "sha256:" + "c" * 64


class Snapshot:
    path = Path("/private/synthetic-kubeconfig")

    def close(self):
        pass


class DummyCore:
    class Result:
        def __init__(self, code=0, out="", err=""):
            self.code, self.out, self.err = code, out, err

    @staticmethod
    def snapshot_kubeconfig_v4(_kubeconfig, _runner):
        return Snapshot()

    @staticmethod
    def install_transaction_signal_handlers_v4():
        return {}

    @staticmethod
    def defer_transaction_signals_v4():
        pass

    @staticmethod
    def restore_transaction_signal_handlers_v4(_handlers):
        pass


def policy_fixture():
    required_absent = [
        MODULE._target("NetworkPolicy", "roebel-staging-participant-gateway", MODULE.NAMESPACE),
        MODULE._target("ServiceAccount", "roebel-staging-participant-gateway", MODULE.NAMESPACE),
        MODULE._target("Service", "roebel-staging-participant-gateway", MODULE.NAMESPACE),
        MODULE._target("Deployment", "roebel-staging-participant-gateway", MODULE.NAMESPACE),
        MODULE._target("Ingress", "roebel-staging-participant-gateway", MODULE.NAMESPACE),
        MODULE._target("NetworkPolicy", "roebel-staging-participant-workbench-ingress", "stadtstack-roebel-staging-lab"),
        MODULE._target("Kustomization", "roebel-staging-participant-gateway", "flux-roebel-staging"),
        MODULE._target("Kustomization", "roebel-staging-participant-workbench-ingress", "flux-roebel-staging"),
    ]
    return {
        "runtime": {
            "secretReferences": MODULE.expected_secret_references(),
            "secretMaterializer": {
                "runner": MODULE.SELF_PATH,
                "receiptSchemaVersion": MODULE.MATERIALIZATION_RECEIPT_SCHEMA,
                "teardownReceiptSchemaVersion": MODULE.TEARDOWN_RECEIPT_SCHEMA,
                "inputTransport": "owned-private-inherited-descriptors-only",
                "createOrder": list(MODULE.CREATE_ORDER),
                "initialState": "both-exact-secret-names-absent",
                "adoption": "forbidden",
                "receiptContainsValues": False,
                "teardown": {
                    "sourceReceiptRequired": True,
                    "deleteOrder": list(MODULE.DELETE_ORDER),
                    "uidResourceVersionPreconditions": True,
                    "requiredAbsentTargets": required_absent,
                },
            },
        },
    }


def values_fixture():
    return {
        "config": {key: f"private-config-{index}".encode() for index, key in enumerate(MODULE.CONFIG_KEYS)},
        "runtime": {key: f"private-runtime-{index}".encode() for index, key in enumerate(MODULE.RUNTIME_KEYS)},
    }


def signed_materialization(created):
    unsigned = MODULE._materialization_unsigned(REV, policy_fixture(), HASHES, created)
    return unsigned | {"canonicalSha256": MODULE.digest(unsigned)}


class Sink:
    def __init__(self):
        self.values = []

    def commit(self, value):
        self.values.append(json.loads(json.dumps(value)))


class FakeRunner:
    def __init__(self, *, fail_runtime=False, present_deactivation_target=False):
        self.fail_runtime = fail_runtime
        self.present_deactivation_target = present_deactivation_target
        self.objects = {}
        self.create_order = []
        self.calls = []

    def run(self, args, *, input_text=None, timeout=10):
        self.calls.append((list(args), input_text, timeout))
        if "create" in args and input_text is not None:
            manifest = json.loads(input_text)
            label = "config" if manifest["metadata"]["name"] == MODULE.CONFIG_NAME else "runtime"
            self.create_order.append(label)
            if label == "runtime" and self.fail_runtime:
                return DummyCore.Result(1, "", "synthetic transport failure")
            record = {
                "uid": "00000000-0000-4000-8000-000000000001" if label == "config" else "00000000-0000-4000-8000-000000000002",
                "resourceVersion": "101" if label == "config" else "102",
                "nonce": manifest["metadata"]["annotations"][MODULE.NONCE_ANNOTATION],
                "keys": sorted(manifest["data"]),
            }
            self.objects[label] = record
            return DummyCore.Result(0, self._projection(record), "")
        if "secret" in args and "get" in args:
            name = args[args.index("secret") + 1]
            label = "config" if name == MODULE.CONFIG_NAME else "runtime"
            record = self.objects.get(label)
            if record is None:
                return DummyCore.Result(1, "", "Error from server (NotFound): secrets not found")
            return DummyCore.Result(0, self._projection(record), "")
        if "get" in args:
            if self.present_deactivation_target:
                return DummyCore.Result(0, "deployment.apps/roebel-staging-participant-gateway\n", "")
            return DummyCore.Result(1, "", "Error from server (NotFound): object not found")
        raise AssertionError(args)

    @staticmethod
    def _projection(record):
        return "\n".join([
            record["uid"],
            record["resourceVersion"],
            record["nonce"],
            "Opaque",
            *record["keys"],
            "",
        ])


class MaterializerTests(unittest.TestCase):
    def setUp(self):
        MODULE.CORE = DummyCore
        MODULE.POLICY = DummyPolicy

    def test_policy_identity_is_closed_to_exact_names_keys_and_deactivation_targets(self):
        value = policy_fixture()
        MODULE.bind_policy_identity(value)
        value["runtime"]["secretReferences"]["config"]["name"] = "other"
        with self.assertRaisesRegex(MODULE.MaterializationError, "identity/keyset"):
            MODULE.bind_policy_identity(value)

    def test_private_env_inputs_are_descriptor_only_exact_and_never_returned_as_text(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.env"
            path.write_text("# private\n" + "\n".join(f"{key}=never-print-{index}" for index, key in enumerate(MODULE.CONFIG_KEYS)) + "\n")
            path.chmod(0o600)
            fd = os.open(path, os.O_RDONLY)
            try:
                values = MODULE.parse_private_env_descriptor(fd, "config", MODULE.CONFIG_KEYS)
            finally:
                os.close(fd)
            self.assertEqual(set(values), set(MODULE.CONFIG_KEYS))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertNotIn("never-print", repr(values.keys()))

    def test_private_env_input_rejects_missing_duplicate_and_non_private_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = [
                "allowed-wallets=x\ninvite-sha256=y\n",
                "allowed-wallets=x\nallowed-wallets=y\ninvite-sha256=z\nmecky-pubkey=q\n",
            ]
            for index, raw in enumerate(cases):
                path = root / f"bad-{index}.env"; path.write_text(raw); path.chmod(0o600)
                fd = os.open(path, os.O_RDONLY)
                try:
                    with self.assertRaises(MODULE.MaterializationError):
                        MODULE.parse_private_env_descriptor(fd, "config", MODULE.CONFIG_KEYS)
                finally:
                    os.close(fd)
            shared = root / "shared.env"; shared.write_text("x=y\n"); shared.chmod(0o644)
            fd = os.open(shared, os.O_RDONLY)
            try:
                with self.assertRaisesRegex(MODULE.MaterializationError, "0600"):
                    MODULE.parse_private_env_descriptor(fd, "config", MODULE.CONFIG_KEYS)
            finally:
                os.close(fd)

    def test_network_lookup_failure_is_never_treated_as_object_absence(self):
        result = DummyCore.Result(1, "", "dial tcp: host not found")
        self.assertFalse(MODULE._not_found(result))

    def test_materialize_requires_both_absent_and_creates_config_then_runtime(self):
        values = values_fixture(); runner = FakeRunner(); sink = Sink()
        result = MODULE.materialize(
            policy_fixture(), REV, "/private/kubeconfig", values["config"], values["runtime"], sink, HASHES, runner,
        )
        self.assertEqual(runner.create_order, ["config", "runtime"])
        self.assertEqual(result["status"], "materialized")
        self.assertFalse(result["valuesInReceipt"])
        encoded = MODULE.canonical(result)
        for private in (*values["config"].values(), *values["runtime"].values()):
            self.assertNotIn(private.decode(), encoded)
        self.assertEqual(len(sink.values), 1)

    def test_uncertain_runtime_create_rolls_back_config_and_records_incomplete_outcome(self):
        values = values_fixture(); runner = FakeRunner(fail_runtime=True); sink = Sink(); deletes = []

        def delete(_snapshot, reference, uid, resource_version, timeout=15):
            deletes.append((reference["name"], uid, resource_version))
            runner.objects.pop("config", None)

        with patch.object(MODULE, "_raw_delete_secret", side_effect=delete):
            with self.assertRaisesRegex(MODULE.MaterializationError, "rollback-incomplete"):
                MODULE.materialize(
                    policy_fixture(), REV, "/private/kubeconfig", values["config"], values["runtime"], sink, HASHES, runner,
                )
        self.assertEqual(deletes, [(MODULE.CONFIG_NAME, "00000000-0000-4000-8000-000000000001", "101")])
        self.assertEqual(sink.values[-1]["status"], "rollback-incomplete")
        self.assertEqual(sink.values[-1]["unresolvedCreateOutcomes"], ["runtime"])
        self.assertFalse(sink.values[-1]["valuesInReceipt"])

    def test_unexpected_failure_text_cannot_enter_receipt_or_raised_error(self):
        values = values_fixture(); runner = FakeRunner(); sink = Sink()
        private_marker = "never-emit-this-private-value"
        with patch.object(MODULE, "secret_projection", side_effect=RuntimeError(private_marker)):
            with self.assertRaises(MODULE.MaterializationError) as caught:
                MODULE.materialize(
                    policy_fixture(), REV, "/private/kubeconfig", values["config"], values["runtime"], sink, HASHES, runner,
                )
        self.assertNotIn(private_marker, str(caught.exception))
        self.assertNotIn(private_marker, MODULE.canonical(sink.values[-1]))
        self.assertEqual(sink.values[-1]["failureType"], "RuntimeError")

    def test_teardown_refuses_while_any_participant_target_exists(self):
        values = values_fixture(); runner = FakeRunner(); create_sink = Sink()
        MODULE.materialize(policy_fixture(), REV, "/private/kubeconfig", values["config"], values["runtime"], create_sink, HASHES, runner)
        receipt = signed_materialization(create_sink.values[-1]["secrets"])
        runner.present_deactivation_target = True
        teardown_sink = Sink()
        with self.assertRaisesRegex(MODULE.MaterializationError, "teardown incomplete"):
            MODULE.teardown(policy_fixture(), REV, "/private/kubeconfig", receipt, teardown_sink, HASHES, runner)
        self.assertEqual(teardown_sink.values[-1]["status"], "teardown-incomplete")
        self.assertEqual(teardown_sink.values[-1]["failureType"], "MaterializationError")

    def test_teardown_deletes_runtime_then_config_at_exact_receipt_uid_rv(self):
        values = values_fixture(); runner = FakeRunner(); create_sink = Sink()
        MODULE.materialize(policy_fixture(), REV, "/private/kubeconfig", values["config"], values["runtime"], create_sink, HASHES, runner)
        receipt = signed_materialization(create_sink.values[-1]["secrets"])
        teardown_sink = Sink(); deletes = []

        def delete(_snapshot, reference, uid, resource_version, timeout=15):
            label = "config" if reference["name"] == MODULE.CONFIG_NAME else "runtime"
            deletes.append((label, uid, resource_version))
            runner.objects.pop(label, None)

        with patch.object(MODULE, "_raw_delete_secret", side_effect=delete):
            result = MODULE.teardown(policy_fixture(), REV, "/private/kubeconfig", receipt, teardown_sink, HASHES, runner)
        self.assertEqual([item[0] for item in deletes], ["runtime", "config"])
        self.assertEqual(result["status"], "torn-down")
        unsigned = teardown_sink.values[-1]
        signed = unsigned | {"canonicalSha256": MODULE.digest(unsigned)}
        projection = MODULE.bind_teardown_receipt(signed, policy_fixture(), REV, HASHES)
        self.assertEqual(projection["teardownOfReceiptSha256"], receipt["canonicalSha256"])

        tampered = json.loads(json.dumps(signed))
        tampered["deleted"][0]["uid"] = "not-a-kubernetes-uid"
        tampered["canonicalSha256"] = MODULE.digest({key: value for key, value in tampered.items() if key != "canonicalSha256"})
        with self.assertRaisesRegex(MODULE.MaterializationError, "identity drift"):
            MODULE.bind_teardown_receipt(tampered, policy_fixture(), REV, HASHES)

    def test_receipt_verifier_rejects_changed_resource_version(self):
        values = values_fixture(); runner = FakeRunner(); sink = Sink()
        MODULE.materialize(policy_fixture(), REV, "/private/kubeconfig", values["config"], values["runtime"], sink, HASHES, runner)
        receipt = signed_materialization(sink.values[-1]["secrets"])
        MODULE.bind_materialization_receipt(receipt, policy_fixture(), REV, HASHES)
        receipt["secrets"]["config"]["resourceVersion"] = "999"
        receipt["canonicalSha256"] = MODULE.digest({key: value for key, value in receipt.items() if key != "canonicalSha256"})
        # A syntactically valid but altered identity still cannot authorize a
        # live Secret whose original resourceVersion differs; the delete path
        # compares it to a fresh value before any mutation.
        with self.assertRaisesRegex(MODULE.MaterializationError, "resourceVersion drift"):
            with patch.object(MODULE, "secret_projection", return_value=sink.values[-1]["secrets"]["config"]):
                MODULE.delete_owned_secret(FakeRunner(), "/kube", Snapshot(), "config", policy_fixture()["runtime"]["secretReferences"]["config"], receipt["secrets"]["config"])


if __name__ == "__main__":
    unittest.main()
