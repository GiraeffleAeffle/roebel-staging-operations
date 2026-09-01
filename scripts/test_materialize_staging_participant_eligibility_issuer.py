from __future__ import annotations

import base64
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "eligibility_issuer_materializer_under_test",
    ROOT / "scripts/materialize-staging-participant-eligibility-issuer.py",
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

REVISION = "a" * 40
NONCE = "b" * 64
UID = "01234567-89ab-cdef-0123-456789abcdef"
RESOURCE_VERSION = "71"
HASHES = {
    path: MODULE.sha256(path.encode("ascii")) for path in MODULE.PROTECTED_PATHS
}
CLUSTER = {
    "apiOrigin": "https://10.255.240.11:6443",
    "caCertificateSha256": "sha256:42fd39869882e3c25a1f37c090542d215ceb0f60a7d68f5603fb9a0583afee28",
    "apiServerSpkiSha256": "sha256:1507430795ee7c9cbeea9133dd3b1a809a500de5bcc4dd8e400163ac9471186a",
    "kubeSystemNamespaceUid": "7bc769bc-e860-4d54-a0d5-d426f3a52420",
    "kubeSystemNamespaceResourceVersion": "9",
    "credentialsIncluded": False,
    "kubeconfigPathIncluded": False,
}


class Result:
    def __init__(self, code=0, out="", err=""):
        self.code, self.out, self.err = code, out, err


def projection(
    *,
    nonce: str = NONCE,
    public_key: str = MODULE.EXPECTED_PUBLIC_KEY,
    live: bool,
) -> str:
    annotations = MODULE.exact_secret_annotations(public_key, nonce)
    return "\n".join(
        [
            UID if live else "",
            RESOURCE_VERSION if live else "",
            MODULE.NAMESPACE,
            MODULE.SECRET_NAME,
            *(MODULE.SECRET_LABELS[key] for key in sorted(MODULE.SECRET_LABELS)),
            *sorted(MODULE.SECRET_LABELS),
            *(annotations[key] for key in sorted(annotations)),
            *sorted(annotations),
        ]
    ) + "\n"


def partial_metadata(
    *,
    nonce: str = NONCE,
    public_key: str = MODULE.EXPECTED_PUBLIC_KEY,
) -> dict:
    return {
        "apiVersion": "meta.k8s.io/v1",
        "kind": "PartialObjectMetadata",
        "metadata": {
            "name": MODULE.SECRET_NAME,
            "namespace": MODULE.NAMESPACE,
            "uid": UID,
            "resourceVersion": RESOURCE_VERSION,
            "labels": dict(MODULE.SECRET_LABELS),
            "annotations": MODULE.exact_secret_annotations(public_key, nonce),
            "creationTimestamp": "2026-09-01T00:00:00Z",
        },
    }


def secret_record(
    *,
    outcome: str = "create-response-and-exact-live-projection",
    nonce: str = NONCE,
) -> dict:
    return {
        "target": {
            "apiVersion": "v1",
            "kind": "Secret",
            "namespace": MODULE.NAMESPACE,
            "name": MODULE.SECRET_NAME,
        },
        "uid": UID,
        "resourceVersion": RESOURCE_VERSION,
        "operationNonce": nonce,
        "type": "Opaque",
        "immutable": True,
        "keySet": [MODULE.SECRET_KEY],
        "labels": dict(MODULE.SECRET_LABELS),
        "annotations": MODULE.exact_secret_annotations(
            MODULE.EXPECTED_PUBLIC_KEY, nonce
        ),
        "valuesRead": False,
        "createOutcome": outcome,
    }


class CreateRunner:
    def __init__(
        self,
        *,
        create_code: int = 0,
        dry_run_existing: bool = False,
        live_nonce: str = NONCE,
        diagnostic: str = "",
        journal_path: Path | None = None,
    ) -> None:
        self.create_code = create_code
        self.dry_run_existing = dry_run_existing
        self.live_nonce = live_nonce
        self.diagnostic = diagnostic
        self.journal_path = journal_path
        self.calls: list[tuple[list[str], str | None, int]] = []
        self.created = False
        self.public_key = MODULE.EXPECTED_PUBLIC_KEY
        self.operation_nonce = NONCE

    def run(self, command, *, input_text=None, timeout=10):
        self.calls.append((list(command), input_text, timeout))
        if "get" in command:
            raise AssertionError("Secret GET must use PartialObjectMetadata HTTP")
        manifest = json.loads(input_text)
        assert manifest["metadata"]["namespace"] == MODULE.NAMESPACE
        assert manifest["metadata"]["name"] == MODULE.SECRET_NAME
        assert set(manifest["data"]) == {MODULE.SECRET_KEY}
        assert base64.b64decode(manifest["data"][MODULE.SECRET_KEY]) == b"11" * 32
        self.public_key = manifest["metadata"]["annotations"][
            MODULE.PUBLIC_KEY_ANNOTATION
        ]
        self.operation_nonce = manifest["metadata"]["annotations"][
            MODULE.NONCE_ANNOTATION
        ]
        if "--dry-run=server" in command:
            if self.dry_run_existing:
                return Result(1, err="Error from server (AlreadyExists): 409")
            return Result(
                out=projection(
                    nonce=self.operation_nonce,
                    public_key=self.public_key,
                    live=False,
                )
            )
        if self.journal_path is not None:
            assert self.journal_path.exists()
            assert self.journal_path.stat().st_size > 0
            persisted_journal = json.loads(self.journal_path.read_bytes())
            assert persisted_journal["phase"] == "create-attempting"
        self.created = True
        if self.create_code:
            return Result(self.create_code, err=self.diagnostic)
        return Result(
            out=projection(
                nonce=self.operation_nonce,
                public_key=self.public_key,
                live=True,
            )
        )

    def live_partial_metadata(self) -> dict | None:
        if not self.created:
            return None
        return partial_metadata(
            nonce=self.live_nonce,
            public_key=self.public_key,
        )

    def live_metadata_record(self, public_key: str, nonce: str) -> dict | None:
        document = self.live_partial_metadata()
        if document is None:
            return None
        return MODULE._parse_partial_object_metadata(document, public_key, nonce)


class Snapshot:
    path = Path("/private/kubeconfig-snapshot")

    def close(self):
        pass


class RecoveryCore:
    def __init__(self, runner):
        self._runner = runner

    def Runner(self):
        return self._runner

    @staticmethod
    def snapshot_kubeconfig_v4(_kubeconfig, _runner):
        return Snapshot()

    @staticmethod
    def cluster_binding_v4(_runner, _snapshot, _policy):
        return dict(CLUSTER)

    @staticmethod
    def install_transaction_signal_handlers_v4():
        return {}

    @staticmethod
    def defer_transaction_signals_v4():
        pass

    @staticmethod
    def restore_transaction_signal_handlers_v4(_handlers):
        pass


class EligibilityIssuerMaterializerTests(unittest.TestCase):
    def policy(self):
        return MODULE.load_policy((ROOT / MODULE.POLICY_PATH).read_bytes())

    def test_ed25519_public_key_derivation_matches_rfc8032(self) -> None:
        seed = bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        )
        self.assertEqual(
            MODULE.ed25519_public_key(seed).hex(),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        )

    def test_private_key_fd_is_exact_owned_lowercase_hex_without_newline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            good = root / "good"
            good.write_bytes(b"11" * 32)
            good.chmod(0o600)
            source_fd = os.open(good, os.O_RDONLY)
            fd = 200
            os.dup2(source_fd, fd, inheritable=True)
            os.close(source_fd)
            self.assertTrue(os.get_inheritable(fd))
            self.assertEqual(
                MODULE.read_private_key_fd(fd), bytes.fromhex("11" * 32)
            )
            with self.assertRaises(OSError):
                os.fstat(fd)
            child = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "import os,sys; "
                        f"sys.exit(1 if os.path.exists('/dev/fd/{fd}') else 0)"
                    ),
                ],
                close_fds=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            self.assertEqual(child.returncode, 0)
            for name, raw, mode in (
                ("newline", b"11" * 32 + b"\n", 0o600),
                ("uppercase", b"AA" * 32, 0o600),
                ("shared", b"11" * 32, 0o640),
            ):
                path = root / name
                path.write_bytes(raw)
                path.chmod(mode)
                fd = os.open(path, os.O_RDONLY)
                with self.assertRaises(MODULE.MaterializationError):
                    MODULE.read_private_key_fd(fd)
                with self.assertRaises(OSError):
                    os.fstat(fd)

    def test_policy_closes_identity_cluster_journal_recovery_and_receipt(self) -> None:
        policy = self.policy()
        self.assertEqual(policy["schemaVersion"], MODULE.POLICY_SCHEMA)
        self.assertEqual(
            policy["keyId"], "roebel-staging-citizen-eligibility-2026-09"
        )
        self.assertEqual(
            policy["publicKey"]["expected"], MODULE.EXPECTED_PUBLIC_KEY
        )
        self.assertEqual(
            policy["input"]["sha256Commitment"],
            MODULE.EXPECTED_PRIVATE_KEY_COMMITMENT,
        )
        self.assertEqual(
            policy["clusterIdentity"],
            {key: CLUSTER[key] for key in MODULE.CLUSTER_IDENTITY_KEYS},
        )
        journal = policy["materialization"]["durableJournal"]
        self.assertEqual(journal["schemaVersion"], MODULE.JOURNAL_SCHEMA)
        self.assertEqual(journal["reservation"], "durable-before-create")
        self.assertFalse(journal["genericAdoption"])
        self.assertEqual(
            policy["materialization"]["metadataOnlyRead"],
            {
                "representation": "PartialObjectMetadata",
                "accept": MODULE.PARTIAL_OBJECT_METADATA_ACCEPT,
                "apiPath": MODULE.SECRET_API_PATH,
            },
        )
        commitments = policy["materialization"]["metadataCommitments"]
        self.assertEqual(
            commitments["contentContractAnnotation"],
            MODULE.CONTENT_CONTRACT_ANNOTATION,
        )
        self.assertEqual(commitments["keySetAnnotation"], MODULE.KEYSET_ANNOTATION)
        self.assertEqual(commitments["keySet"], [MODULE.SECRET_KEY])
        expected_contract = {
            "target": policy["target"],
            "privateKeyCommitmentSha256": policy["input"]["sha256Commitment"],
            "keyId": policy["keyId"],
            "publicKey": policy["publicKey"]["expected"],
        }
        self.assertEqual(
            MODULE.content_contract_commitment(),
            MODULE.sha256(MODULE.canonical(expected_contract).encode("ascii")),
        )
        self.assertEqual(
            MODULE.keyset_commitment(),
            MODULE.sha256(
                MODULE.canonical(commitments["keySet"]).encode("ascii")
            ),
        )
        self.assertEqual(
            policy["receipt"]["schemaVersion"], MODULE.RECEIPT_SCHEMA
        )
        self.assertEqual(
            set(policy["receipt"]["requiredFields"]),
            {
                "schemaVersion",
                "status",
                "protectedRevision",
                "protectedFileSha256",
                "policy",
                "clusterBinding",
                "target",
                "uid",
                "resourceVersion",
                "operationNonce",
                "keyId",
                "publicKey",
                "privateKeyCommitmentSha256",
                "keySet",
                "labels",
                "annotations",
                "createOutcome",
                "valuesRead",
                "receiptContainsValues",
                "authority",
            },
        )

    def test_commitment_and_secret_value_are_over_canonical_ascii_hex(self) -> None:
        seed = bytes.fromhex("11" * 32)
        self.assertEqual(MODULE.canonical_private_key_hex(seed), b"11" * 32)
        self.assertEqual(
            MODULE.private_key_commitment(seed), MODULE.sha256(b"11" * 32)
        )
        self.assertNotEqual(MODULE.private_key_commitment(seed), MODULE.sha256(seed))
        manifest = MODULE._manifest(
            seed, MODULE.ed25519_public_key(seed).hex(), NONCE
        )
        self.assertEqual(
            base64.b64decode(manifest["data"][MODULE.SECRET_KEY]), b"11" * 32
        )

    def test_server_dry_run_then_create_and_exact_live_projection(self) -> None:
        seed = bytes.fromhex("11" * 32)
        public_key = MODULE.ed25519_public_key(seed).hex()
        runner = CreateRunner()
        core = RecoveryCore(runner)
        snapshot = Snapshot()
        MODULE.server_dry_run(seed, public_key, NONCE, runner, str(Snapshot.path))
        with patch.object(
            MODULE,
            "partial_object_metadata_get",
            side_effect=lambda *_args: runner.live_metadata_record(
                _args[-2], _args[-1]
            ),
        ):
            record = MODULE.create_and_observe(
                seed,
                public_key,
                NONCE,
                runner,
                str(Snapshot.path),
                core,
                snapshot,
                self.policy(),
            )
        self.assertEqual(record["uid"], UID)
        self.assertEqual(record["resourceVersion"], RESOURCE_VERSION)
        self.assertFalse(record["valuesRead"])
        self.assertEqual(len(runner.calls), 2)
        self.assertIn("--dry-run=server", runner.calls[0][0])
        self.assertNotIn("--dry-run=server", runner.calls[1][0])
        for command, _, _ in runner.calls:
            self.assertEqual(command[4], MODULE.NAMESPACE)
            self.assertNotIn("delete", command)
            self.assertNotIn("patch", command)
            self.assertNotIn("apply", command)
        with self.assertRaisesRegex(
            MODULE.MaterializationError, "exact target projection mismatch"
        ):
            MODULE._parse_projection(
                projection(live=True) + "unexpected-metadata-key\n",
                MODULE.EXPECTED_PUBLIC_KEY,
                NONCE,
                "live Secret",
                require_identity=True,
            )

    def test_live_read_uses_exact_partial_object_metadata_http_only(self) -> None:
        policy = self.policy()
        sent: list[bytes] = []

        class Transport:
            def sendall(self, value):
                sent.append(value)

            def close(self):
                pass

        class Context:
            def wrap_socket(self, raw, *, server_hostname):
                self.raw = raw
                self.server_hostname = server_hostname
                return raw

        class Response:
            status = 200

            def begin(self):
                pass

            def getheader(self, name, default=None):
                headers = {
                    "Content-Type": "application/json",
                    "Content-Length": str(len(self.body)),
                }
                return headers.get(name, default)

            def read(self, _limit):
                return self.body

            def __init__(self, body):
                self.body = body

        transport = Transport()
        context = Context()
        snapshot = SimpleNamespace(
            ca_pem=b"test-ca",
            client_certificate_path=None,
            client_key_path=None,
            tls_server_name="10.255.240.11",
            hostname="10.255.240.11",
            port=6443,
            bearer_token="test-token",
        )
        core = SimpleNamespace(
            _api_tcp_transport_v4=lambda selected, timeout: transport
        )
        response = Response(
            MODULE.canonical(partial_metadata()).encode("ascii")
        )
        with (
            patch.object(
                MODULE.ssl, "create_default_context", return_value=context
            ),
            patch.object(MODULE.http.client, "HTTPResponse", return_value=response),
        ):
            record = MODULE.partial_object_metadata_get(
                core, snapshot, policy, MODULE.EXPECTED_PUBLIC_KEY, NONCE
            )
        self.assertEqual(record["uid"], UID)
        self.assertFalse(record["valuesRead"])
        request = sent[0].decode("ascii")
        self.assertIn(f"GET {MODULE.SECRET_API_PATH} HTTP/1.1\r\n", request)
        self.assertIn(
            f"Accept: {MODULE.PARTIAL_OBJECT_METADATA_ACCEPT}\r\n", request
        )
        self.assertNotIn("kubectl", request)
        self.assertTrue(request.endswith("\r\n\r\n"))
        self.assertNotIn(MODULE.SECRET_KEY, request)
        self.assertNotIn("application/vnd.kubernetes", request.lower())
        self.assertNotIn(".data", MODULE._projection_template())

        full_secret = partial_metadata()
        full_secret["data"] = {MODULE.SECRET_KEY: "forbidden-value"}
        bad_response = Response(MODULE.canonical(full_secret).encode("ascii"))
        with (
            patch.object(
                MODULE.ssl, "create_default_context", return_value=Context()
            ),
            patch.object(
                MODULE.http.client,
                "HTTPResponse",
                return_value=bad_response,
            ),
        ):
            with self.assertRaisesRegex(
                MODULE.MaterializationError,
                "PartialObjectMetadata projection mismatch",
            ):
                MODULE.partial_object_metadata_get(
                    core, snapshot, policy, MODULE.EXPECTED_PUBLIC_KEY, NONCE
                )

    def test_existing_object_is_rejected_before_any_journal_adoption(self) -> None:
        seed = bytes.fromhex("11" * 32)
        public_key = MODULE.ed25519_public_key(seed).hex()
        runner = CreateRunner(dry_run_existing=True)
        with self.assertRaisesRegex(
            MODULE.MaterializationError, "adoption and recreation forbidden"
        ):
            MODULE.server_dry_run(
                seed, public_key, NONCE, runner, str(Snapshot.path)
            )
        self.assertEqual(len(runner.calls), 1)

    def test_post_send_uncertain_accepts_only_same_nonce_live_projection(self) -> None:
        seed = bytes.fromhex("11" * 32)
        public_key = MODULE.ed25519_public_key(seed).hex()
        secret_hex = seed.hex()
        runner = CreateRunner(
            create_code=124,
            diagnostic=f"synthetic diagnostic {secret_hex}",
        )
        with patch.object(
            MODULE,
            "partial_object_metadata_get",
            side_effect=lambda *_args: runner.live_metadata_record(
                _args[-2], _args[-1]
            ),
        ):
            record = MODULE.create_and_observe(
                seed,
                public_key,
                NONCE,
                runner,
                str(Snapshot.path),
                RecoveryCore(runner),
                Snapshot(),
                self.policy(),
            )
        self.assertEqual(
            record["createOutcome"],
            "nonzero-post-send-exact-same-journal-nonce-live-projection",
        )
        self.assertNotIn(secret_hex, MODULE.canonical(record))

        foreign = CreateRunner(create_code=124, live_nonce="c" * 64)
        with self.assertRaisesRegex(MODULE.MaterializationError, "projection mismatch"):
            with patch.object(
                MODULE,
                "partial_object_metadata_get",
                side_effect=lambda *_args: foreign.live_metadata_record(
                    _args[-2], _args[-1]
                ),
            ):
                MODULE.create_and_observe(
                    seed,
                    public_key,
                    NONCE,
                    foreign,
                    str(Snapshot.path),
                    RecoveryCore(foreign),
                    Snapshot(),
                    self.policy(),
                )

    def test_explicit_create_conflict_never_enters_recovery_or_adoption(self) -> None:
        seed = bytes.fromhex("11" * 32)
        public_key = MODULE.ed25519_public_key(seed).hex()
        runner = CreateRunner(create_code=1, diagnostic="AlreadyExists: 409")
        with self.assertRaisesRegex(
            MODULE.MaterializationError, "create conflict; adoption forbidden"
        ):
            MODULE.create_and_observe(
                seed,
                public_key,
                NONCE,
                runner,
                str(Snapshot.path),
                RecoveryCore(runner),
                Snapshot(),
                self.policy(),
            )
        self.assertEqual(len(runner.calls), 1)
        self.assertIn("create", runner.calls[0][0])

    def test_full_materialization_durably_journals_before_exact_create(self) -> None:
        policy = self.policy()
        seed = bytes.fromhex("11" * 32)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal_path = root / "journal.json"
            receipt_path = root / "receipt.json"
            runner = CreateRunner(journal_path=journal_path)
            core = RecoveryCore(runner)
            with (
                patch.object(
                    MODULE,
                    "load_protected_runtime",
                    return_value=(core, policy, HASHES),
                ),
                patch.object(MODULE, "read_private_key_fd", return_value=seed),
                patch.object(
                    MODULE,
                    "ed25519_public_key",
                    return_value=bytes.fromhex(MODULE.EXPECTED_PUBLIC_KEY),
                ),
                patch.object(
                    MODULE,
                    "private_key_commitment",
                    return_value=MODULE.EXPECTED_PRIVATE_KEY_COMMITMENT,
                ),
                patch.object(
                    MODULE,
                    "partial_object_metadata_get",
                    side_effect=lambda *_args: runner.live_metadata_record(
                        _args[-2], _args[-1]
                    ),
                ),
                patch.object(MODULE.secrets, "token_hex", return_value=NONCE),
            ):
                receipt = MODULE.materialize_live(
                    REVISION,
                    "/private/source-kubeconfig",
                    9,
                    receipt_path,
                    journal_path,
                )

            self.assertEqual(receipt["status"], "materialized")
            self.assertEqual(receipt["uid"], UID)
            terminal = MODULE.bind_journal(
                policy, MODULE.load_journal(journal_path), REVISION, HASHES
            )
            self.assertEqual(terminal["status"], "committed")
            self.assertEqual(terminal["phase"], "committed")
            persisted_receipt = json.loads(receipt_path.read_bytes())
            self.assertEqual(persisted_receipt, receipt)
            self.assertFalse(persisted_receipt["valuesRead"])
            self.assertFalse(persisted_receipt["receiptContainsValues"])
            for command, _, _ in runner.calls:
                self.assertNotIn("delete", command)
                self.assertNotIn("patch", command)
                self.assertNotIn("apply", command)

    def test_race_time_create_conflict_is_durably_nonrecoverable(self) -> None:
        policy = self.policy()
        seed = bytes.fromhex("11" * 32)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal_path = root / "journal.json"
            receipt_path = root / "receipt.json"
            runner = CreateRunner(
                create_code=1,
                diagnostic="AlreadyExists: 409",
                journal_path=journal_path,
            )
            core = RecoveryCore(runner)
            runtime = patch.object(
                MODULE,
                "load_protected_runtime",
                return_value=(core, policy, HASHES),
            )
            with (
                runtime,
                patch.object(MODULE, "read_private_key_fd", return_value=seed),
                patch.object(
                    MODULE,
                    "ed25519_public_key",
                    return_value=bytes.fromhex(MODULE.EXPECTED_PUBLIC_KEY),
                ),
                patch.object(
                    MODULE,
                    "private_key_commitment",
                    return_value=MODULE.EXPECTED_PRIVATE_KEY_COMMITMENT,
                ),
                patch.object(MODULE.secrets, "token_hex", return_value=NONCE),
            ):
                with self.assertRaisesRegex(
                    MODULE.ExistingObjectError,
                    "create conflict; adoption forbidden",
                ):
                    MODULE.materialize_live(
                        REVISION,
                        "/private/source-kubeconfig",
                        9,
                        receipt_path,
                        journal_path,
                    )

            terminal = MODULE.bind_journal(
                policy, MODULE.load_journal(journal_path), REVISION, HASHES
            )
            self.assertEqual(terminal["status"], "blocked")
            self.assertEqual(terminal["phase"], "create-conflict")
            self.assertEqual(receipt_path.read_bytes(), b"")
            calls_before_recovery = len(runner.calls)
            with patch.object(
                MODULE,
                "load_protected_runtime",
                return_value=(core, policy, HASHES),
            ):
                with self.assertRaisesRegex(
                    MODULE.MaterializationError,
                    "recovery and adoption forbidden",
                ):
                    MODULE.recover_from_journal(
                        REVISION,
                        "/private/source-kubeconfig",
                        receipt_path,
                        journal_path,
                    )
            self.assertEqual(len(runner.calls), calls_before_recovery)

    def test_durable_journal_precedes_receipt_and_both_are_value_free(self) -> None:
        policy = self.policy()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal_path = root / "journal.json"
            receipt_path = root / "receipt.json"
            MODULE.reserve_journal(journal_path)
            sink = MODULE.ReceiptSink.reserve(receipt_path)
            journal = MODULE.new_journal(
                policy, REVISION, HASHES, CLUSTER, NONCE, sink.reservation()
            )
            MODULE.write_journal(
                journal_path, policy, journal, REVISION, HASHES
            )
            persisted = MODULE.bind_journal(
                policy, MODULE.load_journal(journal_path), REVISION, HASHES
            )
            self.assertEqual(persisted["phase"], "reserved-before-create")
            self.assertIsNone(persisted["secretRecord"])
            self.assertFalse(persisted["secretValuesIncluded"])
            self.assertEqual(sink.read(), b"")
            core = SimpleNamespace(
                Runner=lambda: (_ for _ in ()).throw(
                    AssertionError("cluster forbidden")
                )
            )
            with patch.object(
                MODULE,
                "load_protected_runtime",
                return_value=(core, policy, HASHES),
            ):
                with self.assertRaisesRegex(
                    MODULE.MaterializationError,
                    "no authorized create attempt",
                ):
                    MODULE.recover_from_journal(
                        REVISION,
                        "/unused",
                        receipt_path,
                        journal_path,
                    )

            incoherent = json.loads(MODULE.canonical(persisted))
            incoherent["phase"] = "committed"
            with self.assertRaisesRegex(
                MODULE.MaterializationError, "journal phase drift"
            ):
                MODULE.bind_journal(
                    policy, incoherent, REVISION, HASHES
                )

            invalid_reservation = json.loads(MODULE.canonical(persisted))
            invalid_reservation["receiptReservation"]["pathSha256"] = (
                "sha256:" + "0" * 64
            )
            with self.assertRaisesRegex(
                MODULE.MaterializationError, "journal boundary drift"
            ):
                MODULE.bind_journal(
                    policy, invalid_reservation, REVISION, HASHES
                )

            record = secret_record()
            receipt = MODULE.build_receipt(
                policy, REVISION, HASHES, CLUSTER, record
            )
            sink.commit(policy, receipt, REVISION, HASHES)
            bound = MODULE.bind_receipt(
                policy, json.loads(sink.read()), REVISION, HASHES
            )
            self.assertEqual(bound["uid"], UID)
            self.assertFalse(bound["valuesRead"])
            raw = sink.read()
            self.assertNotIn(b"private-key-hex\": \"", raw)
            self.assertNotIn(base64.b64encode(bytes.fromhex("11" * 32)), raw)
            with self.assertRaisesRegex(
                MODULE.MaterializationError, "reservation drift"
            ):
                sink.commit(policy, receipt, REVISION, HASHES)

    def test_journal_loader_blocks_leaf_symlink_race_and_reads_same_fd(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            journal_path = root / "journal.json"
            replacement = root / "replacement.json"
            journal_path.write_text('{"marker":"original"}\n', encoding="ascii")
            journal_path.chmod(0o600)
            replacement.write_text(
                '{"marker":"replacement"}\n', encoding="ascii"
            )
            replacement.chmod(0o600)
            real_open = MODULE.os.open
            swapped = False

            def swap_after_open(path, flags, *args, **kwargs):
                nonlocal swapped
                fd = real_open(path, flags, *args, **kwargs)
                if path == journal_path.name and not swapped:
                    swapped = True
                    os.replace(replacement, journal_path)
                return fd

            with patch.object(MODULE.os, "open", side_effect=swap_after_open):
                with self.assertRaisesRegex(
                    MODULE.MaterializationError,
                    "journal must be an owned 0600 regular file",
                ):
                    MODULE.load_journal(journal_path)
            self.assertEqual(
                json.loads(journal_path.read_bytes()),
                {"marker": "replacement"},
            )

            target = root / "target.json"
            target.write_text('{"marker":"target"}\n', encoding="ascii")
            target.chmod(0o600)
            journal_path.write_text('{"marker":"again"}\n', encoding="ascii")
            journal_path.chmod(0o600)
            swapped_to_symlink = False

            def swap_before_open(path, flags, *args, **kwargs):
                nonlocal swapped_to_symlink
                if path == journal_path.name and not swapped_to_symlink:
                    swapped_to_symlink = True
                    journal_path.unlink()
                    journal_path.symlink_to(target)
                return real_open(path, flags, *args, **kwargs)

            with patch.object(MODULE.os, "open", side_effect=swap_before_open):
                with self.assertRaisesRegex(
                    MODULE.MaterializationError, "journal open failed"
                ):
                    MODULE.load_journal(journal_path)

    def test_receipt_stage_crash_leaves_empty_recoverable_final_path(self) -> None:
        policy = self.policy()
        record = secret_record()
        receipt = MODULE.build_receipt(policy, REVISION, HASHES, CLUSTER, record)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal_path = root / "journal.json"
            receipt_path = root / "receipt.json"
            MODULE.reserve_journal(journal_path)
            sink = MODULE.ReceiptSink.reserve(receipt_path)
            journal = MODULE.new_journal(
                policy, REVISION, HASHES, CLUSTER, NONCE, sink.reservation()
            )
            journal["secretRecord"] = record
            journal["phase"] = "materialized-before-receipt-commit"
            MODULE.write_journal(
                journal_path, policy, journal, REVISION, HASHES
            )
            real_replace = MODULE.os.replace

            def crash_before_publish(source, target):
                if str(source).endswith(".receipt-stage"):
                    raise OSError("synthetic crash before atomic publication")
                return real_replace(source, target)

            with patch.object(
                MODULE.os, "replace", side_effect=crash_before_publish
            ):
                with self.assertRaises(OSError):
                    sink.commit(policy, receipt, REVISION, HASHES)
            self.assertEqual(sink.read(), b"")
            self.assertFalse(
                any(path.name.endswith(".receipt-stage") for path in root.iterdir())
            )

            runner = CreateRunner()
            runner.created = True
            core = RecoveryCore(runner)
            with (
                patch.object(
                    MODULE,
                    "load_protected_runtime",
                    return_value=(core, policy, HASHES),
                ),
                patch.object(
                    MODULE,
                    "partial_object_metadata_get",
                    side_effect=lambda *_args: runner.live_metadata_record(
                        _args[-2], _args[-1]
                    ),
                ),
            ):
                recovered = MODULE.recover_from_journal(
                    REVISION,
                    "/private/source-kubeconfig",
                    receipt_path,
                    journal_path,
                )
            self.assertEqual(recovered, receipt)
            self.assertEqual(json.loads(receipt_path.read_bytes()), receipt)

    def test_recovery_finalizes_only_exact_same_journal_nonce_without_create(self) -> None:
        policy = self.policy()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal_path = root / "journal.json"
            receipt_path = root / "receipt.json"
            MODULE.reserve_journal(journal_path)
            sink = MODULE.ReceiptSink.reserve(receipt_path)
            journal = MODULE.new_journal(
                policy, REVISION, HASHES, CLUSTER, NONCE, sink.reservation()
            )
            journal["phase"] = "create-attempting"
            MODULE.write_journal(
                journal_path, policy, journal, REVISION, HASHES
            )
            runner = CreateRunner()
            runner.created = True
            core = RecoveryCore(runner)
            with (
                patch.object(
                    MODULE,
                    "load_protected_runtime",
                    return_value=(core, policy, HASHES),
                ),
                patch.object(
                    MODULE,
                    "partial_object_metadata_get",
                    side_effect=lambda *_args: runner.live_metadata_record(
                        _args[-2], _args[-1]
                    ),
                ),
            ):
                receipt = MODULE.recover_from_journal(
                    REVISION,
                    "/private/source-kubeconfig",
                    receipt_path,
                    journal_path,
                )
            self.assertEqual(receipt["status"], "materialized")
            self.assertEqual(
                receipt["createOutcome"],
                "recovered-exact-same-journal-nonce-live-projection",
            )
            self.assertFalse(runner.calls)
            terminal = MODULE.bind_journal(
                policy, MODULE.load_journal(journal_path), REVISION, HASHES
            )
            self.assertEqual(terminal["status"], "committed")
            self.assertEqual(terminal["phase"], "committed")

    def test_committed_receipt_recovery_and_verify_are_cluster_read_free(self) -> None:
        policy = self.policy()
        record = secret_record()
        receipt = MODULE.build_receipt(
            policy, REVISION, HASHES, CLUSTER, record
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal_path = root / "journal.json"
            receipt_path = root / "receipt.json"
            MODULE.reserve_journal(journal_path)
            sink = MODULE.ReceiptSink.reserve(receipt_path)
            journal = MODULE.new_journal(
                policy, REVISION, HASHES, CLUSTER, NONCE, sink.reservation()
            )
            journal["secretRecord"] = record
            journal["phase"] = "materialized-before-receipt-commit"
            MODULE.write_journal(
                journal_path, policy, journal, REVISION, HASHES
            )
            sink.commit(policy, receipt, REVISION, HASHES)
            core = SimpleNamespace(
                Runner=lambda: (_ for _ in ()).throw(
                    AssertionError("cluster forbidden")
                )
            )
            with patch.object(
                MODULE,
                "load_protected_runtime",
                return_value=(core, policy, HASHES),
            ):
                recovered = MODULE.recover_from_journal(
                    REVISION, "/unused", receipt_path, journal_path
                )
            self.assertEqual(recovered, receipt)

            fd = os.open(receipt_path, os.O_RDONLY)
            try:
                loaded = MODULE._load_owned_json_fd(fd, "receipt")
            finally:
                os.close(fd)
            verified = MODULE.bind_receipt(policy, loaded, REVISION, HASHES)
            projection_value = MODULE.receipt_projection(verified)
            self.assertEqual(projection_value["status"], "materialized")
            self.assertFalse(projection_value["valuesRead"])
            self.assertNotIn("secretRecord", projection_value)

    def test_cli_modes_are_mutually_closed(self) -> None:
        materialize = MODULE.parse_args(
            [
                "--expected-protected-revision",
                REVISION,
                "--materialize",
                "--kubeconfig",
                "/kube",
                "--private-key-fd",
                "9",
                "--receipt",
                "/receipt",
                "--journal",
                "/journal",
            ]
        )
        self.assertTrue(materialize.materialize)
        recovery = MODULE.parse_args(
            [
                "--expected-protected-revision",
                REVISION,
                "--recover-journal",
                "/journal",
                "--kubeconfig",
                "/kube",
                "--receipt",
                "/receipt",
            ]
        )
        self.assertEqual(recovery.recover_journal, Path("/journal"))
        verify = MODULE.parse_args(
            [
                "--expected-protected-revision",
                REVISION,
                "--verify-receipt-fd",
                "8",
            ]
        )
        self.assertEqual(verify.verify_receipt_fd, 8)
        with self.assertRaises(MODULE.MaterializationError):
            MODULE.parse_args(
                [
                    "--expected-protected-revision",
                    REVISION,
                    "--verify-receipt-fd",
                    "8",
                    "--kubeconfig",
                    "/forbidden",
                ]
            )


if __name__ == "__main__":
    unittest.main()
