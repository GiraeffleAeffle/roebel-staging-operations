from __future__ import annotations

import importlib.util, inspect, json, os, socket, stat, sys, tempfile, threading, time, unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "participant_live_wrapper_under_test",
    ROOT / "scripts/run-staging-participant-gateway-live.py",
)
MODULE = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = MODULE; SPEC.loader.exec_module(MODULE)


def recovery_event_chain(specifications: list[tuple[str, str, dict]]) -> list[dict]:
    previous = None; events: list[dict] = []
    for sequence, (stage, operation, details) in enumerate(specifications, start=1):
        event = {"sequence": sequence, "stage": stage, "operation": operation, "previousEntrySha256": previous, **details}
        event["entrySha256"] = MODULE.bytes_sha256(MODULE.canonical(event).encode())
        events.append(event); previous = event["entrySha256"]
    return events


def recovery_verifier_fixture(*, synthetic_after_only: bool = False, omit_first_resume: bool = False, wrong_resume_revision: bool = False, wrong_absent_uid: bool = False, missing_absent_uid: bool = False, unknown_operation: bool = False, terminal_operation: str = "complete", role_uncertain_after_earlier_resume: bool = False) -> tuple[dict, dict, str]:
    revision = "a" * 40
    order = ("kustomization", "roleBinding", "role", "serviceAccount")
    options = {
        name: {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": MODULE.WORKBENCH_RECOVERY_OBJECT_UIDS[name], "resourceVersion": str(100 + index)}}
        for index, name in enumerate(order)
    }
    def intent(name: str, stage: str = "before") -> tuple[str, str, dict]:
        payload = MODULE.canonical(options[name])
        return stage, f"delete.{name}", {"target": MODULE.WORKBENCH_RECOVERY_TARGETS[name], "uid": MODULE.WORKBENCH_RECOVERY_OBJECT_UIDS[name], "resourceVersion": options[name]["preconditions"]["resourceVersion"], "verb": "DELETE", "deleteOptions": options[name], "deletePayload": payload, "deletePayloadSha256": MODULE.bytes_sha256(payload.encode())}
    def absent(name: str) -> tuple[str, str, dict]:
        uid = "00000000-0000-4000-8000-000000000099" if wrong_absent_uid and name == "role" else MODULE.WORKBENCH_RECOVERY_OBJECT_UIDS[name]
        details = {"result": "already-absent", "uid": uid}
        if missing_absent_uid and name == "role": details.pop("uid")
        return "after", f"delete.{name}", details
    def completed_delete(name: str) -> tuple[str, str, dict]:
        stage, operation, details = intent(name, "after")
        return stage, operation, details | {"result": {"absent": True, "uid": MODULE.WORKBENCH_RECOVERY_OBJECT_UIDS[name]}}
    def uncertain_delete(name: str) -> tuple[str, str, dict]:
        stage, operation, details = intent(name, "uncertain")
        return stage, operation, details | {"error": "response lost after DELETE"}
    role_binding = completed_delete("roleBinding")
    if unknown_operation:
        role_binding = (role_binding[0], "unknown-operation", role_binding[2])
    first_resume = ("before", "resume", {"revision": "b" * 40 if wrong_resume_revision else revision})
    if role_uncertain_after_earlier_resume:
        # A resume following Kustomization's uncertain delete cannot authorize
        # Role's later no-payload already-absent outcome.
        specifications = [
            ("before", "preflight", {"baselineDigest": "sha256:21c582036f38a54649b771a6dec1ba599ca859029a1c32246ef8aee6a00359c5", "sourceUid": "0de8a05d-550f-429c-93c5-9b8c76b0bf9b"}),
            uncertain_delete("kustomization"),
            ("before", "resume", {"revision": revision}),
            absent("kustomization"),
            role_binding,
            uncertain_delete("role"),
            absent("role"),
            completed_delete("serviceAccount"),
            ("before", "resume", {"revision": revision}),
            ("before", "resume", {"revision": revision}),
            ("after", terminal_operation, {"baselineDigest": "sha256:21c582036f38a54649b771a6dec1ba599ca859029a1c32246ef8aee6a00359c5", "sourceUid": "0de8a05d-550f-429c-93c5-9b8c76b0bf9b"}),
        ]
    else:
        specifications = [
            ("before", "preflight", {"baselineDigest": "sha256:21c582036f38a54649b771a6dec1ba599ca859029a1c32246ef8aee6a00359c5", "sourceUid": "0de8a05d-550f-429c-93c5-9b8c76b0bf9b"}),
            absent("kustomization") if synthetic_after_only else completed_delete("kustomization"),
            role_binding,
            uncertain_delete("role"),
            *(([] if omit_first_resume else [first_resume])),
            absent("role"),
            completed_delete("serviceAccount"),
            ("before", "resume", {"revision": revision}),
            ("before", "resume", {"revision": revision}),
            ("after", terminal_operation, {"baselineDigest": "sha256:21c582036f38a54649b771a6dec1ba599ca859029a1c32246ef8aee6a00359c5", "sourceUid": "0de8a05d-550f-429c-93c5-9b8c76b0bf9b"}),
        ]
    events = recovery_event_chain(specifications)
    final_absence = {name: {"uid": MODULE.WORKBENCH_RECOVERY_OBJECT_UIDS[name], "absent": True} for name in order}
    state = {
        "schemaVersion": "roebel_staging_workbench_baseline_recovery_journal_v1", "status": "completed", "protectedRevision": revision,
        "events": events, "finalAbsence": final_absence,
    }
    state["journalSha256"] = MODULE.bytes_sha256(MODULE.canonical(state).encode())
    evidence = {
        "schemaVersion": "roebel_staging_workbench_baseline_recovery_receipt_v1", "status": "completed", "protectedRevision": revision,
        "originRevision": MODULE.WORKBENCH_RECOVERY_ORIGIN_REVISION, "operationId": MODULE.WORKBENCH_RECOVERY_OPERATION_ID, "operationMarker": MODULE.WORKBENCH_RECOVERY_MARKER,
        "evidence": MODULE.WORKBENCH_RECOVERY_EVIDENCE,
        "effects": {"deleteOnlyMutation": True, "create": False, "patch": False, "apply": False, "list": False, "secretAccess": False, "civicAuthorityEffects": False, "baselineChanged": False, "sharedSourceChanged": False, "cleanupComplete": True},
        "baseline": {"uid": "298b0f92-0d6b-4563-b141-f93aa8c8fd8f", "digest": "sha256:21c582036f38a54649b771a6dec1ba599ca859029a1c32246ef8aee6a00359c5"},
        "source": {"uid": "0de8a05d-550f-429c-93c5-9b8c76b0bf9b", "revision": f"main@sha1:{revision}"},
        "objects": {name: {"uid": MODULE.WORKBENCH_RECOVERY_OBJECT_UIDS[name], "status": "absent"} for name in order},
        "finalAbsence": final_absence,
        "journal": {"schemaVersion": "roebel_staging_workbench_baseline_recovery_journal_v1", "status": "completed", "eventCount": len(events), "terminalEntrySha256": events[-1]["entrySha256"], "terminalJournalSha256": state["journalSha256"]},
    }
    evidence["canonicalSha256"] = MODULE.bytes_sha256(MODULE.canonical(evidence).encode())
    return evidence, state, revision


def migrated_recovery_verifier_fixture() -> tuple[dict, dict, str, str]:
    evidence, state, revision = recovery_verifier_fixture()
    terminal_revision = "b" * 40
    specifications = []
    for event in state["events"]:
        details = {
            key: value for key, value in event.items()
            if key not in {"sequence", "stage", "operation", "previousEntrySha256", "entrySha256"}
        }
        if event["operation"] == "resume":
            details["revision"] = terminal_revision
        specifications.append((event["stage"], event["operation"], details))
    source_at_recovery = {
        "uid": "0de8a05d-550f-429c-93c5-9b8c76b0bf9b",
        "revision": f"main@sha1:{terminal_revision}",
        "generation": 2,
    }
    source_at_finalization = {
        "uid": source_at_recovery["uid"],
        "revision": f"main@sha1:{revision}",
        "generation": 2,
    }
    baseline = {
        "uid": "298b0f92-0d6b-4563-b141-f93aa8c8fd8f",
        "resourceVersion": "300",
        "digest": "sha256:21c582036f38a54649b771a6dec1ba599ca859029a1c32246ef8aee6a00359c5",
    }
    state["events"] = recovery_event_chain(specifications)
    state["protectedRevision"] = terminal_revision
    state["source"] = source_at_recovery
    state["baseline"] = baseline
    state["journalSha256"] = MODULE.bytes_sha256(MODULE.canonical({key: value for key, value in state.items() if key != "journalSha256"}).encode())
    journal_file_sha256 = MODULE.bytes_sha256((MODULE.canonical(state) + "\n").encode())

    evidence.update({
        "protectedRevision": revision,
        "finalizedAgainstRevision": revision,
        "finalizationParentRevision": "c" * 40,
        "terminalRecoveryRevision": terminal_revision,
        "source": source_at_finalization,
        "sourceAtRecovery": source_at_recovery,
        "sourceAtFinalization": source_at_finalization,
        "baseline": baseline,
    })
    evidence["effects"].update({
        "historicalDeleteOnlyRecovery": True,
        "deleteOnlyMutation": False,
        "getOnlyFinalization": True,
        "clusterMutationCount": 0,
        "newDeletes": 0,
    })
    evidence["journal"] = {
        "schemaVersion": state["schemaVersion"],
        "status": "completed",
        "eventCount": len(state["events"]),
        "terminalEntrySha256": state["events"][-1]["entrySha256"],
        "terminalJournalSha256": state["journalSha256"],
        "protectedRevision": terminal_revision,
        "terminalJournalFileSha256": journal_file_sha256,
    }
    evidence.pop("canonicalSha256", None)
    evidence["canonicalSha256"] = MODULE.bytes_sha256(MODULE.canonical(evidence).encode())
    return evidence, state, revision, journal_file_sha256


class ParticipantLiveWrapperTests(unittest.TestCase):
    def test_terminal_finalizer_requires_the_exact_single_protected_parent(self):
        revision = "a" * 40
        parent = MODULE.WORKBENCH_RECOVERY_FINALIZATION_PARENT_REVISION
        exact = MODULE.subprocess.CompletedProcess([], 0, stdout=f"{revision} {parent}\n", stderr="")
        with patch.object(MODULE, "trusted_git", return_value=exact):
            MODULE.require_protected_revision_parent(revision, parent)

        for observed in (f"{revision} {'b' * 40}\n", f"{revision} {parent} {'c' * 40}\n", f"{'d' * 40} {parent}\n"):
            with self.subTest(observed=observed), patch.object(
                MODULE,
                "trusted_git",
                return_value=MODULE.subprocess.CompletedProcess([], 0, stdout=observed, stderr=""),
            ):
                with self.assertRaisesRegex(MODULE.LiveTransportError, "exact protected parent"):
                    MODULE.require_protected_revision_parent(revision, parent)

    def test_terminal_finalization_preflight_requires_exact_existing_journal_before_transport(self):
        revision = "a" * 40
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700)
            bindings = root / "bindings"; bindings.mkdir(mode=0o700)
            exact = root / "exact.journal"; exact.write_bytes(b"exact terminal journal\n"); exact.chmod(0o600)
            expected_sha256 = MODULE.bytes_sha256(exact.read_bytes())
            with patch.object(MODULE, "WORKBENCH_RECOVERY_TERMINAL_JOURNAL_FILE_SHA256", expected_sha256), patch.object(
                MODULE, "require_protected_revision_parent"
            ) as parent_guard:
                bound = MODULE.bind_terminal_finalization_journal(exact, bindings, revision)
                try:
                    self.assertEqual(bound.sha256, expected_sha256)
                    parent_guard.assert_called_once_with(revision, MODULE.WORKBENCH_RECOVERY_FINALIZATION_PARENT_REVISION)
                finally:
                    bound.close()

            empty = root / "empty.journal"; empty.touch(mode=0o600)
            wrong = root / "wrong.journal"; wrong.write_bytes(b"other\n"); wrong.chmod(0o600)
            for candidate in (root / "absent.journal", empty, wrong):
                with self.subTest(candidate=candidate.name), patch.object(
                    MODULE, "WORKBENCH_RECOVERY_TERMINAL_JOURNAL_FILE_SHA256", expected_sha256
                ), patch.object(MODULE, "require_protected_revision_parent") as parent_guard:
                    with self.assertRaisesRegex((MODULE.LiveTransportError, FileNotFoundError), "exact terminal|bounded owned"):
                        MODULE.bind_terminal_finalization_journal(candidate, bindings, revision)
                    parent_guard.assert_not_called()

    def test_wireproxy_configuration_has_only_one_fixed_stdio_target(self):
        password = "a" * 64
        api_authority = f"{MODULE.API_HOST}:{MODULE.API_PORT}"
        talos_authority = f"{MODULE.API_HOST}:{MODULE.TALOS_PORT}"
        wireguard = b"[Interface]\nPrivateKey = fixture\n\n[Peer]\nPublicKey = fixture\n"
        for value, authority in (
            (MODULE.wireproxy_config(api_authority, wireguard), api_authority),
            (MODULE.wireproxy_config(talos_authority, wireguard), talos_authority),
        ):
            self.assertEqual(value.count(b"[STDIOTunnel]"), 1)
            self.assertIn(f"Target = {authority}".encode(), value)
            self.assertNotIn(b"BindAddress", value)
            self.assertNotIn(b"[http]", value)
            self.assertNotIn(b"[Socks5]", value)
            self.assertNotIn(b"[TCPClientTunnel]", value)
        self.assertEqual(
            MODULE.proxy_url(password, 53161),
            f"http://stadtstack-participant:{password}@127.0.0.1:53161",
        )
        for authority in ("10.255.240.12:6443", f"{MODULE.API_HOST}:22", "example.test:443"):
            with self.subTest(authority=authority), self.assertRaises(MODULE.LiveTransportError):
                MODULE.wireproxy_config(authority, wireguard)

        for injected in (b"\n[HTTP]\nBindAddress = 127.0.0.1:1\n", b"\n[tcpservertunnel]\nTarget = 127.0.0.1:1\n", b"\nWGConfig = /tmp/other\n"):
            with self.subTest(injected=injected), self.assertRaises(MODULE.LiveTransportError):
                MODULE.wireproxy_config(api_authority, wireguard + injected)
    def test_guard_rejects_method_authority_and_auth_then_relays_fixed_tunnel(self):
        backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend.bind(("127.0.0.1", 0)); backend.listen(1)
        backend_port = backend.getsockname()[1]

        class DirectGuard(MODULE.ExactConnectProxy):
            def _spawn_tunnel(self):
                connection = socket.create_connection(("127.0.0.1", backend_port), timeout=2)
                with self.lock: self.connections.add(connection)
                return connection, None

        guard = DirectGuard(
            f"{MODULE.API_HOST}:{MODULE.API_PORT}",
            Path("/bin/false"),
            b"fixed config",
            Path("/private/tmp"),
            "a" * 64,
            {},
        )
        guard_port = guard.start()
        self.addCleanup(backend.close); self.addCleanup(guard.close)

        def response(request: bytes) -> bytes:
            with socket.create_connection(("127.0.0.1", guard_port), timeout=2) as client:
                client.sendall(request); return client.recv(4096)

        self.assertIn(b" 405 ", response(b"GET 10.255.240.11:6443 HTTP/1.1\r\nHost: 10.255.240.11:6443\r\n\r\n"))
        self.assertIn(b" 403 ", response(b"CONNECT 10.255.240.12:6443 HTTP/1.1\r\nHost: 10.255.240.12:6443\r\n\r\n"))
        self.assertIn(b" 407 ", response(b"CONNECT 10.255.240.11:6443 HTTP/1.1\r\nHost: 10.255.240.11:6443\r\nProxy-Authorization: Basic bad\r\n\r\n"))
        self.assertIn(b" 400 ", response(b"CONNECT 10.255.240.11:6443 HTTP/1.1\r\nHost: 10.255.240.11:6443\r\nHost: 10.255.240.11:6443\r\n\r\n"))
        self.assertIn(b" 400 ", response(b"CONNECT 10.255.240.11:6443 HTTP/1.1\r\nHost: 10.255.240.11:6443\r\n\r\npipelined"))

        backend_result: list[bytes] = []
        def echo() -> None:
            connection, _ = backend.accept()
            with connection:
                value = connection.recv(32); backend_result.append(value); connection.sendall(b"pong")
        worker = threading.Thread(target=echo); worker.start()
        authorization = guard.expected_authorization()
        with socket.create_connection(("127.0.0.1", guard_port), timeout=2) as client:
            client.sendall(
                f"CONNECT 10.255.240.11:6443 HTTP/1.1\r\nHost: 10.255.240.11:6443\r\nProxy-Authorization: {authorization}\r\n\r\n".encode()
            )
            self.assertIn(b" 200 ", client.recv(4096))
            client.sendall(b"ping"); self.assertEqual(client.recv(32), b"pong")
        worker.join(timeout=2)
        self.assertEqual(backend_result, [b"ping"])

    def test_guard_worker_count_is_bounded_and_close_joins_active_workers(self):
        guard = MODULE.ExactConnectProxy(
            f"{MODULE.API_HOST}:{MODULE.API_PORT}",
            Path("/bin/false"),
            b"fixed config",
            Path("/private/tmp"),
            "a" * 64,
            {},
            max_workers=1,
        )
        port = guard.start()
        first = socket.create_connection(("127.0.0.1", port), timeout=2)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            with guard.lock:
                if len(guard.workers) == 1: break
            time.sleep(0.01)
        with socket.create_connection(("127.0.0.1", port), timeout=2) as second:
            second.sendall(b"CONNECT 10.255.240.11:6443 HTTP/1.1\r\nHost: 10.255.240.11:6443\r\n\r\n")
            self.assertIn(b" 503 ", second.recv(4096))
        report = guard.close(); first.close()
        self.assertTrue(report["listenerStopped"])
        self.assertTrue(report["workerThreadsStopped"])
        self.assertTrue(report["connectionsClosed"])
        self.assertTrue(report["tunnelProcessGroupsStopped"])
        self.assertEqual(report["workerLimit"], 1)

    def test_early_signal_is_non_raising_and_prevents_process_creation(self):
        state = MODULE.CancellationState(); state.install(); self.addCleanup(state.restore)
        state.handle_signal(MODULE.signal.SIGTERM, None)
        self.assertEqual(state.signals, [MODULE.signal.SIGTERM])
        with patch.object(MODULE.subprocess, "Popen") as spawn, self.assertRaisesRegex(MODULE.LiveTransportInterrupted, "operator signal"):
            state.run(["must-not-start"])
        spawn.assert_not_called()

    def test_process_spawn_race_registers_then_forwards_without_blocking_child_signals(self):
        state = MODULE.CancellationState()
        process = Mock(pid=12345, returncode=-15)
        process.poll.return_value = None
        process.communicate.return_value = ("", "")
        def spawn(*_args, **_kwargs):
            state.handle_signal(MODULE.signal.SIGTERM, None)
            return process
        with patch.object(MODULE.subprocess, "Popen", side_effect=spawn), patch.object(MODULE.os, "killpg") as forward:
            result = state.run(["fixture"], stdout=MODULE.subprocess.PIPE, stderr=MODULE.subprocess.PIPE, text=True)
        self.assertEqual(result.returncode, -15)
        forward.assert_called_once_with(12345, MODULE.signal.SIGTERM)
        self.assertFalse(hasattr(state, "_block"))

    def test_child_exit_signal_race_defers_to_deep_receipt_reconciliation(self):
        state = MODULE.CancellationState(); state.install(); self.addCleanup(state.restore)
        session = MODULE.LiveSession(
            Path("/bin/false"),
            Mock(fd=3),
            Mock(fd=4),
            Path("/private/tmp"),
            "a" * 64,
            "b" * 64,
            state,
        )
        with patch.object(session, "transport_alive", side_effect=[True, False]):
            result = session.run_child([sys.executable, "-I", "-c", "pass"], {})
        self.assertEqual(result.returncode, 0)
        self.assertFalse(result.transport_alive_after)
        self.assertTrue(state.receipt_pending)
        state.handle_signal(MODULE.signal.SIGTERM, None)
        session.receipt_reconciled()
        with patch.object(session, "transport_alive", return_value=True), self.assertRaisesRegex(MODULE.LiveTransportInterrupted, "operator signal"):
            session.run_child(["must-not-start"], {})
        state.begin_finalization(); self.assertTrue(state.cleanup_processes()["ownedProcessGroupsStopped"])

    def test_executable_snapshot_is_private_exclusive_fsynced_and_rehashed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / "source"; source.write_bytes(b"exact executable bytes"); source.chmod(0o700)
            destination = root / "snapshot"; expected = MODULE.bytes_sha256(source.read_bytes())
            with patch.dict(MODULE.EXPECTED_BINARIES, {"fixture": expected}, clear=False):
                snapshot = MODULE.snapshot_binary(source, "fixture", destination)
                try:
                    self.assertEqual(snapshot.sha256, expected)
                    self.assertEqual(MODULE.file_sha256(snapshot.path), expected)
                    self.assertEqual(stat.S_IMODE(snapshot.path.stat().st_mode), 0o500)
                    self.assertEqual(snapshot.path.stat().st_ino, os.fstat(snapshot.fd).st_ino)
                    with self.assertRaises(FileExistsError): MODULE.snapshot_binary(source, "fixture", destination)
                finally:
                    snapshot.close()

    def test_private_inputs_and_wrapper_receipt_are_closed_and_link_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); private = root / "private"; private.write_text("super-secret-value"); private.chmod(0o600)
            link = root / "link"; link.symlink_to(private)
            with self.assertRaisesRegex(MODULE.LiveTransportError, "symlink"):
                MODULE.private_file(link, "fixture")
            receipt = root / "receipt.json"; sink = MODULE.WrapperReceiptSink.reserve(receipt)
            value = {"schemaVersion": MODULE.WRAPPER_RECEIPT_SCHEMA, "status": "blocked", "containsSecretMaterial": False, "civicAuthorityEffects": False}
            checksum = sink.commit(value)
            stored = json.loads(receipt.read_text()); observed = stored.pop("canonicalSha256")
            self.assertEqual(observed, checksum)
            self.assertEqual(checksum, MODULE.bytes_sha256(MODULE.canonical(stored).encode()))
            self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)
            self.assertNotIn("super-secret-value", receipt.read_text())
            hardlink = root / "receipt-link"; os.link(receipt, hardlink)
            with self.assertRaisesRegex(MODULE.LiveTransportError, "nlink-one"):
                MODULE.owned_receipt_file_sha256(receipt)

    def test_trusted_git_ignores_caller_path_and_configuration(self):
        completed = Mock(returncode=0)
        with patch.dict(MODULE.os.environ, {"PATH": "/attacker", "GIT_CONFIG_GLOBAL": "/attacker"}, clear=True), patch.object(
            MODULE.subprocess, "run", return_value=completed,
        ) as run:
            MODULE.trusted_git(["--version"], check=False)
        self.assertEqual(run.call_args.args[0][0], "/usr/bin/git")
        self.assertEqual(run.call_args.args[0][1], "--no-replace-objects")
        self.assertEqual(run.call_args.kwargs["env"]["PATH"], "/usr/bin:/bin")
        self.assertEqual(run.call_args.kwargs["env"]["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(run.call_args.kwargs["env"]["GIT_NO_REPLACE_OBJECTS"], "1")

    def test_bound_runner_executes_unlinked_verified_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = b"import sys\nprint(__file__)\nprint(sys.argv[1])\n"
            blob = MODULE.bind_bytes_to_fd(source, root / "runner.bound", "fixture runner")
            runner = MODULE.BoundRunner("scripts/fixture-runner.py", blob)
            try:
                state = MODULE.CancellationState()
                result = state.run(
                    runner.command(["argument"]),
                    stdout=MODULE.subprocess.PIPE,
                    stderr=MODULE.subprocess.PIPE,
                    text=True,
                    pass_fds=(blob.fd,),
                )
                self.assertEqual(result.returncode, 0)
                self.assertEqual(result.stdout.splitlines(), [str(ROOT / "scripts/fixture-runner.py"), "argument"])
                self.assertFalse((root / "runner.bound").exists())
            finally:
                runner.close()

    def test_dormant_receipt_snapshot_cannot_be_replaced_after_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / "receipt.json"; original = b'{"status":"dormant-ready"}\n'
            source.write_bytes(original); source.chmod(0o600)
            bound = MODULE.snapshot_owned_receipt(source, root / "receipt.bound", "fixture receipt")
            try:
                replacement = root / "replacement"; replacement.write_bytes(b'{"status":"foreign"}\n'); replacement.chmod(0o600)
                os.replace(replacement, source)
                self.assertEqual(os.pread(bound.fd, bound.size + 1, 0), original)
                self.assertEqual(bound.sha256, MODULE.bytes_sha256(original))
            finally:
                bound.close()

    def test_subprocess_environment_removes_every_ambient_proxy_and_kubeconfig(self):
        hostile = {"PATH": "/usr/bin", "HTTP_PROXY": "http://attacker", "https_proxy": "http://attacker", "ALL_PROXY": "socks5://attacker", "no_proxy": "*", "KUBECONFIG": "/attacker", "PYTHONPATH": "/attacker", "SAFE": "yes"}
        with patch.dict(MODULE.os.environ, hostile, clear=True):
            self.assertEqual(MODULE.sanitized_environment(), {"PATH": "/usr/bin", "SAFE": "yes"})

    def test_post_commit_cleanup_failure_is_never_success_or_blocked(self):
        self.assertEqual(MODULE.classify_final_status("activated", activation_committed=True, operation_succeeded=True, cleanup_complete=False), ("activated-cleanup-incomplete", 3))
        self.assertEqual(MODULE.classify_final_status("activated", activation_committed=True, operation_succeeded=True, cleanup_complete=True), ("activated", 0))
        self.assertEqual(MODULE.classify_final_status("dormant-torn-down", activation_committed=False, operation_succeeded=True, cleanup_complete=False), ("dormant-teardown-cleanup-incomplete", 3))
        self.assertEqual(MODULE.classify_final_status("participant-secrets-torn-down", activation_committed=False, operation_succeeded=True, cleanup_complete=True), ("participant-secrets-torn-down", 0))
        source = inspect.getsource(MODULE.main)
        for check in ("bootstrap.returncode != 0", "teardown_returncode != 0", "activation.returncode != 0"):
            self.assertIn(check, source)
        failed_cleanup = Mock(pid=4242, cleanup_error="immutable invocation remained")
        failed_cleanup.poll.return_value = -15
        failed_cleanup.wait.return_value = -15
        with patch.object(MODULE, "process_group_gone", return_value=True):
            self.assertFalse(MODULE.stop_process(failed_cleanup, timeout=0.01))
        self.assertLess(source.index("activation_projection = verify_receipt_with_protected_cli("), source.index("activation_logging_error = best_effort_print_child(activation)"))
        self.assertLess(source.index("bootstrap_projection = verify_receipt_with_protected_cli("), source.index("bootstrap_logging_error = best_effort_print_child(bootstrap)"))
        with patch("builtins.print", side_effect=BrokenPipeError):
            logging_error = MODULE.best_effort_print_child(MODULE.ChildResult(0, "committed", "", True))
        self.assertIn("BrokenPipeError", logging_error)

    def test_signal_state_prebinds_every_transitive_blob_before_snapshot_and_decrypt(self):
        expected = {MODULE.SELF_PATH, MODULE.BOOTSTRAP_RUNNER, MODULE.ACTIVATION_RUNNER, MODULE.SECRET_RUNNER, "scripts/staging_participant_flux_bootstrap.py", "scripts/staging_participant_gateway_policy.py", "policy/staging-participant-gateway-activation-policy.json", ".github/workflows/staging-participant-flux-bootstrap.yml", ".github/workflows/staging-participant-gateway-activation.yml", "scripts/verify-reviewed-render.py", "policy/repository-contract.json"}
        self.assertEqual(set(MODULE.PROTECTED_PATHS), expected)
        source = inspect.getsource(MODULE.main)
        self.assertLess(source.index("cancellation.install()"), source.index("bind_protected_checkout(revision)"))
        self.assertLess(source.index("bind_protected_checkout(revision)"), source.index("bind_bytes_to_fd("))
        self.assertLess(source.index("bind_bytes_to_fd("), source.index("snapshot_binary("))
        self.assertLess(source.index("snapshot_binary("), source.index("decrypt("))
        self.assertIn("--verify-success-receipt-fd", source)
        self.assertIn("--teardown-dormant-receipt", inspect.getsource(MODULE.parse_args))

    def test_wrapper_delegates_kubernetes_writes_to_immutable_protected_runners(self):
        source = inspect.getsource(MODULE.main)
        self.assertIn("bootstrap_runner.command(", source)
        self.assertIn("activation_runner.command(", source)
        self.assertIn("secret_runner.command(", source)
        for forbidden in ("str(ROOT / BOOTSTRAP_RUNNER)", "str(ROOT / ACTIVATION_RUNNER)", "str(ROOT / SECRET_RUNNER)", "kubectl apply", "kubectl create", "kubectl patch", "kubectl delete", "--server", "--token"):
            self.assertNotIn(forbidden, source)
        self.assertEqual(set(MODULE.EXPECTED_BINARIES), {"age", "kubectl", "talosctl", "wireproxy"})
        self.assertTrue(all(MODULE.SHA256.fullmatch(value) for value in MODULE.EXPECTED_BINARIES.values()))

    def test_workbench_mode_is_explicitly_isolated_from_participant_runners(self):
        arguments = [
            "--workbench-baseline-handover", "--live", "--expected-protected-revision", "a" * 40,
            "--age-bin", "/bin/true", "--age-identity", "/private/id", "--bootstrap-bundle", "/private/bundle",
            "--wireproxy-bin", "/bin/true", "--talosctl-bin", "/bin/true", "--kubectl-bin", "/bin/true",
            "--receipt-directory", "/private/attempt", "--workbench-handover-receipt", "/private/handover.json",
            "--workbench-handover-journal", "/private/handover.journal",
        ]
        parsed = MODULE.parse_args(arguments)
        self.assertTrue(parsed.workbench_baseline_handover)
        with self.assertRaises(SystemExit):
            MODULE.parse_args(["--participant-gateway", *arguments])
        with self.assertRaisesRegex(MODULE.LiveTransportError, "requires explicit receipt and journal"):
            MODULE.parse_args([value for value in arguments if value not in {"--workbench-handover-receipt", "/private/handover.json", "--workbench-handover-journal", "/private/handover.journal"}])
        self.assertNotIn(MODULE.BOOTSTRAP_RUNNER, MODULE.WORKBENCH_PROTECTED_PATHS)
        self.assertNotIn(MODULE.ACTIVATION_RUNNER, MODULE.WORKBENCH_PROTECTED_PATHS)
        source = inspect.getsource(MODULE.run_workbench_baseline_handover_transport)
        for forbidden in ("bootstrap_runner", "activation_runner", "run_dormant_teardown", "--teardown"):
            self.assertNotIn(forbidden, source)
        self.assertIn("workbench_implementation_command", source)

    def test_participant_secret_modes_are_explicit_and_mutually_exclusive(self):
        common = [
            "--participant-gateway", "--live", "--expected-protected-revision", "a" * 40,
            "--age-bin", "/bin/true", "--age-identity", "/private/id", "--bootstrap-bundle", "/private/bundle",
            "--wireproxy-bin", "/bin/true", "--talosctl-bin", "/bin/true", "--kubectl-bin", "/bin/true",
            "--receipt-directory", "/private/attempt",
        ]
        activation = MODULE.parse_args([*common, "--participant-secret-bundle", "/private/secrets"])
        self.assertEqual(activation.participant_secret_bundle, Path("/private/secrets"))
        teardown = MODULE.parse_args([*common, "--teardown-participant-secret-receipt", "/private/materialization.json"])
        self.assertEqual(teardown.teardown_participant_secret_receipt, Path("/private/materialization.json"))
        with self.assertRaisesRegex(MODULE.LiveTransportError, "requires an explicit private Secret bundle"):
            MODULE.parse_args(common)
        with self.assertRaisesRegex(MODULE.LiveTransportError, "may not combine"):
            MODULE.parse_args([*common, "--teardown-participant-secret-receipt", "/private/materialization.json", "--teardown-dormant-receipt", "/private/dormant.json"])
        source = inspect.getsource(MODULE.main)
        materialization_call = source[
            source.index("secret_materialization = session.run_child("):
            source.index("secret_materialization_bound = snapshot_owned_receipt(")
        ]
        self.assertIn("forward_signals=False", materialization_call)

    def test_workbench_recovery_mode_is_explicit_delete_only_and_requires_all_evidence(self):
        arguments = [
            "--workbench-baseline-recovery", "--live", "--expected-protected-revision", "a" * 40,
            "--age-bin", "/bin/true", "--age-identity", "/private/id", "--bootstrap-bundle", "/private/bundle",
            "--wireproxy-bin", "/bin/true", "--talosctl-bin", "/bin/true", "--kubectl-bin", "/bin/true",
            "--receipt-directory", "/private/attempt", "--workbench-recovery-receipt", "/private/recovery.json",
            "--workbench-recovery-journal", "/private/recovery.journal", "--workbench-origin-journal", "/private/origin.journal",
            "--workbench-attempt-receipt", "/private/attempt.json", "--workbench-inspection", "/private/inspection.json",
        ]
        parsed = MODULE.parse_args(arguments)
        self.assertTrue(parsed.workbench_baseline_recovery)
        finalizer_arguments = [
            "--workbench-baseline-recovery-finalize" if value == "--workbench-baseline-recovery" else value
            for value in arguments
        ]
        finalized = MODULE.parse_args(finalizer_arguments)
        self.assertTrue(finalized.workbench_baseline_recovery_finalize)
        with self.assertRaisesRegex(MODULE.LiveTransportError, "requires exact evidence"):
            MODULE.parse_args([value for value in arguments if value not in {"--workbench-inspection", "/private/inspection.json"}])
        self.assertNotIn(MODULE.BOOTSTRAP_RUNNER, MODULE.WORKBENCH_RECOVERY_PROTECTED_PATHS)
        self.assertNotIn(MODULE.ACTIVATION_RUNNER, MODULE.WORKBENCH_RECOVERY_PROTECTED_PATHS)
        source = inspect.getsource(MODULE.run_workbench_baseline_handover_transport)
        self.assertIn("WORKBENCH_RECOVERY_IMPLEMENTATION", source)
        self.assertIn("verify_workbench_recovery_evidence", source)
        self.assertIn('"--terminal-finalize"', source)
        self.assertIn("bind_terminal_finalization_journal", source)
        verifier = inspect.getsource(MODULE.verify_workbench_recovery_evidence)
        self.assertIn("terminalJournalSha256", verifier)
        self.assertIn("receipt/journal binding drift", verifier)

    @unittest.skipUnless(hasattr(os, "chflags") and hasattr(stat, "UF_IMMUTABLE"), "requires macOS immutable file flags")
    def test_workbench_pinned_kubectl_path_cannot_be_replaced_between_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / "source"; source.write_bytes(b"immutable kubectl fixture"); source.chmod(0o700)
            snapshot_path = root / "snapshot"; expected = MODULE.bytes_sha256(source.read_bytes())
            with patch.dict(MODULE.EXPECTED_BINARIES, {"fixture": expected}, clear=False):
                snapshot = MODULE.snapshot_binary(source, "fixture", snapshot_path)
                try:
                    MODULE.seal_pinned_snapshot(snapshot)
                    binding = MODULE.PersistentPinnedExecutable(snapshot)
                    binding._verify()  # first simulated KubernetesAdapter call
                    replacement = root / "replacement"; replacement.write_bytes(b"attacker replacement"); replacement.chmod(0o500)
                    with self.assertRaises(OSError):
                        os.replace(replacement, snapshot.path)
                    binding._verify()  # second call observes the original bound bytes
                finally:
                    MODULE.unseal_pinned_snapshot(snapshot)
                    snapshot.close()

    def test_workbench_receipt_and_terminal_journal_must_be_separate_and_complete(self):
        revision = "a" * 40
        protected = {path: MODULE.bytes_sha256(path.encode()) for path in MODULE.WORKBENCH_PROTECTED_PATHS}
        payload = {
            "schemaVersion": "roebel_staging_workbench_baseline_handover_receipt_v1", "status": "completed", "mode": "live",
            "protectedRevision": revision, "protectedFileSha256": protected,
            "baseline": {"uid": "298b0f92-0d6b-4563-b141-f93aa8c8fd8f"},
            "effects": {"networkPolicySpecChanged": False, "existingDeploymentChanged": False, "existingServiceChanged": False, "secretAccess": False, "civicAuthorityEffects": False, "fluxReady": True, "networkPolicyReconciled": True},
            "objects": [{"objectId": name, "uid": f"uid-{name}"} for name in ("serviceAccount", "role", "roleBinding", "kustomization")],
            "flux": {"ready": {}, "networkPolicyReconciled": {}},
        }
        journal = {"schemaVersion": "roebel_staging_workbench_baseline_journal_v1", "status": "completed", "protectedRevision": revision}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = MODULE.bind_bytes_to_fd((MODULE.canonical(payload) + "\n").encode(), root / "receipt.bound", "receipt")
            state = MODULE.bind_bytes_to_fd((MODULE.canonical(journal) + "\n").encode(), root / "journal.bound", "journal")
            try:
                proof = MODULE.verify_workbench_handover_evidence(receipt, state, revision, protected)
                self.assertEqual(proof["networkPolicyUid"], payload["baseline"]["uid"])
                journal["status"] = "in-progress"
                changed = MODULE.bind_bytes_to_fd((MODULE.canonical(journal) + "\n").encode(), root / "changed.bound", "changed")
                try:
                    with self.assertRaisesRegex(MODULE.LiveTransportError, "journal is not terminal"):
                        MODULE.verify_workbench_handover_evidence(receipt, changed, revision, protected)
                finally:
                    changed.close()
            finally:
                receipt.close(); state.close()

    def test_recovery_verifier_accepts_uncertain_delete_intent_then_exact_already_absent_resume(self):
        payload, journal, revision = recovery_verifier_fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt_bound = MODULE.bind_bytes_to_fd((MODULE.canonical(payload) + "\n").encode(), root / "receipt.bound", "recovery receipt")
            journal_bound = MODULE.bind_bytes_to_fd((MODULE.canonical(journal) + "\n").encode(), root / "journal.bound", "recovery journal")
            try:
                proof = MODULE.verify_workbench_recovery_evidence(receipt_bound, journal_bound, revision)
                self.assertTrue(proof["cleanupComplete"])
                self.assertEqual(payload["journal"]["eventCount"], 10)
            finally:
                receipt_bound.close(); journal_bound.close()

    def test_recovery_verifier_accepts_only_dual_provenance_get_only_terminal_finalization(self):
        payload, journal, revision, journal_file_sha256 = migrated_recovery_verifier_fixture()
        with tempfile.TemporaryDirectory() as directory, patch.multiple(
            MODULE,
            WORKBENCH_RECOVERY_TERMINAL_REVISION=journal["protectedRevision"],
            WORKBENCH_RECOVERY_TERMINAL_JOURNAL_FILE_SHA256=journal_file_sha256,
            WORKBENCH_RECOVERY_TERMINAL_JOURNAL_CANONICAL_SHA256=journal["journalSha256"],
            WORKBENCH_RECOVERY_FINALIZATION_PARENT_REVISION=payload["finalizationParentRevision"],
            create=True,
        ):
            root = Path(directory)
            receipt_bound = MODULE.bind_bytes_to_fd((MODULE.canonical(payload) + "\n").encode(), root / "receipt.bound", "recovery receipt")
            journal_bound = MODULE.bind_bytes_to_fd((MODULE.canonical(journal) + "\n").encode(), root / "journal.bound", "recovery journal")
            try:
                with self.assertRaisesRegex(MODULE.LiveTransportError, "mode drift"):
                    MODULE.verify_workbench_recovery_evidence(receipt_bound, journal_bound, revision)
                proof = MODULE.verify_workbench_recovery_evidence(
                    receipt_bound, journal_bound, revision, terminal_finalization_expected=True
                )
                self.assertTrue(proof["cleanupComplete"])
                self.assertEqual(proof["clusterMutationCount"], 0)
                self.assertEqual(proof["terminalRecoveryRevision"], journal["protectedRevision"])
            finally:
                receipt_bound.close(); journal_bound.close()

    def test_recovery_verifier_rejects_ambiguous_terminal_provenance_or_nonzero_mutation(self):
        cases = (
            ("missing-terminal-revision", lambda payload: payload.pop("terminalRecoveryRevision"), "provenance drift"),
            ("wrong-parent", lambda payload: payload.__setitem__("finalizationParentRevision", "d" * 40), "provenance drift"),
            ("nonzero-mutation", lambda payload: payload["effects"].__setitem__("clusterMutationCount", 1), "effect.*drift"),
            ("new-delete", lambda payload: payload["effects"].__setitem__("newDeletes", 1), "effect.*drift"),
            ("current-delete-claim", lambda payload: payload["effects"].__setitem__("deleteOnlyMutation", True), "effect.*drift"),
            ("missing-history", lambda payload: payload["effects"].pop("historicalDeleteOnlyRecovery"), "effect.*drift"),
            ("source-generation", lambda payload: payload["sourceAtFinalization"].__setitem__("generation", 3), "predecessor drift"),
            ("journal-binding", lambda payload: payload["journal"].__setitem__("terminalJournalFileSha256", "sha256:" + "0" * 64), "binding drift"),
        )
        for label, mutate, message in cases:
            with self.subTest(label=label):
                payload, journal, revision, journal_file_sha256 = migrated_recovery_verifier_fixture()
                mutate(payload)
                payload.pop("canonicalSha256", None)
                payload["canonicalSha256"] = MODULE.bytes_sha256(MODULE.canonical(payload).encode())
                with tempfile.TemporaryDirectory() as directory, patch.multiple(
                    MODULE,
                    WORKBENCH_RECOVERY_TERMINAL_REVISION=journal["protectedRevision"],
                    WORKBENCH_RECOVERY_TERMINAL_JOURNAL_FILE_SHA256=journal_file_sha256,
                    WORKBENCH_RECOVERY_TERMINAL_JOURNAL_CANONICAL_SHA256=journal["journalSha256"],
                    WORKBENCH_RECOVERY_FINALIZATION_PARENT_REVISION="c" * 40,
                ):
                    root = Path(directory)
                    receipt_bound = MODULE.bind_bytes_to_fd((MODULE.canonical(payload) + "\n").encode(), root / "receipt.bound", "recovery receipt")
                    journal_bound = MODULE.bind_bytes_to_fd((MODULE.canonical(journal) + "\n").encode(), root / "journal.bound", "recovery journal")
                    try:
                        with self.assertRaisesRegex(MODULE.LiveTransportError, message):
                            MODULE.verify_workbench_recovery_evidence(
                                receipt_bound, journal_bound, revision, terminal_finalization_expected=True
                            )
                    finally:
                        receipt_bound.close(); journal_bound.close()

    def test_recovery_verifier_rejects_after_only_synthetic_delete_event(self):
        payload, journal, revision = recovery_verifier_fixture(synthetic_after_only=True)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt_bound = MODULE.bind_bytes_to_fd((MODULE.canonical(payload) + "\n").encode(), root / "receipt.bound", "recovery receipt")
            journal_bound = MODULE.bind_bytes_to_fd((MODULE.canonical(journal) + "\n").encode(), root / "journal.bound", "recovery journal")
            try:
                with self.assertRaisesRegex(MODULE.LiveTransportError, "after event without prior delete intent"):
                    MODULE.verify_workbench_recovery_evidence(receipt_bound, journal_bound, revision)
            finally:
                receipt_bound.close(); journal_bound.close()

    def test_recovery_verifier_rejects_misplaced_resume_terminal_and_unknown_operations(self):
        cases = (
            ("uncertain-without-resume", {"omit_first_resume": True}, "resumed absence grammar drift"),
            ("wrong-resume-revision", {"wrong_resume_revision": True}, "resume grammar drift"),
            ("non-complete-terminal", {"terminal_operation": "not-complete"}, "terminal grammar drift"),
            ("unknown-operation", {"unknown_operation": True}, "unknown journal operation"),
        )
        for label, arguments, message in cases:
            with self.subTest(label=label):
                payload, journal, revision = recovery_verifier_fixture(**arguments)
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    receipt_bound = MODULE.bind_bytes_to_fd((MODULE.canonical(payload) + "\n").encode(), root / "receipt.bound", "recovery receipt")
                    journal_bound = MODULE.bind_bytes_to_fd((MODULE.canonical(journal) + "\n").encode(), root / "journal.bound", "recovery journal")
                    try:
                        with self.assertRaisesRegex(MODULE.LiveTransportError, message):
                            MODULE.verify_workbench_recovery_evidence(receipt_bound, journal_bound, revision)
                    finally:
                        receipt_bound.close(); journal_bound.close()

    def test_recovery_verifier_rejects_missing_or_wrong_uid_on_resumed_absence(self):
        for arguments in ({"wrong_absent_uid": True}, {"missing_absent_uid": True}):
            with self.subTest(arguments=arguments):
                payload, journal, revision = recovery_verifier_fixture(**arguments)
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    receipt_bound = MODULE.bind_bytes_to_fd((MODULE.canonical(payload) + "\n").encode(), root / "receipt.bound", "recovery receipt")
                    journal_bound = MODULE.bind_bytes_to_fd((MODULE.canonical(journal) + "\n").encode(), root / "journal.bound", "recovery journal")
                    try:
                        with self.assertRaisesRegex(MODULE.LiveTransportError, "resumed absence grammar drift"):
                            MODULE.verify_workbench_recovery_evidence(receipt_bound, journal_bound, revision)
                    finally:
                        receipt_bound.close(); journal_bound.close()

    def test_recovery_verifier_requires_a_resume_after_the_same_objects_uncertain_delete(self):
        payload, journal, revision = recovery_verifier_fixture(role_uncertain_after_earlier_resume=True)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt_bound = MODULE.bind_bytes_to_fd((MODULE.canonical(payload) + "\n").encode(), root / "receipt.bound", "recovery receipt")
            journal_bound = MODULE.bind_bytes_to_fd((MODULE.canonical(journal) + "\n").encode(), root / "journal.bound", "recovery journal")
            try:
                with self.assertRaisesRegex(MODULE.LiveTransportError, "resumed absence grammar drift"):
                    MODULE.verify_workbench_recovery_evidence(receipt_bound, journal_bound, revision)
            finally:
                receipt_bound.close(); journal_bound.close()

    def test_workbench_launcher_rechecks_pinned_kubectl_for_each_adapter_call(self):
        source = MODULE.WORKBENCH_IMPLEMENTATION_LAUNCHER
        self.assertIn("class _PinnedKubernetesAdapter", source)
        self.assertGreaterEqual(source.count("_verify_pinned_kubectl()"), 4)
        self.assertIn("bool(current.st_flags & stat.UF_IMMUTABLE)", source)
        self.assertIn("result=super()._run(args,input_text=input_text)", source)


if __name__ == "__main__": unittest.main()
