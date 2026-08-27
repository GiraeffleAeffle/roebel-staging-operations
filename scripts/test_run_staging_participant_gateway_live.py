from __future__ import annotations

import importlib.util, inspect, json, os, select, socket, stat, sys, tempfile, threading, time, unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "participant_live_wrapper_under_test",
    ROOT / "scripts/run-staging-participant-gateway-live.py",
)
MODULE = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = MODULE; SPEC.loader.exec_module(MODULE)


class AuthenticatedUpstream:
    def __init__(self, backend_port: int, password: str):
        self.backend_port, self.password = backend_port, password
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0)); self.listener.listen(8); self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.stopping = threading.Event(); self.workers: list[threading.Thread] = []
        self.thread = threading.Thread(target=self._serve, daemon=False); self.thread.start()
        self.authorities: list[str] = []

    def _serve(self) -> None:
        while not self.stopping.is_set():
            try: connection, _ = self.listener.accept()
            except socket.timeout: continue
            except OSError: return
            worker = threading.Thread(target=self._connection, args=(connection,), daemon=False)
            self.workers.append(worker); worker.start()

    def _connection(self, connection: socket.socket) -> None:
        backend = None
        try:
            head, remainder = MODULE.ExactConnectProxy._read_head(connection)
            if remainder:
                connection.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"); return
            lines = head.decode("ascii").split("\r\n"); request = lines[0].split(" ")
            headers = {name.lower(): value.strip() for name, value in (line.split(":", 1) for line in lines[1:])}
            expected = MODULE.ExactConnectProxy._authorization(MODULE.UPSTREAM_USERNAME, self.password)
            supplied = headers.get("proxy-authorization")
            if supplied is None:
                connection.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n"); return
            if supplied != expected:
                connection.sendall(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"); return
            authority = request[1]; self.authorities.append(authority)
            if request[0] != "CONNECT" or authority != f"{MODULE.API_HOST}:{MODULE.API_PORT}":
                connection.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"); return
            backend = socket.create_connection(("127.0.0.1", self.backend_port), timeout=2)
            connection.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            connection.settimeout(None); backend.settimeout(None)
            peers = {connection: backend, backend: connection}
            while not self.stopping.is_set():
                readable, _, _ = select.select(list(peers), [], [], 0.1)
                for source in readable:
                    value = source.recv(4096)
                    if not value: return
                    peers[source].sendall(value)
        finally:
            for current in (backend, connection):
                if current is None: continue
                try: current.close()
                except OSError: pass

    def close(self) -> None:
        self.stopping.set()
        try: self.listener.close()
        except OSError: pass
        self.thread.join(timeout=2)
        for worker in self.workers: worker.join(timeout=2)


class ParticipantLiveWrapperTests(unittest.TestCase):
    def test_wireproxy_configuration_exposes_one_authenticated_upstream_only(self):
        password = "a" * 64
        value = MODULE.wireproxy_config(53161)
        self.assertEqual(value.count("[http]"), 1)
        self.assertIn("BindAddress = 127.0.0.1:53161", value)
        self.assertIn(f"Username = ${MODULE.WIREPROXY_USERNAME_ENV}", value)
        self.assertIn(f"Password = ${MODULE.WIREPROXY_PASSWORD_ENV}", value)
        self.assertNotIn("[TCPClientTunnel]", value)
        self.assertNotIn("[Socks5]", value)
        self.assertNotIn("Target =", value)
        self.assertNotIn("0.0.0.0", value)
        self.assertEqual(
            MODULE.proxy_url(password, 53161),
            f"http://stadtstack-participant:{password}@127.0.0.1:53161",
        )
        for port in (0, 80, 65536):
            with self.subTest(port=port), self.assertRaises(MODULE.LiveTransportError):
                MODULE.wireproxy_config(port)

    def test_raw_upstream_requires_separate_auth_and_guard_relays_only_exact_authority(self):
        backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend.bind(("127.0.0.1", 0)); backend.listen(1)
        upstream = AuthenticatedUpstream(backend.getsockname()[1], "b" * 64)
        guard = MODULE.ExactConnectProxy(
            f"{MODULE.API_HOST}:{MODULE.API_PORT}", upstream.port, "a" * 64, "b" * 64,
        )
        guard_port = guard.start()
        self.addCleanup(backend.close); self.addCleanup(upstream.close); self.addCleanup(guard.close)

        with socket.create_connection(("127.0.0.1", upstream.port), timeout=2) as raw:
            raw.sendall(b"CONNECT 10.255.240.11:6443 HTTP/1.1\r\nHost: 10.255.240.11:6443\r\n\r\n")
            self.assertIn(b" 407 ", raw.recv(4096))

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
        self.assertEqual(upstream.authorities, [f"{MODULE.API_HOST}:{MODULE.API_PORT}"])

    def test_guard_worker_count_is_bounded_and_close_joins_active_workers(self):
        guard = MODULE.ExactConnectProxy(
            f"{MODULE.API_HOST}:{MODULE.API_PORT}", 53161, "a" * 64, "b" * 64, max_workers=1,
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
        self.assertEqual(report["workerLimit"], 1)

    def test_early_signal_is_non_raising_and_prevents_process_creation(self):
        state = MODULE.CancellationState(); state.install(); self.addCleanup(state.restore)
        state.handle_signal(MODULE.signal.SIGTERM, None)
        self.assertEqual(state.signals, [MODULE.signal.SIGTERM])
        with patch.object(MODULE.subprocess, "Popen") as spawn, self.assertRaisesRegex(MODULE.LiveTransportInterrupted, "operator signal"):
            state.run(["must-not-start"])
        spawn.assert_not_called()

    def test_process_spawn_is_signal_masked_until_owned_group_is_registered(self):
        state = MODULE.CancellationState()
        process = Mock(pid=12345, returncode=0)
        process.communicate.return_value = ("", "")
        events: list[tuple[str, object]] = []
        def mask(operation, _signals):
            events.append(("mask", operation, state.active_process))
            return set()
        def spawn(*_args, **_kwargs):
            events.append(("spawn", state.active_process))
            return process
        with patch.object(MODULE.signal, "pthread_sigmask", side_effect=mask), patch.object(MODULE.subprocess, "Popen", side_effect=spawn):
            result = state.run(["fixture"], stdout=MODULE.subprocess.PIPE, stderr=MODULE.subprocess.PIPE, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(events[0][0:2], ("mask", MODULE.signal.SIG_BLOCK))
        self.assertEqual(events[1], ("spawn", None))
        self.assertEqual(events[2][0:2], ("mask", MODULE.signal.SIG_SETMASK))
        self.assertIs(events[2][2], process)

    def test_child_exit_signal_race_defers_to_deep_receipt_reconciliation(self):
        state = MODULE.CancellationState(); state.install(); self.addCleanup(state.restore)
        session = MODULE.LiveSession(
            Path("/private/tmp"), Path("/bin/false"), 53161,
            "c" * 64, "a" * 64, "b" * 64, state,
        )
        with patch.object(session, "transport_alive", side_effect=[True, False]):
            result = session.run_child([sys.executable, "-I", "-c", "pass"], {})
        self.assertEqual(result.returncode, 0)
        self.assertFalse(result.transport_alive_after)
        self.assertTrue(state.receipt_pending)
        state.handle_signal(MODULE.signal.SIGTERM, None)
        self.assertEqual(state.signals, [MODULE.signal.SIGTERM])
        session.receipt_reconciled()
        with patch.object(session, "transport_alive", return_value=True), self.assertRaisesRegex(MODULE.LiveTransportInterrupted, "operator signal"):
            session.run_child(["must-not-start"], {})
        state.begin_finalization(); self.assertTrue(state.cleanup_processes()["ownedProcessGroupsStopped"])

    def test_executable_snapshot_is_private_exclusive_fsynced_and_rehashed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / "source"; source.write_bytes(b"exact executable bytes"); source.chmod(0o700)
            destination = root / "snapshot"
            expected = MODULE.bytes_sha256(source.read_bytes())
            with patch.dict(MODULE.EXPECTED_BINARIES, {"fixture": expected}, clear=False):
                snapshot = MODULE.snapshot_binary(source, "fixture", destination)
                self.assertEqual(MODULE.file_sha256(snapshot), expected)
                self.assertEqual(stat.S_IMODE(snapshot.stat().st_mode), 0o500)
                self.assertEqual(snapshot.stat().st_nlink, 1)
                with self.assertRaises(FileExistsError):
                    MODULE.snapshot_binary(source, "fixture", destination)

    def test_private_inputs_and_receipts_reject_links_and_commit_closed_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); private = root / "private"; private.write_text("super-secret-value"); private.chmod(0o600)
            link = root / "link"; link.symlink_to(private)
            with self.assertRaisesRegex(MODULE.LiveTransportError, "symlink"):
                MODULE.private_file(link, "fixture")
            receipt = root / "receipt.json"
            sink = MODULE.WrapperReceiptSink.reserve(receipt)
            value = {
                "schemaVersion": MODULE.WRAPPER_RECEIPT_SCHEMA,
                "status": "blocked",
                "containsSecretMaterial": False,
                "civicAuthorityEffects": False,
            }
            checksum = sink.commit(value)
            stored = json.loads(receipt.read_text()); observed = stored.pop("canonicalSha256")
            self.assertEqual(observed, checksum)
            self.assertEqual(checksum, MODULE.bytes_sha256(MODULE.canonical(stored).encode()))
            self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)
            self.assertNotIn("super-secret-value", receipt.read_text())
            hardlink = root / "receipt-link"; os.link(receipt, hardlink)
            with self.assertRaisesRegex(MODULE.LiveTransportError, "nlink-one"):
                MODULE.owned_receipt_file_sha256(receipt)

    def test_subprocess_environment_removes_every_ambient_proxy_and_kubeconfig(self):
        hostile = {
            "PATH": "/usr/bin", "HTTP_PROXY": "http://attacker", "https_proxy": "http://attacker",
            "ALL_PROXY": "socks5://attacker", "no_proxy": "*", "KUBECONFIG": "/attacker",
            "PYTHONPATH": "/attacker", "SAFE": "yes",
        }
        with patch.dict(MODULE.os.environ, hostile, clear=True):
            self.assertEqual(MODULE.sanitized_environment(), {"PATH": "/usr/bin", "SAFE": "yes"})

    def test_post_commit_cleanup_failure_is_never_success_or_blocked(self):
        self.assertEqual(
            MODULE.classify_final_status("activated", activation_committed=True, operation_succeeded=True, cleanup_complete=False),
            ("activated-cleanup-incomplete", 3),
        )
        self.assertEqual(
            MODULE.classify_final_status("activated", activation_committed=True, operation_succeeded=True, cleanup_complete=True),
            ("activated", 0),
        )
        self.assertEqual(
            MODULE.classify_final_status("dormant-torn-down", activation_committed=False, operation_succeeded=True, cleanup_complete=False),
            ("dormant-teardown-cleanup-incomplete", 3),
        )

    def test_signal_state_prebinds_every_transitive_blob_before_snapshot_and_decrypt(self):
        expected = {
            MODULE.SELF_PATH,
            MODULE.BOOTSTRAP_RUNNER,
            MODULE.ACTIVATION_RUNNER,
            "scripts/staging_participant_flux_bootstrap.py",
            "scripts/staging_participant_gateway_policy.py",
            "policy/staging-participant-gateway-activation-policy.json",
            ".github/workflows/staging-participant-flux-bootstrap.yml",
            ".github/workflows/staging-participant-gateway-activation.yml",
            "scripts/verify-reviewed-render.py",
            "policy/repository-contract.json",
        }
        self.assertEqual(set(MODULE.PROTECTED_PATHS), expected)
        source = inspect.getsource(MODULE.main)
        self.assertLess(source.index("cancellation.install()"), source.index("bind_protected_checkout(revision)"))
        self.assertLess(source.index("bind_protected_checkout(revision)"), source.index("snapshot_binary("))
        self.assertLess(source.index("snapshot_binary("), source.index("decrypt("))
        self.assertIn("--verify-success-receipt", source)
        self.assertIn("--teardown-dormant-receipt", inspect.getsource(MODULE.parse_args))

    def test_wrapper_delegates_all_kubernetes_writes_to_protected_runners(self):
        source = inspect.getsource(MODULE.main)
        self.assertIn("str(ROOT / BOOTSTRAP_RUNNER)", source)
        self.assertIn("str(ROOT / ACTIVATION_RUNNER)", source)
        for forbidden in ("kubectl apply", "kubectl create", "kubectl patch", "kubectl delete", "--server", "--token"):
            self.assertNotIn(forbidden, source)
        self.assertEqual(set(MODULE.EXPECTED_BINARIES), {"age", "kubectl", "talosctl", "wireproxy"})
        self.assertTrue(all(MODULE.SHA256.fullmatch(value) for value in MODULE.EXPECTED_BINARIES.values()))


if __name__ == "__main__": unittest.main()
