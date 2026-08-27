from __future__ import annotations

import importlib.util, json, os, socket, stat, sys, tempfile, threading, unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "participant_live_wrapper_under_test",
    ROOT / "scripts/run-staging-participant-gateway-live.py",
)
MODULE = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = MODULE; SPEC.loader.exec_module(MODULE)

class ParticipantLiveWrapperTests(unittest.TestCase):
    def test_wireproxy_configuration_contains_only_two_static_exact_tunnels(self):
        password = "a" * 64
        value = MODULE.wireproxy_config(53161, 53162)
        self.assertEqual(value.count("[TCPClientTunnel]"), 2)
        self.assertIn("BindAddress = 127.0.0.1:53161", value)
        self.assertIn("Target = 10.255.240.11:6443", value)
        self.assertIn("BindAddress = 127.0.0.1:53162", value)
        self.assertIn("Target = 10.255.240.11:50000", value)
        self.assertNotIn("[http]", value)
        self.assertNotIn("[Socks5]", value)
        self.assertNotIn("TunnelDomains", value)
        self.assertNotIn("0.0.0.0", value)
        self.assertEqual(
            MODULE.proxy_url(password, 53161),
            f"http://stadtstack-participant:{password}@127.0.0.1:53161",
        )
        for api_port, talos_port in ((0, 53162), (80, 53162), (65536, 53162), (53161, 53161)):
            with self.subTest(api_port=api_port, talos_port=talos_port), self.assertRaises(MODULE.LiveTransportError):
                MODULE.wireproxy_config(api_port, talos_port)

    def test_exact_connect_guard_rejects_method_authority_and_auth_then_relays_exact_backend(self):
        backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend.bind(("127.0.0.1", 0)); backend.listen(1)
        backend_port = backend.getsockname()[1]
        guard = MODULE.ExactConnectProxy(
            f"{MODULE.API_HOST}:{MODULE.API_PORT}", backend_port,
            MODULE.PROXY_USERNAME, "a" * 64,
        )
        guard_port = guard.start()
        self.addCleanup(guard.close); self.addCleanup(backend.close)

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

    def test_child_exit_transport_race_defers_classification_to_durable_receipt(self):
        session = MODULE.LiveSession(
            Path("/private/tmp"), Path("/bin/false"), 53161, 53162,
            "a" * 64, "b" * 64,
        )
        child = Mock(returncode=0)
        child.communicate.return_value = ("ok", "")
        with patch.object(session, "transport_alive", side_effect=[True, False]), patch.object(MODULE.subprocess, "Popen", return_value=child):
            result = session.run_child(["protected-runner"], {})
        self.assertEqual(result.returncode, 0)
        self.assertFalse(result.transport_alive_after)
        self.assertTrue(session.child_receipt_pending)
        session.handle_signal(MODULE.signal.SIGTERM, None)
        self.assertEqual(session.signals, [MODULE.signal.SIGTERM])
        self.assertTrue(MODULE.durable_activation_committed(result, "activated"))
        self.assertFalse(MODULE.durable_activation_committed(result, "rollback-complete"))
        session.receipt_reconciled()
        with patch.object(session, "transport_alive", return_value=True), self.assertRaisesRegex(MODULE.LiveTransportError, "operator signal"):
            session.run_child(["must-not-start"], {})

    def test_subprocess_environment_removes_every_ambient_proxy_and_kubeconfig(self):
        hostile = {
            "PATH": "/usr/bin", "HTTP_PROXY": "http://attacker", "https_proxy": "http://attacker",
            "ALL_PROXY": "socks5://attacker", "no_proxy": "*", "KUBECONFIG": "/attacker",
            "PYTHONPATH": "/attacker", "SAFE": "yes",
        }
        with patch.dict(MODULE.os.environ, hostile, clear=True):
            self.assertEqual(MODULE.sanitized_environment(), {"PATH": "/usr/bin", "SAFE": "yes"})

    def test_private_inputs_reject_symlinks_and_receipt_is_closed_without_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); private = root / "private"; private.write_text("super-secret-value"); private.chmod(0o600)
            link = root / "link"; link.symlink_to(private)
            with self.assertRaisesRegex(MODULE.LiveTransportError, "symlink"):
                MODULE.private_file(link, "fixture")
            receipt = root / "receipt.json"
            value = {
                "schemaVersion": MODULE.WRAPPER_RECEIPT_SCHEMA,
                "status": "blocked",
                "containsSecretMaterial": False,
                "civicAuthorityEffects": False,
            }
            MODULE.write_wrapper_receipt(receipt, value)
            stored = json.loads(receipt.read_text()); checksum = stored.pop("canonicalSha256")
            self.assertEqual(checksum, MODULE.bytes_sha256(MODULE.canonical(stored).encode()))
            self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)
            self.assertNotIn("super-secret-value", receipt.read_text())

    def test_wrapper_keeps_proxy_in_separate_session_and_forwards_signals_only_to_runner(self):
        source = (ROOT / MODULE.SELF_PATH).read_text()
        self.assertIn("start_new_session=True", source)
        self.assertIn("os.killpg(self.child.pid, received)", source)
        self.assertIn("stop_process(self.proxy)", source)
        self.assertLess(source.index("session.start_proxy(config)"), source.index("participant-flux-bootstrap.json"))
        self.assertLess(source.index("participant-flux-bootstrap.json"), source.index("participant-gateway-activation.json"))
        self.assertIn('"rootlessTransportRemoved": session is not None and session.proxy is None', source)

    def test_wrapper_delegates_all_kubernetes_writes_to_the_two_protected_runners(self):
        source = (ROOT / MODULE.SELF_PATH).read_text()
        self.assertIn(MODULE.BOOTSTRAP_RUNNER, source)
        self.assertIn(MODULE.ACTIVATION_RUNNER, source)
        for forbidden in ("kubectl apply", "kubectl create", "kubectl patch", "kubectl delete", "--server", "--token"):
            self.assertNotIn(forbidden, source)
        self.assertEqual(set(MODULE.EXPECTED_BINARIES), {"age", "kubectl", "talosctl", "wireproxy"})
        self.assertTrue(all(MODULE.SHA256.fullmatch(value) for value in MODULE.EXPECTED_BINARIES.values()))

if __name__ == "__main__": unittest.main()
