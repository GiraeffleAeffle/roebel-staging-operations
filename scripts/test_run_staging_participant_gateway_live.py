from __future__ import annotations

import importlib.util, json, os, stat, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "participant_live_wrapper_under_test",
    ROOT / "scripts/run-staging-participant-gateway-live.py",
)
MODULE = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = MODULE; SPEC.loader.exec_module(MODULE)

class ParticipantLiveWrapperTests(unittest.TestCase):
    def test_wireproxy_configuration_is_authenticated_loopback_and_exact_destination(self):
        password = "a" * 64
        value = MODULE.wireproxy_config(password, 53161)
        self.assertIn("BindAddress = 127.0.0.1:53161", value)
        self.assertIn("Username = stadtstack-participant", value)
        self.assertIn(f"Password = {password}", value)
        self.assertIn(r"TunnelDomains = ^10\.255\.240\.11$", value)
        self.assertIn("LogDomains = false", value)
        self.assertNotIn("0.0.0.0", value)
        self.assertEqual(
            MODULE.proxy_url(password, 53161),
            f"http://stadtstack-participant:{password}@127.0.0.1:53161",
        )
        for bad_password, bad_port in (("a" * 63, 53161), ("g" * 64, 53161), (password, 0), (password, 80), (password, 65536)):
            with self.subTest(password=bad_password[:4], port=bad_port), self.assertRaises(MODULE.LiveTransportError):
                MODULE.wireproxy_config(bad_password, bad_port)

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
