import base64, contextlib, copy, datetime as dt, importlib.util, json, os, stat, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("activation", Path(__file__).with_name("activate-staging-participant-gateway.py"))
MODULE = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = MODULE; SPEC.loader.exec_module(MODULE)
REV = "a" * 40
MODULE.POLICY = MODULE.compile_verified_policy_module_v4(
    Path(__file__).with_name("staging_participant_gateway_policy.py").read_bytes(),
    REV,
)
MODULE.BOOTSTRAP = MODULE.compile_verified_bootstrap_module_v4(
    Path(__file__).with_name("staging_participant_flux_bootstrap.py").read_bytes(),
    REV,
)
def sha(x="a"): return "sha256:" + x * 64
def object_(kind, name=MODULE.NAME, namespace=MODULE.NAMESPACE, uid="uid", rv="10", **extra):
    value = {"apiVersion": "v1", "kind": kind, "metadata": {"name": name, "namespace": namespace, "uid": uid, "resourceVersion": rv}}; value.update(extra); return value
def policy():
    return copy.deepcopy(MODULE.POLICY.STATIC_ACTIVATION_POLICY)
def ready_policy():
    return MODULE.POLICY.approved_next_activation_policy_descriptor()
def admitted(desired, uid="owned-uid", rv="10"):
    value = copy.deepcopy(desired); value.setdefault("metadata", {})["uid"] = uid; value["metadata"]["resourceVersion"] = rv
    return value
def dormant_ownership():
    return {
        "schemaVersion": "roebel_staging_participant_flux_bootstrap_receipt_v1",
        "status": "dormant-ready",
        "receiptSha256": sha("b"),
        "protectedRevision": REV,
        "activationPolicySha256": MODULE.POLICY.activation_policy_sha256(ready_policy()),
        "objects": [
            {
                "logicalName": logical,
                "target": {"apiVersion": "v1", "kind": "Fixture", "namespace": "fixture", "name": logical},
                "uid": f"uid-{index}",
                "resourceVersion": "10",
                "desiredSemanticSha256": sha(str(index % 10)),
            }
            for index, logical in enumerate(MODULE.POLICY.DORMANT_BOOTSTRAP_OBJECT_ORDER)
        ],
        "bothKustomizationsSuspended": True,
    }
def valid_database_status(value, *, pod_name="gateway-pod-a", pod_uid="pod-uid", before="10", after="11", image_id=None):
    """A complete private readiness receipt, including provenance and RBAC."""
    image = value["productPins"]["imageRepository"] + "@" + value["productPins"]["imageManifestDigest"]
    return MODULE.expected_database_status_v4(value) | {
        "probe": {
            "transport": "authenticated-kubernetes-pod-port-forward",
            "pod": pod_name,
            "loopbackOnly": True,
            "publicIngressUsed": False,
            "serviceProxyUsed": False,
            "redirectsAllowed": False,
            "path": "/status",
            "remotePort": MODULE.POLICY.GATEWAY_PORT,
            "podUid": pod_uid,
            "podImage": image,
            "podImageId": image_id or "docker-pullable://" + image,
            "podReadyAfter": True,
            "podResourceVersionBefore": before,
            "podResourceVersionAfter": after,
        },
        "rbac": {"getPods": True, "listPods": True, "createPodsPortforward": True},
    }
def valid_success_facts(value):
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0); nonce = "a" * 64
    sections = {name: {"ok": True} for name in MODULE.POLICY.trusted_live_facts_contract()["requiredSections"] if name != "protectedRevision"}
    facts = {"schemaVersion": MODULE.POLICY.TRUSTED_LIVE_FACTS_SCHEMA, "policySha256": MODULE.POLICY.activation_policy_sha256(value), "collectedAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "validUntil": (now + dt.timedelta(seconds=300)).strftime("%Y-%m-%dT%H:%M:%SZ"), "maxAgeSeconds": 300, "protectedRevision": REV, **sections}
    cluster = {"apiOrigin": value["clusterIdentity"]["apiOrigin"], "caCertificateSha256": value["clusterIdentity"]["caCertificateSha256"], "apiServerSpkiSha256": value["clusterIdentity"]["apiServerSpkiSha256"], "kubeSystemNamespaceUid": value["clusterIdentity"]["kubeSystemNamespaceUid"]}
    facts["clusterBinding"] = {name: copy.deepcopy(cluster) for name in ("initial", "beforeMutation", "beforeIngress", "beforeFluxUnsuspend", "beforeSuccess")}
    facts["publication"] = {"manifestDigest": value["productPins"]["imageManifestDigest"], "verificationLevel": "anonymous-registry-manifest-digest-only", "cryptographicPublicationProvenanceVerified": False}
    facts["database"] = valid_database_status(value)
    facts["operationReservation"] = {"operationNonce": nonce, "absencePreflight": {"status": "all-six-exact-target-names-absent", "targets": [{"absent": True}] * 6}}
    facts["objectCreateResults"] = [{"operationNonce": nonce, "temporaryNonceRemoved": True} for _ in range(6)]
    facts["semanticObjects"] = {str(i): {"ok": True} for i in range(6)}
    source = {"uid": "source-uid", "resourceVersion": "10", "artifactRevision": f"main@sha1:{REV}"}
    ownership = dormant_ownership()
    facts["fluxTransaction"] = {
        "bootstrapReceiptSha256": ownership["receiptSha256"],
        "bootstrapObjectIdentities": ownership["objects"],
        "casUnsuspended": {"gateway": "11", "workbenchIngress": "21"},
        "ready": {"gateway": {}, "workbenchIngress": {}},
        "sourceBeforeCas": source,
        "sourceAfterReady": source | {"resourceVersion": "11"},
    }
    facts["preservation"] = {"webIngress": {"byteIdenticalCanonicalJson": True}, "existingWorkbenchNetworkPolicy": {"byteIdenticalCanonicalJson": True}}
    secret = {"status": "exact", "secrets": {"config": {"uid": "s"}}}
    facts["secretMaterialization"] = {"beforeCreate": secret, "beforeIngress": copy.deepcopy(secret), "afterFlux": copy.deepcopy(secret)}
    facts["networkPolicyConflictScan"] = {"beforeCreate": {"ok": True}, "beforeIngress": {"ok": True}, "afterFlux": {"ok": True}}
    facts["rollback"] = {"status": "not-required", "finalizersRemovedByRunner": False}
    return facts
class Fake(MODULE.Runner):
    def __init__(self): self.calls = []
    def run(self, args, *, input_text=None, timeout=10):
        self.calls.append((args, input_text))
        if args and args[0] == "curl": return MODULE.Result(out="200" if "GET" in args else "405")
        if " create " in " " + " ".join(args) + " ":
            manifest = json.loads(input_text); manifest["metadata"] |= {"uid": manifest["kind"].lower() + "-uid", "resourceVersion": "10"}
            return MODULE.Result(out=json.dumps(manifest))
        return MODULE.Result()

class ExecutorTests(unittest.TestCase):
    def test_missing_fixed_policy_blocks_before_any_runner_call(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(MODULE, "ROOT", Path(directory)):
            runner = Fake()
            with self.assertRaisesRegex(MODULE.ActivationError, "policy descriptor is not wired"):
                MODULE.policy(REV)
            self.assertEqual(runner.calls, [])
    def test_revision_and_policy_schema_are_closed(self):
        with self.assertRaisesRegex(MODULE.ActivationError, "lowercase"):
            MODULE.revision("A" * 40)
        value = policy(); value["httpBoundary"]["host"] = "example.test"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "policy").mkdir(); path = root / MODULE.POLICY_PATH; path.write_text(json.dumps(value))
            with patch.object(MODULE, "ROOT", root), patch.object(MODULE, "git_blob", return_value=path.read_bytes()):
                with self.assertRaisesRegex(MODULE.ActivationError, "policy drift"):
                    MODULE.policy(REV)

    def test_verified_policy_identity_must_match_runner_constants(self):
        MODULE.bind_verified_policy_identity_v4(MODULE.POLICY)
        drifted = Mock(**{
            "GATEWAY_NAMESPACE": MODULE.POLICY.GATEWAY_NAMESPACE,
            "FLUX_NAMESPACE": MODULE.POLICY.FLUX_NAMESPACE,
            "GATEWAY_NAME": "attacker-selected-gateway",
            "FLUX_SOURCE_NAME": MODULE.POLICY.FLUX_SOURCE_NAME,
            "WORKBENCH_NAMESPACE": MODULE.POLICY.WORKBENCH_NAMESPACE,
            "WORKBENCH_INGRESS_POLICY_NAME": MODULE.POLICY.WORKBENCH_INGRESS_POLICY_NAME,
            "POLICY_PATH": MODULE.POLICY.POLICY_PATH,
        })
        with self.assertRaisesRegex(MODULE.ActivationError, "runner/policy identity drift"):
            MODULE.bind_verified_policy_identity_v4(drifted)
    def test_inert_dry_run_reports_every_blocker_without_runner(self):
        value = policy(); hashes = {"runner": sha()}
        result = MODULE.dry_run_plan(value, REV, hashes)
        self.assertEqual(result["status"], "blocked-policy-incomplete")
        self.assertFalse(result["activationReady"])
        self.assertEqual(result["blockers"], list(MODULE.POLICY.activation_blockers(value)))
        self.assertFalse(result["kubernetesContacted"])
        self.assertEqual(result["protectedRunnerFileSha256"], hashes)
    def test_no_evidence_command_or_allowlist_surface_exists(self):
        source = Path(MODULE.__file__).read_text()
        self.assertNotIn("liveSemanticProjection", source)
        self.assertNotIn("preexistingSelectorAllowlist", source)
        self.assertNotIn("--evidence", source)
        self.assertNotIn("--render-root", source)
        self.assertNotIn("--gateway-url", source)

    def test_command_requires_isolated_mode_before_local_imports_and_policy_compilation(self):
        source = Path(MODULE.__file__).read_text()
        self.assertLess(source.index("runner_hashes = protected_checkout(rev)"), source.index("POLICY = compile_verified_policy_module_v4"))
        with tempfile.TemporaryDirectory() as directory:
            scripts = Path(directory) / "scripts"; scripts.mkdir()
            runner = scripts / "activate-staging-participant-gateway.py"; runner.write_text(source)
            marker = Path(directory) / "shadow-executed"
            (scripts / "secrets.py").write_text(f"from pathlib import Path\nPath({str(marker)!r}).write_text('unsafe')\n")
            args = [str(runner), "--dry-run", "--expected-protected-revision", REV, "--receipt", str(Path(directory) / "receipt.json")]
            unsafe = subprocess.run([sys.executable, *args], text=True, capture_output=True, check=False)
            self.assertEqual(unsafe.returncode, 2); self.assertIn("python3 -I", unsafe.stderr); self.assertFalse(marker.exists())
            isolated = subprocess.run([sys.executable, "-I", *args], text=True, capture_output=True, check=False)
            self.assertEqual(isolated.returncode, 2); self.assertIn("protected repository checkout", isolated.stderr); self.assertFalse(marker.exists())
    def test_empty_and_matching_selectors_are_rejected(self):
        self.assertTrue(MODULE._selector_matches_v4({}, MODULE.POLICY.GATEWAY_LABELS))
        self.assertTrue(MODULE._selector_matches_v4({"matchLabels": {"app.kubernetes.io/name": MODULE.NAME}}, MODULE.POLICY.GATEWAY_LABELS))
        self.assertTrue(MODULE._selector_matches_v4({"matchLabels": {"any:app.kubernetes.io/name": MODULE.NAME}}, MODULE.POLICY.GATEWAY_LABELS))
        self.assertFalse(MODULE._selector_matches_v4({"matchLabels": {"app.kubernetes.io/name": "other"}}, MODULE.POLICY.GATEWAY_LABELS))
        self.assertTrue(MODULE._selector_could_match_with_additional_labels_v4({"matchLabels": {"pod-template-hash": "future"}}, MODULE.POLICY.GATEWAY_LABELS))
        self.assertTrue(MODULE._selector_could_match_with_additional_labels_v4({"matchLabels": {"k8s:io.cilium.k8s.policy.serviceaccount": MODULE.NAME}}, MODULE.POLICY.GATEWAY_LABELS))
        self.assertFalse(MODULE._selector_could_match_with_additional_labels_v4({"matchLabels": {"app.kubernetes.io/name": "other"}}, MODULE.POLICY.GATEWAY_LABELS))
    def test_live_gate_fails_before_runner_or_kubeconfig_validation(self):
        value = policy()
        with self.assertRaisesRegex(MODULE.POLICY.PolicyError, "activation blocked"):
            MODULE.POLICY.assert_activation_ready(value)
        self.assertFalse(value["activationReady"])

    def test_exact_approved_successor_can_pass_the_future_gate_without_runner_code_changes(self):
        value = ready_policy()
        self.assertEqual(MODULE.POLICY.validate_activation_policy(value), value)
        self.assertEqual(MODULE.POLICY.assert_activation_ready(value), value)
        self.assertEqual(MODULE.POLICY.activation_blockers(value), ())

    def test_live_activation_requires_bootstrap_receipt_before_runner_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            kube = Path(directory) / "kubeconfig"
            kube.write_text("not read")
            with self.assertRaisesRegex(MODULE.ActivationError, "requires exact dormant Flux bootstrap receipt"):
                MODULE.activate(
                    ready_policy(),
                    REV,
                    str(kube),
                    Fake(),
                    True,
                    Mock(),
                    {"runner": sha()},
                    None,
                )

    def test_flux_preflight_binds_all_eight_live_uids_to_bootstrap_receipt(self):
        value = ready_policy()
        objects = []
        live = []
        for owner, builder in (
            ("gateway", MODULE.POLICY.gateway_flux_objects),
            ("workbenchIngress", MODULE.POLICY.workbench_ingress_flux_objects),
        ):
            desired = builder(suspended=True)
            for key in ("serviceAccount", "role", "roleBinding", "kustomization"):
                observed = admitted(desired[key], f"{owner}-{key}-uid", "21")
                live.append(observed)
                objects.append({
                    "logicalName": f"{owner}.{key}",
                    "target": value["gitOps"]["reconcilers"][owner][key],
                    "uid": observed["metadata"]["uid"],
                    "resourceVersion": "20",
                    "desiredSemanticSha256": MODULE.POLICY.semantic_sha256(desired[key]),
                })
        ownership = {
            "status": "dormant-ready",
            "receiptSha256": sha("b"),
            "protectedRevision": REV,
            "activationPolicySha256": MODULE.POLICY.activation_policy_sha256(value),
            "objects": objects,
            "bothKustomizationsSuspended": True,
        }
        source = {"metadata": {"uid": "source"}, "status": {"artifact": {"revision": f"main@sha1:{REV}"}}}
        with patch.object(MODULE, "shared_source_revision_v4", return_value=source), patch.object(
            MODULE,
            "_target_live",
            side_effect=live,
        ):
            result = MODULE.flux_preflight_v4(Fake(), "/snapshot", value, REV, ownership)
        self.assertEqual(result["bootstrapReceipt"]["receiptSha256"], sha("b"))
        self.assertEqual(set(result["owners"]), {"gateway", "workbenchIngress"})

        drifted = copy.deepcopy(ownership)
        drifted["objects"][0]["uid"] = "foreign"
        with patch.object(MODULE, "shared_source_revision_v4", return_value=source), patch.object(
            MODULE,
            "_target_live",
            side_effect=live,
        ):
            with self.assertRaisesRegex(MODULE.ActivationError, "no longer matches bootstrap receipt identity"):
                MODULE.flux_preflight_v4(Fake(), "/snapshot", value, REV, drifted)

    def test_duplicate_json_keys_are_rejected_at_every_object_boundary(self):
        with self.assertRaisesRegex(MODULE.ActivationError, "duplicate"):
            MODULE.obj('{"metadata":{},"metadata":{}}', "duplicate fixture")
        with self.assertRaisesRegex(MODULE.ActivationError, "duplicate"):
            MODULE.json_value('{"nested":{"key":1,"key":2}}', "duplicate nested fixture")

    def test_receipt_sink_is_reserved_0600_non_overwriting_and_durable(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "receipts" / "activation.json"
            sink = MODULE.ReceiptSink.reserve(target)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            sink.commit({"status": "test", "civicAuthorityEffects": False})
            committed = json.loads(target.read_text())
            self.assertEqual(committed["status"], "test")
            self.assertIn("canonicalSha256", committed)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                MODULE.ReceiptSink.reserve(target)

    def test_kubeconfig_snapshot_is_single_flattened_0600_file_and_rejects_url_tricks(self):
        pem = b"-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n"
        def flattened(server, proxy=None):
            cluster = {"server": server, "certificate-authority-data": base64.b64encode(pem).decode()}
            if proxy is not None: cluster["proxy-url"] = proxy
            return json.dumps({
                "apiVersion": "v1", "kind": "Config", "current-context": "ctx",
                "clusters": [{"name": "cluster", "cluster": cluster}],
                "contexts": [{"name": "ctx", "context": {"cluster": "cluster", "user": "user"}}],
                "users": [{"name": "user", "user": {"token": "secret-never-receipted"}}],
            })
        class Flatten(MODULE.Runner):
            def __init__(self, raw): self.raw = raw; self.calls = []
            def run(self, args, *, input_text=None, timeout=10): self.calls.append(args); return MODULE.Result(out=self.raw)
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "original"; original.write_text("not-read-by-test-runner")
            runner = Flatten(flattened("https://api.example.test:6443"))
            snapshot = MODULE.snapshot_kubeconfig_v4(str(original), runner)
            try:
                self.assertEqual(snapshot.api_origin, "https://api.example.test:6443")
                self.assertIsNone(snapshot.connect_proxy)
                self.assertEqual(stat.S_IMODE(snapshot.path.stat().st_mode), 0o600)
                self.assertEqual(len(runner.calls), 1)
                self.assertIn("--flatten", runner.calls[0]); self.assertIn("--raw", runner.calls[0])
            finally: snapshot.close()
            self.assertFalse(snapshot.path.exists())
            proxy_password = "a" * 64
            proxy_url = f"http://stadtstack-participant:{proxy_password}@127.0.0.1:16443"
            proxied = MODULE.snapshot_kubeconfig_v4(
                str(original),
                Flatten(flattened("https://api.example.test:6443", proxy_url)),
            )
            try:
                self.assertEqual(proxied.api_origin, "https://api.example.test:6443")
                self.assertEqual(proxied.connect_proxy.host, "127.0.0.1")
                self.assertEqual(proxied.connect_proxy.port, 16443)
                self.assertEqual(proxied.connect_proxy.origin, proxy_url)
                stored = json.loads(proxied.path.read_text())
                self.assertEqual(stored["clusters"][0]["cluster"]["proxy-url"], proxy_url)
            finally: proxied.close()
            for bad in ("https://user@api.example.test:6443", "https://api.example.test:6443/path", "https://api.example.test:6443?x=1", "https://api.example.test:6443#x"):
                with self.assertRaisesRegex(MODULE.ActivationError, "HTTPS origin"):
                    MODULE.snapshot_kubeconfig_v4(str(original), Flatten(flattened(bad)))
            for bad_proxy in (
                "http://127.0.0.1:16443", "https://127.0.0.1:16443", "http://localhost:16443", "http://127.0.0.2:16443",
                "http://[::1]:16443", "http://127.0.0.1", "http://127.0.0.1:0",
                "http://user@127.0.0.1:16443", "http://127.0.0.1:16443/",
                "http://127.0.0.1:16443?x=1", "http://127.0.0.1:16443#x",
                f"http://stadtstack-participant:{'b' * 63}@127.0.0.1:16443",
                f"http://wrong-user:{'b' * 64}@127.0.0.1:16443",
                123,
            ):
                with self.subTest(proxy=bad_proxy), self.assertRaisesRegex(MODULE.ActivationError, "loopback HTTP CONNECT proxy"):
                    MODULE.snapshot_kubeconfig_v4(
                        str(original),
                        Flatten(flattened("https://api.example.test:6443", bad_proxy)),
                    )

            failed_snapshot = Path(directory) / "failed-snapshot"
            def make_failed_snapshot(*_args, **_kwargs):
                failed_snapshot.mkdir(mode=0o700)
                return str(failed_snapshot)
            with patch.object(MODULE.tempfile, "mkdtemp", side_effect=make_failed_snapshot), patch.object(MODULE.os, "fsync", side_effect=OSError("injected fsync failure")):
                with self.assertRaisesRegex(OSError, "injected fsync failure"):
                    MODULE.snapshot_kubeconfig_v4(str(original), Flatten(flattened("https://api.example.test:6443")))
            self.assertFalse(failed_snapshot.exists(), "failed credential snapshot must be removed")

    def test_api_spki_probe_uses_exact_connect_authority_then_end_to_end_tls(self):
        class Connection:
            def __init__(self, response): self.response = bytearray(response); self.sent = b""; self.closed = False
            def sendall(self, value): self.sent += value
            def recv(self, size):
                self.asserted_size = size
                if not self.response: return b""
                value = bytes(self.response[:1]); del self.response[:1]; return value
            def close(self): self.closed = True
            def __enter__(self): return self
            def __exit__(self, *_args): self.close(); return False
        class Secured:
            def getpeercert(self, binary_form=False):
                self.binary_form = binary_form; return b"certificate-der"
            def __enter__(self): return self
            def __exit__(self, *_args): return False
        class Context:
            def __init__(self): self.wrapped = []
            def wrap_socket(self, connection, server_hostname):
                self.wrapped.append((connection, server_hostname)); return Secured()
        connection = Connection(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: wireproxy\r\n\r\n")
        context = Context()
        snapshot = Mock(
            hostname="10.255.240.11", port=6443, tls_server_name="kubernetes",
            ca_pem=b"-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n",
            connect_proxy=MODULE.LoopbackConnectProxy(
                f"http://stadtstack-participant:{'c' * 64}@127.0.0.1:53161",
                "127.0.0.1", 53161, "stadtstack-participant", "c" * 64,
            ),
        )
        openssl = [
            subprocess.CompletedProcess([], 0, b"public-key-pem", b""),
            subprocess.CompletedProcess([], 0, b"public-key-der", b""),
        ]
        with patch.object(MODULE.socket, "create_connection", return_value=connection) as connect, patch.object(
            MODULE.ssl, "create_default_context", return_value=context,
        ) as create_context, patch.object(MODULE.subprocess, "run", side_effect=openssl):
            result = MODULE._api_server_spki_v4(snapshot, 3)
        connect.assert_called_once_with(("127.0.0.1", 53161), timeout=3)
        proxy_authorization = base64.b64encode(("stadtstack-participant:" + "c" * 64).encode("ascii"))
        self.assertEqual(
            connection.sent,
            b"CONNECT 10.255.240.11:6443 HTTP/1.1\r\nHost: 10.255.240.11:6443\r\n"
            + b"Proxy-Authorization: Basic " + proxy_authorization + b"\r\n\r\n",
        )
        self.assertEqual(context.wrapped, [(connection, "kubernetes")])
        create_context.assert_called_once_with(cadata=snapshot.ca_pem.decode("ascii"))
        self.assertEqual(result, MODULE.bytes_digest(b"public-key-der"))
        self.assertTrue(connection.closed)

    def test_api_connect_proxy_rejects_non_success_incomplete_and_oversized_responses(self):
        class Connection:
            def __init__(self, response): self.response = bytearray(response); self.closed = False
            def sendall(self, _value): pass
            def recv(self, _size):
                if not self.response: return b""
                value = bytes(self.response[:1]); del self.response[:1]; return value
            def close(self): self.closed = True
        snapshot = Mock(
            hostname="10.255.240.11", port=6443,
            connect_proxy=MODULE.LoopbackConnectProxy(
                f"http://stadtstack-participant:{'d' * 64}@127.0.0.1:53161",
                "127.0.0.1", 53161, "stadtstack-participant", "d" * 64,
            ),
        )
        cases = (
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
            b"HTTP/1.1 301 Moved Permanently\r\n\r\n",
            b"HTTP/1.1 200 Connection Established\r\n",
            b"NOT HTTP\r\n\r\n",
            b"HTTP/1.1 2000 Not A Status\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nMalformed-Header\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX:" + b"a" * 8192 + b"\r\n\r\n",
        )
        for response in cases:
            connection = Connection(response)
            with self.subTest(response=response[:40]), patch.object(MODULE.socket, "create_connection", return_value=connection), self.assertRaises(MODULE.ActivationError):
                MODULE._api_tcp_transport_v4(snapshot, 3)
            self.assertTrue(connection.closed)

    def test_kubectl_subprocesses_ignore_ambient_proxy_environment(self):
        hostile = {
            "PATH": "/usr/bin", "HTTPS_PROXY": "http://attacker.invalid:8080",
            "http_proxy": "http://attacker.invalid:8080", "ALL_PROXY": "socks5://attacker.invalid:1080",
            "no_proxy": "*", "SAFE_MARKER": "retained",
        }
        completed = subprocess.CompletedProcess([], 0, "ok", "")
        with patch.dict(MODULE.os.environ, hostile, clear=True), patch.object(MODULE.subprocess, "run", return_value=completed) as run:
            result = MODULE.Runner().run(["kubectl", "version"])
        self.assertEqual(result.out, "ok")
        child_env = run.call_args.kwargs["env"]
        self.assertEqual(child_env, {"PATH": "/usr/bin", "SAFE_MARKER": "retained"})

    def test_raw_delete_proxy_exposes_only_the_exact_escaped_resource_path(self):
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *_args): return False
        class Opener:
            def open(self, request, timeout):
                self.request, self.timeout = request, timeout
                return Response()
        class Process:
            def __init__(self):
                read_fd, write_fd = os.pipe()
                os.write(write_fd, b"Starting to serve on 127.0.0.1:41777\n"); os.close(write_fd)
                self.stdout = os.fdopen(read_fd, "rb", buffering=0); self.terminated = False
            def poll(self): return None
            def terminate(self): self.terminated = True
            def wait(self, timeout): return 0
            def kill(self): self.terminated = True
        resource_path = f"/apis/networking.k8s.io/v1/namespaces/{MODULE.NAMESPACE}/networkpolicies/{MODULE.NAME}"
        process, opener = Process(), Opener()
        with patch.object(MODULE.subprocess, "Popen", return_value=process) as popen, patch.object(MODULE.urllib.request, "build_opener", return_value=opener):
            MODULE.raw_delete("/snapshot", resource_path, '{"kind":"DeleteOptions"}')
        command = popen.call_args.args[0]
        self.assertIn("--address=127.0.0.1", command)
        self.assertIn("--accept-hosts=^127\\.0\\.0\\.1$", command)
        self.assertIn("--accept-paths=^" + resource_path.replace(".", r"\.") + "$", command)
        self.assertFalse({"http_proxy", "https_proxy", "all_proxy", "no_proxy"} & {key.lower() for key in popen.call_args.kwargs["env"]})
        self.assertEqual(opener.request.full_url, "http://127.0.0.1:41777" + resource_path)
        self.assertEqual(opener.request.method, "DELETE"); self.assertTrue(process.terminated); self.assertTrue(process.stdout.closed)
        with patch.object(MODULE.subprocess, "Popen") as forbidden:
            with self.assertRaisesRegex(MODULE.ActivationError, "outside closed policy"):
                MODULE.raw_delete("/snapshot", resource_path + "?watch=true", "{}")
        forbidden.assert_not_called()
    def test_definite_create_conflict_is_never_treated_as_uncertain(self):
        class Conflict(MODULE.Runner):
            def run(self, args, *, input_text=None):
                return MODULE.Result(1, "", "Error from server (AlreadyExists): object exists")
        with self.assertRaises(MODULE.CreateConflictError):
            MODULE.checked(Conflict(), ["kubectl", "create"], "create NetworkPolicy", "{}")

    def test_only_transport_failure_enters_uncertain_create_class(self):
        class TimedOut(MODULE.Runner):
            def run(self, args, *, input_text=None):
                return MODULE.Result(124, "", "timeout after 30s")
        with self.assertRaises(MODULE.TransportUncertainError):
            MODULE.checked(TimedOut(), ["kubectl", "create"], "create NetworkPolicy", "{}")

    def test_v4_definite_409_never_discovers_or_adopts(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy()
        rendered = {"desired": desired, "path": "fixed", "blobSha256": sha()}
        class Conflict(MODULE.Runner):
            def run(self, args, *, input_text=None, timeout=10): return MODULE.Result(1, "", "HTTP 409 AlreadyExists")
        with patch.object(MODULE, "live_obj") as discover:
            with self.assertRaises(MODULE.CreateConflictError):
                MODULE.create_v4(Conflict(), "/tmp/kube", "workbenchIngress.networkPolicy", rendered, "a" * 64)
        discover.assert_not_called()

    def test_v4_transport_uncertainty_discovers_exact_uid_rv(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy(); nonce = "a" * 64
        observed = admitted(MODULE.POLICY.with_operation_nonce(desired, nonce))
        rendered = {"desired": desired, "path": "fixed", "blobSha256": sha()}
        class ServerError(MODULE.Runner):
            def run(self, args, *, input_text=None, timeout=10): return MODULE.Result(1, "", "HTTP 503")
        with patch.object(MODULE, "live_obj", return_value=observed) as discover:
            result = MODULE.create_v4(ServerError(), "/tmp/kube", "workbenchIngress.networkPolicy", rendered, nonce)
        discover.assert_called_once()
        self.assertTrue(result.receipt["discoveredAfterPostSendUncertainty"])
        self.assertEqual(result.receipt["uid"], "owned-uid")
        self.assertEqual(result.receipt["resourceVersion"], "10")

    def test_v4_malformed_success_response_discovers_and_owns_only_exact_nonce(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy(); nonce = "b" * 64
        observed = admitted(MODULE.POLICY.with_operation_nonce(desired, nonce))
        rendered = {"desired": desired, "path": "fixed", "blobSha256": sha()}
        class Malformed(MODULE.Runner):
            def run(self, args, *, input_text=None, timeout=10): return MODULE.Result(0, "{malformed", "")
        with patch.object(MODULE, "live_obj", return_value=observed):
            result = MODULE.create_v4(Malformed(), "/tmp/kube", "workbenchIngress.networkPolicy", rendered, nonce)
        self.assertEqual(result.receipt["outcome"], "post-send-uncertain-discovered")
        wrong = admitted(desired)
        with patch.object(MODULE, "live_obj", return_value=wrong):
            with self.assertRaisesRegex(MODULE.TransportUncertainError, "unresolved"):
                MODULE.create_v4(Malformed(), "/tmp/kube", "workbenchIngress.networkPolicy", rendered, nonce)

    def test_v4_transport_uncertainty_without_discovery_stays_unresolved(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy()
        rendered = {"desired": desired, "path": "fixed", "blobSha256": sha()}
        class ServerError(MODULE.Runner):
            def run(self, args, *, input_text=None, timeout=10): return MODULE.Result(1, "", "HTTP 500")
        with patch.object(MODULE, "live_obj", side_effect=MODULE.ActivationError("not readable")):
            with self.assertRaisesRegex(MODULE.TransportUncertainError, "unresolved"):
                MODULE.create_v4(ServerError(), "/tmp/kube", "workbenchIngress.networkPolicy", rendered, "a" * 64)

    def test_v4_uncertain_create_is_boundedly_rediscovered_for_rollback(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy(); nonce = "d" * 64
        rendered = {"desired": desired, "path": "fixed", "blobSha256": sha()}
        observed = admitted(MODULE.POLICY.with_operation_nonce(desired, nonce), "owned", "17")
        with patch.object(MODULE, "get_optional", side_effect=[MODULE.ActivationError("temporary read failure"), observed]), patch.object(MODULE.time, "monotonic", side_effect=[0.0, 0.0, 0.1]), patch.object(MODULE.time, "sleep"):
            recovered = MODULE.rediscover_uncertain_create_v4(Fake(), "/snapshot", "workbenchIngress.networkPolicy", rendered, nonce, 1)
        self.assertIsNotNone(recovered); self.assertEqual(recovered.observed["metadata"]["uid"], "owned")
        self.assertTrue(recovered.receipt["recoveredDuringRollbackEntry"]); self.assertFalse(recovered.receipt["temporaryNonceRemoved"])

    def test_v4_exact_six_target_absence_preflight_is_closed_and_non_adopting(self):
        value = ready_policy()
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            resources = MODULE.POLICY.expected_gateway_resources(value)
            rendered = {
                "gateway.networkPolicy": {"desired": resources["networkPolicy"]},
                "workbenchIngress.networkPolicy": {"desired": MODULE.POLICY.expected_workbench_ingress_network_policy()},
                "gateway.serviceAccount": {"desired": resources["serviceAccount"]},
                "gateway.service": {"desired": resources["service"]},
                "gateway.deployment": {"desired": resources["deployment"]},
                "gateway.ingress": {"desired": resources["ingress"]},
            }
        with patch.object(MODULE, "get_optional", return_value=None) as lookup:
            receipt = MODULE.exact_absence_preflight_v4(Fake(), "/snapshot", rendered)
        self.assertEqual(receipt["status"], "all-six-exact-target-names-absent")
        self.assertEqual(len(receipt["targets"]), 6); self.assertEqual(lookup.call_count, 6)
        occupied = admitted(rendered["gateway.service"]["desired"], "foreign")
        with patch.object(MODULE, "get_optional", side_effect=[None, None, None, None, occupied, None]):
            with self.assertRaisesRegex(MODULE.ActivationError, "adoption forbidden"):
                MODULE.exact_absence_preflight_v4(Fake(), "/snapshot", rendered)

    def test_v4_nonce_removal_uses_uid_rv_nonce_cas_before_final_semantics(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy(); nonce = "c" * 64
        observed = admitted(MODULE.POLICY.with_operation_nonce(desired, nonce), "owned", "10")
        created = MODULE.CreatedV4("workbenchIngress.networkPolicy", desired, observed, {"operationNonce": nonce, "temporaryNonceRemoved": False})
        after = admitted(desired, "owned", "11")
        with patch.object(MODULE, "checked", return_value=json.dumps(after)) as command:
            MODULE.remove_operation_nonce_v4(Fake(), "/snapshot", created, nonce)
        args = command.call_args.args[1]; patch_body = json.loads(args[args.index("-p") + 1])
        self.assertEqual([op["op"] for op in patch_body], ["test", "test", "test", "remove"])
        self.assertEqual(patch_body[0]["value"], "owned"); self.assertEqual(patch_body[1]["value"], "10"); self.assertEqual(patch_body[2]["value"], nonce)
        self.assertTrue(created.receipt["temporaryNonceRemoved"])

    def test_v4_dual_cas_partial_failure_is_rolled_back_to_both_suspended(self):
        gateway = admitted(MODULE.POLICY.gateway_flux_objects(suspended=True)["kustomization"], "g", "10")
        workbench = admitted(MODULE.POLICY.workbench_ingress_flux_objects(suspended=True)["kustomization"], "w", "20")
        active_gateway = admitted(MODULE.POLICY.gateway_flux_objects(suspended=False)["kustomization"], "g", "11")
        source = {"metadata": {"uid": "source-uid"}, "status": {"artifact": {"revision": f"main@sha1:{REV}"}}}
        bootstrap = {"owners": {"gateway": {"kustomization": gateway}, "workbenchIngress": {"kustomization": workbench}}, "source": source}
        with patch.object(MODULE, "cas_flux_v4", side_effect=[active_gateway, MODULE.ActivationError("second CAS failed")]):
            with self.assertRaisesRegex(MODULE.ActivationError, "second CAS"):
                MODULE.unsuspend_both_v4(Fake(), "/tmp/kube", policy(), bootstrap)
        current = [active_gateway, workbench]
        suspended_gateway = admitted(MODULE.POLICY.gateway_flux_objects(suspended=True)["kustomization"], "g", "12")
        quiescent = {"gateway": {"uid": "g", "suspended": True}, "workbenchIngress": {"uid": "w", "suspended": True}}
        source_after = {"metadata": {"uid": "source-uid"}, "status": {"artifact": {"revision": f"main@sha1:{REV}"}}}
        with patch.object(MODULE, "_target_live", side_effect=current), patch.object(MODULE, "cas_flux_v4", side_effect=[suspended_gateway]) as suspend, patch.object(MODULE, "wait_both_suspended_v4", return_value=quiescent), patch.object(MODULE, "shared_source_revision_v4", return_value=source_after):
            result = MODULE.rollback_v4(Fake(), "/tmp/kube", policy(), [], bootstrap, None, None)
        self.assertEqual(result["status"], "complete")
        self.assertTrue(result["bothKustomizationsSuspended"])
        suspend.assert_called_once()

    def test_v4_rollback_accepts_already_absent_owned_object(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy(); created = MODULE.CreatedV4("workbenchIngress.networkPolicy", desired, admitted(desired), {"uid": "owned-uid", "operationNonce": "a" * 64, "temporaryNonceRemoved": True})
        with patch.object(MODULE, "get_optional", return_value=None), patch.object(MODULE, "raw_delete") as delete:
            result = MODULE.delete_with_preconditions_v4(Fake(), "/tmp/kube", created, 1)
        self.assertTrue(result["absent"]); self.assertTrue(result["alreadyAbsent"]); delete.assert_not_called()

    def test_v4_rollback_reports_finalizers_without_removing_them(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy(); current = admitted(desired)
        terminating = admitted(desired); terminating["metadata"] |= {"deletionTimestamp": "2026-01-01T00:00:00Z", "finalizers": ["example.test/hold"]}
        created = MODULE.CreatedV4("workbenchIngress.networkPolicy", desired, current, {"uid": "owned-uid", "operationNonce": "a" * 64, "temporaryNonceRemoved": True})
        with patch.object(MODULE, "get_optional", side_effect=[current, terminating]), patch.object(MODULE, "raw_delete") as delete:
            with self.assertRaisesRegex(MODULE.ActivationError, "blocked by finalizers"):
                MODULE.delete_with_preconditions_v4(Fake(), "/tmp/kube", created, 1)
        path, payload = delete.call_args.args[1:]
        self.assertIn(f"/namespaces/{MODULE.WORKBENCH_NAMESPACE}/networkpolicies/{MODULE.WORKBENCH_POLICY_NAME}", path)
        self.assertIn('"uid":"owned-uid"', payload); self.assertIn('"resourceVersion":"10"', payload)

    def test_v4_deployment_rollback_is_foreground_and_proves_runtime_dependents_absent(self):
        value = ready_policy()
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            desired = MODULE.POLICY.expected_gateway_resources(value)["deployment"]
        current = admitted(desired, "deployment-uid", "31")
        created = MODULE.CreatedV4("gateway.deployment", desired, current, {"uid": "deployment-uid", "operationNonce": "a" * 64, "temporaryNonceRemoved": True})
        with patch.object(MODULE, "get_optional", side_effect=[current, None]), patch.object(MODULE, "raw_delete") as delete:
            receipt = MODULE.delete_with_preconditions_v4(Fake(), "/tmp/kube", created, 1)
        payload = json.loads(delete.call_args.args[2])
        self.assertEqual(payload["propagationPolicy"], "Foreground")
        self.assertEqual(payload["preconditions"], {"uid": "deployment-uid", "resourceVersion": "31"})
        self.assertTrue(receipt["foregroundPropagation"])
        with patch.object(MODULE, "checked", side_effect=[json.dumps({"items": []}), json.dumps({"items": []})]) as query:
            dependents = MODULE.deployment_dependents_absent_v4(Fake(), "/tmp/kube")
        self.assertEqual(dependents["status"], "deployment-foreground-dependents-absent")
        self.assertEqual(query.call_count, 2)

    def test_v4_unresolved_deployment_retains_gateway_isolation_until_runtime_absence(self):
        value = ready_policy()
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            resources = MODULE.POLICY.expected_gateway_resources(value)
        network_policy = MODULE.CreatedV4(
            "gateway.networkPolicy",
            resources["networkPolicy"],
            admitted(resources["networkPolicy"], "network-policy-uid", "20"),
            {"uid": "network-policy-uid", "operationNonce": "a" * 64, "temporaryNonceRemoved": True},
        )
        unresolved_live = admitted(resources["deployment"], "unbound-deployment-uid", "30")
        rendered = {"gateway.deployment": {"desired": resources["deployment"]}}
        # `None` models the definite-409 path, where no-adopt deliberately
        # clears `uncertain` but the racing Deployment is still not ours.
        for uncertain in ("gateway.deployment", None):
            with self.subTest(uncertain=uncertain), patch.object(MODULE, "get_optional", return_value=unresolved_live), patch.object(MODULE, "delete_with_preconditions_v4") as delete:
                result = MODULE.rollback_v4(
                    Fake(), "/tmp/kube", value, [network_policy], None, None,
                    uncertain, rendered=rendered,
                )
            self.assertEqual(result["status"], "incomplete")
            self.assertTrue(any("isolation retained" in error for error in result["errors"]))
            delete.assert_not_called()

    def test_v4_flux_ready_requires_generation_and_exact_revision(self):
        desired = MODULE.POLICY.gateway_flux_objects(suspended=False)["kustomization"]
        live = admitted(desired, "g", "11"); live["metadata"]["generation"] = 7
        live["status"] = {"observedGeneration": 7, "lastAppliedRevision": f"main@sha1:{REV}", "lastAttemptedRevision": f"main@sha1:{REV}", "conditions": [{"type": "Ready", "status": "True", "observedGeneration": 7}]}
        self.assertTrue(MODULE.flux_ready_v4(live, "gateway", "g", REV)["ready"])
        live["status"]["observedGeneration"] = 6
        with self.assertRaisesRegex(MODULE.ActivationError, "observedGeneration"):
            MODULE.flux_ready_v4(live, "gateway", "g", REV)

    def test_v4_suspended_flux_requires_observed_generation_and_no_current_reconciling(self):
        desired = admitted(MODULE.POLICY.gateway_flux_objects(suspended=True)["kustomization"], "g", "11")
        desired["metadata"]["generation"] = 8
        desired["status"] = {"observedGeneration": 8, "conditions": [{"type": "Reconciling", "status": "False", "observedGeneration": 8}]}
        self.assertTrue(MODULE._flux_suspended_and_quiescent_v4(desired, "gateway", "g")["suspended"])
        active = copy.deepcopy(desired); active["status"]["conditions"][0]["status"] = "True"
        with self.assertRaisesRegex(MODULE.ActivationError, "still Reconciling"):
            MODULE._flux_suspended_and_quiescent_v4(active, "gateway", "g")
        stale = copy.deepcopy(desired); stale["status"]["observedGeneration"] = 7
        with self.assertRaisesRegex(MODULE.ActivationError, "generation not observed"):
            MODULE._flux_suspended_and_quiescent_v4(stale, "gateway", "g")

    def test_v4_rollback_absence_requires_all_six_names_quiet_and_rejects_foreign_uid(self):
        rendered = {f"item-{index}": {"desired": {"kind": "Service", "metadata": {"namespace": "ns", "name": f"name-{index}"}}} for index in range(6)}
        owned = {name: f"uid-{index}" for index, name in enumerate(sorted(rendered))}
        with patch.object(MODULE, "get_optional", return_value=None), patch.object(MODULE.time, "monotonic", side_effect=[0.0, 0.0, 0.1, 0.1]), patch.object(MODULE.time, "sleep"):
            receipt = MODULE._all_targets_absent_quiet_v4(Fake(), "/snapshot", rendered, owned, 10.0, 0.05, 0.01)
        self.assertEqual(receipt["status"], "all-six-names-absent-for-quiet-interval")
        foreign = {"metadata": {"uid": "foreign"}}
        with patch.object(MODULE, "get_optional", side_effect=[foreign]), patch.object(MODULE.time, "monotonic", return_value=0.0):
            with self.assertRaisesRegex(MODULE.ActivationError, "unowned UID"):
                MODULE._all_targets_absent_quiet_v4(Fake(), "/snapshot", rendered, owned, 10.0, 1.0, 0.1)

    def test_v4_normalizer_ignores_only_real_deployment_revision_annotation(self):
        value = ready_policy()
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            desired = MODULE.POLICY.expected_gateway_resources(value)["deployment"]
        live = admitted(desired, "deployment-uid", "101")
        live["metadata"] |= {"generation": 4, "annotations": {"deployment.kubernetes.io/revision": "7"}}
        live["status"] = {"observedGeneration": 4}
        MODULE.POLICY.require_semantically_equal(live, desired, "real Deployment fixture")
        malformed = copy.deepcopy(live); malformed["metadata"]["annotations"]["deployment.kubernetes.io/revision"] = "latest"
        with self.assertRaisesRegex(MODULE.POLICY.PolicyError, "semantic drift"):
            MODULE.POLICY.require_semantically_equal(malformed, desired, "malformed revision")
        service = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "s", "namespace": "n", "annotations": {"deployment.kubernetes.io/revision": "7"}}, "spec": {}}
        normalized = MODULE.POLICY.normalize_kubernetes_object(service)
        self.assertIn("deployment.kubernetes.io/revision", normalized["metadata"]["annotations"])

    def test_v4_fixed_timeouts_fail_closed(self):
        class TimedOut(MODULE.Runner):
            def run(self, args, *, input_text=None): return MODULE.Result(124, "", "timeout after 30s")
        with self.assertRaises(MODULE.TransportUncertainError):
            MODULE.checked(TimedOut(), ["curl"], "bounded request")
        with patch.object(MODULE.time, "monotonic", side_effect=[0, 121]):
            with self.assertRaisesRegex(MODULE.ActivationError, "total timeout"):
                MODULE.route_matrix_v4(Fake(), policy())

    def test_v4_route_matrix_is_proxy_free_closed_and_checks_bodies_cors_and_deadline(self):
        value = policy(); origin = value["endpoints"]["browserOrigin"]; prefix = value["httpBoundary"]["prefix"]
        cors = {"access-control-allow-origin": origin, "access-control-allow-credentials": "true", "vary": "Origin"}
        status_body = {"available": True, "active": False, "walletAddress": None, "label": "Staging-Testteilnahme – keine Bürgerverifikation, kein Stimmrecht", "scope": None, "authority": "none"}
        def response(request_origin, method, path, headers, body, timeout):
            self.assertEqual(request_origin, origin); self.assertEqual(timeout, 10)
            if method == "GET" and path == prefix + "/status": return {"status": 200, "headers": cors | {"content-type": "application/json; charset=utf-8"}, "body": json.dumps(status_body)}
            if method == "OPTIONS" and path in MODULE.POLICY.ROUTES:
                preflight = cors | {"access-control-allow-methods": "GET" if path.endswith("/status") else "POST", "access-control-allow-headers": "content-type", "access-control-max-age": "600"}
                return {"status": 204, "headers": preflight, "body": ""}
            if method == "POST" and path in MODULE.POLICY.POST_ROUTES:
                if headers.get("Origin") == "https://attacker.invalid": return {"status": 403, "headers": {"content-type": "application/json"}, "body": '{"error":"origin_forbidden"}'}
                status, error = ((401, "admission_invalid") if path.endswith("/challenge") else (401, "challenge_invalid") if path.endswith("/session") else (401, "session_required"))
                return {"status": status, "headers": cors | {"content-type": "application/json"}, "body": json.dumps({"error": error})}
            if (method, path) in [("POST", prefix + "/status"), *[("GET", item) for item in MODULE.POLICY.POST_ROUTES], ("HEAD", prefix + "/status"), ("DELETE", prefix + "/status")]: return {"status": 405, "headers": {}, "body": ""}
            if path == prefix + "/status?unexpected=1": return {"status": 404, "headers": {"content-type": "application/json"}, "body": '{"error":"not_found"}'}
            return {"status": 404, "headers": {}, "body": ""}
        with patch.object(MODULE, "_route_request_v4", side_effect=response) as request:
            receipt = MODULE.route_matrix_v4(Fake(), value)
        expected_count = len(MODULE.POLICY.ROUTE_EXPECTATIONS)
        self.assertEqual(len(receipt), expected_count); self.assertEqual(request.call_count, expected_count)
        for path in (
            prefix + "/promote-source-post",
            prefix + "/sign-topic-suggestion",
        ):
            self.assertIn(
                {"case": "preflight", "method": "OPTIONS", "path": path, "status": 204},
                [{key: item[key] for key in ("case", "method", "path", "status")} for item in receipt],
            )
            self.assertIn(
                {"case": "unauthenticated-post", "method": "POST", "path": path, "status": 401},
                [{key: item[key] for key in ("case", "method", "path", "status")} for item in receipt],
            )
            self.assertIn(
                {"case": "method-denied", "method": "GET", "path": path, "status": 405},
                [{key: item[key] for key in ("case", "method", "path", "status")} for item in receipt],
            )
        with patch.object(MODULE, "_route_request_v4", return_value={"status": 200, "headers": cors | {"content-type": "application/json"}, "body": json.dumps(status_body)}), patch.object(MODULE.time, "monotonic", side_effect=[0, 0, 121]):
            with self.assertRaisesRegex(MODULE.ActivationError, "after request"):
                MODULE.route_matrix_v4(Fake(), value)

    def test_v4_route_transport_disables_ambient_proxies(self):
        class Headers(dict):
            def items(self): return super().items()
        class Response:
            status = 200; headers = Headers({"content-type": "application/json"})
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def geturl(self): return "https://roebel-web.staging.agentcart.eu/test"
            def read(self, size): return b"{}"
        class Opener:
            def open(self, request, timeout): return Response()
        opener = Opener()
        with patch.object(MODULE.urllib.request, "build_opener", return_value=opener) as build:
            observed = MODULE._route_request_v4("https://roebel-web.staging.agentcart.eu", "GET", "/test", {}, None, 1)
        self.assertEqual(observed["status"], 200)
        proxy = build.call_args.args[0]
        self.assertIsInstance(proxy, MODULE.urllib.request.ProxyHandler); self.assertEqual(proxy.proxies, {})

    def test_v4_protected_executable_blob_drift_is_rejected(self):
        with patch.object(MODULE, "git_blob", return_value=b"definitely-not-the-local-file"):
            with self.assertRaisesRegex(MODULE.ActivationError, "differs from exact Git blob"):
                MODULE.protected_checkout(REV)

    def test_v4_protected_render_semantic_drift_is_rejected(self):
        value = ready_policy()
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            expected = MODULE._expected_render(value); blobs = {}
            for path, (encoding, desired) in expected.items():
                blobs[path] = desired.encode() if encoding == "text" else (json.dumps(desired) + "\n").encode()
            deployment_path = f"{MODULE.POLICY.GATEWAY_ROOT}/deployment.json"
            deployment = json.loads(blobs[deployment_path])
            deployment["spec"]["template"]["spec"]["containers"][0]["securityContext"]["privileged"] = True
            blobs[deployment_path] = (json.dumps(deployment) + "\n").encode()
            with patch.object(MODULE, "git_blob", side_effect=lambda revision, path: blobs[path]):
                with self.assertRaisesRegex(MODULE.ActivationError, "semantic drift"):
                    MODULE.render_v4(REV, value)

    def test_v4_internal_status_contract_is_closed_and_not_public_route(self):
        value = ready_policy(); pins = value["productPins"]
        expected = MODULE.expected_database_status_v4(value)
        selected = {"name": "gateway-pod-a", "uid": "pod-uid", "resourceVersion": "10", "imageId": "docker-pullable://image@" + pins["imageManifestDigest"]}
        runtime = {"readyPodCount": value["runtime"]["replicas"], "pods": [selected]}
        exact_image = pins["imageRepository"] + "@" + pins["imageManifestDigest"]
        current = {
            "metadata": {"uid": "pod-uid", "resourceVersion": "11"},
            "spec": {"containers": [{"image": exact_image}]},
            "status": {"containerStatuses": [{"imageID": selected["imageId"], "ready": True}]},
        }
        probe = {
            "transport": "authenticated-kubernetes-pod-port-forward",
            "pod": selected["name"],
            "loopbackOnly": True,
            "publicIngressUsed": False,
            "serviceProxyUsed": False,
            "redirectsAllowed": False,
            "path": "/status",
            "remotePort": MODULE.POLICY.GATEWAY_PORT,
        }
        with patch.object(MODULE, "checked", return_value="") as authorization, patch.object(MODULE, "_pod_port_forward_get_v4", return_value=(json.dumps(expected), probe)) as request, patch.object(MODULE, "live_obj", return_value=current):
            result = MODULE.database_status_v4(Fake(), "/tmp/kube", value, runtime)
        self.assertEqual(result, valid_database_status(value, image_id=selected["imageId"]))
        self.assertFalse(result["probe"]["publicIngressUsed"])
        self.assertEqual(result["probe"]["podUid"], "pod-uid")
        self.assertEqual(result["probe"]["podImage"], exact_image)
        self.assertTrue(result["probe"]["podReadyAfter"])
        self.assertEqual(len(authorization.call_args_list), 3)
        self.assertTrue(all("auth" in call.args[1] and "can-i" in call.args[1] for call in authorization.call_args_list))
        args = request.call_args.args
        self.assertEqual(args[1:4], ("gateway-pod-a", MODULE.POLICY.GATEWAY_PORT, "/status"))
        self.assertNotIn(value["endpoints"]["browserOrigin"], json.dumps(request.call_args.args))
        with patch.object(MODULE, "checked", return_value=""), patch.object(MODULE, "_pod_port_forward_get_v4", return_value=(json.dumps(expected | {"extra": True}), probe)), patch.object(MODULE, "live_obj", return_value=current):
            with self.assertRaisesRegex(MODULE.ActivationError, "contract drift"):
                MODULE.database_status_v4(Fake(), "/tmp/kube", value, runtime)
        topic_drifts = {
            "municipalityId": "other-town",
            "sourceConversationTopic": "other-conversation",
            "topicPolicyVersion": "other-topic-v1",
            "topicTracerMigrationSha256": sha("0"),
            "topicTracerDatabaseSchemaSha256": sha("1"),
        }
        for key, drift in topic_drifts.items():
            with self.subTest(kind="drift", key=key), patch.object(MODULE, "checked", return_value=""), patch.object(MODULE, "_pod_port_forward_get_v4", return_value=(json.dumps(expected | {key: drift}), probe)), patch.object(MODULE, "live_obj", return_value=current):
                with self.assertRaisesRegex(MODULE.ActivationError, "contract drift"):
                    MODULE.database_status_v4(Fake(), "/tmp/kube", value, runtime)
        for key in topic_drifts:
            missing = copy.deepcopy(expected); missing.pop(key)
            with self.subTest(kind="missing", key=key), patch.object(MODULE, "checked", return_value=""), patch.object(MODULE, "_pod_port_forward_get_v4", return_value=(json.dumps(missing), probe)), patch.object(MODULE, "live_obj", return_value=current):
                with self.assertRaisesRegex(MODULE.ActivationError, "contract drift"):
                    MODULE.database_status_v4(Fake(), "/tmp/kube", value, runtime)
        for key in topic_drifts:
            extra = expected | {"unexpected" + key[:1].upper() + key[1:]: "unexpected"}
            with self.subTest(kind="extra", key=key), patch.object(MODULE, "checked", return_value=""), patch.object(MODULE, "_pod_port_forward_get_v4", return_value=(json.dumps(extra), probe)), patch.object(MODULE, "live_obj", return_value=current):
                with self.assertRaisesRegex(MODULE.ActivationError, "contract drift"):
                    MODULE.database_status_v4(Fake(), "/tmp/kube", value, runtime)
        changed = copy.deepcopy(current); changed["status"]["containerStatuses"][0]["imageID"] = "docker-pullable://wrong@" + pins["imageManifestDigest"]
        with patch.object(MODULE, "checked", return_value=""), patch.object(MODULE, "_pod_port_forward_get_v4", return_value=(json.dumps(expected), probe)), patch.object(MODULE, "live_obj", return_value=changed):
            with self.assertRaisesRegex(MODULE.ActivationError, "runtime pin changed"):
                MODULE.database_status_v4(Fake(), "/tmp/kube", value, runtime)

    def test_v4_runtime_pin_requires_exact_ready_pod_cardinality(self):
        value = ready_policy(); image = value["productPins"]["imageRepository"] + "@" + value["productPins"]["imageManifestDigest"]
        def pod(name):
            return {
                "metadata": {"name": name, "uid": name + "-uid", "resourceVersion": "10"},
                "spec": {"containers": [{"image": image}]},
                "status": {"containerStatuses": [{"ready": True, "imageID": "docker-pullable://" + image}]},
            }
        exact = {"items": [pod(f"pod-{index}") for index in range(value["runtime"]["replicas"])]}
        with patch.object(MODULE, "checked", return_value=json.dumps(exact)):
            receipt = MODULE.runtime_image_v4(Fake(), "/tmp/kube", value)
        self.assertEqual(receipt["readyPodCount"], value["runtime"]["replicas"])
        self.assertEqual(len(receipt["pods"]), value["runtime"]["replicas"])
        extra = {"items": exact["items"] + [pod("pod-extra")]}
        with patch.object(MODULE, "checked", return_value=json.dumps(extra)):
            with self.assertRaisesRegex(MODULE.ActivationError, "cardinality"):
                MODULE.runtime_image_v4(Fake(), "/tmp/kube", value)

    def test_v4_port_forward_is_loopback_bounded_and_process_group_cleaned(self):
        class Headers:
            def get_content_type(self): return "application/json"
        class Response:
            status = 200; headers = Headers()
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def geturl(self): return "http://127.0.0.1:41777/status"
            def read(self, size): self.size = size; return b'{"status":"ready"}'
        class Opener:
            def open(self, request, timeout):
                self.request, self.timeout = request, timeout
                return Response()
        class Process:
            pid = 4242
            def __init__(self):
                import os
                read_fd, write_fd = os.pipe(); os.write(write_fd, b"Forwarding from 127.0.0.1:41777 -> 18085\n"); os.close(write_fd)
                self.stdout = os.fdopen(read_fd, "rb", buffering=0)
            def poll(self): return None
        process, opener = Process(), Opener()
        with patch.object(MODULE.subprocess, "Popen", return_value=process) as popen, patch.object(MODULE.urllib.request, "build_opener", return_value=opener), patch.object(MODULE, "_terminate_process_group") as cleanup:
            body, receipt = MODULE._pod_port_forward_get_v4("/tmp/kube", "pod-a", 18085, "/status", startup_timeout=1, request_timeout=2)
        self.assertEqual(body, '{"status":"ready"}')
        self.assertTrue(receipt["loopbackOnly"]); self.assertFalse(receipt["publicIngressUsed"]); self.assertFalse(receipt["serviceProxyUsed"])
        command = popen.call_args.args[0]
        self.assertIn("--address=127.0.0.1", command); self.assertIn("pod/pod-a", command); self.assertIn(":18085", command)
        self.assertFalse({"http_proxy", "https_proxy", "all_proxy", "no_proxy"} & {key.lower() for key in popen.call_args.kwargs["env"]})
        self.assertTrue(popen.call_args.kwargs["start_new_session"]); self.assertEqual(opener.timeout, 2); cleanup.assert_called_once_with(process)

    def test_v4_manual_policy_named_ports_and_ranges_are_conflicts(self):
        def policy_with(port, end_port=None):
            entry = {"port": port, "protocol": "TCP"}
            if end_port is not None: entry["endPort"] = end_port
            return {"spec": {"ingress": [{"ports": [entry]}]}}
        self.assertTrue(MODULE._allows_workbench_port(policy_with("workbench")))
        self.assertTrue(MODULE._allows_workbench_port(policy_with(18080, 18090)))
        self.assertFalse(MODULE._allows_workbench_port(policy_with(18084)))

    def test_v4_policy_union_uses_runtime_cilium_identity_labels(self):
        labels = {
            "gateway": {
                "namespace": MODULE.NAMESPACE,
                "podCount": 1,
                "kubernetes": [MODULE.POLICY.GATEWAY_LABELS | {"pod-template-hash": "abc123"}],
                "cilium": [MODULE.POLICY.GATEWAY_LABELS | {
                    "pod-template-hash": "abc123",
                    "io.kubernetes.pod.namespace": MODULE.NAMESPACE,
                    "io.cilium.k8s.policy.serviceaccount": MODULE.NAME,
                }],
            },
            "workbench": {
                "namespace": MODULE.WORKBENCH_NAMESPACE,
                "podCount": 0,
                "kubernetes": [MODULE.POLICY.WORKBENCH_SELECTOR],
                "cilium": [MODULE.POLICY.WORKBENCH_SELECTOR | {"io.kubernetes.pod.namespace": MODULE.WORKBENCH_NAMESPACE}],
            },
        }
        cilium_policy = {
            "metadata": {"name": "unexpected-service-account-allow", "namespace": MODULE.NAMESPACE},
            "spec": {"endpointSelector": {"matchLabels": {"k8s:io.cilium.k8s.policy.serviceaccount": MODULE.NAME}}},
        }
        listings = [json.dumps({"items": []}), json.dumps({"items": [cilium_policy]})]
        with patch.object(MODULE, "_target_policy_label_sets_v4", return_value=labels), patch.object(MODULE, "checked", side_effect=listings):
            with self.assertRaisesRegex(MODULE.ActivationError, "overlaps participant selectors"):
                MODULE.policy_union_v4(Fake(), "/tmp/kube")

    def test_v4_policy_union_exempts_owned_policy_only_by_uid_and_exact_semantics(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy()
        observed = admitted(desired, "owned-policy-uid", "10")
        binding = MODULE.CreatedV4("workbenchIngress.networkPolicy", desired, observed, {"operationNonce": "a" * 64})
        owned = {(MODULE.WORKBENCH_NAMESPACE, MODULE.WORKBENCH_POLICY_NAME): binding}
        labels = {
            "gateway": {"namespace": MODULE.NAMESPACE, "podCount": 0, "kubernetes": [MODULE.POLICY.GATEWAY_LABELS], "cilium": [MODULE.POLICY.GATEWAY_LABELS]},
            "workbench": {"namespace": MODULE.WORKBENCH_NAMESPACE, "podCount": 0, "kubernetes": [MODULE.POLICY.WORKBENCH_SELECTOR], "cilium": [MODULE.POLICY.WORKBENCH_SELECTOR]},
        }
        foreign = admitted(desired, "foreign-policy-uid", "11")
        with patch.object(MODULE, "_target_policy_label_sets_v4", return_value=labels), patch.object(MODULE, "checked", return_value=json.dumps({"items": [foreign]})):
            with self.assertRaisesRegex(MODULE.ActivationError, "owned NetworkPolicy UID drift"):
                MODULE.policy_union_v4(Fake(), "/tmp/kube", owned)
        widened = admitted(desired, "owned-policy-uid", "12"); widened["spec"]["ingress"][0]["ports"][0]["port"] = 18084
        with patch.object(MODULE, "_target_policy_label_sets_v4", return_value=labels), patch.object(MODULE, "checked", return_value=json.dumps({"items": [widened]})):
            with self.assertRaisesRegex(MODULE.ActivationError, "semantics"):
                MODULE.policy_union_v4(Fake(), "/tmp/kube", owned)
        with patch.object(MODULE, "_target_policy_label_sets_v4", return_value=labels), patch.object(MODULE, "checked", return_value=json.dumps({"items": []})):
            with self.assertRaisesRegex(MODULE.ActivationError, "set absent or incomplete"):
                MODULE.policy_union_v4(Fake(), "/tmp/kube", owned)

    def test_v4_rollback_rechecks_ingress_absence_after_dual_suspend(self):
        desired = {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress", "metadata": {"name": MODULE.NAME, "namespace": MODULE.NAMESPACE}}
        ingress = MODULE.CreatedV4("gateway.ingress", desired, admitted(desired, "ingress-uid"), {"uid": "ingress-uid", "operationNonce": "a" * 64, "temporaryNonceRemoved": True})
        gateway = admitted(MODULE.POLICY.gateway_flux_objects(suspended=True)["kustomization"], "g", "10")
        workbench = admitted(MODULE.POLICY.workbench_ingress_flux_objects(suspended=True)["kustomization"], "w", "20")
        bootstrap = {"owners": {"gateway": {"kustomization": gateway}, "workbenchIngress": {"kustomization": workbench}}, "source": {"metadata": {"uid": "source"}, "status": {"artifact": {"revision": f"main@sha1:{REV}"}}}}
        recreated = {"metadata": {"uid": "replacement-uid", "resourceVersion": "99"}}
        quiescent = {"gateway": {"uid": "g", "suspended": True}, "workbenchIngress": {"uid": "w", "suspended": True}}
        with patch.object(MODULE, "delete_with_preconditions_v4", return_value={"absent": True}), patch.object(MODULE, "_target_live", side_effect=[gateway, workbench]), patch.object(MODULE, "wait_both_suspended_v4", return_value=quiescent), patch.object(MODULE, "get_optional", return_value=recreated):
            result = MODULE.rollback_v4(Fake(), "/tmp/kube", policy(), [ingress], bootstrap, None, None)
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(result["bothKustomizationsSuspended"])
        self.assertIn("unowned UID", result["errors"][0])

    def test_v4_unproved_ingress_absence_breaks_exposure_through_exact_owned_service(self):
        service_desired = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": MODULE.NAME, "namespace": MODULE.NAMESPACE}}
        service = MODULE.CreatedV4("gateway.service", service_desired, admitted(service_desired, "service-uid", "21"), {"operationNonce": "a" * 64, "temporaryNonceRemoved": True})
        service_deleted = {"logicalName": "gateway.service", "uid": "service-uid", "absent": True}
        with patch.object(MODULE, "delete_with_preconditions_v4", return_value=service_deleted) as delete:
            result = MODULE.rollback_v4(Fake(), "/tmp/kube", policy(), [service], None, None, None)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["finalChecks"]["exposureBreak"]["serviceUid"], "service-uid")
        self.assertTrue(result["finalChecks"]["exposureBreak"]["unknownIngressUntouched"])
        self.assertEqual(delete.call_count, 1); self.assertIs(delete.call_args.args[2], service)

        ingress_desired = {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress", "metadata": {"name": MODULE.NAME, "namespace": MODULE.NAMESPACE}}
        ingress = MODULE.CreatedV4("gateway.ingress", ingress_desired, admitted(ingress_desired, "ingress-uid", "31"), {"operationNonce": "a" * 64, "temporaryNonceRemoved": True})
        with patch.object(MODULE, "delete_with_preconditions_v4", side_effect=[MODULE.ActivationError("Ingress removal unproved"), service_deleted]) as delete:
            result = MODULE.rollback_v4(Fake(), "/tmp/kube", policy(), [service, ingress], None, None, None)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(delete.call_args_list[1].args[2], service)
        self.assertFalse(result["finalChecks"]["exposureBreak"]["unknownIngressUntouched"])

        gateway = admitted(MODULE.POLICY.gateway_flux_objects(suspended=True)["kustomization"], "g", "40")
        workbench = admitted(MODULE.POLICY.workbench_ingress_flux_objects(suspended=True)["kustomization"], "w", "50")
        bootstrap = {
            "owners": {"gateway": {"kustomization": gateway}, "workbenchIngress": {"kustomization": workbench}},
            "source": {"metadata": {"uid": "source"}, "status": {"artifact": {"revision": f"main@sha1:{REV}"}}},
        }
        ingress_deleted = {"logicalName": "gateway.ingress", "uid": "ingress-uid", "absent": True}
        replacement = {"metadata": {"uid": "replacement-ingress-uid", "resourceVersion": "99"}}
        quiescent = {"gateway": {"uid": "g", "suspended": True}, "workbenchIngress": {"uid": "w", "suspended": True}}
        with patch.object(MODULE, "delete_with_preconditions_v4", side_effect=[ingress_deleted, service_deleted, service_deleted]) as delete, patch.object(MODULE, "_target_live", side_effect=[gateway, workbench]), patch.object(MODULE, "wait_both_suspended_v4", return_value=quiescent), patch.object(MODULE, "get_optional", return_value=replacement):
            result = MODULE.rollback_v4(Fake(), "/tmp/kube", policy(), [service, ingress], bootstrap, None, None)
        self.assertEqual(result["status"], "incomplete")
        self.assertIs(delete.call_args_list[0].args[2], ingress)
        self.assertIs(delete.call_args_list[1].args[2], service)
        self.assertIs(delete.call_args_list[2].args[2], service)
        self.assertTrue(result["finalChecks"]["exposureBreak"]["initialIngressAbsenceProved"])
        self.assertTrue(result["finalChecks"]["exposureBreakAfterFlux"]["serviceAbsent"])
        self.assertIn("unowned UID", result["errors"][0])

    def test_v4_rollback_refuses_mutation_if_protected_cluster_identity_changes(self):
        desired = {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress", "metadata": {"name": MODULE.NAME, "namespace": MODULE.NAMESPACE}}
        ingress = MODULE.CreatedV4("gateway.ingress", desired, admitted(desired, "ingress-uid"), {"uid": "ingress-uid", "operationNonce": "a" * 64, "temporaryNonceRemoved": True})
        initial = {"apiOrigin": "https://api.example:6443", "caCertificateSha256": sha("1"), "apiServerSpkiSha256": sha("2"), "kubeSystemNamespaceUid": "cluster-a"}
        changed = initial | {"kubeSystemNamespaceUid": "cluster-b"}
        snapshot = Mock()
        with patch.object(MODULE, "cluster_binding_v4", return_value=changed), patch.object(MODULE, "delete_with_preconditions_v4") as delete:
            result = MODULE.rollback_v4(Fake(), "/tmp/kube", policy(), [ingress], None, None, None, snapshot=snapshot, initial_cluster=initial)
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("protected cluster identity changed before rollback", result["errors"][0])
        delete.assert_not_called()

    def test_v4_success_receipt_rejects_incomplete_object_set(self):
        value = ready_policy(); facts = valid_success_facts(value)
        facts["objectCreateResults"] = facts["objectCreateResults"][:5]
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            with self.assertRaisesRegex(MODULE.ActivationError, "object receipt set incomplete"):
                MODULE.validate_success_facts_v4(facts, value, REV)

    def test_v4_complete_receipt_binds_flux_source_before_and_after(self):
        value = ready_policy(); facts = valid_success_facts(value)
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            MODULE.validate_success_facts_v4(facts, value, REV)
            facts["fluxTransaction"]["sourceAfterReady"]["artifactRevision"] = "main@sha1:" + "c" * 40
            with self.assertRaisesRegex(MODULE.ActivationError, "source revision/UID"):
                MODULE.validate_success_facts_v4(facts, value, REV)

    def test_v4_operator_termination_after_mutation_enters_bounded_rollback_and_receipt(self):
        value = ready_policy()
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            resources = MODULE.POLICY.expected_gateway_resources(value)
        rendered = {
            "gateway.networkPolicy": {"desired": resources["networkPolicy"], "path": "np", "blobSha256": sha()},
            "workbenchIngress.networkPolicy": {"desired": MODULE.POLICY.expected_workbench_ingress_network_policy(), "path": "wnp", "blobSha256": sha()},
            "gateway.serviceAccount": {"desired": resources["serviceAccount"], "path": "sa", "blobSha256": sha()},
            "gateway.service": {"desired": resources["service"], "path": "svc", "blobSha256": sha()},
            "gateway.deployment": {"desired": resources["deployment"], "path": "dep", "blobSha256": sha()},
            "gateway.ingress": {"desired": resources["ingress"], "path": "ing", "blobSha256": sha()},
        }
        snapshot = Mock(path=Path("/snapshot")); snapshot.close = Mock()
        cluster = {"apiOrigin": value["clusterIdentity"]["apiOrigin"], "caCertificateSha256": value["clusterIdentity"]["caCertificateSha256"], "apiServerSpkiSha256": value["clusterIdentity"]["apiServerSpkiSha256"], "kubeSystemNamespaceUid": value["clusterIdentity"]["kubeSystemNamespaceUid"]}
        sink = Mock(); rollback = {"status": "complete", "finalizersRemovedByRunner": False}
        patches = (
            patch.object(MODULE.POLICY, "assert_activation_ready", return_value=value),
            patch.object(MODULE, "render_v4", return_value=rendered),
            patch.object(MODULE, "snapshot_kubeconfig_v4", return_value=snapshot),
            patch.object(MODULE, "cluster_binding_v4", return_value=cluster),
            patch.object(MODULE, "anonymous_publication_v4", return_value={}),
            patch.object(MODULE, "endpoint_facts_v4", return_value={}),
            patch.object(MODULE, "preservation_v4", return_value={}),
            patch.object(MODULE, "flux_preflight_v4", return_value={}),
            patch.object(MODULE, "exact_absence_preflight_v4", return_value={"status": "all-six-exact-target-names-absent", "targets": [{}] * 6}),
            patch.object(MODULE, "secret_materialization_v4", return_value={}),
            patch.object(MODULE, "policy_union_v4", return_value={}),
            patch.object(MODULE, "create_v4", side_effect=MODULE.ActivationInterrupted(MODULE.signal.SIGTERM)),
            patch.object(MODULE, "rediscover_uncertain_create_v4", return_value=None),
            patch.object(MODULE, "rollback_v4", return_value=rollback),
        )
        with tempfile.TemporaryDirectory() as directory:
            kube = Path(directory) / "kube"; kube.write_text("fixture")
            with contextlib.ExitStack() as stack:
                entered = [stack.enter_context(item) for item in patches]
                with self.assertRaisesRegex(MODULE.ActivationError, "rolled-back"):
                    MODULE.activate(value, REV, str(kube), Fake(), True, sink, {"runner": sha()}, dormant_ownership())
        failure = sink.commit.call_args.args[0]
        self.assertEqual(failure["status"], "rolled-back")
        self.assertEqual(failure["termination"], {"interrupted": True, "signal": MODULE.signal.SIGTERM, "signalsDeferredDuringRollback": True})
        entered[-1].assert_called_once(); snapshot.close.assert_called_once()

    def test_v4_success_receipt_persistence_failure_is_inside_transaction_and_rolls_back(self):
        value = ready_policy()
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            resources = MODULE.POLICY.expected_gateway_resources(value)
        rendered = {
            "gateway.networkPolicy": {"desired": resources["networkPolicy"], "path": "np", "blobSha256": sha()},
            "workbenchIngress.networkPolicy": {"desired": MODULE.POLICY.expected_workbench_ingress_network_policy(), "path": "wnp", "blobSha256": sha()},
            "gateway.serviceAccount": {"desired": resources["serviceAccount"], "path": "sa", "blobSha256": sha()},
            "gateway.service": {"desired": resources["service"], "path": "svc", "blobSha256": sha()},
            "gateway.deployment": {"desired": resources["deployment"], "path": "dep", "blobSha256": sha()},
            "gateway.ingress": {"desired": resources["ingress"], "path": "ing", "blobSha256": sha()},
        }
        snapshot = Mock(path=Path("/snapshot")); snapshot.close = Mock()
        source = {"metadata": {"uid": "source", "resourceVersion": "1"}, "status": {"artifact": {"revision": f"main@sha1:{REV}"}}}
        dormant = {"owners": {"gateway": {"kustomization": {"metadata": {"uid": "g"}}}, "workbenchIngress": {"kustomization": {"metadata": {"uid": "w"}}}}, "source": source}
        cluster = {"apiOrigin": value["clusterIdentity"]["apiOrigin"], "caCertificateSha256": value["clusterIdentity"]["caCertificateSha256"], "apiServerSpkiSha256": value["clusterIdentity"]["apiServerSpkiSha256"], "kubeSystemNamespaceUid": value["clusterIdentity"]["kubeSystemNamespaceUid"]}
        def create(_r, _kube, logical, item, nonce):
            desired = item["desired"]; observed = admitted(MODULE.POLICY.with_operation_nonce(desired, nonce), logical + "-uid")
            return MODULE.CreatedV4(logical, desired, observed, {"operationNonce": nonce, "temporaryNonceRemoved": False})
        def remove(_r, _kube, created, _nonce): created.receipt["temporaryNonceRemoved"] = True; created.observed = admitted(created.desired, created.logical_name + "-uid", "11")
        sink = Mock(); sink.commit.side_effect = [OSError("directory fsync failed"), None]
        rollback = {"status": "complete", "finalizersRemovedByRunner": False}
        rollback_patch = patch.object(MODULE, "rollback_v4", return_value=rollback)
        patches = (
            patch.object(MODULE.POLICY, "assert_activation_ready", return_value=value),
            patch.object(MODULE, "render_v4", return_value=rendered), patch.object(MODULE, "snapshot_kubeconfig_v4", return_value=snapshot),
            patch.object(MODULE, "cluster_binding_v4", return_value=cluster), patch.object(MODULE, "anonymous_publication_v4", return_value={"manifestDigest": value["productPins"]["imageManifestDigest"]}),
            patch.object(MODULE, "endpoint_facts_v4", return_value={"ok": True}), patch.object(MODULE, "preservation_v4", return_value={}),
            patch.object(MODULE, "flux_preflight_v4", return_value=dormant), patch.object(MODULE, "exact_absence_preflight_v4", return_value={"status": "all-six-exact-target-names-absent", "targets": [{}] * 6}),
            patch.object(MODULE, "secret_materialization_v4", return_value={"status": "same", "secrets": {"x": {}}}), patch.object(MODULE, "policy_union_v4", return_value={"ok": True}),
            patch.object(MODULE, "create_v4", side_effect=create), patch.object(MODULE, "remove_operation_nonce_v4", side_effect=remove),
            patch.object(MODULE, "health_v4", return_value=({}, {"ok": True})), patch.object(MODULE, "runtime_image_v4", return_value={"readyPodCount": 1, "pods": [{}]}),
            patch.object(MODULE, "database_status_v4", return_value=valid_database_status(value)), patch.object(MODULE, "route_matrix_v4", return_value=[{}]),
            patch.object(MODULE, "shared_source_revision_v4", return_value=source), patch.object(MODULE, "unsuspend_both_v4", return_value={"gateway": {"metadata": {"resourceVersion": "2"}}, "workbenchIngress": {"metadata": {"resourceVersion": "2"}}}),
            patch.object(MODULE, "wait_both_ready_v4", return_value={"gateway": {}, "workbenchIngress": {}}), patch.object(MODULE, "semantic_postconditions_v4", return_value={str(i): {} for i in range(6)}),
            patch.object(MODULE, "verify_preservation_v4", return_value={"webIngress": {"byteIdenticalCanonicalJson": True}, "existingWorkbenchNetworkPolicy": {"byteIdenticalCanonicalJson": True}}),
            patch.object(MODULE, "validate_success_facts_v4"), rollback_patch,
        )
        with tempfile.TemporaryDirectory() as directory:
            kube = Path(directory) / "kube"; kube.write_text("fixture")
            with contextlib.ExitStack() as stack:
                entered = [stack.enter_context(item) for item in patches]
                with self.assertRaisesRegex(MODULE.ActivationError, "rolled-back"):
                    MODULE.activate(value, REV, str(kube), Fake(), True, sink, {"runner": sha()}, dormant_ownership())
        self.assertEqual(sink.commit.call_count, 2)
        self.assertEqual(sink.commit.call_args_list[1].args[0]["status"], "rolled-back")
        entered[-1].assert_called_once(); snapshot.close.assert_called_once()

if __name__ == "__main__": unittest.main()
