import copy, datetime as dt, importlib.util, json, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("activation", Path(__file__).with_name("activate-staging-participant-gateway.py"))
MODULE = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = MODULE; SPEC.loader.exec_module(MODULE)
REV = "a" * 40
def sha(x="a"): return "sha256:" + x * 64
def object_(kind, name=MODULE.NAME, namespace=MODULE.NAMESPACE, uid="uid", rv="10", **extra):
    value = {"apiVersion": "v1", "kind": kind, "metadata": {"name": name, "namespace": namespace, "uid": uid, "resourceVersion": rv}}; value.update(extra); return value
def policy():
    return copy.deepcopy(MODULE.POLICY.STATIC_ACTIVATION_POLICY)
def ready_policy():
    value = policy(); pins = value["productPins"]
    pins["sourceRevision"] = "b" * 40
    pins["sourceTreeSha256"] = sha("1")
    pins["imageManifestDigest"] = sha("2")
    pins["workflowSha256"] = sha("3")
    pins["migration"]["sha256"] = sha("4")
    pins["databaseSchemaSha256"] = sha("5")
    pins["deactivation"]["sha256"] = sha("6")
    value["endpoints"]["supabase"]["ipv4Cidrs"] = ["192.0.2.10/32"]
    value["activationReady"] = True
    return value
def admitted(desired, uid="owned-uid", rv="10"):
    value = copy.deepcopy(desired); value.setdefault("metadata", {})["uid"] = uid; value["metadata"]["resourceVersion"] = rv
    return value
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
    def test_empty_and_matching_selectors_are_rejected(self):
        self.assertTrue(MODULE._selector_matches_v4({}, MODULE.POLICY.GATEWAY_LABELS))
        self.assertTrue(MODULE._selector_matches_v4({"matchLabels": {"app.kubernetes.io/name": MODULE.NAME}}, MODULE.POLICY.GATEWAY_LABELS))
        self.assertTrue(MODULE._selector_matches_v4({"matchLabels": {"any:app.kubernetes.io/name": MODULE.NAME}}, MODULE.POLICY.GATEWAY_LABELS))
        self.assertFalse(MODULE._selector_matches_v4({"matchLabels": {"app.kubernetes.io/name": "other"}}, MODULE.POLICY.GATEWAY_LABELS))
    def test_live_gate_fails_before_runner_or_kubeconfig_validation(self):
        value = policy()
        with self.assertRaisesRegex(MODULE.POLICY.PolicyError, "activation blocked"):
            MODULE.POLICY.assert_activation_ready(value)
        self.assertFalse(value["activationReady"])
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
        with patch.object(MODULE, "checked", side_effect=MODULE.CreateConflictError("409")), patch.object(MODULE, "live_obj") as discover:
            with self.assertRaises(MODULE.CreateConflictError):
                MODULE.create_v4(Fake(), "/tmp/kube", "workbenchIngress.networkPolicy", rendered)
        discover.assert_not_called()

    def test_v4_transport_uncertainty_discovers_exact_uid_rv(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy(); observed = admitted(desired)
        rendered = {"desired": desired, "path": "fixed", "blobSha256": sha()}
        with patch.object(MODULE, "checked", side_effect=MODULE.TransportUncertainError("lost response")), patch.object(MODULE, "live_obj", return_value=observed) as discover:
            result = MODULE.create_v4(Fake(), "/tmp/kube", "workbenchIngress.networkPolicy", rendered)
        discover.assert_called_once()
        self.assertTrue(result.receipt["discoveredAfterTransportUncertainty"])
        self.assertEqual(result.receipt["uid"], "owned-uid")
        self.assertEqual(result.receipt["resourceVersion"], "10")

    def test_v4_transport_uncertainty_without_discovery_stays_unresolved(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy()
        rendered = {"desired": desired, "path": "fixed", "blobSha256": sha()}
        with patch.object(MODULE, "checked", side_effect=MODULE.TransportUncertainError("lost response")), patch.object(MODULE, "live_obj", side_effect=MODULE.ActivationError("not readable")):
            with self.assertRaisesRegex(MODULE.TransportUncertainError, "could not be discovered"):
                MODULE.create_v4(Fake(), "/tmp/kube", "workbenchIngress.networkPolicy", rendered)

    def test_v4_dual_cas_partial_failure_is_rolled_back_to_both_suspended(self):
        gateway = admitted(MODULE.POLICY.gateway_flux_objects(suspended=True)["kustomization"], "g", "10")
        workbench = admitted(MODULE.POLICY.workbench_ingress_flux_objects(suspended=True)["kustomization"], "w", "20")
        active_gateway = admitted(MODULE.POLICY.gateway_flux_objects(suspended=False)["kustomization"], "g", "11")
        bootstrap = {"owners": {"gateway": {"kustomization": gateway}, "workbenchIngress": {"kustomization": workbench}}}
        with patch.object(MODULE, "cas_flux_v4", side_effect=[active_gateway, MODULE.ActivationError("second CAS failed")]):
            with self.assertRaisesRegex(MODULE.ActivationError, "second CAS"):
                MODULE.unsuspend_both_v4(Fake(), "/tmp/kube", policy(), bootstrap)
        current = [active_gateway, workbench]
        suspended_gateway = admitted(MODULE.POLICY.gateway_flux_objects(suspended=True)["kustomization"], "g", "12")
        with patch.object(MODULE, "_target_live", side_effect=current), patch.object(MODULE, "cas_flux_v4", side_effect=[suspended_gateway]) as suspend:
            result = MODULE.rollback_v4(Fake(), "/tmp/kube", policy(), [], bootstrap, None, None)
        self.assertEqual(result["status"], "complete")
        self.assertTrue(result["bothKustomizationsSuspended"])
        suspend.assert_called_once()

    def test_v4_rollback_accepts_already_absent_owned_object(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy(); created = MODULE.CreatedV4("workbenchIngress.networkPolicy", desired, admitted(desired), {"uid": "owned-uid"})
        with patch.object(MODULE, "get_optional", return_value=None), patch.object(MODULE, "raw_delete") as delete:
            result = MODULE.delete_with_preconditions_v4(Fake(), "/tmp/kube", created, 1)
        self.assertTrue(result["absent"]); self.assertTrue(result["alreadyAbsent"]); delete.assert_not_called()

    def test_v4_rollback_reports_finalizers_without_removing_them(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy(); current = admitted(desired)
        terminating = admitted(desired); terminating["metadata"] |= {"deletionTimestamp": "2026-01-01T00:00:00Z", "finalizers": ["example.test/hold"]}
        created = MODULE.CreatedV4("workbenchIngress.networkPolicy", desired, current, {"uid": "owned-uid"})
        with patch.object(MODULE, "get_optional", side_effect=[current, terminating]), patch.object(MODULE, "raw_delete") as delete:
            with self.assertRaisesRegex(MODULE.ActivationError, "blocked by finalizers"):
                MODULE.delete_with_preconditions_v4(Fake(), "/tmp/kube", created, 1)
        path, payload = delete.call_args.args[1:]
        self.assertIn(f"/namespaces/{MODULE.WORKBENCH_NAMESPACE}/networkpolicies/{MODULE.WORKBENCH_POLICY_NAME}", path)
        self.assertIn('"uid":"owned-uid"', payload); self.assertIn('"resourceVersion":"10"', payload)

    def test_v4_flux_ready_requires_generation_and_exact_revision(self):
        desired = MODULE.POLICY.gateway_flux_objects(suspended=False)["kustomization"]
        live = admitted(desired, "g", "11"); live["metadata"]["generation"] = 7
        live["status"] = {"observedGeneration": 7, "lastAppliedRevision": f"main@sha1:{REV}", "lastAttemptedRevision": f"main@sha1:{REV}", "conditions": [{"type": "Ready", "status": "True", "observedGeneration": 7}]}
        self.assertTrue(MODULE.flux_ready_v4(live, "gateway", "g", REV)["ready"])
        live["status"]["observedGeneration"] = 6
        with self.assertRaisesRegex(MODULE.ActivationError, "observedGeneration"):
            MODULE.flux_ready_v4(live, "gateway", "g", REV)

    def test_v4_fixed_timeouts_fail_closed(self):
        class TimedOut(MODULE.Runner):
            def run(self, args, *, input_text=None): return MODULE.Result(124, "", "timeout after 30s")
        with self.assertRaises(MODULE.TransportUncertainError):
            MODULE.checked(TimedOut(), ["curl"], "bounded request")
        with patch.object(MODULE.time, "monotonic", side_effect=[0, 121]):
            with self.assertRaisesRegex(MODULE.ActivationError, "total timeout"):
                MODULE.route_matrix_v4(Fake(), policy())

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
        expected = {"schemaVersion": "roebel_staging_participant_gateway_status_v1", "status": "ready", "sourceRevision": pins["sourceRevision"], "manifestDigest": pins["imageManifestDigest"], "migrationSha256": pins["migration"]["sha256"], "databaseSchemaSha256": pins["databaseSchemaSha256"]}
        selected = {"name": "gateway-pod-a", "uid": "pod-uid", "resourceVersion": "10", "imageId": "docker-pullable://image@" + pins["imageManifestDigest"]}
        runtime = {"readyPodCount": value["runtime"]["replicas"], "pods": [selected]}
        exact_image = pins["imageRepository"] + "@" + pins["imageManifestDigest"]
        current = {
            "metadata": {"uid": "pod-uid", "resourceVersion": "11"},
            "spec": {"containers": [{"image": exact_image}]},
            "status": {"containerStatuses": [{"imageID": selected["imageId"], "ready": True}]},
        }
        probe = {"transport": "authenticated-kubernetes-pod-port-forward", "publicIngressUsed": False}
        with patch.object(MODULE, "checked", return_value="") as authorization, patch.object(MODULE, "_pod_port_forward_get_v4", return_value=(json.dumps(expected), probe)) as request, patch.object(MODULE, "live_obj", return_value=current):
            result = MODULE.database_status_v4(Fake(), "/tmp/kube", value, runtime)
        self.assertEqual({key: result[key] for key in expected}, expected)
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
        self.assertTrue(popen.call_args.kwargs["start_new_session"]); self.assertEqual(opener.timeout, 2); cleanup.assert_called_once_with(process)

    def test_v4_manual_policy_named_ports_and_ranges_are_conflicts(self):
        def policy_with(port, end_port=None):
            entry = {"port": port, "protocol": "TCP"}
            if end_port is not None: entry["endPort"] = end_port
            return {"spec": {"ingress": [{"ports": [entry]}]}}
        self.assertTrue(MODULE._allows_workbench_port(policy_with("workbench")))
        self.assertTrue(MODULE._allows_workbench_port(policy_with(18080, 18090)))
        self.assertFalse(MODULE._allows_workbench_port(policy_with(18084)))

    def test_v4_rollback_rechecks_ingress_absence_after_dual_suspend(self):
        desired = {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress", "metadata": {"name": MODULE.NAME, "namespace": MODULE.NAMESPACE}}
        ingress = MODULE.CreatedV4("gateway.ingress", desired, admitted(desired, "ingress-uid"), {"uid": "ingress-uid"})
        gateway = admitted(MODULE.POLICY.gateway_flux_objects(suspended=True)["kustomization"], "g", "10")
        workbench = admitted(MODULE.POLICY.workbench_ingress_flux_objects(suspended=True)["kustomization"], "w", "20")
        bootstrap = {"owners": {"gateway": {"kustomization": gateway}, "workbenchIngress": {"kustomization": workbench}}}
        recreated = {"metadata": {"uid": "replacement-uid", "resourceVersion": "99"}}
        with patch.object(MODULE, "delete_with_preconditions_v4", return_value={"absent": True}), patch.object(MODULE, "_target_live", side_effect=[gateway, workbench]), patch.object(MODULE, "get_optional", return_value=recreated):
            result = MODULE.rollback_v4(Fake(), "/tmp/kube", policy(), [ingress], bootstrap, None, None)
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(result["bothKustomizationsSuspended"])
        self.assertIn("reappeared", result["errors"][0])

    def test_v4_success_receipt_rejects_incomplete_object_set(self):
        value = ready_policy(); now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        sections = {name: {"ok": True} for name in MODULE.POLICY.trusted_live_facts_contract()["requiredSections"] if name != "protectedRevision"}
        facts = {"schemaVersion": MODULE.POLICY.TRUSTED_LIVE_FACTS_SCHEMA, "policySha256": MODULE.POLICY.activation_policy_sha256(value), "collectedAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "validUntil": (now + dt.timedelta(seconds=300)).strftime("%Y-%m-%dT%H:%M:%SZ"), "maxAgeSeconds": 300, "protectedRevision": REV, **sections}
        facts["publication"] = {"manifestDigest": value["productPins"]["imageManifestDigest"]}
        facts["database"] = {"databaseSchemaSha256": value["productPins"]["databaseSchemaSha256"]}
        facts["objectCreateResults"] = [{"ok": True}] * 5; facts["semanticObjects"] = {str(i): {} for i in range(6)}
        facts["fluxTransaction"] = {"ready": {"gateway": {}, "workbenchIngress": {}}}
        facts["preservation"] = {"webIngress": {"byteIdenticalCanonicalJson": True}, "existingWorkbenchNetworkPolicy": {"byteIdenticalCanonicalJson": True}}
        facts["rollback"] = {"status": "not-required", "finalizersRemovedByRunner": False}
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            with self.assertRaisesRegex(MODULE.ActivationError, "object receipt set incomplete"):
                MODULE.validate_success_facts_v4(facts, value, REV)

    def test_v4_complete_receipt_binds_flux_source_before_and_after(self):
        value = ready_policy(); now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        sections = {name: {"ok": True} for name in MODULE.POLICY.trusted_live_facts_contract()["requiredSections"] if name != "protectedRevision"}
        facts = {"schemaVersion": MODULE.POLICY.TRUSTED_LIVE_FACTS_SCHEMA, "policySha256": MODULE.POLICY.activation_policy_sha256(value), "collectedAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "validUntil": (now + dt.timedelta(seconds=300)).strftime("%Y-%m-%dT%H:%M:%SZ"), "maxAgeSeconds": 300, "protectedRevision": REV, **sections}
        facts["publication"] = {"manifestDigest": value["productPins"]["imageManifestDigest"]}
        facts["database"] = {"databaseSchemaSha256": value["productPins"]["databaseSchemaSha256"]}
        facts["objectCreateResults"] = [{"ok": True}] * 6; facts["semanticObjects"] = {str(i): {"ok": True} for i in range(6)}
        source = {"uid": "source-uid", "resourceVersion": "10", "artifactRevision": f"main@sha1:{REV}"}
        facts["fluxTransaction"] = {"ready": {"gateway": {}, "workbenchIngress": {}}, "sourceBeforeCas": source, "sourceAfterReady": source | {"resourceVersion": "11"}}
        facts["preservation"] = {"webIngress": {"byteIdenticalCanonicalJson": True}, "existingWorkbenchNetworkPolicy": {"byteIdenticalCanonicalJson": True}}
        facts["rollback"] = {"status": "not-required", "finalizersRemovedByRunner": False}
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            MODULE.validate_success_facts_v4(facts, value, REV)
            facts["fluxTransaction"]["sourceAfterReady"]["artifactRevision"] = "main@sha1:" + "c" * 40
            with self.assertRaisesRegex(MODULE.ActivationError, "source revision/UID"):
                MODULE.validate_success_facts_v4(facts, value, REV)

if __name__ == "__main__": unittest.main()
