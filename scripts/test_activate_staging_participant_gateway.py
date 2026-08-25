import importlib.util, json, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("activation", Path(__file__).with_name("activate-staging-participant-gateway.py"))
MODULE = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = MODULE; SPEC.loader.exec_module(MODULE)
REV = "a" * 40
def sha(x="a"): return "sha256:" + x * 64
def object_(kind, name=MODULE.NAME, namespace=MODULE.NAMESPACE, uid="uid", rv="10", **extra):
    value = {"apiVersion": "v1", "kind": kind, "metadata": {"name": name, "namespace": namespace, "uid": uid, "resourceVersion": rv}}; value.update(extra); return value
def policy():
    hexes = "abcdef0123456789"
    return {"schemaVersion": MODULE.SCHEMA, "protectedRevision": REV, "renderBlobs": {f: sha(hexes[i]) for i, f in enumerate(MODULE.RENDER_FILES)}, "liveProjections": {k: sha(hexes[i]) for i, k in enumerate(("sharedSource", "dormantKustomization", "serviceAccount", "role", "roleBinding", "retainedWebIngress", "networkPolicyInventory", "ciliumNetworkPolicyInventory", "ciliumClusterwideNetworkPolicyInventory"))}, "routeMatrix": {"host": "https://roebel-web.staging.agentcart.eu", "expectations": {"GET /api/staging-participant/v1/status": 200, "HEAD /api/staging-participant/v1/status": 405}}, "haproxy": {"namespace": "ingress-system", "daemonSet": "haproxy-ingress", "replicas": 3, "sourceIpRateLimitPerReplica": 30, "uid": "haproxy", "canonicalSha256": sha("f")}, "desiredPolicyObjectDigests": [sha("0")]}
def rendered():
    result = {"kustomization.yaml": b"resources: []\n", "runtime-pin.json": b"{}\n"}
    for file, kind in zip(MODULE.CREATE_FILES, MODULE.CREATE_KINDS, strict=True): result[file] = json.dumps(object_(kind)).encode()
    return result
class Fake(MODULE.Runner):
    def __init__(self): self.calls = []
    def run(self, args, *, input_text=None):
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
        value = policy(); value["routeMatrix"]["host"] = "http://example.test"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "policy").mkdir(); path = root / MODULE.POLICY_PATH; path.write_text(json.dumps(value))
            with patch.object(MODULE, "ROOT", root), patch.object(MODULE, "git_blob", return_value=path.read_bytes()):
                with self.assertRaisesRegex(MODULE.ActivationError, "route matrix invalid"):
                    MODULE.policy(REV)
    def test_render_is_git_blob_bound_not_caller_path(self):
        value, blobs = policy(), rendered()
        # The descriptor deliberately has unrelated pins, so any supplied bytes
        # fail: a CLI cannot substitute a matching local render directory.
        with patch.object(MODULE, "git_blob", side_effect=lambda rev, path: blobs[path.split("/")[-1]]):
            with self.assertRaisesRegex(MODULE.ActivationError, "render Git blob drift"):
                MODULE.render(REV, value)
    def test_no_evidence_command_or_allowlist_surface_exists(self):
        source = Path(MODULE.__file__).read_text()
        self.assertNotIn("liveSemanticProjection", source)
        self.assertNotIn("preexistingSelectorAllowlist", source)
        self.assertNotIn("--evidence", source)
        self.assertNotIn("--render-root", source)
        self.assertNotIn("--gateway-url", source)
    def test_empty_and_matching_selectors_are_rejected(self):
        self.assertTrue(MODULE.labels_match({}))
        self.assertTrue(MODULE.labels_match({"matchLabels": {"app.kubernetes.io/name": MODULE.NAME}}))
        self.assertFalse(MODULE.labels_match({"matchLabels": {"app.kubernetes.io/name": "other"}}))
    def test_full_fake_live_success_captures_create_and_receipt_fields(self):
        value, blobs, runner = policy(), rendered(), Fake(); kube = Path(tempfile.mkstemp()[1])
        # Bind hashes to the synthetic fixed Git blobs for this test only.
        value["renderBlobs"] = {name: MODULE.bytes_digest(blob) for name, blob in blobs.items()}
        dormant = object_("Kustomization", MODULE.NAME, MODULE.FLUX_NAMESPACE, "k", "10", spec={"suspend": True})
        active = object_("Kustomization", MODULE.NAME, MODULE.FLUX_NAMESPACE, "k", "11", spec={"suspend": False})
        values = {"sharedSource": object_("GitRepository", MODULE.SOURCE, MODULE.FLUX_NAMESPACE, "s"), "dormantKustomization": dormant, "serviceAccount": object_("ServiceAccount"), "role": object_("Role"), "roleBinding": object_("RoleBinding"), "retainedWebIngress": object_("Ingress", MODULE.WEB_INGRESS, uid="web")}
        state = {"active": False}
        def verify(_r, _k, _p, dormant):
            if dormant: return values
            return values | {"dormantKustomization": active}
        def live(_r, _k, kind, name, namespace):
            if kind == "kustomization": return active if state["active"] else dormant
            return object_(kind.title(), name, namespace, uid=kind + "-uid")
        original_run = runner.run
        def run(args, *, input_text=None):
            if " patch " in " " + " ".join(args) + " ": state["active"] = True
            return original_run(args, input_text=input_text)
        runner.run = run
        with patch.object(MODULE, "render", return_value=blobs), patch.object(MODULE, "verify_live", side_effect=verify), patch.object(MODULE, "live_obj", side_effect=live), patch.object(MODULE, "inventory", return_value=None), patch.object(MODULE, "route_matrix", return_value=[{"method": "GET", "path": "/api/staging-participant/v1/status", "status": 200}]), patch.object(MODULE, "now", side_effect=["2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z", "2026-01-01T00:00:02Z", "2026-01-01T00:00:03Z", "2026-01-01T00:00:04Z"]):
            result = MODULE.activate(value, REV, str(kube), runner, True, Path(tempfile.mkstemp()[1]))
        self.assertEqual(result["status"], "activated"); self.assertEqual([x["kind"] for x in result["created"]], list(MODULE.CREATE_KINDS)); self.assertTrue(all("canonicalSha256" in x for x in result["created"]))
    def test_uncertain_create_rolls_back_incomplete_and_persists(self):
        receipt = Path(tempfile.mkstemp()[1]); runner = Fake(); created = [("Ingress", object_("Ingress", uid="i"))]
        with patch.object(MODULE, "live_obj", side_effect=MODULE.ActivationError("unknown live UID")):
            complete, errors = MODULE.rollback(runner, "/tmp/k", created, object_("Kustomization", MODULE.NAME, MODULE.FLUX_NAMESPACE, uid="k"))
        self.assertFalse(complete); self.assertTrue(errors)
        MODULE.atomic_receipt(receipt, {"schemaVersion": MODULE.RECEIPT_SCHEMA, "status": "rollback-incomplete"})
        saved = json.loads(receipt.read_text()); self.assertEqual(saved["status"], "rollback-incomplete"); self.assertIn("canonicalSha256", saved)
    def test_precondition_delete_uses_uid_and_resource_version(self):
        runner = Fake(); before = object_("Ingress", uid="u", rv="99")
        MODULE.delete_with_preconditions(runner, "/tmp/k", "ingress", before)
        command = " ".join(runner.calls[-1][0]); self.assertIn("--raw", command); self.assertIn("resourceVersion", runner.calls[-1][0][-1]); self.assertIn("\"uid\":\"u\"", runner.calls[-1][0][-1])

if __name__ == "__main__": unittest.main()
