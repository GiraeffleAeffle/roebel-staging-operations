import copy, importlib.util, json, sys, tempfile, unittest
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
        self.assertTrue(MODULE.labels_match({}))
        self.assertTrue(MODULE.labels_match({"matchLabels": {"app.kubernetes.io/name": MODULE.NAME}}))
        self.assertFalse(MODULE.labels_match({"matchLabels": {"app.kubernetes.io/name": "other"}}))
    def test_live_gate_fails_before_runner_or_kubeconfig_validation(self):
        value = policy()
        with self.assertRaisesRegex(MODULE.POLICY.PolicyError, "activation blocked"):
            MODULE.POLICY.assert_activation_ready(value)
        self.assertFalse(value["activationReady"])
    def test_uncertain_create_rolls_back_incomplete_and_persists(self):
        receipt = Path(tempfile.mkstemp()[1]); runner = Fake(); created = [("Ingress", object_("Ingress", uid="i"))]
        with patch.object(MODULE, "live_obj", side_effect=MODULE.ActivationError("unknown live UID")):
            complete, errors = MODULE.rollback(runner, "/tmp/k", created, object_("Kustomization", MODULE.NAME, MODULE.FLUX_NAMESPACE, uid="k"))
        self.assertFalse(complete); self.assertTrue(errors)
        MODULE.atomic_receipt(receipt, {"schemaVersion": MODULE.RECEIPT_SCHEMA, "status": "rollback-incomplete"})
        saved = json.loads(receipt.read_text()); self.assertEqual(saved["status"], "rollback-incomplete"); self.assertIn("canonicalSha256", saved)
    def test_precondition_delete_uses_uid_and_resource_version(self):
        runner = Fake(); before = object_("Ingress", uid="u", rv="99")
        with patch.object(MODULE, "raw_delete") as delete:
            MODULE.delete_with_preconditions(runner, "/tmp/k", "ingress", before)
        path, payload = delete.call_args.args[1:]
        self.assertEqual(path, f"/apis/networking.k8s.io/v1/namespaces/{MODULE.NAMESPACE}/ingresses/{MODULE.NAME}")
        self.assertIn("resourceVersion", payload); self.assertIn("\"uid\":\"u\"", payload)

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

if __name__ == "__main__": unittest.main()
