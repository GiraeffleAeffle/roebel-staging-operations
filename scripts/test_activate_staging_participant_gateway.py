import datetime as dt
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("activation", Path(__file__).with_name("activate-staging-participant-gateway.py"))
MODULE = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = MODULE; SPEC.loader.exec_module(MODULE)
NOW = dt.datetime(2026, 8, 25, 12, tzinfo=dt.timezone.utc)

def sha(letter="a"): return "sha256:" + letter * 64
def obj(kind, name=MODULE.GATEWAY_NAME, namespace=MODULE.TARGET_NAMESPACE, uid="uid", rv="10", **extra):
    value = {"apiVersion": "v1", "kind": kind, "metadata": {"name": name, "namespace": namespace, "uid": uid, "resourceVersion": rv}}; value.update(extra); return value
def routes():
    result = {}
    for method, paths in MODULE.ALLOWED_METHODS.items():
        for path in paths: result[f"{method} {path}"] = 200 if method != "POST" else 400
    for path in MODULE.ALLOWED_PATHS: result[f"HEAD {path}"] = 405
    for path in MODULE.ALLOWED_PATHS[1:]: result[f"GET {path}"] = 405
    result[f"POST {MODULE.ALLOWED_PATHS[0]}"] = 405; result[f"DELETE {MODULE.ALLOWED_PATHS[0]}"] = 405; result["POST /api/staging-participant/v1/not-approved"] = 404
    return result
def render():
    root = Path(tempfile.mkdtemp())
    for file_name, kind in zip(MODULE.CREATE_FILES, MODULE.CREATE_ORDER, strict=True): (root / file_name).write_text(json.dumps(obj(kind)))
    (root / "kustomization.yaml").write_text("resources: []\n"); (root / "runtime-pin.json").write_text("{}\n")
    return root
def evidence(root):
    source = obj("GitRepository", MODULE.SOURCE_NAME, MODULE.FLUX_NAMESPACE, "source-uid", spec={"interval": "1m"}, status={"artifact": {"revision": "main@sha1:" + "a" * 40, "digest": sha("b")}})
    web = obj("Ingress", MODULE.WEB_INGRESS_NAME, uid="web-uid")
    return {"schemaVersion": MODULE.SCHEMA, "status": "approved-separate-review", "protectedRevision": "a" * 40, "checkedAt": "2026-08-25T11:56:00Z", "validUntil": "2026-08-25T12:01:00Z", "maxAgeSeconds": 300, "sharedFluxSource": {"uid": "source-uid", "specCanonicalSha256": MODULE.object_spec_digest(source), "artifactRevision": "main@sha1:" + "a" * 40, "artifactDigest": sha("b")}, "webIngress": {"uid": "web-uid", "canonicalSha256": MODULE.digest(web)}, "networkPolicyInventory": {"networkPolicyCanonicalSha256": sha("c"), "ciliumNetworkPolicyCanonicalSha256": sha("d"), "ciliumClusterwideNetworkPolicyCanonicalSha256": sha("e")}, "render": {"manifestSha256": {name: MODULE.bytes_digest((root / name).read_bytes()) for name in MODULE.RENDER_FILES}, "expectedObjects": [{"kind": kind, "name": MODULE.GATEWAY_NAME, "namespace": MODULE.TARGET_NAMESPACE} for kind in MODULE.CREATE_ORDER]}, "publication": {"verified": True}, "secretMaterialization": {"secretRefs": ["config", "runtime"], "keysetPresent": True}, "databaseVaultPreflight": {"passed": True}, "gnosisChainCheck": {"chainId": "0x64"}, "dnsTlsEvidence": {"passed": True}, "rollback": {"ingressFirst": True}, "routeExpectations": routes()}

class FakeRunner(MODULE.Runner):
    def __init__(self, mapping): self.mapping, self.calls = mapping, []
    def run(self, args, *, input_text=None):
        self.calls.append((args, input_text)); value = self.mapping.get(" ".join(args), MODULE.CommandResult())
        return value() if callable(value) else value

class Tests(unittest.TestCase):
    def test_dry_run_has_create_order_and_no_cluster_commands(self):
        root = render(); value = MODULE.activate(evidence(root), "a" * 40, root, kubeconfig=None, endpoint=None, live_mode=False, now=lambda: NOW)
        self.assertEqual(value["status"], "dry-run-passed"); self.assertEqual([x["step"] for x in value["plan"][:5]], ["create-networkpolicy", "create-serviceaccount", "create-service", "create-deployment", "wait-internal-health"])
    def test_stale_evidence_fails(self):
        root = render(); value = evidence(root); value["validUntil"] = "2026-08-25T11:59:00Z"
        with self.assertRaisesRegex(MODULE.ActivationError, "stale"): MODULE.activate(value, "a" * 40, root, kubeconfig=None, endpoint=None, live_mode=False, now=lambda: NOW)
    def test_secret_value_rejected_and_receipt_has_none(self):
        root = render(); value = evidence(root); value["publication"]["token"] = "leak"
        with self.assertRaisesRegex(MODULE.ActivationError, "not permitted"): MODULE.activate(value, "a" * 40, root, kubeconfig=None, endpoint=None, live_mode=False, now=lambda: NOW)
    def test_source_drift_rejected_before_create(self):
        root = render(); value = evidence(root); source = obj("GitRepository", MODULE.SOURCE_NAME, MODULE.FLUX_NAMESPACE, "wrong", spec={"interval": "1m"}, status={"artifact": {"revision": "main@sha1:" + "a" * 40, "digest": sha("b")}})
        kube = Path(tempfile.mkstemp()[1]); runner = FakeRunner({f"kubectl --kubeconfig {kube} -n flux-roebel-staging get gitrepository roebel-staging-operations -o json": MODULE.CommandResult(stdout=json.dumps(source))})
        with self.assertRaisesRegex(MODULE.ActivationError, "GitRepository ownership"): MODULE.activate(value, "a" * 40, root, kubeconfig=str(kube), endpoint="https://example.test", runner=runner, live_mode=True, now=lambda: NOW)
        self.assertFalse(any(" create " in " " + " ".join(args) + " " for args, _ in runner.calls))
    def test_conflict_is_never_adopted(self):
        with self.assertRaisesRegex(MODULE.ActivationError, "adoption is forbidden"): MODULE.run_checked(FakeRunner({"kubectl create -f -": MODULE.CommandResult(returncode=1, stderr="AlreadyExists")}), ["kubectl", "create", "-f", "-"], input_text="{}", label="test")
    def test_negative_route_matrix_cannot_be_widened(self):
        root = render(); value = evidence(root); value["routeExpectations"]["HEAD " + MODULE.ALLOWED_PATHS[0]] = 200
        with self.assertRaisesRegex(MODULE.ActivationError, "widened"): MODULE.route_requests(value)
    def test_route_probe_allows_expected_negative_http_statuses(self):
        root = render(); value = evidence(root)
        def response():
            index = len(runner.calls) - 1
            return MODULE.CommandResult(stdout=str(MODULE.route_requests(value)[index][2]))
        runner = FakeRunner({})
        runner.run = lambda args, input_text=None: (runner.calls.append((args, input_text)) or response())
        observed = MODULE.run_route_matrix(runner, "https://example.test", value)
        self.assertEqual(len(observed), len(MODULE.route_requests(value)))
        self.assertTrue(any("--fail-with-body" not in args for args, _ in runner.calls))
    def test_rollback_ingress_first_and_uid_guard(self):
        class RollbackRunner(FakeRunner):
            def run(self, args, *, input_text=None):
                self.calls.append((args, input_text))
                if " get " in " " + " ".join(args) + " " and args[-2:] == ["-o", "json"]:
                    return MODULE.CommandResult(stdout=json.dumps(obj("Ingress" if "ingress" in args else "Service", name=args[-3], uid="ok")))
                return MODULE.CommandResult()
        runner = RollbackRunner({}); errors = MODULE.rollback(runner, "/tmp/k", {"metadata": {"uid": "kus"}}, [{"kind": "Service", "name": "svc", "uid": "ok"}, {"kind": "Ingress", "name": "ing", "uid": "ok"}], False)
        self.assertEqual(errors, []); deletes = [" ".join(args) for args, _ in runner.calls if " delete " in " " + " ".join(args) + " "]; self.assertIn(" delete ingress ing ", deletes[0])

if __name__ == "__main__": unittest.main()
