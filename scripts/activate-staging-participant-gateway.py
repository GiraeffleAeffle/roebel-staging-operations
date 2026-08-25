#!/usr/bin/env python3
"""Policy-owned, fail-closed participant-gateway activation executor.

This program deliberately accepts no evidence, manifest, route, command, or
allowlist from its caller.  A future protected policy bootstrap must add the
fixed descriptor named below.  Until then *both* modes stop before contacting
Kubernetes.  The live mode is consequently safe to ship before its policy.
"""
from __future__ import annotations
import argparse, datetime as dt, hashlib, json, os, subprocess, sys, tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

POLICY_PATH = "policy/staging-participant-gateway-activation-policy.json"
RENDER_ROOT = "reviewed-render/roebel-staging/staging-participant-gateway"
RENDER_FILES = ("networkpolicy.json", "serviceaccount.json", "service.json", "deployment.json", "ingress.json", "kustomization.yaml", "runtime-pin.json")
CREATE_FILES = RENDER_FILES[:5]
CREATE_KINDS = ("NetworkPolicy", "ServiceAccount", "Service", "Deployment", "Ingress")
NAMESPACE, FLUX_NAMESPACE = "stadtstack-roebel-web-preview", "flux-roebel-staging"
NAME, SOURCE, WEB_INGRESS = "roebel-staging-participant-gateway", "roebel-staging-operations", "roebel-web-presentation"
SCHEMA, RECEIPT_SCHEMA = "roebel_staging_participant_gateway_activation_policy_v3", "roebel_staging_participant_gateway_activation_receipt_v3"
ROOT = Path(__file__).resolve().parent.parent

class ActivationError(RuntimeError): pass
def canonical(v: Any) -> str: return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
def digest(v: Any) -> str: return "sha256:" + hashlib.sha256(canonical(v).encode()).hexdigest()
def bytes_digest(v: bytes) -> str: return "sha256:" + hashlib.sha256(v).hexdigest()
def now() -> str: return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
def require(v: bool, msg: str) -> None:
    if not v: raise ActivationError(msg)
def sha(v: Any, label: str) -> str:
    require(isinstance(v, str) and len(v) == 71 and v.startswith("sha256:"), f"{label} must be sha256")
    try: int(v[7:], 16)
    except ValueError as exc: raise ActivationError(f"{label} must be sha256") from exc
    return v
def revision(v: Any) -> str:
    require(isinstance(v, str) and len(v) == 40 and all(c in "0123456789abcdef" for c in v), "expected revision must be 40 lowercase hex")
    return v

@dataclass
class Result: code: int = 0; out: str = ""; err: str = ""
class Runner:
    def run(self, args: list[str], *, input_text: str | None = None) -> Result:
        p = subprocess.run(args, input=input_text, text=True, capture_output=True, check=False); return Result(p.returncode, p.stdout, p.stderr)
def checked(r: Runner, args: list[str], label: str, input_text: str | None = None) -> str:
    x = r.run(args, input_text=input_text)
    if x.code:
        text = (x.out + "\n" + x.err).strip()
        if "AlreadyExists" in text or "409" in text: raise ActivationError(f"{label}: create conflict; adoption forbidden")
        raise ActivationError(f"{label}: {text[:400]}")
    return x.out
def obj(raw: str, label: str) -> dict[str, Any]:
    try: value = json.loads(raw)
    except json.JSONDecodeError as exc: raise ActivationError(f"{label}: invalid JSON") from exc
    require(isinstance(value, dict), f"{label}: JSON object required"); return value
def kb(kubeconfig: str) -> list[str]: return ["kubectl", "--kubeconfig", kubeconfig]
def get(r: Runner, args: list[str], label: str) -> dict[str, Any]: return obj(checked(r, args + ["-o", "json"], label), label)
def git_blob(rev: str, path: str) -> bytes:
    # Both revision and path originate in fixed code/policy, never CLI/evidence.
    p = subprocess.run(["git", "-C", str(ROOT), "show", f"{rev}:{path}"], capture_output=True, check=False)
    if p.returncode: raise ActivationError(f"protected Git blob unavailable: {path}")
    return p.stdout
def live_obj(r: Runner, kube: str, kind: str, name: str, namespace: str) -> dict[str, Any]: return get(r, kb(kube) + ["-n", namespace, "get", kind, name], f"live {kind}/{name}")
def stable_object(value: dict[str, Any]) -> dict[str, Any]:
    """Compare desired manifests to live objects without server-generated fields."""
    result = json.loads(canonical(value)); metadata = result.get("metadata", {})
    for key in ("uid", "resourceVersion", "generation", "creationTimestamp", "managedFields"): metadata.pop(key, None)
    result.pop("status", None); return result
def public_projection(value: Any) -> Any:
    """Policy and receipts cannot carry Secret data; refuse it rather than scrub."""
    encoded = canonical(value).lower()
    require(not any(x in encoded for x in ('"data"', '"stringdata"', '"token"', '"password"', '"privatekey"')), "secret-shaped value is forbidden")
    return value

def policy(rev: str) -> dict[str, Any]:
    path = ROOT / POLICY_PATH
    require(path.is_file() and not path.is_symlink(), "protected activation policy descriptor is not wired")
    raw = path.read_bytes(); require(bytes_digest(git_blob(rev, POLICY_PATH)) == bytes_digest(raw), "policy descriptor is not the exact checked-out protected Git blob")
    p = obj(raw.decode(), "activation policy descriptor"); public_projection(p)
    required = {"schemaVersion", "protectedRevision", "renderBlobs", "liveProjections", "routeMatrix", "haproxy", "desiredPolicyObjectDigests"}
    require(required <= set(p), "activation policy descriptor is incomplete")
    require(p["schemaVersion"] == SCHEMA and p["protectedRevision"] == rev, "activation policy revision/schema mismatch")
    require(set(p["renderBlobs"]) == set(RENDER_FILES), "activation policy render blob inventory is not closed")
    for name, value in p["renderBlobs"].items(): sha(value, f"render blob {name}")
    projection = p["liveProjections"]
    require(set(projection) == {"sharedSource", "dormantKustomization", "activeKustomization", "serviceAccount", "role", "roleBinding", "retainedWebIngress", "networkPolicyInventory", "ciliumNetworkPolicyInventory", "ciliumClusterwideNetworkPolicyInventory"}, "activation policy live projections are not closed")
    for key, value in projection.items(): sha(value, f"live projection {key}")
    route = p["routeMatrix"]; require(isinstance(route, dict) and set(route) == {"host", "expectations"} and isinstance(route["host"], str) and route["host"].startswith("https://"), "activation policy route matrix invalid")
    require(isinstance(route["expectations"], dict) and route["expectations"], "activation policy route expectations absent")
    haproxy = p["haproxy"]
    require(set(haproxy) == {"namespace", "daemonSet", "replicas", "sourceIpRateLimitPerReplica", "uid", "canonicalSha256"} and haproxy["namespace"] == "ingress-system" and haproxy["daemonSet"] == "haproxy-ingress" and haproxy["replicas"] == 3 and haproxy["sourceIpRateLimitPerReplica"] == 30 and isinstance(haproxy["uid"], str) and haproxy["uid"], "HAProxy policy projection invalid")
    sha(haproxy["canonicalSha256"], "HAProxy projection")
    require(isinstance(p["desiredPolicyObjectDigests"], list) and p["desiredPolicyObjectDigests"], "desired policy object digest set absent")
    for item in p["desiredPolicyObjectDigests"]: sha(item, "desired policy object digest")
    return p

def render(rev: str, p: dict[str, Any]) -> dict[str, bytes]:
    result = {}
    for name in RENDER_FILES:
        content = git_blob(rev, f"{RENDER_ROOT}/{name}")
        require(bytes_digest(content) == p["renderBlobs"][name], f"render Git blob drift: {name}")
        result[name] = content
    for name, kind in zip(CREATE_FILES, CREATE_KINDS, strict=True):
        item = obj(result[name].decode(), name); meta = item.get("metadata", {})
        require(item.get("kind") == kind and meta.get("name") == NAME and meta.get("namespace") == NAMESPACE, f"render object ownership drift: {name}")
    return result

def labels_match(selector: dict[str, Any]) -> bool:
    labels = {"app.kubernetes.io/component": "staging-participant-gateway", "app.kubernetes.io/name": NAME, "app.kubernetes.io/part-of": "stadtstack", "stadtstack.io/authority": "none", "stadtstack.io/environment": "staging"}
    require(isinstance(selector, dict) and set(selector) <= {"matchLabels", "matchExpressions"}, "unrecognized policy selector")
    ml, me = selector.get("matchLabels", {}), selector.get("matchExpressions", [])
    require(isinstance(ml, dict) and isinstance(me, list), "invalid policy selector")
    if any(labels.get(k) != v for k, v in ml.items()): return False
    for e in me:
        require(isinstance(e, dict) and set(e) <= {"key", "operator", "values"}, "invalid match expression")
        key, op, values = e.get("key"), e.get("operator"), e.get("values", [])
        require(isinstance(key, str) and op in {"In", "NotIn", "Exists", "DoesNotExist"} and isinstance(values, list), "invalid match expression")
        value = labels.get(key)
        if (op == "In" and (value is None or value not in values)) or (op == "NotIn" and value is not None and value in values) or (op == "Exists" and value is None) or (op == "DoesNotExist" and value is not None): return False
    return True
def inventory(r: Runner, kube: str, p: dict[str, Any]) -> None:
    sources = (("networkPolicyInventory", "networkpolicy", ["-A"], "podSelector", True), ("ciliumNetworkPolicyInventory", "ciliumnetworkpolicies.cilium.io", ["-A"], "endpointSelector", True), ("ciliumClusterwideNetworkPolicyInventory", "ciliumclusterwidenetworkpolicies.cilium.io", [], "endpointSelector", False))
    for pin, resource, extra, field, namespaced in sources:
        value = get(r, kb(kube) + ["get", resource] + extra, resource); retained = []
        for item in value.get("items", []):
            if namespaced and item.get("metadata", {}).get("namespace") != NAMESPACE:
                retained.append(item); continue
            specs = item.get("specs") if field == "endpointSelector" and isinstance(item.get("specs"), list) else [item.get("spec", {})]
            if any(labels_match(spec.get(field, {})) for spec in specs if isinstance(spec, dict)):
                require(digest(stable_object(item)) in p["desiredPolicyObjectDigests"], f"pre-existing {resource} selects participant labels")
                continue
            retained.append(item)
        require(digest(retained) == p["liveProjections"][pin], f"{resource} inventory projection drift")
def verify_live(r: Runner, kube: str, p: dict[str, Any], *, dormant: bool) -> dict[str, Any]:
    q = p["liveProjections"]
    kustomization_pin = "dormantKustomization" if dormant else "activeKustomization"
    specs = (("gitrepository", SOURCE, FLUX_NAMESPACE, "sharedSource"), ("kustomization", NAME, FLUX_NAMESPACE, kustomization_pin), ("serviceaccount", NAME, NAMESPACE, "serviceAccount"), ("role", NAME, NAMESPACE, "role"), ("rolebinding", NAME, NAMESPACE, "roleBinding"), ("ingress", WEB_INGRESS, NAMESPACE, "retainedWebIngress"))
    values = {}
    for kind, name, namespace, pin in specs:
        value = live_obj(r, kube, kind, name, namespace); require(digest(value) == q[pin], f"live {pin} projection drift"); values[pin] = value
    require(values["sharedSource"].get("spec", {}).get("suspend") is not True, "shared source suspended")
    values["participantKustomization"] = values.pop(kustomization_pin)
    require(values["participantKustomization"].get("spec", {}).get("suspend") is dormant, "participant Kustomization suspension drift")
    if not dormant: require(values["participantKustomization"].get("status", {}).get("lastAppliedRevision") == f"main@sha1:{p['protectedRevision']}", "Flux applied revision drift")
    haproxy = live_obj(r, kube, "daemonset", p["haproxy"]["daemonSet"], p["haproxy"]["namespace"])
    require(haproxy.get("metadata", {}).get("uid") == p["haproxy"]["uid"] and digest(haproxy) == p["haproxy"]["canonicalSha256"], "HAProxy projection drift")
    require(haproxy.get("status", {}).get("numberReady") == p["haproxy"]["replicas"], "HAProxy replicas not ready")
    values["haproxy"] = haproxy
    inventory(r, kube, p); return values

def route_matrix(r: Runner, p: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for key, expected in p["routeMatrix"]["expectations"].items():
        require(isinstance(key, str) and " " in key and isinstance(expected, int) and 100 <= expected <= 599, "route expectation invalid")
        method, path = key.split(" ", 1); require(method in {"GET", "POST", "OPTIONS", "HEAD", "DELETE"} and path.startswith("/api/staging-participant/v1/"), "route boundary widened")
        args = ["curl", "--silent", "--show-error", "--output", os.devnull, "--write-out", "%{http_code}", "--request", method]
        if method == "POST": args += ["--header", "content-type: application/json", "--data", "{}"]
        observed = checked(r, args + [p["routeMatrix"]["host"].rstrip("/") + path], f"route {key}").strip()
        require(observed == str(expected), f"route status mismatch {key}"); result.append({"method": method, "path": path, "status": expected})
    return result

def atomic_receipt(path: Path, value: dict[str, Any]) -> None:
    public_projection(value); value["canonicalSha256"] = digest(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as f: f.write(canonical(value) + "\n"); tmp = Path(f.name)
    os.replace(tmp, path)
def delete_with_preconditions(r: Runner, kube: str, kind: str, before: dict[str, Any]) -> None:
    m = before["metadata"]; payload = canonical({"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": m["uid"], "resourceVersion": m["resourceVersion"]}})
    api, plural = {"ingress": ("networking.k8s.io/v1", "ingresses"), "networkpolicy": ("networking.k8s.io/v1", "networkpolicies"), "deployment": ("apps/v1", "deployments"), "service": ("v1", "services"), "serviceaccount": ("v1", "serviceaccounts")}[kind]
    prefix = "/api" if api == "v1" else "/apis"
    # kubectl's raw request transports Kubernetes DeleteOptions unchanged;
    # UID+resourceVersion prevent a recreate from being deleted by rollback.
    checked(r, kb(kube) + ["-n", NAMESPACE, "delete", kind, m["name"], "--raw", f"{prefix}/{api}/namespaces/{NAMESPACE}/{plural}/{m['name']}", "--data", payload], f"rollback delete {kind}")

def rollback(r: Runner, kube: str, created: list[tuple[str, dict[str, Any]]], kustomization: dict[str, Any]) -> tuple[bool, list[str]]:
    errors = []
    try:
        current = live_obj(r, kube, "kustomization", NAME, FLUX_NAMESPACE)
        require(current["metadata"]["uid"] == kustomization["metadata"]["uid"], "Kustomization UID changed during rollback")
        patch = canonical({"metadata": {"resourceVersion": current["metadata"]["resourceVersion"]}, "spec": {"suspend": True}})
        checked(r, kb(kube) + ["-n", FLUX_NAMESPACE, "patch", "kustomization", NAME, "--type=merge", "-p", patch], "rollback CAS suspend")
        require(live_obj(r, kube, "kustomization", NAME, FLUX_NAMESPACE).get("spec", {}).get("suspend") is True, "Kustomization suspension uncertain")
    except Exception as exc: return False, [str(exc)]
    order = {"Ingress": 0, "Deployment": 1, "Service": 2, "ServiceAccount": 3, "NetworkPolicy": 4}
    for kind, value in sorted(created, key=lambda pair: order[pair[0]]):
        try: delete_with_preconditions(r, kube, kind.lower(), value)
        except Exception as exc: errors.append(str(exc)); break
    return not errors, errors

def activate(p: dict[str, Any], rev: str, kube: str | None, r: Runner, live: bool, receipt_path: Path) -> dict[str, Any]:
    rendered = render(rev, p)
    if not live: return {"schemaVersion": RECEIPT_SCHEMA, "status": "dry-run-passed-policy-wired", "protectedRevision": rev, "runnerScriptSha256": bytes_digest(Path(__file__).read_bytes()), "at": now()}
    require(kube is not None and Path(kube).is_file(), "live activation requires explicit existing kubeconfig")
    started = now(); prior = verify_live(r, kube, p, dormant=True); created: list[tuple[str, dict[str, Any]]] = []; timings: dict[str, str] = {"preflightVerifiedAt": now()}
    try:
        for file, kind in zip(CREATE_FILES, CREATE_KINDS, strict=True):
            # ``create -o json`` is the only creation record we trust: it binds
            # the UID/resourceVersion returned by the API to this transaction.
            item = obj(checked(r, kb(kube) + ["-n", NAMESPACE, "create", "-f", "-", "-o", "json"], f"create {kind}", rendered[file].decode()), f"created {kind}")
            require(item.get("kind") == kind and item.get("metadata", {}).get("name") == NAME and item.get("metadata", {}).get("namespace") == NAMESPACE and item.get("metadata", {}).get("uid") and item.get("metadata", {}).get("resourceVersion"), f"atomic create response invalid for {kind}")
            created.append((kind, item))
            inventory(r, kube, p)
            if kind == "Deployment":
                checked(r, kb(kube) + ["-n", NAMESPACE, "rollout", "status", f"deployment/{NAME}", "--timeout=120s"], "deployment readiness")
                checked(r, kb(kube) + ["-n", "ingress-system", "rollout", "status", "daemonset/haproxy-ingress", "--timeout=120s"], "HAProxy readiness")
                timings["internalAndHaproxyReadyAt"] = now()
            if kind == "Ingress": timings["ingressCreatedAt"] = now()
        routes = route_matrix(r, p)
        k = prior["participantKustomization"]; patch = canonical({"metadata": {"resourceVersion": k["metadata"]["resourceVersion"]}, "spec": {"suspend": False}})
        checked(r, kb(kube) + ["-n", FLUX_NAMESPACE, "patch", "kustomization", NAME, "--type=merge", "-p", patch], "CAS unsuspend")
        after = live_obj(r, kube, "kustomization", NAME, FLUX_NAMESPACE); require(after.get("spec", {}).get("suspend") is False, "CAS unsuspend ambiguous")
        checked(r, kb(kube) + ["-n", FLUX_NAMESPACE, "wait", "--for=condition=Ready", f"kustomization/{NAME}", "--timeout=120s"], "Flux readiness")
        inventory(r, kube, p); final = verify_live(r, kube, p, dormant=False)
        timings["completedAt"] = now()
        require(timings.get("internalAndHaproxyReadyAt", "") <= timings.get("ingressCreatedAt", ""), "Ingress was not created last after health")
        return {"schemaVersion": RECEIPT_SCHEMA, "status": "activated", "protectedRevision": rev, "runnerScriptSha256": bytes_digest(Path(__file__).read_bytes()), "startedAt": started, "timings": timings, "routeMatrix": routes, "created": [{"kind": kind, "uid": x["metadata"]["uid"], "resourceVersion": x["metadata"]["resourceVersion"], "canonicalSha256": digest(x)} for kind, x in created], "preProjectionDigests": {key: digest(value) for key, value in prior.items()}, "postProjectionDigests": {key: digest(value) for key, value in final.items()}}
    except Exception as exc:
        complete, errors = rollback(r, kube, created, prior["participantKustomization"])
        status = "rolled-back" if complete else "rollback-incomplete"
        failure = {"schemaVersion": RECEIPT_SCHEMA, "status": status, "protectedRevision": rev, "runnerScriptSha256": bytes_digest(Path(__file__).read_bytes()), "startedAt": started, "completedAt": now(), "failure": str(exc), "rollbackErrors": errors, "created": [{"kind": kind, "uid": x["metadata"]["uid"], "resourceVersion": x["metadata"]["resourceVersion"]} for kind, x in created]}
        atomic_receipt(receipt_path, failure); raise ActivationError(f"activation {status}: {exc}") from exc

def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--expected-protected-revision", required=True); ap.add_argument("--dry-run", action="store_true"); ap.add_argument("--live", action="store_true"); ap.add_argument("--kubeconfig"); ap.add_argument("--receipt", type=Path, default=Path("participant-gateway-activation-receipt.json")); a = ap.parse_args()
    if a.dry_run == a.live: print("activation blocked: choose exactly one of --dry-run or --live", file=sys.stderr); return 2
    try:
        rev = revision(a.expected_protected_revision); require((ROOT / ".git").exists(), "executor must run from the protected repository checkout")
        require(subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True, capture_output=True, check=False).stdout.strip() == rev, "checked-out Git revision is not expected protected revision")
        result = activate(policy(rev), rev, a.kubeconfig, Runner(), a.live, a.receipt)
        atomic_receipt(a.receipt, result); print(canonical(result)); return 0
    except (ActivationError, OSError, json.JSONDecodeError) as exc: print(f"activation blocked: {exc}", file=sys.stderr); return 2
if __name__ == "__main__": raise SystemExit(main())
