#!/usr/bin/env python3
"""Fail-closed executor for the staging participant gateway.

``--dry-run`` validates a separately-approved evidence document and emits a
deterministic plan without starting subprocesses. ``--live`` repeats the
checks using an explicit kubeconfig, creates only the exact objects approved
in the render, and rolls those exact UIDs back on any mismatch.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

SCHEMA = "roebel_staging_participant_gateway_activation_evidence_v2"
RECEIPT_SCHEMA = "roebel_staging_participant_gateway_activation_receipt_v2"
FRESHNESS_SECONDS = 300
TARGET_NAMESPACE = "stadtstack-roebel-web-preview"
FLUX_NAMESPACE = "flux-roebel-staging"
SOURCE_NAME = "roebel-staging-operations"
KUSTOMIZATION_NAME = GATEWAY_NAME = "roebel-staging-participant-gateway"
WEB_INGRESS_NAME = "roebel-web-presentation"
RENDER_FILES = ("networkpolicy.json", "serviceaccount.json", "service.json", "deployment.json", "ingress.json", "kustomization.yaml", "runtime-pin.json")
CREATE_FILES, CREATE_ORDER = RENDER_FILES[:5], ("NetworkPolicy", "ServiceAccount", "Service", "Deployment", "Ingress")
ALLOWED_PATHS = ("/api/staging-participant/v1/status", "/api/staging-participant/v1/challenge", "/api/staging-participant/v1/session", "/api/staging-participant/v1/posts", "/api/staging-participant/v1/comments")
ALLOWED_METHODS = {"GET": (ALLOWED_PATHS[0],), "POST": ALLOWED_PATHS[1:], "OPTIONS": ALLOWED_PATHS}
SECRET_MARKERS = ("secret", "token", "password", "privatekey", "private_key", "credential")

class ActivationError(RuntimeError): pass

def canonical(value: Any) -> str: return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
def digest(value: Any) -> str: return "sha256:" + hashlib.sha256(canonical(value).encode()).hexdigest()
def bytes_digest(value: bytes) -> str: return "sha256:" + hashlib.sha256(value).hexdigest()
def utc_now() -> dt.datetime: return dt.datetime.now(dt.timezone.utc)

def parse_time(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str): raise ActivationError(f"{label} must be an RFC3339 UTC timestamp")
    try: parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc: raise ActivationError(f"{label} timestamp invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0): raise ActivationError(f"{label} must be UTC")
    return parsed

def no_secret_material(value: Any, path: str = "evidence") -> None:
    """Evidence may refer to a keyset but can never transport a secret value."""
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = str(key).lower().replace("-", "").replace("_", "")
            if any(marker.replace("_", "") in lowered for marker in SECRET_MARKERS):
                if key not in {"secretMaterialization", "secretRefs", "secretKeySet", "secretsKeysetsMatch"} or isinstance(child, (str, bytes)):
                    raise ActivationError(f"{path}.{key} is not permitted in activation evidence")
            no_secret_material(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value): no_secret_material(child, f"{path}[{index}]")

def require_keys(value: Any, required: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict): raise ActivationError(f"{label} must be an object")
    if missing := required - set(value): raise ActivationError(f"{label} missing {', '.join(sorted(missing))}")
    return value

def require_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:") or len(value) != 71: raise ActivationError(f"{label} must be a sha256 digest")
    try: int(value[7:], 16)
    except ValueError as exc: raise ActivationError(f"{label} must be a sha256 digest") from exc
    return value

def validate_evidence(evidence: dict[str, Any], protected_revision: str, now: dt.datetime) -> None:
    no_secret_material(evidence)
    required = {"schemaVersion", "status", "protectedRevision", "checkedAt", "validUntil", "maxAgeSeconds", "sharedFluxSource", "webIngress", "networkPolicyInventory", "render", "publication", "secretMaterialization", "databaseVaultPreflight", "gnosisChainCheck", "dnsTlsEvidence", "rollback", "routeExpectations"}
    require_keys(evidence, required, "activation evidence")
    if evidence["schemaVersion"] != SCHEMA or evidence["status"] != "approved-separate-review": raise ActivationError("activation evidence is not separately approved")
    if len(protected_revision) != 40 or any(char not in "0123456789abcdef" for char in protected_revision): raise ActivationError("protected revision must be 40 lowercase hexadecimal characters")
    if evidence["protectedRevision"] != protected_revision: raise ActivationError("protected revision does not match separately approved evidence")
    if evidence["maxAgeSeconds"] != FRESHNESS_SECONDS: raise ActivationError("activation evidence freshness budget must be 300 seconds")
    checked, valid_until = parse_time(evidence["checkedAt"], "checkedAt"), parse_time(evidence["validUntil"], "validUntil")
    if not checked <= now <= valid_until or (valid_until - checked).total_seconds() > FRESHNESS_SECONDS: raise ActivationError("activation evidence is stale or not yet valid")
    source = require_keys(evidence["sharedFluxSource"], {"uid", "specCanonicalSha256", "artifactRevision", "artifactDigest"}, "sharedFluxSource")
    require_sha(source["specCanonicalSha256"], "sharedFluxSource.specCanonicalSha256"); require_sha(source["artifactDigest"], "sharedFluxSource.artifactDigest")
    if not isinstance(source["uid"], str) or not source["uid"] or source["artifactRevision"] != f"main@sha1:{protected_revision}": raise ActivationError("sharedFluxSource artifact revision is not the exact protected revision")
    ingress = require_keys(evidence["webIngress"], {"uid", "canonicalSha256"}, "webIngress"); require_sha(ingress["canonicalSha256"], "webIngress.canonicalSha256")
    if not isinstance(ingress["uid"], str) or not ingress["uid"]: raise ActivationError("webIngress UID invalid")
    inventories = require_keys(evidence["networkPolicyInventory"], {"networkPolicyCanonicalSha256", "ciliumNetworkPolicyCanonicalSha256", "ciliumClusterwideNetworkPolicyCanonicalSha256"}, "networkPolicyInventory")
    for key in ("networkPolicyCanonicalSha256", "ciliumNetworkPolicyCanonicalSha256", "ciliumClusterwideNetworkPolicyCanonicalSha256"): require_sha(inventories[key], f"networkPolicyInventory.{key}")
    render = require_keys(evidence["render"], {"manifestSha256", "expectedObjects"}, "render")
    if set(render["manifestSha256"]) != set(RENDER_FILES): raise ActivationError("render manifest inventory is not closed")
    for name, value in render["manifestSha256"].items(): require_sha(value, f"render.manifestSha256.{name}")
    expected = render["expectedObjects"]
    if not isinstance(expected, list) or len(expected) != len(CREATE_FILES): raise ActivationError("render expected object inventory invalid")
    for entry, expected_kind in zip(expected, CREATE_ORDER, strict=True):
        require_keys(entry, {"kind", "name", "namespace"}, "render expected object")
        if entry["kind"] != expected_kind or entry["name"] != GATEWAY_NAME or entry["namespace"] != TARGET_NAMESPACE: raise ActivationError("render expected object ownership invalid")
    if not isinstance(evidence["secretMaterialization"], dict): raise ActivationError("secret materialization evidence must be semantic metadata")
    projection = require_keys(evidence.get("liveSemanticProjection"), {"command", "canonicalSha256"}, "liveSemanticProjection")
    if not isinstance(projection["command"], list) or not projection["command"] or not all(isinstance(item, str) and item for item in projection["command"]): raise ActivationError("live semantic projection command invalid")
    require_sha(projection["canonicalSha256"], "liveSemanticProjection.canonicalSha256")

def json_object(raw: str, label: str) -> dict[str, Any]:
    try: value = json.loads(raw)
    except json.JSONDecodeError as exc: raise ActivationError(f"{label} returned invalid JSON") from exc
    if not isinstance(value, dict): raise ActivationError(f"{label} returned a non-object")
    return value

@dataclass
class CommandResult:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""

class Runner:
    def run(self, args: list[str], *, input_text: str | None = None) -> CommandResult:
        completed = subprocess.run(args, input=input_text, text=True, capture_output=True, check=False)
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)

def run_checked(runner: Runner, args: list[str], *, input_text: str | None = None, label: str) -> str:
    result = runner.run(args, input_text=input_text)
    if result.returncode:
        text = (result.stdout + "\n" + result.stderr).strip()
        if "409" in text or "AlreadyExists" in text: raise ActivationError(f"{label} conflicts with an existing object; adoption is forbidden")
        raise ActivationError(f"{label} failed: {text[:400]}")
    return result.stdout

def kube_base(kubeconfig: str) -> list[str]: return ["kubectl", "--kubeconfig", kubeconfig]
def get_json(runner: Runner, args: list[str], label: str) -> dict[str, Any]: return json_object(run_checked(runner, args + ["-o", "json"], label=label), label)
def object_spec_digest(value: dict[str, Any]) -> str: return digest(value.get("spec", {}))
def artifact_fields(value: dict[str, Any]) -> tuple[str | None, str | None]:
    artifact = value.get("status", {}).get("artifact", {}); return artifact.get("revision"), artifact.get("digest")
def inventory_digest(value: dict[str, Any]) -> str: return digest(value.get("items", []))

def selector_matches(selector: dict[str, Any], labels: dict[str, str]) -> bool:
    """Closed Kubernetes/Cilium label selector evaluator; empty means all pods."""
    if not isinstance(selector, dict): raise ActivationError("policy selector is not an object")
    allowed = {"matchLabels", "matchExpressions"}
    if set(selector) - allowed: raise ActivationError("policy selector has unsupported fields")
    match_labels = selector.get("matchLabels", {})
    expressions = selector.get("matchExpressions", [])
    if not isinstance(match_labels, dict) or not isinstance(expressions, list): raise ActivationError("policy selector shape invalid")
    if any(not isinstance(key, str) or labels.get(key) != value for key, value in match_labels.items()): return False
    for expression in expressions:
        if not isinstance(expression, dict) or set(expression) - {"key", "operator", "values"}: raise ActivationError("policy match expression invalid")
        key, operator, values = expression.get("key"), expression.get("operator"), expression.get("values", [])
        if not isinstance(key, str) or operator not in {"In", "NotIn", "Exists", "DoesNotExist"} or not isinstance(values, list): raise ActivationError("policy match expression invalid")
        value = labels.get(key)
        if operator == "In" and (value is None or value not in values): return False
        if operator == "NotIn" and value is not None and value in values: return False
        if operator == "Exists" and value is None: return False
        if operator == "DoesNotExist" and value is not None: return False
    return True

def assert_no_preexisting_policy_selects_gateway(inventories: dict[str, dict[str, Any]], evidence: dict[str, Any]) -> None:
    allowlist = evidence["networkPolicyInventory"].get("preexistingSelectorAllowlist", [])
    if not isinstance(allowlist, list): raise ActivationError("policy selector allowlist invalid")
    allowed = {(entry.get("kind"), entry.get("namespace"), entry.get("name"), entry.get("canonicalSha256")) for entry in allowlist if isinstance(entry, dict)}
    labels = {"app.kubernetes.io/component": "staging-participant-gateway", "app.kubernetes.io/name": GATEWAY_NAME, "app.kubernetes.io/part-of": "stadtstack", "stadtstack.io/authority": "none", "stadtstack.io/environment": "staging"}
    for inventory_key, inventory in inventories.items():
        for item in inventory.get("items", []):
            kind, metadata = item.get("kind"), item.get("metadata", {})
            namespace, name = metadata.get("namespace", ""), metadata.get("name", "")
            if inventory_key == "networkPolicyCanonicalSha256":
                if namespace != TARGET_NAMESPACE: continue
                selectors = [item.get("spec", {}).get("podSelector", {})]
            else:
                if inventory_key == "ciliumNetworkPolicyCanonicalSha256" and namespace != TARGET_NAMESPACE: continue
                specs = item.get("specs") if isinstance(item.get("specs"), list) else [item.get("spec", {})]
                selectors = [spec.get("endpointSelector", {}) for spec in specs if isinstance(spec, dict)]
            if any(selector_matches(selector, labels) for selector in selectors):
                identity = (kind, namespace, name, digest(item))
                if identity not in allowed: raise ActivationError(f"preexisting {kind}/{namespace}/{name} selects participant gateway labels")

def assert_semantic_projection(runner: Runner, evidence: dict[str, Any]) -> dict[str, Any]:
    """Run a protected-runner local preflight that emits only a secret-free projection."""
    command = evidence["liveSemanticProjection"]["command"]
    output = run_checked(runner, command, label="live semantic preflight")
    projection = json_object(output, "live semantic preflight")
    no_secret_material(projection, "live semantic preflight")
    if digest(projection) != evidence["liveSemanticProjection"]["canonicalSha256"]: raise ActivationError("live semantic preflight drifted")
    required = {"secretsKeysetsMatch", "databaseVaultPassed", "gnosisChainId", "dnsTlsPassed", "haproxyUid", "haproxyReplicas", "sourceIpRateLimitPerReplica"}
    require_keys(projection, required, "live semantic preflight")
    if projection["secretsKeysetsMatch"] is not True or projection["databaseVaultPassed"] is not True or projection["gnosisChainId"] != "0x64" or projection["dnsTlsPassed"] is not True: raise ActivationError("live semantic preflight failed")
    if not isinstance(projection["haproxyUid"], str) or not projection["haproxyUid"] or projection["haproxyReplicas"] != 3 or projection["sourceIpRateLimitPerReplica"] != 30: raise ActivationError("HAProxy identity, replica, or per-source rate semantics drifted")
    return projection

def assert_live_preconditions(runner: Runner, kubeconfig: str, evidence: dict[str, Any]) -> dict[str, Any]:
    base = kube_base(kubeconfig)
    source = get_json(runner, base + ["-n", FLUX_NAMESPACE, "get", "gitrepository", SOURCE_NAME], "shared Flux GitRepository")
    expected = evidence["sharedFluxSource"]
    actual_revision, actual_digest = artifact_fields(source)
    if source.get("metadata", {}).get("uid") != expected["uid"] or object_spec_digest(source) != expected["specCanonicalSha256"]: raise ActivationError("shared Flux GitRepository ownership or spec drifted")
    if actual_revision != expected["artifactRevision"] or actual_digest != expected["artifactDigest"]: raise ActivationError("shared Flux GitRepository artifact drifted")
    if source.get("spec", {}).get("suspend") is True: raise ActivationError("shared Flux GitRepository is suspended")
    web = get_json(runner, base + ["-n", TARGET_NAMESPACE, "get", "ingress", WEB_INGRESS_NAME], "existing Web Ingress")
    expected_web = evidence["webIngress"]
    if web.get("metadata", {}).get("uid") != expected_web["uid"] or digest(web) != expected_web["canonicalSha256"]: raise ActivationError("existing Web Ingress changed; activation may not proceed")
    inventories: dict[str, dict[str, Any]] = {}
    for key, resource, namespace_args in (("networkPolicyCanonicalSha256", "networkpolicy", ["-A"]), ("ciliumNetworkPolicyCanonicalSha256", "ciliumnetworkpolicies.cilium.io", ["-A"]), ("ciliumClusterwideNetworkPolicyCanonicalSha256", "ciliumclusterwidenetworkpolicies.cilium.io", [])):
        item = get_json(runner, base + ["get", resource] + namespace_args, resource)
        if inventory_digest(item) != evidence["networkPolicyInventory"][key]: raise ActivationError(f"{resource} inventory or selector drifted")
        inventories[key] = item
    assert_no_preexisting_policy_selects_gateway(inventories, evidence)
    semantic = assert_semantic_projection(runner, evidence)
    kustomization = get_json(runner, base + ["-n", FLUX_NAMESPACE, "get", "kustomization", KUSTOMIZATION_NAME], "participant Kustomization")
    if kustomization.get("spec", {}).get("suspend") is not True: raise ActivationError("participant Kustomization must be dormant before activation")
    if kustomization.get("spec", {}).get("sourceRef", {}).get("name") != SOURCE_NAME: raise ActivationError("participant Kustomization references the wrong source")
    if kustomization.get("metadata", {}).get("labels", {}).get("stadtstack.io/flux-tenant") != "roebel-staging": raise ActivationError("participant Kustomization tenant label missing")
    return {"source": source, "webIngress": web, "inventories": inventories, "semantic": semantic, "kustomization": kustomization}

def load_render(render_root: Path, evidence: dict[str, Any]) -> dict[str, bytes]:
    rendered: dict[str, bytes] = {}
    for name in RENDER_FILES:
        path = render_root / name
        if not path.is_file() or path.is_symlink(): raise ActivationError(f"render file is absent or not a regular file: {name}")
        content = path.read_bytes()
        if bytes_digest(content) != evidence["render"]["manifestSha256"][name]: raise ActivationError(f"render file digest mismatch: {name}")
        rendered[name] = content
    for name, expected_kind in zip(CREATE_FILES, CREATE_ORDER, strict=True):
        manifest, metadata = json_object(rendered[name].decode(), name), json_object(rendered[name].decode(), name).get("metadata", {})
        if manifest.get("kind") != expected_kind or metadata.get("name") != GATEWAY_NAME or metadata.get("namespace") != TARGET_NAMESPACE: raise ActivationError(f"render object mismatch: {name}")
    return rendered

def route_requests(evidence: dict[str, Any]) -> list[tuple[str, str, int]]:
    expectations = evidence.get("routeExpectations")
    if not isinstance(expectations, dict): raise ActivationError("route expectations missing")
    requests: list[tuple[str, str, int]] = []; expected_keys: set[str] = set()
    for method, paths in ALLOWED_METHODS.items():
        for path in paths:
            key, status = f"{method} {path}", expectations.get(f"{method} {path}")
            expected_keys.add(key)
            if not isinstance(status, int) or not 200 <= status < 500: raise ActivationError(f"route expectation invalid: {key}")
            requests.append((method, path, status))
    negatives = [("HEAD", path, 405) for path in ALLOWED_PATHS] + [("GET", path, 405) for path in ALLOWED_PATHS[1:]] + [("POST", ALLOWED_PATHS[0], 405), ("DELETE", ALLOWED_PATHS[0], 405), ("POST", "/api/staging-participant/v1/not-approved", 404)]
    for method, path, default in negatives:
        key = f"{method} {path}"; expected_keys.add(key)
        if expectations.get(key, default) != default: raise ActivationError(f"negative route expectation is widened: {key}")
        requests.append((method, path, default))
    if set(expectations) != expected_keys: raise ActivationError("route expectations are not a closed method/path matrix")
    return requests

def command_plan(render_root: Path, evidence: dict[str, Any]) -> list[dict[str, Any]]:
    plan: list[dict[str, Any]] = []
    for file_name, kind in zip(CREATE_FILES, CREATE_ORDER, strict=True):
        plan.append({"step": f"create-{kind.lower()}", "verb": "create-only", "manifest": str(render_root / file_name)})
        if kind == "Deployment": plan.append({"step": "wait-internal-health", "verb": "rollout-status", "resource": f"deployment/{GATEWAY_NAME}"})
    return plan + [{"step": "verify-web-ingress-unchanged", "verb": "digest-compare", "resource": f"ingress/{WEB_INGRESS_NAME}"}, {"step": "verify-route-matrix", "verb": "https-method-matrix", "requestCount": len(route_requests(evidence))}, {"step": "cas-unsuspend-participant-kustomization", "verb": "resource-version-guarded-patch", "resource": f"kustomization/{KUSTOMIZATION_NAME}"}, {"step": "verify-flux-ready-exact-revision", "verb": "wait-and-verify", "resource": f"kustomization/{KUSTOMIZATION_NAME}"}]

def run_route_matrix(runner: Runner, endpoint: str, evidence: dict[str, Any]) -> list[dict[str, Any]]:
    if not endpoint.startswith("https://"): raise ActivationError("gateway endpoint must be HTTPS")
    results: list[dict[str, Any]] = []
    for method, path, expected in route_requests(evidence):
        # Do not use --fail here: 404/405 are the *successful* proof for the
        # negative half of the public boundary matrix.  Transport failures
        # still cause curl to return non-zero and are rejected by run_checked.
        args = ["curl", "--silent", "--show-error", "--output", os.devnull, "--write-out", "%{http_code}", "--request", method]
        if method == "POST": args += ["--header", "content-type: application/json", "--data", "{}"]
        observed = run_checked(runner, args + [endpoint.rstrip("/") + path], label=f"route {method} {path}").strip()
        if observed != str(expected): raise ActivationError(f"route boundary mismatch for {method} {path}: expected {expected}, got {observed}")
        results.append({"method": method, "path": path, "status": expected})
    return results

def cas_suspend(runner: Runner, kubeconfig: str, resource_version: str, value: bool) -> None:
    patch = canonical({"metadata": {"resourceVersion": resource_version}, "spec": {"suspend": value}})
    run_checked(runner, kube_base(kubeconfig) + ["-n", FLUX_NAMESPACE, "patch", "kustomization", KUSTOMIZATION_NAME, "--type=merge", "-p", patch], label="CAS participant Kustomization patch")

def delete_exact(runner: Runner, kubeconfig: str, kind: str, name: str, uid: str) -> None:
    current = get_json(runner, kube_base(kubeconfig) + ["-n", TARGET_NAMESPACE, "get", kind, name], f"rollback {kind}/{name}")
    if current.get("metadata", {}).get("uid") != uid: raise ActivationError(f"rollback refuses {kind}/{name}: UID changed")
    run_checked(runner, kube_base(kubeconfig) + ["-n", TARGET_NAMESPACE, "delete", kind, name, "--wait=true"], label=f"rollback delete {kind}/{name}")

def rollback(runner: Runner, kubeconfig: str, kustomization: dict[str, Any], created: list[dict[str, str]], flux_active: bool) -> list[str]:
    errors: list[str] = []
    if flux_active:
        try:
            current = get_json(runner, kube_base(kubeconfig) + ["-n", FLUX_NAMESPACE, "get", "kustomization", KUSTOMIZATION_NAME], "rollback Kustomization")
            if current.get("metadata", {}).get("uid") != kustomization.get("metadata", {}).get("uid"): errors.append("rollback refuses participant Kustomization: UID changed")
            else:
                cas_suspend(runner, kubeconfig, current["metadata"]["resourceVersion"], True)
                suspended = get_json(runner, kube_base(kubeconfig) + ["-n", FLUX_NAMESPACE, "get", "kustomization", KUSTOMIZATION_NAME], "rollback Kustomization suspension")
                if suspended.get("metadata", {}).get("uid") != current.get("metadata", {}).get("uid") or suspended.get("spec", {}).get("suspend") is not True: errors.append("rollback Kustomization suspension could not be verified")
        except Exception as exc: errors.append(str(exc))
    deletion_order = {"Ingress": 0, "Deployment": 1, "Service": 2, "ServiceAccount": 3, "NetworkPolicy": 4}
    for item in sorted(created, key=lambda item: deletion_order[item["kind"]]):
        try: delete_exact(runner, kubeconfig, item["kind"].lower(), item["name"], item["uid"])
        except Exception as exc: errors.append(str(exc))
    return errors

def receipt(evidence: dict[str, Any], protected_revision: str, *, status: str, live: dict[str, Any] | None = None, created: list[dict[str, str]] | None = None, route_matrix: list[dict[str, Any]] | None = None, transaction: dict[str, Any] | None = None, rollback_errors: list[str] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"schemaVersion": RECEIPT_SCHEMA, "status": status, "protectedRevision": protected_revision, "activationEvidenceCanonicalSha256": digest(evidence), "createOrder": list(CREATE_ORDER), "secretValuesCaptured": False, "at": utc_now().isoformat().replace("+00:00", "Z")}
    if live is not None: result["livePreconditionObjectUids"] = {"sharedFluxSource": live["source"]["metadata"]["uid"], "webIngress": live["webIngress"]["metadata"]["uid"], "participantKustomization": live["kustomization"]["metadata"]["uid"]}
    if created is not None: result["createdObjects"] = created
    if route_matrix is not None: result["routeMatrix"] = route_matrix
    if transaction is not None: result["transaction"] = transaction
    if rollback_errors: result["rollbackErrors"] = rollback_errors
    return result

def activate(evidence: dict[str, Any], protected_revision: str, render_root: Path, *, kubeconfig: str | None, endpoint: str | None, runner: Runner | None = None, live_mode: bool = False, now: Callable[[], dt.datetime] = utc_now) -> dict[str, Any]:
    """Perform a dry plan or the exact guarded transaction.

    The caller supplies a protected-runner-produced evidence file; it is never
    treated as authority by itself.  The live rechecks below bind it again to
    the current shared GitRepository, the existing Web Ingress, all policy
    inventories and a dormant tenant Kustomization before any create occurs.
    """
    validate_evidence(evidence, protected_revision, now()); load_render(render_root, evidence)
    if not live_mode: return receipt(evidence, protected_revision, status="dry-run-passed") | {"plan": command_plan(render_root, evidence)}
    if not kubeconfig or not Path(kubeconfig).is_file() or not endpoint: raise ActivationError("live mode requires explicit existing --kubeconfig and --gateway-url")
    executor = runner or Runner(); live = assert_live_preconditions(executor, kubeconfig, evidence); rendered = load_render(render_root, evidence)
    created: list[dict[str, str]] = []; flux_active = False; transaction: dict[str, Any] = {"startedAt": utc_now().isoformat().replace("+00:00", "Z"), "healthBeforeIngress": False, "ingressCreatedLast": False}
    try:
        for name, kind in zip(CREATE_FILES, CREATE_ORDER, strict=True):
            run_checked(executor, kube_base(kubeconfig) + ["-n", TARGET_NAMESPACE, "create", "-f", "-"], input_text=rendered[name].decode(), label=f"create-only {kind}")
            created_object = get_json(executor, kube_base(kubeconfig) + ["-n", TARGET_NAMESPACE, "get", kind.lower(), GATEWAY_NAME], f"created {kind}")
            uid = created_object.get("metadata", {}).get("uid")
            if not uid: raise ActivationError(f"created {kind} has no UID")
            created.append({"kind": kind, "name": GATEWAY_NAME, "uid": uid, "resourceVersion": created_object["metadata"].get("resourceVersion", ""), "canonicalSha256": digest(created_object)})
            if kind == "Deployment":
                run_checked(executor, kube_base(kubeconfig) + ["-n", TARGET_NAMESPACE, "rollout", "status", f"deployment/{GATEWAY_NAME}", "--timeout=120s"], label="participant internal health")
                transaction["healthBeforeIngress"] = True; transaction["healthVerifiedAt"] = utc_now().isoformat().replace("+00:00", "Z")
            if kind == "Ingress":
                if not transaction["healthBeforeIngress"]: raise ActivationError("Ingress cannot be created before internal health")
                transaction["ingressCreatedLast"] = True; transaction["ingressCreatedAt"] = utc_now().isoformat().replace("+00:00", "Z")
        web_after = get_json(executor, kube_base(kubeconfig) + ["-n", TARGET_NAMESPACE, "get", "ingress", WEB_INGRESS_NAME], "Web Ingress after creates")
        if digest(web_after) != evidence["webIngress"]["canonicalSha256"]: raise ActivationError("existing Web Ingress changed during activation")
        routes = run_route_matrix(executor, endpoint, evidence)
        transaction["casBeforeResourceVersion"] = live["kustomization"]["metadata"]["resourceVersion"]
        cas_suspend(executor, kubeconfig, transaction["casBeforeResourceVersion"], False); flux_active = True
        after_cas = get_json(executor, kube_base(kubeconfig) + ["-n", FLUX_NAMESPACE, "get", "kustomization", KUSTOMIZATION_NAME], "participant Kustomization CAS postcondition")
        if after_cas.get("metadata", {}).get("uid") != live["kustomization"]["metadata"]["uid"] or after_cas.get("spec", {}).get("suspend") is not False: raise ActivationError("participant Kustomization CAS postcondition failed")
        transaction["casAfterResourceVersion"] = after_cas["metadata"].get("resourceVersion", "")
        run_checked(executor, kube_base(kubeconfig) + ["-n", FLUX_NAMESPACE, "wait", "--for=condition=Ready", f"kustomization/{KUSTOMIZATION_NAME}", "--timeout=120s"], label="participant Flux readiness")
        ready = get_json(executor, kube_base(kubeconfig) + ["-n", FLUX_NAMESPACE, "get", "kustomization", KUSTOMIZATION_NAME], "participant Flux exact revision")
        if ready.get("status", {}).get("lastAppliedRevision") != evidence["sharedFluxSource"]["artifactRevision"]: raise ActivationError("participant Flux applied an unexpected revision")
        # The source, existing Web ingress and all policy inventories are re-read
        # after Flux activation; only the expected suspend transition may differ.
        source_after = get_json(executor, kube_base(kubeconfig) + ["-n", FLUX_NAMESPACE, "get", "gitrepository", SOURCE_NAME], "shared Flux source postcondition")
        web_after_flux = get_json(executor, kube_base(kubeconfig) + ["-n", TARGET_NAMESPACE, "get", "ingress", WEB_INGRESS_NAME], "Web Ingress postcondition")
        if source_after.get("metadata", {}).get("uid") != live["source"]["metadata"]["uid"] or object_spec_digest(source_after) != evidence["sharedFluxSource"]["specCanonicalSha256"] or artifact_fields(source_after) != (evidence["sharedFluxSource"]["artifactRevision"], evidence["sharedFluxSource"]["artifactDigest"]) or digest(web_after_flux) != evidence["webIngress"]["canonicalSha256"]: raise ActivationError("shared source or existing Web Ingress changed during activation")
        transaction["completedAt"] = utc_now().isoformat().replace("+00:00", "Z"); transaction["appliedRevision"] = ready["status"]["lastAppliedRevision"]; transaction["sourceArtifactDigest"] = evidence["sharedFluxSource"]["artifactDigest"]
        return receipt(evidence, protected_revision, status="activated", live=live, created=created, route_matrix=routes, transaction=transaction)
    except Exception as exc:
        rollback_errors = rollback(executor, kubeconfig, live["kustomization"], created, flux_active)
        failed = receipt(evidence, protected_revision, status="rolled-back", live=live, created=created, transaction=transaction, rollback_errors=rollback_errors)
        raise ActivationError(f"activation failed and rollback was attempted: {exc}; receipt={canonical(failed)}") from exc

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--expected-protected-revision", "--protected-revision", dest="protected_revision", required=True)
    parser.add_argument("--render-root", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True); mode.add_argument("--dry-run", action="store_true"); mode.add_argument("--live", action="store_true")
    parser.add_argument("--kubeconfig"); parser.add_argument("--gateway-url"); parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    try:
        result = activate(json.loads(args.evidence.read_text()), args.protected_revision, args.render_root, kubeconfig=args.kubeconfig, endpoint=args.gateway_url, live_mode=args.live)
    except (ActivationError, OSError, json.JSONDecodeError) as exc:
        print(f"activation blocked: {exc}", file=sys.stderr); return 2
    rendered = canonical(result) + "\n"
    if args.receipt: args.receipt.write_text(rendered)
    print(rendered, end=""); return 0

if __name__ == "__main__": raise SystemExit(main())
