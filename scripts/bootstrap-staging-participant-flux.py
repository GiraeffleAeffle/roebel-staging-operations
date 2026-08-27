#!/usr/bin/env python3
"""Protected create-only bootstrap for the two dormant participant Flux paths.

The committed policy is intentionally inert.  Dry-run therefore emits a
blocked, no-Kubernetes plan.  A later exact policy-only transition may make
the same protected runner live; live mode then creates only the eight policy
objects, leaves both Kustomizations suspended, and writes the receipt that the
separate activation runner must bind.
"""
from __future__ import annotations

import sys as _bootstrap_sys
if __name__ == "__main__" and not (_bootstrap_sys.flags.isolated and _bootstrap_sys.flags.safe_path):
    print("Flux bootstrap blocked: invoke with python3 -I", file=_bootstrap_sys.stderr)
    raise SystemExit(2)

import argparse
import copy
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import types
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
POLICY_PATH = "policy/staging-participant-gateway-activation-policy.json"
POLICY_MODULE_PATH = "scripts/staging_participant_gateway_policy.py"
BOOTSTRAP_MODULE_PATH = "scripts/staging_participant_flux_bootstrap.py"
ACTIVATION_RUNNER_PATH = "scripts/activate-staging-participant-gateway.py"
BOOTSTRAP_RUNNER_PATH = "scripts/bootstrap-staging-participant-flux.py"
LIVE_WRAPPER_PATH = "scripts/run-staging-participant-gateway-live.py"
BOOTSTRAP_WORKFLOW_PATH = ".github/workflows/staging-participant-flux-bootstrap.yml"
PROTECTED_PATHS = (
    BOOTSTRAP_RUNNER_PATH,
    LIVE_WRAPPER_PATH,
    BOOTSTRAP_MODULE_PATH,
    POLICY_MODULE_PATH,
    POLICY_PATH,
    ACTIVATION_RUNNER_PATH,
    BOOTSTRAP_WORKFLOW_PATH,
    "scripts/verify-reviewed-render.py",
    "policy/repository-contract.json",
)
REVISION = re.compile(r"^[0-9a-f]{40}$")


class CliError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CliError(message)


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def bytes_sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def revision(value: Any) -> str:
    require(isinstance(value, str) and REVISION.fullmatch(value) is not None, "expected revision must be 40 lowercase hex")
    return value


def git_blob(rev: str, path: str) -> bytes:
    revision(rev)
    try:
        result = subprocess.run(
            ["git", "-C", str(ROOT), "show", f"{rev}:{path}"],
            capture_output=True,
            check=False,
            timeout=10,
        )
    except subprocess.TimeoutExpired as exc:
        raise CliError(f"protected Git blob read timed out: {path}") from exc
    require(result.returncode == 0, f"protected Git blob unavailable: {path}")
    return result.stdout


def compile_verified_module(source: bytes, *, name: str, path: str, rev: str) -> Any:
    revision(rev)
    require(isinstance(source, bytes) and source, f"protected module empty: {path}")
    module = types.ModuleType(f"{name}_{rev}")
    module.__file__ = f"git:{rev}:{path}"
    module.__package__ = ""
    sys.modules[module.__name__] = module
    try:
        exec(compile(source, module.__file__, "exec", dont_inherit=True), module.__dict__)
    except BaseException:
        sys.modules.pop(module.__name__, None)
        raise
    return module


def protected_checkout(rev: str) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in PROTECTED_PATHS:
        local = ROOT / path
        require(local.is_file() and not local.is_symlink(), f"protected bootstrap file missing: {path}")
        expected = git_blob(rev, path)
        require(local.read_bytes() == expected, f"protected bootstrap file differs from exact Git blob: {path}")
        hashes[path] = bytes_sha256(expected)
    working = subprocess.run(["git", "-C", str(ROOT), "diff", "--quiet", rev, "--", *PROTECTED_PATHS], check=False)
    staged = subprocess.run(["git", "-C", str(ROOT), "diff", "--cached", "--quiet", rev, "--", *PROTECTED_PATHS], check=False)
    require(working.returncode == 0 and staged.returncode == 0, "protected Flux bootstrap checkout is dirty")
    return hashes


def load_context(rev: str) -> dict[str, Any]:
    revision(rev)
    head = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        text=True,
        capture_output=True,
        check=False,
    )
    require(head.returncode == 0 and head.stdout.strip() == rev, "checked-out Git revision is not expected protected revision")
    hashes = protected_checkout(rev)
    policy_module = compile_verified_module(
        git_blob(rev, POLICY_MODULE_PATH),
        name="staging_participant_gateway_policy",
        path=POLICY_MODULE_PATH,
        rev=rev,
    )
    bootstrap_module = compile_verified_module(
        git_blob(rev, BOOTSTRAP_MODULE_PATH),
        name="staging_participant_flux_bootstrap",
        path=BOOTSTRAP_MODULE_PATH,
        rev=rev,
    )
    try:
        descriptor = bootstrap_module._json_object(git_blob(rev, POLICY_PATH).decode("utf-8"), POLICY_PATH)
        descriptor = policy_module.validate_activation_policy(descriptor)
    except (UnicodeDecodeError, policy_module.PolicyError, bootstrap_module.BootstrapError) as exc:
        raise CliError(str(exc)) from exc
    plan = bootstrap_module.build_plan(policy_module, descriptor, rev, hashes)
    return {
        "revision": rev,
        "hashes": hashes,
        "policy": descriptor,
        "policyModule": policy_module,
        "bootstrapModule": bootstrap_module,
        "plan": plan,
    }


def _target_key(target: dict[str, str]) -> tuple[str, str, str, str]:
    return target["apiVersion"], target["kind"], target["namespace"], target["name"]


class KubernetesAdapter:
    """Closed adapter over one snapshotted kubeconfig and eight exact names."""

    def __init__(self, explicit_kubeconfig: str, context: dict[str, Any]):
        require(isinstance(explicit_kubeconfig, str) and explicit_kubeconfig, "live bootstrap requires explicit --kubeconfig")
        self.context = context
        self.policy = context["policy"]
        self.policy_module = context["policyModule"]
        self.bootstrap_module = context["bootstrapModule"]
        self.plan = context["plan"]
        self.allowed_targets = {_target_key(item["target"]): item for item in self.plan["objects"]}
        activation_source = git_blob(context["revision"], ACTIVATION_RUNNER_PATH)
        self.activation = compile_verified_module(
            activation_source,
            name="staging_participant_gateway_activation_support",
            path=ACTIVATION_RUNNER_PATH,
            rev=context["revision"],
        )
        self.activation.POLICY = self.policy_module
        self.runner = self.activation.Runner()
        self.explicit_kubeconfig = explicit_kubeconfig
        self.snapshot = None
        self.preserved = None
        self.initial_source = None
        self._rollback_signals_deferred = False

    def close(self) -> None:
        if self.snapshot is not None:
            self.snapshot.close()

    def begin_rollback(self) -> None:
        self.activation.defer_transaction_signals_v4()
        self._rollback_signals_deferred = True

    def _item(self, target: dict[str, str]) -> dict[str, Any]:
        item = self.allowed_targets.get(_target_key(target))
        require(item is not None and target == item["target"], "Kubernetes target outside exact dormant bootstrap plan")
        return item

    def get(self, target: dict[str, str]) -> dict[str, Any] | None:
        self._item(target)
        require(self.snapshot is not None, "Kubernetes adapter used before protected preflight")
        return self.activation.get_optional(
            self.runner,
            str(self.snapshot.path),
            target["kind"].lower(),
            target["name"],
            target["namespace"],
        )

    def preflight(self, _plan: dict[str, Any]) -> dict[str, Any]:
        require(self.snapshot is None, "Kubernetes preflight may run only once")
        self.snapshot = self.activation.snapshot_kubeconfig_v4(self.explicit_kubeconfig, self.runner)
        cluster = self.activation.cluster_binding_v4(self.runner, self.snapshot, self.policy)
        source = self.activation.shared_source_revision_v4(
            self.runner,
            str(self.snapshot.path),
            self.context["revision"],
        )
        preserved = self.activation.preservation_v4(self.runner, str(self.snapshot.path), self.policy)
        self.initial_source = copy.deepcopy(source)
        self.preserved = preserved
        return {
            "clusterBinding": cluster,
            "sharedSource": {
                "target": copy.deepcopy(self.policy["repositories"]["operations"]["fluxSource"]),
                "uid": source["metadata"]["uid"],
                "resourceVersion": source["metadata"]["resourceVersion"],
                "artifactRevision": source["status"]["artifact"]["revision"],
                "semanticSha256": self.policy_module.semantic_sha256(source),
                "mutation": "forbidden",
            },
            "preservation": {
                label: {
                    "target": copy.deepcopy(snapshot.target),
                    "beforeCanonicalSha256": snapshot.canonical_sha256,
                    "mutation": "forbidden",
                }
                for label, snapshot in preserved.items()
            },
            "secretAccess": "none",
        }

    def final_checks(self, _plan: dict[str, Any], before: dict[str, Any]) -> dict[str, Any]:
        require(self.preserved is not None and self.initial_source is not None, "bootstrap preservation snapshot absent")
        cluster = self.activation.cluster_binding_v4(self.runner, self.snapshot, self.policy)
        require(cluster == before["clusterBinding"], "cluster identity changed during dormant bootstrap")
        source = self.activation.shared_source_revision_v4(
            self.runner,
            str(self.snapshot.path),
            self.context["revision"],
        )
        require(source["metadata"]["uid"] == before["sharedSource"]["uid"], "shared Flux source UID changed")
        require(
            source["status"]["artifact"]["revision"] == before["sharedSource"]["artifactRevision"],
            "shared Flux source artifact revision changed",
        )
        preservation = self.activation.verify_preservation_v4(
            self.runner,
            str(self.snapshot.path),
            self.preserved,
        )
        return {
            "clusterBinding": cluster,
            "sharedSource": {
                "uid": source["metadata"]["uid"],
                "resourceVersion": source["metadata"]["resourceVersion"],
                "artifactRevision": source["status"]["artifact"]["revision"],
                "semanticSha256": self.policy_module.semantic_sha256(source),
                "mutation": "forbidden",
            },
            "preservation": preservation,
            "secretAccess": "none",
        }

    def create(self, desired: dict[str, Any]) -> Any:
        require(self.snapshot is not None, "Kubernetes adapter used before protected preflight")
        target = self.bootstrap_module.target_of(desired)
        item = self._item(target)
        annotations = desired.get("metadata", {}).get("annotations", {})
        nonce = annotations.get(self.bootstrap_module.NONCE_ANNOTATION) if isinstance(annotations, dict) else None
        require(isinstance(nonce, str), "bootstrap create operation nonce absent")
        self.policy_module.require_semantically_equal(
            desired,
            self.bootstrap_module._with_nonce(item["desired"], nonce),
            item["logicalName"],
        )
        response = self.runner.run(
            self.activation.kb(str(self.snapshot.path))
            + ["-n", target["namespace"], "create", "-f", "-", "-o", "json"],
            input_text=canonical(desired),
            timeout=self.policy["httpBoundary"]["timeoutsSeconds"]["kubernetesRequest"],
        )
        return self.bootstrap_module.RawResult(response.code, response.out, response.err)

    def remove_nonce(
        self,
        desired: dict[str, Any],
        uid: str,
        resource_version: str,
        nonce: str,
    ) -> dict[str, Any]:
        require(self.snapshot is not None, "Kubernetes adapter used before protected preflight")
        target = self.bootstrap_module.target_of(desired)
        self._item(target)
        path = "/metadata/annotations/" + self.bootstrap_module.NONCE_ANNOTATION.replace("~", "~0").replace("/", "~1")
        patch = [
            {"op": "test", "path": "/metadata/uid", "value": uid},
            {"op": "test", "path": "/metadata/resourceVersion", "value": resource_version},
            {"op": "test", "path": path, "value": nonce},
            {"op": "remove", "path": path},
        ]
        raw = self.activation.checked(
            self.runner,
            self.activation.kb(str(self.snapshot.path))
            + ["-n", target["namespace"], "patch", target["kind"].lower(), target["name"], "--type=json", "-p", canonical(patch), "-o", "json"],
            f"remove dormant bootstrap nonce {target['kind']}/{target['name']}",
            timeout=self.policy["httpBoundary"]["timeoutsSeconds"]["kubernetesRequest"],
        )
        after = self.activation.obj(raw, f"nonce removal {target['kind']}/{target['name']}")
        self.policy_module.require_semantically_equal(after, desired, f"nonce removal {target['name']}")
        return after

    def delete(self, target: dict[str, str], uid: str, resource_version: str) -> None:
        require(self.snapshot is not None, "Kubernetes adapter used before protected preflight")
        self._item(target)
        resource_path = self._resource_path(target)
        payload = canonical({
            "apiVersion": "v1",
            "kind": "DeleteOptions",
            "preconditions": {"uid": uid, "resourceVersion": resource_version},
        })
        self._raw_delete(resource_path, payload)

    def _resource_path(self, target: dict[str, str]) -> str:
        mappings = {
            ("v1", "ServiceAccount"): ("/api/v1", "serviceaccounts"),
            ("rbac.authorization.k8s.io/v1", "Role"): ("/apis/rbac.authorization.k8s.io/v1", "roles"),
            ("rbac.authorization.k8s.io/v1", "RoleBinding"): ("/apis/rbac.authorization.k8s.io/v1", "rolebindings"),
            ("kustomize.toolkit.fluxcd.io/v1", "Kustomization"): ("/apis/kustomize.toolkit.fluxcd.io/v1", "kustomizations"),
        }
        prefix, plural = mappings[(target["apiVersion"], target["kind"])]
        return f"{prefix}/namespaces/{target['namespace']}/{plural}/{target['name']}"

    def _raw_delete(self, resource_path: str, payload: str) -> None:
        allowed = {self._resource_path(item["target"]) for item in self.plan["objects"]}
        require(resource_path in allowed, "raw delete path outside exact dormant bootstrap plan")
        accept_path = "^" + resource_path.replace(".", r"\.") + "$"
        process = subprocess.Popen(
            self.activation.kb(str(self.snapshot.path))
            + ["proxy", "--port=0", "--address=127.0.0.1", "--accept-hosts=^127\\.0\\.0\\.1$", f"--accept-paths={accept_path}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env=self.activation.kubernetes_subprocess_environment_v4(),
        )
        selector = selectors.DefaultSelector()
        try:
            require(process.stdout is not None, "kubectl proxy output unavailable")
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 10
            output = b""
            port = None
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise CliError("kubectl proxy exited before bootstrap delete")
                events = selector.select(min(0.25, max(0.0, deadline - time.monotonic())))
                if not events:
                    continue
                chunk = os.read(process.stdout.fileno(), 4096)
                output = (output + chunk)[-16384:]
                match = re.search(rb"Starting to serve on 127\.0\.0\.1:(\d+)", output)
                if match:
                    port = int(match.group(1))
                    break
            require(port is not None, "kubectl proxy did not become ready for bootstrap delete")
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}{resource_path}",
                data=payload.encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="DELETE",
            )
            try:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(request, timeout=15) as response:
                    require(200 <= response.status < 300, "bootstrap delete did not return success")
            except urllib.error.HTTPError as exc:
                if exc.code != 404:
                    raise CliError(f"bootstrap delete rejected: HTTP {exc.code}") from exc
        finally:
            selector.close()
            self.activation._terminate_process_group(process)
            if process.stdout is not None:
                process.stdout.close()

    def wait_all_absent(self, targets: list[dict[str, str]]) -> bool:
        require({_target_key(target) for target in targets} == set(self.allowed_targets), "absence wait target set drift")
        timeouts = self.policy["httpBoundary"]["timeoutsSeconds"]
        deadline = time.monotonic() + timeouts["rollback"]
        quiet_start = None
        while time.monotonic() < deadline:
            live = [self.get(target) for target in targets]
            if all(value is None for value in live):
                quiet_start = quiet_start or time.monotonic()
                if time.monotonic() - quiet_start >= timeouts["rollbackAbsenceQuiet"]:
                    return True
            else:
                quiet_start = None
                for target, value in zip(targets, live, strict=True):
                    if value is None:
                        continue
                    finalizers = value.get("metadata", {}).get("finalizers", [])
                    allowed = ["finalizers.fluxcd.io"] if target["kind"] == "Kustomization" else []
                    require(finalizers in ([], allowed), f"unknown rollback finalizer on {target['kind']}/{target['name']}")
            time.sleep(timeouts["rollbackPoll"])
        return False


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-protected-revision", required=True)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--dry-run", action="store_true")
    modes.add_argument("--live", action="store_true")
    modes.add_argument("--recover", action="store_true")
    parser.add_argument("--kubeconfig")
    parser.add_argument("--receipt", type=Path, default=Path("participant-flux-bootstrap-receipt.json"))
    parser.add_argument("--recovery-receipt", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    adapter = None
    previous_signals = None
    try:
        require(sys.flags.isolated == 1 and bool(sys.flags.safe_path), "executor requires python3 -I isolated safe-path mode")
        os.environ.pop("PYTHONPATH", None)
        args = parse_args(argv)
        context = load_context(revision(args.expected_protected_revision))
        plan = context["plan"]
        module = context["bootstrapModule"]
        if args.dry_run:
            require(args.kubeconfig is None and args.recovery_receipt is None, "dry-run accepts no kubeconfig or recovery receipt")
            sink = module.ReceiptSink.reserve(args.receipt)
            sink.commit(plan)
            print(canonical(plan))
            return 0
        try:
            context["policyModule"].assert_activation_ready(context["policy"])
        except context["policyModule"].PolicyError as exc:
            raise CliError(str(exc)) from exc
        require(isinstance(args.kubeconfig, str) and args.kubeconfig, "live/recovery bootstrap requires explicit --kubeconfig")
        if args.live:
            require(args.recovery_receipt is None, "live bootstrap accepts no recovery receipt")
            prior = None
            mode = "live"
        else:
            require(args.recovery_receipt is not None, "recovery mode requires --recovery-receipt")
            prior = module.load_receipt(args.recovery_receipt)
            mode = "recover"
        # Receipt reservation and its first durable commit happen before the
        # adapter snapshots credentials or makes any Kubernetes request.
        sink = module.ReceiptSink.reserve(args.receipt)
        adapter = KubernetesAdapter(args.kubeconfig, context)
        previous_signals = adapter.activation.install_transaction_signal_handlers_v4()
        result = module.run(
            plan,
            mode=mode,
            kube=adapter,
            sink=sink,
            policy_module=context["policyModule"],
            prior_receipt=prior,
        )
        require(result["status"] in {"dormant-ready", "recovered-rolled-back"}, f"Flux bootstrap incomplete: {result['status']}")
        print(canonical(result))
        return 0
    except Exception as exc:
        print(f"Flux bootstrap blocked: {exc}", file=sys.stderr)
        return 2
    finally:
        if adapter is not None:
            try:
                if isinstance(previous_signals, dict):
                    adapter.activation.restore_transaction_signal_handlers_v4(previous_signals)
            finally:
                adapter.close()


if __name__ == "__main__":
    raise SystemExit(main())
