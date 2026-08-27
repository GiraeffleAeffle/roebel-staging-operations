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
import signal
import stat
import subprocess
import sys
import time
import types
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
GIT_BIN = Path("/usr/bin/git")
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

def trusted_git(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[Any]:
    info = os.lstat(GIT_BIN)
    require(
        stat.S_ISREG(info.st_mode)
        and not GIT_BIN.is_symlink()
        and info.st_uid == 0
        and stat.S_IMODE(info.st_mode) & 0o022 == 0
        and os.access(GIT_BIN, os.X_OK),
        "trusted Git executable metadata invalid",
    )
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "HOME": "/dev/null",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    return subprocess.run([str(GIT_BIN), "--no-replace-objects", *args], env=environment, **kwargs)


def git_blob(rev: str, path: str) -> bytes:
    revision(rev)
    try:
        result = trusted_git(
            ["-C", str(ROOT), "show", f"{rev}:{path}"],
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
    return hashes


def load_context(rev: str) -> dict[str, Any]:
    revision(rev)
    head = trusted_git(
        ["-C", str(ROOT), "rev-parse", "HEAD"],
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
        """Remove the bootstrap nonce despite controller-owned status races."""
        require(self.snapshot is not None, "Kubernetes adapter used before protected preflight")
        require(isinstance(resource_version, str) and resource_version.isdigit(), "created resourceVersion invalid")
        target = self.bootstrap_module.target_of(desired)
        self._item(target)
        path = "/metadata/annotations/" + self.bootstrap_module.NONCE_ANNOTATION.replace("~", "~0").replace("/", "~1")
        expected_with_nonce = self.bootstrap_module._with_nonce(desired, nonce)
        last_error = "nonce removal retry exhausted"
        for attempt in range(4):
            current = self.get(target)
            require(current is not None, f"nonce removal target absent: {target['kind']}/{target['name']}")
            metadata = current.get("metadata", {})
            require(metadata.get("uid") == uid, f"nonce removal UID drift: {target['kind']}/{target['name']}")
            current_resource_version = metadata.get("resourceVersion")
            require(isinstance(current_resource_version, str) and current_resource_version.isdigit(), f"nonce removal resourceVersion absent: {target['kind']}/{target['name']}")
            annotations = metadata.get("annotations", {})
            current_nonce = annotations.get(self.bootstrap_module.NONCE_ANNOTATION) if isinstance(annotations, dict) else None
            if current_nonce is None:
                self.policy_module.require_semantically_equal(current, desired, f"completed nonce removal {target['name']}")
                return current
            require(current_nonce == nonce, f"nonce removal ownership drift: {target['kind']}/{target['name']}")
            self.policy_module.require_semantically_equal(current, expected_with_nonce, f"owned nonce removal {target['name']}")
            patch = [
                {"op": "test", "path": "/metadata/uid", "value": uid},
                {"op": "test", "path": "/metadata/resourceVersion", "value": current_resource_version},
                {"op": "test", "path": path, "value": nonce},
                {"op": "remove", "path": path},
            ]
            response = self.runner.run(
                self.activation.kb(str(self.snapshot.path))
                + ["-n", target["namespace"], "patch", target["kind"].lower(), target["name"], "--type=json", "-p", canonical(patch), "-o", "json"],
                timeout=self.policy["httpBoundary"]["timeoutsSeconds"]["kubernetesRequest"],
            )
            if response.code == 0:
                after = self.activation.obj(response.out, f"nonce removal {target['kind']}/{target['name']}")
                self.policy_module.require_semantically_equal(after, desired, f"nonce removal {target['name']}")
                return after
            last_error = response.err.strip()[:512] or f"exit {response.code}"
            if attempt < 3:
                time.sleep(0.05 * (attempt + 1))
        raise CliError(f"remove dormant bootstrap nonce {target['kind']}/{target['name']}: {last_error}")

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
        require(self.snapshot is not None, "authenticated Kubernetes DELETE snapshot absent")
        self.activation.raw_delete(
            self.snapshot,
            resource_path,
            payload,
            self.policy["httpBoundary"]["timeoutsSeconds"]["kubernetesRequest"],
        )

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
    modes.add_argument("--teardown", action="store_true")
    modes.add_argument("--verify-success-receipt", type=Path)
    modes.add_argument("--verify-teardown-receipt", type=Path)
    modes.add_argument("--verify-success-receipt-fd", type=int)
    modes.add_argument("--verify-teardown-receipt-fd", type=int)
    parser.add_argument("--kubeconfig")
    parser.add_argument("--receipt", type=Path, default=Path("participant-flux-bootstrap-receipt.json"))
    recovery = parser.add_mutually_exclusive_group()
    recovery.add_argument("--recovery-receipt", type=Path)
    recovery.add_argument("--recovery-receipt-fd", type=int)
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
            require(args.kubeconfig is None and args.recovery_receipt is None and args.recovery_receipt_fd is None, "dry-run accepts no kubeconfig or recovery receipt")
            sink = module.ReceiptSink.reserve(args.receipt)
            sink.commit(plan)
            print(canonical(plan))
            return 0
        try:
            context["policyModule"].assert_activation_ready(context["policy"])
        except context["policyModule"].PolicyError as exc:
            raise CliError(str(exc)) from exc
        if any(
            value is not None
            for value in (
                args.verify_success_receipt,
                args.verify_success_receipt_fd,
                args.verify_teardown_receipt,
                args.verify_teardown_receipt_fd,
            )
        ):
            require(args.kubeconfig is None and args.recovery_receipt is None and args.recovery_receipt_fd is None, "receipt verification accepts no kubeconfig or recovery receipt")
            if args.verify_success_receipt is not None or args.verify_success_receipt_fd is not None:
                receipt = module.load_receipt(args.verify_success_receipt) if args.verify_success_receipt is not None else module.load_receipt_fd(args.verify_success_receipt_fd)
                result = module.bind_success_receipt(plan, receipt)
            else:
                receipt = module.load_receipt(args.verify_teardown_receipt) if args.verify_teardown_receipt is not None else module.load_receipt_fd(args.verify_teardown_receipt_fd)
                result = module.bind_teardown_receipt(plan, receipt)
            print(canonical(result))
            return 0
        require(isinstance(args.kubeconfig, str) and args.kubeconfig, "live/recovery/teardown bootstrap requires explicit --kubeconfig")
        if args.live:
            require(args.recovery_receipt is None and args.recovery_receipt_fd is None, "live bootstrap accepts no recovery receipt")
            prior = None
            mode = "live"
        else:
            require(args.recovery_receipt is not None or args.recovery_receipt_fd is not None, "recovery/teardown mode requires a recovery receipt")
            prior = module.load_receipt(args.recovery_receipt) if args.recovery_receipt is not None else module.load_receipt_fd(args.recovery_receipt_fd)
            mode = "teardown" if args.teardown else "recover"
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
        expected = {
            "live": "dormant-ready",
            "recover": "recovered-rolled-back",
            "teardown": "dormant-torn-down",
        }[mode]
        require(result["status"] == expected, f"Flux bootstrap incomplete: {result['status']}")
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
