#!/usr/bin/env python3
"""Protected one-time GET-only handover for the archived dormant Flux receipt."""
from __future__ import annotations

import sys as _bootstrap_sys
if __name__ == "__main__" and not (_bootstrap_sys.flags.isolated and _bootstrap_sys.flags.safe_path):
    print("participant dormant handover blocked: invoke with python3 -I", file=_bootstrap_sys.stderr)
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
import types
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
GIT_BIN = Path("/usr/bin/git")
ARCHIVE_REVISION = "08c4171573bb138845a9160e747f6ac56a3c754e"
ARCHIVE_RECEIPT_RAW_SHA256 = "sha256:32e244e5ba711aa8406a76d8dbf4fdd53289e52e2ced6ff27b77a7ae7577741f"
ARCHIVE_RECEIPT_CANONICAL_SHA256 = "sha256:ab90b49078f423c304b643b9354230611127d0ed6bda0d1022f3abc92772b081"
POLICY_PATH = "policy/staging-participant-gateway-activation-policy.json"
POLICY_MODULE_PATH = "scripts/staging_participant_gateway_policy.py"
BOOTSTRAP_MODULE_PATH = "scripts/staging_participant_flux_bootstrap.py"
BOOTSTRAP_RUNNER_PATH = "scripts/bootstrap-staging-participant-flux.py"
ACTIVATION_RUNNER_PATH = "scripts/activate-staging-participant-gateway.py"
LIVE_WRAPPER_PATH = "scripts/run-staging-participant-gateway-live.py"
HANDOVER_MODULE_PATH = "scripts/staging_participant_dormant_receipt_handover.py"
HANDOVER_RUNNER_PATH = "scripts/handover-staging-participant-dormant-receipt.py"
REPOSITORY_CONTRACT_PATH = "policy/repository-contract.json"
ARCHIVED_BOOTSTRAP_WORKFLOW_PATH = ".github/workflows/staging-participant-flux-bootstrap.yml"
ARCHIVED_PROTECTED_PATHS = (
    BOOTSTRAP_RUNNER_PATH,
    LIVE_WRAPPER_PATH,
    BOOTSTRAP_MODULE_PATH,
    POLICY_MODULE_PATH,
    POLICY_PATH,
    ACTIVATION_RUNNER_PATH,
    ARCHIVED_BOOTSTRAP_WORKFLOW_PATH,
    "scripts/verify-reviewed-render.py",
    REPOSITORY_CONTRACT_PATH,
)
COMPATIBILITY_PATHS = (
    POLICY_PATH,
    POLICY_MODULE_PATH,
    ARCHIVED_BOOTSTRAP_WORKFLOW_PATH,
    ".github/workflows/staging-participant-gateway-activation.yml",
    "reviewed-render/roebel-staging/staging-participant-gateway/networkpolicy.json",
    "reviewed-render/roebel-staging/staging-participant-gateway/serviceaccount.json",
    "reviewed-render/roebel-staging/staging-participant-gateway/service.json",
    "reviewed-render/roebel-staging/staging-participant-gateway/deployment.json",
    "reviewed-render/roebel-staging/staging-participant-gateway/ingress.json",
    "reviewed-render/roebel-staging/staging-participant-gateway/kustomization.yaml",
    "reviewed-render/roebel-staging/staging-participant-gateway/runtime-pin.json",
    "reviewed-render/roebel-staging/staging-participant-gateway/workbench-ingress/networkpolicy.json",
    "reviewed-render/roebel-staging/staging-participant-gateway/workbench-ingress/kustomization.yaml",
)
CURRENT_PROTECTED_PATHS = tuple(dict.fromkeys((
    *ARCHIVED_PROTECTED_PATHS,
    HANDOVER_MODULE_PATH,
    HANDOVER_RUNNER_PATH,
)))
CURRENT_PREBOUND_PATHS = tuple(dict.fromkeys((
    *CURRENT_PROTECTED_PATHS,
    *COMPATIBILITY_PATHS,
)))
REVISION = re.compile(r"^[0-9a-f]{40}$")
_PREBOUND_BLOBS: dict[tuple[str, str], bytes] | None = None


class HandoverCliError(RuntimeError):
    pass


class HandoverSignal(HandoverCliError):
    """Terminate the GET-only phase through the normal cleanup path."""

    def __init__(self, signum: int) -> None:
        self.signum = signum
        super().__init__(f"handover interrupted by signal {signum}")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HandoverCliError(message)


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def bytes_sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


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
        "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1", "HOME": "/dev/null", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin",
    }
    return subprocess.run([str(GIT_BIN), "--no-replace-objects", *args], env=environment, **kwargs)


def git_blob(revision: str, path: str) -> bytes:
    require(REVISION.fullmatch(revision) is not None, "Git revision invalid")
    if _PREBOUND_BLOBS is not None:
        try:
            return _PREBOUND_BLOBS[(revision, path)]
        except KeyError as exc:
            raise HandoverCliError(f"late protected Git blob access forbidden: {revision}:{path}") from exc
    result = trusted_git(["-C", str(ROOT), "show", f"{revision}:{path}"], capture_output=True, check=False, timeout=10)
    require(result.returncode == 0, f"protected Git blob unavailable: {path}")
    return result.stdout


def compile_module(source: bytes, name: str, path: str, revision: str) -> Any:
    require(isinstance(source, bytes) and source, f"protected module empty: {path}")
    module_name = f"{name}_{revision}"
    module = types.ModuleType(module_name)
    module.__file__ = f"git:{revision}:{path}"
    module.__package__ = ""
    sys.modules[module_name] = module
    try:
        exec(compile(source, module.__file__, "exec", dont_inherit=True), module.__dict__)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


def json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs(label))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HandoverCliError(f"{label} invalid") from exc
    require(isinstance(value, dict), f"{label} must be an object")
    return value


def _unique_pairs(label: str):
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            require(key not in result, f"{label} contains duplicate JSON key")
            result[key] = value
        return result
    return pairs


def owned_receipt_raw(fd: int, label: str) -> bytes:
    require(isinstance(fd, int) and fd >= 3, f"{label} descriptor invalid")
    info = os.fstat(fd)
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.geteuid()
        and info.st_nlink in {0, 1}
        and stat.S_IMODE(info.st_mode) == 0o600
        and 0 < info.st_size <= 1024 * 1024,
        f"{label} descriptor metadata invalid",
    )
    raw = os.pread(fd, info.st_size + 1, 0)
    require(len(raw) == info.st_size, f"{label} descriptor read incomplete")
    return raw


def owned_prebound_blob(fd: int, size: int, expected_sha256: str, label: str) -> bytes:
    """Read one inherited, owner-only Git blob without touching Git."""
    require(isinstance(fd, int) and fd >= 3, f"{label} descriptor invalid")
    require(isinstance(size, int) and 0 < size <= 4 * 1024 * 1024, f"{label} size invalid")
    require(isinstance(expected_sha256, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", expected_sha256), f"{label} checksum invalid")
    info = os.fstat(fd)
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.geteuid()
        and info.st_nlink in {0, 1}
        and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_size == size,
        f"{label} descriptor metadata invalid",
    )
    raw = os.pread(fd, size + 1, 0)
    require(len(raw) == size and bytes_sha256(raw) == expected_sha256, f"{label} bytes/checksum drift")
    return raw


def parse_prebound_blob_descriptors(values: list[str] | None, current_revision: str) -> dict[tuple[str, str], bytes]:
    """Validate the exact fd/size/hash descriptors supplied by the wrapper."""
    require(values is not None and values, "complete prebound protected Git closure required")
    blobs: dict[tuple[str, str], bytes] = {}
    for encoded in values:
        try:
            value = json.loads(encoded, object_pairs_hook=_unique_pairs("prebound Git blob descriptor"))
        except (TypeError, ValueError) as exc:
            raise HandoverCliError("prebound Git blob descriptor invalid") from exc
        require(
            isinstance(value, dict)
            and set(value) == {"revision", "path", "fd", "size", "sha256"}
            and isinstance(value["revision"], str)
            and REVISION.fullmatch(value["revision"]) is not None
            and isinstance(value["path"], str)
            and isinstance(value["fd"], int)
            and isinstance(value["size"], int)
            and isinstance(value["sha256"], str),
            "prebound Git blob descriptor fields invalid",
        )
        key = (value["revision"], value["path"])
        require(key not in blobs, "prebound Git blob descriptor duplicated")
        blobs[key] = owned_prebound_blob(value["fd"], value["size"], value["sha256"], f"prebound Git blob {value['path']}")
    require(set(blobs) == _required_prebound_keys(current_revision), "prebound protected Git closure is incomplete or widened")
    return blobs


def _hashes(revision: str, paths: tuple[str, ...]) -> dict[str, str]:
    return {path: bytes_sha256(git_blob(revision, path)) for path in paths}


def _contract_projection(revision: str) -> dict[str, Any]:
    contract = json_object(git_blob(revision, REPOSITORY_CONTRACT_PATH), "repository contract")
    value = contract.get("stagingParticipantGatewayBoundary")
    require(isinstance(value, dict) and bool(value), "participant repository-contract projection absent")
    return value


def set_prebound_blobs(blobs: dict[tuple[str, str], bytes] | None) -> None:
    """Install the outer wrapper's complete immutable Git-blob closure.

    A live handover must never trigger a promisor/partial-clone fetch after
    transport credentials or the Kubernetes snapshot exist.  The wrapper
    therefore supplies every historical and current blob before launching this
    child; once installed, an absent key is a hard error instead of a Git read.
    """
    global _PREBOUND_BLOBS
    if blobs is None:
        _PREBOUND_BLOBS = None
        return
    _PREBOUND_BLOBS = dict(blobs)


def _required_prebound_keys(current_revision: str) -> set[tuple[str, str]]:
    return {
        *((current_revision, path) for path in CURRENT_PREBOUND_PATHS),
        *((ARCHIVE_REVISION, path) for path in dict.fromkeys((*ARCHIVED_PROTECTED_PATHS, *COMPATIBILITY_PATHS))),
    }


def build_context(current_revision: str, archived_raw: bytes, prebound_blobs: dict[tuple[str, str], bytes] | None = None) -> dict[str, Any]:
    require(REVISION.fullmatch(current_revision) is not None, "current protected revision invalid")
    if prebound_blobs is not None:
        set_prebound_blobs(prebound_blobs)
        require(set(_PREBOUND_BLOBS or {}) == _required_prebound_keys(current_revision), "prebound protected Git closure is incomplete or widened")
    else:
        head = trusted_git(["-C", str(ROOT), "rev-parse", "HEAD"], text=True, capture_output=True, check=False)
        require(head.returncode == 0 and head.stdout.strip() == current_revision, "checkout is not the expected protected revision")
    for path in CURRENT_PROTECTED_PATHS:
        local = ROOT / path
        require(local.is_file() and not local.is_symlink() and local.read_bytes() == git_blob(current_revision, path), f"current protected file drift: {path}")
    require(bytes_sha256(archived_raw) == ARCHIVE_RECEIPT_RAW_SHA256, "archived receipt raw checksum drift")

    archived_policy_module = compile_module(git_blob(ARCHIVE_REVISION, POLICY_MODULE_PATH), "archived_participant_policy", POLICY_MODULE_PATH, ARCHIVE_REVISION)
    archived_bootstrap_module = compile_module(git_blob(ARCHIVE_REVISION, BOOTSTRAP_MODULE_PATH), "archived_participant_bootstrap", BOOTSTRAP_MODULE_PATH, ARCHIVE_REVISION)
    current_policy_module = compile_module(git_blob(current_revision, POLICY_MODULE_PATH), "current_participant_policy", POLICY_MODULE_PATH, current_revision)
    current_bootstrap_module = compile_module(git_blob(current_revision, BOOTSTRAP_MODULE_PATH), "current_participant_bootstrap", BOOTSTRAP_MODULE_PATH, current_revision)
    handover_module = compile_module(git_blob(current_revision, HANDOVER_MODULE_PATH), "participant_dormant_handover", HANDOVER_MODULE_PATH, current_revision)
    activation_module = compile_module(git_blob(current_revision, ACTIVATION_RUNNER_PATH), "participant_activation_support", ACTIVATION_RUNNER_PATH, current_revision)
    activation_module.POLICY = current_policy_module

    archived_policy = archived_policy_module.validate_activation_policy(json_object(git_blob(ARCHIVE_REVISION, POLICY_PATH), "archived policy"))
    current_policy = current_policy_module.validate_activation_policy(json_object(git_blob(current_revision, POLICY_PATH), "current policy"))
    archived_plan = archived_bootstrap_module.build_plan(archived_policy_module, archived_policy, ARCHIVE_REVISION, _hashes(ARCHIVE_REVISION, ARCHIVED_PROTECTED_PATHS))
    current_plan = current_bootstrap_module.build_plan(current_policy_module, current_policy, current_revision, _hashes(current_revision, CURRENT_PROTECTED_PATHS))
    archived_receipt = archived_bootstrap_module._json_object(archived_raw.decode("utf-8"), "archived bootstrap receipt")
    archived_projection = archived_bootstrap_module.bind_success_receipt(archived_plan, archived_receipt)
    compatibility_archive = _hashes(ARCHIVE_REVISION, COMPATIBILITY_PATHS)
    compatibility_current = _hashes(current_revision, COMPATIBILITY_PATHS)
    current_plan = copy.deepcopy(current_plan)
    current_plan["sharedSource"] = copy.deepcopy(current_policy["repositories"]["operations"]["fluxSource"])
    current_plan["expectedSharedSource"] = current_policy_module.expected_shared_flux_source_projection()
    current_plan["expectedSharedSourceSemanticSha256"] = current_policy_module.semantic_sha256(
        current_plan["expectedSharedSource"],
    )
    current_plan["preservation"] = copy.deepcopy(current_policy["preservation"])
    binding = handover_module.build_archived_binding(
        archived_receipt_raw=archived_raw,
        archive_revision=ARCHIVE_REVISION,
        current_revision=current_revision,
        archived_plan=archived_plan,
        current_plan=current_plan,
        archived_artifacts=compatibility_archive,
        current_artifacts=compatibility_current,
        archived_participant_contract=_contract_projection(ARCHIVE_REVISION),
        current_participant_contract=_contract_projection(current_revision),
        archived_projection=archived_projection,
        expected_archived_raw_sha256=ARCHIVE_RECEIPT_RAW_SHA256,
        expected_archived_canonical_sha256=ARCHIVE_RECEIPT_CANONICAL_SHA256,
    )
    return {
        "policy": current_policy,
        "policyModule": current_policy_module,
        "handoverModule": handover_module,
        "activationModule": activation_module,
        "binding": binding,
    }


def _target_key(target: dict[str, str]) -> tuple[str, str, str, str]:
    return target["apiVersion"], target["kind"], target["namespace"], target["name"]


class GetOnlyAdapter:
    """One cluster identity check plus exactly eleven named resource GETs."""
    def __init__(self, kubeconfig: str, context: dict[str, Any]):
        self.context = context
        activation = context["activationModule"]
        self.runner = activation.Runner()
        self.snapshot = None
        try:
            self.snapshot = activation.snapshot_kubeconfig_v4(kubeconfig, self.runner)
            binding = context["binding"]
            ordered = [binding["sourceTarget"], *[item["target"] for item in binding["objects"]], *[binding["preservation"][label]["target"] for label in ("webIngress", "existingWorkbenchNetworkPolicy")]]
            self.targets = {_target_key(item): copy.deepcopy(item) for item in ordered}
            require(len(self.targets) == 11, "GET-only target set is not exactly eleven identities")
        except BaseException:
            if self.snapshot is not None:
                self.snapshot.close()
                self.snapshot = None
            raise
        self.calls: list[tuple[str, str, str, str]] = []
        self.cluster_binding_calls = 0

    def close(self) -> None:
        if self.snapshot is not None:
            self.snapshot.close()
            self.snapshot = None

    def get_exact(self, target: dict[str, str]) -> dict[str, Any]:
        key = _target_key(target)
        require(key in self.targets and self.targets[key] == target, "GET target outside one-time handover set")
        require(key not in self.calls, "duplicate handover GET forbidden")
        self.calls.append(key)
        activation = self.context["activationModule"]
        return activation.live_obj(self.runner, str(self.snapshot.path), target["kind"].lower(), target["name"], target["namespace"])

    def cluster_binding(self) -> dict[str, Any]:
        require(self.cluster_binding_calls == 0 and not self.calls, "cluster binding must precede resource GETs")
        self.cluster_binding_calls += 1
        activation = self.context["activationModule"]
        return activation.cluster_binding_v4(self.runner, self.snapshot, self.context["policy"])


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-protected-revision", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--live", action="store_true")
    mode.add_argument("--verify-success-receipt-fd", type=int)
    parser.add_argument("--archived-bootstrap-receipt-fd", type=int)
    parser.add_argument("--prebound-blob", action="append")
    parser.add_argument("--kubeconfig")
    parser.add_argument("--receipt", type=Path)
    return parser.parse_args(argv)


def install_signal_handlers() -> dict[int, Any]:
    previous: dict[int, Any] = {}

    def interrupt(signum: int, _frame: Any) -> None:
        raise HandoverSignal(signum)

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, interrupt)
    except (OSError, ValueError) as exc:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        raise HandoverCliError("GET-only handover requires controllable signal handlers") from exc
    return previous


def restore_signal_handlers(previous: dict[int, Any]) -> None:
    for signum, handler in previous.items():
        signal.signal(signum, handler)


def main(argv: list[str] | None = None) -> int:
    adapter: GetOnlyAdapter | None = None
    previous_handlers: dict[int, Any] = {}
    try:
        require(sys.flags.isolated == 1 and bool(sys.flags.safe_path), "executor requires python3 -I isolated safe-path mode")
        os.environ.pop("PYTHONPATH", None)
        args = parse_args(argv)
        revision = args.expected_protected_revision
        require(args.archived_bootstrap_receipt_fd is not None, "exact archived bootstrap receipt descriptor required")
        previous_handlers = install_signal_handlers()
        prebound = parse_prebound_blob_descriptors(args.prebound_blob, revision)
        archived_raw = owned_receipt_raw(args.archived_bootstrap_receipt_fd, "archived bootstrap receipt")
        context = build_context(revision, archived_raw, prebound)
        module = context["handoverModule"]
        if args.verify_success_receipt_fd is not None:
            require(args.kubeconfig is None and args.receipt is None, "handover verification accepts no kubeconfig or output receipt")
            handover_raw = owned_receipt_raw(args.verify_success_receipt_fd, "handover receipt")
            handover_receipt = json_object(handover_raw, "handover receipt")
            print(canonical(module.bind_handover_receipt(context["binding"], handover_receipt)))
            return 0
        require(args.live is True and isinstance(args.kubeconfig, str) and args.kubeconfig and args.receipt is not None, "live handover requires kubeconfig and receipt")
        sink = module.ReceiptSink.reserve(args.receipt)
        adapter = GetOnlyAdapter(args.kubeconfig, context)
        cluster_binding = adapter.cluster_binding()
        result = module.run_get_only_handover(
            binding=context["binding"],
            kube=adapter,
            receipt=sink,
            cluster_binding=cluster_binding,
            require_semantically_equal=context["policyModule"].require_semantically_equal,
            canonical_object_sha256=context["activationModule"].digest,
            semantic_object_sha256=context["policyModule"].semantic_sha256,
        )
        require(adapter.cluster_binding_calls == 1 and len(adapter.calls) == 11, "GET-only handover call count drift")
        print(canonical(result))
        return 0
    except Exception as exc:
        print(f"participant dormant handover blocked: {exc}", file=sys.stderr)
        return 2
    finally:
        if adapter is not None:
            adapter.close()
        if previous_handlers:
            restore_signal_handlers(previous_handlers)


if __name__ == "__main__":
    raise SystemExit(main())
