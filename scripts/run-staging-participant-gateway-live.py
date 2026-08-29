#!/usr/bin/env python3
"""One-shot authenticated rootless transport for participant Flux activation.

The two protected transaction runners remain the only Kubernetes writers.
This wrapper owns only their short-lived WireGuard transport, administrator
kubeconfig, process lifecycle, and non-secret wrapper receipt.
"""
from __future__ import annotations

import sys as _bootstrap_sys
if __name__ == "__main__" and not (_bootstrap_sys.flags.isolated and _bootstrap_sys.flags.safe_path):
    print("participant live wrapper blocked: invoke with python3 -I", file=_bootstrap_sys.stderr)
    raise SystemExit(2)

import argparse, base64, hashlib, ipaddress, json, os, re, secrets, select, shutil, signal, socket, stat, subprocess, sys, tempfile, threading, time, types
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SELF_PATH = "scripts/run-staging-participant-gateway-live.py"
BOOTSTRAP_RUNNER = "scripts/bootstrap-staging-participant-flux.py"
ACTIVATION_RUNNER = "scripts/activate-staging-participant-gateway.py"
SECRET_RUNNER = "scripts/materialize-staging-participant-gateway-secrets.py"
HANDOVER_RUNNER = "scripts/handover-staging-participant-dormant-receipt.py"
HANDOVER_IMPLEMENTATION = "scripts/staging_participant_dormant_receipt_handover.py"
WORKBENCH_PROMOTER = "scripts/promote-staging-workbench-image.py"
WORKBENCH_RUNNER = "scripts/handover-staging-workbench-baseline.py"
WORKBENCH_IMPLEMENTATION = "scripts/workbench_baseline_handover.py"
WORKBENCH_RECOVERY_IMPLEMENTATION = "scripts/workbench_baseline_recovery.py"
RELAY_FIXTURE_RESET_RUNNER = "scripts/reset-staging-relay-fixtures.py"
PROTECTED_PATHS = (
    SELF_PATH,
    BOOTSTRAP_RUNNER,
    ACTIVATION_RUNNER,
    SECRET_RUNNER,
    HANDOVER_RUNNER,
    HANDOVER_IMPLEMENTATION,
    "scripts/staging_participant_flux_bootstrap.py",
    "scripts/staging_participant_gateway_policy.py",
    "policy/staging-participant-gateway-activation-policy.json",
    ".github/workflows/staging-participant-flux-bootstrap.yml",
    ".github/workflows/staging-participant-gateway-activation.yml",
    "scripts/verify-reviewed-render.py",
    "policy/repository-contract.json",
)
# The dormant-receipt handover child is forbidden from performing Git reads in
# a partial clone.  Keep this closure in the outer wrapper so every current
# and historical transitive blob is bound before decrypting transport inputs or
# snapshotting binaries.  It intentionally mirrors the child runner's fixed
# constants; drift is rejected by the exact-key-set check in that child.
HANDOVER_ARCHIVE_REVISION = "08c4171573bb138845a9160e747f6ac56a3c754e"
HANDOVER_SECRET_RECEIPT_ORIGIN_REVISION = "b790fa76d4f2ad4d0bd86663dcd896b97ba0b61e"
HANDOVER_ARCHIVED_PROTECTED_PATHS = (
    BOOTSTRAP_RUNNER,
    SELF_PATH,
    "scripts/staging_participant_flux_bootstrap.py",
    "scripts/staging_participant_gateway_policy.py",
    "policy/staging-participant-gateway-activation-policy.json",
    ACTIVATION_RUNNER,
    ".github/workflows/staging-participant-flux-bootstrap.yml",
    "scripts/verify-reviewed-render.py",
    "policy/repository-contract.json",
)
HANDOVER_COMPATIBILITY_PATHS = (
    "policy/staging-participant-gateway-activation-policy.json",
    "scripts/staging_participant_gateway_policy.py",
    ".github/workflows/staging-participant-flux-bootstrap.yml",
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
HANDOVER_CURRENT_PROTECTED_PATHS = tuple(dict.fromkeys((
    *HANDOVER_ARCHIVED_PROTECTED_PATHS,
    HANDOVER_IMPLEMENTATION,
    HANDOVER_RUNNER,
)))
HANDOVER_PREBOUND_CURRENT_PATHS = tuple(dict.fromkeys((
    *HANDOVER_CURRENT_PROTECTED_PATHS,
    *HANDOVER_COMPATIBILITY_PATHS,
)))
HANDOVER_PREBOUND_ARCHIVE_PATHS = tuple(dict.fromkeys((
    *HANDOVER_ARCHIVED_PROTECTED_PATHS,
    *HANDOVER_COMPATIBILITY_PATHS,
)))
# This is deliberately a separate protected closure.  Workbench baseline
# transport must never load, bind, or invoke a participant transaction runner.
# The handover runner is retained as a separately bound review identity; the
# implementation blob is executed directly below so its KubernetesAdapter can
# receive the inherited pinned kubectl snapshot rather than its mutable default
# path.
WORKBENCH_PROTECTED_PATHS = (
    SELF_PATH,
    WORKBENCH_RUNNER,
    WORKBENCH_IMPLEMENTATION,
    "scripts/verify-reviewed-render.py",
    "policy/repository-contract.json",
    "reviewed-render/roebel-staging/workbench-baseline/networkpolicy.json",
    "reviewed-render/roebel-staging/workbench-baseline/kustomization.yaml",
    ".github/workflows/reviewed-render-admission.yml",
)
WORKBENCH_RECOVERY_PROTECTED_PATHS = (
    SELF_PATH,
    WORKBENCH_RECOVERY_IMPLEMENTATION,
    "scripts/verify-reviewed-render.py",
    "policy/repository-contract.json",
    ".github/workflows/reviewed-render-admission.yml",
)
# The image promotion is a distinct one-time capability.  Its closure is
# intentionally smaller than the baseline handover closure: it binds the
# wrapper, the exact promoter blob, and the protected repository contract but
# cannot load a participant or baseline transaction runner.
WORKBENCH_PROMOTION_PROTECTED_PATHS = (
    SELF_PATH,
    WORKBENCH_PROMOTER,
    "scripts/verify-reviewed-render.py",
    "policy/repository-contract.json",
)
# Relay emptyDir fixture removal is a distinct one-time capability.  Its
# protected child owns the two exact Pod DELETE requests; this wrapper owns
# only the fixed authenticated transport and immutable executable bindings.
RELAY_FIXTURE_RESET_PROTECTED_PATHS = (
    SELF_PATH,
    RELAY_FIXTURE_RESET_RUNNER,
    "scripts/verify-reviewed-render.py",
    "policy/repository-contract.json",
)
API_HOST, API_PORT, TALOS_PORT = "10.255.240.11", 6443, 50000
PROXY_USERNAME = "stadtstack-participant"
GIT_BIN = Path("/usr/bin/git")
RUNNER_LAUNCHER = """import hashlib,os,sys
path,fd_text,size_text,expected=sys.argv[1:5]
fd,size=int(fd_text),int(size_text)
source=os.pread(fd,size+1,0)
if len(source)!=size or 'sha256:'+hashlib.sha256(source).hexdigest()!=expected:
    raise SystemExit('bound runner bytes differ')
sys.argv=[path,*sys.argv[5:]]
scope={'__name__':'__main__','__file__':path,'__package__':None,'__cached__':None}
exec(compile(source,path,'exec',dont_inherit=True),scope)
"""
WRAPPER_RECEIPT_SCHEMA = "roebel_staging_participant_live_transport_receipt_v3"
WORKBENCH_TRANSPORT_RECEIPT_SCHEMA = "roebel_staging_workbench_baseline_live_transport_receipt_v1"
WORKBENCH_RECOVERY_TRANSPORT_RECEIPT_SCHEMA = "roebel_staging_workbench_baseline_recovery_live_transport_receipt_v1"
WORKBENCH_PROMOTION_TRANSPORT_RECEIPT_SCHEMA = "roebel_staging_workbench_image_promotion_live_transport_receipt_v1"
RELAY_FIXTURE_RESET_TRANSPORT_RECEIPT_SCHEMA = "roebel_staging_relay_fixture_reset_live_transport_receipt_v1"
# The approved reset is callable only with the strict final-v2 evidence
# verifier below.  Keep this guard before output reservation, credential
# decryption, and cluster contact so any future verifier disablement fails shut.
RELAY_FIXTURE_RESET_LIVE_EXECUTION_ENABLED = True
WORKBENCH_PROMOTION_ARTIFACT_RECEIPT_SHA256 = "sha256:872e3e2180e16f69157c5a142c7aa20e3f2e0ea93c10e5363800148b30c99e4c"
WORKBENCH_PROMOTION_SOURCE_REVISION = "b57a3ae2e8ce613bfae4b6ab96e20b95f578ca67"
WORKBENCH_PROMOTION_TARGET_IMAGE = (
    "ghcr.io/giraeffleaeffle/roebel-e2e-workbench@"
    "sha256:03cc0dd35b81004ecc2a6045a16ea09184d2faa10a20bf7c83a825e7440170e2"
)
# The already-reviewed relay-reset capability remains bound to its historical
# two-component pin.  A workbench-only promotion must not silently retarget
# that destructive one-shot path to a newer relay artifact.
RELAY_FIXTURE_RESET_ARTIFACT_RECEIPT_SHA256 = "sha256:08d2b65bb57434ba6f35d8083f32b22f43010e1222544a8ce074e208f95efd9b"
RELAY_FIXTURE_RESET_SOURCE_REVISION = "36ac41d7049df815aaebbe4301c098a0ec7e4101"
RELAY_FIXTURE_RESET_TARGET_IMAGE = (
    "ghcr.io/giraeffleaeffle/roebel-staging-relay@"
    "sha256:6def2f468e3fad47cf17c0287a9215bbdc299b0d7d3b7fc58927b2f2169650ad"
)
WORKBENCH_PUBLIC_PROBE_HOSTNAME = "roebel-web.staging.agentcart.eu"
WORKBENCH_PUBLIC_PROBE_ORIGIN = f"https://{WORKBENCH_PUBLIC_PROBE_HOSTNAME}"
WORKBENCH_PUBLIC_PROBE_PATHS = (
    "/stadtstack-test/api/config",
    "/stadtstack-test/api/feed?profile=public",
)
WORKBENCH_PUBLIC_PROBE_TIMEOUT_SECONDS = 15
WORKBENCH_PUBLIC_PROBE_MAX_BODY_BYTES = 8 * 1024 * 1024
WORKBENCH_RECOVERY_ORIGIN_REVISION = "3be9405c6bfd6b4caf0423b137f969aab3bef323"
WORKBENCH_RECOVERY_OPERATION_ID = "b6b52abc-4b28-4db0-b4ef-74041f41d7c6"
WORKBENCH_RECOVERY_MARKER = "77157c24-d1d0-4cb8-850b-538f380c16fd"
WORKBENCH_RECOVERY_EVIDENCE = {
    "originJournalSha256": "sha256:70015e2728bf8e30491862687c3b507aa3d4d03e4f91b72cafb84ae3dcba30c0",
    "attemptReceiptSha256": "sha256:55a7cfac98cdb40aa49a46a00abbd47d8305cff4d001f8984c57a0c964d51ee9",
    "inspectionSha256": "sha256:d7a94d4e27c18317ede34f6700a7c4a27081133bd7f881e46d5bd30466430755",
}
WORKBENCH_RECOVERY_TERMINAL_REVISION = "18b1780be9b2e1d8bad05e27f81f11d9b104ab06"
WORKBENCH_RECOVERY_TERMINAL_JOURNAL_FILE_SHA256 = "sha256:d6e16407761ecbf2d6ce29aab48f10f4420770a7b97b393b53b9753152f5f604"
WORKBENCH_RECOVERY_TERMINAL_JOURNAL_CANONICAL_SHA256 = "sha256:cdeab725635754bb4a220bc915e4ff69a46246b6336ca954681d7ff6e7497613"
WORKBENCH_RECOVERY_FINALIZATION_PARENT_REVISION = "9f7a7a1e96065e849a8b7a9879de1fadb9ec6e2f"
WORKBENCH_RECOVERY_OBJECT_UIDS = {
    "kustomization": "d251a65f-b322-44a5-8e03-76ca268e72be",
    "roleBinding": "d7e8ec85-3fad-41ff-873b-4b8920c7b8df",
    "role": "2ca77559-34dc-4573-85e3-2c41242eab12",
    "serviceAccount": "c0829ad9-ab20-43a0-9c84-a122098864f0",
}
WORKBENCH_RECOVERY_TARGETS = {
    "kustomization": {"apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization", "namespace": "flux-roebel-staging", "name": "roebel-staging-workbench-baseline"},
    "roleBinding": {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "namespace": "stadtstack-roebel-staging-lab", "name": "roebel-staging-workbench-baseline-reconciler"},
    "role": {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "namespace": "stadtstack-roebel-staging-lab", "name": "roebel-staging-workbench-baseline-reconciler"},
    "serviceAccount": {"apiVersion": "v1", "kind": "ServiceAccount", "namespace": "flux-roebel-staging", "name": "roebel-staging-workbench-baseline-reconciler"},
}
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
MAX_RECEIPT_BYTES = 8 * 1024 * 1024
TRANSACTION_SIGNALS = (signal.SIGINT, signal.SIGTERM)
EXPECTED_BINARIES = {
    "age": "sha256:f52e5ee772e1c0e3c6be5bf837b469a40346df3515db9a1b41230376fdff6a76",
    "kubectl": "sha256:4bcf268eacdc1d2df74e37d86f639f27ca7dea3ae185b7b452b73b9fb5ddc14e",
    "talosctl": "sha256:6a7c0cd313d0b549f135ec4d51e6101a6d4bec753b9f86e516e77f31e2311613",
    "wireproxy": "sha256:37889c2f0ea4a9f2f59fc1bfefc372b24ffc4e56e2e34a0188aabe3a4e8c1ec3",
}

class LiveTransportError(RuntimeError): pass
class LiveTransportInterrupted(LiveTransportError):
    def __init__(self, signum: int): self.signum = signum; super().__init__(f"operator signal {signum}")

def require(value: bool, message: str) -> None:
    if not value: raise LiveTransportError(message)

def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

def bytes_sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()

def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""): digest.update(chunk)
    return "sha256:" + digest.hexdigest()

def workbench_public_probe_binding() -> dict[str, Any]:
    """Return the promoter's exact fixed-origin functional-probe binding."""
    descriptor = {
        "transport": "python-stdlib-direct-https",
        "origin": WORKBENCH_PUBLIC_PROBE_ORIGIN,
        "hostname": WORKBENCH_PUBLIC_PROBE_HOSTNAME,
        "port": 443,
        "method": "GET",
        "expectedStatus": 200,
        "tlsVerification": "default-ca-and-hostname",
        "environmentProxyUse": False,
        "redirectsFollowed": False,
        "timeoutSeconds": WORKBENCH_PUBLIC_PROBE_TIMEOUT_SECONDS,
        "maxBodyBytes": WORKBENCH_PUBLIC_PROBE_MAX_BODY_BYTES,
        "allowedPaths": list(WORKBENCH_PUBLIC_PROBE_PATHS),
    }
    return {
        "kind": "fixed-public-https-origin",
        **descriptor,
        "bindingSha256": bytes_sha256(canonical(descriptor).encode("ascii")),
    }

def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result

def json_object(raw: str, label: str) -> dict[str, Any]:
    try: value = json.loads(raw, object_pairs_hook=_unique_object)
    except (TypeError, ValueError) as exc: raise LiveTransportError(f"{label} is invalid or duplicate-key JSON") from exc
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return value

def fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try: os.fsync(fd)
    finally: os.close(fd)

def reserve_output_directory(path: Path) -> Path:
    path = Path(os.path.realpath(os.path.abspath(path)))
    require(path.is_absolute() and not path.exists() and not path.is_symlink(), "receipt directory must be a new absolute path")
    parent = path.parent; info = os.lstat(parent)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) & 0o022 == 0, "receipt parent is not private and owned")
    path.mkdir(mode=0o700); fsync_directory(parent)
    return path

def private_file(path: Path, label: str, max_bytes: int = 16 * 1024 * 1024) -> Path:
    source = Path(os.path.abspath(path)); source_info = os.lstat(source)
    require(not stat.S_ISLNK(source_info.st_mode), f"{label} must not be a symlink")
    resolved = Path(os.path.realpath(source)); info = os.lstat(resolved)
    require(
        resolved == source
        and stat.S_ISREG(info.st_mode)
        and info.st_uid == os.geteuid()
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) & 0o077 == 0
        and 0 < info.st_size <= max_bytes,
        f"{label} must be a bounded private owned nlink-one regular file",
    )
    return resolved

def git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "HOME": "/dev/null",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }

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
    return subprocess.run([str(GIT_BIN), "--no-replace-objects", *args], env=git_environment(), **kwargs)

def git_blob(revision: str, path: str) -> bytes:
    try:
        result = trusted_git(
            ["-C", str(ROOT), "show", f"{revision}:{path}"],
            capture_output=True,
            check=False,
            timeout=10,
        )
    except subprocess.TimeoutExpired as exc:
        raise LiveTransportError(f"protected Git blob read timed out: {path}") from exc
    require(result.returncode == 0, f"protected Git blob unavailable: {path}")
    return result.stdout

def bind_protected_checkout(
    revision: str,
    *,
    paths: tuple[str, ...] = PROTECTED_PATHS,
) -> tuple[dict[str, str], dict[str, bytes]]:
    require(REVISION.fullmatch(revision) is not None, "protected revision must be lowercase SHA-1")
    head = trusted_git(["-C", str(ROOT), "rev-parse", "HEAD"], text=True, capture_output=True, check=False)
    require(head.returncode == 0 and head.stdout.strip() == revision, "checkout is not the expected protected revision")
    hashes: dict[str, str] = {}; blobs: dict[str, bytes] = {}
    require(paths and len(paths) == len(set(paths)), "protected path closure is invalid")
    for path in paths:
        local = ROOT / path
        info = os.lstat(local)
        require(stat.S_ISREG(info.st_mode) and not local.is_symlink(), f"protected file is not a regular Git blob: {path}")
        expected = git_blob(revision, path)
        require(local.read_bytes() == expected, f"protected file differs from exact Git blob: {path}")
        hashes[path] = bytes_sha256(expected); blobs[path] = expected
    return dict(sorted(hashes.items())), blobs


def require_protected_revision_parent(revision: str, expected_parent: str) -> None:
    """Require one exact parent for the one-shot terminal-finalizer commit."""
    require(REVISION.fullmatch(revision) is not None and REVISION.fullmatch(expected_parent) is not None, "protected parent revision invalid")
    result = trusted_git(
        ["-C", str(ROOT), "rev-list", "--parents", "-n", "1", revision],
        text=True,
        capture_output=True,
        check=False,
    )
    require(
        result.returncode == 0 and result.stdout.strip().split() == [revision, expected_parent],
        "terminal finalizer is not the exact protected parent transition",
    )

def compile_verified_spawn_module(source: bytes, revision: str) -> Any:
    require(isinstance(source, bytes) and source, "verified spawn module source absent")
    name = f"participant_verified_spawn_{revision}"
    module = types.ModuleType(name)
    module.__file__ = f"git:{revision}:{ACTIVATION_RUNNER}"
    module.__package__ = ""
    sys.modules[name] = module
    try:
        exec(compile(source, module.__file__, "exec", dont_inherit=True), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module

@dataclass
class PinnedExecutableSnapshot:
    path: Path
    fd: int
    device: int
    inode: int
    size: int
    sha256: str
    immutable: bool = False

    def to_binding(self, module: Any) -> Any:
        require(self.fd >= 0, "pinned executable binding already transferred")
        self.path.unlink()
        fsync_directory(self.path.parent)
        binding = module.ExecutableBinding(
            self.path,
            self.fd,
            self.device,
            self.inode,
            self.size,
            self.sha256,
            owns_fd=True,
        )
        self.fd = -1
        return binding

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd); self.fd = -1


def seal_pinned_snapshot(snapshot: PinnedExecutableSnapshot) -> None:
    """Make a private snapshot path non-replaceable for path-only consumers.

    The frozen workbench KubernetesAdapter intentionally accepts a Path.  On
    the local macOS operator host, UF_IMMUTABLE closes the lstat-to-exec swap
    window while the inherited descriptor remains open for byte proof.  A host
    without this primitive is not an admissible live transport host.
    """
    require(hasattr(os, "chflags") and hasattr(stat, "UF_IMMUTABLE"), "workbench transport requires immutable-file support")
    snapshot_info = os.lstat(snapshot.path); opened = os.fstat(snapshot.fd)
    require(
        (snapshot_info.st_dev, snapshot_info.st_ino, snapshot_info.st_size) == (snapshot.device, snapshot.inode, snapshot.size)
        and (opened.st_dev, opened.st_ino, opened.st_size) == (snapshot.device, snapshot.inode, snapshot.size),
        "pinned snapshot identity drift before sealing",
    )
    os.chflags(snapshot.path, snapshot_info.st_flags | stat.UF_IMMUTABLE)
    sealed = os.lstat(snapshot.path)
    require(bool(sealed.st_flags & stat.UF_IMMUTABLE), "pinned snapshot immutable seal unavailable")
    snapshot.immutable = True


def unseal_pinned_snapshot(snapshot: PinnedExecutableSnapshot) -> None:
    if not snapshot.immutable:
        return
    require(hasattr(os, "chflags") and hasattr(stat, "UF_IMMUTABLE"), "pinned snapshot unseal unavailable")
    info = os.lstat(snapshot.path)
    require((info.st_dev, info.st_ino, info.st_size) == (snapshot.device, snapshot.inode, snapshot.size), "pinned snapshot identity drift before unseal")
    os.chflags(snapshot.path, info.st_flags & ~stat.UF_IMMUTABLE)
    require(not bool(os.lstat(snapshot.path).st_flags & stat.UF_IMMUTABLE), "pinned snapshot immutable unseal failed")
    snapshot.immutable = False


class PersistentPinnedExecutable:
    """A path-backed pinned snapshot for the workbench-only transport setup.

    Unlike the participant runner's descriptor-executed binding, the frozen
    workbench implementation accepts a ``Path`` in its KubernetesAdapter.
    This adapter therefore keeps the private snapshot present until the inner
    transaction is finished and rechecks descriptor identity and bytes before
    every outer transport process spawn.  The snapshot directory is owner-only
    and is removed as part of the single wrapper cleanup path.
    """
    def __init__(self, snapshot: PinnedExecutableSnapshot):
        self.snapshot = snapshot
        self.path = snapshot.path
        self.fd = snapshot.fd

    def _verify(self) -> None:
        snapshot = self.snapshot
        require(snapshot.fd >= 0, "pinned executable descriptor closed")
        info = os.lstat(snapshot.path); opened = os.fstat(snapshot.fd)
        require(
            stat.S_ISREG(info.st_mode)
            and not snapshot.path.is_symlink()
            and (info.st_dev, info.st_ino, info.st_size) == (snapshot.device, snapshot.inode, snapshot.size)
            and (opened.st_dev, opened.st_ino, opened.st_size) == (snapshot.device, snapshot.inode, snapshot.size)
            and (not snapshot.immutable or bool(info.st_flags & stat.UF_IMMUTABLE))
            and bytes_sha256(os.pread(snapshot.fd, snapshot.size + 1, 0)) == snapshot.sha256,
            "pinned executable snapshot drift",
        )

    def popen(self, arguments: list[str], **kwargs: Any) -> subprocess.Popen[Any]:
        self._verify()
        require(arguments and arguments[0] == str(self.path), "pinned executable command path drift")
        return subprocess.Popen(arguments, **kwargs)

    def environment(self, prefix: str) -> dict[str, str]:
        self._verify()
        snapshot = self.snapshot
        return {
            f"{prefix}_PATH": str(snapshot.path),
            f"{prefix}_FD": str(snapshot.fd),
            f"{prefix}_DEVICE": str(snapshot.device),
            f"{prefix}_INODE": str(snapshot.inode),
            f"{prefix}_SIZE": str(snapshot.size),
            f"{prefix}_SHA256": snapshot.sha256,
        }

def snapshot_binary(source_path: Path, label: str, destination: Path) -> PinnedExecutableSnapshot:
    resolved = Path(source_path).expanduser().resolve(strict=True)
    source_flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"): source_flags |= os.O_NOFOLLOW
    source_fd = os.open(resolved, source_flags)
    destination_fd = -1
    try:
        before = os.fstat(source_fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size > 0, f"{label} must resolve to a non-empty regular executable")
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"): flags |= os.O_NOFOLLOW
        destination_fd = os.open(destination, flags, 0o500)
        digest = hashlib.sha256()
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk: break
            digest.update(chunk)
            pending = memoryview(chunk)
            while pending:
                written = os.write(destination_fd, pending)
                pending = pending[written:]
        os.fchmod(destination_fd, 0o500); os.fsync(destination_fd)
        after = os.fstat(source_fd); bound = os.fstat(destination_fd)
        observed = "sha256:" + digest.hexdigest()
        path_info = os.lstat(destination)
        require(
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            and observed == EXPECTED_BINARIES[label]
            and stat.S_ISREG(bound.st_mode)
            and bound.st_uid == os.geteuid()
            and bound.st_nlink == 1
            and stat.S_IMODE(bound.st_mode) == 0o500
            and (bound.st_dev, bound.st_ino, bound.st_size)
            == (path_info.st_dev, path_info.st_ino, path_info.st_size)
            and "sha256:" + hashlib.sha256(os.pread(destination_fd, bound.st_size + 1, 0)).hexdigest() == observed,
            f"{label} executable snapshot verification failed",
        )
        fsync_directory(destination.parent)
        result = PinnedExecutableSnapshot(destination, destination_fd, bound.st_dev, bound.st_ino, bound.st_size, observed)
        destination_fd = -1
        return result
    finally:
        if destination_fd >= 0: os.close(destination_fd)
        os.close(source_fd)

def wireproxy_config(authority: str, wireguard: bytes) -> bytes:
    require(authority in {f"{API_HOST}:{API_PORT}", f"{API_HOST}:{TALOS_PORT}"}, "wireproxy target authority is not protected")
    require(isinstance(wireguard, bytes) and 0 < len(wireguard) <= 1024 * 1024, "WireGuard configuration byte size invalid")
    try:
        text = wireguard.decode("ascii")
    except UnicodeDecodeError as exc:
        raise LiveTransportError("WireGuard configuration must be ASCII") from exc
    sections: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if re.match(r"(?i)^wgconfig\s*=", line):
            raise LiveTransportError("nested WireGuard configuration path is forbidden")
        if not line.startswith("["):
            continue
        match = re.fullmatch(r"\[([A-Za-z0-9]+)\](?:\s*[#;].*)?", line)
        require(match is not None, "WireGuard section syntax invalid")
        sections.append(match.group(1).lower())
    require(
        sections.count("interface") == 1
        and sections.count("peer") >= 1
        and set(sections) == {"interface", "peer"},
        "WireGuard configuration may contain only one Interface and one-or-more Peer sections",
    )
    return wireguard.rstrip() + (
        "\n\n[STDIOTunnel]\n"
        f"Target = {authority}\n"
    ).encode()

def proxy_url(password: str, port: int) -> str:
    require(re.fullmatch(r"[0-9a-f]{64}", password) is not None, "proxy credential must be CSPRNG hex")
    require(1024 <= port <= 65535, "proxy port outside unprivileged range")
    return f"http://{PROXY_USERNAME}:{password}@127.0.0.1:{port}"


def sanitized_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    blocked = {"http_proxy", "https_proxy", "all_proxy", "no_proxy", "kubeconfig", "pythonpath"}
    value = {key: content for key, content in os.environ.items() if key.lower() not in blocked}
    if extra: value.update(extra)
    return value

def write_private(path: Path, value: bytes, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"): flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            fd = -1; stream.write(value); stream.flush(); os.fsync(stream.fileno())
    finally:
        if fd >= 0: os.close(fd)
    fsync_directory(path.parent)

@dataclass
class BoundBlob:
    fd: int
    size: int
    sha256: str
    label: str

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

@dataclass
class BoundRunner:
    logical_path: str
    blob: BoundBlob

    def command(self, arguments: list[str]) -> list[str]:
        return [
            sys.executable,
            "-I",
            "-c",
            RUNNER_LAUNCHER,
            str(ROOT / self.logical_path),
            str(self.blob.fd),
            str(self.blob.size),
            self.blob.sha256,
            *arguments,
        ]

    def close(self) -> None:
        self.blob.close()

# This launcher is part of this protected wrapper.  It never imports the
# worktree implementation: it reads the already-bound Git blob from an
# inherited descriptor, verifies it again, injects only the already-pinned
# kubectl snapshot into the exact implementation module, and calls its narrow
# ``main`` entry point.  The implementation's own KubernetesAdapter retains
# ownership of the allowed resource/verb validation.
WORKBENCH_IMPLEMENTATION_LAUNCHER = """import hashlib,os,stat,sys
from pathlib import Path
path,fd_text,size_text,expected,kubectl_path,kubectl_fd_text,kubectl_dev_text,kubectl_inode_text,kubectl_size_text,kubectl_expected=sys.argv[1:11]
fd,size=int(fd_text),int(size_text)
source=os.pread(fd,size+1,0)
if len(source)!=size or 'sha256:'+hashlib.sha256(source).hexdigest()!=expected:
    raise SystemExit('bound workbench implementation bytes differ')
kubectl_fd,kubectl_dev,kubectl_inode,kubectl_size=(int(kubectl_fd_text),int(kubectl_dev_text),int(kubectl_inode_text),int(kubectl_size_text))
opened=os.fstat(kubectl_fd)
info=os.lstat(kubectl_path)
if not (stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and stat.S_ISREG(opened.st_mode) and bool(info.st_flags & stat.UF_IMMUTABLE) and (info.st_dev,info.st_ino,info.st_size)==(kubectl_dev,kubectl_inode,kubectl_size) and (opened.st_dev,opened.st_ino,opened.st_size)==(kubectl_dev,kubectl_inode,kubectl_size) and 'sha256:'+hashlib.sha256(os.pread(kubectl_fd,kubectl_size+1,0)).hexdigest()==kubectl_expected):
    raise SystemExit('pinned kubectl snapshot differs before workbench execution')
scope={'__name__':'protected_workbench_baseline_handover','__file__':path,'__package__':None,'__cached__':None}
exec(compile(source,path,'exec',dont_inherit=True),scope)
scope['KUBECTL_BIN']=Path(kubectl_path)
def _verify_pinned_kubectl():
    current=os.lstat(kubectl_path); current_fd=os.fstat(kubectl_fd)
    if not (stat.S_ISREG(current.st_mode) and not stat.S_ISLNK(current.st_mode) and bool(current.st_flags & stat.UF_IMMUTABLE) and (current.st_dev,current.st_ino,current.st_size)==(kubectl_dev,kubectl_inode,kubectl_size) and (current_fd.st_dev,current_fd.st_ino,current_fd.st_size)==(kubectl_dev,kubectl_inode,kubectl_size) and 'sha256:'+hashlib.sha256(os.pread(kubectl_fd,kubectl_size+1,0)).hexdigest()==kubectl_expected):
        raise scope['HandoverError']('pinned kubectl snapshot drift')
_BaseKubernetesAdapter=scope['KubernetesAdapter']
class _PinnedKubernetesAdapter(_BaseKubernetesAdapter):
    def __init__(self,kubeconfig,*,kubectl=scope['KUBECTL_BIN']):
        if Path(kubectl)!=Path(kubectl_path):
            raise scope['HandoverError']('workbench KubernetesAdapter kubectl override forbidden')
        _verify_pinned_kubectl()
        super().__init__(kubeconfig,kubectl=Path(kubectl_path))
    def _run(self,args,*,input_text=None):
        _verify_pinned_kubectl()
        result=super()._run(args,input_text=input_text)
        _verify_pinned_kubectl()
        return result
scope['KubernetesAdapter']=_PinnedKubernetesAdapter
raise SystemExit(int(scope['main'](sys.argv[11:])))
"""

def workbench_implementation_command(
    implementation: BoundRunner,
    kubectl: PinnedExecutableSnapshot,
    arguments: list[str],
) -> list[str]:
    """Return the only command shape admitted for workbench handover mode."""
    require(kubectl.fd >= 0 and kubectl.path.exists(), "pinned workbench kubectl snapshot unavailable")
    return [
        sys.executable,
        "-I",
        "-c",
        WORKBENCH_IMPLEMENTATION_LAUNCHER,
        str(ROOT / implementation.logical_path),
        str(implementation.blob.fd),
        str(implementation.blob.size),
        implementation.blob.sha256,
        str(kubectl.path),
        str(kubectl.fd),
        str(kubectl.device),
        str(kubectl.inode),
        str(kubectl.size),
        kubectl.sha256,
        *arguments,
    ]

# The image promoter has a different error type and Kubernetes adapter
# signature from the baseline handover implementation.  Derive a separate
# launcher from the already-closed, audited pinned-kubectl launcher rather
# than adding a generic command executor or importing the ambient worktree.
WORKBENCH_PROMOTER_LAUNCHER = (
    WORKBENCH_IMPLEMENTATION_LAUNCHER
    .replace("protected_workbench_baseline_handover", "protected_workbench_image_promotion")
    .replace("HandoverError", "PromotionError")
    .replace("pinned kubectl snapshot differs before workbench execution", "pinned kubectl snapshot differs before workbench promotion")
    .replace("workbench KubernetesAdapter kubectl override forbidden", "workbench promoter kubectl override forbidden")
    # The promoter hard-binds its functional probes to the fixed public HTTPS
    # origin while independently proving Service/EndpointSlice-to-Pod binding.
    # Do not expose an arbitrary network destination through the launcher.
    .replace(
        "def _run(self,args,*,input_text=None):",
        "def _run(self,args,*,input_text=None,timeout=40,request_timeout_seconds=30):",
    )
    .replace(
        "super()._run(args,input_text=input_text)",
        "super()._run(args,input_text=input_text,timeout=timeout,request_timeout_seconds=request_timeout_seconds)",
    )
)

def workbench_promoter_command(
    promoter: BoundRunner,
    kubectl: PinnedExecutableSnapshot,
    arguments: list[str],
) -> list[str]:
    """Return the only command shape admitted for image promotion mode."""
    require(kubectl.fd >= 0 and kubectl.path.exists(), "pinned workbench kubectl snapshot unavailable")
    return [
        sys.executable,
        "-I",
        "-c",
        WORKBENCH_PROMOTER_LAUNCHER,
        str(ROOT / promoter.logical_path),
        str(promoter.blob.fd),
        str(promoter.blob.size),
        promoter.blob.sha256,
        str(kubectl.path),
        str(kubectl.fd),
        str(kubectl.device),
        str(kubectl.inode),
        str(kubectl.size),
        kubectl.sha256,
        *arguments,
    ]

# The relay reset child has its own exact gated two-Pod reset plus public-Mecky
# Flux suspend/scale/restore capability and error type. Reuse the
# descriptor-pinned launcher shape without introducing a generic Kubernetes
# command executor or permitting caller-selected targets.
RELAY_FIXTURE_RESET_LAUNCHER = (
    WORKBENCH_PROMOTER_LAUNCHER
    .replace("protected_workbench_image_promotion", "protected_relay_fixture_reset")
    .replace("PromotionError", "RelayResetError")
    .replace("pinned kubectl snapshot differs before workbench promotion", "pinned kubectl snapshot differs before relay fixture reset")
    .replace("workbench promoter kubectl override forbidden", "relay fixture reset kubectl override forbidden")
)

def relay_fixture_reset_command(
    runner: BoundRunner,
    kubectl: PinnedExecutableSnapshot,
    arguments: list[str],
) -> list[str]:
    """Return the only command shape admitted for relay fixture reset mode."""
    require(kubectl.fd >= 0 and kubectl.path.exists(), "pinned relay reset kubectl snapshot unavailable")
    return [
        sys.executable,
        "-I",
        "-c",
        RELAY_FIXTURE_RESET_LAUNCHER,
        str(ROOT / runner.logical_path),
        str(runner.blob.fd),
        str(runner.blob.size),
        runner.blob.sha256,
        str(kubectl.path),
        str(kubectl.fd),
        str(kubectl.device),
        str(kubectl.inode),
        str(kubectl.size),
        kubectl.sha256,
        *arguments,
    ]

def bind_bytes_to_fd(value: bytes, destination: Path, label: str) -> BoundBlob:
    require(isinstance(value, bytes) and 0 < len(value) <= MAX_RECEIPT_BYTES, f"{label} byte size invalid")
    write_private(destination, value)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"): flags |= os.O_NOFOLLOW
    fd = os.open(destination, flags)
    try:
        info = os.fstat(fd)
        observed = bytes_sha256(os.pread(fd, info.st_size + 1, 0))
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.geteuid()
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_size == len(value)
            and observed == bytes_sha256(value),
            f"{label} immutable snapshot verification failed",
        )
        destination.unlink(); fsync_directory(destination.parent)
        return BoundBlob(fd, info.st_size, observed, label)
    except BaseException:
        os.close(fd)
        try: destination.unlink()
        except FileNotFoundError: pass
        raise


def bind_handover_git_closure(
    revision: str,
    binding_dir: Path,
    protected_blobs: dict[str, bytes],
) -> tuple[dict[tuple[str, str], BoundBlob], list[BoundBlob]]:
    """Bind every Git blob the dormant handover may transitively inspect.

    Current blobs are checked against the protected checkout; historical blobs
    are fetched once by this outer wrapper and then inherited by descriptor.
    The child receives no Git capability and fails closed if a descriptor is
    missing or widened.
    """
    bound: dict[tuple[str, str], BoundBlob] = {}
    owned: list[BoundBlob] = []
    try:
        for index, path in enumerate(HANDOVER_PREBOUND_CURRENT_PATHS):
            local = ROOT / path
            info = os.lstat(local)
            require(stat.S_ISREG(info.st_mode) and not local.is_symlink(), f"handover protected file is not regular: {path}")
            expected = protected_blobs.get(path)
            if expected is None:
                expected = git_blob(revision, path)
            require(local.read_bytes() == expected, f"handover current protected file drift: {path}")
            item = bind_bytes_to_fd(expected, binding_dir / f"handover-current-{index}.bound", f"handover current Git blob {path}")
            bound[(revision, path)] = item; owned.append(item)
        for index, path in enumerate(HANDOVER_PREBOUND_ARCHIVE_PATHS):
            expected = git_blob(HANDOVER_ARCHIVE_REVISION, path)
            item = bind_bytes_to_fd(expected, binding_dir / f"handover-archive-{index}.bound", f"handover archived Git blob {path}")
            bound[(HANDOVER_ARCHIVE_REVISION, path)] = item; owned.append(item)
        current_secret = protected_blobs[SECRET_RUNNER]
        current_secret_item = bind_bytes_to_fd(
            current_secret,
            binding_dir / "handover-current-secret-materializer.bound",
            "handover current Secret materializer Git blob",
        )
        bound[(revision, SECRET_RUNNER)] = current_secret_item; owned.append(current_secret_item)
        historical_secret = git_blob(HANDOVER_SECRET_RECEIPT_ORIGIN_REVISION, SECRET_RUNNER)
        historical_secret_item = bind_bytes_to_fd(
            historical_secret,
            binding_dir / "handover-historical-secret-materializer.bound",
            "handover historical Secret materializer Git blob",
        )
        bound[(HANDOVER_SECRET_RECEIPT_ORIGIN_REVISION, SECRET_RUNNER)] = historical_secret_item; owned.append(historical_secret_item)
        require(
            set(bound) == {
                *((revision, path) for path in HANDOVER_PREBOUND_CURRENT_PATHS),
                *((HANDOVER_ARCHIVE_REVISION, path) for path in HANDOVER_PREBOUND_ARCHIVE_PATHS),
                (revision, SECRET_RUNNER),
                (HANDOVER_SECRET_RECEIPT_ORIGIN_REVISION, SECRET_RUNNER),
            },
            "handover prebound Git closure is incomplete or widened",
        )
        fsync_directory(binding_dir)
        return bound, owned
    except BaseException:
        for item in owned:
            item.close()
        raise

def snapshot_owned_receipt(source: Path, destination: Path, label: str) -> BoundBlob:
    selected = Path(os.path.abspath(source)); info = os.lstat(selected)
    require(
        stat.S_ISREG(info.st_mode)
        and not selected.is_symlink()
        and info.st_uid == os.geteuid()
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o600
        and 0 < info.st_size <= MAX_RECEIPT_BYTES,
        f"{label} must be a bounded owned 0600 nlink-one regular file",
    )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"): flags |= os.O_NOFOLLOW
    source_fd = os.open(selected, flags)
    try:
        opened = os.fstat(source_fd)
        require(
            (opened.st_dev, opened.st_ino, opened.st_size)
            == (info.st_dev, info.st_ino, info.st_size),
            f"{label} identity changed while opening",
        )
        raw = os.pread(source_fd, opened.st_size + 1, 0)
        after = os.fstat(source_fd)
        require(
            len(raw) == opened.st_size
            and (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            f"{label} changed while snapshotting",
        )
    finally:
        os.close(source_fd)
    return bind_bytes_to_fd(raw, destination, label)


def snapshot_owned_file_path(
    source: Path,
    destination: Path,
    label: str,
    *,
    max_bytes: int = MAX_RECEIPT_BYTES,
) -> Path:
    """Copy one owner-only input into the private transaction directory.

    The protected child receives a path because the workbench promoter's
    audited CLI accepts a path, not an inherited descriptor.  The source is
    nevertheless identity-checked and the copy is created owner-only inside
    the wrapper's private temporary directory, so the child cannot be steered
    to a caller-replaced or world-readable artifact pin.
    """
    selected = private_file(source, label, max_bytes)
    info = os.lstat(selected)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    source_fd = os.open(selected, flags)
    try:
        opened = os.fstat(source_fd)
        require(
            (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            == (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns),
            f"{label} identity changed while opening",
        )
        raw = os.pread(source_fd, opened.st_size + 1, 0)
        after = os.fstat(source_fd)
        require(
            len(raw) == opened.st_size
            and (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            f"{label} changed while snapshotting",
        )
    finally:
        os.close(source_fd)
    write_private(destination, raw)
    copied = os.lstat(destination)
    require(
        stat.S_ISREG(copied.st_mode)
        and copied.st_uid == os.geteuid()
        and copied.st_nlink == 1
        and stat.S_IMODE(copied.st_mode) == 0o600
        and copied.st_size == len(raw)
        and bytes_sha256(destination.read_bytes()) == bytes_sha256(raw),
        f"{label} private snapshot verification failed",
    )
    return destination


def bind_terminal_finalization_journal(source: Path, binding_directory: Path, revision: str) -> BoundBlob:
    """Bind the one exact terminal journal before any live transport exists."""
    try:
        bound = snapshot_owned_receipt(
            source,
            binding_directory / "recovery-terminal-finalization-journal.bound",
            "exact terminal-finalization journal",
        )
    except (LiveTransportError, OSError) as exc:
        raise LiveTransportError("exact terminal-finalization journal is absent or invalid") from exc
    try:
        require(
            bound.sha256 == WORKBENCH_RECOVERY_TERMINAL_JOURNAL_FILE_SHA256,
            "exact terminal-finalization journal checksum drift",
        )
        require_protected_revision_parent(revision, WORKBENCH_RECOVERY_FINALIZATION_PARENT_REVISION)
        return bound
    except BaseException:
        bound.close()
        raise

def process_group_gone(process: subprocess.Popen[Any]) -> bool:
    try: os.killpg(process.pid, 0)
    except ProcessLookupError: return True
    except PermissionError: return False
    return False

def stop_process(process: subprocess.Popen[Any] | None, timeout: float = 5) -> bool:
    if process is None: return True
    if not process_group_gone(process):
        try: os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError: pass
    try: process.wait(timeout=timeout)
    except subprocess.TimeoutExpired: pass
    if not process_group_gone(process):
        try: os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError: pass
    try: process.wait(timeout=timeout)
    except subprocess.TimeoutExpired: pass
    deadline = time.monotonic() + timeout
    while not process_group_gone(process) and time.monotonic() < deadline: time.sleep(0.05)
    return (
        process.poll() is not None
        and process_group_gone(process)
        and getattr(process, "cleanup_error", None) is None
    )

@dataclass
class ProcessResult:
    returncode: int
    stdout: str | bytes | None
    stderr: str | bytes | None

class CancellationState:
    """Non-raising signal state installed before any sensitive run artifact."""
    def __init__(self):
        self.signals: list[int] = []
        self.previous_handlers: dict[int, Any] = {}
        self.active_process: subprocess.Popen[Any] | None = None
        self.forward_active_signal = False
        self.receipt_pending = False
        self.finalizing = False
        self.owned_processes: list[subprocess.Popen[Any]] = []

    def install(self) -> None:
        require(not self.previous_handlers, "cancellation state already installed")
        for signum in TRANSACTION_SIGNALS:
            self.previous_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, self.handle_signal)

    def handle_signal(self, received: int, _frame: Any) -> None:
        try:
            self.signals.append(received)
            process = self.active_process if self.forward_active_signal else None
            if process is not None and process.poll() is None:
                try: os.killpg(process.pid, received)
                except (OSError, ProcessLookupError): pass
        except BaseException:
            pass

    def checkpoint(self) -> None:
        if self.signals and not self.finalizing:
            raise LiveTransportInterrupted(self.signals[-1])


    def run(
        self,
        command: list[str],
        *,
        allow_cancelled: bool = False,
        forward_signals: bool = True,
        receipt_pending: bool = False,
        timeout: float | None = None,
        executable_binding: Any | None = None,
        **kwargs: Any,
    ) -> ProcessResult:
        if not allow_cancelled: self.checkpoint()
        process = (
            executable_binding.popen(command, start_new_session=True, **kwargs)
            if executable_binding is not None
            else subprocess.Popen(command, start_new_session=True, **kwargs)
        )
        self.owned_processes.append(process)
        self.active_process = process
        self.forward_active_signal = forward_signals
        if forward_signals and self.signals and process.poll() is None:
            try: os.killpg(process.pid, self.signals[-1])
            except (OSError, ProcessLookupError): pass
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            stop_process(process)
            raise LiveTransportError(f"owned process timed out: {Path(command[0]).name}") from exc
        finally:
            if self.active_process is process:
                self.active_process = None
                self.forward_active_signal = False
            if receipt_pending:
                self.receipt_pending = True
        return ProcessResult(int(process.returncode), stdout, stderr)


    def receipt_reconciled(self) -> None:
        self.receipt_pending = False

    def begin_finalization(self) -> None:
        self.finalizing = True
        self.active_process = None
        self.forward_active_signal = False

    def cleanup_processes(self) -> dict[str, Any]:
        stopped = [stop_process(process) for process in reversed(self.owned_processes)]
        return {"ownedProcessGroupsStopped": all(stopped), "ownedProcessGroupCount": len(stopped)}

    def restore(self) -> None:
        for signum, handler in self.previous_handlers.items(): signal.signal(signum, handler)
        self.previous_handlers.clear()

def decrypt(state: CancellationState, age: Any, identity: Path, source: Path, destination: Path) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"): flags |= os.O_NOFOLLOW
    fd = os.open(destination, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            fd = -1
            result = state.run(
                [str(age.path), "--decrypt", "--identity", str(identity), str(source)],
                stdout=stream,
                stderr=subprocess.PIPE,
                timeout=30,
                executable_binding=age,
            )
            stream.flush(); os.fsync(stream.fileno())
        require(result.returncode == 0, "encrypted transport input could not be decrypted")
        state.checkpoint()
    finally:
        if fd >= 0: os.close(fd)

@dataclass
class ChildResult:
    returncode: int
    stdout: str
    stderr: str
    transport_alive_after: bool

class ExactConnectProxy:
    """Authenticated exact-authority listener spawning fixed-target stdio tunnels."""
    def __init__(
        self,
        authority: str,
        proxy_binary: Any,
        config: bytes,
        config_directory: Path,
        client_password: str,
        environment: dict[str, str],
        max_workers: int = 16,
    ):
        require(authority in {f"{API_HOST}:{API_PORT}", f"{API_HOST}:{TALOS_PORT}"}, "CONNECT authority is not protected")
        require(re.fullmatch(r"[0-9a-f]{64}", client_password) is not None, "CONNECT credential must be CSPRNG hex")
        require(1 <= max_workers <= 64, "CONNECT worker bound invalid")
        self.authority, self.proxy_binary = authority, proxy_binary
        self.config, self.config_directory = config, config_directory
        self.client_password, self.environment = client_password, environment
        self.max_workers = max_workers
        self.listener: socket.socket | None = None
        self.port: int | None = None
        self.thread: threading.Thread | None = None
        self.connections: set[socket.socket] = set()
        self.processes: set[subprocess.Popen[Any]] = set()
        self.workers: set[threading.Thread] = set()
        self.lock = threading.Lock()
        self.stopping = threading.Event()

    @staticmethod
    def _authorization(username: str, password: str) -> str:
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        return f"Basic {encoded}"

    def expected_authorization(self) -> str:
        return self._authorization(PROXY_USERNAME, self.client_password)

    def _response(self, connection: socket.socket, status: int, reason: str, authenticate: bool = False) -> None:
        extra = 'Proxy-Authenticate: Basic realm="stadtstack-participant"\r\n' if authenticate else ""
        try: connection.sendall(f"HTTP/1.1 {status} {reason}\r\n{extra}Connection: close\r\nContent-Length: 0\r\n\r\n".encode("ascii"))
        except OSError: pass

    def _read_head(self, connection: socket.socket) -> tuple[bytes, bytes]:
        value = bytearray(); connection.settimeout(0.25)
        deadline = time.monotonic() + 5
        while b"\r\n\r\n" not in value:
            if self.stopping.is_set():
                raise LiveTransportError("CONNECT guard stopped before headers")
            try: chunk = connection.recv(2048)
            except socket.timeout:
                if time.monotonic() >= deadline:
                    raise LiveTransportError("CONNECT peer header timeout")
                continue
            except OSError as exc: raise LiveTransportError("CONNECT peer read failed") from exc
            if not chunk: raise LiveTransportError("CONNECT peer closed before headers")
            value.extend(chunk)
            require(len(value) <= 8192, "CONNECT headers exceed 8192 bytes")
        return bytes(value).split(b"\r\n\r\n", 1)

    def _read_request(self, connection: socket.socket) -> tuple[int, str, bool]:
        try: head, remainder = self._read_head(connection)
        except LiveTransportError: return 400, "Bad Request", False
        if remainder: return 400, "Bad Request", False
        try: lines = head.decode("ascii").split("\r\n")
        except UnicodeDecodeError: return 400, "Bad Request", False
        request = lines[0].split(" ")
        if len(request) != 3 or request[2] not in {"HTTP/1.0", "HTTP/1.1"}: return 400, "Bad Request", False
        if request[0] != "CONNECT": return 405, "Method Not Allowed", False
        if request[1] != self.authority: return 403, "Forbidden", False
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line or line[:1] in {" ", "\t"} or ":" not in line: return 400, "Bad Request", False
            name, content = line.split(":", 1); lower = name.lower()
            if re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) is None or lower in headers: return 400, "Bad Request", False
            headers[lower] = content.strip()
        if headers.get("host") != self.authority: return 400, "Bad Request", False
        supplied = headers.get("proxy-authorization", "")
        if not secrets.compare_digest(supplied, self.expected_authorization()): return 407, "Proxy Authentication Required", False
        return 200, "Connection Established", True

    def _spawn_tunnel(self) -> tuple[socket.socket, subprocess.Popen[Any]]:
        require(not self.stopping.is_set(), "CONNECT guard is stopping")
        parent, child = socket.socketpair()
        process: subprocess.Popen[Any] | None = None
        try:
            config_blob = bind_bytes_to_fd(
                self.config,
                self.config_directory / f".wireproxy-{secrets.token_hex(16)}.bound",
                f"{self.authority} fixed-target wireproxy config",
            )
            try:
                process = self.proxy_binary.popen(
                    [str(self.proxy_binary.path), "-s", "-c", f"/dev/fd/{config_blob.fd}"],
                    stdin=child,
                    stdout=child,
                    stderr=subprocess.DEVNULL,
                    env=self.environment,
                    pass_fds=(config_blob.fd,),
                    start_new_session=True,
                )
            finally:
                config_blob.close()
            child.close()
            with self.lock:
                self.connections.add(parent); self.processes.add(process)
            if self.stopping.is_set():
                raise LiveTransportError("CONNECT guard stopped during tunnel spawn")
            deadline = time.monotonic() + 0.25
            while time.monotonic() < deadline:
                require(process.poll() is None, "fixed-target stdio tunnel exited before relay")
                time.sleep(0.01)
            parent.settimeout(None)
            return parent, process
        except BaseException:
            try: child.close()
            except OSError: pass
            try: parent.close()
            except OSError: pass
            if process is not None:
                stop_process(process, 1)
                with self.lock: self.processes.discard(process)
            with self.lock: self.connections.discard(parent)
            raise

    def _relay(self, left: socket.socket, right: socket.socket) -> None:
        peers = {left: right, right: left}
        try:
            while not self.stopping.is_set():
                readable, _, _ = select.select(list(peers), [], [], 0.25)
                for source in readable:
                    data = source.recv(65536)
                    if not data: return
                    peers[source].sendall(data)
        except (OSError, ValueError): return

    def _serve_connection(self, connection: socket.socket) -> None:
        backend: socket.socket | None = None; process: subprocess.Popen[Any] | None = None
        try:
            status, reason, accepted = self._read_request(connection)
            if not accepted:
                self._response(connection, status, reason, authenticate=status == 407)
                return
            try: backend, process = self._spawn_tunnel()
            except (OSError, LiveTransportError):
                self._response(connection, 502, "Bad Gateway")
                return
            connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            connection.settimeout(None)
            self._relay(connection, backend)
        finally:
            for current in (backend, connection):
                if current is None: continue
                try: current.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                try: current.close()
                except OSError: pass
                with self.lock: self.connections.discard(current)
            if process is not None:
                stop_process(process, 1)
                with self.lock: self.processes.discard(process)
            with self.lock: self.workers.discard(threading.current_thread())

    def _serve(self) -> None:
        assert self.listener is not None
        self.listener.settimeout(0.25)
        while not self.stopping.is_set():
            try: connection, peer = self.listener.accept()
            except socket.timeout: continue
            except OSError: return
            if peer[0] != "127.0.0.1":
                connection.close(); continue
            with self.lock:
                if len(self.workers) >= self.max_workers:
                    worker = None
                else:
                    self.connections.add(connection)
                    worker = threading.Thread(target=self._serve_connection, args=(connection,), daemon=False)
                    self.workers.add(worker)
            if worker is None:
                self._response(connection, 503, "Service Unavailable")
                connection.close()
                continue
            try: worker.start()
            except BaseException:
                with self.lock:
                    self.workers.discard(worker); self.connections.discard(connection)
                connection.close()
                raise

    def start(self) -> int:
        require(self.listener is None, "CONNECT guard already started")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.bind(("127.0.0.1", 0)); listener.listen(self.max_workers)
        except BaseException:
            listener.close(); raise
        self.listener = listener; self.port = int(listener.getsockname()[1])
        self.thread = threading.Thread(target=self._serve, daemon=False); self.thread.start()
        return self.port

    def alive(self) -> bool:
        return self.listener is not None and self.thread is not None and self.thread.is_alive() and not self.stopping.is_set()

    def close(self, timeout: float = 5) -> dict[str, Any]:
        self.stopping.set()
        if self.listener is not None:
            try: self.listener.close()
            except OSError: pass
            self.listener = None
        with self.lock:
            connections = list(self.connections); processes = list(self.processes)
        for connection in connections:
            try: connection.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            try: connection.close()
            except OSError: pass
        process_results = [stop_process(process, 1) for process in processes]
        deadline = time.monotonic() + timeout
        if self.thread is not None:
            self.thread.join(timeout=max(0, deadline - time.monotonic()))
        while True:
            with self.lock: workers = list(self.workers)
            if not workers or time.monotonic() >= deadline: break
            for worker in workers: worker.join(timeout=max(0, deadline - time.monotonic()))
        listener_stopped = self.thread is None or not self.thread.is_alive()
        with self.lock:
            remaining_processes = list(self.processes)
            workers_stopped = all(not worker.is_alive() for worker in self.workers)
            connections_closed = not self.connections
        process_results.extend(stop_process(process, 1) for process in remaining_processes)
        tunnels_stopped = all(process_results) and all(process_group_gone(process) for process in remaining_processes)
        if listener_stopped: self.thread = None
        return {
            "listenerStopped": listener_stopped,
            "workerThreadsStopped": workers_stopped,
            "connectionsClosed": connections_closed,
            "tunnelProcessGroupsStopped": tunnels_stopped,
            "workerLimit": self.max_workers,
        }

class LiveSession:
    def __init__(
        self,
        proxy_binary: Any,
        api_config: bytes,
        talos_config: bytes,
        config_directory: Path,
        api_password: str,
        talos_password: str,
        cancellation: CancellationState,
    ):
        self.api_password, self.talos_password = api_password, talos_password
        self.cancellation = cancellation
        environment = sanitized_environment()
        self.api_guard = ExactConnectProxy(f"{API_HOST}:{API_PORT}", proxy_binary, api_config, config_directory, api_password, environment)
        self.talos_guard = ExactConnectProxy(f"{API_HOST}:{TALOS_PORT}", proxy_binary, talos_config, config_directory, talos_password, environment)
        self.listener_verified = False

    def start_proxy(self) -> tuple[int, int]:
        api_guard_port = self.api_guard.start(); talos_guard_port = self.talos_guard.start()
        self.listener_verified = self.api_guard.alive() and self.talos_guard.alive()
        require(self.listener_verified, "exact CONNECT guards failed to start")
        return api_guard_port, talos_guard_port

    def transport_alive(self) -> bool:
        return self.api_guard.alive() and self.talos_guard.alive()

    def run_child(
        self,
        command: list[str],
        environment: dict[str, str],
        *,
        allow_cancelled: bool = False,
        forward_signals: bool = True,
        receipt_pending: bool = True,
        require_transport: bool = True,
        timeout: float = 900,
        pass_fds: tuple[int, ...] = (),
        executable_binding: Any | None = None,
    ) -> ChildResult:
        if require_transport: require(self.transport_alive(), "owned exact transport absent before protected runner")
        result = self.cancellation.run(
            command,
            allow_cancelled=allow_cancelled,
            forward_signals=forward_signals,
            receipt_pending=receipt_pending,
            timeout=timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
            pass_fds=pass_fds,
            executable_binding=executable_binding,
        )
        stdout = result.stdout if isinstance(result.stdout, str) else ""
        stderr = result.stderr if isinstance(result.stderr, str) else ""
        redacted = "[REDACTED-PROXY-CREDENTIAL]"
        for password in (self.api_password, self.talos_password):
            stdout = stdout.replace(password, redacted); stderr = stderr.replace(password, redacted)
        return ChildResult(result.returncode, stdout, stderr, self.transport_alive())

    def receipt_reconciled(self) -> None:
        self.cancellation.receipt_reconciled()

    def close(self) -> dict[str, Any]:
        api = self.api_guard.close(); talos = self.talos_guard.close()
        return {
            "apiGuard": api,
            "talosGuard": talos,
            "wireproxyProcessGroupStopped": api["tunnelProcessGroupsStopped"] and talos["tunnelProcessGroupsStopped"],
            "allGuardWorkersStopped": all(
                report["listenerStopped"]
                and report["workerThreadsStopped"]
                and report["connectionsClosed"]
                and report["tunnelProcessGroupsStopped"]
                for report in (api, talos)
            ),
        }

def create_admin_kubeconfig(
    session: LiveSession,
    talosctl: Any,
    kubectl: Any,
    talosconfig: Path,
    destination: Path,
    talos_proxy: str,
    api_proxy: str,
    temp: Path,
) -> None:
    direct = temp / "talos-kubeconfig"
    environment = sanitized_environment() | {"HTTPS_PROXY": talos_proxy, "HTTP_PROXY": talos_proxy, "NO_PROXY": ""}
    generated = session.run_child(
        [str(talosctl.path), "--talosconfig", str(talosconfig), "--endpoints", API_HOST, "--nodes", API_HOST, "kubeconfig", str(direct), "--force", "--merge=false"],
        environment,
        receipt_pending=False,
        timeout=60,
        executable_binding=talosctl,
    )
    require(generated.returncode == 0, "Talos administrator kubeconfig generation failed")
    os.chmod(direct, 0o600)
    flattened = session.run_child(
        [str(kubectl.path), "--kubeconfig", str(direct), "config", "view", "--raw", "--flatten", "--minify", "-o", "json"],
        sanitized_environment(),
        receipt_pending=False,
        require_transport=False,
        timeout=30,
        executable_binding=kubectl,
    )
    require(flattened.returncode == 0, "generated kubeconfig flattening failed")
    config = json_object(flattened.stdout, "generated kubeconfig")
    clusters = config.get("clusters")
    require(isinstance(clusters, list) and len(clusters) == 1 and isinstance(clusters[0].get("cluster"), dict), "generated kubeconfig cluster cardinality differs")
    cluster = clusters[0]["cluster"]
    cluster["server"] = f"https://{API_HOST}:{API_PORT}"
    cluster["proxy-url"] = api_proxy
    cluster.pop("tls-server-name", None)
    write_private(destination, (canonical(config) + "\n").encode())

def owned_receipt_file_sha256(path: Path) -> str:
    selected = Path(os.path.abspath(path)); info = os.lstat(selected)
    require(
        stat.S_ISREG(info.st_mode)
        and not selected.is_symlink()
        and info.st_uid == os.geteuid()
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o600
        and 0 < info.st_size <= MAX_RECEIPT_BYTES,
        f"receipt file is not a bounded owned 0600 nlink-one regular file: {selected.name}",
    )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"): flags |= os.O_NOFOLLOW
    fd = os.open(selected, flags)
    digest = hashlib.sha256(); total = 0
    try:
        opened = os.fstat(fd)
        require(
            (opened.st_dev, opened.st_ino, opened.st_size)
            == (info.st_dev, info.st_ino, info.st_size),
            f"receipt identity changed while opening: {selected.name}",
        )
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk: break
            total += len(chunk); require(total <= MAX_RECEIPT_BYTES, "receipt exceeds size bound")
            digest.update(chunk)
    finally:
        os.close(fd)
    return "sha256:" + digest.hexdigest()

class WrapperReceiptSink:
    """Pre-reserved atomic durable sink for the wrapper's final evidence."""
    def __init__(self, path: Path, device: int, inode: int):
        self.path, self.device, self.inode = path, device, inode

    @classmethod
    def reserve(cls, path: Path) -> "WrapperReceiptSink":
        selected = Path(os.path.abspath(path))
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"): flags |= os.O_NOFOLLOW
        fd = os.open(selected, flags, 0o600)
        try:
            os.fchmod(fd, 0o600); os.fsync(fd); info = os.fstat(fd)
        finally:
            os.close(fd)
        fsync_directory(selected.parent)
        return cls(selected, info.st_dev, info.st_ino)

    def commit(self, value: dict[str, Any]) -> str:
        require("canonicalSha256" not in value, "wrapper receipt already closed")
        checksum = bytes_sha256(canonical(value).encode())
        final = dict(value) | {"canonicalSha256": checksum}
        encoded = (canonical(final) + "\n").encode()
        require(len(encoded) <= MAX_RECEIPT_BYTES, "wrapper receipt exceeds size bound")
        current = os.lstat(self.path)
        require(
            stat.S_ISREG(current.st_mode)
            and current.st_dev == self.device
            and current.st_ino == self.inode
            and current.st_nlink == 1,
            "reserved wrapper receipt identity changed",
        )
        fd, raw_name = tempfile.mkstemp(prefix=".participant-live-receipt-", dir=self.path.parent)
        temporary = Path(raw_name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=True) as stream:
                stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            committed = os.lstat(self.path)
            require(
                stat.S_ISREG(committed.st_mode)
                and committed.st_uid == os.geteuid()
                and committed.st_nlink == 1
                and stat.S_IMODE(committed.st_mode) == 0o600,
                "committed wrapper receipt metadata drift",
            )
            self.device, self.inode = committed.st_dev, committed.st_ino
            fsync_directory(self.path.parent)
        finally:
            try: temporary.unlink()
            except FileNotFoundError: pass
        return checksum

def verify_receipt_with_protected_cli(
    cancellation: CancellationState,
    runner: BoundRunner,
    mode: str,
    receipt: BoundBlob,
    revision: str,
    environment: dict[str, str],
    expected_status: str,
    *,
    allow_cancelled: bool,
    expected_source_sha256: str | None = None,
    expected_projection_revision: str | None = None,
    extra_args: tuple[str, ...] = (),
    extra_pass_fds: tuple[int, ...] = (),
) -> dict[str, Any]:
    result = cancellation.run(
        runner.command([mode, str(receipt.fd), "--expected-protected-revision", revision, *extra_args]),
        allow_cancelled=allow_cancelled,
        forward_signals=False,
        receipt_pending=False,
        timeout=60,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
        pass_fds=(runner.blob.fd, receipt.fd, *extra_pass_fds),
    )
    require(result.returncode == 0, f"protected receipt verifier rejected {receipt.label}")
    output = result.stdout.strip() if isinstance(result.stdout, str) else ""
    require(output and "\n" not in output, f"protected receipt verifier output invalid: {receipt.label}")
    projection = json_object(output, f"verified {receipt.label}")
    require(projection.get("status") == expected_status, f"protected receipt status drift: {receipt.label}")
    require(
        projection.get("protectedRevision") == (expected_projection_revision or revision),
        f"protected receipt revision drift: {receipt.label}",
    )
    require(
        isinstance(projection.get("receiptSha256"), str)
        and SHA256.fullmatch(projection["receiptSha256"]) is not None,
        f"protected receipt checksum projection invalid: {receipt.label}",
    )
    if expected_source_sha256 is not None:
        require(
            projection.get("teardownOfReceiptSha256") == expected_source_sha256,
            f"protected teardown source receipt drift: {receipt.label}",
        )
    require(projection.get("civicAuthorityEffects") is False, f"protected receipt widened civic authority: {receipt.label}")
    return projection

def best_effort_print_child(result: ChildResult) -> str | None:
    try:
        if result.stdout: print(result.stdout, end="")
        if result.stderr: print(result.stderr, end="", file=sys.stderr)
        return None
    except (BrokenPipeError, OSError) as exc:
        return f"protected child output forwarding failed: {type(exc).__name__}"

def best_effort_stderr(message: str) -> None:
    try: print(message, file=sys.stderr)
    except (BrokenPipeError, OSError): pass

def receipt_record(projection: dict[str, Any] | None, receipt: BoundBlob | None) -> dict[str, Any]:
    return {
        "status": projection.get("status") if projection is not None else None,
        "canonicalSha256": projection.get("receiptSha256") if projection is not None else None,
        "fileSha256": receipt.sha256 if receipt is not None else None,
    }


def private_workbench_output(path: Path, label: str) -> Path:
    """Accept one explicit, private durable workbench output target.

    The inner protected runner owns its receipt/journal reservation semantics;
    this outer check only makes the transport contract explicit and rejects
    symlinked, shared, or non-private targets before any tunnel exists.
    """
    selected = Path(os.path.abspath(path))
    require(selected.is_absolute() and not selected.is_symlink(), f"{label} must be an absolute non-symlink path")
    parent = selected.parent
    parent_info = os.lstat(parent)
    require(
        stat.S_ISDIR(parent_info.st_mode)
        and parent_info.st_uid == os.geteuid()
        and stat.S_IMODE(parent_info.st_mode) & 0o077 == 0,
        f"{label} parent must be private and owned",
    )
    if selected.exists():
        info = os.lstat(selected)
        require(
            stat.S_ISREG(info.st_mode)
            and not selected.is_symlink()
            and info.st_uid == os.geteuid()
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_size <= MAX_RECEIPT_BYTES,
            f"{label} existing file must be bounded private and owned",
        )
    return selected


def private_new_workbench_output(path: Path, label: str) -> Path:
    """Require a fresh owner-only output file for a one-time mutation."""
    selected = private_workbench_output(path, label)
    require(not selected.exists(), f"{label} must not already exist")
    return selected


def private_workbench_promotion_outputs(receipt_path: Path, journal_path: Path) -> tuple[Path, Path]:
    """Accept only a fresh pair or one exact interrupted-run reservation."""
    receipt = private_workbench_output(receipt_path, "workbench image promotion receipt")
    journal = private_workbench_output(journal_path, "workbench image promotion journal")
    require(
        os.path.normcase(os.path.normpath(os.fspath(receipt)))
        != os.path.normcase(os.path.normpath(os.fspath(journal))),
        "workbench image promotion receipt and journal paths must be distinct",
    )
    receipt_exists = receipt.exists()
    journal_exists = journal.exists()
    if not receipt_exists and not journal_exists:
        return receipt, journal
    require(receipt_exists and journal_exists, "workbench image promotion restart requires both reserved output paths")
    receipt_info = os.lstat(receipt); journal_info = os.lstat(journal)
    require(
        receipt_info.st_size == 0 and 0 < journal_info.st_size <= MAX_RECEIPT_BYTES,
        "workbench image promotion restart requires an empty receipt and nonterminal journal",
    )
    return receipt, journal


def private_relay_fixture_reset_outputs(receipt_path: Path, journal_path: Path) -> tuple[Path, Path]:
    """Require two fresh outputs because destructive reset attempts are never retried blindly."""
    receipt = private_new_workbench_output(receipt_path, "relay fixture reset receipt")
    journal = private_new_workbench_output(journal_path, "relay fixture reset journal")
    require(
        os.path.normcase(os.path.normpath(os.fspath(receipt)))
        != os.path.normcase(os.path.normpath(os.fspath(journal))),
        "relay fixture reset receipt and journal paths must be distinct",
    )
    return receipt, journal


def read_bound_json(receipt: BoundBlob, label: str) -> dict[str, Any]:
    raw = os.pread(receipt.fd, receipt.size + 1, 0)
    require(len(raw) == receipt.size, f"{label} bound receipt size drift")
    return json_object(raw.decode("utf-8"), label)

def require_value_free_relay_reset_evidence(value: Any, path: str = "$") -> None:
    """Reject captured Secret values while allowing exact value-free refs."""
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower().replace("_", "").replace("-", "")
            require(
                normalized not in {"data", "stringdata"},
                f"relay reset evidence contains secret-shaped data at {path}.{key}",
            )
            if normalized == "secretkeyref":
                require(
                    isinstance(child, dict)
                    and set(child) == {"name", "key", "optional"}
                    and isinstance(child.get("name"), str)
                    and bool(child["name"])
                    and isinstance(child.get("key"), str)
                    and bool(child["key"])
                    and child.get("optional") is False,
                    f"relay reset Secret reference drift at {path}.{key}",
                )
                continue
            if normalized in {"secretvaluesread", "civicauthorityeffects", "secretread", "secretwrite"}:
                require(isinstance(child, bool), f"relay reset effect flag at {path}.{key} must be boolean")
            require_value_free_relay_reset_evidence(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            require_value_free_relay_reset_evidence(child, f"{path}[{index}]")


def verify_relay_fixture_reset_evidence(
    receipt: BoundBlob,
    journal: BoundBlob,
    revision: str,
    protected_hashes: dict[str, str],
    artifact_pin_sha256: str,
) -> dict[str, Any]:
    """Verify the reset runner's exact completed v2 receipt and journal."""
    namespace = "stadtstack-roebel-staging-lab"
    components = ("citizen-relay", "agent-relay")
    sequence = [
        "gate-workbench", "suspend-public-mecky", "scale-public-mecky-zero",
        "delete-citizen-relay", "delete-agent-relay", "scale-public-mecky-one",
        "restore-public-mecky-flux", "restore-workbench-gate",
    ]
    relay_digest = RELAY_FIXTURE_RESET_TARGET_IMAGE.rsplit("@", 1)[1]
    expected_profile = {
        "kind0Count": 1,
        "kind1Count": 0,
        "validKind0Count": 1,
        "expectedAuthorHash": True,
        "eventIdVerified": True,
        "signatureVerified": True,
        "bot": True,
        "identityVerified": True,
        "aboutNonempty": True,
        "agentTagVerified": True,
    }
    ingress_target = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "namespace": namespace,
        "name": "stadtstack-test-workbench",
    }
    deployment_target = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "namespace": namespace,
        "name": "public-mecky",
    }
    kustomization_target = {
        "apiVersion": "kustomize.toolkit.fluxcd.io/v1",
        "kind": "Kustomization",
        "namespace": "flux-roebel-staging",
        "name": "roebel-staging-public-mecky-workload",
    }

    def exact_dict(value: Any, fields: set[str], label: str) -> dict[str, Any]:
        require(isinstance(value, dict) and set(value) == fields, f"relay reset {label} field set drift")
        return value

    def exact_sha(value: Any, label: str) -> str:
        require(isinstance(value, str) and SHA256.fullmatch(value) is not None, f"relay reset {label} SHA-256 invalid")
        return value

    def exact_uuid(value: Any, label: str) -> str:
        require(isinstance(value, str) and UUID.fullmatch(value) is not None, f"relay reset {label} UUID invalid")
        return value

    def resource_version(value: Any, label: str) -> str:
        require(isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*", value) is not None, f"relay reset {label} resourceVersion invalid")
        return value

    def positive_generation(value: Any, label: str) -> int:
        require(isinstance(value, int) and not isinstance(value, bool) and value >= 1, f"relay reset {label} generation invalid")
        return value

    def validate_object_proof(value: Any, fields: set[str], label: str) -> dict[str, Any]:
        item = exact_dict(value, fields, label)
        exact_uuid(item.get("uid"), f"{label} uid")
        if "resourceVersion" in fields:
            resource_version(item.get("resourceVersion"), label)
        if "generation" in fields:
            positive_generation(item.get("generation"), label)
        if "object" in fields:
            require(isinstance(item.get("object"), dict), f"relay reset {label} object absent")
            require(
                item.get("objectSha256") == bytes_sha256(canonical(item["object"]).encode("utf-8")),
                f"relay reset {label} object checksum drift",
            )
        if "specSha256" in fields:
            exact_sha(item.get("specSha256"), f"{label} spec")
        return item

    def validate_inventory(value: Any, component: str, *, empty: bool, profile: bool) -> dict[str, Any]:
        item = exact_dict(value, {"health", "eventStore", "admissionStore", "profile", "valueFree"}, f"{component} inventory")
        require(item.get("valueFree") is True, f"relay reset {component} inventory is not value-free")
        health = exact_dict(item.get("health"), {"component", "identityVerified", "events", "empty"}, f"{component} health")
        require(
            health == {
                "component": component,
                "identityVerified": True,
                "events": 0 if empty else health.get("events"),
                "empty": empty,
            }
            and isinstance(health.get("events"), int)
            and not isinstance(health["events"], bool)
            and (health["events"] == 0 if empty else health["events"] > 0),
            f"relay reset {component} health proof drift",
        )
        event_store = exact_dict(item.get("eventStore"), {"present", "bytes", "records"}, f"{component} event store")
        require(
            isinstance(event_store.get("present"), bool)
            and all(isinstance(event_store.get(key), int) and not isinstance(event_store[key], bool) and event_store[key] >= 0 for key in ("bytes", "records")),
            f"relay reset {component} event-store counters invalid",
        )
        if empty:
            require(event_store["bytes"] == 0 and event_store["records"] == 0, f"relay reset {component} event store not empty")
        admission = exact_dict(item.get("admissionStore"), {"applicable", "present", "bytes", "records"}, f"{component} admission store")
        require(
            admission.get("applicable") is (component == "citizen-relay")
            and isinstance(admission.get("present"), bool)
            and admission.get("bytes") == 0
            and admission.get("records") == 0,
            f"relay reset {component} admission-store boundary drift",
        )
        if component == "agent-relay":
            require(admission == {"applicable": False, "present": False, "bytes": 0, "records": 0}, "relay reset agent admission store widened")
        if profile:
            require(item.get("profile") == expected_profile, "relay reset Mecky profile proof drift")
            require(health["events"] == 1 and event_store["records"] == 1 and event_store["bytes"] > 0, "relay reset Mecky profile inventory drift")
        else:
            require(item.get("profile") is None, f"relay reset {component} unexpected profile evidence")
        return item

    def validate_pod(value: Any, component: str, label: str, expected_digest: str) -> dict[str, Any]:
        pod = exact_dict(value, {"name", "uid", "resourceVersion", "replicaSetUid", "addresses", "ready", "imageDigest"}, label)
        require(isinstance(pod.get("name"), str) and pod["name"].startswith(f"{component}-"), f"relay reset {label} name drift")
        exact_uuid(pod.get("uid"), f"{label} uid")
        exact_uuid(pod.get("replicaSetUid"), f"{label} ReplicaSet uid")
        resource_version(pod.get("resourceVersion"), label)
        require(
            pod.get("ready") is True
            and pod.get("imageDigest") == expected_digest
            and isinstance(pod.get("addresses"), list)
            and bool(pod["addresses"])
            and len(pod["addresses"]) == len(set(pod["addresses"])),
            f"relay reset {label} readiness/image/address drift",
        )
        return pod

    def validate_endpoint(value: Any, component: str, pod: dict[str, Any], label: str, port: int) -> dict[str, Any]:
        endpoint = exact_dict(value, {"service", "podUid", "podName", "addresses", "endpointSliceUids", "port", "ready"}, label)
        require(
            endpoint.get("service") == component
            and endpoint.get("podUid") == pod["uid"]
            and endpoint.get("podName") == pod["name"]
            and endpoint.get("addresses") == pod["addresses"]
            and endpoint.get("port") == port
            and endpoint.get("ready") is True
            and isinstance(endpoint.get("endpointSliceUids"), list)
            and bool(endpoint["endpointSliceUids"])
            and len(endpoint["endpointSliceUids"]) == len(set(endpoint["endpointSliceUids"])),
            f"relay reset {label} Pod/Service binding drift",
        )
        for uid in endpoint["endpointSliceUids"]:
            exact_uuid(uid, f"{label} EndpointSlice uid")
        return endpoint

    def validate_snapshot(value: Any, *, after: bool) -> dict[str, Any]:
        expected_fields = {
            "resources", "runtime", "networkPolicies", "publicMecky", "publicMeckyRuntime", "ingress",
        } | (
            {"participantGateway", "feed", "feedObservations", "exact"}
            if after
            else {"workbench", "participantAdmissionBoundary"}
        )
        snapshot = exact_dict(value, expected_fields, "after snapshot" if after else "before snapshot")
        resources = exact_dict(snapshot.get("resources"), set(components), "relay resources")
        runtime = exact_dict(snapshot.get("runtime"), set(components), "relay runtime")
        for component in components:
            resource = exact_dict(resources.get(component), {"deployment", "service"}, f"{component} resources")
            validate_object_proof(resource.get("deployment"), {"uid", "resourceVersion", "generation", "specSha256"}, f"{component} Deployment")
            validate_object_proof(resource.get("service"), {"uid", "resourceVersion", "object", "objectSha256"}, f"{component} Service")
            running = exact_dict(runtime.get(component), {"pod", "endpointSlice", "inventory"}, f"{component} runtime")
            pod = validate_pod(running.get("pod"), component, f"{component} Pod", relay_digest)
            validate_endpoint(running.get("endpointSlice"), component, pod, f"{component} EndpointSlice", 18081)
            validate_inventory(running.get("inventory"), component, empty=after and component == "citizen-relay", profile=after and component == "agent-relay")
        policies = snapshot.get("networkPolicies")
        require(isinstance(policies, list) and bool(policies), "relay reset NetworkPolicy inventory absent")
        policy_names: list[str] = []
        for index, policy_value in enumerate(policies):
            policy = validate_object_proof(policy_value, {"name", "uid", "generation", "object", "objectSha256"}, f"NetworkPolicy[{index}]")
            require(isinstance(policy.get("name"), str) and bool(policy["name"]), "relay reset NetworkPolicy name invalid")
            policy_names.append(policy["name"])
        require(policy_names == sorted(set(policy_names)), "relay reset NetworkPolicy inventory order/cardinality drift")
        ingress = validate_object_proof(snapshot.get("ingress"), {"uid", "resourceVersion", "generation", "policy", "object", "objectSha256", "specSha256"}, "workbench Ingress")
        require(
            ingress.get("uid") == "02cc55b5-30c5-46dd-b819-727e53c58806"
            and ingress.get("generation") == 1
            and isinstance(ingress.get("object"), dict)
            and ingress.get("specSha256") == bytes_sha256(canonical(ingress["object"].get("spec")).encode("utf-8")),
            "relay reset workbench Ingress identity/spec drift",
        )
        public_mecky = exact_dict(snapshot.get("publicMecky"), {"deployment", "service", "kustomization"}, "public-Mecky resources")
        deployment = validate_object_proof(public_mecky.get("deployment"), {"uid", "resourceVersion", "generation", "replicas", "specSha256"}, "public-Mecky Deployment")
        require(deployment.get("uid") == "96987f99-0fb7-4149-a5e7-f0b7c469ab75" and deployment.get("replicas") == 1, "relay reset public-Mecky Deployment state drift")
        validate_object_proof(public_mecky.get("service"), {"uid", "object", "objectSha256"}, "public-Mecky Service")
        flux = validate_object_proof(public_mecky.get("kustomization"), {"uid", "resourceVersion", "generation", "suspended", "suspendExplicit", "specSha256"}, "public-Mecky Kustomization")
        require(
            flux.get("uid") == "4d49b8eb-c84b-442a-a96e-26c94f24177a"
            and flux.get("suspended") is False
            and isinstance(flux.get("suspendExplicit"), bool),
            "relay reset public-Mecky Kustomization state drift",
        )
        mecky_runtime = exact_dict(snapshot.get("publicMeckyRuntime"), {"pod", "endpointSlice"}, "public-Mecky runtime")
        mecky_pod = validate_pod(mecky_runtime.get("pod"), "public-mecky", "public-Mecky Pod", "sha256:aa66c9b8bb75989e1c47b628845523fa345a944b0a1a82bd17863f96c1f128e4")
        validate_endpoint(mecky_runtime.get("endpointSlice"), "public-mecky", mecky_pod, "public-Mecky EndpointSlice", 18084)
        return snapshot

    require(REVISION.fullmatch(revision) is not None, "relay reset protected revision invalid")
    require(
        artifact_pin_sha256 == RELAY_FIXTURE_RESET_ARTIFACT_RECEIPT_SHA256,
        "relay reset artifact pin argument drift",
    )
    require(
        set(protected_hashes) == set(RELAY_FIXTURE_RESET_PROTECTED_PATHS)
        and all(isinstance(value, str) and SHA256.fullmatch(value) is not None for value in protected_hashes.values()),
        "relay reset expected protected closure invalid",
    )
    evidence = read_bound_json(receipt, "relay fixture reset receipt")
    state = read_bound_json(journal, "relay fixture reset journal")
    require_value_free_relay_reset_evidence(evidence)
    require_value_free_relay_reset_evidence(state)
    receipt_checksum = evidence.pop("canonicalSha256", None)
    exact_sha(receipt_checksum, "receipt canonical")
    require(receipt_checksum == bytes_sha256(canonical(evidence).encode("utf-8")), "relay reset receipt checksum drift")
    require(
        set(evidence) == {
            "schemaVersion", "status", "operationId", "protectedRevision", "protectedGitBlobSha256",
            "artifact", "mode", "namespace", "sequence", "before", "gate", "meckyLifecycle",
            "resets", "after", "restoration", "uncertainOutcome", "failure", "authority", "effects",
            "completedAt",
        },
        "relay reset receipt field set drift",
    )
    require(
        evidence.get("schemaVersion") == "roebel_staging_relay_fixture_reset_receipt_v2"
        and evidence.get("status") == "completed"
        and evidence.get("mode") == "live-one-shot"
        and evidence.get("namespace") == namespace
        and evidence.get("protectedRevision") == revision
        and evidence.get("protectedGitBlobSha256") == protected_hashes
        and evidence.get("sequence") == sequence
        and evidence.get("uncertainOutcome") is None
        and evidence.get("failure") is None
        and isinstance(evidence.get("completedAt"), str)
        and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", evidence["completedAt"]) is not None,
        "relay reset completed receipt identity/status drift",
    )
    exact_uuid(evidence.get("operationId"), "operation")
    artifact = exact_dict(evidence.get("artifact"), {"receiptSha256", "sourceRevision", "component", "repository", "manifestDigest", "image", "civicAuthority", "deploymentEffect"}, "artifact")
    require(
        artifact == {
            "receiptSha256": artifact_pin_sha256,
            "sourceRevision": RELAY_FIXTURE_RESET_SOURCE_REVISION,
            "component": "roebel-staging-relay",
            "repository": RELAY_FIXTURE_RESET_TARGET_IMAGE.rsplit("@", 1)[0],
            "manifestDigest": relay_digest,
            "image": RELAY_FIXTURE_RESET_TARGET_IMAGE,
            "civicAuthority": "none",
            "deploymentEffect": False,
        },
        "relay reset artifact binding drift",
    )
    require(
        evidence.get("authority") == {"civicAuthority": "none", "municipalDecision": False, "voteMutation": False, "treasuryMutation": False},
        "relay reset civic-authority boundary drift",
    )
    effects = exact_dict(
        evidence.get("effects"),
        {"clusterMutationAttempted", "ingressPatchRequests", "kustomizationPatchRequests", "deploymentPatchRequests", "podDeleteRequests", "readOnlyExecRequests", "secretValuesRead", "eventContentsEmitted", "publicKeysEmitted", "civicAuthorityEffects", "admissionStoreContentRead", "dataRollbackPossible", "automaticMutationRetry"},
        "effects",
    )
    require(
        effects.get("clusterMutationAttempted") is True
        and effects.get("ingressPatchRequests") == 2
        and effects.get("kustomizationPatchRequests") == 2
        and effects.get("deploymentPatchRequests") == 2
        and effects.get("podDeleteRequests") == 2
        and isinstance(effects.get("readOnlyExecRequests"), int)
        and not isinstance(effects["readOnlyExecRequests"], bool)
        and effects["readOnlyExecRequests"] >= 13
        and all(effects.get(key) is False for key in ("secretValuesRead", "eventContentsEmitted", "publicKeysEmitted", "civicAuthorityEffects", "admissionStoreContentRead", "dataRollbackPossible", "automaticMutationRetry")),
        "relay reset mutation/effect boundary drift",
    )
    before = validate_snapshot(evidence.get("before"), after=False)
    after = validate_snapshot(evidence.get("after"), after=True)
    require(after.get("exact") is True, "relay reset final preservation flag absent")

    workbench = exact_dict(before.get("workbench"), {"config", "feed"}, "workbench preflight")
    config = exact_dict(workbench.get("config"), {"schemaVersion", "authorityBinding", "mode", "personaCount", "meckyPubkeyHashVerified", "canonicalSha256"}, "workbench config")
    require(config.get("schemaVersion") == "roebel_e2e_workbench_config_v1" and config.get("authorityBinding") == "none" and config.get("meckyPubkeyHashVerified") is True and isinstance(config.get("personaCount"), int) and config["personaCount"] >= 0, "relay reset workbench config proof drift")
    exact_sha(config.get("canonicalSha256"), "workbench config")
    before_feed = exact_dict(workbench.get("feed"), {"postCount", "allSynthetic", "canonicalSha256"}, "workbench feed")
    require(isinstance(before_feed.get("postCount"), int) and before_feed["postCount"] > 0 and before_feed.get("allSynthetic") is True, "relay reset preflight synthetic feed proof drift")
    exact_sha(before_feed.get("canonicalSha256"), "workbench feed")
    participant_before = exact_dict(before.get("participantAdmissionBoundary"), {"status", "runtimeTargets", "fluxReconcilers", "secretValuesRead", "realAdmissionObserved", "writeIngressQuiescent", "admissionStoreZeroProven", "proofScope", "admissionStoreContentRead"}, "participant admission boundary")
    require(
        participant_before.get("status") == "no-active-participant-gateway"
        and participant_before.get("secretValuesRead") is False
        and participant_before.get("realAdmissionObserved") is False
        and participant_before.get("writeIngressQuiescent") is False
        and participant_before.get("admissionStoreZeroProven") is True
        and participant_before.get("admissionStoreContentRead") is False
        and isinstance(participant_before.get("runtimeTargets"), list)
        and isinstance(participant_before.get("fluxReconcilers"), list)
        and isinstance(participant_before.get("proofScope"), str),
        "relay reset participant/admission precondition drift",
    )
    participant_after = exact_dict(after.get("participantGateway"), {"status", "runtimeTargets", "fluxReconcilers", "secretValuesRead"}, "final participant boundary")
    require(participant_after == {key: participant_before[key] for key in participant_after}, "relay reset participant inactive boundary changed")
    final_feed = exact_dict(after.get("feed"), {"postCount", "allSynthetic", "canonicalSha256"}, "final feed")
    require(final_feed.get("postCount") == 0 and final_feed.get("allSynthetic") is True, "relay reset final feed is not empty")
    exact_sha(final_feed.get("canonicalSha256"), "final feed")
    require(after.get("feedObservations") == [final_feed, final_feed], "relay reset final empty-feed observations drift")

    gate = exact_dict(evidence.get("gate"), {"applied", "quietObservations", "restored"}, "gate")
    quiet = gate.get("quietObservations")
    require(gate.get("applied") is True and gate.get("restored") is True and isinstance(quiet, list) and len(quiet) == 3 and quiet[0] == quiet[1] == quiet[2], "relay reset write gate/quiescence proof drift")
    for observation in quiet:
        observation = exact_dict(observation, {"feedSha256", "ingressObjectSha256", "relayInventorySha256", "admissionStoreZero"}, "quiet observation")
        require(observation.get("feedSha256") == before_feed["canonicalSha256"] and observation.get("admissionStoreZero") is True, "relay reset quiet observation drift")
        exact_sha(observation.get("ingressObjectSha256"), "gated Ingress object")
        exact_sha(observation.get("relayInventorySha256"), "quiet relay inventory")
    lifecycle = exact_dict(evidence.get("meckyLifecycle"), {"fluxSuspended", "scaledToZero", "scaledToOne", "profile", "fluxRestored"}, "Mecky lifecycle")
    require(lifecycle == {"fluxSuspended": True, "scaledToZero": True, "scaledToOne": True, "profile": expected_profile, "fluxRestored": True}, "relay reset public-Mecky lifecycle drift")
    restoration = exact_dict(evidence.get("restoration"), {"required", "scaleUp", "flux", "ingress", "complete"}, "restoration")
    for key in ("scaleUp", "flux", "ingress"):
        exact_dict(restoration.get(key), {"attempted", "proven"}, f"restoration {key}")
    require(
        restoration == {
            "required": True,
            "scaleUp": {"attempted": False, "proven": True},
            "flux": {"attempted": True, "proven": True},
            "ingress": {"attempted": True, "proven": True},
            "complete": True,
        },
        "relay reset restoration proof drift",
    )

    require(before["networkPolicies"] == after["networkPolicies"], "relay reset NetworkPolicy preservation drift")
    for component in components:
        before_resource = before["resources"][component]
        after_resource = after["resources"][component]
        require(
            before_resource["deployment"]["uid"] == after_resource["deployment"]["uid"]
            and before_resource["deployment"]["generation"] == after_resource["deployment"]["generation"]
            and before_resource["deployment"]["specSha256"] == after_resource["deployment"]["specSha256"]
            and before_resource["service"]["uid"] == after_resource["service"]["uid"]
            and before_resource["service"]["object"] == after_resource["service"]["object"]
            and before_resource["service"]["objectSha256"] == after_resource["service"]["objectSha256"],
            f"relay reset {component} workload/Service preservation drift",
        )
    before_mecky = before["publicMecky"]
    after_mecky = after["publicMecky"]
    require(
        before_mecky["deployment"]["uid"] == after_mecky["deployment"]["uid"]
        and before_mecky["deployment"]["specSha256"] == after_mecky["deployment"]["specSha256"]
        and before_mecky["deployment"]["replicas"] == after_mecky["deployment"]["replicas"] == 1
        and after_mecky["deployment"]["generation"] >= before_mecky["deployment"]["generation"]
        and before_mecky["service"] == after_mecky["service"]
        and before_mecky["kustomization"]["uid"] == after_mecky["kustomization"]["uid"]
        and before_mecky["kustomization"]["specSha256"] == after_mecky["kustomization"]["specSha256"]
        and before_mecky["kustomization"]["suspendExplicit"] == after_mecky["kustomization"]["suspendExplicit"]
        and after_mecky["kustomization"]["generation"] >= before_mecky["kustomization"]["generation"]
        and before_mecky["kustomization"]["suspended"] is False
        and after_mecky["kustomization"]["suspended"] is False,
        "relay reset public-Mecky Deployment/Service/Flux preservation drift",
    )
    require(
        before["ingress"]["uid"] == after["ingress"]["uid"]
        and before["ingress"]["generation"] == after["ingress"]["generation"]
        and before["ingress"]["policy"] == after["ingress"]["policy"]
        and before["ingress"]["object"] == after["ingress"]["object"]
        and before["ingress"]["objectSha256"] == after["ingress"]["objectSha256"]
        and before["ingress"]["specSha256"] == after["ingress"]["specSha256"],
        "relay reset Ingress restoration drift",
    )
    require(before["publicMeckyRuntime"]["pod"]["uid"] != after["publicMeckyRuntime"]["pod"]["uid"], "relay reset public-Mecky Pod did not restart")

    resets = evidence.get("resets")
    require(isinstance(resets, list) and len(resets) == 2, "relay reset must contain exactly two Pod resets")
    for index, component in enumerate(components):
        reset = exact_dict(resets[index], {"component", "oldPodUid", "newPodUid", "endpointBindingSha256", "eventStoreEmpty", "admissionStoreReset", "requestSha256"}, f"{component} reset")
        before_pod = before["runtime"][component]["pod"]
        after_pod = after["runtime"][component]["pod"]
        expected_delete = {
            "method": "DELETE",
            "path": f"/api/v1/namespaces/{namespace}/pods/{before_pod['name']}",
            "body": {
                "apiVersion": "v1",
                "kind": "DeleteOptions",
                "preconditions": {"uid": before_pod["uid"], "resourceVersion": before_pod["resourceVersion"]},
            },
        }
        require(
            reset.get("component") == component
            and reset.get("oldPodUid") == before_pod["uid"]
            and reset.get("newPodUid") == after_pod["uid"]
            and reset["oldPodUid"] != reset["newPodUid"]
            and reset.get("endpointBindingSha256") == bytes_sha256(canonical(after["runtime"][component]["endpointSlice"]).encode("utf-8"))
            and reset.get("eventStoreEmpty") is True
            and reset.get("admissionStoreReset") is (component == "citizen-relay")
            and reset.get("requestSha256") == bytes_sha256(canonical(expected_delete).encode("utf-8")),
            f"relay reset {component} delete/replacement binding drift",
        )
    require(after["runtime"]["agent-relay"]["inventory"]["profile"] == expected_profile, "relay reset final Mecky profile missing")

    journal_checksum = state.pop("journalSha256", None)
    exact_sha(journal_checksum, "journal canonical")
    require(journal_checksum == bytes_sha256(canonical(state).encode("utf-8")), "relay reset journal checksum drift")
    require(
        set(state) == {"schemaVersion", "status", "operationId", "protectedRevision", "protectedGitBlobSha256", "artifact", "namespace", "sequence", "before", "gate", "meckyLifecycle", "resets", "after", "restoration", "events"},
        "relay reset journal field set drift",
    )
    require(
        state.get("schemaVersion") == "roebel_staging_relay_fixture_reset_journal_v2"
        and state.get("status") == "completed"
        and state.get("operationId") == evidence["operationId"]
        and state.get("protectedRevision") == revision
        and state.get("protectedGitBlobSha256") == protected_hashes
        and state.get("artifact") == artifact
        and state.get("namespace") == namespace
        and state.get("sequence") == sequence
        and state.get("before") == evidence["before"]
        and state.get("gate") == gate
        and state.get("meckyLifecycle") == lifecycle
        and state.get("resets") == resets
        and state.get("after") == evidence["after"]
        and state.get("restoration") == restoration,
        "relay reset receipt/journal binding drift",
    )
    events = state.get("events")
    require(isinstance(events, list) and len(events) == 25, "relay reset completed journal grammar length drift")
    previous: str | None = None
    for index, event_value in enumerate(events, start=1):
        require(isinstance(event_value, dict), f"relay reset journal event {index} invalid")
        event = dict(event_value)
        entry_sha = event.pop("entrySha256", None)
        exact_sha(entry_sha, f"journal event {index}")
        require(
            event.get("sequence") == index
            and event.get("previousEntrySha256") == previous
            and entry_sha == bytes_sha256(canonical(event).encode("utf-8")),
            f"relay reset journal event {index} hash-chain drift",
        )
        previous = entry_sha

    base_fields = {"sequence", "operation", "stage", "previousEntrySha256", "entrySha256"}
    def journal_event(index: int, operation: str, stages: set[str], detail_fields: set[str]) -> dict[str, Any]:
        event = events[index - 1]
        require(
            set(event) == base_fields | detail_fields
            and event.get("operation") == operation
            and event.get("stage") in stages,
            f"relay reset journal event {index} grammar drift",
        )
        return event

    preflight = journal_event(1, "preflight", {"after"}, {"snapshotSha256", "feedSha256", "admissionStoreZero", "participantInactive"})
    exact_sha(preflight.get("snapshotSha256"), "preflight snapshot")
    require(preflight["feedSha256"] == before_feed["canonicalSha256"] and preflight["admissionStoreZero"] is True and preflight["participantInactive"] is True, "relay reset preflight journal binding drift")

    mutation_specs = (
        (2, "gate-workbench", ingress_target, "GET-HEAD-POST-to-GET-HEAD", "desiredStateObserved"),
        (4, "suspend-public-mecky", kustomization_target, "false-to-true", "desiredStateObserved"),
        (6, "scale-public-mecky-zero", deployment_target, "1-to-0", "requestAccepted"),
        (15, "scale-public-mecky-one", deployment_target, "0-to-1", "requestAccepted"),
        (18, "restore-public-mecky-flux", kustomization_target, "true-to-original-false", "desiredStateObserved"),
        (20, "restore-workbench-gate", ingress_target, "GET-HEAD-to-GET-HEAD-POST", "desiredStateObserved"),
    )
    for index, operation, target, transition, after_field in mutation_specs:
        intent = journal_event(index, operation, {"intent"}, {"target", "requestSha256", "transition"})
        require(intent.get("target") == target and intent.get("transition") == transition, f"relay reset {operation} intent drift")
        exact_sha(intent.get("requestSha256"), f"{operation} request")
        resolution = events[index]
        if resolution.get("stage") == "after":
            resolution = journal_event(index + 1, operation, {"after"}, {"requestSha256", after_field})
            require(resolution.get(after_field) is True, f"relay reset {operation} success proof drift")
        else:
            resolution = journal_event(index + 1, operation, {"classified"}, {"requestSha256", "classification", "mutationRetried"})
            require(resolution.get("classification") == "desired-observed" and resolution.get("mutationRetried") is False, f"relay reset {operation} classification drift")
        require(resolution.get("requestSha256") == intent["requestSha256"], f"relay reset {operation} request/result binding drift")

    zero_event = journal_event(8, "wait-public-mecky-zero", {"after"}, {"deploymentSha256", "selectedPodCount"})
    require(exact_sha(zero_event.get("deploymentSha256"), "scaled-zero Deployment") and zero_event.get("selectedPodCount") == 0, "relay reset zero-replica journal proof drift")
    for reset_index, (intent_index, wait_index, component) in enumerate(((9, 11, "citizen-relay"), (12, 14, "agent-relay"))):
        reset = resets[reset_index]
        before_pod = before["runtime"][component]["pod"]
        target = {"apiVersion": "v1", "kind": "Pod", "namespace": namespace, "name": before_pod["name"]}
        intent = journal_event(intent_index, f"delete-{component}-pod", {"intent"}, {"target", "uid", "resourceVersion", "requestSha256"})
        require(intent.get("target") == target and intent.get("uid") == before_pod["uid"] and intent.get("resourceVersion") == before_pod["resourceVersion"] and intent.get("requestSha256") == reset["requestSha256"], f"relay reset {component} DELETE intent drift")
        resolution = events[intent_index]
        if resolution.get("stage") == "after":
            resolution = journal_event(intent_index + 1, f"delete-{component}-pod", {"after"}, {"requestSha256", "requestAccepted"})
            require(resolution.get("requestAccepted") is True, f"relay reset {component} DELETE success drift")
        else:
            resolution = journal_event(intent_index + 1, f"delete-{component}-pod", {"classified"}, {"requestSha256", "classification", "mutationRetried"})
            require(resolution.get("classification") == "old-pod-absent" and resolution.get("mutationRetried") is False, f"relay reset {component} DELETE classification drift")
        require(resolution.get("requestSha256") == reset["requestSha256"], f"relay reset {component} DELETE result drift")
        wait = journal_event(wait_index, f"wait-{component}-replacement", {"after"}, set(reset))
        require({key: wait[key] for key in reset} == reset, f"relay reset {component} replacement journal drift")
    profile_event = journal_event(17, "wait-public-mecky-profile", {"after"}, {"newPodUid", "profileProofSha256", "kind0Count", "kind1Count"})
    require(
        profile_event.get("newPodUid") == after["publicMeckyRuntime"]["pod"]["uid"]
        and profile_event.get("profileProofSha256") == bytes_sha256(canonical(expected_profile).encode("utf-8"))
        and profile_event.get("kind0Count") == 1
        and profile_event.get("kind1Count") == 0,
        "relay reset Mecky profile journal proof drift",
    )
    postconditions = journal_event(22, "postconditions", {"after"}, {"snapshotSha256", "preservationExact", "emptyFeedObservations"})
    exact_sha(postconditions.get("snapshotSha256"), "postcondition snapshot")
    require(postconditions.get("preservationExact") is True and postconditions.get("emptyFeedObservations") == 2, "relay reset final preservation journal drift")
    transaction = journal_event(23, "transaction", {"final"}, {"status"})
    require(transaction.get("status") == "completed", "relay reset terminal journal status drift")
    receipt_intent = journal_event(24, "receipt", {"intent"}, {"requestSha256", "status"})
    receipt_after = journal_event(25, "receipt", {"after"}, {"requestSha256", "status"})
    require(
        receipt_intent.get("requestSha256") == receipt_checksum
        and receipt_after.get("requestSha256") == receipt_checksum
        and receipt_intent.get("status") == receipt_after.get("status") == "completed",
        "relay reset receipt commit/journal binding drift",
    )
    return {
        "receiptSha256": receipt.sha256,
        "receiptCanonicalSha256": receipt_checksum,
        "journalSha256": journal.sha256,
        "journalCanonicalSha256": journal_checksum,
        "artifactPinSha256": artifact_pin_sha256,
        "targetImage": RELAY_FIXTURE_RESET_TARGET_IMAGE,
        "mutationSequence": sequence,
        "deleteCount": 2,
        "gateRestored": True,
        "fluxReady": True,
        "admissionsZero": True,
        "meckyProfileProven": True,
        "preservationExact": True,
        "cleanupComplete": True,
    }


def verify_workbench_handover_evidence(
    receipt: BoundBlob,
    journal: BoundBlob,
    revision: str,
    protected_hashes: dict[str, str],
) -> dict[str, Any]:
    """Validate the value-free proof the frozen runner leaves behind."""
    evidence = read_bound_json(receipt, "workbench handover receipt")
    state = read_bound_json(journal, "workbench handover journal")
    require(evidence.get("schemaVersion") == "roebel_staging_workbench_baseline_handover_receipt_v1", "workbench handover receipt schema drift")
    require(evidence.get("status") == "completed", "workbench handover did not complete")
    require(evidence.get("mode") == "live", "workbench handover receipt mode drift")
    require(evidence.get("protectedRevision") == revision, "workbench handover receipt revision drift")
    protected = evidence.get("protectedFileSha256")
    require(isinstance(protected, dict), "workbench handover protected file proof absent")
    for path in (WORKBENCH_RUNNER, WORKBENCH_IMPLEMENTATION, "scripts/verify-reviewed-render.py", "policy/repository-contract.json"):
        require(protected.get(path) == protected_hashes.get(path), f"workbench handover protected blob drift: {path}")
    baseline = evidence.get("baseline")
    require(isinstance(baseline, dict) and baseline.get("uid") == "298b0f92-0d6b-4563-b141-f93aa8c8fd8f", "workbench NetworkPolicy UID proof drift")
    effects = evidence.get("effects")
    require(isinstance(effects, dict), "workbench handover effects absent")
    require(
        effects.get("networkPolicySpecChanged") is False
        and effects.get("existingDeploymentChanged") is False
        and effects.get("existingServiceChanged") is False
        and effects.get("secretAccess") is False
        and effects.get("civicAuthorityEffects") is False
        and effects.get("fluxReady") is True
        and effects.get("networkPolicyReconciled") is True,
        "workbench handover effect boundary drift",
    )
    objects = evidence.get("objects")
    expected_ids = {"serviceAccount", "role", "roleBinding", "kustomization"}
    require(isinstance(objects, list) and {entry.get("objectId") for entry in objects if isinstance(entry, dict)} == expected_ids, "workbench Flux UID inventory drift")
    require(all(isinstance(entry, dict) and isinstance(entry.get("uid"), str) for entry in objects), "workbench Flux UID proof absent")
    flux = evidence.get("flux")
    require(isinstance(flux, dict) and isinstance(flux.get("ready"), dict) and isinstance(flux.get("networkPolicyReconciled"), dict), "workbench Flux Ready proof absent")
    require(state.get("schemaVersion") == "roebel_staging_workbench_baseline_journal_v1", "workbench journal schema drift")
    require(state.get("status") == "completed" and state.get("protectedRevision") == revision, "workbench journal is not terminal for this revision")
    return {
        "receiptSha256": receipt.sha256,
        "journalSha256": journal.sha256,
        "networkPolicyUid": baseline["uid"],
        "fluxObjectUids": {entry["objectId"]: entry["uid"] for entry in objects},
        "ready": True,
    }


def verify_workbench_image_promotion_evidence(
    receipt: BoundBlob,
    journal: BoundBlob,
    revision: str,
    protected_hashes: dict[str, str],
    artifact_pin_sha256: str,
) -> dict[str, Any]:
    """Validate the protected promoter's value-free terminal evidence."""
    evidence = read_bound_json(receipt, "workbench image promotion receipt")
    state = read_bound_json(journal, "workbench image promotion journal")
    receipt_checksum = evidence.pop("canonicalSha256", None)
    require(
        isinstance(receipt_checksum, str)
        and receipt_checksum == bytes_sha256(canonical(evidence).encode("utf-8")),
        "workbench image promotion receipt checksum drift",
    )
    require(
        set(evidence) == {
            "schemaVersion", "status", "mode", "operation", "protectedRevision",
            "protectedGitBlobSha256", "probeBinding", "artifact", "target",
            "deployment", "preservation", "rollout", "backendBinding", "probes",
            "patch", "rollback", "effects", "completedAt",
        },
        "workbench image promotion receipt field set drift",
    )
    require(
        evidence.get("schemaVersion") == "roebel_staging_workbench_image_promotion_receipt_v1"
        and evidence.get("status") == "completed"
        and evidence.get("mode") == "live",
        "workbench image promotion receipt status drift",
    )
    operation = evidence.get("operation")
    require(
        isinstance(operation, dict)
        and set(operation) == {"operationId"}
        and isinstance(operation.get("operationId"), str)
        and UUID.fullmatch(operation["operationId"]) is not None
        and evidence.get("protectedRevision") == revision
        and evidence.get("protectedGitBlobSha256") == protected_hashes,
        "workbench image promotion protected operation binding drift",
    )
    require(
        evidence.get("probeBinding") == workbench_public_probe_binding(),
        "workbench image promotion fixed public HTTPS probe binding drift",
    )
    artifact = evidence.get("artifact")
    require(
        isinstance(artifact, dict)
        and artifact.get("receiptSha256") == artifact_pin_sha256
        and artifact.get("sourceRevision") == WORKBENCH_PROMOTION_SOURCE_REVISION
        and artifact.get("component") == "roebel-e2e-workbench"
        and artifact.get("manifestDigest") == WORKBENCH_PROMOTION_TARGET_IMAGE.rsplit("@", 1)[1]
        and artifact.get("image") == WORKBENCH_PROMOTION_TARGET_IMAGE,
        "workbench image promotion artifact binding drift",
    )
    require(
        evidence.get("target") == {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "namespace": "stadtstack-roebel-staging-lab",
            "name": "e2e-workbench",
        },
        "workbench image promotion target drift",
    )
    effects = evidence.get("effects")
    require(
        isinstance(effects, dict)
        and set(effects) == {
            "clusterMutation", "deploymentImageChanged", "rollbackApplied",
            "serviceChanged", "networkPolicyChanged", "secretValuesRead",
            "civicAuthorityEffects",
        }
        and effects == {
            "clusterMutation": True,
            "deploymentImageChanged": True,
            "rollbackApplied": False,
            "serviceChanged": False,
            "networkPolicyChanged": False,
            "secretValuesRead": False,
            "civicAuthorityEffects": False,
        },
        "workbench image promotion effect boundary drift",
    )
    preservation = evidence.get("preservation")
    require(
        isinstance(preservation, dict)
        and preservation.get("unchanged") is True
        and isinstance(preservation.get("service"), dict)
        and isinstance(preservation.get("networkPolicy"), dict),
        "workbench image promotion preservation proof drift",
    )
    deployment = evidence.get("deployment")
    require(
        isinstance(deployment, dict)
        and deployment.get("environmentTransition") == {
            "added": [
                {"name": "WORKBENCH_MODE", "value": "public-signed-only"},
                {
                    "name": "LEGACY_SYNTHETIC_PUBKEYS_JSON",
                    "value": "[\"21abe1bf2bf9a906d356488d107db36d505b55d54c20ab46792fcd31c4e1b88a\",\"7c6ed2e0b6ae1ea67523d055b1194e55036522c397e589c2bb20f0c68b558974\"]",
                },
            ],
            "removedNames": [
                "CASE_STEWARD_TOKEN",
                "STADTSTACK_CONTROL_BASE_URL",
                "STADTSTACK_PUBLIC_BASE_URL",
                "SYNTHETIC_CITIZENS_JSON",
            ],
        },
        "workbench image promotion public-mode transition proof drift",
    )
    rollout = evidence.get("rollout")
    backend = evidence.get("backendBinding")
    probes = evidence.get("probes")
    rollout_pods = rollout.get("podImageProof", {}).get("pods", []) if isinstance(rollout, dict) else []
    backend_targets = backend.get("podTargets", []) if isinstance(backend, dict) else []
    expected_backend_targets: list[dict[str, Any]] = []
    expected_address_types: set[str] = set()
    if isinstance(rollout_pods, list):
        for item in rollout_pods:
            if not isinstance(item, dict) or not isinstance(item.get("podIPs"), list):
                continue
            addresses = item["podIPs"]
            try:
                parsed = [ipaddress.ip_address(address) for address in addresses]
            except (TypeError, ValueError):
                continue
            if not addresses or len(addresses) != len(set(addresses)) or any(str(value) != address for value, address in zip(parsed, addresses)):
                continue
            expected_address_types.update("IPv4" if value.version == 4 else "IPv6" for value in parsed)
            expected_backend_targets.append({"uid": item.get("uid"), "name": item.get("name"), "addresses": sorted(addresses)})
    require(
        isinstance(rollout, dict)
        and isinstance(rollout.get("podImageProof"), dict)
        and rollout["podImageProof"].get("expectedImage") == WORKBENCH_PROMOTION_TARGET_IMAGE
        and isinstance(backend, dict)
        and set(backend) == {"selector", "servicePort", "targetPort", "containerPort", "endpointSliceUids", "addressTypes", "podTargets"}
        and isinstance(backend.get("selector"), dict)
        and bool(backend["selector"])
        and backend.get("servicePort") == 18083
        and backend.get("targetPort") == 18083
        and backend.get("containerPort") == {"name": "http", "port": 18083, "protocol": "TCP"}
        and isinstance(backend.get("endpointSliceUids"), list)
        and backend["endpointSliceUids"]
        and len(backend["endpointSliceUids"]) == len(set(backend["endpointSliceUids"]))
        and all(isinstance(value, str) and UUID.fullmatch(value) is not None for value in backend["endpointSliceUids"])
        and backend.get("addressTypes") == sorted(expected_address_types)
        and sorted(backend_targets, key=lambda item: str(item.get("uid")) if isinstance(item, dict) else "")
        == sorted(expected_backend_targets, key=lambda item: str(item.get("uid")))
        and len(expected_backend_targets) == len(rollout_pods)
        and isinstance(probes, dict)
        and probes.get("methods") == {"config": "GET", "feed": "GET"},
        "workbench image promotion postcondition proof drift",
    )
    require(
        set(state) == {
            "schemaVersion", "status", "operationId", "protectedRevision",
            "protectedGitBlobSha256", "artifact", "target", "events", "before", "journalSha256",
        }
        and state.get("schemaVersion") == "roebel_staging_workbench_image_promotion_journal_v1"
        and state.get("status") == "completed"
        and state.get("operationId") == operation["operationId"]
        and state.get("protectedRevision") == revision
        and state.get("protectedGitBlobSha256") == protected_hashes
        and state.get("artifact") == artifact
        and state.get("target") == evidence.get("target"),
        "workbench image promotion journal is not terminal",
    )
    journal_checksum = state.pop("journalSha256", None)
    require(
        isinstance(journal_checksum, str)
        and journal_checksum == bytes_sha256(canonical(state).encode("utf-8")),
        "workbench image promotion journal checksum drift",
    )
    events = state.get("events")
    require(isinstance(events, list) and events, "workbench image promotion journal events absent")
    previous: str | None = None
    grammar: list[tuple[str, str]] = []
    patch_request_sha256: str | None = None
    for sequence, event in enumerate(events, start=1):
        require(isinstance(event, dict), "workbench image promotion journal event invalid")
        entry = dict(event)
        entry_hash = entry.pop("entrySha256", None)
        require(
            event.get("sequence") == sequence
            and event.get("previousEntrySha256") == previous
            and isinstance(entry_hash, str)
            and entry_hash == bytes_sha256(canonical(entry).encode("utf-8")),
            "workbench image promotion journal event hash drift",
        )
        previous = entry_hash
        operation_name, stage = event.get("operation"), event.get("stage")
        grammar.append((operation_name, stage))
        base = {"sequence", "operation", "stage", "previousEntrySha256", "entrySha256"}
        details = {key: value for key, value in event.items() if key not in base}
        if (operation_name, stage) == ("preflight", "after"):
            require(set(details) == {"deploymentResourceVersion"} and isinstance(details["deploymentResourceVersion"], str), "workbench promotion preflight event grammar drift")
        elif (operation_name, stage) == ("patch-deployment-image", "intent"):
            require(set(details) == {"requestSha256", "target"} and details["target"] == evidence["target"] and SHA256.fullmatch(details["requestSha256"]) is not None, "workbench promotion patch intent grammar drift")
            patch_request_sha256 = details["requestSha256"]
        elif (operation_name, stage) == ("patch-deployment-image", "after"):
            require(details == {"response": "accepted"}, "workbench promotion patch response grammar drift")
        elif (operation_name, stage) == ("patch-deployment-image", "classified"):
            require(details == {"classification": "applied"}, "workbench promotion patch classification grammar drift")
        elif (operation_name, stage) == ("resume", "before"):
            require(details == {"operationId": operation["operationId"]}, "workbench promotion resume-before grammar drift")
        elif (operation_name, stage) == ("resume", "classified"):
            require(details == {"operationId": operation["operationId"], "classification": "target-image"}, "workbench promotion resume classification grammar drift")
        elif (operation_name, stage) == ("postconditions", "after"):
            require(details == {"status": "verified"}, "workbench promotion postcondition grammar drift")
        elif (operation_name, stage) in {("transaction", "finalizing"), ("transaction", "completed")}:
            require(details == {"receiptStatus": "completed"}, "workbench promotion terminal grammar drift")
        else:
            raise LiveTransportError("workbench promotion unknown journal operation")
    middle = grammar[2:-3]
    if middle and middle[0] in {("patch-deployment-image", "after"), ("patch-deployment-image", "classified")}:
        middle = middle[1:]
    # A process can be terminated after durably recording resume/before but
    # before its one classification GET returns.  Each later invocation may
    # therefore contribute another before marker; the final invocation must
    # close the chain with the exact target-image classification accepted by
    # this completed receipt.
    recovery_grammar_valid = True
    cursor = 0
    while cursor < len(middle):
        # A prior invocation may have durably verified postconditions and
        # then been killed before finalization.  It must be followed by a new
        # exact resume epoch, not treated as the proof for this receipt.
        if middle[cursor] == ("postconditions", "after"):
            cursor += 1
            if cursor == len(middle):
                recovery_grammar_valid = False
                break
        before_count = 0
        while cursor < len(middle) and middle[cursor] == ("resume", "before"):
            before_count += 1
            cursor += 1
        if before_count == 0 or cursor == len(middle) or middle[cursor] != ("resume", "classified"):
            recovery_grammar_valid = False
            break
        cursor += 1
    require(
        grammar[:2] == [("preflight", "after"), ("patch-deployment-image", "intent")]
        and grammar[-3:] == [("postconditions", "after"), ("transaction", "finalizing"), ("transaction", "completed")]
        and grammar.count(("patch-deployment-image", "intent")) == 1
        and recovery_grammar_valid,
        "workbench promotion journal grammar drift",
    )
    before = state.get("before")
    deployment = evidence.get("deployment")
    require(
        isinstance(before, dict)
        and set(before) == {"deploymentUid", "resourceVersion", "specSha256", "normalizedSpecSha256", "environment", "service", "serviceRouting", "networkPolicy"}
        and before.get("deploymentUid") == deployment.get("uid")
        and before.get("resourceVersion") == deployment.get("beforeResourceVersion")
        and before.get("specSha256") == deployment.get("beforeSpecSha256")
        and before.get("normalizedSpecSha256") == deployment.get("beforeNormalizedSpecSha256")
        and isinstance(before.get("environment"), dict)
        and set(before["environment"]) == {"containerIndex", "entries"}
        and isinstance(before["environment"].get("containerIndex"), int)
        and not isinstance(before["environment"].get("containerIndex"), bool)
        and isinstance(before["environment"].get("entries"), list)
        and before.get("service") == preservation.get("service")
        and before.get("networkPolicy") == preservation.get("networkPolicy")
        and before.get("serviceRouting") == {key: backend.get(key) for key in ("selector", "servicePort", "targetPort", "containerPort")}
        and patch_request_sha256 == evidence.get("patch", {}).get("requestSha256"),
        "workbench promotion receipt/journal cross-binding drift",
    )
    return {
        "receiptSha256": receipt.sha256,
        "receiptCanonicalSha256": receipt_checksum,
        "journalSha256": journal.sha256,
        "artifactPinSha256": artifact_pin_sha256,
        "targetImage": WORKBENCH_PROMOTION_TARGET_IMAGE,
        "deploymentImageChanged": True,
        "preservationUnchanged": True,
    }


def verify_workbench_recovery_evidence(
    receipt: BoundBlob,
    journal: BoundBlob,
    revision: str,
    *,
    terminal_finalization_expected: bool = False,
) -> dict[str, Any]:
    """Validate the exact delete-only recovery proof before wrapper success."""
    evidence = read_bound_json(receipt, "workbench recovery receipt")
    state = read_bound_json(journal, "workbench recovery journal")
    receipt_checksum = evidence.pop("canonicalSha256", None)
    require(isinstance(receipt_checksum, str) and receipt_checksum == bytes_sha256(canonical(evidence).encode("utf-8")), "workbench recovery receipt checksum drift")
    require(evidence.get("schemaVersion") == "roebel_staging_workbench_baseline_recovery_receipt_v1", "workbench recovery receipt schema drift")
    require(evidence.get("status") == "completed" and evidence.get("protectedRevision") == revision, "workbench recovery did not complete at protected revision")
    journal_revision = state.get("protectedRevision")
    terminal_finalization = journal_revision != revision
    require(
        terminal_finalization is terminal_finalization_expected,
        "workbench recovery terminal-finalization mode drift",
    )
    require(
        state.get("schemaVersion") == "roebel_staging_workbench_baseline_recovery_journal_v1"
        and state.get("status") == "completed",
        "workbench recovery journal is not terminal",
    )
    if terminal_finalization:
        require(
            journal_revision == WORKBENCH_RECOVERY_TERMINAL_REVISION
            and journal.sha256 == WORKBENCH_RECOVERY_TERMINAL_JOURNAL_FILE_SHA256
            and evidence.get("terminalRecoveryRevision") == WORKBENCH_RECOVERY_TERMINAL_REVISION
            and evidence.get("finalizedAgainstRevision") == revision
            and evidence.get("finalizationParentRevision") == WORKBENCH_RECOVERY_FINALIZATION_PARENT_REVISION,
            "workbench recovery terminal-finalization provenance drift",
        )
    else:
        require(journal_revision == revision, "workbench recovery journal is not terminal")
    require(
        evidence.get("originRevision") == WORKBENCH_RECOVERY_ORIGIN_REVISION
        and evidence.get("operationId") == WORKBENCH_RECOVERY_OPERATION_ID
        and evidence.get("operationMarker") == WORKBENCH_RECOVERY_MARKER
        and evidence.get("evidence") == WORKBENCH_RECOVERY_EVIDENCE,
        "workbench recovery origin/evidence binding drift",
    )
    effects = evidence.get("effects")
    require(
        isinstance(effects, dict)
        and effects.get("deleteOnlyMutation") is (not terminal_finalization)
        and effects.get("create") is False
        and effects.get("patch") is False
        and effects.get("apply") is False
        and effects.get("list") is False
        and effects.get("secretAccess") is False
        and effects.get("civicAuthorityEffects") is False
        and effects.get("baselineChanged") is False
        and effects.get("sharedSourceChanged") is False
        and effects.get("cleanupComplete") is True,
        "workbench recovery effect boundary drift",
    )
    if terminal_finalization:
        require(
            effects.get("historicalDeleteOnlyRecovery") is True
            and effects.get("getOnlyFinalization") is True
            and effects.get("clusterMutationCount") == 0
            and effects.get("newDeletes") == 0,
            "workbench recovery terminal-finalization effect drift",
        )
    baseline = evidence.get("baseline")
    source = evidence.get("source")
    require(isinstance(baseline, dict) and baseline.get("uid") == "298b0f92-0d6b-4563-b141-f93aa8c8fd8f" and baseline.get("digest") == "sha256:21c582036f38a54649b771a6dec1ba599ca859029a1c32246ef8aee6a00359c5", "workbench recovery baseline proof drift")
    require(isinstance(source, dict) and source.get("uid") == "0de8a05d-550f-429c-93c5-9b8c76b0bf9b" and source.get("revision") == f"main@sha1:{revision}", "workbench recovery source proof drift")
    objects = evidence.get("objects")
    expected = {"kustomization", "roleBinding", "role", "serviceAccount"}
    require(isinstance(objects, dict) and set(objects) == expected and all(objects[name].get("status") == "absent" and objects[name].get("uid") == WORKBENCH_RECOVERY_OBJECT_UIDS[name] for name in expected), "workbench recovery cleanup inventory drift")
    final_absence = evidence.get("finalAbsence")
    require(
        isinstance(final_absence, dict) and set(final_absence) == expected
        and all(final_absence[name].get("uid") == WORKBENCH_RECOVERY_OBJECT_UIDS[name] and final_absence[name].get("absent") is True for name in expected),
        "workbench recovery final absence proof drift",
    )
    persisted_checksum = state.pop("journalSha256", None)
    require(
        isinstance(persisted_checksum, str)
        and persisted_checksum == bytes_sha256(canonical(state).encode("utf-8")),
        "workbench recovery journal checksum drift",
    )
    if terminal_finalization:
        require(
            persisted_checksum == WORKBENCH_RECOVERY_TERMINAL_JOURNAL_CANONICAL_SHA256,
            "workbench recovery terminal journal canonical checksum drift",
        )
        source_at_recovery = evidence.get("sourceAtRecovery")
        source_at_finalization = evidence.get("sourceAtFinalization")
        require(
            source_at_recovery == state.get("source")
            and source_at_finalization == source
            and isinstance(source_at_recovery, dict)
            and source_at_recovery.get("uid") == source.get("uid")
            and source_at_recovery.get("revision") == f"main@sha1:{WORKBENCH_RECOVERY_TERMINAL_REVISION}"
            and source_at_recovery.get("generation") == source.get("generation")
            and baseline == state.get("baseline"),
            "workbench recovery terminal-finalization predecessor drift",
        )
    events = state.get("events")
    require(isinstance(events, list) and events and isinstance(events[-1], dict), "workbench recovery journal event chain absent")
    previous = None
    for sequence, event in enumerate(events, start=1):
        entry = dict(event); entry_hash = entry.pop("entrySha256", None)
        require(
            event.get("sequence") == sequence
            and event.get("previousEntrySha256") == previous
            and entry_hash == bytes_sha256(canonical(entry).encode("utf-8")),
            "workbench recovery journal event hash drift",
        )
        previous = entry_hash
    first, terminal = events[0], events[-1]
    require(
        first.get("stage") == "before"
        and first.get("operation") == "preflight"
        and {key: value for key, value in first.items() if key not in {"sequence", "stage", "operation", "previousEntrySha256", "entrySha256"}}
        == {"baselineDigest": baseline["digest"], "sourceUid": source["uid"]},
        "workbench recovery preflight grammar drift",
    )
    require(
        terminal.get("stage") == "after"
        and terminal.get("operation") == "complete"
        and {key: value for key, value in terminal.items() if key not in {"sequence", "stage", "operation", "previousEntrySha256", "entrySha256"}}
        == {"baselineDigest": baseline["digest"], "sourceUid": source["uid"]},
        "workbench recovery terminal grammar drift",
    )
    expected_delete_order = ["kustomization", "roleBinding", "role", "serviceAccount"]
    logical_delete_order: list[str] = []
    delete_intents: set[str] = set()
    delete_outcomes: set[str] = set()
    seen_uncertain = False
    resume_epochs = 0
    uncertain_epoch_by_name: dict[str, int] = {}
    payload_fields = ("deleteOptions", "deletePayload", "deletePayloadSha256")
    for event in events[1:-1]:
        operation, stage = event.get("operation"), event.get("stage")
        if operation == "resume":
            require(
                stage == "before"
                and {key: value for key, value in event.items() if key not in {"sequence", "stage", "operation", "previousEntrySha256", "entrySha256"}} == {"revision": journal_revision}
                and seen_uncertain,
                "workbench recovery resume grammar drift",
            )
            resume_epochs += 1
            continue
        require(isinstance(operation, str) and operation.startswith("delete."), "workbench recovery unknown journal operation")
        name = operation.removeprefix("delete.")
        require(name in WORKBENCH_RECOVERY_OBJECT_UIDS, "workbench recovery delete target drift")
        has_payload = any(field in event for field in payload_fields)
        if stage in {"before", "uncertain"} or (stage == "after" and has_payload):
            options = event.get("deleteOptions")
            payload = event.get("deletePayload")
            resource_version = event.get("resourceVersion")
            require(
                event.get("target") == WORKBENCH_RECOVERY_TARGETS[name]
                and event.get("uid") == WORKBENCH_RECOVERY_OBJECT_UIDS[name]
                and event.get("verb") == "DELETE"
                and isinstance(resource_version, str) and resource_version.isdigit()
                and options == {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": WORKBENCH_RECOVERY_OBJECT_UIDS[name], "resourceVersion": resource_version}}
                and isinstance(payload, str)
                and event.get("deletePayloadSha256") == bytes_sha256(payload.encode("utf-8"))
                and payload == canonical(options),
                "workbench recovery delete precondition drift",
            )
            if name not in delete_intents:
                require(len(logical_delete_order) < len(expected_delete_order) and name == expected_delete_order[len(logical_delete_order)], "workbench recovery delete order drift")
                logical_delete_order.append(name); delete_intents.add(name)
            else:
                require(logical_delete_order and logical_delete_order[-1] == name, "workbench recovery delete retry order drift")
            if stage == "uncertain":
                require(isinstance(event.get("error"), str) and event["error"], "workbench recovery uncertain outcome drift")
                seen_uncertain = True
                uncertain_epoch_by_name[name] = resume_epochs
        if stage == "after":
            require(name in delete_intents, "workbench recovery after event without prior delete intent")
            result = event.get("result")
            if not has_payload:
                require(
                    name in uncertain_epoch_by_name
                    and resume_epochs > uncertain_epoch_by_name[name]
                    and event.get("uid") == WORKBENCH_RECOVERY_OBJECT_UIDS[name]
                    and result == "already-absent",
                    "workbench recovery resumed absence grammar drift",
                )
            else:
                require(result == {"absent": True, "uid": WORKBENCH_RECOVERY_OBJECT_UIDS[name]}, "workbench recovery delete outcome drift")
            delete_outcomes.add(name)
        elif stage not in {"before", "uncertain"}:
            raise LiveTransportError("workbench recovery delete event stage drift")
    require(logical_delete_order == expected_delete_order and delete_outcomes == set(expected_delete_order), "workbench recovery delete order drift")
    require(state.get("finalAbsence") == final_absence, "workbench recovery final absence journal drift")
    terminal_hash = events[-1].get("entrySha256")
    journal_binding = evidence.get("journal")
    expected_journal_binding = {
        "schemaVersion": "roebel_staging_workbench_baseline_recovery_journal_v1",
        "status": "completed",
        "eventCount": len(events),
        "terminalEntrySha256": terminal_hash,
        "terminalJournalSha256": persisted_checksum,
    }
    if terminal_finalization:
        expected_journal_binding.update({
            "protectedRevision": WORKBENCH_RECOVERY_TERMINAL_REVISION,
            "terminalJournalFileSha256": WORKBENCH_RECOVERY_TERMINAL_JOURNAL_FILE_SHA256,
        })
    require(
        journal_binding == expected_journal_binding,
        "workbench recovery receipt/journal binding drift",
    )
    result = {"receiptSha256": receipt.sha256, "journalSha256": journal.sha256, "cleanupComplete": True}
    if terminal_finalization:
        result.update({"clusterMutationCount": 0, "terminalRecoveryRevision": WORKBENCH_RECOVERY_TERMINAL_REVISION})
    return result

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    # Omission preserves the pre-existing participant transaction CLI.  The
    # explicit participant flag is useful only when automation wants a fully
    # self-documenting mode selection.
    mode.add_argument("--participant-gateway", action="store_true")
    mode.add_argument("--workbench-baseline-handover", action="store_true")
    mode.add_argument("--workbench-baseline-recovery", action="store_true")
    mode.add_argument("--workbench-baseline-recovery-finalize", action="store_true")
    mode.add_argument("--workbench-image-promotion", action="store_true")
    mode.add_argument("--relay-fixture-reset", action="store_true")
    parser.add_argument("--expected-protected-revision", required=True)
    parser.add_argument("--age-bin", required=True, type=Path)
    parser.add_argument("--age-identity", required=True, type=Path)
    parser.add_argument("--bootstrap-bundle", required=True, type=Path)
    parser.add_argument("--wireproxy-bin", required=True, type=Path)
    parser.add_argument("--talosctl-bin", required=True, type=Path)
    parser.add_argument("--kubectl-bin", required=True, type=Path)
    parser.add_argument("--receipt-directory", required=True, type=Path)
    parser.add_argument("--teardown-dormant-receipt", type=Path)
    parser.add_argument("--participant-secret-bundle", type=Path)
    parser.add_argument("--teardown-participant-secret-receipt", type=Path)
    parser.add_argument("--handover-dormant-receipt", type=Path)
    parser.add_argument(
        "--participant-secret-materialization-receipt",
        "--secret-materialization-receipt",
        dest="participant_secret_materialization_receipt",
        type=Path,
    )
    parser.add_argument("--workbench-handover-receipt", type=Path)
    parser.add_argument("--workbench-handover-journal", type=Path)
    parser.add_argument("--workbench-recovery-receipt", type=Path)
    parser.add_argument("--workbench-recovery-journal", type=Path)
    parser.add_argument("--workbench-origin-journal", type=Path)
    parser.add_argument("--workbench-attempt-receipt", type=Path)
    parser.add_argument("--workbench-inspection", type=Path)
    parser.add_argument("--workbench-artifact-pin", type=Path)
    parser.add_argument("--workbench-promotion-receipt", type=Path)
    parser.add_argument("--workbench-promotion-journal", type=Path)
    parser.add_argument("--relay-reset-artifact-pin", type=Path)
    parser.add_argument("--relay-reset-receipt", type=Path)
    parser.add_argument("--relay-reset-journal", type=Path)
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args(argv)
    promotion_paths = (
        args.workbench_artifact_pin,
        args.workbench_promotion_receipt,
        args.workbench_promotion_journal,
    )
    relay_reset_paths = (
        args.relay_reset_artifact_pin,
        args.relay_reset_receipt,
        args.relay_reset_journal,
    )
    if args.relay_fixture_reset:
        require(args.live is True, "relay fixture reset requires --live")
        require(all(value is not None for value in relay_reset_paths), "relay fixture reset requires artifact pin, receipt, and journal")
        require(all(value is None for value in promotion_paths), "relay fixture reset may not receive workbench promotion inputs")
        require(
            all(value is None for value in (
                args.teardown_dormant_receipt,
                args.participant_secret_bundle,
                args.teardown_participant_secret_receipt,
                args.handover_dormant_receipt,
                args.participant_secret_materialization_receipt,
                args.workbench_handover_receipt,
                args.workbench_handover_journal,
                args.workbench_recovery_receipt,
                args.workbench_recovery_journal,
                args.workbench_origin_journal,
                args.workbench_attempt_receipt,
                args.workbench_inspection,
            )),
            "relay fixture reset may not receive participant or baseline inputs",
        )
        require(
            os.path.normcase(os.path.normpath(os.fspath(args.relay_reset_receipt)))
            != os.path.normcase(os.path.normpath(os.fspath(args.relay_reset_journal))),
            "relay fixture reset receipt and journal paths must be distinct",
        )
    elif any(value is not None for value in relay_reset_paths):
        raise LiveTransportError("relay fixture reset paths require --relay-fixture-reset")
    elif args.workbench_image_promotion:
        require(args.live is True, "workbench image promotion requires --live")
        require(
            all(value is None for value in (
                args.teardown_dormant_receipt,
                args.participant_secret_bundle,
                args.teardown_participant_secret_receipt,
                args.handover_dormant_receipt,
                args.participant_secret_materialization_receipt,
                args.workbench_handover_receipt,
                args.workbench_handover_journal,
                args.workbench_recovery_receipt,
                args.workbench_recovery_journal,
                args.workbench_origin_journal,
                args.workbench_attempt_receipt,
                args.workbench_inspection,
            )),
            "workbench image promotion may not receive participant or baseline inputs",
        )
        require(all(value is not None for value in promotion_paths), "workbench image promotion requires artifact pin, receipt, and journal")
        require(
            os.path.normcase(os.path.normpath(os.fspath(args.workbench_promotion_receipt)))
            != os.path.normcase(os.path.normpath(os.fspath(args.workbench_promotion_journal))),
            "workbench image promotion receipt and journal paths must be distinct",
        )
    elif any(value is not None for value in promotion_paths):
        raise LiveTransportError("workbench image promotion paths require --workbench-image-promotion")
    elif args.workbench_baseline_handover:
        require(args.teardown_dormant_receipt is None, "workbench handover may not request participant teardown")
        require(
            args.participant_secret_bundle is None
            and args.teardown_participant_secret_receipt is None
            and args.handover_dormant_receipt is None
            and args.participant_secret_materialization_receipt is None,
            "workbench handover may not receive participant Secret or continuation inputs",
        )
        require(args.workbench_handover_receipt is not None and args.workbench_handover_journal is not None, "workbench handover requires explicit receipt and journal paths for resume")
        require(all(value is None for value in (args.workbench_recovery_receipt, args.workbench_recovery_journal, args.workbench_origin_journal, args.workbench_attempt_receipt, args.workbench_inspection)), "workbench handover may not receive recovery paths")
    elif args.workbench_baseline_recovery or args.workbench_baseline_recovery_finalize:
        require(args.teardown_dormant_receipt is None, "workbench recovery may not request participant teardown")
        require(
            args.participant_secret_bundle is None
            and args.teardown_participant_secret_receipt is None
            and args.handover_dormant_receipt is None
            and args.participant_secret_materialization_receipt is None,
            "workbench recovery may not receive participant Secret or continuation inputs",
        )
        require(all(value is not None for value in (args.workbench_recovery_receipt, args.workbench_recovery_journal, args.workbench_origin_journal, args.workbench_attempt_receipt, args.workbench_inspection)), "workbench recovery requires exact evidence, receipt, and journal paths")
        require(args.workbench_handover_receipt is None and args.workbench_handover_journal is None, "workbench recovery may not receive handover paths")
    else:
        require(all(value is None for value in (args.workbench_handover_receipt, args.workbench_handover_journal, args.workbench_recovery_receipt, args.workbench_recovery_journal, args.workbench_origin_journal, args.workbench_attempt_receipt, args.workbench_inspection)), "participant mode may not receive workbench paths")
        continuation = args.handover_dormant_receipt is not None or args.participant_secret_materialization_receipt is not None
        if continuation:
            require(
                args.handover_dormant_receipt is not None
                and args.participant_secret_materialization_receipt is not None
                and args.teardown_dormant_receipt is None
                and args.teardown_participant_secret_receipt is None
                and args.participant_secret_bundle is None,
                "participant continuation requires archived dormant and Secret materialization receipts only",
            )
        elif args.teardown_participant_secret_receipt is not None:
            require(args.teardown_dormant_receipt is None, "participant Secret teardown may not combine with dormant Flux teardown")
            require(args.participant_secret_bundle is None and args.handover_dormant_receipt is None and args.participant_secret_materialization_receipt is None, "participant Secret teardown accepts no Secret input or continuation receipts")
        elif args.teardown_dormant_receipt is not None:
            require(args.participant_secret_bundle is None and args.handover_dormant_receipt is None and args.participant_secret_materialization_receipt is None, "dormant Flux teardown accepts no Secret input or continuation receipts")
        else:
            require(args.participant_secret_bundle is not None, "participant activation requires an explicit private Secret bundle")
            require(args.handover_dormant_receipt is None and args.participant_secret_materialization_receipt is None, "participant activation accepts no continuation receipts")
    return args

def run_dormant_teardown(
    session: LiveSession,
    cancellation: CancellationState,
    runner: BoundRunner,
    revision: str,
    kubeconfig: Path,
    source_receipt: BoundBlob,
    source_canonical_sha256: str,
    output_receipt: Path,
    snapshot_path: Path,
    environment: dict[str, str],
    extra_pass_fds: tuple[int, ...] = (),
) -> tuple[dict[str, Any], int, BoundBlob, str | None]:
    result = session.run_child(
        runner.command([
            "--teardown",
            "--expected-protected-revision",
            revision,
            "--kubeconfig",
            str(kubeconfig),
            "--recovery-receipt-fd",
            str(source_receipt.fd),
            "--receipt",
            str(output_receipt),
        ]),
        environment,
        allow_cancelled=True,
        forward_signals=False,
        receipt_pending=True,
        pass_fds=(runner.blob.fd, source_receipt.fd, *extra_pass_fds),
    )
    bound_output: BoundBlob | None = None
    try:
        bound_output = snapshot_owned_receipt(output_receipt, snapshot_path, "dormant teardown receipt")
        projection = verify_receipt_with_protected_cli(
            cancellation,
            runner,
            "--verify-teardown-receipt-fd",
            bound_output,
            revision,
            environment,
            "dormant-torn-down",
            allow_cancelled=True,
            expected_source_sha256=source_canonical_sha256,
        )
        logging_error = best_effort_print_child(result)
        return projection, result.returncode, bound_output, logging_error
    except BaseException:
        if bound_output is not None: bound_output.close()
        raise
    finally:
        session.receipt_reconciled()

def classify_final_status(
    base_status: str,
    *,
    activation_committed: bool,
    operation_succeeded: bool,
    cleanup_complete: bool,
) -> tuple[str, int]:
    if activation_committed:
        return ("activated", 0) if cleanup_complete else ("activated-cleanup-incomplete", 3)
    if operation_succeeded and base_status == "dormant-torn-down":
        return ("dormant-torn-down", 0) if cleanup_complete else ("dormant-teardown-cleanup-incomplete", 3)
    if operation_succeeded and base_status == "participant-secrets-torn-down":
        return ("participant-secrets-torn-down", 0) if cleanup_complete else ("participant-secret-teardown-cleanup-incomplete", 3)
    if not cleanup_complete:
        return (f"{base_status}-cleanup-incomplete", 3)
    return base_status, 2


def run_workbench_baseline_handover_transport(args: argparse.Namespace) -> int:
    """Run only the reviewed E2E-workbench handover over private transport.

    This is intentionally not a branch inside the participant transaction:
    its protected closure contains no participant bootstrap, activation, or
    teardown code, and its receipt does not claim any participant state.
    """
    receipt_dir: Path | None = None; receipt_sink: WrapperReceiptSink | None = None
    temp: Path | None = None; session: LiveSession | None = None
    cancellation = CancellationState(); installed = False
    snapshots: dict[str, PinnedExecutableSnapshot] = {}; bindings: dict[str, PersistentPinnedExecutable] = {}
    bound: list[BoundRunner] = []; evidence: list[BoundBlob] = []
    protected_hashes: dict[str, str] = {}; credentials: list[str] = []
    cleanup_errors: list[str] = []; error: str | None = None; completed = False
    listener_verified = False; proof: dict[str, Any] | None = None
    revision = args.expected_protected_revision
    is_terminal_finalization = bool(getattr(args, "workbench_baseline_recovery_finalize", False))
    is_recovery = bool(getattr(args, "workbench_baseline_recovery", False) or is_terminal_finalization)
    handover_receipt: Path | None = None; handover_journal: Path | None = None
    recovery_receipt: Path | None = None; recovery_journal: Path | None = None
    pending_recovery_evidence: dict[str, dict[str, Any]] = {}
    try:
        require(sys.flags.isolated == 1 and bool(sys.flags.safe_path), "wrapper requires python3 -I isolated safe-path mode")
        require(args.live is True and (args.workbench_baseline_handover is True or is_recovery), "workbench transport requires explicit workbench mode and --live")
        require(REVISION.fullmatch(revision) is not None, "protected revision must be lowercase SHA-1")
        if is_recovery:
            recovery_receipt = private_workbench_output(args.workbench_recovery_receipt, "workbench recovery receipt")
            recovery_journal = private_workbench_output(args.workbench_recovery_journal, "workbench recovery journal")
            require(not recovery_receipt.exists(), "workbench recovery receipt must be a new immutable attempt output")
            require(os.path.normcase(os.path.normpath(os.fspath(recovery_receipt))) != os.path.normcase(os.path.normpath(os.fspath(recovery_journal))), "workbench recovery receipt and journal paths must be distinct")
        else:
            handover_receipt = private_workbench_output(args.workbench_handover_receipt, "workbench handover receipt")
            handover_journal = private_workbench_output(args.workbench_handover_journal, "workbench handover journal")
            require(os.path.normcase(os.path.normpath(os.fspath(handover_receipt))) != os.path.normcase(os.path.normpath(os.fspath(handover_journal))), "workbench handover receipt and journal paths must be distinct")
        cancellation.install(); installed = True
        receipt_dir = reserve_output_directory(args.receipt_directory)
        attempt_name = (
            "workbench-baseline-recovery-finalization-transport-attempt.json"
            if is_terminal_finalization
            else ("workbench-baseline-recovery-transport-attempt.json" if is_recovery else "workbench-baseline-transport-attempt.json")
        )
        attempt_path = receipt_dir / attempt_name
        receipt_sink = WrapperReceiptSink.reserve(attempt_path)
        cancellation.checkpoint()
        protected_hashes, protected_blobs = bind_protected_checkout(revision, paths=WORKBENCH_RECOVERY_PROTECTED_PATHS if is_recovery else WORKBENCH_PROTECTED_PATHS)
        identity = private_file(args.age_identity, "age identity")
        bundle_source = Path(os.path.abspath(args.bootstrap_bundle)); bundle_source_info = os.lstat(bundle_source)
        require(not stat.S_ISLNK(bundle_source_info.st_mode), "bootstrap bundle must not be a symlink")
        bundle = Path(os.path.realpath(bundle_source))
        bundle_info = os.lstat(bundle)
        require(bundle == bundle_source and stat.S_ISDIR(bundle_info.st_mode) and bundle_info.st_uid == os.geteuid() and stat.S_IMODE(bundle_info.st_mode) & 0o077 == 0, "bootstrap bundle must be a private owned directory")
        encrypted_wg = private_file(bundle / "wireguard-daily.conf.age", "encrypted WireGuard input")
        encrypted_talos = private_file(bundle / "talosconfig.yaml.age", "encrypted Talos input")
        temp = Path(tempfile.mkdtemp(prefix="roebel-workbench-live-", dir="/private/tmp")); os.chmod(temp, 0o700)
        binding_dir = temp / "bindings"; binding_dir.mkdir(mode=0o700)
        # The recovery binds only its own protected implementation.  The
        # ordinary handover retains its separately reviewed runner identity.
        logical_paths = (WORKBENCH_RECOVERY_IMPLEMENTATION,) if is_recovery else (WORKBENCH_RUNNER, WORKBENCH_IMPLEMENTATION)
        for logical_path in logical_paths:
            blob = bind_bytes_to_fd(protected_blobs[logical_path], binding_dir / (Path(logical_path).name + ".bound"), f"protected workbench blob {logical_path}")
            bound.append(BoundRunner(logical_path, blob))
        implementation = next(item for item in bound if item.logical_path == (WORKBENCH_RECOVERY_IMPLEMENTATION if is_recovery else WORKBENCH_IMPLEMENTATION))
        recovery_inputs: dict[str, BoundBlob] = {}
        if is_recovery:
            for name, source in (
                ("origin-journal", args.workbench_origin_journal),
                ("attempt-receipt", args.workbench_attempt_receipt),
                ("inspection", args.workbench_inspection),
            ):
                recovery_inputs[name] = snapshot_owned_receipt(source, binding_dir / f"recovery-{name}.bound", f"workbench recovery {name}")
            evidence.extend(recovery_inputs.values())
            if is_terminal_finalization:
                require(recovery_journal is not None, "terminal-finalization journal path absent")
                existing_journal = bind_terminal_finalization_journal(recovery_journal, binding_dir, revision)
                evidence.append(existing_journal)
            elif recovery_journal is not None and recovery_journal.exists() and recovery_journal.stat().st_size > 0:
                existing_journal = snapshot_owned_receipt(
                    recovery_journal,
                    binding_dir / "recovery-existing-journal.bound",
                    "workbench recovery existing journal",
                )
                evidence.append(existing_journal)
        executable_dir = temp / "executables"; executable_dir.mkdir(mode=0o700)
        for label, source in sorted({"age": args.age_bin, "kubectl": args.kubectl_bin, "talosctl": args.talosctl_bin, "wireproxy": args.wireproxy_bin}.items()):
            snapshot = snapshot_binary(source, label, executable_dir / label)
            seal_pinned_snapshot(snapshot)
            snapshots[label] = snapshot; bindings[label] = PersistentPinnedExecutable(snapshot)
            cancellation.checkpoint()
        fsync_directory(executable_dir)
        wireguard = temp / "wireguard.conf"; talosconfig = temp / "talosconfig.yaml"
        decrypt(cancellation, bindings["age"], identity, encrypted_wg, wireguard)
        decrypt(cancellation, bindings["age"], identity, encrypted_talos, talosconfig)
        wireguard_bytes = wireguard.read_bytes(); wireguard.unlink(); fsync_directory(wireguard.parent)
        api_config = wireproxy_config(f"{API_HOST}:{API_PORT}", wireguard_bytes)
        talos_config = wireproxy_config(f"{API_HOST}:{TALOS_PORT}", wireguard_bytes)
        api_password = secrets.token_hex(32); talos_password = secrets.token_hex(32); credentials = [api_password, talos_password]
        for index, config in enumerate((api_config, talos_config)):
            config_blob = bind_bytes_to_fd(config, binding_dir / f"wireproxy-config-{index}.bound", f"workbench fixed-target wireproxy config {index}")
            try:
                checked = cancellation.run(
                    [str(bindings["wireproxy"].path), "-n", "-c", f"/dev/fd/{config_blob.fd}"],
                    timeout=10, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=sanitized_environment(), pass_fds=(config_blob.fd,), executable_binding=bindings["wireproxy"],
                )
                require(checked.returncode == 0, f"wireproxy rejected protected fixed-target config {index}")
            finally:
                config_blob.close()
        session = LiveSession(bindings["wireproxy"], api_config, talos_config, binding_dir, api_password, talos_password, cancellation)
        api_port, talos_port = session.start_proxy(); listener_verified = session.listener_verified
        kubeconfig = temp / "admin-kubeconfig.json"
        create_admin_kubeconfig(
            session, bindings["talosctl"], bindings["kubectl"], talosconfig, kubeconfig,
            proxy_url(talos_password, talos_port), proxy_url(api_password, api_port), temp,
        )
        child_environment = sanitized_environment() | {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin"}
        child_arguments = (
            (["--terminal-finalize"] if is_terminal_finalization else []) + [
                "--expected-protected-revision", revision, "--kubeconfig", str(kubeconfig),
                "--origin-journal-fd", str(recovery_inputs["origin-journal"].fd),
                "--attempt-receipt-fd", str(recovery_inputs["attempt-receipt"].fd),
                "--inspection-fd", str(recovery_inputs["inspection"].fd),
                "--recovery-journal", str(recovery_journal), "--receipt", str(recovery_receipt),
            ]
            if is_recovery else
            ["--expected-protected-revision", revision, "--kubeconfig", str(kubeconfig), "--receipt", str(handover_receipt), "--journal", str(handover_journal)]
        )
        child = session.run_child(
            workbench_implementation_command(
                implementation,
                snapshots["kubectl"],
                child_arguments,
            ),
            child_environment,
            receipt_pending=True,
            pass_fds=(implementation.blob.fd, snapshots["kubectl"].fd, *(item.fd for item in recovery_inputs.values())),
        )
        try:
            if is_recovery and child.returncode != 0:
                for label, output in (("receipt", recovery_receipt), ("journal", recovery_journal)):
                    require(output is not None, "workbench recovery output path absent")
                    if output.exists() and output.stat().st_size > 0:
                        pending = snapshot_owned_receipt(output, binding_dir / f"workbench-recovery-pending-{label}.bound", f"workbench recovery pending {label}")
                        evidence.append(pending)
                        pending_recovery_evidence[label] = {"sha256": pending.sha256, "size": pending.size}
            require(child.returncode == 0, f"protected workbench {'recovery' if is_recovery else 'handover'} exited {child.returncode}")
            receipt_bound = snapshot_owned_receipt(recovery_receipt if is_recovery else handover_receipt, binding_dir / ("workbench-recovery-receipt.bound" if is_recovery else "workbench-handover-receipt.bound"), f"workbench {'recovery' if is_recovery else 'handover'} receipt")
            journal_bound = snapshot_owned_receipt(recovery_journal if is_recovery else handover_journal, binding_dir / ("workbench-recovery-journal.bound" if is_recovery else "workbench-handover-journal.bound"), f"workbench {'recovery' if is_recovery else 'handover'} journal")
            evidence.extend((receipt_bound, journal_bound))
            proof = verify_workbench_recovery_evidence(
                receipt_bound,
                journal_bound,
                revision,
                terminal_finalization_expected=is_terminal_finalization,
            ) if is_recovery else verify_workbench_handover_evidence(receipt_bound, journal_bound, revision, protected_hashes)
            bindings["kubectl"]._verify()
            logging_error = best_effort_print_child(child)
            require(logging_error is None, logging_error or "protected child output forwarding failed")
            completed = True
        finally:
            session.receipt_reconciled()
    except BaseException as exc:
        error = str(exc) or type(exc).__name__
        best_effort_stderr(f"workbench live wrapper blocked: {error}")
    if installed: cancellation.begin_finalization()
    session_cleanup: dict[str, Any] = {"wireproxyProcessGroupStopped": True, "allGuardWorkersStopped": True}
    if session is not None:
        try: session_cleanup = session.close()
        except BaseException as exc: cleanup_errors.append(f"transport cleanup: {exc}")
    process_cleanup = {"ownedProcessGroupsStopped": True, "ownedProcessGroupCount": 0}
    if installed:
        try: process_cleanup = cancellation.cleanup_processes()
        except BaseException as exc: cleanup_errors.append(f"process cleanup: {exc}")
    for snapshot in snapshots.values():
        try: unseal_pinned_snapshot(snapshot)
        except BaseException as exc: cleanup_errors.append(f"pinned snapshot unseal: {exc}")
        try: snapshot.close()
        except BaseException as exc: cleanup_errors.append(f"pinned snapshot close: {exc}")
    for item in evidence:
        try: item.close()
        except BaseException as exc: cleanup_errors.append(f"evidence close: {exc}")
    for item in bound:
        try: item.close()
        except BaseException as exc: cleanup_errors.append(f"protected blob close: {exc}")
    plaintext_removed = temp is None
    if temp is not None:
        try: shutil.rmtree(temp)
        except BaseException as exc: cleanup_errors.append(f"private temp cleanup: {exc}")
        plaintext_removed = not temp.exists()
    cleanup_complete = not cleanup_errors and session_cleanup.get("wireproxyProcessGroupStopped") is True and session_cleanup.get("allGuardWorkersStopped") is True and process_cleanup["ownedProcessGroupsStopped"] is True and plaintext_removed
    status = "completed" if completed and cleanup_complete else ("completed-cleanup-incomplete" if completed else "blocked")
    payload = {
        "schemaVersion": WORKBENCH_RECOVERY_TRANSPORT_RECEIPT_SCHEMA if is_recovery else WORKBENCH_TRANSPORT_RECEIPT_SCHEMA,
        "status": status,
        "protectedRevision": revision,
        "protectedGitBlobSha256": protected_hashes,
        "binarySha256": {name: snapshot.sha256 for name, snapshot in sorted(snapshots.items())},
        "transport": {"mode": "authenticated-exact-connect-guards-spawning-fixed-wireproxy-stdio-tunnels", "apiAuthority": f"{API_HOST}:{API_PORT}", "talosAuthority": f"{API_HOST}:{TALOS_PORT}", "listenerOwnershipAndAuthenticationVerified": listener_verified, "temporaryTransportStopped": session_cleanup.get("wireproxyProcessGroupStopped") is True, "plaintextTransportInputsRemoved": plaintext_removed},
        "recovery" if is_recovery else "handover": proof or ({"receiptSha256": None, "journalSha256": None, "cleanupComplete": False, "pendingEvidence": pending_recovery_evidence} if is_recovery else {"receiptSha256": None, "journalSha256": None, "networkPolicyUid": None, "fluxObjectUids": {}, "ready": False}),
        "resume": {"explicitReceiptAndJournalRequired": True, "automaticRetry": False, "sameProtectedRevisionRequired": True},
        "cleanup": {"complete": cleanup_complete, "errors": cleanup_errors, "processes": process_cleanup},
        "failure": error,
        "containsSecretMaterial": False,
        "civicAuthorityEffects": False,
        "automaticRetry": False,
    }
    committed = False
    if receipt_sink is not None:
        try:
            encoded = canonical(payload); require(not any(value in encoded for value in credentials), "workbench wrapper receipt contains transport credential")
            receipt_sink.commit(payload); committed = True
        except BaseException as exc:
            best_effort_stderr(f"workbench live wrapper receipt-incomplete: {exc}")
    if installed: cancellation.restore()
    return 0 if completed and cleanup_complete and committed else 3 if completed else 2


def run_relay_fixture_reset_transport(args: argparse.Namespace) -> int:
    """Run the one-shot protected relay fixture reset over pinned transport.

    The child alone owns its exact Ingress write gate/restore, the two ordered
    citizen-then-agent Pod DELETE requests, and the public-Mecky Flux suspend,
    Deployment scale 1-to-0-to-1, and restore sequence.  This wrapper binds the
    child source from the protected Git revision, copies and verifies the
    immutable relay runtime pin, snapshots every executable, and exposes only
    authenticated fixed CONNECT guards and descriptor-pinned kubectl. Outputs
    must be fresh because an interrupted destructive attempt is never retried.
    """
    receipt_dir: Path | None = None; receipt_sink: WrapperReceiptSink | None = None
    temp: Path | None = None; session: LiveSession | None = None
    cancellation = CancellationState(); installed = False
    snapshots: dict[str, PinnedExecutableSnapshot] = {}
    bindings: dict[str, PersistentPinnedExecutable] = {}
    bound: list[BoundRunner] = []; evidence: list[BoundBlob] = []
    protected_hashes: dict[str, str] = {}; credentials: list[str] = []
    cleanup_errors: list[str] = []; error: str | None = None; completed = False
    listener_verified = False; proof: dict[str, Any] | None = None
    revision = args.expected_protected_revision
    reset_receipt = Path(args.relay_reset_receipt)
    reset_journal = Path(args.relay_reset_journal)
    artifact_pin_copy: Path | None = None
    try:
        require(sys.flags.isolated == 1 and bool(sys.flags.safe_path), "wrapper requires python3 -I isolated safe-path mode")
        require(args.live is True and args.relay_fixture_reset is True, "relay fixture reset requires explicit mode and --live")
        require(REVISION.fullmatch(revision) is not None, "protected revision must be lowercase SHA-1")
        require(
            RELAY_FIXTURE_RESET_LIVE_EXECUTION_ENABLED is True,
            "relay fixture reset strict v2 evidence guard is disabled",
        )
        reset_receipt, reset_journal = private_relay_fixture_reset_outputs(reset_receipt, reset_journal)
        cancellation.install(); installed = True
        receipt_dir = reserve_output_directory(args.receipt_directory)
        receipt_sink = WrapperReceiptSink.reserve(receipt_dir / "relay-fixture-reset-transport-attempt.json")
        cancellation.checkpoint()
        protected_hashes, protected_blobs = bind_protected_checkout(
            revision,
            paths=RELAY_FIXTURE_RESET_PROTECTED_PATHS,
        )
        identity = private_file(args.age_identity, "age identity")
        bundle_source = Path(os.path.abspath(args.bootstrap_bundle)); bundle_source_info = os.lstat(bundle_source)
        require(not stat.S_ISLNK(bundle_source_info.st_mode), "bootstrap bundle must not be a symlink")
        bundle = Path(os.path.realpath(bundle_source)); bundle_info = os.lstat(bundle)
        require(
            bundle == bundle_source
            and stat.S_ISDIR(bundle_info.st_mode)
            and bundle_info.st_uid == os.geteuid()
            and stat.S_IMODE(bundle_info.st_mode) & 0o077 == 0,
            "bootstrap bundle must be a private owned directory",
        )
        encrypted_wg = private_file(bundle / "wireguard-daily.conf.age", "encrypted WireGuard input")
        encrypted_talos = private_file(bundle / "talosconfig.yaml.age", "encrypted Talos input")

        temp = Path(tempfile.mkdtemp(prefix="roebel-relay-fixture-reset-live-", dir="/private/tmp")); os.chmod(temp, 0o700)
        binding_dir = temp / "bindings"; binding_dir.mkdir(mode=0o700)
        runner_blob = bind_bytes_to_fd(
            protected_blobs[RELAY_FIXTURE_RESET_RUNNER],
            binding_dir / "reset-staging-relay-fixtures.py.bound",
            "protected relay fixture reset runner",
        )
        bound.append(BoundRunner(RELAY_FIXTURE_RESET_RUNNER, runner_blob))
        runner = bound[0]
        artifact_pin_copy = temp / "relay-runtime-pin.json"
        snapshot_owned_file_path(
            Path(args.relay_reset_artifact_pin),
            artifact_pin_copy,
            "relay fixture reset artifact pin",
            max_bytes=MAX_RECEIPT_BYTES,
        )
        require(
            file_sha256(artifact_pin_copy) == RELAY_FIXTURE_RESET_ARTIFACT_RECEIPT_SHA256,
            "relay fixture reset artifact pin checksum drift",
        )
        executable_dir = temp / "executables"; executable_dir.mkdir(mode=0o700)
        for label, source in sorted({
            "age": args.age_bin,
            "kubectl": args.kubectl_bin,
            "talosctl": args.talosctl_bin,
            "wireproxy": args.wireproxy_bin,
        }.items()):
            snapshot = snapshot_binary(source, label, executable_dir / label)
            seal_pinned_snapshot(snapshot)
            snapshots[label] = snapshot
            bindings[label] = PersistentPinnedExecutable(snapshot)
            cancellation.checkpoint()
        fsync_directory(executable_dir)
        wireguard = temp / "wireguard.conf"; talosconfig = temp / "talosconfig.yaml"
        decrypt(cancellation, bindings["age"], identity, encrypted_wg, wireguard)
        decrypt(cancellation, bindings["age"], identity, encrypted_talos, talosconfig)
        wireguard_bytes = wireguard.read_bytes(); wireguard.unlink(); fsync_directory(wireguard.parent)
        api_config = wireproxy_config(f"{API_HOST}:{API_PORT}", wireguard_bytes)
        talos_config = wireproxy_config(f"{API_HOST}:{TALOS_PORT}", wireguard_bytes)
        api_password = secrets.token_hex(32); talos_password = secrets.token_hex(32)
        credentials = [api_password, talos_password]
        for index, config in enumerate((api_config, talos_config)):
            config_blob = bind_bytes_to_fd(
                config,
                binding_dir / f"wireproxy-config-{index}.bound",
                f"relay fixture reset fixed-target wireproxy config {index}",
            )
            try:
                checked = cancellation.run(
                    [str(bindings["wireproxy"].path), "-n", "-c", f"/dev/fd/{config_blob.fd}"],
                    timeout=10,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=sanitized_environment(),
                    pass_fds=(config_blob.fd,),
                    executable_binding=bindings["wireproxy"],
                )
                require(checked.returncode == 0, f"wireproxy rejected protected fixed-target config {index}")
            finally:
                config_blob.close()
        session = LiveSession(
            bindings["wireproxy"], api_config, talos_config, binding_dir,
            api_password, talos_password, cancellation,
        )
        api_port, talos_port = session.start_proxy(); listener_verified = session.listener_verified
        kubeconfig = temp / "admin-kubeconfig.json"
        create_admin_kubeconfig(
            session,
            bindings["talosctl"],
            bindings["kubectl"],
            talosconfig,
            kubeconfig,
            proxy_url(talos_password, talos_port),
            proxy_url(api_password, api_port),
            temp,
        )
        child_environment = sanitized_environment() | {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin"}
        child = session.run_child(
            relay_fixture_reset_command(
                runner,
                snapshots["kubectl"],
                [
                    "--artifact-pin", str(artifact_pin_copy),
                    "--kubeconfig", str(kubeconfig),
                    "--receipt", str(reset_receipt),
                    "--journal", str(reset_journal),
                    "--protected-revision", revision,
                    "--protected-hashes", canonical(protected_hashes),
                ],
            ),
            child_environment,
            receipt_pending=True,
            pass_fds=(runner.blob.fd, snapshots["kubectl"].fd),
        )
        try:
            require(child.returncode == 0, f"protected relay fixture reset runner exited {child.returncode}")
            receipt_bound = snapshot_owned_receipt(
                reset_receipt,
                binding_dir / "relay-fixture-reset-receipt.bound",
                "relay fixture reset receipt",
            )
            journal_bound = snapshot_owned_receipt(
                reset_journal,
                binding_dir / "relay-fixture-reset-journal.bound",
                "relay fixture reset journal",
            )
            evidence.extend((receipt_bound, journal_bound))
            proof = verify_relay_fixture_reset_evidence(
                receipt_bound,
                journal_bound,
                revision,
                protected_hashes,
                RELAY_FIXTURE_RESET_ARTIFACT_RECEIPT_SHA256,
            )
            bindings["kubectl"]._verify()
            logging_error = best_effort_print_child(child)
            require(logging_error is None, logging_error or "protected relay fixture reset output forwarding failed")
            completed = True
        finally:
            session.receipt_reconciled()
    except BaseException as exc:
        error = str(exc) or type(exc).__name__
        best_effort_stderr(f"relay fixture reset wrapper blocked: {error}")
    if installed: cancellation.begin_finalization()
    session_cleanup: dict[str, Any] = {"wireproxyProcessGroupStopped": True, "allGuardWorkersStopped": True}
    if session is not None:
        try: session_cleanup = session.close()
        except BaseException as exc: cleanup_errors.append(f"transport cleanup: {exc}")
    process_cleanup = {"ownedProcessGroupsStopped": True, "ownedProcessGroupCount": 0}
    if installed:
        try: process_cleanup = cancellation.cleanup_processes()
        except BaseException as exc: cleanup_errors.append(f"process cleanup: {exc}")
    for snapshot in snapshots.values():
        try: unseal_pinned_snapshot(snapshot)
        except BaseException as exc: cleanup_errors.append(f"pinned snapshot unseal: {exc}")
        try: snapshot.close()
        except BaseException as exc: cleanup_errors.append(f"pinned snapshot close: {exc}")
    for item in evidence:
        try: item.close()
        except BaseException as exc: cleanup_errors.append(f"relay reset evidence close: {exc}")
    for item in bound:
        try: item.close()
        except BaseException as exc: cleanup_errors.append(f"protected relay reset runner close: {exc}")
    plaintext_removed = temp is None
    if temp is not None:
        try: shutil.rmtree(temp)
        except BaseException as exc: cleanup_errors.append(f"private relay reset temp cleanup: {exc}")
        plaintext_removed = not temp.exists()
    cleanup_complete = (
        not cleanup_errors
        and session_cleanup.get("wireproxyProcessGroupStopped") is True
        and session_cleanup.get("allGuardWorkersStopped") is True
        and process_cleanup["ownedProcessGroupsStopped"] is True
        and plaintext_removed
    )
    status = "completed" if completed and cleanup_complete else ("completed-cleanup-incomplete" if completed else "blocked")
    payload = {
        "schemaVersion": RELAY_FIXTURE_RESET_TRANSPORT_RECEIPT_SCHEMA,
        "status": status,
        "protectedRevision": revision,
        "protectedGitBlobSha256": protected_hashes,
        "binarySha256": {name: snapshot.sha256 for name, snapshot in sorted(snapshots.items())},
        "artifactPinSha256": RELAY_FIXTURE_RESET_ARTIFACT_RECEIPT_SHA256,
        "targetImage": RELAY_FIXTURE_RESET_TARGET_IMAGE,
        "transport": {
            "mode": "authenticated-exact-connect-guards-spawning-protected-relay-fixture-reset",
            "apiAuthority": f"{API_HOST}:{API_PORT}",
            "talosAuthority": f"{API_HOST}:{TALOS_PORT}",
            "listenerOwnershipAndAuthenticationVerified": listener_verified,
            "temporaryTransportStopped": session_cleanup.get("wireproxyProcessGroupStopped") is True,
            "plaintextTransportInputsRemoved": plaintext_removed,
        },
        "reset": proof or {
            "receiptSha256": None,
            "journalSha256": None,
            "cleanupComplete": False,
        },
        "resume": {
            "explicitReceiptPath": str(reset_receipt),
            "explicitJournalPath": str(reset_journal),
            "automaticRetry": False,
            "sameProtectedRevisionRequired": True,
            "freshOutputsRequired": True,
        },
        "cleanup": {"complete": cleanup_complete, "errors": cleanup_errors, "processes": process_cleanup},
        "failure": error,
        "containsSecretMaterial": False,
        "civicAuthorityEffects": False,
        "automaticRetry": False,
    }
    committed = False
    if receipt_sink is not None:
        try:
            encoded = canonical(payload)
            require(not any(value in encoded for value in credentials), "relay fixture reset wrapper receipt contains transport credential")
            receipt_sink.commit(payload); committed = True
        except BaseException as exc:
            best_effort_stderr(f"relay fixture reset wrapper receipt-incomplete: {exc}")
    if installed: cancellation.restore()
    return 0 if completed and cleanup_complete and committed else 3 if completed else 2


def run_workbench_image_promotion_transport(args: argparse.Namespace) -> int:
    """Promote the reviewed workbench image through the protected promoter.

    This is a separate capability from both participant activation and the
    workbench baseline handover.  The wrapper binds the promoter source from
    the exact protected Git revision, snapshots the immutable artifact pin,
    and gives the child only the two explicit output paths plus the inherited
    pinned kubectl descriptor.  The promoter itself owns the narrow Deployment
    CAS mutation, a fixed public HTTPS functional probe, and the separately
    bound Service/EndpointSlice-to-target-Pod proof.
    """
    receipt_dir: Path | None = None; receipt_sink: WrapperReceiptSink | None = None
    temp: Path | None = None; session: LiveSession | None = None
    cancellation = CancellationState(); installed = False
    snapshots: dict[str, PinnedExecutableSnapshot] = {}
    bindings: dict[str, PersistentPinnedExecutable] = {}
    bound: list[BoundRunner] = []; evidence: list[BoundBlob] = []
    protected_hashes: dict[str, str] = {}; credentials: list[str] = []
    cleanup_errors: list[str] = []; error: str | None = None; completed = False
    listener_verified = False; proof: dict[str, Any] | None = None
    revision = args.expected_protected_revision
    promotion_receipt = Path(args.workbench_promotion_receipt)
    promotion_journal = Path(args.workbench_promotion_journal)
    artifact_pin_copy: Path | None = None
    try:
        require(sys.flags.isolated == 1 and bool(sys.flags.safe_path), "wrapper requires python3 -I isolated safe-path mode")
        require(args.live is True and args.workbench_image_promotion is True, "workbench image promotion requires explicit mode and --live")
        require(REVISION.fullmatch(revision) is not None, "protected revision must be lowercase SHA-1")
        # Reserve and validate caller-owned durable outputs before any
        # transport, credential, or Kubernetes state is created.  The child
        # promoter will create these exact paths with its own owner-only,
        # immutable sink checks.
        promotion_receipt, promotion_journal = private_workbench_promotion_outputs(promotion_receipt, promotion_journal)
        cancellation.install(); installed = True
        receipt_dir = reserve_output_directory(args.receipt_directory)
        receipt_sink = WrapperReceiptSink.reserve(receipt_dir / "workbench-image-promotion-transport-attempt.json")
        cancellation.checkpoint()
        protected_hashes, protected_blobs = bind_protected_checkout(revision, paths=WORKBENCH_PROMOTION_PROTECTED_PATHS)
        identity = private_file(args.age_identity, "age identity")
        bundle_source = Path(os.path.abspath(args.bootstrap_bundle)); bundle_source_info = os.lstat(bundle_source)
        require(not stat.S_ISLNK(bundle_source_info.st_mode), "bootstrap bundle must not be a symlink")
        bundle = Path(os.path.realpath(bundle_source)); bundle_info = os.lstat(bundle)
        require(
            bundle == bundle_source
            and stat.S_ISDIR(bundle_info.st_mode)
            and bundle_info.st_uid == os.geteuid()
            and stat.S_IMODE(bundle_info.st_mode) & 0o077 == 0,
            "bootstrap bundle must be a private owned directory",
        )
        encrypted_wg = private_file(bundle / "wireguard-daily.conf.age", "encrypted WireGuard input")
        encrypted_talos = private_file(bundle / "talosconfig.yaml.age", "encrypted Talos input")

        temp = Path(tempfile.mkdtemp(prefix="roebel-workbench-promotion-live-", dir="/private/tmp")); os.chmod(temp, 0o700)
        binding_dir = temp / "bindings"; binding_dir.mkdir(mode=0o700)
        promoter_blob = bind_bytes_to_fd(
            protected_blobs[WORKBENCH_PROMOTER],
            binding_dir / "promote-staging-workbench-image.py.bound",
            "protected workbench image promoter",
        )
        bound.append(BoundRunner(WORKBENCH_PROMOTER, promoter_blob))
        promoter = bound[0]
        # The pin is a caller input, not a repository file.  Copy it into the
        # private transaction directory and bind its reviewed checksum before
        # the first cluster contact; the protected child receives only this
        # verified copy.
        artifact_pin_copy = temp / "artifact-pin.json"
        snapshot_owned_file_path(
            Path(args.workbench_artifact_pin),
            artifact_pin_copy,
            "workbench artifact pin",
            max_bytes=MAX_RECEIPT_BYTES,
        )
        require(file_sha256(artifact_pin_copy) == WORKBENCH_PROMOTION_ARTIFACT_RECEIPT_SHA256, "workbench artifact pin checksum drift")
        executable_dir = temp / "executables"; executable_dir.mkdir(mode=0o700)
        for label, source in sorted({"age": args.age_bin, "kubectl": args.kubectl_bin, "talosctl": args.talosctl_bin, "wireproxy": args.wireproxy_bin}.items()):
            snapshot = snapshot_binary(source, label, executable_dir / label)
            seal_pinned_snapshot(snapshot)
            snapshots[label] = snapshot; bindings[label] = PersistentPinnedExecutable(snapshot)
            cancellation.checkpoint()
        fsync_directory(executable_dir)
        wireguard = temp / "wireguard.conf"; talosconfig = temp / "talosconfig.yaml"
        decrypt(cancellation, bindings["age"], identity, encrypted_wg, wireguard)
        decrypt(cancellation, bindings["age"], identity, encrypted_talos, talosconfig)
        wireguard_bytes = wireguard.read_bytes(); wireguard.unlink(); fsync_directory(wireguard.parent)
        api_config = wireproxy_config(f"{API_HOST}:{API_PORT}", wireguard_bytes)
        talos_config = wireproxy_config(f"{API_HOST}:{TALOS_PORT}", wireguard_bytes)
        api_password = secrets.token_hex(32); talos_password = secrets.token_hex(32); credentials = [api_password, talos_password]
        for index, config in enumerate((api_config, talos_config)):
            config_blob = bind_bytes_to_fd(config, binding_dir / f"wireproxy-config-{index}.bound", f"workbench promotion fixed-target wireproxy config {index}")
            try:
                checked = cancellation.run(
                    [str(bindings["wireproxy"].path), "-n", "-c", f"/dev/fd/{config_blob.fd}"],
                    timeout=10,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=sanitized_environment(),
                    pass_fds=(config_blob.fd,),
                    executable_binding=bindings["wireproxy"],
                )
                require(checked.returncode == 0, f"wireproxy rejected protected fixed-target config {index}")
            finally:
                config_blob.close()
        session = LiveSession(bindings["wireproxy"], api_config, talos_config, binding_dir, api_password, talos_password, cancellation)
        api_port, talos_port = session.start_proxy(); listener_verified = session.listener_verified
        kubeconfig = temp / "admin-kubeconfig.json"
        create_admin_kubeconfig(
            session,
            bindings["talosctl"],
            bindings["kubectl"],
            talosconfig,
            kubeconfig,
            proxy_url(talos_password, talos_port),
            proxy_url(api_password, api_port),
            temp,
        )
        child_environment = sanitized_environment() | {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin"}
        child = session.run_child(
            workbench_promoter_command(
                promoter,
                snapshots["kubectl"],
                [
                    "--artifact-pin", str(artifact_pin_copy),
                    "--kubeconfig", str(kubeconfig),
                    "--receipt", str(promotion_receipt),
                    "--journal", str(promotion_journal),
                    "--protected-revision", revision,
                    "--protected-hashes", canonical(protected_hashes),
                ],
            ),
            child_environment,
            receipt_pending=True,
            pass_fds=(promoter.blob.fd, snapshots["kubectl"].fd),
        )
        try:
            require(child.returncode == 0, f"protected workbench image promoter exited {child.returncode}")
            receipt_bound = snapshot_owned_receipt(
                promotion_receipt,
                binding_dir / "workbench-promotion-receipt.bound",
                "workbench image promotion receipt",
            )
            journal_bound = snapshot_owned_receipt(
                promotion_journal,
                binding_dir / "workbench-promotion-journal.bound",
                "workbench image promotion journal",
            )
            evidence.extend((receipt_bound, journal_bound))
            proof = verify_workbench_image_promotion_evidence(
                receipt_bound,
                journal_bound,
                revision,
                protected_hashes,
                WORKBENCH_PROMOTION_ARTIFACT_RECEIPT_SHA256,
            )
            bindings["kubectl"]._verify()
            logging_error = best_effort_print_child(child)
            require(logging_error is None, logging_error or "protected workbench image promoter output forwarding failed")
            completed = True
        finally:
            session.receipt_reconciled()
    except BaseException as exc:
        error = str(exc) or type(exc).__name__
        best_effort_stderr(f"workbench image promotion wrapper blocked: {error}")
    if installed: cancellation.begin_finalization()
    session_cleanup: dict[str, Any] = {"wireproxyProcessGroupStopped": True, "allGuardWorkersStopped": True}
    if session is not None:
        try: session_cleanup = session.close()
        except BaseException as exc: cleanup_errors.append(f"transport cleanup: {exc}")
    process_cleanup = {"ownedProcessGroupsStopped": True, "ownedProcessGroupCount": 0}
    if installed:
        try: process_cleanup = cancellation.cleanup_processes()
        except BaseException as exc: cleanup_errors.append(f"process cleanup: {exc}")
    for snapshot in snapshots.values():
        try: unseal_pinned_snapshot(snapshot)
        except BaseException as exc: cleanup_errors.append(f"pinned snapshot unseal: {exc}")
        try: snapshot.close()
        except BaseException as exc: cleanup_errors.append(f"pinned snapshot close: {exc}")
    for item in evidence:
        try: item.close()
        except BaseException as exc: cleanup_errors.append(f"promotion evidence close: {exc}")
    for item in bound:
        try: item.close()
        except BaseException as exc: cleanup_errors.append(f"protected promoter close: {exc}")
    plaintext_removed = temp is None
    if temp is not None:
        try: shutil.rmtree(temp)
        except BaseException as exc: cleanup_errors.append(f"private promotion temp cleanup: {exc}")
        plaintext_removed = not temp.exists()
    cleanup_complete = (
        not cleanup_errors
        and session_cleanup.get("wireproxyProcessGroupStopped") is True
        and session_cleanup.get("allGuardWorkersStopped") is True
        and process_cleanup["ownedProcessGroupsStopped"] is True
        and plaintext_removed
    )
    status = "completed" if completed and cleanup_complete else ("completed-cleanup-incomplete" if completed else "blocked")
    payload = {
        "schemaVersion": WORKBENCH_PROMOTION_TRANSPORT_RECEIPT_SCHEMA,
        "status": status,
        "protectedRevision": revision,
        "protectedGitBlobSha256": protected_hashes,
        "binarySha256": {name: snapshot.sha256 for name, snapshot in sorted(snapshots.items())},
        "artifactPinSha256": WORKBENCH_PROMOTION_ARTIFACT_RECEIPT_SHA256,
        "targetImage": WORKBENCH_PROMOTION_TARGET_IMAGE,
        "transport": {
            "mode": "authenticated-exact-connect-guards-spawning-protected-workbench-promoter",
            "apiAuthority": f"{API_HOST}:{API_PORT}",
            "talosAuthority": f"{API_HOST}:{TALOS_PORT}",
            "listenerOwnershipAndAuthenticationVerified": listener_verified,
            "temporaryTransportStopped": session_cleanup.get("wireproxyProcessGroupStopped") is True,
            "plaintextTransportInputsRemoved": plaintext_removed,
        },
        "promotion": proof or {"receiptSha256": None, "journalSha256": None, "cleanupComplete": False},
        "resume": {
            "explicitReceiptPath": str(promotion_receipt),
            "explicitJournalPath": str(promotion_journal),
            "automaticRetry": False,
            "sameProtectedRevisionRequired": True,
        },
        "cleanup": {"complete": cleanup_complete, "errors": cleanup_errors, "processes": process_cleanup},
        "failure": error,
        "containsSecretMaterial": False,
        "civicAuthorityEffects": False,
        "automaticRetry": False,
    }
    committed = False
    if receipt_sink is not None:
        try:
            encoded = canonical(payload)
            require(not any(value in encoded for value in credentials), "workbench promotion wrapper receipt contains transport credential")
            receipt_sink.commit(payload); committed = True
        except BaseException as exc:
            best_effort_stderr(f"workbench image promotion wrapper receipt-incomplete: {exc}")
    if installed: cancellation.restore()
    return 0 if completed and cleanup_complete and committed else 3 if completed else 2


def main(argv: list[str] | None = None) -> int:
    receipt_dir: Path | None = None; receipt_sink: WrapperReceiptSink | None = None
    temp: Path | None = None; session: LiveSession | None = None
    cancellation = CancellationState(); cancellation_installed = False
    pinned_snapshots: dict[str, PinnedExecutableSnapshot] = {}
    revision: str | None = None; protected_hashes: dict[str, str] = {}; protected_blobs: dict[str, bytes] = {}
    snapshot_hashes: dict[str, str] = {}; credentials: list[str] = []
    bound_runners: dict[str, BoundRunner] = {}; bound_receipts: list[BoundBlob] = []
    handover_prebound: dict[tuple[str, str], BoundBlob] = {}; handover_prebound_owned: list[BoundBlob] = []
    verified_spawn_module: Any | None = None; executable_bindings: dict[str, Any] = {}
    source_dormant_receipt: BoundBlob | None = None; handover_archive_receipt: BoundBlob | None = None; handover_bound: BoundBlob | None = None; bootstrap_bound: BoundBlob | None = None
    recovery_bound: BoundBlob | None = None; teardown_bound: BoundBlob | None = None
    activation_bound: BoundBlob | None = None
    secret_config_input: BoundBlob | None = None; secret_runtime_input: BoundBlob | None = None
    source_secret_receipt: BoundBlob | None = None; secret_materialization_bound: BoundBlob | None = None
    secret_teardown_bound: BoundBlob | None = None
    bootstrap_receipt: Path | None = None; handover_receipt: Path | None = None; recovery_receipt: Path | None = None
    teardown_receipt: Path | None = None; activation_receipt: Path | None = None
    source_dormant_projection: dict[str, Any] | None = None
    bootstrap_projection: dict[str, Any] | None = None; handover_projection: dict[str, Any] | None = None
    teardown_projection: dict[str, Any] | None = None
    activation_projection: dict[str, Any] | None = None
    source_secret_projection: dict[str, Any] | None = None
    secret_materialization_projection: dict[str, Any] | None = None
    secret_teardown_projection: dict[str, Any] | None = None
    recovery_attempted = False; recovery_returncode: int | None = None
    child_cleanup_errors: list[str] = []
    base_status = "blocked"; error: str | None = None
    activation_committed = False; operation_succeeded = False
    listener_verified = False
    try:
        args = parse_args(argv)
        if args.workbench_baseline_handover or args.workbench_baseline_recovery or args.workbench_baseline_recovery_finalize:
            return run_workbench_baseline_handover_transport(args)
        if args.relay_fixture_reset:
            return run_relay_fixture_reset_transport(args)
        if args.workbench_image_promotion:
            return run_workbench_image_promotion_transport(args)
        require(sys.flags.isolated == 1 and bool(sys.flags.safe_path), "wrapper requires python3 -I isolated safe-path mode")
        require(args.live is True, "wrapper requires explicit --live")
        revision = args.expected_protected_revision
        require(REVISION.fullmatch(revision) is not None, "protected revision must be lowercase SHA-1")

        cancellation.install(); cancellation_installed = True
        receipt_dir = reserve_output_directory(args.receipt_directory)
        receipt_sink = WrapperReceiptSink.reserve(receipt_dir / "transport-transaction.json")
        cancellation.checkpoint()
        protected_hashes, protected_blobs = bind_protected_checkout(revision)
        verified_spawn_module = compile_verified_spawn_module(protected_blobs[ACTIVATION_RUNNER], revision)
        cancellation.checkpoint()

        identity = private_file(args.age_identity, "age identity")
        bundle_source = Path(os.path.abspath(args.bootstrap_bundle)); bundle_source_info = os.lstat(bundle_source)
        require(not stat.S_ISLNK(bundle_source_info.st_mode), "bootstrap bundle must not be a symlink")
        bundle = Path(os.path.realpath(bundle_source)); bundle_info = os.lstat(bundle)
        require(
            bundle == bundle_source
            and stat.S_ISDIR(bundle_info.st_mode)
            and bundle_info.st_uid == os.geteuid()
            and stat.S_IMODE(bundle_info.st_mode) & 0o077 == 0,
            "bootstrap bundle must be a private owned directory",
        )
        encrypted_wg = private_file(bundle / "wireguard-daily.conf.age", "encrypted WireGuard input")
        encrypted_talos = private_file(bundle / "talosconfig.yaml.age", "encrypted Talos input")

        temp = Path(tempfile.mkdtemp(prefix="roebel-participant-live-", dir="/private/tmp")); os.chmod(temp, 0o700)
        binding_dir = temp / "bindings"; binding_dir.mkdir(mode=0o700)
        for runner_path in (BOOTSTRAP_RUNNER, ACTIVATION_RUNNER, SECRET_RUNNER, HANDOVER_RUNNER):
            runner_blob = bind_bytes_to_fd(
                protected_blobs[runner_path],
                binding_dir / (Path(runner_path).name + ".bound"),
                f"protected runner {runner_path}",
            )
            bound_runners[runner_path] = BoundRunner(runner_path, runner_blob)
        if args.handover_dormant_receipt is not None:
            handover_prebound, handover_prebound_owned = bind_handover_git_closure(revision, binding_dir, protected_blobs)
        fsync_directory(binding_dir)
        cancellation.checkpoint()

        verifier_environment = sanitized_environment() | {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin"}
        if args.handover_dormant_receipt is not None:
            handover_archive_receipt = snapshot_owned_receipt(
                args.handover_dormant_receipt,
                binding_dir / "archived-dormant-receipt.bound",
                "archived dormant receipt",
            )
            bound_receipts.append(handover_archive_receipt)
            source_secret_receipt = snapshot_owned_receipt(
                args.participant_secret_materialization_receipt,
                binding_dir / "source-secret-materialization-receipt.bound",
                "source Secret materialization receipt",
            )
            bound_receipts.append(source_secret_receipt)
            # Verify both prior receipts against protected current code before
            # opening the transport.  The Secret verifier only inspects the
            # value-free receipt and never reads or rematerializes a Secret.
            source_secret_projection = verify_receipt_with_protected_cli(
                cancellation,
                bound_runners[ACTIVATION_RUNNER],
                "--verify-secret-materialization-receipt-fd",
                source_secret_receipt,
                revision,
                verifier_environment,
                "materialized",
                allow_cancelled=False,
                expected_projection_revision=HANDOVER_SECRET_RECEIPT_ORIGIN_REVISION,
            )
        elif args.teardown_dormant_receipt is not None:
            source_dormant_receipt = snapshot_owned_receipt(
                args.teardown_dormant_receipt,
                binding_dir / "source-dormant-receipt.bound",
                "source dormant receipt",
            )
            bound_receipts.append(source_dormant_receipt)
            source_dormant_projection = verify_receipt_with_protected_cli(
                cancellation,
                bound_runners[BOOTSTRAP_RUNNER],
                "--verify-success-receipt-fd",
                source_dormant_receipt,
                revision,
                verifier_environment,
                "dormant-ready",
                allow_cancelled=False,
            )
        elif args.teardown_participant_secret_receipt is not None:
            source_secret_receipt = snapshot_owned_receipt(
                args.teardown_participant_secret_receipt,
                binding_dir / "source-secret-materialization-receipt.bound",
                "source Secret materialization receipt",
            )
            bound_receipts.append(source_secret_receipt)
            source_secret_projection = verify_receipt_with_protected_cli(
                cancellation,
                bound_runners[SECRET_RUNNER],
                "--verify-materialization-receipt-fd",
                source_secret_receipt,
                revision,
                verifier_environment,
                "materialized",
                allow_cancelled=False,
            )
        else:
            bundle_source = Path(os.path.abspath(args.participant_secret_bundle)); bundle_source_info = os.lstat(bundle_source)
            require(not stat.S_ISLNK(bundle_source_info.st_mode), "participant Secret bundle must not be a symlink")
            secret_bundle = Path(os.path.realpath(bundle_source)); secret_bundle_info = os.lstat(secret_bundle)
            require(
                secret_bundle == bundle_source
                and stat.S_ISDIR(secret_bundle_info.st_mode)
                and secret_bundle_info.st_uid == os.geteuid()
                and stat.S_IMODE(secret_bundle_info.st_mode) & 0o077 == 0,
                "participant Secret bundle must be a private owned directory",
            )
            secret_config_input = snapshot_owned_receipt(
                private_file(secret_bundle / "config.env", "participant config input", 256 * 1024),
                binding_dir / "participant-config-input.bound",
                "participant config input",
            )
            secret_runtime_input = snapshot_owned_receipt(
                private_file(secret_bundle / "runtime.env", "participant runtime input", 256 * 1024),
                binding_dir / "participant-runtime-input.bound",
                "participant runtime input",
            )
            bound_receipts.extend((secret_config_input, secret_runtime_input))

        executable_dir = temp / "executables"; executable_dir.mkdir(mode=0o700)
        binary_sources = {
            "age": args.age_bin,
            "kubectl": args.kubectl_bin,
            "talosctl": args.talosctl_bin,
            "wireproxy": args.wireproxy_bin,
        }
        for label in sorted(binary_sources):
            snapshot = snapshot_binary(binary_sources[label], label, executable_dir / label)
            pinned_snapshots[label] = snapshot
            snapshot_hashes[label] = snapshot.sha256
            executable_bindings[label] = snapshot.to_binding(verified_spawn_module)
            cancellation.checkpoint()
        fsync_directory(executable_dir)

        wireguard = temp / "wireguard.conf"; talosconfig = temp / "talosconfig.yaml"
        decrypt(cancellation, executable_bindings["age"], identity, encrypted_wg, wireguard)
        decrypt(cancellation, executable_bindings["age"], identity, encrypted_talos, talosconfig)

        wireguard_bytes = wireguard.read_bytes()
        api_config = wireproxy_config(f"{API_HOST}:{API_PORT}", wireguard_bytes)
        talos_config = wireproxy_config(f"{API_HOST}:{TALOS_PORT}", wireguard_bytes)
        wireguard.unlink(); fsync_directory(wireguard.parent)
        api_password = secrets.token_hex(32); talos_password = secrets.token_hex(32)
        credentials = [api_password, talos_password]
        require(all(len(value) == 64 for value in credentials) and len(set(credentials)) == 2, "proxy CSPRNG failed")
        for index, config in enumerate((api_config, talos_config)):
            config_blob = bind_bytes_to_fd(
                config,
                binding_dir / f"wireproxy-config-test-{index}.bound",
                f"wireproxy fixed-target config test {index}",
            )
            try:
                config_test = cancellation.run(
                    [str(executable_bindings["wireproxy"].path), "-n", "-c", f"/dev/fd/{config_blob.fd}"],
                    timeout=10,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=sanitized_environment(),
                    pass_fds=(config_blob.fd,),
                    executable_binding=executable_bindings["wireproxy"],
                )
            finally:
                config_blob.close()
            cancellation.checkpoint()
            require(config_test.returncode == 0, f"wireproxy rejected protected fixed-target config {index}")

        session = LiveSession(
            executable_bindings["wireproxy"],
            api_config,
            talos_config,
            binding_dir,
            api_password,
            talos_password,
            cancellation,
        )
        api_guard_port, talos_guard_port = session.start_proxy()
        listener_verified = session.listener_verified
        kubeconfig = temp / "admin-kubeconfig.json"
        api_proxy = proxy_url(api_password, api_guard_port)
        talos_proxy = proxy_url(talos_password, talos_guard_port)
        create_admin_kubeconfig(
            session,
            executable_bindings["talosctl"],
            executable_bindings["kubectl"],
            talosconfig,
            kubeconfig,
            talos_proxy,
            api_proxy,
            temp,
        )
        child_environment = sanitized_environment() | {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin",
            **executable_bindings["kubectl"].environment("ROEBEL_PINNED_KUBECTL"),
        }
        bootstrap_runner = bound_runners[BOOTSTRAP_RUNNER]
        activation_runner = bound_runners[ACTIVATION_RUNNER]
        secret_runner = bound_runners[SECRET_RUNNER]
        handover_runner = bound_runners[HANDOVER_RUNNER]
        kubectl_fd = executable_bindings["kubectl"].fd
        participant_blob_args: list[str] = []
        participant_blob_fds: list[int] = []
        handover_blob_args: list[str] = []
        handover_blob_fds: list[int] = []
        for (blob_revision, blob_path), blob in sorted(handover_prebound.items()):
            descriptor = canonical({"revision": blob_revision, "path": blob_path, "fd": blob.fd, "size": blob.size, "sha256": blob.sha256})
            participant_blob_args.extend((
                "--prebound-blob",
                descriptor,
            ))
            participant_blob_fds.append(blob.fd)
            if (
                (blob_revision == revision and blob_path in HANDOVER_PREBOUND_CURRENT_PATHS)
                or (blob_revision == HANDOVER_ARCHIVE_REVISION and blob_path in HANDOVER_PREBOUND_ARCHIVE_PATHS)
            ):
                handover_blob_args.extend(("--prebound-blob", descriptor))
                handover_blob_fds.append(blob.fd)
        if handover_archive_receipt is not None:
            require(
                handover_blob_args
                and len(handover_blob_fds) + 2 == len(handover_prebound)
                and len(participant_blob_fds) == len(handover_prebound),
                "participant continuation protected Git closure was not prebound",
            )

        if handover_archive_receipt is not None:
            # Revalidate the current cluster against the archived dormant
            # receipt with a strictly GET-only protected child.  This creates
            # the value-free handover receipt consumed by activation below.
            handover_receipt = receipt_dir / "participant-flux-dormant-handover.json"
            handover = session.run_child(
                handover_runner.command([
                    "--live",
                    "--expected-protected-revision",
                    revision,
                    "--archived-bootstrap-receipt-fd",
                    str(handover_archive_receipt.fd),
                    "--kubeconfig",
                    str(kubeconfig),
                    "--receipt",
                    str(handover_receipt),
                    *handover_blob_args,
                ]),
                child_environment,
                forward_signals=False,
                pass_fds=(handover_runner.blob.fd, handover_archive_receipt.fd, kubectl_fd, *handover_blob_fds),
            )
            handover_verification_error: str | None = None
            try:
                if handover_receipt.exists():
                    handover_bound = snapshot_owned_receipt(
                        handover_receipt,
                        binding_dir / "handover-receipt.bound",
                        "dormant bootstrap handover receipt",
                    )
                    bound_receipts.append(handover_bound)
                    handover_projection = verify_receipt_with_protected_cli(
                        cancellation,
                        handover_runner,
                        "--verify-success-receipt-fd",
                        handover_bound,
                        revision,
                        child_environment,
                        "dormant-ready",
                        allow_cancelled=False,
                        extra_args=(
                            "--archived-bootstrap-receipt-fd",
                            str(handover_archive_receipt.fd),
                            *handover_blob_args,
                        ),
                        extra_pass_fds=(handover_archive_receipt.fd, *handover_blob_fds),
                    )
            except (LiveTransportError, OSError) as exc:
                handover_verification_error = str(exc)
            finally:
                session.receipt_reconciled()
            handover_logging_error = best_effort_print_child(handover)
            if handover_logging_error is not None:
                child_cleanup_errors.append(handover_logging_error)
            if handover_projection is None:
                base_status = "handover-state-indeterminate" if handover_bound is not None else "blocked"
                raise LiveTransportError(handover_verification_error or "dormant handover did not yield verified receipt")
            if handover.returncode != 0:
                child_cleanup_errors.append(f"protected dormant handover exited {handover.returncode} after durable commit")
                raise LiveTransportError("protected dormant handover cleanup incomplete after durable commit")
            # Continuation is a separate path: the archived handover already
            # proved the dormant Flux objects and the Secret receipt was bound
            # before transport.  Do not materialize Secrets or bootstrap Flux
            # again; invoke activation directly with the three exact receipt
            # descriptors while the GET-only transport is still alive.
            if cancellation.signals or not session.transport_alive():
                base_status = "handover-ready"
                raise LiveTransportError("activation cancelled after GET-only dormant handover; retry the explicit continuation")
            activation_receipt = receipt_dir / "participant-gateway-activation.json"
            require(handover_bound is not None and source_secret_receipt is not None, "handover activation bindings unavailable")
            activation_arguments = [
                "--archived-flux-bootstrap-receipt-fd",
                str(handover_archive_receipt.fd),
                "--dormant-bootstrap-handover-receipt-fd",
                str(handover_bound.fd),
                "--secret-materialization-receipt-fd",
                str(source_secret_receipt.fd),
            ]
            activation_fds = (
                activation_runner.blob.fd,
                handover_archive_receipt.fd,
                handover_bound.fd,
                source_secret_receipt.fd,
                kubectl_fd,
                *participant_blob_fds,
            )
            activation = session.run_child(
                activation_runner.command([
                    "--live",
                    "--expected-protected-revision",
                    revision,
                    "--kubeconfig",
                    str(kubeconfig),
                    *activation_arguments,
                    *participant_blob_args,
                    "--receipt",
                    str(activation_receipt),
                ]),
                child_environment,
                pass_fds=activation_fds,
            )
            try:
                require(activation_receipt.exists(), "activation runner produced no durable receipt")
                activation_bound = snapshot_owned_receipt(
                    activation_receipt,
                    binding_dir / "activation-receipt.bound",
                    "activation success receipt",
                )
                bound_receipts.append(activation_bound)
                activation_projection = verify_receipt_with_protected_cli(
                    cancellation,
                    activation_runner,
                    "--verify-success-receipt-fd",
                    activation_bound,
                    revision,
                    child_environment,
                    "activated",
                    allow_cancelled=True,
                    extra_args=tuple(participant_blob_args),
                    extra_pass_fds=tuple(participant_blob_fds),
                )
            finally:
                session.receipt_reconciled()
            activation_committed = True; operation_succeeded = True; base_status = "activated"
            activation_logging_error = best_effort_print_child(activation)
            if activation_logging_error is not None:
                child_cleanup_errors.append(activation_logging_error)
            if activation.returncode != 0:
                child_cleanup_errors.append(f"protected activation exited {activation.returncode} after durable commit")
                raise LiveTransportError("protected activation cleanup incomplete after durable commit")
        elif source_secret_receipt is not None:
            secret_teardown_receipt = receipt_dir / "participant-secret-teardown.json"
            secret_teardown = session.run_child(
                secret_runner.command([
                    "--teardown",
                    "--expected-protected-revision",
                    revision,
                    "--kubeconfig",
                    str(kubeconfig),
                    "--source-materialization-receipt-fd",
                    str(source_secret_receipt.fd),
                    "--receipt",
                    str(secret_teardown_receipt),
                ]),
                child_environment,
                allow_cancelled=True,
                forward_signals=False,
                receipt_pending=True,
                pass_fds=(secret_runner.blob.fd, source_secret_receipt.fd, kubectl_fd),
            )
            try:
                secret_teardown_bound = snapshot_owned_receipt(
                    secret_teardown_receipt,
                    binding_dir / "secret-teardown-receipt.bound",
                    "participant Secret teardown receipt",
                )
                bound_receipts.append(secret_teardown_bound)
                secret_teardown_projection = verify_receipt_with_protected_cli(
                    cancellation,
                    secret_runner,
                    "--verify-teardown-receipt-fd",
                    secret_teardown_bound,
                    revision,
                    child_environment,
                    "torn-down",
                    allow_cancelled=True,
                    expected_source_sha256=source_secret_projection["receiptSha256"],
                )
            finally:
                session.receipt_reconciled()
            logging_error = best_effort_print_child(secret_teardown)
            if logging_error is not None:
                child_cleanup_errors.append(logging_error)
            if secret_teardown.returncode != 0:
                child_cleanup_errors.append(f"protected Secret teardown exited {secret_teardown.returncode} after durable commit")
            base_status = "participant-secrets-torn-down"; operation_succeeded = True
        elif source_dormant_receipt is not None:
            teardown_receipt = receipt_dir / "participant-flux-dormant-teardown.json"
            teardown_projection, teardown_returncode, teardown_bound, teardown_logging_error = run_dormant_teardown(
                session,
                cancellation,
                bootstrap_runner,
                revision,
                kubeconfig,
                source_dormant_receipt,
                source_dormant_projection["receiptSha256"],
                teardown_receipt,
                binding_dir / "teardown-receipt.bound",
                child_environment,
                extra_pass_fds=(kubectl_fd,),
            )
            bound_receipts.append(teardown_bound)
            base_status = "dormant-torn-down"; operation_succeeded = True
            if teardown_logging_error is not None:
                child_cleanup_errors.append(teardown_logging_error)
            if teardown_returncode != 0:
                child_cleanup_errors.append(f"protected dormant teardown exited {teardown_returncode} after durable commit")
        else:
            secret_materialization_receipt = receipt_dir / "participant-secret-materialization.json"
            secret_materialization = session.run_child(
                secret_runner.command([
                    "--materialize",
                    "--expected-protected-revision",
                    revision,
                    "--kubeconfig",
                    str(kubeconfig),
                    "--config-input-fd",
                    str(secret_config_input.fd),
                    "--runtime-input-fd",
                    str(secret_runtime_input.fd),
                    "--receipt",
                    str(secret_materialization_receipt),
                ]),
                child_environment,
                forward_signals=False,
                pass_fds=(secret_runner.blob.fd, secret_config_input.fd, secret_runtime_input.fd, kubectl_fd),
            )
            try:
                require(secret_materialization_receipt.exists(), "Secret materializer produced no durable receipt")
                secret_materialization_bound = snapshot_owned_receipt(
                    secret_materialization_receipt,
                    binding_dir / "secret-materialization-receipt.bound",
                    "participant Secret materialization receipt",
                )
                bound_receipts.append(secret_materialization_bound)
                secret_materialization_projection = verify_receipt_with_protected_cli(
                    cancellation,
                    secret_runner,
                    "--verify-materialization-receipt-fd",
                    secret_materialization_bound,
                    revision,
                    child_environment,
                    "materialized",
                    allow_cancelled=True,
                )
            finally:
                session.receipt_reconciled()
            materialization_logging_error = best_effort_print_child(secret_materialization)
            if materialization_logging_error is not None:
                child_cleanup_errors.append(materialization_logging_error)
            require(secret_materialization.returncode == 0, "protected Secret materialization did not complete cleanly")

            bootstrap_receipt = receipt_dir / "participant-flux-bootstrap.json"
            bootstrap = session.run_child(
                bootstrap_runner.command([
                    "--live",
                    "--expected-protected-revision",
                    revision,
                    "--kubeconfig",
                    str(kubeconfig),
                    "--receipt",
                    str(bootstrap_receipt),
                ]),
                child_environment,
                pass_fds=(bootstrap_runner.blob.fd, kubectl_fd),
            )
            bootstrap_verification_error: str | None = None
            try:
                if bootstrap_receipt.exists():
                    bootstrap_bound = snapshot_owned_receipt(
                        bootstrap_receipt,
                        binding_dir / "bootstrap-receipt.bound",
                        "dormant bootstrap receipt",
                    )
                    bound_receipts.append(bootstrap_bound)
                    bootstrap_projection = verify_receipt_with_protected_cli(
                        cancellation,
                        bootstrap_runner,
                        "--verify-success-receipt-fd",
                        bootstrap_bound,
                        revision,
                        child_environment,
                        "dormant-ready",
                        allow_cancelled=True,
                    )
            except (LiveTransportError, OSError) as exc:
                bootstrap_verification_error = str(exc)
            finally:
                session.receipt_reconciled()
            if bootstrap_projection is not None:
                bootstrap_logging_error = best_effort_print_child(bootstrap)
                if bootstrap_logging_error is not None:
                    base_status = "dormant-ready"
                    child_cleanup_errors.append(bootstrap_logging_error)
                    raise LiveTransportError("bootstrap committed but output evidence forwarding failed")
            if bootstrap_projection is None:
                if bootstrap.returncode != 0 and bootstrap_bound is not None and session.transport_alive():
                    recovery_attempted = True
                    recovery_receipt = receipt_dir / "participant-flux-bootstrap-recovery.json"
                    recovery = session.run_child(
                        bootstrap_runner.command([
                            "--recover",
                            "--expected-protected-revision",
                            revision,
                            "--kubeconfig",
                            str(kubeconfig),
                            "--recovery-receipt-fd",
                            str(bootstrap_bound.fd),
                            "--receipt",
                            str(recovery_receipt),
                        ]),
                        child_environment,
                        allow_cancelled=True,
                        forward_signals=False,
                        receipt_pending=True,
                        pass_fds=(bootstrap_runner.blob.fd, bootstrap_bound.fd, kubectl_fd),
                    )
                    recovery_returncode = recovery.returncode; best_effort_print_child(recovery); session.receipt_reconciled()
                    if recovery_receipt.exists():
                        recovery_bound = snapshot_owned_receipt(
                            recovery_receipt,
                            binding_dir / "recovery-receipt.bound",
                            "bootstrap recovery receipt",
                        )
                        bound_receipts.append(recovery_bound)
                detail = bootstrap_verification_error or "no durable verified success receipt"
                raise LiveTransportError(f"dormant Flux bootstrap did not yield verified success: {detail}")
            if bootstrap.returncode != 0:
                base_status = "dormant-ready"
                child_cleanup_errors.append(f"protected dormant bootstrap exited {bootstrap.returncode} after durable commit")
                raise LiveTransportError("protected dormant bootstrap cleanup incomplete after durable commit")

            if cancellation.signals or not session.transport_alive():
                if handover_archive_receipt is not None:
                    base_status = "handover-ready"
                    raise LiveTransportError("activation cancelled after GET-only dormant handover; retry the explicit continuation")
                if session.transport_alive():
                    teardown_receipt = receipt_dir / "participant-flux-dormant-teardown.json"
                    teardown_projection, teardown_returncode, teardown_bound, teardown_logging_error = run_dormant_teardown(
                        session,
                        cancellation,
                        bootstrap_runner,
                        revision,
                        kubeconfig,
                        bootstrap_bound,
                        bootstrap_projection["receiptSha256"],
                        teardown_receipt,
                        binding_dir / "teardown-receipt.bound",
                        child_environment,
                        extra_pass_fds=(kubectl_fd,),
                    )
                    bound_receipts.append(teardown_bound)
                    base_status = "cancelled-dormant-torn-down" if cancellation.signals else "transport-lost-dormant-torn-down"
                    if teardown_logging_error is not None:
                        child_cleanup_errors.append(teardown_logging_error)
                    if teardown_returncode != 0:
                        child_cleanup_errors.append(f"protected dormant teardown exited {teardown_returncode} after durable commit")
                    raise LiveTransportError("activation cancelled after exact dormant teardown")
                base_status = "dormant-cleanup-required"
                raise LiveTransportError("verified dormant bootstrap lost transport; exact teardown continuation required")

            activation_receipt = receipt_dir / "participant-gateway-activation.json"
            if handover_archive_receipt is not None:
                require(handover_bound is not None and source_secret_receipt is not None, "handover activation bindings unavailable")
                activation_arguments = [
                    "--archived-flux-bootstrap-receipt-fd",
                    str(handover_archive_receipt.fd),
                    "--dormant-bootstrap-handover-receipt-fd",
                    str(handover_bound.fd),
                    "--secret-materialization-receipt-fd",
                    str(source_secret_receipt.fd),
                ]
                activation_fds = (activation_runner.blob.fd, handover_archive_receipt.fd, handover_bound.fd, source_secret_receipt.fd, kubectl_fd)
            else:
                require(bootstrap_bound is not None, "dormant bootstrap activation binding unavailable")
                activation_arguments = ["--flux-bootstrap-receipt-fd", str(bootstrap_bound.fd)]
                activation_fds = (activation_runner.blob.fd, bootstrap_bound.fd, kubectl_fd)
            activation = session.run_child(
                activation_runner.command([
                    "--live",
                    "--expected-protected-revision",
                    revision,
                    "--kubeconfig",
                    str(kubeconfig),
                    *activation_arguments,
                    "--receipt",
                    str(activation_receipt),
                ]),
                child_environment,
                pass_fds=activation_fds,
            )
            try:
                require(activation_receipt.exists(), "activation runner produced no durable receipt")
                activation_bound = snapshot_owned_receipt(
                    activation_receipt,
                    binding_dir / "activation-receipt.bound",
                    "activation success receipt",
                )
                bound_receipts.append(activation_bound)
                activation_projection = verify_receipt_with_protected_cli(
                    cancellation,
                    activation_runner,
                    "--verify-success-receipt-fd",
                    activation_bound,
                    revision,
                    child_environment,
                    "activated",
                    allow_cancelled=True,
                )
            finally:
                session.receipt_reconciled()
            activation_committed = True; operation_succeeded = True; base_status = "activated"
            activation_logging_error = best_effort_print_child(activation)
            if activation_logging_error is not None:
                child_cleanup_errors.append(activation_logging_error)
            if activation.returncode != 0:
                child_cleanup_errors.append(f"protected activation exited {activation.returncode} after durable commit")
                raise LiveTransportError("protected activation cleanup incomplete after durable commit")
    except BaseException as exc:
        error = str(exc) or type(exc).__name__
        if (
            bootstrap_projection is not None
            and activation_projection is None
            and teardown_projection is None
            and base_status == "blocked"
        ):
            base_status = "bootstrap-state-indeterminate"
        best_effort_stderr(f"participant live wrapper blocked: {error}")

    if cancellation_installed: cancellation.begin_finalization()
    cleanup_errors: list[str] = list(child_cleanup_errors)
    session_cleanup: dict[str, Any] = {
        "apiGuard": {"listenerStopped": True, "workerThreadsStopped": True, "connectionsClosed": True, "tunnelProcessGroupsStopped": True, "workerLimit": 16},
        "talosGuard": {"listenerStopped": True, "workerThreadsStopped": True, "connectionsClosed": True, "tunnelProcessGroupsStopped": True, "workerLimit": 16},
        "wireproxyProcessGroupStopped": True,
        "allGuardWorkersStopped": True,
    }
    if session is not None:
        try: session_cleanup = session.close()
        except BaseException as exc:
            cleanup_errors.append(f"transport cleanup: {exc}")
            session_cleanup["wireproxyProcessGroupStopped"] = False
            session_cleanup["allGuardWorkersStopped"] = False
    process_cleanup = {"ownedProcessGroupsStopped": True, "ownedProcessGroupCount": 0}
    if cancellation_installed:
        try: process_cleanup = cancellation.cleanup_processes()
        except BaseException as exc:
            cleanup_errors.append(f"process-group cleanup: {exc}")
            process_cleanup["ownedProcessGroupsStopped"] = False
    bindings_closed = True
    for snapshot in pinned_snapshots.values():
        try: snapshot.close()
        except BaseException as exc:
            bindings_closed = False; cleanup_errors.append(f"pinned snapshot cleanup: {exc}")
    for receipt in bound_receipts:
        try: receipt.close()
        except BaseException as exc:
            bindings_closed = False; cleanup_errors.append(f"receipt binding cleanup: {exc}")
    for binding in executable_bindings.values():
        try: binding.close()
        except BaseException as exc:
            bindings_closed = False; cleanup_errors.append(f"executable binding cleanup: {exc}")
    for runner in bound_runners.values():
        try: runner.close()
        except BaseException as exc:
            bindings_closed = False; cleanup_errors.append(f"runner binding cleanup: {exc}")
    for item in handover_prebound_owned:
        try: item.close()
        except BaseException as exc:
            bindings_closed = False; cleanup_errors.append(f"handover Git blob cleanup: {exc}")
    plaintext_removed = temp is None
    if temp is not None:
        try: shutil.rmtree(temp)
        except BaseException as exc: cleanup_errors.append(f"private temp cleanup: {exc}")
        plaintext_removed = not temp.exists()
        if not plaintext_removed: cleanup_errors.append("private temp directory remains")

    cleanup_complete = (
        not cleanup_errors
        and session_cleanup["wireproxyProcessGroupStopped"]
        and session_cleanup["allGuardWorkersStopped"]
        and process_cleanup["ownedProcessGroupsStopped"]
        and bindings_closed
        and plaintext_removed
    )

    source_record = receipt_record(source_dormant_projection, source_dormant_receipt)
    source_secret_record = receipt_record(source_secret_projection, source_secret_receipt)
    secret_materialization_record = receipt_record(secret_materialization_projection, secret_materialization_bound)
    secret_teardown_record = receipt_record(secret_teardown_projection, secret_teardown_bound)
    bootstrap_record = receipt_record(bootstrap_projection, bootstrap_bound)
    handover_record = receipt_record(handover_projection, handover_bound)
    teardown_record = receipt_record(teardown_projection, teardown_bound)
    activation_record = receipt_record(activation_projection, activation_bound)
    recovery_record = receipt_record(None, recovery_bound)
    status, exit_code = classify_final_status(
        base_status,
        activation_committed=activation_committed,
        operation_succeeded=operation_succeeded,
        cleanup_complete=cleanup_complete,
    )
    interrupted = bool(cancellation.signals)
    wrapper_receipt = {
        "schemaVersion": WRAPPER_RECEIPT_SCHEMA,
        "status": status,
        "protectedRevision": revision,
        "protectedGitBlobSha256": protected_hashes,
        "binarySha256": {
            "expected": {name: EXPECTED_BINARIES[name] for name in sorted(EXPECTED_BINARIES)},
            "ownedExecutableSnapshots": snapshot_hashes,
        },
        "transport": {
            "mode": "authenticated-exact-connect-guards-spawning-fixed-wireproxy-stdio-tunnels",
            "apiAuthority": f"{API_HOST}:{API_PORT}",
            "talosAuthority": f"{API_HOST}:{TALOS_PORT}",
            "perRunFrontAuthentication": True,
            "rawBackendListeners": False,
            "callerSelectedDestination": False,
            "listenerOwnershipAndAuthenticationVerified": listener_verified,
            "temporaryTransportStopped": session_cleanup["wireproxyProcessGroupStopped"],
            "allGuardWorkersStopped": session_cleanup["allGuardWorkersStopped"],
            "plaintextTransportInputsRemoved": plaintext_removed,
        },
        "cleanup": {
            "complete": cleanup_complete,
            "errors": cleanup_errors,
            "session": session_cleanup,
            "processes": process_cleanup,
            "immutableBindingsClosed": bindings_closed,
            "protectedChildExitClean": not child_cleanup_errors,
            "wrapperReceiptCommit": "atomic-replace-file-and-parent-fsync",
        },
        "sourceDormant": source_record,
        "sourceArchivedDormant": {
            "fileSha256": handover_archive_receipt.sha256 if handover_archive_receipt is not None else None,
            "canonicalSha256": None,
            "status": "archived-input-bound" if handover_archive_receipt is not None else None,
        },
        "sourceSecretMaterialization": source_secret_record,
        "secretMaterialization": secret_materialization_record,
        "secretTeardown": secret_teardown_record,
        "bootstrap": bootstrap_record,
        "handover": handover_record,
        "recovery": recovery_record | {"attempted": recovery_attempted, "runnerReturnCode": recovery_returncode},
        "teardown": teardown_record,
        "activation": activation_record,
        "dormantContinuation": {
            "required": base_status in {"dormant-cleanup-required", "bootstrap-state-indeterminate", "dormant-ready"},
            "mode": "--handover-dormant-receipt" if handover_archive_receipt is not None else "--teardown-dormant-receipt",
            "requiresClosedDormantPreflight": True,
            "requiresExistingSecretMaterializationReceipt": handover_archive_receipt is not None,
            "handoverReceiptSha256": handover_projection.get("receiptSha256") if handover_projection is not None else None,
            "adoptsArbitraryObjects": False,
        },
        "secretContinuation": {
            "required": secret_materialization_projection is not None and not activation_committed and secret_teardown_projection is None,
            "mode": "--teardown-participant-secret-receipt",
            "requiresParticipantDeactivation": True,
            "sourceReceiptSha256": secret_materialization_projection.get("receiptSha256") if secret_materialization_projection is not None else None,
            "deletesOnlyReceiptBoundUidResourceVersions": True,
        },
        "interrupted": interrupted,
        "signalsObserved": cancellation.signals,
        "failure": error,
        "containsSecretMaterial": False,
        "civicAuthorityEffects": False,
        "automaticRetry": False,
    }
    receipt_committed = False
    if receipt_sink is not None:
        try:
            encoded = canonical(wrapper_receipt)
            require(not any(value in encoded for value in credentials), "wrapper receipt contains a transport credential")
            receipt_sink.commit(wrapper_receipt); receipt_committed = True
        except BaseException as exc:
            exit_code = 3
            label = "activated-cleanup-incomplete" if activation_committed else f"{status}-receipt-incomplete"
            best_effort_stderr(f"participant live wrapper {label}: durable wrapper receipt failed: {exc}")
    else:
        exit_code = 3
        best_effort_stderr("participant live wrapper receipt-incomplete: wrapper receipt target unavailable")
    if cancellation_installed: cancellation.restore()
    if activation_committed and (not cleanup_complete or not receipt_committed):
        return 3
    return exit_code

if __name__ == "__main__":
    raise SystemExit(main())
