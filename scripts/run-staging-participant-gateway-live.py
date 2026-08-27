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

import argparse, base64, hashlib, json, os, re, secrets, select, shutil, signal, socket, stat, subprocess, sys, tempfile, threading, time, types
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SELF_PATH = "scripts/run-staging-participant-gateway-live.py"
BOOTSTRAP_RUNNER = "scripts/bootstrap-staging-participant-flux.py"
ACTIVATION_RUNNER = "scripts/activate-staging-participant-gateway.py"
WORKBENCH_RUNNER = "scripts/handover-staging-workbench-baseline.py"
WORKBENCH_IMPLEMENTATION = "scripts/workbench_baseline_handover.py"
PROTECTED_PATHS = (
    SELF_PATH,
    BOOTSTRAP_RUNNER,
    ACTIVATION_RUNNER,
    "scripts/staging_participant_flux_bootstrap.py",
    "scripts/staging_participant_gateway_policy.py",
    "policy/staging-participant-gateway-activation-policy.json",
    ".github/workflows/staging-participant-flux-bootstrap.yml",
    ".github/workflows/staging-participant-gateway-activation.yml",
    "scripts/verify-reviewed-render.py",
    "policy/repository-contract.json",
)
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
WRAPPER_RECEIPT_SCHEMA = "roebel_staging_participant_live_transport_receipt_v2"
WORKBENCH_TRANSPORT_RECEIPT_SCHEMA = "roebel_staging_workbench_baseline_live_transport_receipt_v1"
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
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

    @staticmethod
    def _read_head(connection: socket.socket) -> tuple[bytes, bytes]:
        value = bytearray(); connection.settimeout(5)
        while b"\r\n\r\n" not in value:
            try: chunk = connection.recv(2048)
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
) -> dict[str, Any]:
    result = cancellation.run(
        runner.command([mode, str(receipt.fd), "--expected-protected-revision", revision]),
        allow_cancelled=allow_cancelled,
        forward_signals=False,
        receipt_pending=False,
        timeout=60,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
        pass_fds=(runner.blob.fd, receipt.fd),
    )
    require(result.returncode == 0, f"protected receipt verifier rejected {receipt.label}")
    output = result.stdout.strip() if isinstance(result.stdout, str) else ""
    require(output and "\n" not in output, f"protected receipt verifier output invalid: {receipt.label}")
    projection = json_object(output, f"verified {receipt.label}")
    require(projection.get("status") == expected_status, f"protected receipt status drift: {receipt.label}")
    require(projection.get("protectedRevision") == revision, f"protected receipt revision drift: {receipt.label}")
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


def read_bound_json(receipt: BoundBlob, label: str) -> dict[str, Any]:
    raw = os.pread(receipt.fd, receipt.size + 1, 0)
    require(len(raw) == receipt.size, f"{label} bound receipt size drift")
    return json_object(raw.decode("utf-8"), label)


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

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    # Omission preserves the pre-existing participant transaction CLI.  The
    # explicit participant flag is useful only when automation wants a fully
    # self-documenting mode selection.
    mode.add_argument("--participant-gateway", action="store_true")
    mode.add_argument("--workbench-baseline-handover", action="store_true")
    parser.add_argument("--expected-protected-revision", required=True)
    parser.add_argument("--age-bin", required=True, type=Path)
    parser.add_argument("--age-identity", required=True, type=Path)
    parser.add_argument("--bootstrap-bundle", required=True, type=Path)
    parser.add_argument("--wireproxy-bin", required=True, type=Path)
    parser.add_argument("--talosctl-bin", required=True, type=Path)
    parser.add_argument("--kubectl-bin", required=True, type=Path)
    parser.add_argument("--receipt-directory", required=True, type=Path)
    parser.add_argument("--teardown-dormant-receipt", type=Path)
    parser.add_argument("--workbench-handover-receipt", type=Path)
    parser.add_argument("--workbench-handover-journal", type=Path)
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args(argv)
    if args.workbench_baseline_handover:
        require(args.teardown_dormant_receipt is None, "workbench handover may not request participant teardown")
        require(args.workbench_handover_receipt is not None and args.workbench_handover_journal is not None, "workbench handover requires explicit receipt and journal paths for resume")
    else:
        require(args.workbench_handover_receipt is None and args.workbench_handover_journal is None, "participant mode may not receive workbench handover paths")
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
    handover_receipt: Path | None = None; handover_journal: Path | None = None
    try:
        require(sys.flags.isolated == 1 and bool(sys.flags.safe_path), "wrapper requires python3 -I isolated safe-path mode")
        require(args.live is True and args.workbench_baseline_handover is True, "workbench transport requires explicit --workbench-baseline-handover --live")
        require(REVISION.fullmatch(revision) is not None, "protected revision must be lowercase SHA-1")
        handover_receipt = private_workbench_output(args.workbench_handover_receipt, "workbench handover receipt")
        handover_journal = private_workbench_output(args.workbench_handover_journal, "workbench handover journal")
        require(
            os.path.normcase(os.path.normpath(os.fspath(handover_receipt))) != os.path.normcase(os.path.normpath(os.fspath(handover_journal))),
            "workbench handover receipt and journal paths must be distinct",
        )
        cancellation.install(); installed = True
        receipt_dir = reserve_output_directory(args.receipt_directory)
        attempt_path = receipt_dir / "workbench-baseline-transport-attempt.json"
        receipt_sink = WrapperReceiptSink.reserve(attempt_path)
        cancellation.checkpoint()
        protected_hashes, protected_blobs = bind_protected_checkout(revision, paths=WORKBENCH_PROTECTED_PATHS)
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
        # Bind both blobs.  Only the implementation blob is executed; the
        # companion runner blob is a separately retained review identity.
        for logical_path in (WORKBENCH_RUNNER, WORKBENCH_IMPLEMENTATION):
            blob = bind_bytes_to_fd(protected_blobs[logical_path], binding_dir / (Path(logical_path).name + ".bound"), f"protected workbench blob {logical_path}")
            bound.append(BoundRunner(logical_path, blob))
        implementation = next(item for item in bound if item.logical_path == WORKBENCH_IMPLEMENTATION)
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
        child = session.run_child(
            workbench_implementation_command(
                implementation,
                snapshots["kubectl"],
                ["--expected-protected-revision", revision, "--kubeconfig", str(kubeconfig), "--receipt", str(handover_receipt), "--journal", str(handover_journal)],
            ),
            child_environment,
            receipt_pending=True,
            pass_fds=(implementation.blob.fd, snapshots["kubectl"].fd),
        )
        try:
            require(child.returncode == 0, f"protected workbench handover exited {child.returncode}")
            receipt_bound = snapshot_owned_receipt(handover_receipt, binding_dir / "workbench-handover-receipt.bound", "workbench handover receipt")
            journal_bound = snapshot_owned_receipt(handover_journal, binding_dir / "workbench-handover-journal.bound", "workbench handover journal")
            evidence.extend((receipt_bound, journal_bound))
            proof = verify_workbench_handover_evidence(receipt_bound, journal_bound, revision, protected_hashes)
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
        "schemaVersion": WORKBENCH_TRANSPORT_RECEIPT_SCHEMA,
        "status": status,
        "protectedRevision": revision,
        "protectedGitBlobSha256": protected_hashes,
        "binarySha256": {name: snapshot.sha256 for name, snapshot in sorted(snapshots.items())},
        "transport": {"mode": "authenticated-exact-connect-guards-spawning-fixed-wireproxy-stdio-tunnels", "apiAuthority": f"{API_HOST}:{API_PORT}", "talosAuthority": f"{API_HOST}:{TALOS_PORT}", "listenerOwnershipAndAuthenticationVerified": listener_verified, "temporaryTransportStopped": session_cleanup.get("wireproxyProcessGroupStopped") is True, "plaintextTransportInputsRemoved": plaintext_removed},
        "handover": proof or {"receiptSha256": None, "journalSha256": None, "networkPolicyUid": None, "fluxObjectUids": {}, "ready": False},
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


def main(argv: list[str] | None = None) -> int:
    receipt_dir: Path | None = None; receipt_sink: WrapperReceiptSink | None = None
    temp: Path | None = None; session: LiveSession | None = None
    cancellation = CancellationState(); cancellation_installed = False
    pinned_snapshots: dict[str, PinnedExecutableSnapshot] = {}
    revision: str | None = None; protected_hashes: dict[str, str] = {}; protected_blobs: dict[str, bytes] = {}
    snapshot_hashes: dict[str, str] = {}; credentials: list[str] = []
    bound_runners: dict[str, BoundRunner] = {}; bound_receipts: list[BoundBlob] = []
    verified_spawn_module: Any | None = None; executable_bindings: dict[str, Any] = {}
    source_dormant_receipt: BoundBlob | None = None; bootstrap_bound: BoundBlob | None = None
    recovery_bound: BoundBlob | None = None; teardown_bound: BoundBlob | None = None
    activation_bound: BoundBlob | None = None
    bootstrap_receipt: Path | None = None; recovery_receipt: Path | None = None
    teardown_receipt: Path | None = None; activation_receipt: Path | None = None
    source_dormant_projection: dict[str, Any] | None = None
    bootstrap_projection: dict[str, Any] | None = None
    teardown_projection: dict[str, Any] | None = None
    activation_projection: dict[str, Any] | None = None
    recovery_attempted = False; recovery_returncode: int | None = None
    child_cleanup_errors: list[str] = []
    base_status = "blocked"; error: str | None = None
    activation_committed = False; operation_succeeded = False
    listener_verified = False
    try:
        args = parse_args(argv)
        if args.workbench_baseline_handover:
            return run_workbench_baseline_handover_transport(args)
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
        for runner_path in (BOOTSTRAP_RUNNER, ACTIVATION_RUNNER):
            runner_blob = bind_bytes_to_fd(
                protected_blobs[runner_path],
                binding_dir / (Path(runner_path).name + ".bound"),
                f"protected runner {runner_path}",
            )
            bound_runners[runner_path] = BoundRunner(runner_path, runner_blob)
        fsync_directory(binding_dir)
        cancellation.checkpoint()

        verifier_environment = sanitized_environment() | {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin"}
        if args.teardown_dormant_receipt is not None:
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
        kubectl_fd = executable_bindings["kubectl"].fd

        if source_dormant_receipt is not None:
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
            activation = session.run_child(
                activation_runner.command([
                    "--live",
                    "--expected-protected-revision",
                    revision,
                    "--kubeconfig",
                    str(kubeconfig),
                    "--flux-bootstrap-receipt-fd",
                    str(bootstrap_bound.fd),
                    "--receipt",
                    str(activation_receipt),
                ]),
                child_environment,
                pass_fds=(activation_runner.blob.fd, bootstrap_bound.fd, kubectl_fd),
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
    bootstrap_record = receipt_record(bootstrap_projection, bootstrap_bound)
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
        "bootstrap": bootstrap_record,
        "recovery": recovery_record | {"attempted": recovery_attempted, "runnerReturnCode": recovery_returncode},
        "teardown": teardown_record,
        "activation": activation_record,
        "dormantContinuation": {
            "required": base_status in {"dormant-cleanup-required", "bootstrap-state-indeterminate", "dormant-ready"},
            "mode": "--teardown-dormant-receipt",
            "requiresClosedDormantPreflight": True,
            "adoptsArbitraryObjects": False,
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
