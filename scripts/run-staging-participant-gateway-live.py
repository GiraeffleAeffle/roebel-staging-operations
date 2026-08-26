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

import argparse, hashlib, json, os, re, secrets, shutil, signal, socket, stat, subprocess, sys, tempfile, time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SELF_PATH = "scripts/run-staging-participant-gateway-live.py"
BOOTSTRAP_RUNNER = "scripts/bootstrap-staging-participant-flux.py"
ACTIVATION_RUNNER = "scripts/activate-staging-participant-gateway.py"
API_HOST, API_PORT = "10.255.240.11", 6443
PROXY_USERNAME = "stadtstack-participant"
WRAPPER_RECEIPT_SCHEMA = "roebel_staging_participant_live_transport_receipt_v1"
SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
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

def load_json(path: Path) -> dict[str, Any]:
    try: value = json.loads(path.read_text(), object_pairs_hook=_unique_object)
    except (OSError, ValueError) as exc: raise LiveTransportError(f"durable runner receipt unreadable: {path.name}") from exc
    require(isinstance(value, dict), "durable runner receipt must be an object")
    return value

def reserve_output_directory(path: Path) -> Path:
    path = Path(os.path.realpath(os.path.abspath(path)))
    require(path.is_absolute() and not path.exists() and not path.is_symlink(), "receipt directory must be a new absolute path")
    parent = path.parent; info = os.lstat(parent)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) & 0o022 == 0, "receipt parent is not private and owned")
    path.mkdir(mode=0o700)
    return path

def private_file(path: Path, label: str) -> Path:
    source = Path(os.path.abspath(path)); source_info = os.lstat(source)
    require(not stat.S_ISLNK(source_info.st_mode), f"{label} must not be a symlink")
    resolved = Path(os.path.realpath(source)); info = os.lstat(resolved)
    require(resolved == source and stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) & 0o077 == 0, f"{label} must be a private owned regular file")
    return resolved

def pinned_binary(path: Path, label: str) -> Path:
    resolved = Path(path).expanduser().resolve(strict=True); info = os.stat(resolved)
    require(stat.S_ISREG(info.st_mode) and os.access(resolved, os.X_OK), f"{label} must resolve to a regular executable")
    require(file_sha256(resolved) == EXPECTED_BINARIES[label], f"{label} binary digest differs")
    return resolved

def exact_checkout(revision: str) -> None:
    require(re.fullmatch(r"[0-9a-f]{40}", revision) is not None, "protected revision must be lowercase SHA-1")
    head = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True, capture_output=True, check=False)
    require(head.returncode == 0 and head.stdout.strip() == revision, "checkout is not the expected protected revision")
    blob = subprocess.run(["git", "-C", str(ROOT), "show", f"{revision}:{SELF_PATH}"], capture_output=True, check=False)
    require(blob.returncode == 0 and blob.stdout == (ROOT / SELF_PATH).read_bytes(), "live wrapper is not the exact protected Git blob")
    dirty = subprocess.run(["git", "-C", str(ROOT), "diff", "--quiet", revision, "--", SELF_PATH], check=False)
    cached = subprocess.run(["git", "-C", str(ROOT), "diff", "--cached", "--quiet", revision, "--", SELF_PATH], check=False)
    require(dirty.returncode == 0 and cached.returncode == 0, "live wrapper checkout is dirty")

def wireproxy_config(password: str, port: int) -> str:
    require(re.fullmatch(r"[0-9a-f]{64}", password) is not None, "proxy credential must be CSPRNG hex")
    require(1024 <= port <= 65535, "proxy port outside unprivileged range")
    return (
        "WGConfig = wireguard.conf\n\n"
        "[http]\n"
        f"BindAddress = 127.0.0.1:{port}\n"
        f"Username = {PROXY_USERNAME}\n"
        f"Password = {password}\n"
        r"TunnelDomains = ^10\.255\.240\.11$" + "\n"
        "LogDomains = false\n"
    )

def proxy_url(password: str, port: int) -> str:
    require(re.fullmatch(r"[0-9a-f]{64}", password) is not None, "proxy credential must be CSPRNG hex")
    require(1024 <= port <= 65535, "proxy port outside unprivileged range")
    return f"http://{PROXY_USERNAME}:{password}@127.0.0.1:{port}"

def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0)); return int(listener.getsockname()[1])

def sanitized_environment() -> dict[str, str]:
    blocked = {"http_proxy", "https_proxy", "all_proxy", "no_proxy", "kubeconfig", "pythonpath"}
    return {key: value for key, value in os.environ.items() if key.lower() not in blocked}

def write_private(path: Path, value: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"): flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream: fd = -1; stream.write(value); stream.flush(); os.fsync(stream.fileno())
    finally:
        if fd >= 0: os.close(fd)

def decrypt(age: Path, identity: Path, source: Path, destination: Path) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"): flags |= os.O_NOFOLLOW
    fd = os.open(destination, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            fd = -1
            result = subprocess.run([str(age), "--decrypt", "--identity", str(identity), str(source)], stdout=stream, stderr=subprocess.PIPE, check=False)
            stream.flush(); os.fsync(stream.fileno())
        require(result.returncode == 0, "encrypted transport input could not be decrypted")
    finally:
        if fd >= 0: os.close(fd)

def stop_process(process: subprocess.Popen[Any] | None) -> None:
    if process is None or process.poll() is not None: return
    try: os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError: return
    try: process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try: os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        process.wait(timeout=5)

@dataclass
class ChildResult:
    returncode: int
    stdout: str
    stderr: str

class LiveSession:
    def __init__(self, temp: Path, proxy_binary: Path, password: str, port: int):
        self.temp, self.proxy_binary, self.password, self.port = temp, proxy_binary, password, port
        self.proxy: subprocess.Popen[Any] | None = None
        self.child: subprocess.Popen[Any] | None = None
        self.signals: list[int] = []
        self.listener_verified = False

    def handle_signal(self, received: int, _frame: Any) -> None:
        self.signals.append(received)
        if self.child is not None and self.child.poll() is None:
            try: os.killpg(self.child.pid, received)
            except ProcessLookupError: pass
            return
        raise LiveTransportInterrupted(received)

    def start_proxy(self, config: Path) -> None:
        log = (self.temp / "wireproxy.log").open("wb")
        try:
            self.proxy = subprocess.Popen(
                [str(self.proxy_binary), "-s", "-c", str(config)],
                stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                env=sanitized_environment(),
            )
        finally: log.close()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            require(self.proxy.poll() is None, "owned wireproxy exited before readiness")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.settimeout(0.25)
                if probe.connect_ex(("127.0.0.1", self.port)) == 0: break
            time.sleep(0.1)
        else: raise LiveTransportError("owned wireproxy did not bind its loopback listener")
        owner = subprocess.run(
            ["/usr/sbin/lsof", "-nP", "-a", "-p", str(self.proxy.pid), f"-iTCP@127.0.0.1:{self.port}", "-sTCP:LISTEN"],
            text=True, capture_output=True, check=False,
        )
        require(owner.returncode == 0 and str(self.proxy.pid) in owner.stdout, "loopback listener is not owned by the started wireproxy")
        self.listener_verified = True

    def run_child(self, command: list[str], environment: dict[str, str]) -> ChildResult:
        require(self.proxy is not None and self.proxy.poll() is None, "owned wireproxy absent before protected runner")
        self.child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True, env=environment)
        try: stdout, stderr = self.child.communicate()
        finally: process = self.child; self.child = None
        require(self.proxy.poll() is None or process.returncode != 0, "owned wireproxy exited during successful protected runner")
        redacted = "[REDACTED-PROXY-CREDENTIAL]"
        return ChildResult(process.returncode, stdout.replace(self.password, redacted), stderr.replace(self.password, redacted))

    def close(self) -> None:
        stop_process(self.child); self.child = None
        stop_process(self.proxy); self.proxy = None

def create_admin_kubeconfig(talosctl: Path, kubectl: Path, talosconfig: Path, destination: Path, proxy: str, temp: Path) -> None:
    direct = temp / "talos-kubeconfig"
    environment = sanitized_environment() | {"HTTPS_PROXY": proxy, "HTTP_PROXY": proxy, "NO_PROXY": ""}
    generated = subprocess.run(
        [str(talosctl), "--talosconfig", str(talosconfig), "--endpoints", API_HOST, "--nodes", API_HOST, "kubeconfig", str(direct), "--force", "--merge=false"],
        text=True, capture_output=True, check=False, env=environment,
    )
    require(generated.returncode == 0, "Talos administrator kubeconfig generation failed")
    os.chmod(direct, 0o600)
    flattened = subprocess.run(
        [str(kubectl), "--kubeconfig", str(direct), "config", "view", "--raw", "--flatten", "--minify", "-o", "json"],
        text=True, capture_output=True, check=False, env=sanitized_environment(),
    )
    require(flattened.returncode == 0, "generated kubeconfig flattening failed")
    try: config = json.loads(flattened.stdout, object_pairs_hook=_unique_object)
    except ValueError as exc: raise LiveTransportError("generated kubeconfig is invalid JSON") from exc
    clusters = config.get("clusters") if isinstance(config, dict) else None
    require(isinstance(clusters, list) and len(clusters) == 1 and isinstance(clusters[0].get("cluster"), dict), "generated kubeconfig cluster cardinality differs")
    cluster = clusters[0]["cluster"]
    cluster["server"] = f"https://{API_HOST}:{API_PORT}"
    cluster["proxy-url"] = proxy
    cluster.pop("tls-server-name", None)
    write_private(destination, (canonical(config) + "\n").encode())

def receipt_digest(path: Path) -> str | None:
    return file_sha256(path) if path.is_file() and not path.is_symlink() else None

def write_wrapper_receipt(path: Path, value: dict[str, Any]) -> None:
    unsigned = dict(value); require("canonicalSha256" not in unsigned, "wrapper receipt already closed")
    final = unsigned | {"canonicalSha256": bytes_sha256(canonical(unsigned).encode())}
    write_private(path, (canonical(final) + "\n").encode())

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-protected-revision", required=True)
    parser.add_argument("--age-bin", required=True, type=Path)
    parser.add_argument("--age-identity", required=True, type=Path)
    parser.add_argument("--bootstrap-bundle", required=True, type=Path)
    parser.add_argument("--wireproxy-bin", required=True, type=Path)
    parser.add_argument("--talosctl-bin", required=True, type=Path)
    parser.add_argument("--kubectl-bin", required=True, type=Path)
    parser.add_argument("--receipt-directory", required=True, type=Path)
    parser.add_argument("--live", action="store_true")
    return parser.parse_args(argv)

def main(argv: list[str] | None = None) -> int:
    receipt_dir: Path | None = None; temp: Path | None = None; session: LiveSession | None = None
    outcome = "blocked"; error = None; bootstrap_status = None; recovery_status = None; activation_status = None
    binaries: dict[str, str] = {}; revision = None; interrupted = False
    previous_handlers: dict[int, Any] = {}
    bootstrap_receipt = activation_receipt = recovery_receipt = None
    try:
        require(sys.flags.isolated == 1 and bool(sys.flags.safe_path), "wrapper requires python3 -I isolated safe-path mode")
        args = parse_args(argv); require(args.live is True, "wrapper requires explicit --live")
        revision = args.expected_protected_revision; exact_checkout(revision)
        receipt_dir = reserve_output_directory(args.receipt_directory)
        age = pinned_binary(args.age_bin, "age"); kubectl = pinned_binary(args.kubectl_bin, "kubectl")
        talosctl = pinned_binary(args.talosctl_bin, "talosctl"); wireproxy = pinned_binary(args.wireproxy_bin, "wireproxy")
        binaries = {name: EXPECTED_BINARIES[name] for name in sorted(EXPECTED_BINARIES)}
        identity = private_file(args.age_identity, "age identity")
        bundle_source = Path(os.path.abspath(args.bootstrap_bundle)); bundle_source_info = os.lstat(bundle_source)
        require(not stat.S_ISLNK(bundle_source_info.st_mode), "bootstrap bundle must not be a symlink")
        bundle = Path(os.path.realpath(bundle_source)); bundle_info = os.lstat(bundle)
        require(bundle == bundle_source and stat.S_ISDIR(bundle_info.st_mode) and bundle_info.st_uid == os.geteuid() and stat.S_IMODE(bundle_info.st_mode) & 0o077 == 0, "bootstrap bundle must be a private owned directory")
        encrypted_wg = private_file(bundle / "wireguard-daily.conf.age", "encrypted WireGuard input")
        encrypted_talos = private_file(bundle / "talosconfig.yaml.age", "encrypted Talos input")
        temp = Path(tempfile.mkdtemp(prefix="roebel-participant-live-", dir="/private/tmp")); os.chmod(temp, 0o700)
        wireguard = temp / "wireguard.conf"; talosconfig = temp / "talosconfig.yaml"
        decrypt(age, identity, encrypted_wg, wireguard); decrypt(age, identity, encrypted_talos, talosconfig)
        password = secrets.token_hex(32); require(len(password) == 64, "proxy CSPRNG failed")
        port = reserve_port(); config = temp / "wireproxy.conf"; write_private(config, wireproxy_config(password, port).encode())
        config_test = subprocess.run([str(wireproxy), "-n", "-c", str(config)], capture_output=True, check=False, env=sanitized_environment())
        require(config_test.returncode == 0, "wireproxy rejected the protected one-shot configuration")
        session = LiveSession(temp, wireproxy, password, port)
        for signum in (signal.SIGINT, signal.SIGTERM): previous_handlers[signum] = signal.getsignal(signum); signal.signal(signum, session.handle_signal)
        session.start_proxy(config)
        kubeconfig = temp / "admin-kubeconfig.json"; proxy = proxy_url(password, port)
        create_admin_kubeconfig(talosctl, kubectl, talosconfig, kubeconfig, proxy, temp)
        tool_bin = temp / "bin"; tool_bin.mkdir(mode=0o700); os.link(kubectl, tool_bin / "kubectl")
        child_environment = sanitized_environment() | {"PATH": f"{tool_bin}:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin"}
        bootstrap_receipt = receipt_dir / "participant-flux-bootstrap.json"
        bootstrap_command = [
            sys.executable, "-I", str(ROOT / BOOTSTRAP_RUNNER), "--live",
            "--expected-protected-revision", revision, "--kubeconfig", str(kubeconfig),
            "--receipt", str(bootstrap_receipt),
        ]
        bootstrap = session.run_child(bootstrap_command, child_environment)
        if bootstrap.stdout: print(bootstrap.stdout, end="")
        if bootstrap.stderr: print(bootstrap.stderr, end="", file=sys.stderr)
        if bootstrap_receipt.is_file(): bootstrap_status = load_json(bootstrap_receipt).get("status")
        if bootstrap.returncode != 0:
            if bootstrap_status == "rollback-incomplete":
                recovery_receipt = receipt_dir / "participant-flux-bootstrap-recovery.json"
                recovery = session.run_child([
                    sys.executable, "-I", str(ROOT / BOOTSTRAP_RUNNER), "--recover",
                    "--expected-protected-revision", revision, "--kubeconfig", str(kubeconfig),
                    "--recovery-receipt", str(bootstrap_receipt), "--receipt", str(recovery_receipt),
                ], child_environment)
                if recovery.stdout: print(recovery.stdout, end="")
                if recovery.stderr: print(recovery.stderr, end="", file=sys.stderr)
                if recovery_receipt.is_file(): recovery_status = load_json(recovery_receipt).get("status")
            raise LiveTransportError(f"dormant Flux bootstrap did not complete: {bootstrap_status or 'no durable status'}")
        require(bootstrap_status == "dormant-ready", "bootstrap returned success without dormant-ready receipt")
        activation_receipt = receipt_dir / "participant-gateway-activation.json"
        activation = session.run_child([
            sys.executable, "-I", str(ROOT / ACTIVATION_RUNNER), "--live",
            "--expected-protected-revision", revision, "--kubeconfig", str(kubeconfig),
            "--flux-bootstrap-receipt", str(bootstrap_receipt), "--receipt", str(activation_receipt),
        ], child_environment)
        if activation.stdout: print(activation.stdout, end="")
        if activation.stderr: print(activation.stderr, end="", file=sys.stderr)
        if activation_receipt.is_file(): activation_status = load_json(activation_receipt).get("status")
        require(activation.returncode == 0 and activation_status == "activated", "participant activation did not commit")
        outcome = "activated"
        return 0
    except (LiveTransportError, OSError, ValueError) as exc:
        interrupted = isinstance(exc, LiveTransportInterrupted); error = str(exc)
        print(f"participant live wrapper blocked: {error}", file=sys.stderr)
        return 2
    finally:
        if session is not None: session.close()
        for signum, handler in previous_handlers.items(): signal.signal(signum, handler)
        if temp is not None: shutil.rmtree(temp, ignore_errors=True)
        if receipt_dir is not None:
            wrapper_receipt = {
                "schemaVersion": WRAPPER_RECEIPT_SCHEMA,
                "status": outcome,
                "protectedRevision": revision,
                "binarySha256": binaries,
                "transport": {
                    "mode": "owned-authenticated-rootless-wireproxy-loopback-http-connect",
                    "apiAuthority": f"{API_HOST}:{API_PORT}",
                    "perRunProxyAuthentication": True,
                    "listenerOwnershipVerified": session is not None and session.listener_verified,
                    "rootlessTransportRemoved": session is not None and session.proxy is None,
                    "plaintextTransportInputsRemoved": temp is not None and not temp.exists(),
                },
                "bootstrap": {"status": bootstrap_status, "receiptSha256": receipt_digest(bootstrap_receipt) if bootstrap_receipt else None},
                "recovery": {"status": recovery_status, "receiptSha256": receipt_digest(recovery_receipt) if recovery_receipt else None},
                "activation": {"status": activation_status, "receiptSha256": receipt_digest(activation_receipt) if activation_receipt else None},
                "interrupted": interrupted,
                "failure": error,
                "containsSecretMaterial": False,
                "civicAuthorityEffects": False,
                "automaticRetry": False,
            }
            try: write_wrapper_receipt(receipt_dir / "transport-transaction.json", wrapper_receipt)
            except (OSError, LiveTransportError) as receipt_error: print(f"participant live wrapper receipt failed: {receipt_error}", file=sys.stderr)

if __name__ == "__main__":
    raise SystemExit(main())
