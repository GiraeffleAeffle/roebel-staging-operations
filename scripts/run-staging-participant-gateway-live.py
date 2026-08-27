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

import argparse, base64, hashlib, json, os, re, secrets, select, shutil, signal, socket, stat, subprocess, sys, tempfile, threading, time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SELF_PATH = "scripts/run-staging-participant-gateway-live.py"
BOOTSTRAP_RUNNER = "scripts/bootstrap-staging-participant-flux.py"
ACTIVATION_RUNNER = "scripts/activate-staging-participant-gateway.py"
API_HOST, API_PORT, TALOS_PORT = "10.255.240.11", 6443, 50000
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

def wireproxy_config(api_tunnel_port: int, talos_tunnel_port: int) -> str:
    require(1024 <= api_tunnel_port <= 65535, "API tunnel port outside unprivileged range")
    require(1024 <= talos_tunnel_port <= 65535, "Talos tunnel port outside unprivileged range")
    require(api_tunnel_port != talos_tunnel_port, "static tunnel ports must be distinct")
    return (
        "WGConfig = wireguard.conf\n\n"
        "[TCPClientTunnel]\n"
        f"BindAddress = 127.0.0.1:{api_tunnel_port}\n"
        f"Target = {API_HOST}:{API_PORT}\n\n"
        "[TCPClientTunnel]\n"
        f"BindAddress = 127.0.0.1:{talos_tunnel_port}\n"
        f"Target = {API_HOST}:{TALOS_PORT}\n"
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
    transport_alive_after: bool

class ExactConnectProxy:
    """Authenticated loopback CONNECT guard for one immutable authority.

    wireproxy v1.1.3's HTTP mode accepts arbitrary CONNECT/GET destinations.
    This guard therefore fronts a static TCPClientTunnel whose target is fixed
    by wireproxy itself; neither layer can turn caller input into a destination.
    """
    def __init__(self, authority: str, backend_port: int, username: str, password: str):
        require(authority in {f"{API_HOST}:{API_PORT}", f"{API_HOST}:{TALOS_PORT}"}, "CONNECT authority is not protected")
        require(1024 <= backend_port <= 65535, "CONNECT backend port outside unprivileged range")
        require(username == PROXY_USERNAME, "CONNECT username differs")
        require(re.fullmatch(r"[0-9a-f]{64}", password) is not None, "CONNECT credential must be CSPRNG hex")
        self.authority, self.backend_port = authority, backend_port
        self.username, self.password = username, password
        self.listener: socket.socket | None = None
        self.port: int | None = None
        self.thread: threading.Thread | None = None
        self.clients: set[socket.socket] = set()
        self.lock = threading.Lock()
        self.stopping = threading.Event()

    def expected_authorization(self) -> str:
        encoded = base64.b64encode(f"{self.username}:{self.password}".encode()).decode("ascii")
        return f"Basic {encoded}"

    def _response(self, connection: socket.socket, status: int, reason: str, authenticate: bool = False) -> None:
        extra = 'Proxy-Authenticate: Basic realm="stadtstack-participant"\r\n' if authenticate else ""
        try: connection.sendall(f"HTTP/1.1 {status} {reason}\r\n{extra}Connection: close\r\nContent-Length: 0\r\n\r\n".encode("ascii"))
        except OSError: pass

    def _read_request(self, connection: socket.socket) -> tuple[int, str, bytes | None]:
        value = bytearray()
        connection.settimeout(5)
        while b"\r\n\r\n" not in value:
            chunk = connection.recv(2048)
            if not chunk: return 400, "Bad Request", None
            value.extend(chunk)
            if len(value) > 8192: return 431, "Request Header Fields Too Large", None
        head, remainder = bytes(value).split(b"\r\n\r\n", 1)
        if remainder: return 400, "Bad Request", None
        try: lines = head.decode("ascii").split("\r\n")
        except UnicodeDecodeError: return 400, "Bad Request", None
        request = lines[0].split(" ")
        if len(request) != 3 or request[2] not in {"HTTP/1.0", "HTTP/1.1"}: return 400, "Bad Request", None
        if request[0] != "CONNECT": return 405, "Method Not Allowed", None
        if request[1] != self.authority: return 403, "Forbidden", None
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line or line[:1] in {" ", "\t"} or ":" not in line: return 400, "Bad Request", None
            name, content = line.split(":", 1); lower = name.lower()
            if re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) is None or lower in headers: return 400, "Bad Request", None
            headers[lower] = content.strip()
        if headers.get("host") != self.authority: return 400, "Bad Request", None
        supplied = headers.get("proxy-authorization", "")
        if not secrets.compare_digest(supplied, self.expected_authorization()): return 407, "Proxy Authentication Required", None
        return 200, "Connection Established", b""

    def _relay(self, left: socket.socket, right: socket.socket) -> None:
        peers = {left: right, right: left}
        try:
            while peers:
                readable, _, _ = select.select(list(peers), [], [], 1)
                if self.stopping.is_set(): return
                for source in readable:
                    data = source.recv(65536)
                    if not data: return
                    peers[source].sendall(data)
        except (OSError, ValueError): return

    def _serve_connection(self, connection: socket.socket) -> None:
        with self.lock: self.clients.add(connection)
        backend: socket.socket | None = None
        try:
            status, reason, accepted = self._read_request(connection)
            if accepted is None:
                self._response(connection, status, reason, authenticate=status == 407)
                return
            try: backend = socket.create_connection(("127.0.0.1", self.backend_port), timeout=5)
            except OSError:
                self._response(connection, 502, "Bad Gateway")
                return
            connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            connection.settimeout(None); backend.settimeout(None)
            self._relay(connection, backend)
        finally:
            if backend is not None:
                try: backend.close()
                except OSError: pass
            try: connection.close()
            except OSError: pass
            with self.lock: self.clients.discard(connection)

    def _serve(self) -> None:
        assert self.listener is not None
        self.listener.settimeout(0.25)
        while not self.stopping.is_set():
            try: connection, peer = self.listener.accept()
            except socket.timeout: continue
            except OSError: return
            if peer[0] != "127.0.0.1":
                connection.close(); continue
            threading.Thread(target=self._serve_connection, args=(connection,), daemon=True).start()

    def start(self) -> int:
        require(self.listener is None, "CONNECT guard already started")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.bind(("127.0.0.1", 0)); listener.listen(16)
        except BaseException:
            listener.close(); raise
        self.listener = listener; self.port = int(listener.getsockname()[1])
        self.thread = threading.Thread(target=self._serve, daemon=True); self.thread.start()
        return self.port

    def alive(self) -> bool:
        return self.listener is not None and self.thread is not None and self.thread.is_alive() and not self.stopping.is_set()

    def close(self) -> None:
        self.stopping.set()
        if self.listener is not None:
            try: self.listener.close()
            except OSError: pass
            self.listener = None
        with self.lock: clients = list(self.clients)
        for connection in clients:
            try: connection.close()
            except OSError: pass
        if self.thread is not None: self.thread.join(timeout=2)
        self.thread = None

class LiveSession:
    def __init__(self, temp: Path, proxy_binary: Path, api_tunnel_port: int, talos_tunnel_port: int, api_password: str, talos_password: str):
        self.temp, self.proxy_binary = temp, proxy_binary
        self.api_tunnel_port, self.talos_tunnel_port = api_tunnel_port, talos_tunnel_port
        self.api_password, self.talos_password = api_password, talos_password
        self.proxy: subprocess.Popen[Any] | None = None
        self.api_guard = ExactConnectProxy(f"{API_HOST}:{API_PORT}", api_tunnel_port, PROXY_USERNAME, api_password)
        self.talos_guard = ExactConnectProxy(f"{API_HOST}:{TALOS_PORT}", talos_tunnel_port, PROXY_USERNAME, talos_password)
        self.child: subprocess.Popen[Any] | None = None
        self.signals: list[int] = []
        self.child_receipt_pending = False
        self.listener_verified = False

    def handle_signal(self, received: int, _frame: Any) -> None:
        self.signals.append(received)
        if self.child is not None and self.child.poll() is None:
            try: os.killpg(self.child.pid, received)
            except ProcessLookupError: pass
            return
        if self.child is not None or self.child_receipt_pending:
            # Never raise between child exit and durable receipt loading.  The
            # receipt is the only authority for committed/rolled-back state.
            return
        raise LiveTransportInterrupted(received)

    def start_proxy(self, config: Path) -> tuple[int, int]:
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
            ready = True
            for port in (self.api_tunnel_port, self.talos_tunnel_port):
                owner = subprocess.run(
                    ["/usr/sbin/lsof", "-nP", "-a", "-p", str(self.proxy.pid), f"-iTCP@127.0.0.1:{port}", "-sTCP:LISTEN"],
                    text=True, capture_output=True, check=False,
                )
                ready = ready and owner.returncode == 0 and str(self.proxy.pid) in owner.stdout
            if ready: break
            time.sleep(0.1)
        else: raise LiveTransportError("owned wireproxy did not bind its loopback listener")
        for port in (self.api_tunnel_port, self.talos_tunnel_port):
            owner = subprocess.run(
                ["/usr/sbin/lsof", "-nP", "-a", "-p", str(self.proxy.pid), f"-iTCP@127.0.0.1:{port}", "-sTCP:LISTEN"],
                text=True, capture_output=True, check=False,
            )
            require(owner.returncode == 0 and str(self.proxy.pid) in owner.stdout, "static loopback tunnel is not owned by the started wireproxy")
        api_guard_port = self.api_guard.start(); talos_guard_port = self.talos_guard.start()
        self.listener_verified = True
        return api_guard_port, talos_guard_port

    def transport_alive(self) -> bool:
        return self.proxy is not None and self.proxy.poll() is None and self.api_guard.alive() and self.talos_guard.alive()

    def run_child(self, command: list[str], environment: dict[str, str], allow_pending_signal: bool = False) -> ChildResult:
        require(self.transport_alive(), "owned exact transport absent before protected runner")
        require(allow_pending_signal or not self.signals, "operator signal blocks the next protected runner")
        self.child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True, env=environment)
        try: stdout, stderr = self.child.communicate()
        finally:
            process = self.child
            self.child_receipt_pending = True
            self.child = None
        redacted = "[REDACTED-PROXY-CREDENTIAL]"
        for password in (self.api_password, self.talos_password):
            stdout = stdout.replace(password, redacted); stderr = stderr.replace(password, redacted)
        return ChildResult(process.returncode, stdout, stderr, self.transport_alive())

    def receipt_reconciled(self) -> None:
        self.child_receipt_pending = False

    def close(self) -> None:
        stop_process(self.child); self.child = None
        self.api_guard.close(); self.talos_guard.close()
        stop_process(self.proxy); self.proxy = None

def create_admin_kubeconfig(talosctl: Path, kubectl: Path, talosconfig: Path, destination: Path, talos_proxy: str, api_proxy: str, temp: Path) -> None:
    direct = temp / "talos-kubeconfig"
    environment = sanitized_environment() | {"HTTPS_PROXY": talos_proxy, "HTTP_PROXY": talos_proxy, "NO_PROXY": ""}
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
    cluster["proxy-url"] = api_proxy
    cluster.pop("tls-server-name", None)
    write_private(destination, (canonical(config) + "\n").encode())

def receipt_digest(path: Path) -> str | None:
    return file_sha256(path) if path.is_file() and not path.is_symlink() else None

def durable_activation_committed(result: ChildResult, status: Any) -> bool:
    # The runner may be signalled or lose transport after fsyncing its success
    # receipt.  Process/transport status cannot override that durable commit.
    return status == "activated"

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
        api_password = secrets.token_hex(32); talos_password = secrets.token_hex(32)
        require(len(api_password) == len(talos_password) == 64 and api_password != talos_password, "proxy CSPRNG failed")
        api_tunnel_port = reserve_port(); talos_tunnel_port = reserve_port()
        require(api_tunnel_port != talos_tunnel_port, "static tunnel port allocation collided")
        config = temp / "wireproxy.conf"
        write_private(config, wireproxy_config(api_tunnel_port, talos_tunnel_port).encode())
        config_test = subprocess.run([str(wireproxy), "-n", "-c", str(config)], capture_output=True, check=False, env=sanitized_environment())
        require(config_test.returncode == 0, "wireproxy rejected the protected one-shot configuration")
        session = LiveSession(temp, wireproxy, api_tunnel_port, talos_tunnel_port, api_password, talos_password)
        for signum in (signal.SIGINT, signal.SIGTERM): previous_handlers[signum] = signal.getsignal(signum); signal.signal(signum, session.handle_signal)
        api_guard_port, talos_guard_port = session.start_proxy(config)
        kubeconfig = temp / "admin-kubeconfig.json"
        api_proxy = proxy_url(api_password, api_guard_port)
        talos_proxy = proxy_url(talos_password, talos_guard_port)
        create_admin_kubeconfig(talosctl, kubectl, talosconfig, kubeconfig, talos_proxy, api_proxy, temp)
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
                session.receipt_reconciled()
                recovery_receipt = receipt_dir / "participant-flux-bootstrap-recovery.json"
                recovery = session.run_child([
                    sys.executable, "-I", str(ROOT / BOOTSTRAP_RUNNER), "--recover",
                    "--expected-protected-revision", revision, "--kubeconfig", str(kubeconfig),
                    "--recovery-receipt", str(bootstrap_receipt), "--receipt", str(recovery_receipt),
                ], child_environment, allow_pending_signal=True)
                if recovery.stdout: print(recovery.stdout, end="")
                if recovery.stderr: print(recovery.stderr, end="", file=sys.stderr)
                if recovery_receipt.is_file(): recovery_status = load_json(recovery_receipt).get("status")
                session.receipt_reconciled()
            else:
                session.receipt_reconciled()
            raise LiveTransportError(f"dormant Flux bootstrap did not complete: {bootstrap_status or 'no durable status'}")
        require(bootstrap_status == "dormant-ready", "bootstrap returned success without dormant-ready receipt")
        require(bootstrap.transport_alive_after, "exact transport was lost after dormant bootstrap; activation was not attempted")
        if session.signals: raise LiveTransportInterrupted(session.signals[-1])
        session.receipt_reconciled()
        activation_receipt = receipt_dir / "participant-gateway-activation.json"
        activation = session.run_child([
            sys.executable, "-I", str(ROOT / ACTIVATION_RUNNER), "--live",
            "--expected-protected-revision", revision, "--kubeconfig", str(kubeconfig),
            "--flux-bootstrap-receipt", str(bootstrap_receipt), "--receipt", str(activation_receipt),
        ], child_environment)
        if activation.stdout: print(activation.stdout, end="")
        if activation.stderr: print(activation.stderr, end="", file=sys.stderr)
        if activation_receipt.is_file(): activation_status = load_json(activation_receipt).get("status")
        require(durable_activation_committed(activation, activation_status), "participant activation did not commit")
        interrupted = bool(session.signals)
        outcome = "activated"
        return 0
    except (LiveTransportError, OSError, ValueError) as exc:
        interrupted = isinstance(exc, LiveTransportInterrupted) or (session is not None and bool(session.signals)); error = str(exc)
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
                    "mode": "owned-authenticated-exact-connect-guards-over-static-wireproxy-tunnels",
                    "apiAuthority": f"{API_HOST}:{API_PORT}",
                    "talosAuthority": f"{API_HOST}:{TALOS_PORT}",
                    "perRunProxyAuthentication": True,
                    "callerSelectedDestination": False,
                    "listenerOwnershipVerified": session is not None and session.listener_verified,
                    "exactConnectGuardsRemoved": session is not None and not session.api_guard.alive() and not session.talos_guard.alive(),
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
