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
API_HOST, API_PORT, TALOS_PORT = "10.255.240.11", 6443, 50000
PROXY_USERNAME = "stadtstack-participant"
UPSTREAM_USERNAME = "stadtstack-wireproxy-upstream"
WIREPROXY_USERNAME_ENV = "ROEBEL_WIREPROXY_USERNAME"
WIREPROXY_PASSWORD_ENV = "ROEBEL_WIREPROXY_PASSWORD"
WRAPPER_RECEIPT_SCHEMA = "roebel_staging_participant_live_transport_receipt_v2"
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

def git_blob(revision: str, path: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(ROOT), "show", f"{revision}:{path}"],
            capture_output=True,
            check=False,
            timeout=10,
        )
    except subprocess.TimeoutExpired as exc:
        raise LiveTransportError(f"protected Git blob read timed out: {path}") from exc
    require(result.returncode == 0, f"protected Git blob unavailable: {path}")
    return result.stdout

def bind_protected_checkout(revision: str) -> dict[str, str]:
    require(REVISION.fullmatch(revision) is not None, "protected revision must be lowercase SHA-1")
    head = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True, capture_output=True, check=False)
    require(head.returncode == 0 and head.stdout.strip() == revision, "checkout is not the expected protected revision")
    hashes: dict[str, str] = {}
    for path in PROTECTED_PATHS:
        local = ROOT / path
        info = os.lstat(local)
        require(stat.S_ISREG(info.st_mode) and not local.is_symlink(), f"protected file is not a regular Git blob: {path}")
        expected = git_blob(revision, path)
        require(local.read_bytes() == expected, f"protected file differs from exact Git blob: {path}")
        hashes[path] = bytes_sha256(expected)
    dirty = subprocess.run(["git", "-C", str(ROOT), "diff", "--quiet", revision, "--", *PROTECTED_PATHS], check=False)
    cached = subprocess.run(["git", "-C", str(ROOT), "diff", "--cached", "--quiet", revision, "--", *PROTECTED_PATHS], check=False)
    require(dirty.returncode == 0 and cached.returncode == 0, "protected transport checkout is dirty")
    return dict(sorted(hashes.items()))

def snapshot_binary(source_path: Path, label: str, destination: Path) -> Path:
    resolved = Path(source_path).expanduser().resolve(strict=True)
    source_flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"): source_flags |= os.O_NOFOLLOW
    source_fd = os.open(resolved, source_flags)
    destination_fd = -1
    try:
        before = os.fstat(source_fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size > 0, f"{label} must resolve to a non-empty regular executable")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
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
        after = os.fstat(source_fd)
        require(
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            f"{label} binary changed while snapshotting",
        )
        observed = "sha256:" + digest.hexdigest()
        require(observed == EXPECTED_BINARIES[label], f"{label} binary digest differs")
    finally:
        if destination_fd >= 0: os.close(destination_fd)
        os.close(source_fd)
    info = os.lstat(destination)
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.geteuid()
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o500
        and file_sha256(destination) == EXPECTED_BINARIES[label],
        f"{label} executable snapshot verification failed",
    )
    fsync_directory(destination.parent)
    return destination

def wireproxy_config(upstream_port: int) -> str:
    require(1024 <= upstream_port <= 65535, "wireproxy upstream port outside unprivileged range")
    return (
        "WGConfig = wireguard.conf\n\n"
        "[http]\n"
        f"BindAddress = 127.0.0.1:{upstream_port}\n"
        f"Username = ${WIREPROXY_USERNAME_ENV}\n"
        f"Password = ${WIREPROXY_PASSWORD_ENV}\n"
    )

def proxy_url(password: str, port: int) -> str:
    require(re.fullmatch(r"[0-9a-f]{64}", password) is not None, "proxy credential must be CSPRNG hex")
    require(1024 <= port <= 65535, "proxy port outside unprivileged range")
    return f"http://{PROXY_USERNAME}:{password}@127.0.0.1:{port}"

def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0)); return int(listener.getsockname()[1])

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
    return process.poll() is not None and process_group_gone(process)

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
        require(hasattr(signal, "pthread_sigmask"), "transaction requires pthread signal masking")
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

    def _block(self) -> set[signal.Signals]:
        return signal.pthread_sigmask(signal.SIG_BLOCK, TRANSACTION_SIGNALS)

    def _restore_mask(self, previous: set[signal.Signals]) -> None:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)

    def run(
        self,
        command: list[str],
        *,
        allow_cancelled: bool = False,
        forward_signals: bool = True,
        receipt_pending: bool = False,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> ProcessResult:
        if not allow_cancelled: self.checkpoint()
        previous = self._block()
        if self.signals and not allow_cancelled:
            self._restore_mask(previous)
            raise LiveTransportInterrupted(self.signals[-1])
        process: subprocess.Popen[Any] | None = None
        try:
            process = subprocess.Popen(command, start_new_session=True, **kwargs)
            self.owned_processes.append(process)
            self.active_process = process
            self.forward_active_signal = forward_signals
        finally:
            self._restore_mask(previous)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            stop_process(process)
            process.communicate()
            raise LiveTransportError(f"owned process timed out: {Path(command[0]).name}") from exc
        finally:
            previous = self._block()
            try:
                if self.active_process is process:
                    self.active_process = None
                    self.forward_active_signal = False
                if receipt_pending:
                    self.receipt_pending = True
            finally:
                self._restore_mask(previous)
        return ProcessResult(process.returncode, stdout, stderr)

    def spawn_background(self, command: list[str], **kwargs: Any) -> subprocess.Popen[Any]:
        self.checkpoint()
        previous = self._block()
        if self.signals:
            self._restore_mask(previous)
            raise LiveTransportInterrupted(self.signals[-1])
        try:
            process = subprocess.Popen(command, start_new_session=True, **kwargs)
            self.owned_processes.append(process)
        finally:
            self._restore_mask(previous)
        self.checkpoint()
        return process

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

def decrypt(state: CancellationState, age: Path, identity: Path, source: Path, destination: Path) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"): flags |= os.O_NOFOLLOW
    fd = os.open(destination, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            fd = -1
            result = state.run(
                [str(age), "--decrypt", "--identity", str(identity), str(source)],
                stdout=stream,
                stderr=subprocess.PIPE,
                timeout=30,
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
    """One authenticated exact-authority listener over an authenticated upstream."""
    def __init__(
        self,
        authority: str,
        upstream_port: int,
        client_password: str,
        upstream_password: str,
        max_workers: int = 16,
    ):
        require(authority in {f"{API_HOST}:{API_PORT}", f"{API_HOST}:{TALOS_PORT}"}, "CONNECT authority is not protected")
        require(1024 <= upstream_port <= 65535, "CONNECT upstream port outside unprivileged range")
        require(re.fullmatch(r"[0-9a-f]{64}", client_password) is not None, "CONNECT credential must be CSPRNG hex")
        require(re.fullmatch(r"[0-9a-f]{64}", upstream_password) is not None, "upstream credential must be CSPRNG hex")
        require(client_password != upstream_password, "front and upstream credentials must differ")
        require(1 <= max_workers <= 64, "CONNECT worker bound invalid")
        self.authority, self.upstream_port = authority, upstream_port
        self.client_password, self.upstream_password = client_password, upstream_password
        self.max_workers = max_workers
        self.listener: socket.socket | None = None
        self.port: int | None = None
        self.thread: threading.Thread | None = None
        self.connections: set[socket.socket] = set()
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

    def _connect_upstream(self) -> socket.socket:
        upstream = socket.create_connection(("127.0.0.1", self.upstream_port), timeout=5)
        with self.lock: self.connections.add(upstream)
        authorization = self._authorization(UPSTREAM_USERNAME, self.upstream_password)
        request = (
            f"CONNECT {self.authority} HTTP/1.1\r\n"
            f"Host: {self.authority}\r\n"
            f"Proxy-Authorization: {authorization}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        try:
            upstream.sendall(request)
            head, remainder = self._read_head(upstream)
            require(not remainder, "wireproxy upstream sent data before CONNECT acceptance")
            first = head.split(b"\r\n", 1)[0]
            require(first == b"HTTP/1.1 200 Connection established", "wireproxy upstream rejected exact CONNECT")
            upstream.settimeout(None)
            return upstream
        except BaseException:
            try: upstream.close()
            except OSError: pass
            with self.lock: self.connections.discard(upstream)
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
        backend: socket.socket | None = None
        try:
            status, reason, accepted = self._read_request(connection)
            if not accepted:
                self._response(connection, status, reason, authenticate=status == 407)
                return
            try: backend = self._connect_upstream()
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
        with self.lock: connections = list(self.connections)
        for connection in connections:
            try: connection.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            try: connection.close()
            except OSError: pass
        deadline = time.monotonic() + timeout
        if self.thread is not None:
            self.thread.join(timeout=max(0, deadline - time.monotonic()))
        while True:
            with self.lock: workers = list(self.workers)
            if not workers or time.monotonic() >= deadline: break
            for worker in workers: worker.join(timeout=max(0, deadline - time.monotonic()))
        listener_stopped = self.thread is None or not self.thread.is_alive()
        with self.lock:
            workers_stopped = all(not worker.is_alive() for worker in self.workers)
            connections_closed = not self.connections
        if listener_stopped: self.thread = None
        return {
            "listenerStopped": listener_stopped,
            "workerThreadsStopped": workers_stopped,
            "connectionsClosed": connections_closed,
            "workerLimit": self.max_workers,
        }

class LiveSession:
    def __init__(
        self,
        temp: Path,
        proxy_binary: Path,
        upstream_port: int,
        upstream_password: str,
        api_password: str,
        talos_password: str,
        cancellation: CancellationState,
    ):
        self.temp, self.proxy_binary = temp, proxy_binary
        self.upstream_port, self.upstream_password = upstream_port, upstream_password
        self.api_password, self.talos_password = api_password, talos_password
        self.cancellation = cancellation
        self.proxy: subprocess.Popen[Any] | None = None
        self.api_guard = ExactConnectProxy(f"{API_HOST}:{API_PORT}", upstream_port, api_password, upstream_password)
        self.talos_guard = ExactConnectProxy(f"{API_HOST}:{TALOS_PORT}", upstream_port, talos_password, upstream_password)
        self.listener_verified = False

    def _probe_wireproxy_auth(self, authorization: str | None) -> bytes:
        with socket.create_connection(("127.0.0.1", self.upstream_port), timeout=5) as connection:
            header = f"Proxy-Authorization: {authorization}\r\n" if authorization is not None else ""
            connection.sendall(
                (
                    f"CONNECT {API_HOST}:{API_PORT} HTTP/1.1\r\n"
                    f"Host: {API_HOST}:{API_PORT}\r\n"
                    f"{header}Connection: close\r\n\r\n"
                ).encode("ascii"),
            )
            head, _ = ExactConnectProxy._read_head(connection)
            return head.split(b"\r\n", 1)[0]

    def start_proxy(self, config: Path) -> tuple[int, int]:
        log_path = self.temp / "wireproxy.log"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"): flags |= os.O_NOFOLLOW
        log_fd = os.open(log_path, flags, 0o600)
        environment = sanitized_environment({
            WIREPROXY_USERNAME_ENV: UPSTREAM_USERNAME,
            WIREPROXY_PASSWORD_ENV: self.upstream_password,
        })
        try:
            os.fchmod(log_fd, 0o600)
            with os.fdopen(log_fd, "wb", closefd=True) as log:
                log_fd = -1
                self.proxy = self.cancellation.spawn_background(
                    [str(self.proxy_binary), "-s", "-c", str(config)],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    env=environment,
                )
        finally:
            if log_fd >= 0: os.close(log_fd)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            require(self.proxy.poll() is None, "owned wireproxy exited before readiness")
            owner = subprocess.run(
                ["/usr/sbin/lsof", "-nP", "-a", "-p", str(self.proxy.pid), f"-iTCP@127.0.0.1:{self.upstream_port}", "-sTCP:LISTEN"],
                text=True,
                capture_output=True,
                check=False,
            )
            if owner.returncode == 0 and str(self.proxy.pid) in owner.stdout: break
            self.cancellation.checkpoint()
            time.sleep(0.1)
        else: raise LiveTransportError("owned wireproxy did not bind its authenticated loopback listener")
        require(
            self._probe_wireproxy_auth(None).startswith(b"HTTP/1.1 407 "),
            "wireproxy upstream accepts unauthenticated CONNECT",
        )
        wrong = ExactConnectProxy._authorization(UPSTREAM_USERNAME, "0" * 64)
        require(
            self._probe_wireproxy_auth(wrong).startswith(b"HTTP/1.1 401 "),
            "wireproxy upstream accepts an invalid credential",
        )
        api_guard_port = self.api_guard.start(); talos_guard_port = self.talos_guard.start()
        self.listener_verified = self.api_guard.alive() and self.talos_guard.alive()
        require(self.listener_verified, "exact CONNECT guards failed to start")
        return api_guard_port, talos_guard_port

    def transport_alive(self) -> bool:
        return self.proxy is not None and self.proxy.poll() is None and self.api_guard.alive() and self.talos_guard.alive()

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
        )
        stdout = result.stdout if isinstance(result.stdout, str) else ""
        stderr = result.stderr if isinstance(result.stderr, str) else ""
        redacted = "[REDACTED-PROXY-CREDENTIAL]"
        for password in (self.api_password, self.talos_password, self.upstream_password):
            stdout = stdout.replace(password, redacted); stderr = stderr.replace(password, redacted)
        return ChildResult(result.returncode, stdout, stderr, self.transport_alive())

    def receipt_reconciled(self) -> None:
        self.cancellation.receipt_reconciled()

    def close(self) -> dict[str, Any]:
        api = self.api_guard.close(); talos = self.talos_guard.close()
        proxy_stopped = stop_process(self.proxy); self.proxy = None
        return {
            "apiGuard": api,
            "talosGuard": talos,
            "wireproxyProcessGroupStopped": proxy_stopped,
            "allGuardWorkersStopped": all(
                report["listenerStopped"] and report["workerThreadsStopped"] and report["connectionsClosed"]
                for report in (api, talos)
            ),
        }

def create_admin_kubeconfig(
    session: LiveSession,
    talosctl: Path,
    kubectl: Path,
    talosconfig: Path,
    destination: Path,
    talos_proxy: str,
    api_proxy: str,
    temp: Path,
) -> None:
    direct = temp / "talos-kubeconfig"
    environment = sanitized_environment() | {"HTTPS_PROXY": talos_proxy, "HTTP_PROXY": talos_proxy, "NO_PROXY": ""}
    generated = session.run_child(
        [str(talosctl), "--talosconfig", str(talosconfig), "--endpoints", API_HOST, "--nodes", API_HOST, "kubeconfig", str(direct), "--force", "--merge=false"],
        environment,
        receipt_pending=False,
        timeout=60,
    )
    require(generated.returncode == 0, "Talos administrator kubeconfig generation failed")
    os.chmod(direct, 0o600)
    flattened = session.run_child(
        [str(kubectl), "--kubeconfig", str(direct), "config", "view", "--raw", "--flatten", "--minify", "-o", "json"],
        sanitized_environment(),
        receipt_pending=False,
        require_transport=False,
        timeout=30,
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
    runner: str,
    mode: str,
    receipt: Path,
    revision: str,
    environment: dict[str, str],
    expected_status: str,
    *,
    allow_cancelled: bool,
) -> dict[str, Any]:
    result = cancellation.run(
        [sys.executable, "-I", str(ROOT / runner), mode, str(receipt), "--expected-protected-revision", revision],
        allow_cancelled=allow_cancelled,
        forward_signals=False,
        receipt_pending=False,
        timeout=60,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
    )
    require(result.returncode == 0, f"protected receipt verifier rejected {receipt.name}")
    output = result.stdout.strip() if isinstance(result.stdout, str) else ""
    require(output and "\n" not in output, f"protected receipt verifier output invalid: {receipt.name}")
    projection = json_object(output, f"verified {receipt.name}")
    require(projection.get("status") == expected_status, f"protected receipt status drift: {receipt.name}")
    require(projection.get("protectedRevision") == revision, f"protected receipt revision drift: {receipt.name}")
    require(
        isinstance(projection.get("receiptSha256"), str)
        and SHA256.fullmatch(projection["receiptSha256"]) is not None,
        f"protected receipt checksum projection invalid: {receipt.name}",
    )
    require(projection.get("civicAuthorityEffects") is False, f"protected receipt widened civic authority: {receipt.name}")
    return projection

def print_child(result: ChildResult) -> None:
    if result.stdout: print(result.stdout, end="")
    if result.stderr: print(result.stderr, end="", file=sys.stderr)

def receipt_record(projection: dict[str, Any] | None, path: Path | None) -> dict[str, Any]:
    return {
        "status": projection.get("status") if projection is not None else None,
        "canonicalSha256": projection.get("receiptSha256") if projection is not None else None,
        "fileSha256": owned_receipt_file_sha256(path) if path is not None and path.exists() else None,
    }

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
    parser.add_argument("--teardown-dormant-receipt", type=Path)
    parser.add_argument("--live", action="store_true")
    return parser.parse_args(argv)

def run_dormant_teardown(
    session: LiveSession,
    cancellation: CancellationState,
    revision: str,
    kubeconfig: Path,
    source_receipt: Path,
    output_receipt: Path,
    environment: dict[str, str],
) -> dict[str, Any]:
    result = session.run_child(
        [
            sys.executable,
            "-I",
            str(ROOT / BOOTSTRAP_RUNNER),
            "--teardown",
            "--expected-protected-revision",
            revision,
            "--kubeconfig",
            str(kubeconfig),
            "--recovery-receipt",
            str(source_receipt),
            "--receipt",
            str(output_receipt),
        ],
        environment,
        allow_cancelled=True,
        forward_signals=False,
        receipt_pending=True,
    )
    print_child(result)
    try:
        return verify_receipt_with_protected_cli(
            cancellation,
            BOOTSTRAP_RUNNER,
            "--verify-teardown-receipt",
            output_receipt,
            revision,
            environment,
            "dormant-torn-down",
            allow_cancelled=True,
        )
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


def main(argv: list[str] | None = None) -> int:
    receipt_dir: Path | None = None; receipt_sink: WrapperReceiptSink | None = None
    temp: Path | None = None; session: LiveSession | None = None
    cancellation = CancellationState(); cancellation_installed = False
    revision: str | None = None; protected_hashes: dict[str, str] = {}
    snapshot_hashes: dict[str, str] = {}; credentials: list[str] = []
    bootstrap_receipt: Path | None = None; recovery_receipt: Path | None = None
    teardown_receipt: Path | None = None; activation_receipt: Path | None = None
    source_dormant_projection: dict[str, Any] | None = None
    bootstrap_projection: dict[str, Any] | None = None
    teardown_projection: dict[str, Any] | None = None
    activation_projection: dict[str, Any] | None = None
    recovery_attempted = False; recovery_returncode: int | None = None
    base_status = "blocked"; error: str | None = None
    activation_committed = False; operation_succeeded = False
    listener_verified = False
    try:
        require(sys.flags.isolated == 1 and bool(sys.flags.safe_path), "wrapper requires python3 -I isolated safe-path mode")
        args = parse_args(argv); require(args.live is True, "wrapper requires explicit --live")
        revision = args.expected_protected_revision
        require(REVISION.fullmatch(revision) is not None, "protected revision must be lowercase SHA-1")

        cancellation.install(); cancellation_installed = True
        receipt_dir = reserve_output_directory(args.receipt_directory)
        receipt_sink = WrapperReceiptSink.reserve(receipt_dir / "transport-transaction.json")
        cancellation.checkpoint()
        protected_hashes = bind_protected_checkout(revision)
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

        verifier_environment = sanitized_environment() | {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin"}
        if args.teardown_dormant_receipt is not None:
            source_dormant_projection = verify_receipt_with_protected_cli(
                cancellation,
                BOOTSTRAP_RUNNER,
                "--verify-success-receipt",
                args.teardown_dormant_receipt,
                revision,
                verifier_environment,
                "dormant-ready",
                allow_cancelled=False,
            )

        temp = Path(tempfile.mkdtemp(prefix="roebel-participant-live-", dir="/private/tmp")); os.chmod(temp, 0o700)
        executable_dir = temp / "executables"; executable_dir.mkdir(mode=0o700)
        binary_sources = {
            "age": args.age_bin,
            "kubectl": args.kubectl_bin,
            "talosctl": args.talosctl_bin,
            "wireproxy": args.wireproxy_bin,
        }
        snapshots: dict[str, Path] = {}
        for label in sorted(binary_sources):
            snapshots[label] = snapshot_binary(binary_sources[label], label, executable_dir / label)
            snapshot_hashes[label] = file_sha256(snapshots[label])
            cancellation.checkpoint()
        fsync_directory(executable_dir)

        wireguard = temp / "wireguard.conf"; talosconfig = temp / "talosconfig.yaml"
        decrypt(cancellation, snapshots["age"], identity, encrypted_wg, wireguard)
        decrypt(cancellation, snapshots["age"], identity, encrypted_talos, talosconfig)

        api_password = secrets.token_hex(32); talos_password = secrets.token_hex(32); upstream_password = secrets.token_hex(32)
        credentials = [api_password, talos_password, upstream_password]
        require(
            all(len(value) == 64 for value in credentials) and len(set(credentials)) == 3,
            "proxy CSPRNG failed",
        )
        upstream_port = reserve_port()
        config = temp / "wireproxy.conf"
        write_private(config, wireproxy_config(upstream_port).encode())
        wireproxy_environment = sanitized_environment({
            WIREPROXY_USERNAME_ENV: UPSTREAM_USERNAME,
            WIREPROXY_PASSWORD_ENV: upstream_password,
        })
        config_test = cancellation.run(
            [str(snapshots["wireproxy"]), "-n", "-c", str(config)],
            timeout=10,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=wireproxy_environment,
        )
        cancellation.checkpoint()
        require(config_test.returncode == 0, "wireproxy rejected the protected one-shot configuration")

        session = LiveSession(
            temp,
            snapshots["wireproxy"],
            upstream_port,
            upstream_password,
            api_password,
            talos_password,
            cancellation,
        )
        api_guard_port, talos_guard_port = session.start_proxy(config)
        listener_verified = session.listener_verified
        kubeconfig = temp / "admin-kubeconfig.json"
        api_proxy = proxy_url(api_password, api_guard_port)
        talos_proxy = proxy_url(talos_password, talos_guard_port)
        create_admin_kubeconfig(
            session,
            snapshots["talosctl"],
            snapshots["kubectl"],
            talosconfig,
            kubeconfig,
            talos_proxy,
            api_proxy,
            temp,
        )
        child_environment = sanitized_environment() | {
            "PATH": f"{executable_dir}:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin",
        }

        if args.teardown_dormant_receipt is not None:
            teardown_receipt = receipt_dir / "participant-flux-dormant-teardown.json"
            teardown_projection = run_dormant_teardown(
                session,
                cancellation,
                revision,
                kubeconfig,
                args.teardown_dormant_receipt,
                teardown_receipt,
                child_environment,
            )
            base_status = "dormant-torn-down"; operation_succeeded = True
        else:
            bootstrap_receipt = receipt_dir / "participant-flux-bootstrap.json"
            bootstrap = session.run_child(
                [
                    sys.executable,
                    "-I",
                    str(ROOT / BOOTSTRAP_RUNNER),
                    "--live",
                    "--expected-protected-revision",
                    revision,
                    "--kubeconfig",
                    str(kubeconfig),
                    "--receipt",
                    str(bootstrap_receipt),
                ],
                child_environment,
            )
            print_child(bootstrap)
            bootstrap_verification_error: str | None = None
            try:
                if bootstrap_receipt.exists():
                    bootstrap_projection = verify_receipt_with_protected_cli(
                        cancellation,
                        BOOTSTRAP_RUNNER,
                        "--verify-success-receipt",
                        bootstrap_receipt,
                        revision,
                        child_environment,
                        "dormant-ready",
                        allow_cancelled=True,
                    )
            except (LiveTransportError, OSError) as exc:
                bootstrap_verification_error = str(exc)
            finally:
                session.receipt_reconciled()
            if bootstrap_projection is None:
                if bootstrap.returncode != 0 and bootstrap_receipt.exists() and session.transport_alive():
                    recovery_attempted = True
                    recovery_receipt = receipt_dir / "participant-flux-bootstrap-recovery.json"
                    recovery = session.run_child(
                        [
                            sys.executable,
                            "-I",
                            str(ROOT / BOOTSTRAP_RUNNER),
                            "--recover",
                            "--expected-protected-revision",
                            revision,
                            "--kubeconfig",
                            str(kubeconfig),
                            "--recovery-receipt",
                            str(bootstrap_receipt),
                            "--receipt",
                            str(recovery_receipt),
                        ],
                        child_environment,
                        allow_cancelled=True,
                        forward_signals=False,
                        receipt_pending=True,
                    )
                    recovery_returncode = recovery.returncode; print_child(recovery); session.receipt_reconciled()
                detail = bootstrap_verification_error or "no durable verified success receipt"
                raise LiveTransportError(f"dormant Flux bootstrap did not yield verified success: {detail}")

            if cancellation.signals or not session.transport_alive():
                if session.transport_alive():
                    teardown_receipt = receipt_dir / "participant-flux-dormant-teardown.json"
                    teardown_projection = run_dormant_teardown(
                        session,
                        cancellation,
                        revision,
                        kubeconfig,
                        bootstrap_receipt,
                        teardown_receipt,
                        child_environment,
                    )
                    base_status = "cancelled-dormant-torn-down" if cancellation.signals else "transport-lost-dormant-torn-down"
                    raise LiveTransportError("activation cancelled after exact dormant teardown")
                base_status = "dormant-cleanup-required"
                raise LiveTransportError("verified dormant bootstrap lost transport; exact teardown continuation required")

            activation_receipt = receipt_dir / "participant-gateway-activation.json"
            activation = session.run_child(
                [
                    sys.executable,
                    "-I",
                    str(ROOT / ACTIVATION_RUNNER),
                    "--live",
                    "--expected-protected-revision",
                    revision,
                    "--kubeconfig",
                    str(kubeconfig),
                    "--flux-bootstrap-receipt",
                    str(bootstrap_receipt),
                    "--receipt",
                    str(activation_receipt),
                ],
                child_environment,
            )
            print_child(activation)
            try:
                require(activation_receipt.exists(), "activation runner produced no durable receipt")
                activation_projection = verify_receipt_with_protected_cli(
                    cancellation,
                    ACTIVATION_RUNNER,
                    "--verify-success-receipt",
                    activation_receipt,
                    revision,
                    child_environment,
                    "activated",
                    allow_cancelled=True,
                )
            finally:
                session.receipt_reconciled()
            activation_committed = True; operation_succeeded = True; base_status = "activated"
    except BaseException as exc:
        error = str(exc) or type(exc).__name__
        if (
            bootstrap_projection is not None
            and activation_projection is None
            and teardown_projection is None
            and base_status == "blocked"
        ):
            base_status = "bootstrap-state-indeterminate"
        print(f"participant live wrapper blocked: {error}", file=sys.stderr)

    if cancellation_installed: cancellation.begin_finalization()
    cleanup_errors: list[str] = []
    session_cleanup: dict[str, Any] = {
        "apiGuard": {"listenerStopped": True, "workerThreadsStopped": True, "connectionsClosed": True, "workerLimit": 16},
        "talosGuard": {"listenerStopped": True, "workerThreadsStopped": True, "connectionsClosed": True, "workerLimit": 16},
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
        and plaintext_removed
    )

    def safe_receipt_record(projection: dict[str, Any] | None, path: Path | None) -> dict[str, Any]:
        nonlocal cleanup_complete
        try: return receipt_record(projection, path)
        except BaseException as exc:
            cleanup_errors.append(f"receipt evidence: {exc}"); cleanup_complete = False
            return {"status": projection.get("status") if projection else None, "canonicalSha256": projection.get("receiptSha256") if projection else None, "fileSha256": None}

    source_record = safe_receipt_record(source_dormant_projection, args.teardown_dormant_receipt if 'args' in locals() else None)
    bootstrap_record = safe_receipt_record(bootstrap_projection, bootstrap_receipt)
    teardown_record = safe_receipt_record(teardown_projection, teardown_receipt)
    activation_record = safe_receipt_record(activation_projection, activation_receipt)
    recovery_record = safe_receipt_record(None, recovery_receipt)
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
            "mode": "authenticated-exact-connect-guards-over-authenticated-wireproxy-http-upstream",
            "apiAuthority": f"{API_HOST}:{API_PORT}",
            "talosAuthority": f"{API_HOST}:{TALOS_PORT}",
            "perRunFrontAuthentication": True,
            "perRunUpstreamAuthentication": True,
            "upstreamCredentialExposedToProtectedRunners": False,
            "frontGuardCallerSelectedDestination": False,
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
            "wrapperReceiptCommit": "atomic-replace-file-and-parent-fsync",
        },
        "sourceDormant": source_record,
        "bootstrap": bootstrap_record,
        "recovery": recovery_record | {"attempted": recovery_attempted, "runnerReturnCode": recovery_returncode},
        "teardown": teardown_record,
        "activation": activation_record,
        "dormantContinuation": {
            "required": base_status in {"dormant-cleanup-required", "bootstrap-state-indeterminate"},
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
            print(f"participant live wrapper {label}: durable wrapper receipt failed: {exc}", file=sys.stderr)
    else:
        exit_code = 3
        print("participant live wrapper receipt-incomplete: wrapper receipt target unavailable", file=sys.stderr)
    if cancellation_installed: cancellation.restore()
    if activation_committed and (not cleanup_complete or not receipt_committed):
        return 3
    return exit_code

if __name__ == "__main__":
    raise SystemExit(main())
