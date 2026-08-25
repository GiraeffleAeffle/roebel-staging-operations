#!/usr/bin/env python3
"""Policy-owned, fail-closed participant-gateway activation executor.

This program deliberately accepts no evidence, manifest, route, command, or
allowlist from its caller.  A future protected policy bootstrap must add the
fixed descriptor named below.  Until then *both* modes stop before contacting
Kubernetes.  The live mode is consequently safe to ship before its policy.
"""
from __future__ import annotations

# The command-line executor must start in Python isolated/safe-path mode before
# importing anything except the built-in ``sys`` module.  This prevents an
# untracked ``scripts/secrets.py`` (or a PYTHONPATH entry) from shadowing a
# standard-library dependency before protected Git blobs are checked.
import sys as _bootstrap_sys
if __name__ == "__main__" and not (_bootstrap_sys.flags.isolated and _bootstrap_sys.flags.safe_path):
    print("activation blocked: invoke with python3 -I", file=_bootstrap_sys.stderr)
    raise SystemExit(2)

import argparse, base64, datetime as dt, hashlib, json, os, re, secrets, selectors, signal, socket, ssl, stat, subprocess, sys, tempfile, time, types, urllib.error, urllib.parse, urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

POLICY_PATH = "policy/staging-participant-gateway-activation-policy.json"
NAMESPACE, FLUX_NAMESPACE = "stadtstack-roebel-web-preview", "flux-roebel-staging"
NAME, SOURCE = "roebel-staging-participant-gateway", "roebel-staging-operations"
WORKBENCH_NAMESPACE, WORKBENCH_POLICY_NAME = "stadtstack-roebel-staging-lab", "roebel-staging-participant-workbench-ingress"
RECEIPT_SCHEMA = "roebel_staging_participant_gateway_activation_receipt_v4"
ROOT = Path(__file__).resolve().parent.parent
POLICY_MODULE_PATH = "scripts/staging_participant_gateway_policy.py"
WORKFLOW_PATH = ".github/workflows/staging-participant-gateway-activation.yml"

POLICY: Any = None

def compile_verified_policy_module_v4(source: bytes, rev: str) -> Any:
    """Compile only policy bytes already read from the exact protected blob."""
    revision(rev)
    require(isinstance(source, bytes) and source, "protected policy blob is empty")
    name = f"staging_participant_gateway_policy_{rev}"
    module = types.ModuleType(name)
    module.__file__ = f"git:{rev}:{POLICY_MODULE_PATH}"
    module.__package__ = ""
    sys.modules[name] = module
    try:
        code = compile(source, module.__file__, "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module

def bind_verified_policy_identity_v4(module: Any) -> None:
    """Fail closed if runner constants drift from the protected policy blob."""
    expected = (
        module.GATEWAY_NAMESPACE,
        module.FLUX_NAMESPACE,
        module.GATEWAY_NAME,
        module.FLUX_SOURCE_NAME,
        module.WORKBENCH_NAMESPACE,
        module.WORKBENCH_INGRESS_POLICY_NAME,
        module.POLICY_PATH,
    )
    actual = (
        NAMESPACE,
        FLUX_NAMESPACE,
        NAME,
        SOURCE,
        WORKBENCH_NAMESPACE,
        WORKBENCH_POLICY_NAME,
        POLICY_PATH,
    )
    require(actual == expected, "protected runner/policy identity drift")
PLAN_RECEIPT_SCHEMA = "roebel_staging_participant_gateway_activation_plan_v4"

class ActivationError(RuntimeError): pass
class CreateConflictError(ActivationError): pass
class TransportUncertainError(ActivationError): pass
class ActivationInterrupted(ActivationError):
    def __init__(self, signum: int):
        self.signum = signum
        super().__init__(f"activation interrupted by signal {signum}")

TRANSACTION_SIGNALS = (signal.SIGINT, signal.SIGTERM)

def install_transaction_signal_handlers_v4() -> dict[int, Any]:
    """Convert operator termination into a rollback-visible exception."""
    previous: dict[int, Any] = {}
    def interrupt(received: int, _frame: Any) -> None:
        raise ActivationInterrupted(received)
    try:
        for signum in TRANSACTION_SIGNALS:
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, interrupt)
    except (OSError, ValueError) as exc:
        for signum, handler in previous.items(): signal.signal(signum, handler)
        raise ActivationError("live activation requires controllable main-thread signal handlers") from exc
    return previous

def defer_transaction_signals_v4() -> None:
    """Ignore further termination while rollback/receipt durability completes."""
    for signum in TRANSACTION_SIGNALS: signal.signal(signum, signal.SIG_IGN)

def restore_transaction_signal_handlers_v4(previous: dict[int, Any]) -> None:
    for signum, handler in previous.items(): signal.signal(signum, handler)

def canonical(v: Any) -> str: return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
def digest(v: Any) -> str: return "sha256:" + hashlib.sha256(canonical(v).encode()).hexdigest()
def bytes_digest(v: bytes) -> str: return "sha256:" + hashlib.sha256(v).hexdigest()
def require(v: bool, msg: str) -> None:
    if not v: raise ActivationError(msg)
def revision(v: Any) -> str:
    require(isinstance(v, str) and len(v) == 40 and all(c in "0123456789abcdef" for c in v), "expected revision must be 40 lowercase hex")
    return v

def protected_checkout(rev: str) -> dict[str, str]:
    """Bind every executable repo file before any Kubernetes subprocess exists."""
    paths = (Path(__file__).relative_to(ROOT).as_posix(), POLICY_MODULE_PATH, POLICY_PATH, WORKFLOW_PATH, "scripts/verify-reviewed-render.py", "policy/repository-contract.json")
    hashes: dict[str, str] = {}
    for path in paths:
        local = ROOT / path
        require(local.is_file() and not local.is_symlink(), f"protected executable missing: {path}")
        expected = git_blob(rev, path)
        require(local.read_bytes() == expected, f"protected executable differs from exact Git blob: {path}")
        hashes[path] = bytes_digest(expected)
    diff = subprocess.run(["git", "-C", str(ROOT), "diff", "--quiet", rev, "--", *paths], check=False)
    cached = subprocess.run(["git", "-C", str(ROOT), "diff", "--cached", "--quiet", rev, "--", *paths], check=False)
    require(diff.returncode == 0 and cached.returncode == 0, "protected executable checkout is dirty")
    return hashes

@dataclass
class Result: code: int = 0; out: str = ""; err: str = ""
class Runner:
    def run(self, args: list[str], *, input_text: str | None = None, timeout: int | float = 10) -> Result:
        try: p = subprocess.run(args, input=input_text, text=True, capture_output=True, check=False, timeout=timeout)
        except subprocess.TimeoutExpired as exc: return Result(124, "", f"timeout after {timeout}s: {exc}")
        return Result(p.returncode, p.stdout, p.stderr)
def checked(r: Runner, args: list[str], label: str, input_text: str | None = None, timeout: int | float | None = None) -> str:
    kwargs: dict[str, Any] = {"input_text": input_text}
    if timeout is not None: kwargs["timeout"] = timeout
    x = r.run(args, **kwargs)
    if x.code: raise _checked_error(x, label)
    return x.out
def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result: raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result

def json_value(raw: str, label: str) -> Any:
    try: value = json.loads(raw, object_pairs_hook=_unique_object)
    except ValueError as exc: raise ActivationError(f"{label}: invalid or duplicate-key JSON") from exc
    return value

def obj(raw: str, label: str) -> dict[str, Any]:
    try: value = json.loads(raw, object_pairs_hook=_unique_object)
    except json.JSONDecodeError as exc: raise ActivationError(f"{label}: invalid JSON") from exc
    except ValueError as exc: raise ActivationError(f"{label}: duplicate JSON key") from exc
    require(isinstance(value, dict), f"{label}: JSON object required"); return value
def kb(kubeconfig: str) -> list[str]: return ["kubectl", "--kubeconfig", kubeconfig]
def get(r: Runner, args: list[str], label: str) -> dict[str, Any]: return obj(checked(r, args + ["-o", "json"], label), label)
def git_blob(rev: str, path: str) -> bytes:
    # Both revision and path originate in fixed code/policy, never CLI/evidence.
    try:
        p = subprocess.run(
            ["git", "-C", str(ROOT), "show", f"{rev}:{path}"],
            capture_output=True,
            check=False,
            timeout=10,
        )
    except subprocess.TimeoutExpired as exc:
        raise ActivationError(f"protected Git blob read timed out: {path}") from exc
    if p.returncode: raise ActivationError(f"protected Git blob unavailable: {path}")
    return p.stdout
def live_obj(r: Runner, kube: str, kind: str, name: str, namespace: str) -> dict[str, Any]: return get(r, kb(kube) + ["-n", namespace, "get", kind, name], f"live {kind}/{name}")
def public_projection(value: Any) -> Any:
    """Policy and receipts cannot carry Secret data; refuse it rather than scrub."""
    encoded = canonical(value).lower()
    require(not any(x in encoded for x in ('"data"', '"stringdata"', '"token"', '"password"', '"privatekey"')), "secret-shaped value is forbidden")
    return value

def policy(rev: str) -> dict[str, Any]:
    path = ROOT / POLICY_PATH
    require(path.is_file() and not path.is_symlink(), "protected activation policy descriptor is not wired")
    raw = path.read_bytes()
    require(raw == git_blob(rev, POLICY_PATH), "policy descriptor is not the exact checked-out protected Git blob")
    p = obj(raw.decode(), "activation policy descriptor"); public_projection(p)
    try: return POLICY.validate_activation_policy(p)
    except POLICY.PolicyError as exc: raise ActivationError(str(exc)) from exc

def dry_run_plan(p: dict[str, Any], rev: str, runner_hashes: dict[str, str]) -> dict[str, Any]:
    blockers = list(POLICY.activation_blockers(p))
    return {
        "schemaVersion": PLAN_RECEIPT_SCHEMA,
        "status": "blocked-policy-incomplete" if blockers else "ready-no-cluster-plan",
        "mode": "dry-run",
        "protectedRevision": rev,
        "activationReady": p["activationReady"] is True and not blockers,
        "blockers": blockers,
        "activationPolicySha256": POLICY.activation_policy_sha256(p),
        "protectedRunnerFileSha256": runner_hashes,
        "renderFiles": list(POLICY.ALL_RENDER_FILES),
        "fluxTransaction": {"owners": ["gateway", "workbenchIngress"], "initialState": "both-suspended", "failureState": "both-suspended"},
        "kubernetesContacted": False,
        "callerEvidenceAccepted": False,
    }

class ReceiptSink:
    """A pre-reserved, non-overwriting, durably committed receipt target."""
    def __init__(self, path: Path, device: int, inode: int):
        self.path, self.device, self.inode = path, device, inode

    @classmethod
    def reserve(cls, path: Path) -> "ReceiptSink":
        path = Path(os.path.realpath(os.path.abspath(path))); parent = path.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent_info = os.lstat(parent)
        require(parent.resolve() == parent and stat.S_ISDIR(parent_info.st_mode) and parent_info.st_uid == os.geteuid() and stat.S_IMODE(parent_info.st_mode) & 0o022 == 0, "receipt parent must be an owned non-writable real directory")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"): flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        try:
            os.fchmod(fd, 0o600); os.fsync(fd); info = os.fstat(fd)
        finally: os.close(fd)
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try: os.fsync(directory)
        finally: os.close(directory)
        return cls(path, info.st_dev, info.st_ino)

    def commit(self, value: dict[str, Any]) -> None:
        public_projection(value); final = dict(value); final["canonicalSha256"] = digest(value)
        current = os.lstat(self.path)
        require(stat.S_ISREG(current.st_mode) and current.st_dev == self.device and current.st_ino == self.inode, "reserved receipt target identity changed")
        fd, raw_name = tempfile.mkstemp(prefix=".participant-receipt-", dir=self.path.parent)
        tmp = Path(raw_name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=True) as stream:
                stream.write((canonical(final) + "\n").encode()); stream.flush(); os.fsync(stream.fileno())
            os.replace(tmp, self.path)
            replaced = os.lstat(self.path)
            self.device, self.inode = replaced.st_dev, replaced.st_ino
            directory = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try: os.fsync(directory)
            finally: os.close(directory)
            committed = os.lstat(self.path)
            require(stat.S_ISREG(committed.st_mode) and stat.S_IMODE(committed.st_mode) == 0o600, "committed receipt mode drift")
            self.device, self.inode = committed.st_dev, committed.st_ino
        finally:
            try: tmp.unlink()
            except FileNotFoundError: pass

@dataclass
class KubeconfigSnapshot:
    path: Path
    directory: Path
    api_origin: str
    hostname: str
    port: int
    tls_server_name: str
    ca_pem: bytes
    ca_sha256: str

    def close(self) -> None:
        try: self.path.unlink()
        except FileNotFoundError: pass
        try: self.directory.rmdir()
        except FileNotFoundError: pass

def _api_origin(server: str) -> tuple[str, str, int]:
    try: parsed = urllib.parse.urlsplit(server)
    except ValueError as exc: raise ActivationError("Kubernetes API server URL invalid") from exc
    require(
        parsed.scheme == "https" and parsed.hostname is not None
        and parsed.username is None and parsed.password is None
        and parsed.query == "" and parsed.fragment == "" and parsed.path in {"", "/"},
        "Kubernetes API server must be an HTTPS origin without userinfo, path, query, or fragment",
    )
    try: port = parsed.port or 443
    except ValueError as exc: raise ActivationError("Kubernetes API server port invalid") from exc
    host = parsed.hostname.lower(); bracketed = f"[{host}]" if ":" in host else host
    return f"https://{bracketed}" + ("" if port == 443 else f":{port}"), host, port

def snapshot_kubeconfig_v4(explicit: str, r: Runner) -> KubeconfigSnapshot:
    """Flatten one explicit kubeconfig into an owned 0600 one-use snapshot."""
    source = Path(explicit).absolute(); info = os.lstat(source)
    require(stat.S_ISREG(info.st_mode) and not source.is_symlink(), "explicit kubeconfig must be a regular non-symlink file")
    flattened_result = r.run(["kubectl", "--kubeconfig", str(source), "config", "view", "--raw", "--flatten", "--minify", "-o", "json"])
    require(flattened_result.code == 0, "explicit kubeconfig flattening failed")
    flattened = flattened_result.out
    config = obj(flattened, "flattened kubeconfig")
    clusters, contexts, users = config.get("clusters"), config.get("contexts"), config.get("users")
    require(all(isinstance(value, list) and len(value) == 1 for value in (clusters, contexts, users)), "flattened kubeconfig must contain exactly one cluster, context, and user")
    require(config.get("current-context") == contexts[0].get("name"), "flattened kubeconfig current context drift")
    cluster = clusters[0].get("cluster", {}); require(isinstance(cluster, dict), "flattened kubeconfig cluster absent")
    require(not cluster.get("insecure-skip-tls-verify") and "proxy-url" not in cluster, "insecure or proxied Kubernetes API configuration forbidden")
    origin, hostname, port = _api_origin(cluster.get("server", ""))
    encoded_ca = cluster.get("certificate-authority-data")
    require(isinstance(encoded_ca, str) and encoded_ca and "certificate-authority" not in cluster, "flattened kubeconfig must embed its CA")
    try: ca_pem = base64.b64decode(encoded_ca, validate=True)
    except (ValueError, TypeError) as exc: raise ActivationError("flattened kubeconfig CA data invalid") from exc
    require(b"BEGIN CERTIFICATE" in ca_pem and len(ca_pem) <= 1024 * 1024, "flattened kubeconfig CA certificate invalid")
    tls_name = cluster.get("tls-server-name", hostname)
    require(isinstance(tls_name, str) and tls_name and not any(ch.isspace() for ch in tls_name), "Kubernetes TLS server name invalid")
    user = users[0].get("user", {}); require(isinstance(user, dict) and user, "flattened kubeconfig user absent")
    forbidden_user_fields = {"exec", "auth-provider", "client-certificate", "client-key", "tokenFile"}
    require(not (forbidden_user_fields & set(user)), "flattened kubeconfig still depends on external credential execution or files")
    directory = Path(tempfile.mkdtemp(prefix="participant-kubeconfig-")); path = directory / "config"; fd = -1
    try:
        os.chmod(directory, 0o700)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"): flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        os.fchmod(fd, 0o600)
        raw = canonical(config).encode() + b"\n"
        stream = os.fdopen(fd, "wb", closefd=True); fd = -1
        with stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        parent = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try: os.fsync(parent)
        finally: os.close(parent)
    except BaseException:
        if fd >= 0:
            try: os.close(fd)
            except OSError: pass
        try: path.unlink()
        except FileNotFoundError: pass
        try: directory.rmdir()
        except FileNotFoundError: pass
        except OSError as cleanup_error:
            raise ActivationError("failed to remove incomplete kubeconfig snapshot") from cleanup_error
        raise
    return KubeconfigSnapshot(path, directory, origin, hostname, port, tls_name, ca_pem, bytes_digest(ca_pem))

def _api_server_spki_v4(snapshot: KubeconfigSnapshot, timeout: int | float) -> str:
    context = ssl.create_default_context(cadata=snapshot.ca_pem.decode("ascii"))
    with socket.create_connection((snapshot.hostname, snapshot.port), timeout=timeout) as connection:
        with context.wrap_socket(connection, server_hostname=snapshot.tls_server_name) as secured:
            certificate = secured.getpeercert(binary_form=True)
    require(isinstance(certificate, bytes) and certificate, "Kubernetes API TLS certificate absent")
    first = subprocess.run(["openssl", "x509", "-inform", "DER", "-pubkey", "-noout"], input=certificate, capture_output=True, check=False, timeout=timeout)
    require(first.returncode == 0 and first.stdout, "Kubernetes API certificate SPKI extraction failed")
    second = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"], input=first.stdout, capture_output=True, check=False, timeout=timeout)
    require(second.returncode == 0 and second.stdout, "Kubernetes API SPKI normalization failed")
    return bytes_digest(second.stdout)
def raw_delete(kube: str, resource_path: str, payload: str) -> None:
    """Issue a real Kubernetes HTTP DELETE through a short-lived kubectl proxy.

    ``kubectl delete`` has no UID+resourceVersion DeleteOptions transport.
    The proxy authenticates with the explicit kubeconfig; urllib sends the raw
    DELETE body unchanged and Kubernetes enforces its preconditions.
    """
    # Let kubectl choose the port atomically; parsing its loopback-only startup
    # line avoids reserving and releasing a raceable port in this process.  The
    # proxy is credentialed, so expose only this exact escaped resource path to
    # other loopback processes during its bounded lifetime.
    allowed = re.fullmatch(
        r"/(?:api/v1|apis/(?:apps|networking\.k8s\.io)/v1)/namespaces/"
        r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?/(?:ingresses|networkpolicies|deployments|services|serviceaccounts)/"
        r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?",
        resource_path,
    )
    require(allowed is not None, "raw rollback delete resource path outside closed policy")
    # The closed path grammar above contains no regexp metacharacters except
    # dots. Avoid Python's ``re.escape`` because its ``\-`` escape is not
    # portable to kubectl proxy's Go/RE2 regexp parser.
    accept_paths = "^" + resource_path.replace(".", r"\.") + "$"
    process = subprocess.Popen(
        kb(kube) + [
            "proxy", "--port=0", "--address=127.0.0.1",
            "--accept-hosts=^127\\.0\\.0\\.1$",
            f"--accept-paths={accept_paths}",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    selector = selectors.DefaultSelector()
    try:
        require(process.stdout is not None, "kubectl proxy output pipe unavailable")
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + 10; port: int | None = None; output = b""
        while time.monotonic() < deadline:
            if process.poll() is not None: raise ActivationError("kubectl proxy terminated before raw rollback delete")
            remaining = max(0.0, deadline - time.monotonic())
            events = selector.select(timeout=min(0.25, remaining))
            if not events: continue
            chunk = os.read(process.stdout.fileno(), 4096)
            if not chunk: continue
            output = (output + chunk)[-16384:]
            match = re.search(rb"Starting to serve on 127\.0\.0\.1:(\d+)", output)
            if match:
                try: port = int(match.group(1))
                except ValueError as exc: raise ActivationError("kubectl proxy emitted malformed loopback port") from exc
                break
        require(port is not None, "kubectl proxy did not become ready for raw rollback delete")
        request = urllib.request.Request(f"http://127.0.0.1:{port}{resource_path}", data=payload.encode(), headers={"Content-Type": "application/json"}, method="DELETE")
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(request, timeout=15) as response: require(200 <= response.status < 300, "raw rollback delete did not return success")
        except urllib.error.HTTPError as exc:
            if exc.code != 404: raise ActivationError(f"raw rollback delete rejected by Kubernetes: HTTP {exc.code}") from exc
    finally:
        selector.close()
        process.terminate()
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
        if process.stdout is not None: process.stdout.close()


def _terminate_process_group(process: subprocess.Popen[Any]) -> None:
    """Bounded cleanup for a subprocess created with ``start_new_session``."""
    if process.poll() is not None: return
    try: os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError: return
    try: process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try: os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        process.wait(timeout=5)

@dataclass
class CreatedV4:
    logical_name: str
    desired: dict[str, Any]
    observed: dict[str, Any]
    receipt: dict[str, Any]

@dataclass(frozen=True)
class PreservedV4:
    label: str
    target: dict[str, str]
    value: dict[str, Any]
    canonical_sha256: str

HAPROXY_NAMESPACE = "ingress-system"
HAPROXY_DAEMONSET = "haproxy-ingress"

def _policy_call(function: Any, *args: Any, **kwargs: Any) -> Any:
    try: return function(*args, **kwargs)
    except POLICY.PolicyError as exc: raise ActivationError(str(exc)) from exc

def get_optional(r: Runner, kubeconfig: str, kind: str, name: str, namespace: str) -> dict[str, Any] | None:
    result = r.run(kb(kubeconfig) + ["-n", namespace, "get", kind, name, "-o", "json"])
    if result.code:
        text = (result.out + "\n" + result.err).lower()
        if "notfound" in text or re.search(r"\b404\b", text): return None
        raise _checked_error(result, f"get {kind}/{namespace}/{name}")
    return obj(result.out, f"{kind}/{namespace}/{name}")

def _checked_error(result: Result, label: str) -> ActivationError:
    text = (result.out + "\n" + result.err).strip(); lowered = text.lower()
    if "alreadyexists" in lowered or re.search(r"\b409\b", lowered): return CreateConflictError(f"{label}: create conflict; adoption forbidden")
    markers = ("context deadline exceeded", "connection reset", "connection refused", "connection timed out", "i/o timeout", "tls handshake timeout", "unexpected eof", "timeout after", "timeout:")
    if result.code == 124 or any(marker in lowered for marker in markers): return TransportUncertainError(f"{label}: API transport outcome uncertain: {text[:320]}")
    return ActivationError(f"{label}: {text[:400]}")

def _expected_render(p: dict[str, Any]) -> dict[str, tuple[str, Any]]:
    expected = _policy_call(POLICY.expected_gateway_resources, p)
    gateway, workbench = POLICY.GATEWAY_ROOT, POLICY.WORKBENCH_INGRESS_ROOT
    return {
        f"{gateway}/networkpolicy.json": ("object", expected["networkPolicy"]),
        f"{gateway}/serviceaccount.json": ("object", expected["serviceAccount"]),
        f"{gateway}/service.json": ("object", expected["service"]),
        f"{gateway}/deployment.json": ("object", expected["deployment"]),
        f"{gateway}/ingress.json": ("object", expected["ingress"]),
        f"{gateway}/kustomization.yaml": ("text", expected["kustomization"]),
        f"{gateway}/runtime-pin.json": ("json", expected["runtimePin"]),
        f"{workbench}/networkpolicy.json": ("object", expected["workbenchIngressNetworkPolicy"]),
        f"{workbench}/kustomization.yaml": ("text", expected["workbenchIngressKustomization"]),
    }

def render_v4(rev: str, p: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Load the exact nine-file ordinary render from protected Git blobs."""
    expectations = _expected_render(p)
    require(set(expectations) == set(POLICY.ALL_RENDER_FILES), "participant render file set drift")
    logical = {
        f"{POLICY.GATEWAY_ROOT}/networkpolicy.json": "gateway.networkPolicy",
        f"{POLICY.GATEWAY_ROOT}/serviceaccount.json": "gateway.serviceAccount",
        f"{POLICY.GATEWAY_ROOT}/service.json": "gateway.service",
        f"{POLICY.GATEWAY_ROOT}/deployment.json": "gateway.deployment",
        f"{POLICY.GATEWAY_ROOT}/ingress.json": "gateway.ingress",
        f"{POLICY.WORKBENCH_INGRESS_ROOT}/networkpolicy.json": "workbenchIngress.networkPolicy",
    }
    result: dict[str, dict[str, Any]] = {}
    for path, (encoding, expected) in expectations.items():
        raw = git_blob(rev, path)
        if encoding == "text": require(raw.decode() == expected, f"render Git blob drift: {path}"); continue
        parsed = obj(raw.decode(), path)
        if encoding == "json": require(parsed == expected, f"runtime pin Git blob drift: {path}"); continue
        _policy_call(POLICY.require_semantically_equal, parsed, expected, path)
        result[logical[path]] = {"path": path, "desired": expected, "blobSha256": bytes_digest(raw)}
    require(set(result) == set(logical.values()), "participant render object inventory drift")
    return result

def _definite_create_conflict(result: Result) -> bool:
    text = (result.out + "\n" + result.err).lower()
    return result.code != 0 and ("alreadyexists" in text or re.search(r"\b409\b", text) is not None)

def exact_absence_preflight_v4(r: Runner, kubeconfig: str, rendered: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Reserve the transaction only when all six exact names are absent."""
    require(len(rendered) == 6, "exact six-target render inventory required")
    targets = []
    for logical_name in sorted(rendered):
        desired = rendered[logical_name]["desired"]; metadata = desired["metadata"]
        found = get_optional(r, kubeconfig, desired["kind"].lower(), metadata["name"], metadata["namespace"])
        require(found is None, f"activation target already exists; adoption forbidden: {logical_name}")
        targets.append({"logicalName": logical_name, "kind": desired["kind"], "namespace": metadata["namespace"], "name": metadata["name"], "absent": True})
    return {"status": "all-six-exact-target-names-absent", "targets": targets}

def create_v4(r: Runner, kubeconfig: str, logical_name: str, rendered: dict[str, Any], operation_nonce: str) -> CreatedV4:
    static_desired = rendered["desired"]
    desired = _policy_call(POLICY.with_operation_nonce, static_desired, operation_nonce)
    metadata = desired["metadata"]
    args = kb(kubeconfig) + ["-n", metadata["namespace"], "create", "-f", "-", "-o", "json"]
    response = r.run(args, input_text=canonical(desired))
    if _definite_create_conflict(response):
        # A lost response from an earlier actor is intentionally not inferred:
        # without this run's nonce in an admitted response it is never owned.
        raise CreateConflictError(f"create {logical_name}: create conflict; adoption forbidden")
    outcome = "http-201-created"; observed: dict[str, Any] | None = None
    if response.code == 0:
        try:
            candidate = obj(response.out, f"created {logical_name}")
            _policy_call(POLICY.bind_create_result, outcome=outcome, observed=candidate, desired=desired, label=logical_name, operation_nonce=operation_nonce)
            observed = candidate
        except Exception:
            # Once the create was sent, even rc=0 with a malformed/unbindable
            # response is uncertain and must be discovered or rolled back.
            observed = None
    if observed is None:
        outcome = "post-send-uncertain-discovered"
        try:
            discovered = live_obj(r, kubeconfig, desired["kind"].lower(), metadata["name"], metadata["namespace"])
            _policy_call(POLICY.bind_create_result, outcome=outcome, observed=discovered, desired=desired, label=logical_name, operation_nonce=operation_nonce)
            observed = discovered
        except Exception as exc:
            raise TransportUncertainError(f"{logical_name}: post-send create outcome unresolved") from exc
    receipt = _policy_call(POLICY.bind_create_result, outcome=outcome, observed=observed, desired=desired, label=logical_name, operation_nonce=operation_nonce)
    receipt |= {"protectedRenderPath": rendered["path"], "protectedRenderBlobSha256": rendered["blobSha256"], "temporaryNonceRemoved": False}
    return CreatedV4(logical_name, static_desired, observed, receipt)

def rediscover_uncertain_create_v4(r: Runner, kubeconfig: str, logical_name: str, rendered: dict[str, Any], operation_nonce: str, timeout: int | float) -> CreatedV4 | None:
    """Boundedly recover only this run's exact nonce-marked uncertain create."""
    static_desired = rendered["desired"]; desired = _policy_call(POLICY.with_operation_nonce, static_desired, operation_nonce); metadata = desired["metadata"]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try: observed = get_optional(r, kubeconfig, desired["kind"].lower(), metadata["name"], metadata["namespace"])
        except ActivationError:
            time.sleep(0.25); continue
        if observed is None:
            time.sleep(0.25); continue
        receipt = _policy_call(POLICY.bind_create_result, outcome="post-send-uncertain-discovered", observed=observed, desired=desired, label=logical_name, operation_nonce=operation_nonce)
        receipt |= {"protectedRenderPath": rendered["path"], "protectedRenderBlobSha256": rendered["blobSha256"], "temporaryNonceRemoved": False, "recoveredDuringRollbackEntry": True}
        return CreatedV4(logical_name, static_desired, observed, receipt)
    return None

def remove_operation_nonce_v4(r: Runner, kubeconfig: str, created: CreatedV4, operation_nonce: str) -> dict[str, Any]:
    metadata = created.observed.get("metadata", {}); uid, rv = metadata.get("uid"), metadata.get("resourceVersion")
    require(isinstance(uid, str) and uid and isinstance(rv, str) and rv.isdigit(), f"{created.logical_name} nonce-removal preconditions absent")
    annotation_path = "/metadata/annotations/" + POLICY.OPERATION_NONCE_ANNOTATION.replace("~", "~0").replace("/", "~1")
    patch = [
        {"op": "test", "path": "/metadata/uid", "value": uid},
        {"op": "test", "path": "/metadata/resourceVersion", "value": rv},
        {"op": "test", "path": annotation_path, "value": operation_nonce},
        {"op": "remove", "path": annotation_path},
    ]
    desired_metadata = created.desired["metadata"]
    raw = checked(
        r,
        kb(kubeconfig) + ["-n", desired_metadata["namespace"], "patch", created.desired["kind"].lower(), desired_metadata["name"], "--type=json", "-p", canonical(patch), "-o", "json"],
        f"{created.logical_name} remove operation nonce",
    )
    after = obj(raw, f"{created.logical_name} nonce-removal response")
    require(after.get("metadata", {}).get("uid") == uid, f"{created.logical_name} UID changed during nonce removal")
    _policy_call(POLICY.require_semantically_equal, after, created.desired, f"{created.logical_name} post-nonce semantics")
    created.observed = after; created.receipt["temporaryNonceRemoved"] = True
    created.receipt["postNonceRemovalResourceVersion"] = after.get("metadata", {}).get("resourceVersion")
    return after

def _target_live(r: Runner, kubeconfig: str, target: dict[str, str]) -> dict[str, Any]:
    return live_obj(r, kubeconfig, target["kind"].lower(), target["name"], target["namespace"])

def flux_preflight_v4(r: Runner, kubeconfig: str, p: dict[str, Any], rev: str) -> dict[str, Any]:
    source = shared_source_revision_v4(r, kubeconfig, rev)

    builders = {"gateway": POLICY.gateway_flux_objects, "workbenchIngress": POLICY.workbench_ingress_flux_objects}
    owners: dict[str, dict[str, Any]] = {}
    for owner, builder in builders.items():
        expected = _policy_call(builder, suspended=True); live: dict[str, Any] = {}
        for key in ("serviceAccount", "role", "roleBinding", "kustomization"):
            target = p["gitOps"]["reconcilers"][owner][key]; live[key] = _target_live(r, kubeconfig, target)
            _policy_call(POLICY.require_semantically_equal, live[key], expected[key], f"{owner} dormant {key}")
        require(live["kustomization"].get("spec", {}).get("suspend") is True, f"{owner} Kustomization not dormant")
        owners[owner] = live
    return {"source": source, "owners": owners}

def shared_source_revision_v4(r: Runner, kubeconfig: str, rev: str) -> dict[str, Any]:
    source = live_obj(r, kubeconfig, "gitrepository", SOURCE, FLUX_NAMESPACE)
    _policy_call(POLICY.require_semantically_equal, source, POLICY.expected_shared_flux_source_projection(), "shared Flux source")
    require(source.get("spec", {}).get("suspend") is not True, "shared Flux source suspended")
    expected_revision = f"main@sha1:{rev}"; status = source.get("status", {})
    require(status.get("artifact", {}).get("revision") == expected_revision, "shared Flux source artifact revision drift")
    require(status.get("observedGeneration") == source.get("metadata", {}).get("generation"), "shared Flux source generation not observed")
    ready = next((condition for condition in status.get("conditions", []) if condition.get("type") == "Ready"), None)
    require(isinstance(ready, dict) and ready.get("status") == "True", "shared Flux source not Ready")
    return source

def cas_flux_v4(r: Runner, kubeconfig: str, p: dict[str, Any], owner: str, before: dict[str, Any], suspend: bool) -> dict[str, Any]:
    metadata = before.get("metadata", {}); require(metadata.get("uid") and str(metadata.get("resourceVersion", "")).isdigit(), f"{owner} CAS preconditions absent")
    target = p["gitOps"]["reconcilers"][owner]["kustomization"]
    patch_body = canonical({"metadata": {"resourceVersion": metadata["resourceVersion"]}, "spec": {"suspend": suspend}})
    raw = checked(r, kb(kubeconfig) + ["-n", target["namespace"], "patch", "kustomization", target["name"], "--type=merge", "-p", patch_body, "-o", "json"], f"{owner} CAS {'suspend' if suspend else 'unsuspend'}")
    after = obj(raw, f"{owner} CAS response")
    require(after.get("metadata", {}).get("uid") == metadata["uid"], f"{owner} Kustomization UID changed")
    require(after.get("spec", {}).get("suspend") is suspend, f"{owner} CAS ambiguous")
    require(int(after.get("metadata", {}).get("resourceVersion", "0")) > int(metadata["resourceVersion"]), f"{owner} CAS resourceVersion did not advance")
    builder = POLICY.gateway_flux_objects if owner == "gateway" else POLICY.workbench_ingress_flux_objects
    _policy_call(POLICY.require_semantically_equal, after, _policy_call(builder, suspended=suspend)["kustomization"], f"{owner} Kustomization CAS")
    return after

def flux_ready_v4(value: dict[str, Any], owner: str, uid: str, rev: str) -> dict[str, Any]:
    metadata, status = value.get("metadata", {}), value.get("status", {})
    require(metadata.get("uid") == uid and value.get("spec", {}).get("suspend") is False, f"{owner} active identity drift")
    require(status.get("observedGeneration") == metadata.get("generation"), f"{owner} observedGeneration drift")
    ready = next((condition for condition in status.get("conditions", []) if condition.get("type") == "Ready"), None)
    require(isinstance(ready, dict) and ready.get("status") == "True", f"{owner} not Ready")
    if "observedGeneration" in ready: require(ready["observedGeneration"] == metadata.get("generation"), f"{owner} Ready generation drift")
    expected = f"main@sha1:{rev}"; require(status.get("lastAppliedRevision") == expected, f"{owner} applied revision drift")
    if status.get("lastAttemptedRevision") is not None: require(status["lastAttemptedRevision"] == expected, f"{owner} attempted revision drift")
    return {"uid": uid, "resourceVersion": metadata.get("resourceVersion"), "observedGeneration": status["observedGeneration"], "lastAppliedRevision": expected, "ready": True}

def unsuspend_both_v4(r: Runner, kubeconfig: str, p: dict[str, Any], bootstrap: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for owner in ("gateway", "workbenchIngress"):
        result[owner] = cas_flux_v4(r, kubeconfig, p, owner, bootstrap["owners"][owner]["kustomization"], False)
    return result

def wait_both_ready_v4(r: Runner, kubeconfig: str, p: dict[str, Any], bootstrap: dict[str, Any], rev: str) -> dict[str, Any]:
    timeout = p["httpBoundary"]["timeoutsSeconds"]["fluxReady"]; result = {}
    for owner in ("gateway", "workbenchIngress"):
        target = p["gitOps"]["reconcilers"][owner]["kustomization"]
        checked(r, kb(kubeconfig) + ["-n", target["namespace"], "wait", "--for=condition=Ready", f"kustomization/{target['name']}", f"--timeout={timeout}s"], f"{owner} Flux readiness", timeout=timeout + 5)
        live = _target_live(r, kubeconfig, target)
        result[owner] = flux_ready_v4(live, owner, bootstrap["owners"][owner]["kustomization"]["metadata"]["uid"], rev)
    return result

def preservation_v4(r: Runner, kubeconfig: str, p: dict[str, Any]) -> dict[str, PreservedV4]:
    result = {}
    for label, descriptor in p["preservation"].items():
        value = _target_live(r, kubeconfig, descriptor["target"])
        result[label] = PreservedV4(label, descriptor["target"], value, digest(value))
    return result

def verify_preservation_v4(r: Runner, kubeconfig: str, snapshots: dict[str, PreservedV4]) -> dict[str, Any]:
    result = {}
    for label, snapshot in snapshots.items():
        after = _target_live(r, kubeconfig, snapshot.target); after_hash = digest(after)
        require(after_hash == snapshot.canonical_sha256, f"preserved {label} changed")
        result[label] = {"target": snapshot.target, "beforeCanonicalSha256": snapshot.canonical_sha256, "afterCanonicalSha256": after_hash, "byteIdenticalCanonicalJson": True}
    return result

def secret_materialization_v4(r: Runner, kubeconfig: str, p: dict[str, Any]) -> dict[str, Any]:
    template = '{{.metadata.uid}}{{"\\n"}}{{.metadata.resourceVersion}}{{"\\n"}}{{range $k,$v := .data}}{{$k}}{{"\\n"}}{{end}}'; result = {}
    for label, reference in p["runtime"]["secretReferences"].items():
        raw = checked(r, kb(kubeconfig) + ["-n", reference["namespace"], "get", "secret", reference["name"], "-o", f"go-template={template}"], f"Secret keyset {label}")
        lines = [line for line in raw.splitlines() if line]; require(len(lines) >= 2, f"Secret {label} metadata absent")
        uid, rv, *keys = lines; require(rv.isdigit() and sorted(keys) == sorted(reference["keys"]), f"Secret {label} keyset drift")
        result[label] = {"name": reference["name"], "namespace": reference["namespace"], "uid": uid, "resourceVersion": rv, "keys": sorted(keys), "valuesRead": False}
    return {"status": "exact-keysets-present-without-reading-values", "secrets": result}

def require_same_secret_materialization_v4(before: dict[str, Any], after: dict[str, Any], label: str) -> None:
    require(after == before, f"Secret identity/keyset/resourceVersion changed {label}")

def cluster_binding_v4(r: Runner, snapshot: KubeconfigSnapshot, p: dict[str, Any]) -> dict[str, Any]:
    """Bind the snapshotted credentials to the protected cluster identity."""
    expected = p["clusterIdentity"]
    require(snapshot.api_origin == expected["apiOrigin"], "Kubernetes API origin differs from protected identity")
    require(snapshot.ca_sha256 == expected["caCertificateSha256"], "Kubernetes CA differs from protected identity")
    spki = _api_server_spki_v4(snapshot, p["httpBoundary"]["timeoutsSeconds"]["routeRequest"])
    require(spki == expected["apiServerSpkiSha256"], "Kubernetes API SPKI differs from protected identity")
    namespace = obj(checked(r, kb(str(snapshot.path)) + ["get", "namespace", "kube-system", "-o", "json"], "kube-system namespace identity"), "kube-system namespace")
    metadata = namespace.get("metadata", {}); uid, rv = metadata.get("uid"), metadata.get("resourceVersion")
    require(uid == expected["kubeSystemNamespaceUid"] and isinstance(rv, str) and rv.isdigit(), "Kubernetes immutable cluster identifier drift")
    return {
        "apiOrigin": snapshot.api_origin,
        "caCertificateSha256": snapshot.ca_sha256,
        "apiServerSpkiSha256": spki,
        "kubeSystemNamespaceUid": uid,
        "kubeSystemNamespaceResourceVersion": rv,
        "credentialsIncluded": False,
        "kubeconfigPathIncluded": False,
    }

def require_same_cluster_identity_v4(before: dict[str, Any], after: dict[str, Any], label: str) -> None:
    keys = ("apiOrigin", "caCertificateSha256", "apiServerSpkiSha256", "kubeSystemNamespaceUid")
    require(all(before.get(key) == after.get(key) for key in keys), f"protected cluster identity changed {label}")

def endpoint_facts_v4(p: dict[str, Any]) -> dict[str, Any]:
    """Resolve and TLS-check only the two fixed policy origins."""
    timeout = p["httpBoundary"]["timeoutsSeconds"]["routeRequest"]; context = ssl.create_default_context(); facts = {}
    for label in ("gnosis", "supabase"):
        endpoint = p["endpoints"][label]; parsed = urllib.parse.urlparse(endpoint["httpsOrigin"])
        require(parsed.scheme == "https" and parsed.hostname and parsed.path in {"", "/"}, f"{label} origin invalid")
        addresses = sorted({entry[4][0] for entry in socket.getaddrinfo(parsed.hostname, endpoint["port"], type=socket.SOCK_STREAM) if ":" not in entry[4][0]})
        expected = sorted(cidr.removesuffix("/32") for cidr in endpoint["ipv4Cidrs"])
        require(addresses == expected and addresses, f"{label} DNS answers differ from protected /32 set")
        tls = []
        for address in addresses:
            with socket.create_connection((address, endpoint["port"]), timeout=timeout) as connection:
                with context.wrap_socket(connection, server_hostname=parsed.hostname) as secured:
                    certificate = secured.getpeercert(binary_form=True); require(certificate is not None, f"{label} TLS certificate absent")
                    tls.append({"ipv4": address, "tlsVersion": secured.version(), "certificateDerSha256": "sha256:" + hashlib.sha256(certificate).hexdigest()})
        facts[label] = {"origin": endpoint["httpsOrigin"], "port": endpoint["port"], "ipv4Answers": addresses, "protectedIpv4Cidrs": endpoint["ipv4Cidrs"], "tls": tls}
    return {"status": "fixed-origins-match-protected-ipv4-and-tls", "origins": facts}

def anonymous_publication_v4(p: dict[str, Any]) -> dict[str, Any]:
    """Fetch the exact public GHCR manifest without ambient credentials."""
    pins = p["productPins"]; repository = pins["imageRepository"]
    require(repository.startswith("ghcr.io/") and repository.count("/") == 2, "image repository boundary drift")
    image = repository.removeprefix("ghcr.io/"); manifest = pins["imageManifestDigest"]
    url = f"https://ghcr.io/v2/{image}/manifests/{manifest}"; timeout = p["httpBoundary"]["timeoutsSeconds"]["routeRequest"]
    headers = {"Accept": "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json"}
    # Do not inherit ambient proxy credentials or registry credentials.  The
    # only credential ever used below is the repository-scoped anonymous
    # Bearer token returned by GHCR itself.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, headers=headers)
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        require(exc.code == 401, f"anonymous manifest request failed: HTTP {exc.code}")
        challenge = exc.headers.get("WWW-Authenticate", "")
        match = re.fullmatch(r'Bearer realm="([^"]+)",service="([^"]+)",scope="([^"]+)"', challenge)
        require(match is not None, "anonymous registry challenge drift"); realm, service, scope = match.groups()
        require(realm == "https://ghcr.io/token" and service == "ghcr.io" and scope == f"repository:{image}:pull", "anonymous registry authority/scope drift")
        token_url = realm + "?" + urllib.parse.urlencode({"service": service, "scope": scope})
        with opener.open(token_url, timeout=timeout) as token_response:
            try: token_raw = token_response.read().decode("utf-8")
            except UnicodeDecodeError as exc: raise ActivationError("anonymous registry token response is not UTF-8") from exc
            token = obj(token_raw, "anonymous registry token response").get("token")
        require(isinstance(token, str) and token, "anonymous registry token absent")
        response = opener.open(urllib.request.Request(url, headers=headers | {"Authorization": "Bearer " + token}), timeout=timeout)
    with response:
        body = response.read(); header_digest = response.headers.get("Docker-Content-Digest")
    observed = "sha256:" + hashlib.sha256(body).hexdigest()
    require(observed == manifest and (header_digest is None or header_digest == manifest), "anonymous manifest digest drift")
    return {
        "repository": repository,
        "manifestDigest": manifest,
        "anonymousCredentialInput": False,
        "anonymousBearerExchangeAllowed": True,
        "manifestBodySha256": observed,
        "dockerContentDigest": header_digest or observed,
        "verificationLevel": "anonymous-registry-manifest-digest-only",
        "cryptographicPublicationProvenanceVerified": False,
        "sbomOrAttestationVerified": False,
        "reviewedStaticPins": {
            "sourceRevision": pins["sourceRevision"],
            "sourceTreeSha256": pins["sourceTreeSha256"],
            "sourceTreeHashSemantics": pins["sourceTreeHashSemantics"],
            "workflowIdentity": pins["workflowIdentity"],
            "workflowSha256": pins["workflowSha256"],
            "workflowHashSemantics": pins["workflowHashSemantics"],
        },
    }

def runtime_image_v4(r: Runner, kubeconfig: str, p: dict[str, Any]) -> dict[str, Any]:
    selector = ",".join(f"{key}={value}" for key, value in sorted(POLICY.GATEWAY_LABELS.items()))
    listing = obj(checked(r, kb(kubeconfig) + ["-n", NAMESPACE, "get", "pods", "-l", selector, "-o", "json"], "participant runtime image"), "participant pods")
    items = listing.get("items", [])
    require(isinstance(items, list) and len(items) == p["runtime"]["replicas"], "participant Pod cardinality drift")
    expected = p["productPins"]["imageRepository"] + "@" + p["productPins"]["imageManifestDigest"]; image_ids = []; pods = []
    for pod in items:
        spec, status = pod.get("spec", {}), pod.get("status", {}); require(not spec.get("imagePullSecrets"), "participant Pod has imagePullSecrets")
        containers, statuses = spec.get("containers", []), status.get("containerStatuses", [])
        require(len(containers) == len(statuses) == 1 and containers[0].get("image") == expected and statuses[0].get("ready") is True, "participant Pod image/readiness drift")
        image_id = statuses[0].get("imageID", ""); require(image_id.endswith("@" + p["productPins"]["imageManifestDigest"]), "participant runtime imageID drift"); image_ids.append(image_id)
        metadata = pod.get("metadata", {}); uid, rv, name = metadata.get("uid"), metadata.get("resourceVersion"), metadata.get("name")
        require(isinstance(uid, str) and uid and isinstance(rv, str) and rv.isdigit() and isinstance(name, str) and name, "participant Pod identity absent")
        pods.append({"name": name, "uid": uid, "resourceVersion": rv, "imageId": image_id})
    return {"expectedImage": expected, "readyPodCount": len(items), "runtimeImageIds": sorted(image_ids), "pods": sorted(pods, key=lambda item: item["name"]), "imagePullSecretRefsAbsent": True}

def _selector_matches_v4(selector: Any, labels: dict[str, str]) -> bool:
    def cilium_key(value: Any) -> Any:
        if not isinstance(value, str): return value
        for prefix in ("k8s:", "any:"):
            if value.startswith(prefix): return value.removeprefix(prefix)
        return value

    require(isinstance(selector, dict) and set(selector) <= {"matchLabels", "matchExpressions"}, "unrecognized policy selector")
    match_labels, expressions = selector.get("matchLabels", {}), selector.get("matchExpressions", [])
    require(isinstance(match_labels, dict) and isinstance(expressions, list), "invalid policy selector")
    if any(labels.get(cilium_key(key)) != value for key, value in match_labels.items()): return False
    for expression in expressions:
        require(isinstance(expression, dict) and set(expression) <= {"key", "operator", "values"}, "invalid policy expression")
        key, operator, values = cilium_key(expression.get("key", "")), expression.get("operator"), expression.get("values", [])
        current = labels.get(key); require(operator in {"In", "NotIn", "Exists", "DoesNotExist"} and isinstance(values, list), "invalid policy expression")
        if operator == "In" and (current is None or current not in values): return False
        if operator == "NotIn" and current is not None and current in values: return False
        if operator == "Exists" and current is None: return False
        if operator == "DoesNotExist" and current is not None: return False
    return True

def _selector_could_match_with_additional_labels_v4(selector: Any, labels: dict[str, str]) -> bool:
    """Conservatively match a selector against fixed plus future labels."""
    def key(value: Any) -> Any:
        if not isinstance(value, str): return value
        for prefix in ("k8s:", "any:"):
            if value.startswith(prefix): return value.removeprefix(prefix)
        return value
    require(isinstance(selector, dict) and set(selector) <= {"matchLabels", "matchExpressions"}, "unrecognized policy selector")
    match_labels, expressions = selector.get("matchLabels", {}), selector.get("matchExpressions", [])
    require(isinstance(match_labels, dict) and isinstance(expressions, list), "invalid policy selector")
    for raw_key, expected in match_labels.items():
        current = labels.get(key(raw_key))
        if current is not None and current != expected: return False
    for expression in expressions:
        require(isinstance(expression, dict) and set(expression) <= {"key", "operator", "values"}, "invalid policy expression")
        current = labels.get(key(expression.get("key", ""))); operator, values = expression.get("operator"), expression.get("values", [])
        require(operator in {"In", "NotIn", "Exists", "DoesNotExist"} and isinstance(values, list), "invalid policy expression")
        if operator == "In" and current is not None and current not in values: return False
        if operator == "NotIn" and current is not None and current in values: return False
        if operator == "DoesNotExist" and current is not None: return False
        # Unknown In/Exists/NotIn/DoesNotExist keys can all be satisfied by a
        # future controller label choice (or continued absence), so they stay
        # conservatively overlapping.
    return True

def _target_policy_label_sets_v4(r: Runner, kubeconfig: str) -> dict[str, dict[str, Any]]:
    targets = {
        "gateway": (NAMESPACE, POLICY.GATEWAY_LABELS, NAME),
        "workbench": (WORKBENCH_NAMESPACE, POLICY.WORKBENCH_SELECTOR, None),
    }
    result: dict[str, dict[str, Any]] = {}
    for label, (namespace, fixed, expected_service_account) in targets.items():
        selector = ",".join(f"{key}={value}" for key, value in sorted(fixed.items()))
        listing = obj(checked(r, kb(kubeconfig) + ["-n", namespace, "get", "pods", "-l", selector, "-o", "json"], f"fresh {label} Pod-label scan"), f"{label} Pod-label scan")
        items = listing.get("items", []); require(isinstance(items, list), f"{label} Pod-label items absent")
        kubernetes_sets: list[dict[str, str]] = []; cilium_sets: list[dict[str, str]] = []
        for pod in items:
            labels = pod.get("metadata", {}).get("labels", {}); service_account = pod.get("spec", {}).get("serviceAccountName")
            require(isinstance(labels, dict) and all(isinstance(key, str) and isinstance(value, str) for key, value in labels.items()), f"{label} Pod labels invalid")
            require(all(labels.get(key) == value for key, value in fixed.items()), f"{label} Pod fixed labels drift")
            require(isinstance(service_account, str) and service_account, f"{label} Pod service account absent")
            if expected_service_account is not None: require(service_account == expected_service_account, f"{label} Pod service account drift")
            kubernetes_sets.append(dict(labels))
            cilium_sets.append(dict(labels) | {"io.kubernetes.pod.namespace": namespace, "io.cilium.k8s.policy.serviceaccount": service_account})
        # Before creation there is no gateway Pod. Fixed labels plus the exact
        # expected service-account identity are still a conservative seed;
        # unknown selector keys remain possible in the matcher above.
        if not kubernetes_sets:
            kubernetes_sets = [dict(fixed)]
            cilium_sets = [dict(fixed) | {"io.kubernetes.pod.namespace": namespace} | ({"io.cilium.k8s.policy.serviceaccount": expected_service_account} if expected_service_account else {})]
        result[label] = {"namespace": namespace, "podCount": len(items), "kubernetes": kubernetes_sets, "cilium": cilium_sets}
    return result

def _allows_workbench_port(value: dict[str, Any]) -> bool:
    for rule in value.get("spec", {}).get("ingress", []):
        ports = rule.get("ports")
        if ports is None: return True
        for entry in ports:
            if entry.get("protocol", "TCP") != "TCP": continue
            configured = entry.get("port")
            # A named port may resolve to 18083 and an endPort range may span
            # it, so both are conservatively treated as additive allows.
            if isinstance(configured, str) and not configured.isdigit(): return True
            if configured is None: return True
            start, end = int(configured), int(entry.get("endPort", configured))
            if start <= POLICY.WORKBENCH_PORT <= end: return True
    return False

def policy_union_v4(r: Runner, kubeconfig: str, owned: dict[tuple[str, str], CreatedV4] | None = None) -> dict[str, Any]:
    """Conservatively reject additive K8s/Cilium participant allows."""
    owned = owned or {}; count = 0; label_sets = _target_policy_label_sets_v4(r, kubeconfig); owned_validated = []
    families = (("networkpolicy", ["-A"], "kubernetes"), ("ciliumnetworkpolicies.cilium.io", ["-A"], "cilium"), ("ciliumclusterwidenetworkpolicies.cilium.io", [], "cilium-clusterwide"))
    for resource, extra, family in families:
        listing = obj(checked(r, kb(kubeconfig) + ["get", resource, *extra, "-o", "json"], f"fresh {resource} scan"), resource)
        require(isinstance(listing.get("items"), list), f"{resource} items absent")
        for item in listing["items"]:
            count += 1; metadata = item.get("metadata", {}); namespace, name = metadata.get("namespace", ""), metadata.get("name")
            if family == "kubernetes" and (namespace, name) in owned:
                binding = owned[(namespace, name)]
                require(item.get("metadata", {}).get("uid") == binding.observed.get("metadata", {}).get("uid"), f"owned NetworkPolicy UID drift: {namespace}/{name}")
                _policy_call(POLICY.require_semantically_equal, item, binding.desired, f"owned NetworkPolicy semantics {namespace}/{name}")
                owned_validated.append({"namespace": namespace, "name": name, "uid": item["metadata"]["uid"], "semanticSha256": POLICY.semantic_sha256(item)})
                continue
            if family == "kubernetes":
                selector = item.get("spec", {}).get("podSelector", {})
                if namespace == NAMESPACE and any(_selector_could_match_with_additional_labels_v4(selector, labels) for labels in label_sets["gateway"]["kubernetes"]): raise ActivationError(f"pre-existing NetworkPolicy can select gateway: {namespace}/{name}")
                if namespace == WORKBENCH_NAMESPACE and any(_selector_could_match_with_additional_labels_v4(selector, labels) for labels in label_sets["workbench"]["kubernetes"]):
                    require(name == POLICY.WORKBENCH_NAME, f"pre-existing NetworkPolicy selects workbench: {namespace}/{name}")
                    require(not _allows_workbench_port(item), "manual workbench policy already allows participant port 18083")
            else:
                specs = item.get("specs") if isinstance(item.get("specs"), list) else [item.get("spec", {})]
                candidates = []
                if family == "cilium-clusterwide" or namespace == NAMESPACE: candidates.extend(label_sets["gateway"]["cilium"])
                if family == "cilium-clusterwide" or namespace == WORKBENCH_NAMESPACE: candidates.extend(label_sets["workbench"]["cilium"])
                if candidates and any(_selector_could_match_with_additional_labels_v4(spec.get("endpointSelector", {}), labels) for spec in specs for labels in candidates): raise ActivationError(f"pre-existing {resource} overlaps participant selectors: {namespace}/{name}")
    validated_keys = {(item["namespace"], item["name"]) for item in owned_validated}
    require(
        validated_keys == set(owned) and len(owned_validated) == len(owned),
        "owned NetworkPolicy set absent or incomplete during additive-policy scan",
    )
    return {"status": "no-additive-participant-allow-conflicts", "families": [family for _, _, family in families], "objectsScanned": count, "ownedNetworkPoliciesValidated": sorted(owned_validated, key=lambda item: (item["namespace"], item["name"])), "runtimeSelectorFacts": label_sets}

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request: Any, file_pointer: Any, code: int, message: str, headers: Any, new_url: str) -> None:
        return None


def _pod_port_forward_get_v4(
    kubeconfig: str,
    pod_name: str,
    remote_port: int,
    path: str,
    *,
    startup_timeout: int | float,
    request_timeout: int | float,
) -> tuple[str, dict[str, Any]]:
    """GET an internal Pod endpoint through an authenticated API stream.

    Kubernetes Pod port-forward is deliberately used instead of Service proxy
    traffic: the latter has CNI-dependent source identity and can be denied by
    the participant NetworkPolicy.  The stream is bound only to loopback, does
    not traverse public Ingress, does not follow redirects, and is always
    terminated by this function.
    """
    command = kb(kubeconfig) + [
        "-n", NAMESPACE, "port-forward", "--address=127.0.0.1",
        f"pod/{pod_name}", f":{remote_port}",
    ]
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    selector = selectors.DefaultSelector()
    try:
        require(process.stdout is not None, "kubectl port-forward output pipe unavailable")
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + startup_timeout; local_port: int | None = None; output = b""
        while time.monotonic() < deadline:
            if process.poll() is not None: raise ActivationError("kubectl port-forward terminated before readiness probe")
            events = selector.select(timeout=min(0.25, max(0.0, deadline - time.monotonic())))
            if not events: continue
            chunk = os.read(process.stdout.fileno(), 4096)
            if not chunk: continue
            output = (output + chunk)[-16384:]
            match = re.search(rb"Forwarding from 127\.0\.0\.1:(\d+) -> (\d+)", output)
            if match:
                local_port, forwarded_port = int(match.group(1)), int(match.group(2))
                require(forwarded_port == remote_port, "kubectl port-forward remote port drift")
                break
        require(local_port is not None, "kubectl port-forward did not become ready")
        url = f"http://127.0.0.1:{local_port}{path}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        request = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
        try:
            with opener.open(request, timeout=request_timeout) as response:
                require(response.status == 200 and response.geturl() == url, "internal participant readiness HTTP boundary drift")
                content_type = response.headers.get_content_type()
                require(content_type == "application/json", "internal participant readiness content type drift")
                raw = response.read(8193)
        except urllib.error.HTTPError as exc:
            raise ActivationError(f"internal participant readiness rejected: HTTP {exc.code}") from exc
        require(len(raw) <= 8192, "internal participant readiness response too large")
        try: body = raw.decode("utf-8")
        except UnicodeDecodeError as exc: raise ActivationError("internal participant readiness is not UTF-8") from exc
        return body, {
            "transport": "authenticated-kubernetes-pod-port-forward",
            "pod": pod_name,
            "loopbackOnly": True,
            "publicIngressUsed": False,
            "serviceProxyUsed": False,
            "redirectsAllowed": False,
            "path": path,
            "remotePort": remote_port,
        }
    finally:
        selector.close()
        _terminate_process_group(process)
        if process.stdout is not None: process.stdout.close()


def database_status_v4(r: Runner, kubeconfig: str, p: dict[str, Any], runtime: dict[str, Any]) -> dict[str, Any]:
    # This is the container-internal readiness contract. It is reached only by
    # an authenticated Pod port-forward and is deliberately distinct from the
    # public participant-session UI status route.
    require(runtime.get("readyPodCount") == p["runtime"]["replicas"] and len(runtime.get("pods", [])) == p["runtime"]["replicas"], "verified participant Pod set absent")
    for verb in ("get", "list"):
        checked(r, kb(kubeconfig) + ["auth", "can-i", "--quiet", verb, "pods", "-n", NAMESPACE], f"internal status RBAC {verb} pods")
    checked(r, kb(kubeconfig) + ["auth", "can-i", "--quiet", "create", "pods/portforward", "-n", NAMESPACE], "internal status RBAC create pods/portforward")
    selected = runtime["pods"][0]; timeout = p["httpBoundary"]["timeoutsSeconds"]["routeRequest"]
    body, probe = _pod_port_forward_get_v4(
        kubeconfig,
        selected["name"],
        POLICY.GATEWAY_PORT,
        "/status",
        startup_timeout=timeout,
        request_timeout=timeout,
    )
    current = live_obj(r, kubeconfig, "pod", selected["name"], NAMESPACE)
    pins = p["productPins"]
    current_metadata, current_spec, current_status = current.get("metadata", {}), current.get("spec", {}), current.get("status", {})
    current_containers, current_container_statuses = current_spec.get("containers", []), current_status.get("containerStatuses", [])
    exact_image = pins["imageRepository"] + "@" + pins["imageManifestDigest"]
    require(current_metadata.get("uid") == selected["uid"], "readiness-probed participant Pod UID changed")
    require(
        len(current_containers) == len(current_container_statuses) == 1
        and current_containers[0].get("image") == exact_image
        and current_container_statuses[0].get("imageID") == selected["imageId"]
        and current_container_statuses[0].get("ready") is True
        and not current_spec.get("imagePullSecrets"),
        "readiness-probed participant Pod runtime pin changed",
    )
    expected = {"schemaVersion": "roebel_staging_participant_gateway_status_v1", "status": "ready", "sourceRevision": pins["sourceRevision"], "manifestDigest": pins["imageManifestDigest"], "migrationSha256": pins["migration"]["sha256"], "databaseSchemaSha256": pins["databaseSchemaSha256"]}
    require(obj(body, "internal participant /status") == expected, "internal participant /status product/database contract drift")
    return expected | {
        "probe": probe | {"podUid": selected["uid"], "podImage": exact_image, "podImageId": selected["imageId"], "podReadyAfter": True, "podResourceVersionBefore": selected["resourceVersion"], "podResourceVersionAfter": current_metadata.get("resourceVersion")},
        "rbac": {"getPods": True, "listPods": True, "createPodsPortforward": True},
    }

def _route_request_v4(origin: str, method: str, path: str, headers: dict[str, str], body: bytes | None, timeout: int | float) -> dict[str, Any]:
    require(origin == "https://roebel-web.staging.agentcart.eu" and path.startswith("/"), "route request authority/path drift")
    url = origin + path; request = urllib.request.Request(url, data=body, headers=headers, method=method)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        raw = response.read(8193); status = response.status
        require(response.geturl() == url and len(raw) <= 8192, "public route redirected or response too large")
        normalized_headers = {key.lower(): value.strip() for key, value in response.headers.items()}
    try: decoded = raw.decode("utf-8")
    except UnicodeDecodeError as exc: raise ActivationError("public route response is not UTF-8") from exc
    return {"status": status, "headers": normalized_headers, "body": decoded}

def _require_json_response_v4(observed: dict[str, Any], expected_status: int, expected_body: dict[str, Any], label: str) -> None:
    require(observed["status"] == expected_status, f"{label} status drift")
    media_type = observed["headers"].get("content-type", "").split(";", 1)[0].strip().lower()
    require(media_type == "application/json", f"{label} content type drift")
    require(obj(observed["body"], label + " body") == expected_body, f"{label} body drift")

def _require_cors_v4(observed: dict[str, Any], origin: str, *, preflight_method: str | None = None) -> None:
    headers = observed["headers"]
    require(headers.get("access-control-allow-origin") == origin and headers.get("access-control-allow-credentials") == "true", "route CORS origin/credentials drift")
    vary = {item.strip().lower() for item in headers.get("vary", "").split(",") if item.strip()}
    require("origin" in vary, "route CORS Vary drift")
    if preflight_method is not None:
        methods = {item.strip().upper() for item in headers.get("access-control-allow-methods", "").split(",") if item.strip()}
        allowed_headers = {item.strip().lower() for item in headers.get("access-control-allow-headers", "").split(",") if item.strip()}
        require(methods == {preflight_method} and allowed_headers == {"content-type"} and headers.get("access-control-max-age") == "600", "route CORS preflight contract drift")

def route_matrix_v4(r: Runner, p: dict[str, Any]) -> list[dict[str, Any]]:
    del r  # The fixed urllib transport deliberately cannot inherit shell proxy state.
    boundary = p["httpBoundary"]; timeout = boundary["timeoutsSeconds"]["routeRequest"]
    total_deadline = time.monotonic() + boundary["timeoutsSeconds"]["routeMatrixTotal"]
    origin = p["endpoints"]["browserOrigin"].rstrip("/"); prefix = boundary["prefix"]
    status_path = prefix + "/status"; posts = [prefix + suffix for suffix in ("/challenge", "/session", "/posts", "/comments", "/nostr-post")]
    require([entry["path"] for entry in boundary["routes"]] == [status_path, *posts], "fixed six-route inventory drift")
    result: list[dict[str, Any]] = []

    def call(method: str, path: str, *, request_origin: str | None = origin, body: bytes | None = None, requested_method: str | None = None) -> dict[str, Any]:
        require(time.monotonic() < total_deadline, "route matrix total timeout")
        headers: dict[str, str] = {"Accept": "application/json"}
        if request_origin is not None: headers["Origin"] = request_origin
        if body is not None: headers["Content-Type"] = "application/json"
        if requested_method is not None:
            headers["Access-Control-Request-Method"] = requested_method; headers["Access-Control-Request-Headers"] = "content-type"
        observed = _route_request_v4(origin, method, path, headers, body, timeout)
        require(time.monotonic() < total_deadline, "route matrix total timeout after request")
        return observed

    status_body = {"available": True, "active": False, "walletAddress": None, "label": "Staging-Testteilnahme – keine Bürgerverifikation, kein Stimmrecht", "scope": None, "authority": "none"}
    observed = call("GET", status_path); _require_json_response_v4(observed, 200, status_body, "GET status"); _require_cors_v4(observed, origin); result.append({"case": "status", "method": "GET", "path": status_path, "status": 200})
    for path, allowed in [(status_path, "GET"), *[(path, "POST") for path in posts]]:
        observed = call("OPTIONS", path, requested_method=allowed)
        require(observed["status"] == 204 and observed["body"] == "" and "content-type" not in observed["headers"], f"OPTIONS {path} response drift")
        _require_cors_v4(observed, origin, preflight_method=allowed); result.append({"case": "preflight", "method": "OPTIONS", "path": path, "status": 204})
    post_errors = {
        posts[0]: (401, {"error": "admission_invalid"}),
        posts[1]: (401, {"error": "challenge_invalid"}),
        posts[2]: (401, {"error": "session_required"}),
        posts[3]: (401, {"error": "session_required"}),
        posts[4]: (401, {"error": "session_required"}),
    }
    for path, (status, expected_body) in post_errors.items():
        observed = call("POST", path, body=b"{}")
        _require_json_response_v4(observed, status, expected_body, f"POST {path}"); _require_cors_v4(observed, origin)
        result.append({"case": "unauthenticated-post", "method": "POST", "path": path, "status": status})
    for method, path in [("POST", status_path), *[("GET", path) for path in posts], ("HEAD", status_path), ("DELETE", status_path)]:
        observed = call(method, path, body=b"{}" if method == "POST" else None)
        require(observed["status"] == 405 and observed["body"] == "" and "content-type" not in observed["headers"], f"method boundary drift: {method} {path}")
        result.append({"case": "method-denied", "method": method, "path": path, "status": 405})
    for label, method, path in (
        ("unknown", "GET", prefix + "/unknown"),
        ("trailing-slash", "GET", status_path + "/"),
        ("query", "GET", status_path + "?unexpected=1"),
        ("unknown-preflight", "OPTIONS", prefix + "/unknown"),
    ):
        observed = call(method, path, requested_method="POST" if method == "OPTIONS" else None)
        if label == "query":
            # HAProxy's exact `path` ACL intentionally ignores the query; the
            # protected product rejects it with the closed JSON response.
            _require_json_response_v4(observed, 404, {"error": "not_found"}, "query route")
            require("access-control-allow-origin" not in observed["headers"], "query rejection exposed CORS authority")
        else:
            require(observed["status"] == 404 and observed["body"] == "" and "content-type" not in observed["headers"], f"{label} route boundary drift")
        result.append({"case": label, "method": method, "path": path, "status": 404})
    wrong_origin = "https://attacker.invalid"
    observed = call("POST", posts[0], request_origin=wrong_origin, body=b"{}")
    _require_json_response_v4(observed, 403, {"error": "origin_forbidden"}, "wrong-origin challenge")
    require("access-control-allow-origin" not in observed["headers"], "wrong-origin response reflected CORS authority")
    result.append({"case": "wrong-origin", "method": "POST", "path": posts[0], "status": 403})
    require(result == boundary["expectations"], "route matrix receipt differs from protected static expectations")
    return result

def health_v4(r: Runner, kubeconfig: str, p: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    timeout = p["httpBoundary"]["timeoutsSeconds"]["deploymentRollout"]
    checked(r, kb(kubeconfig) + ["-n", NAMESPACE, "rollout", "status", f"deployment/{NAME}", f"--timeout={timeout}s"], "Deployment readiness", timeout=timeout + 5)
    deployment = live_obj(r, kubeconfig, "deployment", NAME, NAMESPACE); metadata, status = deployment.get("metadata", {}), deployment.get("status", {})
    require(status.get("observedGeneration") == metadata.get("generation") and status.get("availableReplicas") == p["runtime"]["replicas"], "Deployment readiness projection drift")
    haproxy = live_obj(r, kubeconfig, "daemonset", HAPROXY_DAEMONSET, HAPROXY_NAMESPACE); hm, hs = haproxy.get("metadata", {}), haproxy.get("status", {})
    desired = hs.get("desiredNumberScheduled")
    require(
        isinstance(desired, int)
        and desired > 0
        and hs.get("numberReady") == desired
        and hs.get("numberAvailable") == desired
        and hs.get("updatedNumberScheduled") == desired
        and hs.get("observedGeneration") == hm.get("generation"),
        "HAProxy readiness projection drift",
    )
    return deployment, {"uid": hm.get("uid"), "resourceVersion": hm.get("resourceVersion"), "observedGeneration": hs["observedGeneration"], "desiredNumberScheduled": desired, "updatedNumberScheduled": desired, "numberAvailable": desired, "numberReady": desired, "rateLimit": p["httpBoundary"]["haproxyRateLimit"]}

def semantic_postconditions_v4(r: Runner, kubeconfig: str, created: list[CreatedV4]) -> dict[str, Any]:
    result = {}
    for item in created:
        metadata = item.desired["metadata"]
        live = live_obj(r, kubeconfig, item.desired["kind"].lower(), metadata["name"], metadata["namespace"])
        require(live.get("metadata", {}).get("uid") == item.observed.get("metadata", {}).get("uid"), f"{item.logical_name} UID changed after Flux")
        normalized = _policy_call(POLICY.require_semantically_equal, live, item.desired, f"{item.logical_name} final")
        result[item.logical_name] = {"uid": live["metadata"]["uid"], "resourceVersion": live["metadata"]["resourceVersion"], "semanticSha256": POLICY.canonical_sha256(normalized)}
    return result

def delete_with_preconditions_v4(r: Runner, kubeconfig: str, created: CreatedV4, timeout: int = 120) -> dict[str, Any]:
    desired, admitted = created.desired, created.observed; metadata = desired["metadata"]
    current = get_optional(r, kubeconfig, desired["kind"].lower(), metadata["name"], metadata["namespace"])
    if current is None: return {"logicalName": created.logical_name, "absent": True, "alreadyAbsent": True}
    require(current.get("metadata", {}).get("uid") == admitted.get("metadata", {}).get("uid"), f"rollback UID mismatch for {created.logical_name}")
    nonce = created.receipt.get("operationNonce")
    require(isinstance(nonce, str) and bool(POLICY.NONCE.fullmatch(nonce)), f"rollback operation nonce receipt absent for {created.logical_name}")
    if created.receipt.get("temporaryNonceRemoved") is True:
        _policy_call(POLICY.require_semantically_equal, current, desired, f"rollback ownership {created.logical_name}")
    else:
        nonce_desired = _policy_call(POLICY.with_operation_nonce, desired, nonce)
        try: _policy_call(POLICY.require_semantically_equal, current, nonce_desired, f"rollback nonce ownership {created.logical_name}")
        except ActivationError:
            # The nonce-removal CAS response may itself have been lost. The
            # exact originally receipt-bound UID plus exact post-removal static
            # semantics still proves transaction ownership; anything else is
            # left untouched and makes rollback incomplete.
            _policy_call(POLICY.require_semantically_equal, current, desired, f"rollback post-nonce ownership {created.logical_name}")
    rv = current["metadata"].get("resourceVersion"); require(isinstance(rv, str) and rv.isdigit(), f"rollback resourceVersion absent for {created.logical_name}")
    kind = desired["kind"].lower()
    foreground = kind == "deployment"
    payload_value: dict[str, Any] = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": current["metadata"]["uid"], "resourceVersion": rv}}
    if foreground: payload_value["propagationPolicy"] = "Foreground"
    payload = canonical(payload_value)
    api, plural = {"ingress": ("networking.k8s.io/v1", "ingresses"), "networkpolicy": ("networking.k8s.io/v1", "networkpolicies"), "deployment": ("apps/v1", "deployments"), "service": ("v1", "services"), "serviceaccount": ("v1", "serviceaccounts")}[kind]
    prefix = "/api" if api == "v1" else "/apis"
    resource_path = f"{prefix}/{api}/namespaces/{metadata['namespace']}/{plural}/{metadata['name']}"
    raw_delete(kubeconfig, resource_path, payload)
    deadline = time.monotonic() + timeout
    while True:
        after = get_optional(r, kubeconfig, kind, metadata["name"], metadata["namespace"])
        if after is None: break
        finalizers = after.get("metadata", {}).get("finalizers", [])
        if after.get("metadata", {}).get("deletionTimestamp") and finalizers:
            allowed = ["foregroundDeletion"] if foreground else []
            require(finalizers == allowed, f"rollback blocked by finalizers for {created.logical_name}: {finalizers}")
        require(time.monotonic() < deadline, f"rollback absence timeout for {created.logical_name}")
        time.sleep(0.1)
    return {"logicalName": created.logical_name, "uid": current["metadata"]["uid"], "deleteResourceVersion": rv, "absent": True, "foregroundPropagation": foreground, "finalizersRemovedByRunner": False}

def deployment_dependents_absent_v4(r: Runner, kubeconfig: str) -> dict[str, Any]:
    selector = ",".join(f"{key}={value}" for key, value in sorted(POLICY.GATEWAY_LABELS.items()))
    result = {}
    for resource in ("pods", "replicasets.apps"):
        listing = obj(checked(r, kb(kubeconfig) + ["-n", NAMESPACE, "get", resource, "-l", selector, "-o", "json"], f"rollback {resource} absence"), f"rollback {resource}")
        items = listing.get("items", []); require(isinstance(items, list) and not items, f"rollback left participant {resource} running")
        result[resource] = {"selector": dict(POLICY.GATEWAY_LABELS), "count": 0}
    return {"status": "deployment-foreground-dependents-absent", "resources": result}

def _flux_suspended_and_quiescent_v4(value: dict[str, Any], owner: str, uid: str) -> dict[str, Any]:
    metadata, status = value.get("metadata", {}), value.get("status", {})
    require(metadata.get("uid") == uid and value.get("spec", {}).get("suspend") is True, f"{owner} rollback suspended identity drift")
    generation = metadata.get("generation")
    require(isinstance(generation, int) and status.get("observedGeneration") == generation, f"{owner} suspended generation not observed")
    for condition in status.get("conditions", []):
        if condition.get("type") == "Reconciling" and condition.get("status") == "True":
            observed = condition.get("observedGeneration")
            require(observed is not None and observed != generation, f"{owner} still Reconciling suspended generation")
    return {"uid": uid, "resourceVersion": metadata.get("resourceVersion"), "generation": generation, "observedGeneration": generation, "suspended": True, "reconcilingCurrentGeneration": False}

def wait_both_suspended_v4(r: Runner, kubeconfig: str, p: dict[str, Any], bootstrap: dict[str, Any], deadline: float) -> dict[str, Any]:
    result: dict[str, Any] = {}; poll = p["httpBoundary"]["timeoutsSeconds"]["rollbackPoll"]
    for owner in ("gateway", "workbenchIngress"):
        target = p["gitOps"]["reconcilers"][owner]["kustomization"]
        uid = bootstrap["owners"][owner]["kustomization"]["metadata"]["uid"]
        while True:
            require(time.monotonic() < deadline, f"{owner} rollback suspension timeout")
            current = _target_live(r, kubeconfig, target)
            try:
                result[owner] = _flux_suspended_and_quiescent_v4(current, owner, uid); break
            except ActivationError as exc:
                if "UID" in str(exc) or "identity drift" in str(exc): raise
                time.sleep(poll)
    return result

def _all_targets_absent_quiet_v4(r: Runner, kubeconfig: str, rendered: dict[str, dict[str, Any]], owned_uids: dict[str, str], deadline: float, quiet: float, poll: float) -> dict[str, Any]:
    require(len(rendered) == 6, "rollback exact six-target inventory absent")
    quiet_started: float | None = None; checks = 0
    while True:
        now = time.monotonic(); require(now < deadline, "rollback all-target absence timeout")
        present = []
        for logical_name in sorted(rendered):
            desired = rendered[logical_name]["desired"]; metadata = desired["metadata"]
            current = get_optional(r, kubeconfig, desired["kind"].lower(), metadata["name"], metadata["namespace"])
            if current is not None:
                uid = current.get("metadata", {}).get("uid")
                require(owned_uids.get(logical_name) == uid, f"rollback target name occupied by unowned UID: {logical_name}")
                present.append({"logicalName": logical_name, "uid": uid})
        checks += 1
        if present: quiet_started = None
        elif quiet_started is None: quiet_started = now
        elif now - quiet_started >= quiet:
            return {"status": "all-six-names-absent-for-quiet-interval", "quietSeconds": quiet, "checks": checks}
        time.sleep(poll)

def rollback_v4(
    r: Runner,
    kubeconfig: str,
    p: dict[str, Any],
    created: list[CreatedV4],
    bootstrap: dict[str, Any] | None,
    preserved: dict[str, PreservedV4] | None,
    uncertain: str | None,
    *,
    rendered: dict[str, dict[str, Any]] | None = None,
    snapshot: KubeconfigSnapshot | None = None,
    initial_cluster: dict[str, Any] | None = None,
) -> dict[str, Any]:
    errors: list[str] = []; deleted: list[dict[str, Any]] = []; flux: dict[str, Any] = {}; final_checks: dict[str, Any] = {}
    ingress = next((item for item in created if item.logical_name == "gateway.ingress"), None)
    exposure_service = next((item for item in created if item.logical_name == "gateway.service"), None)
    exposure_service_deleted = False
    settings = p["httpBoundary"]["timeoutsSeconds"]; timeout = settings["rollback"]; deadline = time.monotonic() + timeout
    # Re-bind the protected cluster before the first rollback mutation. A
    # changed API origin/CA/SPKI/cluster UID is not authority to delete objects
    # in whatever cluster the snapshot now reaches.
    if snapshot is not None and initial_cluster is not None:
        try:
            entry_cluster = cluster_binding_v4(r, snapshot, p)
            require_same_cluster_identity_v4(initial_cluster, entry_cluster, "before rollback")
            final_checks["clusterBindingBeforeRollback"] = entry_cluster
        except Exception as exc: errors.append(str(exc))
    rollback_authorized = not errors
    # Exposure closes first, before either reconciler is touched.
    ingress_absence_proved = False
    if ingress and rollback_authorized:
        try:
            ingress_result = delete_with_preconditions_v4(r, kubeconfig, ingress, max(1, int(deadline - time.monotonic())))
            deleted.append(ingress_result); ingress_absence_proved = ingress_result.get("absent") is True
        except Exception as exc: errors.append(str(exc))
    # A 409 or unbindable create response is never authority to touch an
    # unknown Ingress. Always sever the exact transaction-owned backend before
    # waiting on Flux: even an initially deleted owned Ingress can be recreated
    # with a new UID before a failing reconciler becomes quiescent.
    if rollback_authorized and exposure_service is not None:
        try:
            service_result = delete_with_preconditions_v4(r, kubeconfig, exposure_service, max(1, int(deadline - time.monotonic())))
            deleted.append(service_result); exposure_service_deleted = service_result.get("absent") is True
            require(exposure_service_deleted, "participant Service exposure-break absence was not proved")
            final_checks["exposureBreak"] = {
                "reason": "always-remove-owned-service-before-flux",
                "initialIngressAbsenceProved": ingress_absence_proved,
                "serviceUid": exposure_service.observed.get("metadata", {}).get("uid"),
                "serviceAbsent": True,
                "unknownIngressUntouched": ingress is None,
            }
        except Exception as exc: errors.append(str(exc))
    if bootstrap and rollback_authorized:
        for owner in ("gateway", "workbenchIngress"):
            try:
                target = p["gitOps"]["reconcilers"][owner]["kustomization"]; current = _target_live(r, kubeconfig, target)
                uid = bootstrap["owners"][owner]["kustomization"]["metadata"]["uid"]
                require(current.get("metadata", {}).get("uid") == uid, f"{owner} rollback Kustomization UID drift")
                if current.get("spec", {}).get("suspend") is not True: cas_flux_v4(r, kubeconfig, p, owner, current, True)
            except Exception as exc: errors.append(str(exc))
        try: flux = wait_both_suspended_v4(r, kubeconfig, p, bootstrap, deadline)
        except Exception as exc: errors.append(str(exc))
    # If deletion was acknowledged but the same transaction UID remains or
    # reappears, delete it again only after both reconcilers are quiescent.
    if ingress and not errors:
        metadata = ingress.desired["metadata"]
        try:
            current = get_optional(r, kubeconfig, "ingress", metadata["name"], metadata["namespace"])
            if current is not None:
                require(current.get("metadata", {}).get("uid") == ingress.observed.get("metadata", {}).get("uid"), "participant Ingress reappeared with unowned UID")
                deleted.append(delete_with_preconditions_v4(r, kubeconfig, ingress, max(1, int(deadline - time.monotonic()))))
        except Exception as exc: errors.append(str(exc))
    # Re-prove the exposure breaker after the Flux/reappearance phase even
    # when that phase produced an error. A controller may have recreated the
    # Service alongside an unknown Ingress; only the original exact UID and
    # protected semantics remain deletable by this transaction.
    if rollback_authorized and exposure_service is not None and bootstrap is not None:
        try:
            service_after_flux = delete_with_preconditions_v4(r, kubeconfig, exposure_service, max(1, int(deadline - time.monotonic())))
            deleted.append(service_after_flux)
            require(service_after_flux.get("absent") is True, "participant Service exposure-break post-Flux absence was not proved")
            final_checks["exposureBreakAfterFlux"] = {
                "serviceUid": exposure_service.observed.get("metadata", {}).get("uid"),
                "serviceAbsent": True,
                "sameOwnedUidOnly": True,
            }
        except Exception as exc: errors.append(str(exc))
    # An uncertain or definite-conflict Deployment create may race admission
    # without ever becoming transaction-owned. Never remove gateway isolation
    # merely because that unowned outcome is absent from `created`.
    # Exact name and runtime-dependent absence must both be proved first; the
    # later all-target quiet interval supplies a second bounded absence proof.
    bound_deployment = next((item for item in created if item.logical_name == "gateway.deployment"), None)
    gateway_isolation = next((item for item in created if item.logical_name == "gateway.networkPolicy"), None)
    if bound_deployment is None and gateway_isolation is not None and not errors:
        try:
            require(rendered is not None and "gateway.deployment" in rendered, "unbound Deployment render binding absent")
            desired = rendered["gateway.deployment"]["desired"]; metadata = desired["metadata"]
            current = get_optional(r, kubeconfig, "deployment", metadata["name"], metadata["namespace"])
            require(current is None, "unbound participant Deployment may still exist; gateway isolation retained")
            final_checks["unboundDeploymentRuntime"] = {
                "deploymentNameAbsent": True,
                "dependents": deployment_dependents_absent_v4(r, kubeconfig),
                "gatewayIsolationRetainedUntilProof": True,
            }
        except Exception as exc: errors.append(str(exc))
    if not errors and (bootstrap is None or len(flux) == 2):
        remaining = [
            entry for entry in created
            if entry is not ingress and not (exposure_service_deleted and entry is exposure_service)
        ]
        deployment = next((entry for entry in remaining if entry.logical_name == "gateway.deployment"), None)
        if deployment is not None:
            try:
                deleted.append(delete_with_preconditions_v4(r, kubeconfig, deployment, max(1, int(deadline - time.monotonic()))))
                final_checks["deploymentDependents"] = deployment_dependents_absent_v4(r, kubeconfig)
                remaining.remove(deployment)
            except Exception as exc: errors.append(str(exc))
        if not errors:
            for item in reversed(remaining):
                try: deleted.append(delete_with_preconditions_v4(r, kubeconfig, item, max(1, int(deadline - time.monotonic()))))
                except Exception as exc: errors.append(str(exc)); break
    if not errors and rendered is not None:
        try:
            owned_uids = {item.logical_name: item.observed.get("metadata", {}).get("uid") for item in created}
            final_checks["absence"] = _all_targets_absent_quiet_v4(r, kubeconfig, rendered, owned_uids, deadline, settings["rollbackAbsenceQuiet"], settings["rollbackPoll"])
        except Exception as exc: errors.append(str(exc))
    if not errors and bootstrap:
        try:
            final_checks["flux"] = wait_both_suspended_v4(r, kubeconfig, p, bootstrap, deadline)
            source = shared_source_revision_v4(r, kubeconfig, bootstrap["source"]["status"]["artifact"]["revision"].removeprefix("main@sha1:"))
            require(source.get("metadata", {}).get("uid") == bootstrap["source"].get("metadata", {}).get("uid"), "shared Flux source UID changed during rollback")
            final_checks["sharedSource"] = {"uid": source["metadata"]["uid"], "artifactRevision": source["status"]["artifact"]["revision"], "unchanged": True}
        except Exception as exc: errors.append(str(exc))
    preservation = {}
    if preserved:
        try: preservation = verify_preservation_v4(r, kubeconfig, preserved)
        except Exception as exc: errors.append(str(exc))
    if snapshot is not None and initial_cluster is not None:
        try:
            final_cluster = cluster_binding_v4(r, snapshot, p)
            require_same_cluster_identity_v4(initial_cluster, final_cluster, "during rollback")
            final_checks["clusterBinding"] = final_cluster
        except Exception as exc: errors.append(str(exc))
    if uncertain: errors.append(f"post-send create outcome unresolved: {uncertain}")
    return {"status": "complete" if not errors else "incomplete", "bothKustomizationsSuspended": len(flux) == 2, "flux": flux, "deleted": deleted, "finalChecks": final_checks, "preservation": preservation, "uncertainTarget": uncertain, "errors": errors, "finalizersRemovedByRunner": False}

def validate_success_facts_v4(facts: dict[str, Any], p: dict[str, Any], rev: str) -> None:
    _policy_call(POLICY.validate_trusted_live_facts, facts)
    require(facts["protectedRevision"] == rev and facts["policySha256"] == POLICY.activation_policy_sha256(p), "trusted facts Git/policy binding drift")
    require(facts["publication"]["manifestDigest"] == p["productPins"]["imageManifestDigest"], "trusted publication digest drift")
    require(facts["publication"]["verificationLevel"] == "anonymous-registry-manifest-digest-only" and facts["publication"]["cryptographicPublicationProvenanceVerified"] is False, "publication verification claim widened")
    require(facts["database"]["databaseSchemaSha256"] == p["productPins"]["databaseSchemaSha256"], "trusted database schema drift")
    require(len(facts["objectCreateResults"]) == 6 and len(facts["semanticObjects"]) == 6, "trusted object receipt set incomplete")
    require(facts["operationReservation"]["absencePreflight"]["status"] == "all-six-exact-target-names-absent" and len(facts["operationReservation"]["absencePreflight"]["targets"]) == 6, "trusted operation absence reservation incomplete")
    require(all(item["operationNonce"] == facts["operationReservation"]["operationNonce"] and item["temporaryNonceRemoved"] is True for item in facts["objectCreateResults"]), "trusted operation nonce lifecycle incomplete")
    require(set(facts["fluxTransaction"]["ready"]) == {"gateway", "workbenchIngress"}, "trusted dual Flux receipt incomplete")
    source_before, source_after = facts["fluxTransaction"]["sourceBeforeCas"], facts["fluxTransaction"]["sourceAfterReady"]
    require(source_before["uid"] == source_after["uid"] and source_before["artifactRevision"] == source_after["artifactRevision"] == f"main@sha1:{rev}", "trusted Flux source revision/UID receipt drift")
    require(set(facts["preservation"]) == {"webIngress", "existingWorkbenchNetworkPolicy"} and all(value["byteIdenticalCanonicalJson"] for value in facts["preservation"].values()), "trusted preservation receipt incomplete")
    secrets_receipt = facts["secretMaterialization"]
    require(set(secrets_receipt) == {"beforeCreate", "beforeIngress", "afterFlux"} and secrets_receipt["beforeCreate"] == secrets_receipt["beforeIngress"] == secrets_receipt["afterFlux"], "trusted Secret recheck receipt incomplete")
    require(set(facts["networkPolicyConflictScan"]) == {"beforeCreate", "beforeIngress", "afterFlux"}, "trusted policy-union recheck receipt incomplete")
    require(facts["rollback"] == {"status": "not-required", "finalizersRemovedByRunner": False}, "trusted success rollback receipt drift")

def activate(p: dict[str, Any], rev: str, kube: str | None, r: Runner, live: bool, sink: ReceiptSink, runner_hashes: dict[str, str]) -> dict[str, Any]:
    """Execute both Flux paths as one guarded transaction; no caller evidence."""
    if not live: return dry_run_plan(p, rev, {})
    _policy_call(POLICY.assert_activation_ready, p); require(kube is not None and Path(kube).is_file(), "live activation requires explicit existing kubeconfig")
    rendered = render_v4(rev, p); created: list[CreatedV4] = []; bootstrap = None; preserved = None; uncertain = None; operation_nonce: str | None = None; partial: dict[str, Any] = {}; snapshot: KubeconfigSnapshot | None = None; mutation_started = False
    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    previous_signal_handlers = install_transaction_signal_handlers_v4()
    try:
        snapshot = snapshot_kubeconfig_v4(kube, r); snapshot_path = str(snapshot.path)
        partial["clusterBinding"] = cluster_binding_v4(r, snapshot, p)
        partial["publication"] = anonymous_publication_v4(p)
        partial["endpoints"] = endpoint_facts_v4(p)
        preserved = preservation_v4(r, snapshot_path, p); bootstrap = flux_preflight_v4(r, snapshot_path, p, rev)
        absence = exact_absence_preflight_v4(r, snapshot_path, rendered); operation_nonce = secrets.token_hex(32)
        require(bool(POLICY.NONCE.fullmatch(operation_nonce)), "runner CSPRNG operation nonce invalid")
        secret_before = secret_materialization_v4(r, snapshot_path, p); policy_before = policy_union_v4(r, snapshot_path)
        cluster_before_mutation = cluster_binding_v4(r, snapshot, p); require_same_cluster_identity_v4(partial["clusterBinding"], cluster_before_mutation, "before mutation")
        order = ("gateway.networkPolicy", "workbenchIngress.networkPolicy", "gateway.serviceAccount", "gateway.service", "gateway.deployment")
        deployment = haproxy = None
        for logical in order:
            uncertain = logical; mutation_started = True
            try: item = create_v4(r, snapshot_path, logical, rendered[logical], operation_nonce)
            except CreateConflictError: uncertain = None; raise
            except TransportUncertainError: raise
            except Exception: uncertain = None; raise
            created.append(item); remove_operation_nonce_v4(r, snapshot_path, item, operation_nonce); uncertain = None
            if logical == "gateway.deployment": deployment, haproxy = health_v4(r, snapshot_path, p)
        require(deployment is not None and haproxy is not None, "internal health facts absent")
        owned = {(item.desired["metadata"]["namespace"], item.desired["metadata"]["name"]): item for item in created if item.desired["kind"] == "NetworkPolicy"}
        partial["publication"]["runtime"] = runtime_image_v4(r, snapshot_path, p)
        secret_before_ingress = secret_materialization_v4(r, snapshot_path, p); require_same_secret_materialization_v4(secret_before, secret_before_ingress, "before Ingress")
        policy_before_ingress = policy_union_v4(r, snapshot_path, owned)
        partial["database"] = database_status_v4(r, snapshot_path, p, partial["publication"]["runtime"])
        uncertain = "gateway.ingress"
        try: ingress = create_v4(r, snapshot_path, uncertain, rendered[uncertain], operation_nonce)
        except CreateConflictError: uncertain = None; raise
        except TransportUncertainError: raise
        except Exception: uncertain = None; raise
        created.append(ingress); remove_operation_nonce_v4(r, snapshot_path, ingress, operation_nonce); uncertain = None
        partial["routeMatrix"] = route_matrix_v4(r, p)
        source_before_cas = shared_source_revision_v4(r, snapshot_path, rev)
        changed = unsuspend_both_v4(r, snapshot_path, p, bootstrap); ready = wait_both_ready_v4(r, snapshot_path, p, bootstrap, rev)
        source_after_ready = shared_source_revision_v4(r, snapshot_path, rev)
        secret_after_flux = secret_materialization_v4(r, snapshot_path, p); require_same_secret_materialization_v4(secret_before, secret_after_flux, "after Flux")
        policy_after_flux = policy_union_v4(r, snapshot_path, owned)
        final_semantics = semantic_postconditions_v4(r, snapshot_path, created)
        preservation = verify_preservation_v4(r, snapshot_path, preserved)
        final_cluster = cluster_binding_v4(r, snapshot, p); require_same_cluster_identity_v4(partial["clusterBinding"], final_cluster, "before success")
        valid_until = started + dt.timedelta(seconds=300)
        facts = {"schemaVersion": POLICY.TRUSTED_LIVE_FACTS_SCHEMA, "policySha256": POLICY.activation_policy_sha256(p), "collectedAt": started.strftime("%Y-%m-%dT%H:%M:%SZ"), "validUntil": valid_until.strftime("%Y-%m-%dT%H:%M:%SZ"), "maxAgeSeconds": 300, "clusterBinding": {"initial": partial["clusterBinding"], "beforeMutation": cluster_before_mutation, "beforeSuccess": final_cluster}, "operationReservation": {"operationNonce": operation_nonce, "annotation": POLICY.OPERATION_NONCE_ANNOTATION, "absencePreflight": absence, "temporaryAnnotationsRemovedBeforeFlux": True}, "protectedRevision": rev, "publication": partial["publication"], "database": partial["database"], "endpoints": partial["endpoints"], "secretMaterialization": {"beforeCreate": secret_before, "beforeIngress": secret_before_ingress, "afterFlux": secret_after_flux}, "networkPolicyConflictScan": {"beforeCreate": policy_before, "beforeIngress": policy_before_ingress, "afterFlux": policy_after_flux}, "objectCreateResults": [item.receipt for item in created], "semanticObjects": final_semantics, "haproxy": haproxy, "routeMatrix": partial["routeMatrix"], "fluxTransaction": {"sourceBeforeCas": {"uid": source_before_cas["metadata"]["uid"], "resourceVersion": source_before_cas["metadata"]["resourceVersion"], "artifactRevision": f"main@sha1:{rev}"}, "casUnsuspended": {owner: value["metadata"]["resourceVersion"] for owner, value in changed.items()}, "ready": ready, "sourceAfterReady": {"uid": source_after_ready["metadata"]["uid"], "resourceVersion": source_after_ready["metadata"]["resourceVersion"], "artifactRevision": f"main@sha1:{rev}"}}, "preservation": preservation, "rollback": {"status": "not-required", "finalizersRemovedByRunner": False}}
        validate_success_facts_v4(facts, p, rev)
        require(dt.datetime.now(dt.timezone.utc) <= valid_until, "trusted live facts expired")
        success = {"schemaVersion": RECEIPT_SCHEMA, "status": "activated", "protectedRevision": rev, "activationPolicySha256": POLICY.activation_policy_sha256(p), "protectedRunnerFileSha256": runner_hashes, "trustedLiveFacts": facts, "civicAuthorityEffects": False}
        # Durable receipt persistence is the transaction commit point. Any
        # failure here is handled exactly like an activation failure. Ignore
        # termination only across this commit point and subsequent cleanup.
        defer_transaction_signals_v4()
        sink.commit(success)
        return success
    except (Exception, KeyboardInterrupt) as exc:
        # A second SIGINT/SIGTERM cannot interrupt the bounded rollback and
        # leave a partially exposed transaction without a durable receipt.
        defer_transaction_signals_v4()
        if mutation_started and snapshot is not None:
            if uncertain is not None and operation_nonce is not None:
                try:
                    recovered = rediscover_uncertain_create_v4(r, str(snapshot.path), uncertain, rendered[uncertain], operation_nonce, p["httpBoundary"]["timeoutsSeconds"]["kubernetesRequest"])
                    if recovered is not None: created.append(recovered); uncertain = None
                except Exception:
                    # A mismatched or still unreadable name is deliberately not
                    # adopted. rollback_v4 records the unresolved target and
                    # cannot report completion while it remains present.
                    pass
            rolled = rollback_v4(r, str(snapshot.path), p, created, bootstrap, preserved, uncertain, rendered=rendered, snapshot=snapshot, initial_cluster=partial.get("clusterBinding"))
        else:
            rolled = {"status": "complete", "bothKustomizationsSuspended": False, "flux": {}, "deleted": [], "finalChecks": {"noMutationStarted": True}, "preservation": {}, "uncertainTarget": None, "errors": [], "finalizersRemovedByRunner": False}
        interrupted = isinstance(exc, (ActivationInterrupted, KeyboardInterrupt))
        failure_text = str(exc) or "activation interrupted by operator"
        failure = {"schemaVersion": RECEIPT_SCHEMA, "status": "rolled-back" if rolled["status"] == "complete" else "rollback-incomplete", "protectedRevision": rev, "failure": failure_text, "protectedRunnerFileSha256": runner_hashes, "objectCreateResults": [item.receipt for item in created], "rollback": rolled, "termination": {"interrupted": interrupted, "signal": exc.signum if isinstance(exc, ActivationInterrupted) else None, "signalsDeferredDuringRollback": True}, "civicAuthorityEffects": False}
        sink.commit(failure); raise ActivationError(f"activation {failure['status']}: {exc}") from exc
    finally:
        try:
            if snapshot is not None: snapshot.close()
        finally:
            restore_transaction_signal_handlers_v4(previous_signal_handlers)

def main() -> int:
    global POLICY
    ap = argparse.ArgumentParser(); ap.add_argument("--expected-protected-revision", required=True); ap.add_argument("--dry-run", action="store_true"); ap.add_argument("--live", action="store_true"); ap.add_argument("--kubeconfig"); ap.add_argument("--receipt", type=Path, default=Path("participant-gateway-activation-receipt.json")); a = ap.parse_args()
    if a.dry_run == a.live: print("activation blocked: choose exactly one of --dry-run or --live", file=sys.stderr); return 2
    try:
        require(sys.flags.isolated == 1 and bool(sys.flags.safe_path), "executor requires python3 -I isolated safe-path mode")
        os.environ.pop("PYTHONPATH", None)
        rev = revision(a.expected_protected_revision); require((ROOT / ".git").exists(), "executor must run from the protected repository checkout")
        require(subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True, capture_output=True, check=False).stdout.strip() == rev, "checked-out Git revision is not expected protected revision")
        runner_hashes = protected_checkout(rev)
        POLICY = compile_verified_policy_module_v4(git_blob(rev, POLICY_MODULE_PATH), rev)
        bind_verified_policy_identity_v4(POLICY)
        p = policy(rev)
        if a.dry_run:
            result = dry_run_plan(p, rev, runner_hashes)
            sink = ReceiptSink.reserve(a.receipt); sink.commit(result); print(canonical(result)); return 0
        # The immutable readiness gate deliberately precedes kubeconfig
        # validation and Runner construction. The committed policy therefore
        # cannot contact Kubernetes in live mode.
        try: POLICY.assert_activation_ready(p)
        except POLICY.PolicyError as exc: raise ActivationError(str(exc)) from exc
        sink = ReceiptSink.reserve(a.receipt)
        result = activate(p, rev, a.kubeconfig, Runner(), True, sink, runner_hashes)
        print(canonical(result)); return 0
    except (ActivationError, OSError, json.JSONDecodeError) as exc: print(f"activation blocked: {exc}", file=sys.stderr); return 2
if __name__ == "__main__": raise SystemExit(main())
