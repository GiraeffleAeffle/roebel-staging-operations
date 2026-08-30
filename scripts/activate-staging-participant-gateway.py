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

import argparse, base64, copy, ctypes, datetime as dt, errno, hashlib, http.client, json, os, re, secrets, selectors, signal, socket, ssl, stat, subprocess, sys, tempfile, threading, time, types, urllib.error, urllib.parse, urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

POLICY_PATH = "policy/staging-participant-gateway-activation-policy.json"
NAMESPACE, FLUX_NAMESPACE = "stadtstack-roebel-web-preview", "flux-roebel-staging"
NAME, SOURCE = "roebel-staging-participant-gateway", "roebel-staging-operations"
WORKBENCH_NAMESPACE, WORKBENCH_POLICY_NAME = "stadtstack-roebel-staging-lab", "roebel-staging-participant-workbench-ingress"
RECEIPT_SCHEMA = "roebel_staging_participant_gateway_activation_receipt_v4"
RECOVERY_RECEIPT_SCHEMA = "roebel_staging_participant_gateway_recovery_receipt_v1"
PUBLIC_ROUTE_PROPAGATION_POLL_SECONDS = 0.25
ROOT = Path(__file__).resolve().parent.parent
GIT_BIN = Path("/usr/bin/git")
POLICY_MODULE_PATH = "scripts/staging_participant_gateway_policy.py"
WORKFLOW_PATH = ".github/workflows/staging-participant-gateway-activation.yml"
BOOTSTRAP_MODULE_PATH = "scripts/staging_participant_flux_bootstrap.py"
BOOTSTRAP_RUNNER_PATH = "scripts/bootstrap-staging-participant-flux.py"
LIVE_WRAPPER_PATH = "scripts/run-staging-participant-gateway-live.py"
HANDOVER_RUNNER_PATH = "scripts/handover-staging-participant-dormant-receipt.py"
HANDOVER_MODULE_PATH = "scripts/staging_participant_dormant_receipt_handover.py"
SECRET_MATERIALIZER_PATH = "scripts/materialize-staging-participant-gateway-secrets.py"
TRACER_ACTIVATION_RECEIPT_SCHEMA = "roebel_tracer_data_plane_activation_receipt_v1"
TRACER_ACTIVATION_RUNNER_PATH = "scripts/run-tracer-data-plane-live.py"
TRACER_MATERIALIZER_PATH = "scripts/materialize-tracer-data-plane-secrets.py"
TRACER_POLICY_PATH = "scripts/tracer_data_plane_policy.py"
TRACER_RENDER_ROOT = "reviewed-render/roebel-staging/tracer-data-plane"
TRACER_RECEIPT_ORIGIN_REVISION = "068c1248dcbc7e1967b5822abad42a55dce7c0f8"
TRACER_RECEIPT_INTERMEDIATE_REVISION = "abd199dff25066e1d60911667b23c2655e826b75"
TRACER_RECEIPT_SECOND_SUCCESSOR_REVISION = "f41bb1ac2ec27c6332a3b5614e65516349f239b0"
TRACER_RECEIPT_THIRD_SUCCESSOR_REVISION = "89cc247c412374205d83433dcc5f774f8c705b1b"
TRACER_RECEIPT_FOURTH_SUCCESSOR_REVISION = "93d9e5bb87acb18887250316fb0b7a1bdf4c7cfa"
TRACER_RECEIPT_FIFTH_SUCCESSOR_REVISION = "7aa2db7f174742555ec0374725d2c80ee0350e8a"
TRACER_RECEIPT_SIXTH_SUCCESSOR_REVISION = "720e058a61c185c8c64e2679e14d5dc8eea96ba0"
TRACER_RECEIPT_ORIGIN_RAW_SHA256 = "sha256:75b92c90537734f9e514dee6bbee0d3a09fcc9dc9cfad8fe039b7a8f159ea282"
TRACER_RECEIPT_ORIGIN_ACTIVATION_RUNNER_SHA256 = "sha256:83f7b1f6fd9830436e97a1c90d30976610908368bbbc2a9a408cb8dd7862a547"
TRACER_RECEIPT_ORIGIN_TO_INTERMEDIATE_FILES = frozenset({
    "scripts/activate-staging-participant-gateway.py",
    "scripts/test_activate_staging_participant_gateway.py",
})
TRACER_RECEIPT_INTERMEDIATE_TO_SECOND_SUCCESSOR_FILES = frozenset({
    "scripts/activate-staging-participant-gateway.py",
    "scripts/test_activate_staging_participant_gateway.py",
    "scripts/run-staging-participant-gateway-live.py",
    "scripts/test_run_staging_participant_gateway_live.py",
})
TRACER_RECEIPT_SECOND_TO_THIRD_SUCCESSOR_FILES = frozenset({
    "scripts/activate-staging-participant-gateway.py",
    "scripts/test_activate_staging_participant_gateway.py",
})
TRACER_RECEIPT_THIRD_TO_FOURTH_SUCCESSOR_FILES = frozenset({
    "scripts/run-staging-participant-gateway-live.py",
    "scripts/test_run_staging_participant_gateway_live.py",
})
TRACER_RECEIPT_FOURTH_TO_FIFTH_SUCCESSOR_FILES = frozenset({
    "scripts/run-staging-participant-gateway-live.py",
    "scripts/test_run_staging_participant_gateway_live.py",
})
TRACER_RECEIPT_FIFTH_TO_SIXTH_SUCCESSOR_FILES = frozenset({
    "scripts/activate-staging-participant-gateway.py",
    "scripts/test_activate_staging_participant_gateway.py",
    "scripts/run-staging-participant-gateway-live.py",
    "scripts/test_run_staging_participant_gateway_live.py",
})
TRACER_RECEIPT_SIXTH_SUCCESSOR_TO_ACCEPTOR_FILES = frozenset({
    "scripts/activate-staging-participant-gateway.py",
    "scripts/test_activate_staging_participant_gateway.py",
    "scripts/run-staging-participant-gateway-live.py",
    "scripts/test_run_staging_participant_gateway_live.py",
})
TRACER_RECEIPT_PROTECTED_PATHS = (
    TRACER_ACTIVATION_RUNNER_PATH,
    "scripts/activate-staging-participant-gateway.py",
    TRACER_POLICY_PATH,
    POLICY_MODULE_PATH,
    POLICY_PATH,
    TRACER_MATERIALIZER_PATH,
    "policy/repository-contract.json",
    f"{TRACER_RENDER_ROOT}/runtime-pin.json",
    f"{TRACER_RENDER_ROOT}/serviceaccount.json",
    f"{TRACER_RENDER_ROOT}/postgres-deployment.json",
    f"{TRACER_RENDER_ROOT}/postgres-service.json",
    f"{TRACER_RENDER_ROOT}/postgres-networkpolicy.json",
    f"{TRACER_RENDER_ROOT}/postgrest-deployment.json",
    f"{TRACER_RENDER_ROOT}/postgrest-service.json",
    f"{TRACER_RENDER_ROOT}/postgrest-networkpolicy.json",
    f"{TRACER_RENDER_ROOT}/kustomization.yaml",
    f"{TRACER_RENDER_ROOT}/bootstrap/zz-roebel-tracer.sh",
    f"{TRACER_RENDER_ROOT}/bootstrap/71-roebel-tracer-baseline.sql",
    f"{TRACER_RENDER_ROOT}/bootstrap/72-provision-roebel-vault.sh",
    f"{TRACER_RENDER_ROOT}/bootstrap/73-staging-participant-gateway.sql",
    f"{TRACER_RENDER_ROOT}/bootstrap/74-staging-participant-topic-tracer.sql",
)
BOOTSTRAP_WORKFLOW_PATH = ".github/workflows/staging-participant-flux-bootstrap.yml"
HANDOVER_ARCHIVE_REVISION = "08c4171573bb138845a9160e747f6ac56a3c754e"
# A materialization receipt produced by the reviewed b790 transaction is the
# sole historical Secret input accepted by the dormant-receipt continuation.
# These are value-free provenance binders: activation still GETs only the live
# Secret UID/keyset/resourceVersion before its first mutation.
SECRET_RECEIPT_ORIGIN_REVISION = "b790fa76d4f2ad4d0bd86663dcd896b97ba0b61e"
SECRET_RECEIPT_ORIGIN_RAW_SHA256 = "sha256:b8c8aab74cc3101ef20394b080c1e18e7435fb1d07661fcf103b46e73b750be3"
SECRET_RECEIPT_ORIGIN_CANONICAL_SHA256 = "sha256:173d52ab2fc1b496d61241eebbf986a5ece27bb66298b96db31d16b9ce273aa9"
SECRET_RECEIPT_ORIGIN_ACTIVATION_POLICY_SHA256 = "sha256:3319969ef3bec5eb3705ac7b551197a89aada430a9bc7b231ad543e10a8ccd51"
SECRET_RECEIPT_ORIGIN_RUNNER_FILE_SHA256 = {
    "policy/repository-contract.json": "sha256:1e47d943cd741c2d00ef1a14fdeb2dab7e0d5b481af88dce8685ad83519bd29e",
    "policy/staging-participant-gateway-activation-policy.json": "sha256:f9ec42610af3ced30e0951bae9ffa2e0176d555819712b0e9e67e25650817c1a",
    "scripts/activate-staging-participant-gateway.py": "sha256:d4870e21ccd2b6eaf6d8de405142c8c16dfce0b0320e1da17af33de2a3136518",
    "scripts/materialize-staging-participant-gateway-secrets.py": "sha256:e8eb56782cd52403411de6990379fd5827d06e12d2aa7181ae7fdb142d1292b9",
    "scripts/run-staging-participant-gateway-live.py": "sha256:11d4bc7ef959aea416109111a3358dbe11b35bfed89204e09d5d25daac158f14",
    "scripts/staging_participant_gateway_policy.py": "sha256:14f78ce3284adb6bba46bfc74c96c62059b12566051f0015c95f2acafa04cd97",
}
SECRET_RECEIPT_ORIGIN_RESOURCE_VERSIONS = {"config": "15906163", "runtime": "15906221"}
SECRET_RECEIPT_ORIGIN_SECRET_RECORDS = {
    "config": {
        "target": {
            "apiVersion": "v1",
            "kind": "Secret",
            "name": "roebel-staging-participant-gateway-config",
            "namespace": "stadtstack-roebel-web-preview",
        },
        "uid": "f1ccc7ce-767b-4c08-9afc-d3f1302b1f86",
        "resourceVersion": "15906163",
        "keySet": ["allowed-wallets", "invite-sha256", "mecky-pubkey"],
        "ownershipNonce": "a42a7790e04a116a6f5642f8d9c03e879348bfce24563ddfae7995f5ad354c63",
        "valuesRead": False,
    },
    "runtime": {
        "target": {
            "apiVersion": "v1",
            "kind": "Secret",
            "name": "roebel-staging-participant-gateway-runtime",
            "namespace": "stadtstack-roebel-web-preview",
        },
        "uid": "11b986e3-c6b6-41bd-8744-72a485210988",
        "resourceVersion": "15906221",
        "keySet": ["session-key", "supabase-anon-key", "supabase-rpc-secret"],
        "ownershipNonce": "845f2e0976c5197c417ffe35639ce5204ff4dc54c75ea7ef383803cd33de2359",
        "valuesRead": False,
    },
}
# One-shot authority for recovering the failed-closed aaca3166 activation.
# The raw digest binds every byte of the original durable receipt; the deep
# projection below independently constrains every field later used to delete.
FAILED_ACTIVATION_ORIGIN_REVISION = "aaca3166110b76ace201548ac37ff60016a899d6"
FAILED_ACTIVATION_RAW_SHA256 = "sha256:4cc9272ddccd8b42a3c7748fdc51b0ae1c0374f29c5d83b59578da540dcf3545"
FAILED_ACTIVATION_CANONICAL_SHA256 = "sha256:b043effbf0764042d32283b2e856c850380fe0bcc180febc71e3566dc2cabfda"
FAILED_ACTIVATION_OPERATION_NONCE = "4c8f7bc2cdc2a4f95564d12ea483d6f7169b09c2a591407cf7a2a37eaa0e4a82"
FAILED_ACTIVATION_FAILURE = "gateway.deployment: post-send create outcome unresolved"
FAILED_ACTIVATION_CREATED_ORDER = (
    "gateway.networkPolicy",
    "workbenchIngress.networkPolicy",
    "gateway.serviceAccount",
    "gateway.service",
)
FAILED_ACTIVATION_OBJECT_UIDS = {
    "gateway.networkPolicy": "7c8dab73-f107-4c35-910b-3cd486ca8c69",
    "workbenchIngress.networkPolicy": "3b418a42-ba04-4983-9142-89530dda5fb1",
    "gateway.serviceAccount": "9b572a8e-7a73-450c-a617-15f19902936b",
    "gateway.service": "f1ecb145-6bd4-463d-8ab8-eeb72acbad31",
}
FAILED_ACTIVATION_RUNNER_FILE_SHA256 = {
    ".github/workflows/staging-participant-flux-bootstrap.yml": "sha256:bbb62179e5f727a08f700611800fc927e242b8b78713f17f2d99aca5c42574da",
    ".github/workflows/staging-participant-gateway-activation.yml": "sha256:5b024042e8d2e60f86fa372b75c27ef435d3117b2fe69edaf7e33fa11b3ef9ad",
    "policy/repository-contract.json": "sha256:91a31cf5019baac108c9b86a0c85c8bdf148d97f09363d4599c7b5a781239a89",
    "policy/staging-participant-gateway-activation-policy.json": "sha256:f9ec42610af3ced30e0951bae9ffa2e0176d555819712b0e9e67e25650817c1a",
    "scripts/activate-staging-participant-gateway.py": "sha256:eb0ec2f0292d11587e2f6ae3cb9fc2f057b80cb77f8f0a83d3bbde2dc19073d7",
    "scripts/bootstrap-staging-participant-flux.py": "sha256:53eea57ac0569a60d7d786e31bc8415790ad022e479a107eb1d5020d3579e079",
    "scripts/handover-staging-participant-dormant-receipt.py": "sha256:252ea84b99631442fe5e938b1c4e97de11e19191d6006878779804d41f878091",
    "scripts/run-staging-participant-gateway-live.py": "sha256:5ffd001e5cda48ebfa1ecc67a2be437521daca890956b12d85a7a7383ef38061",
    "scripts/staging_participant_dormant_receipt_handover.py": "sha256:e6cb83a3b6b97f8eeee1d92584f916ca8b325327c1d993d8ec74c055d08b2fd7",
    "scripts/staging_participant_flux_bootstrap.py": "sha256:540b61de77c03a8e2bbee765a745cad271e4af4b2b26563886fbeb869eea99ba",
    "scripts/staging_participant_gateway_policy.py": "sha256:14f78ce3284adb6bba46bfc74c96c62059b12566051f0015c95f2acafa04cd97",
    "scripts/verify-reviewed-render.py": "sha256:98919049aed32559e717ce18cc6e7119a07eef6c5dae99efc995f867e8876e10",
}
FAILED_ACTIVATION_OBJECT_CREATE_RESULTS = (
    {
        "discoveredAfterPostSendUncertainty": False,
        "operationNonce": FAILED_ACTIVATION_OPERATION_NONCE,
        "outcome": "http-201-created",
        "postNonceRemovalResourceVersion": "16386498",
        "protectedRenderBlobSha256": "sha256:57078c094aba79e4f70730b8df577d6142bbb97c8b593a55c96f8551db63c04a",
        "protectedRenderPath": "reviewed-render/roebel-staging/staging-participant-gateway/networkpolicy.json",
        "resourceVersion": "16386487",
        "rollbackOwned": True,
        "semanticSha256": "sha256:64dbb159ef21319791ac4b473b82e0fce876c1e33d5988f31c314d3d06564afc",
        "target": {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "name": "roebel-staging-participant-gateway", "namespace": "stadtstack-roebel-web-preview"},
        "temporaryNonceRemoved": True,
        "uid": FAILED_ACTIVATION_OBJECT_UIDS["gateway.networkPolicy"],
    },
    {
        "discoveredAfterPostSendUncertainty": False,
        "operationNonce": FAILED_ACTIVATION_OPERATION_NONCE,
        "outcome": "http-201-created",
        "postNonceRemovalResourceVersion": "16386516",
        "protectedRenderBlobSha256": "sha256:c7e161a50d67f0fcb4b46e08e52ed6cba12e49fc81cf392ea9cadb3aa367e1ed",
        "protectedRenderPath": "reviewed-render/roebel-staging/staging-participant-gateway/workbench-ingress/networkpolicy.json",
        "resourceVersion": "16386508",
        "rollbackOwned": True,
        "semanticSha256": "sha256:64e6a69a9a40df7d1c421e985fd4036ccfced62dfd73c6f9358c637a631263ac",
        "target": {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "name": "roebel-staging-participant-workbench-ingress", "namespace": "stadtstack-roebel-staging-lab"},
        "temporaryNonceRemoved": True,
        "uid": FAILED_ACTIVATION_OBJECT_UIDS["workbenchIngress.networkPolicy"],
    },
    {
        "discoveredAfterPostSendUncertainty": False,
        "operationNonce": FAILED_ACTIVATION_OPERATION_NONCE,
        "outcome": "http-201-created",
        "postNonceRemovalResourceVersion": "16386540",
        "protectedRenderBlobSha256": "sha256:488e31034f296d29c638df0a4b1f4a2b745c2559a9f49abb43b52bceccdcc0f0",
        "protectedRenderPath": "reviewed-render/roebel-staging/staging-participant-gateway/serviceaccount.json",
        "resourceVersion": "16386527",
        "rollbackOwned": True,
        "semanticSha256": "sha256:32b583b5e1ea31afc4cd13a42f00455e8114bb7d07f707b2a5921d9e23517da7",
        "target": {"apiVersion": "v1", "kind": "ServiceAccount", "name": "roebel-staging-participant-gateway", "namespace": "stadtstack-roebel-web-preview"},
        "temporaryNonceRemoved": True,
        "uid": FAILED_ACTIVATION_OBJECT_UIDS["gateway.serviceAccount"],
    },
    {
        "discoveredAfterPostSendUncertainty": False,
        "operationNonce": FAILED_ACTIVATION_OPERATION_NONCE,
        "outcome": "http-201-created",
        "postNonceRemovalResourceVersion": "16386566",
        "protectedRenderBlobSha256": "sha256:9327fa75f3516a231e69573bb52ea63907e8c89a0a439ba1738b4390ca029f35",
        "protectedRenderPath": "reviewed-render/roebel-staging/staging-participant-gateway/service.json",
        "resourceVersion": "16386553",
        "rollbackOwned": True,
        "semanticSha256": "sha256:4beace9f0e1850e62e07721e7154a586b9273308f3c8755449a0c3f1545986cf",
        "target": {"apiVersion": "v1", "kind": "Service", "name": "roebel-staging-participant-gateway", "namespace": "stadtstack-roebel-web-preview"},
        "temporaryNonceRemoved": True,
        "uid": FAILED_ACTIVATION_OBJECT_UIDS["gateway.service"],
    },
)
BOOTSTRAP_PROTECTED_PATHS = (
    BOOTSTRAP_RUNNER_PATH,
    LIVE_WRAPPER_PATH,
    HANDOVER_RUNNER_PATH,
    HANDOVER_MODULE_PATH,
    BOOTSTRAP_MODULE_PATH,
    POLICY_MODULE_PATH,
    POLICY_PATH,
    "scripts/activate-staging-participant-gateway.py",
    BOOTSTRAP_WORKFLOW_PATH,
    "scripts/verify-reviewed-render.py",
    "policy/repository-contract.json",
)
HANDOVER_COMPATIBILITY_PATHS = (
    POLICY_PATH,
    POLICY_MODULE_PATH,
    BOOTSTRAP_WORKFLOW_PATH,
    WORKFLOW_PATH,
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
HANDOVER_CURRENT_PRESERVATION_PATHS = (
    "reviewed-render/roebel-staging/web/ingress.json",
    "reviewed-render/roebel-staging/workbench-baseline/networkpolicy.json",
)
HANDOVER_ARCHIVED_PROTECTED_PATHS = (
    BOOTSTRAP_RUNNER_PATH,
    LIVE_WRAPPER_PATH,
    BOOTSTRAP_MODULE_PATH,
    POLICY_MODULE_PATH,
    POLICY_PATH,
    "scripts/activate-staging-participant-gateway.py",
    BOOTSTRAP_WORKFLOW_PATH,
    "scripts/verify-reviewed-render.py",
    "policy/repository-contract.json",
)

POLICY: Any = None
BOOTSTRAP: Any = None
SECRET_MATERIALIZER: Any = None
_PREBOUND_GIT_BLOBS: dict[tuple[str, str], bytes] | None = None

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

def compile_verified_bootstrap_module_v4(source: bytes, rev: str) -> Any:
    """Compile the exact protected receipt binder without local imports."""
    revision(rev)
    require(isinstance(source, bytes) and source, "protected bootstrap module blob is empty")
    name = f"staging_participant_flux_bootstrap_{rev}"
    module = types.ModuleType(name)
    module.__file__ = f"git:{rev}:{BOOTSTRAP_MODULE_PATH}"
    module.__package__ = ""
    sys.modules[name] = module
    try:
        exec(compile(source, module.__file__, "exec", dont_inherit=True), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module

def compile_verified_tracer_policy_module_v4(source: bytes, rev: str) -> Any:
    """Compile only the current protected tracer policy bytes."""
    revision(rev)
    require(isinstance(source, bytes) and source, "protected tracer policy blob is empty")
    name = f"tracer_data_plane_policy_{rev}"
    module = types.ModuleType(name)
    module.__file__ = f"git:{rev}:{TRACER_POLICY_PATH}"
    module.__package__ = ""
    sys.modules[name] = module
    try:
        exec(compile(source, module.__file__, "exec", dont_inherit=True), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module

def compile_verified_handover_runner_v4(source: bytes, rev: str) -> Any:
    """Compile the exact protected handover binder without local imports."""
    revision(rev)
    require(isinstance(source, bytes) and source, "protected handover runner blob is empty")
    name = f"staging_participant_dormant_handover_runner_{rev}"
    module = types.ModuleType(name)
    module.__file__ = f"git:{rev}:{HANDOVER_RUNNER_PATH}"
    module.__package__ = ""
    sys.modules[name] = module
    try:
        exec(compile(source, module.__file__, "exec", dont_inherit=True), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    module.ROOT = ROOT
    module.GIT_BIN = GIT_BIN
    return module

def compile_verified_secret_materializer_v4(source: bytes, rev: str) -> Any:
    """Compile the current protected Secret receipt binder without imports."""
    revision(rev)
    require(isinstance(source, bytes) and source, "protected Secret materializer blob is empty")
    name = f"staging_participant_secret_materializer_{rev}"
    module = types.ModuleType(name)
    module.__file__ = f"git:{rev}:{SECRET_MATERIALIZER_PATH}"
    module.__package__ = ""
    sys.modules[name] = module
    try:
        exec(compile(source, module.__file__, "exec", dont_inherit=True), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    module.POLICY = POLICY
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

def trusted_git_v4(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[Any]:
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
        "GIT_NO_LAZY_FETCH": "1",
        "HOME": "/dev/null",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    return subprocess.run([str(GIT_BIN), "--no-replace-objects", *args], env=environment, **kwargs)

def exact_revision_transition_files_v4(parent: str, child: str, label: str) -> set[str]:
    """Prove one non-merge Git edge and return its exact path delta."""
    revision(parent); revision(child)
    try:
        lineage = trusted_git_v4(
            ["-C", str(ROOT), "rev-list", "--parents", "-n", "1", child],
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
        require(
            lineage.returncode == 0
            and lineage.stdout.strip().split() == [child, parent],
            f"{label} protected parent drift",
        )
        changed = trusted_git_v4(
            [
                "-C", str(ROOT), "diff", "--no-ext-diff", "--no-renames",
                "--name-only", "-z", parent, child, "--",
            ],
            capture_output=True,
            check=False,
            timeout=10,
        )
    except subprocess.TimeoutExpired as exc:
        raise ActivationError(f"{label} protected transition timed out") from exc
    require(changed.returncode == 0, f"{label} protected file set unavailable")
    try:
        paths = [item.decode("utf-8") for item in changed.stdout.split(b"\0") if item]
    except UnicodeDecodeError as exc:
        raise ActivationError(f"{label} protected file set is not UTF-8") from exc
    require(len(paths) == len(set(paths)), f"{label} protected file set duplicated")
    return set(paths)

def protected_checkout(rev: str) -> dict[str, str]:
    """Bind every executable repo file before any Kubernetes subprocess exists."""
    paths = tuple(dict.fromkeys((*BOOTSTRAP_PROTECTED_PATHS, WORKFLOW_PATH)))
    hashes: dict[str, str] = {}
    for path in paths:
        local = ROOT / path
        require(local.is_file() and not local.is_symlink(), f"protected executable missing: {path}")
        expected = git_blob(rev, path)
        require(local.read_bytes() == expected, f"protected executable differs from exact Git blob: {path}")
        hashes[path] = bytes_digest(expected)
    return hashes

@dataclass
class Result: code: int = 0; out: str = ""; err: str = ""

@dataclass
class ExecutableBinding:
    path: Path
    fd: int
    device: int
    inode: int
    size: int
    sha256: str
    owns_fd: bool = True

    def close(self) -> None:
        if self.owns_fd and self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def environment(self, prefix: str) -> dict[str, str]:
        return {
            f"{prefix}_PATH": str(self.path),
            f"{prefix}_FD": str(self.fd),
            f"{prefix}_DEVICE": str(self.device),
            f"{prefix}_INODE": str(self.inode),
            f"{prefix}_SIZE": str(self.size),
            f"{prefix}_SHA256": self.sha256,
        }

    def popen(self, args: list[str], **kwargs: Any) -> "VerifiedProcess":
        return verified_popen(self, args, **kwargs)

def bind_executable_snapshot(path: Path, expected_sha256: str) -> ExecutableBinding:
    selected = Path(os.path.abspath(path)); info = os.lstat(selected)
    require(
        stat.S_ISREG(info.st_mode)
        and not selected.is_symlink()
        and info.st_uid == os.geteuid()
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o500
        and info.st_size > 0,
        "executable snapshot metadata invalid",
    )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"): flags |= os.O_NOFOLLOW
    fd = os.open(selected, flags)
    try:
        opened = os.fstat(fd)
        raw = os.pread(fd, opened.st_size + 1, 0)
        observed = bytes_digest(raw)
        require(
            (opened.st_dev, opened.st_ino, opened.st_size)
            == (info.st_dev, info.st_ino, info.st_size)
            and len(raw) == opened.st_size
            and observed == expected_sha256,
            "executable snapshot binding drift",
        )
        return ExecutableBinding(selected, fd, opened.st_dev, opened.st_ino, opened.st_size, observed)
    except BaseException:
        os.close(fd)
        raise

def executable_binding_from_environment(prefix: str) -> ExecutableBinding:
    try:
        path = Path(os.environ[f"{prefix}_PATH"])
        fd = int(os.environ[f"{prefix}_FD"])
        device = int(os.environ[f"{prefix}_DEVICE"])
        inode = int(os.environ[f"{prefix}_INODE"])
        size = int(os.environ[f"{prefix}_SIZE"])
        expected = os.environ[f"{prefix}_SHA256"]
    except (KeyError, ValueError) as exc:
        raise ActivationError(f"{prefix} executable binding environment invalid") from exc
    info = os.fstat(fd)
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.geteuid()
        and (info.st_dev, info.st_ino, info.st_size) == (device, inode, size)
        and bytes_digest(os.pread(fd, size + 1, 0)) == expected,
        f"{prefix} inherited executable binding drift",
    )
    return ExecutableBinding(path, fd, device, inode, size, expected, owns_fd=False)

def _set_descriptor_flags(fd: int, flags: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    code = libc.fchflags(ctypes.c_int(fd), ctypes.c_uint(flags))
    require(code == 0, f"descriptor flags update failed: errno {ctypes.get_errno()}")

class VerifiedProcess:
    def __init__(
        self,
        pid: int,
        args: list[str],
        stdin: Any,
        stdout: Any,
        stderr: Any,
        *,
        text: bool,
        cleanup_binding: ExecutableBinding | None = None,
    ):
        self.pid, self.args = pid, args
        self.stdin, self.stdout, self.stderr = stdin, stdout, stderr
        self.text = text
        self.returncode: int | None = None
        self.cleanup_binding = cleanup_binding
        self.cleanup_error: str | None = None

    @staticmethod
    def _exitcode(status: int) -> int:
        return os.waitstatus_to_exitcode(status)

    def _cleanup_materialization(self) -> None:
        binding = self.cleanup_binding
        if binding is None: return
        self.cleanup_binding = None
        try:
            info = os.lstat(binding.path)
            opened = os.fstat(binding.fd)
            if (
                (info.st_dev, info.st_ino, info.st_size) != (binding.device, binding.inode, binding.size)
                or (opened.st_dev, opened.st_ino, opened.st_size) != (binding.device, binding.inode, binding.size)
                or not (opened.st_flags & stat.UF_IMMUTABLE)
                or bytes_digest(os.pread(binding.fd, binding.size + 1, 0)) != binding.sha256
            ):
                raise ActivationError("per-spawn executable path or content changed")
            _set_descriptor_flags(binding.fd, 0)
            binding.path.unlink()
            parent = os.open(binding.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try: os.fsync(parent)
            finally: os.close(parent)
        except BaseException as exc:
            self.cleanup_error = str(exc)
            self.returncode = 125
        finally:
            binding.close()

    def poll(self) -> int | None:
        if self.returncode is not None: return self.returncode
        try: pid, status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError: return self.returncode
        if pid == self.pid:
            self.returncode = self._exitcode(status)
            self._cleanup_materialization()
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        deadline = None if timeout is None else time.monotonic() + timeout
        while self.poll() is None:
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(self.args, timeout)
            time.sleep(0.01)
        return int(self.returncode)

    def terminate(self) -> None:
        try: os.killpg(self.pid, signal.SIGTERM)
        except ProcessLookupError: pass

    def kill(self) -> None:
        try: os.killpg(self.pid, signal.SIGKILL)
        except ProcessLookupError: pass

    def communicate(self, input: str | bytes | None = None, timeout: float | None = None) -> tuple[Any, Any]:
        input_bytes = input.encode() if isinstance(input, str) else input
        outputs: dict[str, bytes] = {"stdout": b"", "stderr": b""}
        threads: list[threading.Thread] = []
        def read_stream(name: str, stream: Any) -> None:
            try: outputs[name] = stream.read()
            finally: stream.close()
        def write_stream(stream: Any) -> None:
            try:
                if input_bytes: stream.write(input_bytes); stream.flush()
            finally: stream.close()
        for name, stream in (("stdout", self.stdout), ("stderr", self.stderr)):
            if stream is not None:
                thread = threading.Thread(target=read_stream, args=(name, stream), daemon=False)
                threads.append(thread); thread.start()
        if self.stdin is not None:
            thread = threading.Thread(target=write_stream, args=(self.stdin,), daemon=False)
            threads.append(thread); thread.start()
        try:
            self.wait(timeout)
        except subprocess.TimeoutExpired:
            self.kill()
            try: self.wait(5)
            except subprocess.TimeoutExpired: pass
            for thread in threads: thread.join(timeout=5)
            raise
        for thread in threads: thread.join(timeout=5)
        stdout, stderr = outputs["stdout"], outputs["stderr"]
        if self.text:
            return stdout.decode(errors="replace"), stderr.decode(errors="replace")
        return stdout, stderr

def _verified_text_vnode(pid: int, binding: ExecutableBinding) -> None:
    lsof = Path("/usr/sbin/lsof"); info = os.lstat(lsof)
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == 0
        and stat.S_IMODE(info.st_mode) & 0o022 == 0
        and os.access(lsof, os.X_OK),
        "trusted lsof executable metadata invalid",
    )
    result = subprocess.run(
        [str(lsof), "-a", "-p", str(pid), "-d", "txt", "-F0"],
        capture_output=True,
        check=False,
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        timeout=10,
    )
    require(result.returncode == 0, "suspended executable identity unavailable")
    expected_device = f"D0x{binding.device:x}".encode()
    expected_inode = f"i{binding.inode}".encode()
    expected_size = f"s{binding.size}".encode()
    records = [set(record.split(b"\0")) for record in result.stdout.split(b"\n") if record]
    require(
        any(b"ftxt" in record and expected_device in record and expected_inode in record and expected_size in record for record in records),
        "spawned executable vnode differs from verified binding",
    )

def _verified_code_signature(pid: int) -> None:
    flags = ctypes.c_uint32(0)
    libc = ctypes.CDLL(None, use_errno=True)
    code = libc.csops(ctypes.c_int(pid), ctypes.c_uint(0), ctypes.byref(flags), ctypes.sizeof(flags))
    require(code == 0, f"spawned code-sign status unavailable: errno {ctypes.get_errno()}")
    required = 0x00000001 | 0x00000200 | 0x00020000
    require(flags.value & required == required, "spawned executable lacks valid kill-on-invalid linker signature")

VERIFIED_SPAWN_LOCK = threading.Lock()

def _materialize_bound_executable(binding: ExecutableBinding) -> ExecutableBinding:
    destination = binding.path.parent / f".bound-exec-{secrets.token_hex(16)}"
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"): flags |= os.O_NOFOLLOW
    fd = os.open(destination, flags, 0o500)
    try:
        digest = hashlib.sha256(); offset = 0
        while offset < binding.size:
            chunk = os.pread(binding.fd, min(1024 * 1024, binding.size - offset), offset)
            require(bool(chunk), "bound executable source read was incomplete")
            pending = memoryview(chunk)
            while pending:
                written = os.write(fd, pending)
                pending = pending[written:]
            digest.update(chunk); offset += len(chunk)
        os.fchmod(fd, 0o500); os.fsync(fd)
        info = os.fstat(fd); observed = "sha256:" + digest.hexdigest()
        require(
            offset == binding.size
            and info.st_size == binding.size
            and info.st_nlink == 1
            and observed == binding.sha256,
            "per-spawn executable materialization drift",
        )
        _set_descriptor_flags(fd, stat.UF_IMMUTABLE)
        require(os.fstat(fd).st_flags & stat.UF_IMMUTABLE, "per-spawn executable immutable descriptor flag absent")
        parent = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try: os.fsync(parent)
        finally: os.close(parent)
        return ExecutableBinding(destination, fd, info.st_dev, info.st_ino, info.st_size, observed)
    except BaseException:
        try: _set_descriptor_flags(fd, 0)
        except BaseException: pass
        os.close(fd)
        try: destination.unlink()
        except FileNotFoundError: pass
        raise

def verified_popen(
    binding: ExecutableBinding,
    args: list[str],
    *,
    stdin: Any = None,
    stdout: Any = None,
    stderr: Any = None,
    text: bool = False,
    env: dict[str, str] | None = None,
    pass_fds: tuple[int, ...] = (),
    start_new_session: bool = True,
) -> VerifiedProcess:
    require(sys.platform == "darwin", "verified executable spawn requires Darwin suspended spawn")
    require(start_new_session, "verified executable spawn requires a separate session")
    opened = os.fstat(binding.fd)
    require(
        (opened.st_dev, opened.st_ino, opened.st_size) == (binding.device, binding.inode, binding.size)
        and bytes_digest(os.pread(binding.fd, binding.size + 1, 0)) == binding.sha256,
        "executable binding changed before spawn",
    )
    invocation: ExecutableBinding | None = _materialize_bound_executable(binding)
    libc = ctypes.CDLL(None, use_errno=True)
    actions = ctypes.c_void_p(); attributes = ctypes.c_void_p()
    actions_ready = attributes_ready = False
    parent_stdin = parent_stdout = parent_stderr = None
    child_fds: list[int] = []; devnull_fd: int | None = None; spawned_pid: int | None = None
    try:
        require(libc.posix_spawn_file_actions_init(ctypes.byref(actions)) == 0, "posix_spawn file actions unavailable")
        actions_ready = True
        require(libc.posix_spawnattr_init(ctypes.byref(attributes)) == 0, "posix_spawn attributes unavailable")
        attributes_ready = True
        def fileno(value: Any) -> int:
            return value if isinstance(value, int) else value.fileno()
        def pipe_for(target: int, reading_in_parent: bool) -> Any:
            read_fd, write_fd = os.pipe()
            child_fd, parent_fd = (write_fd, read_fd) if reading_in_parent else (read_fd, write_fd)
            require(libc.posix_spawn_file_actions_adddup2(ctypes.byref(actions), child_fd, target) == 0, "posix_spawn pipe action failed")
            child_fds.append(child_fd)
            return os.fdopen(parent_fd, "rb" if reading_in_parent else "wb", buffering=0)
        if stdin == subprocess.PIPE:
            parent_stdin = pipe_for(0, False)
        elif stdin == subprocess.DEVNULL:
            devnull_fd = os.open("/dev/null", os.O_RDWR)
            require(libc.posix_spawn_file_actions_adddup2(ctypes.byref(actions), devnull_fd, 0) == 0, "stdin action failed")
        elif stdin is not None:
            require(libc.posix_spawn_file_actions_adddup2(ctypes.byref(actions), fileno(stdin), 0) == 0, "stdin action failed")
        if stdout == subprocess.PIPE:
            parent_stdout = pipe_for(1, True)
        elif stdout == subprocess.DEVNULL:
            devnull_fd = devnull_fd if devnull_fd is not None else os.open("/dev/null", os.O_RDWR)
            require(libc.posix_spawn_file_actions_adddup2(ctypes.byref(actions), devnull_fd, 1) == 0, "stdout action failed")
        elif stdout is not None:
            require(libc.posix_spawn_file_actions_adddup2(ctypes.byref(actions), fileno(stdout), 1) == 0, "stdout action failed")
        if stderr == subprocess.PIPE:
            parent_stderr = pipe_for(2, True)
        elif stderr == subprocess.STDOUT:
            require(libc.posix_spawn_file_actions_adddup2(ctypes.byref(actions), 1, 2) == 0, "stderr redirect action failed")
        elif stderr == subprocess.DEVNULL:
            devnull_fd = devnull_fd if devnull_fd is not None else os.open("/dev/null", os.O_RDWR)
            require(libc.posix_spawn_file_actions_adddup2(ctypes.byref(actions), devnull_fd, 2) == 0, "stderr action failed")
        elif stderr is not None:
            require(libc.posix_spawn_file_actions_adddup2(ctypes.byref(actions), fileno(stderr), 2) == 0, "stderr action failed")
        empty_mask = ctypes.c_uint32(0)
        require(libc.posix_spawnattr_setsigmask(ctypes.byref(attributes), ctypes.byref(empty_mask)) == 0, "spawn signal mask setup failed")
        flags = 0x0080 | 0x0400 | 0x0008
        require(libc.posix_spawnattr_setflags(ctypes.byref(attributes), ctypes.c_short(flags)) == 0, "suspended spawn flags unavailable")
        encoded_args = [str(invocation.path), *args[1:]]
        argv = (ctypes.c_char_p * (len(encoded_args) + 1))(*[value.encode() for value in encoded_args], None)
        environment = os.environ.copy() if env is None else env
        encoded_environment = [f"{key}={value}".encode() for key, value in environment.items()]
        envp = (ctypes.c_char_p * (len(encoded_environment) + 1))(*encoded_environment, None)
        inherited_states = {fd: os.get_inheritable(fd) for fd in dict.fromkeys(pass_fds)}
        with VERIFIED_SPAWN_LOCK:
            try:
                for inherited_fd in inherited_states: os.set_inheritable(inherited_fd, True)
                pid = ctypes.c_int()
                code = libc.posix_spawn(
                    ctypes.byref(pid),
                    str(invocation.path).encode(),
                    ctypes.byref(actions),
                    ctypes.byref(attributes),
                    argv,
                    envp,
                )
                require(code == 0, f"verified executable spawn failed: errno {code}")
                spawned_pid = pid.value
            finally:
                for inherited_fd, was_inheritable in inherited_states.items():
                    os.set_inheritable(inherited_fd, was_inheritable)
        _verified_text_vnode(spawned_pid, invocation)
        opened_invocation = os.fstat(invocation.fd)
        path_invocation = os.lstat(invocation.path)
        require(
            (opened_invocation.st_dev, opened_invocation.st_ino, opened_invocation.st_size)
            == (invocation.device, invocation.inode, invocation.size)
            and (path_invocation.st_dev, path_invocation.st_ino, path_invocation.st_size)
            == (invocation.device, invocation.inode, invocation.size)
            and opened_invocation.st_flags & stat.UF_IMMUTABLE
            and bytes_digest(os.pread(invocation.fd, invocation.size + 1, 0)) == invocation.sha256,
            "spawned executable binding changed before resume",
        )
        _verified_text_vnode(spawned_pid, invocation)
        _verified_code_signature(spawned_pid)
        for child_fd in child_fds: os.close(child_fd)
        child_fds.clear()
        os.kill(spawned_pid, signal.SIGCONT)
        process = VerifiedProcess(
            spawned_pid,
            encoded_args,
            parent_stdin,
            parent_stdout,
            parent_stderr,
            text=text,
            cleanup_binding=invocation,
        )
        invocation = None
        return process
    except BaseException:
        if spawned_pid is not None:
            try: os.kill(spawned_pid, signal.SIGKILL)
            except ProcessLookupError: pass
            try: os.waitpid(spawned_pid, 0)
            except ChildProcessError: pass
        for stream in (parent_stdin, parent_stdout, parent_stderr):
            if stream is not None:
                try: stream.close()
                except OSError: pass
        raise
    finally:
        for child_fd in child_fds:
            try: os.close(child_fd)
            except OSError: pass
        if devnull_fd is not None:
            try: os.close(devnull_fd)
            except OSError: pass
        if actions_ready: libc.posix_spawn_file_actions_destroy(ctypes.byref(actions))
        if attributes_ready: libc.posix_spawnattr_destroy(ctypes.byref(attributes))
        if invocation is not None:
            try: _set_descriptor_flags(invocation.fd, 0)
            except BaseException: pass
            try: invocation.path.unlink()
            except FileNotFoundError: pass
            invocation.close()

def kubectl_binding_v4() -> ExecutableBinding:
    return executable_binding_from_environment("ROEBEL_PINNED_KUBECTL")
def kubernetes_subprocess_environment_v4() -> dict[str, str]:
    """Keep caller state except ambient proxy routing for Kubernetes clients.

    The only permitted Kubernetes proxy is the validated ``proxy-url`` inside
    the snapshotted kubeconfig.  Inherited proxy variables would otherwise add
    a second, unreviewed transport path.
    """
    proxy_names = {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}
    return {key: value for key, value in os.environ.items() if key.lower() not in proxy_names}
class Runner:
    def run(self, args: list[str], *, input_text: str | None = None, timeout: int | float = 10) -> Result:
        if args and args[0] == "kubectl":
            read_attempts = 3 if input_text is None and "get" in args[1:] else 1
            for attempt in range(read_attempts):
                binding = kubectl_binding_v4()
                process = verified_popen(
                    binding,
                    [str(binding.path), *args[1:]],
                    stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=kubernetes_subprocess_environment_v4(),
                )
                try:
                    stdout, stderr = process.communicate(input_text, timeout=timeout)
                except subprocess.TimeoutExpired as exc:
                    if attempt + 1 < read_attempts:
                        continue
                    return Result(124, "", f"timeout after {timeout}s: {exc}")
                return Result(int(process.returncode), stdout, stderr)
            raise AssertionError("unreachable Kubernetes read retry")
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

def load_owned_receipt_v4(path: Path, label: str) -> dict[str, Any]:
    """Read one bounded owned receipt without following or racing links."""
    selected = Path(os.path.abspath(path))
    info = os.lstat(selected)
    require(
        stat.S_ISREG(info.st_mode)
        and not selected.is_symlink()
        and info.st_uid == os.geteuid()
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o600
        and 0 < info.st_size <= 8 * 1024 * 1024,
        f"{label} must be an owned 0600 regular non-symlink nlink-one file under 8 MiB",
    )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(selected, flags)
    try:
        opened = os.fstat(fd)
        require(
            opened.st_dev == info.st_dev
            and opened.st_ino == info.st_ino
            and opened.st_size == info.st_size,
            f"{label} identity changed while opening",
        )
        raw = os.read(fd, 8 * 1024 * 1024 + 1)
    finally:
        os.close(fd)
    require(len(raw) <= 8 * 1024 * 1024, f"{label} exceeds 8 MiB")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ActivationError(f"{label} must be UTF-8 JSON") from exc
    return obj(text, label)

def load_owned_receipt_fd_raw_v4(fd: int, label: str) -> bytes:
    """Read one inherited immutable regular-file receipt descriptor."""
    require(isinstance(fd, int) and fd >= 3, f"{label} descriptor invalid")
    info = os.fstat(fd)
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.geteuid()
        and info.st_nlink in {0, 1}
        and stat.S_IMODE(info.st_mode) == 0o600
        and 0 < info.st_size <= 8 * 1024 * 1024,
        f"{label} descriptor must reference a bounded owned 0600 regular file",
    )
    raw = os.pread(fd, info.st_size + 1, 0)
    require(len(raw) == info.st_size, f"{label} descriptor read was incomplete")
    return raw

def load_owned_receipt_fd_v4(fd: int, label: str) -> dict[str, Any]:
    raw = load_owned_receipt_fd_raw_v4(fd, label)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ActivationError(f"{label} must be UTF-8 JSON") from exc
    return obj(text, label)

def required_handover_prebound_keys_v4(current_revision: str) -> set[tuple[str, str]]:
    current_paths = tuple(dict.fromkeys((
        *BOOTSTRAP_PROTECTED_PATHS,
        SECRET_MATERIALIZER_PATH,
        *TRACER_RECEIPT_PROTECTED_PATHS,
        *HANDOVER_COMPATIBILITY_PATHS,
        *HANDOVER_CURRENT_PRESERVATION_PATHS,
    )))
    archived_paths = tuple(dict.fromkeys((*HANDOVER_ARCHIVED_PROTECTED_PATHS, *HANDOVER_COMPATIBILITY_PATHS)))
    return {
        *((current_revision, path) for path in current_paths),
        *((HANDOVER_ARCHIVE_REVISION, path) for path in archived_paths),
        (SECRET_RECEIPT_ORIGIN_REVISION, SECRET_MATERIALIZER_PATH),
    }

def required_nested_handover_prebound_keys_v4(current_revision: str) -> set[tuple[str, str]]:
    """Return only the two-revision closure understood by the handover runner."""
    current_paths = tuple(dict.fromkeys((
        *BOOTSTRAP_PROTECTED_PATHS,
        *HANDOVER_COMPATIBILITY_PATHS,
        *HANDOVER_CURRENT_PRESERVATION_PATHS,
    )))
    archived_paths = tuple(dict.fromkeys((*HANDOVER_ARCHIVED_PROTECTED_PATHS, *HANDOVER_COMPATIBILITY_PATHS)))
    return {
        *((current_revision, path) for path in current_paths),
        *((HANDOVER_ARCHIVE_REVISION, path) for path in archived_paths),
    }

def parse_prebound_git_blob_descriptors_v4(values: list[str] | None, current_revision: str) -> dict[tuple[str, str], bytes]:
    """Read the wrapper's exact fd-bound handover closure without Git access."""
    require(values is not None and values, "complete prebound protected Git closure required")
    result: dict[tuple[str, str], bytes] = {}
    for encoded in values:
        value = obj(encoded, "prebound Git blob descriptor")
        require(
            set(value) == {"revision", "path", "fd", "size", "sha256"}
            and isinstance(value.get("revision"), str)
            and re.fullmatch(r"[0-9a-f]{40}", value["revision"]) is not None
            and isinstance(value.get("path"), str)
            and isinstance(value.get("fd"), int)
            and value["fd"] >= 3
            and isinstance(value.get("size"), int)
            and 0 < value["size"] <= 8 * 1024 * 1024
            and isinstance(value.get("sha256"), str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", value["sha256"]) is not None,
            "prebound Git blob descriptor invalid",
        )
        key = (value["revision"], value["path"])
        require(key not in result, "prebound Git blob descriptor duplicated")
        info = os.fstat(value["fd"])
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.geteuid()
            and info.st_nlink in {0, 1}
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_size == value["size"],
            "prebound Git blob descriptor metadata invalid",
        )
        raw = os.pread(value["fd"], value["size"] + 1, 0)
        require(len(raw) == value["size"] and bytes_digest(raw) == value["sha256"], "prebound Git blob bytes/checksum drift")
        result[key] = raw
    require(set(result) == required_handover_prebound_keys_v4(current_revision), "prebound protected Git closure is incomplete or widened")
    return result

def kb(kubeconfig: str) -> list[str]: return ["kubectl", "--kubeconfig", kubeconfig]
def get(r: Runner, args: list[str], label: str) -> dict[str, Any]: return obj(checked(r, args + ["-o", "json"], label), label)
def git_blob(rev: str, path: str) -> bytes:
    # Both revision and path originate in fixed code/policy, never CLI/evidence.
    if _PREBOUND_GIT_BLOBS is not None:
        key = (rev, path)
        require(key in _PREBOUND_GIT_BLOBS, f"protected Git blob was not prebound: {path}")
        return _PREBOUND_GIT_BLOBS[key]
    try:
        p = trusted_git_v4(
            ["-C", str(ROOT), "show", f"{rev}:{path}"],
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

def bind_flux_bootstrap_receipt_v4(
    p: dict[str, Any],
    rev: str,
    runner_hashes: dict[str, str],
    receipt_path: Path,
) -> dict[str, Any]:
    """Bind exact dormant UIDs before constructing a Kubernetes runner."""
    require(BOOTSTRAP is not None, "protected dormant Flux bootstrap binder unavailable")
    bootstrap_hashes = {path: runner_hashes[path] for path in BOOTSTRAP_PROTECTED_PATHS}
    try:
        plan = BOOTSTRAP.build_plan(POLICY, p, rev, bootstrap_hashes)
        receipt = BOOTSTRAP.load_receipt(receipt_path)
        return BOOTSTRAP.bind_success_receipt(plan, receipt)
    except (BOOTSTRAP.BootstrapError, OSError) as exc:
        raise ActivationError(f"dormant Flux bootstrap receipt rejected: {exc}") from exc

def bind_flux_bootstrap_receipt_value_v4(
    p: dict[str, Any],
    rev: str,
    runner_hashes: dict[str, str],
    receipt: dict[str, Any],
) -> dict[str, Any]:
    """Bind an already snapshotted dormant receipt before Kubernetes access."""
    require(BOOTSTRAP is not None, "protected dormant Flux bootstrap binder unavailable")
    bootstrap_hashes = {path: runner_hashes[path] for path in BOOTSTRAP_PROTECTED_PATHS}
    try:
        plan = BOOTSTRAP.build_plan(POLICY, p, rev, bootstrap_hashes)
        return BOOTSTRAP.bind_success_receipt(plan, receipt)
    except BOOTSTRAP.BootstrapError as exc:
        raise ActivationError(f"dormant Flux bootstrap receipt rejected: {exc}") from exc

def bind_handover_receipt_pair_v4(
    p: dict[str, Any],
    rev: str,
    archived_receipt_fd: int,
    handover_receipt_fd: int,
    prebound_blobs: dict[tuple[str, str], bytes],
) -> dict[str, Any]:
    """Bind the archived receipt and its GET-only current-revision bridge."""
    try:
        runner = compile_verified_handover_runner_v4(git_blob(rev, HANDOVER_RUNNER_PATH), rev)
        archived_raw = runner.owned_receipt_raw(archived_receipt_fd, "archived dormant bootstrap receipt")
        require(set(prebound_blobs) == required_handover_prebound_keys_v4(rev), "handover prebound Git closure drift")
        handover_blobs = {key: value for key, value in prebound_blobs.items() if key in required_nested_handover_prebound_keys_v4(rev)}
        context = runner.build_context(rev, archived_raw, handover_blobs)
        require(context["policy"] == p, "handover/current activation policy drift")
        handover_raw = runner.owned_receipt_raw(handover_receipt_fd, "dormant bootstrap handover receipt")
        handover_receipt = runner.json_object(handover_raw, "dormant bootstrap handover receipt")
        ownership = context["handoverModule"].bind_handover_receipt(context["binding"], handover_receipt)
        require(
            ownership.get("protectedRevision") == rev
            and ownership.get("activationPolicySha256") == POLICY.activation_policy_sha256(p)
            and ownership.get("civicAuthorityEffects") is False,
            "dormant bootstrap handover ownership drift",
        )
        return ownership
    except ActivationError:
        raise
    except Exception as exc:
        raise ActivationError(f"dormant Flux handover receipt pair rejected: {exc}") from exc

def bind_failed_activation_recovery_source_v4(receipt_fd: int) -> dict[str, Any]:
    """Bind deletion authority to the one durable failed aaca3166 receipt."""
    raw = load_owned_receipt_fd_raw_v4(receipt_fd, "failed participant activation receipt")
    require(bytes_digest(raw) == FAILED_ACTIVATION_RAW_SHA256, "failed activation receipt raw checksum drift")
    try:
        receipt = obj(raw.decode("utf-8"), "failed participant activation receipt")
    except UnicodeDecodeError as exc:
        raise ActivationError("failed participant activation receipt must be UTF-8 JSON") from exc
    public_projection(receipt)
    require(
        set(receipt) == {
            "schemaVersion", "status", "protectedRevision", "failure",
            "protectedRunnerFileSha256", "objectCreateResults", "rollback",
            "termination", "civicAuthorityEffects", "canonicalSha256",
        },
        "failed activation receipt field set drift",
    )
    unsigned = {key: copy.deepcopy(value) for key, value in receipt.items() if key != "canonicalSha256"}
    require(
        receipt.get("canonicalSha256") == FAILED_ACTIVATION_CANONICAL_SHA256
        and digest(unsigned) == FAILED_ACTIVATION_CANONICAL_SHA256,
        "failed activation receipt canonical checksum drift",
    )
    require(receipt.get("schemaVersion") == RECEIPT_SCHEMA, "failed activation receipt schema drift")
    require(receipt.get("status") == "rollback-incomplete", "failed activation receipt status drift")
    require(receipt.get("protectedRevision") == FAILED_ACTIVATION_ORIGIN_REVISION, "failed activation receipt revision drift")
    require(receipt.get("failure") == FAILED_ACTIVATION_FAILURE, "failed activation receipt failure drift")
    require(receipt.get("protectedRunnerFileSha256") == FAILED_ACTIVATION_RUNNER_FILE_SHA256, "failed activation receipt protected runner drift")
    require(receipt.get("objectCreateResults") == list(FAILED_ACTIVATION_OBJECT_CREATE_RESULTS), "failed activation receipt object ownership drift")
    require(
        receipt.get("termination") == {
            "interrupted": False,
            "signal": None,
            "signalsDeferredDuringRollback": True,
        }
        and receipt.get("civicAuthorityEffects") is False,
        "failed activation receipt termination or authority drift",
    )
    rollback = receipt.get("rollback")
    require(
        isinstance(rollback, dict)
        and rollback.get("status") == "incomplete"
        and rollback.get("bothKustomizationsSuspended") is False
        and rollback.get("uncertainTarget") == "gateway.deployment"
        and rollback.get("errors") == [
            "gateway rollback suspension timeout",
            "post-send create outcome unresolved: gateway.deployment",
        ]
        and rollback.get("finalizersRemovedByRunner") is False,
        "failed activation receipt rollback state drift",
    )
    deleted = rollback.get("deleted")
    require(
        isinstance(deleted, list)
        and bool(deleted)
        and all(item.get("logicalName") == "gateway.service" and item.get("absent") is True for item in deleted if isinstance(item, dict))
        and any(item.get("uid") == FAILED_ACTIVATION_OBJECT_UIDS["gateway.service"] for item in deleted if isinstance(item, dict)),
        "failed activation receipt Service absence proof drift",
    )
    checks = rollback.get("finalChecks", {})
    exposure = checks.get("exposureBreak", {})
    exposure_after = checks.get("exposureBreakAfterFlux", {})
    require(
        exposure.get("serviceUid") == FAILED_ACTIVATION_OBJECT_UIDS["gateway.service"]
        and exposure.get("serviceAbsent") is True
        and exposure.get("unknownIngressUntouched") is True
        and exposure_after.get("serviceUid") == FAILED_ACTIVATION_OBJECT_UIDS["gateway.service"]
        and exposure_after.get("serviceAbsent") is True
        and exposure_after.get("sameOwnedUidOnly") is True,
        "failed activation receipt exposure-break proof drift",
    )
    preservation = rollback.get("preservation", {})
    require(
        set(preservation) == {"webIngress", "existingWorkbenchNetworkPolicy"}
        and all(value.get("byteIdenticalCanonicalJson") is True for value in preservation.values()),
        "failed activation receipt preservation proof drift",
    )
    return {
        "originProtectedRevision": FAILED_ACTIVATION_ORIGIN_REVISION,
        "originRawSha256": FAILED_ACTIVATION_RAW_SHA256,
        "originReceiptSha256": FAILED_ACTIVATION_CANONICAL_SHA256,
        "operationNonce": FAILED_ACTIVATION_OPERATION_NONCE,
        "objects": {
            logical: copy.deepcopy(record)
            for logical, record in zip(FAILED_ACTIVATION_CREATED_ORDER, FAILED_ACTIVATION_OBJECT_CREATE_RESULTS)
        },
        "serviceExposureBreakProved": True,
        "ingressNeverCreated": True,
        "civicAuthorityEffects": False,
    }

def bind_historical_secret_materialization_fields_v4(
    p: dict[str, Any],
    receipt: dict[str, Any],
) -> dict[str, Any]:
    """Close b790 fields and prove current target/keyset compatibility."""
    require(
        isinstance(receipt, dict)
        and set(receipt) == {
            "schemaVersion", "status", "protectedRevision", "activationPolicySha256",
            "protectedRunnerFileSha256", "createOrder", "secrets", "inputTransport",
            "valuesInReceipt", "civicAuthorityEffects", "canonicalSha256",
        },
        "historical Secret receipt field closure drift",
    )
    require(
        receipt.get("canonicalSha256") == SECRET_RECEIPT_ORIGIN_CANONICAL_SHA256,
        "historical Secret receipt canonical checksum drift",
    )
    require(
        receipt.get("schemaVersion") == "roebel_staging_participant_secret_materialization_receipt_v1"
        and receipt.get("status") == "materialized"
        and receipt.get("protectedRevision") == SECRET_RECEIPT_ORIGIN_REVISION
        and receipt.get("activationPolicySha256") == SECRET_RECEIPT_ORIGIN_ACTIVATION_POLICY_SHA256
        and receipt.get("protectedRunnerFileSha256") == SECRET_RECEIPT_ORIGIN_RUNNER_FILE_SHA256
        and receipt.get("createOrder") == ["config", "runtime"]
        and receipt.get("inputTransport") == "owned-private-inherited-descriptors-only"
        and receipt.get("valuesInReceipt") is False
        and receipt.get("civicAuthorityEffects") is False,
        "historical Secret receipt origin field drift",
    )
    records = receipt.get("secrets")
    require(records == SECRET_RECEIPT_ORIGIN_SECRET_RECORDS, "historical Secret receipt origin record drift")
    references = p.get("runtime", {}).get("secretReferences")
    require(
        isinstance(references, dict)
        and {"config", "runtime"} < set(references),
        "current participant Secret reference inventory drift",
    )
    for label in ("config", "runtime"):
        reference = references[label]
        record = records[label]
        require(
            isinstance(reference, dict)
            and set(reference) == {"name", "namespace", "keys"}
            and record["target"] == {
                "apiVersion": "v1",
                "kind": "Secret",
                "namespace": reference["namespace"],
                "name": reference["name"],
            }
            and record["keySet"] == sorted(reference["keys"])
            and record["resourceVersion"] == SECRET_RECEIPT_ORIGIN_RESOURCE_VERSIONS[label],
            f"historical Secret receipt current target/keyset compatibility drift: {label}",
        )
    return {
        "status": "materialized",
        "protectedRevision": SECRET_RECEIPT_ORIGIN_REVISION,
        "receiptSha256": SECRET_RECEIPT_ORIGIN_CANONICAL_SHA256,
        "secretUids": {label: records[label]["uid"] for label in ("config", "runtime")},
        "secretRecords": {
            label: {
                "target": copy.deepcopy(records[label]["target"]),
                "uid": records[label]["uid"],
                "resourceVersion": records[label]["resourceVersion"],
                "keySet": copy.deepcopy(records[label]["keySet"]),
                "valuesRead": False,
            }
            for label in ("config", "runtime")
        },
        "civicAuthorityEffects": False,
        "receiptProvenance": {
            "mode": "historical-b790-value-free-secret-materialization",
            "protectedRevision": SECRET_RECEIPT_ORIGIN_REVISION,
            "rawSha256": SECRET_RECEIPT_ORIGIN_RAW_SHA256,
            "canonicalSha256": SECRET_RECEIPT_ORIGIN_CANONICAL_SHA256,
        },
    }


def bind_historical_secret_materialization_receipt_v4(
    p: dict[str, Any],
    receipt: dict[str, Any],
    raw: bytes,
) -> dict[str, Any]:
    """Bind only the exact audited b790 value-free Secret receipt.

    The b790 materializer cannot validate a later activation policy digest.
    Instead, close every historical field over pinned origin constants and
    separately prove that its two participant Secret targets/keysets remain
    compatible with the current policy.  No historical executable is asked
    to reinterpret the current policy.
    """
    require(bytes_digest(raw) == SECRET_RECEIPT_ORIGIN_RAW_SHA256, "historical Secret receipt raw checksum drift")
    unsigned = {key: copy.deepcopy(value) for key, value in receipt.items() if key != "canonicalSha256"}
    require(
        digest(unsigned) == SECRET_RECEIPT_ORIGIN_CANONICAL_SHA256,
        "historical Secret receipt canonical checksum drift",
    )
    return bind_historical_secret_materialization_fields_v4(p, receipt)


def bind_secret_materialization_receipt_v4(
    p: dict[str, Any],
    rev: str,
    receipt_fd: int,
) -> dict[str, Any]:
    """Bind an existing value-free Secret receipt to the current policy.

    This is deliberately a receipt-only operation.  The binder never receives
    or reads Secret values; activation later performs a metadata/keyset-only
    GET and compares it to the returned ownership projection.
    """
    global SECRET_MATERIALIZER
    try:
        raw = load_owned_receipt_fd_raw_v4(receipt_fd, "Secret materialization receipt")
        try:
            receipt = obj(raw.decode("utf-8"), "Secret materialization receipt")
        except UnicodeDecodeError as exc:
            raise ActivationError("Secret materialization receipt must be UTF-8 JSON") from exc
        receipt_revision = receipt.get("protectedRevision")
        if receipt_revision == SECRET_RECEIPT_ORIGIN_REVISION:
            return bind_historical_secret_materialization_receipt_v4(p, receipt, raw)
        require(receipt_revision == rev, "Secret materialization receipt protected revision drift")
        if SECRET_MATERIALIZER is None:
            SECRET_MATERIALIZER = compile_verified_secret_materializer_v4(git_blob(rev, SECRET_MATERIALIZER_PATH), rev)
        protected_paths = tuple(getattr(SECRET_MATERIALIZER, "PROTECTED_PATHS", ()))
        require(protected_paths and len(protected_paths) == len(set(protected_paths)), "Secret materializer protected path closure invalid")
        hashes = {path: bytes_digest(git_blob(rev, path)) for path in protected_paths}
        return SECRET_MATERIALIZER.bind_materialization_receipt(receipt, p, rev, hashes)
    except ActivationError:
        raise
    except Exception as exc:
        raise ActivationError(f"Secret materialization receipt rejected: {exc}") from exc


def bind_tracer_receipt_revision_v4(
    receipt: dict[str, Any],
    raw: bytes,
    rev: str,
) -> dict[str, Any]:
    """Admit current receipts or the exact successful run19 seven-hop lineage."""
    receipt_revision = receipt.get("protectedRevision")
    hashes = receipt.get("protectedFileSha256")
    require(
        isinstance(hashes, dict)
        and set(hashes) == set(TRACER_RECEIPT_PROTECTED_PATHS)
        and all(
            isinstance(hashes[path], str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", hashes[path]) is not None
            for path in TRACER_RECEIPT_PROTECTED_PATHS
        ),
        "tracer data-plane protected file closure drift",
    )
    current_hashes = {
        path: bytes_digest(git_blob(rev, path))
        for path in TRACER_RECEIPT_PROTECTED_PATHS
    }
    if receipt_revision == rev:
        require(hashes == current_hashes, "tracer data-plane protected file closure drift")
        return {
            "mode": "current-protected-revision",
            "originProtectedRevision": rev,
            "acceptedByProtectedRevision": rev,
            "allowedAppliedRevisions": [rev],
        }

    require(
        receipt_revision == TRACER_RECEIPT_ORIGIN_REVISION
        and bytes_digest(raw) == TRACER_RECEIPT_ORIGIN_RAW_SHA256,
        "tracer data-plane receipt is not the exact approved run19 predecessor",
    )
    require(
        exact_revision_transition_files_v4(
            TRACER_RECEIPT_ORIGIN_REVISION,
            TRACER_RECEIPT_INTERMEDIATE_REVISION,
            "tracer receipt origin-to-intermediate",
        ) == set(TRACER_RECEIPT_ORIGIN_TO_INTERMEDIATE_FILES),
        "tracer receipt origin-to-intermediate file set drift",
    )
    require(
        exact_revision_transition_files_v4(
            TRACER_RECEIPT_INTERMEDIATE_REVISION,
            TRACER_RECEIPT_SECOND_SUCCESSOR_REVISION,
            "tracer receipt intermediate-to-second-successor",
        ) == set(TRACER_RECEIPT_INTERMEDIATE_TO_SECOND_SUCCESSOR_FILES),
        "tracer receipt intermediate-to-second-successor file set drift",
    )
    require(
        exact_revision_transition_files_v4(
            TRACER_RECEIPT_SECOND_SUCCESSOR_REVISION,
            TRACER_RECEIPT_THIRD_SUCCESSOR_REVISION,
            "tracer receipt second-to-third-successor",
        ) == set(TRACER_RECEIPT_SECOND_TO_THIRD_SUCCESSOR_FILES),
        "tracer receipt second-to-third-successor file set drift",
    )
    require(
        exact_revision_transition_files_v4(
            TRACER_RECEIPT_THIRD_SUCCESSOR_REVISION,
            TRACER_RECEIPT_FOURTH_SUCCESSOR_REVISION,
            "tracer receipt third-to-fourth-successor",
        ) == set(TRACER_RECEIPT_THIRD_TO_FOURTH_SUCCESSOR_FILES),
        "tracer receipt third-to-fourth-successor file set drift",
    )
    require(
        exact_revision_transition_files_v4(
            TRACER_RECEIPT_FOURTH_SUCCESSOR_REVISION,
            TRACER_RECEIPT_FIFTH_SUCCESSOR_REVISION,
            "tracer receipt fourth-to-fifth-successor",
        ) == set(TRACER_RECEIPT_FOURTH_TO_FIFTH_SUCCESSOR_FILES),
        "tracer receipt fourth-to-fifth-successor file set drift",
    )
    require(
        exact_revision_transition_files_v4(
            TRACER_RECEIPT_FIFTH_SUCCESSOR_REVISION,
            TRACER_RECEIPT_SIXTH_SUCCESSOR_REVISION,
            "tracer receipt fifth-to-sixth-successor",
        ) == set(TRACER_RECEIPT_FIFTH_TO_SIXTH_SUCCESSOR_FILES),
        "tracer receipt fifth-to-sixth-successor file set drift",
    )
    require(
        exact_revision_transition_files_v4(
            TRACER_RECEIPT_SIXTH_SUCCESSOR_REVISION,
            rev,
            "tracer receipt sixth-successor-to-acceptor",
        ) == set(TRACER_RECEIPT_SIXTH_SUCCESSOR_TO_ACCEPTOR_FILES),
        "tracer receipt sixth-successor-to-acceptor file set drift",
    )
    require(
        hashes.get("scripts/activate-staging-participant-gateway.py")
        == TRACER_RECEIPT_ORIGIN_ACTIVATION_RUNNER_SHA256,
        "tracer origin activation-runner hash drift",
    )
    changed_protected_paths = {
        path
        for path in TRACER_RECEIPT_PROTECTED_PATHS
        if hashes[path] != current_hashes[path]
    }
    require(
        changed_protected_paths == {"scripts/activate-staging-participant-gateway.py"},
        "tracer compatible protected path change drift",
    )
    return {
        "mode": "exact-run19-seven-hop-unchanged-tracer-plane",
        "originProtectedRevision": TRACER_RECEIPT_ORIGIN_REVISION,
        "acceptedByProtectedRevision": rev,
        "allowedAppliedRevisions": [
            TRACER_RECEIPT_ORIGIN_REVISION,
            TRACER_RECEIPT_INTERMEDIATE_REVISION,
            TRACER_RECEIPT_SECOND_SUCCESSOR_REVISION,
            TRACER_RECEIPT_THIRD_SUCCESSOR_REVISION,
            TRACER_RECEIPT_FOURTH_SUCCESSOR_REVISION,
            TRACER_RECEIPT_FIFTH_SUCCESSOR_REVISION,
            TRACER_RECEIPT_SIXTH_SUCCESSOR_REVISION,
            rev,
        ],
    }


def bind_tracer_activation_receipt_v4(
    p: dict[str, Any],
    rev: str,
    receipt_fd: int,
) -> dict[str, Any]:
    """Bind the completed data plane without reading any Secret value."""
    raw = load_owned_receipt_fd_raw_v4(receipt_fd, "tracer data-plane activation receipt")
    try:
        receipt = obj(raw.decode("utf-8"), "tracer data-plane activation receipt")
    except UnicodeDecodeError as exc:
        raise ActivationError("tracer data-plane activation receipt must be UTF-8 JSON") from exc
    expected_fields = {
        "schemaVersion", "status", "protectedRevision", "operationNonce", "productSourceRevision",
        "protectedFileSha256", "clusterBinding", "sharedFluxSource",
        "secretMaterializationReceiptSha256", "secretRecords", "createOrder",
        "objectRecords", "flux", "serviceBindings", "failureRollback",
        "secretValuesRead", "civicAuthorityEffects",
        "signalsDeferredDuringFinalization", "functionalHttpRpcProof",
    }
    require(set(receipt) == expected_fields, "tracer data-plane activation receipt field set drift")
    require(
        receipt.get("schemaVersion") == TRACER_ACTIVATION_RECEIPT_SCHEMA
        and receipt.get("status") == "activated"
        and isinstance(receipt.get("protectedRevision"), str)
        and re.fullmatch(r"[0-9a-f]{40}", receipt["protectedRevision"]) is not None
        and receipt.get("productSourceRevision") == p["productPins"]["sourceRevision"]
        and isinstance(receipt.get("operationNonce"), str)
        and re.fullmatch(r"[0-9a-f]{64}", receipt["operationNonce"]) is not None
        and isinstance(receipt.get("secretMaterializationReceiptSha256"), str)
        and POLICY.SHA256.fullmatch(receipt["secretMaterializationReceiptSha256"]) is not None
        and receipt.get("secretValuesRead") is False
        and receipt.get("civicAuthorityEffects") is False
        and receipt.get("failureRollback") == "exact-operation-owned-uids-only",
        "tracer data-plane activation receipt status/source boundary drift",
    )
    revision_binding = bind_tracer_receipt_revision_v4(receipt, raw, rev)
    receipt_revision = receipt["protectedRevision"]
    validate_bound_cluster_identity_v4(receipt.get("clusterBinding"), p, "tracer data-plane")
    require(
        receipt.get("sharedFluxSource")
        == {"revision": f"main@sha1:{receipt_revision}", "ready": True, "mutation": False},
        "tracer shared Flux source receipt drift",
    )
    records = receipt.get("secretRecords")
    secret_contract = {
        "dataPlane": {
            "target": {"apiVersion": "v1", "kind": "Secret", "name": "roebel-tracer-data-plane-runtime", "namespace": "stadtstack-roebel-staging-lab"},
            "keySet": ["anon-jwt", "authenticator-password", "environment-arm", "jwt-secret", "pgsodium-root-key", "postgres-password", "postgrest-db-uri", "rpc-secret"],
        },
        "webFeed": {
            "target": {"apiVersion": "v1", "kind": "Secret", "name": "roebel-tracer-feed-runtime", "namespace": "stadtstack-roebel-web-preview"},
            "keySet": ["supabase-anon-key"],
        },
        "participantPostgrest": {
            "target": {"apiVersion": "v1", "kind": "Secret", "name": p["runtime"]["secretReferences"]["postgrest"]["name"], "namespace": p["runtime"]["secretReferences"]["postgrest"]["namespace"]},
            "keySet": sorted(p["runtime"]["secretReferences"]["postgrest"]["keys"]),
        },
    }
    require(isinstance(records, dict) and set(records) == set(secret_contract), "tracer Secret receipt set drift")
    secret_nonces: set[str] = set()
    for label, expected in secret_contract.items():
        record = records[label]
        require(
            isinstance(record, dict)
            and set(record) == {"target", "uid", "resourceVersion", "keySet", "ownershipNonce", "valuesRead"}
            and record.get("target") == expected["target"]
            and record.get("keySet") == expected["keySet"]
            and isinstance(record.get("uid"), str) and bool(record["uid"])
            and isinstance(record.get("resourceVersion"), str) and record["resourceVersion"].isdigit()
            and isinstance(record.get("ownershipNonce"), str)
            and re.fullmatch(r"[0-9a-f]{64}", record["ownershipNonce"]) is not None
            and record.get("valuesRead") is False,
            f"tracer Secret projection drift: {label}",
        )
        secret_nonces.add(record["ownershipNonce"])
    require(len(secret_nonces) == 1, "tracer Secret bundle nonce drift")
    postgrest = records.get("participantPostgrest") if isinstance(records, dict) else None
    reference = p["runtime"]["secretReferences"]["postgrest"]
    require(
        isinstance(postgrest, dict)
        and postgrest.get("target")
        == {
            "apiVersion": "v1", "kind": "Secret",
            "name": reference["name"], "namespace": reference["namespace"],
        }
        and postgrest.get("keySet") == sorted(reference["keys"])
        and isinstance(postgrest.get("uid"), str)
        and isinstance(postgrest.get("resourceVersion"), str)
        and postgrest["resourceVersion"].isdigit()
        and postgrest.get("valuesRead") is False,
        "tracer participant PostgREST Secret projection drift",
    )
    object_targets = {
        "application.postgresNetworkPolicy": ("networking.k8s.io/v1", "NetworkPolicy", "stadtstack-roebel-staging-lab", "roebel-tracer-postgres"),
        "application.postgrestNetworkPolicy": ("networking.k8s.io/v1", "NetworkPolicy", "stadtstack-roebel-staging-lab", "roebel-tracer-postgrest"),
        "application.serviceAccount": ("v1", "ServiceAccount", "stadtstack-roebel-staging-lab", "roebel-tracer-data-plane"),
        "application.bootstrapConfigMap": ("v1", "ConfigMap", "stadtstack-roebel-staging-lab", "roebel-tracer-data-plane-bootstrap-v1"),
        "application.postgresService": ("v1", "Service", "stadtstack-roebel-staging-lab", "roebel-tracer-postgres"),
        "application.postgrestService": ("v1", "Service", "stadtstack-roebel-staging-lab", "roebel-tracer-postgrest"),
        "application.postgresDeployment": ("apps/v1", "Deployment", "stadtstack-roebel-staging-lab", "roebel-tracer-postgres"),
        "application.postgrestDeployment": ("apps/v1", "Deployment", "stadtstack-roebel-staging-lab", "roebel-tracer-postgrest"),
        "flux.serviceAccount": ("v1", "ServiceAccount", "flux-roebel-staging", "roebel-tracer-data-plane-reconciler"),
        "flux.role": ("rbac.authorization.k8s.io/v1", "Role", "stadtstack-roebel-staging-lab", "roebel-tracer-data-plane-reconciler"),
        "flux.roleBinding": ("rbac.authorization.k8s.io/v1", "RoleBinding", "stadtstack-roebel-staging-lab", "roebel-tracer-data-plane-reconciler"),
        "flux.kustomization": ("kustomize.toolkit.fluxcd.io/v1", "Kustomization", "flux-roebel-staging", "roebel-tracer-data-plane"),
    }
    create_order = list(object_targets)
    object_records = receipt.get("objectRecords")
    require(receipt.get("createOrder") == create_order and isinstance(object_records, dict) and set(object_records) == set(create_order), "tracer object receipt closure drift")
    operation_nonce = receipt["operationNonce"]
    for label, identity in object_targets.items():
        record = object_records[label]
        api_version, kind, namespace, name = identity
        require(
            isinstance(record, dict)
            and set(record) == {"target", "uid", "resourceVersion", "ownershipNonce", "temporaryNonceRemoved"}
            and record.get("target") == {"apiVersion": api_version, "kind": kind, "namespace": namespace, "name": name}
            and isinstance(record.get("uid"), str) and bool(record["uid"])
            and isinstance(record.get("resourceVersion"), str) and record["resourceVersion"].isdigit()
            and record.get("ownershipNonce") == operation_nonce
            and record.get("temporaryNonceRemoved") is True,
            f"tracer object ownership receipt drift: {label}",
        )
    require(
        receipt.get("flux") == {
            "uid": object_records["flux.kustomization"]["uid"],
            "lastAppliedRevision": f"main@sha1:{receipt_revision}",
            "ready": True,
        },
        "tracer Flux readiness receipt drift",
    )
    services = receipt.get("serviceBindings")
    require(isinstance(services, dict) and set(services) == {"postgres", "postgrest"}, "tracer Service receipt set drift")
    for label, port in (("postgres", 5432), ("postgrest", p["endpoints"]["supabase"]["port"])):
        binding = services[label]
        require(
            isinstance(binding, dict)
            and set(binding) == {"serviceUid", "port", "readyEndpointAddresses"}
            and isinstance(binding.get("serviceUid"), str) and bool(binding["serviceUid"])
            and binding.get("port") == port
            and isinstance(binding.get("readyEndpointAddresses"), list)
            and bool(binding["readyEndpointAddresses"])
            and binding["readyEndpointAddresses"] == sorted(set(binding["readyEndpointAddresses"]))
            and all(isinstance(address, str) and address for address in binding["readyEndpointAddresses"]),
            f"tracer Service readiness receipt drift: {label}",
        )
    service = services.get("postgrest") if isinstance(services, dict) else None
    require(
        isinstance(service, dict)
        and isinstance(service.get("serviceUid"), str)
        and service.get("port") == p["endpoints"]["supabase"]["port"]
        and isinstance(service.get("readyEndpointAddresses"), list)
        and bool(service["readyEndpointAddresses"])
        and all(isinstance(address, str) and address for address in service["readyEndpointAddresses"]),
        "tracer PostgREST Service readiness receipt drift",
    )
    require(
        receipt.get("functionalHttpRpcProof")
        == {
            "status": "pending-participant-gateway-protected-preflight",
            "secretValuesRead": False,
        },
        "tracer functional proof handoff drift",
    )
    return {
        "receiptFileSha256": bytes_digest(raw),
        "originProtectedRevision": receipt["protectedRevision"],
        "receiptProvenance": revision_binding,
        "participantPostgrestSecret": copy.deepcopy(postgrest),
        "postgrestService": copy.deepcopy(service),
        "tracerFluxKustomization": copy.deepcopy(object_records["flux.kustomization"]),
        "civicAuthorityEffects": False,
    }


def require_tracer_activation_binding_v4(
    endpoints: dict[str, Any],
    secrets: dict[str, Any],
    ownership: dict[str, Any],
    r: Runner,
    kubeconfig: str,
    current_revision: str,
) -> None:
    live_secret = secrets.get("secrets", {}).get("postgrest")
    owned_secret = ownership["participantPostgrestSecret"]
    require(
        isinstance(live_secret, dict)
        and live_secret.get("name") == owned_secret["target"]["name"]
        and live_secret.get("namespace") == owned_secret["target"]["namespace"]
        and live_secret.get("uid") == owned_secret["uid"]
        and live_secret.get("resourceVersion") == owned_secret["resourceVersion"]
        and live_secret.get("keys") == owned_secret["keySet"]
        and live_secret.get("valuesRead") is False,
        "live participant PostgREST Secret no longer binds tracer receipt",
    )
    live_service = endpoints.get("postgrest")
    owned_service = ownership["postgrestService"]
    require(
        isinstance(live_service, dict)
        and live_service.get("serviceUid") == owned_service["serviceUid"]
        and live_service.get("readyEndpointAddresses") == owned_service["readyEndpointAddresses"]
        and live_service.get("externalIngress") is False,
        "live PostgREST Service no longer binds tracer receipt",
    )
    provenance = ownership.get("receiptProvenance")
    allowed_revisions = provenance.get("allowedAppliedRevisions") if isinstance(provenance, dict) else None
    require(
        isinstance(allowed_revisions, list)
        and allowed_revisions
        and allowed_revisions[-1] == current_revision
        and len(allowed_revisions) == len(set(allowed_revisions))
        and all(isinstance(item, str) and re.fullmatch(r"[0-9a-f]{40}", item) is not None for item in allowed_revisions),
        "tracer receipt revision provenance drift",
    )
    tracer_policy = compile_verified_tracer_policy_module_v4(
        git_blob(current_revision, TRACER_POLICY_PATH), current_revision,
    )
    expected_kustomization = tracer_policy.dormant_flux_objects(suspended=False)["kustomization"]
    owned_kustomization = ownership.get("tracerFluxKustomization")
    require(
        isinstance(owned_kustomization, dict)
        and owned_kustomization.get("target") == {
            "apiVersion": "kustomize.toolkit.fluxcd.io/v1",
            "kind": "Kustomization",
            "namespace": FLUX_NAMESPACE,
            "name": "roebel-tracer-data-plane",
        }
        and isinstance(owned_kustomization.get("uid"), str)
        and bool(owned_kustomization["uid"]),
        "tracer Flux Kustomization receipt projection drift",
    )
    live_kustomization = live_obj(
        r, kubeconfig, "kustomization", "roebel-tracer-data-plane", FLUX_NAMESPACE,
    )
    _policy_call(
        POLICY.require_semantically_equal,
        live_kustomization,
        expected_kustomization,
        "live tracer Flux Kustomization",
    )
    metadata = live_kustomization.get("metadata", {})
    status = live_kustomization.get("status", {})
    require(
        metadata.get("uid") == owned_kustomization["uid"]
        and isinstance(metadata.get("generation"), int)
        and status.get("observedGeneration") == metadata["generation"],
        "live tracer Flux Kustomization identity/generation drift",
    )
    ready = next(
        (condition for condition in status.get("conditions", []) if condition.get("type") == "Ready"),
        None,
    )
    require(
        isinstance(ready, dict)
        and ready.get("status") == "True"
        and ready.get("observedGeneration", metadata["generation"]) == metadata["generation"],
        "live tracer Flux Kustomization not Ready",
    )
    allowed_flux_revisions = {f"main@sha1:{item}" for item in allowed_revisions}
    applied_revision = status.get("lastAppliedRevision")
    attempted_revision = status.get("lastAttemptedRevision")
    require(
        applied_revision in allowed_flux_revisions
        and (attempted_revision is None or attempted_revision == applied_revision),
        "live tracer Flux Kustomization revision drift",
    )

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

@dataclass(frozen=True)
class LoopbackConnectProxy:
    origin: str
    host: str
    port: int
    username: str
    password: str

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
    connect_proxy: LoopbackConnectProxy | None
    client_certificate_path: Path | None
    client_key_path: Path | None
    bearer_token: str | None

    def close(self) -> None:
        for value in (self.client_key_path, self.client_certificate_path, self.path):
            if value is None: continue
            try: value.unlink()
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

def _loopback_connect_proxy_v4(value: Any) -> LoopbackConnectProxy:
    """Validate the sole rootless transport adapter accepted by the runner."""
    require(isinstance(value, str) and value.isascii(), "Kubernetes proxy must be an exact loopback HTTP CONNECT proxy")
    try: parsed = urllib.parse.urlsplit(value)
    except ValueError as exc: raise ActivationError("Kubernetes proxy must be an exact loopback HTTP CONNECT proxy") from exc
    require(
        parsed.scheme == "http" and parsed.hostname == "127.0.0.1"
        and parsed.username == "stadtstack-participant"
        and isinstance(parsed.password, str) and re.fullmatch(r"[0-9a-f]{64}", parsed.password) is not None
        and parsed.path == "" and parsed.query == "" and parsed.fragment == ""
        and parsed.netloc.startswith("stadtstack-participant:"),
        "Kubernetes proxy must be an exact loopback HTTP CONNECT proxy",
    )
    try: port = parsed.port
    except ValueError as exc: raise ActivationError("Kubernetes proxy must be an exact loopback HTTP CONNECT proxy") from exc
    require(isinstance(port, int) and 1024 <= port <= 65535, "Kubernetes proxy must be an exact loopback HTTP CONNECT proxy")
    origin = f"http://stadtstack-participant:{parsed.password}@127.0.0.1:{port}"
    require(value == origin, "Kubernetes proxy must be an exact loopback HTTP CONNECT proxy")
    return LoopbackConnectProxy(origin, "127.0.0.1", port, "stadtstack-participant", parsed.password)

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
    require(not cluster.get("insecure-skip-tls-verify"), "insecure Kubernetes API configuration forbidden")
    connect_proxy = _loopback_connect_proxy_v4(cluster["proxy-url"]) if "proxy-url" in cluster else None
    origin, hostname, port = _api_origin(cluster.get("server", ""))
    encoded_ca = cluster.get("certificate-authority-data")
    require(isinstance(encoded_ca, str) and encoded_ca and "certificate-authority" not in cluster, "flattened kubeconfig must embed its CA")
    try: ca_pem = base64.b64decode(encoded_ca, validate=True)
    except (ValueError, TypeError) as exc: raise ActivationError("flattened kubeconfig CA data invalid") from exc
    require(b"BEGIN CERTIFICATE" in ca_pem and len(ca_pem) <= 1024 * 1024, "flattened kubeconfig CA certificate invalid")
    require("tls-server-name" not in cluster, "Kubernetes TLS server name override forbidden")
    tls_name = hostname
    user = users[0].get("user", {}); require(isinstance(user, dict) and user, "flattened kubeconfig user absent")
    forbidden_user_fields = {"exec", "auth-provider", "client-certificate", "client-key", "tokenFile", "username", "password"}
    require(not (forbidden_user_fields & set(user)), "flattened kubeconfig still depends on external or forbidden credentials")
    bearer_token: str | None = None
    client_certificate_pem: bytes | None = None
    client_key_pem: bytes | None = None
    if set(user) == {"token"}:
        bearer_token = user["token"]
        require(
            isinstance(bearer_token, str)
            and 0 < len(bearer_token) <= 64 * 1024
            and bearer_token.isascii()
            and all(character not in bearer_token for character in "\r\n"),
            "flattened kubeconfig bearer token invalid",
        )
    else:
        require(
            set(user) == {"client-certificate-data", "client-key-data"},
            "flattened kubeconfig must contain exactly one supported credential form",
        )
        try:
            client_certificate_pem = base64.b64decode(user["client-certificate-data"], validate=True)
            client_key_pem = base64.b64decode(user["client-key-data"], validate=True)
        except (ValueError, TypeError) as exc:
            raise ActivationError("flattened kubeconfig client credential data invalid") from exc
        require(
            b"BEGIN CERTIFICATE" in client_certificate_pem
            and b"PRIVATE KEY" in client_key_pem
            and len(client_certificate_pem) <= 1024 * 1024
            and len(client_key_pem) <= 1024 * 1024,
            "flattened kubeconfig client credential PEM invalid",
        )
    directory = Path(tempfile.mkdtemp(prefix="participant-kubeconfig-"))
    path = directory / "config"; certificate_path = directory / "client.crt"; key_path = directory / "client.key"
    created: list[Path] = []; fd = -1
    try:
        os.chmod(directory, 0o700)
        values = [(path, canonical(config).encode() + b"\n")]
        if client_certificate_pem is not None and client_key_pem is not None:
            values.extend(((certificate_path, client_certificate_pem), (key_path, client_key_pem)))
        for destination, raw in values:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"): flags |= os.O_NOFOLLOW
            fd = os.open(destination, flags, 0o600)
            created.append(destination)
            os.fchmod(fd, 0o600)
            stream = os.fdopen(fd, "wb", closefd=True); fd = -1
            with stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        parent = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try: os.fsync(parent)
        finally: os.close(parent)
    except BaseException:
        if fd >= 0:
            try: os.close(fd)
            except OSError: pass
        for created_path in reversed(created):
            try: created_path.unlink()
            except FileNotFoundError: pass
        try: directory.rmdir()
        except FileNotFoundError: pass
        except OSError as cleanup_error:
            raise ActivationError("failed to remove incomplete kubeconfig snapshot") from cleanup_error
        raise
    return KubeconfigSnapshot(
        path,
        directory,
        origin,
        hostname,
        port,
        tls_name,
        ca_pem,
        bytes_digest(ca_pem),
        connect_proxy,
        certificate_path if client_certificate_pem is not None else None,
        key_path if client_key_pem is not None else None,
        bearer_token,
    )

def _api_tcp_transport_v4(snapshot: KubeconfigSnapshot, timeout: int | float) -> socket.socket:
    """Open the protected API stream directly or through the local adapter."""
    target = (snapshot.hostname, snapshot.port)
    if snapshot.connect_proxy is None:
        return socket.create_connection(target, timeout=timeout)
    proxy = snapshot.connect_proxy
    connection = socket.create_connection((proxy.host, proxy.port), timeout=timeout)
    try:
        host = f"[{snapshot.hostname}]" if ":" in snapshot.hostname else snapshot.hostname
        authority = f"{host}:{snapshot.port}"
        authorization = base64.b64encode(f"{proxy.username}:{proxy.password}".encode("ascii")).decode("ascii")
        connection.sendall(
            f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
            f"Proxy-Authorization: Basic {authorization}\r\n\r\n".encode("ascii")
        )
        header = bytearray()
        while not header.endswith(b"\r\n\r\n"):
            chunk = connection.recv(1)
            require(chunk != b"", "Kubernetes loopback CONNECT proxy response incomplete")
            header.extend(chunk)
            require(len(header) <= 8192, "Kubernetes loopback CONNECT proxy response too large")
        lines = bytes(header[:-4]).split(b"\r\n")
        require(
            bool(lines) and re.fullmatch(rb"HTTP/1\.[01] 200(?: [\x20-\x7e]*)?", lines[0]) is not None,
            "Kubernetes loopback CONNECT proxy refused or malformed the tunnel",
        )
        require(
            all(re.fullmatch(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+:[\x20-\x7e]*", line) is not None for line in lines[1:]),
            "Kubernetes loopback CONNECT proxy headers malformed",
        )
        return connection
    except BaseException:
        connection.close()
        raise

def _api_server_spki_v4(snapshot: KubeconfigSnapshot, timeout: int | float) -> str:
    context = ssl.create_default_context(cadata=snapshot.ca_pem.decode("ascii"))
    with _api_tcp_transport_v4(snapshot, timeout) as connection:
        with context.wrap_socket(connection, server_hostname=snapshot.tls_server_name) as secured:
            certificate = secured.getpeercert(binary_form=True)
    require(isinstance(certificate, bytes) and certificate, "Kubernetes API TLS certificate absent")
    first = subprocess.run(["openssl", "x509", "-inform", "DER", "-pubkey", "-noout"], input=certificate, capture_output=True, check=False, timeout=timeout)
    require(first.returncode == 0 and first.stdout, "Kubernetes API certificate SPKI extraction failed")
    second = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"], input=first.stdout, capture_output=True, check=False, timeout=timeout)
    require(second.returncode == 0 and second.stdout, "Kubernetes API SPKI normalization failed")
    return bytes_digest(second.stdout)
def raw_delete(snapshot: KubeconfigSnapshot, resource_path: str, payload: str, timeout: int | float = 15) -> None:
    """Send one exact UID/resourceVersion DELETE over authenticated API TLS."""
    name = r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?"
    allowed_patterns = (
        rf"/api/v1/namespaces/{name}/(?:configmaps|secrets|services|serviceaccounts)/{name}",
        rf"/apis/apps/v1/namespaces/{name}/deployments/{name}",
        rf"/apis/networking\.k8s\.io/v1/namespaces/{name}/(?:ingresses|networkpolicies)/{name}",
        rf"/apis/rbac\.authorization\.k8s\.io/v1/namespaces/{name}/(?:roles|rolebindings)/{name}",
        rf"/apis/kustomize\.toolkit\.fluxcd\.io/v1/namespaces/{name}/kustomizations/{name}",
    )
    require(any(re.fullmatch(pattern, resource_path) is not None for pattern in allowed_patterns), "raw rollback delete resource path outside closed policy")
    options = obj(payload, "raw rollback DeleteOptions")
    require(
        set(options) in (
            {"apiVersion", "kind", "preconditions"},
            {"apiVersion", "kind", "preconditions", "propagationPolicy"},
        )
        and options.get("apiVersion") == "v1"
        and options.get("kind") == "DeleteOptions"
        and isinstance(options.get("preconditions"), dict)
        and set(options["preconditions"]) == {"uid", "resourceVersion"}
        and isinstance(options["preconditions"]["uid"], str)
        and bool(options["preconditions"]["uid"])
        and isinstance(options["preconditions"]["resourceVersion"], str)
        and options["preconditions"]["resourceVersion"].isdigit()
        and ("propagationPolicy" not in options or options["propagationPolicy"] == "Foreground")
        and canonical(options) == payload,
        "raw rollback DeleteOptions outside closed UID/resourceVersion policy",
    )
    context = ssl.create_default_context(cadata=snapshot.ca_pem.decode("ascii"))
    if snapshot.client_certificate_path is not None or snapshot.client_key_path is not None:
        require(
            snapshot.client_certificate_path is not None and snapshot.client_key_path is not None,
            "Kubernetes client certificate snapshot incomplete",
        )
        context.load_cert_chain(str(snapshot.client_certificate_path), str(snapshot.client_key_path))
    raw = _api_tcp_transport_v4(snapshot, timeout)
    secured: ssl.SSLSocket | None = None
    try:
        secured = context.wrap_socket(raw, server_hostname=snapshot.tls_server_name)
        host = f"[{snapshot.hostname}]" if ":" in snapshot.hostname else snapshot.hostname
        authority = host if snapshot.port == 443 else f"{host}:{snapshot.port}"
        body = payload.encode("ascii")
        headers = [
            f"DELETE {resource_path} HTTP/1.1",
            f"Host: {authority}",
            "Accept: application/json",
            "Content-Type: application/json",
            f"Content-Length: {len(body)}",
            "Connection: close",
        ]
        if snapshot.bearer_token is not None:
            headers.append(f"Authorization: Bearer {snapshot.bearer_token}")
        secured.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body)
        response = http.client.HTTPResponse(secured)
        response.begin()
        response_body = response.read(1024 * 1024 + 1)
        require(len(response_body) <= 1024 * 1024, "Kubernetes DELETE response exceeds 1 MiB")
        require(200 <= response.status < 300 or response.status == 404, f"raw rollback delete rejected by Kubernetes: HTTP {response.status}")
    finally:
        if secured is not None:
            try: secured.close()
            except OSError: pass
        else:
            try: raw.close()
            except OSError: pass


def _terminate_process_group(process: subprocess.Popen[Any]) -> None:
    """Bounded cleanup for a subprocess created with ``start_new_session``."""
    if process.poll() is None:
        try: os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError: pass
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait(timeout=5)
    require(getattr(process, "cleanup_error", None) is None, "verified subprocess materialization cleanup failed")

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
    # The current protected tracer includes the reviewed Web presentation ->
    # workbench civic-projection read path.  Keep this an explicit additive
    # source; the policy builder's default deliberately excludes it.
    expected = _policy_call(
        POLICY.expected_gateway_resources,
        p,
        include_web_presentation=True,
    )
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
    metadata = created.observed.get("metadata", {}); uid, created_rv = metadata.get("uid"), metadata.get("resourceVersion")
    require(
        isinstance(uid, str) and uid and isinstance(created_rv, str) and created_rv.isdigit(),
        f"{created.logical_name} nonce-removal preconditions absent",
    )
    annotation_path = "/metadata/annotations/" + POLICY.OPERATION_NONCE_ANNOTATION.replace("~", "~0").replace("/", "~1")
    desired_metadata = created.desired["metadata"]
    nonce_desired = _policy_call(POLICY.with_operation_nonce, created.desired, operation_nonce)
    last_error = "nonce removal retry exhausted"
    patch_attempted = False
    for attempt in range(4):
        current = live_obj(
            r,
            kubeconfig,
            created.desired["kind"].lower(),
            desired_metadata["name"],
            desired_metadata["namespace"],
        )
        current_metadata = current.get("metadata", {})
        require(current_metadata.get("uid") == uid, f"{created.logical_name} UID changed during nonce removal")
        current_rv = current_metadata.get("resourceVersion")
        require(isinstance(current_rv, str) and current_rv.isdigit(), f"{created.logical_name} nonce-removal resourceVersion absent")
        annotations = current_metadata.get("annotations", {})
        current_nonce = annotations.get(POLICY.OPERATION_NONCE_ANNOTATION) if isinstance(annotations, dict) else None
        if current_nonce is None:
            require(patch_attempted, f"{created.logical_name} operation nonce disappeared before nonce-removal CAS")
            _policy_call(POLICY.require_semantically_equal, current, created.desired, f"{created.logical_name} completed nonce removal")
            created.observed = current; created.receipt["temporaryNonceRemoved"] = True
            created.receipt["postNonceRemovalResourceVersion"] = current_rv
            return current
        require(current_nonce == operation_nonce, f"{created.logical_name} operation nonce ownership mismatch")
        _policy_call(POLICY.require_semantically_equal, current, nonce_desired, f"{created.logical_name} owned nonce removal")
        patch = [
            {"op": "test", "path": "/metadata/uid", "value": uid},
            {"op": "test", "path": "/metadata/resourceVersion", "value": current_rv},
            {"op": "test", "path": annotation_path, "value": operation_nonce},
            {"op": "remove", "path": annotation_path},
        ]
        patch_attempted = True
        response = r.run(
            kb(kubeconfig) + ["-n", desired_metadata["namespace"], "patch", created.desired["kind"].lower(), desired_metadata["name"], "--type=json", "-p", canonical(patch), "-o", "json"],
        )
        if response.code == 0:
            try:
                after = obj(response.out, f"{created.logical_name} nonce-removal response")
            except ActivationError as exc:
                last_error = str(exc)
            else:
                after_metadata = after.get("metadata", {})
                require(after_metadata.get("uid") == uid, f"{created.logical_name} UID changed during nonce removal")
                after_rv = after_metadata.get("resourceVersion")
                require(isinstance(after_rv, str) and after_rv.isdigit(), f"{created.logical_name} post-nonce resourceVersion absent")
                _policy_call(POLICY.require_semantically_equal, after, created.desired, f"{created.logical_name} post-nonce semantics")
                created.observed = after; created.receipt["temporaryNonceRemoved"] = True
                created.receipt["postNonceRemovalResourceVersion"] = after_rv
                return after
        else:
            last_error = str(_checked_error(response, f"{created.logical_name} remove operation nonce"))
        if attempt < 3: time.sleep(0.05 * (attempt + 1))
    final = live_obj(
        r,
        kubeconfig,
        created.desired["kind"].lower(),
        desired_metadata["name"],
        desired_metadata["namespace"],
    )
    final_metadata = final.get("metadata", {})
    require(final_metadata.get("uid") == uid, f"{created.logical_name} UID changed during nonce removal")
    final_rv = final_metadata.get("resourceVersion")
    require(isinstance(final_rv, str) and final_rv.isdigit(), f"{created.logical_name} nonce-removal resourceVersion absent")
    final_annotations = final_metadata.get("annotations", {})
    final_nonce = final_annotations.get(POLICY.OPERATION_NONCE_ANNOTATION) if isinstance(final_annotations, dict) else None
    if final_nonce is None:
        _policy_call(POLICY.require_semantically_equal, final, created.desired, f"{created.logical_name} completed nonce removal")
        created.observed = final; created.receipt["temporaryNonceRemoved"] = True
        created.receipt["postNonceRemovalResourceVersion"] = final_rv
        return final
    require(final_nonce == operation_nonce, f"{created.logical_name} operation nonce ownership mismatch")
    _policy_call(POLICY.require_semantically_equal, final, nonce_desired, f"{created.logical_name} owned nonce removal")
    raise ActivationError(f"{created.logical_name} remove operation nonce: {last_error}")

def _target_live(r: Runner, kubeconfig: str, target: dict[str, str]) -> dict[str, Any]:
    return live_obj(r, kubeconfig, target["kind"].lower(), target["name"], target["namespace"])

def validate_dormant_receipt_provenance_v4(value: Any, receipt_sha256: str) -> dict[str, Any]:
    """Validate the value-free provenance of an activation receipt source."""
    require(isinstance(value, dict), "dormant receipt provenance absent")
    mode = value.get("mode")
    if mode == "current-v1":
        require(
            set(value) == {"mode", "currentReceiptCanonicalSha256"}
            and value["currentReceiptCanonicalSha256"] == receipt_sha256
            and POLICY.SHA256.fullmatch(receipt_sha256) is not None,
            "current dormant receipt provenance drift",
        )
    elif mode == "archived-v1+get-only-handover":
        require(
            set(value) == {
                "mode", "archivedRawSha256", "archivedCanonicalSha256",
                "handoverCanonicalSha256", "handoverEffects",
            }
            and all(
                isinstance(value.get(field), str) and POLICY.SHA256.fullmatch(value[field]) is not None
                for field in ("archivedRawSha256", "archivedCanonicalSha256", "handoverCanonicalSha256")
            )
            and value["handoverCanonicalSha256"] == receipt_sha256
            and value["handoverEffects"] == {
                "verbs": ["GET"], "kubernetesGetCount": 12, "resourceGetCount": 11,
                "clusterMutationCount": 0, "secretReads": False, "civicAuthorityEffects": False,
            },
            "archived dormant handover provenance drift",
        )
    else:
        raise ActivationError("dormant receipt provenance mode invalid")
    return copy.deepcopy(value)

def validate_bound_cluster_identity_v4(value: Any, p: dict[str, Any], label: str) -> dict[str, Any]:
    expected_fields = {
        "apiOrigin", "caCertificateSha256", "apiServerSpkiSha256",
        "kubeSystemNamespaceUid", "kubeSystemNamespaceResourceVersion",
        "credentialsIncluded", "kubeconfigPathIncluded",
    }
    expected = p["clusterIdentity"]
    require(
        isinstance(value, dict)
        and set(value) == expected_fields
        and {key: value.get(key) for key in expected} == expected
        and isinstance(value.get("kubeSystemNamespaceResourceVersion"), str)
        and value["kubeSystemNamespaceResourceVersion"].isdigit()
        and value.get("credentialsIncluded") is False
        and value.get("kubeconfigPathIncluded") is False,
        f"{label} protected cluster binding drift",
    )
    return copy.deepcopy(value)

def validate_bound_preservation_v4(value: Any, p: dict[str, Any]) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == set(p["preservation"]), "dormant preservation binding set drift")
    result: dict[str, Any] = {}
    for label, descriptor in p["preservation"].items():
        observed = value[label]
        require(
            isinstance(observed, dict)
            and set(observed) == {"target", "canonicalSha256"}
            and observed.get("target") == descriptor["target"]
            and isinstance(observed.get("canonicalSha256"), str)
            and POLICY.SHA256.fullmatch(observed["canonicalSha256"]) is not None,
            f"dormant preservation binding drift: {label}",
        )
        result[label] = copy.deepcopy(observed)
    return result

def require_current_preservation_binding_v4(
    snapshots: dict[str, PreservedV4],
    ownership: dict[str, Any],
    p: dict[str, Any],
) -> None:
    """Revalidate the current (never archived) preservation boundary.

    The archived receipt proves only what the old transaction observed.  The
    handover GET-only phase records a fresh digest for the current objects and
    carries the exact Git-derived desired objects outside the receipt payload;
    activation must bind both proofs again before its first write.
    """
    bound = validate_bound_preservation_v4(ownership.get("preservation"), p)
    require(set(snapshots) == set(bound), "current preservation snapshot set drift")
    protected = ownership.get("currentProtectedPreservation")
    if protected is not None:
        require(
            isinstance(protected, dict) and set(protected) == set(bound),
            "current protected preservation set drift",
        )
    for label, snapshot in snapshots.items():
        expected = bound[label]
        require(snapshot.target == expected["target"], f"current preservation target drift: {label}")
        if protected is not None:
            desired_binding = protected[label]
            require(
                isinstance(desired_binding, dict)
                and set(desired_binding) == {"target", "desired", "desiredSemanticSha256"}
                and desired_binding.get("target") == expected["target"]
                and isinstance(desired_binding.get("desired"), dict)
                and isinstance(desired_binding.get("desiredSemanticSha256"), str)
                and POLICY.SHA256.fullmatch(desired_binding["desiredSemanticSha256"]) is not None
                and desired_binding["desiredSemanticSha256"]
                    == _policy_call(POLICY.semantic_sha256, desired_binding["desired"]),
                f"current protected preservation binding drift: {label}",
            )
            _policy_call(
                POLICY.require_semantically_equal,
                snapshot.value,
                desired_binding["desired"],
                f"current protected {label}",
            )
        require(snapshot.canonical_sha256 == expected["canonicalSha256"], f"current preservation digest drift: {label}")

def require_secret_materialization_binding_v4(
    current: dict[str, Any],
    ownership: dict[str, Any],
    p: dict[str, Any],
) -> None:
    """Bind the two participant-owned Secrets to their prior receipt.

    The PostgREST projection is deliberately owned by the tracer data-plane
    materializer, not by the older participant materializer.  Its exact live
    identity and keyset are still checked by :func:`secret_materialization_v4`,
    but it must not be adopted into (or coupled to teardown of) the participant
    receipt that owns only ``config`` and ``runtime``.
    """
    require(
        current.get("status") == "exact-keysets-present-without-reading-values"
        and ownership.get("status") == "materialized"
        and ownership.get("civicAuthorityEffects") is False,
        "Secret materialization continuation status drift",
    )
    participant_labels = {"config", "runtime"}
    records = ownership.get("secretRecords")
    require(
        isinstance(records, dict) and set(records) == participant_labels,
        "Secret materialization continuation record set drift",
    )
    live_records = current.get("secrets")
    require(
        isinstance(live_records, dict)
        and set(live_records) == set(p["runtime"]["secretReferences"])
        and participant_labels < set(live_records),
        "current Secret materialization record set drift",
    )
    references = p["runtime"]["secretReferences"]
    for label, record in records.items():
        live = live_records[label]
        reference = references[label]
        require(
            isinstance(record, dict)
            and set(record) == {"target", "uid", "resourceVersion", "keySet", "valuesRead"}
            and record["target"] == {"apiVersion": "v1", "kind": "Secret", "namespace": reference["namespace"], "name": reference["name"]}
            and isinstance(record["uid"], str)
            and isinstance(record["resourceVersion"], str)
            and record["resourceVersion"].isdigit()
            and record["keySet"] == sorted(reference["keys"])
            and record["valuesRead"] is False,
            f"Secret materialization ownership record invalid: {label}",
        )
        require(
            isinstance(live, dict)
            and live.get("name") == reference["name"]
            and live.get("namespace") == reference["namespace"]
            and live.get("uid") == record["uid"]
            and isinstance(live.get("resourceVersion"), str)
            and live["resourceVersion"].isdigit()
            and int(live["resourceVersion"]) == int(record["resourceVersion"])
            and live.get("keys") == record["keySet"]
            and live.get("valuesRead") is False,
            f"Secret materialization identity/keyset drift: {label}",
        )

def _validate_handover_object_ownership_v4(
    dormant_ownership: dict[str, Any],
    p: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    expected_names = tuple(POLICY.DORMANT_BOOTSTRAP_OBJECT_ORDER)
    objects = dormant_ownership.get("objects")
    require(
        isinstance(objects, list)
        and len(objects) == len(expected_names)
        and [item.get("logicalName") for item in objects if isinstance(item, dict)] == list(expected_names),
        "dormant handover object order invalid",
    )
    bound = {item["logicalName"]: item for item in objects}
    require(len(bound) == len(expected_names), "dormant handover object names are duplicated")
    uids = [item.get("uid") for item in objects]
    targets = [canonical(item.get("target")) for item in objects]
    require(
        all(isinstance(uid, str) and bool(uid) for uid in uids)
        and len(set(uids)) == len(uids)
        and len(set(targets)) == len(targets),
        "dormant handover object identities are duplicated or invalid",
    )
    return bound

def flux_preflight_v4(
    r: Runner,
    kubeconfig: str,
    p: dict[str, Any],
    rev: str,
    dormant_ownership: dict[str, Any],
) -> dict[str, Any]:
    source = shared_source_revision_v4(r, kubeconfig, rev)

    handover_provenance = dormant_ownership.get("receiptProvenance")
    handover_mode = isinstance(handover_provenance, dict) and handover_provenance.get("mode") == "archived-v1+get-only-handover"
    if handover_mode:
        validate_dormant_receipt_provenance_v4(handover_provenance, dormant_ownership.get("receiptSha256"))
        validate_bound_cluster_identity_v4(dormant_ownership.get("clusterBinding"), p, "dormant handover")
        validate_bound_preservation_v4(dormant_ownership.get("preservation"), p)
        shared_source = dormant_ownership.get("sharedSource")
        require(
            isinstance(shared_source, dict)
            and source.get("metadata", {}).get("uid") == shared_source.get("uid")
            and source.get("status", {}).get("artifact", {}).get("revision") == f"main@sha1:{rev}",
            "dormant handover shared Source identity drift",
        )
        require(
            shared_source.get("semanticSha256") == POLICY.semantic_sha256(source),
            "dormant handover shared Source identity drift",
        )

    builders = {"gateway": POLICY.gateway_flux_objects, "workbenchIngress": POLICY.workbench_ingress_flux_objects}
    bound = {
        item["logicalName"]: item
        for item in dormant_ownership.get("objects", [])
        if isinstance(item, dict) and isinstance(item.get("logicalName"), str)
    }
    require(
        dormant_ownership.get("status") == "dormant-ready"
        and dormant_ownership.get("protectedRevision") == rev
        and dormant_ownership.get("activationPolicySha256") == POLICY.activation_policy_sha256(p)
        and dormant_ownership.get("bothKustomizationsSuspended") is True
        and set(bound) == set(POLICY.DORMANT_BOOTSTRAP_OBJECT_ORDER),
        "dormant Flux bootstrap receipt ownership set invalid",
    )
    if handover_mode:
        _validate_handover_object_ownership_v4(dormant_ownership, p)
    owners: dict[str, dict[str, Any]] = {}
    for owner, builder in builders.items():
        expected = _policy_call(builder, suspended=True); live: dict[str, Any] = {}
        for key in ("serviceAccount", "role", "roleBinding", "kustomization"):
            target = p["gitOps"]["reconcilers"][owner][key]; live[key] = _target_live(r, kubeconfig, target)
            _policy_call(POLICY.require_semantically_equal, live[key], expected[key], f"{owner} dormant {key}")
            receipt = bound[f"{owner}.{key}"]
            metadata = live[key].get("metadata", {})
            require(
                receipt["target"] == target
                and metadata.get("uid") == receipt["uid"]
                and isinstance(metadata.get("resourceVersion"), str)
                and metadata["resourceVersion"].isdigit()
                and int(metadata["resourceVersion"]) >= int(receipt["resourceVersion"]),
                f"{owner} dormant {key} no longer matches bootstrap receipt identity",
            )
            if handover_mode:
                require(
                    receipt.get("desiredSemanticSha256") == POLICY.semantic_sha256(expected[key])
                    and receipt.get("target") == target,
                    f"{owner} dormant {key} desired semantic binding drift",
                )
        require(live["kustomization"].get("spec", {}).get("suspend") is True, f"{owner} Kustomization not dormant")
        owners[owner] = live
    return {
        "source": source,
        "owners": owners,
        "bootstrapReceipt": {
            "receiptSha256": dormant_ownership["receiptSha256"],
            "protectedRevision": dormant_ownership["protectedRevision"],
            "objects": copy.deepcopy(dormant_ownership["objects"]),
        },
    }

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

def endpoint_facts_v4(r: Runner, kubeconfig: str, p: dict[str, Any]) -> dict[str, Any]:
    """Verify the fixed Gnosis TLS origin and internal PostgREST binding."""
    timeout = p["httpBoundary"]["timeoutsSeconds"]["routeRequest"]
    context = ssl.create_default_context()
    gnosis = p["endpoints"]["gnosis"]
    parsed = urllib.parse.urlparse(gnosis["httpsOrigin"])
    require(
        parsed.scheme == "https" and parsed.hostname and parsed.path in {"", "/"},
        "gnosis origin invalid",
    )
    addresses = sorted({
        entry[4][0]
        for entry in socket.getaddrinfo(
            parsed.hostname,
            gnosis["port"],
            type=socket.SOCK_STREAM,
        )
        if ":" not in entry[4][0]
    })
    expected = sorted(cidr.removesuffix("/32") for cidr in gnosis["ipv4Cidrs"])
    require(addresses == expected and addresses, "gnosis DNS answers differ from protected /32 set")
    tls = []
    for address in addresses:
        with socket.create_connection((address, gnosis["port"]), timeout=timeout) as connection:
            with context.wrap_socket(connection, server_hostname=parsed.hostname) as secured:
                certificate = secured.getpeercert(binary_form=True)
                require(certificate is not None, "gnosis TLS certificate absent")
                tls.append({
                    "ipv4": address,
                    "tlsVersion": secured.version(),
                    "certificateDerSha256": "sha256:" + hashlib.sha256(certificate).hexdigest(),
                })

    postgrest = p["endpoints"]["supabase"]
    target = postgrest["service"]
    namespace = target["namespace"]
    name = target["name"]
    service = obj(
        checked(
            r,
            kb(kubeconfig) + ["-n", namespace, "get", "service", name, "-o", "json"],
            "internal PostgREST Service",
        ),
        "internal PostgREST Service",
    )
    service_spec = service.get("spec", {})
    require(service_spec.get("type") == "ClusterIP", "internal PostgREST Service type drift")
    require(
        service_spec.get("selector") == POLICY.TRACER_POSTGREST_LABELS,
        "internal PostgREST Service selector drift",
    )
    require(
        service_spec.get("ports") == [{
            "name": "http",
            "port": postgrest["port"],
            "protocol": "TCP",
            "targetPort": "http",
        }],
        "internal PostgREST Service port drift",
    )
    slices = obj(
        checked(
            r,
            kb(kubeconfig) + [
                "-n", namespace, "get", "endpointslices",
                "-l", f"kubernetes.io/service-name={name}", "-o", "json",
            ],
            "internal PostgREST EndpointSlices",
        ),
        "internal PostgREST EndpointSlices",
    )
    ready_addresses = sorted({
        address
        for item in slices.get("items", [])
        for endpoint in item.get("endpoints", [])
        if endpoint.get("conditions", {}).get("ready") is True
        for address in endpoint.get("addresses", [])
    })
    require(ready_addresses, "internal PostgREST has no ready endpoint")
    return {
        "status": "fixed-external-tls-and-internal-service-binding-match",
        "gnosis": {
            "origin": gnosis["httpsOrigin"],
            "port": gnosis["port"],
            "ipv4Answers": addresses,
            "protectedIpv4Cidrs": gnosis["ipv4Cidrs"],
            "tls": tls,
        },
        "postgrest": {
            "origin": postgrest["internalOrigin"],
            "service": target,
            "serviceUid": service.get("metadata", {}).get("uid"),
            "serviceResourceVersion": service.get("metadata", {}).get("resourceVersion"),
            "readyEndpointAddresses": ready_addresses,
            "externalIngress": False,
        },
    }

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
        # Kubernetes treats an omitted or empty ports list as all ports.
        if ports is None or ports == []: return True
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

def _is_explicit_workbench_egress_only_policy_v4(value: dict[str, Any]) -> bool:
    """Recognize a policy that cannot participate in the ingress union."""
    spec = value.get("spec")
    return (
        isinstance(spec, dict)
        and spec.get("policyTypes") == ["Egress"]
        and spec.get("ingress", []) == []
    )

_REVIEWED_PUBLIC_INGRESS_SOURCE_PEERS_V4 = (
    {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "ingress-system"}}},
    *(
        {"ipBlock": {"cidr": cidr}}
        for cidr in (
            "10.42.0.10/32", "10.42.0.11/32", "10.42.0.12/32",
            "10.244.0.0/32", "10.244.1.0/32", "10.244.2.0/32",
            "10.244.0.1/32", "10.244.1.1/32", "10.244.2.1/32",
        )
    ),
)
_REVIEWED_PUBLIC_WORKBENCH_SELECTOR_V4 = {
    "matchLabels": {
        "app.kubernetes.io/component": "e2e-workbench",
        "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
    },
}

def _is_exact_reviewed_public_workbench_ingress_v4(value: dict[str, Any]) -> bool:
    """Recognize the existing HAProxy-to-workbench capability, not its name.

    This is the same fixed ingress-system/node/Flannel source boundary already
    reviewed for the public staging presentation.  The participant path is a
    direct, non-host-network ClusterIP path and therefore has a Pod source
    identity rather than any of these exact peers.  Any selector, peer, port,
    direction, rule, or extra capability drift remains a conflict.
    """
    spec = value.get("spec")
    if not isinstance(spec, dict) or set(spec) - {"podSelector", "policyTypes", "ingress", "egress"}: return False
    if spec.get("podSelector") != _REVIEWED_PUBLIC_WORKBENCH_SELECTOR_V4: return False
    if spec.get("policyTypes") != ["Ingress"] or spec.get("egress", []) != []: return False
    ingress = spec.get("ingress")
    if not isinstance(ingress, list) or len(ingress) != 1 or not isinstance(ingress[0], dict): return False
    rule = ingress[0]
    if set(rule) != {"from", "ports"} or rule.get("ports") != [{"port": POLICY.WORKBENCH_PORT, "protocol": "TCP"}]: return False
    peers = rule.get("from")
    if not isinstance(peers, list) or len(peers) != len(_REVIEWED_PUBLIC_INGRESS_SOURCE_PEERS_V4): return False
    return {canonical(peer) for peer in peers} == {canonical(peer) for peer in _REVIEWED_PUBLIC_INGRESS_SOURCE_PEERS_V4}

def _cilium_api_group_present_v4(r: Runner, kubeconfig: str) -> bool:
    """Discover Cilium directly from the live API instead of assuming a CRD."""
    discovery = obj(
        checked(r, kb(kubeconfig) + ["get", "--raw=/apis"], "fresh Kubernetes API-group discovery"),
        "Kubernetes API-group discovery",
    )
    require(discovery.get("kind") == "APIGroupList" and isinstance(discovery.get("groups"), list), "Kubernetes API-group discovery invalid")
    names = []
    for group in discovery["groups"]:
        require(isinstance(group, dict) and isinstance(group.get("name"), str) and group["name"], "Kubernetes API-group entry invalid")
        names.append(group["name"])
    require(len(names) == len(set(names)), "Kubernetes API-group discovery contains duplicates")
    return "cilium.io" in names

def policy_union_v4(r: Runner, kubeconfig: str, owned: dict[tuple[str, str], CreatedV4] | None = None) -> dict[str, Any]:
    """Conservatively reject additive K8s/Cilium participant allows."""
    owned = owned or {}; count = 0; label_sets = _target_policy_label_sets_v4(r, kubeconfig); owned_validated = []; compatible_workbench_egress = []; compatible_workbench = []
    cilium_present: bool | None = None
    families = (("networkpolicy", ["-A"], "kubernetes"), ("ciliumnetworkpolicies.cilium.io", ["-A"], "cilium"), ("ciliumclusterwidenetworkpolicies.cilium.io", [], "cilium-clusterwide"))
    for resource, extra, family in families:
        if family != "kubernetes":
            if cilium_present is None: cilium_present = _cilium_api_group_present_v4(r, kubeconfig)
            if not cilium_present: break
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
                    if name == POLICY.WORKBENCH_NAME:
                        require(not _allows_workbench_port(item), "manual workbench policy already allows participant port 18083")
                    else:
                        classification = (
                            "no-ingress-allow-for-participant-port"
                            if not _allows_workbench_port(item)
                            else "exact-reviewed-public-ingress-boundary"
                            if _is_exact_reviewed_public_workbench_ingress_v4(item)
                            else None
                        )
                        require(classification is not None, f"pre-existing NetworkPolicy selects workbench: {namespace}/{name}")
                        require(isinstance(name, str) and name and isinstance(metadata.get("uid"), str) and metadata["uid"], "compatible workbench policy identity absent")
                        evidence = {"namespace": namespace, "name": name, "uid": metadata["uid"], "semanticSha256": POLICY.semantic_sha256(item)}
                        compatible_workbench.append(evidence | {"classification": classification})
                        if _is_explicit_workbench_egress_only_policy_v4(item): compatible_workbench_egress.append(evidence)
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
    if cilium_present is None: cilium_present = _cilium_api_group_present_v4(r, kubeconfig)
    return {"status": "no-additive-participant-allow-conflicts", "families": ["kubernetes", "cilium", "cilium-clusterwide"], "ciliumApiDiscovery": {"apiGroup": "cilium.io", "present": cilium_present}, "objectsScanned": count, "ownedNetworkPoliciesValidated": sorted(owned_validated, key=lambda item: (item["namespace"], item["name"])), "compatibleWorkbenchEgressPolicies": sorted(compatible_workbench_egress, key=lambda item: (item["namespace"], item["name"])), "compatibleWorkbenchPolicies": sorted(compatible_workbench, key=lambda item: (item["namespace"], item["name"])), "runtimeSelectorFacts": label_sets}

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request: Any, file_pointer: Any, code: int, message: str, headers: Any, new_url: str) -> None:
        return None


_PORT_FORWARD_OUTPUT_TAIL_BYTES_V4 = 16384
_PORT_FORWARD_ERROR_OUTPUT_CHARS_V4 = 2048


def _sanitized_port_forward_output_tail_v4(output: bytes) -> str:
    """Return only allowlisted kubectl diagnostics from a bounded byte tail."""
    decoded = output[-_PORT_FORWARD_OUTPUT_TAIL_BYTES_V4:].decode("utf-8", "replace")
    printable = "".join(character if character in "\n\t" or character.isprintable() else "?" for character in decoded)
    sanitized = []
    for line in printable.splitlines():
        if re.fullmatch(r"Forwarding from 127\.0\.0\.1:\d+ -> \d+", line):
            sanitized.append(line)
        elif re.fullmatch(r"Handling connection for \d+", line):
            sanitized.append(line)
        elif line:
            sanitized.append("<redacted kubectl output line>")
    return "\n".join(sanitized)[-_PORT_FORWARD_ERROR_OUTPUT_CHARS_V4:]


def _port_forward_transport_error_v4(
    *,
    phase: str,
    path: str,
    request_budget: int | float,
    attempts: int,
    process: subprocess.Popen[Any],
    output: bytes,
    error_type: str,
) -> ActivationError:
    exit_code = process.poll()
    evidence = {
        "phase": phase,
        "path": path,
        "requestBudgetSeconds": request_budget,
        "attempts": attempts,
        "errorType": error_type,
        "processState": {"alive": exit_code is None, "exitCode": exit_code},
        "kubectlOutputTail": _sanitized_port_forward_output_tail_v4(output),
    }
    return ActivationError("internal participant readiness transport failure: " + canonical(evidence))


def _is_transport_timeout_v4(exc: BaseException) -> bool:
    if isinstance(exc, TimeoutError):
        return True
    if isinstance(exc, urllib.error.URLError):
        return isinstance(exc.reason, TimeoutError) or (
            isinstance(exc.reason, OSError) and exc.reason.errno == errno.ETIMEDOUT
        )
    return isinstance(exc, OSError) and exc.errno == errno.ETIMEDOUT


class _RetryablePortForwardTimeoutV4(Exception):
    def __init__(self, error: ActivationError):
        super().__init__()
        self.error = error


def _pod_port_forward_get_once_v4(
    kubeconfig: str,
    pod_name: str,
    remote_port: int,
    path: str,
    *,
    startup_timeout: int | float,
    request_timeout: int | float,
    attempt: int,
) -> tuple[str, dict[str, Any]]:
    command = kb(kubeconfig) + [
        "-n", NAMESPACE, "port-forward", "--address=127.0.0.1",
        f"pod/{pod_name}", f":{remote_port}",
    ]
    binding = kubectl_binding_v4()
    process = verified_popen(
        binding,
        [str(binding.path), *command[1:]],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=kubernetes_subprocess_environment_v4(),
    )
    output_lock = threading.Lock()
    output_tail = bytearray()
    ready = threading.Event()
    reader_done = threading.Event()
    reader_stop = threading.Event()
    forwarded: list[tuple[int, int]] = []
    reader_error: list[str] = []

    def output_snapshot() -> bytes:
        with output_lock:
            return bytes(output_tail)

    def drain_output() -> None:
        stream_selector = selectors.DefaultSelector()
        try:
            require(process.stdout is not None, "kubectl port-forward output pipe unavailable")
            stream_selector.register(process.stdout, selectors.EVENT_READ)
            while not reader_stop.is_set():
                events = stream_selector.select(timeout=0.1)
                if not events:
                    if process.poll() is not None:
                        break
                    continue
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    break
                with output_lock:
                    output_tail.extend(chunk)
                    del output_tail[:-_PORT_FORWARD_OUTPUT_TAIL_BYTES_V4]
                    match = re.search(rb"Forwarding from 127\.0\.0\.1:(\d+) -> (\d+)", output_tail)
                    if match and not forwarded:
                        forwarded.append((int(match.group(1)), int(match.group(2))))
                        ready.set()
        except (OSError, ValueError) as exc:
            reader_error.append(type(exc).__name__)
        finally:
            stream_selector.close()
            reader_done.set()

    reader = threading.Thread(target=drain_output, name="participant-port-forward-output", daemon=False)
    reader.start()
    try:
        deadline = time.monotonic() + startup_timeout
        while not ready.wait(timeout=min(0.05, max(0.0, deadline - time.monotonic()))):
            if process.poll() is not None or reader_done.is_set():
                reader_done.wait(timeout=0.1)
                raise _port_forward_transport_error_v4(
                    phase="startup", path=path, request_budget=startup_timeout, attempts=attempt,
                    process=process, output=output_snapshot(),
                    error_type=reader_error[0] if reader_error else "ForwardProcessExited",
                )
            if time.monotonic() >= deadline:
                raise _port_forward_transport_error_v4(
                    phase="startup", path=path, request_budget=startup_timeout, attempts=attempt,
                    process=process, output=output_snapshot(), error_type="TimeoutError",
                )
        local_port, forwarded_port = forwarded[0]
        require(forwarded_port == remote_port, "kubectl port-forward remote port drift")
        url = f"http://127.0.0.1:{local_port}{path}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        phase = "open"
        request = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
        try:
            with opener.open(request, timeout=request_timeout) as response:
                require(response.status == 200 and response.geturl() == url, "internal participant readiness HTTP boundary drift")
                content_type = response.headers.get_content_type()
                require(content_type == "application/json", "internal participant readiness content type drift")
                phase = "response-read"
                raw = response.read(8193)
        except urllib.error.HTTPError as exc:
            exc.close()
            raise ActivationError(f"internal participant readiness rejected: HTTP {exc.code}") from exc
        except (TimeoutError, urllib.error.URLError, OSError) as exc:
            error = _port_forward_transport_error_v4(
                phase=phase, path=path, request_budget=request_timeout, attempts=attempt,
                process=process, output=output_snapshot(), error_type=type(exc).__name__,
            )
            if _is_transport_timeout_v4(exc):
                raise _RetryablePortForwardTimeoutV4(error) from exc
            raise error from exc
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
        try:
            _terminate_process_group(process)
        finally:
            reader_stop.set()
            reader.join(timeout=1)
            if process.stdout is not None:
                process.stdout.close()
        require(not reader.is_alive(), "kubectl port-forward output drain cleanup failed")


def _pod_port_forward_get_v4(
    kubeconfig: str,
    pod_name: str,
    remote_port: int,
    path: str,
    *,
    startup_timeout: int | float,
    request_timeout: int | float,
    retry_timeout: bool = True,
) -> tuple[str, dict[str, Any]]:
    """GET an internal Pod endpoint through a fresh authenticated API stream.

    Kubernetes Pod port-forward is deliberately used instead of Service proxy
    traffic: the latter has CNI-dependent source identity and can be denied by
    the participant NetworkPolicy.  A single retry is allowed only after a
    classified request timeout and creates a new kubectl stream.  HTTP errors
    and contract drift never retry.
    """
    attempts = (1, 2) if retry_timeout else (1,)
    for attempt in attempts:
        try:
            return _pod_port_forward_get_once_v4(
                kubeconfig, pod_name, remote_port, path,
                startup_timeout=startup_timeout, request_timeout=request_timeout,
                attempt=attempt,
            )
        except _RetryablePortForwardTimeoutV4 as exc:
            if attempt == attempts[-1]:
                raise exc.error from exc
    raise ActivationError("internal participant readiness transport retry state invalid")


def expected_participant_http_status_v4() -> dict[str, Any]:
    return {
        "available": True,
        "active": False,
        "walletAddress": None,
        "label": "Staging-Testteilnahme – keine Bürgerverifikation, kein Stimmrecht",
        "scope": None,
        "authority": "none",
    }


def participant_http_status_preflight_v4(
    kubeconfig: str,
    pod_name: str,
    timeout: int | float,
    *,
    retry_timeout: bool = True,
) -> dict[str, Any]:
    """Prove the gateway's DB-free HTTP route before probing DB readiness."""
    path = POLICY.ROUTES[0]
    require(path == POLICY.HTTP_PREFIX + "/status", "participant status route policy drift")
    body, probe = _pod_port_forward_get_v4(
        kubeconfig, pod_name, POLICY.GATEWAY_PORT, path,
        startup_timeout=timeout, request_timeout=timeout, retry_timeout=retry_timeout,
    )
    require(
        obj(body, "internal DB-free participant status") == expected_participant_http_status_v4(),
        "internal DB-free participant status contract drift",
    )
    require(
        probe == {
            "transport": "authenticated-kubernetes-pod-port-forward",
            "pod": pod_name,
            "loopbackOnly": True,
            "publicIngressUsed": False,
            "serviceProxyUsed": False,
            "redirectsAllowed": False,
            "path": path,
            "remotePort": POLICY.GATEWAY_PORT,
        },
        "internal DB-free participant status probe drift",
    )
    return probe


def _readiness_failure_projection_v4(exc: ActivationError) -> dict[str, Any]:
    message = str(exc)
    http_match = re.fullmatch(r"internal participant readiness rejected: HTTP (\d{3})", message)
    if http_match:
        return {"kind": "http-rejected", "status": int(http_match.group(1))}
    prefix = "internal participant readiness transport failure: "
    if message.startswith(prefix):
        try:
            evidence = json.loads(message[len(prefix):])
        except (json.JSONDecodeError, TypeError):
            evidence = None
        if isinstance(evidence, dict):
            phase = evidence.get("phase")
            attempts = evidence.get("attempts")
            budget = evidence.get("requestBudgetSeconds")
            process_state = evidence.get("processState")
            if (
                phase in {"startup", "open", "response-read"}
                and type(attempts) is int and 0 <= attempts <= 2
                and type(budget) in {int, float} and 0 < budget <= 600
                and isinstance(process_state, dict)
                and type(process_state.get("alive")) is bool
                and (process_state.get("exitCode") is None or type(process_state.get("exitCode")) is int)
            ):
                return {
                    "kind": "transport-failure",
                    "phase": phase,
                    "attempts": attempts,
                    "requestBudgetSeconds": budget,
                    "processState": {
                        "alive": process_state["alive"],
                        "exitCode": process_state["exitCode"],
                    },
                }
    return {"kind": "contract-failure", "errorType": type(exc).__name__}


def topic_tracer_readiness_projection_v4(p: dict[str, Any]) -> dict[str, str]:
    """Return the closed five-field topic-tracer binding from policy data."""
    pins = p["productPins"]
    topic_policy = p["runtime"]["topicPolicy"]
    return {
        "municipalityId": topic_policy["municipalityId"],
        "sourceConversationTopic": topic_policy["sourceConversationTopic"],
        "topicPolicyVersion": topic_policy["policyVersion"],
        "topicTracerMigrationSha256": pins["topicTracerMigration"]["sha256"],
        "topicTracerDatabaseSchemaSha256": pins["topicTracerDatabaseSchemaSha256"],
    }


def expected_database_status_v4(p: dict[str, Any]) -> dict[str, str]:
    """The exact payload emitted by the private gateway readiness endpoint."""
    pins = p["productPins"]
    return {
        "schemaVersion": "roebel_staging_participant_gateway_status_v2",
        "status": "ready",
        "sourceRevision": pins["sourceRevision"],
        "manifestDigest": pins["imageManifestDigest"],
        "migrationSha256": pins["migration"]["sha256"],
        "databaseSchemaSha256": pins["databaseSchemaSha256"],
        **topic_tracer_readiness_projection_v4(p),
    }


def validate_database_status_receipt_v4(value: Any, p: dict[str, Any]) -> dict[str, Any]:
    """Fail closed on the complete private readiness receipt, not a subset."""
    require(isinstance(value, dict), "internal participant readiness receipt must be an object")
    expected_status = expected_database_status_v4(p)
    expected_keys = set(expected_status) | {"probe", "rbac"}
    require(set(value) == expected_keys, "internal participant readiness receipt field set drift")
    require(
        {key: value[key] for key in expected_status} == expected_status,
        "internal participant readiness product/topic-tracer contract drift",
    )
    require(
        topic_tracer_readiness_projection_v4(p)
        == {key: value[key] for key in topic_tracer_readiness_projection_v4(p)},
        "internal participant readiness topic-tracer projection drift",
    )
    probe = value["probe"]
    require(
        isinstance(probe, dict)
        and set(probe)
        == {
            "transport",
            "pod",
            "loopbackOnly",
            "publicIngressUsed",
            "serviceProxyUsed",
            "redirectsAllowed",
            "path",
            "remotePort",
            "podUid",
            "podImage",
            "podImageId",
            "podReadyAfter",
            "podResourceVersionBefore",
            "podResourceVersionAfter",
        },
        "internal participant readiness probe receipt field set drift",
    )
    require(
        probe["transport"] == "authenticated-kubernetes-pod-port-forward"
        and isinstance(probe["pod"], str)
        and bool(probe["pod"])
        and probe["loopbackOnly"] is True
        and probe["publicIngressUsed"] is False
        and probe["serviceProxyUsed"] is False
        and probe["redirectsAllowed"] is False
        and probe["path"] == "/status"
        and probe["remotePort"] == POLICY.GATEWAY_PORT
        and isinstance(probe["podUid"], str)
        and bool(probe["podUid"])
        and probe["podImage"] == p["productPins"]["imageRepository"] + "@" + p["productPins"]["imageManifestDigest"]
        and isinstance(probe["podImageId"], str)
        and bool(probe["podImageId"])
        and probe["podReadyAfter"] is True
        and isinstance(probe["podResourceVersionBefore"], str)
        and probe["podResourceVersionBefore"].isdigit()
        and isinstance(probe["podResourceVersionAfter"], str)
        and probe["podResourceVersionAfter"].isdigit()
        and int(probe["podResourceVersionAfter"]) >= int(probe["podResourceVersionBefore"]),
        "internal participant readiness probe receipt drift",
    )
    require(
        value["rbac"] == {
            "getPods": True,
            "listPods": True,
            "createPodsPortforward": True,
        },
        "internal participant readiness RBAC receipt drift",
    )
    return copy.deepcopy(value)


def database_status_v4(r: Runner, kubeconfig: str, p: dict[str, Any], runtime: dict[str, Any]) -> dict[str, Any]:
    # This is the container-internal readiness contract. It is reached only by
    # an authenticated Pod port-forward and is deliberately distinct from the
    # public participant-session UI status route.
    require(runtime.get("readyPodCount") == p["runtime"]["replicas"] and len(runtime.get("pods", [])) == p["runtime"]["replicas"], "verified participant Pod set absent")
    for verb in ("get", "list"):
        checked(r, kb(kubeconfig) + ["auth", "can-i", "--quiet", verb, "pods", "-n", NAMESPACE], f"internal status RBAC {verb} pods")
    checked(r, kb(kubeconfig) + ["auth", "can-i", "--quiet", "create", "pods/portforward", "-n", NAMESPACE], "internal status RBAC create pods/portforward")
    selected = runtime["pods"][0]; timeout = p["httpBoundary"]["timeoutsSeconds"]["routeRequest"]
    participant_http_status_preflight_v4(kubeconfig, selected["name"], timeout)
    try:
        body, probe = _pod_port_forward_get_v4(
            kubeconfig,
            selected["name"],
            POLICY.GATEWAY_PORT,
            "/status",
            startup_timeout=timeout,
            request_timeout=timeout,
        )
    except ActivationError as database_failure:
        database_projection = _readiness_failure_projection_v4(database_failure)
        try:
            participant_http_status_preflight_v4(kubeconfig, selected["name"], timeout, retry_timeout=False)
        except ActivationError as db_free_failure:
            evidence = {
                "classification": "db-backed-failed",
                "dbFreeBefore": {"kind": "healthy"},
                "dbBacked": database_projection,
                "dbFreeAfter": _readiness_failure_projection_v4(db_free_failure),
            }
            raise ActivationError("internal participant readiness discriminator: " + canonical(evidence)) from database_failure
        evidence = {
            "classification": "db-backed-failed",
            "dbFreeBefore": {"kind": "healthy"},
            "dbBacked": database_projection,
            "dbFreeAfter": {"kind": "healthy"},
        }
        raise ActivationError("internal participant readiness discriminator: " + canonical(evidence)) from database_failure
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
    expected = expected_database_status_v4(p)
    require(obj(body, "internal participant /status") == expected, "internal participant /status product/topic-tracer contract drift")
    return validate_database_status_receipt_v4(expected | {
        "probe": probe | {"podUid": selected["uid"], "podImage": exact_image, "podImageId": selected["imageId"], "podReadyAfter": True, "podResourceVersionBefore": selected["resourceVersion"], "podResourceVersionAfter": current_metadata.get("resourceVersion")},
        "rbac": {"getPods": True, "listPods": True, "createPodsPortforward": True},
    }, p)

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
    require(prefix == POLICY.HTTP_PREFIX, "fixed route prefix drift")
    status_path = POLICY.ROUTES[0]; posts = list(POLICY.POST_ROUTES)
    require([entry["path"] for entry in boundary["routes"]] == list(POLICY.ROUTES), "fixed eight-route inventory drift")
    result: list[dict[str, Any]] = []

    def propagation_timeout(attempts: int, status: int) -> None:
        raise ActivationError(f"GET status route propagation timeout: attempts={attempts} lastStatus={status}")

    def call(method: str, path: str, *, request_origin: str | None = origin, body: bytes | None = None, requested_method: str | None = None, propagation_attempt: int | None = None) -> dict[str, Any]:
        before_request = time.monotonic()
        if before_request >= total_deadline:
            if propagation_attempt is not None and propagation_attempt > 1:
                propagation_timeout(propagation_attempt - 1, 404)
            raise ActivationError("route matrix total timeout")
        headers: dict[str, str] = {"Accept": "application/json"}
        if request_origin is not None: headers["Origin"] = request_origin
        if body is not None: headers["Content-Type"] = "application/json"
        if requested_method is not None:
            headers["Access-Control-Request-Method"] = requested_method; headers["Access-Control-Request-Headers"] = "content-type"
        observed = _route_request_v4(origin, method, path, headers, body, timeout)
        if time.monotonic() >= total_deadline:
            if propagation_attempt is not None and observed["status"] == 404:
                propagation_timeout(propagation_attempt, 404)
            raise ActivationError("route matrix total timeout after request")
        return observed

    status_body = expected_participant_http_status_v4()
    status_attempts = 0
    while True:
        if status_attempts and time.monotonic() >= total_deadline:
            propagation_timeout(status_attempts, 404)
        observed = call("GET", status_path, propagation_attempt=status_attempts + 1)
        status_attempts += 1
        if observed["status"] != 404:
            break
        if time.monotonic() >= total_deadline:
            propagation_timeout(status_attempts, 404)
        time.sleep(PUBLIC_ROUTE_PROPAGATION_POLL_SECONDS)
    _require_json_response_v4(observed, 200, status_body, "GET status"); _require_cors_v4(observed, origin); result.append({"case": "status", "method": "GET", "path": status_path, "status": 200})
    for path, allowed in [(status_path, "GET"), *[(path, "POST") for path in posts]]:
        observed = call("OPTIONS", path, requested_method=allowed)
        require(observed["status"] == 204 and observed["body"] == "" and "content-type" not in observed["headers"], f"OPTIONS {path} response drift")
        _require_cors_v4(observed, origin, preflight_method=allowed); result.append({"case": "preflight", "method": "OPTIONS", "path": path, "status": 204})
    post_errors = {
        posts[0]: (401, {"error": "admission_invalid"}),
        posts[1]: (401, {"error": "challenge_invalid"}),
        **{path: (401, {"error": "session_required"}) for path in posts[2:]},
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

def delete_with_preconditions_v4(r: Runner, kubeconfig: str, created: CreatedV4, timeout: int = 120, snapshot: KubeconfigSnapshot | None = None) -> dict[str, Any]:
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
    require(snapshot is not None, "authenticated Kubernetes DELETE snapshot absent")
    raw_delete(snapshot, resource_path, payload, min(15, timeout))
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
    generation, observed = metadata.get("generation"), status.get("observedGeneration")
    # A Kustomization created suspended is intentionally never reconciled;
    # Flux reports observedGeneration=-1 for that safe dormant state. Suspend
    # also does not cancel work already in flight, so any active Reconciling
    # condition remains a hard failure regardless of its generation.
    require(
        type(generation) is int
        and generation >= 1
        and type(observed) is int
        and -1 <= observed <= generation,
        f"{owner} suspended observedGeneration invalid",
    )
    for condition in status.get("conditions", []):
        require(isinstance(condition, dict), f"{owner} suspended condition invalid")
        if condition.get("type") == "Reconciling" and condition.get("status") == "True":
            raise ActivationError(f"{owner} still Reconciling while suspended")
    return {"uid": uid, "resourceVersion": metadata.get("resourceVersion"), "generation": generation, "observedGeneration": observed, "suspended": True, "reconcilingCurrentGeneration": False}

def wait_both_suspended_v4(r: Runner, kubeconfig: str, p: dict[str, Any], bootstrap: dict[str, Any], deadline: float) -> dict[str, Any]:
    result: dict[str, Any] = {}; poll = p["httpBoundary"]["timeoutsSeconds"]["rollbackPoll"]
    for owner in ("gateway", "workbenchIngress"):
        target = p["gitOps"]["reconcilers"][owner]["kustomization"]
        uid = bootstrap["owners"][owner]["kustomization"]["metadata"]["uid"]
        expected = (
            POLICY.gateway_flux_objects(suspended=True)["kustomization"]
            if owner == "gateway"
            else POLICY.workbench_ingress_flux_objects(suspended=True)["kustomization"]
        )
        while True:
            require(time.monotonic() < deadline, f"{owner} rollback suspension timeout")
            current = _target_live(r, kubeconfig, target)
            try:
                _policy_call(POLICY.require_semantically_equal, current, expected, f"{owner} rollback suspended semantics")
                result[owner] = _flux_suspended_and_quiescent_v4(current, owner, uid); break
            except ActivationError as exc:
                if "UID" in str(exc) or "identity drift" in str(exc) or "semantics" in str(exc): raise
                time.sleep(poll)
    return result

def validate_recovery_incident_binding_v4(value: Any) -> dict[str, Any]:
    require(
        isinstance(value, dict)
        and set(value) == {
            "originProtectedRevision", "originRawSha256", "originReceiptSha256",
            "operationNonce", "objects", "serviceExposureBreakProved",
            "ingressNeverCreated", "civicAuthorityEffects",
        }
        and value.get("originProtectedRevision") == FAILED_ACTIVATION_ORIGIN_REVISION
        and value.get("originRawSha256") == FAILED_ACTIVATION_RAW_SHA256
        and value.get("originReceiptSha256") == FAILED_ACTIVATION_CANONICAL_SHA256
        and value.get("operationNonce") == FAILED_ACTIVATION_OPERATION_NONCE
        and value.get("serviceExposureBreakProved") is True
        and value.get("ingressNeverCreated") is True
        and value.get("civicAuthorityEffects") is False,
        "failed activation recovery incident binding drift",
    )
    expected_objects = {
        logical: record
        for logical, record in zip(FAILED_ACTIVATION_CREATED_ORDER, FAILED_ACTIVATION_OBJECT_CREATE_RESULTS)
    }
    require(value.get("objects") == expected_objects, "failed activation recovery object binding drift")
    return copy.deepcopy(value)

def _recovery_receipt_stub_v4(desired: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    observed = copy.deepcopy(desired)
    observed.setdefault("metadata", {})["uid"] = record["uid"]
    observed["metadata"]["resourceVersion"] = record["postNonceRemovalResourceVersion"]
    return observed

def bind_recovery_targets_v4(
    r: Runner,
    kubeconfig: str,
    rendered: dict[str, dict[str, Any]],
    incident: dict[str, Any],
) -> dict[str, Any]:
    """GET-only classification of all six names before recovery may delete."""
    incident = validate_recovery_incident_binding_v4(incident)
    require(
        set(rendered) == {
            "gateway.networkPolicy", "workbenchIngress.networkPolicy",
            "gateway.serviceAccount", "gateway.service",
            "gateway.deployment", "gateway.ingress",
        },
        "recovery exact six-target render inventory drift",
    )
    created: list[CreatedV4] = []
    classifications: dict[str, Any] = {}
    receipt_owned = incident["objects"]
    for logical_name in FAILED_ACTIVATION_CREATED_ORDER:
        entry = rendered[logical_name]; desired = entry["desired"]; metadata = desired["metadata"]
        record = receipt_owned[logical_name]
        incident_desired = _policy_call(POLICY.with_operation_nonce, desired, incident["operationNonce"])
        require(
            entry.get("path") == record["protectedRenderPath"]
            and entry.get("blobSha256") == record["protectedRenderBlobSha256"]
            and POLICY.semantic_sha256(incident_desired) == record["semanticSha256"]
            and record["target"] == {
                "apiVersion": desired["apiVersion"], "kind": desired["kind"],
                "namespace": metadata["namespace"], "name": metadata["name"],
            },
            f"{logical_name} current protected render no longer matches incident",
        )
        current = get_optional(r, kubeconfig, desired["kind"].lower(), metadata["name"], metadata["namespace"])
        if logical_name == "gateway.service":
            require(current is None, "gateway.service must remain absent before recovery")
            observed = _recovery_receipt_stub_v4(desired, record)
            classifications[logical_name] = {
                "state": "absent-exposure-break-proved", "uid": record["uid"],
                "sourceReceiptSha256": incident["originReceiptSha256"],
            }
        elif current is None:
            # Idempotent retry after an earlier recovery deleted this exact
            # receipt-owned object. Keep its UID stub so the final quiet scan
            # still rejects any replacement under the same name.
            observed = _recovery_receipt_stub_v4(desired, record)
            classifications[logical_name] = {
                "state": "already-absent-receipt-owned", "uid": record["uid"],
                "sourceReceiptSha256": incident["originReceiptSha256"],
            }
        else:
            require(current.get("metadata", {}).get("uid") == record["uid"], f"{logical_name} incident UID drift")
            _policy_call(POLICY.require_semantically_equal, current, desired, f"{logical_name} recovery semantics")
            observed = current
            classifications[logical_name] = {
                "state": "present-exact-receipt-owned", "uid": record["uid"],
                "resourceVersion": current.get("metadata", {}).get("resourceVersion"),
                "sourceReceiptSha256": incident["originReceiptSha256"],
            }
        created.append(CreatedV4(logical_name, desired, observed, copy.deepcopy(record) | {"recoverySource": True}))

    deployment_entry = rendered["gateway.deployment"]
    deployment_desired = deployment_entry["desired"]
    deployment_metadata = deployment_desired["metadata"]
    deployment = get_optional(
        r, kubeconfig, "deployment", deployment_metadata["name"], deployment_metadata["namespace"]
    )
    if deployment is None:
        classifications["gateway.deployment"] = {
            "state": "absent-unresolved-create",
            "dependents": deployment_dependents_absent_v4(r, kubeconfig),
        }
    else:
        nonce_desired = _policy_call(POLICY.with_operation_nonce, deployment_desired, incident["operationNonce"])
        deployment_receipt = _policy_call(
            POLICY.bind_create_result,
            outcome="post-send-uncertain-discovered",
            observed=deployment,
            desired=nonce_desired,
            label="gateway.deployment recovery",
            operation_nonce=incident["operationNonce"],
        )
        deployment_receipt |= {
            "protectedRenderPath": deployment_entry["path"],
            "protectedRenderBlobSha256": deployment_entry["blobSha256"],
            "temporaryNonceRemoved": False,
            "recoveredFromFailedReceiptSha256": incident["originReceiptSha256"],
        }
        created.append(CreatedV4("gateway.deployment", deployment_desired, deployment, deployment_receipt))
        classifications["gateway.deployment"] = {
            "state": "present-exact-failed-nonce-owned",
            "uid": deployment_receipt["uid"],
            "resourceVersion": deployment_receipt["resourceVersion"],
            "operationNonce": incident["operationNonce"],
        }

    ingress_entry = rendered["gateway.ingress"]
    ingress_desired = ingress_entry["desired"]
    ingress_metadata = ingress_desired["metadata"]
    ingress = get_optional(r, kubeconfig, "ingress", ingress_metadata["name"], ingress_metadata["namespace"])
    require(ingress is None, "gateway.ingress must remain absent before recovery")
    classifications["gateway.ingress"] = {
        "state": "absent-never-created", "sourceReceiptSha256": incident["originReceiptSha256"],
    }
    require(len(classifications) == 6, "recovery target classification incomplete")
    return {"created": created, "classifications": classifications}

def recovery_flux_preflight_v4(bootstrap: dict[str, Any]) -> dict[str, Any]:
    require(isinstance(bootstrap, dict) and set(bootstrap.get("owners", {})) == {"gateway", "workbenchIngress"}, "recovery dormant Flux ownership incomplete")
    result = {}
    for owner in ("gateway", "workbenchIngress"):
        current = bootstrap["owners"][owner]["kustomization"]
        uid = current.get("metadata", {}).get("uid")
        require(isinstance(uid, str) and uid, f"{owner} recovery Kustomization UID absent")
        bound = _flux_suspended_and_quiescent_v4(current, owner, uid)
        # This is deliberately narrower than the general rollback helper. The
        # two participant Kustomizations were created suspended at generation
        # one and have never reconciled. A stale-but-previously-observed state
        # may be safe for an ordinary rollback, but it is not the exact failed
        # transaction authorized by the pinned incident receipt.
        require(
            bound["generation"] == 1 and bound["observedGeneration"] == -1,
            f"{owner} recovery Kustomization is not the exact dormant incident state",
        )
        result[owner] = bound
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
            ingress_result = delete_with_preconditions_v4(r, kubeconfig, ingress, max(1, int(deadline - time.monotonic())), snapshot)
            deleted.append(ingress_result); ingress_absence_proved = ingress_result.get("absent") is True
        except Exception as exc: errors.append(str(exc))
    # A 409 or unbindable create response is never authority to touch an
    # unknown Ingress. Always sever the exact transaction-owned backend before
    # waiting on Flux: even an initially deleted owned Ingress can be recreated
    # with a new UID before a failing reconciler becomes quiescent.
    if rollback_authorized and exposure_service is not None:
        try:
            service_result = delete_with_preconditions_v4(r, kubeconfig, exposure_service, max(1, int(deadline - time.monotonic())), snapshot)
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
                deleted.append(delete_with_preconditions_v4(r, kubeconfig, ingress, max(1, int(deadline - time.monotonic())), snapshot))
        except Exception as exc: errors.append(str(exc))
    # Re-prove the exposure breaker after the Flux/reappearance phase even
    # when that phase produced an error. A controller may have recreated the
    # Service alongside an unknown Ingress; only the original exact UID and
    # protected semantics remain deletable by this transaction.
    if rollback_authorized and exposure_service is not None and bootstrap is not None:
        try:
            service_after_flux = delete_with_preconditions_v4(r, kubeconfig, exposure_service, max(1, int(deadline - time.monotonic())), snapshot)
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
                deleted.append(delete_with_preconditions_v4(r, kubeconfig, deployment, max(1, int(deadline - time.monotonic())), snapshot))
                final_checks["deploymentDependents"] = deployment_dependents_absent_v4(r, kubeconfig)
                remaining.remove(deployment)
            except Exception as exc: errors.append(str(exc))
        if not errors:
            for item in reversed(remaining):
                try: deleted.append(delete_with_preconditions_v4(r, kubeconfig, item, max(1, int(deadline - time.monotonic())), snapshot))
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
            final_checks["sharedSource"] = {
                "uid": source["metadata"]["uid"],
                "resourceVersion": source["metadata"]["resourceVersion"],
                "artifactRevision": source["status"]["artifact"]["revision"],
                "unchanged": True,
            }
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

def recovery_source_preflight_v4(source: dict[str, Any], rev: str) -> dict[str, Any]:
    metadata, status = source.get("metadata", {}), source.get("status", {})
    generation, observed = metadata.get("generation"), status.get("observedGeneration")
    ready = next((item for item in status.get("conditions", []) if item.get("type") == "Ready"), None)
    require(
        isinstance(metadata.get("uid"), str)
        and bool(metadata["uid"])
        and recovery_ascii_decimal_v4(metadata.get("resourceVersion"))
        and type(generation) is int
        and generation >= 1
        and type(observed) is int
        and observed == generation
        and status.get("artifact", {}).get("revision") == f"main@sha1:{rev}"
        and isinstance(ready, dict)
        and ready.get("status") == "True",
        "recovery shared Source preflight drift",
    )
    return {
        "uid": metadata["uid"],
        "resourceVersion": metadata["resourceVersion"],
        "generation": generation,
        "observedGeneration": observed,
        "artifactRevision": f"main@sha1:{rev}",
        "ready": True,
    }

def recovery_dormant_receipt_preflight_v4(bootstrap: dict[str, Any], rev: str) -> dict[str, Any]:
    receipt = bootstrap.get("bootstrapReceipt")
    require(
        isinstance(receipt, dict)
        and set(receipt) == {"receiptSha256", "protectedRevision", "objects"}
        and isinstance(receipt.get("receiptSha256"), str)
        and POLICY.SHA256.fullmatch(receipt["receiptSha256"]) is not None
        and receipt.get("protectedRevision") == rev
        and isinstance(receipt.get("objects"), list),
        "recovery dormant handover receipt preflight drift",
    )
    objects = receipt["objects"]
    require(
        len(objects) == len(POLICY.DORMANT_BOOTSTRAP_OBJECT_ORDER)
        and all(isinstance(item, dict) for item in objects)
        and [item.get("logicalName") for item in objects] == list(POLICY.DORMANT_BOOTSTRAP_OBJECT_ORDER),
        "recovery dormant handover object inventory drift",
    )
    by_name = {item["logicalName"]: item for item in objects}
    require(len(by_name) == len(objects), "recovery dormant handover object names duplicated")
    kustomization_uids = {}
    for owner in ("gateway", "workbenchIngress"):
        record = by_name[f"{owner}.kustomization"]
        live_uid = bootstrap.get("owners", {}).get(owner, {}).get("kustomization", {}).get("metadata", {}).get("uid")
        require(
            isinstance(record.get("uid"), str)
            and bool(record["uid"])
            and record["uid"] == live_uid,
            f"{owner} recovery dormant handover Kustomization UID drift",
        )
        kustomization_uids[owner] = record["uid"]
    return {
        "receiptSha256": receipt["receiptSha256"],
        "protectedRevision": rev,
        "kustomizationUids": kustomization_uids,
    }

def recovery_ascii_decimal_v4(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*", value) is not None

def validate_recovery_flux_projection_v4(value: Any, label: str) -> dict[str, Any]:
    require(
        isinstance(value, dict)
        and set(value) == {
            "uid", "resourceVersion", "generation", "observedGeneration",
            "suspended", "reconcilingCurrentGeneration",
        }
        and isinstance(value.get("uid"), str)
        and bool(value["uid"])
        and recovery_ascii_decimal_v4(value.get("resourceVersion"))
        and type(value.get("generation")) is int
        and value["generation"] == 1
        and type(value.get("observedGeneration")) is int
        and value["observedGeneration"] == -1
        and value.get("suspended") is True
        and value.get("reconcilingCurrentGeneration") is False,
        f"{label} is not the exact dormant incident Flux state",
    )
    return copy.deepcopy(value)

def validate_recovery_dependent_absence_v4(value: Any, label: str) -> dict[str, Any]:
    require(
        isinstance(value, dict)
        and set(value) == {"status", "resources"}
        and value.get("status") == "deployment-foreground-dependents-absent"
        and isinstance(value.get("resources"), dict)
        and set(value["resources"]) == {"pods", "replicasets.apps"},
        f"{label} field set drift",
    )
    for resource in ("pods", "replicasets.apps"):
        proof = value["resources"][resource]
        require(
            isinstance(proof, dict)
            and set(proof) == {"selector", "count"}
            and proof.get("selector") == POLICY.GATEWAY_LABELS
            and type(proof.get("count")) is int
            and proof["count"] == 0,
            f"{label} drift: {resource}",
        )
    return copy.deepcopy(value)

def validate_recovery_quiet_absence_v4(value: Any, p: dict[str, Any]) -> dict[str, Any]:
    require(
        isinstance(value, dict)
        and set(value) == {"status", "quietSeconds", "checks"}
        and value.get("status") == "all-six-names-absent-for-quiet-interval"
        and type(value.get("quietSeconds")) in {int, float}
        and value["quietSeconds"] == p["httpBoundary"]["timeoutsSeconds"]["rollbackAbsenceQuiet"]
        and type(value.get("checks")) is int
        and value["checks"] >= 2,
        "recovery rollback all-target quiet absence proof drift",
    )
    return copy.deepcopy(value)

def validate_recovery_preservation_proof_v4(value: Any, p: dict[str, Any], label: str) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == set(p["preservation"]), f"{label} set drift")
    result = {}
    for name, descriptor in p["preservation"].items():
        proof = value[name]
        require(
            isinstance(proof, dict)
            and set(proof) == {
                "target", "beforeCanonicalSha256", "afterCanonicalSha256",
                "byteIdenticalCanonicalJson",
            }
            and proof.get("target") == descriptor["target"]
            and isinstance(proof.get("beforeCanonicalSha256"), str)
            and POLICY.SHA256.fullmatch(proof["beforeCanonicalSha256"]) is not None
            and proof.get("afterCanonicalSha256") == proof["beforeCanonicalSha256"]
            and proof.get("byteIdenticalCanonicalJson") is True,
            f"{label} drift: {name}",
        )
        result[name] = copy.deepcopy(proof)
    return result

def validate_recovery_preflight_receipt_v4(
    preflight: Any,
    p: dict[str, Any],
    rev: str,
) -> dict[str, Any]:
    require(
        isinstance(preflight, dict)
        and set(preflight) == {
            "clusterBinding", "dormantReceipt", "flux", "source", "targets", "preservation",
        },
        "recovery receipt preflight field set drift",
    )
    cluster = preflight.get("clusterBinding")
    require(isinstance(cluster, dict) and set(cluster) == {"initial", "beforeRollback"}, "recovery receipt cluster preflight drift")
    initial = validate_bound_cluster_identity_v4(cluster.get("initial"), p, "recovery receipt initial cluster")
    before_rollback = validate_bound_cluster_identity_v4(cluster.get("beforeRollback"), p, "recovery receipt pre-rollback cluster")
    require(
        recovery_ascii_decimal_v4(initial["kubeSystemNamespaceResourceVersion"])
        and recovery_ascii_decimal_v4(before_rollback["kubeSystemNamespaceResourceVersion"]),
        "recovery receipt cluster resourceVersion is not ASCII decimal",
    )
    require_same_cluster_identity_v4(initial, before_rollback, "in recovery receipt preflight")
    require(
        int(before_rollback["kubeSystemNamespaceResourceVersion"])
        >= int(initial["kubeSystemNamespaceResourceVersion"]),
        "recovery receipt cluster resourceVersion moved backwards",
    )
    dormant = preflight.get("dormantReceipt")
    require(
        isinstance(dormant, dict)
        and set(dormant) == {"receiptSha256", "protectedRevision", "kustomizationUids"}
        and isinstance(dormant.get("receiptSha256"), str)
        and POLICY.SHA256.fullmatch(dormant["receiptSha256"]) is not None
        and dormant.get("protectedRevision") == rev
        and isinstance(dormant.get("kustomizationUids"), dict)
        and set(dormant["kustomizationUids"]) == {"gateway", "workbenchIngress"},
        "recovery receipt dormant handover binding drift",
    )
    flux = preflight.get("flux")
    require(isinstance(flux, dict) and set(flux) == {"gateway", "workbenchIngress"}, "recovery receipt Flux preflight incomplete")
    for owner in ("gateway", "workbenchIngress"):
        proof = validate_recovery_flux_projection_v4(flux[owner], f"recovery receipt {owner} Flux preflight")
        require(proof["uid"] == dormant["kustomizationUids"].get(owner), f"recovery receipt {owner} Flux/handover UID drift")
    source = preflight.get("source")
    require(
        isinstance(source, dict)
        and set(source) == {"uid", "resourceVersion", "generation", "observedGeneration", "artifactRevision", "ready"}
        and isinstance(source.get("uid"), str)
        and bool(source["uid"])
        and recovery_ascii_decimal_v4(source.get("resourceVersion"))
        and type(source.get("generation")) is int
        and source["generation"] >= 1
        and type(source.get("observedGeneration")) is int
        and source.get("observedGeneration") == source["generation"]
        and source.get("artifactRevision") == f"main@sha1:{rev}"
        and source.get("ready") is True,
        "recovery receipt shared Source preflight drift",
    )
    targets = preflight.get("targets")
    expected_targets = {
        "gateway.networkPolicy", "workbenchIngress.networkPolicy", "gateway.serviceAccount",
        "gateway.service", "gateway.deployment", "gateway.ingress",
    }
    require(isinstance(targets, dict) and set(targets) == expected_targets and all(isinstance(value, dict) for value in targets.values()), "recovery receipt target preflight incomplete")
    for logical_name in ("gateway.networkPolicy", "workbenchIngress.networkPolicy", "gateway.serviceAccount"):
        state = targets[logical_name]
        if state.get("state") == "present-exact-receipt-owned":
            require(
                set(state) == {"state", "uid", "resourceVersion", "sourceReceiptSha256"},
                f"recovery receipt present target field set drift: {logical_name}",
            )
        else:
            require(
                set(state) == {"state", "uid", "sourceReceiptSha256"},
                f"recovery receipt absent target field set drift: {logical_name}",
            )
        require(
            state.get("state") in {"present-exact-receipt-owned", "already-absent-receipt-owned"}
            and state.get("uid") == FAILED_ACTIVATION_OBJECT_UIDS[logical_name]
            and state.get("sourceReceiptSha256") == FAILED_ACTIVATION_CANONICAL_SHA256,
            f"recovery receipt target ownership drift: {logical_name}",
        )
        if state["state"] == "present-exact-receipt-owned":
            require(
                recovery_ascii_decimal_v4(state.get("resourceVersion")),
                f"recovery receipt target resourceVersion drift: {logical_name}",
            )
    service = targets["gateway.service"]
    require(
        set(service) == {"state", "uid", "sourceReceiptSha256"}
        and service.get("state") == "absent-exposure-break-proved"
        and service.get("uid") == FAILED_ACTIVATION_OBJECT_UIDS["gateway.service"]
        and service.get("sourceReceiptSha256") == FAILED_ACTIVATION_CANONICAL_SHA256,
        "recovery receipt Service preflight drift",
    )
    ingress = targets["gateway.ingress"]
    require(
        ingress == {"state": "absent-never-created", "sourceReceiptSha256": FAILED_ACTIVATION_CANONICAL_SHA256},
        "recovery receipt Ingress preflight drift",
    )
    deployment = targets["gateway.deployment"]
    if deployment.get("state") == "present-exact-failed-nonce-owned":
        require(
            set(deployment) == {"state", "uid", "resourceVersion", "operationNonce"}
            and isinstance(deployment.get("uid"), str)
            and bool(deployment["uid"])
            and recovery_ascii_decimal_v4(deployment.get("resourceVersion"))
            and deployment.get("operationNonce") == FAILED_ACTIVATION_OPERATION_NONCE,
            "recovery receipt Deployment ownership drift",
        )
    else:
        require(
            set(deployment) == {"state", "dependents"}
            and deployment.get("state") == "absent-unresolved-create"
            and isinstance(deployment.get("dependents"), dict)
            and deployment["dependents"].get("status") == "deployment-foreground-dependents-absent",
            "recovery receipt absent Deployment proof drift",
        )
        validate_recovery_dependent_absence_v4(
            deployment["dependents"], "recovery receipt absent Deployment dependents",
        )
    validate_recovery_preservation_proof_v4(preflight.get("preservation"), p, "recovery receipt preservation preflight")
    return copy.deepcopy(preflight)

def validate_complete_recovery_rollback_v4(
    rollback: Any,
    preflight: dict[str, Any],
    p: dict[str, Any],
    rev: str,
) -> None:
    preflight = validate_recovery_preflight_receipt_v4(preflight, p, rev)
    flux = rollback.get("flux") if isinstance(rollback, dict) else None
    require(
        isinstance(rollback, dict)
        and set(rollback) == {
            "status", "bothKustomizationsSuspended", "flux", "deleted",
            "finalChecks", "preservation", "uncertainTarget", "errors",
            "finalizersRemovedByRunner",
        }
        and rollback.get("status") == "complete"
        and rollback.get("bothKustomizationsSuspended") is True
        and isinstance(flux, dict)
        and set(flux) == {"gateway", "workbenchIngress"}
        and rollback.get("uncertainTarget") is None
        and rollback.get("errors") == []
        and rollback.get("finalizersRemovedByRunner") is False,
        "recovery rollback incomplete",
    )
    for owner in ("gateway", "workbenchIngress"):
        before = preflight["flux"][owner]
        current = validate_recovery_flux_projection_v4(flux[owner], f"recovery rollback {owner} Flux")
        require(
            current["uid"] == before["uid"]
            and current["generation"] == before["generation"]
            and current["observedGeneration"] == before["observedGeneration"]
            and int(current["resourceVersion"]) >= int(before["resourceVersion"]),
            f"recovery rollback {owner} Flux no longer binds preflight",
        )

    deleted = rollback.get("deleted")
    require(isinstance(deleted, list) and all(isinstance(item, dict) for item in deleted), "recovery rollback deletion proof absent")
    deployment_present = preflight["targets"]["gateway.deployment"]["state"] == "present-exact-failed-nonce-owned"
    expected_order = ["gateway.service", "gateway.service"]
    if deployment_present:
        expected_order.append("gateway.deployment")
    expected_order.extend(("gateway.serviceAccount", "workbenchIngress.networkPolicy", "gateway.networkPolicy"))
    require(
        [item.get("logicalName") for item in deleted] == expected_order
        and all(item.get("absent") is True for item in deleted),
        "recovery rollback deletion order or absence proof drift",
    )
    service_records = deleted[:2]
    require(
        all(
            set(item) == {"logicalName", "absent", "alreadyAbsent"}
            and item.get("alreadyAbsent") is True
            for item in service_records
        ),
        "recovery rollback Service absence no longer binds failed exposure break",
    )
    by_name = {item["logicalName"]: item for item in deleted[2:]}
    for logical_name in ("gateway.serviceAccount", "workbenchIngress.networkPolicy", "gateway.networkPolicy"):
        record = by_name[logical_name]
        target = preflight["targets"][logical_name]
        if target["state"] == "present-exact-receipt-owned":
            require(
                set(record) == {
                    "logicalName", "uid", "deleteResourceVersion", "absent",
                    "foregroundPropagation", "finalizersRemovedByRunner",
                }
                and record.get("uid") == target["uid"] == FAILED_ACTIVATION_OBJECT_UIDS[logical_name]
                and recovery_ascii_decimal_v4(record.get("deleteResourceVersion"))
                and int(record["deleteResourceVersion"]) >= int(target["resourceVersion"])
                and record.get("absent") is True
                and record.get("foregroundPropagation") is False
                and record.get("finalizersRemovedByRunner") is False,
                f"recovery rollback deletion UID drift: {logical_name}",
            )
        else:
            require(
                set(record) == {"logicalName", "absent", "alreadyAbsent"}
                and record.get("absent") is True
                and record.get("alreadyAbsent") is True,
                f"recovery rollback already-absent proof drift: {logical_name}",
            )
    deployment_records = [item for item in deleted if item.get("logicalName") == "gateway.deployment"]
    if deployment_present:
        require(
            len(deployment_records) == 1
            and set(deployment_records[0]) == {
                "logicalName", "uid", "deleteResourceVersion", "absent",
                "foregroundPropagation", "finalizersRemovedByRunner",
            }
            and deployment_records[0].get("uid") == preflight["targets"]["gateway.deployment"]["uid"]
            and recovery_ascii_decimal_v4(deployment_records[0].get("deleteResourceVersion"))
            and int(deployment_records[0]["deleteResourceVersion"])
            >= int(preflight["targets"]["gateway.deployment"]["resourceVersion"])
            and deployment_records[0].get("absent") is True
            and deployment_records[0].get("foregroundPropagation") is True
            and deployment_records[0].get("finalizersRemovedByRunner") is False,
            "recovery Deployment deletion no longer binds preflight ownership",
        )
    else:
        require(not deployment_records, "recovery deleted a Deployment absent from preflight")
    final = rollback.get("finalChecks"); final_flux = final.get("flux") if isinstance(final, dict) else None
    deployment_final_key = "deploymentDependents" if deployment_present else "unboundDeploymentRuntime"
    require(
        isinstance(final, dict)
        and set(final) == {
            "clusterBindingBeforeRollback", "exposureBreak", "exposureBreakAfterFlux",
            deployment_final_key, "absence", "flux", "sharedSource", "clusterBinding",
        }
        and isinstance(final_flux, dict)
        and set(final_flux) == {"gateway", "workbenchIngress"},
        "recovery rollback final proof incomplete",
    )
    validate_recovery_quiet_absence_v4(final.get("absence"), p)
    initial_cluster = preflight["clusterBinding"]["initial"]
    rollback_entry_cluster = validate_bound_cluster_identity_v4(
        final.get("clusterBindingBeforeRollback"), p, "recovery rollback entry cluster",
    )
    final_cluster = validate_bound_cluster_identity_v4(final.get("clusterBinding"), p, "recovery rollback final cluster")
    require(
        recovery_ascii_decimal_v4(rollback_entry_cluster["kubeSystemNamespaceResourceVersion"])
        and recovery_ascii_decimal_v4(final_cluster["kubeSystemNamespaceResourceVersion"]),
        "recovery rollback cluster resourceVersion is not ASCII decimal",
    )
    require_same_cluster_identity_v4(initial_cluster, rollback_entry_cluster, "at recovery rollback entry")
    require_same_cluster_identity_v4(initial_cluster, final_cluster, "at recovery rollback completion")
    initial_cluster_rv = int(initial_cluster["kubeSystemNamespaceResourceVersion"])
    require(
        int(rollback_entry_cluster["kubeSystemNamespaceResourceVersion"]) >= initial_cluster_rv
        and int(final_cluster["kubeSystemNamespaceResourceVersion"])
        >= int(rollback_entry_cluster["kubeSystemNamespaceResourceVersion"]),
        "recovery rollback cluster resourceVersion moved backwards",
    )
    for owner in ("gateway", "workbenchIngress"):
        rollback_flux = flux[owner]
        after = validate_recovery_flux_projection_v4(final_flux[owner], f"recovery final {owner} Flux")
        require(
            after["uid"] == rollback_flux["uid"]
            and after["generation"] == rollback_flux["generation"]
            and after["observedGeneration"] == rollback_flux["observedGeneration"]
            and int(after["resourceVersion"]) >= int(rollback_flux["resourceVersion"]),
            f"recovery final {owner} Flux no longer binds rollback",
        )
    source = final.get("sharedSource")
    require(
        isinstance(source, dict)
        and set(source) == {"uid", "resourceVersion", "artifactRevision", "unchanged"}
        and source.get("uid") == preflight["source"]["uid"]
        and recovery_ascii_decimal_v4(source.get("resourceVersion"))
        and int(source["resourceVersion"]) >= int(preflight["source"]["resourceVersion"])
        and source.get("artifactRevision") == preflight["source"]["artifactRevision"] == f"main@sha1:{rev}"
        and source.get("unchanged") is True,
        "recovery rollback shared Source no longer binds preflight",
    )
    exposure = final.get("exposureBreak")
    exposure_after = final.get("exposureBreakAfterFlux")
    require(
        isinstance(exposure, dict)
        and set(exposure) == {
            "reason", "initialIngressAbsenceProved", "serviceUid",
            "serviceAbsent", "unknownIngressUntouched",
        }
        and exposure.get("reason") == "always-remove-owned-service-before-flux"
        and exposure.get("initialIngressAbsenceProved") is False
        and exposure.get("serviceUid") == FAILED_ACTIVATION_OBJECT_UIDS["gateway.service"]
        and exposure.get("serviceAbsent") is True
        and exposure.get("unknownIngressUntouched") is True
        and isinstance(exposure_after, dict)
        and set(exposure_after) == {"serviceUid", "serviceAbsent", "sameOwnedUidOnly"}
        and exposure_after.get("serviceUid") == FAILED_ACTIVATION_OBJECT_UIDS["gateway.service"]
        and exposure_after.get("serviceAbsent") is True
        and exposure_after.get("sameOwnedUidOnly") is True,
        "recovery rollback exposure-break proof drift",
    )
    if deployment_present:
        dependents = final.get("deploymentDependents")
        require("unboundDeploymentRuntime" not in final, "recovery rollback mixed bound/unbound Deployment proof")
    else:
        runtime = final.get("unboundDeploymentRuntime")
        require(
            isinstance(runtime, dict)
            and set(runtime) == {"deploymentNameAbsent", "dependents", "gatewayIsolationRetainedUntilProof"}
            and runtime.get("deploymentNameAbsent") is True
            and runtime.get("gatewayIsolationRetainedUntilProof") is True
            and "deploymentDependents" not in final,
            "recovery unbound Deployment runtime proof incomplete",
        )
        dependents = runtime.get("dependents")
    validate_recovery_dependent_absence_v4(dependents, "recovery Deployment dependent absence")
    preservation = validate_recovery_preservation_proof_v4(
        rollback.get("preservation"), p, "recovery rollback preservation",
    )
    for name in p["preservation"]:
        require(
            preservation[name]["beforeCanonicalSha256"]
            == preservation[name]["afterCanonicalSha256"]
            == preflight["preservation"][name]["beforeCanonicalSha256"]
            == preflight["preservation"][name]["afterCanonicalSha256"],
            f"recovery rollback preservation no longer binds preflight: {name}",
        )

def recover_incomplete_activation_v4(
    p: dict[str, Any],
    rev: str,
    kube: str | None,
    r: Runner,
    sink: ReceiptSink,
    runner_hashes: dict[str, str],
    dormant_ownership: dict[str, Any],
    incident: dict[str, Any],
) -> dict[str, Any]:
    """Recover only the pinned failed transaction; never activate afterward."""
    _policy_call(POLICY.assert_activation_ready, p)
    require(kube is not None and Path(kube).is_file(), "live recovery requires explicit existing kubeconfig")
    require(
        isinstance(dormant_ownership, dict)
        and dormant_ownership.get("receiptProvenance", {}).get("mode") == "archived-v1+get-only-handover",
        "recovery requires a fresh GET-only dormant handover receipt",
    )
    incident = validate_recovery_incident_binding_v4(incident)
    rendered = render_v4(rev, p)
    snapshot: KubeconfigSnapshot | None = None
    previous_signal_handlers = install_transaction_signal_handlers_v4()
    try:
        try:
            snapshot = snapshot_kubeconfig_v4(kube, r); snapshot_path = str(snapshot.path)
            initial_cluster = cluster_binding_v4(r, snapshot, p)
            handover_cluster = validate_bound_cluster_identity_v4(dormant_ownership.get("clusterBinding"), p, "recovery dormant handover")
            require_same_cluster_identity_v4(initial_cluster, handover_cluster, "recovery dormant handover continuation")
            preserved = preservation_v4(r, snapshot_path, p)
            require_current_preservation_binding_v4(preserved, dormant_ownership, p)
            bootstrap = flux_preflight_v4(r, snapshot_path, p, rev, dormant_ownership)
            flux = recovery_flux_preflight_v4(bootstrap)
            targets = bind_recovery_targets_v4(r, snapshot_path, rendered, incident)
            preservation_before = verify_preservation_v4(r, snapshot_path, preserved)
            before_rollback = cluster_binding_v4(r, snapshot, p)
            require_same_cluster_identity_v4(initial_cluster, before_rollback, "before incident recovery rollback")
            preflight = {
                "clusterBinding": {"initial": initial_cluster, "beforeRollback": before_rollback},
                "dormantReceipt": recovery_dormant_receipt_preflight_v4(bootstrap, rev),
                "flux": flux,
                "source": recovery_source_preflight_v4(bootstrap["source"], rev),
                "targets": targets["classifications"],
                "preservation": preservation_before,
            }
            validate_recovery_preflight_receipt_v4(preflight, p, rev)
        except (Exception, KeyboardInterrupt) as exc:
            blocked = {
                "schemaVersion": RECOVERY_RECEIPT_SCHEMA,
                "status": "recovery-blocked",
                "protectedRevision": rev,
                "activationPolicySha256": POLICY.activation_policy_sha256(p),
                "protectedRunnerFileSha256": runner_hashes,
                "recoveredIncident": incident,
                "failure": str(exc) or "incident recovery preflight interrupted",
                "mutationStarted": False,
                "automaticActivationRetry": False,
                "civicAuthorityEffects": False,
            }
            defer_transaction_signals_v4(); sink.commit(blocked)
            raise ActivationError(f"recovery blocked before mutation: {blocked['failure']}") from exc

        # Recovery deletion is itself the bounded rollback. Defer termination
        # for this existing transaction exactly as ordinary activation does.
        defer_transaction_signals_v4()
        try:
            rollback = rollback_v4(
                r,
                snapshot_path,
                p,
                targets["created"],
                bootstrap,
                preserved,
                None,
                rendered=rendered,
                snapshot=snapshot,
                initial_cluster=initial_cluster,
            )
        except (Exception, KeyboardInterrupt) as exc:
            rollback = {
                "status": "incomplete", "bothKustomizationsSuspended": False,
                "flux": {}, "deleted": [], "finalChecks": {}, "preservation": {},
                "uncertainTarget": None, "errors": [str(exc) or "incident recovery interrupted"],
                "finalizersRemovedByRunner": False,
            }
        try:
            validate_complete_recovery_rollback_v4(rollback, preflight, p, rev)
            status = "recovered"
        except ActivationError:
            status = "recovery-incomplete"
        result = {
            "schemaVersion": RECOVERY_RECEIPT_SCHEMA,
            "status": status,
            "protectedRevision": rev,
            "activationPolicySha256": POLICY.activation_policy_sha256(p),
            "protectedRunnerFileSha256": runner_hashes,
            "recoveredIncident": incident,
            "preflight": preflight,
            "rollback": rollback,
            "automaticActivationRetry": False,
            "civicAuthorityEffects": False,
        }
        sink.commit(result)
        if status != "recovered":
            raise ActivationError("incident recovery incomplete; durable receipt written")
        return result
    finally:
        try:
            if snapshot is not None: snapshot.close()
        finally:
            restore_transaction_signal_handlers_v4(previous_signal_handlers)

def bind_recovery_receipt_v4(
    receipt: dict[str, Any],
    p: dict[str, Any],
    rev: str,
    runner_hashes: dict[str, str],
) -> dict[str, Any]:
    require(isinstance(receipt, dict), "recovery receipt must be an object")
    require(
        set(receipt) == {
            "schemaVersion", "status", "protectedRevision", "activationPolicySha256",
            "protectedRunnerFileSha256", "recoveredIncident", "preflight", "rollback",
            "automaticActivationRetry", "civicAuthorityEffects", "canonicalSha256",
        },
        "recovery receipt field set drift",
    )
    checksum = receipt.get("canonicalSha256")
    unsigned = {key: copy.deepcopy(value) for key, value in receipt.items() if key != "canonicalSha256"}
    require(isinstance(checksum, str) and POLICY.SHA256.fullmatch(checksum) is not None and digest(unsigned) == checksum, "recovery receipt checksum mismatch")
    public_projection(unsigned)
    require(receipt.get("schemaVersion") == RECOVERY_RECEIPT_SCHEMA, "recovery receipt schema drift")
    require(receipt.get("status") == "recovered", "recovery receipt is not recovered")
    require(receipt.get("protectedRevision") == rev, "recovery receipt revision drift")
    require(receipt.get("activationPolicySha256") == POLICY.activation_policy_sha256(p), "recovery receipt policy drift")
    require(receipt.get("protectedRunnerFileSha256") == runner_hashes, "recovery receipt protected file drift")
    require(receipt.get("automaticActivationRetry") is False, "recovery receipt automatic retry widened")
    require(receipt.get("civicAuthorityEffects") is False, "recovery receipt civic authority widened")
    validate_recovery_incident_binding_v4(receipt.get("recoveredIncident"))
    preflight = validate_recovery_preflight_receipt_v4(receipt.get("preflight"), p, rev)
    validate_complete_recovery_rollback_v4(receipt.get("rollback"), preflight, p, rev)
    return {
        "schemaVersion": RECOVERY_RECEIPT_SCHEMA,
        "status": "recovered",
        "receiptSha256": checksum,
        "protectedRevision": rev,
        "sourceFailedReceiptSha256": FAILED_ACTIVATION_CANONICAL_SHA256,
        "dormantHandoverReceiptSha256": preflight["dormantReceipt"]["receiptSha256"],
        "automaticActivationRetry": False,
        "civicAuthorityEffects": False,
    }

def validate_success_facts_v4(facts: dict[str, Any], p: dict[str, Any], rev: str) -> None:
    _policy_call(POLICY.validate_trusted_live_facts, facts)
    require(facts["protectedRevision"] == rev and facts["policySha256"] == POLICY.activation_policy_sha256(p), "trusted facts Git/policy binding drift")
    require(facts["publication"]["manifestDigest"] == p["productPins"]["imageManifestDigest"], "trusted publication digest drift")
    require(facts["publication"]["verificationLevel"] == "anonymous-registry-manifest-digest-only" and facts["publication"]["cryptographicPublicationProvenanceVerified"] is False, "publication verification claim widened")
    database = validate_database_status_receipt_v4(facts["database"], p)
    require(
        {key: database[key] for key in topic_tracer_readiness_projection_v4(p)}
        == topic_tracer_readiness_projection_v4(p),
        "trusted topic-tracer readiness projection drift",
    )
    require(len(facts["objectCreateResults"]) == 6 and len(facts["semanticObjects"]) == 6, "trusted object receipt set incomplete")
    require(facts["operationReservation"]["absencePreflight"]["status"] == "all-six-exact-target-names-absent" and len(facts["operationReservation"]["absencePreflight"]["targets"]) == 6, "trusted operation absence reservation incomplete")
    require(all(item["operationNonce"] == facts["operationReservation"]["operationNonce"] and item["temporaryNonceRemoved"] is True for item in facts["objectCreateResults"]), "trusted operation nonce lifecycle incomplete")
    flux = facts["fluxTransaction"]
    require(
        set(flux)
        == {
            "bootstrapReceiptSha256",
            "bootstrapObjectIdentities",
            "sourceBeforeCas",
            "casUnsuspended",
            "ready",
            "sourceAfterReady",
        }
        and isinstance(flux["bootstrapReceiptSha256"], str)
        and bool(POLICY.SHA256.fullmatch(flux["bootstrapReceiptSha256"]))
        and isinstance(flux["bootstrapObjectIdentities"], list)
        and [item.get("logicalName") for item in flux["bootstrapObjectIdentities"]]
        == list(POLICY.DORMANT_BOOTSTRAP_OBJECT_ORDER)
        and set(flux["ready"]) == {"gateway", "workbenchIngress"},
        "trusted dual Flux/bootstrap receipt incomplete",
    )
    source_before, source_after = facts["fluxTransaction"]["sourceBeforeCas"], facts["fluxTransaction"]["sourceAfterReady"]
    require(source_before["uid"] == source_after["uid"] and source_before["artifactRevision"] == source_after["artifactRevision"] == f"main@sha1:{rev}", "trusted Flux source revision/UID receipt drift")
    require(set(facts["preservation"]) == {"webIngress", "existingWorkbenchNetworkPolicy"} and all(value["byteIdenticalCanonicalJson"] for value in facts["preservation"].values()), "trusted preservation receipt incomplete")
    secrets_receipt = facts["secretMaterialization"]
    require(set(secrets_receipt) == {"beforeCreate", "beforeIngress", "afterFlux"} and secrets_receipt["beforeCreate"] == secrets_receipt["beforeIngress"] == secrets_receipt["afterFlux"], "trusted Secret recheck receipt incomplete")
    require(set(facts["networkPolicyConflictScan"]) == {"beforeCreate", "beforeIngress", "afterFlux"}, "trusted policy-union recheck receipt incomplete")
    cluster_bindings = facts["clusterBinding"]
    expected_cluster = p["clusterIdentity"]
    expected_binding_fields = {
        "apiOrigin",
        "caCertificateSha256",
        "apiServerSpkiSha256",
        "kubeSystemNamespaceUid",
        "kubeSystemNamespaceResourceVersion",
        "credentialsIncluded",
        "kubeconfigPathIncluded",
    }
    require(
        set(cluster_bindings) == {"initial", "beforeMutation", "beforeIngress", "beforeFluxUnsuspend", "beforeSuccess"}
        and all(value == cluster_bindings["initial"] for value in cluster_bindings.values())
        and all(
            isinstance(value, dict)
            and set(value) == expected_binding_fields
            and {key: value[key] for key in expected_cluster} == expected_cluster
            and isinstance(value["kubeSystemNamespaceResourceVersion"], str)
            and value["kubeSystemNamespaceResourceVersion"].isdigit()
            and value["credentialsIncluded"] is False
            and value["kubeconfigPathIncluded"] is False
            for value in cluster_bindings.values()
        ),
        "trusted cluster identity recheck sequence or protected binding drift",
    )
    require(facts["rollback"] == {"status": "not-required", "finalizersRemovedByRunner": False}, "trusted success rollback receipt drift")

def bind_success_receipt_v4(
    receipt: dict[str, Any],
    p: dict[str, Any],
    rev: str,
    runner_hashes: dict[str, str],
) -> dict[str, Any]:
    """Deep-verify the durable activation commit without contacting Kubernetes."""
    require(isinstance(receipt, dict), "activation success receipt must be an object")
    expected_fields = {
        "schemaVersion",
        "status",
        "protectedRevision",
        "activationPolicySha256",
        "protectedRunnerFileSha256",
        "trustedLiveFacts",
        "civicAuthorityEffects",
        "canonicalSha256",
    }
    require(set(receipt) == expected_fields, "activation success receipt field set drift")
    checksum = receipt["canonicalSha256"]
    require(isinstance(checksum, str) and bool(POLICY.SHA256.fullmatch(checksum)), "activation success receipt checksum invalid")
    unsigned = {key: copy.deepcopy(value) for key, value in receipt.items() if key != "canonicalSha256"}
    require(digest(unsigned) == checksum, "activation success receipt checksum mismatch")
    public_projection(unsigned)
    require(receipt["schemaVersion"] == RECEIPT_SCHEMA, "activation success receipt schema drift")
    require(receipt["status"] == "activated", "activation success receipt is not activated")
    require(receipt["protectedRevision"] == rev, "activation success receipt revision drift")
    require(
        receipt["activationPolicySha256"] == POLICY.activation_policy_sha256(p),
        "activation success receipt policy drift",
    )
    require(
        receipt["protectedRunnerFileSha256"] == runner_hashes,
        "activation success receipt protected file drift",
    )
    require(receipt["civicAuthorityEffects"] is False, "activation success receipt civic authority widened")
    validate_success_facts_v4(receipt["trustedLiveFacts"], p, rev)
    return {
        "schemaVersion": RECEIPT_SCHEMA,
        "status": "activated",
        "receiptSha256": checksum,
        "protectedRevision": rev,
        "activationPolicySha256": receipt["activationPolicySha256"],
        "civicAuthorityEffects": False,
    }

def activate(
    p: dict[str, Any],
    rev: str,
    kube: str | None,
    r: Runner,
    live: bool,
    sink: ReceiptSink,
    runner_hashes: dict[str, str],
    dormant_ownership: dict[str, Any] | None = None,
    secret_materialization_ownership: dict[str, Any] | None = None,
    tracer_activation_ownership: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute both Flux paths as one guarded transaction; no caller evidence."""
    if not live: return dry_run_plan(p, rev, {})
    _policy_call(POLICY.assert_activation_ready, p); require(kube is not None and Path(kube).is_file(), "live activation requires explicit existing kubeconfig")
    require(dormant_ownership is not None, "live activation requires exact dormant Flux bootstrap receipt")
    require(tracer_activation_ownership is not None, "live activation requires completed tracer data-plane receipt")
    handover_mode = isinstance(dormant_ownership.get("receiptProvenance"), dict) and dormant_ownership["receiptProvenance"].get("mode") == "archived-v1+get-only-handover"
    if handover_mode:
        require(secret_materialization_ownership is not None, "dormant handover activation requires existing Secret materialization receipt")
    rendered = render_v4(rev, p); created: list[CreatedV4] = []; bootstrap = None; preserved = None; uncertain = None; operation_nonce: str | None = None; partial: dict[str, Any] = {}; snapshot: KubeconfigSnapshot | None = None; mutation_started = False
    started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    previous_signal_handlers = install_transaction_signal_handlers_v4()
    try:
        snapshot = snapshot_kubeconfig_v4(kube, r); snapshot_path = str(snapshot.path)
        partial["clusterBinding"] = cluster_binding_v4(r, snapshot, p)
        if handover_mode:
            bound_cluster = validate_bound_cluster_identity_v4(dormant_ownership.get("clusterBinding"), p, "dormant handover")
            require_same_cluster_identity_v4(partial["clusterBinding"], bound_cluster, "dormant handover continuation")
        partial["publication"] = anonymous_publication_v4(p)
        partial["endpoints"] = endpoint_facts_v4(r, snapshot_path, p)
        preserved = preservation_v4(r, snapshot_path, p)
        if handover_mode:
            require_current_preservation_binding_v4(preserved, dormant_ownership, p)
        bootstrap = flux_preflight_v4(r, snapshot_path, p, rev, dormant_ownership)
        absence = exact_absence_preflight_v4(r, snapshot_path, rendered); operation_nonce = secrets.token_hex(32)
        require(bool(POLICY.NONCE.fullmatch(operation_nonce)), "runner CSPRNG operation nonce invalid")
        secret_before = secret_materialization_v4(r, snapshot_path, p)
        if handover_mode:
            require_secret_materialization_binding_v4(secret_before, secret_materialization_ownership, p)
        require_tracer_activation_binding_v4(
            partial["endpoints"], secret_before, tracer_activation_ownership,
            r, snapshot_path, rev,
        )
        policy_before = policy_union_v4(r, snapshot_path)
        cluster_before_mutation = cluster_binding_v4(r, snapshot, p); require_same_cluster_identity_v4(partial["clusterBinding"], cluster_before_mutation, "before mutation")
        order = ("gateway.networkPolicy", "workbenchIngress.networkPolicy", "gateway.serviceAccount", "gateway.service", "gateway.deployment")
        deployment = haproxy = None
        for logical in order:
            uncertain = logical; mutation_started = True
            try: item = create_v4(r, snapshot_path, logical, rendered[logical], operation_nonce)
            except CreateConflictError: uncertain = None; raise
            except TransportUncertainError: raise
            except Exception: uncertain = None; raise
            created.append(item); uncertain = None
            remove_operation_nonce_v4(r, snapshot_path, item, operation_nonce)
            if logical == "gateway.deployment": deployment, haproxy = health_v4(r, snapshot_path, p)
        require(deployment is not None and haproxy is not None, "internal health facts absent")
        owned = {(item.desired["metadata"]["namespace"], item.desired["metadata"]["name"]): item for item in created if item.desired["kind"] == "NetworkPolicy"}
        partial["publication"]["runtime"] = runtime_image_v4(r, snapshot_path, p)
        secret_before_ingress = secret_materialization_v4(r, snapshot_path, p); require_same_secret_materialization_v4(secret_before, secret_before_ingress, "before Ingress")
        policy_before_ingress = policy_union_v4(r, snapshot_path, owned)
        partial["database"] = database_status_v4(r, snapshot_path, p, partial["publication"]["runtime"])
        cluster_before_ingress = cluster_binding_v4(r, snapshot, p); require_same_cluster_identity_v4(partial["clusterBinding"], cluster_before_ingress, "before Ingress")
        uncertain = "gateway.ingress"
        try: ingress = create_v4(r, snapshot_path, uncertain, rendered[uncertain], operation_nonce)
        except CreateConflictError: uncertain = None; raise
        except TransportUncertainError: raise
        except Exception: uncertain = None; raise
        created.append(ingress); uncertain = None
        remove_operation_nonce_v4(r, snapshot_path, ingress, operation_nonce)
        partial["routeMatrix"] = route_matrix_v4(r, p)
        source_before_cas = shared_source_revision_v4(r, snapshot_path, rev)
        cluster_before_flux = cluster_binding_v4(r, snapshot, p); require_same_cluster_identity_v4(partial["clusterBinding"], cluster_before_flux, "before Flux unsuspend")
        changed = unsuspend_both_v4(r, snapshot_path, p, bootstrap); ready = wait_both_ready_v4(r, snapshot_path, p, bootstrap, rev)
        source_after_ready = shared_source_revision_v4(r, snapshot_path, rev)
        secret_after_flux = secret_materialization_v4(r, snapshot_path, p); require_same_secret_materialization_v4(secret_before, secret_after_flux, "after Flux")
        policy_after_flux = policy_union_v4(r, snapshot_path, owned)
        final_semantics = semantic_postconditions_v4(r, snapshot_path, created)
        preservation = verify_preservation_v4(r, snapshot_path, preserved)
        final_cluster = cluster_binding_v4(r, snapshot, p); require_same_cluster_identity_v4(partial["clusterBinding"], final_cluster, "before success")
        valid_until = started + dt.timedelta(seconds=300)
        facts = {"schemaVersion": POLICY.TRUSTED_LIVE_FACTS_SCHEMA, "policySha256": POLICY.activation_policy_sha256(p), "collectedAt": started.strftime("%Y-%m-%dT%H:%M:%SZ"), "validUntil": valid_until.strftime("%Y-%m-%dT%H:%M:%SZ"), "maxAgeSeconds": 300, "clusterBinding": {"initial": partial["clusterBinding"], "beforeMutation": cluster_before_mutation, "beforeIngress": cluster_before_ingress, "beforeFluxUnsuspend": cluster_before_flux, "beforeSuccess": final_cluster}, "operationReservation": {"operationNonce": operation_nonce, "annotation": POLICY.OPERATION_NONCE_ANNOTATION, "absencePreflight": absence, "temporaryAnnotationsRemovedBeforeFlux": True}, "protectedRevision": rev, "publication": partial["publication"], "database": partial["database"], "endpoints": partial["endpoints"], "secretMaterialization": {"beforeCreate": secret_before, "beforeIngress": secret_before_ingress, "afterFlux": secret_after_flux}, "networkPolicyConflictScan": {"beforeCreate": policy_before, "beforeIngress": policy_before_ingress, "afterFlux": policy_after_flux}, "objectCreateResults": [item.receipt for item in created], "semanticObjects": final_semantics, "haproxy": haproxy, "routeMatrix": partial["routeMatrix"], "fluxTransaction": {"bootstrapReceiptSha256": dormant_ownership["receiptSha256"], "bootstrapObjectIdentities": copy.deepcopy(dormant_ownership["objects"]), "sourceBeforeCas": {"uid": source_before_cas["metadata"]["uid"], "resourceVersion": source_before_cas["metadata"]["resourceVersion"], "artifactRevision": f"main@sha1:{rev}"}, "casUnsuspended": {owner: value["metadata"]["resourceVersion"] for owner, value in changed.items()}, "ready": ready, "sourceAfterReady": {"uid": source_after_ready["metadata"]["uid"], "resourceVersion": source_after_ready["metadata"]["resourceVersion"], "artifactRevision": f"main@sha1:{rev}"}}, "preservation": preservation, "rollback": {"status": "not-required", "finalizersRemovedByRunner": False}}
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

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-protected-revision", required=True)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--dry-run", action="store_true")
    modes.add_argument("--live", action="store_true")
    modes.add_argument("--verify-success-receipt", type=Path)
    modes.add_argument("--verify-success-receipt-fd", type=int)
    modes.add_argument("--verify-secret-materialization-receipt-fd", type=int)
    modes.add_argument("--recover-rollback-incomplete-receipt-fd", type=int)
    modes.add_argument("--verify-recovery-receipt-fd", type=int)
    modes.add_argument("--verify-failed-activation-recovery-source-fd", type=int)
    parser.add_argument("--kubeconfig")
    bootstrap = parser.add_mutually_exclusive_group()
    bootstrap.add_argument("--flux-bootstrap-receipt", type=Path)
    bootstrap.add_argument("--flux-bootstrap-receipt-fd", type=int)
    parser.add_argument("--archived-flux-bootstrap-receipt-fd", type=int)
    parser.add_argument("--dormant-bootstrap-handover-receipt-fd", type=int)
    parser.add_argument("--secret-materialization-receipt-fd", type=int)
    parser.add_argument("--tracer-data-plane-activation-receipt-fd", type=int)
    parser.add_argument("--prebound-blob", action="append")
    parser.add_argument("--receipt", type=Path, default=Path("participant-gateway-activation-receipt.json"))
    return parser.parse_args(argv)

def main(argv: list[str] | None = None) -> int:
    global POLICY, BOOTSTRAP, _PREBOUND_GIT_BLOBS
    try:
        _PREBOUND_GIT_BLOBS = None
        a = parse_args(argv)
        require(sys.flags.isolated == 1 and bool(sys.flags.safe_path), "executor requires python3 -I isolated safe-path mode")
        os.environ.pop("PYTHONPATH", None)
        rev = revision(a.expected_protected_revision); require((ROOT / ".git").exists(), "executor must run from the protected repository checkout")
        if a.prebound_blob:
            _PREBOUND_GIT_BLOBS = parse_prebound_git_blob_descriptors_v4(a.prebound_blob, rev)
        require(trusted_git_v4(["-C", str(ROOT), "rev-parse", "HEAD"], text=True, capture_output=True, check=False).stdout.strip() == rev, "checked-out Git revision is not expected protected revision")
        runner_hashes = protected_checkout(rev)
        POLICY = compile_verified_policy_module_v4(git_blob(rev, POLICY_MODULE_PATH), rev)
        BOOTSTRAP = compile_verified_bootstrap_module_v4(git_blob(rev, BOOTSTRAP_MODULE_PATH), rev)
        bind_verified_policy_identity_v4(POLICY)
        p = policy(rev)
        if a.dry_run:
            require(
                a.kubeconfig is None
                and a.flux_bootstrap_receipt is None
                and a.flux_bootstrap_receipt_fd is None
                and a.archived_flux_bootstrap_receipt_fd is None
                and a.dormant_bootstrap_handover_receipt_fd is None
                and a.secret_materialization_receipt_fd is None
                and a.tracer_data_plane_activation_receipt_fd is None
                and a.prebound_blob is None,
                "dry-run accepts no kubeconfig or continuation receipts",
            )
            result = dry_run_plan(p, rev, runner_hashes)
            sink = ReceiptSink.reserve(a.receipt); sink.commit(result); print(canonical(result)); return 0
        # The immutable readiness gate precedes receipt or kubeconfig input.
        try: POLICY.assert_activation_ready(p)
        except POLICY.PolicyError as exc: raise ActivationError(str(exc)) from exc
        if (
            a.verify_success_receipt is not None
            or a.verify_success_receipt_fd is not None
            or a.verify_secret_materialization_receipt_fd is not None
            or a.verify_recovery_receipt_fd is not None
            or a.verify_failed_activation_recovery_source_fd is not None
        ):
            require(
                a.kubeconfig is None
                and a.flux_bootstrap_receipt is None
                and a.flux_bootstrap_receipt_fd is None
                and a.archived_flux_bootstrap_receipt_fd is None
                and a.dormant_bootstrap_handover_receipt_fd is None
                and a.secret_materialization_receipt_fd is None
                and a.tracer_data_plane_activation_receipt_fd is None,
                "receipt verification accepts no kubeconfig or continuation receipts",
            )
            require(a.prebound_blob is None, "receipt verification accepts no prebound Git closure")
            if a.verify_secret_materialization_receipt_fd is not None:
                result = bind_secret_materialization_receipt_v4(p, rev, a.verify_secret_materialization_receipt_fd)
                print(canonical(result))
                return 0
            if a.verify_recovery_receipt_fd is not None:
                recovery_receipt = load_owned_receipt_fd_v4(a.verify_recovery_receipt_fd, "participant recovery receipt")
                result = bind_recovery_receipt_v4(recovery_receipt, p, rev, runner_hashes)
                print(canonical(result))
                return 0
            if a.verify_failed_activation_recovery_source_fd is not None:
                source = bind_failed_activation_recovery_source_v4(a.verify_failed_activation_recovery_source_fd)
                result = {
                    "status": "rollback-incomplete-recovery-source-bound",
                    "receiptSha256": source["originReceiptSha256"],
                    "fileSha256": source["originRawSha256"],
                    "protectedRevision": rev,
                    "originProtectedRevision": source["originProtectedRevision"],
                    "civicAuthorityEffects": False,
                }
                print(canonical(result))
                return 0
            receipt = (
                load_owned_receipt_v4(a.verify_success_receipt, "activation success receipt")
                if a.verify_success_receipt is not None
                else load_owned_receipt_fd_v4(a.verify_success_receipt_fd, "activation success receipt")
            )
            result = bind_success_receipt_v4(receipt, p, rev, runner_hashes)
            print(canonical(result))
            return 0
        if a.recover_rollback_incomplete_receipt_fd is not None:
            require(
                a.kubeconfig is not None
                and a.archived_flux_bootstrap_receipt_fd is not None
                and a.dormant_bootstrap_handover_receipt_fd is not None
                and a.flux_bootstrap_receipt is None
                and a.flux_bootstrap_receipt_fd is None
                and a.secret_materialization_receipt_fd is None
                and a.tracer_data_plane_activation_receipt_fd is None
                and _PREBOUND_GIT_BLOBS is not None,
                "incident recovery requires kubeconfig, archived and fresh handover receipts, failed receipt, and prebound Git closure only",
            )
            dormant_ownership = bind_handover_receipt_pair_v4(
                p,
                rev,
                a.archived_flux_bootstrap_receipt_fd,
                a.dormant_bootstrap_handover_receipt_fd,
                _PREBOUND_GIT_BLOBS,
            )
            incident = bind_failed_activation_recovery_source_v4(a.recover_rollback_incomplete_receipt_fd)
            sink = ReceiptSink.reserve(a.receipt)
            result = recover_incomplete_activation_v4(
                p,
                rev,
                a.kubeconfig,
                Runner(),
                sink,
                runner_hashes,
                dormant_ownership,
                incident,
            )
            print(canonical(result))
            return 0
        require(a.live is True, "ordinary participant activation requires --live")
        require(
            a.tracer_data_plane_activation_receipt_fd is not None,
            "ordinary participant activation requires completed tracer data-plane receipt",
        )
        tracer_activation_ownership = bind_tracer_activation_receipt_v4(
            p,
            rev,
            a.tracer_data_plane_activation_receipt_fd,
        )
        handover_flags = (a.archived_flux_bootstrap_receipt_fd, a.dormant_bootstrap_handover_receipt_fd, a.secret_materialization_receipt_fd)
        handover_requested = any(value is not None for value in handover_flags)
        if handover_requested:
            require(
                a.archived_flux_bootstrap_receipt_fd is not None
                and a.dormant_bootstrap_handover_receipt_fd is not None
                and a.secret_materialization_receipt_fd is not None
                and a.flux_bootstrap_receipt is None
                and a.flux_bootstrap_receipt_fd is None
                and _PREBOUND_GIT_BLOBS is not None,
                "handover continuation requires archived, handover, Secret, and prebound Git closure receipts only",
            )
            dormant_ownership = bind_handover_receipt_pair_v4(
                p,
                rev,
                a.archived_flux_bootstrap_receipt_fd,
                a.dormant_bootstrap_handover_receipt_fd,
                _PREBOUND_GIT_BLOBS,
            )
            secret_materialization_ownership = bind_secret_materialization_receipt_v4(
                p,
                rev,
                a.secret_materialization_receipt_fd,
            )
        else:
            require(a.flux_bootstrap_receipt is not None or a.flux_bootstrap_receipt_fd is not None, "live activation requires a Flux bootstrap receipt")
            require(a.secret_materialization_receipt_fd is None and a.prebound_blob is None, "ordinary activation accepts no continuation Secret receipt or prebound Git closure")
            if a.flux_bootstrap_receipt is not None:
                dormant_ownership = bind_flux_bootstrap_receipt_v4(p, rev, runner_hashes, a.flux_bootstrap_receipt)
            else:
                dormant_ownership = bind_flux_bootstrap_receipt_value_v4(
                    p,
                    rev,
                    runner_hashes,
                    BOOTSTRAP.load_receipt_fd(a.flux_bootstrap_receipt_fd),
                )
            secret_materialization_ownership = None
        sink = ReceiptSink.reserve(a.receipt)
        result = activate(
            p,
            rev,
            a.kubeconfig,
            Runner(),
            True,
            sink,
            runner_hashes,
            dormant_ownership,
            secret_materialization_ownership,
            tracer_activation_ownership,
        )
        print(canonical(result)); return 0
    except (ActivationError, OSError, json.JSONDecodeError) as exc: print(f"activation blocked: {exc}", file=sys.stderr); return 2
if __name__ == "__main__": raise SystemExit(main())
