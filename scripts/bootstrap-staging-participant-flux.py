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
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")

# This is a one-incident capability, not a generic historical receipt bridge.
# Every source and every dormant identity is pinned to the successful run29-r2
# recovery evidence.  The original bridge is pinned exactly, and only a
# merge-free descendant lineage whose cumulative tree changes remain the four
# reviewed hotfix files may retain the incident receipt pins below.
RUN29_TEARDOWN_BASE_REVISION = "890e001c76a94755d8f25ebfcf83593da24a082e"
RUN29_TEARDOWN_BRIDGE_REVISION = "92dbe194d1ff3ba45844409d6f478b9012c5182c"
RUN29_TEARDOWN_ARCHIVE_REVISION = "08c4171573bb138845a9160e747f6ac56a3c754e"
RUN29_TEARDOWN_CHANGED_PATHS = frozenset({
    "scripts/bootstrap-staging-participant-flux.py",
    "scripts/run-staging-participant-gateway-live.py",
    "scripts/staging_participant_flux_bootstrap.py",
    "scripts/test_run_staging_participant_gateway_live.py",
    "scripts/test_staging_participant_flux_bootstrap.py",
})
RUN29_TEARDOWN_HOTFIX_CHANGED_PATHS = frozenset({
    "scripts/bootstrap-staging-participant-flux.py",
    "scripts/run-staging-participant-gateway-live.py",
    "scripts/test_run_staging_participant_gateway_live.py",
    "scripts/test_staging_participant_flux_bootstrap.py",
})
RUN29_TEARDOWN_RECEIPT_PINS = {
    "archivedDormant": {
        "rawSha256": "sha256:32e244e5ba711aa8406a76d8dbf4fdd53289e52e2ced6ff27b77a7ae7577741f",
        "canonicalSha256": "sha256:ab90b49078f423c304b643b9354230611127d0ed6bda0d1022f3abc92772b081",
    },
    "dormantHandover": {
        "rawSha256": "sha256:003c1a7fcbaf43a33872d86420596c4371b0815f4c3bbc1e40f9f5f1c61ead5e",
        "canonicalSha256": "sha256:9860575a8e378a576615fd28b6e826ab9a7f650ae759d2e396a63234b5c4b21e",
    },
    "participantRecovery": {
        "rawSha256": "sha256:d316bc4309f52e64dee3b4b6d682313caead4c529e184035e540f2814b20652f",
        "canonicalSha256": "sha256:57f9c8d2d39cd98f4fc239ba1f388f80f7a99d488a9ddabc376372862d2493ea",
    },
}
RUN29_TEARDOWN_OBJECTS = (
    ("gateway.serviceAccount", "a846abe8-0887-47bd-a13c-d1bcc235c56e", "sha256:6bffe7650eeed6830608b0d43cb5ec20b61e150ad6267cdefc2b2edf47a70d94"),
    ("workbenchIngress.serviceAccount", "37de1f6f-8b9b-4ede-ab99-5df283d16ede", "sha256:7cda88c90efb6ceafc97b625f25cbc092e9e48b6f57377421ea41be8f6303508"),
    ("gateway.role", "e0155df8-8482-4ed2-a82b-f64a6774fd90", "sha256:76156f0618822f24a4e46d26eb184e8e8b415e5a704bd8b966f29e2dfdf26982"),
    ("workbenchIngress.role", "d25da66f-08af-4e01-bdb0-31dbe2cf7ac0", "sha256:deb903db43cb560b875e53d0f745922bff210db6cc2048a837effb3130ebaabe"),
    ("gateway.roleBinding", "7583208d-a277-486a-afd9-f49ef196a948", "sha256:4c9c84598079e070f10540f2f1dd0fed50b3ff0a7f3efea8dd359d37df28939d"),
    ("workbenchIngress.roleBinding", "4911cf39-750d-455d-9fc7-9cbeadc58006", "sha256:220c2af2bff1c601903f49fd3a271d9a768eaf665d68d0d1184b75c48a15d8c9"),
    ("gateway.kustomization", "fc13f246-b5de-41d6-b42d-4621648fe1d7", "sha256:d8dbe6c25e31aef323c88c55f96417c5c7ee603a02b45f7f9e943326c2d694ce"),
    ("workbenchIngress.kustomization", "5732fcc4-5d34-4107-99c3-0690e541cccf", "sha256:77511a42e32c965465839f772ed76abf6583e7deeb83d2509373bab23946d173"),
)
RUN29_TEARDOWN_SOURCE_UID = "0de8a05d-550f-429c-93c5-9b8c76b0bf9b"


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


def require_run29_teardown_lineage(current_revision: str) -> list[str]:
    """Prove the pinned bridge or one linear, path-closed hotfix lineage."""
    revision(current_revision)
    require(current_revision != RUN29_TEARDOWN_BASE_REVISION, "run29 teardown candidate revision did not advance")
    try:
        if current_revision == RUN29_TEARDOWN_BRIDGE_REVISION:
            lineage = trusted_git(
                ["-C", str(ROOT), "rev-list", "--parents", "-n", "1", current_revision],
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )
        else:
            lineage = trusted_git(
                [
                    "-C", str(ROOT), "rev-list", "--parents", "--reverse", "--ancestry-path",
                    f"{RUN29_TEARDOWN_BRIDGE_REVISION}..{current_revision}",
                ],
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )
    except subprocess.TimeoutExpired as exc:
        raise CliError("run29 teardown protected lineage timed out") from exc
    if current_revision == RUN29_TEARDOWN_BRIDGE_REVISION:
        parents = lineage.stdout.strip().split() if lineage.returncode == 0 else []
        require(
            parents == [RUN29_TEARDOWN_BRIDGE_REVISION, RUN29_TEARDOWN_BASE_REVISION],
            "run29 teardown protected parent drift",
        )
        expected_parent = RUN29_TEARDOWN_BASE_REVISION
        expected_paths = RUN29_TEARDOWN_CHANGED_PATHS
    else:
        require(lineage.returncode == 0, "run29 teardown protected parent drift")
        rows = [line.split() for line in lineage.stdout.splitlines() if line.strip()]
        previous = RUN29_TEARDOWN_BRIDGE_REVISION
        for row in rows:
            require(
                len(row) == 2
                and REVISION.fullmatch(row[0]) is not None
                and REVISION.fullmatch(row[1]) is not None
                and row[1] == previous,
                "run29 teardown protected parent drift",
            )
            previous = row[0]
        require(rows and previous == current_revision, "run29 teardown protected parent drift")
        expected_parent = RUN29_TEARDOWN_BRIDGE_REVISION
        expected_paths = RUN29_TEARDOWN_HOTFIX_CHANGED_PATHS
    try:
        changed = trusted_git(
            [
                "-C", str(ROOT), "diff", "--no-ext-diff", "--no-renames",
                "--name-only", "-z", expected_parent, current_revision, "--",
            ],
            capture_output=True,
            check=False,
            timeout=10,
        )
    except subprocess.TimeoutExpired as exc:
        raise CliError("run29 teardown protected lineage timed out") from exc
    require(changed.returncode == 0, "run29 teardown protected file set unavailable")
    try:
        paths = [item.decode("utf-8") for item in changed.stdout.split(b"\0") if item]
    except UnicodeDecodeError as exc:
        raise CliError("run29 teardown protected file set is not UTF-8") from exc
    require(len(paths) == len(set(paths)), "run29 teardown protected file set duplicated")
    require(set(paths) == set(expected_paths), "run29 teardown protected file set drift")
    return sorted(paths)


def _owned_receipt_raw(fd: int, label: str) -> bytes:
    require(isinstance(fd, int) and fd >= 3, f"{label} descriptor invalid")
    info = os.fstat(fd)
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.geteuid()
        and info.st_nlink in {0, 1}
        and stat.S_IMODE(info.st_mode) == 0o600
        and 0 < info.st_size <= 1024 * 1024,
        f"{label} must be a bounded owned 0600 regular file",
    )
    raw = os.pread(fd, info.st_size + 1, 0)
    require(len(raw) == info.st_size, f"{label} descriptor read incomplete")
    return raw


def _receipt_object(module: Any, raw: bytes, label: str) -> tuple[dict[str, Any], str]:
    try:
        value = module._json_object(raw.decode("utf-8"), label)
    except UnicodeDecodeError as exc:
        raise CliError(f"{label} must be UTF-8 JSON") from exc
    unsigned = copy.deepcopy(value)
    checksum = unsigned.pop("canonicalSha256", None)
    require(
        isinstance(checksum, str)
        and SHA256.fullmatch(checksum) is not None
        and bytes_sha256(canonical(unsigned).encode("utf-8")) == checksum,
        f"{label} canonical checksum drift",
    )
    require(
        not any(token in canonical(unsigned).lower() for token in ('"data"', '"stringdata"', '"token"', '"password"', '"privatekey"')),
        f"{label} contains secret-shaped material",
    )
    return value, checksum


def _bind_archived_dormant_receipt(raw: bytes) -> dict[str, Any]:
    archive_policy = compile_verified_module(
        git_blob(RUN29_TEARDOWN_ARCHIVE_REVISION, POLICY_MODULE_PATH),
        name="run29_archive_policy",
        path=POLICY_MODULE_PATH,
        rev=RUN29_TEARDOWN_ARCHIVE_REVISION,
    )
    archive_bootstrap = compile_verified_module(
        git_blob(RUN29_TEARDOWN_ARCHIVE_REVISION, BOOTSTRAP_MODULE_PATH),
        name="run29_archive_bootstrap",
        path=BOOTSTRAP_MODULE_PATH,
        rev=RUN29_TEARDOWN_ARCHIVE_REVISION,
    )
    descriptor = archive_policy.validate_activation_policy(
        archive_bootstrap._json_object(
            git_blob(RUN29_TEARDOWN_ARCHIVE_REVISION, POLICY_PATH).decode("utf-8"),
            "archived activation policy",
        ),
    )
    hashes = {
        path: bytes_sha256(git_blob(RUN29_TEARDOWN_ARCHIVE_REVISION, path))
        for path in PROTECTED_PATHS
    }
    plan = archive_bootstrap.build_plan(
        archive_policy,
        descriptor,
        RUN29_TEARDOWN_ARCHIVE_REVISION,
        hashes,
    )
    value, _checksum = _receipt_object(archive_bootstrap, raw, "archived dormant receipt")
    return archive_bootstrap.bind_success_receipt(plan, value)


def _bind_run29_recovery_receipt(raw: bytes) -> dict[str, Any]:
    base_policy = compile_verified_module(
        git_blob(RUN29_TEARDOWN_BASE_REVISION, POLICY_MODULE_PATH),
        name="run29_recovery_policy",
        path=POLICY_MODULE_PATH,
        rev=RUN29_TEARDOWN_BASE_REVISION,
    )
    base_bootstrap = compile_verified_module(
        git_blob(RUN29_TEARDOWN_BASE_REVISION, BOOTSTRAP_MODULE_PATH),
        name="run29_recovery_bootstrap",
        path=BOOTSTRAP_MODULE_PATH,
        rev=RUN29_TEARDOWN_BASE_REVISION,
    )
    base_activation = compile_verified_module(
        git_blob(RUN29_TEARDOWN_BASE_REVISION, ACTIVATION_RUNNER_PATH),
        name="run29_recovery_activation",
        path=ACTIVATION_RUNNER_PATH,
        rev=RUN29_TEARDOWN_BASE_REVISION,
    )
    base_activation.ROOT = ROOT
    base_activation.GIT_BIN = GIT_BIN
    base_activation.POLICY = base_policy
    base_activation.BOOTSTRAP = base_bootstrap
    descriptor = base_policy.validate_activation_policy(
        base_activation.obj(
            git_blob(RUN29_TEARDOWN_BASE_REVISION, POLICY_PATH).decode("utf-8"),
            "run29 recovery activation policy",
        ),
    )
    runner_paths = tuple(dict.fromkeys((*base_activation.BOOTSTRAP_PROTECTED_PATHS, base_activation.WORKFLOW_PATH)))
    hashes = {
        path: bytes_sha256(git_blob(RUN29_TEARDOWN_BASE_REVISION, path))
        for path in runner_paths
    }
    value, _checksum = _receipt_object(base_bootstrap, raw, "run29 participant recovery receipt")
    return base_activation.bind_recovery_receipt_v4(
        value,
        descriptor,
        RUN29_TEARDOWN_BASE_REVISION,
        hashes,
    )


def _current_preservation_expectations(context: dict[str, Any]) -> dict[str, dict[str, Any]]:
    labels = {
        "webIngress": {
            "kustomize.toolkit.fluxcd.io/name": "roebel-staging-web-workload",
            "kustomize.toolkit.fluxcd.io/namespace": "flux-roebel-staging",
        },
        "existingWorkbenchNetworkPolicy": {
            "kustomize.toolkit.fluxcd.io/name": "roebel-staging-workbench-baseline",
            "kustomize.toolkit.fluxcd.io/namespace": "flux-roebel-staging",
        },
    }
    paths = {
        "webIngress": "reviewed-render/roebel-staging/web/ingress.json",
        "existingWorkbenchNetworkPolicy": "reviewed-render/roebel-staging/workbench-baseline/networkpolicy.json",
    }
    result: dict[str, dict[str, Any]] = {}
    for label, path in paths.items():
        desired = context["bootstrapModule"]._json_object(
            git_blob(context["revision"], path).decode("utf-8"), path,
        )
        desired.setdefault("metadata", {}).setdefault("labels", {}).update(copy.deepcopy(labels[label]))
        target = {
            "apiVersion": desired["apiVersion"],
            "kind": desired["kind"],
            "namespace": desired["metadata"]["namespace"],
            "name": desired["metadata"]["name"],
        }
        require(target == context["policy"]["preservation"][label]["target"], f"run29 preservation target drift: {label}")
        result[label] = {
            "target": target,
            "desired": desired,
            "desiredSemanticSha256": context["policyModule"].semantic_sha256(desired),
        }
    return result


def build_run29_handover_teardown_binding(
    context: dict[str, Any],
    *,
    archived_raw: bytes,
    handover_raw: bytes,
    recovery_raw: bytes,
) -> dict[str, Any]:
    """Bind the exact three receipts to one current-plan teardown ownership set."""
    changed_paths = require_run29_teardown_lineage(context["revision"])
    raws = {
        "archivedDormant": archived_raw,
        "dormantHandover": handover_raw,
        "participantRecovery": recovery_raw,
    }
    parsed: dict[str, dict[str, Any]] = {}
    for label, raw in raws.items():
        require(bytes_sha256(raw) == RUN29_TEARDOWN_RECEIPT_PINS[label]["rawSha256"], f"run29 {label} raw checksum drift")
        value, checksum = _receipt_object(context["bootstrapModule"], raw, f"run29 {label} receipt")
        require(checksum == RUN29_TEARDOWN_RECEIPT_PINS[label]["canonicalSha256"], f"run29 {label} canonical checksum drift")
        parsed[label] = value

    archived_projection = _bind_archived_dormant_receipt(archived_raw)
    recovery_projection = _bind_run29_recovery_receipt(recovery_raw)
    handover = parsed["dormantHandover"]
    require(
        handover.get("schemaVersion") == "roebel_staging_participant_dormant_receipt_handover_v2"
        and handover.get("status") == "dormant-ready-revalidated"
        and handover.get("archivedRevision") == RUN29_TEARDOWN_ARCHIVE_REVISION
        and handover.get("currentRevision") == RUN29_TEARDOWN_BASE_REVISION
        and handover.get("archivedReceipt") == RUN29_TEARDOWN_RECEIPT_PINS["archivedDormant"]
        and handover.get("bothKustomizationsSuspended") is True
        and handover.get("effects") == {
            "verbs": ["GET"], "kubernetesGetCount": 12, "resourceGetCount": 11,
            "clusterMutationCount": 0, "secretReads": False, "civicAuthorityEffects": False,
        }
        and handover.get("civicAuthorityEffects") is False,
        "run29 dormant handover receipt provenance drift",
    )
    require(
        recovery_projection.get("dormantHandoverReceiptSha256")
        == RUN29_TEARDOWN_RECEIPT_PINS["dormantHandover"]["canonicalSha256"],
        "run29 recovery no longer binds the pinned dormant handover",
    )
    plan_objects = context["plan"]["objects"]
    handover_objects = handover.get("objects")
    require(
        isinstance(handover_objects, list)
        and len(handover_objects) == len(RUN29_TEARDOWN_OBJECTS)
        and len(plan_objects) == len(RUN29_TEARDOWN_OBJECTS),
        "run29 exact eight-object inventory drift",
    )
    bound_objects: list[dict[str, Any]] = []
    for plan_item, observed, pin, archived in zip(
        plan_objects, handover_objects, RUN29_TEARDOWN_OBJECTS, archived_projection["objects"], strict=True,
    ):
        logical_name, uid, semantic_sha256 = pin
        require(
            isinstance(observed, dict)
            and set(observed) == {"logicalName", "target", "uid", "resourceVersion", "desiredSemanticSha256"}
            and observed.get("logicalName") == logical_name == plan_item["logicalName"] == archived["logicalName"]
            and observed.get("target") == plan_item["target"] == archived["target"]
            and observed.get("uid") == uid == archived["uid"]
            and observed.get("desiredSemanticSha256") == semantic_sha256 == plan_item["desiredSemanticSha256"] == archived["desiredSemanticSha256"]
            and isinstance(observed.get("resourceVersion"), str)
            and observed["resourceVersion"].isdigit(),
            f"run29 exact dormant identity drift: {logical_name}",
        )
        bound_objects.append(copy.deepcopy(observed))
    require(
        handover.get("sharedSource", {}).get("uid") == RUN29_TEARDOWN_SOURCE_UID,
        "run29 dormant handover shared Source UID drift",
    )
    activation = compile_verified_module(
        git_blob(context["revision"], ACTIVATION_RUNNER_PATH),
        name="run29_current_activation",
        path=ACTIVATION_RUNNER_PATH,
        rev=context["revision"],
    )
    activation.ROOT = ROOT
    activation.GIT_BIN = GIT_BIN
    activation.POLICY = context["policyModule"]
    activation.BOOTSTRAP = context["bootstrapModule"]
    rendered = activation.render_v4(context["revision"], context["policy"])
    participant_targets = [
        {
            "logicalName": logical_name,
            "target": {
                "apiVersion": item["desired"]["apiVersion"],
                "kind": item["desired"]["kind"],
                "namespace": item["desired"]["metadata"]["namespace"],
                "name": item["desired"]["metadata"]["name"],
            },
        }
        for logical_name, item in sorted(rendered.items())
    ]
    require(len(participant_targets) == 6 and all(item["target"]["kind"] != "Secret" for item in participant_targets), "run29 participant exact six-target set drift")
    provenance = {
        "baseRevision": RUN29_TEARDOWN_BASE_REVISION,
        "acceptedRevision": context["revision"],
        "changedPaths": changed_paths,
        "receipts": copy.deepcopy(RUN29_TEARDOWN_RECEIPT_PINS),
        "sourceUid": RUN29_TEARDOWN_SOURCE_UID,
        "objects": [
            {"logicalName": item[0], "uid": item[1], "desiredSemanticSha256": item[2]}
            for item in RUN29_TEARDOWN_OBJECTS
        ],
        "bothKustomizationsSuspended": True,
        "allSixParticipantObjectsRecoveredAbsent": True,
        "participantAbsenceQuietSeconds": context["policy"]["httpBoundary"]["timeoutsSeconds"]["rollbackAbsenceQuiet"],
        "secretAccess": "none",
        "civicAuthorityEffects": False,
    }
    return {
        "bound": {
            "schemaVersion": context["bootstrapModule"].RECEIPT_SCHEMA,
            "status": "dormant-ready",
            "receiptSha256": RUN29_TEARDOWN_RECEIPT_PINS["dormantHandover"]["canonicalSha256"],
            "protectedRevision": context["revision"],
            "activationPolicySha256": context["plan"]["activationPolicySha256"],
            "objects": bound_objects,
            "bothKustomizationsSuspended": True,
        },
        "provenance": provenance,
        "participantTargets": participant_targets,
        "expectedPreservation": _current_preservation_expectations(context),
        "expectedSharedSource": {
            "uid": RUN29_TEARDOWN_SOURCE_UID,
            "semanticSha256": context["policyModule"].semantic_sha256(
                context["policyModule"].expected_shared_flux_source_projection(),
            ),
        },
    }


def _target_key(target: dict[str, str]) -> tuple[str, str, str, str]:
    return target["apiVersion"], target["kind"], target["namespace"], target["name"]


class KubernetesAdapter:
    """Closed adapter over one snapshotted kubeconfig and eight exact names."""

    def __init__(
        self,
        explicit_kubeconfig: str,
        context: dict[str, Any],
        run29_handover_teardown_binding: dict[str, Any] | None = None,
    ):
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
        self.run29_binding = copy.deepcopy(run29_handover_teardown_binding)
        self.participant_preflight = None
        if self.run29_binding is not None:
            require(
                set(self.run29_binding) == {
                    "bound", "provenance", "participantTargets",
                    "expectedPreservation", "expectedSharedSource",
                }
                and self.run29_binding["bound"]["protectedRevision"] == context["revision"],
                "run29 handover teardown adapter binding invalid",
            )

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
        if self.run29_binding is not None:
            expected_source = self.run29_binding["expectedSharedSource"]
            require(
                source.get("metadata", {}).get("uid") == expected_source["uid"]
                and self.policy_module.semantic_sha256(source) == expected_source["semanticSha256"],
                "run29 handover teardown shared Source identity drift",
            )
            require(
                set(preserved) == set(self.run29_binding["expectedPreservation"]),
                "run29 handover teardown preservation set drift",
            )
            for label, snapshot in preserved.items():
                expected = self.run29_binding["expectedPreservation"][label]
                require(snapshot.target == expected["target"], f"run29 preservation target drift: {label}")
                self.policy_module.require_semantically_equal(
                    snapshot.value,
                    expected["desired"],
                    f"run29 current protected preservation {label}",
                )
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

    def _participant_absence_objects(self, expected_targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
        require(
            self.run29_binding is not None
            and expected_targets == self.run29_binding["participantTargets"]
            and self.snapshot is not None,
            "run29 participant absence target binding drift",
        )
        objects = []
        for item in expected_targets:
            target = item["target"]
            require(target["kind"] != "Secret", "run29 participant absence Secret target forbidden")
            found = self.activation.get_optional(
                self.runner,
                str(self.snapshot.path),
                target["kind"].lower(),
                target["name"],
                target["namespace"],
            )
            require(found is None, f"run29 participant target is not absent: {item['logicalName']}")
            objects.append({
                "logicalName": item["logicalName"],
                "target": copy.deepcopy(target),
                "absent": True,
            })
        return objects

    def participant_application_absence_preflight(
        self,
        expected_targets: list[dict[str, Any]],
    ) -> dict[str, Any]:
        require(self.participant_preflight is None, "run29 participant absence preflight already collected")
        result = {
            "status": "all-six-exact-target-names-absent",
            "objects": self._participant_absence_objects(expected_targets),
        }
        self.participant_preflight = copy.deepcopy(result)
        return result

    def participant_application_absence_postconditions(
        self,
        expected_targets: list[dict[str, Any]],
    ) -> dict[str, Any]:
        require(self.participant_preflight is not None, "run29 participant absence preflight missing")
        timeouts = self.policy["httpBoundary"]["timeoutsSeconds"]
        quiet = timeouts["rollbackAbsenceQuiet"]
        deadline = time.monotonic() + timeouts["rollback"]
        quiet_start = None
        checks = 0
        last_objects = None
        while time.monotonic() < deadline:
            checks += 1
            try:
                last_objects = self._participant_absence_objects(expected_targets)
            except CliError:
                quiet_start = None
                raise
            quiet_start = quiet_start or time.monotonic()
            if checks >= 2 and time.monotonic() - quiet_start >= quiet:
                return {
                    "status": "all-six-names-absent-for-quiet-interval",
                    "quietSeconds": quiet,
                    "checks": checks,
                    "objects": last_objects,
                }
            time.sleep(timeouts["rollbackPoll"])
        raise CliError("run29 participant names did not remain absent for the quiet interval")

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
    modes.add_argument("--teardown-run29-handover", action="store_true")
    modes.add_argument("--verify-success-receipt", type=Path)
    modes.add_argument("--verify-teardown-receipt", type=Path)
    modes.add_argument("--verify-success-receipt-fd", type=int)
    modes.add_argument("--verify-teardown-receipt-fd", type=int)
    modes.add_argument("--verify-run29-handover-teardown-sources", action="store_true")
    modes.add_argument("--verify-run29-handover-teardown-receipt-fd", type=int)
    parser.add_argument("--kubeconfig")
    parser.add_argument("--receipt", type=Path, default=Path("participant-flux-bootstrap-receipt.json"))
    recovery = parser.add_mutually_exclusive_group()
    recovery.add_argument("--recovery-receipt", type=Path)
    recovery.add_argument("--recovery-receipt-fd", type=int)
    parser.add_argument("--run29-archived-dormant-receipt-fd", type=int)
    parser.add_argument("--run29-dormant-handover-receipt-fd", type=int)
    parser.add_argument("--run29-participant-recovery-receipt-fd", type=int)
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
        run29_source_fds = (
            args.run29_archived_dormant_receipt_fd,
            args.run29_dormant_handover_receipt_fd,
            args.run29_participant_recovery_receipt_fd,
        )
        if args.dry_run:
            require(
                args.kubeconfig is None
                and args.recovery_receipt is None
                and args.recovery_receipt_fd is None
                and all(value is None for value in run29_source_fds),
                "dry-run accepts no kubeconfig or recovery receipt",
            )
            sink = module.ReceiptSink.reserve(args.receipt)
            sink.commit(plan)
            print(canonical(plan))
            return 0
        try:
            context["policyModule"].assert_activation_ready(context["policy"])
        except context["policyModule"].PolicyError as exc:
            raise CliError(str(exc)) from exc
        run29_binding = None
        if any(value is not None for value in run29_source_fds):
            require(
                all(value is not None for value in run29_source_fds),
                "run29 teardown requires all three exact receipt descriptors",
            )
            run29_binding = build_run29_handover_teardown_binding(
                context,
                archived_raw=_owned_receipt_raw(run29_source_fds[0], "run29 archived dormant receipt"),
                handover_raw=_owned_receipt_raw(run29_source_fds[1], "run29 dormant handover receipt"),
                recovery_raw=_owned_receipt_raw(run29_source_fds[2], "run29 participant recovery receipt"),
            )
        if args.verify_run29_handover_teardown_sources:
            require(
                run29_binding is not None
                and args.kubeconfig is None
                and args.recovery_receipt is None
                and args.recovery_receipt_fd is None,
                "run29 teardown source verification accepts only its three receipt descriptors",
            )
            result = {
                "schemaVersion": "roebel_staging_participant_flux_run29_handover_teardown_binding_v1",
                "status": "run29-handover-teardown-ready",
                "receiptSha256": bytes_sha256(canonical(run29_binding["provenance"]).encode("utf-8")),
                "protectedRevision": context["revision"],
                "sources": copy.deepcopy(run29_binding["provenance"]["receipts"]),
                "objects": copy.deepcopy(run29_binding["provenance"]["objects"]),
                "participantTargetCount": 6,
                "secretAccess": "none",
                "civicAuthorityEffects": False,
            }
            print(canonical(result))
            return 0
        if args.verify_run29_handover_teardown_receipt_fd is not None:
            require(
                run29_binding is not None
                and args.kubeconfig is None
                and args.recovery_receipt is None
                and args.recovery_receipt_fd is None,
                "run29 teardown receipt verification accepts only its receipt and three source descriptors",
            )
            receipt = module.load_receipt_fd(args.verify_run29_handover_teardown_receipt_fd)
            print(canonical(module.bind_run29_handover_teardown_receipt(plan, receipt, run29_binding)))
            return 0
        if any(
            value is not None
            for value in (
                args.verify_success_receipt,
                args.verify_success_receipt_fd,
                args.verify_teardown_receipt,
                args.verify_teardown_receipt_fd,
            )
        ):
            require(
                args.kubeconfig is None
                and args.recovery_receipt is None
                and args.recovery_receipt_fd is None
                and run29_binding is None,
                "receipt verification accepts no kubeconfig or recovery receipt",
            )
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
            require(
                args.recovery_receipt is None
                and args.recovery_receipt_fd is None
                and run29_binding is None,
                "live bootstrap accepts no recovery receipt",
            )
            prior = None
            mode = "live"
        elif args.teardown_run29_handover:
            require(
                run29_binding is not None
                and args.recovery_receipt is None
                and args.recovery_receipt_fd is None,
                "run29 handover teardown requires only its exact three source receipts",
            )
            prior = None
            mode = "run29-handover-teardown"
        else:
            require(run29_binding is None, "generic recovery/teardown accepts no run29 compatibility receipts")
            require(args.recovery_receipt is not None or args.recovery_receipt_fd is not None, "recovery/teardown mode requires a recovery receipt")
            prior = module.load_receipt(args.recovery_receipt) if args.recovery_receipt is not None else module.load_receipt_fd(args.recovery_receipt_fd)
            mode = "teardown" if args.teardown else "recover"
        # Receipt reservation and its first durable commit happen before the
        # adapter snapshots credentials or makes any Kubernetes request.
        sink = module.ReceiptSink.reserve(args.receipt)
        adapter = KubernetesAdapter(args.kubeconfig, context, run29_binding)
        previous_signals = adapter.activation.install_transaction_signal_handlers_v4()
        result = module.run(
            plan,
            mode=mode,
            kube=adapter,
            sink=sink,
            policy_module=context["policyModule"],
            prior_receipt=prior,
            handover_teardown_binding=run29_binding,
        )
        expected = {
            "live": "dormant-ready",
            "recover": "recovered-rolled-back",
            "teardown": "dormant-torn-down",
            "run29-handover-teardown": "dormant-handover-torn-down",
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
