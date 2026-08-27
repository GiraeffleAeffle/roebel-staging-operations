#!/usr/bin/env python3
"""Focused tests for the one-time E2E workbench policy handover."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
import signal
import tempfile
import unittest
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("workbench_baseline_handover.py")
SPEC = importlib.util.spec_from_file_location("workbench_baseline_handover_under_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


REVISION = "0123456789abcdef0123456789abcdef01234567"


def key(identity: dict[str, str]) -> tuple[str, str, str, str]:
    return (
        identity["apiVersion"],
        identity["kind"],
        identity["namespace"],
        identity["name"],
    )


def json_pointer(value: str) -> list[str]:
    if value == "":
        return []
    return [part.replace("~1", "/").replace("~0", "~") for part in value.lstrip("/").split("/")]


def pointer_get(value: Any, path: str) -> Any:
    current = value
    for part in json_pointer(path):
        current = current[int(part)] if isinstance(current, list) else current[part]
    return current


def pointer_parent(value: Any, path: str) -> tuple[Any, str]:
    parts = json_pointer(path)
    if not parts:
        raise AssertionError("root operation is not used by this test adapter")
    current = value
    for part in parts[:-1]:
        current = current[int(part)] if isinstance(current, list) else current[part]
    return current, parts[-1]


def apply_json_patch(value: dict[str, Any], operations: list[dict[str, Any]]) -> dict[str, Any]:
    result = copy.deepcopy(value)
    for operation in operations:
        op = operation["op"]
        path = operation["path"]
        if op == "test":
            if pointer_get(result, path) != operation["value"]:
                raise AssertionError(f"JSON patch test failed: {path}")
            continue
        parent, part = pointer_parent(result, path)
        if op in {"add", "replace"}:
            if isinstance(parent, list):
                if part == "-":
                    parent.append(copy.deepcopy(operation["value"]))
                else:
                    parent[int(part)] = copy.deepcopy(operation["value"])
            else:
                parent[part] = copy.deepcopy(operation["value"])
        elif op == "remove":
            if isinstance(parent, list):
                del parent[int(part)]
            else:
                del parent[part]
        else:
            raise AssertionError(f"unsupported operation {op}")
    return result


def baseline_live() -> dict[str, Any]:
    value = copy.deepcopy(MODULE.expected_before_network_policy())
    value["metadata"].update({
        "creationTimestamp": "2026-08-27T13:57:29Z",
        "generation": 1,
        "resourceVersion": "15339370",
        "uid": MODULE.BASELINE_UID,
    })
    return value


def source_live(*, revision: str = REVISION) -> dict[str, Any]:
    value = copy.deepcopy(MODULE.expected_source_projection())
    value["metadata"].update({
        "generation": 1,
        "resourceVersion": "15500000",
        "uid": "00000000-0000-4000-8000-000000000010",
    })
    value["status"] = {
        "artifact": {"revision": f"main@sha1:{revision}"},
        "observedGeneration": 1,
        "conditions": [{"type": "Ready", "status": "True", "observedGeneration": 1}],
    }
    return value


def temporary_root(directory: str) -> Path:
    """Use the owner-private temporary directory without symlinked parents.

    ``TemporaryDirectory`` creates a mode-0700 directory, but macOS commonly
    exposes its temporary root through ``/var`` (a symlink to ``/private/var``).
    The production sinks intentionally reject every symlinked path component,
    so resolve the directory created by the standard-library helper before
    handing it to them.  Linux paths are unchanged by ``resolve``.
    """
    return Path(directory).resolve()


class FakeKubernetes:
    """A deliberately narrow API fake: no list, wildcard, or delete-all path."""

    def __init__(self, *, baseline: dict[str, Any] | None = None) -> None:
        self.objects: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        if baseline is not None:
            self.objects[key(MODULE.target(baseline))] = copy.deepcopy(baseline)
        source = source_live()
        self.objects[key(MODULE.target(source))] = source
        self.created: list[dict[str, Any]] = []
        self.patched: list[tuple[dict[str, str], list[dict[str, Any]]]] = []
        self.deleted: list[dict[str, str]] = []
        self._next_uid = 1
        self._next_resource_version = 16000000

    def get(self, identity: dict[str, str]) -> dict[str, Any] | None:
        value = self.objects.get(key(identity))
        return copy.deepcopy(value) if value is not None else None

    def create(self, value: dict[str, Any]) -> dict[str, Any]:
        identity = MODULE.target(value)
        if key(identity) in self.objects:
            raise MODULE.Conflict(f"{identity['kind']}/{identity['name']} already exists")
        observed = copy.deepcopy(value)
        observed["metadata"]["uid"] = str(uuid.UUID(f"00000000-0000-4000-8000-{self._next_uid:012d}"))
        observed["metadata"]["resourceVersion"] = str(self._next_resource_version)
        self._next_uid += 1
        self._next_resource_version += 1
        self.objects[key(identity)] = observed
        self.created.append(copy.deepcopy(observed))
        return copy.deepcopy(observed)

    def patch(self, identity: dict[str, str], operations: list[dict[str, Any]]) -> dict[str, Any]:
        current = self.objects[key(identity)]
        updated = apply_json_patch(current, operations)
        updated["metadata"]["resourceVersion"] = str(self._next_resource_version)
        self._next_resource_version += 1
        if identity["kind"] == "Kustomization":
            old_suspended = current["spec"]["suspend"]
            new_suspended = updated["spec"]["suspend"]
            if old_suspended != new_suspended:
                updated["metadata"]["generation"] = current.get("metadata", {}).get("generation", 1) + 1
                generation = updated["metadata"]["generation"]
                updated["status"] = {
                    "observedGeneration": generation,
                    "conditions": [{"type": "Ready", "status": "True", "observedGeneration": generation}],
                }
                if new_suspended is False:
                    updated["metadata"]["finalizers"] = ["finalizers.fluxcd.io"]
                    revision = self.objects[key(MODULE.target(source_live()))]["status"]["artifact"]["revision"]
                    updated["status"].update({
                        "lastAppliedRevision": revision,
                        "lastAttemptedRevision": revision,
                    })
                    policy_identity = MODULE.target(MODULE.expected_before_network_policy())
                    policy = self.objects.get(key(policy_identity))
                    if policy is not None:
                        policy["metadata"]["labels"].update(copy.deepcopy(MODULE.FLUX_INVENTORY_LABELS))
                        policy["metadata"]["resourceVersion"] = str(self._next_resource_version)
                        self._next_resource_version += 1
        self.objects[key(identity)] = updated
        self.patched.append((copy.deepcopy(identity), copy.deepcopy(operations)))
        return copy.deepcopy(updated)

    def delete(self, identity: dict[str, str], *, uid: str, resource_version: str) -> None:
        current = self.objects.get(key(identity))
        if current is None:
            return
        current_uid, current_resource_version = MODULE._identity_metadata(current, f"delete {identity['kind']}/{identity['name']}")
        if current_uid != uid or current_resource_version != resource_version:
            raise MODULE.Conflict(f"delete precondition failed for {identity['kind']}/{identity['name']}")
        self.objects.pop(key(identity), None)
        self.deleted.append(copy.deepcopy(identity))


class ContactRecordingKubernetes(FakeKubernetes):
    """Count all API reads so sink guards can prove zero contact."""

    def __init__(self, *, baseline: dict[str, Any] | None = None) -> None:
        self.contact_count = 0
        super().__init__(baseline=baseline)

    def get(self, identity: dict[str, str]) -> dict[str, Any] | None:
        self.contact_count += 1
        return super().get(identity)


class PatchResponseDriftKubernetes(FakeKubernetes):
    """Apply the baseline patch but return a response with semantic drift."""

    def patch(self, identity: dict[str, str], operations: list[dict[str, Any]]) -> dict[str, Any]:
        updated = super().patch(identity, operations)
        if identity["kind"] == "NetworkPolicy" and sum(item[0]["kind"] == "NetworkPolicy" for item in self.patched) == 1:
            updated["spec"]["egress"][0]["ports"][0]["port"] = 54
        return updated


class PatchTransportFailureAfterApplyKubernetes(FakeKubernetes):
    """Simulate an API timeout after the server has committed the patch."""

    def patch(self, identity: dict[str, str], operations: list[dict[str, Any]]) -> dict[str, Any]:
        updated = super().patch(identity, operations)
        if identity["kind"] == "NetworkPolicy" and sum(item[0]["kind"] == "NetworkPolicy" for item in self.patched) == 1:
            raise TimeoutError("response lost after apply")
        return updated


class ConcurrentBaselineMutationKubernetes(FakeKubernetes):
    """Inject a concurrent annotation update between preflight and patch."""

    def patch(self, identity: dict[str, str], operations: list[dict[str, Any]]) -> dict[str, Any]:
        if identity["kind"] == "NetworkPolicy" and not any(item[0]["kind"] == "NetworkPolicy" for item in self.patched):
            current = self.objects[key(identity)]
            current.setdefault("metadata", {}).setdefault("annotations", {})["example.org/concurrent"] = "preserve"
            self._next_resource_version += 1
            current["metadata"]["resourceVersion"] = str(self._next_resource_version)
        return super().patch(identity, operations)


class SourceRevisionDriftKubernetes(FakeKubernetes):
    def __init__(self, *, baseline: dict[str, Any] | None = None) -> None:
        super().__init__(baseline=baseline)
        source = self.objects[key(MODULE.source_target())]
        source["status"]["artifact"]["revision"] = "main@sha1:" + "f" * 40


class ReceiptFailureAfterReconcileSink(MODULE.MemoryReceiptSink):
    def commit(self, value: dict[str, Any]) -> None:
        if value.get("status") == "completed":
            raise RuntimeError("simulated durable receipt failure")
        super().commit(value)


class SimulatedProcessDeath(BaseException):
    """Deterministic stand-in for a process disappearing at a crash point."""


class CreateResponseLostKubernetes(FakeKubernetes):
    """The API server commits the first create, but its response is lost."""

    def create(self, value: dict[str, Any]) -> dict[str, Any]:
        observed = super().create(value)
        if len(self.created) == 1:
            raise TimeoutError("response lost after server-side create")
        return observed


class CreateResponseLostThenPatchDriftKubernetes(CreateResponseLostKubernetes):
    """Response-lost create followed by a failed postcondition."""

    def patch(self, identity: dict[str, str], operations: list[dict[str, Any]]) -> dict[str, Any]:
        updated = super().patch(identity, operations)
        if identity["kind"] == "NetworkPolicy" and sum(item[0]["kind"] == "NetworkPolicy" for item in self.patched) == 1:
            updated["spec"]["egress"][0]["ports"][0]["port"] = 54
        return updated


class CreateResponseLostWithoutMarkerKubernetes(FakeKubernetes):
    """A same-name response-lost object without our marker is never adopted."""

    def create(self, value: dict[str, Any]) -> dict[str, Any]:
        observed = super().create(value)
        observed["metadata"]["annotations"].pop(MODULE.HANDOVER_OPERATION_ANNOTATION, None)
        self.objects[key(MODULE.target(observed))] = copy.deepcopy(observed)
        raise TimeoutError("response lost and marker was not present")


class ReplacementBetweenGetAndDeleteKubernetes(FakeKubernetes):
    """Replace one owned object immediately before the conditional DELETE."""

    def __init__(self, *, baseline: dict[str, Any] | None = None) -> None:
        super().__init__(baseline=baseline)
        self.replaced = False

    def delete(self, identity: dict[str, str], *, uid: str, resource_version: str) -> None:
        if identity["kind"] == "ServiceAccount" and not self.replaced:
            current = self.objects[key(identity)]
            current["metadata"]["uid"] = "00000000-0000-4000-8000-000000009999"
            current["metadata"]["resourceVersion"] = "17000000"
            self.replaced = True
        return super().delete(identity, uid=uid, resource_version=resource_version)


class CrashAfterCreateKubernetes(FakeKubernetes):
    def create(self, value: dict[str, Any]) -> dict[str, Any]:
        observed = super().create(value)
        if len(self.created) == 1:
            raise SimulatedProcessDeath("crash after create before journal-after")
        return observed


class CrashAfterNetworkPolicyPatchKubernetes(FakeKubernetes):
    def patch(self, identity: dict[str, str], operations: list[dict[str, Any]]) -> dict[str, Any]:
        updated = super().patch(identity, operations)
        if identity["kind"] == "NetworkPolicy" and sum(item[0]["kind"] == "NetworkPolicy" for item in self.patched) == 1:
            raise SimulatedProcessDeath("crash after NetworkPolicy patch")
        return updated


class CrashAfterUnsuspendKubernetes(FakeKubernetes):
    def patch(self, identity: dict[str, str], operations: list[dict[str, Any]]) -> dict[str, Any]:
        updated = super().patch(identity, operations)
        if identity["kind"] == "Kustomization" and updated.get("spec", {}).get("suspend") is False:
            raise SimulatedProcessDeath("crash after Kustomization unsuspend")
        return updated


class CrashAfterUnsuspendThenStuckDeleteKubernetes(CrashAfterUnsuspendKubernetes):
    """Crash after activation, then retain the exact Kustomization once."""

    def __init__(self, *, baseline: dict[str, Any] | None = None) -> None:
        super().__init__(baseline=baseline)
        self.allow_kustomization_delete = False
        self.delete_attempts: list[dict[str, str]] = []

    def delete(self, identity: dict[str, str], *, uid: str, resource_version: str) -> None:
        if identity["kind"] == "Kustomization":
            self.delete_attempts.append(copy.deepcopy(identity))
            if not self.allow_kustomization_delete:
                return
        return FakeKubernetes.delete(self, identity, uid=uid, resource_version=resource_version)


class CrashAfterCompletedReceiptSink(MODULE.MemoryReceiptSink):
    def commit(self, value: dict[str, Any]) -> None:
        super().commit(value)
        if value.get("status") == "completed":
            raise SimulatedProcessDeath("crash after receipt before journal final")


class CrashAfterMarkerRemovalKubernetes(FakeKubernetes):
    def patch(self, identity: dict[str, str], operations: list[dict[str, Any]]) -> dict[str, Any]:
        updated = super().patch(identity, operations)
        if identity["kind"] == "ServiceAccount" and any(item.get("op") == "remove" for item in operations):
            raise SimulatedProcessDeath("crash after marker removal")
        return updated


class CrashBeforeMarkerRemovalPatchKubernetes(FakeKubernetes):
    """Crash after durable marker-removal intent but before sending PATCH."""

    def patch(self, identity: dict[str, str], operations: list[dict[str, Any]]) -> dict[str, Any]:
        if identity["kind"] == "ServiceAccount" and any(item.get("op") == "remove" for item in operations):
            raise SimulatedProcessDeath("crash before marker removal patch")
        return super().patch(identity, operations)


class CrashBeforeMarkerRemovalWithReplacementKubernetes(FakeKubernetes):
    """Crash before PATCH after the exact-name object has been replaced."""

    def patch(self, identity: dict[str, str], operations: list[dict[str, Any]]) -> dict[str, Any]:
        if identity["kind"] == "ServiceAccount" and any(item.get("op") == "remove" for item in operations):
            current = self.objects[key(identity)]
            current["metadata"]["uid"] = "00000000-0000-4000-8000-000000009997"
            current["metadata"]["resourceVersion"] = "17000002"
            raise SimulatedProcessDeath("crash before marker patch after replacement")
        return super().patch(identity, operations)


class CrashBeforeMarkerRemovalWithForeignMarkerKubernetes(FakeKubernetes):
    """Crash before PATCH after another operation marker was installed."""

    def patch(self, identity: dict[str, str], operations: list[dict[str, Any]]) -> dict[str, Any]:
        if identity["kind"] == "ServiceAccount" and any(item.get("op") == "remove" for item in operations):
            current = self.objects[key(identity)]
            current["metadata"]["annotations"][MODULE.HANDOVER_OPERATION_ANNOTATION] = "00000000-0000-4000-8000-000000009996"
            raise SimulatedProcessDeath("crash before marker patch after foreign marker")
        return super().patch(identity, operations)


class CrashAfterRollbackSuspendKubernetes(FakeKubernetes):
    def patch(self, identity: dict[str, str], operations: list[dict[str, Any]]) -> dict[str, Any]:
        updated = super().patch(identity, operations)
        if identity["kind"] == "Kustomization" and updated.get("spec", {}).get("suspend") is True and any(item.get("op") == "replace" for item in operations):
            raise SimulatedProcessDeath("crash after rollback suspend")
        return updated


class CrashAfterRollbackRestoreKubernetes(FakeKubernetes):
    def patch(self, identity: dict[str, str], operations: list[dict[str, Any]]) -> dict[str, Any]:
        updated = super().patch(identity, operations)
        if identity["kind"] == "NetworkPolicy" and any(
            item.get("op") == "replace"
            and item.get("path") == "/metadata/labels/stadtstack.io~1owner"
            and item.get("value") == MODULE.OLD_OWNER
            for item in operations
        ):
            raise SimulatedProcessDeath("crash after rollback restore")
        return updated


class CrashAfterRollbackDeleteKubernetes(FakeKubernetes):
    def delete(self, identity: dict[str, str], *, uid: str, resource_version: str) -> None:
        super().delete(identity, uid=uid, resource_version=resource_version)
        if identity["kind"] == "Kustomization":
            raise SimulatedProcessDeath("crash after rollback delete")


class StuckKustomizationDeleteKubernetes(FakeKubernetes):
    def __init__(self, *, baseline: dict[str, Any] | None = None) -> None:
        super().__init__(baseline=baseline)
        self.delete_attempts: list[dict[str, str]] = []

    def delete(self, identity: dict[str, str], *, uid: str, resource_version: str) -> None:
        self.delete_attempts.append(copy.deepcopy(identity))
        if identity["kind"] == "Kustomization":
            # Simulate a successful API response while finalizers keep the
            # object in Terminating state.  Kubernetes may advance the
            # resourceVersion while setting deletionTimestamp, so recovery
            # must use the fresh RV while retaining the journaled UID.
            current = self.objects[key(identity)]
            current["metadata"]["deletionTimestamp"] = "2026-08-27T17:00:00Z"
            current["metadata"]["resourceVersion"] = str(self._next_resource_version)
            self._next_resource_version += 1
            return
        return super().delete(identity, uid=uid, resource_version=resource_version)


class RetryableKustomizationDeleteKubernetes(StuckKustomizationDeleteKubernetes):
    """Keep the exact Kustomization once, then clear its finalizer on retry."""

    def __init__(self, *, baseline: dict[str, Any] | None = None) -> None:
        super().__init__(baseline=baseline)
        self.allow_kustomization_delete = False

    def delete(self, identity: dict[str, str], *, uid: str, resource_version: str) -> None:
        self.delete_attempts.append(copy.deepcopy(identity))
        if identity["kind"] == "Kustomization" and not self.allow_kustomization_delete:
            return
        return FakeKubernetes.delete(self, identity, uid=uid, resource_version=resource_version)


class KustomizationReplacementBetweenGetAndDeleteKubernetes(FakeKubernetes):
    """Replace the owned Kustomization before its conditional DELETE."""

    def delete(self, identity: dict[str, str], *, uid: str, resource_version: str) -> None:
        if identity["kind"] == "Kustomization":
            current = self.objects[key(identity)]
            current["metadata"]["uid"] = "00000000-0000-4000-8000-000000009995"
            current["metadata"]["resourceVersion"] = "17000003"
        return super().delete(identity, uid=uid, resource_version=resource_version)


class MarkerResponseLostThenReplacementKubernetes(FakeKubernetes):
    def patch(self, identity: dict[str, str], operations: list[dict[str, Any]]) -> dict[str, Any]:
        updated = super().patch(identity, operations)
        if identity["kind"] == "ServiceAccount" and any(item.get("op") == "remove" for item in operations):
            replacement = copy.deepcopy(updated)
            replacement["metadata"]["uid"] = "00000000-0000-4000-8000-000000009999"
            replacement["metadata"]["resourceVersion"] = "17000000"
            self.objects[key(identity)] = replacement
            raise TimeoutError("marker response lost after delete/recreate")
        return updated


class CrashAfterMarkerRemovalThenReplacementKubernetes(FakeKubernetes):
    def patch(self, identity: dict[str, str], operations: list[dict[str, Any]]) -> dict[str, Any]:
        updated = super().patch(identity, operations)
        if identity["kind"] == "ServiceAccount" and any(item.get("op") == "remove" for item in operations):
            replacement = copy.deepcopy(updated)
            replacement["metadata"]["uid"] = "00000000-0000-4000-8000-000000009998"
            replacement["metadata"]["resourceVersion"] = "17000001"
            self.objects[key(identity)] = replacement
            raise SimulatedProcessDeath("crash after marker removal and delete/recreate")
        return updated


class CrashAfterRollbackJournalCommit(MODULE.MemoryJournalSink):
    def __init__(self, *, crash_status: str) -> None:
        super().__init__()
        self.crash_status = crash_status
        self.crashed = False

    def commit(self, value: dict[str, Any]) -> None:
        super().commit(value)
        if value.get("status") == self.crash_status and not self.crashed:
            self.crashed = True
            raise SimulatedProcessDeath(f"crash after journal {self.crash_status}")


class WorkbenchBaselineHandoverTests(unittest.TestCase):
    def plan(self) -> dict[str, Any]:
        hashes = {
            path: MODULE.bytes_digest(f"{path}\n".encode())
            for path in MODULE.PROTECTED_PATHS
        }
        return MODULE.build_plan(REVISION, hashes)

    def test_exact_live_baseline_digest_and_render_preserve_spec(self) -> None:
        live = baseline_live()
        self.assertEqual(MODULE.digest(live), MODULE.BASELINE_BEFORE_DIGEST)
        self.assertEqual(MODULE._server_fields(live), MODULE.expected_before_network_policy())
        final = MODULE.expected_network_policy()
        self.assertEqual(final["spec"], live["spec"])
        self.assertEqual(final["metadata"]["labels"]["stadtstack.io/owner"], MODULE.NEW_OWNER)
        self.assertEqual(final["metadata"]["annotations"], {MODULE.SSA_ANNOTATION: MODULE.SSA_MODE})
        self.assertEqual(
            set(final["metadata"]["labels"]),
            set(live["metadata"]["labels"]),
        )
        reconciled = MODULE.expected_reconciled_network_policy()
        self.assertEqual(reconciled["spec"], live["spec"])
        self.assertEqual(reconciled["metadata"]["labels"][MODULE.FLUX_INVENTORY_NAME_LABEL], MODULE.FLUX_NAME)
        self.assertEqual(reconciled["metadata"]["labels"][MODULE.FLUX_INVENTORY_NAMESPACE_LABEL], MODULE.FLUX_NAMESPACE)

    def test_flux_scope_is_one_suspended_networkpolicy_only(self) -> None:
        objects = MODULE.expected_flux_objects(suspended=True)
        MODULE.validate_flux_objects(objects, suspended=True)
        self.assertEqual(set(objects), {"serviceAccount", "role", "roleBinding", "kustomization"})
        self.assertEqual(objects["role"]["metadata"]["namespace"], MODULE.WORKBENCH_NAMESPACE)
        self.assertEqual(objects["role"]["rules"], [{
            "apiGroups": ["networking.k8s.io"],
            "resourceNames": [MODULE.WORKBENCH_NAME],
            "resources": ["networkpolicies"],
            "verbs": ["get", "patch", "update"],
        }])
        self.assertFalse(objects["kustomization"]["spec"]["prune"])
        self.assertTrue(objects["kustomization"]["spec"]["suspend"])
        self.assertEqual(objects["kustomization"]["spec"]["path"], f"./{MODULE.BASELINE_ROOT}")

    def test_source_and_ready_validators_bind_exact_revision_and_generation(self) -> None:
        source = source_live()
        source_proof = MODULE.validate_source(source, REVISION)
        self.assertEqual(source_proof["artifactRevision"], f"main@sha1:{REVISION}")
        kustomization = copy.deepcopy(MODULE.expected_flux_objects(suspended=False)["kustomization"])
        kustomization["metadata"].update({
            "generation": 2,
            "resourceVersion": "16000005",
            "uid": "00000000-0000-4000-8000-000000000011",
            "finalizers": ["finalizers.fluxcd.io"],
        })
        kustomization["status"] = {
            "observedGeneration": 2,
            "lastAppliedRevision": f"main@sha1:{REVISION}",
            "lastAttemptedRevision": f"main@sha1:{REVISION}",
            "conditions": [{"type": "Ready", "status": "True", "observedGeneration": 2}],
        }
        ready = MODULE.validate_flux_ready(kustomization, kustomization["metadata"]["uid"], REVISION)
        self.assertTrue(ready["ready"])

    def test_reconciled_policy_requires_flux_inventory_and_exact_spec(self) -> None:
        kube = FakeKubernetes(baseline=baseline_live())
        policy = baseline_live()
        policy["metadata"]["labels"].update(copy.deepcopy(MODULE.FLUX_INVENTORY_LABELS))
        policy["metadata"]["labels"]["stadtstack.io/owner"] = MODULE.NEW_OWNER
        policy["metadata"]["annotations"] = {MODULE.SSA_ANNOTATION: MODULE.SSA_MODE}
        MODULE.validate_reconciled_network_policy(policy)
        policy["spec"]["egress"][0]["ports"][0]["port"] = 54
        with self.assertRaises(MODULE.HandoverError):
            MODULE.validate_reconciled_network_policy(policy)

    def test_live_handover_creates_only_owned_flux_and_patches_existing_policy(self) -> None:
        sink = MODULE.MemoryReceiptSink()
        kube = FakeKubernetes(baseline=baseline_live())
        receipt = MODULE.run(self.plan(), mode="live", kube=kube, sink=sink)
        self.assertEqual(receipt["status"], "completed")
        self.assertEqual(len(sink.values), 1)
        self.assertEqual(len(kube.created), 4)
        self.assertEqual(len(kube.deleted), 0)
        final = kube.get(MODULE.target(MODULE.expected_before_network_policy()))
        assert final is not None
        self.assertEqual(MODULE._server_fields(final), MODULE.expected_reconciled_network_policy())
        self.assertEqual(final["metadata"]["uid"], MODULE.BASELINE_UID)
        self.assertEqual(receipt["effects"]["networkPolicySpecChanged"], False)
        self.assertEqual(receipt["effects"]["networkPolicyOwnerLabelChanged"], True)
        self.assertEqual(receipt["effects"]["fluxSsaOverrideAdded"], True)
        self.assertEqual(receipt["effects"]["kustomizationUnsuspended"], True)
        self.assertEqual(receipt["effects"]["fluxReady"], True)
        self.assertEqual(receipt["effects"]["networkPolicyReconciled"], True)
        self.assertEqual(receipt["flux"]["ready"]["lastAppliedRevision"], f"main@sha1:{REVISION}")
        self.assertEqual(receipt["flux"]["sourceBefore"]["uid"], receipt["flux"]["sourceAfter"]["uid"])
        self.assertTrue(receipt["flux"]["networkPolicyReconciled"]["reconciled"])
        self.assertEqual(receipt["adoption"]["mode"], "flux-ssa-override")
        self.assertEqual(receipt["baseline"]["beforeResourceVersion"], "15339370")

        patch_targets = [identity["kind"] for identity, _operations in kube.patched]
        self.assertEqual(
            patch_targets,
            ["ServiceAccount", "Role", "RoleBinding", "Kustomization", "NetworkPolicy", "Kustomization"],
        )
        self.assertTrue(kube.get(MODULE.source_target()) is not None)

    def test_receipt_failure_after_flux_reconcile_suspends_restores_inventory_and_deletes_owned_objects(self) -> None:
        kube = FakeKubernetes(baseline=baseline_live())
        sink = ReceiptFailureAfterReconcileSink()
        with self.assertRaisesRegex(MODULE.HandoverError, "rolled-back"):
            MODULE.run(self.plan(), mode="live", kube=kube, sink=sink)
        self.assertEqual(sink.values[0]["status"], "rolled-back")
        self.assertTrue(sink.values[0]["rollback"]["suspendFirst"])
        self.assertTrue(sink.values[0]["rollback"]["restoredPriorOwnerAndSsa"])
        self.assertEqual(
            [identity["kind"] for identity, _operations in kube.patched],
            [
                "ServiceAccount", "Role", "RoleBinding", "Kustomization",
                "NetworkPolicy", "Kustomization", "Kustomization", "NetworkPolicy",
            ],
        )
        baseline = kube.get(MODULE.target(MODULE.expected_before_network_policy()))
        assert baseline is not None
        self.assertEqual(MODULE._server_fields(baseline), MODULE.expected_before_network_policy())
        self.assertEqual(
            set(sink.values[0]["rollback"]["deletedObjectIds"]),
            {"serviceAccount", "role", "roleBinding", "kustomization"},
        )
        self.assertIsNotNone(kube.get(MODULE.source_target()))

    def test_stale_shared_source_blocks_before_creating_flux_objects(self) -> None:
        kube = SourceRevisionDriftKubernetes(baseline=baseline_live())
        sink = MODULE.MemoryReceiptSink()
        with patch.object(MODULE, "FLUX_READY_TIMEOUT_SECONDS", 0):
            with self.assertRaisesRegex(MODULE.HandoverError, "blocked"):
                MODULE.run(self.plan(), mode="live", kube=kube, sink=sink)
        self.assertEqual(sink.values[0]["status"], "blocked")
        self.assertEqual(kube.created, [])
        self.assertEqual(kube.patched, [])

    def test_preexisting_flux_identity_blocks_without_mutation(self) -> None:
        kube = FakeKubernetes(baseline=baseline_live())
        existing = next(iter(MODULE.expected_flux_objects().values()))
        kube.create(existing)
        sink = MODULE.MemoryReceiptSink()
        with self.assertRaises(MODULE.HandoverError):
            MODULE.run(self.plan(), mode="live", kube=kube, sink=sink)
        self.assertEqual(len(sink.values), 1)
        self.assertEqual(sink.values[0]["status"], "blocked")
        self.assertEqual(sink.values[0]["rollback"]["status"], "not-started")
        self.assertEqual(len(kube.created), 1)
        self.assertEqual(len(kube.patched), 0)
        baseline = kube.get(MODULE.target(MODULE.expected_before_network_policy()))
        assert baseline is not None
        self.assertEqual(MODULE._server_fields(baseline), MODULE.expected_before_network_policy())

    def test_patch_postcondition_failure_rolls_back_owner_and_owned_flux(self) -> None:
        kube = PatchResponseDriftKubernetes(baseline=baseline_live())
        sink = MODULE.MemoryReceiptSink()
        with self.assertRaisesRegex(MODULE.HandoverError, "rolled-back"):
            MODULE.run(self.plan(), mode="live", kube=kube, sink=sink)
        self.assertEqual(len(sink.values), 1)
        self.assertEqual(sink.values[0]["status"], "rolled-back")
        self.assertFalse(sink.values[0]["rollback"]["existingNetworkPolicyDeleted"])
        self.assertEqual(
            set(sink.values[0]["rollback"]["deletedObjectIds"]),
            {"serviceAccount", "role", "roleBinding", "kustomization"},
        )
        baseline = kube.get(MODULE.target(MODULE.expected_before_network_policy()))
        assert baseline is not None
        self.assertEqual(MODULE._server_fields(baseline), MODULE.expected_before_network_policy())
        self.assertEqual(
            [identity for identity in kube.objects if identity[2] == MODULE.FLUX_NAMESPACE],
            [key(MODULE.source_target())],
        )
        self.assertEqual(
            len([identity for identity in kube.objects if identity[1] == "NetworkPolicy"]),
            1,
        )

    def test_patch_transport_failure_after_apply_rolls_back_by_rechecking_live_object(self) -> None:
        kube = PatchTransportFailureAfterApplyKubernetes(baseline=baseline_live())
        sink = MODULE.MemoryReceiptSink()
        with self.assertRaisesRegex(MODULE.HandoverError, "rolled-back"):
            MODULE.run(self.plan(), mode="live", kube=kube, sink=sink)
        self.assertEqual(sink.values[0]["status"], "rolled-back")
        baseline = kube.get(MODULE.target(MODULE.expected_before_network_policy()))
        assert baseline is not None
        self.assertEqual(MODULE._server_fields(baseline), MODULE.expected_before_network_policy())

    def test_response_lost_after_server_create_is_adopted_only_with_exact_marker_and_spec(self) -> None:
        kube = CreateResponseLostKubernetes(baseline=baseline_live())
        sink = MODULE.MemoryReceiptSink()
        receipt = MODULE.run(self.plan(), mode="live", kube=kube, sink=sink)
        self.assertEqual(receipt["status"], "completed")
        self.assertEqual(receipt["objects"][0]["apiOutcome"], "post-send-uncertain-discovered")
        self.assertTrue(all(record["markerRemoved"] for record in receipt["objects"]))
        self.assertEqual(len(kube.created), 4)

    def test_response_lost_create_is_in_rollback_inventory(self) -> None:
        kube = CreateResponseLostThenPatchDriftKubernetes(baseline=baseline_live())
        sink = MODULE.MemoryReceiptSink()
        with self.assertRaisesRegex(MODULE.HandoverError, "rolled-back"):
            MODULE.run(self.plan(), mode="live", kube=kube, sink=sink)
        self.assertEqual(sink.values[0]["status"], "rolled-back")
        self.assertEqual(
            set(sink.values[0]["rollback"]["deletedObjectIds"]),
            set(MODULE.object_order()),
        )
        self.assertEqual(sink.values[0]["objects"][0]["apiOutcome"], "post-send-uncertain-discovered")
        baseline = kube.get(MODULE.target(MODULE.expected_before_network_policy()))
        assert baseline is not None
        self.assertEqual(MODULE._server_fields(baseline), MODULE.expected_before_network_policy())

    def test_response_lost_object_without_transaction_marker_fails_closed(self) -> None:
        kube = CreateResponseLostWithoutMarkerKubernetes(baseline=baseline_live())
        sink = MODULE.MemoryReceiptSink()
        with self.assertRaisesRegex(MODULE.HandoverError, "rolled-back"):
            MODULE.run(self.plan(), mode="live", kube=kube, sink=sink)
        self.assertEqual(sink.values[0]["status"], "rolled-back")
        identity = MODULE.target(MODULE.expected_flux_objects()["serviceAccount"])
        surviving = kube.get(identity)
        self.assertIsNotNone(surviving)
        self.assertNotIn(MODULE.HANDOVER_OPERATION_ANNOTATION, surviving["metadata"].get("annotations", {}))
        self.assertEqual(sink.values[0]["rollback"]["deletedObjectIds"], [])

    def test_replacement_between_get_and_delete_survives_uid_resource_version_preconditions(self) -> None:
        kube = ReplacementBetweenGetAndDeleteKubernetes(baseline=baseline_live())
        sink = ReceiptFailureAfterReconcileSink()
        with self.assertRaisesRegex(MODULE.HandoverError, "rollback-incomplete"):
            MODULE.run(self.plan(), mode="live", kube=kube, sink=sink)
        self.assertTrue(kube.replaced)
        identity = MODULE.target(MODULE.expected_flux_objects()["serviceAccount"])
        replacement = kube.get(identity)
        self.assertIsNotNone(replacement)
        self.assertEqual(replacement["metadata"]["uid"], "00000000-0000-4000-8000-000000009999")
        self.assertEqual(replacement["metadata"]["resourceVersion"], "17000000")
        self.assertNotIn(identity, kube.deleted)

    def test_recovery_after_crash_at_create_discovers_and_rolls_back_exact_object(self) -> None:
        kube = CrashAfterCreateKubernetes(baseline=baseline_live())
        sink = MODULE.MemoryReceiptSink()
        journal = MODULE.MemoryJournalSink()
        with self.assertRaises(SimulatedProcessDeath):
            MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        self.assertEqual(journal.state["status"], "in-progress")
        recovered = MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        self.assertEqual(recovered["status"], "recovered-rolled-back")
        self.assertTrue(recovered["recoveredFromJournal"])
        self.assertEqual(set(recovered["rollback"]["deletedObjectIds"]), {"serviceAccount"})
        self.assertIsNone(kube.get(MODULE.target(MODULE.expected_flux_objects()["serviceAccount"])))

    def test_recovery_after_crash_at_network_policy_patch_restores_before_delete(self) -> None:
        kube = CrashAfterNetworkPolicyPatchKubernetes(baseline=baseline_live())
        sink = MODULE.MemoryReceiptSink()
        journal = MODULE.MemoryJournalSink()
        with self.assertRaises(SimulatedProcessDeath):
            MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        recovered = MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        self.assertEqual(recovered["status"], "recovered-rolled-back")
        baseline = kube.get(MODULE.target(MODULE.expected_before_network_policy()))
        assert baseline is not None
        self.assertEqual(MODULE._server_fields(baseline), MODULE.expected_before_network_policy())
        self.assertEqual(set(recovered["rollback"]["deletedObjectIds"]), set(MODULE.object_order()))
        self.assertEqual(
            [identity["kind"] for identity, _operations in kube.patched][-2:],
            ["NetworkPolicy", "NetworkPolicy"],
        )

    def test_recovery_after_crash_at_unsuspend_suspends_first_and_restores_inventory(self) -> None:
        kube = CrashAfterUnsuspendKubernetes(baseline=baseline_live())
        sink = MODULE.MemoryReceiptSink()
        journal = MODULE.MemoryJournalSink()
        with self.assertRaises(SimulatedProcessDeath):
            MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        recovered = MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        self.assertEqual(recovered["status"], "recovered-rolled-back")
        self.assertTrue(recovered["rollback"]["suspendFirst"])
        self.assertTrue(recovered["rollback"]["restoredPriorOwnerAndSsa"])
        baseline = kube.get(MODULE.target(MODULE.expected_before_network_policy()))
        assert baseline is not None
        self.assertEqual(MODULE._server_fields(baseline), MODULE.expected_before_network_policy())
        self.assertEqual(set(recovered["rollback"]["deletedObjectIds"]), set(MODULE.object_order()))

    def test_file_recovery_origin_timeout_stays_reserved_until_third_reentry(self) -> None:
        kube = CrashAfterUnsuspendThenStuckDeleteKubernetes(baseline=baseline_live())
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            receipt_path = root / "handover.receipt"
            journal_path = root / "handover.journal"
            receipt = MODULE.ReceiptSink(receipt_path)
            journal = MODULE.JournalSink(journal_path)

            # First invocation dies after the successful unsuspend.  The
            # durable receipt is still only its zero-byte reservation.
            with self.assertRaises(SimulatedProcessDeath):
                MODULE.run(self.plan(), mode="live", kube=kube, sink=receipt, journal=journal)
            self.assertEqual(receipt_path.stat().st_size, 0)

            # Recovery suspends/restores first, then observes an exact,
            # same-UID terminating Kustomization.  It must leave the journal
            # retryable and never turn the zero-byte reservation into an
            # immutable rollback-incomplete receipt.
            with patch.object(MODULE, "FLUX_DELETE_TIMEOUT_SECONDS", 0), patch.object(MODULE, "FLUX_DELETE_POLL_SECONDS", 0):
                with self.assertRaisesRegex(MODULE.HandoverError, "pending"):
                    MODULE.run(self.plan(), mode="live", kube=kube, sink=receipt, journal=journal)
            self.assertEqual(receipt_path.stat().st_size, 0)
            reopened_journal = MODULE.JournalSink(journal_path)
            pending = reopened_journal.load()
            self.assertIsNotNone(pending)
            self.assertEqual(pending["status"], "rollback-finalizing")
            self.assertEqual(pending["rollback"]["status"], MODULE.ROLLBACK_PENDING_STATUS)
            self.assertEqual(pending["rollback"]["pendingObjectIds"], ["kustomization"])
            self.assertTrue(
                any(
                    identity["kind"] == "Kustomization"
                    and any(operation.get("value") is True for operation in operations)
                    for identity, operations in kube.patched
                )
            )
            self.assertTrue(
                any(
                    identity["kind"] == "NetworkPolicy"
                    and any(operation.get("value") == MODULE.OLD_OWNER for operation in operations)
                    for identity, operations in kube.patched
                )
            )
            self.assertIsNone(MODULE.ReceiptSink(receipt_path, allow_existing_completed=True).load())
            for name in ("serviceAccount", "role", "roleBinding", "kustomization"):
                self.assertIsNotNone(kube.get(MODULE.target(MODULE.expected_flux_objects()[name])))

            # The finalizer clears between retries.  Reopening both sinks is
            # part of the contract: the third exact invocation completes the
            # same operation and atomically commits its receipt.
            kube.allow_kustomization_delete = True
            reopened_receipt = MODULE.ReceiptSink(receipt_path, allow_existing_completed=True)
            final_journal = MODULE.JournalSink(journal_path)
            with patch.object(MODULE, "FLUX_DELETE_TIMEOUT_SECONDS", 0), patch.object(MODULE, "FLUX_DELETE_POLL_SECONDS", 0):
                completed = MODULE.run(self.plan(), mode="live", kube=kube, sink=reopened_receipt, journal=final_journal)
            self.assertEqual(completed["status"], "recovered-rolled-back")
            self.assertGreater(receipt_path.stat().st_size, 0)
            self.assertEqual(MODULE.JournalSink(journal_path).load()["status"], "recovered-rolled-back")
            self.assertEqual(set(completed["rollback"]["deletedObjectIds"]), set(MODULE.object_order()))

    def test_reentry_after_receipt_before_journal_finalization_proves_and_finalizes(self) -> None:
        kube = FakeKubernetes(baseline=baseline_live())
        sink = CrashAfterCompletedReceiptSink()
        journal = MODULE.MemoryJournalSink()
        with self.assertRaises(SimulatedProcessDeath):
            MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        self.assertEqual(journal.state["status"], "finalizing")
        self.assertEqual(sink.values[-1]["status"], "completed")
        completed = MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        self.assertEqual(completed["status"], "completed")
        self.assertTrue(journal.state["finalizedFromReceipt"])
        self.assertEqual(journal.state["status"], "completed")
        self.assertEqual(len(sink.values), 1)

    def test_receipt_load_observes_post_replace_failure_and_later_commit_is_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = temporary_root(directory) / "receipt.json"
            sink = MODULE.ReceiptSink(path)
            replaced = False
            original_replace = MODULE.os.replace
            original_fsync = MODULE.os.fsync

            def replace(source: str | bytes | os.PathLike[str], destination: str | bytes | os.PathLike[str]) -> None:
                nonlocal replaced
                original_replace(source, destination)
                replaced = True

            def fsync(fd: int) -> None:
                if replaced:
                    raise OSError("simulated fsync failure after atomic replace")
                original_fsync(fd)

            value = {"schemaVersion": MODULE.RECEIPT_SCHEMA, "status": "completed", "mode": "live"}
            with patch.object(MODULE.os, "replace", replace), patch.object(MODULE.os, "fsync", fsync):
                with self.assertRaises(OSError):
                    sink.commit(value)
            observed = sink.load()
            self.assertIsNotNone(observed)
            self.assertEqual(observed["status"], "completed")
            with self.assertRaisesRegex(MODULE.HandoverError, "immutable"):
                sink.commit({"schemaVersion": MODULE.RECEIPT_SCHEMA, "status": "completed", "mode": "live"})
            reopened = MODULE.ReceiptSink(path, allow_existing_completed=True)
            self.assertEqual(reopened.load()["status"], "completed")

    def test_recovery_synthesizes_receipt_from_finalized_rollback_journal(self) -> None:
        kube = FakeKubernetes(baseline=baseline_live())
        sink = ReceiptFailureAfterReconcileSink()
        journal = MODULE.MemoryJournalSink()
        with self.assertRaisesRegex(MODULE.HandoverError, "rolled-back"):
            MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        self.assertEqual(journal.state["status"], "rolled-back")
        sink.values.clear()
        recovered_sink = MODULE.MemoryReceiptSink()
        recovered = MODULE.run(self.plan(), mode="live", kube=kube, sink=recovered_sink, journal=journal)
        self.assertEqual(recovered["status"], "rolled-back")
        self.assertTrue(recovered["recoveredFromJournal"])
        self.assertTrue(journal.state["finalizedFromReceipt"])
        self.assertEqual(len(recovered_sink.values), 1)

    def test_recovery_after_rollback_finalization_journal_crash_is_idempotent(self) -> None:
        kube = FakeKubernetes(baseline=baseline_live())
        sink = MODULE.MemoryReceiptSink()
        journal = CrashAfterRollbackJournalCommit(crash_status="rollback-finalizing")
        with self.assertRaises(SimulatedProcessDeath):
            # A failed final postcondition drives rollback; the journal crash
            # occurs after rollback proof and before receipt persistence.
            MODULE.run(self.plan(), mode="live", kube=PatchResponseDriftKubernetes(baseline=baseline_live()), sink=sink, journal=journal)
        self.assertEqual(journal.state["status"], "rollback-finalizing")
        recovered = MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        self.assertEqual(recovered["status"], "recovered-rolled-back")
        self.assertEqual(journal.state["status"], "recovered-rolled-back")

    def test_kustomization_delete_timeout_stays_recoverable_until_finalizer_clears(self) -> None:
        kube = RetryableKustomizationDeleteKubernetes(baseline=baseline_live())
        sink = ReceiptFailureAfterReconcileSink()
        journal = MODULE.MemoryJournalSink()
        with patch.object(MODULE, "FLUX_DELETE_TIMEOUT_SECONDS", 0), patch.object(MODULE, "FLUX_DELETE_POLL_SECONDS", 0):
            with self.assertRaisesRegex(MODULE.HandoverError, "rollback pending"):
                MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        self.assertEqual(sink.values, [])
        self.assertEqual(journal.state["status"], "rollback-finalizing")
        self.assertEqual(journal.state["rollback"]["status"], MODULE.ROLLBACK_PENDING_STATUS)
        self.assertEqual(journal.state["rollback"]["pendingObjectIds"], ["kustomization"])
        self.assertEqual([item["kind"] for item in kube.delete_attempts], ["Kustomization"])
        self.assertEqual(kube.deleted, [])
        for name in ("serviceAccount", "role", "roleBinding", "kustomization"):
            self.assertIsNotNone(kube.get(MODULE.target(MODULE.expected_flux_objects()[name])))

        kube.allow_kustomization_delete = True
        with patch.object(MODULE, "FLUX_DELETE_TIMEOUT_SECONDS", 0), patch.object(MODULE, "FLUX_DELETE_POLL_SECONDS", 0):
            recovered = MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        self.assertEqual(recovered["status"], "recovered-rolled-back")
        self.assertEqual(journal.state["status"], "recovered-rolled-back")
        self.assertEqual(set(recovered["rollback"]["deletedObjectIds"]), set(MODULE.object_order()))

    def test_kustomization_replacement_on_delete_is_terminal_incomplete(self) -> None:
        kube = KustomizationReplacementBetweenGetAndDeleteKubernetes(baseline=baseline_live())
        sink = ReceiptFailureAfterReconcileSink()
        with self.assertRaisesRegex(MODULE.HandoverError, "rollback-incomplete"):
            MODULE.run(self.plan(), mode="live", kube=kube, sink=sink)
        self.assertEqual(sink.values[0]["status"], "rollback-incomplete")
        identity = MODULE.target(MODULE.expected_flux_objects()["kustomization"])
        replacement = kube.get(identity)
        self.assertIsNotNone(replacement)
        self.assertEqual(replacement["metadata"]["uid"], "00000000-0000-4000-8000-000000009995")

    def test_symlink_components_and_dangling_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            real = root / "real"
            real.mkdir()
            link = root / "link"
            link.symlink_to(real, target_is_directory=True)
            dangling = root / "dangling"
            dangling.symlink_to(root / "missing", target_is_directory=True)
            with self.assertRaises(MODULE.HandoverError):
                MODULE.ReceiptSink(link / "receipt.json")
            with self.assertRaises(MODULE.HandoverError):
                MODULE.JournalSink(dangling / "handover.journal")

    def test_receipt_and_journal_same_path_are_rejected_before_kubernetes_contact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = temporary_root(directory) / "receipt.json"
            receipt = MODULE.ReceiptSink(path)
            journal = MODULE.JournalSink(path)
            kube = ContactRecordingKubernetes(baseline=baseline_live())
            with self.assertRaisesRegex(MODULE.HandoverError, "paths must be distinct"):
                MODULE.run(self.plan(), mode="live", kube=kube, sink=receipt, journal=journal)
            self.assertEqual(kube.contact_count, 0)

    def test_receipt_and_journal_normalized_path_alias_is_rejected_before_kubernetes_contact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            receipt = MODULE.ReceiptSink(root / "nested" / ".." / "receipt.json")
            journal = MODULE.JournalSink(root / "receipt.json")
            kube = ContactRecordingKubernetes(baseline=baseline_live())
            with self.assertRaisesRegex(MODULE.HandoverError, "paths must be distinct"):
                MODULE.run(self.plan(), mode="live", kube=kube, sink=receipt, journal=journal)
            self.assertEqual(kube.contact_count, 0)

    def test_receipt_and_journal_hardlink_alias_is_rejected_before_kubernetes_contact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            receipt_path = root / "receipt.json"
            journal_path = root / "journal"
            receipt = MODULE.ReceiptSink(receipt_path)
            os.link(receipt_path, journal_path)
            journal = MODULE.JournalSink(journal_path)
            kube = ContactRecordingKubernetes(baseline=baseline_live())
            with self.assertRaisesRegex(MODULE.HandoverError, "inode aliases"):
                MODULE.run(self.plan(), mode="live", kube=kube, sink=receipt, journal=journal)
            self.assertEqual(kube.contact_count, 0)

    def test_sink_alias_after_reservation_is_rejected_from_descriptor_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = temporary_root(directory)
            receipt_path = root / "receipt.json"
            journal_path = root / "journal"
            receipt = MODULE.ReceiptSink(receipt_path)
            journal = MODULE.JournalSink(journal_path)
            journal_path.unlink()
            os.link(receipt_path, journal_path)
            kube = ContactRecordingKubernetes(baseline=baseline_live())
            with self.assertRaisesRegex(MODULE.HandoverError, "reservation identity changed"):
                MODULE.run(self.plan(), mode="live", kube=kube, sink=receipt, journal=journal)
            self.assertEqual(kube.contact_count, 0)

    def test_receipt_limits_and_nested_secret_keys_without_false_positive_metadata(self) -> None:
        safe = MODULE.MemoryReceiptSink()
        safe.commit({
            "schemaVersion": MODULE.RECEIPT_SCHEMA,
            "status": "completed",
            "metadata": {"automountServiceAccountToken": False, "secretAccess": "forbidden"},
        })
        for forbidden in ("apiKey", "clientSecret", "authorization", "sessionKey", "accessToken", "dbPassword"):
            with self.assertRaises(MODULE.HandoverError):
                MODULE.MemoryReceiptSink().commit({"nested": [{forbidden: "x"}]})
        with self.assertRaisesRegex(MODULE.HandoverError, "bounded size"):
            MODULE.MemoryReceiptSink().commit({"notes": "x" * (MODULE.ReceiptSink.MAX_BYTES + 1)})

    def test_wrapper_verifies_exact_revision_blob_before_execution(self) -> None:
        wrapper = Path(__file__).with_name("handover-staging-workbench-baseline.py").read_text()
        self.assertNotIn("importlib.util", wrapper)
        self.assertIn('"show", f"{revision}:{IMPLEMENTATION_PATH}"', wrapper)
        self.assertIn("exec(compile(blob", wrapper)

    def test_test_temp_roots_are_platform_portable(self) -> None:
        source = Path(__file__).read_text()
        private_tmp = os.path.join(os.sep, "private", "tmp")
        temporary_directory_with_dir = "TemporaryDirectory" + "(dir="
        self.assertNotIn(private_tmp, source)
        self.assertNotIn(temporary_directory_with_dir, source)

    def test_crash_after_marker_removal_recovers_without_uid_adoption(self) -> None:
        kube = CrashAfterMarkerRemovalKubernetes(baseline=baseline_live())
        sink = MODULE.MemoryReceiptSink()
        journal = MODULE.MemoryJournalSink()
        with self.assertRaises(SimulatedProcessDeath):
            MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        recovered = MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        self.assertEqual(recovered["status"], "recovered-rolled-back")
        self.assertEqual(set(recovered["rollback"]["deletedObjectIds"]), {"serviceAccount"})

    def test_crash_before_marker_patch_keeps_exact_marked_object_rollback_owned(self) -> None:
        kube = CrashBeforeMarkerRemovalPatchKubernetes(baseline=baseline_live())
        sink = MODULE.MemoryReceiptSink()
        journal = MODULE.MemoryJournalSink()
        with self.assertRaises(SimulatedProcessDeath):
            MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        record = journal.state["createdObjects"][0]
        self.assertFalse(record["markerRemoved"])
        marked = kube.get(record["target"])
        self.assertIsNotNone(marked)
        self.assertEqual(
            marked["metadata"]["annotations"],
            {MODULE.HANDOVER_OPERATION_ANNOTATION: journal.state["operationMarker"]},
        )
        recovered = MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        self.assertEqual(recovered["status"], "recovered-rolled-back")
        self.assertEqual(record["uid"], recovered["objects"][0]["uid"])
        self.assertIsNone(kube.get(record["target"]))

    def test_crash_before_marker_patch_rejects_replacement_uid_without_adoption(self) -> None:
        kube = CrashBeforeMarkerRemovalWithReplacementKubernetes(baseline=baseline_live())
        sink = MODULE.MemoryReceiptSink()
        journal = MODULE.MemoryJournalSink()
        with self.assertRaises(SimulatedProcessDeath):
            MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        with self.assertRaisesRegex(MODULE.HandoverError, "marker UID changed|transaction-owned"):
            MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        record = journal.state["createdObjects"][0]
        self.assertEqual(record["uid"], "00000000-0000-4000-8000-000000000001")
        replacement = kube.get(record["target"])
        self.assertIsNotNone(replacement)
        self.assertEqual(replacement["metadata"]["uid"], "00000000-0000-4000-8000-000000009997")

    def test_crash_before_marker_patch_rejects_foreign_marker_without_adoption(self) -> None:
        kube = CrashBeforeMarkerRemovalWithForeignMarkerKubernetes(baseline=baseline_live())
        sink = MODULE.MemoryReceiptSink()
        journal = MODULE.MemoryJournalSink()
        with self.assertRaises(SimulatedProcessDeath):
            MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        with self.assertRaisesRegex(MODULE.HandoverError, "marker state ambiguous"):
            MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        record = journal.state["createdObjects"][0]
        self.assertEqual(record["uid"], "00000000-0000-4000-8000-000000000001")
        foreign = kube.get(record["target"])
        self.assertIsNotNone(foreign)
        self.assertEqual(
            foreign["metadata"]["annotations"][MODULE.HANDOVER_OPERATION_ANNOTATION],
            "00000000-0000-4000-8000-000000009996",
        )

    def test_crash_after_rollback_suspend_recovers_same_transaction(self) -> None:
        kube = CrashAfterRollbackSuspendKubernetes(baseline=baseline_live())
        sink = ReceiptFailureAfterReconcileSink()
        journal = MODULE.MemoryJournalSink()
        with self.assertRaises(SimulatedProcessDeath):
            MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        recovered = MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        self.assertEqual(recovered["status"], "recovered-rolled-back")
        self.assertTrue(recovered["rollback"]["restoredPriorOwnerAndSsa"])

    def test_crash_after_rollback_restore_recovers_same_transaction(self) -> None:
        kube = CrashAfterRollbackRestoreKubernetes(baseline=baseline_live())
        sink = ReceiptFailureAfterReconcileSink()
        journal = MODULE.MemoryJournalSink()
        with self.assertRaises(SimulatedProcessDeath):
            MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        recovered = MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        self.assertEqual(recovered["status"], "recovered-rolled-back")
        self.assertTrue(recovered["rollback"]["restoredPriorOwnerAndSsa"])

    def test_crash_after_rollback_delete_recovers_without_deleting_replacement(self) -> None:
        kube = CrashAfterRollbackDeleteKubernetes(baseline=baseline_live())
        sink = ReceiptFailureAfterReconcileSink()
        journal = MODULE.MemoryJournalSink()
        with self.assertRaises(SimulatedProcessDeath):
            MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        recovered = MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        self.assertEqual(recovered["status"], "recovered-rolled-back")
        self.assertTrue(recovered["rollback"]["restoredPriorOwnerAndSsa"])

    def test_lost_marker_response_with_delete_recreate_keeps_replacement_uid_out_of_journal(self) -> None:
        kube = MarkerResponseLostThenReplacementKubernetes(baseline=baseline_live())
        sink = MODULE.MemoryReceiptSink()
        with self.assertRaisesRegex(MODULE.HandoverError, "rollback-incomplete"):
            MODULE.run(self.plan(), mode="live", kube=kube, sink=sink)
        identity = MODULE.target(MODULE.expected_flux_objects()["serviceAccount"])
        replacement = kube.get(identity)
        self.assertEqual(replacement["metadata"]["uid"], "00000000-0000-4000-8000-000000009999")
        self.assertEqual(sink.values[0]["status"], "rollback-incomplete")
        self.assertEqual(sink.values[0]["objects"][0]["uid"], "00000000-0000-4000-8000-000000000001")
        self.assertNotIn(identity, kube.deleted)

    def test_recovery_after_lost_marker_patch_rejects_delete_recreate_uid(self) -> None:
        kube = CrashAfterMarkerRemovalThenReplacementKubernetes(baseline=baseline_live())
        sink = MODULE.MemoryReceiptSink()
        journal = MODULE.MemoryJournalSink()
        with self.assertRaises(SimulatedProcessDeath):
            MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        with self.assertRaisesRegex(MODULE.HandoverError, "UID changed"):
            MODULE.run(self.plan(), mode="live", kube=kube, sink=sink, journal=journal)
        record = journal.state["createdObjects"][0]
        self.assertEqual(record["uid"], "00000000-0000-4000-8000-000000000001")
        identity = MODULE.target(MODULE.expected_flux_objects()["serviceAccount"])
        self.assertEqual(kube.get(identity)["metadata"]["uid"], "00000000-0000-4000-8000-000000009998")

    def test_kubernetes_delete_uses_uid_and_resource_version_preconditions_in_request(self) -> None:
        adapter = MODULE.KubernetesAdapter.__new__(MODULE.KubernetesAdapter)
        calls: list[tuple[list[str], str | None]] = []

        def fake_run(args: list[str], *, input_text: str | None = None) -> tuple[int, str, str]:
            calls.append((args, input_text))
            return 0, "{}", ""

        adapter._run = fake_run
        identity = MODULE.target(MODULE.expected_flux_objects()["serviceAccount"])
        uid = "00000000-0000-4000-8000-000000000001"
        MODULE.KubernetesAdapter.delete(adapter, identity, uid=uid, resource_version="17000001")
        self.assertEqual(len(calls), 1)
        args, payload = calls[0]
        self.assertEqual(args[:3], ["delete", "--raw", "/api/v1/namespaces/flux-roebel-staging/serviceaccounts/roebel-staging-workbench-baseline-reconciler"])
        self.assertEqual(
            json.loads(payload or ""),
            {
                "apiVersion": "v1",
                "kind": "DeleteOptions",
                "preconditions": {"uid": uid, "resourceVersion": "17000001"},
            },
        )

    def test_journal_sink_persists_checksum_bound_state_and_reloads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = temporary_root(directory) / "handover.journal"
            journal = MODULE.JournalSink(path)
            state = {
                "schemaVersion": MODULE.JOURNAL_SCHEMA,
                "status": "in-progress",
                "operationId": "00000000-0000-4000-8000-000000000001",
            }
            journal.commit(state)
            self.assertEqual(json.loads(path.read_text())["journalSha256"], MODULE.digest(state))
            reopened = MODULE.JournalSink(path)
            self.assertEqual(reopened.load(), state)

    def test_journal_reentry_observes_post_replace_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = temporary_root(directory) / "handover.journal"
            journal = MODULE.JournalSink(path)
            state = {
                "schemaVersion": MODULE.JOURNAL_SCHEMA,
                "status": "in-progress",
                "operationId": "00000000-0000-4000-8000-000000000001",
            }
            replaced = False
            original_replace = MODULE.os.replace
            original_fsync = MODULE.os.fsync

            def replace(source: str | bytes | os.PathLike[str], destination: str | bytes | os.PathLike[str]) -> None:
                nonlocal replaced
                original_replace(source, destination)
                replaced = True

            def fsync(fd: int) -> None:
                if replaced:
                    raise OSError("simulated journal fsync failure after atomic replace")
                original_fsync(fd)

            with patch.object(MODULE.os, "replace", replace), patch.object(MODULE.os, "fsync", fsync):
                with self.assertRaises(OSError):
                    journal.commit(state)
            reopened = MODULE.JournalSink(path)
            self.assertEqual(reopened.load(), state)

    def test_sigterm_is_routed_to_handover_signal_handler(self) -> None:
        previous, state = MODULE._install_signal_handlers()
        try:
            with self.assertRaises(MODULE.HandoverSignal):
                signal.raise_signal(signal.SIGTERM)
            state["rollbackActive"] = True
            signal.raise_signal(signal.SIGINT)
        finally:
            MODULE._restore_signal_handlers(previous)

    def test_concurrent_policy_update_is_rejected_without_clobbering_metadata(self) -> None:
        kube = ConcurrentBaselineMutationKubernetes(baseline=baseline_live())
        sink = MODULE.MemoryReceiptSink()
        with self.assertRaisesRegex(MODULE.HandoverError, "rollback-incomplete"):
            MODULE.run(self.plan(), mode="live", kube=kube, sink=sink)
        self.assertEqual(sink.values[0]["status"], "rollback-incomplete")
        baseline = kube.get(MODULE.target(MODULE.expected_before_network_policy()))
        assert baseline is not None
        self.assertEqual(baseline["metadata"]["labels"]["stadtstack.io/owner"], MODULE.OLD_OWNER)
        self.assertEqual(baseline["metadata"]["annotations"], {"example.org/concurrent": "preserve"})

    def test_dry_run_is_non_mutating_and_receipt_binds_all_protected_blobs(self) -> None:
        sink = MODULE.MemoryReceiptSink()
        receipt = MODULE.run(self.plan(), mode="dry-run", sink=sink)
        self.assertEqual(receipt["status"], "dry-run")
        self.assertEqual(len(sink.values), 1)
        self.assertEqual(set(receipt["protectedFileSha256"]), set(MODULE.PROTECTED_PATHS))
        self.assertEqual(receipt["plan"]["baseline"]["uid"], MODULE.BASELINE_UID)
        self.assertEqual(receipt["plan"]["baseline"]["beforeDigest"], MODULE.BASELINE_BEFORE_DIGEST)

    def test_receipt_sink_is_owner_only_and_non_overwriting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = temporary_root(directory) / "receipt.json"
            sink = MODULE.ReceiptSink(path)
            sink.commit({"schemaVersion": MODULE.RECEIPT_SCHEMA, "status": "dry-run"})
            parsed = json.loads(path.read_text())
            self.assertEqual(parsed["status"], "dry-run")
            with self.assertRaises(FileExistsError):
                MODULE.ReceiptSink(path)

    def test_receipt_sink_can_load_completed_receipt_for_journal_reentry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = temporary_root(directory) / "receipt.json"
            sink = MODULE.ReceiptSink(path)
            value = {"schemaVersion": MODULE.RECEIPT_SCHEMA, "status": "completed", "mode": "live"}
            sink.commit(value)
            reentry = MODULE.ReceiptSink(path, allow_existing_completed=True)
            self.assertEqual(reentry.load()["status"], "completed")

    def test_receipt_sinks_reject_secret_shaped_payloads(self) -> None:
        sink = MODULE.MemoryReceiptSink()
        with self.assertRaises(MODULE.HandoverError):
            sink.commit({"schemaVersion": MODULE.RECEIPT_SCHEMA, "token": "forbidden"})
        with tempfile.TemporaryDirectory() as directory:
            durable = MODULE.ReceiptSink(temporary_root(directory) / "receipt.json")
            with self.assertRaises(MODULE.HandoverError):
                durable.commit({"schemaVersion": MODULE.RECEIPT_SCHEMA, "privateKey": "forbidden"})


if __name__ == "__main__":
    unittest.main()
