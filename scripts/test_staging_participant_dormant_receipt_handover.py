#!/usr/bin/env python3
"""Focused contract tests for the GET-only archived participant receipt bridge.

The bridge deliberately has a small, pure seam so it can be tested without a
cluster.  ``build_archived_binding`` accepts the two protected participant
plans, path-digest inventories and the *raw* archived v1 receipt.  It returns
the only binding that ``run_get_only_handover`` may consume.  The latter is
given an adapter exposing only ``get_exact`` and a receipt sink.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import signal
import stat
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


PATH = Path(__file__).with_name("staging_participant_dormant_receipt_handover.py")
SPEC = importlib.util.spec_from_file_location("participant_dormant_receipt_handover_under_test", PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

RUNNER_PATH = Path(__file__).with_name("handover-staging-participant-dormant-receipt.py")
RUNNER_SPEC = importlib.util.spec_from_file_location("participant_dormant_receipt_runner_under_test", RUNNER_PATH)
assert RUNNER_SPEC is not None and RUNNER_SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(RUNNER_SPEC)
RUNNER_SPEC.loader.exec_module(RUNNER)


ARCHIVE = "08c4171573bb138845a9160e747f6ac56a3c754e"
CURRENT = "3b079948d63a7e7612212ef85a3a6ef1931ef9eb"
POLICY_SHA = "sha256:" + "a" * 64
SOURCE_SEMANTIC_SHA = "sha256:" + "d" * 64


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical(value).encode()).hexdigest()


def raw_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def target(kind: str, name: str, namespace: str, api_version: str = "v1") -> dict[str, str]:
    return {"apiVersion": api_version, "kind": kind, "namespace": namespace, "name": name}


SOURCE = target("GitRepository", "roebel-staging-operations", "flux-roebel-staging", "source.toolkit.fluxcd.io/v1")
WEB = target("Ingress", "roebel-web-presentation", "stadtstack-roebel-web-preview", "networking.k8s.io/v1")
WORKBENCH = target("NetworkPolicy", "e2e-workbench", "stadtstack-roebel-staging-lab", "networking.k8s.io/v1")
CLUSTER_BINDING = {
    "apiOrigin": "https://10.0.0.2:6443",
    "caCertificateSha256": "sha256:" + "1" * 64,
    "apiServerSpkiSha256": "sha256:" + "2" * 64,
    "kubeSystemNamespaceUid": "cluster-uid",
    "kubeSystemNamespaceResourceVersion": "700",
    "credentialsIncluded": False,
    "kubeconfigPathIncluded": False,
}


def object_targets() -> list[dict[str, str]]:
    return [
        target("ServiceAccount", "roebel-staging-participant-gateway-reconciler", "flux-roebel-staging"),
        target("ServiceAccount", "roebel-staging-participant-workbench-ingress-reconciler", "flux-roebel-staging"),
        target("Role", "roebel-staging-participant-gateway-reconciler", "stadtstack-roebel-web-preview", "rbac.authorization.k8s.io/v1"),
        target("Role", "roebel-staging-participant-workbench-ingress-reconciler", "stadtstack-roebel-staging-lab", "rbac.authorization.k8s.io/v1"),
        target("RoleBinding", "roebel-staging-participant-gateway-reconciler", "stadtstack-roebel-web-preview", "rbac.authorization.k8s.io/v1"),
        target("RoleBinding", "roebel-staging-participant-workbench-ingress-reconciler", "stadtstack-roebel-staging-lab", "rbac.authorization.k8s.io/v1"),
        target("Kustomization", "roebel-staging-participant-gateway", "flux-roebel-staging", "kustomize.toolkit.fluxcd.io/v1"),
        target("Kustomization", "roebel-staging-participant-workbench-ingress", "flux-roebel-staging", "kustomize.toolkit.fluxcd.io/v1"),
    ]


def identity_key(value: dict[str, str]) -> tuple[str, str, str, str]:
    return value["apiVersion"], value["kind"], value["namespace"], value["name"]


def desired(index: int, item: dict[str, str]) -> dict:
    value = {
        "apiVersion": item["apiVersion"],
        "kind": item["kind"],
        "metadata": {"name": item["name"], "namespace": item["namespace"], "labels": {"app": f"participant-{index}"}},
        "spec": {"marker": index},
    }
    if item["kind"] == "Kustomization":
        value["spec"] = {"suspend": True, "path": f"./participant/{index}"}
    return value


def participant_plan(revision: str) -> dict:
    objects = []
    for index, item in enumerate(object_targets(), start=1):
        rendered = desired(index, item)
        objects.append({
            "logicalName": ("gateway" if index in {1, 3, 5, 7} else "workbenchIngress")
            + "." + item["kind"][0].lower() + item["kind"][1:],
            "target": item,
            "desired": rendered,
            "desiredSemanticSha256": digest(rendered),
        })
    return {
        "protectedRevision": revision,
        "activationPolicySha256": POLICY_SHA,
        "objects": objects,
        "sharedSource": SOURCE,
        "expectedSharedSource": {"apiVersion": SOURCE["apiVersion"], "kind": SOURCE["kind"], "metadata": {"name": SOURCE["name"], "namespace": SOURCE["namespace"]}, "spec": {"suspend": False}},
        "expectedSharedSourceSemanticSha256": SOURCE_SEMANTIC_SHA,
        "preservation": {"webIngress": WEB, "existingWorkbenchNetworkPolicy": WORKBENCH},
    }


def archived_receipt(plan: dict) -> bytes:
    """A closed v1 proof shape that must also pass its historical binder."""
    source = {"uid": "source-uid", "resourceVersion": "90", "artifactRevision": f"main@sha1:{ARCHIVE}", "semanticSha256": SOURCE_SEMANTIC_SHA, "mutation": "forbidden"}
    preservation = {
        "webIngress": {"target": WEB, "beforeCanonicalSha256": "sha256:" + "b" * 64, "mutation": "forbidden"},
        "existingWorkbenchNetworkPolicy": {"target": WORKBENCH, "beforeCanonicalSha256": "sha256:" + "c" * 64, "mutation": "forbidden"},
    }
    receipt = {
        "schemaVersion": "roebel_staging_participant_flux_bootstrap_receipt_v1",
        "status": "dormant-ready",
        "protectedRevision": ARCHIVE,
        "activationPolicySha256": POLICY_SHA,
        "preflight": {"sharedSource": source, "preservation": preservation},
        "postconditions": {
            "finalChecks": {
                "sharedSource": source,
                "preservation": {
                    label: {
                        "target": value["target"],
                        "beforeCanonicalSha256": value["beforeCanonicalSha256"],
                        "afterCanonicalSha256": value["beforeCanonicalSha256"],
                        "byteIdenticalCanonicalJson": True,
                    }
                    for label, value in preservation.items()
                },
            },
        },
        "effects": {"secretRead": False, "secretWrite": False, "sharedSourceMutation": False, "civicAuthorityEffects": False},
    }
    receipt["canonicalSha256"] = digest(receipt)
    return (canonical(receipt) + "\n").encode()


def archived_projection(plan: dict) -> dict:
    return {
        "status": "dormant-ready",
        "protectedRevision": ARCHIVE,
        "objects": [
            {
                "logicalName": item["logicalName"], "target": item["target"],
                "uid": f"object-uid-{index}", "resourceVersion": str(100 + index),
                "desiredSemanticSha256": item["desiredSemanticSha256"],
            }
            for index, item in enumerate(plan["objects"], start=1)
        ],
    }


def artifacts() -> dict[str, str]:
    return {
        "policy/staging-participant-gateway-activation-policy.json": "sha256:" + "1" * 64,
        "scripts/staging_participant_gateway_policy.py": "sha256:" + "2" * 64,
        "scripts/staging_participant_flux_bootstrap.py": "sha256:" + "3" * 64,
        "scripts/bootstrap-staging-participant-flux.py": "sha256:" + "4" * 64,
        "scripts/activate-staging-participant-gateway.py": "sha256:" + "5" * 64,
        "reviewed-render/roebel-staging/staging-participant-gateway/deployment.json": "sha256:" + "6" * 64,
        "reviewed-render/roebel-staging/staging-participant-gateway/ingress.json": "sha256:" + "7" * 64,
        "reviewed-render/roebel-staging/staging-participant-gateway/kustomization.yaml": "sha256:" + "8" * 64,
        "reviewed-render/roebel-staging/staging-participant-gateway/networkpolicy.json": "sha256:" + "9" * 64,
        "reviewed-render/roebel-staging/staging-participant-gateway/runtime-pin.json": "sha256:" + "a" * 64,
        "reviewed-render/roebel-staging/staging-participant-gateway/service.json": "sha256:" + "b" * 64,
        "reviewed-render/roebel-staging/staging-participant-gateway/serviceaccount.json": "sha256:" + "c" * 64,
        "reviewed-render/roebel-staging/staging-participant-gateway/workbench-ingress/kustomization.yaml": "sha256:" + "d" * 64,
        "reviewed-render/roebel-staging/staging-participant-gateway/workbench-ingress/networkpolicy.json": "sha256:" + "e" * 64,
    }


class MemorySink:
    def __init__(self) -> None:
        self.values: list[dict] = []

    def commit(self, value: dict) -> None:
        self.values.append(copy.deepcopy(value))


class GetOnlyKube:
    def __init__(self, plan: dict) -> None:
        self.calls: list[dict[str, str]] = []
        self.objects: dict[tuple[str, str, str, str], dict] = {}
        self.objects[identity_key(SOURCE)] = {
            "apiVersion": SOURCE["apiVersion"], "kind": SOURCE["kind"],
            "metadata": {"name": SOURCE["name"], "namespace": SOURCE["namespace"], "uid": "source-uid", "resourceVersion": "400", "generation": 3},
            "spec": {"suspend": False},
            "status": {"artifact": {"revision": f"main@sha1:{CURRENT}"}, "observedGeneration": 3, "conditions": [{"type": "Ready", "status": "True", "observedGeneration": 3}]},
        }
        for index, item in enumerate(plan["objects"], start=1):
            value = copy.deepcopy(item["desired"])
            value["metadata"].update({"uid": f"object-uid-{index}", "resourceVersion": str(200 + index)})
            self.objects[identity_key(item["target"])] = value
        for name, item, checksum in (
            ("webIngress", WEB, "sha256:" + "b" * 64),
            ("existingWorkbenchNetworkPolicy", WORKBENCH, "sha256:" + "c" * 64),
        ):
            self.objects[identity_key(item)] = {
                "apiVersion": item["apiVersion"], "kind": item["kind"],
                "metadata": {"name": item["name"], "namespace": item["namespace"], "uid": name, "resourceVersion": "300"},
                "spec": {"canonicalSha256Fixture": checksum},
            }

    def get_exact(self, item: dict[str, str]) -> dict:
        self.calls.append(copy.deepcopy(item))
        value = self.objects.get(identity_key(item))
        if value is None:
            raise AssertionError("unexpected GET target")
        return copy.deepcopy(value)

    def __getattr__(self, name: str):
        raise AssertionError(f"forbidden adapter method: {name}")


class HandoverTests(unittest.TestCase):
    def binding(self) -> dict:
        archive_plan = participant_plan(ARCHIVE)
        current_plan = participant_plan(CURRENT)
        return MODULE.build_archived_binding(
            archived_receipt_raw=archived_receipt(archive_plan),
            archive_revision=ARCHIVE,
            current_revision=CURRENT,
            archived_plan=archive_plan,
            current_plan=current_plan,
            archived_artifacts=artifacts(),
            current_artifacts=artifacts(),
            archived_participant_contract={"activationReady": True, "component": "staging-participant-gateway"},
            current_participant_contract={"activationReady": True, "component": "staging-participant-gateway"},
            archived_projection=archived_projection(archive_plan),
        )

    def invoke(self, kube: GetOnlyKube | None = None, sink: MemorySink | None = None):
        current_plan = participant_plan(CURRENT)
        kube = kube or GetOnlyKube(current_plan)
        sink = sink or MemorySink()
        result = MODULE.run_get_only_handover(
            binding=self.binding(), kube=kube, receipt=sink,
            cluster_binding=copy.deepcopy(CLUSTER_BINDING),
            semantic_object_sha256=lambda _value: SOURCE_SEMANTIC_SHA,
        )
        return result, kube, sink

    def test_archive_revision_and_raw_canonical_binding_are_exact(self) -> None:
        binding = self.binding()
        self.assertEqual(MODULE.ARCHIVE_REVISION, ARCHIVE)
        self.assertEqual(binding["archivedRevision"], ARCHIVE)
        self.assertEqual(binding["currentRevision"], CURRENT)
        self.assertEqual(binding["archivedReceiptRawSha256"], raw_digest(archived_receipt(participant_plan(ARCHIVE))))
        self.assertEqual(binding["archivedReceiptCanonicalSha256"], json.loads(archived_receipt(participant_plan(ARCHIVE)))["canonicalSha256"])
        tampered = archived_receipt(participant_plan(ARCHIVE)).replace(b"dormant-ready", b"dormant-readdy")
        with self.assertRaises(MODULE.HandoverError):
            MODULE.build_archived_binding(
                archived_receipt_raw=tampered, archive_revision=ARCHIVE, current_revision=CURRENT,
                archived_plan=participant_plan(ARCHIVE), current_plan=participant_plan(CURRENT),
                archived_artifacts=artifacts(), current_artifacts=artifacts(),
                archived_participant_contract={"activationReady": True, "component": "staging-participant-gateway"},
                current_participant_contract={"activationReady": True, "component": "staging-participant-gateway"},
                archived_projection=archived_projection(participant_plan(ARCHIVE)),
            )

    def test_compatibility_requires_exact_participant_artifacts_plan_and_contract(self) -> None:
        changed = artifacts(); changed["reviewed-render/roebel-staging/staging-participant-gateway/deployment.json"] = "sha256:" + "f" * 64
        with self.assertRaises(MODULE.HandoverError):
            MODULE.build_archived_binding(
                archived_receipt_raw=archived_receipt(participant_plan(ARCHIVE)), archive_revision=ARCHIVE, current_revision=CURRENT,
                archived_plan=participant_plan(ARCHIVE), current_plan=participant_plan(CURRENT),
                archived_artifacts=artifacts(), current_artifacts=changed,
                archived_participant_contract={"activationReady": True, "component": "staging-participant-gateway"},
                current_participant_contract={"activationReady": True, "component": "staging-participant-gateway"},
                archived_projection=archived_projection(participant_plan(ARCHIVE)),
            )
        changed_plan = participant_plan(CURRENT); changed_plan["objects"][0]["desiredSemanticSha256"] = "sha256:" + "f" * 64
        with self.assertRaises(MODULE.HandoverError):
            MODULE.build_archived_binding(
                archived_receipt_raw=archived_receipt(participant_plan(ARCHIVE)), archive_revision=ARCHIVE, current_revision=CURRENT,
                archived_plan=participant_plan(ARCHIVE), current_plan=changed_plan,
                archived_artifacts=artifacts(), current_artifacts=artifacts(),
                archived_participant_contract={"activationReady": True, "component": "staging-participant-gateway"},
                current_participant_contract={"activationReady": False, "component": "staging-participant-gateway"},
                archived_projection=archived_projection(participant_plan(ARCHIVE)),
            )

    def test_exactly_eleven_gets_and_no_other_adapter_surface(self) -> None:
        result, kube, sink = self.invoke()
        self.assertEqual(result["status"], "dormant-ready-revalidated")
        self.assertEqual(len(kube.calls), 11)
        self.assertEqual(kube.calls[0], SOURCE)
        self.assertEqual(kube.calls[1:9], object_targets())
        self.assertEqual(kube.calls[9:], [WEB, WORKBENCH])
        self.assertEqual(len(sink.values), 1)
        self.assertEqual(sink.values[0]["effects"], {"verbs": ["GET"], "kubernetesGetCount": 12, "resourceGetCount": 11, "clusterMutationCount": 0, "secretReads": False, "civicAuthorityEffects": False})
        self.assertEqual(sink.values[0]["clusterBinding"], CLUSTER_BINDING)

    def test_source_uid_revision_and_ready_state_are_cross_transaction_preconditions(self) -> None:
        for mutate in (
            lambda source: source["metadata"].__setitem__("uid", "replacement-source"),
            lambda source: source["status"]["artifact"].__setitem__("revision", "main@sha1:" + "f" * 40),
            lambda source: source["status"]["conditions"].__setitem__(0, {"type": "Ready", "status": "False"}),
        ):
            kube = GetOnlyKube(participant_plan(CURRENT)); mutate(kube.objects[identity_key(SOURCE)])
            with self.subTest(mutate=mutate):
                with self.assertRaises(MODULE.HandoverError): self.invoke(kube=kube)
                self.assertEqual(len(kube.calls), 1)

    def test_source_receipt_uses_the_policy_semantic_hash_not_the_full_object_hash(self) -> None:
        current_plan = participant_plan(CURRENT)
        kube = GetOnlyKube(current_plan)
        sink = MemorySink()
        semantic_sha = "sha256:" + "d" * 64
        result = MODULE.run_get_only_handover(
            binding=self.binding(),
            kube=kube,
            receipt=sink,
            cluster_binding=copy.deepcopy(CLUSTER_BINDING),
            semantic_object_sha256=lambda _value: semantic_sha,
        )
        self.assertEqual(result["sharedSource"]["semanticSha256"], semantic_sha)
        self.assertNotEqual(result["sharedSource"]["semanticSha256"], digest(kube.objects[identity_key(SOURCE)]))

    def test_each_dormant_uid_semantics_resource_version_and_suspension_is_rechecked(self) -> None:
        for index, item in enumerate(participant_plan(CURRENT)["objects"], start=1):
            for field, mutate in (
                ("uid", lambda value: value["metadata"].__setitem__("uid", "replacement")),
                ("semantic", lambda value: value["spec"].__setitem__("marker", 999)),
                ("resourceVersion", lambda value: value["metadata"].__setitem__("resourceVersion", "1")),
                ("suspension", lambda value: value["spec"].__setitem__("suspend", False) if value["kind"] == "Kustomization" else value["metadata"].__setitem__("labels", {"app": "wrong"})),
            ):
                kube = GetOnlyKube(participant_plan(CURRENT)); mutate(kube.objects[identity_key(item["target"])])
                with self.subTest(index=index, field=field):
                    with self.assertRaises(MODULE.HandoverError): self.invoke(kube=kube)
                    self.assertLessEqual(len(kube.calls), index + 1)

    def test_preservation_hash_drift_fails_after_the_first_ten_gets(self) -> None:
        for item in (WEB, WORKBENCH):
            kube = GetOnlyKube(participant_plan(CURRENT))
            kube.objects[identity_key(item)]["spec"]["canonicalSha256Fixture"] = "sha256:" + "f" * 64
            with self.subTest(target=item):
                with self.assertRaises(MODULE.HandoverError): self.invoke(kube=kube)
                self.assertEqual(len(kube.calls), 10 if item == WEB else 11)

    def test_receipt_is_checksumbound_no_authority_and_owner_only(self) -> None:
        result, _kube, sink = self.invoke()
        self.assertEqual(result["schemaVersion"], MODULE.HANDOVER_RECEIPT_SCHEMA)
        self.assertFalse(result["civicAuthorityEffects"])
        self.assertEqual(result["canonicalSha256"], digest({key: value for key, value in result.items() if key != "canonicalSha256"}))
        bound = MODULE.bind_handover_receipt(self.binding(), result)
        self.assertEqual(bound["receiptProvenance"]["mode"], "archived-v1+get-only-handover")
        self.assertEqual(bound["clusterBinding"], CLUSTER_BINDING)
        tampered = copy.deepcopy(result)
        tampered["objects"][0]["extra"] = "not-closed"
        tampered["canonicalSha256"] = digest({key: value for key, value in tampered.items() if key != "canonicalSha256"})
        with self.assertRaises(MODULE.HandoverError):
            MODULE.bind_handover_receipt(self.binding(), tampered)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "handover.json"
            receipt_sink = MODULE.ReceiptSink.reserve(path)
            receipt_sink.commit(result)
            info = path.stat()
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            self.assertEqual(info.st_nlink, 1)
            self.assertEqual(json.loads(path.read_text()), result)
        self.assertEqual(sink.values[0]["canonicalSha256"], result["canonicalSha256"])

    def test_runner_constructor_failure_closes_plaintext_kubeconfig_snapshot(self) -> None:
        snapshot = types.SimpleNamespace(close=Mock(), path=Path("/private/tmp/fixture-kubeconfig"))
        activation = types.SimpleNamespace(
            Runner=Mock(return_value=object()),
            snapshot_kubeconfig_v4=Mock(return_value=snapshot),
        )
        duplicate = target("ServiceAccount", "duplicate", "fixture")
        context = {
            "activationModule": activation,
            "binding": {
                "sourceTarget": duplicate,
                "objects": [{"target": duplicate} for _ in range(8)],
                "preservation": {
                    "webIngress": {"target": duplicate},
                    "existingWorkbenchNetworkPolicy": {"target": duplicate},
                },
            },
        }
        with self.assertRaisesRegex(RUNNER.HandoverCliError, "exactly eleven"):
            RUNNER.GetOnlyAdapter("fixture", context)
        snapshot.close.assert_called_once_with()

    def test_runner_sigterm_is_converted_to_cleanup_and_closes_snapshot(self) -> None:
        snapshot = types.SimpleNamespace(close=Mock(), path=Path("/private/tmp/fixture-kubeconfig"))
        activation = types.SimpleNamespace(
            Runner=Mock(return_value=object()),
            snapshot_kubeconfig_v4=Mock(return_value=snapshot),
            cluster_binding_v4=Mock(return_value=copy.deepcopy(CLUSTER_BINDING)),
            digest=Mock(return_value="sha256:" + "4" * 64),
        )
        binding = {
            "sourceTarget": SOURCE,
            "objects": [{"target": item} for item in object_targets()],
            "preservation": {
                "webIngress": {"target": WEB},
                "existingWorkbenchNetworkPolicy": {"target": WORKBENCH},
            },
        }

        class Sink:
            @classmethod
            def reserve(cls, _path):
                return cls()

        def terminate(**_kwargs):
            handler = signal.getsignal(signal.SIGTERM)
            self.assertTrue(callable(handler))
            handler(signal.SIGTERM, None)

        handover = types.SimpleNamespace(ReceiptSink=Sink, run_get_only_handover=terminate)
        policy_module = types.SimpleNamespace(
            require_semantically_equal=Mock(),
            semantic_sha256=Mock(return_value=SOURCE_SEMANTIC_SHA),
        )
        context = {
            "policy": {},
            "policyModule": policy_module,
            "handoverModule": handover,
            "activationModule": activation,
            "binding": binding,
        }
        args = types.SimpleNamespace(
            expected_protected_revision=CURRENT,
            archived_bootstrap_receipt_fd=3,
            prebound_blob=[],
            verify_success_receipt_fd=None,
            live=True,
            kubeconfig="fixture",
            receipt=Path("/private/tmp/fixture-handover-receipt.json"),
        )
        previous_sigterm = signal.getsignal(signal.SIGTERM)
        with (
            patch.object(RUNNER, "parse_args", return_value=args),
            patch.object(RUNNER, "parse_prebound_blob_descriptors", return_value={}),
            patch.object(RUNNER, "owned_receipt_raw", return_value=b"{}"),
            patch.object(RUNNER, "build_context", return_value=context),
        ):
            self.assertEqual(RUNNER.main([]), 2)
        snapshot.close.assert_called_once_with()
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous_sigterm)


if __name__ == "__main__":
    unittest.main()
