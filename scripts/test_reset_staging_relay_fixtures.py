#!/usr/bin/env python3
"""Focused acceptance tests for the protected relay fixture-reset transaction."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import inspect
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any


MODULE_PATH = Path(__file__).with_name("reset-staging-relay-fixtures.py")
SPEC = importlib.util.spec_from_file_location("reset_staging_relay_fixtures", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


PIN_BYTES = b'''{
  "schemaVersion": "roebel_e2e_runtime_pin_v1",
  "sourceRevision": "36ac41d7049df815aaebbe4301c098a0ec7e4101",
  "components": [
    {
      "component": "roebel-e2e-workbench",
      "image": "ghcr.io/giraeffleaeffle/roebel-e2e-workbench",
      "manifestDigest": "sha256:2158831bd76865db483ca6a8dc211e7d5c3de51d0113613fc0a22a4ca27fc6ce",
      "provenance": {
        "id": "42606241",
        "url": "https://github.com/GiraeffleAeffle/Roebel-App/attestations/42606241"
      },
      "sbomAttestation": {
        "id": "42606265",
        "url": "https://github.com/GiraeffleAeffle/Roebel-App/attestations/42606265"
      },
      "workflowIdentity": "https://github.com/GiraeffleAeffle/Roebel-App/.github/workflows/roebel-e2e-runtime-publish.yml@refs/heads/main"
    },
    {
      "component": "roebel-staging-relay",
      "image": "ghcr.io/giraeffleaeffle/roebel-staging-relay",
      "manifestDigest": "sha256:6def2f468e3fad47cf17c0287a9215bbdc299b0d7d3b7fc58927b2f2169650ad",
      "provenance": {
        "id": "42606248",
        "url": "https://github.com/GiraeffleAeffle/Roebel-App/attestations/42606248"
      },
      "sbomAttestation": {
        "id": "42606286",
        "url": "https://github.com/GiraeffleAeffle/Roebel-App/attestations/42606286"
      },
      "workflowIdentity": "https://github.com/GiraeffleAeffle/Roebel-App/.github/workflows/roebel-e2e-runtime-publish.yml@refs/heads/main"
    }
  ],
  "civicAuthority": "none",
  "deploymentEffect": false
}
'''


UIDS = {
    "citizen-relay": {
        "oldPod": "11111111-1111-4111-8111-111111111111",
        "newPod": "33333333-3333-4333-8333-333333333333",
        "oldRs": "55555555-5555-4555-8555-555555555555",
        "newRs": "77777777-7777-4777-8777-777777777777",
        "service": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "policy": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "oldSlice": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        "newSlice": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
    },
    "agent-relay": {
        "oldPod": "22222222-2222-4222-8222-222222222222",
        "newPod": "44444444-4444-4444-8444-444444444444",
        "oldRs": "66666666-6666-4666-8666-666666666666",
        "newRs": "88888888-8888-4888-8888-888888888888",
        "service": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        "policy": "ffffffff-ffff-4fff-8fff-ffffffffffff",
        "oldSlice": "99999999-9999-4999-8999-999999999999",
        "newSlice": "abababab-abab-4bab-8bab-abababababab",
    },
}


def protected_hashes() -> dict[str, str]:
    return {path: "sha256:" + hashlib.sha256(path.encode()).hexdigest() for path in MODULE.PROTECTED_PATHS}


def metadata(component: str, uid: str, resource_version: str = "10", *, generation: int = 1) -> dict[str, Any]:
    return {
        "name": component,
        "namespace": MODULE.NAMESPACE,
        "uid": uid,
        "resourceVersion": resource_version,
        "generation": generation,
        "labels": MODULE.relay_labels(component),
    }


def deployment(component: str, *, resource_version: str = "10") -> dict[str, Any]:
    labels = MODULE.relay_labels(component)
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": metadata(component, MODULE.DEPLOYMENT_UIDS[component], resource_version, generation=4),
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": labels},
            "strategy": {"type": "RollingUpdate", "rollingUpdate": {"maxSurge": "25%", "maxUnavailable": "25%"}},
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "automountServiceAccountToken": False,
                    "containers": [{
                        "name": component,
                        "image": MODULE.RELAY_IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                        "env": MODULE._relay_environment(component),
                        "ports": [{"containerPort": MODULE.RELAY_PORT, "name": "http", "protocol": "TCP"}],
                        "volumeMounts": [{"mountPath": "/relay", "name": "relay-store"}],
                    }],
                    "volumes": [{"emptyDir": {"sizeLimit": "128Mi"}, "name": "relay-store"}],
                },
            },
        },
        "status": {"observedGeneration": 4, "readyReplicas": 1, "availableReplicas": 1},
    }


def service(component: str) -> dict[str, Any]:
    value = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": metadata(component, UIDS[component]["service"], "20"),
        "spec": {
            "clusterIP": "10.96.0.20",
            "ports": [{"name": "http", "port": 18081, "protocol": "TCP", "targetPort": "http"}],
            "selector": MODULE.relay_labels(component),
            "sessionAffinity": "None",
            "type": "ClusterIP",
        },
    }
    value["metadata"].pop("generation")
    return value


def network_policy(component: str) -> dict[str, Any]:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": metadata(component, UIDS[component]["policy"], "30", generation=2),
        "spec": {
            "podSelector": {"matchLabels": MODULE.relay_labels(component)},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": MODULE.NAMESPACE}}}]}],
            "egress": [],
        },
    }


def replica_set(component: str, *, replacement: bool) -> dict[str, Any]:
    uid = UIDS[component]["newRs" if replacement else "oldRs"]
    suffix = "new" if replacement else "old"
    return {
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "metadata": {
            "name": f"{component}-{suffix}",
            "namespace": MODULE.NAMESPACE,
            "uid": uid,
            "ownerReferences": [{
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "name": component,
                "uid": MODULE.DEPLOYMENT_UIDS[component],
                "controller": True,
            }],
        },
    }


def pod(component: str, *, replacement: bool) -> dict[str, Any]:
    suffix = "new" if replacement else "old"
    uid = UIDS[component]["newPod" if replacement else "oldPod"]
    rs_uid = UIDS[component]["newRs" if replacement else "oldRs"]
    address = "10.244.1.31" if component == "citizen-relay" else "10.244.2.41"
    if replacement:
        address = "10.244.1.32" if component == "citizen-relay" else "10.244.2.42"
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": f"{component}-{suffix}",
            "namespace": MODULE.NAMESPACE,
            "uid": uid,
            "resourceVersion": "101" if replacement else "100",
            "labels": MODULE.relay_labels(component),
            "ownerReferences": [{
                "apiVersion": "apps/v1",
                "kind": "ReplicaSet",
                "name": f"{component}-{suffix}",
                "uid": rs_uid,
                "controller": True,
            }],
        },
        "status": {
            "phase": "Running",
            "conditions": [{"type": "Ready", "status": "True"}],
            "containerStatuses": [{
                "name": component,
                "ready": True,
                "imageID": f"containerd://{MODULE.RELAY_IMAGE}",
            }],
            "podIP": address,
            "podIPs": [{"ip": address}],
        },
    }


def endpoint_slice(component: str, *, replacement: bool) -> dict[str, Any]:
    selected_pod = pod(component, replacement=replacement)
    pod_meta = selected_pod["metadata"]
    address = selected_pod["status"]["podIP"]
    return {
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSlice",
        "metadata": {
            "name": f"{component}-slice",
            "namespace": MODULE.NAMESPACE,
            "uid": UIDS[component]["newSlice" if replacement else "oldSlice"],
            "labels": {MODULE.ENDPOINT_SLICE_LABEL: component},
        },
        "ports": [{"name": "http", "port": 18081, "protocol": "TCP"}],
        "endpoints": [{
            "addresses": [address],
            "conditions": {"ready": True},
            "targetRef": {
                "apiVersion": "v1",
                "kind": "Pod",
                "namespace": MODULE.NAMESPACE,
                "name": pod_meta["name"],
                "uid": pod_meta["uid"],
            },
        }],
    }


def synthetic_feed() -> dict[str, Any]:
    return {
        "schemaVersion": MODULE.WORKBENCH_FEED_SCHEMA,
        "posts": [{
            "id": "fixture-post",
            "synthetic": True,
            "author": {"name": "Fixture", "synthetic": True},
            "conversation": {"synthetic": True},
        }],
        "authorityBinding": "none",
    }


def empty_feed() -> dict[str, Any]:
    return {"schemaVersion": MODULE.WORKBENCH_FEED_SCHEMA, "posts": [], "authorityBinding": "none"}


def workbench_config() -> dict[str, Any]:
    return {
        "schemaVersion": MODULE.WORKBENCH_CONFIG_SCHEMA,
        "authorityBinding": "none",
        "mode": "legacy-fixture",
        "personas": [{"id": "fixture", "name": "Fixture", "publicKey": "b" * 64}],
        "meckyPubkey": "53effb6fc32e569df164bad34aa3ae3505547032602d549826a912423c31d554",
    }


def ingress(policy: str = MODULE.WORKBENCH_INGRESS_OPEN, resource_version: str = "40") -> dict[str, Any]:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {
            "name": MODULE.WORKBENCH_INGRESS_NAME,
            "namespace": MODULE.NAMESPACE,
            "uid": MODULE.WORKBENCH_INGRESS_UID,
            "resourceVersion": resource_version,
            "generation": MODULE.WORKBENCH_INGRESS_GENERATION,
            "annotations": {MODULE.WORKBENCH_INGRESS_ANNOTATION: policy, "stadtstack.io/fixed": "true"},
            "labels": {"stadtstack.io/authority": "none"},
        },
        "spec": {"ingressClassName": "haproxy", "rules": [{"host": MODULE.PUBLIC_ORIGIN_HOST}]},
        "status": {"loadBalancer": {"ingress": [{"ip": "10.42.0.20"}]}},
    }


def public_mecky_deployment(*, replicas: int = 1, resource_version: str = "50", generation: int = 7) -> dict[str, Any]:
    spec = {
        "replicas": replicas,
        "selector": {"matchLabels": copy.deepcopy(MODULE.PUBLIC_MECKY_LABELS)},
        "strategy": {"type": "Recreate"},
        "template": {
            "metadata": {"labels": copy.deepcopy(MODULE.PUBLIC_MECKY_LABELS)},
            "spec": {
                "automountServiceAccountToken": False,
                "containers": [{
                    "name": MODULE.PUBLIC_MECKY_NAME,
                    "image": MODULE.PUBLIC_MECKY_IMAGE,
                    "ports": [{"containerPort": MODULE.PUBLIC_MECKY_PORT, "name": MODULE.PUBLIC_MECKY_PORT_NAME, "protocol": "TCP"}],
                    "env": [{"name": "NODE_ID", "value": "roebel-e2e"}],
                }],
            },
        },
    }
    status = {"observedGeneration": generation}
    if replicas == 1:
        status.update({"replicas": 1, "readyReplicas": 1, "availableReplicas": 1})
    else:
        status.update({"replicas": 0, "readyReplicas": 0, "availableReplicas": 0})
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": MODULE.PUBLIC_MECKY_NAME,
            "namespace": MODULE.NAMESPACE,
            "uid": MODULE.PUBLIC_MECKY_UID,
            "resourceVersion": resource_version,
            "generation": generation,
            "labels": copy.deepcopy(MODULE.PUBLIC_MECKY_LABELS),
        },
        "spec": spec,
        "status": status,
    }


def public_mecky_service() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": MODULE.PUBLIC_MECKY_NAME,
            "namespace": MODULE.NAMESPACE,
            "uid": "12121212-1212-4121-8121-121212121212",
            "resourceVersion": "60",
            "labels": copy.deepcopy(MODULE.PUBLIC_MECKY_LABELS),
        },
        "spec": {
            "clusterIP": "10.96.0.84",
            "selector": copy.deepcopy(MODULE.PUBLIC_MECKY_LABELS),
            "ports": [{"name": MODULE.PUBLIC_MECKY_PORT_NAME, "port": MODULE.PUBLIC_MECKY_PORT, "protocol": "TCP", "targetPort": MODULE.PUBLIC_MECKY_PORT_NAME}],
            "type": "ClusterIP",
        },
    }


def public_mecky_kustomization(*, suspended: bool = False, resource_version: str = "70", explicit: bool = False) -> dict[str, Any]:
    spec: dict[str, Any] = {"interval": "10m", "path": "./reviewed-render/roebel-staging/public-mecky", "prune": True}
    if explicit or suspended:
        spec["suspend"] = suspended
    return {
        "apiVersion": "kustomize.toolkit.fluxcd.io/v1",
        "kind": "Kustomization",
        "metadata": {
            "name": MODULE.PUBLIC_MECKY_KUSTOMIZATION,
            "namespace": MODULE.FLUX_NAMESPACE,
            "uid": MODULE.PUBLIC_MECKY_KUSTOMIZATION_UID,
            "resourceVersion": resource_version,
            "generation": 3,
        },
        "spec": spec,
        "status": {"conditions": [{"type": "Ready", "status": "True", "observedGeneration": 3}]},
    }


MECKY_UIDS = {
    "oldPod": "13131313-1313-4131-8131-131313131313",
    "newPod": "14141414-1414-4141-8141-141414141414",
    "oldRs": "15151515-1515-4151-8151-151515151515",
    "newRs": "16161616-1616-4161-8161-161616161616",
    "oldSlice": "17171717-1717-4171-8171-171717171717",
    "newSlice": "18181818-1818-4181-8181-181818181818",
}


def public_mecky_replica_set(*, replacement: bool) -> dict[str, Any]:
    suffix = "new" if replacement else "old"
    return {
        "apiVersion": "apps/v1", "kind": "ReplicaSet",
        "metadata": {
            "name": f"public-mecky-{suffix}", "namespace": MODULE.NAMESPACE,
            "uid": MECKY_UIDS["newRs" if replacement else "oldRs"],
            "ownerReferences": [{"apiVersion": "apps/v1", "kind": "Deployment", "name": MODULE.PUBLIC_MECKY_NAME, "uid": MODULE.PUBLIC_MECKY_UID, "controller": True}],
        },
    }


def public_mecky_pod(*, replacement: bool) -> dict[str, Any]:
    suffix = "new" if replacement else "old"
    uid = MECKY_UIDS["newPod" if replacement else "oldPod"]
    rs_uid = MECKY_UIDS["newRs" if replacement else "oldRs"]
    address = "10.244.3.52" if replacement else "10.244.3.51"
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {
            "name": f"public-mecky-{suffix}", "namespace": MODULE.NAMESPACE,
            "uid": uid, "resourceVersion": "201" if replacement else "200",
            "labels": copy.deepcopy(MODULE.PUBLIC_MECKY_LABELS),
            "ownerReferences": [{"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": f"public-mecky-{suffix}", "uid": rs_uid, "controller": True}],
        },
        "status": {
            "phase": "Running", "conditions": [{"type": "Ready", "status": "True"}],
            "containerStatuses": [{"name": MODULE.PUBLIC_MECKY_NAME, "ready": True, "imageID": f"containerd://{MODULE.PUBLIC_MECKY_IMAGE}"}],
            "podIP": address, "podIPs": [{"ip": address}],
        },
    }


def public_mecky_slice(*, replacement: bool) -> dict[str, Any]:
    selected = public_mecky_pod(replacement=replacement)
    return {
        "apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice",
        "metadata": {"name": "public-mecky-slice", "namespace": MODULE.NAMESPACE, "uid": MECKY_UIDS["newSlice" if replacement else "oldSlice"], "labels": {MODULE.ENDPOINT_SLICE_LABEL: MODULE.PUBLIC_MECKY_NAME}},
        "ports": [{"name": MODULE.PUBLIC_MECKY_PORT_NAME, "port": MODULE.PUBLIC_MECKY_PORT, "protocol": "TCP"}],
        "endpoints": [{"addresses": [selected["status"]["podIP"]], "conditions": {"ready": True}, "targetRef": {"apiVersion": "v1", "kind": "Pod", "namespace": MODULE.NAMESPACE, "name": selected["metadata"]["name"], "uid": selected["metadata"]["uid"]}}],
    }


def profile_proof() -> dict[str, Any]:
    return {
        "kind0Count": 1, "kind1Count": 0, "validKind0Count": 1,
        "expectedAuthorHash": True, "eventIdVerified": True, "signatureVerified": True,
        "bot": True, "identityVerified": True, "aboutNonempty": True, "agentTagVerified": True,
    }


class FakeKubernetes:
    def __init__(self) -> None:
        self.objects: dict[str, dict[str, Any]] = {}
        self.pods: dict[str, list[dict[str, Any]]] = {}
        self.replica_sets: dict[str, list[dict[str, Any]]] = {}
        self.slices: dict[str, list[dict[str, Any]]] = {}
        self.health = {
            "citizen-relay": {"ok": True, "name": "Röbel E2E Bürger-Relay", "events": 3},
            "agent-relay": {"ok": True, "name": "Röbel E2E Mecky-Relay", "events": 3},
        }
        self.feed = synthetic_feed()
        self.calls: list[tuple[Any, ...]] = []
        self.deletes: list[dict[str, Any]] = []
        self.patches: list[tuple[str, list[dict[str, Any]]]] = []
        self.read_only_exec_requests = 0
        self.journal: Any | None = None
        self.fail_operation: str | None = None
        self.fail_after_apply = False
        self.stale_endpoint: str | None = None
        self.drift_quiet = False
        self.invalid_profile = False
        self.flux_restore_ready_after_gets = 0
        self.flux_restore_gets = 0
        self.flux_restore_pending = False
        self.classification_get_failure: str | None = None
        self.classification_get_failure_remaining = 0
        self.feed_probe_count = 0
        for component in MODULE.COMPONENT_ORDER:
            for target, value in (
                (MODULE.deployment_target(component), deployment(component)),
                (MODULE.service_target(component), service(component)),
                (MODULE.network_policy_target(component), network_policy(component)),
            ):
                self.objects[MODULE.canonical(target)] = value
            self.pods[component] = [pod(component, replacement=False)]
            self.replica_sets[component] = [replica_set(component, replacement=False)]
            self.slices[component] = [endpoint_slice(component, replacement=False)]
        self.objects[MODULE.canonical(MODULE.workbench_ingress_target())] = ingress()
        self.objects[MODULE.canonical(MODULE.public_mecky_deployment_target())] = public_mecky_deployment()
        self.objects[MODULE.canonical(MODULE.public_mecky_service_target())] = public_mecky_service()
        self.objects[MODULE.canonical(MODULE.public_mecky_kustomization_target())] = public_mecky_kustomization()
        self.pods[MODULE.PUBLIC_MECKY_NAME] = [public_mecky_pod(replacement=False)]
        self.replica_sets[MODULE.PUBLIC_MECKY_NAME] = [public_mecky_replica_set(replacement=False)]
        self.slices[MODULE.PUBLIC_MECKY_NAME] = [public_mecky_slice(replacement=False)]
        self.policies = [network_policy(component) for component in MODULE.COMPONENT_ORDER]
        self.policies.append({
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "public-mecky-chat-from-web", "namespace": MODULE.NAMESPACE, "uid": "19191919-1919-4191-8191-191919191919", "resourceVersion": "80", "generation": 2},
            "spec": {"podSelector": {"matchLabels": copy.deepcopy(MODULE.PUBLIC_MECKY_LABELS)}, "policyTypes": ["Ingress", "Egress"], "ingress": [], "egress": []},
        })

    def get(self, target: dict[str, str]) -> dict[str, Any] | None:
        self.calls.append(("get", copy.deepcopy(target)))
        key = MODULE.canonical(target)
        if self.classification_get_failure == key and self.classification_get_failure_remaining > 0 and any(name == self.fail_operation for name, _ in self.patches):
            self.classification_get_failure_remaining -= 1
            raise MODULE.TransportUncertain("simulated classification GET loss")
        value = self.objects.get(key)
        if key == MODULE.canonical(MODULE.public_mecky_kustomization_target()) and value is not None and self.flux_restore_pending and self.flux_restore_ready_after_gets > 0:
            self.flux_restore_gets += 1
            if self.flux_restore_gets >= self.flux_restore_ready_after_gets:
                generation = value["metadata"]["generation"]
                value["status"] = {"conditions": [{"type": "Ready", "status": "True", "observedGeneration": generation}]}
                self.flux_restore_pending = False
        return copy.deepcopy(value) if value is not None else None

    def get_pods(self, component: str) -> list[dict[str, Any]]:
        self.calls.append(("get_pods", component))
        return copy.deepcopy(self.pods[component])

    def get_replica_sets(self, component: str) -> list[dict[str, Any]]:
        self.calls.append(("get_replica_sets", component))
        return copy.deepcopy(self.replica_sets[component])

    def get_endpoint_slices(self, component: str) -> list[dict[str, Any]]:
        self.calls.append(("get_endpoint_slices", component))
        return copy.deepcopy(self.slices[component])

    def get_network_policies(self) -> list[dict[str, Any]]:
        self.calls.append(("get_network_policies",))
        return copy.deepcopy(self.policies)

    def inspect_relay(self, component: str, pod_name: str, *, profile: bool = False) -> dict[str, Any]:
        self.calls.append(("inspect_relay", component, pod_name, profile))
        self.read_only_exec_requests += 1
        raw_health = copy.deepcopy(self.health[component])
        expected_name = "Röbel E2E Bürger-Relay" if component == "citizen-relay" else "Röbel E2E Mecky-Relay"
        health = {"ok": raw_health["ok"], "identityVerified": raw_health["name"] == expected_name, "events": raw_health["events"]}
        if profile:
            proof = profile_proof()
            if self.invalid_profile:
                proof["signatureVerified"] = False
                proof["validKind0Count"] = 0
            return {
                "health": health,
                "eventStore": {"present": True, "bytes": 321, "records": 1},
                "admissionStore": {"applicable": False, "present": False, "bytes": 0, "records": 0},
                "profile": proof,
            }
        records = health["events"]
        return {
            "health": health,
            "eventStore": {"present": records > 0, "bytes": 0 if records > 0 else 0, "records": records},
            "admissionStore": {
                "applicable": component == "citizen-relay",
                "present": component == "citizen-relay",
                "bytes": 0,
                "records": 0,
            },
            "profile": None,
        }

    def _assert_intent(self, operation: str) -> None:
        if self.journal is None:
            return
        durable = self.journal.state if hasattr(self.journal, "state") else json.loads(self.journal.path.read_text())
        assert durable["events"][-1]["operation"] == operation and durable["events"][-1]["stage"] == "intent"

    def _intent_operation(self) -> str:
        assert self.journal is not None
        durable = self.journal.state if hasattr(self.journal, "state") else json.loads(self.journal.path.read_text())
        assert durable["events"][-1]["stage"] == "intent"
        return durable["events"][-1]["operation"]

    @staticmethod
    def _increment(value: dict[str, Any]) -> None:
        value["metadata"]["resourceVersion"] = str(int(value["metadata"]["resourceVersion"]) + 1)

    def _maybe_fail(self, operation: str, *, after: bool) -> None:
        if self.fail_operation == operation and self.fail_after_apply is after:
            raise MODULE.TransportUncertain(f"simulated {operation} transport loss")

    def patch_ingress(self, operations: list[dict[str, Any]]) -> dict[str, Any]:
        operation = "restore-workbench-gate" if operations[-1]["value"] == MODULE.WORKBENCH_INGRESS_OPEN else "gate-workbench"
        self._assert_intent(operation)
        self.patches.append((operation, copy.deepcopy(operations)))
        self._maybe_fail(operation, after=False)
        key = MODULE.canonical(MODULE.workbench_ingress_target())
        self.objects[key]["metadata"]["annotations"][MODULE.WORKBENCH_INGRESS_ANNOTATION] = operations[-1]["value"]
        self._increment(self.objects[key])
        self._maybe_fail(operation, after=True)
        return copy.deepcopy(self.objects[key])

    def patch_public_mecky_kustomization(self, operations: list[dict[str, Any]]) -> dict[str, Any]:
        last = operations[-1]
        restore = last["op"] == "remove" or last.get("value") is False
        operation = "restore-public-mecky-flux" if restore else "suspend-public-mecky"
        self._assert_intent(operation)
        self.patches.append((operation, copy.deepcopy(operations)))
        self._maybe_fail(operation, after=False)
        key = MODULE.canonical(MODULE.public_mecky_kustomization_target())
        spec = self.objects[key]["spec"]
        if last["op"] == "remove":
            spec.pop("suspend", None)
        else:
            spec["suspend"] = last["value"]
        self._increment(self.objects[key])
        self.objects[key]["metadata"]["generation"] += 1
        if restore:
            self.flux_restore_pending = self.flux_restore_ready_after_gets > 0
        if restore and self.flux_restore_ready_after_gets == 0:
            generation = self.objects[key]["metadata"]["generation"]
            self.objects[key]["status"] = {"conditions": [{"type": "Ready", "status": "True", "observedGeneration": generation}]}
        self._maybe_fail(operation, after=True)
        return copy.deepcopy(self.objects[key])

    def patch_public_mecky_deployment(self, operations: list[dict[str, Any]]) -> dict[str, Any]:
        replicas = operations[-1]["value"]
        operation = self._intent_operation()
        assert operation in {"scale-public-mecky-zero", "scale-public-mecky-one", "restore-public-mecky-scale"}
        self._assert_intent(operation)
        self.patches.append((operation, copy.deepcopy(operations)))
        self._maybe_fail(operation, after=False)
        key = MODULE.canonical(MODULE.public_mecky_deployment_target())
        value = self.objects[key]
        value["spec"]["replicas"] = replicas
        self._increment(value)
        if replicas == 0:
            value["metadata"]["generation"] += 1
            value["status"] = {"observedGeneration": value["metadata"]["generation"], "replicas": 0, "readyReplicas": 0, "availableReplicas": 0}
            self.pods[MODULE.PUBLIC_MECKY_NAME] = []
            self.replica_sets[MODULE.PUBLIC_MECKY_NAME] = []
            self.slices[MODULE.PUBLIC_MECKY_NAME] = []
        else:
            value["metadata"]["generation"] += 1
            value["status"] = {"observedGeneration": value["metadata"]["generation"], "replicas": 1, "readyReplicas": 1, "availableReplicas": 1}
            self.pods[MODULE.PUBLIC_MECKY_NAME] = [public_mecky_pod(replacement=True)]
            self.replica_sets[MODULE.PUBLIC_MECKY_NAME] = [public_mecky_replica_set(replacement=True)]
            self.slices[MODULE.PUBLIC_MECKY_NAME] = [public_mecky_slice(replacement=True)]
            self.health["agent-relay"] = {"ok": True, "name": "Röbel E2E Mecky-Relay", "events": 1}
        self._maybe_fail(operation, after=True)
        return copy.deepcopy(value)

    def _replace(self, component: str) -> None:
        self.pods[component] = [pod(component, replacement=True)]
        self.replica_sets[component] = [replica_set(component, replacement=True)]
        if self.stale_endpoint != component:
            self.slices[component] = [endpoint_slice(component, replacement=True)]
        self.health[component] = {"ok": True, "name": component, "events": 0}
        self.health[component]["name"] = "Röbel E2E Bürger-Relay" if component == "citizen-relay" else "Röbel E2E Mecky-Relay"
        deployment_key = MODULE.canonical(MODULE.deployment_target(component))
        current_rv = int(self.objects[deployment_key]["metadata"]["resourceVersion"])
        self.objects[deployment_key]["metadata"]["resourceVersion"] = str(current_rv + 1)
        if component == "agent-relay":
            self.feed = empty_feed()

    def delete_pod(self, component: str, pod_name: str, options: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(("delete_pod", component, pod_name, copy.deepcopy(options)))
        self._assert_intent(f"delete-{component}-pod")
        self.deletes.append({"component": component, "name": pod_name, "options": copy.deepcopy(options)})
        self._maybe_fail(f"delete-{component}-pod", after=False)
        self._replace(component)
        self._maybe_fail(f"delete-{component}-pod", after=True)
        return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": pod_name}}


class FakePublicHttps:
    def __init__(self, kube: FakeKubernetes) -> None:
        self.kube = kube
        self.calls: list[tuple[str, str]] = []

    def probe_gate(self) -> int:
        self.calls.append(("POST", MODULE.WORKBENCH_GATE_PROBE_PATH))
        value = self.kube.objects[MODULE.canonical(MODULE.workbench_ingress_target())]
        policy = value["metadata"]["annotations"][MODULE.WORKBENCH_INGRESS_ANNOTATION]
        return 405 if policy == MODULE.WORKBENCH_INGRESS_GATED else 404

    def get_workbench(self, path: str) -> dict[str, Any]:
        self.calls.append(("GET", path))
        if path == MODULE.WORKBENCH_CONFIG_PATH:
            return workbench_config()
        if path == MODULE.WORKBENCH_FEED_PATH:
            self.kube.feed_probe_count += 1
            if self.kube.drift_quiet and self.kube.feed_probe_count > 2:
                changed = copy.deepcopy(self.kube.feed)
                if changed["posts"]:
                    changed["posts"][0]["id"] = "changed-fixture"
                return changed
            return copy.deepcopy(self.kube.feed)
        raise AssertionError(path)


class FastClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        self.value += 1.0
        return self.value


class RelayResetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        os.chmod(self.root, 0o700)
        self.pin = self.root / "runtime-pin.json"
        self.pin.write_bytes(PIN_BYTES)
        os.chmod(self.pin, 0o600)
        self.hashes = protected_hashes()
        self.revision = "a" * 40
        self.operation_id = "12345678-1234-4123-8123-123456789abc"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def execute(self, kube: FakeKubernetes, *, public: Any | None = None, journal: Any | None = None, receipt: Any | None = None, **kwargs: Any) -> tuple[dict[str, Any], Any, Any]:
        journal = journal or MODULE.MemoryJournal()
        receipt = receipt or MODULE.MemoryReceipt()
        kube.journal = journal
        result = MODULE._run_transaction(
            kube=kube,
            public=public or FakePublicHttps(kube),
            artifact_pin=self.pin,
            receipt=receipt,
            journal=journal,
            protected_revision=self.revision,
            protected_hashes=self.hashes,
            operation_id=self.operation_id,
            replacement_timeout_seconds=kwargs.pop("replacement_timeout_seconds", 3),
            sleep_fn=kwargs.pop("sleep_fn", lambda _seconds: None),
            monotonic_fn=kwargs.pop("monotonic_fn", FastClock()),
            **kwargs,
        )
        return result, journal, receipt

    def test_exact_artifact_pin_is_bound(self) -> None:
        self.assertEqual("sha256:" + hashlib.sha256(PIN_BYTES).hexdigest(), MODULE.ARTIFACT_PIN_RECEIPT_SHA256)
        proof = MODULE.validate_artifact_pin(self.pin)
        self.assertEqual(proof["sourceRevision"], MODULE.SOURCE_REVISION)
        self.assertEqual(proof["image"], MODULE.RELAY_IMAGE)
        self.assertEqual(proof["civicAuthority"], "none")

    def test_completed_transaction_orders_gate_quiescence_resets_profile_and_restoration(self) -> None:
        kube = FakeKubernetes()
        result, journal, receipt = self.execute(kube)
        self.assertEqual(result["status"], "completed")
        self.assertEqual([item["component"] for item in kube.deletes], ["citizen-relay", "agent-relay"])
        self.assertEqual([name for name, _ in kube.patches], [
            "gate-workbench", "suspend-public-mecky", "scale-public-mecky-zero",
            "scale-public-mecky-one", "restore-public-mecky-flux", "restore-workbench-gate",
        ])
        self.assertEqual(result["after"]["feed"]["postCount"], 0)
        self.assertEqual(len(result["after"]["feedObservations"]), 2)
        self.assertEqual(result["after"]["feedObservations"][0], result["after"]["feedObservations"][1])
        self.assertTrue(result["gate"]["applied"] and result["gate"]["restored"])
        self.assertEqual(len(result["gate"]["quietObservations"]), 3)
        self.assertTrue(result["meckyLifecycle"]["scaledToZero"])
        self.assertTrue(result["meckyLifecycle"]["scaledToOne"])
        self.assertTrue(result["meckyLifecycle"]["fluxRestored"])
        self.assertEqual(result["meckyLifecycle"]["profile"], profile_proof())
        self.assertTrue(result["restoration"]["complete"])
        self.assertFalse(result["effects"]["secretValuesRead"])
        self.assertFalse(result["effects"]["eventContentsEmitted"])
        self.assertFalse(result["effects"]["publicKeysEmitted"])
        self.assertFalse(result["effects"]["civicAuthorityEffects"])
        self.assertFalse(result["effects"]["dataRollbackPossible"])
        self.assertFalse(result["effects"]["automaticMutationRetry"])
        for item in kube.deletes:
            self.assertEqual(set(item["options"]), {"apiVersion", "kind", "preconditions"})
            self.assertEqual(item["options"]["apiVersion"], "v1")
            self.assertEqual(item["options"]["kind"], "DeleteOptions")
            self.assertEqual(set(item["options"]["preconditions"]), {"uid", "resourceVersion"})
        self.assertEqual(kube.deletes[0]["options"]["preconditions"]["uid"], UIDS["citizen-relay"]["oldPod"])
        self.assertEqual(kube.deletes[1]["options"]["preconditions"]["uid"], UIDS["agent-relay"]["oldPod"])
        events = journal.state["events"]
        citizen_intent = next(index for index, event in enumerate(events) if event["operation"] == "delete-citizen-relay-pod" and event["stage"] == "intent")
        citizen_ready = next(index for index, event in enumerate(events) if event["operation"] == "wait-citizen-relay-replacement" and event["stage"] == "after")
        agent_intent = next(index for index, event in enumerate(events) if event["operation"] == "delete-agent-relay-pod" and event["stage"] == "intent")
        self.assertLess(citizen_intent, citizen_ready)
        self.assertLess(citizen_ready, agent_intent)
        scale_up = next(index for index, event in enumerate(events) if event["operation"] == "scale-public-mecky-one" and event["stage"] == "intent")
        profile = next(index for index, event in enumerate(events) if event["operation"] == "wait-public-mecky-profile" and event["stage"] == "after")
        flux_restore = next(index for index, event in enumerate(events) if event["operation"] == "restore-public-mecky-flux" and event["stage"] == "intent")
        ingress_restore = next(index for index, event in enumerate(events) if event["operation"] == "restore-workbench-gate" and event["stage"] == "intent")
        self.assertLess(agent_intent, scale_up)
        self.assertLess(scale_up, profile)
        self.assertLess(profile, flux_restore)
        self.assertLess(flux_restore, ingress_restore)
        self.assertEqual(receipt.value["status"], "completed")

    def test_artifact_or_protected_closure_drift_fails_before_cluster_reads(self) -> None:
        kube = FakeKubernetes()
        self.pin.write_bytes(PIN_BYTES + b" ")
        with self.assertRaisesRegex(MODULE.RelayResetError, "checksum drift"):
            self.execute(kube)
        self.assertEqual(kube.calls, [])
        self.pin.write_bytes(PIN_BYTES)
        bad = dict(self.hashes)
        bad.pop(MODULE.PROTECTED_PATHS[-1])
        with self.assertRaisesRegex(MODULE.RelayResetError, "closure drift"):
            MODULE._run_transaction(
                kube=kube,
                public=FakePublicHttps(kube),
                artifact_pin=self.pin,
                receipt=MODULE.MemoryReceipt(),
                journal=MODULE.MemoryJournal(),
                protected_revision=self.revision,
                protected_hashes=bad,
            )
        self.assertEqual(kube.calls, [])

    def test_preflight_rejects_identity_emptydir_admission_or_real_feed_without_mutation(self) -> None:
        mutations = (
            lambda kube: kube.objects[MODULE.canonical(MODULE.deployment_target("citizen-relay"))]["metadata"].__setitem__("uid", "12121212-1212-4121-8121-121212121212"),
            lambda kube: kube.objects[MODULE.canonical(MODULE.deployment_target("citizen-relay"))]["spec"]["template"]["spec"]["volumes"][0]["emptyDir"].__setitem__("sizeLimit", "256Mi"),
            lambda kube: kube.pods["citizen-relay"].append(copy.deepcopy(kube.pods["citizen-relay"][0])),
            lambda kube: kube.health["citizen-relay"].__setitem__("name", "wrong"),
            lambda kube: kube.feed["posts"][0].__setitem__("synthetic", False),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                kube = FakeKubernetes()
                mutate(kube)
                result, _, _ = self.execute(kube)
                self.assertEqual(result["status"], "preflight-failed")
                self.assertEqual(kube.deletes, [])

    def test_quiet_drift_aborts_before_destructive_mutation_and_restores_gate_once(self) -> None:
        kube = FakeKubernetes()
        kube.drift_quiet = True
        result, _, _ = self.execute(kube)
        self.assertEqual(result["status"], "failed-restored")
        self.assertEqual(kube.deletes, [])
        self.assertEqual([name for name, _ in kube.patches], ["gate-workbench", "restore-workbench-gate"])
        self.assertTrue(result["gate"]["restored"])

    def test_lost_delete_response_is_classified_once_and_never_retried(self) -> None:
        kube = FakeKubernetes()
        kube.fail_operation = "delete-citizen-relay-pod"
        kube.fail_after_apply = True
        result, journal, _ = self.execute(kube)
        self.assertEqual(result["status"], "completed")
        self.assertEqual([item["component"] for item in kube.deletes], list(MODULE.COMPONENT_ORDER))
        classified = [event for event in journal.state["events"] if event["operation"] == "delete-citizen-relay-pod" and event["stage"] == "classified"]
        self.assertEqual(len(classified), 1)
        self.assertFalse(classified[0]["mutationRetried"])

    def test_failure_after_scale_down_restores_mecky_then_flux_then_gate(self) -> None:
        kube = FakeKubernetes()
        kube.fail_operation = "delete-citizen-relay-pod"
        kube.fail_after_apply = False
        result, journal, _ = self.execute(kube)
        self.assertEqual(result["status"], "uncertain")
        self.assertEqual(len(kube.deletes), 1)
        self.assertEqual([name for name, _ in kube.patches], [
            "gate-workbench", "suspend-public-mecky", "scale-public-mecky-zero",
            "restore-public-mecky-scale", "restore-public-mecky-flux", "restore-workbench-gate",
        ])
        self.assertTrue(result["restoration"]["scaleUp"]["proven"])
        self.assertTrue(result["restoration"]["flux"]["proven"])
        self.assertTrue(result["restoration"]["ingress"]["proven"])
        self.assertFalse(result["uncertainOutcome"]["mutationRetried"])
        operations = [event["operation"] for event in journal.state["events"] if event["stage"] == "intent"]
        self.assertLess(operations.index("restore-public-mecky-scale"), operations.index("restore-public-mecky-flux"))
        self.assertLess(operations.index("restore-public-mecky-flux"), operations.index("restore-workbench-gate"))

    def test_scale_down_not_applied_restores_preflight_ready_flux_and_gate_without_retry(self) -> None:
        kube = FakeKubernetes()
        kube.fail_operation = "scale-public-mecky-zero"
        kube.fail_after_apply = False
        result, journal, _ = self.execute(kube)
        self.assertEqual(result["status"], "uncertain")
        self.assertEqual(kube.deletes, [])
        self.assertEqual([name for name, _ in kube.patches], [
            "gate-workbench", "suspend-public-mecky", "scale-public-mecky-zero",
            "restore-public-mecky-flux", "restore-workbench-gate",
        ])
        self.assertTrue(result["restoration"]["flux"]["proven"])
        self.assertTrue(result["restoration"]["ingress"]["proven"])
        classified = [event for event in journal.state["events"] if event["operation"] == "scale-public-mecky-zero" and event["stage"] == "classified"]
        self.assertEqual(len(classified), 1)
        self.assertEqual(classified[0]["classification"], "source-observed")

    def test_profile_timeout_never_retries_scale_up_and_keeps_flux_suspended_but_restores_gate(self) -> None:
        kube = FakeKubernetes()
        kube.invalid_profile = True
        result, _, _ = self.execute(kube, replacement_timeout_seconds=1, monotonic_fn=FastClock())
        self.assertEqual(result["status"], "uncertain")
        names = [name for name, _ in kube.patches]
        self.assertEqual(names.count("scale-public-mecky-one"), 1)
        self.assertNotIn("restore-public-mecky-scale", names)
        self.assertNotIn("restore-public-mecky-flux", names)
        self.assertEqual(names[-1], "restore-workbench-gate")
        self.assertFalse(result["restoration"]["complete"])
        self.assertTrue(result["restoration"]["ingress"]["proven"])

    def test_flux_restore_waits_for_ready_generation_without_second_patch(self) -> None:
        kube = FakeKubernetes()
        kube.flux_restore_ready_after_gets = 2
        result, _, _ = self.execute(kube)
        self.assertEqual(result["status"], "completed")
        names = [name for name, _ in kube.patches]
        self.assertEqual(names.count("restore-public-mecky-flux"), 1)
        self.assertGreaterEqual(kube.flux_restore_gets, 2)

    def test_ambiguous_suspend_is_never_retried_or_falsely_restored_complete(self) -> None:
        kube = FakeKubernetes()
        kube.fail_operation = "suspend-public-mecky"
        kube.fail_after_apply = True
        kube.classification_get_failure = MODULE.canonical(MODULE.public_mecky_kustomization_target())
        kube.classification_get_failure_remaining = 1
        result, journal, _ = self.execute(kube)
        self.assertEqual(result["status"], "uncertain")
        self.assertEqual([name for name, _ in kube.patches], ["gate-workbench", "suspend-public-mecky", "restore-workbench-gate"])
        self.assertFalse(result["restoration"]["complete"])
        self.assertTrue(result["restoration"]["ingress"]["proven"])
        classified = [event for event in journal.state["events"] if event["operation"] == "suspend-public-mecky" and event["stage"] == "classified"]
        self.assertEqual(len(classified), 1)
        self.assertFalse(classified[0]["mutationRetried"])

    def test_ambiguous_gate_is_not_retried_or_falsely_reported_restored(self) -> None:
        kube = FakeKubernetes()
        kube.fail_operation = "gate-workbench"
        kube.fail_after_apply = True
        kube.classification_get_failure = MODULE.canonical(MODULE.workbench_ingress_target())
        kube.classification_get_failure_remaining = 1
        result, journal, _ = self.execute(kube)
        self.assertEqual(result["status"], "uncertain")
        self.assertEqual([name for name, _ in kube.patches], ["gate-workbench"])
        self.assertTrue(result["restoration"]["required"])
        self.assertFalse(result["restoration"]["complete"])
        self.assertFalse(result["gate"]["restored"])
        classified = [event for event in journal.state["events"] if event["operation"] == "gate-workbench" and event["stage"] == "classified"]
        self.assertEqual(len(classified), 1)
        self.assertFalse(classified[0]["mutationRetried"])

    def test_existing_journal_state_is_not_resumed(self) -> None:
        kube = FakeKubernetes()
        journal = MODULE.MemoryJournal()
        journal.state = {"schemaVersion": MODULE.JOURNAL_SCHEMA, "status": "uncertain"}
        with self.assertRaisesRegex(MODULE.RelayResetError, "resume is forbidden"):
            self.execute(kube, journal=journal)
        self.assertEqual(kube.calls, [])
        self.assertEqual(kube.deletes, [])

    def test_json_receipt_and_journal_are_owner_only_hash_linked_and_non_resumable(self) -> None:
        kube = FakeKubernetes()
        receipt_path = self.root / "receipt.json"
        journal_path = self.root / "journal.json"
        receipt = MODULE.JsonReceipt(receipt_path)
        journal = MODULE.JsonJournal(journal_path)
        result, _, _ = self.execute(kube, journal=journal, receipt=receipt)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(journal_path.stat().st_mode), 0o600)
        receipt_value = json.loads(receipt_path.read_text())
        journal_value = json.loads(journal_path.read_text())
        self.assertEqual(receipt_value["schemaVersion"], MODULE.RECEIPT_SCHEMA)
        self.assertEqual(journal_value["schemaVersion"], MODULE.JOURNAL_SCHEMA)
        self.assertEqual(receipt_value["canonicalSha256"], MODULE.digest({key: value for key, value in receipt_value.items() if key != "canonicalSha256"}))
        events = journal_value["events"]
        for index, event in enumerate(events):
            prior = events[index - 1]["entrySha256"] if index else None
            self.assertEqual(event["previousEntrySha256"], prior)
            payload = {key: value for key, value in event.items() if key != "entrySha256"}
            self.assertEqual(event["entrySha256"], MODULE.digest(payload))
        with self.assertRaisesRegex(MODULE.RelayResetError, "must be absent"):
            MODULE.JsonJournal(journal_path)

    def test_adapter_emits_only_raw_preconditioned_delete_shape(self) -> None:
        adapter = object.__new__(MODULE.KubernetesAdapter)
        calls: list[tuple[list[str], str | None, float]] = []

        def fake_run(args: list[str], *, input_text: str | None = None, timeout: float = 40) -> subprocess.CompletedProcess[str]:
            calls.append((args, input_text, timeout))
            return subprocess.CompletedProcess(args, 0, '{"apiVersion":"v1","kind":"Pod"}', "")

        adapter._run = fake_run
        selected = pod("citizen-relay", replacement=False)["metadata"]
        options = MODULE.delete_options({"uid": selected["uid"], "resourceVersion": selected["resourceVersion"]})
        adapter.delete_pod("citizen-relay", selected["name"], options)
        self.assertEqual(calls[0][0], [
            "delete", "--raw",
            f"/api/v1/namespaces/{MODULE.NAMESPACE}/pods/{selected['name']}",
            "-f", "-",
        ])
        self.assertEqual(json.loads(calls[0][1]), options)
        widened = copy.deepcopy(options)
        widened["gracePeriodSeconds"] = 0
        with self.assertRaisesRegex(MODULE.RelayResetError, "fields widened"):
            adapter.delete_pod("citizen-relay", selected["name"], widened)
        self.assertEqual(len(calls), 1)

    def test_adapter_patch_and_exec_capabilities_are_descriptor_fixed(self) -> None:
        adapter = object.__new__(MODULE.KubernetesAdapter)
        adapter.read_only_exec_requests = 0
        calls: list[tuple[list[str], str | None]] = []

        def fake_run(args: list[str], *, input_text: str | None = None, timeout: float = 40) -> subprocess.CompletedProcess[str]:
            calls.append((copy.deepcopy(args), input_text))
            if "exec" in args:
                return subprocess.CompletedProcess(args, 0, json.dumps({
                    "health": {"ok": True, "identityVerified": True, "events": 0},
                    "eventStore": {"present": False, "bytes": 0, "records": 0},
                    "admissionStore": {"applicable": True, "present": False, "bytes": 0, "records": 0},
                    "profile": None,
                }), "")
            return subprocess.CompletedProcess(args, 0, json.dumps(ingress(MODULE.WORKBENCH_INGRESS_GATED, "41")), "")

        adapter._run = fake_run
        adapter.inspect_relay("citizen-relay", "citizen-relay-old")
        self.assertIn(["--", "/usr/local/bin/node", "-e"], [calls[0][0][index:index + 3] for index in range(len(calls[0][0]) - 2)])
        self.assertNotIn("sh", calls[0][0])
        facts = MODULE.validate_workbench_ingress(ingress(), expected_policy=MODULE.WORKBENCH_INGRESS_OPEN)
        patch = MODULE.ingress_patch(facts, MODULE.WORKBENCH_INGRESS_OPEN, MODULE.WORKBENCH_INGRESS_GATED)
        adapter.patch_ingress(patch)
        widened = copy.deepcopy(patch)
        widened[-1]["value"] = "allow all"
        with self.assertRaises(MODULE.RelayResetError):
            adapter.patch_ingress(widened)

    def test_public_https_adapter_has_exact_origin_verified_tls_no_redirects_or_proxy(self) -> None:
        self.assertEqual(MODULE.PublicHttpsAdapter.ALLOWED, {
            ("GET", MODULE.WORKBENCH_CONFIG_PATH),
            ("GET", MODULE.WORKBENCH_FEED_PATH),
            ("POST", MODULE.WORKBENCH_GATE_PROBE_PATH),
        })
        whole_source = MODULE_PATH.read_text()
        start = whole_source.index("class PublicHttpsAdapter")
        end = whole_source.index("\ndef _relay_inventory_script", start)
        source = whole_source[start:end]
        self.assertIn("ssl.create_default_context", source)
        self.assertIn("HTTPSConnection", source)
        self.assertNotIn("Proxy", source)
        self.assertNotIn("redirect", source.lower().replace("redirects", ""))

    def test_profile_proof_rejects_any_failed_signature_identity_or_cardinality_bit(self) -> None:
        base = {
            "health": {"ok": True, "identityVerified": True, "events": 1},
            "eventStore": {"present": True, "bytes": 100, "records": 1},
            "admissionStore": {"applicable": False, "present": False, "bytes": 0, "records": 0},
            "profile": profile_proof(),
        }
        MODULE.validate_relay_inventory(base, "agent-relay", empty=False, profile=True)
        for key in ("signatureVerified", "eventIdVerified", "expectedAuthorHash", "identityVerified", "agentTagVerified"):
            with self.subTest(key=key):
                bad = copy.deepcopy(base)
                bad["profile"][key] = False
                with self.assertRaises(MODULE.PostconditionFailure):
                    MODULE.validate_relay_inventory(bad, "agent-relay", empty=False, profile=True)
        bad = copy.deepcopy(base)
        bad["profile"]["kind1Count"] = 1
        with self.assertRaises(MODULE.PostconditionFailure):
            MODULE.validate_relay_inventory(bad, "agent-relay", empty=False, profile=True)

    def test_interface_scope_and_no_authority_contract(self) -> None:
        signature = inspect.signature(MODULE.KubernetesAdapter)
        self.assertEqual(list(signature.parameters), ["kubeconfig", "kubectl"])
        run_signature = inspect.signature(MODULE.KubernetesAdapter._run)
        self.assertEqual(list(run_signature.parameters), ["self", "args", "input_text", "timeout"])
        self.assertEqual(MODULE.RECEIPT_SCHEMA, "roebel_staging_relay_fixture_reset_receipt_v2")
        self.assertEqual(MODULE.JOURNAL_SCHEMA, "roebel_staging_relay_fixture_reset_journal_v2")
        self.assertTrue(MODULE.LIVE_EXECUTION_ENABLED)
        self.assertNotIn("Secret", {target["kind"] for target in MODULE.ALLOWED_GET_TARGETS})
        source = MODULE_PATH.read_text()
        self.assertNotIn("gracePeriodSeconds\": 0", source)
        self.assertNotIn("propagationPolicy", source)
        self.assertNotIn("get secret", source.lower())
        self.assertIn("dataRollbackPossible\": False", source)


if __name__ == "__main__":
    unittest.main()
