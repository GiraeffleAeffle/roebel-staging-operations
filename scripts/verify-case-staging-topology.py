#!/usr/bin/env python3
"""Fail closed over the inert Röbel Case staging runtime gate.

The records below are review data, not a Kustomization. They describe the
smallest future two-process runtime without supplying an image digest,
credential payload, PVC, RBAC object, Flux reference, or live bind.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


TOPOLOGY_ROOT = "case-staging-topology"
NAMESPACE = "stadtstack-roebel-staging-lab"
PART_OF = "roebel-case-staging"
CONTROL = "roebel-case-steward-control"
PUBLIC = "roebel-case-public-binding"
CONTROL_COMPONENT = "case-steward-control"
PUBLIC_COMPONENT = "case-public-binding"
WEB_NAMESPACE = "stadtstack-roebel-web-preview"
DNS_NAMESPACE = "kube-system"
MISSING_CONTROL_PREFLIGHT_EVIDENCE = [
    "controlDeploymentPreflight.expectedBindingChecksum",
    "controlDeploymentPreflight.binding.releaseDigest",
    "controlDeploymentPreflight.binding.operationsTopologyChecksum",
    "controlDeploymentPreflight.binding.storage.pvcUid",
    "controlDeploymentPreflight.binding.storage.pvName",
    "controlDeploymentPreflight.binding.storage.storageClass",
    "controlDeploymentPreflight.binding.storage.accessMode",
    "controlDeploymentPreflight.binding.storage.volumeMode",
    "controlDeploymentPreflight.binding.storage.requestedBytes",
    "controlDeploymentPreflight.binding.storage.uid",
    "controlDeploymentPreflight.binding.storage.gid",
    "controlDeploymentPreflight.binding.storage.mode",
    "controlDeploymentPreflight.binding.storage.filesystemType",
    "controlDeploymentPreflight.binding.storage.minAvailableBytes",
    "controlDeploymentPreflight.binding.storage.marker.checksum",
    "controlDeploymentPreflight.binding.storage.marker.uid",
    "controlDeploymentPreflight.binding.storage.marker.gid",
    "controlDeploymentPreflight.binding.storage.marker.mode",
    "controlDeploymentPreflight.binding.bindingChecksum",
]
SERVICE_SPECS = (
    (CONTROL, CONTROL_COMPONENT, "admission", 18085),
    (f"{CONTROL}-private-outbox", CONTROL_COMPONENT, "private-outbox", 18087),
    (PUBLIC, PUBLIC_COMPONENT, "public", 18086),
)
EXPECTED_FILES = {
    "contract.json",
    f"{CONTROL}-serviceaccount.json",
    f"{PUBLIC}-serviceaccount.json",
    *{f"{name}-service.json" for name, _component, _port_name, _port in SERVICE_SPECS},
    f"{CONTROL}-default-deny-networkpolicy.json",
    f"{PUBLIC}-default-deny-networkpolicy.json",
    f"{CONTROL}-allow-private-outbox-from-public-networkpolicy.json",
    f"{PUBLIC}-allow-private-outbox-and-dns-egress-networkpolicy.json",
    f"{PUBLIC}-allow-roebel-web-ingress-networkpolicy.json",
}


class VerificationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    require(path.is_file() and not path.is_symlink(), f"regular file required: {path.name}")
    require(path.stat().st_size <= 64 * 1024, f"topology contract file too large: {path.name}")
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=object_pairs)


def labels(component: str) -> dict[str, str]:
    return {
        "app.kubernetes.io/component": component,
        "app.kubernetes.io/part-of": PART_OF,
        "stadtstack.io/authority": "none",
    }


def selector(component: str) -> dict[str, str]:
    return {
        "app.kubernetes.io/component": component,
        "app.kubernetes.io/part-of": PART_OF,
    }


def metadata(name: str, component: str) -> dict[str, Any]:
    return {"labels": labels(component), "name": name, "namespace": NAMESPACE}


def expected_contract() -> dict[str, Any]:
    blocked_image = {
        "state": "blocked",
        "immutableDigestOnly": True,
        "provenanceRequired": True,
        "sbomRequired": True,
        "value": None,
    }
    return {
        "schemaVersion": "roebel_case_staging_runtime_gate_v1",
        "mode": "inert_review_only",
        "namespace": NAMESPACE,
        "reconciliationAllowed": False,
        "fluxKustomizationAllowed": False,
        "applicationCompositionRequired": True,
        "reviewContractOnly": True,
        "allowedKinds": ["NetworkPolicy", "Service", "ServiceAccount"],
        "otherKindsAllowed": False,
        "invariants": {
            "automountServiceAccountToken": False,
            "clusterMutation": False,
            "credentialsAllowed": False,
            "liveBindAllowed": False,
            "publicSQLiteMountAllowed": False,
            "serviceExposure": "ClusterIP_only",
            "workloadDefinitionAllowed": False,
            "imagePullSecretsAllowed": False,
            "secretObjectsAllowed": False,
            "pvcObjectsAllowed": False,
            "rbacObjectsAllowed": False,
            "fluxObjectsAllowed": False,
        },
        "controlDeploymentPreflight": {
            "status": "blocked",
            "reviewedOperations": {
                "repository": "GiraeffleAeffle/roebel-staging-operations",
                "ownership": "remote_but_owned",
                "contractPath": "case-staging-topology/contract.json",
            },
            "schemaVersion": "staging_case_control_deployment_binding_v1",
            "deploymentEnvironment": "staging",
            "municipalityId": "roebel-mueritz",
            "namespace": NAMESPACE,
            "workloadName": CONTROL,
            "deploymentName": CONTROL,
            "markerSchema": "staging_case_control_storage_marker_v1",
            "expectedBindingChecksum": None,
            "binding": {
                "schemaVersion": "staging_case_control_deployment_binding_v1",
                "deploymentEnvironment": "staging",
                "municipalityId": "roebel-mueritz",
                "workloadName": CONTROL,
                "workload": {
                    "serviceAccountName": CONTROL,
                    "automountServiceAccountToken": False,
                    "imagePullSecrets": [],
                },
                "releaseDigest": None,
                "operationsTopologyChecksum": None,
                "deployment": {
                    "replicas": 1,
                    "strategy": "Recreate",
                    "noOverlappingPods": True,
                },
                "storage": {
                    "rootDir": "/var/lib/stadtstack/case-control",
                    "pvcNamespace": NAMESPACE,
                    "pvcName": "roebel-case-steward-control-state",
                    "pvcUid": None,
                    "pvName": None,
                    "storageClass": None,
                    "accessMode": None,
                    "volumeMode": None,
                    "requestedBytes": None,
                    "uid": None,
                    "gid": None,
                    "mode": None,
                    "filesystemType": None,
                    "minAvailableBytes": None,
                    "marker": {
                        "fileName": ".stadtstack-control-storage-v1.json",
                        "checksum": None,
                        "uid": None,
                        "gid": None,
                        "mode": None,
                    },
                },
                "listeners": [
                    {"id": "admission", "port": 18085, "bindScope": "pod_network"},
                    {"id": "private-outbox", "port": 18087, "bindScope": "pod_network"},
                    {"id": "probe", "port": 18088, "bindScope": "pod_network"},
                ],
                "bindingChecksum": None,
            },
            "missingEvidence": MISSING_CONTROL_PREFLIGHT_EVIDENCE,
        },
        "futureWorkloads": {
            "control": {
                "deploymentName": CONTROL,
                "serviceAccount": CONTROL,
                "automountServiceAccountToken": False,
                "imagePullSecretsAllowed": False,
                "image": blocked_image,
                "preexistingSecretRefs": ["roebel-case-steward-control-runtime"],
                "preexistingSecretRefUsage": {
                    "roebel-case-steward-control-runtime": "container_env_valueFrom_only",
                },
                "preexistingPersistentVolumeClaimRefs": ["roebel-case-steward-control-state"],
                "ports": [
                    {"name": "admission", "port": 18085},
                    {"name": "private-outbox", "port": 18087},
                    {"name": "control-probe", "port": 18088},
                ],
                "directProbePorts": [{"name": "control-probe", "port": 18088}],
                "servicePorts": ["admission", "private-outbox"],
                "tokenAdapter": {
                    "marker": "stadtstack.io/staging-token-adapter-v1",
                    "environment": "staging",
                    "productionRejected": True,
                },
            },
            "public": {
                "deploymentName": PUBLIC,
                "serviceAccount": PUBLIC,
                "automountServiceAccountToken": False,
                "imagePullSecretsAllowed": False,
                "image": blocked_image,
                "preexistingSecretRefs": [],
                "preexistingSecretRefUsage": {},
                "preexistingPersistentVolumeClaimRefs": [],
                "forbiddenReferences": ["Secret", "PersistentVolumeClaim", "Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding", "token"],
                "ports": [{"name": "public", "port": 18086}, {"name": "public-probe", "port": 18089}],
                "directProbePorts": [{"name": "public-probe", "port": 18089}],
                "servicePorts": ["public"],
            },
        },
        "network": {
            "controlAdmission": {
                "state": "blocked",
                "reason": "future staff gateway identity is not pinned in this runtime gate",
            },
            "controlPrivateOutbox": {"from": PUBLIC, "port": 18087, "protocol": "TCP"},
            "publicIngress": {
                "fromNamespace": WEB_NAMESPACE,
                "fromPodLabels": {"app.kubernetes.io/name": "roebel-web-presentation"},
                "port": 18086,
                "protocol": "TCP",
            },
            "publicEgress": {
                "dns": {"namespace": DNS_NAMESPACE, "podLabels": {"k8s-app": "kube-dns"}, "ports": [53]},
                "privateOutbox": {"to": CONTROL, "port": 18087, "protocol": "TCP"},
            },
        },
        "blockers": [
            "immutable image digests with provenance and SPDX SBOM evidence are required before Deployments exist",
            "the staff gateway identity is not pinned, so admission remains default-denied",
            "the protected Roebel Web egress policy does not yet permit the public binding service on port 18086",
            "the reviewed Stadtstack control application module is pending admission until its PR is merged; no immutable release or bind is authorized",
            "the control PVC identity, filesystem ownership/mode/magic/free-space observation, release binding, and Operations topology digest are not yet available",
            "a separate protected policy-migration ceremony must admit the reviewed application release and exact preflight before reconciliation",
        ],
    }


def verify_control_deployment_preflight(contract: dict[str, Any]) -> None:
    """Keep the deployment/storage admission record closed-world and inert."""

    preflight = contract.get("controlDeploymentPreflight")
    require(isinstance(preflight, dict), "control deployment preflight missing")
    require(preflight.get("status") == "blocked", "control deployment preflight must stay blocked")
    require(preflight.get("schemaVersion") == "staging_case_control_deployment_binding_v1", "control deployment preflight schema drift")
    require(preflight.get("deploymentEnvironment") == "staging", "control deployment preflight environment drift")
    require(preflight.get("municipalityId") == "roebel-mueritz", "control deployment preflight municipality drift")
    require(preflight.get("namespace") == NAMESPACE, "control deployment preflight namespace drift")
    require(preflight.get("workloadName") == CONTROL and preflight.get("deploymentName") == CONTROL, "control deployment workload name drift")
    require(preflight.get("markerSchema") == "staging_case_control_storage_marker_v1", "control deployment marker schema drift")
    require(preflight.get("expectedBindingChecksum") is None, "placeholder immutable deployment binding pin is forbidden")
    require(preflight.get("reviewedOperations", {}).get("ownership") == "remote_but_owned", "reviewed Operations ownership drift")
    binding = preflight.get("binding")
    require(isinstance(binding, dict), "control deployment binding missing")
    require(binding.get("schemaVersion") == "staging_case_control_deployment_binding_v1", "control deployment binding schema drift")
    require(binding.get("deploymentEnvironment") == "staging", "control deployment binding environment drift")
    require(binding.get("municipalityId") == "roebel-mueritz", "control deployment binding municipality drift")
    require(binding.get("workloadName") == CONTROL, "control deployment binding workload drift")

    workload = binding.get("workload")
    require(isinstance(workload, dict), "control deployment workload preflight missing")
    require(
        workload
        == {
            "serviceAccountName": CONTROL,
            "automountServiceAccountToken": False,
            "imagePullSecrets": [],
        },
        "control deployment token/image-pull credential posture drift",
    )
    require(binding.get("deployment") == {"replicas": 1, "strategy": "Recreate", "noOverlappingPods": True}, "control deployment rollout facts drift")
    require(binding.get("listeners") == [
        {"id": "admission", "port": 18085, "bindScope": "pod_network"},
        {"id": "private-outbox", "port": 18087, "bindScope": "pod_network"},
        {"id": "probe", "port": 18088, "bindScope": "pod_network"},
    ], "control deployment listener boundary drift")

    storage = binding.get("storage")
    require(isinstance(storage, dict), "control deployment storage preflight missing")
    require(storage.get("rootDir") == "/var/lib/stadtstack/case-control", "control deployment root drift")
    require(storage.get("pvcNamespace") == NAMESPACE, "control deployment PVC namespace drift")
    require(storage.get("pvcName") == "roebel-case-steward-control-state", "control deployment PVC name drift")
    require(storage.get("marker", {}).get("fileName") == ".stadtstack-control-storage-v1.json", "control deployment marker filename drift")
    for field in ("pvcUid", "pvName", "storageClass", "accessMode", "volumeMode", "requestedBytes", "uid", "gid", "mode", "filesystemType", "minAvailableBytes"):
        require(storage.get(field) is None, f"placeholder storage {field} is forbidden")
    marker = storage.get("marker")
    require(isinstance(marker, dict), "control deployment marker preflight missing")
    for field in ("checksum", "uid", "gid", "mode"):
        require(marker.get(field) is None, f"placeholder marker {field} is forbidden")
    require(binding.get("releaseDigest") is None, "placeholder release digest is forbidden")
    require(binding.get("operationsTopologyChecksum") is None, "placeholder Operations topology checksum is forbidden")
    require(binding.get("bindingChecksum") is None, "placeholder binding checksum is forbidden")
    require(preflight.get("missingEvidence") == MISSING_CONTROL_PREFLIGHT_EVIDENCE, "control deployment missing evidence drift")

    public = contract.get("futureWorkloads", {}).get("public", {})
    require(isinstance(public, dict), "public workload contract missing")
    require("controlDeploymentPreflight" not in public, "public workload cannot carry control preflight")
    require("storage" not in public and "stateMount" not in public, "public workload cannot carry storage fields")


def expected_service_account(capability: str, component: str) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "automountServiceAccountToken": False,
        "imagePullSecrets": [],
        "metadata": metadata(capability, component),
    }


def expected_service(name: str, component: str, port_name: str, port: int) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": metadata(name, component),
        "spec": {
            "ports": [{"name": port_name, "port": port, "protocol": "TCP", "targetPort": port}],
            "selector": selector(component),
            "type": "ClusterIP",
        },
    }


def expected_default_deny(capability: str, component: str) -> dict[str, Any]:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": metadata(f"{capability}-default-deny", component),
        "spec": {"podSelector": {"matchLabels": selector(component)}, "policyTypes": ["Ingress", "Egress"]},
    }


def expected_control_private_outbox_allow() -> dict[str, Any]:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": metadata(f"{CONTROL}-allow-private-outbox-from-public", CONTROL_COMPONENT),
        "spec": {
            "podSelector": {"matchLabels": selector(CONTROL_COMPONENT)},
            "policyTypes": ["Ingress"],
            "ingress": [{"from": [{"podSelector": {"matchLabels": selector(PUBLIC_COMPONENT)}}], "ports": [{"port": 18087, "protocol": "TCP"}]}],
        },
    }


def expected_public_egress_allow() -> dict[str, Any]:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": metadata(f"{PUBLIC}-allow-private-outbox-and-dns-egress", PUBLIC_COMPONENT),
        "spec": {
            "podSelector": {"matchLabels": selector(PUBLIC_COMPONENT)},
            "policyTypes": ["Egress"],
            "egress": [
                {
                    "to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": DNS_NAMESPACE}}, "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}],
                    "ports": [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}],
                },
                {"to": [{"podSelector": {"matchLabels": selector(CONTROL_COMPONENT)}}], "ports": [{"port": 18087, "protocol": "TCP"}]},
            ],
        },
    }


def expected_public_ingress_allow() -> dict[str, Any]:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": metadata(f"{PUBLIC}-allow-roebel-web-ingress", PUBLIC_COMPONENT),
        "spec": {
            "podSelector": {"matchLabels": selector(PUBLIC_COMPONENT)},
            "policyTypes": ["Ingress"],
            "ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": WEB_NAMESPACE}}, "podSelector": {"matchLabels": {"app.kubernetes.io/name": "roebel-web-presentation"}}}], "ports": [{"port": 18086, "protocol": "TCP"}]}],
        },
    }


def topology_files(root: Path) -> set[str]:
    topology = root / TOPOLOGY_ROOT
    require(topology.is_dir() and not topology.is_symlink(), "topology root missing or symlinked")
    files: set[str] = set()
    for path in topology.rglob("*"):
        relative = path.relative_to(topology)
        require(not path.is_symlink(), f"topology symlink forbidden: {relative}")
        if path.is_dir():
            require(relative.parent == Path("."), f"nested topology directory forbidden: {relative}")
            continue
        require(path.is_file(), f"non-regular topology entry forbidden: {relative}")
        files.add(str(relative))
    require(files == EXPECTED_FILES, "topology file set drift")
    return files


def verify(root: Path) -> dict[str, Any]:
    root = root.resolve()
    require(root.is_dir(), "repository root missing")
    topology_files(root)
    topology = root / TOPOLOGY_ROOT
    contract = load_json(topology / "contract.json")
    require(isinstance(contract, dict), "runtime gate contract must be an object")
    verify_control_deployment_preflight(contract)
    require(contract == expected_contract(), "runtime gate contract drift")
    require(load_json(topology / f"{CONTROL}-serviceaccount.json") == expected_service_account(CONTROL, CONTROL_COMPONENT), "control ServiceAccount drift")
    require(load_json(topology / f"{PUBLIC}-serviceaccount.json") == expected_service_account(PUBLIC, PUBLIC_COMPONENT), "public ServiceAccount drift")
    for name, component, port_name, port in SERVICE_SPECS:
        require(load_json(topology / f"{name}-service.json") == expected_service(name, component, port_name, port), f"{name} Service drift")
    require(load_json(topology / f"{CONTROL}-default-deny-networkpolicy.json") == expected_default_deny(CONTROL, CONTROL_COMPONENT), "control default-deny NetworkPolicy drift")
    require(load_json(topology / f"{PUBLIC}-default-deny-networkpolicy.json") == expected_default_deny(PUBLIC, PUBLIC_COMPONENT), "public default-deny NetworkPolicy drift")
    require(load_json(topology / f"{CONTROL}-allow-private-outbox-from-public-networkpolicy.json") == expected_control_private_outbox_allow(), "control private-outbox NetworkPolicy drift")
    require(load_json(topology / f"{PUBLIC}-allow-private-outbox-and-dns-egress-networkpolicy.json") == expected_public_egress_allow(), "public egress NetworkPolicy drift")
    require(load_json(topology / f"{PUBLIC}-allow-roebel-web-ingress-networkpolicy.json") == expected_public_ingress_allow(), "public ingress NetworkPolicy drift")
    return {
        "schemaVersion": "roebel_case_staging_runtime_gate_verification_v1",
        "status": "passed",
        "mode": "inert_review_only",
        "namespace": NAMESPACE,
        "reconciliationAllowed": False,
        "fluxKustomizationAllowed": False,
        "effects": {"clusterMutation": False, "credentialRead": False, "credentialWrite": False, "liveBind": False, "publicStorageMount": False, "workloadDefinition": False},
        "blockers": expected_contract()["blockers"],
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = verify(args.root)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, VerificationError) as error:
        print(f"case-staging-topology verification failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
