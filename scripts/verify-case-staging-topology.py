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
            "secretObjectsAllowed": False,
            "pvcObjectsAllowed": False,
            "rbacObjectsAllowed": False,
            "fluxObjectsAllowed": False,
        },
        "futureWorkloads": {
            "control": {
                "deploymentName": CONTROL,
                "serviceAccount": CONTROL,
                "automountServiceAccountToken": False,
                "image": blocked_image,
                "preexistingSecretRefs": ["roebel-case-steward-control-runtime"],
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
                "image": blocked_image,
                "preexistingSecretRefs": [],
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
            "the current Stadtstack runtime reference binds civic listeners to loopback and has no reviewed deployment bind adapter",
            "a separate protected policy-migration ceremony must add a reviewed application composition root before reconciliation",
        ],
    }


def expected_service_account(capability: str, component: str) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "automountServiceAccountToken": False,
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
    require(load_json(topology / "contract.json") == expected_contract(), "runtime gate contract drift")
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
