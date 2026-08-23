#!/usr/bin/env python3
"""Fail closed over inert Röbel Case staging topology contracts.

This verifier deliberately validates static contracts only.  It does not
render, bind, apply, or connect Kubernetes resources.  A later, separately
reviewed application composition root must supply workloads, explicit network
allows, identity wiring, storage, and any live listener.
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
CAPABILITIES = (
    ("roebel-case-steward-control", "case-steward-control", 18085),
    ("roebel-case-public-binding", "case-public-binding", 18086),
)
EXPECTED_FILES = {
    "contract.json",
    *{
        name
        for capability, _component, _port in CAPABILITIES
        for name in (
            f"{capability}-serviceaccount.json",
            f"{capability}-service.json",
            f"{capability}-default-deny-networkpolicy.json",
        )
    },
}
ALLOWED_KINDS = ["NetworkPolicy", "Service", "ServiceAccount"]


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


def expected_contract() -> dict[str, Any]:
    return {
        "schemaVersion": "roebel_case_staging_topology_foundation_v1",
        "mode": "inert_review_only",
        "namespace": NAMESPACE,
        "applicationCompositionRequired": True,
        "capabilities": [
            {
                "name": capability,
                "serviceAccount": capability,
                "service": capability,
                "defaultDenyNetworkPolicy": f"{capability}-default-deny",
            }
            for capability, _component, _port in CAPABILITIES
        ],
        "allowedKinds": ALLOWED_KINDS,
        "otherKindsAllowed": False,
        "invariants": {
            "automountServiceAccountToken": False,
            "clusterMutation": False,
            "credentialsAllowed": False,
            "liveBindAllowed": False,
            "publicSQLiteMountAllowed": False,
            "serviceExposure": "ClusterIP_only",
            "workloadDefinitionAllowed": False,
        },
    }


def expected_service_account(capability: str, component: str) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "automountServiceAccountToken": False,
        "metadata": {"labels": labels(component), "name": capability, "namespace": NAMESPACE},
    }


def expected_service(capability: str, component: str, port: int) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"labels": labels(component), "name": capability, "namespace": NAMESPACE},
        "spec": {
            "ports": [{"name": "http", "port": port, "protocol": "TCP", "targetPort": port}],
            "selector": selector(component),
            "type": "ClusterIP",
        },
    }


def expected_default_deny(capability: str, component: str) -> dict[str, Any]:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "labels": labels(component),
            "name": f"{capability}-default-deny",
            "namespace": NAMESPACE,
        },
        "spec": {"podSelector": {"matchLabels": selector(component)}, "policyTypes": ["Ingress", "Egress"]},
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
    require(load_json(topology / "contract.json") == expected_contract(), "topology contract drift")

    seen_names: set[str] = set()
    for capability, component, port in CAPABILITIES:
        service_account = load_json(topology / f"{capability}-serviceaccount.json")
        service = load_json(topology / f"{capability}-service.json")
        default_deny = load_json(topology / f"{capability}-default-deny-networkpolicy.json")
        require(service_account == expected_service_account(capability, component), f"{capability} ServiceAccount drift")
        require(service == expected_service(capability, component, port), f"{capability} Service drift")
        require(default_deny == expected_default_deny(capability, component), f"{capability} default-deny NetworkPolicy drift")
        for resource in (service_account, service, default_deny):
            name = resource["metadata"]["name"]
            require(name not in seen_names or name == capability, f"topology resource identity overlap: {name}")
            seen_names.add(name)

    return {
        "schemaVersion": "roebel_case_staging_topology_verification_v1",
        "status": "passed",
        "mode": "inert_review_only",
        "namespace": NAMESPACE,
        "capabilities": [capability for capability, _component, _port in CAPABILITIES],
        "effects": {
            "clusterMutation": False,
            "credentialRead": False,
            "credentialWrite": False,
            "liveBind": False,
            "publicStorageMount": False,
            "workloadDefinition": False,
        },
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
