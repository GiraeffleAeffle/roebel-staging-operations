#!/usr/bin/env python3
"""Render one immutable Röbel Release Set into the protected Flux tree.

This module is effect-free. It accepts the publisher's value-free candidate
and evidence bundle, compares the complete previous head, and changes only the
five admitted Deployment fields. It never contacts GitHub or Kubernetes.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
COMPONENT_ORDER = ("public-mecky", "roebel-web-staging")
POLICY = {
    "public-mecky": {
        "directory": "public-mecky",
        "repository": "ghcr.io/giraeffleaeffle/public-mecky",
        "container": "public-mecky",
        "namespace": "stadtstack-roebel-staging-lab",
        "name": "public-mecky",
    },
    "roebel-web-staging": {
        "directory": "web",
        "repository": "ghcr.io/giraeffleaeffle/roebel-web-staging",
        "container": "web",
        "namespace": "stadtstack-roebel-web-preview",
        "name": "roebel-web-presentation",
    },
}
SIGNER = "https://github.com/GiraeffleAeffle/Roebel-App/.github/workflows/roebel-staging-publish.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
RENDER_ROOT = Path("reviewed-render/roebel-staging")


class PromotionError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PromotionError(message)


def pairs(pairs_value: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs_value:
        require(key not in result, f"duplicate key: {key}")
        result[key] = value
    return result


def load(path: Path) -> Any:
    require(path.is_file() and not path.is_symlink(), f"input is not a regular file: {path}")
    return json.loads(path.read_text(), object_pairs_hook=pairs)


def read_text(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), f"input is not a regular file: {path}")
    return path.read_text()


def closed(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == expected, f"{label} shape invalid")
    return value


def canonical_candidate_payload(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode()


def canonical_render(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, prefix=f".{path.name}.", delete=False) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = Path(output.name)
    os.replace(temporary, path)


def validate_head(value: Any, label: str) -> dict[str, Any]:
    head = closed(value, {"schemaVersion", "promotionRevision", "releaseSetDigest", "components"}, label)
    require(head["schemaVersion"] == "roebel_staging_release_set_head_v1", f"{label} schema invalid")
    require(isinstance(head["promotionRevision"], str) and REVISION.fullmatch(head["promotionRevision"]), f"{label} revision invalid")
    require(isinstance(head["releaseSetDigest"], str) and DIGEST.fullmatch(head["releaseSetDigest"]), f"{label} digest invalid")
    require(isinstance(head["components"], list) and len(head["components"]) == 2, f"{label} components invalid")
    for index, component_name in enumerate(COMPONENT_ORDER):
        component = closed(head["components"][index], {"component", "sourceRevision", "manifestDigest"}, f"{label} component")
        require(component["component"] == component_name, f"{label} component order invalid")
        require(isinstance(component["sourceRevision"], str) and REVISION.fullmatch(component["sourceRevision"]), f"{label} component revision invalid")
        require(isinstance(component["manifestDigest"], str) and DIGEST.fullmatch(component["manifestDigest"]), f"{label} component digest invalid")
    return head


def validate_candidate(value: Any, current_head: dict[str, Any]) -> dict[str, Any]:
    candidate = closed(
        value,
        {"schemaVersion", "promotionRevision", "expectedPreviousHead", "components", "candidatePayloadDigest"},
        "candidate",
    )
    require(candidate["schemaVersion"] == "roebel_staging_release_set_candidate_v1", "candidate schema invalid")
    require(isinstance(candidate["promotionRevision"], str) and REVISION.fullmatch(candidate["promotionRevision"]), "candidate revision invalid")
    expected_head = validate_head(
        {"schemaVersion": "roebel_staging_release_set_head_v1", **candidate["expectedPreviousHead"]},
        "expected previous head",
    )
    require(expected_head == current_head, "candidate previous head is stale")
    require(isinstance(candidate["components"], list) and len(candidate["components"]) == 2, "candidate components invalid")
    previous_components = {
        component["component"]: component for component in expected_head["components"]
    }

    for index, component_name in enumerate(COMPONENT_ORDER):
        component = closed(
            candidate["components"][index],
            {"component", "sourceRevision", "manifestDigest", "configDigest", "layerDigests", "provenance", "sbom"},
            f"candidate {component_name}",
        )
        require(component["component"] == component_name, "candidate component order invalid")
        require(isinstance(component["sourceRevision"], str) and REVISION.fullmatch(component["sourceRevision"]), "component revision invalid")
        for field in ("manifestDigest", "configDigest"):
            require(isinstance(component[field], str) and DIGEST.fullmatch(component[field]), f"component {field} invalid")
        require(isinstance(component["layerDigests"], list) and component["layerDigests"], "component layers invalid")
        require(all(isinstance(item, str) and DIGEST.fullmatch(item) for item in component["layerDigests"]), "component layer digest invalid")
        provenance = closed(component["provenance"], {"issuer", "identity", "predicateType", "attestationDigest"}, "candidate provenance")
        require(provenance["issuer"] == ISSUER and provenance["identity"] == SIGNER, "candidate provenance identity invalid")
        require(provenance["predicateType"] == "https://slsa.dev/provenance/v1", "candidate provenance type invalid")
        require(isinstance(provenance["attestationDigest"], str) and DIGEST.fullmatch(provenance["attestationDigest"]), "candidate attestation digest invalid")
        sbom = closed(component["sbom"], {"format", "identity", "artifactDigest"}, "candidate sbom")
        require(sbom["format"] == "SPDX-2.3" and sbom["identity"] == "https://spdx.dev/spdx/v2.3", "candidate sbom identity invalid")
        require(isinstance(sbom["artifactDigest"], str) and DIGEST.fullmatch(sbom["artifactDigest"]), "candidate sbom digest invalid")

        # A release-set can reuse an unchanged component, but only from the
        # complete head that this candidate compare-and-swaps.  This permits
        # affected-component publishing without turning the handoff into a
        # historical image-selection mechanism.
        previous = previous_components[component_name]
        if component["sourceRevision"] != candidate["promotionRevision"]:
            require(
                component["sourceRevision"] == previous["sourceRevision"]
                and component["manifestDigest"] == previous["manifestDigest"],
                f"{component_name} non-promotion component must exactly reuse the expected previous head",
            )

    payload = {
        "schemaVersion": candidate["schemaVersion"],
        "promotionRevision": candidate["promotionRevision"],
        "expectedPreviousHead": candidate["expectedPreviousHead"],
        "components": candidate["components"],
    }
    require(candidate["candidatePayloadDigest"] == digest_bytes(canonical_candidate_payload(payload)), "candidate payload digest invalid")
    require(any(item["sourceRevision"] == candidate["promotionRevision"] for item in candidate["components"]), "candidate is a no-op")
    return candidate


def validate_evidence(candidate: dict[str, Any], evidence_root: Path) -> None:
    for component in candidate["components"]:
        name = component["component"]
        evidence = closed(
            load(evidence_root / "evidence" / f"{name}.component-evidence.json"),
            {"schemaVersion", "component", "sourceRevision", "manifestDigest", "provenance", "sbom"},
            f"{name} evidence",
        )
        require(evidence["schemaVersion"] == "roebel_staging_component_evidence_v1", "evidence schema invalid")
        require(evidence["component"] == name and evidence["sourceRevision"] == component["sourceRevision"], "evidence component binding invalid")
        require(evidence["manifestDigest"] == component["manifestDigest"], "evidence manifest binding invalid")
        provenance = closed(evidence["provenance"], {"issuer", "identity", "predicateType", "subjectDigest", "attestationDigest"}, "evidence provenance")
        require(provenance["issuer"] == ISSUER and provenance["identity"] == SIGNER, "evidence provenance identity invalid")
        require(provenance["predicateType"] == "https://slsa.dev/provenance/v1", "evidence provenance type invalid")
        require(provenance["subjectDigest"] == component["manifestDigest"], "evidence provenance subject invalid")
        require(provenance["attestationDigest"] == component["provenance"]["attestationDigest"], "evidence provenance digest invalid")
        bundle = evidence_root / "bundles" / "provenance" / name / f"sha256-{component['manifestDigest'].removeprefix('sha256:')}.jsonl"
        require(bundle.is_file() and not bundle.is_symlink(), "provenance bundle missing")
        require(digest_bytes(bundle.read_bytes()) == provenance["attestationDigest"], "provenance bundle checksum invalid")
        sbom = closed(evidence["sbom"], {"format", "identity", "subjectDigest", "artifactDigest"}, "evidence sbom")
        require(sbom["format"] == "SPDX-2.3" and sbom["identity"] == "https://spdx.dev/spdx/v2.3", "evidence sbom identity invalid")
        require(sbom["subjectDigest"] == component["manifestDigest"], "evidence sbom subject invalid")
        require(sbom["artifactDigest"] == component["sbom"]["artifactDigest"], "evidence sbom digest invalid")
        sbom_bundle = evidence_root / "bundles" / "sbom" / name / f"sha256-{component['manifestDigest'].removeprefix('sha256:')}.jsonl"
        require(sbom_bundle.is_file() and not sbom_bundle.is_symlink() and sbom_bundle.stat().st_size > 0, "sbom bundle missing")


def primary_container(deployment: dict[str, Any], component: str) -> dict[str, Any]:
    containers = deployment["spec"]["template"]["spec"]["containers"]
    found = [item for item in containers if item.get("name") == POLICY[component]["container"]]
    require(len(found) == 1, f"{component} primary container invalid")
    return found[0]


def render(root: Path, candidate_path: Path, evidence_root: Path) -> dict[str, Any]:
    render_root = root / RENDER_ROOT
    current_head = validate_head(load(render_root / "head.json"), "current head")
    candidate = validate_candidate(load(candidate_path), current_head)
    validate_evidence(candidate, evidence_root)
    by_component = {item["component"]: item for item in candidate["components"]}
    next_head = {
        "components": [
            {
                "component": name,
                "manifestDigest": by_component[name]["manifestDigest"],
                "sourceRevision": by_component[name]["sourceRevision"],
            }
            for name in COMPONENT_ORDER
        ],
        "promotionRevision": candidate["promotionRevision"],
        "releaseSetDigest": candidate["candidatePayloadDigest"],
        "schemaVersion": "roebel_staging_release_set_head_v1",
    }

    desired_deployments: list[dict[str, Any]] = []
    previous_preconditions = load(render_root / "live-preconditions.json")["requiredLivePreconditions"]
    preconditions: list[dict[str, Any]] = []
    patches: list[dict[str, Any]] = []
    for index, name in enumerate(COMPONENT_ORDER):
        policy = POLICY[name]
        deployment_path = render_root / policy["directory"] / "deployment.json"
        deployment = copy.deepcopy(load(deployment_path))
        current_image = primary_container(deployment, name)["image"]
        record = by_component[name]
        deployment.setdefault("metadata", {}).setdefault("annotations", {})["stadtstack.io/source-revision"] = record["sourceRevision"]
        deployment["metadata"]["annotations"]["stadtstack.io/release-set-sha256"] = next_head["releaseSetDigest"]
        deployment["spec"]["template"].setdefault("metadata", {}).setdefault("annotations", {})["stadtstack.io/source-revision"] = record["sourceRevision"]
        container = primary_container(deployment, name)
        container["image"] = f"{policy['repository']}@{record['manifestDigest']}"
        container["imagePullPolicy"] = "IfNotPresent"
        desired_deployments.append(deployment)
        precondition = copy.deepcopy(previous_preconditions[index])
        require(precondition["component"] == name, "base precondition order invalid")
        precondition["currentImage"] = current_image
        preconditions.append(precondition)
        target = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "name": policy["name"],
            "namespace": policy["namespace"],
        }
        patches.append(
            {
                "component": name,
                "operations": [
                    {"op": "add", "path": "/metadata/annotations/stadtstack.io~1source-revision", "value": record["sourceRevision"]},
                    {"op": "add", "path": "/metadata/annotations/stadtstack.io~1release-set-sha256", "value": next_head["releaseSetDigest"]},
                    {"op": "replace", "path": "/spec/template/metadata/annotations/stadtstack.io~1source-revision", "value": record["sourceRevision"]},
                    {"op": "replace", "path": "/spec/template/spec/containers/0/image", "value": container["image"]},
                    {"op": "replace", "path": "/spec/template/spec/containers/0/imagePullPolicy", "value": "IfNotPresent"},
                ],
                "target": target,
            }
        )

    desired_objects = [
        desired_deployments[0],
        load(render_root / "public-mecky/service.json"),
        load(render_root / "public-mecky/networkpolicy.json"),
        desired_deployments[1],
        load(render_root / "web/networkpolicy.json"),
        load(render_root / "web/ingress.json"),
    ]
    network_boundary_migration = load(
        render_root / "network-boundary-migration.json"
    )
    checksum_payload: dict[str, Any] = {
        "nextEnvironmentHead": next_head,
        "objects": desired_objects,
    }
    reviewed_knowledge_root = render_root / "reviewed-public-knowledge"
    if reviewed_knowledge_root.is_dir() and not reviewed_knowledge_root.is_symlink():
        checksum_payload["reviewedPublicKnowledge"] = {
            "deployment": load(reviewed_knowledge_root / "deployment.json"),
            "service": load(reviewed_knowledge_root / "service.json"),
            "networkPolicy": load(reviewed_knowledge_root / "networkpolicy.json"),
            "kustomization": read_text(reviewed_knowledge_root / "kustomization.yaml"),
            "runtimePin": load(reviewed_knowledge_root / "runtime-pin.json"),
        }
    integrity = {
        "desiredRenderSha256": digest_bytes(canonical_render(checksum_payload)),
        "networkBoundaryMigrationSha256": digest_bytes(
            canonical_render(network_boundary_migration)
        ),
        "releaseSetDigest": next_head["releaseSetDigest"],
        "schemaVersion": "roebel_staging_reviewed_render_v1",
    }
    live = {
        "patches": patches,
        "previousEnvironmentHead": current_head,
        "requiredLivePreconditions": preconditions,
    }
    write_json(render_root / "head.json", next_head)
    write_json(render_root / "integrity.json", integrity)
    write_json(render_root / "live-preconditions.json", live)
    for index, name in enumerate(COMPONENT_ORDER):
        write_json(render_root / POLICY[name]["directory"] / "deployment.json", desired_deployments[index])
    return {
        "schemaVersion": "roebel_staging_automatic_promotion_render_v1",
        "status": "rendered_effect_free",
        "promotionRevision": next_head["promotionRevision"],
        "releaseSetDigest": next_head["releaseSetDigest"],
        "changedComponents": [
            name
            for name in COMPONENT_ORDER
            if next_head["components"][COMPONENT_ORDER.index(name)]
            != current_head["components"][COMPONENT_ORDER.index(name)]
        ],
        "effects": {"clusterMutation": False, "secretRead": False, "civicMutation": False},
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = render(args.root.resolve(), args.candidate.resolve(), args.evidence_root.resolve())
    except (OSError, KeyError, IndexError, TypeError, json.JSONDecodeError, PromotionError) as error:
        print(f"automatic promotion render failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
