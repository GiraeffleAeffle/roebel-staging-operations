#!/usr/bin/env python3
"""Prepare a signed-Nostr staging activation preflight.

This module is intentionally an evidence planner, not an activation client.
It reads one explicit JSON observation document, reuses the protected
reviewed-render constructors, and emits deterministic canonical JSON.  It
never contacts GitHub, a registry, DNS, Kubernetes, Flux, or a Secret store;
it never writes manifests and it has no mutation mode.

The output is useful before the separately reviewed activation record exists:
it makes the exact sixteen-file candidate shape, twenty-four owned objects,
external Secret key prerequisites, blockers, and the required executor order
visible without turning observations into authority.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any


VERIFY_PATH = Path(__file__).with_name("verify-reviewed-render.py")
VERIFY_SPEC = importlib.util.spec_from_file_location("protected_reviewed_render", VERIFY_PATH)
if VERIFY_SPEC is None or VERIFY_SPEC.loader is None:  # pragma: no cover - import failure is environmental
    raise RuntimeError("protected reviewed-render verifier unavailable")
VERIFY = importlib.util.module_from_spec(VERIFY_SPEC)
VERIFY_SPEC.loader.exec_module(VERIFY)


SCHEMA = "roebel_signed_nostr_preflight_input_v1"
OUTPUT_SCHEMA = "roebel_signed_nostr_preflight_output_v1"
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
UUID = VERIFY.UUID

TOP_LEVEL_KEYS = {
    "schemaVersion",
    "publisherRuntimePin",
    "artifactObservations",
    "dnsTlsObservations",
    "gnosisRpcObservation",
    "boundaryObservations",
    "liveObservations",
    "externalSecretMetadata",
    "executor",
}
BOUNDARY_KEYS = {
    "integritySha256",
    "webIngressSha256",
    "publicMeckyNetworkPolicySha256",
    "boundaryReceiptSha256",
}
EXECUTOR_KEYS = {
    "available",
    "sequence",
    "mutationAllowed",
}
GNOSIS_KEYS = {
    "chainId",
    "upstreamHost",
    "upstreamPort",
    "pinnedIpv4Cidr",
    "allowedMethods",
    "privateProxyRequired",
}
SECRET_KEYS = {"name", "namespace", "keyNames"}
ARTIFACT_OBSERVATIONS_KEYS = {"components", "anonymousDigestPullReceipts"}
ARTIFACT_COMPONENT_KEYS = {
    "component",
    "imageRepository",
    "manifestDigest",
    "provenance",
    "sbomAttestation",
}
LIVE_KEYS = {
    "objectId",
    "target",
    "desiredObjectDigest",
    "state",
    "uid",
    "resourceVersion",
    "currentObjectDigest",
}

class PreflightError(RuntimeError):
    """Input is malformed and cannot safely be interpreted."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreflightError(message)


def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    require(path.is_file() and not path.is_symlink(), f"input is not a regular file: {path}")
    try:
        return json.loads(path.read_text(), object_pairs_hook=object_pairs)
    except json.JSONDecodeError as error:
        raise PreflightError(f"input JSON invalid: {error}") from error


def closed(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    require(set(value) == keys, f"{label} keys mismatch")
    return value


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def verify_digest(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA256.fullmatch(value), f"{label} must be a sha256 digest")
    return value


def expected_file_plan() -> list[dict[str, str]]:
    """Describe exactly the sixteen files, without materialising any file."""
    root = VERIFY.SIGNED_NOSTR_ROOT
    entries: list[tuple[str, str]] = [
        (VERIFY.SIGNED_NOSTR_RUNTIME_PIN, "runtime pin"),
    ]
    for component in VERIFY.SIGNED_NOSTR_COMPONENTS:
        for kind in ("deployment.json", "service.json", "networkpolicy.json", "kustomization.yaml"):
            entries.append((f"{root}/{component}/{kind}", f"{component} {kind.removesuffix('.json')}"))
        if component == "workbench":
            entries.extend([
                (f"{root}/workbench/gnosis-proxy-deployment.json", "Gnosis private proxy deployment"),
                (f"{root}/workbench/gnosis-proxy-service.json", "Gnosis private proxy service"),
                (f"{root}/workbench/gnosis-proxy-networkpolicy.json", "Gnosis private proxy network policy"),
            ])
    require(len(entries) == 16, "signed-Nostr candidate file policy unexpectedly changed")
    return [
        {
            "path": path,
            "purpose": purpose,
            "materialization": "candidate-only-after-separate-review",
        }
        for path, purpose in entries
    ]


def publisher_wrapper(publisher: Any, boundaries: dict[str, Any]) -> dict[str, Any]:
    """Validate a publisher pin through the protected verifier's pure policy."""
    require(isinstance(publisher, dict), "publisherRuntimePin must be an object")
    wrapper = {
        "schemaVersion": "roebel_signed_nostr_activation_render_pin_v1",
        "publisherPin": publisher,
        "publisherPinCanonicalSha256": digest(publisher),
        "activationEvidence": {
            "status": "pending-separate-review",
            "gnosisRpcEgress": None,
            "fluxIdentity": None,
            "anonymousDigestPullReceipts": None,
        },
        "rollback": {
            "fromRender": "reviewed-public-knowledge",
            "integritySha256": boundaries["integritySha256"],
            "webIngressSha256": boundaries["webIngressSha256"],
            "publicMeckyNetworkPolicySha256": boundaries["publicMeckyNetworkPolicySha256"],
            "boundaryReceiptSha256": boundaries["boundaryReceiptSha256"],
        },
    }
    try:
        return VERIFY.verify_signed_nostr_runtime_pin(wrapper)["publisherPin"]
    except (VERIFY.VerificationError, KeyError, TypeError) as error:
        raise PreflightError(f"publisher runtime pin drift: {error}") from error


def validate_boundaries(value: Any) -> dict[str, str]:
    boundaries = closed(value, BOUNDARY_KEYS, "boundaryObservations")
    return {key: verify_digest(boundaries[key], f"boundaryObservations.{key}") for key in sorted(BOUNDARY_KEYS)}


def validate_gnosis(value: Any, blockers: list[dict[str, str]]) -> dict[str, Any] | None:
    if value is None:
        blockers.append({
            "code": "gnosis-rpc-required",
            "detail": "Current signed-Nostr policy requires the private Gnosis proxy and its restricted egress; omission is not permitted.",
        })
        return None
    observation = closed(value, GNOSIS_KEYS, "gnosisRpcObservation")
    expected = {
        "chainId": 100,
        "upstreamHost": VERIFY.SIGNED_NOSTR_GNOSIS_UPSTREAM_HOST,
        "upstreamPort": VERIFY.SIGNED_NOSTR_GNOSIS_UPSTREAM_PORT,
        "pinnedIpv4Cidr": VERIFY.SIGNED_NOSTR_GNOSIS_UPSTREAM_IPV4_CIDR,
        "allowedMethods": list(VERIFY.SIGNED_NOSTR_GNOSIS_ALLOWED_METHODS),
        "privateProxyRequired": True,
    }
    if observation != expected:
        blockers.append({
            "code": "gnosis-rpc-policy-drift",
            "detail": "gnosisRpcObservation does not equal the protected chain, /32, method, and private-proxy policy.",
        })
    return observation


def validate_dns(value: Any, blockers: list[dict[str, str]]) -> list[dict[str, Any]]:
    require(isinstance(value, list), "dnsTlsObservations must be an array")
    parsed: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        try:
            parsed.append(VERIFY.verify_signed_nostr_dns_tls_evidence(item, f"dnsTlsObservations[{index}]"))
        except (VERIFY.VerificationError, KeyError, TypeError) as error:
            raise PreflightError(f"DNS/TLS observation invalid: {error}") from error
    if not parsed:
        blockers.append({
            "code": "dns-tls-observation-missing",
            "detail": "A fresh reviewed DNS/TLS observation for the pinned Gnosis upstream is required.",
        })
    return parsed


def validate_artifacts(
    value: Any,
    publisher: dict[str, Any],
    publisher_checksum: str,
    blockers: list[dict[str, str]],
) -> dict[str, Any]:
    observations = closed(value, ARTIFACT_OBSERVATIONS_KEYS, "artifactObservations")
    components = observations["components"]
    receipts = observations["anonymousDigestPullReceipts"]
    require(isinstance(components, list), "artifactObservations.components must be an array")
    require(isinstance(receipts, list), "artifactObservations.anonymousDigestPullReceipts must be an array")
    expected_components = publisher["components"]
    if len(components) != len(expected_components):
        blockers.append({
            "code": "artifact-observation-count",
            "detail": f"Expected {len(expected_components)} artifact observations in publisher order; received {len(components)}.",
        })
    for index, expected in enumerate(expected_components):
        if index >= len(components):
            blockers.append({
                "code": "artifact-observation-missing",
                "detail": f"Missing artifact observation for {expected['component']}.",
            })
            continue
        item = closed(components[index], ARTIFACT_COMPONENT_KEYS, f"artifactObservations.components[{index}]")
        expected_name = VERIFY.SIGNED_NOSTR_PUBLISHER_COMPONENT_ORDER[index]
        if item["component"] != expected_name:
            blockers.append({
                "code": "artifact-observation-order",
                "detail": f"Artifact observation {index} must be {expected_name}.",
            })
        if item["imageRepository"] != expected["image"] or item["manifestDigest"] != expected["manifestDigest"]:
            blockers.append({
                "code": "artifact-observation-drift",
                "detail": f"Artifact observation for {expected_name} does not match the publisher pin.",
            })
        for field, publisher_receipt in (("provenance", expected["provenance"]), ("sbomAttestation", expected["sbomAttestation"])):
            try:
                VERIFY.verify_signed_nostr_attestation_receipt(
                    item[field],
                    publisher_receipt,
                    expected["manifestDigest"],
                    f"artifactObservations.components[{index}].{field}",
                )
            except (VERIFY.VerificationError, KeyError, TypeError) as error:
                raise PreflightError(f"artifact observation invalid: {error}") from error

    if len(receipts) != 2:
        blockers.append({
            "code": "anonymous-resolution-observation-count",
            "detail": f"Expected two anonymous digest resolution observations; received {len(receipts)}.",
        })
    for index, expected_name in enumerate(VERIFY.SIGNED_NOSTR_PUBLISHER_COMPONENT_ORDER):
        if index >= len(receipts):
            blockers.append({
                "code": "anonymous-resolution-observation-missing",
                "detail": f"Missing anonymous digest resolution for {expected_name}.",
            })
    if len(receipts) == 2:
        try:
            VERIFY.verify_signed_nostr_anonymous_digest_pull_receipts(
                receipts,
                publisher,
                publisher_checksum,
            )
        except (VERIFY.VerificationError, KeyError, TypeError) as error:
            blockers.append({
                "code": "anonymous-resolution-observation-drift",
                "detail": str(error),
            })
    return {
        "components": components,
        "anonymousDigestPullReceipts": receipts,
    }


def expected_managed_objects(publisher: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        return VERIFY.expected_signed_nostr_managed_objects(publisher, suspended_flux=True)
    except (VERIFY.VerificationError, KeyError, TypeError) as error:
        raise PreflightError(f"managed object construction failed: {error}") from error


def validate_live(
    value: Any,
    managed: list[dict[str, Any]],
    blockers: list[dict[str, str]],
) -> list[dict[str, Any]]:
    require(isinstance(value, list), "liveObservations must be an array")
    parsed: list[dict[str, Any]] = []
    if len(value) != len(managed):
        blockers.append({
            "code": "live-observation-count",
            "detail": f"Expected exactly {len(managed)} live observations in policy order; received {len(value)}.",
        })
    for index, expected in enumerate(managed):
        if index >= len(value):
            blockers.append({
                "code": "live-observation-missing",
                "detail": f"Missing live observation for {expected['objectId']}.",
            })
            continue
        item = closed(value[index], LIVE_KEYS, f"liveObservations[{index}]")
        target = VERIFY.signed_nostr_object_target(expected["object"])
        if item["objectId"] != expected["objectId"] or item["target"] != target:
            blockers.append({
                "code": "live-observation-target-drift",
                "detail": f"Live observation {index} does not target {expected['objectId']} exactly.",
            })
        expected_digest = digest(expected["object"])
        if item["desiredObjectDigest"] != expected_digest:
            blockers.append({
                "code": "live-observation-desired-digest-drift",
                "detail": f"Live observation {expected['objectId']} desired digest differs from the generated object.",
            })
        state = item["state"]
        if state == "absent":
            if any(item[field] is not None for field in ("uid", "resourceVersion", "currentObjectDigest")):
                raise PreflightError(f"liveObservations[{index}] absent observation contains live identity")
        elif state == "present-exact":
            require(isinstance(item["uid"], str) and UUID.fullmatch(item["uid"]), f"liveObservations[{index}] UID invalid")
            require(isinstance(item["resourceVersion"], str) and item["resourceVersion"].isdigit(), f"liveObservations[{index}] resourceVersion invalid")
            if item["currentObjectDigest"] != expected_digest:
                blockers.append({
                    "code": "live-object-drift",
                    "detail": f"Present live object {expected['objectId']} is not byte-exact and cannot be adopted.",
                })
        else:
            raise PreflightError(f"liveObservations[{index}] state invalid")
        parsed.append(item)
    return parsed


def secret_references(managed: list[dict[str, Any]]) -> list[dict[str, Any]]:
    refs: dict[tuple[str, str, str], None] = {}

    def walk(value: Any, namespace: str) -> None:
        if isinstance(value, dict):
            secret_ref = value.get("secretKeyRef")
            if isinstance(secret_ref, dict):
                name = secret_ref.get("name")
                key = secret_ref.get("key")
                if isinstance(name, str) and isinstance(key, str):
                    refs[(namespace, name, key)] = None
            for child in value.values():
                walk(child, namespace)
        elif isinstance(value, list):
            for child in value:
                walk(child, namespace)

    for entry in managed:
        obj = entry["object"]
        walk(obj, obj["metadata"]["namespace"])
    grouped: dict[tuple[str, str], set[str]] = {}
    for namespace, name, key in refs:
        grouped.setdefault((namespace, name), set()).add(key)
    return [
        {"namespace": namespace, "name": name, "keyNames": sorted(keys)}
        for (namespace, name), keys in sorted(grouped.items())
    ]


def validate_secret_metadata(value: Any, required: list[dict[str, Any]], blockers: list[dict[str, str]]) -> list[dict[str, Any]]:
    # A single metadata record is accepted as a convenience, but the output
    # still reports the missing namespace when the same Secret must exist in
    # both runtime namespaces.
    if isinstance(value, dict):
        value = [value]
    require(isinstance(value, list), "externalSecretMetadata must be an array or metadata object")
    parsed: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        metadata = closed(item, SECRET_KEYS, f"externalSecretMetadata[{index}]")
        require(isinstance(metadata["name"], str) and metadata["name"], f"externalSecretMetadata[{index}].name invalid")
        require(isinstance(metadata["namespace"], str) and metadata["namespace"], f"externalSecretMetadata[{index}].namespace invalid")
        keys = metadata["keyNames"]
        require(isinstance(keys, list) and all(isinstance(key, str) and key for key in keys), f"externalSecretMetadata[{index}].keyNames invalid")
        require(len(keys) == len(set(keys)), f"externalSecretMetadata[{index}].keyNames repeated")
        parsed.append({"name": metadata["name"], "namespace": metadata["namespace"], "keyNames": sorted(keys)})
    actual = {(item["namespace"], item["name"]): set(item["keyNames"]) for item in parsed}
    expected = {(item["namespace"], item["name"]): set(item["keyNames"]) for item in required}
    if actual != expected:
        blockers.append({
            "code": "external-secret-key-shape",
            "detail": "External Secret metadata must contain exactly the namespace/name/key-name sets referenced by the generated objects; values are never accepted.",
        })
    return sorted(parsed, key=lambda item: (item["namespace"], item["name"]))


def validate_executor(value: Any, blockers: list[dict[str, str]]) -> dict[str, Any] | None:
    if value is None:
        blockers.append({
            "code": "executor-sequencing-missing",
            "detail": "No executor receipt is supplied. The four lifecycle steps cannot be claimed as one ordered operation; this tool remains descriptive and dry-run only.",
        })
        return None
    executor = closed(value, EXECUTOR_KEYS, "executor")
    require(isinstance(executor["available"], bool), "executor.available must be boolean")
    require(isinstance(executor["mutationAllowed"], bool), "executor.mutationAllowed must be boolean")
    sequence = executor["sequence"]
    expected_sequence = ["atomic-post-no-op-bootstrap", "live-recheck", "cas-unsuspend", "rollback"]
    require(isinstance(sequence, list) and all(isinstance(step, str) for step in sequence), "executor.sequence invalid")
    if sequence != expected_sequence:
        blockers.append({
            "code": "executor-sequence-paradox",
            "detail": "Executor sequence must be atomic POST/no-op/bootstrap, live recheck, CAS unsuspend, rollback.",
        })
    if executor["mutationAllowed"]:
        blockers.append({
            "code": "mutation-mode-forbidden",
            "detail": "This preparation tool never accepts mutation authorization; executor mutationAllowed must be false.",
        })
    if not executor["available"]:
        blockers.append({
            "code": "executor-unavailable",
            "detail": "No external executor is available for the required lifecycle sequence.",
        })
    return {"available": executor["available"], "mutationAllowed": executor["mutationAllowed"], "sequence": sequence}


def command_plan() -> dict[str, Any]:
    """Return a descriptive plan; every step explicitly has no local effect."""
    return {
        "mode": "description-only",
        "mutation": False,
        "steps": [
            {
                "id": "atomic-post-no-op-bootstrap",
                "order": 1,
                "api": "Kubernetes API POST create per absent target; explicit no-op for present-exact target",
                "guard": "HTTP 409, UID mismatch, resourceVersion mismatch, or digest drift is a hard stop",
                "effect": "not executed by this tool",
            },
            {
                "id": "live-recheck",
                "order": 2,
                "api": "read the same 24 exact targets and the four boundary byte digests",
                "guard": "fresh DNS/TLS evidence and exact object ownership must still match",
                "effect": "not executed by this tool",
            },
            {
                "id": "cas-unsuspend",
                "order": 3,
                "api": "UID/resourceVersion compare-and-swap patch of /spec/suspend true to false on three Flux Kustomizations",
                "guard": "only after live-recheck and within the five-minute preflight window",
                "effect": "not executed by this tool",
            },
            {
                "id": "rollback",
                "order": 4,
                "api": "suspend exact reconcilers, restore four boundary bytes, scale down then delete exact owned UIDs, prove absence",
                "guard": "UID mismatch stops before delete; no prune or implicit teardown",
                "effect": "not executed by this tool",
            },
        ],
    }


def build_preflight(value: Any) -> dict[str, Any]:
    """Validate observations and build a deterministic, non-authorizing plan."""
    top = closed(value, TOP_LEVEL_KEYS, "preflight input")
    require(top["schemaVersion"] == SCHEMA, "preflight input schema invalid")
    blockers: list[dict[str, str]] = []
    boundaries = validate_boundaries(top["boundaryObservations"])
    publisher = publisher_wrapper(top["publisherRuntimePin"], boundaries)
    publisher_checksum = digest(publisher)
    gnosis = validate_gnosis(top["gnosisRpcObservation"], blockers)
    artifacts = validate_artifacts(top["artifactObservations"], publisher, publisher_checksum, blockers)
    dns = validate_dns(top["dnsTlsObservations"], blockers)
    managed = expected_managed_objects(publisher)
    live = validate_live(top["liveObservations"], managed, blockers)
    required_secrets = secret_references(managed)
    secrets = validate_secret_metadata(top["externalSecretMetadata"], required_secrets, blockers)
    executor = validate_executor(top["executor"], blockers)

    # The protected policy deliberately has no approved activation record yet.
    # A complete observation set therefore remains preparation-only even if no
    # local observation blocker is present.
    if VERIFY.SIGNED_NOSTR_APPROVED_ACTIVATION_EVIDENCE is None:
        blockers.append({
            "code": "protected-activation-approval-pending",
            "detail": "The protected signed-Nostr activation constant is None; this plan cannot authorize a render or reconciliation.",
        })

    inventory = []
    for entry in managed:
        inventory.append({
            "objectId": entry["objectId"],
            "class": entry["class"],
            "target": VERIFY.signed_nostr_object_target(entry["object"]),
            "object": entry["object"],
            "objectDigest": digest(entry["object"]),
            "fluxSuspended": entry["objectId"].startswith("flux/"),
        })
    blockers = sorted(blockers, key=lambda item: (item["code"], item["detail"]))
    return {
        "schemaVersion": OUTPUT_SCHEMA,
        "status": "blocked" if blockers else "prepared-but-not-authorized",
        "activationAuthorized": False,
        "effects": {
            "network": False,
            "registry": False,
            "dns": False,
            "kubernetes": False,
            "flux": False,
            "secretRead": False,
            "secretWrite": False,
            "manifestWrite": False,
        },
        "candidatePlan": {
            "renderRoot": VERIFY.SIGNED_NOSTR_ROOT,
            "fileCount": 16,
            "files": expected_file_plan(),
            "mutableExistingFiles": sorted(VERIFY.SIGNED_NOSTR_MUTABLE_EXISTING_FILES),
        },
        "managedObjectInventory": inventory,
        "publisher": {
            "schemaVersion": publisher["schemaVersion"],
            "sourceRevision": publisher["sourceRevision"],
            "canonicalSha256": publisher_checksum,
            "components": [
                {"component": item["component"], "image": item["image"], "manifestDigest": item["manifestDigest"]}
                for item in publisher["components"]
            ],
        },
        "observations": {
            "artifact": artifacts,
            "dnsTls": dns,
            "gnosisRpc": gnosis,
            "boundary": boundaries,
            "live": live,
            "externalSecretMetadata": secrets,
            "executor": executor,
        },
        "externalSecretPrerequisite": {
            "required": required_secrets,
            "valuesAccepted": False,
            "valuesRead": False,
        },
        "blockers": blockers,
        "commandPlan": command_plan(),
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="explicit JSON observation document")
    parser.add_argument("--output", type=Path, help="optional local output file; no cluster or registry write")
    parser.add_argument("--execute", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.execute:
        print("preflight has no executable mutation mode", file=sys.stderr)
        return 2
    try:
        result = build_preflight(load_json(args.input))
        output = canonical_json(result)
        if args.output is not None:
            args.output.write_bytes(output)
        else:
            sys.stdout.buffer.write(output)
        return 0 if result["status"] != "blocked" else 2
    except (OSError, PreflightError, VERIFY.VerificationError, KeyError, TypeError) as error:
        print(f"signed-Nostr preflight failed closed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
