#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "signed_nostr_preflight",
    ROOT / "scripts/prepare-signed-nostr-preflight.py",
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SignedNostrPreflightTests(unittest.TestCase):
    def publisher(self) -> dict[str, object]:
        return {
            "schemaVersion": "roebel_e2e_runtime_pin_v1",
            "sourceRevision": "b" * 40,
            "civicAuthority": "none",
            "deploymentEffect": False,
            "components": [
                {
                    "component": "roebel-e2e-workbench",
                    "image": "ghcr.io/giraeffleaeffle/roebel-e2e-workbench",
                    "manifestDigest": "sha256:" + "c" * 64,
                    "provenance": {"id": "workbench-provenance", "url": "https://github.com/GiraeffleAeffle/Roebel-App/attestations/1"},
                    "sbomAttestation": {"id": "workbench-sbom", "url": "https://github.com/GiraeffleAeffle/Roebel-App/attestations/2"},
                    "workflowIdentity": MODULE.VERIFY.SIGNED_NOSTR_WORKFLOW,
                },
                {
                    "component": "roebel-staging-relay",
                    "image": "ghcr.io/giraeffleaeffle/roebel-staging-relay",
                    "manifestDigest": "sha256:" + "d" * 64,
                    "provenance": {"id": "relay-provenance", "url": "https://github.com/GiraeffleAeffle/Roebel-App/attestations/3"},
                    "sbomAttestation": {"id": "relay-sbom", "url": "https://github.com/GiraeffleAeffle/Roebel-App/attestations/4"},
                    "workflowIdentity": MODULE.VERIFY.SIGNED_NOSTR_WORKFLOW,
                },
            ],
        }

    def dns(self) -> dict[str, object]:
        return {
            "schemaVersion": MODULE.VERIFY.SIGNED_NOSTR_DNS_TLS_EVIDENCE_SCHEMA,
            "canonicalEncoding": "canonical-json",
            "resolverIdentity": "reviewed-doh-resolver",
            "resolutionMethod": "dns-over-https-a-and-aaaa",
            "queriedHost": MODULE.VERIFY.SIGNED_NOSTR_GNOSIS_UPSTREAM_HOST,
            "queriedPort": MODULE.VERIFY.SIGNED_NOSTR_GNOSIS_UPSTREAM_PORT,
            "observedAt": "2026-08-24T12:00:00Z",
            "validUntil": "2026-08-24T12:05:00Z",
            "maxAgeSeconds": 300,
            "addresses": {"a": ["34.111.230.52"], "aaaa": []},
            "tlsCertificate": {
                "serverName": MODULE.VERIFY.SIGNED_NOSTR_GNOSIS_UPSTREAM_HOST,
                "issuer": "reviewed-test-ca",
                "certificateSha256": "sha256:" + "e" * 64,
                "notBefore": "2026-08-01T00:00:00Z",
                "notAfter": "2026-11-01T00:00:00Z",
            },
        }

    def artifact_observations(self, publisher: dict[str, object]) -> dict[str, object]:
        components = []
        for index, item in enumerate(publisher["components"]):
            marker = chr(ord("a") + index)
            components.append({
                "component": item["component"],
                "imageRepository": item["image"],
                "manifestDigest": item["manifestDigest"],
                "provenance": {
                    "receiptId": item["provenance"]["id"],
                    "receiptUrl": item["provenance"]["url"],
                    "attestationDigest": "sha256:" + marker * 64,
                    "subjectDigest": item["manifestDigest"],
                },
                "sbomAttestation": {
                    "receiptId": item["sbomAttestation"]["id"],
                    "receiptUrl": item["sbomAttestation"]["url"],
                    "attestationDigest": "sha256:" + chr(ord("c") + index) * 64,
                    "subjectDigest": item["manifestDigest"],
                },
            })
        checksum = MODULE.digest(publisher)
        receipts = []
        for item in publisher["components"]:
            receipt = {
                "schemaVersion": MODULE.VERIFY.SIGNED_NOSTR_ANONYMOUS_DIGEST_PULL_RECEIPT_SCHEMA,
                "canonicalEncoding": "canonical-json",
                "publisherPinCanonicalSha256": checksum,
                "component": item["component"],
                "imageRepository": item["image"],
                "manifestDigest": item["manifestDigest"],
                "sourceRevision": publisher["sourceRevision"],
                "authContext": "clean-empty-auth-config",
                "authConfigCanonicalSha256": MODULE.VERIFY.SIGNED_NOSTR_CLEAN_EMPTY_AUTH_CONFIG_SHA256,
                "resolverIdentity": "oras-resolve-anonymous",
                "resolvedManifestDigest": item["manifestDigest"],
            }
            receipt["receiptDigest"] = MODULE.digest(receipt)
            receipts.append(receipt)
        return {"components": components, "anonymousDigestPullReceipts": receipts}

    def base_input(self) -> dict[str, object]:
        publisher = self.publisher()
        boundaries = {
            "integritySha256": "sha256:" + "1" * 64,
            "webIngressSha256": "sha256:" + "2" * 64,
            "publicMeckyNetworkPolicySha256": "sha256:" + "3" * 64,
            "boundaryReceiptSha256": "sha256:" + "4" * 64,
        }
        managed = MODULE.expected_managed_objects(publisher)
        live = [
            {
                "objectId": entry["objectId"],
                "target": MODULE.VERIFY.signed_nostr_object_target(entry["object"]),
                "desiredObjectDigest": MODULE.digest(entry["object"]),
                "state": "absent",
                "uid": None,
                "resourceVersion": None,
                "currentObjectDigest": None,
            }
            for entry in managed
        ]
        return {
            "schemaVersion": MODULE.SCHEMA,
            "publisherRuntimePin": publisher,
            "artifactObservations": self.artifact_observations(publisher),
            "dnsTlsObservations": [self.dns()],
            "gnosisRpcObservation": {
                "chainId": 100,
                "upstreamHost": MODULE.VERIFY.SIGNED_NOSTR_GNOSIS_UPSTREAM_HOST,
                "upstreamPort": MODULE.VERIFY.SIGNED_NOSTR_GNOSIS_UPSTREAM_PORT,
                "pinnedIpv4Cidr": MODULE.VERIFY.SIGNED_NOSTR_GNOSIS_UPSTREAM_IPV4_CIDR,
                "allowedMethods": list(MODULE.VERIFY.SIGNED_NOSTR_GNOSIS_ALLOWED_METHODS),
                "privateProxyRequired": True,
            },
            "boundaryObservations": boundaries,
            "liveObservations": live,
            "externalSecretMetadata": MODULE.secret_references(managed),
            "executor": None,
        }

    def test_secret_prerequisite_is_explicit_and_value_free(self) -> None:
        result = MODULE.build_preflight(self.base_input())
        self.assertEqual(result["externalSecretPrerequisite"]["valuesAccepted"], False)
        self.assertEqual(result["externalSecretPrerequisite"]["valuesRead"], False)
        self.assertEqual(len(result["externalSecretPrerequisite"]["required"]), 2)
        self.assertTrue(any(item["code"] == "executor-sequencing-missing" for item in result["blockers"]))
        encoded = json.dumps(result, sort_keys=True)
        self.assertNotIn("PRIVATE KEY", encoded)
        self.assertNotIn("secretValue", encoded)

    def test_secret_values_are_rejected(self) -> None:
        value = self.base_input()
        metadata = copy.deepcopy(value["externalSecretMetadata"])
        metadata[0]["value"] = "must-never-be-accepted"
        value["externalSecretMetadata"] = metadata
        with self.assertRaisesRegex(MODULE.PreflightError, "keys mismatch"):
            MODULE.build_preflight(value)

    def test_gnosis_cannot_be_omitted_under_current_policy(self) -> None:
        value = self.base_input()
        value["gnosisRpcObservation"] = None
        result = MODULE.build_preflight(value)
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(any(item["code"] == "gnosis-rpc-required" for item in result["blockers"]))
        proxy_ids = [item["objectId"] for item in result["managedObjectInventory"] if "gnosis-proxy" in item["objectId"]]
        self.assertEqual(len(proxy_ids), 3)

    def test_inventory_marks_only_kustomizations_as_suspended(self) -> None:
        result = MODULE.build_preflight(self.base_input())
        inventory = result["managedObjectInventory"]
        suspended = [item for item in inventory if "reconciliationSuspended" in item]
        self.assertEqual(len(suspended), 3)
        self.assertTrue(all(item["reconciliationSuspended"] is True for item in suspended))
        self.assertTrue(all(item["object"]["kind"] == "Kustomization" for item in suspended))
        self.assertTrue(all("reconciliationSuspended" not in item for item in inventory if item["object"]["kind"] != "Kustomization"))

    def test_missing_executor_sequencing_paradox_is_reported(self) -> None:
        result = MODULE.build_preflight(self.base_input())
        codes = {item["code"] for item in result["blockers"]}
        self.assertIn("executor-sequencing-missing", codes)
        self.assertFalse(result["commandPlan"]["mutation"])
        self.assertEqual(
            [step["id"] for step in result["commandPlan"]["steps"]],
            ["atomic-post-no-op-bootstrap", "live-recheck", "cas-unsuspend", "rollback"],
        )

    def test_output_is_deterministic(self) -> None:
        value = self.base_input()
        first = MODULE.canonical_json(MODULE.build_preflight(value))
        second = MODULE.canonical_json(MODULE.build_preflight(copy.deepcopy(value)))
        self.assertEqual(first, second)
        self.assertTrue(first.endswith(b"\n"))


if __name__ == "__main__":
    unittest.main()
