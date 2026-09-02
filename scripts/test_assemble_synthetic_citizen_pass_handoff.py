from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/assemble-synthetic-citizen-pass-handoff.py"
SPEC = importlib.util.spec_from_file_location("synthetic_handoff", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def encoded(value: object) -> bytes:
    return (json.dumps(value, indent=2) + "\n").encode()


class SyntheticCitizenPassHandoffTests(unittest.TestCase):
    def fixture(self) -> tuple[tempfile.TemporaryDirectory[str], dict[str, object]]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        handoff = root / "release-set"
        handoff.mkdir()
        manifest = lambda character: "sha256:" + character * 64
        components = []
        head_components = []
        for name, character in (("public-mecky", "1"), ("roebel-web-staging", "2")):
            bundle_bytes = f"{name}-provenance\n".encode()
            component = {
                "component": name,
                "sourceRevision": MODULE.SOURCE_REVISION,
                "manifestDigest": manifest(character),
                "configDigest": manifest("a" if name == "public-mecky" else "b"),
                "layerDigests": [manifest("c" if name == "public-mecky" else "d")],
                "provenance": {
                    "issuer": MODULE.ISSUER,
                    "identity": "https://github.com/GiraeffleAeffle/Roebel-App/.github/workflows/roebel-staging-publish.yml@refs/heads/main",
                    "predicateType": "https://slsa.dev/provenance/v1",
                    "attestationDigest": MODULE.digest_bytes(bundle_bytes),
                },
                "sbom": {
                    "format": "SPDX-2.3",
                    "identity": "https://spdx.dev/spdx/v2.3",
                    "artifactDigest": manifest("e"),
                },
            }
            components.append(component)
            head_components.append({
                "component": name,
                "sourceRevision": MODULE.SOURCE_REVISION,
                "manifestDigest": manifest(character),
            })
            bundle = f"sha256-{character * 64}.jsonl"
            for kind in ("provenance", "sbom"):
                path = handoff / "bundles" / kind / name / bundle
                path.parent.mkdir(parents=True)
                path.write_bytes(bundle_bytes if kind == "provenance" else f"{name}-{kind}\n".encode())
            evidence = handoff / "evidence" / f"{name}.component-evidence.json"
            evidence.parent.mkdir(exist_ok=True)
            evidence.write_text("{}\n")
        candidate = {
            "schemaVersion": "roebel_staging_release_set_candidate_v1",
            "promotionRevision": MODULE.SOURCE_REVISION,
            "expectedPreviousHead": {"promotionRevision": "0" * 40, "releaseSetDigest": manifest("3"), "components": head_components},
            "components": components,
            "candidatePayloadDigest": manifest("4"),
        }
        (handoff / "release-set.candidate.json").write_bytes(encoded(candidate))
        (handoff / "previous-head.json").write_text("{}\n")

        migration = b"synthetic migration fixture\n"
        migration_path = handoff / "artifacts" / MODULE.MIGRATION_FILENAME
        migration_path.parent.mkdir()
        migration_path.write_bytes(migration)
        sbom = encoded({"spdxVersion": "SPDX-2.3"})
        sbom_path = root / "gateway.spdx.json"
        sbom_path.write_bytes(sbom)

        release_pins = {
            "schemaVersion": "roebel_staging_participant_gateway_release_pins_v4",
            **MODULE.REAL_RELEASE_PINS,
            "syntheticCitizenAdoptionMigrationSha256": MODULE.digest_bytes(migration),
            "syntheticCitizenAdoptionDatabaseSchemaSha256": manifest("5"),
        }
        release_pins_path = root / "gateway.release-pins.json"
        release_pins_path.write_bytes(encoded(release_pins))
        release_pins_sha = MODULE.digest_bytes(release_pins_path.read_bytes())

        source_receipt = {
            "schemaVersion": "roebel_staging_service_oci_receipt_v1",
            "sourceRevision": MODULE.SOURCE_REVISION,
            "component": MODULE.GATEWAY_COMPONENT,
            "importName": f"stadtstack.local/roebel-staging-lab/{MODULE.GATEWAY_COMPONENT}:source-{MODULE.SOURCE_REVISION}",
            "podReference": f"stadtstack.local/roebel-staging-lab/{MODULE.GATEWAY_COMPONENT}@{MODULE.GATEWAY_MANIFEST}",
            "manifestDigest": MODULE.GATEWAY_MANIFEST,
            "configDigest": manifest("6"),
            "layerDigests": [manifest("7")],
            "user": "65532:65532",
            "entrypoint": ["node", "/app/staging-participant-gateway.cjs"],
            "releasePinsSha256": release_pins_sha,
            "topicTracerMigrationSha256": release_pins["topicTracerMigrationSha256"],
            "topicTracerDatabaseSchemaSha256": release_pins["topicTracerDatabaseSchemaSha256"],
            "citizenAdoptionMigrationSha256": release_pins["citizenAdoptionMigrationSha256"],
            "citizenAdoptionDatabaseSchemaSha256": release_pins["citizenAdoptionDatabaseSchemaSha256"],
            "syntheticCitizenAdoptionMigrationSha256": release_pins["syntheticCitizenAdoptionMigrationSha256"],
            "syntheticCitizenAdoptionDatabaseSchemaSha256": release_pins["syntheticCitizenAdoptionDatabaseSchemaSha256"],
        }
        source_receipt_path = root / "gateway.source-receipt.json"
        source_receipt_path.write_bytes(encoded(source_receipt))

        publication_receipt = {
            "schemaVersion": "roebel_staging_publication_receipt_v4",
            "component": MODULE.GATEWAY_COMPONENT,
            "sourceRevision": MODULE.SOURCE_REVISION,
            "image": MODULE.GATEWAY_IMAGE,
            "tag": f"source-{MODULE.SOURCE_REVISION}",
            "manifestDigest": MODULE.GATEWAY_MANIFEST,
            "archiveSha256": manifest("8"),
            "sourceReceiptSha256": MODULE.digest_bytes(source_receipt_path.read_bytes()),
            "sbomSha256": MODULE.digest_bytes(sbom),
            **MODULE.REAL_RELEASE_PINS,
            "syntheticCitizenAdoptionMigrationSha256": release_pins["syntheticCitizenAdoptionMigrationSha256"],
            "syntheticCitizenAdoptionDatabaseSchemaSha256": release_pins["syntheticCitizenAdoptionDatabaseSchemaSha256"],
            "provenance": {"id": "1", "url": "https://github.com/GiraeffleAeffle/Roebel-App/attestations/1"},
            "sbomAttestation": {"id": "2", "url": "https://github.com/GiraeffleAeffle/Roebel-App/attestations/2"},
            "workflowIdentity": MODULE.GATEWAY_SIGNER,
            "runId": MODULE.GATEWAY_RUN_ID,
            "civicAuthority": "none",
            "deploymentEffect": False,
        }
        publication_receipt_path = root / "gateway.publication-receipt.json"
        publication_receipt_path.write_bytes(encoded(publication_receipt))

        bundle = f"sha256-{MODULE.GATEWAY_MANIFEST.removeprefix('sha256:')}.jsonl"
        for kind in ("provenance", "sbom"):
            path = handoff / "bundles" / kind / MODULE.GATEWAY_COMPONENT / bundle
            path.parent.mkdir(parents=True)
            path.write_text(f"gateway-{kind}\n")

        return temporary, {
            "root": root,
            "handoff": handoff,
            "migration": migration,
            "release_pins_path": release_pins_path,
            "source_receipt_path": source_receipt_path,
            "publication_receipt_path": publication_receipt_path,
            "sbom_path": sbom_path,
            "schema_sha": manifest("5"),
        }

    def assemble(self, fixture: dict[str, object]) -> dict[str, object]:
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(MODULE, "MIGRATION_SHA256", MODULE.digest_bytes(fixture["migration"])))
            stack.enter_context(mock.patch.object(MODULE, "DATABASE_SCHEMA_SHA256", fixture["schema_sha"]))
            stack.enter_context(mock.patch.object(MODULE, "RELEASE_PINS_SHA256", MODULE.digest_bytes(fixture["release_pins_path"].read_bytes())))
            stack.enter_context(mock.patch.object(MODULE, "SOURCE_RECEIPT_SHA256", MODULE.digest_bytes(fixture["source_receipt_path"].read_bytes())))
            stack.enter_context(mock.patch.object(MODULE, "PUBLICATION_RECEIPT_SHA256", MODULE.digest_bytes(fixture["publication_receipt_path"].read_bytes())))
            stack.enter_context(mock.patch.object(MODULE, "SBOM_SHA256", MODULE.digest_bytes(fixture["sbom_path"].read_bytes())))
            return MODULE.assemble(
                fixture["handoff"], fixture["source_receipt_path"],
                fixture["publication_receipt_path"], fixture["release_pins_path"],
                fixture["sbom_path"], MODULE.GATEWAY_SOURCE_TREE,
                MODULE.GATEWAY_WORKFLOW_SHA256,
            )

    def test_assembles_one_closed_v2_handoff(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        candidate = self.assemble(fixture)
        self.assertEqual(candidate["schemaVersion"], "roebel_staging_release_set_candidate_v2")
        gateway = candidate["syntheticCitizenPass"]["gateway"]
        self.assertEqual(gateway["sourceTreeSha256"], MODULE.GATEWAY_SOURCE_TREE)
        self.assertEqual(gateway["workflowSha256"], MODULE.GATEWAY_WORKFLOW_SHA256)
        evidence = json.loads((fixture["handoff"] / "evidence/staging-participant-gateway.component-evidence.json").read_text())
        self.assertEqual(evidence["sourceTreeSha256"], gateway["sourceTreeSha256"])
        self.assertEqual(evidence["workflowSha256"], gateway["workflowSha256"])
        loaded = json.loads((fixture["handoff"] / "release-set.candidate.json").read_text())
        payload = {
            key: loaded[key]
            for key in (
                "schemaVersion", "promotionRevision", "expectedPreviousHead",
                "components", "syntheticCitizenPass",
            )
        }
        self.assertEqual(
            loaded["candidatePayloadDigest"],
            MODULE.digest_bytes(MODULE.canonical_candidate(payload)),
        )

    def test_rejects_wrong_source_tree_or_workflow(self) -> None:
        for field in ("source-tree", "workflow"):
            with self.subTest(field=field):
                temporary, fixture = self.fixture()
                self.addCleanup(temporary.cleanup)
                with self.assertRaisesRegex(MODULE.HandoffError, f"gateway {field} checksum invalid"):
                    MODULE.assemble(
                        fixture["handoff"], fixture["source_receipt_path"],
                        fixture["publication_receipt_path"], fixture["release_pins_path"],
                        fixture["sbom_path"],
                        "sha256:" + "f" * 64 if field == "source-tree" else MODULE.GATEWAY_SOURCE_TREE,
                        "sha256:" + "f" * 64 if field == "workflow" else MODULE.GATEWAY_WORKFLOW_SHA256,
                    )

    def test_rejects_extra_or_missing_handoff_files(self) -> None:
        for label, mutate in (
            ("extra", lambda root: (root / "unexpected").write_text("no\n")),
            ("missing", lambda root: (root / "previous-head.json").unlink()),
        ):
            with self.subTest(label=label):
                temporary, fixture = self.fixture()
                self.addCleanup(temporary.cleanup)
                mutate(fixture["handoff"])
                with self.assertRaisesRegex(MODULE.HandoffError, "preassembled handoff file set invalid"):
                    self.assemble(fixture)

    def test_rejects_authority_relabel_even_with_a_rebound_file_pin(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        receipt = json.loads(fixture["publication_receipt_path"].read_text())
        receipt["civicAuthority"] = "municipal"
        fixture["publication_receipt_path"].write_bytes(encoded(receipt))
        with self.assertRaisesRegex(MODULE.HandoffError, "authority boundary invalid"):
            self.assemble(fixture)

    def test_rejects_real_citizen_adoption_drift_even_when_receipts_agree(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        drift = "sha256:" + "f" * 64
        release_pins = json.loads(fixture["release_pins_path"].read_text())
        release_pins["citizenAdoptionMigrationSha256"] = drift
        fixture["release_pins_path"].write_bytes(encoded(release_pins))
        source_receipt = json.loads(fixture["source_receipt_path"].read_text())
        source_receipt["citizenAdoptionMigrationSha256"] = drift
        source_receipt["releasePinsSha256"] = MODULE.digest_bytes(
            fixture["release_pins_path"].read_bytes(),
        )
        fixture["source_receipt_path"].write_bytes(encoded(source_receipt))
        publication = json.loads(fixture["publication_receipt_path"].read_text())
        publication["citizenAdoptionMigrationSha256"] = drift
        publication["sourceReceiptSha256"] = MODULE.digest_bytes(
            fixture["source_receipt_path"].read_bytes(),
        )
        fixture["publication_receipt_path"].write_bytes(encoded(publication))
        with self.assertRaisesRegex(MODULE.HandoffError, "real gateway or citizen-adoption pin drift"):
            self.assemble(fixture)


if __name__ == "__main__":
    unittest.main()
