from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "render_release_set_promotion",
    Path(__file__).with_name("render-release-set-promotion.py"),
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


class AutomaticPromotionTests(unittest.TestCase):
    def fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path, Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name) / "repo"
        shutil.copytree(ROOT, root, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        incoming = Path(temporary.name) / "incoming"
        (incoming / "evidence").mkdir(parents=True)

        head = json.loads((root / "reviewed-render/roebel-staging/head.json").read_text())
        revision = "f" * 40
        component_values = []
        digest_chars = (("3", "5", "7", "9"), ("4", "6", "8", "a"))
        for index, name in enumerate(MODULE.COMPONENT_ORDER):
            manifest_char, config_char, layer_char, sbom_char = digest_chars[index]
            manifest = "sha256:" + manifest_char * 64
            provenance_bundle = (json.dumps({"component": name, "kind": "provenance"}) + "\n").encode()
            provenance_dir = incoming / "bundles" / "provenance" / name
            sbom_dir = incoming / "bundles" / "sbom" / name
            provenance_dir.mkdir(parents=True)
            sbom_dir.mkdir(parents=True)
            bundle_name = f"sha256-{manifest.removeprefix('sha256:')}.jsonl"
            (provenance_dir / bundle_name).write_bytes(provenance_bundle)
            (sbom_dir / bundle_name).write_text('{"kind":"sbom-attestation"}\n')
            component = {
                "component": name,
                "sourceRevision": revision,
                "manifestDigest": manifest,
                "configDigest": "sha256:" + config_char * 64,
                "layerDigests": ["sha256:" + layer_char * 64],
                "provenance": {
                    "issuer": MODULE.ISSUER,
                    "identity": MODULE.SIGNER,
                    "predicateType": "https://slsa.dev/provenance/v1",
                    "attestationDigest": sha(provenance_bundle),
                },
                "sbom": {
                    "format": "SPDX-2.3",
                    "identity": "https://spdx.dev/spdx/v2.3",
                    "artifactDigest": "sha256:" + sbom_char * 64,
                },
            }
            component_values.append(component)
            evidence = {
                "schemaVersion": "roebel_staging_component_evidence_v1",
                "component": name,
                "sourceRevision": revision,
                "manifestDigest": manifest,
                "provenance": {
                    **component["provenance"],
                    "subjectDigest": manifest,
                },
                "sbom": {
                    **component["sbom"],
                    "subjectDigest": manifest,
                },
            }
            (incoming / "evidence" / f"{name}.component-evidence.json").write_text(json.dumps(evidence))

        payload = {
            "schemaVersion": "roebel_staging_release_set_candidate_v1",
            "promotionRevision": revision,
            "expectedPreviousHead": {
                "promotionRevision": head["promotionRevision"],
                "releaseSetDigest": head["releaseSetDigest"],
                "components": head["components"],
            },
            "components": component_values,
        }
        candidate = {**payload, "candidatePayloadDigest": sha(MODULE.canonical_candidate_payload(payload))}
        candidate_path = incoming / "release-set.candidate.json"
        candidate_path.write_text(json.dumps(candidate, indent=2) + "\n")
        return temporary, root, incoming, candidate_path

    def test_renders_exact_five_field_transition_accepted_by_protected_verifier(self) -> None:
        temporary, root, incoming, candidate = self.fixture()
        self.addCleanup(temporary.cleanup)
        result = MODULE.render(root, candidate, incoming)
        self.assertEqual(result["status"], "rendered_effect_free")
        self.assertEqual(result["changedComponents"], list(MODULE.COMPONENT_ORDER))

        verification = MODULE.Path(ROOT / "scripts/verify-reviewed-render.py")
        import subprocess

        completed = subprocess.run(
            ["python3", str(verification), "--root", str(root), "--base-root", str(ROOT)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_rejects_stale_previous_head(self) -> None:
        temporary, root, incoming, candidate_path = self.fixture()
        self.addCleanup(temporary.cleanup)
        candidate = json.loads(candidate_path.read_text())
        candidate["expectedPreviousHead"]["releaseSetDigest"] = "sha256:" + "0" * 64
        payload = {key: value for key, value in candidate.items() if key != "candidatePayloadDigest"}
        candidate["candidatePayloadDigest"] = sha(MODULE.canonical_candidate_payload(payload))
        candidate_path.write_text(json.dumps(candidate))
        with self.assertRaisesRegex(MODULE.PromotionError, "previous head is stale"):
            MODULE.render(root, candidate_path, incoming)

    def test_rejects_payload_and_provenance_tampering(self) -> None:
        temporary, root, incoming, candidate_path = self.fixture()
        self.addCleanup(temporary.cleanup)
        candidate = json.loads(candidate_path.read_text())
        candidate["components"][0]["manifestDigest"] = "sha256:" + "a" * 64
        candidate_path.write_text(json.dumps(candidate))
        with self.assertRaisesRegex(MODULE.PromotionError, "payload digest invalid"):
            MODULE.render(root, candidate_path, incoming)

        temporary2, root2, incoming2, candidate_path2 = self.fixture()
        self.addCleanup(temporary2.cleanup)
        component = json.loads((incoming2 / "evidence/public-mecky.component-evidence.json").read_text())
        component["provenance"]["identity"] = "https://example.invalid/untrusted"
        (incoming2 / "evidence/public-mecky.component-evidence.json").write_text(json.dumps(component))
        with self.assertRaisesRegex(MODULE.PromotionError, "provenance identity invalid"):
            MODULE.render(root2, candidate_path2, incoming2)


if __name__ == "__main__":
    unittest.main()
