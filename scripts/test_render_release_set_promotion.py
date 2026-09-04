from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import shutil
import tempfile
import unittest
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "render_release_set_promotion",
    Path(__file__).with_name("render-release-set-promotion.py"),
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
VERIFIER_SPEC = importlib.util.spec_from_file_location(
    "reviewed_render_verifier_for_promotion_test",
    Path(__file__).with_name("verify-reviewed-render.py"),
)
assert VERIFIER_SPEC and VERIFIER_SPEC.loader
VERIFIER = importlib.util.module_from_spec(VERIFIER_SPEC)
VERIFIER_SPEC.loader.exec_module(VERIFIER)
FIXTURE_SPEC = importlib.util.spec_from_file_location(
    "reviewed_render_fixtures_for_promotion_test",
    Path(__file__).with_name("test_verify_reviewed_render.py"),
)
assert FIXTURE_SPEC and FIXTURE_SPEC.loader
FIXTURES = importlib.util.module_from_spec(FIXTURE_SPEC)
FIXTURE_SPEC.loader.exec_module(FIXTURES)


def sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


SYNTHETIC_CITIZEN_ADOPTION_SQL_ZLIB_BASE64 = (
    "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"
)


class AutomaticPromotionTests(unittest.TestCase):
    def test_synthetic_gateway_allowlist_fits_haproxy_parser_word_limit(self) -> None:
        exact_paths = [
            *VERIFIER.PARTICIPANT_POLICY.ROUTES,
            *MODULE.SYNTHETIC_CITIZEN_PASS_POST_ROUTES,
        ]
        post_paths = [
            *VERIFIER.PARTICIPANT_POLICY.POST_ROUTES,
            *MODULE.SYNTHETIC_CITIZEN_PASS_POST_ROUTES,
        ]
        dynamic_get_prefixes = [
            *VERIFIER.PARTICIPANT_POLICY.DYNAMIC_GET_PREFIXES,
            MODULE.SYNTHETIC_CITIZEN_PASS_DYNAMIC_GET_PREFIX,
        ]

        annotation = MODULE.gateway_early_allowlist(
            exact_paths,
            post_paths,
            dynamic_get_prefixes,
        )
        lines = annotation.splitlines()

        self.assertTrue(lines)
        self.assertLessEqual(max(len(line.split()) for line in lines), 64)
        self.assertEqual(
            lines[0],
            "http-request deny deny_status 404 if "
            f"!{{ path {' '.join(exact_paths)} }} "
            f"!{{ path_beg {' '.join(dynamic_get_prefixes)} }}",
        )

    def fixture(
        self, *, before_synthetic_activation: bool = False,
    ) -> tuple[tempfile.TemporaryDirectory[str], Path, Path, Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name) / "repo"
        base = Path(temporary.name) / "base"
        shutil.copytree(ROOT, base, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        if before_synthetic_activation:
            # Historical activation tests need a verified pre-activation base;
            # ordinary image promotions must exercise the current steady state.
            FIXTURES.ReviewedRenderVerifierTests().normalize_synthetic_citizen_pass_seed(base)
        shutil.copytree(base, root)
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

    def synthetic_fixture(
        self,
    ) -> tuple[tempfile.TemporaryDirectory[str], Path, Path, Path]:
        temporary, root, incoming, candidate_path = self.fixture(
            before_synthetic_activation=True,
        )
        candidate = json.loads(candidate_path.read_text())
        revision = MODULE.SYNTHETIC_CITIZEN_PASS_SOURCE_REVISION
        candidate["promotionRevision"] = revision
        for component in candidate["components"]:
            component["sourceRevision"] = revision
            evidence_path = incoming / "evidence" / f"{component['component']}.component-evidence.json"
            evidence_value = json.loads(evidence_path.read_text())
            evidence_value["sourceRevision"] = revision
            evidence_path.write_text(json.dumps(evidence_value))
        manifest = MODULE.SYNTHETIC_CITIZEN_PASS_GATEWAY_MANIFEST_DIGEST
        provenance_bundle = b'{"component":"staging-participant-gateway","kind":"provenance"}\n'
        bundle_name = f"sha256-{manifest.removeprefix('sha256:')}.jsonl"
        provenance_dir = incoming / "bundles/provenance/staging-participant-gateway"
        sbom_dir = incoming / "bundles/sbom/staging-participant-gateway"
        provenance_dir.mkdir(parents=True)
        sbom_dir.mkdir(parents=True)
        (provenance_dir / bundle_name).write_bytes(provenance_bundle)
        (sbom_dir / bundle_name).write_text('{"kind":"sbom-attestation"}\n')
        gateway = {
            "component": "staging-participant-gateway",
            "sourceRevision": revision,
            "sourceTreeSha256": MODULE.SYNTHETIC_CITIZEN_PASS_GATEWAY_SOURCE_TREE_SHA256,
            "workflowSha256": MODULE.SYNTHETIC_CITIZEN_PASS_GATEWAY_WORKFLOW_SHA256,
            "manifestDigest": manifest,
            "configDigest": "sha256:" + "d" * 64,
            "layerDigests": ["sha256:" + "e" * 64],
            "provenance": {
                "issuer": MODULE.ISSUER,
                "identity": MODULE.PARTICIPANT_GATEWAY_SIGNER,
                "predicateType": "https://slsa.dev/provenance/v1",
                "attestationDigest": sha(provenance_bundle),
            },
            "sbom": {
                "format": "SPDX-2.3",
                "identity": "https://spdx.dev/spdx/v2.3",
                "artifactDigest": "sha256:" + "f" * 64,
            },
        }
        evidence = {
            "schemaVersion": "roebel_staging_component_evidence_v1",
            "component": gateway["component"],
            "sourceRevision": revision,
            "sourceTreeSha256": gateway["sourceTreeSha256"],
            "workflowSha256": gateway["workflowSha256"],
            "manifestDigest": manifest,
            "provenance": {
                **gateway["provenance"],
                "subjectDigest": manifest,
            },
            "sbom": {
                **gateway["sbom"],
                "subjectDigest": manifest,
            },
        }
        (incoming / "evidence/staging-participant-gateway.component-evidence.json").write_text(
            json.dumps(evidence),
        )
        migration = zlib.decompress(
            base64.b64decode(SYNTHETIC_CITIZEN_ADOPTION_SQL_ZLIB_BASE64),
        )
        self.assertEqual(
            sha(migration),
            MODULE.SYNTHETIC_CITIZEN_ADOPTION_MIGRATION_SHA256,
        )
        (incoming / "artifacts").mkdir()
        (incoming / "artifacts" / MODULE.SYNTHETIC_CITIZEN_ADOPTION_FILENAME).write_bytes(
            migration,
        )
        candidate["schemaVersion"] = "roebel_staging_release_set_candidate_v2"
        candidate["syntheticCitizenPass"] = {
            "schemaVersion": "roebel_staging_synthetic_citizen_pass_release_v1",
            "environment": "staging",
            "testOnly": True,
            "authorityBinding": "none",
            "policyVersion": MODULE.SYNTHETIC_CITIZEN_PASS_POLICY_VERSION,
            "testCitizenNft": MODULE.synthetic_citizen_pass_boundary()["testCitizenNft"],
            "gateway": gateway,
            "migration": {
                "configMapFilename": MODULE.SYNTHETIC_CITIZEN_ADOPTION_FILENAME,
                "path": MODULE.SYNTHETIC_CITIZEN_ADOPTION_SOURCE_PATH,
                "sha256": MODULE.SYNTHETIC_CITIZEN_ADOPTION_MIGRATION_SHA256,
                "databaseSchemaSha256": MODULE.SYNTHETIC_CITIZEN_ADOPTION_DATABASE_SCHEMA_SHA256,
            },
        }
        payload = {
            key: value
            for key, value in candidate.items()
            if key != "candidatePayloadDigest"
        }
        candidate["candidatePayloadDigest"] = sha(
            MODULE.canonical_candidate_payload(payload),
        )
        candidate_path.write_text(json.dumps(candidate, indent=2) + "\n")
        return temporary, root, incoming, candidate_path

    def refresh_integrity(self, root: Path) -> None:
        render = root / MODULE.RENDER_ROOT
        head = json.loads((render / "head.json").read_text())
        payload: dict[str, object] = {
            "nextEnvironmentHead": head,
            "objects": [
                json.loads((render / "public-mecky/deployment.json").read_text()),
                json.loads((render / "public-mecky/service.json").read_text()),
                json.loads((render / "public-mecky/networkpolicy.json").read_text()),
                json.loads((render / "web/deployment.json").read_text()),
                json.loads((render / "web/networkpolicy.json").read_text()),
                json.loads((render / "web/ingress.json").read_text()),
            ],
            "reviewedPublicKnowledge": VERIFIER.verify_reviewed_public_knowledge(root),
        }
        policy = VERIFIER.verify_participant_gateway_static_policy(
            root,
            "reviewed-public-knowledge-participant-gateway",
        )
        gateway = VERIFIER.verify_participant_gateway(root, policy)
        payload["stagingParticipantGateway"] = {
            key: value for key, value in gateway.items()
            if key != "civicProjectionRoute"
        }
        migration = json.loads((render / "network-boundary-migration.json").read_text())
        integrity_path = render / "integrity.json"
        integrity = json.loads(integrity_path.read_text())
        integrity["releaseSetDigest"] = head["releaseSetDigest"]
        integrity["desiredRenderSha256"] = VERIFIER.digest(payload)
        integrity["networkBoundaryMigrationSha256"] = VERIFIER.digest(migration)
        integrity_path.write_text(json.dumps(integrity, indent=2) + "\n")

    def verify_with_base(self, candidate: Path) -> tuple[int, str]:
        import subprocess

        completed = subprocess.run(
            [
                "python3",
                str(ROOT / "scripts/verify-reviewed-render.py"),
                "--root",
                str(candidate),
                "--base-root",
                str(candidate.parent / "base"),
            ],
            capture_output=True,
            text=True,
        )
        return completed.returncode, completed.stderr

    def test_v1_preserves_current_identity_and_protected_topology(self) -> None:
        for before_activation in (False, True):
            with self.subTest(before_synthetic_activation=before_activation):
                temporary, root, incoming, candidate = self.fixture(
                    before_synthetic_activation=before_activation,
                )
                self.addCleanup(temporary.cleanup)
                before = VERIFIER.verify_tree(root)
                if before_activation:
                    self.assertIsNone(before["webIdentityContractSet"])
                mutable = {
                    "head.json", "integrity.json", "live-preconditions.json",
                    "public-mecky/deployment.json", "web/deployment.json",
                }
                render = root / MODULE.RENDER_ROOT
                protected = {
                    str(path.relative_to(render)): path.read_bytes()
                    for path in render.rglob("*")
                    if path.is_file() and str(path.relative_to(render)) not in mutable
                }
                result = MODULE.render(root, candidate, incoming)
                self.assertEqual(result["status"], "rendered_effect_free")
                self.assertEqual(result["changedComponents"], list(MODULE.COMPONENT_ORDER))
                after = VERIFIER.verify_tree(root)
                self.assertEqual(after["webIdentityContractSet"], before["webIdentityContractSet"])
                self.assertEqual(
                    {
                        str(path.relative_to(render)): path.read_bytes()
                        for path in render.rglob("*")
                        if path.is_file() and str(path.relative_to(render)) not in mutable
                    },
                    protected,
                )
                returncode, stderr = self.verify_with_base(root)
                self.assertEqual(returncode, 0, stderr)

    def test_v2_renders_only_the_atomic_synthetic_citizen_pass_transition(self) -> None:
        temporary, root, incoming, candidate = self.synthetic_fixture()
        self.addCleanup(temporary.cleanup)
        result = MODULE.render(root, candidate, incoming)
        self.assertEqual(
            result["schemaVersion"],
            "roebel_staging_automatic_promotion_render_v2",
        )
        web = json.loads(
            (root / "reviewed-render/roebel-staging/web/deployment.json").read_text(),
        )
        web_environment = {
            item["name"]: item
            for item in web["spec"]["template"]["spec"]["containers"][0]["env"]
        }
        self.assertEqual(
            [web_environment[item["name"]] for item in MODULE.WEB_IDENTITY_CONTRACT_SET_ENV],
            MODULE.WEB_IDENTITY_CONTRACT_SET_ENV,
        )
        gateway = json.loads(
            (root / MODULE.PARTICIPANT_GATEWAY_ROOT / "deployment.json").read_text(),
        )
        gateway_environment = {
            item["name"]: item
            for item in gateway["spec"]["template"]["spec"]["containers"][0]["env"]
        }
        self.assertEqual(
            [gateway_environment[item["name"]] for item in MODULE.SYNTHETIC_CITIZEN_PASS_ENV],
            MODULE.SYNTHETIC_CITIZEN_PASS_ENV,
        )
        transition = json.loads(
            (root / MODULE.SYNTHETIC_CITIZEN_PASS_TRANSITION_PATH).read_text(),
        )
        self.assertEqual(
            transition["rollback"]["removeFiles"],
            [
                str(
                    MODULE.TRACER_DATA_PLANE_ROOT
                    / "bootstrap"
                    / MODULE.SYNTHETIC_CITIZEN_ADOPTION_FILENAME
                ),
                str(MODULE.SYNTHETIC_CITIZEN_PASS_TRANSITION_PATH),
            ],
        )
        self.assertEqual(
            {item["path"] for item in transition["rollback"]["restoreFiles"]},
            set(MODULE.SYNTHETIC_CITIZEN_PASS_EXISTING_PATHS),
        )
        base_pin = json.loads(
            (root.parent / "base" / MODULE.PARTICIPANT_GATEWAY_ROOT / "runtime-pin.json").read_text(),
        )
        candidate_pin = json.loads(
            (root / MODULE.PARTICIPANT_GATEWAY_ROOT / "runtime-pin.json").read_text(),
        )
        self.assertEqual(candidate_pin["citizenAdoption"], base_pin["citizenAdoption"])
        for relative in (
            MODULE.PARTICIPANT_GATEWAY_ROOT / "service.json",
            MODULE.PARTICIPANT_GATEWAY_ROOT / "networkpolicy.json",
            MODULE.PARTICIPANT_GATEWAY_ROOT / "serviceaccount.json",
            MODULE.PARTICIPANT_GATEWAY_ROOT / "kustomization.yaml",
            MODULE.PARTICIPANT_GATEWAY_ROOT / "workbench-ingress/networkpolicy.json",
            MODULE.PARTICIPANT_GATEWAY_ROOT / "workbench-ingress/kustomization.yaml",
            MODULE.RENDER_ROOT / "web/networkpolicy.json",
            MODULE.RENDER_ROOT / "web/ingress.json",
            Path("policy/staging-participant-gateway-activation-policy.json"),
            Path("policy/staging-participant-eligibility-issuer-materialization-policy.json"),
        ):
            self.assertEqual(
                (root / relative).read_bytes(),
                (root.parent / "base" / relative).read_bytes(),
                str(relative),
            )
        base_ingress = json.loads(
            (root.parent / "base" / MODULE.PARTICIPANT_GATEWAY_ROOT / "ingress.json").read_text(),
        )
        candidate_ingress = json.loads(
            (root / MODULE.PARTICIPANT_GATEWAY_ROOT / "ingress.json").read_text(),
        )
        self.assertEqual(
            candidate_ingress["metadata"]["annotations"][
                "haproxy-ingress.github.io/config-backend-early"
            ],
            VERIFIER.synthetic_gateway_early_allowlist(),
        )
        del base_ingress["metadata"]["annotations"][
            "haproxy-ingress.github.io/config-backend-early"
        ]
        del candidate_ingress["metadata"]["annotations"][
            "haproxy-ingress.github.io/config-backend-early"
        ]
        self.assertEqual(candidate_ingress, base_ingress)

        returncode, stderr = self.verify_with_base(root)
        self.assertEqual(returncode, 0, stderr)

    def test_protected_verifier_rejects_each_synthetic_leg_in_isolation(self) -> None:
        def remove_selector(root: Path) -> None:
            path = root / MODULE.RENDER_ROOT / "web/deployment.json"
            value = json.loads(path.read_text())
            container = value["spec"]["template"]["spec"]["containers"][0]
            container["env"] = [
                item for item in container["env"]
                if item["name"] not in MODULE.WEB_IDENTITY_CONTRACT_SET_ENV_NAMES
            ]
            annotations = value["spec"]["template"]["metadata"]["annotations"]
            for name in MODULE.WEB_IDENTITY_CONTRACT_SET_ANNOTATIONS:
                annotations.pop(name, None)
            path.write_text(json.dumps(value, indent=2) + "\n")

        def restore_paths(root: Path, paths: list[str]) -> None:
            for relative in paths:
                (root / relative).write_bytes((root.parent / "base" / relative).read_bytes())

        gateway_paths = [
            str(MODULE.PARTICIPANT_GATEWAY_ROOT / "runtime-pin.json"),
            str(MODULE.PARTICIPANT_GATEWAY_ROOT / "deployment.json"),
            str(MODULE.PARTICIPANT_GATEWAY_ROOT / "ingress.json"),
            str(MODULE.RENDER_ROOT / "network-boundary-migration.json"),
        ]
        tracer_paths = [
            str(MODULE.TRACER_DATA_PLANE_ROOT / "runtime-pin.json"),
            str(MODULE.TRACER_DATA_PLANE_ROOT / "postgres-deployment.json"),
            str(MODULE.TRACER_DATA_PLANE_ROOT / "kustomization.yaml"),
            str(MODULE.TRACER_DATA_PLANE_ROOT / "bootstrap/zz-roebel-tracer.sh"),
        ]

        for label in ("selector-only", "gateway-only", "migration-only"):
            with self.subTest(label=label):
                temporary, root, incoming, candidate = self.synthetic_fixture()
                self.addCleanup(temporary.cleanup)
                MODULE.render(root, candidate, incoming)
                if label != "selector-only":
                    remove_selector(root)
                if label != "gateway-only":
                    restore_paths(root, gateway_paths)
                if label != "migration-only":
                    restore_paths(root, tracer_paths + ["policy/repository-contract.json"])
                    (
                        root
                        / MODULE.TRACER_DATA_PLANE_ROOT
                        / "bootstrap"
                        / MODULE.SYNTHETIC_CITIZEN_ADOPTION_FILENAME
                    ).unlink()
                    (root / MODULE.SYNTHETIC_CITIZEN_PASS_TRANSITION_PATH).unlink()
                self.refresh_integrity(root)
                returncode, stderr = self.verify_with_base(root)
                self.assertNotEqual(returncode, 0)
                self.assertIn(
                    "synthetic citizen pass must transition Web, gateway, and migration atomically",
                    stderr,
                )

    def test_v2_rejects_wrong_authority_hash_and_publication_bindings(self) -> None:
        def rewrite_digest(candidate_path: Path, candidate: dict[str, object]) -> None:
            payload = {
                key: value for key, value in candidate.items()
                if key != "candidatePayloadDigest"
            }
            candidate["candidatePayloadDigest"] = sha(
                MODULE.canonical_candidate_payload(payload),
            )
            candidate_path.write_text(json.dumps(candidate, indent=2) + "\n")

        cases = (
            (
                "authority",
                lambda candidate, _incoming: candidate["syntheticCitizenPass"].__setitem__("authorityBinding", "municipal"),
                "authority boundary invalid",
            ),
            (
                "schema-hash",
                lambda candidate, _incoming: candidate["syntheticCitizenPass"]["migration"].__setitem__("databaseSchemaSha256", "sha256:" + "0" * 64),
                "migration binding invalid",
            ),
            (
                "runtime-hash",
                lambda candidate, _incoming: candidate["syntheticCitizenPass"]["testCitizenNft"].__setitem__("runtimeCodeKeccak256", "0x" + "0" * 64),
                "test CitizenNFT binding invalid",
            ),
            (
                "workflow-hash",
                lambda candidate, _incoming: candidate["syntheticCitizenPass"]["gateway"].__setitem__("workflowSha256", "sha256:" + "0" * 64),
                "protected publication binding invalid",
            ),
            (
                "source-tree-evidence",
                lambda _candidate, incoming: json.loads((incoming / "evidence/staging-participant-gateway.component-evidence.json").read_text()),
                "evidence source-tree binding invalid",
            ),
        )
        for label, mutate, expected in cases:
            with self.subTest(label=label):
                temporary, root, incoming, candidate_path = self.synthetic_fixture()
                self.addCleanup(temporary.cleanup)
                candidate = json.loads(candidate_path.read_text())
                if label == "source-tree-evidence":
                    evidence_path = incoming / "evidence/staging-participant-gateway.component-evidence.json"
                    evidence = json.loads(evidence_path.read_text())
                    evidence["sourceTreeSha256"] = "sha256:" + "0" * 64
                    evidence_path.write_text(json.dumps(evidence))
                else:
                    mutate(candidate, incoming)
                    rewrite_digest(candidate_path, candidate)
                with self.assertRaisesRegex(MODULE.PromotionError, expected):
                    MODULE.render(root, candidate_path, incoming)

    def test_v2_rejects_partial_gateway_env_real_path_and_rollback_drift(self) -> None:
        for label, mutate, expected in (
            (
                "partial-env",
                lambda root: self._remove_gateway_env(root),
                "staging participant gateway resource drift",
            ),
            (
                "real-citizen-path",
                lambda root: self._drift_real_citizen_path(root),
                "synthetic participant gateway runtime pin drift",
            ),
            (
                "rollback",
                lambda root: self._drift_rollback(root),
                "synthetic citizen pass rollback record drift",
            ),
        ):
            with self.subTest(label=label):
                temporary, root, incoming, candidate = self.synthetic_fixture()
                self.addCleanup(temporary.cleanup)
                MODULE.render(root, candidate, incoming)
                mutate(root)
                returncode, stderr = self.verify_with_base(root)
                self.assertNotEqual(returncode, 0)
                self.assertIn(expected, stderr)

    def _remove_gateway_env(self, root: Path) -> None:
        path = root / MODULE.PARTICIPANT_GATEWAY_ROOT / "deployment.json"
        value = json.loads(path.read_text())
        environment = value["spec"]["template"]["spec"]["containers"][0]["env"]
        environment[:] = [
            item for item in environment
            if item["name"] != MODULE.SYNTHETIC_CITIZEN_PASS_ENV[0]["name"]
        ]
        path.write_text(json.dumps(value, indent=2) + "\n")

    def _drift_real_citizen_path(self, root: Path) -> None:
        path = root / MODULE.PARTICIPANT_GATEWAY_ROOT / "runtime-pin.json"
        value = json.loads(path.read_text())
        value["citizenAdoption"]["citizenNft"]["address"] = (
            "0x0be374808a567c9088ac8208b90a4239432b3220"
        )
        path.write_text(json.dumps(value, indent=2) + "\n")

    def _drift_rollback(self, root: Path) -> None:
        path = root / MODULE.SYNTHETIC_CITIZEN_PASS_TRANSITION_PATH
        value = json.loads(path.read_text())
        value["rollback"]["strategy"] = "best-effort"
        path.write_text(json.dumps(value, indent=2) + "\n")

    def test_renderer_rejects_partial_or_mixed_identity_predecessor(self) -> None:
        mixed = copy.deepcopy(MODULE.WEB_IDENTITY_CONTRACT_SET_ENV)
        mixed[1]["value"] = "0x59aa26f499d7c2b3ec2c8524ed06f54fc4e85de5"
        for items, expected in (
            ([MODULE.WEB_IDENTITY_CONTRACT_SET_ENV[0]], "predecessor is partial"),
            (mixed, "predecessor address binding drift"),
        ):
            with self.subTest(expected=expected):
                temporary, root, incoming, candidate = self.synthetic_fixture()
                self.addCleanup(temporary.cleanup)
                path = root / "reviewed-render/roebel-staging/web/deployment.json"
                deployment = json.loads(path.read_text())
                environment = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
                environment.extend(copy.deepcopy(items))
                path.write_text(json.dumps(deployment, indent=2) + "\n")
                with self.assertRaisesRegex(
                    MODULE.PromotionError,
                    expected,
                ):
                    MODULE.render(root, candidate, incoming)

    def test_renders_mixed_source_reuse_from_exact_expected_previous_head(self) -> None:
        temporary, root, incoming, candidate_path = self.fixture()
        self.addCleanup(temporary.cleanup)
        candidate = json.loads(candidate_path.read_text())
        previous = candidate["expectedPreviousHead"]["components"][0]
        component = candidate["components"][0]
        component["sourceRevision"] = previous["sourceRevision"]
        component["manifestDigest"] = previous["manifestDigest"]

        provenance_bundle = b'{"component":"public-mecky","kind":"reused-provenance"}\n'
        bundle_name = f"sha256-{component['manifestDigest'].removeprefix('sha256:')}.jsonl"
        provenance_path = incoming / "bundles" / "provenance" / "public-mecky" / bundle_name
        sbom_path = incoming / "bundles" / "sbom" / "public-mecky" / bundle_name
        provenance_path.write_bytes(provenance_bundle)
        sbom_path.write_text('{"kind":"reused-sbom-attestation"}\n')
        component["provenance"]["attestationDigest"] = sha(provenance_bundle)
        evidence = json.loads((incoming / "evidence/public-mecky.component-evidence.json").read_text())
        evidence["sourceRevision"] = component["sourceRevision"]
        evidence["manifestDigest"] = component["manifestDigest"]
        evidence["provenance"]["subjectDigest"] = component["manifestDigest"]
        evidence["provenance"]["attestationDigest"] = component["provenance"]["attestationDigest"]
        evidence["sbom"]["subjectDigest"] = component["manifestDigest"]
        (incoming / "evidence/public-mecky.component-evidence.json").write_text(json.dumps(evidence))
        payload = {key: value for key, value in candidate.items() if key != "candidatePayloadDigest"}
        candidate["candidatePayloadDigest"] = sha(MODULE.canonical_candidate_payload(payload))
        candidate_path.write_text(json.dumps(candidate, indent=2) + "\n")

        result = MODULE.render(root, candidate_path, incoming)
        self.assertEqual(result["changedComponents"], ["roebel-web-staging"])

    def test_rejects_non_promotion_component_from_arbitrary_history(self) -> None:
        temporary, root, incoming, candidate_path = self.fixture()
        self.addCleanup(temporary.cleanup)
        candidate = json.loads(candidate_path.read_text())
        candidate["components"][0]["sourceRevision"] = "0" * 40
        payload = {key: value for key, value in candidate.items() if key != "candidatePayloadDigest"}
        candidate["candidatePayloadDigest"] = sha(MODULE.canonical_candidate_payload(payload))
        candidate_path.write_text(json.dumps(candidate))

        with self.assertRaisesRegex(MODULE.PromotionError, "must exactly reuse the expected previous head"):
            MODULE.render(root, candidate_path, incoming)

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
