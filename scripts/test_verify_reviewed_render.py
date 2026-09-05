#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import copy
import base64
import shutil
import tempfile
import unittest
import zlib
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("reviewed_render_verifier", ROOT / "scripts/verify-reviewed-render.py")
assert SPEC and SPEC.loader
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)

TRACER_PHASE_A_FIXTURE_REVISION = "7b7893a0ae7b8e509e9794625019626c9f0654df"
TRACER_PHASE_A_FIXTURE_FILES = {
    "reviewed-render/roebel-staging/head.json",
    "reviewed-render/roebel-staging/integrity.json",
    "reviewed-render/roebel-staging/live-preconditions.json",
    "reviewed-render/roebel-staging/public-mecky/deployment.json",
    "reviewed-render/roebel-staging/web/deployment.json",
}
# The protected automatic-promotion workflow runs these tests from a Git
# archive. Keep the historical active render self-contained and bind every
# reconstructed file to the exact predecessor revision's bytes.
TRACER_PHASE_A_FIXTURE_SHA256 = {
    "reviewed-render/roebel-staging/head.json":
        "sha256:78f40bde028ccbdf51c030fc0b8060607b156b86a2b0079dc0d3ae254e87d686",
    "reviewed-render/roebel-staging/integrity.json":
        "sha256:94f8c8d0aee19bc4b6dde09b917580cae36afc578038b1b6fc56dd5b0e28548c",
    "reviewed-render/roebel-staging/live-preconditions.json":
        "sha256:4e4062db4703f8b9e90741c81ee132864dcdb5287f581212a316ef8cac7afade",
    "reviewed-render/roebel-staging/public-mecky/deployment.json":
        "sha256:d70d4d5e57dafdc903d3d8ab83aa03ef3b5fbd6d59e5ddcc5bbabb7ec7878eac",
    "reviewed-render/roebel-staging/web/deployment.json":
        "sha256:8285b66120a7ba7cb747e8e3d9aa5ee1ffaf99decc9ef7b1d7c219b79d8571c0",
}
TRACER_PHASE_A_DESIRED_RENDER_SHA256 = (
    "sha256:25b94898d375c1d7e5a50ba82d7cda2c9668fc567237490f599ccdcec70d1339"
)
TRACER_PHASE_A_PREVIOUS_HEAD = {
    "components": [
        {
            "component": "public-mecky",
            "manifestDigest": "sha256:aa66c9b8bb75989e1c47b628845523fa345a944b0a1a82bd17863f96c1f128e4",
            "sourceRevision": "9a478809a3d64b9efea279b6ee088a1346b045b4",
        },
        {
            "component": "roebel-web-staging",
            "manifestDigest": "sha256:ffe0fb8ec74040a960d62ff4a8da3fd4763832b45d10358173947504aef586b0",
            "sourceRevision": "460944f4e87fb09b3a33b4a843b01a4e8e8a5115",
        },
    ],
    "promotionRevision": "460944f4e87fb09b3a33b4a843b01a4e8e8a5115",
    "releaseSetDigest": "sha256:5e898a86b17c5af6b921eb785177da1670db45cf60c0fd0a04fc7e81457c6b97",
    "schemaVersion": "roebel_staging_release_set_head_v1",
}


CITIZEN_ADOPTION_SQL_ZLIB_BASE64 = (
    "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"
    "jC4UyEgWizB/3vt/RTG+FQ=="
)


def participant_ready_policy() -> dict:
    return VERIFIER.PARTICIPANT_POLICY.approved_next_activation_policy_descriptor()


class ReviewedRenderVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        # Protected admission uses the real UTC clock. Tests pin one explicit
        # instant so freshness assertions remain deterministic.
        VERIFIER.SIGNED_NOSTR_APPROVED_ACTIVATION_EVIDENCE = None
        VERIFIER.SIGNED_NOSTR_APPROVED_DEACTIVATION_EVIDENCE = None
        VERIFIER.SIGNED_NOSTR_VERIFICATION_TIME_OVERRIDE = datetime(
            2026, 8, 24, 12, 4, 0, tzinfo=timezone.utc,
        )

    def tearDown(self) -> None:
        VERIFIER.SIGNED_NOSTR_APPROVED_ACTIVATION_EVIDENCE = None
        VERIFIER.SIGNED_NOSTR_APPROVED_DEACTIVATION_EVIDENCE = None
        VERIFIER.SIGNED_NOSTR_VERIFICATION_TIME_OVERRIDE = None

    def test_reviewed_admission_fetches_history_only_for_trusted_checkouts(self) -> None:
        workflow = (ROOT / ".github/workflows/reviewed-render-admission.yml").read_text()
        self.assertEqual(workflow.count("fetch-depth: 0"), 2)
        self.assertEqual(workflow.count("fetch-depth: 1"), 1)
        self.assertIn("name: Check out protected base", workflow)
        self.assertIn("name: Check out untrusted candidate as data", workflow)
        self.assertIn("name: Check out protected main", workflow)

    def test_eligibility_issuer_materialization_policy_is_exact(self) -> None:
        policy = VERIFIER.verify_eligibility_issuer_materialization_policy(ROOT)
        self.assertEqual(
            policy["keyId"],
            "roebel-staging-citizen-eligibility-2026-09",
        )
        self.assertEqual(policy["target"]["immutable"], True)
        self.assertEqual(
            policy["materialization"]["metadataOnlyRead"],
            {
                "representation": "PartialObjectMetadata",
                "accept": (
                    "application/json;as=PartialObjectMetadata;"
                    "g=meta.k8s.io;v=v1"
                ),
                "apiPath": (
                    "/api/v1/namespaces/stadtstack-roebel-web-preview/"
                    "secrets/roebel-staging-participant-gateway-"
                    "eligibility-issuer"
                ),
            },
        )
        self.assertEqual(
            policy["materialization"]["metadataCommitments"],
            {
                "contentContractAnnotation": (
                    "stadtstack.io/eligibility-issuer-"
                    "content-contract-sha256"
                ),
                "contentContractFields": [
                    "target",
                    "input.sha256Commitment",
                    "keyId",
                    "publicKey.expected",
                ],
                "keySetAnnotation": (
                    "stadtstack.io/eligibility-issuer-keyset-sha256"
                ),
                "keySet": ["private-key-hex"],
            },
        )
        self.assertEqual(
            policy["materialization"]["durableJournal"]["recovery"],
            "same-protected-journal-and-operation-nonce-only",
        )

        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        path = candidate / VERIFIER.ELIGIBILITY_ISSUER_POLICY_PATH
        drift = json.loads(path.read_text())
        drift["materialization"]["existingObject"] = "adopt"
        path.write_text(json.dumps(drift, indent=2) + "\n")
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            "eligibility issuer materialization policy drift",
        ):
            VERIFIER.verify_eligibility_issuer_materialization_policy(candidate)

    def test_repository_file_sets_admit_only_legacy_or_citizen_tracer(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for relative in VERIFIER.PARTICIPANT_GATEWAY_EXPECTED_FILES:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        self.assertEqual(
            VERIFIER.verify_repository_file_set(root),
            "reviewed-public-knowledge-participant-gateway",
        )

        citizen_sql = root / VERIFIER.CITIZEN_ADOPTION_SQL_PATH
        citizen_sql.parent.mkdir(parents=True, exist_ok=True)
        citizen_sql.touch()
        self.assertEqual(
            VERIFIER.verify_repository_file_set(root),
            "reviewed-public-knowledge-participant-gateway",
        )

        extra = root / "reviewed-render/roebel-staging/tracer-data-plane/bootstrap/76-unreviewed.sql"
        extra.touch()
        with self.assertRaisesRegex(VERIFIER.VerificationError, "file set drift"):
            VERIFIER.verify_repository_file_set(root)

    def test_gateway_v5_has_no_inherited_v4_runtime_release_lineage(self) -> None:
        legacy = VERIFIER.PARTICIPANT_POLICY.activation_policy_descriptor()
        successor = (
            VERIFIER.PARTICIPANT_POLICY.approved_next_activation_policy_descriptor()
        )
        self.assertGreater(
            len(VERIFIER.participant_gateway_runtime_release_pins(legacy)),
            0,
        )
        self.assertEqual(
            VERIFIER.participant_gateway_runtime_release_pins(successor),
            (),
        )
        expected = VERIFIER.PARTICIPANT_POLICY.expected_runtime_pin(successor)
        self.assertEqual(
            VERIFIER.verify_participant_gateway_runtime_pin(expected, successor),
            expected,
        )

    def test_gateway_http_contract_is_exact_for_v4_and_v5(self) -> None:
        legacy = VERIFIER.participant_gateway_http_contract(
            VERIFIER.PARTICIPANT_POLICY.activation_policy_descriptor(),
        )
        self.assertEqual(
            legacy["exactGatewayPaths"],
            list(VERIFIER.PARTICIPANT_POLICY.LEGACY_ROUTES),
        )
        self.assertNotIn("dynamicGetPrefixes", legacy)
        self.assertEqual(
            legacy["schemaVersion"],
            "roebel_staging_participant_gateway_runtime_pin_v3",
        )

        successor = VERIFIER.participant_gateway_http_contract(
            VERIFIER.PARTICIPANT_POLICY.approved_next_activation_policy_descriptor(),
        )
        self.assertEqual(
            successor["exactGatewayPaths"],
            list(VERIFIER.PARTICIPANT_POLICY.ROUTES),
        )
        self.assertEqual(
            successor["dynamicGetPrefixes"],
            list(VERIFIER.PARTICIPANT_POLICY.DYNAMIC_GET_PREFIXES),
        )
        self.assertEqual(
            successor["methodPathMatrix"]["GET"],
            [
                VERIFIER.PARTICIPANT_POLICY.ROUTES[0],
                *VERIFIER.PARTICIPANT_POLICY.PUBLIC_GET_ROUTES,
            ],
        )
        self.assertEqual(
            successor["schemaVersion"],
            "roebel_staging_participant_gateway_runtime_pin_v4",
        )

    def tracer_transition_snapshot(
        self,
        root: Path,
        *,
        citizen_adoption: bool,
        policy: dict,
        gateway_runtime: dict,
    ) -> dict:
        artifacts = (
            VERIFIER.TRACER_DATA_PLANE.PRODUCT_ARTIFACTS
            if citizen_adoption
            else VERIFIER.TRACER_DATA_PLANE.LEGACY_PRODUCT_ARTIFACTS
        )
        revision = (
            VERIFIER.TRACER_DATA_PLANE.PRODUCT_SOURCE_REVISION
            if citizen_adoption
            else VERIFIER.TRACER_DATA_PLANE.LEGACY_PRODUCT_SOURCE_REVISION
        )
        return {
            "root": root,
            "renderFileSet": "reviewed-public-knowledge-participant-gateway",
            "head": {"releaseSetDigest": "sha256:" + "a" * 64},
            "tracerDataPlane": {
                "productSourceRevision": revision,
                "productArtifacts": [
                    {"path": path, "sha256": digest}
                    for _filename, path, digest in artifacts
                ],
            },
            "stagingParticipantGatewayPolicy": copy.deepcopy(policy),
            "stagingParticipantGateway": {
                "runtimePin": copy.deepcopy(gateway_runtime),
                "civicProjectionRoute": True,
            },
            "publicMeckyReviewedEgress": True,
            "publicMeckyReviewedWebSource": True,
            "webTracerFeed": True,
            "signedNostr": None,
        }

    def transition_file_roots(
        self,
        changed: set[str],
        *,
        added: set[str] | None = None,
        preserved: set[str] | None = None,
    ) -> tuple[tempfile.TemporaryDirectory[str], Path, Path]:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        base = Path(temp.name) / "base"
        candidate = Path(temp.name) / "candidate"
        base.mkdir()
        candidate.mkdir()
        added = set() if added is None else added
        for relative in sorted(changed | (preserved or set())):
            candidate_path = candidate / relative
            candidate_path.parent.mkdir(parents=True, exist_ok=True)
            candidate_path.write_text("candidate\n" if relative in changed else "same\n")
            if relative not in added:
                base_path = base / relative
                base_path.parent.mkdir(parents=True, exist_ok=True)
                base_path.write_text("base\n" if relative in changed else "same\n")
        return temp, base, candidate

    def test_issuer_dry_run_projection_admission_is_exact_and_effect_free(self) -> None:
        expected = {
            "scripts/materialize-staging-participant-eligibility-issuer.py": {
                "predecessorSha256": "sha256:2f0f147d169b11ecbc2b288416d83531c9de45907ff32460d1615e2d43d70ee1",
                "successorSha256": "sha256:042f7ca54367cd1c92cd9ab4685fc2f20ef0af48ae8f7eec795f5fdf473bab44",
            },
            "scripts/test_materialize_staging_participant_eligibility_issuer.py": {
                "predecessorSha256": "sha256:471b834e8e7cbea2d04df3e07caec4b2508ae7b919d2a1defbea7059d3af046f",
                "successorSha256": "sha256:09052236fc3d9d2419ef3141461e5743f7e89b274899a1a9d2ebdb13ffab2b7b",
            },
            "scripts/test_run_staging_participant_gateway_live.py": {
                "predecessorSha256": "sha256:c27d8688f01fe0cb9e2c2407d2e1ddcd20f54494f7103c7d2737121e8a65887e",
                "successorSha256": "sha256:fbba0df00287771040272ecc960dc4a43130d5cd7b49caeb3d53b6b3290225da",
            },
        }
        self.assertEqual(
            VERIFIER.ELIGIBILITY_ISSUER_DRY_RUN_PROJECTION_TRANSITION,
            expected,
        )

        _temp, base_root, candidate_root = self.transition_file_roots(
            set(expected)
        )
        synthetic = {
            relative: {
                "predecessorSha256": VERIFIER.bytes_digest(
                    (base_root / relative).read_bytes()
                ),
                "successorSha256": VERIFIER.bytes_digest(
                    (candidate_root / relative).read_bytes()
                ),
            }
            for relative in expected
        }
        base = VERIFIER.verify_tree(ROOT)
        candidate = copy.deepcopy(base)
        base = copy.deepcopy(base)
        candidate["root"] = candidate_root
        base["root"] = base_root

        def verify_synthetic(
            candidate_snapshot: dict | None = None,
        ) -> dict:
            with (
                mock.patch.object(
                    VERIFIER,
                    "ELIGIBILITY_ISSUER_DRY_RUN_PROJECTION_TRANSITION",
                    synthetic,
                ),
                mock.patch.object(
                    VERIFIER,
                    "verify_tree",
                    side_effect=[candidate_snapshot or candidate, base],
                ),
            ):
                return VERIFIER.verify(candidate_root, base_root)

        result = verify_synthetic()
        self.assertTrue(result["baseTransitionVerified"])
        self.assertEqual(
            result["effects"],
            {
                "secretRead": False,
                "secretWrite": False,
                "clusterMutation": False,
                "civicMutation": False,
            },
        )

        for relative in sorted(expected):
            candidate_target = candidate_root / relative
            candidate_exact = candidate_target.read_bytes()
            candidate_target.write_bytes(
                candidate_exact + b"# successor byte-range drift\n"
            )
            with self.assertRaisesRegex(
                VERIFIER.VerificationError,
                "successor byte drift",
            ):
                verify_synthetic()
            candidate_target.write_bytes(candidate_exact)

            base_target = base_root / relative
            base_exact = base_target.read_bytes()
            base_target.write_bytes(base_exact + b"# predecessor byte-range drift\n")
            with self.assertRaisesRegex(
                VERIFIER.VerificationError,
                "predecessor byte drift",
            ):
                verify_synthetic()
            base_target.write_bytes(base_exact)

            candidate_target.write_bytes(base_exact)
            with self.assertRaisesRegex(
                VERIFIER.VerificationError,
                "changed file set drift",
            ):
                verify_synthetic()
            candidate_target.write_bytes(candidate_exact)

        with (
            mock.patch.object(
                VERIFIER,
                "ELIGIBILITY_ISSUER_DRY_RUN_PROJECTION_TRANSITION",
                synthetic,
            ),
            mock.patch.object(
                VERIFIER,
                "verify_tree",
                side_effect=[base, candidate],
            ),
        ):
            with self.assertRaisesRegex(
                VERIFIER.VerificationError,
                "predecessor byte drift",
            ):
                VERIFIER.verify(base_root, candidate_root)

        (candidate_root / "README.md").write_text("extra changed file\n")
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            "changed file set drift",
        ):
            verify_synthetic()
        (candidate_root / "README.md").unlink()

        changed_snapshot = copy.deepcopy(candidate)
        changed_snapshot["head"]["promotionRevision"] = "f" * 40
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            "render snapshot drift",
        ):
            verify_synthetic(changed_snapshot)

    def test_c1_is_the_exact_standalone_six_file_transition(self) -> None:
        _temp, base_root, candidate_root = self.transition_file_roots(
            VERIFIER.CITIZEN_ADOPTION_DATA_PLANE_TRANSITION_FILES,
            added={VERIFIER.CITIZEN_ADOPTION_SQL_PATH},
        )
        legacy_tracer = VERIFIER.TRACER_DATA_PLANE.runtime_pin(
            VERIFIER.TRACER_DATA_PLANE.LEGACY_PRODUCT_SOURCE_REVISION,
            VERIFIER.TRACER_DATA_PLANE.LEGACY_PRODUCT_ARTIFACTS,
        )
        successor_tracer = VERIFIER.TRACER_DATA_PLANE.runtime_pin(
            VERIFIER.TRACER_DATA_PLANE.PRODUCT_SOURCE_REVISION,
            VERIFIER.TRACER_DATA_PLANE.PRODUCT_ARTIFACTS,
        )
        runtime_path = (
            VERIFIER.TRACER_DATA_PLANE.RENDER_ROOT / "runtime-pin.json"
        )
        (base_root / runtime_path).write_text(json.dumps(legacy_tracer) + "\n")
        (candidate_root / runtime_path).write_text(
            json.dumps(successor_tracer) + "\n"
        )
        legacy_policy = VERIFIER.PARTICIPANT_POLICY.activation_policy_descriptor()
        gateway_runtime = VERIFIER.expected_participant_gateway_runtime_release_pin(
            legacy_policy,
        )
        base = self.tracer_transition_snapshot(
            base_root,
            citizen_adoption=False,
            policy=legacy_policy,
            gateway_runtime=gateway_runtime,
        )
        candidate = self.tracer_transition_snapshot(
            candidate_root,
            citizen_adoption=True,
            policy=legacy_policy,
            gateway_runtime=gateway_runtime,
        )
        VERIFIER.verify_transition(candidate, base)

        unexpected = candidate_root / "unreviewed.txt"
        unexpected.write_text("drift\n")
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            "data-plane transition changed file set drift",
        ):
            VERIFIER.verify_transition(candidate, base)
        unexpected.unlink()
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            "cannot regress",
        ):
            VERIFIER.verify_transition(base, candidate)

    def test_c2_is_the_exact_standalone_seven_file_transition(self) -> None:
        _temp, base_root, candidate_root = self.transition_file_roots(
            VERIFIER.CITIZEN_ADOPTION_GATEWAY_TRANSITION_FILES,
            preserved=VERIFIER.CITIZEN_ADOPTION_GATEWAY_PRESERVED_RENDER_FILES,
        )
        legacy_policy = VERIFIER.PARTICIPANT_POLICY.activation_policy_descriptor()
        successor_policy = (
            VERIFIER.PARTICIPANT_POLICY.approved_next_activation_policy_descriptor()
        )
        legacy_runtime = VERIFIER.expected_participant_gateway_runtime_release_pin(
            legacy_policy,
        )
        successor_runtime = VERIFIER.PARTICIPANT_POLICY.expected_runtime_pin(
            successor_policy,
        )
        base = self.tracer_transition_snapshot(
            base_root,
            citizen_adoption=True,
            policy=legacy_policy,
            gateway_runtime=legacy_runtime,
        )
        candidate = self.tracer_transition_snapshot(
            candidate_root,
            citizen_adoption=True,
            policy=successor_policy,
            gateway_runtime=successor_runtime,
        )
        VERIFIER.verify_transition(candidate, base)

        preserved_path = candidate_root / next(
            iter(VERIFIER.CITIZEN_ADOPTION_GATEWAY_PRESERVED_RENDER_FILES)
        )
        preserved_path.write_text("drift\n")
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            "gateway transition changed file set drift",
        ):
            VERIFIER.verify_transition(candidate, base)

        before_c1 = copy.deepcopy(base)
        before_c1["tracerDataPlane"] = self.tracer_transition_snapshot(
            base_root,
            citizen_adoption=False,
            policy=legacy_policy,
            gateway_runtime=legacy_runtime,
        )["tracerDataPlane"]
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            "data-plane transition changed participant policy",
        ):
            VERIFIER.verify_transition(candidate, before_c1)

    def test_full_tree_a_to_c1_to_c2_sequence_is_exact_and_closed(self) -> None:
        _temp, phase_a, c1, c2 = self.citizen_adoption_sequence_roots()
        a_result = VERIFIER.verify(phase_a)
        c1_result = VERIFIER.verify(c1, phase_a)
        c2_result = VERIFIER.verify(c2, c1)
        self.assertEqual(a_result["status"], "passed")
        self.assertTrue(c1_result["baseTransitionVerified"])
        self.assertTrue(c2_result["baseTransitionVerified"])

        a_tree = VERIFIER.verify_tree(phase_a)
        c1_tree = VERIFIER.verify_tree(c1)
        c2_tree = VERIFIER.verify_tree(c2)
        self.assertFalse(VERIFIER.tracer_citizen_adoption_enabled(a_tree))
        self.assertTrue(VERIFIER.tracer_citizen_adoption_enabled(c1_tree))
        self.assertTrue(VERIFIER.tracer_citizen_adoption_enabled(c2_tree))
        self.assertEqual(len(a_tree["tracerDataPlane"]["productArtifacts"]), 3)
        self.assertEqual(len(c1_tree["tracerDataPlane"]["productArtifacts"]), 4)
        self.assertEqual(len(c2_tree["tracerDataPlane"]["productArtifacts"]), 4)
        self.assertEqual(
            a_tree["stagingParticipantGatewayPolicy"],
            VERIFIER.PARTICIPANT_POLICY.STATIC_ACTIVATION_POLICY,
        )
        self.assertEqual(
            c1_tree["stagingParticipantGatewayPolicy"],
            VERIFIER.PARTICIPANT_POLICY.STATIC_ACTIVATION_POLICY,
        )
        self.assertEqual(
            c2_tree["stagingParticipantGatewayPolicy"],
            VERIFIER.PARTICIPANT_POLICY.APPROVED_NEXT_ACTIVATION_POLICY,
        )
        self.assertEqual(
            a_tree["stagingParticipantGateway"]["runtimePin"],
            c1_tree["stagingParticipantGateway"]["runtimePin"],
        )
        self.assertEqual(
            c1_tree["stagingParticipantGateway"]["runtimePin"]["schemaVersion"],
            "roebel_staging_participant_gateway_runtime_pin_v3",
        )
        self.assertEqual(
            c2_tree["stagingParticipantGateway"]["runtimePin"]["schemaVersion"],
            "roebel_staging_participant_gateway_runtime_pin_v4",
        )

        self.assertEqual(
            VERIFIER.changed_repository_files(c1, phase_a),
            VERIFIER.CITIZEN_ADOPTION_DATA_PLANE_TRANSITION_FILES,
        )
        self.assertEqual(
            VERIFIER.changed_repository_files(c2, c1),
            VERIFIER.CITIZEN_ADOPTION_GATEWAY_TRANSITION_FILES,
        )
        self.assertEqual(
            VERIFIER.repository_files(c1) - VERIFIER.repository_files(phase_a),
            {VERIFIER.CITIZEN_ADOPTION_SQL_PATH},
        )
        self.assertEqual(
            VERIFIER.repository_files(c2),
            VERIFIER.repository_files(c1),
        )
        self.assertEqual(
            (phase_a / VERIFIER.RENDER_ROOT / "integrity.json").read_bytes(),
            (c1 / VERIFIER.RENDER_ROOT / "integrity.json").read_bytes(),
        )
        self.assertEqual(
            (
                phase_a
                / VERIFIER.RENDER_ROOT
                / "network-boundary-migration.json"
            ).read_bytes(),
            (c1 / VERIFIER.RENDER_ROOT / "network-boundary-migration.json").read_bytes(),
        )

        contracts = [
            json.loads((root / "policy/repository-contract.json").read_text())
            for root in (phase_a, c1, c2)
        ]
        issuer_projections = [
            value["stagingParticipantGatewayBoundary"]
            ["eligibilityIssuerMaterialization"]
            for value in contracts
        ]
        self.assertEqual(issuer_projections[0], issuer_projections[1])
        self.assertEqual(issuer_projections[1], issuer_projections[2])
        self.assertEqual(
            contracts[0]["ephemeralTracerDataPlaneBoundary"],
            VERIFIER.TRACER_DATA_PLANE.contract_boundary(
                VERIFIER.TRACER_DATA_PLANE.LEGACY_PRODUCT_ARTIFACTS,
            ),
        )
        for value in contracts[1:]:
            self.assertEqual(
                value["ephemeralTracerDataPlaneBoundary"],
                VERIFIER.TRACER_DATA_PLANE.contract_boundary(
                    VERIFIER.TRACER_DATA_PLANE.PRODUCT_ARTIFACTS,
                ),
            )
        for relative in VERIFIER.CITIZEN_ADOPTION_GATEWAY_PRESERVED_RENDER_FILES:
            self.assertEqual(
                (c1 / relative).read_bytes(),
                (c2 / relative).read_bytes(),
                relative,
            )

    def repository_shape(self, root: Path) -> str:
        participant = (root / VERIFIER.PARTICIPANT_GATEWAY_ROOT).is_dir()
        signed_nostr = root / "reviewed-render/roebel-staging/signed-nostr"
        if signed_nostr.is_dir():
            return "signed-nostr-participant-gateway" if participant else "signed-nostr"
        future = root / "reviewed-render/roebel-staging/reviewed-public-knowledge"
        if future.is_dir():
            return (
                "reviewed-public-knowledge-participant-gateway"
                if participant
                else "reviewed-public-knowledge"
            )
        return "current"

    def current_boundary_receipt(
        self,
        web_network_policy: dict[str, object],
        web_ingress: dict[str, object],
    ) -> dict[str, object]:
        """Build the exact legacy, non-participant boundary fixture."""
        return {
            "authority": "none",
            "boundary": {
                "ingress": {
                    "allowedMethods": ["GET", "HEAD", "POST"],
                    "exactPostPath": "/api/chat/mecky",
                    "apiReadOnlyPrefixes": ["/api/public-feed/", "/api/civic/v1/"],
                    "apiReadOnlyExactPaths": ["/api/notifications/unread-count"],
                    "apiReadOnlyMethods": ["GET", "HEAD"],
                    "otherApiPaths": "404_except_public_feed_civic_v1_notifications_and_exact_mecky_path",
                    "otherMethods": "405",
                    "otherPostPaths": "405",
                    "resource": {
                        "kind": "Ingress",
                        "name": "roebel-web-presentation",
                        "namespace": "stadtstack-roebel-web-preview",
                    },
                },
                "webEgress": {
                    "destinationNamespace": "stadtstack-roebel-staging-lab",
                    "destinationPodLabels": {
                        "app.kubernetes.io/component": "public-mecky",
                        "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
                    },
                    "port": 18084,
                    "protocol": "TCP",
                    "resource": {
                        "kind": "NetworkPolicy",
                        "name": "roebel-web-presentation",
                        "namespace": "stadtstack-roebel-web-preview",
                    },
                },
            },
            "effects": {
                "civicMutation": False,
                "clusterMutation": False,
                "secretRead": False,
                "secretWrite": False,
            },
            "objects": [
                {
                    "kind": "NetworkPolicy",
                    "name": "roebel-web-presentation",
                    "namespace": "stadtstack-roebel-web-preview",
                    "sha256": VERIFIER.digest(web_network_policy),
                },
                {
                    "kind": "Ingress",
                    "name": "roebel-web-presentation",
                    "namespace": "stadtstack-roebel-web-preview",
                    "sha256": VERIFIER.digest(web_ingress),
                },
            ],
            "rbacBootstrap": {
                "createAllowed": False,
                "deleteAllowed": False,
                "listAllowed": False,
                "required": True,
                "roleNamespace": "stadtstack-roebel-web-preview",
                "serviceAccount": {
                    "name": "roebel-web-reconciler",
                    "namespace": "flux-roebel-staging",
                },
                "watchAllowed": False,
                "rules": [
                    {
                        "apiGroups": ["networking.k8s.io"],
                        "resourceNames": ["roebel-web-presentation"],
                        "resources": ["networkpolicies"],
                        "verbs": ["get", "patch", "update"],
                    },
                    {
                        "apiGroups": ["networking.k8s.io"],
                        "resourceNames": ["roebel-web-presentation"],
                        "resources": ["ingresses"],
                        "verbs": ["get", "patch", "update"],
                    },
                ],
                "liveMutationPerformed": False,
            },
            "schemaVersion": "roebel_staging_network_boundary_bootstrap_v1",
            "status": "local_candidate_ready_for_one_time_policy_bootstrap",
        }

    def refresh_current_integrity(self, destination: Path) -> None:
        """Restore the exact legacy boundary and checksum after fixture normalization."""
        render = destination / "reviewed-render/roebel-staging"
        web_ingress = VERIFIER.expected_web_ingress(False, False)
        (render / "web/ingress.json").write_text(
            json.dumps(web_ingress, indent=2) + "\n",
        )
        web_network_policy = json.loads((render / "web/networkpolicy.json").read_text())
        boundary = self.current_boundary_receipt(web_network_policy, web_ingress)
        (render / "network-boundary-migration.json").write_text(
            json.dumps(boundary, indent=2) + "\n",
        )

        integrity_path = render / "integrity.json"
        integrity = json.loads(integrity_path.read_text())
        integrity["desiredRenderSha256"] = VERIFIER.digest(
            {
                "nextEnvironmentHead": json.loads((render / "head.json").read_text()),
                "objects": [
                    json.loads((render / "public-mecky/deployment.json").read_text()),
                    json.loads((render / "public-mecky/service.json").read_text()),
                    json.loads((render / "public-mecky/networkpolicy.json").read_text()),
                    json.loads((render / "web/deployment.json").read_text()),
                    web_network_policy,
                    web_ingress,
                ],
            }
        )
        integrity["networkBoundaryMigrationSha256"] = VERIFIER.digest(boundary)
        integrity_path.write_text(json.dumps(integrity, indent=2) + "\n")

    def normalize_synthetic_citizen_pass_seed(self, destination: Path) -> None:
        """Restore an ordinary v4 fixture from the admitted synthetic steady state."""
        source = VERIFIER.verify_tree(destination)
        synthetic_state = (
            source["webIdentityContractSet"] is not None,
            VERIFIER.tracer_synthetic_citizen_pass_enabled(source),
            VERIFIER.gateway_synthetic_citizen_pass_enabled(source),
        )
        if synthetic_state == (False, False, False):
            return
        self.assertEqual(synthetic_state, (True, True, True))

        render = destination / VERIFIER.RENDER_ROOT
        # Historical v4 fixtures discard later identity/storage transition records.
        # This only edits the disposable fixture, never a live database.
        for relative in (VERIFIER.IDENTITY_ROTATION_SQL_PATH, VERIFIER.IDENTITY_ROTATION_RECORD_PATH, VERIFIER.TRACER_DATA_PLANE.RETAINED_RECORD_PATH):
            (destination / relative).unlink(missing_ok=True)
        for relative in (
            VERIFIER.SYNTHETIC_CITIZEN_ADOPTION_SQL_PATH,
            VERIFIER.SYNTHETIC_CITIZEN_PASS_TRANSITION_PATH,
        ):
            (destination / relative).unlink()

        tracer = destination / VERIFIER.TRACER_DATA_PLANE.RENDER_ROOT
        tracer_artifacts = VERIFIER.TRACER_DATA_PLANE.PRODUCT_ARTIFACTS
        (tracer / "runtime-pin.json").write_text(
            json.dumps(
                VERIFIER.TRACER_DATA_PLANE.runtime_pin(
                    VERIFIER.TRACER_DATA_PLANE.PRODUCT_SOURCE_REVISION,
                    tracer_artifacts,
                ),
                indent=2,
            )
            + "\n",
        )
        (tracer / "postgres-deployment.json").write_text(
            json.dumps(
                VERIFIER.TRACER_DATA_PLANE.expected_postgres_deployment(
                    tracer_artifacts,
                ),
                indent=2,
            )
            + "\n",
        )
        (tracer / "kustomization.yaml").write_text(
            VERIFIER.TRACER_DATA_PLANE.kustomization_text(tracer_artifacts),
        )
        (tracer / "bootstrap/zz-roebel-tracer.sh").write_text(
            VERIFIER.TRACER_DATA_PLANE.bootstrap_verify_script(tracer_artifacts),
        )

        policy = source["stagingParticipantGatewayPolicy"]
        runtime_pin = VERIFIER.PARTICIPANT_POLICY.expected_runtime_pin(policy)
        resources = VERIFIER.expected_participant_gateway_resources(
            runtime_pin,
            policy,
            civic_projection_route=(
                source["stagingParticipantGateway"]["civicProjectionRoute"]
            ),
        )
        participant = destination / VERIFIER.PARTICIPANT_GATEWAY_ROOT
        for name in ("deployment", "ingress", "runtime-pin"):
            value = runtime_pin if name == "runtime-pin" else resources[name]
            (participant / f"{name}.json").write_text(
                json.dumps(value, indent=2) + "\n",
            )

        web_path = render / "web/deployment.json"
        web = json.loads(web_path.read_text())
        web_template = web["spec"]["template"]
        for name in VERIFIER.WEB_IDENTITY_CONTRACT_SET_ANNOTATIONS:
            web_template["metadata"]["annotations"].pop(name)
        environment = web_template["spec"]["containers"][0]["env"]
        environment[:] = [
            item
            for item in environment
            if item["name"] not in VERIFIER.WEB_IDENTITY_CONTRACT_SET_ENV_NAMES
        ]
        web_path.write_text(json.dumps(web, indent=2) + "\n")

        http = VERIFIER.participant_gateway_http_contract(policy)
        contract_path = destination / "policy/repository-contract.json"
        contract = json.loads(contract_path.read_text())
        contract["ephemeralTracerDataPlaneBoundary"] = (
            VERIFIER.TRACER_DATA_PLANE.contract_boundary(tracer_artifacts)
        )
        gateway_contract = contract["stagingParticipantGatewayBoundary"]
        gateway_contract["exactGatewayPaths"] = http["exactGatewayPaths"]
        gateway_contract["dynamicGetPrefixes"] = http["dynamicGetPrefixes"]
        gateway_contract["methodPathMatrix"] = http["methodPathMatrix"]
        gateway_contract["routeProbeSamples"] = http["routeProbeSamples"]
        gateway_contract["schemaVersion"] = http["schemaVersion"]
        gateway_contract.pop("syntheticCitizenAdoption")
        contract_path.write_text(json.dumps(contract, indent=2) + "\n")

        migration_path = render / "network-boundary-migration.json"
        migration = copy.deepcopy(source["migration"])
        ingress_boundary = migration["boundary"]["ingress"]
        ingress_boundary["exactGatewayPaths"] = http["exactGatewayPaths"]
        ingress_boundary["exactPostPaths"] = http["methodPathMatrix"]["POST"]
        ingress_boundary["dynamicGetPrefixes"] = http["dynamicGetPrefixes"]
        ingress_boundary["gatewayMethodPathMatrix"] = http["methodPathMatrix"]
        ingress_boundary["routeProbeSamples"] = http["routeProbeSamples"]
        for kind, resource in (
            ("Deployment", resources["deployment"]),
            ("Ingress", resources["ingress"]),
        ):
            next(
                item
                for item in migration["objects"]
                if item["kind"] == kind
                and item["name"] == VERIFIER.PARTICIPANT_GATEWAY_NAME
            )["sha256"] = VERIFIER.digest(resource)
        migration_path.write_text(json.dumps(migration, indent=2) + "\n")

        objects = copy.deepcopy(source["objects"])
        objects[3] = web
        checksum_payload: dict[str, object] = {
            "nextEnvironmentHead": source["head"],
            "objects": objects,
            "stagingParticipantGateway": {
                "runtimePin": runtime_pin,
                **resources,
            },
        }
        if source["reviewedPublicKnowledge"] is not None:
            checksum_payload["reviewedPublicKnowledge"] = source[
                "reviewedPublicKnowledge"
            ]
        if source["signedNostr"] is not None:
            checksum_payload["signedNostr"] = source["signedNostr"]
        integrity_path = render / "integrity.json"
        integrity = json.loads(integrity_path.read_text())
        integrity["desiredRenderSha256"] = VERIFIER.digest(checksum_payload)
        integrity["networkBoundaryMigrationSha256"] = VERIFIER.digest(migration)
        integrity_path.write_text(json.dumps(integrity, indent=2) + "\n")

        normalized = VERIFIER.verify_tree(destination)
        self.assertIsNone(normalized["webIdentityContractSet"])
        self.assertFalse(
            VERIFIER.tracer_synthetic_citizen_pass_enabled(normalized),
        )
        self.assertFalse(
            VERIFIER.gateway_synthetic_citizen_pass_enabled(normalized),
        )

    def normalize_current_seed(self, destination: Path) -> None:
        """Make mutation fixtures current-shaped even when ROOT is future-shaped."""
        render = destination / "reviewed-render/roebel-staging"
        future = render / "reviewed-public-knowledge"
        if not future.is_dir():
            return
        self.normalize_synthetic_citizen_pass_seed(destination)

        public_path = render / "public-mecky/deployment.json"
        public = json.loads(public_path.read_text())
        env = public["spec"]["template"]["spec"]["containers"][0]["env"]
        env[:] = [
            item
            for item in env
            if item["name"] not in {
                "MECKY_REVIEWED_SOURCE_KINDS",
                "MECKY_REVIEWED_KNOWLEDGE_BASE_URL",
            }
        ]
        base_url = next(item for item in env if item["name"] == "STADTSTACK_PUBLIC_BASE_URL")
        base_url["value"] = "http://stadtstack-public.stadtstack-roebel-staging-lab.svc.cluster.local:18080"
        url_index = env.index(base_url)
        env[url_index + 1:url_index + 1] = [
            {"name": "STADTSTACK_E2E_MODE", "value": "synthetic-reviewed"},
            {"name": "STADTSTACK_E2E_SYNTHETIC_EVIDENCE_ALLOWED", "value": "true"},
            {
                "name": "STADTSTACK_E2E_REVIEWED_EVIDENCE",
                "valueFrom": {
                    "configMapKeyRef": {
                        "key": "evidence.json",
                        "name": "reviewed-evidence",
                        "optional": False,
                    }
                },
            },
            {
                "name": "STADTSTACK_E2E_REVIEWED_EVIDENCE_SHA256",
                "valueFrom": {
                    "configMapKeyRef": {
                        "key": "evidence.sha256",
                        "name": "reviewed-evidence",
                        "optional": False,
                    }
                },
            },
        ]
        public_path.write_text(json.dumps(public, indent=2) + "\n")

        public_policy_path = render / "public-mecky/networkpolicy.json"
        public_policy_path.write_text(json.dumps(
            VERIFIER.expected_public_mecky_network_policy(False),
            indent=2,
        ) + "\n")

        shutil.rmtree(future)
        tracer = destination / VERIFIER.TRACER_DATA_PLANE.RENDER_ROOT
        citizen_sql = destination / VERIFIER.CITIZEN_ADOPTION_SQL_PATH
        if citizen_sql.exists():
            citizen_sql.unlink()
        (tracer / "runtime-pin.json").write_text(
            json.dumps(
                VERIFIER.TRACER_DATA_PLANE.runtime_pin(
                    VERIFIER.TRACER_DATA_PLANE.LEGACY_PRODUCT_SOURCE_REVISION,
                    VERIFIER.TRACER_DATA_PLANE.LEGACY_PRODUCT_ARTIFACTS,
                ),
                indent=2,
            )
            + "\n",
        )
        (tracer / "postgres-deployment.json").write_text(
            json.dumps(
                VERIFIER.TRACER_DATA_PLANE.expected_postgres_deployment(
                    VERIFIER.TRACER_DATA_PLANE.LEGACY_PRODUCT_ARTIFACTS,
                ),
                indent=2,
            )
            + "\n",
        )
        (tracer / "kustomization.yaml").write_text(
            VERIFIER.TRACER_DATA_PLANE.kustomization_text(
                VERIFIER.TRACER_DATA_PLANE.LEGACY_PRODUCT_ARTIFACTS,
            ),
        )
        (tracer / "bootstrap/zz-roebel-tracer.sh").write_text(
            VERIFIER.TRACER_DATA_PLANE.bootstrap_verify_script(
                VERIFIER.TRACER_DATA_PLANE.LEGACY_PRODUCT_ARTIFACTS,
            ),
        )
        self.refresh_current_integrity(destination)

    def candidate(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temp = tempfile.TemporaryDirectory()
        destination = Path(temp.name) / "candidate"
        shutil.copytree(ROOT, destination, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        self.normalize_current_seed(destination)
        self.normalize_inert_participant_seed(destination)
        self.normalize_no_participant_gateway_seed(destination)
        return temp, destination

    def activate_web_identity_contract_set(
        self,
        root: Path,
        *,
        promote: bool = True,
    ) -> None:
        """Render the selector with one immutable Web promotion, never alone."""
        protected = VERIFIER.verify_tree(root)
        if protected["webIdentityContractSet"] is not None:
            self.normalize_synthetic_citizen_pass_seed(root)
            protected = VERIFIER.verify_tree(root)
        self.assertIsNone(protected["webIdentityContractSet"])
        if promote:
            self.make_valid_transition(root)
        render = root / VERIFIER.RENDER_ROOT
        head = json.loads((render / "head.json").read_text())
        deployment = VERIFIER.expected_web_identity_contract_set_deployment(
            protected["deployments"]["roebel-web-staging"],
            head,
        )
        (render / "web/deployment.json").write_text(
            json.dumps(deployment, indent=2) + "\n",
        )
        objects = copy.deepcopy(protected["objects"])
        objects[0] = json.loads(
            (render / "public-mecky/deployment.json").read_text(),
        )
        objects[3] = deployment
        payload: dict[str, object] = {
            "nextEnvironmentHead": head,
            "objects": objects,
        }
        if protected["reviewedPublicKnowledge"] is not None:
            payload["reviewedPublicKnowledge"] = protected["reviewedPublicKnowledge"]
        if protected["signedNostr"] is not None:
            payload["signedNostr"] = protected["signedNostr"]
        if protected["stagingParticipantGateway"] is not None:
            payload["stagingParticipantGateway"] = {
                key: value
                for key, value in protected["stagingParticipantGateway"].items()
                if key != "civicProjectionRoute"
            }
        integrity_path = render / "integrity.json"
        integrity = json.loads(integrity_path.read_text())
        integrity["releaseSetDigest"] = head["releaseSetDigest"]
        integrity["desiredRenderSha256"] = VERIFIER.digest(payload)
        integrity_path.write_text(json.dumps(integrity, indent=2) + "\n")
        self.assertEqual(
            VERIFIER.verify_tree(root)["webIdentityContractSet"],
            VERIFIER.WEB_IDENTITY_CONTRACT_SET,
        )

    def set_current_tracer_feed_route(self, root: Path, enabled: bool) -> None:
        """Normalize one current-head fixture to the exact private feed route state."""
        source = VERIFIER.verify_tree(ROOT)
        render = root / "reviewed-render/roebel-staging"

        deployment_path = render / "web/deployment.json"
        deployment = json.loads(deployment_path.read_text())
        environment = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
        environment[:] = [
            item
            for item in environment
            if item["name"] not in {
                VERIFIER.TRACER_FEED_URL_ENV["name"],
                VERIFIER.TRACER_FEED_ANON_ENV["name"],
            }
        ]
        if enabled:
            names = [item["name"] for item in environment]
            insertion = names.index("ROEBEL_PUBLIC_THIRDWEB_CLIENT_ID")
            environment[insertion:insertion] = [
                copy.deepcopy(VERIFIER.TRACER_FEED_URL_ENV),
                copy.deepcopy(VERIFIER.TRACER_FEED_ANON_ENV),
            ]
        deployment_path.write_text(json.dumps(deployment, indent=2) + "\n")

        civic_projection = bool(
            source["stagingParticipantGateway"]
            and source["stagingParticipantGateway"]["civicProjectionRoute"]
        )
        network_policy = VERIFIER.expected_web_network_policy(
            civic_projection,
            enabled,
            source["publicMeckyReviewedWebSource"],
        )
        (render / "web/networkpolicy.json").write_text(
            json.dumps(network_policy, indent=2) + "\n",
        )

        migration_path = render / "network-boundary-migration.json"
        migration = copy.deepcopy(source["migration"])
        if enabled:
            migration["boundary"]["webTracerFeed"] = {
                "authority": "none",
                "credentialSecret": {
                    "key": VERIFIER.TRACER_DATA_PLANE.WEB_FEED_SECRET_KEYS[0],
                    "name": VERIFIER.TRACER_DATA_PLANE.WEB_FEED_SECRET,
                    "namespace": VERIFIER.TRACER_DATA_PLANE.PREVIEW_NAMESPACE,
                    "valuesCommitted": False,
                },
                "destinationNamespace": VERIFIER.TRACER_DATA_PLANE.NAMESPACE,
                "destinationPodLabels": VERIFIER.TRACER_DATA_PLANE.POSTGREST_LABELS,
                "port": VERIFIER.TRACER_DATA_PLANE.POSTGREST_PORT,
                "protocol": "TCP",
                "source": {
                    "namespace": VERIFIER.PARTICIPANT_GATEWAY_NAMESPACE,
                    "podSelector": VERIFIER.WEB_PRESENTATION_LABELS,
                },
                "upstreamUrl": VERIFIER.TRACER_DATA_PLANE.POSTGREST_CLUSTER_URL,
            }
        else:
            migration["boundary"].pop("webTracerFeed", None)
        web_policy_receipt = next(
            item
            for item in migration["objects"]
            if item["kind"] == "NetworkPolicy"
            and item["name"] == "roebel-web-presentation"
        )
        web_policy_receipt["sha256"] = VERIFIER.digest(network_policy)
        migration_path.write_text(json.dumps(migration, indent=2) + "\n")

        objects = copy.deepcopy(source["objects"])
        objects[3] = deployment
        objects[4] = network_policy
        payload: dict[str, object] = {
            "nextEnvironmentHead": json.loads((render / "head.json").read_text()),
            "objects": objects,
        }
        if source["reviewedPublicKnowledge"] is not None:
            payload["reviewedPublicKnowledge"] = source["reviewedPublicKnowledge"]
        if source["signedNostr"] is not None:
            payload["signedNostr"] = source["signedNostr"]
        if source["stagingParticipantGateway"] is not None:
            payload["stagingParticipantGateway"] = {
                key: value
                for key, value in source["stagingParticipantGateway"].items()
                if key != "civicProjectionRoute"
            }
        integrity_path = render / "integrity.json"
        integrity = json.loads(integrity_path.read_text())
        integrity["desiredRenderSha256"] = VERIFIER.digest(payload)
        integrity["networkBoundaryMigrationSha256"] = VERIFIER.digest(migration)
        integrity_path.write_text(json.dumps(integrity, indent=2) + "\n")

    def enable_public_mecky_reviewed_web_source(self, root: Path) -> None:
        """Materialize the exact internal Web knowledge route under review."""
        source = VERIFIER.verify_tree(root)
        if source["publicMeckyReviewedWebSource"]:
            return
        render = root / "reviewed-render/roebel-staging"

        deployment_path = render / "public-mecky/deployment.json"
        deployment = json.loads(deployment_path.read_text())
        environment = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
        environment.append({
            "name": "MECKY_REVIEWED_KNOWLEDGE_BASE_URL",
            "value": (
                "http://roebel-web-presentation.stadtstack-roebel-web-preview."
                "svc.cluster.local:8080"
            ),
        })
        deployment_path.write_text(json.dumps(deployment, indent=2) + "\n")

        public_policy = copy.deepcopy(source["objects"][2])
        public_policy["spec"]["egress"].extend([
            {
                "to": [{
                    "namespaceSelector": {
                        "matchLabels": {"kubernetes.io/metadata.name": "kube-system"},
                    },
                    "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
                }],
                "ports": [
                    {"port": 53, "protocol": "UDP"},
                    {"port": 53, "protocol": "TCP"},
                ],
            },
            {
                "to": [{
                    "namespaceSelector": {
                        "matchLabels": {
                            "kubernetes.io/metadata.name": "stadtstack-roebel-web-preview",
                        },
                    },
                    "podSelector": {
                        "matchLabels": {
                            "app.kubernetes.io/name": "roebel-web-presentation",
                        },
                    },
                }],
                "ports": [{"port": 8080, "protocol": "TCP"}],
            },
        ])
        (render / "public-mecky/networkpolicy.json").write_text(
            json.dumps(public_policy, indent=2) + "\n",
        )

        web_policy = copy.deepcopy(source["objects"][4])
        web_policy["spec"]["ingress"].append({
            "from": [{
                "namespaceSelector": {
                    "matchLabels": {
                        "kubernetes.io/metadata.name": "stadtstack-roebel-staging-lab",
                    },
                },
                "podSelector": {
                    "matchLabels": {
                        "app.kubernetes.io/component": "public-mecky",
                        "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
                    },
                },
            }],
            "ports": [{"port": 8080, "protocol": "TCP"}],
        })
        (render / "web/networkpolicy.json").write_text(
            json.dumps(web_policy, indent=2) + "\n",
        )

        migration = copy.deepcopy(source["migration"])
        migration["boundary"]["publicMeckyReviewedWebSource"] = {
            "authority": "none",
            "destinationNamespace": "stadtstack-roebel-web-preview",
            "destinationPodLabels": {
                "app.kubernetes.io/name": "roebel-web-presentation",
            },
            "dns": {
                "destinationNamespace": "kube-system",
                "destinationPodLabels": {"k8s-app": "kube-dns"},
                "ports": [
                    {"port": 53, "protocol": "UDP"},
                    {"port": 53, "protocol": "TCP"},
                ],
            },
            "knowledgeOrigin": (
                "http://roebel-web-presentation.stadtstack-roebel-web-preview."
                "svc.cluster.local:8080"
            ),
            "port": 8080,
            "protocol": "TCP",
            "publicIndexOrigin": None,
            "source": {
                "namespace": "stadtstack-roebel-staging-lab",
                "podSelector": {
                    "app.kubernetes.io/component": "public-mecky",
                    "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
                },
            },
            "sourceKinds": "local_news,ratsinformation",
        }
        next(
            item
            for item in migration["objects"]
            if item["kind"] == "NetworkPolicy"
            and item["name"] == "roebel-web-presentation"
        )["sha256"] = VERIFIER.digest(web_policy)
        migration["objects"].append({
            "kind": "NetworkPolicy",
            "name": "public-mecky-chat-from-web",
            "namespace": "stadtstack-roebel-staging-lab",
            "sha256": VERIFIER.digest(public_policy),
        })
        (render / "network-boundary-migration.json").write_text(
            json.dumps(migration, indent=2) + "\n",
        )

        objects = copy.deepcopy(source["objects"])
        objects[0] = deployment
        objects[2] = public_policy
        objects[4] = web_policy
        checksum_payload: dict[str, object] = {
            "nextEnvironmentHead": source["head"],
            "objects": objects,
        }
        if source["reviewedPublicKnowledge"] is not None:
            checksum_payload["reviewedPublicKnowledge"] = source["reviewedPublicKnowledge"]
        if source["signedNostr"] is not None:
            checksum_payload["signedNostr"] = source["signedNostr"]
        if source["stagingParticipantGateway"] is not None:
            checksum_payload["stagingParticipantGateway"] = {
                key: value
                for key, value in source["stagingParticipantGateway"].items()
                if key != "civicProjectionRoute"
            }
        integrity_path = render / "integrity.json"
        integrity = json.loads(integrity_path.read_text())
        integrity["desiredRenderSha256"] = VERIFIER.digest(checksum_payload)
        integrity["networkBoundaryMigrationSha256"] = VERIFIER.digest(migration)
        integrity_path.write_text(json.dumps(integrity, indent=2) + "\n")

    def disable_public_mecky_reviewed_web_source(self, root: Path) -> None:
        """Restore the exact predecessor route for historical transition fixtures."""
        source = VERIFIER.verify_tree(root)
        if not source["publicMeckyReviewedWebSource"]:
            return
        render = root / "reviewed-render/roebel-staging"

        deployment_path = render / "public-mecky/deployment.json"
        deployment = json.loads(deployment_path.read_text())
        environment = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
        environment[:] = [
            item
            for item in environment
            if item["name"] != "MECKY_REVIEWED_KNOWLEDGE_BASE_URL"
        ]
        deployment_path.write_text(json.dumps(deployment, indent=2) + "\n")

        signed_nostr = source["signedNostr"] is not None
        public_policy = VERIFIER.expected_public_mecky_network_policy(
            True,
            signed_nostr,
            False,
        )
        (render / "public-mecky/networkpolicy.json").write_text(
            json.dumps(public_policy, indent=2) + "\n",
        )
        civic_projection = bool(
            source["stagingParticipantGateway"]
            and source["stagingParticipantGateway"]["civicProjectionRoute"]
        )
        web_policy = VERIFIER.expected_web_network_policy(
            civic_projection,
            source["webTracerFeed"],
            False,
        )
        (render / "web/networkpolicy.json").write_text(
            json.dumps(web_policy, indent=2) + "\n",
        )

        migration = copy.deepcopy(source["migration"])
        migration["boundary"].pop("publicMeckyReviewedWebSource", None)
        next(
            item
            for item in migration["objects"]
            if item["kind"] == "NetworkPolicy"
            and item["name"] == "roebel-web-presentation"
        )["sha256"] = VERIFIER.digest(web_policy)
        public_receipts = [
            item
            for item in migration["objects"]
            if item["kind"] == "NetworkPolicy"
            and item["name"] == "public-mecky-chat-from-web"
            and item["namespace"] == "stadtstack-roebel-staging-lab"
        ]
        if signed_nostr:
            self.assertEqual(len(public_receipts), 1)
            public_receipts[0]["sha256"] = VERIFIER.digest(public_policy)
        else:
            migration["objects"][:] = [
                item
                for item in migration["objects"]
                if item not in public_receipts
            ]
        (render / "network-boundary-migration.json").write_text(
            json.dumps(migration, indent=2) + "\n",
        )

        objects = copy.deepcopy(source["objects"])
        objects[0] = deployment
        objects[2] = public_policy
        objects[4] = web_policy
        checksum_payload: dict[str, object] = {
            "nextEnvironmentHead": source["head"],
            "objects": objects,
        }
        if source["reviewedPublicKnowledge"] is not None:
            checksum_payload["reviewedPublicKnowledge"] = source["reviewedPublicKnowledge"]
        if source["signedNostr"] is not None:
            checksum_payload["signedNostr"] = source["signedNostr"]
        if source["stagingParticipantGateway"] is not None:
            checksum_payload["stagingParticipantGateway"] = {
                key: value
                for key, value in source["stagingParticipantGateway"].items()
                if key != "civicProjectionRoute"
            }
        integrity_path = render / "integrity.json"
        integrity = json.loads(integrity_path.read_text())
        integrity["desiredRenderSha256"] = VERIFIER.digest(checksum_payload)
        integrity["networkBoundaryMigrationSha256"] = VERIFIER.digest(migration)
        integrity_path.write_text(json.dumps(integrity, indent=2) + "\n")

    def normalize_no_participant_gateway_seed(self, destination: Path) -> None:
        """Remove only the closed participant subtree from copied mutation fixtures."""
        participant = destination / VERIFIER.PARTICIPANT_GATEWAY_ROOT
        if not participant.is_dir():
            return
        shutil.rmtree(participant)
        web_path = destination / "reviewed-render/roebel-staging/web/deployment.json"
        web = json.loads(web_path.read_text())
        env = web["spec"]["template"]["spec"]["containers"][0]["env"]
        env[:] = [
            item
            for item in env
            if item["name"] not in {
                "STADTSTACK_CIVIC_PROJECTION_UPSTREAM_URL",
                VERIFIER.TRACER_FEED_URL_ENV["name"],
                VERIFIER.TRACER_FEED_ANON_ENV["name"],
            }
        ]
        web_path.write_text(json.dumps(web, indent=2) + "\n")
        network_policy_path = (
            destination / "reviewed-render/roebel-staging/web/networkpolicy.json"
        )
        network_policy_path.write_text(
            json.dumps(VERIFIER.expected_web_network_policy(False), indent=2) + "\n",
        )
        self.refresh_current_integrity(destination)

    def normalize_inert_participant_seed(self, destination: Path) -> None:
        """Keep transition fixtures anchored to the exact current v4 predecessor."""
        policy = VERIFIER.PARTICIPANT_POLICY.activation_policy_descriptor()
        policy_path = destination / VERIFIER.PARTICIPANT_POLICY.POLICY_PATH
        policy_path.write_text(
            json.dumps(policy, indent=2) + "\n",
        )
        contract_path = destination / "policy/repository-contract.json"
        contract = json.loads(contract_path.read_text())
        contract["ephemeralTracerDataPlaneBoundary"] = (
            VERIFIER.TRACER_DATA_PLANE.contract_boundary(
                VERIFIER.TRACER_DATA_PLANE.LEGACY_PRODUCT_ARTIFACTS,
            )
        )
        issuer = VERIFIER.verify_eligibility_issuer_materialization_policy(
            destination,
        )
        gateway = contract["stagingParticipantGatewayBoundary"]
        gateway["activationReady"] = policy["activationReady"]
        gateway["eligibilityIssuerMaterialization"] = (
            VERIFIER.eligibility_issuer_contract_projection(issuer)
        )
        http = VERIFIER.participant_gateway_http_contract(policy)
        gateway["exactGatewayPaths"] = http["exactGatewayPaths"]
        gateway["methodPathMatrix"] = http["methodPathMatrix"]
        gateway["schemaVersion"] = http["schemaVersion"]
        gateway.pop("dynamicGetPrefixes", None)
        gateway.pop("routeProbeSamples", None)
        gateway.pop("syntheticCitizenAdoption", None)
        contract_path.write_text(json.dumps(contract, indent=2) + "\n")

    def refresh_participant_gateway_integrity(
        self,
        root: Path,
        source: dict,
        runtime_pin: dict,
        resources: dict,
        migration: dict,
    ) -> None:
        """Bind one exact gateway render into the existing release checksum."""
        gateway = {
            "runtimePin": copy.deepcopy(runtime_pin),
            **copy.deepcopy(resources),
        }
        payload: dict[str, object] = {
            "nextEnvironmentHead": source["head"],
            "objects": source["objects"],
            "stagingParticipantGateway": gateway,
        }
        if source["reviewedPublicKnowledge"] is not None:
            payload["reviewedPublicKnowledge"] = source["reviewedPublicKnowledge"]
        if source["signedNostr"] is not None:
            payload["signedNostr"] = source["signedNostr"]
        integrity_path = root / VERIFIER.RENDER_ROOT / "integrity.json"
        integrity = json.loads(integrity_path.read_text())
        integrity["desiredRenderSha256"] = VERIFIER.digest(payload)
        integrity["networkBoundaryMigrationSha256"] = VERIFIER.digest(migration)
        integrity_path.write_text(json.dumps(integrity, indent=2) + "\n")

    def normalize_citizen_adoption_c1_seed(self, destination: Path) -> None:
        """Reverse only C2, yielding the exact four-artifact/v4 C1 tree."""
        source = VERIFIER.verify_tree(destination)
        self.assertTrue(VERIFIER.tracer_citizen_adoption_enabled(source))
        legacy_policy = VERIFIER.PARTICIPANT_POLICY.activation_policy_descriptor()
        if source["stagingParticipantGatewayPolicy"] == legacy_policy:
            return
        self.assertEqual(
            source["stagingParticipantGatewayPolicy"],
            VERIFIER.PARTICIPANT_POLICY.APPROVED_NEXT_ACTIVATION_POLICY,
        )
        civic_projection = source["stagingParticipantGateway"]["civicProjectionRoute"]
        runtime_pin = VERIFIER.expected_participant_gateway_runtime_release_pin(
            legacy_policy,
        )
        resources = VERIFIER.expected_participant_gateway_resources(
            runtime_pin,
            legacy_policy,
            civic_projection_route=civic_projection,
        )

        policy_path = destination / VERIFIER.PARTICIPANT_POLICY.POLICY_PATH
        policy_path.write_text(json.dumps(legacy_policy, indent=2) + "\n")
        contract_path = destination / "policy/repository-contract.json"
        contract = json.loads(contract_path.read_text())
        contract["ephemeralTracerDataPlaneBoundary"] = (
            VERIFIER.TRACER_DATA_PLANE.contract_boundary(
                VERIFIER.TRACER_DATA_PLANE.PRODUCT_ARTIFACTS,
            )
        )
        gateway_contract = contract["stagingParticipantGatewayBoundary"]
        gateway_contract["activationReady"] = legacy_policy["activationReady"]
        issuer = VERIFIER.verify_eligibility_issuer_materialization_policy(
            destination,
        )
        gateway_contract["eligibilityIssuerMaterialization"] = (
            VERIFIER.eligibility_issuer_contract_projection(issuer)
        )
        http = VERIFIER.participant_gateway_http_contract(legacy_policy)
        gateway_contract["exactGatewayPaths"] = http["exactGatewayPaths"]
        gateway_contract["methodPathMatrix"] = http["methodPathMatrix"]
        gateway_contract["schemaVersion"] = http["schemaVersion"]
        gateway_contract.pop("dynamicGetPrefixes", None)
        gateway_contract.pop("routeProbeSamples", None)
        contract_path.write_text(json.dumps(contract, indent=2) + "\n")

        participant = destination / VERIFIER.PARTICIPANT_GATEWAY_ROOT
        (participant / "runtime-pin.json").write_text(
            json.dumps(runtime_pin, indent=2) + "\n",
        )
        (participant / "deployment.json").write_text(
            json.dumps(resources["deployment"], indent=2) + "\n",
        )
        (participant / "ingress.json").write_text(
            json.dumps(resources["ingress"], indent=2) + "\n",
        )

        migration_path = destination / VERIFIER.RENDER_ROOT / "network-boundary-migration.json"
        migration = copy.deepcopy(source["migration"])
        ingress_boundary = migration["boundary"]["ingress"]
        ingress_boundary["exactGatewayPaths"] = http["exactGatewayPaths"]
        ingress_boundary["exactPostPaths"] = http["methodPathMatrix"]["POST"]
        ingress_boundary["gatewayMethodPathMatrix"] = http["methodPathMatrix"]
        ingress_boundary.pop("dynamicGetPrefixes", None)
        ingress_boundary.pop("routeProbeSamples", None)
        for kind, resource in (
            ("Deployment", resources["deployment"]),
            ("Ingress", resources["ingress"]),
        ):
            receipt = next(
                item
                for item in migration["objects"]
                if item["kind"] == kind
                and item["name"] == VERIFIER.PARTICIPANT_GATEWAY_NAME
            )
            receipt["sha256"] = VERIFIER.digest(resource)
        migration_path.write_text(json.dumps(migration, indent=2) + "\n")
        self.refresh_participant_gateway_integrity(
            destination,
            source,
            runtime_pin,
            resources,
            migration,
        )
        normalized = VERIFIER.verify_tree(destination)
        self.assertEqual(
            normalized["stagingParticipantGatewayPolicy"],
            legacy_policy,
        )
        self.assertTrue(VERIFIER.tracer_citizen_adoption_enabled(normalized))

    def citizen_adoption_sql_fixture_bytes(self) -> bytes:
        """Decode and verify the sole protected C1 SQL successor artifact."""
        compressed = base64.b64decode(
            "".join(CITIZEN_ADOPTION_SQL_ZLIB_BASE64),
            validate=True,
        )
        value = zlib.decompress(compressed)
        expected = next(
            digest
            for filename, _source, digest in VERIFIER.TRACER_DATA_PLANE.PRODUCT_ARTIFACTS
            if filename == "75-staging-citizen-adoption.sql"
        )
        self.assertEqual(VERIFIER.bytes_digest(value), expected)
        self.assertEqual(len(value), 62015)
        return value

    def materialize_citizen_adoption_c1_seed(self, destination: Path) -> None:
        """Apply only the exact six-file C1 successor to a full A tree."""
        source = VERIFIER.verify_tree(destination)
        self.assertEqual(
            source["stagingParticipantGatewayPolicy"],
            VERIFIER.PARTICIPANT_POLICY.STATIC_ACTIVATION_POLICY,
        )
        if VERIFIER.tracer_citizen_adoption_enabled(source):
            return
        tracer = destination / VERIFIER.TRACER_DATA_PLANE.RENDER_ROOT
        sql_path = destination / VERIFIER.CITIZEN_ADOPTION_SQL_PATH
        sql_path.write_bytes(self.citizen_adoption_sql_fixture_bytes())
        (tracer / "runtime-pin.json").write_text(
            json.dumps(
                VERIFIER.TRACER_DATA_PLANE.runtime_pin(
                    VERIFIER.TRACER_DATA_PLANE.PRODUCT_SOURCE_REVISION,
                    VERIFIER.TRACER_DATA_PLANE.PRODUCT_ARTIFACTS,
                ),
                indent=2,
            )
            + "\n",
        )
        (tracer / "postgres-deployment.json").write_text(
            json.dumps(
                VERIFIER.TRACER_DATA_PLANE.expected_postgres_deployment(
                    VERIFIER.TRACER_DATA_PLANE.PRODUCT_ARTIFACTS,
                ),
                indent=2,
            )
            + "\n",
        )
        (tracer / "kustomization.yaml").write_text(
            VERIFIER.TRACER_DATA_PLANE.kustomization_text(
                VERIFIER.TRACER_DATA_PLANE.PRODUCT_ARTIFACTS,
            ),
        )
        (tracer / "bootstrap/zz-roebel-tracer.sh").write_text(
            VERIFIER.TRACER_DATA_PLANE.bootstrap_verify_script(
                VERIFIER.TRACER_DATA_PLANE.PRODUCT_ARTIFACTS,
            ),
        )
        contract_path = destination / "policy/repository-contract.json"
        contract = json.loads(contract_path.read_text())
        contract["ephemeralTracerDataPlaneBoundary"] = (
            VERIFIER.TRACER_DATA_PLANE.contract_boundary(
                VERIFIER.TRACER_DATA_PLANE.PRODUCT_ARTIFACTS,
            )
        )
        contract_path.write_text(json.dumps(contract, indent=2) + "\n")
        normalized = VERIFIER.verify_tree(destination)
        self.assertTrue(VERIFIER.tracer_citizen_adoption_enabled(normalized))

    def materialize_citizen_adoption_c2_seed(self, destination: Path) -> None:
        """Apply only the exact seven-file C2 successor to a full C1 tree."""
        source = VERIFIER.verify_tree(destination)
        self.assertTrue(VERIFIER.tracer_citizen_adoption_enabled(source))
        successor_policy = (
            VERIFIER.PARTICIPANT_POLICY.approved_next_activation_policy_descriptor()
        )
        if source["stagingParticipantGatewayPolicy"] == successor_policy:
            return
        self.assertEqual(
            source["stagingParticipantGatewayPolicy"],
            VERIFIER.PARTICIPANT_POLICY.STATIC_ACTIVATION_POLICY,
        )
        civic_projection = source["stagingParticipantGateway"]["civicProjectionRoute"]
        runtime_pin = VERIFIER.PARTICIPANT_POLICY.expected_runtime_pin(
            successor_policy,
        )
        resources = VERIFIER.expected_participant_gateway_resources(
            runtime_pin,
            successor_policy,
            civic_projection_route=civic_projection,
        )
        policy_path = destination / VERIFIER.PARTICIPANT_POLICY.POLICY_PATH
        policy_path.write_text(json.dumps(successor_policy, indent=2) + "\n")

        contract_path = destination / "policy/repository-contract.json"
        contract = json.loads(contract_path.read_text())
        gateway_contract = contract["stagingParticipantGatewayBoundary"]
        gateway_contract["activationReady"] = successor_policy["activationReady"]
        issuer = VERIFIER.verify_eligibility_issuer_materialization_policy(
            destination,
        )
        gateway_contract["eligibilityIssuerMaterialization"] = (
            VERIFIER.eligibility_issuer_contract_projection(issuer)
        )
        http = VERIFIER.participant_gateway_http_contract(successor_policy)
        gateway_contract["exactGatewayPaths"] = http["exactGatewayPaths"]
        gateway_contract["dynamicGetPrefixes"] = http["dynamicGetPrefixes"]
        gateway_contract["methodPathMatrix"] = http["methodPathMatrix"]
        gateway_contract["routeProbeSamples"] = http["routeProbeSamples"]
        gateway_contract["schemaVersion"] = http["schemaVersion"]
        contract_path.write_text(json.dumps(contract, indent=2) + "\n")

        participant = destination / VERIFIER.PARTICIPANT_GATEWAY_ROOT
        (participant / "runtime-pin.json").write_text(
            json.dumps(runtime_pin, indent=2) + "\n",
        )
        (participant / "deployment.json").write_text(
            json.dumps(resources["deployment"], indent=2) + "\n",
        )
        (participant / "ingress.json").write_text(
            json.dumps(resources["ingress"], indent=2) + "\n",
        )

        migration_path = (
            destination / VERIFIER.RENDER_ROOT / "network-boundary-migration.json"
        )
        migration = copy.deepcopy(source["migration"])
        ingress_boundary = migration["boundary"]["ingress"]
        ingress_boundary["exactGatewayPaths"] = http["exactGatewayPaths"]
        ingress_boundary["exactPostPaths"] = http["methodPathMatrix"]["POST"]
        ingress_boundary["dynamicGetPrefixes"] = http["dynamicGetPrefixes"]
        ingress_boundary["gatewayMethodPathMatrix"] = http["methodPathMatrix"]
        ingress_boundary["routeProbeSamples"] = http["routeProbeSamples"]
        for kind, resource in (
            ("Deployment", resources["deployment"]),
            ("Ingress", resources["ingress"]),
        ):
            receipt = next(
                item
                for item in migration["objects"]
                if item["kind"] == kind
                and item["name"] == VERIFIER.PARTICIPANT_GATEWAY_NAME
            )
            receipt["sha256"] = VERIFIER.digest(resource)
        migration_path.write_text(json.dumps(migration, indent=2) + "\n")
        self.refresh_participant_gateway_integrity(
            destination,
            source,
            runtime_pin,
            resources,
            migration,
        )
        normalized = VERIFIER.verify_tree(destination)
        self.assertEqual(
            normalized["stagingParticipantGatewayPolicy"],
            successor_policy,
        )
        self.assertTrue(VERIFIER.tracer_citizen_adoption_enabled(normalized))

    def normalize_citizen_adoption_a_seed(self, destination: Path) -> None:
        """Reverse C1 after C2, yielding exact v4/three-artifact A."""
        source = VERIFIER.verify_tree(destination)
        if (
            source["stagingParticipantGatewayPolicy"]
            == VERIFIER.PARTICIPANT_POLICY.APPROVED_NEXT_ACTIVATION_POLICY
        ):
            self.normalize_citizen_adoption_c1_seed(destination)
            source = VERIFIER.verify_tree(destination)
        self.assertEqual(
            source["stagingParticipantGatewayPolicy"],
            VERIFIER.PARTICIPANT_POLICY.STATIC_ACTIVATION_POLICY,
        )
        if not VERIFIER.tracer_citizen_adoption_enabled(source):
            return

        tracer = destination / VERIFIER.TRACER_DATA_PLANE.RENDER_ROOT
        (destination / VERIFIER.CITIZEN_ADOPTION_SQL_PATH).unlink()
        (tracer / "runtime-pin.json").write_text(
            json.dumps(
                VERIFIER.TRACER_DATA_PLANE.runtime_pin(
                    VERIFIER.TRACER_DATA_PLANE.LEGACY_PRODUCT_SOURCE_REVISION,
                    VERIFIER.TRACER_DATA_PLANE.LEGACY_PRODUCT_ARTIFACTS,
                ),
                indent=2,
            )
            + "\n",
        )
        (tracer / "postgres-deployment.json").write_text(
            json.dumps(
                VERIFIER.TRACER_DATA_PLANE.expected_postgres_deployment(
                    VERIFIER.TRACER_DATA_PLANE.LEGACY_PRODUCT_ARTIFACTS,
                ),
                indent=2,
            )
            + "\n",
        )
        (tracer / "kustomization.yaml").write_text(
            VERIFIER.TRACER_DATA_PLANE.kustomization_text(
                VERIFIER.TRACER_DATA_PLANE.LEGACY_PRODUCT_ARTIFACTS,
            ),
        )
        (tracer / "bootstrap/zz-roebel-tracer.sh").write_text(
            VERIFIER.TRACER_DATA_PLANE.bootstrap_verify_script(
                VERIFIER.TRACER_DATA_PLANE.LEGACY_PRODUCT_ARTIFACTS,
            ),
        )
        contract_path = destination / "policy/repository-contract.json"
        contract = json.loads(contract_path.read_text())
        contract["ephemeralTracerDataPlaneBoundary"] = (
            VERIFIER.TRACER_DATA_PLANE.contract_boundary(
                VERIFIER.TRACER_DATA_PLANE.LEGACY_PRODUCT_ARTIFACTS,
            )
        )
        contract_path.write_text(json.dumps(contract, indent=2) + "\n")
        normalized = VERIFIER.verify_tree(destination)
        self.assertFalse(VERIFIER.tracer_citizen_adoption_enabled(normalized))

    def citizen_adoption_sequence_roots(
        self,
    ) -> tuple[tempfile.TemporaryDirectory[str], Path, Path, Path]:
        """Build exact full-tree A, C1, and C2 from any admitted sequence state."""
        source = VERIFIER.verify_tree(ROOT)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        fixture_root = Path(temp.name)
        ignored = shutil.ignore_patterns(".git", "__pycache__", "*.pyc")
        phase_a = fixture_root / "a"
        c1 = fixture_root / "c1"
        c2 = fixture_root / "c2"
        if (
            source["stagingParticipantGatewayPolicy"]
            == VERIFIER.PARTICIPANT_POLICY.APPROVED_NEXT_ACTIVATION_POLICY
        ):
            self.assertTrue(VERIFIER.tracer_citizen_adoption_enabled(source))
            shutil.copytree(ROOT, c2, ignore=ignored)
            self.normalize_synthetic_citizen_pass_seed(c2)
            shutil.copytree(c2, c1)
            self.normalize_citizen_adoption_c1_seed(c1)
            shutil.copytree(c1, phase_a)
            self.normalize_citizen_adoption_a_seed(phase_a)
        elif VERIFIER.tracer_citizen_adoption_enabled(source):
            self.assertEqual(
                source["stagingParticipantGatewayPolicy"],
                VERIFIER.PARTICIPANT_POLICY.STATIC_ACTIVATION_POLICY,
            )
            shutil.copytree(ROOT, c1, ignore=ignored)
            shutil.copytree(c1, phase_a)
            self.normalize_citizen_adoption_a_seed(phase_a)
            shutil.copytree(c1, c2)
            self.materialize_citizen_adoption_c2_seed(c2)
        else:
            self.assertEqual(
                source["stagingParticipantGatewayPolicy"],
                VERIFIER.PARTICIPANT_POLICY.STATIC_ACTIVATION_POLICY,
            )
            shutil.copytree(ROOT, phase_a, ignore=ignored)
            shutil.copytree(phase_a, c1)
            self.materialize_citizen_adoption_c1_seed(c1)
            shutil.copytree(c1, c2)
            self.materialize_citizen_adoption_c2_seed(c2)
        return temp, phase_a, c1, c2

    def current_v4_participant_fixture(
        self,
    ) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        """Copy ROOT and normalize it to the full v4/three-artifact A tree."""
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        destination = Path(temp.name) / "candidate"
        shutil.copytree(
            ROOT,
            destination,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        )
        self.normalize_synthetic_citizen_pass_seed(destination)
        self.normalize_citizen_adoption_a_seed(destination)
        return temp, destination

    def current_base(self) -> Path:
        temp, base = self.candidate()
        self.addCleanup(temp.cleanup)
        return base

    def protected_participant_candidate(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        """Build full-tree A and pin the exact v4 release predecessor."""
        temp, destination = self.current_v4_participant_fixture()
        self.normalize_participant_gateway_runtime_predecessor(destination)
        return temp, destination

    def normalize_participant_gateway_runtime_predecessor(self, root: Path) -> None:
        """Restore the exact gateway predecessor when ROOT already has the release."""
        protected = VERIFIER.verify_tree(root)
        policy = protected["stagingParticipantGatewayPolicy"]
        predecessor = VERIFIER.expected_participant_gateway_runtime_release_predecessor_pin(policy)
        current = protected["stagingParticipantGateway"]["runtimePin"]
        if current == predecessor:
            return
        self.assertEqual(
            current,
            VERIFIER.expected_participant_gateway_runtime_release_pin(policy),
        )
        self.render_participant_gateway_runtime_pin(root, predecessor)

    def normalize_participant_gateway_runtime_activation(self, root: Path) -> None:
        """Restore the immutable activation pin for historical tracer fixtures."""
        protected = VERIFIER.verify_tree(root)
        policy = protected["stagingParticipantGatewayPolicy"]
        activation = VERIFIER.PARTICIPANT_POLICY.expected_runtime_pin(policy)
        current = protected["stagingParticipantGateway"]["runtimePin"]
        if current == activation:
            return
        self.assertIn(
            current,
            VERIFIER.participant_gateway_runtime_release_pins(policy),
        )
        self.render_participant_gateway_runtime_pin(root, activation)

    def render_participant_gateway_runtime_pin(
        self,
        root: Path,
        runtime_pin: dict[str, object],
    ) -> None:
        """Render one admitted gateway pin and its two integrity bindings."""
        protected = VERIFIER.verify_tree(root)
        policy = protected["stagingParticipantGatewayPolicy"]
        civic_projection = protected["stagingParticipantGateway"]["civicProjectionRoute"]
        resources = VERIFIER.expected_participant_gateway_resources(
            runtime_pin,
            policy,
            civic_projection_route=civic_projection,
        )
        render = root / VERIFIER.RENDER_ROOT
        participant = root / VERIFIER.PARTICIPANT_GATEWAY_ROOT
        (participant / "runtime-pin.json").write_text(
            json.dumps(runtime_pin, indent=2) + "\n",
        )
        (participant / "deployment.json").write_text(
            json.dumps(resources["deployment"], indent=2) + "\n",
        )

        migration_path = render / "network-boundary-migration.json"
        migration = copy.deepcopy(protected["migration"])
        deployment_receipt = next(
            item
            for item in migration["objects"]
            if item["kind"] == "Deployment"
            and item["name"] == VERIFIER.PARTICIPANT_GATEWAY_NAME
        )
        deployment_receipt["sha256"] = VERIFIER.digest(resources["deployment"])
        migration_path.write_text(json.dumps(migration, indent=2) + "\n")

        gateway = {
            key: copy.deepcopy(value)
            for key, value in protected["stagingParticipantGateway"].items()
            if key != "civicProjectionRoute"
        }
        gateway["runtimePin"] = runtime_pin
        gateway["deployment"] = resources["deployment"]
        payload: dict[str, object] = {
            "nextEnvironmentHead": protected["head"],
            "objects": protected["objects"],
            "stagingParticipantGateway": gateway,
        }
        if protected["reviewedPublicKnowledge"] is not None:
            payload["reviewedPublicKnowledge"] = protected["reviewedPublicKnowledge"]
        if protected["signedNostr"] is not None:
            payload["signedNostr"] = protected["signedNostr"]
        integrity_path = render / "integrity.json"
        integrity = json.loads(integrity_path.read_text())
        integrity["desiredRenderSha256"] = VERIFIER.digest(payload)
        integrity["networkBoundaryMigrationSha256"] = VERIFIER.digest(migration)
        integrity_path.write_text(json.dumps(integrity, indent=2) + "\n")

    def apply_participant_gateway_runtime_release(self, root: Path) -> None:
        """Render the exact successor and recompute only the desired checksum."""
        predecessor = VERIFIER.verify_tree(root)
        policy = predecessor["stagingParticipantGatewayPolicy"]
        successor = VERIFIER.expected_participant_gateway_runtime_release_pin(policy)
        self.render_participant_gateway_runtime_pin(root, successor)

    def participant_activation_policy_transition(self, root: Path) -> None:
        policy = (
            VERIFIER.PARTICIPANT_POLICY.approved_next_activation_policy_descriptor()
        )
        policy_path = root / VERIFIER.PARTICIPANT_POLICY.POLICY_PATH
        policy_path.write_text(
            json.dumps(policy, indent=2) + "\n",
        )
        contract_path = root / "policy/repository-contract.json"
        contract = json.loads(contract_path.read_text())
        gateway = contract["stagingParticipantGatewayBoundary"]
        gateway["activationReady"] = True
        http = VERIFIER.participant_gateway_http_contract(policy)
        gateway["exactGatewayPaths"] = http["exactGatewayPaths"]
        gateway["dynamicGetPrefixes"] = http["dynamicGetPrefixes"]
        gateway["methodPathMatrix"] = http["methodPathMatrix"]
        gateway["routeProbeSamples"] = http["routeProbeSamples"]
        gateway["schemaVersion"] = http["schemaVersion"]
        contract_path.write_text(json.dumps(contract, indent=2) + "\n")

    def signed_nostr_pin(self, root: Path) -> dict[str, object]:
        render = root / "reviewed-render/roebel-staging"
        publisher_pin = {
            "schemaVersion": "roebel_e2e_runtime_pin_v1",
            "sourceRevision": "b" * 40,
            "civicAuthority": "none",
            "deploymentEffect": False,
            "components": [
                {
                    "component": "roebel-e2e-workbench",
                    "image": "ghcr.io/giraeffleaeffle/roebel-e2e-workbench",
                    "manifestDigest": "sha256:" + "c" * 64,
                    "provenance": {"id": "workbench-provenance", "url": "https://github.com/GiraeffleAeffle/Roebel-App/actions/runs/1"},
                    "sbomAttestation": {"id": "workbench-sbom", "url": "https://github.com/GiraeffleAeffle/Roebel-App/actions/runs/1"},
                    "workflowIdentity": VERIFIER.SIGNED_NOSTR_WORKFLOW,
                },
                {
                    "component": "roebel-staging-relay",
                    "image": "ghcr.io/giraeffleaeffle/roebel-staging-relay",
                    "manifestDigest": "sha256:" + "d" * 64,
                    "provenance": {"id": "relay-provenance", "url": "https://github.com/GiraeffleAeffle/Roebel-App/actions/runs/1"},
                    "sbomAttestation": {"id": "relay-sbom", "url": "https://github.com/GiraeffleAeffle/Roebel-App/actions/runs/1"},
                    "workflowIdentity": VERIFIER.SIGNED_NOSTR_WORKFLOW,
                },
            ],
        }
        return {
            "schemaVersion": "roebel_signed_nostr_activation_render_pin_v1",
            "publisherPin": publisher_pin,
            "publisherPinCanonicalSha256": VERIFIER.digest(publisher_pin),
            "activationEvidence": {
                "status": "pending-separate-review",
                "gnosisRpcEgress": None,
                "fluxIdentity": None,
                "anonymousDigestPullReceipts": None,
            },
            "rollback": {
                "fromRender": "reviewed-public-knowledge",
                "integritySha256": VERIFIER.bytes_digest((render / "integrity.json").read_bytes()),
                "webIngressSha256": VERIFIER.bytes_digest((render / "web/ingress.json").read_bytes()),
                "publicMeckyNetworkPolicySha256": VERIFIER.bytes_digest((render / "public-mecky/networkpolicy.json").read_bytes()),
                "boundaryReceiptSha256": VERIFIER.bytes_digest((render / "network-boundary-migration.json").read_bytes()),
            },
        }

    def signed_nostr_reviewed_pin(self, root: Path) -> dict[str, object]:
        pin = self.signed_nostr_pin(root)
        publisher = pin["publisherPin"]
        receipts: list[dict[str, object]] = []
        for component in publisher["components"]:
            receipt: dict[str, object] = {
                "schemaVersion": VERIFIER.SIGNED_NOSTR_ANONYMOUS_DIGEST_PULL_RECEIPT_SCHEMA,
                "canonicalEncoding": "canonical-json",
                "publisherPinCanonicalSha256": pin["publisherPinCanonicalSha256"],
                "component": component["component"],
                "imageRepository": component["image"],
                "manifestDigest": component["manifestDigest"],
                "sourceRevision": publisher["sourceRevision"],
                "authContext": "clean-empty-auth-config",
                "authConfigCanonicalSha256": VERIFIER.SIGNED_NOSTR_CLEAN_EMPTY_AUTH_CONFIG_SHA256,
                "resolverIdentity": "oras-resolve-anonymous",
                "resolvedManifestDigest": component["manifestDigest"],
            }
            receipt["receiptDigest"] = VERIFIER.digest(receipt)
            receipts.append(receipt)
        components: list[dict[str, object]] = []
        for index, component in enumerate(publisher["components"]):
            marker = chr(ord("a") + index)
            components.append({
                "component": component["component"],
                "imageRepository": component["image"],
                "manifestDigest": component["manifestDigest"],
                "provenance": {
                    "receiptId": component["provenance"]["id"],
                    "receiptUrl": component["provenance"]["url"],
                    "attestationDigest": "sha256:" + marker * 64,
                    "subjectDigest": component["manifestDigest"],
                },
                "sbomAttestation": {
                    "receiptId": component["sbomAttestation"]["id"],
                    "receiptUrl": component["sbomAttestation"]["url"],
                    "attestationDigest": "sha256:" + chr(ord("c") + index) * 64,
                    "subjectDigest": component["manifestDigest"],
                },
            })
        flux_bindings: list[dict[str, object]] = []
        for component in VERIFIER.SIGNED_NOSTR_FLUX_BINDING_ORDER:
            objects = VERIFIER.expected_signed_nostr_flux_objects(component)
            flux_bindings.append({
                "component": component,
                **{
                    name: {"object": value, "objectDigest": VERIFIER.digest(value)}
                    for name, value in objects.items()
                },
            })
        workbench_component = next(
            component for component in publisher["components"]
            if component["component"] == "roebel-e2e-workbench"
        )
        workbench_image = f"{workbench_component['image']}@{workbench_component['manifestDigest']}"
        proxy_deployment = VERIFIER.expected_signed_nostr_gnosis_private_proxy_deployment(workbench_image)
        proxy_service = VERIFIER.expected_signed_nostr_gnosis_private_proxy_service()
        proxy_policy = VERIFIER.expected_signed_nostr_gnosis_private_proxy_network_policy()
        workbench_policy = VERIFIER.expected_signed_nostr_workbench_network_policy()
        dns_tls = {
            "schemaVersion": VERIFIER.SIGNED_NOSTR_DNS_TLS_EVIDENCE_SCHEMA,
            "canonicalEncoding": "canonical-json",
            "resolverIdentity": "reviewed-doh-resolver",
            "resolutionMethod": "dns-over-https-a-and-aaaa",
            "queriedHost": VERIFIER.SIGNED_NOSTR_GNOSIS_UPSTREAM_HOST,
            "queriedPort": VERIFIER.SIGNED_NOSTR_GNOSIS_UPSTREAM_PORT,
            "observedAt": "2026-08-24T12:00:00Z",
            "validUntil": "2026-08-24T12:05:00Z",
            "maxAgeSeconds": 300,
            "addresses": {"a": ["34.111.230.52"], "aaaa": []},
            "tlsCertificate": {
                "serverName": VERIFIER.SIGNED_NOSTR_GNOSIS_UPSTREAM_HOST,
                "issuer": "reviewed-test-ca",
                "certificateSha256": "sha256:" + "e" * 64,
                "notBefore": "2026-08-01T00:00:00Z",
                "notAfter": "2026-11-01T00:00:00Z",
            },
        }
        managed_suspended = VERIFIER.expected_signed_nostr_managed_objects(
            publisher,
            suspended_flux=True,
        )
        managed_active = VERIFIER.expected_signed_nostr_managed_objects(
            publisher,
            suspended_flux=False,
        )
        preconditions: list[dict[str, object]] = []
        postconditions: list[dict[str, object]] = []
        for index, entry in enumerate(managed_suspended):
            target = VERIFIER.signed_nostr_object_target(entry["object"])
            preconditions.append({
                "objectId": entry["objectId"],
                "target": target,
                "desiredObjectDigest": VERIFIER.digest(entry["object"]),
                "state": "absent",
                "uid": None,
                "resourceVersion": None,
                "currentObjectDigest": None,
            })
            postconditions.append({
                "objectId": entry["objectId"],
                "target": target,
                "uid": f"00000000-0000-4000-8000-{index + 1:012d}",
                "resourceVersion": str(100 + index),
                "objectDigest": VERIFIER.digest(entry["object"]),
                "action": "created-by-atomic-post-after-verified-absence",
                "apiOperation": "POST-create",
                "requiredUid": None,
                "requiredResourceVersion": None,
                "conflictPolicy": "fail-on-http-409-no-adopt",
                "apiOutcome": "http-201-created",
            })
        bootstrap = {
            "schemaVersion": VERIFIER.SIGNED_NOSTR_BOOTSTRAP_RECEIPT_SCHEMA,
            "canonicalEncoding": "canonical-json",
            "status": "completed-exact-cas",
            "operationId": "10000000-0000-4000-8000-000000000001",
            "observedAt": "2026-08-24T12:01:00Z",
            "validUntil": "2026-08-24T12:06:00Z",
            "maxAgeSeconds": 300,
            "preconditionsCanonicalSha256": VERIFIER.digest(preconditions),
            "postconditions": postconditions,
            "postconditionsCanonicalSha256": VERIFIER.digest(postconditions),
            "kustomizationsInitiallySuspended": True,
            "authority": "one-time-cluster-admin-exact-targets",
            "effects": {
                "clusterMutation": True,
                "civicMutation": False,
                "secretRead": False,
                "secretWrite": False,
                "wildcardAuthority": False,
                "ssaPatchUsedForAbsentTargets": False,
                "absenceGuardSource": "atomic-post-create-http-409-no-adopt",
                "presentGuardSource": "uid-resourceVersion-bound-no-op",
            },
        }
        dns_tls_recheck = copy.deepcopy(dns_tls)
        dns_tls_recheck["observedAt"] = "2026-08-24T12:02:00Z"
        dns_tls_recheck["validUntil"] = "2026-08-24T12:07:00Z"
        live_recheck = {
            "schemaVersion": VERIFIER.SIGNED_NOSTR_LIVE_RECHECK_SCHEMA,
            "canonicalEncoding": "canonical-json",
            "status": "passed-no-drift",
            "checkedAt": "2026-08-24T12:02:00Z",
            "validUntil": "2026-08-24T12:07:00Z",
            "maxAgeSeconds": 300,
            "bootstrapReceiptCanonicalSha256": VERIFIER.digest(bootstrap),
            "objectStates": copy.deepcopy(postconditions),
            "objectStatesCanonicalSha256": VERIFIER.digest(postconditions),
            "boundaryState": VERIFIER.rollback_boundary_digest_record(pin["rollback"]),
            "dnsTlsRecheck": dns_tls_recheck,
        }
        suspended_by_id = {entry["objectId"]: entry for entry in managed_suspended}
        active_by_id = {entry["objectId"]: entry for entry in managed_active}
        post_by_id = {entry["objectId"]: entry for entry in postconditions}
        unsuspensions: list[dict[str, object]] = []
        for index, component in enumerate(VERIFIER.SIGNED_NOSTR_FLUX_BINDING_ORDER):
            object_id = f"flux/{component}/kustomization"
            before = suspended_by_id[object_id]["object"]
            after = active_by_id[object_id]["object"]
            live = post_by_id[object_id]
            unsuspensions.append({
                "objectId": object_id,
                "target": VERIFIER.signed_nostr_object_target(before),
                "requiredUid": live["uid"],
                "requiredResourceVersion": live["resourceVersion"],
                "beforeObjectDigest": VERIFIER.digest(before),
                "patch": {"op": "replace", "path": "/spec/suspend", "expected": True, "value": False},
                "postResourceVersion": str(1000 + index),
                "afterObjectDigest": VERIFIER.digest(after),
            })
        reconcile = {
            "schemaVersion": "roebel_signed_nostr_reconcile_activation_receipt_v1",
            "canonicalEncoding": "canonical-json",
            "status": "completed-after-live-recheck",
            "operationId": "20000000-0000-4000-8000-000000000001",
            "completedAt": "2026-08-24T12:03:00Z",
            "liveRecheckCanonicalSha256": VERIFIER.digest(live_recheck),
            "unsuspensions": unsuspensions,
            "unsuspensionsCanonicalSha256": VERIFIER.digest(unsuspensions),
            "effects": {
                "clusterMutation": True,
                "civicMutation": False,
                "secretRead": False,
                "secretWrite": False,
                "onlySuspendFieldChanged": True,
            },
        }
        rollback_contract = VERIFIER.expected_signed_nostr_rollback_contract(
            managed_suspended,
            bootstrap,
            reconcile,
            pin["rollback"],
        )
        pin["activationEvidence"] = {
            "schemaVersion": VERIFIER.SIGNED_NOSTR_ACTIVATION_EVIDENCE_SCHEMA,
            "canonicalEncoding": "canonical-json",
            "status": "reviewed",
            "publisherPinCanonicalSha256": pin["publisherPinCanonicalSha256"],
            "publisherSourceRevision": publisher["sourceRevision"],
            "publisherWorkflowIdentity": VERIFIER.SIGNED_NOSTR_WORKFLOW,
            "components": components,
            "fluxBindings": flux_bindings,
            "gnosisRpcEgress": {
                "chainId": 100,
                "upstream": {
                    "scheme": "https",
                    "host": VERIFIER.SIGNED_NOSTR_GNOSIS_UPSTREAM_HOST,
                    "port": VERIFIER.SIGNED_NOSTR_GNOSIS_UPSTREAM_PORT,
                    "pinnedIpv4Cidr": VERIFIER.SIGNED_NOSTR_GNOSIS_UPSTREAM_IPV4_CIDR,
                    "allowedMethods": list(VERIFIER.SIGNED_NOSTR_GNOSIS_ALLOWED_METHODS),
                    "dnsTlsEvidence": dns_tls,
                },
                "privateProxy": {
                    "name": VERIFIER.SIGNED_NOSTR_GNOSIS_PROXY_NAME,
                    "namespace": VERIFIER.SIGNED_NOSTR_WEB_NAMESPACE,
                    "port": VERIFIER.SIGNED_NOSTR_GNOSIS_PROXY_PORT,
                    "runtimeRole": "gnosis-rpc-proxy",
                    "deployment": {"object": proxy_deployment, "objectDigest": VERIFIER.digest(proxy_deployment)},
                    "service": {"object": proxy_service, "objectDigest": VERIFIER.digest(proxy_service)},
                    "networkPolicy": {"object": proxy_policy, "objectDigest": VERIFIER.digest(proxy_policy)},
                },
                "workbenchNetworkPolicy": {"object": workbench_policy, "objectDigest": VERIFIER.digest(workbench_policy)},
            },
            "anonymousDigestPullReceipts": receipts,
            "lifecycle": {
                "livePreconditions": preconditions,
                "bootstrapReceipt": bootstrap,
                "activationLiveRecheck": live_recheck,
                "reconcileActivationReceipt": reconcile,
                "rollbackContract": rollback_contract,
            },
        }
        return pin

    def signed_nostr_runtime(self, root: Path, reviewed: bool = False) -> None:
        pin = self.signed_nostr_reviewed_pin(root) if reviewed else self.signed_nostr_pin(root)
        parsed = VERIFIER.verify_signed_nostr_runtime_pin(pin)
        resources = VERIFIER.expected_signed_nostr_resources(parsed)
        signed_root = root / "reviewed-render/roebel-staging/signed-nostr"
        signed_root.mkdir()
        (signed_root / "runtime-pin.json").write_text(json.dumps(pin, indent=2) + "\n")
        for component, expected in resources.items():
            component_root = signed_root / component
            component_root.mkdir()
            (component_root / "deployment.json").write_text(json.dumps(expected["deployment"], indent=2) + "\n")
            (component_root / "service.json").write_text(json.dumps(expected["service"], indent=2) + "\n")
            (component_root / "networkpolicy.json").write_text(json.dumps(expected["networkPolicy"], indent=2) + "\n")
            if component == "workbench":
                (component_root / "gnosis-proxy-deployment.json").write_text(json.dumps(expected["gnosisProxyDeployment"], indent=2) + "\n")
                (component_root / "gnosis-proxy-service.json").write_text(json.dumps(expected["gnosisProxyService"], indent=2) + "\n")
                (component_root / "gnosis-proxy-networkpolicy.json").write_text(json.dumps(expected["gnosisProxyNetworkPolicy"], indent=2) + "\n")
            (component_root / "kustomization.yaml").write_text(expected["kustomization"])

    def signed_nostr_boundary_receipt(
        self,
        public_mecky_network_policy: dict[str, object],
        web_ingress: dict[str, object],
    ) -> dict[str, object]:
        return {
            "authority": "none",
            "boundary": {
                "ingress": {
                    "allowedMethods": ["GET", "HEAD", "POST"],
                    "exactPostPaths": [
                        "/api/chat/mecky",
                        "/stadtstack-test/api/session/admit",
                        "/stadtstack-test/api/signed-event",
                    ],
                    "apiReadOnlyPrefixes": ["/api/public-feed/", "/api/civic/v1/"],
                    "apiReadOnlyExactPaths": ["/api/notifications/unread-count"],
                    "apiReadOnlyMethods": ["GET", "HEAD"],
                    "readOnlyPrefix": "/stadtstack-test",
                    "resource": {
                        "kind": "Ingress",
                        "name": "roebel-web-presentation",
                        "namespace": VERIFIER.SIGNED_NOSTR_WEB_NAMESPACE,
                    },
                },
                "publicMeckyRelayEgress": {
                    "destinationNamespace": VERIFIER.SIGNED_NOSTR_NAMESPACE,
                    "destinationPorts": [18081],
                    "relays": ["citizen-relay", "agent-relay"],
                    "resource": {
                        "kind": "NetworkPolicy",
                        "name": "public-mecky-chat-from-web",
                        "namespace": VERIFIER.SIGNED_NOSTR_NAMESPACE,
                    },
                },
                "relays": {
                    "ingress": "workbench-only",
                    "ingressClass": "none",
                    "namespace": VERIFIER.SIGNED_NOSTR_NAMESPACE,
                    "persistentVolume": False,
                    "emptyDirSizeLimit": "128Mi",
                    "combinedPersistedBudgetBytes": 83886080,
                },
            },
            "evidence": {
                "gnosisRpcEgress": None,
                "fluxIdentity": None,
                "status": "pending-separate-review",
            },
            "effects": {
                "civicMutation": False,
                "clusterMutation": False,
                "secretRead": False,
                "secretWrite": False,
            },
            "objects": [
                {
                    "kind": "NetworkPolicy",
                    "name": "public-mecky-chat-from-web",
                    "namespace": VERIFIER.SIGNED_NOSTR_NAMESPACE,
                    "sha256": VERIFIER.digest(public_mecky_network_policy),
                },
                {
                    "kind": "Ingress",
                    "name": "roebel-web-presentation",
                    "namespace": VERIFIER.SIGNED_NOSTR_WEB_NAMESPACE,
                    "sha256": VERIFIER.digest(web_ingress),
                },
            ],
            "rbacBootstrap": {
                "createAllowed": False,
                "deleteAllowed": False,
                "listAllowed": False,
                "required": True,
                "roleNamespace": VERIFIER.SIGNED_NOSTR_WEB_NAMESPACE,
                "serviceAccount": {
                    "name": "roebel-web-reconciler",
                    "namespace": "flux-roebel-staging",
                },
                "watchAllowed": False,
                "rules": [
                    {
                        "apiGroups": ["networking.k8s.io"],
                        "resourceNames": ["roebel-web-presentation"],
                        "resources": ["networkpolicies"],
                        "verbs": ["get", "patch", "update"],
                    },
                    {
                        "apiGroups": ["networking.k8s.io"],
                        "resourceNames": ["roebel-web-presentation"],
                        "resources": ["ingresses"],
                        "verbs": ["get", "patch", "update"],
                    },
                ],
                "liveMutationPerformed": False,
            },
            "schemaVersion": "roebel_staging_signed_nostr_boundary_v1",
            "status": "blocked_pending_separately_reviewed_signed_nostr_evidence",
        }

    def make_signed_nostr_render(self, root: Path) -> dict[str, object]:
        render = root / "reviewed-render/roebel-staging"
        self.signed_nostr_runtime(root, reviewed=True)
        runtime_pin = json.loads((render / "signed-nostr/runtime-pin.json").read_text())
        evidence = runtime_pin["activationEvidence"]
        VERIFIER.SIGNED_NOSTR_APPROVED_ACTIVATION_EVIDENCE = copy.deepcopy(evidence)

        web_ingress = VERIFIER.expected_web_ingress(True)
        public_policy = VERIFIER.expected_public_mecky_network_policy(True, True)
        (render / "web/ingress.json").write_text(json.dumps(web_ingress, indent=2) + "\n")
        (render / "public-mecky/networkpolicy.json").write_text(
            json.dumps(public_policy, indent=2) + "\n"
        )
        boundary = self.signed_nostr_boundary_receipt(public_policy, web_ingress)
        (render / "network-boundary-migration.json").write_text(
            json.dumps(boundary, indent=2) + "\n"
        )

        signed = VERIFIER.verify_signed_nostr(root)
        integrity_path = render / "integrity.json"
        integrity = json.loads(integrity_path.read_text())
        integrity["desiredRenderSha256"] = VERIFIER.digest({
            "nextEnvironmentHead": json.loads((render / "head.json").read_text()),
            "objects": [
                json.loads((render / "public-mecky/deployment.json").read_text()),
                json.loads((render / "public-mecky/service.json").read_text()),
                public_policy,
                json.loads((render / "web/deployment.json").read_text()),
                json.loads((render / "web/networkpolicy.json").read_text()),
                web_ingress,
            ],
            "reviewedPublicKnowledge": VERIFIER.verify_reviewed_public_knowledge(root),
            "signedNostr": signed,
        })
        integrity["networkBoundaryMigrationSha256"] = VERIFIER.digest(boundary)
        integrity_path.write_text(json.dumps(integrity, indent=2) + "\n")
        return evidence

    def deactivation_receipt(
        self,
        activation_evidence: dict[str, object],
    ) -> dict[str, object]:
        contract = activation_evidence["lifecycle"]["rollbackContract"]
        completed = "2026-08-24T12:15:00Z"
        return {
            "schemaVersion": VERIFIER.SIGNED_NOSTR_DEACTIVATION_EVIDENCE_SCHEMA,
            "canonicalEncoding": "canonical-json",
            "status": "completed-and-verified",
            "startedAt": "2026-08-24T12:05:00Z",
            "completedAt": completed,
            "validUntil": "2026-08-24T12:20:00Z",
            "maxAgeSeconds": 300,
            "activationEvidenceCanonicalSha256": VERIFIER.digest(activation_evidence),
            "rollbackContractCanonicalSha256": VERIFIER.digest(contract),
            "stepReceipts": VERIFIER.expected_signed_nostr_deactivation_steps(contract),
            "boundaryVerification": {
                "verifiedAt": completed,
                "status": "exact-baseline-restored",
                **contract["boundaryBaseline"],
            },
            "absenceVerification": {
                "verifiedAt": completed,
                "status": "all-exact-targets-absent",
                "targets": contract["absenceVerificationTargets"],
            },
            "effects": {
                "clusterMutation": True,
                "civicMutation": False,
                "secretRead": False,
                "secretWrite": False,
                "uidMismatchObserved": False,
                "unrelatedObjectMutation": False,
            },
        }

    def nested_dicts(self, value: object):
        if isinstance(value, dict):
            yield value
            for child in value.values():
                yield from self.nested_dicts(child)
        elif isinstance(value, list):
            for child in value:
                yield from self.nested_dicts(child)

    def make_valid_transition(self, candidate: Path) -> None:
        render = candidate / "reviewed-render/roebel-staging"
        base_head = json.loads((render / "head.json").read_text())
        base_public = json.loads((render / "public-mecky/deployment.json").read_text())
        base_web = json.loads((render / "web/deployment.json").read_text())
        head = json.loads((render / "head.json").read_text())
        new_revision = "a" * 40
        new_release = "sha256:" + "b" * 64
        new_web_manifest = "sha256:" + "c" * 64
        head["promotionRevision"] = new_revision
        head["releaseSetDigest"] = new_release
        head["components"][1]["sourceRevision"] = new_revision
        head["components"][1]["manifestDigest"] = new_web_manifest
        (render / "head.json").write_text(json.dumps(head, indent=2) + "\n")

        public = json.loads((render / "public-mecky/deployment.json").read_text())
        public["metadata"]["annotations"]["stadtstack.io/release-set-sha256"] = new_release
        (render / "public-mecky/deployment.json").write_text(json.dumps(public, indent=2) + "\n")

        web = json.loads((render / "web/deployment.json").read_text())
        web["metadata"]["annotations"]["stadtstack.io/release-set-sha256"] = new_release
        web["metadata"]["annotations"]["stadtstack.io/source-revision"] = new_revision
        web["spec"]["template"]["metadata"]["annotations"]["stadtstack.io/source-revision"] = new_revision
        web["spec"]["template"]["spec"]["containers"][0]["image"] = (
            "ghcr.io/giraeffleaeffle/roebel-web-staging@" + new_web_manifest
        )
        (render / "web/deployment.json").write_text(json.dumps(web, indent=2) + "\n")

        integrity = json.loads((render / "integrity.json").read_text())
        integrity["releaseSetDigest"] = new_release
        service = json.loads((render / "public-mecky/service.json").read_text())
        network_policy = json.loads((render / "public-mecky/networkpolicy.json").read_text())
        web_network_policy = json.loads((render / "web/networkpolicy.json").read_text())
        web_ingress = json.loads((render / "web/ingress.json").read_text())
        migration = json.loads((render / "network-boundary-migration.json").read_text())
        integrity["desiredRenderSha256"] = VERIFIER.digest(
            {
                "nextEnvironmentHead": head,
                "objects": [
                    public,
                    service,
                    network_policy,
                    web,
                    web_network_policy,
                    web_ingress,
                ],
            }
        )
        integrity["networkBoundaryMigrationSha256"] = VERIFIER.digest(migration)
        (render / "integrity.json").write_text(json.dumps(integrity, indent=2) + "\n")

        live = json.loads((render / "live-preconditions.json").read_text())
        live["previousEnvironmentHead"] = base_head
        live["requiredLivePreconditions"][0]["currentImage"] = base_public["spec"]["template"]["spec"]["containers"][0]["image"]
        live["requiredLivePreconditions"][1]["currentImage"] = base_web["spec"]["template"]["spec"]["containers"][0]["image"]
        live["patches"][0]["operations"] = [
            {
                "op": "replace",
                "path": "/metadata/annotations/stadtstack.io~1release-set-sha256",
                "value": new_release,
            }
        ]
        live["patches"][1]["operations"] = [
            {
                "op": "replace",
                "path": "/metadata/annotations/stadtstack.io~1source-revision",
                "value": new_revision,
            },
            {
                "op": "replace",
                "path": "/metadata/annotations/stadtstack.io~1release-set-sha256",
                "value": new_release,
            },
            {
                "op": "replace",
                "path": "/spec/template/metadata/annotations/stadtstack.io~1source-revision",
                "value": new_revision,
            },
            {
                "op": "replace",
                "path": "/spec/template/spec/containers/0/image",
                "value": "ghcr.io/giraeffleaeffle/roebel-web-staging@" + new_web_manifest,
            },
        ]
        (render / "live-preconditions.json").write_text(json.dumps(live, indent=2) + "\n")

    def make_reviewed_knowledge_render(self, candidate: Path) -> None:
        render = candidate / "reviewed-render/roebel-staging"
        runtime_digest = VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_IMAGE_DIGEST
        revision = VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_SOURCE_REVISION
        pin = {
            "schemaVersion": "stadtstack_reviewed_public_knowledge_runtime_pin_v1",
            "component": "reviewed-public-knowledge-runtime",
            "sourceRevision": revision,
            "sourceTag": VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_SOURCE_TAG,
            "imageRepository": VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_IMAGE,
            "manifestDigest": runtime_digest,
            "workflowIdentity": VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_WORKFLOW,
            "slsaProvenance": {
                "issuer": "https://token.actions.githubusercontent.com",
                "publisherIdentity": VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_WORKFLOW,
                "predicateType": "https://slsa.dev/provenance/v1",
                "repository": "GiraeffleAeffle/stadtstack",
                "gitRef": "refs/heads/main",
                "sourceRevision": revision,
                "subjectDigest": runtime_digest,
                "attestationDigest": VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_SLSA_DIGEST,
            },
            "spdxSbom": {
                "format": "SPDX-2.3",
                "predicateType": "https://spdx.dev/Document/v2.3",
                "repository": "GiraeffleAeffle/stadtstack",
                "gitRef": "refs/heads/main",
                "sourceRevision": revision,
                "subjectDigest": runtime_digest,
                "attestationDigest": VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_SPDX_DIGEST,
            },
            "anonymousPublicPullReceipt": {
                "schemaVersion": "stadtstack_reviewed_public_knowledge_anonymous_digest_pull_receipt_v1",
                "canonicalEncoding": "canonical-json",
                "component": "reviewed-public-knowledge-runtime",
                "imageRepository": VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_IMAGE,
                "manifestDigest": runtime_digest,
                "sourceRevision": revision,
                "packageVisibility": "public",
                "authContext": "clean-empty-auth-config",
                "authConfigCanonicalSha256": VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_AUTH_DIGEST,
                "resolverIdentity": "oras-resolve-anonymous",
                "resolvedManifestDigest": runtime_digest,
                "receiptDigest": VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_RECEIPT_DIGEST,
            },
            "authorityBinding": "none",
            "deploymentEffect": False,
        }
        deployment = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "labels": VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_LABELS,
                "name": VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_NAME,
                "namespace": VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_NAMESPACE,
            },
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_LABELS},
                "template": {
                    "metadata": {"labels": VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_LABELS},
                    "spec": {
                        "automountServiceAccountToken": False,
                        "containers": [{
                            "env": [],
                            "image": VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_IMAGE + "@" + runtime_digest,
                            "imagePullPolicy": "IfNotPresent",
                            "livenessProbe": {
                                "failureThreshold": 3, "periodSeconds": 20, "successThreshold": 1,
                                "tcpSocket": {"port": "http"}, "timeoutSeconds": 3,
                            },
                            "name": VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_NAME,
                            "ports": [{"containerPort": 8080, "name": "http", "protocol": "TCP"}],
                            "readinessProbe": {
                                "failureThreshold": 3, "periodSeconds": 10, "successThreshold": 1,
                                "tcpSocket": {"port": "http"}, "timeoutSeconds": 3,
                            },
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "capabilities": {"drop": ["ALL"]},
                                "readOnlyRootFilesystem": True,
                            },
                            "startupProbe": {
                                "failureThreshold": 30, "periodSeconds": 2, "successThreshold": 1,
                                "tcpSocket": {"port": "http"}, "timeoutSeconds": 3,
                            },
                        }],
                        "restartPolicy": "Always",
                        "securityContext": {
                            "fsGroup": 65532,
                            "runAsGroup": 65532,
                            "runAsNonRoot": True,
                            "runAsUser": 65532,
                            "seccompProfile": {"type": "RuntimeDefault"},
                        },
                    },
                },
            },
        }
        service = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "labels": VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_LABELS,
                "name": VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_NAME,
                "namespace": VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_NAMESPACE,
            },
            "spec": {
                "ports": [{"name": "http", "port": 18080, "protocol": "TCP", "targetPort": "http"}],
                "selector": VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_LABELS,
                "type": "ClusterIP",
            },
        }
        network_policy = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "labels": VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_LABELS,
                "name": VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_NAME,
                "namespace": VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_NAMESPACE,
            },
            "spec": {
                "egress": [],
                "ingress": [{
                    "from": [{
                        "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_NAMESPACE}},
                        "podSelector": {"matchLabels": {
                            "app.kubernetes.io/component": "public-mecky",
                            "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
                        }},
                    }],
                    "ports": [{"port": 8080, "protocol": "TCP"}],
                }],
                "podSelector": {"matchLabels": VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_LABELS},
                "policyTypes": ["Ingress", "Egress"],
            },
        }
        kustomization = (
            "apiVersion: kustomize.config.k8s.io/v1beta1\n"
            "kind: Kustomization\n"
            "resources:\n"
            "  - deployment.json\n"
            "  - service.json\n"
            "  - networkpolicy.json\n"
        )
        future = render / "reviewed-public-knowledge"
        future.mkdir()
        (future / "deployment.json").write_text(json.dumps(deployment, indent=2) + "\n")
        (future / "service.json").write_text(json.dumps(service, indent=2) + "\n")
        (future / "networkpolicy.json").write_text(json.dumps(network_policy, indent=2) + "\n")
        (future / "kustomization.yaml").write_text(kustomization)
        (future / "runtime-pin.json").write_text(json.dumps(pin, indent=2) + "\n")

        public_path = render / "public-mecky/deployment.json"
        public = json.loads(public_path.read_text())
        env = public["spec"]["template"]["spec"]["containers"][0]["env"]
        env[:] = [item for item in env if item["name"] not in {
            "STADTSTACK_E2E_MODE",
            "STADTSTACK_E2E_SYNTHETIC_EVIDENCE_ALLOWED",
            "STADTSTACK_E2E_REVIEWED_EVIDENCE",
            "STADTSTACK_E2E_REVIEWED_EVIDENCE_SHA256",
        }]
        next(item for item in env if item["name"] == "STADTSTACK_PUBLIC_BASE_URL")["value"] = VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_BASE_URL
        env.append({"name": "MECKY_REVIEWED_SOURCE_KINDS", "value": VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_SOURCE_KINDS})
        public_path.write_text(json.dumps(public, indent=2) + "\n")

        integrity_path = render / "integrity.json"
        integrity = json.loads(integrity_path.read_text())
        integrity["desiredRenderSha256"] = VERIFIER.digest({
            "nextEnvironmentHead": json.loads((render / "head.json").read_text()),
            "objects": [
                public,
                json.loads((render / "public-mecky/service.json").read_text()),
                json.loads((render / "public-mecky/networkpolicy.json").read_text()),
                json.loads((render / "web/deployment.json").read_text()),
                json.loads((render / "web/networkpolicy.json").read_text()),
                json.loads((render / "web/ingress.json").read_text()),
            ],
            "reviewedPublicKnowledge": {
                "deployment": deployment,
                "service": service,
                "networkPolicy": network_policy,
                "kustomization": kustomization,
                "runtimePin": pin,
            },
        })
        integrity_path.write_text(json.dumps(integrity, indent=2) + "\n")

    def refresh_reviewed_integrity(self, candidate: Path) -> None:
        render = candidate / "reviewed-render/roebel-staging"
        integrity_path = render / "integrity.json"
        integrity = json.loads(integrity_path.read_text())
        integrity["desiredRenderSha256"] = VERIFIER.digest({
            "nextEnvironmentHead": json.loads((render / "head.json").read_text()),
            "objects": [
                json.loads((render / "public-mecky/deployment.json").read_text()),
                json.loads((render / "public-mecky/service.json").read_text()),
                json.loads((render / "public-mecky/networkpolicy.json").read_text()),
                json.loads((render / "web/deployment.json").read_text()),
                json.loads((render / "web/networkpolicy.json").read_text()),
                json.loads((render / "web/ingress.json").read_text()),
            ],
            "reviewedPublicKnowledge": {
                "deployment": json.loads((render / "reviewed-public-knowledge/deployment.json").read_text()),
                "service": json.loads((render / "reviewed-public-knowledge/service.json").read_text()),
                "networkPolicy": json.loads((render / "reviewed-public-knowledge/networkpolicy.json").read_text()),
                "kustomization": (render / "reviewed-public-knowledge/kustomization.yaml").read_text(),
                "runtimePin": json.loads((render / "reviewed-public-knowledge/runtime-pin.json").read_text()),
            },
        })
        integrity_path.write_text(json.dumps(integrity, indent=2) + "\n")

    def enable_reviewed_mecky_egress(self, candidate: Path) -> None:
        render = candidate / "reviewed-render/roebel-staging"
        path = render / "public-mecky/networkpolicy.json"
        path.write_text(json.dumps(
            VERIFIER.expected_public_mecky_network_policy(True),
            indent=2,
        ) + "\n")
        self.refresh_reviewed_integrity(candidate)

    def materialize_tracer_phase_a_fixture(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        """Overlay the byte-pinned Phase-A render without requiring Git metadata."""
        temp, destination = self.current_v4_participant_fixture()
        self.normalize_participant_gateway_runtime_activation(destination)
        self.disable_public_mecky_reviewed_web_source(destination)

        render = destination / "reviewed-render/roebel-staging"
        phase_a_head = copy.deepcopy(VERIFIER.TRACER_PHASE_A_HEAD)
        phase_a_components = {
            item["component"]: item for item in phase_a_head["components"]
        }

        head_path = render / "head.json"
        head = json.loads(head_path.read_text())
        self.assertEqual(
            {item["component"] for item in head["components"]},
            set(phase_a_components),
        )
        head["promotionRevision"] = phase_a_head["promotionRevision"]
        head["releaseSetDigest"] = phase_a_head["releaseSetDigest"]
        for item in head["components"]:
            expected = phase_a_components[item["component"]]
            item["sourceRevision"] = expected["sourceRevision"]
            item["manifestDigest"] = expected["manifestDigest"]
        head_path.write_text(json.dumps(head, indent=2) + "\n")

        integrity_path = render / "integrity.json"
        integrity = json.loads(integrity_path.read_text())
        integrity["desiredRenderSha256"] = TRACER_PHASE_A_DESIRED_RENDER_SHA256
        integrity["releaseSetDigest"] = phase_a_head["releaseSetDigest"]
        integrity_path.write_text(json.dumps(integrity, indent=2) + "\n")

        public_path = render / "public-mecky/deployment.json"
        public = json.loads(public_path.read_text())
        public_component = phase_a_components["public-mecky"]
        public["metadata"]["annotations"]["stadtstack.io/release-set-sha256"] = (
            phase_a_head["releaseSetDigest"]
        )
        public["metadata"]["annotations"]["stadtstack.io/source-revision"] = (
            public_component["sourceRevision"]
        )
        public_template = public["spec"]["template"]
        public_template["metadata"]["annotations"]["stadtstack.io/source-revision"] = (
            public_component["sourceRevision"]
        )
        public_template["spec"]["containers"][0]["image"] = (
            f"{VERIFIER.COMPONENTS['public-mecky']['repository']}@"
            f"{public_component['manifestDigest']}"
        )
        public_path.write_text(json.dumps(public, indent=2) + "\n")

        web_path = render / "web/deployment.json"
        web = json.loads(web_path.read_text())
        web_component = phase_a_components["roebel-web-staging"]
        web["metadata"]["annotations"]["stadtstack.io/release-set-sha256"] = (
            phase_a_head["releaseSetDigest"]
        )
        web["metadata"]["annotations"]["stadtstack.io/source-revision"] = (
            web_component["sourceRevision"]
        )
        template = web["spec"]["template"]
        template["metadata"]["annotations"]["stadtstack.io/source-revision"] = (
            web_component["sourceRevision"]
        )
        template["spec"]["containers"][0]["image"] = (
            f"{VERIFIER.COMPONENTS['roebel-web-staging']['repository']}@"
            f"{web_component['manifestDigest']}"
        )
        for name in VERIFIER.WEB_IDENTITY_CONTRACT_SET_ANNOTATIONS:
            template["metadata"]["annotations"].pop(name, None)
        web_environment = template["spec"]["containers"][0]["env"]
        web_environment[:] = [
            item
            for item in web_environment
            if item["name"] not in {
                VERIFIER.TRACER_FEED_URL_ENV["name"],
                VERIFIER.TRACER_FEED_ANON_ENV["name"],
            }
            | VERIFIER.WEB_IDENTITY_CONTRACT_SET_ENV_NAMES
        ]
        web_path.write_text(json.dumps(web, indent=2) + "\n")

        web_policy = VERIFIER.expected_web_network_policy(True, False)
        (render / "web/networkpolicy.json").write_text(
            json.dumps(web_policy, indent=2) + "\n",
        )
        boundary_path = render / "network-boundary-migration.json"
        boundary = json.loads(boundary_path.read_text())
        boundary["boundary"].pop("webTracerFeed", None)
        next(
            item
            for item in boundary["objects"]
            if item["kind"] == "NetworkPolicy"
            and item["name"] == "roebel-web-presentation"
        )["sha256"] = VERIFIER.digest(web_policy)
        boundary_path.write_text(json.dumps(boundary, indent=2) + "\n")
        integrity = json.loads(integrity_path.read_text())
        integrity["networkBoundaryMigrationSha256"] = VERIFIER.digest(boundary)
        integrity_path.write_text(json.dumps(integrity, indent=2) + "\n")

        previous_components = {
            item["component"]: item
            for item in TRACER_PHASE_A_PREVIOUS_HEAD["components"]
        }
        live_path = render / "live-preconditions.json"
        live = json.loads(live_path.read_text())
        live["previousEnvironmentHead"] = copy.deepcopy(TRACER_PHASE_A_PREVIOUS_HEAD)
        for precondition in live["requiredLivePreconditions"]:
            component = precondition["component"]
            previous = previous_components[component]
            precondition["currentImage"] = (
                f"{VERIFIER.COMPONENTS[component]['repository']}@"
                f"{previous['manifestDigest']}"
            )
        for patch in live["patches"]:
            component = patch["component"]
            for operation in patch["operations"]:
                operation["value"] = VERIFIER.expected_patch_value(
                    component,
                    operation["path"],
                    phase_a_head,
                )
        live_path.write_text(json.dumps(live, indent=2) + "\n")

        self.assertEqual(
            set(TRACER_PHASE_A_FIXTURE_SHA256),
            TRACER_PHASE_A_FIXTURE_FILES,
        )
        for relative, expected_digest in TRACER_PHASE_A_FIXTURE_SHA256.items():
            self.assertEqual(
                VERIFIER.bytes_digest((destination / relative).read_bytes()),
                expected_digest,
                f"{TRACER_PHASE_A_FIXTURE_REVISION}:{relative}",
            )
        actual_changes = VERIFIER.changed_repository_files(destination, ROOT)
        allowed_changes = (
            set(TRACER_PHASE_A_FIXTURE_FILES)
            | VERIFIER.CITIZEN_ADOPTION_DATA_PLANE_TRANSITION_FILES
            | VERIFIER.CITIZEN_ADOPTION_GATEWAY_TRANSITION_FILES
            | VERIFIER.PARTICIPANT_GATEWAY_RUNTIME_RELEASE_TRANSITION_FILES
            | VERIFIER.PUBLIC_MECKY_REVIEWED_WEB_SOURCE_TRANSITION_FILES
            | VERIFIER.CURRENT_TRACER_FEED_ROUTE_TRANSITION_FILES
            | {
                VERIFIER.SYNTHETIC_CITIZEN_ADOPTION_SQL_PATH,
                VERIFIER.SYNTHETIC_CITIZEN_PASS_TRANSITION_PATH,
                # These later artifacts are absent from the exact phase-A
                # predecessor reconstructed above. This is fixture removal,
                # not an admitted live transition or a changed source hash.
                VERIFIER.IDENTITY_ROTATION_SQL_PATH,
                VERIFIER.IDENTITY_ROTATION_RECORD_PATH,
                str(VERIFIER.TRACER_DATA_PLANE.RETAINED_RECORD_PATH),
            }
        )
        self.assertTrue(TRACER_PHASE_A_FIXTURE_FILES <= actual_changes)
        self.assertTrue(actual_changes <= allowed_changes, sorted(actual_changes - allowed_changes))
        return temp, destination

    def make_tracer_phase_b_successor(self, candidate: Path, base_root: Path) -> None:
        """Materialize the exact seven-file active successor without using its stash."""
        render = candidate / "reviewed-render/roebel-staging"
        base = VERIFIER.verify_tree(base_root)
        successor_head = VERIFIER.expected_tracer_phase_b_head(base["head"])
        (render / "head.json").write_text(json.dumps(successor_head, indent=2) + "\n")

        public_path = render / "public-mecky/deployment.json"
        public = VERIFIER.expected_tracer_phase_b_public_mecky_deployment(
            base["deployments"]["public-mecky"],
            successor_head,
        )
        public_path.write_text(json.dumps(public, indent=2) + "\n")

        web_path = render / "web/deployment.json"
        web = VERIFIER.expected_tracer_phase_b_web_deployment(
            base["deployments"]["roebel-web-staging"],
            successor_head,
        )
        web_path.write_text(json.dumps(web, indent=2) + "\n")

        web_policy = VERIFIER.expected_web_network_policy(True, True)
        (render / "web/networkpolicy.json").write_text(
            json.dumps(web_policy, indent=2) + "\n",
        )
        live = VERIFIER.expected_tracer_phase_b_live_preconditions(
            base_root,
            base,
            successor_head,
        )
        (render / "live-preconditions.json").write_text(
            json.dumps(live, indent=2) + "\n",
        )

        boundary_path = render / "network-boundary-migration.json"
        boundary = json.loads(boundary_path.read_text())
        boundary["boundary"]["webTracerFeed"] = {
            "authority": "none",
            "credentialSecret": {
                "key": VERIFIER.TRACER_DATA_PLANE.WEB_FEED_SECRET_KEYS[0],
                "name": VERIFIER.TRACER_DATA_PLANE.WEB_FEED_SECRET,
                "namespace": VERIFIER.TRACER_DATA_PLANE.PREVIEW_NAMESPACE,
                "valuesCommitted": False,
            },
            "destinationNamespace": VERIFIER.TRACER_DATA_PLANE.NAMESPACE,
            "destinationPodLabels": VERIFIER.TRACER_DATA_PLANE.POSTGREST_LABELS,
            "port": VERIFIER.TRACER_DATA_PLANE.POSTGREST_PORT,
            "protocol": "TCP",
            "source": {
                "namespace": VERIFIER.PARTICIPANT_GATEWAY_NAMESPACE,
                "podSelector": VERIFIER.WEB_PRESENTATION_LABELS,
            },
            "upstreamUrl": VERIFIER.TRACER_DATA_PLANE.POSTGREST_CLUSTER_URL,
        }
        boundary["objects"][0]["sha256"] = VERIFIER.digest(web_policy)
        boundary_path.write_text(json.dumps(boundary, indent=2) + "\n")

        participant_policy = VERIFIER.verify_participant_gateway_static_policy(
            candidate,
            base["renderFileSet"],
        )
        participant = VERIFIER.verify_participant_gateway(candidate, participant_policy)
        checksum_payload = {
            "nextEnvironmentHead": successor_head,
            "objects": [
                public,
                json.loads((render / "public-mecky/service.json").read_text()),
                json.loads((render / "public-mecky/networkpolicy.json").read_text()),
                web,
                web_policy,
                json.loads((render / "web/ingress.json").read_text()),
            ],
            "reviewedPublicKnowledge": VERIFIER.verify_reviewed_public_knowledge(candidate),
            "stagingParticipantGateway": {
                key: value
                for key, value in participant.items()
                if key != "civicProjectionRoute"
            },
        }
        integrity_path = render / "integrity.json"
        integrity = json.loads(integrity_path.read_text())
        integrity["releaseSetDigest"] = successor_head["releaseSetDigest"]
        integrity["desiredRenderSha256"] = VERIFIER.digest(checksum_payload)
        integrity["networkBoundaryMigrationSha256"] = VERIFIER.digest(boundary)
        integrity_path.write_text(json.dumps(integrity, indent=2) + "\n")

    def test_seed_is_valid(self) -> None:
        result = VERIFIER.verify(ROOT)
        self.assertEqual(result["status"], "passed")
        self.assertFalse(result["baseTransitionVerified"])
        self.assertEqual(result["renderFileSet"], self.repository_shape(ROOT))
        tree = VERIFIER.verify_tree(ROOT)
        self.assertEqual(
            tree["webIdentityContractSet"],
            VERIFIER.IDENTITY_ROTATION.WEB_IDENTITY
            if (ROOT / VERIFIER.IDENTITY_ROTATION_RECORD_PATH).is_file()
            else VERIFIER.WEB_IDENTITY_CONTRACT_SET,
        )
        self.assertTrue(VERIFIER.tracer_synthetic_citizen_pass_enabled(tree))
        self.assertTrue(VERIFIER.gateway_synthetic_citizen_pass_enabled(tree))

        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        fixture = VERIFIER.verify(candidate)
        self.assertEqual(fixture["status"], "passed")
        self.assertEqual(fixture["renderFileSet"], "current")

    def test_web_identity_contract_set_policy_is_exact_and_non_authoritative(self) -> None:
        tree = VERIFIER.verify_tree(ROOT)
        contract_set = tree["webIdentityContractSet"]
        expected_contracts = {
            "gnosis-staging-test-v1": {
                "attesterNft": {
                    "address": "0x5983F6300bCE3D9C1336a858Bd73F259bB8330F3",
                    "runtimeCodeKeccak256": "0x3c12a034ea9c2749c786497b5d50dcfaa4eff84860819d788517145a2276ee51",
                },
                "citizenNft": {
                    "address": "0x0Be374808A567c9088aC8208B90a4239432B3220",
                    "runtimeCodeKeccak256": "0x481949efe62483d881190ec16e7ac6ffd796b0e601ea952507fa6eee1986bafb",
                },
            },
            "gnosis-staging-test-v2": {
                "attesterNft": {
                    "address": "0x76b558Feb869c77790431497554C9aa8797896Fa",
                    "runtimeCodeKeccak256": "0x3c12a034ea9c2749c786497b5d50dcfaa4eff84860819d788517145a2276ee51",
                },
                "citizenNft": {
                    "address": "0x4765cB681E8eB080B3191DD550E81eaA41907323",
                    "runtimeCodeKeccak256": "0x0131b35a46839c2c50e013a5702dd1a75ab2c079890711900071d56486d1bce4",
                },
            },
        }
        # Check both immutable sets, even when only one is deployed. Derive
        # neither the expected addresses nor hashes from the current render.
        for identity in (
            VERIFIER.WEB_IDENTITY_CONTRACT_SET,
            VERIFIER.IDENTITY_ROTATION.WEB_IDENTITY,
            contract_set,
        ):
            with self.subTest(profile=identity["profile"]):
                self.assertIn(identity["profile"], expected_contracts)
                self.assertEqual(identity["chainId"], 100)
                self.assertEqual(identity["authority"], "none")
                self.assertEqual(
                    identity["contracts"], expected_contracts[identity["profile"]],
                )
        web = tree["deployments"]["roebel-web-staging"]
        env = web["spec"]["template"]["spec"]["containers"][0]["env"]
        by_name = {item["name"]: item for item in env}
        self.assertEqual(
            {
                name: by_name[name]["value"]
                for name in VERIFIER.WEB_IDENTITY_CONTRACT_SET_ENV_NAMES
            },
            {
                "ROEBEL_PUBLIC_IDENTITY_CONTRACT_SET": contract_set["profile"],
                "ROEBEL_PUBLIC_ATTESTER_NFT_ADDRESS": expected_contracts[
                    contract_set["profile"]
                ]["attesterNft"]["address"],
                "ROEBEL_PUBLIC_CITIZEN_NFT_ADDRESS": expected_contracts[
                    contract_set["profile"]
                ]["citizenNft"]["address"],
            },
        )
        self.assertFalse(
            any("RUNTIME_CODE" in item["name"] for item in env),
            "runtime code hashes are reviewed evidence, not browser input",
        )

        # The real ADR-0023 gateway remains bound to its original production
        # CitizenNFT and issuer; the burner-mintable test set cannot issue a
        # real-shaped eligibility receipt.
        adoption = tree["stagingParticipantGateway"]["runtimePin"]["citizenAdoption"]
        self.assertEqual(
            adoption["citizenNft"],
            {
                "chainId": 100,
                "address": "0x59aa26f499d7c2b3ec2c8524ed06f54fc4e85de5",
                "runtimeCodeHash": (
                    "0x952276d2d6da4bfe3ed3dbc39f6745f2421b01ad476c286cb7a6fa166c7e4218"
                ),
            },
        )
        self.assertEqual(
            adoption["eligibilityIssuer"]["keyId"],
            "roebel-staging-citizen-eligibility-2026-09",
        )

    def test_web_identity_contract_set_cannot_transition_without_gateway_and_migration(self) -> None:
        base_temp = tempfile.TemporaryDirectory()
        self.addCleanup(base_temp.cleanup)
        base = Path(base_temp.name) / "base"
        shutil.copytree(
            ROOT,
            base,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        )
        self.normalize_synthetic_citizen_pass_seed(base)
        candidate_temp = tempfile.TemporaryDirectory()
        self.addCleanup(candidate_temp.cleanup)
        candidate = Path(candidate_temp.name) / "candidate"
        shutil.copytree(
            ROOT,
            candidate,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        )
        self.activate_web_identity_contract_set(candidate)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            "must transition Web, gateway, and migration atomically",
        ):
            VERIFIER.verify(candidate, base)

    def test_web_identity_contract_set_cannot_roll_the_old_image(self) -> None:
        base_temp = tempfile.TemporaryDirectory()
        self.addCleanup(base_temp.cleanup)
        base = Path(base_temp.name) / "base"
        shutil.copytree(
            ROOT,
            base,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        )
        self.normalize_synthetic_citizen_pass_seed(base)
        candidate_temp = tempfile.TemporaryDirectory()
        self.addCleanup(candidate_temp.cleanup)
        candidate = Path(candidate_temp.name) / "candidate"
        shutil.copytree(
            ROOT,
            candidate,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        )
        self.activate_web_identity_contract_set(candidate, promote=False)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            "must transition Web, gateway, and migration atomically",
        ):
            VERIFIER.verify(candidate, base)

    def test_web_identity_contract_set_rejects_partial_or_mixed_config(self) -> None:
        for mutate, expected in (
            (
                lambda env: env.__setitem__(
                    slice(None),
                    [
                        item for item in env
                        if item["name"] != "ROEBEL_PUBLIC_CITIZEN_NFT_ADDRESS"
                    ],
                ),
                "must configure profile and both addresses atomically",
            ),
            (
                lambda env: next(
                    item for item in env
                    if item["name"] == "ROEBEL_PUBLIC_CITIZEN_NFT_ADDRESS"
                ).__setitem__(
                    "value",
                    "0x59aa26f499d7c2b3ec2c8524ed06f54fc4e85de5",
                ),
                "profile/address binding invalid",
            ),
        ):
            with self.subTest(expected=expected):
                temp = tempfile.TemporaryDirectory()
                self.addCleanup(temp.cleanup)
                candidate = Path(temp.name) / "candidate"
                shutil.copytree(
                    ROOT,
                    candidate,
                    ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
                )
                self.activate_web_identity_contract_set(candidate)
                path = candidate / VERIFIER.RENDER_ROOT / "web/deployment.json"
                deployment = json.loads(path.read_text())
                environment = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
                mutate(environment)
                path.write_text(json.dumps(deployment, indent=2) + "\n")
                with self.assertRaisesRegex(VERIFIER.VerificationError, expected):
                    VERIFIER.verify(candidate)

    def test_web_identity_contract_set_rejects_authority_or_code_hash_drift(self) -> None:
        for annotation, value in (
            ("stadtstack.io/identity-contract-authority", "municipal"),
            (
                "stadtstack.io/identity-citizen-runtime-code-keccak256",
                "0x" + "0" * 64,
            ),
        ):
            with self.subTest(annotation=annotation):
                temp = tempfile.TemporaryDirectory()
                self.addCleanup(temp.cleanup)
                candidate = Path(temp.name) / "candidate"
                shutil.copytree(
                    ROOT,
                    candidate,
                    ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
                )
                self.activate_web_identity_contract_set(candidate)
                path = candidate / VERIFIER.RENDER_ROOT / "web/deployment.json"
                deployment = json.loads(path.read_text())
                deployment["spec"]["template"]["metadata"]["annotations"][annotation] = value
                path.write_text(json.dumps(deployment, indent=2) + "\n")
                with self.assertRaisesRegex(
                    VERIFIER.VerificationError,
                    "authority/code evidence invalid",
                ):
                    VERIFIER.verify(candidate)

    def test_web_identity_transition_rejects_any_gateway_byte_change(self) -> None:
        base_temp = tempfile.TemporaryDirectory()
        self.addCleanup(base_temp.cleanup)
        base = Path(base_temp.name) / "base"
        shutil.copytree(
            ROOT,
            base,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        )
        self.normalize_synthetic_citizen_pass_seed(base)
        candidate_temp = tempfile.TemporaryDirectory()
        self.addCleanup(candidate_temp.cleanup)
        candidate = Path(candidate_temp.name) / "candidate"
        shutil.copytree(
            ROOT,
            candidate,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        )
        self.activate_web_identity_contract_set(candidate)
        runtime_pin = (
            candidate
            / VERIFIER.PARTICIPANT_GATEWAY_ROOT
            / "runtime-pin.json"
        )
        runtime_pin.write_text(runtime_pin.read_text() + "\n")
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            "must transition Web, gateway, and migration atomically",
        ):
            VERIFIER.verify(candidate, base)

    def test_exact_public_mecky_reviewed_web_source_transition_is_accepted(self) -> None:
        base_temp = tempfile.TemporaryDirectory()
        self.addCleanup(base_temp.cleanup)
        base = Path(base_temp.name) / "base"
        shutil.copytree(
            ROOT,
            base,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        )
        self.disable_public_mecky_reviewed_web_source(base)

        candidate_temp = tempfile.TemporaryDirectory()
        self.addCleanup(candidate_temp.cleanup)
        candidate = Path(candidate_temp.name) / "candidate"
        shutil.copytree(
            ROOT,
            candidate,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        )
        self.enable_public_mecky_reviewed_web_source(candidate)

        result = VERIFIER.verify(candidate, base)
        self.assertTrue(result["baseTransitionVerified"])

    def test_public_mecky_reviewed_web_source_rejects_dead_public_index(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        candidate = Path(temp.name) / "candidate"
        shutil.copytree(
            ROOT,
            candidate,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        )
        deployment_path = (
            candidate
            / "reviewed-render/roebel-staging/public-mecky/deployment.json"
        )
        deployment = json.loads(deployment_path.read_text())
        deployment["spec"]["template"]["spec"]["containers"][0]["env"].append({
            "name": "MECKY_PUBLIC_INDEX_BASE_URL",
            "value": "https://index.roebel.app",
        })
        deployment_path.write_text(json.dumps(deployment, indent=2) + "\n")

        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            "public index is blocked until the exact signed event is queryable",
        ):
            VERIFIER.verify(candidate)

    def test_public_mecky_reviewed_web_source_rejects_network_widening(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        candidate = Path(temp.name) / "candidate"
        shutil.copytree(
            ROOT,
            candidate,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        )
        self.enable_public_mecky_reviewed_web_source(candidate)
        policy_path = (
            candidate
            / "reviewed-render/roebel-staging/public-mecky/networkpolicy.json"
        )
        policy = json.loads(policy_path.read_text())
        policy["spec"]["egress"].append({
            "to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}],
        })
        policy_path.write_text(json.dumps(policy, indent=2) + "\n")

        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            "Public Mecky NetworkPolicy drift",
        ):
            VERIFIER.verify(candidate)

    def test_public_mecky_reviewed_web_source_cannot_regress(self) -> None:
        base_temp = tempfile.TemporaryDirectory()
        candidate_temp = tempfile.TemporaryDirectory()
        self.addCleanup(base_temp.cleanup)
        self.addCleanup(candidate_temp.cleanup)
        base = Path(base_temp.name) / "base"
        shutil.copytree(
            ROOT,
            base,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        )
        self.enable_public_mecky_reviewed_web_source(base)
        candidate = Path(candidate_temp.name) / "candidate"
        shutil.copytree(
            base,
            candidate,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        )
        self.disable_public_mecky_reviewed_web_source(candidate)

        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            "reviewed Web source cannot regress",
        ):
            VERIFIER.verify(candidate, base)

    def test_live_participant_wrapper_is_pinned_in_every_repository_shape(self) -> None:
        live_wrapper_files = {
            "scripts/run-staging-participant-gateway-live.py",
            "scripts/test_run_staging_participant_gateway_live.py",
        }
        for expected_files in (
            VERIFIER.EXPECTED_FILES,
            VERIFIER.FUTURE_EXPECTED_FILES,
            VERIFIER.PARTICIPANT_GATEWAY_EXPECTED_FILES,
            VERIFIER.SIGNED_NOSTR_EXPECTED_FILES,
            VERIFIER.SIGNED_NOSTR_PARTICIPANT_GATEWAY_EXPECTED_FILES,
        ):
            self.assertTrue(live_wrapper_files <= expected_files)

    def test_tracer_live_runners_and_tests_are_pinned_in_every_repository_shape(self) -> None:
        tracer_live_files = {
            "scripts/materialize-tracer-data-plane-secrets.py",
            "scripts/run-tracer-data-plane-live.py",
            "scripts/test_materialize_tracer_data_plane_secrets.py",
            "scripts/test_run_tracer_data_plane_live.py",
        }
        for expected_files in (
            VERIFIER.EXPECTED_FILES,
            VERIFIER.FUTURE_EXPECTED_FILES,
            VERIFIER.PARTICIPANT_GATEWAY_EXPECTED_FILES,
            VERIFIER.SIGNED_NOSTR_EXPECTED_FILES,
            VERIFIER.SIGNED_NOSTR_PARTICIPANT_GATEWAY_EXPECTED_FILES,
        ):
            self.assertTrue(tracer_live_files <= expected_files)

        workflow = (ROOT / ".github/workflows/reviewed-render-admission.yml").read_text()
        for relative in (
            "scripts/test_materialize_tracer_data_plane_secrets.py",
            "scripts/test_run_tracer_data_plane_live.py",
        ):
            self.assertEqual(workflow.count(relative), 2)

    def test_phase_a_admission_is_closed_and_preserves_every_active_release_file(self) -> None:
        expected_added = VERIFIER.TRACER_DATA_PLANE.expected_files(
            VERIFIER.TRACER_DATA_PLANE.LEGACY_PRODUCT_ARTIFACTS,
        ) | {
            "scripts/materialize-tracer-data-plane-secrets.py",
            "scripts/run-tracer-data-plane-live.py",
            "scripts/test_materialize_tracer_data_plane_secrets.py",
            "scripts/test_run_tracer_data_plane_live.py",
            "scripts/test_tracer_data_plane_policy.py",
            "scripts/tracer_data_plane_policy.py",
        }
        self.assertEqual(VERIFIER.TRACER_PHASE_A_ADDED_FILES, expected_added)
        self.assertTrue(
            expected_added <= VERIFIER.TRACER_PHASE_A_TRANSITION_FILES,
        )
        expected_active = {
            "reviewed-render/roebel-staging/head.json",
            "reviewed-render/roebel-staging/live-preconditions.json",
            "reviewed-render/roebel-staging/public-mecky/deployment.json",
            "reviewed-render/roebel-staging/public-mecky/kustomization.yaml",
            "reviewed-render/roebel-staging/public-mecky/networkpolicy.json",
            "reviewed-render/roebel-staging/public-mecky/service.json",
            "reviewed-render/roebel-staging/web/deployment.json",
            "reviewed-render/roebel-staging/web/ingress.json",
            "reviewed-render/roebel-staging/web/kustomization.yaml",
            "reviewed-render/roebel-staging/web/networkpolicy.json",
        }
        self.assertEqual(VERIFIER.TRACER_PHASE_A_PRESERVED_ACTIVE_FILES, expected_active)
        self.assertTrue(
            expected_active.isdisjoint(VERIFIER.TRACER_PHASE_A_TRANSITION_FILES),
        )
        phase_a_temp, phase_a_root = self.materialize_tracer_phase_a_fixture()
        self.addCleanup(phase_a_temp.cleanup)
        phase_a = VERIFIER.verify_tree(phase_a_root)
        self.assertEqual(phase_a["head"], VERIFIER.TRACER_PHASE_A_HEAD)
        self.assertFalse(phase_a["webTracerFeed"])
        self.assertTrue(phase_a["tracerDataPlane"]["activationReady"])
        boundary = phase_a["migration"]["boundary"]
        self.assertEqual(
            boundary["participantGateway"]["internalPostgrest"]["origin"],
            VERIFIER.TRACER_DATA_PLANE.POSTGREST_CLUSTER_URL,
        )
        self.assertFalse(
            boundary["participantGateway"]["internalPostgrest"]["externalIngress"],
        )
        self.assertEqual(
            boundary["tracerActivation"],
            {
                "applicationObjectCount": 8,
                "createBeforeUnsuspend": True,
                "runner": "scripts/run-tracer-data-plane-live.py",
                "secretMaterializerRunner": "scripts/materialize-tracer-data-plane-secrets.py",
                "sharedSourceMutation": "forbidden",
            },
        )

        base_temp = tempfile.TemporaryDirectory()
        candidate_temp = tempfile.TemporaryDirectory()
        self.addCleanup(base_temp.cleanup)
        self.addCleanup(candidate_temp.cleanup)
        base = Path(base_temp.name) / "base"
        candidate = Path(candidate_temp.name) / "candidate"
        shutil.copytree(
            phase_a_root,
            base,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        )
        shutil.copytree(
            phase_a_root,
            candidate,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        )

        for relative in VERIFIER.TRACER_PHASE_A_TRANSITION_FILES:
            path = base / relative
            if relative in VERIFIER.TRACER_PHASE_A_ADDED_FILES:
                path.unlink()
            else:
                path.write_bytes(path.read_bytes() + b"\nprotected predecessor bytes\n")
        VERIFIER.verify_tracer_phase_a_file_boundary(candidate, base)

        active = candidate / "reviewed-render/roebel-staging/web/deployment.json"
        active.write_bytes(active.read_bytes() + b"\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "Phase A changed active release file"):
            VERIFIER.verify_tracer_phase_a_file_boundary(candidate, base)

        active.write_bytes((base / active.relative_to(candidate)).read_bytes())
        readme = candidate / "README.md"
        readme.write_bytes(readme.read_bytes() + b"\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "Phase A changed file set drift"):
            VERIFIER.verify_tracer_phase_a_file_boundary(candidate, base)

    def test_phase_b_admits_only_the_exact_feed_secret_network_and_release_successor(self) -> None:
        self.assertEqual(
            VERIFIER.TRACER_PHASE_B_TRANSITION_FILES,
            {
                "reviewed-render/roebel-staging/head.json",
                "reviewed-render/roebel-staging/integrity.json",
                "reviewed-render/roebel-staging/live-preconditions.json",
                "reviewed-render/roebel-staging/network-boundary-migration.json",
                "reviewed-render/roebel-staging/public-mecky/deployment.json",
                "reviewed-render/roebel-staging/web/deployment.json",
                "reviewed-render/roebel-staging/web/networkpolicy.json",
            },
        )
        base_temp, base = self.materialize_tracer_phase_a_fixture()
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(base_temp.cleanup)
        self.addCleanup(temp.cleanup)
        candidate = Path(temp.name) / "candidate"
        shutil.copytree(base, candidate, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        self.make_tracer_phase_b_successor(candidate, base)

        result = VERIFIER.verify(candidate, base)
        self.assertTrue(result["baseTransitionVerified"])
        self.assertEqual(result["releaseSetDigest"], VERIFIER.TRACER_PHASE_B_RELEASE_SET_DIGEST)
        web = json.loads(
            (candidate / "reviewed-render/roebel-staging/web/deployment.json").read_text(),
        )
        environment = web["spec"]["template"]["spec"]["containers"][0]["env"]
        self.assertEqual(
            [
                item
                for item in environment
                if item["name"] in {
                    VERIFIER.TRACER_FEED_URL_ENV["name"],
                    VERIFIER.TRACER_FEED_ANON_ENV["name"],
                }
            ],
            [VERIFIER.TRACER_FEED_URL_ENV, VERIFIER.TRACER_FEED_ANON_ENV],
        )
        policy = json.loads(
            (candidate / "reviewed-render/roebel-staging/web/networkpolicy.json").read_text(),
        )
        self.assertEqual(policy["spec"]["egress"][0], VERIFIER.tracer_postgrest_web_egress())

    def test_phase_b_rejects_feed_secret_network_release_or_eighth_file_drift(self) -> None:
        base_temp, base = self.materialize_tracer_phase_a_fixture()
        self.addCleanup(base_temp.cleanup)
        for label in ("feed-url", "secret-name"):
            with self.subTest(label=label):
                temp = tempfile.TemporaryDirectory()
                self.addCleanup(temp.cleanup)
                candidate = Path(temp.name) / "candidate"
                shutil.copytree(base, candidate, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
                self.make_tracer_phase_b_successor(candidate, base)
                path = candidate / "reviewed-render/roebel-staging/web/deployment.json"
                value = json.loads(path.read_text())
                env = value["spec"]["template"]["spec"]["containers"][0]["env"]
                target = next(
                    item for item in env
                    if item["name"] == (
                        VERIFIER.TRACER_FEED_URL_ENV["name"]
                        if label == "feed-url"
                        else VERIFIER.TRACER_FEED_ANON_ENV["name"]
                    )
                )
                if label == "feed-url":
                    target["value"] = "https://example.invalid"
                else:
                    target["valueFrom"]["secretKeyRef"]["name"] = "other-secret"
                path.write_text(json.dumps(value, indent=2) + "\n")
                with self.assertRaises(VERIFIER.VerificationError):
                    VERIFIER.verify(candidate, base)

        for label, relative, mutate in (
            (
                "network",
                "reviewed-render/roebel-staging/web/networkpolicy.json",
                lambda value: value["spec"]["egress"][0]["to"][0]["podSelector"]["matchLabels"].clear(),
            ),
            (
                "release",
                "reviewed-render/roebel-staging/head.json",
                lambda value: value.__setitem__("releaseSetDigest", "sha256:" + "0" * 64),
            ),
        ):
            with self.subTest(label=label):
                temp = tempfile.TemporaryDirectory()
                self.addCleanup(temp.cleanup)
                candidate = Path(temp.name) / "candidate"
                shutil.copytree(base, candidate, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
                self.make_tracer_phase_b_successor(candidate, base)
                path = candidate / relative
                value = json.loads(path.read_text())
                mutate(value)
                path.write_text(json.dumps(value, indent=2) + "\n")
                with self.assertRaises(VERIFIER.VerificationError):
                    VERIFIER.verify(candidate, base)

        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        candidate = Path(temp.name) / "candidate"
        shutil.copytree(base, candidate, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        self.make_tracer_phase_b_successor(candidate, base)
        ingress = candidate / "reviewed-render/roebel-staging/web/ingress.json"
        ingress.write_bytes(ingress.read_bytes() + b"\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "Phase B changed file set drift"):
            VERIFIER.verify(candidate, base)

    def test_current_head_admits_only_the_exact_private_tracer_feed_route(self) -> None:
        self.assertEqual(
            VERIFIER.CURRENT_TRACER_FEED_ROUTE_TRANSITION_FILES,
            {
                "reviewed-render/roebel-staging/integrity.json",
                "reviewed-render/roebel-staging/network-boundary-migration.json",
                "reviewed-render/roebel-staging/web/deployment.json",
                "reviewed-render/roebel-staging/web/networkpolicy.json",
            },
        )
        base_temp = tempfile.TemporaryDirectory()
        candidate_temp = tempfile.TemporaryDirectory()
        self.addCleanup(base_temp.cleanup)
        self.addCleanup(candidate_temp.cleanup)
        base = Path(base_temp.name) / "base"
        candidate = Path(candidate_temp.name) / "candidate"
        shutil.copytree(ROOT, base, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        shutil.copytree(ROOT, candidate, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        self.set_current_tracer_feed_route(base, False)
        self.set_current_tracer_feed_route(candidate, True)

        result = VERIFIER.verify(candidate, base)
        self.assertTrue(result["baseTransitionVerified"])
        self.assertEqual(
            json.loads((candidate / "reviewed-render/roebel-staging/head.json").read_text()),
            json.loads((base / "reviewed-render/roebel-staging/head.json").read_text()),
        )
        web = json.loads(
            (candidate / "reviewed-render/roebel-staging/web/deployment.json").read_text(),
        )
        environment = web["spec"]["template"]["spec"]["containers"][0]["env"]
        self.assertEqual(
            [
                item
                for item in environment
                if item["name"] in {
                    VERIFIER.TRACER_FEED_URL_ENV["name"],
                    VERIFIER.TRACER_FEED_ANON_ENV["name"],
                }
            ],
            [VERIFIER.TRACER_FEED_URL_ENV, VERIFIER.TRACER_FEED_ANON_ENV],
        )
        policy = json.loads(
            (candidate / "reviewed-render/roebel-staging/web/networkpolicy.json").read_text(),
        )
        self.assertEqual(
            policy["spec"]["egress"][0],
            VERIFIER.tracer_postgrest_web_egress(),
        )

    def test_current_head_rejects_partial_widened_or_unrelated_tracer_feed_changes(self) -> None:
        base_temp = tempfile.TemporaryDirectory()
        self.addCleanup(base_temp.cleanup)
        base = Path(base_temp.name) / "base"
        shutil.copytree(ROOT, base, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        self.set_current_tracer_feed_route(base, False)

        def partial_environment(candidate: Path) -> None:
            path = candidate / "reviewed-render/roebel-staging/web/deployment.json"
            value = json.loads(path.read_text())
            env = value["spec"]["template"]["spec"]["containers"][0]["env"]
            env[:] = [
                item
                for item in env
                if item["name"] != VERIFIER.TRACER_FEED_ANON_ENV["name"]
            ]
            path.write_text(json.dumps(value, indent=2) + "\n")

        def widened_network(candidate: Path) -> None:
            path = candidate / "reviewed-render/roebel-staging/web/networkpolicy.json"
            value = json.loads(path.read_text())
            value["spec"]["egress"][0]["to"][0]["podSelector"]["matchLabels"].clear()
            path.write_text(json.dumps(value, indent=2) + "\n")

        def unrelated_file(candidate: Path) -> None:
            path = candidate / "README.md"
            path.write_bytes(path.read_bytes() + b"\nunrelated tracer-feed change\n")

        for label, mutate, expected_error in (
            (
                "partial-environment",
                partial_environment,
                "Web tracer feed Secret reference invalid",
            ),
            ("widened-network", widened_network, "Web NetworkPolicy drift"),
            (
                "unrelated-file",
                unrelated_file,
                "current tracer-feed route changed protected file: README.md",
            ),
        ):
            with self.subTest(label=label):
                candidate_temp = tempfile.TemporaryDirectory()
                self.addCleanup(candidate_temp.cleanup)
                candidate = Path(candidate_temp.name) / "candidate"
                shutil.copytree(ROOT, candidate, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
                self.set_current_tracer_feed_route(candidate, True)
                mutate(candidate)
                with self.assertRaisesRegex(VERIFIER.VerificationError, expected_error):
                    VERIFIER.verify(candidate, base)

    def test_signed_nostr_policy_reserves_exactly_sixteen_files(self) -> None:
        self.assertEqual(len(VERIFIER.SIGNED_NOSTR_FILES), 16)
        self.assertNotIn(
            "reviewed-render/roebel-staging/signed-nostr/runtime-pin.json",
            VERIFIER.repository_files(ROOT),
        )
        self.assertTrue(VERIFIER.FUTURE_EXPECTED_FILES < VERIFIER.SIGNED_NOSTR_EXPECTED_FILES)

    def test_participant_gateway_policy_reserves_a_closed_composable_subtree(self) -> None:
        self.assertEqual(len(VERIFIER.PARTICIPANT_GATEWAY_FILES), 9)
        committed = VERIFIER.PARTICIPANT_GATEWAY_FILES & VERIFIER.repository_files(ROOT)
        self.assertTrue(
            not committed or committed == VERIFIER.PARTICIPANT_GATEWAY_FILES,
            "participant gateway subtree must be entirely absent or entirely committed",
        )
        if committed:
            self.assertIn(
                self.repository_shape(ROOT),
                {
                    "reviewed-public-knowledge-participant-gateway",
                    "signed-nostr-participant-gateway",
                },
            )
        self.assertTrue(VERIFIER.FUTURE_EXPECTED_FILES < VERIFIER.PARTICIPANT_GATEWAY_EXPECTED_FILES)
        self.assertTrue(
            VERIFIER.SIGNED_NOSTR_EXPECTED_FILES
            < VERIFIER.SIGNED_NOSTR_PARTICIPANT_GATEWAY_EXPECTED_FILES,
        )

    def test_participant_bootstrap_marker_does_not_change_signed_nostr_semantics(self) -> None:
        contract = json.loads((ROOT / "policy/repository-contract.json").read_text())
        committed_policy = json.loads(
            (ROOT / VERIFIER.PARTICIPANT_POLICY.POLICY_PATH).read_text(),
        )
        self.assertEqual(
            contract["signedNostrBoundary"]["activationEvidence"],
            "pending-separate-review",
        )
        self.assertEqual(
            contract["stagingParticipantGatewayBoundary"]["activationPolicy"],
            "policy/staging-participant-gateway-activation-policy.json",
        )
        self.assertEqual(
            contract["stagingParticipantGatewayBoundary"]["activationReady"],
            committed_policy["activationReady"],
        )
        self.assertEqual(
            contract["stagingParticipantGatewayBoundary"]["trustedLiveFacts"],
            "protected-local-runner-out-of-band-only",
        )
        http = VERIFIER.participant_gateway_http_contract(committed_policy)
        gateway = contract["stagingParticipantGatewayBoundary"]
        if "syntheticCitizenAdoption" in gateway:
            http["schemaVersion"] = (
                "roebel_staging_participant_gateway_runtime_pin_v5"
            )
            http["exactGatewayPaths"].extend(
                VERIFIER.SYNTHETIC_CITIZEN_PASS_POST_ROUTES,
            )
            http["methodPathMatrix"]["OPTIONS"].extend(
                VERIFIER.SYNTHETIC_CITIZEN_PASS_POST_ROUTES,
            )
            http["methodPathMatrix"]["POST"].extend(
                VERIFIER.SYNTHETIC_CITIZEN_PASS_POST_ROUTES,
            )
            http["dynamicGetPrefixes"].append(
                VERIFIER.SYNTHETIC_CITIZEN_PASS_DYNAMIC_GET_PREFIX,
            )
            self.assertEqual(
                gateway["syntheticCitizenAdoption"],
                VERIFIER.IDENTITY_ROTATION.boundary(
                    VERIFIER.synthetic_citizen_pass_boundary(),
                )
                if (ROOT / VERIFIER.IDENTITY_ROTATION_RECORD_PATH).is_file()
                else VERIFIER.synthetic_citizen_pass_boundary(),
            )
        self.assertEqual(gateway["exactGatewayPaths"], http["exactGatewayPaths"])
        self.assertEqual(gateway["methodPathMatrix"], http["methodPathMatrix"])
        self.assertEqual(
            gateway.get("dynamicGetPrefixes"),
            http.get("dynamicGetPrefixes"),
        )
        self.assertEqual(
            gateway.get("routeProbeSamples"),
            http.get("routeProbeSamples"),
        )
        self.assertEqual(gateway["schemaVersion"], http["schemaVersion"])
        issuer = VERIFIER.verify_eligibility_issuer_materialization_policy(ROOT)
        self.assertEqual(
            gateway["eligibilityIssuerMaterialization"],
            VERIFIER.eligibility_issuer_contract_projection(issuer),
        )
        self.assertNotIn(
            "clusterIdentity",
            gateway["eligibilityIssuerMaterialization"],
        )
        self.assertNotIn(
            "httpBoundary",
            gateway["eligibilityIssuerMaterialization"],
        )

    def test_participant_gateway_ingress_is_exact_and_rate_limited(self) -> None:
        expected = VERIFIER.PARTICIPANT_POLICY.ROUTES
        ingress = VERIFIER.expected_participant_gateway_ingress(
            participant_ready_policy(),
        )
        lines = ingress["metadata"]["annotations"]["haproxy-ingress.github.io/config-backend-early"].split("\n")
        self.assertEqual(
            lines[0],
            "http-request deny deny_status 404 if "
            + " ".join(f"!{{ path {path} }}" for path in expected)
            + " "
            + " ".join(
                f"!{{ path_beg {prefix} }}"
                for prefix in VERIFIER.PARTICIPANT_POLICY.DYNAMIC_GET_PREFIXES
            ),
        )
        self.assertEqual(lines[1], "http-request deny deny_status 405 if { method POST } " + " ".join(f"!{{ path {path} }}" for path in expected[1:]))
        self.assertEqual(lines[2], "http-request deny deny_status 405 if { method OPTIONS } " + " ".join(f"!{{ path {path} }}" for path in expected))
        self.assertEqual(lines[3], "http-request deny deny_status 405 if { method HEAD }")
        self.assertEqual(
            lines[4],
            f"http-request deny deny_status 405 if {{ method GET }} !{{ path {expected[0]} }} "
            + " ".join(
                f"!{{ path_beg {prefix} }}"
                for prefix in VERIFIER.PARTICIPANT_POLICY.DYNAMIC_GET_PREFIXES
            ),
        )
        self.assertEqual(lines[5], "http-request deny deny_status 405 unless { method GET HEAD POST OPTIONS }")
        self.assertIn("http-request deny deny_status 429 if { sc_http_req_rate(0) gt 30 }", lines)
        self.assertEqual(ingress["spec"]["rules"][0]["http"]["paths"][0]["path"], "/api/staging-participant/v1")
        self.assertEqual(
            ingress["spec"]["rules"][0]["http"]["paths"][1]["path"],
            "/api/civic/v1/eligibility/status",
        )
        self.assertEqual(VERIFIER.expected_web_ingress(False), VERIFIER.expected_web_ingress(False, participant_gateway=True))

    def test_synthetic_gateway_ingress_allowlist_fits_haproxy_parser_word_limit(self) -> None:
        exact_paths = [
            *VERIFIER.PARTICIPANT_POLICY.ROUTES,
            *VERIFIER.SYNTHETIC_CITIZEN_PASS_POST_ROUTES,
        ]
        dynamic_get_prefixes = [
            *VERIFIER.PARTICIPANT_POLICY.DYNAMIC_GET_PREFIXES,
            VERIFIER.SYNTHETIC_CITIZEN_PASS_DYNAMIC_GET_PREFIX,
        ]
        ingress = VERIFIER.expected_synthetic_citizen_pass_gateway_ingress()
        lines = ingress["metadata"]["annotations"][
            "haproxy-ingress.github.io/config-backend-early"
        ].splitlines()

        self.assertLessEqual(max(len(line.split()) for line in lines), 64)
        self.assertEqual(
            lines[0],
            "http-request deny deny_status 404 if "
            f"!{{ path {' '.join(exact_paths)} }} "
            f"!{{ path_beg {' '.join(dynamic_get_prefixes)} }}",
        )

    def test_participant_gateway_policy_forbids_web_ingress_mutation(self) -> None:
        preserved = VERIFIER.PARTICIPANT_POLICY.activation_policy_descriptor()["preservation"]["webIngress"]
        self.assertEqual(preserved["mutation"], "forbidden")
        self.assertEqual(preserved["adoption"], "forbidden")
        self.assertTrue(preserved["prePostByteEqualityRequired"])
        self.assertEqual(
            VERIFIER.expected_web_ingress(False),
            VERIFIER.expected_web_ingress(False, participant_gateway=True),
        )

    def test_participant_gateway_cannot_roll_out_a_second_challenge_store(self) -> None:
        with mock.patch.object(
            VERIFIER.PARTICIPANT_POLICY,
            "STATIC_ACTIVATION_POLICY",
            participant_ready_policy(),
        ):
            pin = VERIFIER.PARTICIPANT_POLICY.expected_runtime_pin()
            resources = VERIFIER.expected_participant_gateway_resources(pin)
        self.assertEqual(resources["deployment"]["spec"]["replicas"], 1)
        self.assertEqual(resources["deployment"]["spec"]["strategy"], {"type": "Recreate"})

    def test_participant_flux_bootstrap_is_suspended_and_cannot_own_web_ingress(self) -> None:
        flux = VERIFIER.expected_participant_gateway_flux_objects()
        self.assertEqual(flux["serviceAccount"]["metadata"]["namespace"], "flux-roebel-staging")
        self.assertEqual(
            flux["roleBinding"]["subjects"],
            [{
                "kind": "ServiceAccount",
                "name": "roebel-staging-participant-gateway-reconciler",
                "namespace": "flux-roebel-staging",
            }],
        )
        specification = flux["kustomization"]["spec"]
        self.assertEqual(
            {key: specification[key] for key in ("suspend", "prune", "force", "deletionPolicy", "path", "sourceRef", "dependsOn")},
            {
                "suspend": True,
                "prune": False,
                "force": False,
                "deletionPolicy": "Orphan",
                "path": "./reviewed-render/roebel-staging/staging-participant-gateway",
                "sourceRef": {
                    "kind": "GitRepository",
                    "name": "roebel-staging-operations",
                    "namespace": "flux-roebel-staging",
                },
                "dependsOn": [],
            },
        )
        rules = flux["role"]["rules"]
        self.assertNotIn("roebel-web-presentation", json.dumps(rules))
        self.assertEqual(
            [rule["resources"] for rule in rules],
            [["serviceaccounts", "services"], ["deployments"], ["networkpolicies", "ingresses"]],
        )
        reciprocal = VERIFIER.expected_participant_workbench_ingress_flux_objects()
        self.assertEqual(reciprocal["role"]["metadata"]["namespace"], "stadtstack-roebel-staging-lab")
        self.assertTrue(reciprocal["kustomization"]["spec"]["suspend"])

    def test_participant_uses_shared_active_flux_source_without_owning_it(self) -> None:
        source = VERIFIER.expected_participant_gateway_flux_source()
        self.assertEqual(source["spec"]["suspend"], False)
        self.assertEqual(source["spec"]["ref"], {"branch": "main"})
        self.assertNotIn("secretRef", source["spec"])
        self.assertNotIn("verify", source["spec"])

    def test_participant_gateway_origins_are_literal_while_secrets_contain_only_secret_material(self) -> None:
        protected = participant_ready_policy()
        with mock.patch.object(
            VERIFIER.PARTICIPANT_POLICY,
            "STATIC_ACTIVATION_POLICY",
            protected,
        ):
            pin = VERIFIER.PARTICIPANT_POLICY.expected_runtime_pin()
            resources = VERIFIER.expected_participant_gateway_resources(pin)
        container = resources["deployment"]["spec"]["template"]["spec"]["containers"][0]
        env = {
            item["name"]: item
            for item in container["env"]
        }
        self.assertEqual(env["ROEBEL_STAGING_PARTICIPANT_GATEWAY_GNOSIS_RPC_URL"], {"name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_GNOSIS_RPC_URL", "value": "https://rpc.gnosischain.com"})
        self.assertEqual(
            env["ROEBEL_STAGING_PARTICIPANT_GATEWAY_SUPABASE_URL"],
            {
                "name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_SUPABASE_URL",
                "value": VERIFIER.PARTICIPANT_POLICY.TRACER_POSTGREST_ORIGIN,
            },
        )
        for name, key in (
            ("ROEBEL_STAGING_PARTICIPANT_GATEWAY_SUPABASE_ANON_KEY", "supabase-anon-key"),
            ("ROEBEL_STAGING_PARTICIPANT_GATEWAY_SUPABASE_RPC_SECRET", "supabase-rpc-secret"),
        ):
            self.assertEqual(
                env[name]["valueFrom"]["secretKeyRef"],
                {
                    "key": key,
                    "name": VERIFIER.PARTICIPANT_POLICY.PARTICIPANT_POSTGREST_SECRET,
                    "optional": False,
                },
            )
        secret_keys = {
            item["valueFrom"]["secretKeyRef"]["key"]
            for item in env.values()
            if "valueFrom" in item
        }
        self.assertEqual(
            secret_keys,
            {
                "allowed-wallets",
                "invite-sha256",
                "mecky-pubkey",
                "session-key",
                "supabase-anon-key",
                "supabase-rpc-secret",
                "private-key-hex",
            },
        )
        expected_literals = {
            "ROEBEL_STAGING_PARTICIPANT_GATEWAY_SOURCE_REVISION": protected["productPins"]["sourceRevision"],
            "ROEBEL_STAGING_PARTICIPANT_GATEWAY_MANIFEST_DIGEST": protected["productPins"]["imageManifestDigest"],
            "ROEBEL_STAGING_PARTICIPANT_GATEWAY_MIGRATION_SHA256": protected["productPins"]["migration"]["sha256"],
            "ROEBEL_STAGING_PARTICIPANT_GATEWAY_DATABASE_SCHEMA_SHA256": protected["productPins"]["databaseSchemaSha256"],
            "ROEBEL_STAGING_PARTICIPANT_GATEWAY_TOPIC_TRACER_MIGRATION_SHA256": protected["productPins"]["topicTracerMigration"]["sha256"],
            "ROEBEL_STAGING_PARTICIPANT_GATEWAY_TOPIC_TRACER_DATABASE_SCHEMA_SHA256": protected["productPins"]["topicTracerDatabaseSchemaSha256"],
            "ROEBEL_STAGING_PARTICIPANT_GATEWAY_MUNICIPALITY_ID": protected["runtime"]["topicPolicy"]["municipalityId"],
            "ROEBEL_STAGING_PARTICIPANT_GATEWAY_SOURCE_CONVERSATION_TOPIC": protected["runtime"]["topicPolicy"]["sourceConversationTopic"],
            "ROEBEL_STAGING_PARTICIPANT_GATEWAY_TOPIC_POLICY_VERSION": protected["runtime"]["topicPolicy"]["policyVersion"],
        }
        for name, value in expected_literals.items():
            self.assertEqual(env[name], {"name": name, "value": value})
        self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
        self.assertNotIn("command", container)
        self.assertNotIn("args", container)
        self.assertNotIn("/app", [mount["mountPath"] for mount in container.get("volumeMounts", [])])

    def test_participant_gateway_runtime_release_pin_changes_only_published_artifact_leaves(self) -> None:
        policy = VERIFIER.PARTICIPANT_POLICY.activation_policy_descriptor()
        predecessor = VERIFIER.expected_participant_gateway_runtime_release_predecessor_pin(policy)
        successor = VERIFIER.expected_participant_gateway_runtime_release_pin(policy)
        self.assertEqual(
            {
                key
                for key in predecessor
                if predecessor[key] != successor[key]
            },
            {"sourceRevision", "sourceTreeSha256", "manifestDigest"},
        )
        self.assertEqual(
            successor["workflowSha256"],
            predecessor["workflowSha256"],
        )
        for key in (
            "activationPolicySha256",
            "migrationSha256",
            "databaseSchemaSha256",
            "topicTracerMigrationSha256",
            "topicTracerDatabaseSchemaSha256",
            "deactivationSha256",
            "municipalityId",
            "sourceConversationTopic",
            "topicPolicyVersion",
        ):
            self.assertEqual(successor[key], predecessor[key])

    def test_participant_gateway_runtime_release_lineage_is_exact_and_closed(self) -> None:
        policy = VERIFIER.PARTICIPANT_POLICY.activation_policy_descriptor()
        predecessor = VERIFIER.expected_participant_gateway_runtime_release_predecessor_pin(policy)
        successor = VERIFIER.expected_participant_gateway_runtime_release_pin(policy)
        self.assertEqual(
            {
                "sourceRevision": predecessor["sourceRevision"],
                "sourceTreeSha256": predecessor["sourceTreeSha256"],
                "manifestDigest": predecessor["manifestDigest"],
                "workflowSha256": predecessor["workflowSha256"],
            },
            {
                "sourceRevision": "f2e5c93c8fb0127d3aacc33d4be1a1a63f707dc1",
                "sourceTreeSha256": "sha256:0325e742e595de75a694d6662ffe6d84cd38818239c3f334d4ce802ed48ca819",
                "manifestDigest": "sha256:ba12dea1ebffa2cb85b58f135882085c66c1675f4461f27af116b63737a95a57",
                "workflowSha256": "sha256:a0c55933682bd94cb29630c83d6f7168ea19e9eba66a40d8132e8a91823c96c5",
            },
        )
        self.assertEqual(
            {
                "sourceRevision": successor["sourceRevision"],
                "sourceTreeSha256": successor["sourceTreeSha256"],
                "manifestDigest": successor["manifestDigest"],
                "workflowSha256": successor["workflowSha256"],
            },
            {
                "sourceRevision": "b81f273c8de5e825b60468df302f0e2057f51e2e",
                "sourceTreeSha256": "sha256:3b49a62498d560da36d0cb67121a1622260fb5690a51123e74c3c88712720974",
                "manifestDigest": "sha256:e8ba5a0dfce7340575abcd7e06e10f8153343571776b29f6ab3f54467ec80391",
                "workflowSha256": "sha256:a0c55933682bd94cb29630c83d6f7168ea19e9eba66a40d8132e8a91823c96c5",
            },
        )

    def test_participant_gateway_runtime_release_resources_change_only_three_deployment_leaves(self) -> None:
        policy = VERIFIER.PARTICIPANT_POLICY.activation_policy_descriptor()
        predecessor_pin = VERIFIER.expected_participant_gateway_runtime_release_predecessor_pin(policy)
        successor = VERIFIER.expected_participant_gateway_runtime_release_pin(policy)
        civic_projection = True
        predecessor = VERIFIER.expected_participant_gateway_resources(
            predecessor_pin,
            policy,
            civic_projection_route=civic_projection,
        )
        candidate = VERIFIER.expected_participant_gateway_resources(
            successor,
            policy,
            civic_projection_route=civic_projection,
        )
        normalized = copy.deepcopy(candidate)
        normalized["deployment"]["spec"]["template"]["spec"]["containers"][0]["image"] = (
            predecessor_pin["imageRepository"] + "@" + predecessor_pin["manifestDigest"]
        )
        environment = {
            item["name"]: item
            for item in normalized["deployment"]["spec"]["template"]["spec"]["containers"][0]["env"]
        }
        environment["ROEBEL_STAGING_PARTICIPANT_GATEWAY_SOURCE_REVISION"]["value"] = predecessor_pin["sourceRevision"]
        environment["ROEBEL_STAGING_PARTICIPANT_GATEWAY_MANIFEST_DIGEST"]["value"] = predecessor_pin["manifestDigest"]
        self.assertEqual(normalized, predecessor)

    def test_exact_participant_gateway_runtime_release_transition_is_admitted(self) -> None:
        base_temp, base = self.protected_participant_candidate()
        candidate_temp, candidate = self.protected_participant_candidate()
        self.addCleanup(base_temp.cleanup)
        self.addCleanup(candidate_temp.cleanup)
        self.apply_participant_gateway_runtime_release(candidate)
        result = VERIFIER.verify(candidate, base)
        self.assertTrue(result["baseTransitionVerified"])
        self.assertEqual(
            VERIFIER.changed_repository_files(candidate, base),
            VERIFIER.PARTICIPANT_GATEWAY_RUNTIME_RELEASE_TRANSITION_FILES,
        )

    def test_participant_gateway_runtime_release_rejects_activation_skips(self) -> None:
        base_temp, activation_base = self.current_v4_participant_fixture()
        predecessor_temp, predecessor = self.protected_participant_candidate()
        successor_temp, successor = self.protected_participant_candidate()
        self.addCleanup(base_temp.cleanup)
        self.addCleanup(predecessor_temp.cleanup)
        self.addCleanup(successor_temp.cleanup)

        protected = VERIFIER.verify_tree(activation_base)
        activation_pin = VERIFIER.PARTICIPANT_POLICY.expected_runtime_pin(
            protected["stagingParticipantGatewayPolicy"],
        )
        self.render_participant_gateway_runtime_pin(activation_base, activation_pin)
        self.apply_participant_gateway_runtime_release(successor)

        for label, candidate in (
            ("activation-to-predecessor", predecessor),
            ("activation-to-successor", successor),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    VERIFIER.VerificationError,
                    "predecessor pin drift",
                ):
                    VERIFIER.verify(candidate, activation_base)

    def test_participant_gateway_runtime_release_rejects_pin_resource_file_and_reverse_drift(self) -> None:
        pin_mutations = {
            "source": lambda value: value.__setitem__("sourceRevision", "f" * 40),
            "tree": lambda value: value.__setitem__("sourceTreeSha256", "sha256:" + "f" * 64),
            "image": lambda value: value.__setitem__("manifestDigest", "sha256:" + "f" * 64),
            "workflow": lambda value: value.__setitem__("workflowSha256", "sha256:" + "f" * 64),
            "activation": lambda value: value.__setitem__("activationPolicySha256", "sha256:" + "f" * 64),
            "database": lambda value: value.__setitem__("databaseSchemaSha256", "sha256:" + "f" * 64),
        }
        for label, mutate in pin_mutations.items():
            with self.subTest(label=label):
                candidate_temp, candidate = self.protected_participant_candidate()
                self.addCleanup(candidate_temp.cleanup)
                self.apply_participant_gateway_runtime_release(candidate)
                path = candidate / VERIFIER.PARTICIPANT_GATEWAY_ROOT / "runtime-pin.json"
                value = json.loads(path.read_text())
                mutate(value)
                path.write_text(json.dumps(value, indent=2) + "\n")
                with self.assertRaisesRegex(
                    VERIFIER.VerificationError,
                    "runtime pin drift",
                ):
                    VERIFIER.verify(candidate)

        base_temp, base = self.protected_participant_candidate()
        candidate_temp, candidate = self.protected_participant_candidate()
        self.addCleanup(base_temp.cleanup)
        self.addCleanup(candidate_temp.cleanup)
        self.apply_participant_gateway_runtime_release(candidate)
        deployment_path = candidate / VERIFIER.PARTICIPANT_GATEWAY_ROOT / "deployment.json"
        deployment = json.loads(deployment_path.read_text())
        deployment["spec"]["template"]["spec"]["containers"][0]["image"] = "invalid"
        deployment_path.write_text(json.dumps(deployment, indent=2) + "\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "resource drift"):
            VERIFIER.verify(candidate)

        base_temp, base = self.protected_participant_candidate()
        candidate_temp, candidate = self.protected_participant_candidate()
        self.addCleanup(base_temp.cleanup)
        self.addCleanup(candidate_temp.cleanup)
        self.apply_participant_gateway_runtime_release(candidate)
        policy_path = candidate / VERIFIER.PARTICIPANT_GATEWAY_ROOT / "networkpolicy.json"
        policy_path.write_text(policy_path.read_text() + "\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "changed file set drift"):
            VERIFIER.verify(candidate, base)

        successor_temp, successor = self.protected_participant_candidate()
        old_temp, old = self.protected_participant_candidate()
        self.addCleanup(successor_temp.cleanup)
        self.addCleanup(old_temp.cleanup)
        self.apply_participant_gateway_runtime_release(successor)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "predecessor pin drift"):
            VERIFIER.verify(old, successor)

    def test_legacy_participant_secret_verifier_matches_static_three_key_contract(self) -> None:
        def record(target_name: str, key_set: list[str], semantic_checks: dict[str, bool]) -> dict:
            value = {
                "target": VERIFIER.participant_gateway_target("Secret", target_name, VERIFIER.PARTICIPANT_GATEWAY_NAMESPACE),
                "uid": "00000000-0000-4000-8000-000000000001",
                "resourceVersion": "123",
                "keySet": key_set,
                "state": "present-exact-keyset",
                "semanticChecks": semantic_checks,
                "materializedAt": "2026-08-25T10:00:00Z",
                "validUntil": "2026-08-25T10:05:00Z",
                "maxAgeSeconds": 300,
                "vaultArm": "roebel_staging_participant_environment_arm=staging-only",
            }
            value["receiptCanonicalSha256"] = VERIFIER.digest(value)
            return value

        config = record(
            VERIFIER.PARTICIPANT_GATEWAY_CONFIG_SECRET,
            ["allowed-wallets", "invite-sha256", "mecky-pubkey"],
            {"inviteSha256Is64LowerHex": True, "meckyPubkeyIs64LowerHex": True, "walletAllowListNonEmptyNormalized": True},
        )
        runtime = record(
            VERIFIER.PARTICIPANT_GATEWAY_RUNTIME_SECRET,
            ["session-key", "supabase-anon-key", "supabase-rpc-secret"],
            {"sessionHmacKeyAtLeast32Bytes": True, "sessionHmacKeyHighEntropy": True, "stagingSupabaseAnonCredentialValid": True, "stagingRpcSecretAccepted": True},
        )
        VERIFIER.verify_participant_gateway_secret_materialization({"config": config, "runtime": runtime}, "participant Secrets")
        config_without_mecky = copy.deepcopy(config)
        config_without_mecky["keySet"] = ["allowed-wallets", "invite-sha256"]
        config_without_mecky["receiptCanonicalSha256"] = VERIFIER.digest({key: value for key, value in config_without_mecky.items() if key != "receiptCanonicalSha256"})
        with self.assertRaisesRegex(VERIFIER.VerificationError, "key set invalid"):
            VERIFIER.verify_participant_gateway_secret_materialization({"config": config_without_mecky, "runtime": runtime}, "participant Secrets")

    def test_participant_database_preflight_binds_both_topic_tracer_hashes(self) -> None:
        policy = participant_ready_policy()
        runtime_pin = VERIFIER.PARTICIPANT_POLICY.expected_runtime_pin(policy)
        value = {
            "databaseProject": "vdlksxpihmoumebjpeix",
            "environment": "staging",
            "vaultArm": "roebel_staging_participant_environment_arm=staging-only",
            "migrationSha256": runtime_pin["migrationSha256"],
            "schemaSha256": runtime_pin["databaseSchemaSha256"],
            "topicTracerMigrationSha256": runtime_pin["topicTracerMigrationSha256"],
            "topicTracerDatabaseSchemaSha256": runtime_pin["topicTracerDatabaseSchemaSha256"],
            "observedAt": "2026-08-25T10:00:00Z",
            "validUntil": "2026-08-25T10:05:00Z",
            "maxAgeSeconds": 300,
            "apiOutcome": "staging-schema-and-vault-arm-exact",
        }
        value["receiptCanonicalSha256"] = VERIFIER.digest(value)
        self.assertEqual(
            VERIFIER.verify_participant_gateway_database_preflight(
                value,
                runtime_pin,
                "participant database preflight",
            ),
            value,
        )
        drifted = copy.deepcopy(value)
        drifted["topicTracerMigrationSha256"] = "sha256:" + "0" * 64
        drifted["receiptCanonicalSha256"] = VERIFIER.digest(
            {key: item for key, item in drifted.items() if key != "receiptCanonicalSha256"},
        )
        with self.assertRaisesRegex(VERIFIER.VerificationError, "pinned schema contract drift"):
            VERIFIER.verify_participant_gateway_database_preflight(
                drifted,
                runtime_pin,
                "participant database preflight",
            )

    def test_participant_gateway_runtime_is_blocked_without_exact_policy_evidence(self) -> None:
        policy = VERIFIER.PARTICIPANT_POLICY.activation_policy_descriptor()
        self.assertTrue(policy["activationReady"])
        current = VERIFIER.PARTICIPANT_POLICY.expected_runtime_pin(policy)
        self.assertEqual(
            VERIFIER.verify_participant_gateway_runtime_pin(current, policy),
            current,
        )
        pin = {
            "schemaVersion": "roebel_staging_participant_gateway_runtime_pin_v3",
            "component": "staging-participant-gateway",
            "sourceRevision": "a" * 40,
            "imageRepository": VERIFIER.PARTICIPANT_GATEWAY_IMAGE,
            "manifestDigest": "sha256:" + "b" * 64,
            "workflowIdentity": VERIFIER.PARTICIPANT_GATEWAY_WORKFLOW,
        }
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            "runtime pin drift",
        ):
            VERIFIER.verify_participant_gateway_runtime_pin(pin, policy)

    def test_participant_render_is_rejected_while_static_policy_is_not_ready(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        self.assertEqual(
            VERIFIER.verify_participant_gateway_static_policy(
                candidate,
                "reviewed-public-knowledge-participant-gateway",
            ),
            VERIFIER.PARTICIPANT_POLICY.activation_policy_descriptor(),
        )

    def test_candidate_cannot_widen_static_activation_policy(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        path = candidate / VERIFIER.PARTICIPANT_POLICY.POLICY_PATH
        policy = json.loads(path.read_text())
        policy["network"]["conflictScan"]["staticInventoryHashes"] = True
        path.write_text(json.dumps(policy, indent=2) + "\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "activation policy drift"):
            VERIFIER.verify_participant_gateway_static_policy(candidate, "reviewed-public-knowledge")

    def test_exact_participant_activation_policy_transition_is_admitted_as_data(self) -> None:
        base = self.current_base()
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        self.participant_activation_policy_transition(candidate)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            "requires the admitted C1 data plane",
        ):
            VERIFIER.verify(candidate, base)

    def test_participant_activation_policy_transition_rejects_each_fact_drift(self) -> None:
        mutations = {
            "api-origin": lambda value: value["clusterIdentity"].__setitem__("apiOrigin", "https://10.255.240.12:6443"),
            "ca": lambda value: value["clusterIdentity"].__setitem__("caCertificateSha256", "sha256:" + "a" * 64),
            "spki": lambda value: value["clusterIdentity"].__setitem__("apiServerSpkiSha256", "sha256:" + "b" * 64),
            "cluster-uid": lambda value: value["clusterIdentity"].__setitem__("kubeSystemNamespaceUid", "00000000-0000-4000-8000-000000000001"),
            "external-postgrest": lambda value: value["endpoints"]["supabase"].__setitem__("internalOrigin", "https://example.invalid"),
            "postgrest-service": lambda value: value["endpoints"]["supabase"]["service"].__setitem__("name", "other-postgrest"),
            "postgrest-ingress": lambda value: value["endpoints"]["supabase"].__setitem__("externalIngress", True),
            "readiness": lambda value: value.__setitem__("activationReady", False),
            "extra": lambda value: value.__setitem__("liveEvidence", {"trusted": True}),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                base = self.current_base()
                temp, candidate = self.candidate()
                self.addCleanup(temp.cleanup)
                self.participant_activation_policy_transition(candidate)
                path = candidate / VERIFIER.PARTICIPANT_POLICY.POLICY_PATH
                value = json.loads(path.read_text())
                mutate(value)
                path.write_text(json.dumps(value, indent=2) + "\n")
                with self.assertRaisesRegex(VERIFIER.VerificationError, "activation policy drift"):
                    VERIFIER.verify(candidate, base)

    def test_participant_activation_policy_transition_rejects_partial_contract_and_reverse(self) -> None:
        base = self.current_base()
        temp, partial = self.candidate()
        self.addCleanup(temp.cleanup)
        self.participant_activation_policy_transition(partial)
        contract_path = partial / "policy/repository-contract.json"
        contract = json.loads(contract_path.read_text())
        contract["stagingParticipantGatewayBoundary"]["activationReady"] = False
        contract_path.write_text(json.dumps(contract, indent=2) + "\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "repository contract drift"):
            VERIFIER.verify(partial, base)

        ready_temp, ready_base = self.candidate()
        self.addCleanup(ready_temp.cleanup)
        self.participant_activation_policy_transition(ready_base)
        current_temp, current_candidate = self.candidate()
        self.addCleanup(current_temp.cleanup)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            "requires the admitted C1 data plane",
        ):
            VERIFIER.verify(current_candidate, ready_base)

    def test_participant_activation_policy_transition_cannot_change_executable_render_or_live_files(self) -> None:
        self.assertEqual(
            VERIFIER.PARTICIPANT_ACTIVATION_POLICY_TRANSITION_FILES,
            {
                "policy/repository-contract.json",
                "policy/staging-participant-gateway-activation-policy.json",
            },
        )
        base = self.current_base()
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        self.participant_activation_policy_transition(candidate)
        readme = candidate / "README.md"
        readme.write_text(readme.read_text() + "\n")
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            "requires the admitted C1 data plane",
        ):
            VERIFIER.verify(candidate, base)

    def test_candidate_embedded_participant_live_evidence_api_is_closed(self) -> None:
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            "candidate-embedded participant activation evidence is forbidden",
        ):
            VERIFIER.verify_participant_gateway_activation_evidence({}, {})

    def test_signed_nostr_runtime_is_exact_but_blocked_pending_external_evidence(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        self.make_reviewed_knowledge_render(candidate)
        self.signed_nostr_runtime(candidate)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            "activation blocked: complete Gnosis, Flux, provenance, and anonymous-pull evidence require separate review",
        ):
            VERIFIER.verify_signed_nostr(candidate)

    def test_signed_nostr_runtime_rejects_service_account_or_relay_budget_widening(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        self.make_reviewed_knowledge_render(candidate)
        self.signed_nostr_runtime(candidate)
        deployment_path = candidate / "reviewed-render/roebel-staging/signed-nostr/workbench/deployment.json"
        deployment = json.loads(deployment_path.read_text())
        deployment["spec"]["template"]["spec"]["serviceAccountName"] = "default"
        deployment_path.write_text(json.dumps(deployment, indent=2) + "\n")
        previous_gate = VERIFIER.SIGNED_NOSTR_APPROVED_ACTIVATION_EVIDENCE
        VERIFIER.SIGNED_NOSTR_APPROVED_ACTIVATION_EVIDENCE = {"reviewed": True}
        self.addCleanup(lambda: setattr(VERIFIER, "SIGNED_NOSTR_APPROVED_ACTIVATION_EVIDENCE", previous_gate))
        with self.assertRaisesRegex(VERIFIER.VerificationError, "workbench Deployment drift"):
            VERIFIER.verify_signed_nostr(candidate)

    def test_signed_nostr_ingress_and_mecky_policy_allow_only_exact_new_surface(self) -> None:
        ingress = VERIFIER.expected_web_ingress(True)
        early = ingress["metadata"]["annotations"]["haproxy-ingress.github.io/config-backend-early"]
        self.assertIn("/stadtstack-test/api/session/admit", early)
        self.assertIn("/stadtstack-test/api/signed-event", early)
        for path in (
            "/stadtstack-test/healthz",
            "/stadtstack-test/api/config",
            "/stadtstack-test/api/feed",
            "/stadtstack-test/api/thread",
            "/stadtstack-test/api/conversation",
        ):
            self.assertIn(f"!{{ path {path} }}", early)
            self.assertNotIn(f"!{{ path_beg {path} }}", early)
        self.assertEqual(
            [entry["path"] for entry in ingress["spec"]["rules"][0]["http"]["paths"]],
            ["/supabase-read", "/stadtstack-test", "/"],
        )
        policy = VERIFIER.expected_public_mecky_network_policy(True, True)
        egress = policy["spec"]["egress"]
        self.assertEqual(len(egress), 3)
        self.assertEqual(
            [item["to"][0]["podSelector"]["matchLabels"]["app.kubernetes.io/name"] for item in egress[1:]],
            ["citizen-relay", "agent-relay"],
        )

    def test_signed_nostr_relay_network_policies_require_both_exact_peers(self) -> None:
        expected_workbench = {
            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": VERIFIER.SIGNED_NOSTR_WEB_NAMESPACE}},
            "podSelector": {"matchLabels": VERIFIER.signed_nostr_labels("workbench")},
        }
        expected_mecky = {
            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": VERIFIER.SIGNED_NOSTR_NAMESPACE}},
            "podSelector": {"matchLabels": VERIFIER.PUBLIC_MECKY_LABELS},
        }
        for relay in ("citizen-relay", "agent-relay"):
            with self.subTest(relay=relay):
                temp, candidate = self.candidate()
                self.addCleanup(temp.cleanup)
                self.make_reviewed_knowledge_render(candidate)
                self.signed_nostr_runtime(candidate)
                path = candidate / f"reviewed-render/roebel-staging/signed-nostr/{relay}/networkpolicy.json"
                policy = json.loads(path.read_text())
                self.assertEqual(policy["spec"]["ingress"][0]["from"], [expected_workbench, expected_mecky])
                policy["spec"]["ingress"][0]["from"][1]["namespaceSelector"] = {}
                path.write_text(json.dumps(policy, indent=2) + "\n")
                previous_gate = VERIFIER.SIGNED_NOSTR_APPROVED_ACTIVATION_EVIDENCE
                VERIFIER.SIGNED_NOSTR_APPROVED_ACTIVATION_EVIDENCE = {"reviewed": True}
                try:
                    with self.assertRaisesRegex(VERIFIER.VerificationError, f"{relay} NetworkPolicy drift"):
                        VERIFIER.verify_signed_nostr(candidate)
                finally:
                    VERIFIER.SIGNED_NOSTR_APPROVED_ACTIVATION_EVIDENCE = previous_gate

    def test_signed_nostr_ingress_rejects_suffix_admin_and_fixture_read_variants(self) -> None:
        for variant in (
            "/stadtstack-test/api/config/fixture",
            "/stadtstack-test/api/administration",
            "/stadtstack-test/api/feed/extra",
        ):
            with self.subTest(variant=variant):
                temp, candidate = self.candidate()
                self.addCleanup(temp.cleanup)
                ingress_path = candidate / "reviewed-render/roebel-staging/web/ingress.json"
                ingress = VERIFIER.expected_web_ingress(True)
                early_key = "haproxy-ingress.github.io/config-backend-early"
                ingress["metadata"]["annotations"][early_key] += f" !{{ path {variant} }}"
                ingress_path.write_text(json.dumps(ingress, indent=2) + "\n")
                with self.assertRaisesRegex(VERIFIER.VerificationError, "Web Ingress drift"):
                    VERIFIER.verify_web_ingress(candidate, True)

    def test_signed_nostr_publisher_pin_checksum_and_anonymous_receipts_are_bound(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        pin = self.signed_nostr_pin(candidate)
        publisher = pin["publisherPin"]
        pin["publisherPinCanonicalSha256"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(VERIFIER.VerificationError, "canonical checksum invalid"):
            VERIFIER.verify_signed_nostr_runtime_pin(pin)

        pin = self.signed_nostr_reviewed_pin(candidate)
        publisher = pin["publisherPin"]
        self.assertEqual(
            VERIFIER.verify_signed_nostr_runtime_pin(pin)["publisherPin"],
            publisher,
        )

        pin = self.signed_nostr_reviewed_pin(candidate)
        pin["activationEvidence"]["anonymousDigestPullReceipts"][0]["resolvedManifestDigest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(VERIFIER.VerificationError, "resolved digest invalid"):
            VERIFIER.verify_signed_nostr_runtime_pin(pin)

        pin = self.signed_nostr_reviewed_pin(candidate)
        pin["activationEvidence"]["anonymousDigestPullReceipts"][0]["authConfigCanonicalSha256"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(VERIFIER.VerificationError, "auth hash invalid"):
            VERIFIER.verify_signed_nostr_runtime_pin(pin)

        pin = self.signed_nostr_reviewed_pin(candidate)
        pin["activationEvidence"]["anonymousDigestPullReceipts"][0]["receiptDigest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(VERIFIER.VerificationError, "checksum invalid"):
            VERIFIER.verify_signed_nostr_runtime_pin(pin)

        pin = self.signed_nostr_reviewed_pin(candidate)
        pin["activationEvidence"]["anonymousDigestPullReceipts"].reverse()
        with self.assertRaisesRegex(VERIFIER.VerificationError, "component order invalid"):
            VERIFIER.verify_signed_nostr_runtime_pin(pin)

        pin = self.signed_nostr_reviewed_pin(candidate)
        pin["publisherPin"]["components"].reverse()
        pin["publisherPinCanonicalSha256"] = VERIFIER.digest(pin["publisherPin"])
        pin["activationEvidence"]["publisherPinCanonicalSha256"] = pin["publisherPinCanonicalSha256"]
        for receipt in pin["activationEvidence"]["anonymousDigestPullReceipts"]:
            receipt["publisherPinCanonicalSha256"] = pin["publisherPinCanonicalSha256"]
            receipt["receiptDigest"] = VERIFIER.digest({key: item for key, item in receipt.items() if key != "receiptDigest"})
        with self.assertRaisesRegex(VERIFIER.VerificationError, "publisher component order invalid"):
            VERIFIER.verify_signed_nostr_runtime_pin(pin)

        pin = self.signed_nostr_reviewed_pin(candidate)
        pin["activationEvidence"]["anonymousDigestPullReceipts"][0]["schemaVersion"] = "roebel_signed_nostr_anonymous_digest_pull_receipt_v0"
        with self.assertRaisesRegex(VERIFIER.VerificationError, "schema invalid"):
            VERIFIER.verify_signed_nostr_runtime_pin(pin)

        pin = self.signed_nostr_reviewed_pin(candidate)
        pin["activationEvidence"]["anonymousDigestPullReceipts"][0]["publisherPinCanonicalSha256"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(VERIFIER.VerificationError, "publisher checksum binding invalid"):
            VERIFIER.verify_signed_nostr_runtime_pin(pin)

    def test_signed_nostr_activation_evidence_is_closed_for_every_field_and_requires_exact_policy(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        self.make_reviewed_knowledge_render(candidate)
        pin = self.signed_nostr_reviewed_pin(candidate)
        evidence = pin["activationEvidence"]
        publisher = pin["publisherPin"]
        publisher_sha = pin["publisherPinCanonicalSha256"]
        self.assertEqual(
            VERIFIER.verify_signed_nostr_activation_evidence(evidence, publisher, publisher_sha, pin["rollback"]),
            evidence,
        )

        changed = copy.deepcopy(evidence)
        changed["fluxBindings"][2]["kustomization"]["object"]["metadata"]["name"] = changed["fluxBindings"][1]["kustomization"]["object"]["metadata"]["name"]
        with self.assertRaisesRegex(VERIFIER.VerificationError, "Kustomization object invalid"):
            VERIFIER.verify_signed_nostr_activation_evidence(changed, publisher, publisher_sha, pin["rollback"])

        changed = copy.deepcopy(evidence)
        changed["components"][0]["sbomAttestation"] = copy.deepcopy(changed["components"][0]["provenance"])
        changed_publisher = copy.deepcopy(publisher)
        changed_publisher["components"][0]["sbomAttestation"] = copy.deepcopy(changed_publisher["components"][0]["provenance"])
        with self.assertRaisesRegex(VERIFIER.VerificationError, "receipt id reused"):
            VERIFIER.verify_signed_nostr_activation_evidence(changed, changed_publisher, publisher_sha, pin["rollback"])

        changed = copy.deepcopy(evidence)
        changed["components"][1]["sbomAttestation"]["attestationDigest"] = changed["components"][0]["provenance"]["attestationDigest"]
        with self.assertRaisesRegex(VERIFIER.VerificationError, "attestation digest reused"):
            VERIFIER.verify_signed_nostr_activation_evidence(changed, publisher, publisher_sha, pin["rollback"])

        changed = copy.deepcopy(evidence)
        changed["gnosisRpcEgress"]["privateProxy"]["service"]["object"]["spec"]["type"] = "LoadBalancer"
        with self.assertRaisesRegex(VERIFIER.VerificationError, "private proxy Service object invalid"):
            VERIFIER.verify_signed_nostr_activation_evidence(changed, publisher, publisher_sha, pin["rollback"])

        changed = copy.deepcopy(evidence)
        changed["gnosisRpcEgress"]["workbenchNetworkPolicy"]["object"]["spec"]["egress"].append({"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]})
        with self.assertRaisesRegex(VERIFIER.VerificationError, "NetworkPolicy object invalid"):
            VERIFIER.verify_signed_nostr_activation_evidence(changed, publisher, publisher_sha, pin["rollback"])

        changed = copy.deepcopy(evidence)
        changed["gnosisRpcEgress"]["workbenchNetworkPolicy"]["objectDigest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(VERIFIER.VerificationError, "NetworkPolicy digest binding invalid"):
            VERIFIER.verify_signed_nostr_activation_evidence(changed, publisher, publisher_sha, pin["rollback"])

        # Every closed record rejects an unknown key and every required field
        # rejects deletion or a nonconforming mutation.  This deliberately
        # exercises nested component attestations, Flux/RBAC, Gnosis evidence,
        # and both anonymous receipts without relying on a live value.
        for record in self.nested_dicts(evidence):
            for key in tuple(record):
                with self.subTest(kind="missing", key=key):
                    changed = copy.deepcopy(evidence)
                    target = next(item for item in self.nested_dicts(changed) if set(item) == set(record))
                    # Structural equality is ambiguous for some test fixtures;
                    # mutate the first matching closed record through a stable
                    # unique marker by applying the operation to all matches.
                    for candidate_record in self.nested_dicts(changed):
                        if candidate_record == record:
                            candidate_record.pop(key)
                            break
                    with self.assertRaises(VERIFIER.VerificationError):
                        VERIFIER.verify_signed_nostr_activation_evidence(changed, publisher, publisher_sha, pin["rollback"])
                with self.subTest(kind="unknown", key=key):
                    changed = copy.deepcopy(evidence)
                    for candidate_record in self.nested_dicts(changed):
                        if candidate_record == record:
                            candidate_record["unexpected"] = True
                            break
                    with self.assertRaises(VERIFIER.VerificationError):
                        VERIFIER.verify_signed_nostr_activation_evidence(changed, publisher, publisher_sha, pin["rollback"])
                with self.subTest(kind="mutation", key=key):
                    if record[key] is None:
                        # Null is the intentional closed representation for an
                        # observed-absent object and for non-Kustomization
                        # post-suspend state. Missing/unknown-key checks above
                        # still prove that the field itself is mandatory.
                        continue
                    changed = copy.deepcopy(evidence)
                    for candidate_record in self.nested_dicts(changed):
                        if candidate_record == record:
                            candidate_record[key] = None
                            break
                    with self.assertRaises(VERIFIER.VerificationError):
                        VERIFIER.verify_signed_nostr_activation_evidence(changed, publisher, publisher_sha, pin["rollback"])

        self.signed_nostr_runtime(candidate, reviewed=True)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "activation blocked"):
            VERIFIER.verify_signed_nostr(candidate)

        previous = VERIFIER.SIGNED_NOSTR_APPROVED_ACTIVATION_EVIDENCE
        VERIFIER.SIGNED_NOSTR_APPROVED_ACTIVATION_EVIDENCE = copy.deepcopy(evidence)
        self.addCleanup(lambda: setattr(VERIFIER, "SIGNED_NOSTR_APPROVED_ACTIVATION_EVIDENCE", previous))
        self.assertIn("components", VERIFIER.verify_signed_nostr(candidate))

        VERIFIER.SIGNED_NOSTR_APPROVED_ACTIVATION_EVIDENCE = copy.deepcopy(evidence)
        VERIFIER.SIGNED_NOSTR_APPROVED_ACTIVATION_EVIDENCE["gnosisRpcEgress"]["chainId"] = 1
        with self.assertRaisesRegex(VERIFIER.VerificationError, "does not equal the exact approved policy record"):
            VERIFIER.verify_signed_nostr(candidate)

    def test_signed_nostr_gnosis_proxy_and_flux_objects_are_exact_and_credential_free(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        pin = self.signed_nostr_reviewed_pin(candidate)
        evidence = pin["activationEvidence"]
        publisher = pin["publisherPin"]
        publisher_sha = pin["publisherPinCanonicalSha256"]
        proxy = evidence["gnosisRpcEgress"]["privateProxy"]
        environment = proxy["deployment"]["object"]["spec"]["template"]["spec"]["containers"][0]["env"]
        self.assertEqual(
            {item["name"] for item in environment},
            {
                "ROEBEL_RUNTIME_ROLE",
                "GNOSIS_PROXY_BIND_HOST",
                "GNOSIS_PROXY_PORT",
                "GNOSIS_PROXY_UPSTREAM_URL",
                "GNOSIS_PROXY_EXPECTED_CHAIN_ID",
                "GNOSIS_PROXY_ALLOWED_METHODS",
                "GNOSIS_PROXY_MAX_BODY_BYTES",
                "GNOSIS_PROXY_UPSTREAM_TIMEOUT_MS",
                "GNOSIS_PROXY_MAX_CONCURRENT",
            },
        )
        self.assertTrue(all("valueFrom" not in item for item in environment))
        workbench = VERIFIER.verify_signed_nostr_runtime_pin(pin)
        resources = VERIFIER.expected_signed_nostr_resources(workbench)
        workbench_env = resources["workbench"]["deployment"]["spec"]["template"]["spec"]["containers"][0]["env"]
        self.assertIn(
            {
                "name": "GNOSIS_RPC_URL",
                "value": "http://gnosis-private-rpc.stadtstack-roebel-web-preview.svc.cluster.local:8545",
            },
            workbench_env,
        )
        self.assertIn(
            {
                "name": "LEGACY_SYNTHETIC_PUBKEYS_JSON",
                "value": "[\"21abe1bf2bf9a906d356488d107db36d505b55d54c20ab46792fcd31c4e1b88a\",\"7c6ed2e0b6ae1ea67523d055b1194e55036522c397e589c2bb20f0c68b558974\"]",
            },
            workbench_env,
        )

        mutations = []
        changed = copy.deepcopy(evidence)
        changed["gnosisRpcEgress"]["upstream"]["pinnedIpv4Cidr"] = "0.0.0.0/0"
        mutations.append(changed)
        changed = copy.deepcopy(evidence)
        changed["gnosisRpcEgress"]["privateProxy"]["deployment"]["object"]["spec"]["template"]["spec"]["containers"][0]["env"][5]["value"] += ",eth_sendRawTransaction"
        mutations.append(changed)
        changed = copy.deepcopy(evidence)
        changed["gnosisRpcEgress"]["privateProxy"]["networkPolicy"]["object"]["spec"]["egress"][1]["to"][0]["ipBlock"]["cidr"] = "0.0.0.0/0"
        mutations.append(changed)
        changed = copy.deepcopy(evidence)
        changed["fluxBindings"][0]["serviceAccount"]["object"]["metadata"]["namespace"] = "stadtstack-roebel-web-preview"
        mutations.append(changed)
        changed = copy.deepcopy(evidence)
        changed["fluxBindings"][0]["role"]["object"]["rules"][0]["verbs"].append("create")
        mutations.append(changed)
        changed = copy.deepcopy(evidence)
        changed["fluxBindings"][0]["kustomization"]["object"]["spec"]["prune"] = True
        mutations.append(changed)
        for changed in mutations:
            with self.assertRaises(VERIFIER.VerificationError):
                VERIFIER.verify_signed_nostr_activation_evidence(changed, publisher, publisher_sha, pin["rollback"])

    def test_signed_nostr_live_ownership_preconditions_reject_absence_or_uid_drift(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        pin = self.signed_nostr_reviewed_pin(candidate)
        evidence = pin["activationEvidence"]

        changed = copy.deepcopy(evidence)
        precondition = changed["lifecycle"]["livePreconditions"][0]
        precondition.update({
            "state": "present-exact",
            "uid": "30000000-0000-4000-8000-000000000001",
            "resourceVersion": "77",
            "currentObjectDigest": "sha256:" + "0" * 64,
        })
        with self.assertRaisesRegex(VERIFIER.VerificationError, "not exact"):
            VERIFIER.verify_signed_nostr_activation_evidence(
                changed,
                pin["publisherPin"],
                pin["publisherPinCanonicalSha256"],
                pin["rollback"],
            )

        changed = copy.deepcopy(evidence)
        changed["lifecycle"]["bootstrapReceipt"]["postconditions"][0]["uid"] = (
            "30000000-0000-4000-8000-000000000002"
        )
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify_signed_nostr_activation_evidence(
                changed,
                pin["publisherPin"],
                pin["publisherPinCanonicalSha256"],
                pin["rollback"],
            )

    def test_signed_nostr_bootstrap_uses_atomic_create_and_exact_present_no_op(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        pin = self.signed_nostr_reviewed_pin(candidate)
        evidence = pin["activationEvidence"]
        lifecycle = evidence["lifecycle"]
        precondition = lifecycle["livePreconditions"][0]
        postcondition = lifecycle["bootstrapReceipt"]["postconditions"][0]

        # Convert one valid absent/create receipt into one valid
        # present-exact/no-op receipt while keeping its exact identity.
        precondition.update({
            "state": "present-exact",
            "uid": postcondition["uid"],
            "resourceVersion": postcondition["resourceVersion"],
            "currentObjectDigest": precondition["desiredObjectDigest"],
        })
        postcondition.update({
            "action": "retained-exact-owned-object-no-op",
            "apiOperation": "none",
            "requiredUid": precondition["uid"],
            "requiredResourceVersion": precondition["resourceVersion"],
            "conflictPolicy": "fail-on-uid-or-resourceVersion-mismatch-no-adopt",
            "apiOutcome": "unchanged-after-atomic-precondition-recheck",
        })
        bootstrap = lifecycle["bootstrapReceipt"]
        bootstrap["preconditionsCanonicalSha256"] = VERIFIER.digest(lifecycle["livePreconditions"])
        bootstrap["postconditionsCanonicalSha256"] = VERIFIER.digest(bootstrap["postconditions"])
        live = lifecycle["activationLiveRecheck"]
        live["bootstrapReceiptCanonicalSha256"] = VERIFIER.digest(bootstrap)
        live["objectStates"] = copy.deepcopy(bootstrap["postconditions"])
        live["objectStatesCanonicalSha256"] = VERIFIER.digest(live["objectStates"])
        lifecycle["reconcileActivationReceipt"]["liveRecheckCanonicalSha256"] = VERIFIER.digest(live)
        self.assertEqual(
            VERIFIER.verify_signed_nostr_activation_evidence(
                evidence,
                pin["publisherPin"],
                pin["publisherPinCanonicalSha256"],
                pin["rollback"],
            ),
            evidence,
        )

        present_mutations = (
            ("requiredUid", "90000000-0000-4000-8000-000000000001"),
            ("requiredResourceVersion", "999"),
            ("uid", "90000000-0000-4000-8000-000000000002"),
            ("resourceVersion", "998"),
        )
        for field, value in present_mutations:
            with self.subTest(field=field):
                changed = copy.deepcopy(evidence)
                changed["lifecycle"]["bootstrapReceipt"]["postconditions"][0][field] = value
                with self.assertRaises(VERIFIER.VerificationError):
                    VERIFIER.verify_signed_nostr_activation_evidence(
                        changed,
                        pin["publisherPin"],
                        pin["publisherPinCanonicalSha256"],
                        pin["rollback"],
                    )

        absent = self.signed_nostr_reviewed_pin(candidate)
        absent_post = absent["activationEvidence"]["lifecycle"]["bootstrapReceipt"]["postconditions"][0]
        absent_post["apiOperation"] = "PATCH-apply"
        with self.assertRaisesRegex(VERIFIER.VerificationError, "not atomic create-only"):
            VERIFIER.verify_signed_nostr_activation_evidence(
                absent["activationEvidence"],
                absent["publisherPin"],
                absent["publisherPinCanonicalSha256"],
                absent["rollback"],
            )

    def test_signed_nostr_activation_transition_requires_current_exact_preflight(self) -> None:
        base_temp, reviewed = self.candidate()
        self.addCleanup(base_temp.cleanup)
        self.make_reviewed_knowledge_render(reviewed)
        self.enable_reviewed_mecky_egress(reviewed)

        signed_temp = tempfile.TemporaryDirectory()
        self.addCleanup(signed_temp.cleanup)
        signed = Path(signed_temp.name) / "signed"
        shutil.copytree(reviewed, signed)
        evidence = self.make_signed_nostr_render(signed)

        VERIFIER.SIGNED_NOSTR_APPROVED_ACTIVATION_EVIDENCE = None
        with self.assertRaisesRegex(VERIFIER.VerificationError, "activation blocked"):
            VERIFIER.verify(signed, reviewed)

        VERIFIER.SIGNED_NOSTR_APPROVED_ACTIVATION_EVIDENCE = copy.deepcopy(evidence)
        self.assertTrue(VERIFIER.verify(signed, reviewed)["baseTransitionVerified"])

        VERIFIER.SIGNED_NOSTR_VERIFICATION_TIME_OVERRIDE = datetime(
            2026, 8, 24, 12, 8, 0, tzinfo=timezone.utc,
        )
        with self.assertRaisesRegex(VERIFIER.VerificationError, "outside the current five-minute preflight"):
            VERIFIER.verify(signed, reviewed)
        # Freshness grants the transition once; it must not make an already
        # active exact render unverifiable after the original preflight.
        self.assertFalse(VERIFIER.verify(signed)["baseTransitionVerified"])

        VERIFIER.SIGNED_NOSTR_VERIFICATION_TIME_OVERRIDE = datetime(
            2026, 8, 24, 12, 1, 0, tzinfo=timezone.utc,
        )
        with self.assertRaisesRegex(VERIFIER.VerificationError, "future-dated"):
            VERIFIER.verify(signed, reviewed)

    def test_signed_nostr_deactivation_transition_requires_fresh_exact_total_absence(self) -> None:
        reviewed_temp, reviewed = self.candidate()
        self.addCleanup(reviewed_temp.cleanup)
        self.make_reviewed_knowledge_render(reviewed)
        self.enable_reviewed_mecky_egress(reviewed)

        signed_temp = tempfile.TemporaryDirectory()
        self.addCleanup(signed_temp.cleanup)
        signed = Path(signed_temp.name) / "signed"
        shutil.copytree(reviewed, signed)
        evidence = self.make_signed_nostr_render(signed)
        VERIFIER.SIGNED_NOSTR_APPROVED_ACTIVATION_EVIDENCE = copy.deepcopy(evidence)
        deactivation = self.deactivation_receipt(evidence)
        VERIFIER.SIGNED_NOSTR_VERIFICATION_TIME_OVERRIDE = datetime(
            2026, 8, 24, 12, 16, 0, tzinfo=timezone.utc,
        )

        VERIFIER.SIGNED_NOSTR_APPROVED_DEACTIVATION_EVIDENCE = None
        with self.assertRaisesRegex(VERIFIER.VerificationError, "deactivation blocked"):
            VERIFIER.verify(reviewed, signed)

        VERIFIER.SIGNED_NOSTR_APPROVED_DEACTIVATION_EVIDENCE = copy.deepcopy(deactivation)
        self.assertTrue(VERIFIER.verify(reviewed, signed)["baseTransitionVerified"])

        mutations = [
            ("UID", lambda value: value["stepReceipts"][0].update({"requiredUid": "90000000-0000-4000-8000-000000000001"})),
            ("digest", lambda value: value["stepReceipts"][4].update({"beforeObjectDigest": "sha256:" + "0" * 64})),
            ("boundary", lambda value: value["boundaryVerification"].update({"integritySha256": "sha256:" + "0" * 64})),
            ("absence", lambda value: value["absenceVerification"].update({"status": "target-recreated"})),
        ]
        for label, mutate in mutations:
            with self.subTest(label=label):
                changed = copy.deepcopy(deactivation)
                mutate(changed)
                VERIFIER.SIGNED_NOSTR_APPROVED_DEACTIVATION_EVIDENCE = changed
                with self.assertRaises(VERIFIER.VerificationError):
                    VERIFIER.verify(reviewed, signed)

        VERIFIER.SIGNED_NOSTR_APPROVED_DEACTIVATION_EVIDENCE = copy.deepcopy(deactivation)
        VERIFIER.SIGNED_NOSTR_VERIFICATION_TIME_OVERRIDE = datetime(
            2026, 8, 24, 12, 21, 0, tzinfo=timezone.utc,
        )
        with self.assertRaisesRegex(VERIFIER.VerificationError, "expired, or replayed"):
            VERIFIER.verify(reviewed, signed)

        VERIFIER.SIGNED_NOSTR_VERIFICATION_TIME_OVERRIDE = datetime(
            2026, 8, 24, 12, 14, 0, tzinfo=timezone.utc,
        )
        with self.assertRaisesRegex(VERIFIER.VerificationError, "future-dated"):
            VERIFIER.verify(reviewed, signed)

        invalid_window = copy.deepcopy(deactivation)
        invalid_window["validUntil"] = "2026-08-24T12:20:01Z"
        VERIFIER.SIGNED_NOSTR_APPROVED_DEACTIVATION_EVIDENCE = invalid_window
        VERIFIER.SIGNED_NOSTR_VERIFICATION_TIME_OVERRIDE = datetime(
            2026, 8, 24, 12, 16, 0, tzinfo=timezone.utc,
        )
        with self.assertRaisesRegex(VERIFIER.VerificationError, "validity window invalid"):
            VERIFIER.verify(reviewed, signed)

    def test_signed_nostr_rollback_inventory_covers_every_exact_target(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        pin = self.signed_nostr_reviewed_pin(candidate)
        evidence = pin["activationEvidence"]
        contract = evidence["lifecycle"]["rollbackContract"]
        targets = contract["absenceVerificationTargets"]
        self.assertEqual(len(targets), 24)
        self.assertEqual(len({tuple(target.values()) for target in targets}), 24)
        self.assertEqual(len(contract["runtimeTargets"]), 12)
        self.assertEqual(len(contract["identityTargets"]), 12)
        steps = VERIFIER.expected_signed_nostr_deactivation_steps(contract)
        self.assertEqual(len(steps), 28)
        self.assertEqual(
            [step["sequence"] for step in steps],
            list(range(1, 29)),
        )
        self.assertEqual(
            [step["action"] for step in steps[:4]],
            ["suspend-exact-reconciler"] * 3 + ["restore-four-public-boundary-bytes"],
        )
        for collection in ("runtimeTargets", "identityTargets"):
            for index in range(len(contract[collection])):
                with self.subTest(collection=collection, index=index):
                    changed = copy.deepcopy(evidence)
                    changed["lifecycle"]["rollbackContract"][collection].pop(index)
                    with self.assertRaisesRegex(VERIFIER.VerificationError, "rollback contract incomplete"):
                        VERIFIER.verify_signed_nostr_activation_evidence(
                            changed,
                            pin["publisherPin"],
                            pin["publisherPinCanonicalSha256"],
                            pin["rollback"],
                        )

    def test_signed_nostr_dns_tls_evidence_must_be_complete_fresh_and_equal_at_activation(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        pin = self.signed_nostr_reviewed_pin(candidate)
        evidence = pin["activationEvidence"]

        changed = copy.deepcopy(evidence)
        changed["gnosisRpcEgress"]["upstream"]["dnsTlsEvidence"]["validUntil"] = (
            "2026-08-24T12:05:01Z"
        )
        with self.assertRaisesRegex(VERIFIER.VerificationError, "stale"):
            VERIFIER.verify_signed_nostr_activation_evidence(
                changed,
                pin["publisherPin"],
                pin["publisherPinCanonicalSha256"],
                pin["rollback"],
            )

        changed = copy.deepcopy(evidence)
        changed["lifecycle"]["activationLiveRecheck"]["dnsTlsRecheck"]["tlsCertificate"]["certificateSha256"] = (
            "sha256:" + "f" * 64
        )
        with self.assertRaisesRegex(VERIFIER.VerificationError, "changed resolution or certificate"):
            VERIFIER.verify_signed_nostr_activation_evidence(
                changed,
                pin["publisherPin"],
                pin["publisherPinCanonicalSha256"],
                pin["rollback"],
            )

    def test_signed_nostr_bootstrap_stays_suspended_and_activation_cannot_outlive_preflight(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        pin = self.signed_nostr_reviewed_pin(candidate)
        evidence = pin["activationEvidence"]

        changed = copy.deepcopy(evidence)
        changed["lifecycle"]["bootstrapReceipt"]["kustomizationsInitiallySuspended"] = False
        with self.assertRaisesRegex(VERIFIER.VerificationError, "must start suspended"):
            VERIFIER.verify_signed_nostr_activation_evidence(
                changed,
                pin["publisherPin"],
                pin["publisherPinCanonicalSha256"],
                pin["rollback"],
            )

        changed = copy.deepcopy(evidence)
        kustomization = changed["fluxBindings"][0]["kustomization"]
        kustomization["object"]["spec"]["suspend"] = False
        kustomization["objectDigest"] = VERIFIER.digest(kustomization["object"])
        with self.assertRaisesRegex(VERIFIER.VerificationError, "Kustomization object invalid"):
            VERIFIER.verify_signed_nostr_activation_evidence(
                changed,
                pin["publisherPin"],
                pin["publisherPinCanonicalSha256"],
                pin["rollback"],
            )

        changed = copy.deepcopy(evidence)
        changed["lifecycle"]["reconcileActivationReceipt"]["completedAt"] = "2026-08-24T12:07:01Z"
        with self.assertRaisesRegex(VERIFIER.VerificationError, "outside the live-preflight window"):
            VERIFIER.verify_signed_nostr_activation_evidence(
                changed,
                pin["publisherPin"],
                pin["publisherPinCanonicalSha256"],
                pin["rollback"],
            )

    def test_signed_nostr_rollback_contract_and_completed_receipt_are_all_or_nothing(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        pin = self.signed_nostr_reviewed_pin(candidate)
        evidence = pin["activationEvidence"]
        contract = evidence["lifecycle"]["rollbackContract"]

        changed = copy.deepcopy(evidence)
        changed["lifecycle"]["rollbackContract"]["runtimeTargets"].pop()
        with self.assertRaisesRegex(VERIFIER.VerificationError, "rollback contract incomplete"):
            VERIFIER.verify_signed_nostr_activation_evidence(
                changed,
                pin["publisherPin"],
                pin["publisherPinCanonicalSha256"],
                pin["rollback"],
            )

        completed = "2026-08-24T12:15:00Z"
        deactivation = {
            "schemaVersion": VERIFIER.SIGNED_NOSTR_DEACTIVATION_EVIDENCE_SCHEMA,
            "canonicalEncoding": "canonical-json",
            "status": "completed-and-verified",
            "startedAt": "2026-08-24T12:05:00Z",
            "completedAt": completed,
            "validUntil": "2026-08-24T12:20:00Z",
            "maxAgeSeconds": 300,
            "activationEvidenceCanonicalSha256": VERIFIER.digest(evidence),
            "rollbackContractCanonicalSha256": VERIFIER.digest(contract),
            "stepReceipts": VERIFIER.expected_signed_nostr_deactivation_steps(contract),
            "boundaryVerification": {
                "verifiedAt": completed,
                "status": "exact-baseline-restored",
                **contract["boundaryBaseline"],
            },
            "absenceVerification": {
                "verifiedAt": completed,
                "status": "all-exact-targets-absent",
                "targets": contract["absenceVerificationTargets"],
            },
            "effects": {
                "clusterMutation": True,
                "civicMutation": False,
                "secretRead": False,
                "secretWrite": False,
                "uidMismatchObserved": False,
                "unrelatedObjectMutation": False,
            },
        }
        VERIFIER.SIGNED_NOSTR_VERIFICATION_TIME_OVERRIDE = datetime(
            2026, 8, 24, 12, 16, 0, tzinfo=timezone.utc,
        )
        self.assertEqual(
            VERIFIER.verify_signed_nostr_deactivation_evidence(
                deactivation,
                evidence,
                contract,
            ),
            deactivation,
        )
        deactivation["stepReceipts"].pop()
        with self.assertRaisesRegex(VERIFIER.VerificationError, "step receipt set incomplete"):
            VERIFIER.verify_signed_nostr_deactivation_evidence(
                deactivation,
                evidence,
                contract,
            )

    def test_complete_reviewed_public_knowledge_render_set_is_accepted(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        self.make_reviewed_knowledge_render(candidate)
        result = VERIFIER.verify(candidate)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["renderFileSet"], "reviewed-public-knowledge")

    def test_current_to_future_reviewed_knowledge_activation_is_accepted(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        self.make_reviewed_knowledge_render(candidate)
        result = VERIFIER.verify(candidate, self.current_base())
        self.assertTrue(result["baseTransitionVerified"])

    def test_activation_rejects_unrelated_public_mecky_drift(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        self.make_reviewed_knowledge_render(candidate)
        path = candidate / "reviewed-render/roebel-staging/public-mecky/deployment.json"
        value = json.loads(path.read_text())
        next(item for item in value["spec"]["template"]["spec"]["containers"][0]["env"] if item["name"] == "NODE_NAME")["value"] = "unrelated drift"
        path.write_text(json.dumps(value, indent=2) + "\n")
        self.refresh_reviewed_integrity(candidate)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "Public Mecky transformation drift"):
            VERIFIER.verify(candidate, self.current_base())

    def test_activation_rejects_public_mecky_environment_reordering(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        self.make_reviewed_knowledge_render(candidate)
        path = candidate / "reviewed-render/roebel-staging/public-mecky/deployment.json"
        value = json.loads(path.read_text())
        value["spec"]["template"]["spec"]["containers"][0]["env"] = list(reversed(value["spec"]["template"]["spec"]["containers"][0]["env"]))
        path.write_text(json.dumps(value, indent=2) + "\n")
        self.refresh_reviewed_integrity(candidate)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "Public Mecky transformation drift"):
            VERIFIER.verify(candidate, self.current_base())

    def test_activation_rejects_unrelated_existing_render_drift(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        self.make_reviewed_knowledge_render(candidate)
        path = candidate / "reviewed-render/roebel-staging/web/deployment.json"
        value = json.loads(path.read_text())
        value["spec"]["replicas"] = 2
        path.write_text(json.dumps(value, indent=2) + "\n")
        self.refresh_reviewed_integrity(candidate)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "activation changed existing file"):
            VERIFIER.verify(candidate, self.current_base())

    def test_first_tracer_runtime_pin_rejects_each_independent_evidence_drift(self) -> None:
        mutations = (
            ("sourceRevision", lambda pin: pin.__setitem__("sourceRevision", "f" * 40)),
            ("sourceTag", lambda pin: pin.__setitem__("sourceTag", "source-" + "f" * 40)),
            ("imageDigest", lambda pin: pin.__setitem__("manifestDigest", "sha256:" + "0" * 64)),
            ("slsaDigest", lambda pin: pin["slsaProvenance"].__setitem__("attestationDigest", "sha256:" + "0" * 64)),
            ("spdxDigest", lambda pin: pin["spdxSbom"].__setitem__("attestationDigest", "sha256:" + "0" * 64)),
            ("anonymousAuthDigest", lambda pin: pin["anonymousPublicPullReceipt"].__setitem__("authConfigCanonicalSha256", "sha256:" + "0" * 64)),
            ("receiptDigest", lambda pin: pin["anonymousPublicPullReceipt"].__setitem__("receiptDigest", "sha256:" + "0" * 64)),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                temp, candidate = self.candidate()
                self.addCleanup(temp.cleanup)
                self.make_reviewed_knowledge_render(candidate)
                path = candidate / "reviewed-render/roebel-staging/reviewed-public-knowledge/runtime-pin.json"
                value = json.loads(path.read_text())
                mutate(value)
                path.write_text(json.dumps(value, indent=2) + "\n")
                with self.assertRaises(VERIFIER.VerificationError):
                    VERIFIER.verify(candidate)

    def test_future_to_future_no_op_promotion_is_rejected(self) -> None:
        base_temp, base = self.candidate()
        self.addCleanup(base_temp.cleanup)
        self.make_reviewed_knowledge_render(base)
        candidate_temp, candidate = self.candidate()
        self.addCleanup(candidate_temp.cleanup)
        self.make_reviewed_knowledge_render(candidate)
        live_path = candidate / "reviewed-render/roebel-staging/live-preconditions.json"
        live = json.loads(live_path.read_text())
        live["previousEnvironmentHead"] = json.loads((base / "reviewed-render/roebel-staging/head.json").read_text())
        live_path.write_text(json.dumps(live, indent=2) + "\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "no-op promotion"):
            VERIFIER.verify(candidate, base)

    def test_future_public_mecky_reviewed_runtime_egress_transition_is_accepted(self) -> None:
        base_temp, base = self.candidate()
        self.addCleanup(base_temp.cleanup)
        self.make_reviewed_knowledge_render(base)
        candidate_temp, candidate = self.candidate()
        self.addCleanup(candidate_temp.cleanup)
        self.make_reviewed_knowledge_render(candidate)
        self.enable_reviewed_mecky_egress(candidate)
        result = VERIFIER.verify(candidate, base)
        self.assertTrue(result["baseTransitionVerified"])

    def test_combined_policy_bootstrap_and_exact_egress_transition_is_accepted(self) -> None:
        base_temp, base = self.candidate()
        self.addCleanup(base_temp.cleanup)
        self.make_reviewed_knowledge_render(base)
        (base / "scripts/verify-reviewed-render.py").write_text(
            "# protected predecessor verifier bytes\n"
        )
        (base / "scripts/test_verify_reviewed_render.py").write_text(
            "# protected predecessor tests bytes\n"
        )
        (base / "scripts/render-release-set-promotion.py").write_text(
            "# protected predecessor promotion renderer bytes\n"
        )
        candidate_temp, candidate = self.candidate()
        self.addCleanup(candidate_temp.cleanup)
        self.make_reviewed_knowledge_render(candidate)
        self.enable_reviewed_mecky_egress(candidate)
        result = VERIFIER.verify(candidate, base)
        self.assertTrue(result["baseTransitionVerified"])

    def test_future_public_mecky_reviewed_runtime_egress_cannot_regress(self) -> None:
        base_temp, base = self.candidate()
        self.addCleanup(base_temp.cleanup)
        self.make_reviewed_knowledge_render(base)
        self.enable_reviewed_mecky_egress(base)
        candidate_temp, candidate = self.candidate()
        self.addCleanup(candidate_temp.cleanup)
        self.make_reviewed_knowledge_render(candidate)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "egress cannot regress"):
            VERIFIER.verify(candidate, base)

    def test_future_public_mecky_reviewed_runtime_egress_rejects_every_widening(self) -> None:
        mutations = (
            lambda policy: policy["spec"]["egress"][0]["to"][0]["namespaceSelector"].update({"matchLabels": {}}),
            lambda policy: policy["spec"]["egress"][0]["to"][0]["podSelector"].update({"matchLabels": {}}),
            lambda policy: policy["spec"]["egress"][0]["ports"].__setitem__(0, {"port": 18080, "protocol": "TCP"}),
            lambda policy: policy["spec"]["egress"].append({"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}),
            lambda policy: policy["spec"].__setitem__("policyTypes", ["Ingress"]),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                temp, candidate = self.candidate()
                self.addCleanup(temp.cleanup)
                self.make_reviewed_knowledge_render(candidate)
                self.enable_reviewed_mecky_egress(candidate)
                path = candidate / "reviewed-render/roebel-staging/public-mecky/networkpolicy.json"
                policy = json.loads(path.read_text())
                mutation(policy)
                path.write_text(json.dumps(policy, indent=2) + "\n")
                self.refresh_reviewed_integrity(candidate)
                with self.assertRaisesRegex(VERIFIER.VerificationError, "NetworkPolicy drift"):
                    VERIFIER.verify(candidate)

    def test_future_to_current_regression_is_rejected(self) -> None:
        base_temp, base = self.candidate()
        self.addCleanup(base_temp.cleanup)
        self.make_reviewed_knowledge_render(base)
        candidate_temp, candidate = self.candidate()
        self.addCleanup(candidate_temp.cleanup)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "cannot regress"):
            VERIFIER.verify(candidate, base)

    def test_each_future_reviewed_knowledge_file_is_required(self) -> None:
        for relative in sorted(VERIFIER.REVIEWED_PUBLIC_KNOWLEDGE_FILES):
            temp, candidate = self.candidate()
            self.addCleanup(temp.cleanup)
            self.make_reviewed_knowledge_render(candidate)
            (candidate / relative).unlink()
            with self.assertRaisesRegex(VERIFIER.VerificationError, "file set drift"):
                VERIFIER.verify(candidate)

    def test_partial_future_reviewed_knowledge_set_is_rejected(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        future = candidate / "reviewed-render/roebel-staging/reviewed-public-knowledge"
        future.mkdir()
        for relative in ("deployment.json", "service.json"):
            (future / relative).write_text("{}\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "file set drift"):
            VERIFIER.verify(candidate)

    def test_unknown_file_is_rejected_even_with_complete_future_set(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        self.make_reviewed_knowledge_render(candidate)
        (candidate / "reviewed-render/roebel-staging/reviewed-public-knowledge/unknown.json").write_text("{}\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "file set drift"):
            VERIFIER.verify(candidate)

    def test_future_public_mecky_cannot_keep_legacy_synthetic_evidence(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        self.make_reviewed_knowledge_render(candidate)
        path = candidate / "reviewed-render/roebel-staging/public-mecky/deployment.json"
        value = json.loads(path.read_text())
        value["spec"]["template"]["spec"]["containers"][0]["env"].append({
            "name": "STADTSTACK_E2E_REVIEWED_EVIDENCE",
            "value": "legacy",
        })
        path.write_text(json.dumps(value, indent=2) + "\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "legacy synthetic evidence field"):
            VERIFIER.verify(candidate)

    def test_future_runtime_requires_non_http_probes_and_no_egress(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        self.make_reviewed_knowledge_render(candidate)
        path = candidate / "reviewed-render/roebel-staging/reviewed-public-knowledge/deployment.json"
        value = json.loads(path.read_text())
        value["spec"]["template"]["spec"]["containers"][0]["readinessProbe"] = {
            "httpGet": {"path": "/healthz", "port": "http"},
        }
        path.write_text(json.dumps(value, indent=2) + "\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "readiness probe must be non-HTTP"):
            VERIFIER.verify(candidate)

        temp2, candidate2 = self.candidate()
        self.addCleanup(temp2.cleanup)
        self.make_reviewed_knowledge_render(candidate2)
        policy_path = candidate2 / "reviewed-render/roebel-staging/reviewed-public-knowledge/networkpolicy.json"
        policy = json.loads(policy_path.read_text())
        policy["spec"]["egress"] = [{"to": []}]
        policy_path.write_text(json.dumps(policy, indent=2) + "\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "NetworkPolicy boundary invalid"):
            VERIFIER.verify(candidate2)

    def test_future_runtime_rejects_unreviewed_deployment_rollout_controls(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        self.make_reviewed_knowledge_render(candidate)
        path = candidate / "reviewed-render/roebel-staging/reviewed-public-knowledge/deployment.json"
        value = json.loads(path.read_text())
        value["spec"]["paused"] = True
        path.write_text(json.dumps(value, indent=2) + "\n")
        self.refresh_reviewed_integrity(candidate)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "Deployment spec keys mismatch"):
            VERIFIER.verify(candidate, self.current_base())

    def test_future_runtime_proof_binds_source_tag_and_immutable_digest(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        self.make_reviewed_knowledge_render(candidate)
        path = candidate / "reviewed-render/roebel-staging/reviewed-public-knowledge/runtime-pin.json"
        value = json.loads(path.read_text())
        value["sourceTag"] = "source-" + "f" * 40
        path.write_text(json.dumps(value, indent=2) + "\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "source tag invalid"):
            VERIFIER.verify(candidate)

    def test_protected_verifier_rejects_case_topology_semantic_drift(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        path = candidate / "case-staging-topology/roebel-case-public-binding-service.json"
        value = json.loads(path.read_text())
        value["spec"]["type"] = "LoadBalancer"
        path.write_text(json.dumps(value, indent=2) + "\n")
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            "Case staging topology verification failed: roebel-case-public-binding Service drift",
        ):
            VERIFIER.verify(candidate)

    def test_protected_verifier_requires_service_account_public_metadata_kind(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        path = candidate / "policy/repository-contract.json"
        value = json.loads(path.read_text())
        value["publicMetadataBoundary"]["allowedKinds"].remove("ServiceAccount")
        path.write_text(json.dumps(value, indent=2) + "\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "repository contract drift"):
            VERIFIER.verify(candidate)

    def test_protected_verifier_binds_the_one_time_relay_fixture_reset_boundary(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        path = candidate / "policy/repository-contract.json"
        value = json.loads(path.read_text())
        boundary = value["ephemeralRelayFixtureResetBoundary"]
        self.assertEqual(boundary["deleteOrder"], ["citizen-relay", "agent-relay"])
        self.assertEqual(
            [target["deploymentUid"] for target in boundary["relayDeleteTargets"]],
            [
                "86b9aada-2b27-428b-9c98-27376b965f58",
                "d62fbb00-feed-40aa-ba72-180bfd80c4e7",
            ],
        )
        self.assertEqual(
            boundary["publicMeckyQuiescence"]["kustomizationUid"],
            "4d49b8eb-c84b-442a-a96e-26c94f24177a",
        )
        self.assertEqual(boundary["publicMeckyQuiescence"]["temporaryReplicas"], 0)
        self.assertEqual(boundary["writeGate"]["uid"], "02cc55b5-30c5-46dd-b819-727e53c58806")
        self.assertTrue(boundary["writeGateRollbackRequired"])
        self.assertFalse(boundary["dataRollbackPossible"])
        self.assertFalse(boundary["automaticRetry"])
        boundary["relayDeleteTargets"].reverse()
        path.write_text(json.dumps(value, indent=2) + "\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "repository contract drift"):
            VERIFIER.verify(candidate)

    def test_protected_verifier_binds_the_public_https_workbench_probe(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        path = candidate / "policy/repository-contract.json"
        value = json.loads(path.read_text())
        probe = value["workbenchImagePromotionBoundary"]["probeTransport"]
        self.assertEqual(probe["origin"], "https://roebel-web.staging.agentcart.eu")
        self.assertEqual(probe["tlsVerification"], "default-ca-and-hostname")
        self.assertFalse(probe["environmentProxyUse"])
        self.assertFalse(probe["redirectsFollowed"])
        probe["origin"] = "https://example.invalid"
        path.write_text(json.dumps(value, indent=2) + "\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "repository contract drift"):
            VERIFIER.verify(candidate)

    def test_workbench_promotion_pin_advances_without_retargeting_relay_reset(self) -> None:
        contract = json.loads((ROOT / "policy/repository-contract.json").read_text())
        workbench = contract["workbenchImagePromotionBoundary"]
        relay_reset = contract["ephemeralRelayFixtureResetBoundary"]
        self.assertEqual(workbench["transactionSchemaVersion"], "roebel_staging_workbench_image_promotion_v2")
        self.assertEqual(workbench["journalSchemaVersion"], "roebel_staging_workbench_image_promotion_journal_v2")
        self.assertEqual(workbench["receiptSchemaVersion"], "roebel_staging_workbench_image_promotion_receipt_v2")
        self.assertEqual(workbench["transportReceiptSchemaVersion"], "roebel_staging_workbench_image_promotion_live_transport_receipt_v2")
        self.assertEqual(workbench["artifactPin"], {
            "schemaVersion": "roebel_e2e_runtime_pin_v1",
            "sourceRevision": "6b78c635f5b8f9603e16d3fe386eb8574df27740",
            "receiptSha256": "sha256:0398095ccdc3a054df42f94abdc75d348201695947ce0268ba81318d05947683",
            "targetImage": "ghcr.io/giraeffleaeffle/roebel-e2e-workbench@sha256:3e6e572b2a661a34fc981a65f3875dd3ba437f8c155be1f4ab0c30f4079ed529",
        })
        self.assertEqual(workbench["environmentTransition"], {
            "mode": "public-signed-only",
            "preservedByteForByte": True,
            "removedNames": [],
            "added": [],
        })
        self.assertEqual(workbench["imageTransition"], {
            "predecessorImage": "ghcr.io/giraeffleaeffle/roebel-e2e-workbench@sha256:03cc0dd35b81004ecc2a6045a16ea09184d2faa10a20bf7c83a825e7440170e2",
            "targetImage": "ghcr.io/giraeffleaeffle/roebel-e2e-workbench@sha256:3e6e572b2a661a34fc981a65f3875dd3ba437f8c155be1f4ab0c30f4079ed529",
            "forward": "image-only-exact-cas",
            "rollback": "target-to-predecessor-image-only-exact-cas",
        })
        self.assertEqual(relay_reset["artifactPin"]["sourceRevision"], "36ac41d7049df815aaebbe4301c098a0ec7e4101")
        self.assertEqual(relay_reset["artifactPin"]["receiptSha256"], "sha256:08d2b65bb57434ba6f35d8083f32b22f43010e1222544a8ce074e208f95efd9b")

    def test_valid_mixed_source_web_only_transition_is_accepted(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        self.make_valid_transition(candidate)
        result = VERIFIER.verify(candidate, self.current_base())
        self.assertTrue(result["baseTransitionVerified"])
        self.assertEqual(result["components"][1]["sourceRevision"], "a" * 40)
        base_head = json.loads((self.current_base() / "reviewed-render/roebel-staging/head.json").read_text())
        self.assertEqual(result["components"][0]["sourceRevision"], base_head["components"][0]["sourceRevision"])

    def test_changed_component_cannot_substitute_an_arbitrary_historical_source(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        self.make_valid_transition(candidate)
        render = candidate / "reviewed-render/roebel-staging"
        head_path = render / "head.json"
        head = json.loads(head_path.read_text())
        historical = "d" * 40
        head["components"][1]["sourceRevision"] = historical
        head_path.write_text(json.dumps(head, indent=2) + "\n")

        web_path = render / "web/deployment.json"
        web = json.loads(web_path.read_text())
        web["metadata"]["annotations"]["stadtstack.io/source-revision"] = historical
        web["spec"]["template"]["metadata"]["annotations"]["stadtstack.io/source-revision"] = historical
        web_path.write_text(json.dumps(web, indent=2) + "\n")

        live_path = render / "live-preconditions.json"
        live = json.loads(live_path.read_text())
        live["patches"][1]["operations"][0]["value"] = historical
        live["patches"][1]["operations"][2]["value"] = historical
        live_path.write_text(json.dumps(live, indent=2) + "\n")

        integrity_path = render / "integrity.json"
        integrity = json.loads(integrity_path.read_text())
        public = json.loads((render / "public-mecky/deployment.json").read_text())
        service = json.loads((render / "public-mecky/service.json").read_text())
        network_policy = json.loads((render / "public-mecky/networkpolicy.json").read_text())
        web_network_policy = json.loads((render / "web/networkpolicy.json").read_text())
        web_ingress = json.loads((render / "web/ingress.json").read_text())
        integrity["desiredRenderSha256"] = VERIFIER.digest(
            {
                "nextEnvironmentHead": head,
                "objects": [
                    public,
                    service,
                    network_policy,
                    web,
                    web_network_policy,
                    web_ingress,
                ],
            }
        )
        integrity_path.write_text(json.dumps(integrity, indent=2) + "\n")

        with self.assertRaisesRegex(VERIFIER.VerificationError, "must bind to the promotion revision"):
            VERIFIER.verify(candidate, self.current_base())

    def test_extra_file_is_rejected(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        (candidate / "reviewed-render/roebel-staging/civic-record.json").write_text("{}\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "file set drift"):
            VERIFIER.verify(candidate)

    def test_symlink_is_rejected(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        path = candidate / "reviewed-render/roebel-staging/head.json"
        path.unlink()
        path.symlink_to(candidate / "README.md")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "symlink forbidden"):
            VERIFIER.verify(candidate)

    def test_literal_secret_value_is_rejected(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        path = candidate / "reviewed-render/roebel-staging/public-mecky/deployment.json"
        value = json.loads(path.read_text())
        env = value["spec"]["template"]["spec"]["containers"][0]["env"]
        item = next(item for item in env if item["name"] == "MECKY_INFERENCE_API_KEY")
        item.pop("valueFrom")
        item["value"] = "not-a-real-key"
        path.write_text(json.dumps(value, indent=2) + "\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "literal secret-shaped"):
            VERIFIER.verify(candidate)

    def test_tag_image_is_rejected(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        path = candidate / "reviewed-render/roebel-staging/web/deployment.json"
        value = json.loads(path.read_text())
        value["spec"]["template"]["spec"]["containers"][0]["image"] = "ghcr.io/giraeffleaeffle/roebel-web-staging:latest"
        path.write_text(json.dumps(value, indent=2) + "\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "image binding invalid"):
            VERIFIER.verify(candidate)

    def test_secret_payload_field_is_rejected(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        path = candidate / "reviewed-render/roebel-staging/web/deployment.json"
        value = json.loads(path.read_text())
        value["spec"]["template"]["spec"]["containers"][0]["data"] = {"token": "hidden"}
        path.write_text(json.dumps(value, indent=2) + "\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "Secret payload-shaped"):
            VERIFIER.verify(candidate)

    def test_public_mecky_service_cannot_be_exposed_publicly(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        path = candidate / "reviewed-render/roebel-staging/public-mecky/service.json"
        value = json.loads(path.read_text())
        value["spec"]["type"] = "LoadBalancer"
        path.write_text(json.dumps(value, indent=2) + "\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "Service drift"):
            VERIFIER.verify(candidate)

    def test_public_mecky_ingress_cannot_widen_beyond_exact_web_pods(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        path = candidate / "reviewed-render/roebel-staging/public-mecky/networkpolicy.json"
        value = json.loads(path.read_text())
        value["spec"]["ingress"][0]["from"][0]["namespaceSelector"] = {}
        path.write_text(json.dumps(value, indent=2) + "\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "NetworkPolicy drift"):
            VERIFIER.verify(candidate)

    def test_web_egress_cannot_widen_beyond_exact_public_mecky(self) -> None:
        for mutation in (
            lambda value: value["spec"]["egress"][2]["to"][0][
                "namespaceSelector"
            ]["matchLabels"].clear(),
            lambda value: value["spec"]["egress"][2]["to"][0][
                "podSelector"
            ]["matchLabels"].update(
                {"app.kubernetes.io/name": "public-mecky"}
            ),
            lambda value: value["spec"]["egress"][2]["ports"].__setitem__(
                0, {"protocol": "TCP", "port": 443}
            ),
        ):
            temp, candidate = self.candidate()
            self.addCleanup(temp.cleanup)
            path = candidate / "reviewed-render/roebel-staging/web/networkpolicy.json"
            value = json.loads(path.read_text())
            mutation(value)
            path.write_text(json.dumps(value, indent=2) + "\n")
            with self.assertRaisesRegex(VERIFIER.VerificationError, "Web NetworkPolicy drift"):
                VERIFIER.verify(candidate)

    def test_civic_projection_route_is_exactly_private_and_read_only(self) -> None:
        result = VERIFIER.verify(ROOT)
        self.assertEqual(result["renderFileSet"], "reviewed-public-knowledge-participant-gateway")
        render = ROOT / "reviewed-render/roebel-staging"
        ingress = json.loads((render / "web/ingress.json").read_text())
        self.assertEqual(
            ingress["metadata"]["annotations"][
                "haproxy-ingress.github.io/config-backend-early"
            ].split("\n"),
            [
                "http-request deny deny_status 405 if { method POST } !{ path /api/chat/mecky }",
                "http-request deny deny_status 405 unless { method GET HEAD POST }",
                "http-request deny deny_status 404 if { path_beg /api } !{ path_beg /api/public-feed/ } !{ path_beg /api/civic/v1/ } !{ path /api/notifications/unread-count } !{ path /api/chat/mecky }",
            ],
        )
        web = json.loads((render / "web/deployment.json").read_text())
        env = web["spec"]["template"]["spec"]["containers"][0]["env"]
        self.assertIn(
            {
                "name": "STADTSTACK_CIVIC_PROJECTION_UPSTREAM_URL",
                "value": VERIFIER.CIVIC_PROJECTION_UPSTREAM_URL,
            },
            env,
        )
        policy = json.loads((render / "web/networkpolicy.json").read_text())
        self.assertIn(
            {
                "to": [
                    {
                        "namespaceSelector": {
                            "matchLabels": {
                                "kubernetes.io/metadata.name": VERIFIER.PARTICIPANT_POLICY.WORKBENCH_NAMESPACE,
                            },
                        },
                        "podSelector": {
                            "matchLabels": VERIFIER.PARTICIPANT_POLICY.WORKBENCH_SELECTOR,
                        },
                    },
                ],
                "ports": [
                    {
                        "port": VERIFIER.PARTICIPANT_POLICY.WORKBENCH_PORT,
                        "protocol": "TCP",
                    },
                ],
            },
            policy["spec"]["egress"],
        )
        reciprocal = json.loads(
            (
                render
                / "staging-participant-gateway/workbench-ingress/networkpolicy.json"
            ).read_text(),
        )
        self.assertEqual(
            reciprocal["spec"]["ingress"][0]["from"][1],
            {
                "namespaceSelector": {
                    "matchLabels": {
                        "kubernetes.io/metadata.name": "stadtstack-roebel-web-preview",
                    },
                },
                "podSelector": {"matchLabels": VERIFIER.WEB_PRESENTATION_LABELS},
            },
        )

    def test_web_ingress_cannot_widen_mecky_post_path(self) -> None:
        for replacement in (
            "http-request deny deny_status 405 if { method POST } !{ path /api/chat/mecky/other }\n"
            "http-request deny deny_status 405 unless { method GET HEAD POST }\n"
            "http-request deny deny_status 404 if { path_beg /api } !{ path_beg /api/public-feed/ } !{ path_beg /api/civic/v1/ } !{ path /api/notifications/unread-count } !{ path /api/chat/mecky/other }",
            "http-request deny deny_status 405 unless { method GET HEAD }\n"
            "http-request deny deny_status 404 if { path_beg /api } !{ path_beg /api/public-feed/ } !{ path_beg /api/civic/v1/ } !{ path /api/notifications/unread-count }",
            "http-request deny deny_status 405 if { method POST } !{ path /api/chat/mecky }\n"
            "http-request deny deny_status 405 unless { method GET HEAD POST }\n"
            "http-request deny deny_status 404 if { path_beg /api } !{ path_beg /api/public-feed/ } !{ path_beg /api/civic/v1/ } !{ path /api/chat/mecky }",
            "http-request deny deny_status 405 if { method POST } !{ path /api/chat/mecky }\n"
            "http-request deny deny_status 405 unless { method GET HEAD POST }\n"
            "http-request deny deny_status 404 if { path_beg /api } !{ path_beg /api/public-feed/ } !{ path_beg /api/civic/v1 } !{ path /api/notifications/unread-count } !{ path /api/chat/mecky }",
        ):
            temp, candidate = self.candidate()
            self.addCleanup(temp.cleanup)
            path = candidate / "reviewed-render/roebel-staging/web/ingress.json"
            value = json.loads(path.read_text())
            value["metadata"]["annotations"][
                "haproxy-ingress.github.io/config-backend-early"
            ] = replacement
            path.write_text(json.dumps(value, indent=2) + "\n")
            with self.assertRaisesRegex(VERIFIER.VerificationError, "Web Ingress drift"):
                VERIFIER.verify(candidate)

    def test_web_ingress_csp_allows_only_the_exact_thirdweb_wallet_and_gnosis_origins(self) -> None:
        replacements = (
            "connect-src 'self' https://roebel-stadtstack.agentcart.eu https://embedded-wallet.thirdweb.com https://*.thirdweb.com; "
            "frame-src https://embedded-wallet.thirdweb.com;",
            "connect-src 'self' https://roebel-stadtstack.agentcart.eu https://embedded-wallet.thirdweb.com https://api.thirdweb.com https://*.rpc.thirdweb.com; "
            "frame-src https://embedded-wallet.thirdweb.com;",
            "connect-src 'self' https://roebel-stadtstack.agentcart.eu https://embedded-wallet.thirdweb.com https://api.thirdweb.com https://100.rpc.thirdweb.com https://thirdweb.com; "
            "frame-src https://embedded-wallet.thirdweb.com;",
            "connect-src 'self' https://roebel-stadtstack.agentcart.eu https://embedded-wallet.thirdweb.com https://api.thirdweb.com https://100.rpc.thirdweb.com https://137.rpc.thirdweb.com; "
            "frame-src https://embedded-wallet.thirdweb.com;",
            "connect-src 'self' https://roebel-stadtstack.agentcart.eu https://embedded-wallet.thirdweb.com https://api.thirdweb.com https://100.rpc.thirdweb.com; "
            "frame-src https://embedded-wallet.thirdweb.com https://thirdweb.com;",
            "connect-src 'self' https://roebel-stadtstack.agentcart.eu https://embedded-wallet.thirdweb.com https://api.thirdweb.com https://100.rpc.thirdweb.com; "
            "frame-src https://*.thirdweb.com;",
        )
        expected = (
            "connect-src 'self' https://roebel-stadtstack.agentcart.eu https://embedded-wallet.thirdweb.com https://api.thirdweb.com https://100.rpc.thirdweb.com; "
            "frame-src https://embedded-wallet.thirdweb.com;"
        )
        for replacement in replacements:
            with self.subTest(replacement=replacement):
                temp, candidate = self.candidate()
                self.addCleanup(temp.cleanup)
                path = candidate / "reviewed-render/roebel-staging/web/ingress.json"
                value = json.loads(path.read_text())
                current = value["metadata"]["annotations"][
                    "haproxy-ingress.github.io/config-backend"
                ]
                value["metadata"]["annotations"][
                    "haproxy-ingress.github.io/config-backend"
                ] = current.replace(expected, replacement)
                path.write_text(json.dumps(value, indent=2) + "\n")
                with self.assertRaisesRegex(VERIFIER.VerificationError, "Web Ingress drift"):
                    VERIFIER.verify(candidate)

    def test_web_cannot_point_public_mecky_at_an_external_url(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        path = candidate / "reviewed-render/roebel-staging/web/deployment.json"
        value = json.loads(path.read_text())
        env = value["spec"]["template"]["spec"]["containers"][0]["env"]
        next(item for item in env if item["name"] == "PUBLIC_MECKY_CHAT_URL")["value"] = "https://example.invalid"
        path.write_text(json.dumps(value, indent=2) + "\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "Web Public Mecky URL invalid"):
            VERIFIER.verify(candidate)

    def test_public_mecky_listener_port_is_fixed(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        path = candidate / "reviewed-render/roebel-staging/public-mecky/deployment.json"
        value = json.loads(path.read_text())
        env = value["spec"]["template"]["spec"]["containers"][0]["env"]
        next(item for item in env if item["name"] == "MECKY_CHAT_PORT")["value"] = "8080"
        path.write_text(json.dumps(value, indent=2) + "\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "MECKY_CHAT_PORT binding invalid"):
            VERIFIER.verify(candidate)

    def test_public_mecky_synthetic_evidence_requires_explicit_capability(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        path = candidate / "reviewed-render/roebel-staging/public-mecky/deployment.json"
        value = json.loads(path.read_text())
        env = value["spec"]["template"]["spec"]["containers"][0]["env"]
        next(
            item for item in env
            if item["name"] == "STADTSTACK_E2E_SYNTHETIC_EVIDENCE_ALLOWED"
        )["value"] = "false"
        path.write_text(json.dumps(value, indent=2) + "\n")
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            "STADTSTACK_E2E_SYNTHETIC_EVIDENCE_ALLOWED binding invalid",
        ):
            VERIFIER.verify(candidate)

    def test_integrity_drift_is_rejected(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        path = candidate / "reviewed-render/roebel-staging/integrity.json"
        value = json.loads(path.read_text())
        value["desiredRenderSha256"] = "sha256:" + "0" * 64
        path.write_text(json.dumps(value, indent=2) + "\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "checksum mismatch"):
            VERIFIER.verify(candidate)

    def test_duplicate_json_key_is_rejected(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        path = candidate / "reviewed-render/roebel-staging/integrity.json"
        path.write_text('{"schemaVersion":"roebel_staging_reviewed_render_v1","schemaVersion":"x","releaseSetDigest":"sha256:' + "0" * 64 + '","desiredRenderSha256":"sha256:' + "0" * 64 + '"}\n')
        with self.assertRaisesRegex(VERIFIER.VerificationError, "duplicate JSON key"):
            VERIFIER.verify(candidate)

    def test_invalid_patch_path_is_rejected(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        path = candidate / "reviewed-render/roebel-staging/live-preconditions.json"
        value = json.loads(path.read_text())
        value["patches"][0]["operations"][0]["path"] = "/spec/replicas"
        value["patches"][0]["operations"][0]["value"] = 99
        path.write_text(json.dumps(value, indent=2) + "\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "patch path invalid"):
            VERIFIER.verify(candidate)

    def test_no_op_base_transition_is_rejected(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        head = json.loads((candidate / "reviewed-render/roebel-staging/head.json").read_text())
        live_path = candidate / "reviewed-render/roebel-staging/live-preconditions.json"
        live = json.loads(live_path.read_text())
        live["previousEnvironmentHead"] = head
        live_path.write_text(json.dumps(live, indent=2) + "\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "no-op promotion"):
            VERIFIER.verify(candidate, self.current_base())

    def test_policy_change_in_promotion_is_rejected(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        readme = candidate / "README.md"
        readme.write_text(readme.read_text() + "\nchanged\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "protected policy file"):
            VERIFIER.verify(candidate, self.current_base())


if __name__ == "__main__":
    unittest.main()
