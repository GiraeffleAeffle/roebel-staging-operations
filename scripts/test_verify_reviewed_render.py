#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("reviewed_render_verifier", ROOT / "scripts/verify-reviewed-render.py")
assert SPEC and SPEC.loader
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class ReviewedRenderVerifierTests(unittest.TestCase):
    def candidate(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temp = tempfile.TemporaryDirectory()
        destination = Path(temp.name) / "candidate"
        shutil.copytree(ROOT, destination, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        return temp, destination

    def make_valid_transition(self, candidate: Path) -> None:
        render = candidate / "reviewed-render/roebel-staging"
        base_head = json.loads((ROOT / "reviewed-render/roebel-staging/head.json").read_text())
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
        base_public = json.loads((ROOT / "reviewed-render/roebel-staging/public-mecky/deployment.json").read_text())
        base_web = json.loads((ROOT / "reviewed-render/roebel-staging/web/deployment.json").read_text())
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

    def test_seed_is_valid(self) -> None:
        result = VERIFIER.verify(ROOT)
        self.assertEqual(result["status"], "passed")
        self.assertFalse(result["baseTransitionVerified"])

    def test_valid_mixed_source_web_only_transition_is_accepted(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        self.make_valid_transition(candidate)
        result = VERIFIER.verify(candidate, ROOT)
        self.assertTrue(result["baseTransitionVerified"])
        self.assertEqual(result["components"][1]["sourceRevision"], "a" * 40)
        base_head = json.loads((ROOT / "reviewed-render/roebel-staging/head.json").read_text())
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
            VERIFIER.verify(candidate, ROOT)

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

    def test_web_ingress_cannot_widen_mecky_post_path(self) -> None:
        for replacement in (
            "http-request deny deny_status 405 if { method POST } !{ path /api/chat/mecky/other }\n"
            "http-request deny deny_status 405 unless { method GET HEAD POST }\n"
            "http-request deny deny_status 404 if { path_beg /api } !{ path_beg /api/public-feed/ } !{ path /api/notifications/unread-count } !{ path /api/chat/mecky/other }",
            "http-request deny deny_status 405 unless { method GET HEAD }\n"
            "http-request deny deny_status 404 if { path_beg /api } !{ path_beg /api/public-feed/ } !{ path /api/notifications/unread-count }",
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
            VERIFIER.verify(candidate, ROOT)

    def test_policy_change_in_promotion_is_rejected(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        readme = candidate / "README.md"
        readme.write_text(readme.read_text() + "\nchanged\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "protected policy file"):
            VERIFIER.verify(candidate, ROOT)


if __name__ == "__main__":
    unittest.main()
