#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import copy
import shutil
import tempfile
import unittest
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

    def normalize_current_seed(self, destination: Path) -> None:
        """Make mutation fixtures current-shaped even when ROOT is future-shaped."""
        render = destination / "reviewed-render/roebel-staging"
        future = render / "reviewed-public-knowledge"
        if not future.is_dir():
            return

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
        self.refresh_current_integrity(destination)

    def candidate(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temp = tempfile.TemporaryDirectory()
        destination = Path(temp.name) / "candidate"
        shutil.copytree(ROOT, destination, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        self.normalize_current_seed(destination)
        self.normalize_inert_participant_seed(destination)
        self.normalize_no_participant_gateway_seed(destination)
        return temp, destination

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
        """Keep transition fixtures anchored to the immutable inert predecessor."""
        policy_path = destination / VERIFIER.PARTICIPANT_POLICY.POLICY_PATH
        policy_path.write_text(
            json.dumps(
                VERIFIER.PARTICIPANT_POLICY.activation_policy_descriptor(),
                indent=2,
            )
            + "\n",
        )
        contract_path = destination / "policy/repository-contract.json"
        contract = json.loads(contract_path.read_text())
        contract["stagingParticipantGatewayBoundary"]["activationReady"] = False
        contract_path.write_text(json.dumps(contract, indent=2) + "\n")

    def current_base(self) -> Path:
        temp, base = self.candidate()
        self.addCleanup(temp.cleanup)
        return base

    def protected_participant_candidate(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        """Copy the protected render and pin the runtime-release predecessor."""
        temp = tempfile.TemporaryDirectory()
        destination = Path(temp.name) / "candidate"
        shutil.copytree(
            ROOT,
            destination,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        )
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
        policy_path = root / VERIFIER.PARTICIPANT_POLICY.POLICY_PATH
        policy_path.write_text(
            json.dumps(
                VERIFIER.PARTICIPANT_POLICY.approved_next_activation_policy_descriptor(),
                indent=2,
            )
            + "\n",
        )
        contract_path = root / "policy/repository-contract.json"
        contract = json.loads(contract_path.read_text())
        contract["stagingParticipantGatewayBoundary"]["activationReady"] = True
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
        temp = tempfile.TemporaryDirectory()
        destination = Path(temp.name) / "phase-a"
        shutil.copytree(
            ROOT,
            destination,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        )
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
        web_environment = template["spec"]["containers"][0]["env"]
        web_environment[:] = [
            item
            for item in web_environment
            if item["name"] not in {
                VERIFIER.TRACER_FEED_URL_ENV["name"],
                VERIFIER.TRACER_FEED_ANON_ENV["name"],
            }
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
        expected_changes = set(TRACER_PHASE_A_FIXTURE_FILES)
        if VERIFIER.public_mecky_reviewed_web_source_enabled(ROOT):
            expected_changes.update({
                "reviewed-render/roebel-staging/public-mecky/deployment.json",
                "reviewed-render/roebel-staging/public-mecky/networkpolicy.json",
                "reviewed-render/roebel-staging/web/networkpolicy.json",
                "reviewed-render/roebel-staging/network-boundary-migration.json",
                "reviewed-render/roebel-staging/integrity.json",
            })
        if VERIFIER.web_tracer_feed_route_enabled(ROOT):
            expected_changes.update({
                "reviewed-render/roebel-staging/network-boundary-migration.json",
                "reviewed-render/roebel-staging/web/networkpolicy.json",
            })
        protected_root = VERIFIER.verify_tree(ROOT)
        protected_policy = protected_root["stagingParticipantGatewayPolicy"]
        if (
            protected_root["stagingParticipantGateway"]["runtimePin"]
            != VERIFIER.PARTICIPANT_POLICY.expected_runtime_pin(protected_policy)
        ):
            expected_changes.update(
                VERIFIER.PARTICIPANT_GATEWAY_RUNTIME_RELEASE_TRANSITION_FILES,
            )
        self.assertEqual(VERIFIER.changed_repository_files(destination, ROOT), expected_changes)
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

        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        fixture = VERIFIER.verify(candidate)
        self.assertEqual(fixture["status"], "passed")
        self.assertEqual(fixture["renderFileSet"], "current")

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
        expected_added = VERIFIER.TRACER_DATA_PLANE.expected_files() | {
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
        self.assertEqual(
            contract["stagingParticipantGatewayBoundary"]["exactGatewayPaths"],
            list(VERIFIER.PARTICIPANT_POLICY.ROUTES),
        )
        self.assertEqual(
            contract["stagingParticipantGatewayBoundary"]["methodPathMatrix"],
            {
                "GET": [VERIFIER.PARTICIPANT_POLICY.ROUTES[0]],
                "OPTIONS": list(VERIFIER.PARTICIPANT_POLICY.ROUTES),
                "POST": list(VERIFIER.PARTICIPANT_POLICY.POST_ROUTES),
            },
        )

    def test_participant_gateway_ingress_is_exact_and_rate_limited(self) -> None:
        expected = VERIFIER.PARTICIPANT_POLICY.ROUTES
        with mock.patch.object(
            VERIFIER.PARTICIPANT_POLICY,
            "STATIC_ACTIVATION_POLICY",
            participant_ready_policy(),
        ):
            ingress = VERIFIER.expected_participant_gateway_ingress()
        lines = ingress["metadata"]["annotations"]["haproxy-ingress.github.io/config-backend-early"].split("\n")
        self.assertEqual(lines[0], "http-request deny deny_status 404 if " + " ".join(f"!{{ path {path} }}" for path in expected))
        self.assertEqual(lines[1], "http-request deny deny_status 405 if { method POST } " + " ".join(f"!{{ path {path} }}" for path in expected[1:]))
        self.assertEqual(lines[2], "http-request deny deny_status 405 if { method OPTIONS } " + " ".join(f"!{{ path {path} }}" for path in expected))
        self.assertEqual(lines[3], "http-request deny deny_status 405 if { method HEAD }")
        self.assertEqual(lines[4], f"http-request deny deny_status 405 if {{ method GET }} !{{ path {expected[0]} }}")
        self.assertEqual(lines[5], "http-request deny deny_status 405 unless { method GET HEAD POST OPTIONS }")
        self.assertIn("http-request deny deny_status 429 if { sc_http_req_rate(0) gt 30 }", lines)
        self.assertEqual(ingress["spec"]["rules"][0]["http"]["paths"][0]["path"], "/api/staging-participant/v1")
        self.assertEqual(VERIFIER.expected_web_ingress(False), VERIFIER.expected_web_ingress(False, participant_gateway=True))

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
        self.assertEqual(secret_keys, {"allowed-wallets", "invite-sha256", "mecky-pubkey", "session-key", "supabase-anon-key", "supabase-rpc-secret"})
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
        protected = VERIFIER.verify_tree(ROOT)
        policy = protected["stagingParticipantGatewayPolicy"]
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
        protected = VERIFIER.verify_tree(ROOT)
        policy = protected["stagingParticipantGatewayPolicy"]
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
                "sourceRevision": "722c75a0ae2303edcaa8c8281af7d6fe3c53089b",
                "sourceTreeSha256": "sha256:06955333455bc805645ed1f956aa79dfea1b556be970da2182bb2e76b29b4a68",
                "manifestDigest": "sha256:2b77d59eed440df844c86c4adf0ae5f3577f7526d4b09160c2f1e5e731dc7f2b",
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
                "sourceRevision": "f2e5c93c8fb0127d3aacc33d4be1a1a63f707dc1",
                "sourceTreeSha256": "sha256:0325e742e595de75a694d6662ffe6d84cd38818239c3f334d4ce802ed48ca819",
                "manifestDigest": "sha256:ba12dea1ebffa2cb85b58f135882085c66c1675f4461f27af116b63737a95a57",
                "workflowSha256": "sha256:a0c55933682bd94cb29630c83d6f7168ea19e9eba66a40d8132e8a91823c96c5",
            },
        )

    def test_participant_gateway_runtime_release_resources_change_only_three_deployment_leaves(self) -> None:
        protected = VERIFIER.verify_tree(ROOT)
        policy = protected["stagingParticipantGatewayPolicy"]
        predecessor_pin = VERIFIER.expected_participant_gateway_runtime_release_predecessor_pin(policy)
        successor = VERIFIER.expected_participant_gateway_runtime_release_pin(policy)
        civic_projection = protected["stagingParticipantGateway"]["civicProjectionRoute"]
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
        base_temp, activation_base = self.protected_participant_candidate()
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
        self.assertFalse(VERIFIER.PARTICIPANT_POLICY.activation_policy_descriptor()["activationReady"])
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
            "activation blocked: protected product, database and endpoint pins are incomplete",
        ):
            VERIFIER.verify_participant_gateway_runtime_pin(pin)

    def test_participant_render_is_rejected_while_static_policy_is_not_ready(self) -> None:
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            "activation blocked: protected product, database and endpoint pins are incomplete",
        ):
            VERIFIER.verify_participant_gateway_static_policy(
                candidate,
                "reviewed-public-knowledge-participant-gateway",
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
        result = VERIFIER.verify(candidate, base)
        self.assertTrue(result["baseTransitionVerified"])
        self.assertEqual(result["renderFileSet"], VERIFIER.verify_tree(base)["renderFileSet"])
        self.assertTrue(
            VERIFIER.verify_tree(candidate)["stagingParticipantGatewayPolicy"]["activationReady"],
        )

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
        with self.assertRaisesRegex(VERIFIER.VerificationError, "transition base drift"):
            VERIFIER.verify(current_candidate, ready_base)

    def test_participant_activation_policy_transition_cannot_change_executable_render_or_live_files(self) -> None:
        protected = (
            "README.md",
            "scripts/activate-staging-participant-gateway.py",
            ".github/workflows/staging-participant-gateway-activation.yml",
            "reviewed-render/roebel-staging/web/ingress.json",
            "reviewed-render/roebel-staging/live-preconditions.json",
        )
        self.assertEqual(
            VERIFIER.PARTICIPANT_ACTIVATION_POLICY_TRANSITION_FILES,
            {
                "policy/repository-contract.json",
                "policy/staging-participant-gateway-activation-policy.json",
            },
        )
        for relative in protected:
            with self.subTest(relative=relative):
                base = self.current_base()
                temp, candidate = self.candidate()
                self.addCleanup(temp.cleanup)
                self.participant_activation_policy_transition(candidate)
                path = candidate / relative
                path.write_text(path.read_text() + "\n")
                with self.assertRaisesRegex(VERIFIER.VerificationError, "changed protected file"):
                    VERIFIER.verify(candidate, base)

        base = self.current_base()
        temp, candidate = self.candidate()
        self.addCleanup(temp.cleanup)
        self.participant_activation_policy_transition(candidate)
        secret = candidate / "reviewed-render/roebel-staging/staging-participant-secret.json"
        secret.write_text('{"apiVersion":"v1","kind":"Secret"}\n')
        with self.assertRaisesRegex(VERIFIER.VerificationError, "repository file set drift"):
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
