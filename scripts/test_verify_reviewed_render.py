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
    def repository_shape(self, root: Path) -> str:
        future = root / "reviewed-render/roebel-staging/reviewed-public-knowledge"
        return "reviewed-public-knowledge" if future.is_dir() else "current"

    def normalize_current_seed(self, destination: Path) -> None:
        """Make mutation fixtures current-shaped even when ROOT is future-shaped."""
        render = destination / "reviewed-render/roebel-staging"
        future = render / "reviewed-public-knowledge"
        if not future.is_dir():
            return

        public_path = render / "public-mecky/deployment.json"
        public = json.loads(public_path.read_text())
        env = public["spec"]["template"]["spec"]["containers"][0]["env"]
        env[:] = [item for item in env if item["name"] != "MECKY_REVIEWED_SOURCE_KINDS"]
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

        integrity_path = render / "integrity.json"
        integrity = json.loads(integrity_path.read_text())
        integrity["desiredRenderSha256"] = VERIFIER.digest(
            {
                "nextEnvironmentHead": json.loads((render / "head.json").read_text()),
                "objects": [
                    public,
                    json.loads((render / "public-mecky/service.json").read_text()),
                    json.loads((render / "public-mecky/networkpolicy.json").read_text()),
                    json.loads((render / "web/deployment.json").read_text()),
                    json.loads((render / "web/networkpolicy.json").read_text()),
                    json.loads((render / "web/ingress.json").read_text()),
                ],
            }
        )
        integrity_path.write_text(json.dumps(integrity, indent=2) + "\n")
        shutil.rmtree(future)

    def candidate(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temp = tempfile.TemporaryDirectory()
        destination = Path(temp.name) / "candidate"
        shutil.copytree(ROOT, destination, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        self.normalize_current_seed(destination)
        return temp, destination

    def current_base(self) -> Path:
        temp, base = self.candidate()
        self.addCleanup(temp.cleanup)
        return base

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
