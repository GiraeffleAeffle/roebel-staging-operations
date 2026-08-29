#!/usr/bin/env python3
"""Focused tests for the one-time workbench image promotion runner."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import inspect
import json
import signal
import stat
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch


MODULE_PATH = Path(__file__).with_name("promote-staging-workbench-image.py")
SPEC = importlib.util.spec_from_file_location("workbench_image_promotion", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def uid(seed: int) -> str:
    return str(uuid.UUID(f"00000000-0000-4000-8000-{seed:012d}"))


def deployment() -> dict[str, Any]:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": MODULE.WORKBENCH_NAME,
            "namespace": MODULE.WORKBENCH_NAMESPACE,
            "uid": MODULE.WORKBENCH_DEPLOYMENT_UID,
            "resourceVersion": "15370001",
            "generation": 3,
            "labels": {
                MODULE.OWNER_LABEL_KEY: MODULE.OWNER_LABEL_VALUE,
                "app.kubernetes.io/component": "e2e-workbench",
            },
        },
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app.kubernetes.io/component": "e2e-workbench"}},
            "strategy": {"type": "RollingUpdate", "rollingUpdate": {"maxSurge": 1, "maxUnavailable": 0}},
            "template": {
                "metadata": {"labels": {"app.kubernetes.io/component": "e2e-workbench"}},
                "spec": {
                    "containers": [{
                        "name": MODULE.WORKBENCH_CONTAINER_NAME,
                        "image": MODULE.OLD_IMAGE,
                        "imagePullPolicy": "IfNotPresent",
                        "env": [
                            {"name": "WORKBENCH_BIND_HOST", "value": "0.0.0.0"},
                            {"name": "WORKBENCH_PORT", "value": "18083"},
                            {"name": "CITIZEN_RELAY_URL", "value": "http://citizen-relay:18080"},
                            {"name": "AGENT_RELAY_URL", "value": "http://agent-relay:18080"},
                            {"name": "STADTSTACK_PUBLIC_BASE_URL", "value": "http://stadtstack-public:18080"},
                            {"name": "STADTSTACK_CONTROL_BASE_URL", "value": "http://stadtstack-control:18080"},
                            {"name": "MECKY_PUBKEY", "value": "a" * 64},
                            {"name": "SYNTHETIC_CITIZENS_JSON", "valueFrom": {"secretKeyRef": {"name": "synthetic-citizens", "key": "json"}}},
                            {"name": "CASE_STEWARD_TOKEN", "valueFrom": {"secretKeyRef": {"name": "case-steward", "key": "token"}}},
                            {"name": "CITIZEN_RELAY_ADMISSION_TOKEN", "valueFrom": {"secretKeyRef": {"name": "citizen-relay", "key": "admission-token"}}},
                            {"name": "GNOSIS_RPC_URL", "value": "https://rpc.example.invalid"},
                        ],
                        "ports": [{"name": "http", "containerPort": 18083}],
                    }],
                },
            },
        },
        "status": {"observedGeneration": 3, "readyReplicas": 1, "updatedReplicas": 1, "availableReplicas": 1},
    }


def service() -> dict[str, Any]:
    return {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": MODULE.SERVICE_NAME, "namespace": MODULE.WORKBENCH_NAMESPACE, "uid": uid(10), "resourceVersion": "1"},
        "spec": {"selector": {"app.kubernetes.io/component": "e2e-workbench"}, "ports": [{"name": "http", "port": 18083, "targetPort": 18083}]},
    }


def network_policy() -> dict[str, Any]:
    return {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"name": MODULE.NETWORK_POLICY_NAME, "namespace": MODULE.WORKBENCH_NAMESPACE, "uid": uid(11), "resourceVersion": "2"},
        "spec": {"podSelector": {"matchLabels": {"app.kubernetes.io/component": "e2e-workbench"}}, "policyTypes": ["Ingress", "Egress"], "egress": []},
    }


def pod(image: str) -> dict[str, Any]:
    return {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "e2e-workbench-abc-xyz", "namespace": MODULE.WORKBENCH_NAMESPACE, "uid": uid(12)},
        "status": {
            "podIP": "10.0.0.12",
            "podIPs": [{"ip": "10.0.0.12"}],
            "containerStatuses": [{"name": MODULE.WORKBENCH_CONTAINER_NAME, "ready": True, "imageID": image}],
        },
    }


def endpoint_slice(*, pod_uid: str | None = None, service_name: str | None = None, address: str = "10.0.0.12", address_type: str = "IPv4") -> dict[str, Any]:
    return {
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSlice",
        "metadata": {
            "name": "e2e-workbench-abc",
            "namespace": MODULE.WORKBENCH_NAMESPACE,
            "uid": uid(13),
            "labels": {MODULE.ENDPOINT_SLICE_LABEL: service_name or MODULE.SERVICE_NAME},
        },
        "addressType": address_type,
        "ports": [{"name": MODULE.WORKBENCH_SERVICE_PORT_NAME, "port": MODULE.WORKBENCH_SERVICE_PORT, "protocol": "TCP"}],
        "endpoints": [{
            "addresses": [address],
            "conditions": {"ready": True},
            "targetRef": {
                "apiVersion": "v1",
                "kind": "Pod",
                "namespace": MODULE.WORKBENCH_NAMESPACE,
                "name": "e2e-workbench-abc-xyz",
                "uid": pod_uid or uid(12),
            },
        }],
    }


def public_config() -> dict[str, Any]:
    return {
        "schemaVersion": MODULE.PUBLIC_CONFIG_SCHEMA,
        "personas": [],
        "meckyPubkey": "a" * 64,
        "mode": "public-signed-only",
        "authorityBinding": "none",
    }


def public_feed(*, synthetic: bool = False) -> dict[str, Any]:
    return {"schemaVersion": MODULE.PUBLIC_FEED_SCHEMA, "posts": ([{"id": "1", "synthetic": True}] if synthetic else []), "authorityBinding": "none"}


def ordinary_post() -> dict[str, Any]:
    return {
        "id": "a" * 64,
        "entryType": "post",
        "event": {
            "id": "b" * 64,
            "pubkey": "c" * 64,
            "created_at": 1_724_800_000,
            "kind": 1,
            "tags": [["t", "roebel"]],
            "content": "Die Querung an der Marienfelder Straße ist schlecht einsehbar.",
            "sig": "d" * 128,
        },
        "author": {
            "name": "Anna",
            "kind": "citizen",
            "pubkey": "e" * 64,
            "synthetic": False,
        },
        "content": "Die Querung an der Marienfelder Straße ist schlecht einsehbar.",
        "createdAt": "2026-08-28T08:00:00Z",
        "replyCount": 0,
        "meckyMentioned": False,
        "meckyAnswered": False,
        "promotedDiscussionId": None,
        "promotedTopicId": None,
        "sourceAppPostId": None,
        "synthetic": False,
    }


def topic_post() -> dict[str, Any]:
    author = {
        "name": "Anna",
        "kind": "citizen",
        "pubkey": "e" * 64,
        "synthetic": False,
    }
    discussion = {
        "id": "f" * 64,
        "author": copy.deepcopy(author),
        "content": "Die Querung soll gemeinsam geprüft werden.",
        "createdAt": "2026-08-28T08:05:00Z",
        "replyCount": 0,
        "meckyMentioned": False,
        "meckyAnswered": False,
        "suggestionSigned": False,
        "caseBinding": None,
        "sourceConversation": None,
        "synthetic": False,
    }
    return {
        "id": discussion["id"],
        "entryType": "topic",
        "author": author,
        "content": discussion["content"],
        "createdAt": discussion["createdAt"],
        "replyCount": 0,
        "meckyMentioned": False,
        "meckyAnswered": False,
        "suggestionSigned": False,
        "caseBinding": None,
        "sourceConversation": None,
        "topicId": "querung-marienfelder-strasse",
        "topicTitle": "Sichere Querung",
        "synthetic": False,
        "lastActivityAt": discussion["createdAt"],
        "discussionCount": 1,
        "discussionIds": [discussion["id"]],
        "discussions": [discussion],
        "sourcePostIds": ["a" * 64],
        "activityCount": 1,
    }


def write_pin(directory: Path) -> tuple[Path, str]:
    value = {
        "schemaVersion": "roebel_e2e_runtime_pin_v1",
        "sourceRevision": MODULE.SOURCE_REVISION,
        "components": [
            {
                "component": "roebel-e2e-workbench",
                "image": MODULE.TARGET_IMAGE.split("@", 1)[0],
                "manifestDigest": MODULE.TARGET_DIGEST,
                "provenance": {"id": "1", "url": "https://github.com/example/attestations/1"},
                "sbomAttestation": {"id": "2", "url": "https://github.com/example/attestations/2"},
                "workflowIdentity": "https://github.com/Giraeffleaeffle/Roebel-App/.github/workflows/roebel-e2e-runtime-publish.yml@refs/heads/main",
            },
            {
                "component": "roebel-staging-relay",
                "image": "ghcr.io/giraeffleaeffle/roebel-staging-relay",
                "manifestDigest": "sha256:" + "b" * 64,
                "provenance": {"id": "3", "url": "https://github.com/example/attestations/3"},
                "sbomAttestation": {"id": "4", "url": "https://github.com/example/attestations/4"},
                "workflowIdentity": "https://github.com/Giraeffleaeffle/Roebel-App/.github/workflows/roebel-e2e-runtime-publish.yml@refs/heads/main",
            },
        ],
        "civicAuthority": "none",
        "deploymentEffect": False,
    }
    raw = (json.dumps(value, indent=2) + "\n").encode()
    path = directory / "runtime-pin.json"
    path.write_bytes(raw)
    return path, sha256(raw)


class FakeKubernetes:
    def __init__(self) -> None:
        self.objects = {
            "deployment": deployment(),
            "service": service(),
            "networkpolicy": network_policy(),
        }
        self.pods = [pod(MODULE.OLD_IMAGE)]
        self.endpoint_slices = [endpoint_slice()]
        self.patch_calls: list[list[dict[str, Any]]] = []
        self.get_calls: list[dict[str, str]] = []
        self.rollout_calls = 0
        self.rollout_timeouts: list[int] = []
        self.probes = {MODULE.PROBE_CONFIG_PATH: public_config(), MODULE.PROBE_FEED_PATH: public_feed()}
        self.raise_after_apply = False
        self.raise_before_apply = False
        self.drift_after_apply = False
        self.synthetic_feed = False
        self.rollout_failure = False
        self.rollback_rollout_failure = False
        self.service_drift_after_apply = False

    def get(self, target: dict[str, str]) -> dict[str, Any] | None:
        self.get_calls.append(copy.deepcopy(target))
        value = self.objects.get(target["kind"].lower())
        return copy.deepcopy(value) if value is not None else None

    def get_pods(self, namespace: str, selector: dict[str, str]) -> list[dict[str, Any]]:
        self.pod_selector = (namespace, copy.deepcopy(selector))
        return copy.deepcopy(self.pods)

    def get_endpoint_slices(self, namespace: str, service_name: str) -> list[dict[str, Any]]:
        self.endpoint_slice_selector = (namespace, service_name)
        return copy.deepcopy(self.endpoint_slices)

    def patch(self, target: dict[str, str], operations: list[dict[str, Any]]) -> dict[str, Any]:
        self.patch_calls.append(copy.deepcopy(operations))
        if self.raise_before_apply:
            raise TimeoutError("response lost before server apply")
        current = self.objects["deployment"]
        container = current["spec"]["template"]["spec"]["containers"][0]
        image = operations[5]["value"]
        container["image"] = image
        for operation in operations[6:]:
            path = operation["path"]
            if path.endswith("/-"):
                container["env"].append(copy.deepcopy(operation["value"]))
            else:
                index = int(path.rsplit("/", 1)[1])
                if operation["op"] == "remove":
                    container["env"].pop(index)
                else:
                    container["env"].insert(index, copy.deepcopy(operation["value"]))
        current["metadata"]["resourceVersion"] = str(int(current["metadata"]["resourceVersion"]) + 1)
        self.pods = [pod(image)]
        if self.drift_after_apply:
            current["spec"]["strategy"]["rollingUpdate"]["maxUnavailable"] = 1
        if self.service_drift_after_apply:
            self.objects["service"]["spec"]["ports"][0]["port"] = 18084
        response = copy.deepcopy(current)
        if self.raise_after_apply:
            raise TimeoutError("response lost after server apply")
        return response

    def rollout_status(self, target: dict[str, str], timeout_seconds: int) -> None:
        self.rollout_calls += 1
        self.rollout_timeouts.append(timeout_seconds)
        if (
            (self.rollout_failure and self.rollout_calls == 1)
            or (self.rollback_rollout_failure and self.rollout_calls == 2)
        ):
            raise MODULE.PostconditionFailure("synthetic rollout failure")

    def probe_get(self, path: str) -> dict[str, Any]:
        return copy.deepcopy(public_feed(synthetic=True) if path == MODULE.PROBE_FEED_PATH and self.synthetic_feed else self.probes[path])


class FailOnceJournal(MODULE.MemoryJournal):
    """Fail one selected durable write, then permit recovery journaling."""

    def __init__(self, fail_on_commit: int) -> None:
        super().__init__()
        self.commit_count = 0
        self.fail_on_commit = fail_on_commit
        self.failed = False

    def commit(self, value: dict[str, Any]) -> None:
        self.commit_count += 1
        if self.commit_count == self.fail_on_commit and not self.failed:
            self.failed = True
            raise OSError("injected journal sink failure")
        super().commit(value)


class CommitThenRaiseReceipt(MODULE.MemoryReceipt):
    """Model a receipt sink that durably writes before losing its response."""

    def commit(self, value: dict[str, Any]) -> None:
        super().commit(value)
        raise OSError("injected receipt response loss")


class PromotionTests(unittest.TestCase):
    def setUp(self) -> None:
        portable_temp_root = Path(tempfile.gettempdir()).resolve(strict=True)
        self.temporary = tempfile.TemporaryDirectory(dir=portable_temp_root)
        self.root = Path(self.temporary.name)
        self.pin, self.pin_sha = write_pin(self.root)
        self.protected_revision = "a" * 40
        self.protected_hashes = {path: sha256(path.encode()) for path in MODULE.PROTECTED_PATHS}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def invoke(
        self,
        kube: FakeKubernetes,
        *,
        dry_run: bool = False,
        journal: MODULE.MemoryJournal | None = None,
        receipt: MODULE.MemoryReceipt | None = None,
    ) -> tuple[dict[str, Any], FakeKubernetes, MODULE.MemoryJournal, MODULE.MemoryReceipt]:
        journal = journal if journal is not None else MODULE.MemoryJournal()
        receipt = receipt if receipt is not None else MODULE.MemoryReceipt()
        result = MODULE.run(
            kube=kube,
            artifact_pin=self.pin,
            receipt=receipt,
            journal=journal,
            dry_run=dry_run,
            operation_id=uid(99),
            artifact_receipt_sha256=self.pin_sha,
            protected_revision=self.protected_revision,
            protected_hashes=self.protected_hashes,
        )
        return result, kube, journal, receipt

    def test_patch_is_exact_public_mode_transition(self) -> None:
        before = deployment()
        patch = MODULE.build_image_patch(before)
        self.assertEqual(
            [item["op"] for item in patch],
            ["test"] * 5 + ["replace"] + ["remove"] * 4 + ["add"],
        )
        self.assertEqual({item["path"] for item in patch[:5]}, {
            "/metadata/uid",
            "/metadata/resourceVersion",
            "/metadata/labels/stadtstack.io~1owner",
            "/spec/template/spec/containers/0/name",
            "/spec/template/spec/containers/0/image",
        })
        self.assertEqual(patch[5], {"op": "replace", "path": "/spec/template/spec/containers/0/image", "value": MODULE.TARGET_IMAGE})
        self.assertEqual(
            [item["path"] for item in patch[6:10]],
            [
                "/spec/template/spec/containers/0/env/8",
                "/spec/template/spec/containers/0/env/7",
                "/spec/template/spec/containers/0/env/5",
                "/spec/template/spec/containers/0/env/4",
            ],
        )
        self.assertEqual(
            patch[10],
            {"op": "add", "path": "/spec/template/spec/containers/0/env/-", "value": {"name": MODULE.WORKBENCH_MODE_ENV_NAME, "value": MODULE.WORKBENCH_MODE_ENV_VALUE}},
        )

    def test_rollback_patch_restores_exact_old_public_environment(self) -> None:
        before = deployment()
        current = deployment()
        current["spec"]["template"]["spec"]["containers"][0]["image"] = MODULE.TARGET_IMAGE
        current["spec"]["template"]["spec"]["containers"][0]["env"] = [
            entry for entry in current["spec"]["template"]["spec"]["containers"][0]["env"]
            if entry["name"] not in MODULE.FORBIDDEN_PUBLIC_MODE_ENV_SET
        ] + [{"name": MODULE.WORKBENCH_MODE_ENV_NAME, "value": MODULE.WORKBENCH_MODE_ENV_VALUE}]
        patch = MODULE.build_rollback_patch(current, before=before)
        self.assertEqual(
            [item["op"] for item in patch],
            ["test"] * 5 + ["replace", "remove"] + ["add"] * 4,
        )
        self.assertEqual(patch[5], {"op": "replace", "path": "/spec/template/spec/containers/0/image", "value": MODULE.OLD_IMAGE})
        self.assertEqual(patch[6], {"op": "remove", "path": "/spec/template/spec/containers/0/env/7"})
        self.assertEqual(
            [item["path"] for item in patch[7:]],
            [
                "/spec/template/spec/containers/0/env/4",
                "/spec/template/spec/containers/0/env/5",
                "/spec/template/spec/containers/0/env/7",
                "/spec/template/spec/containers/0/env/8",
            ],
        )

    def test_success_proves_rollout_pod_digest_probes_and_preservation(self) -> None:
        result, kube, journal, receipt = self.invoke(FakeKubernetes())
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(kube.patch_calls), 1)
        self.assertTrue(result["effects"]["deploymentImageChanged"])
        self.assertTrue(result["preservation"]["unchanged"])
        self.assertEqual(result["probes"]["methods"], {"config": "GET", "feed": "GET"})
        self.assertTrue(result["rollout"]["podImageProof"]["pods"][0]["imageId"].endswith("@" + MODULE.TARGET_DIGEST))
        self.assertIsNotNone(receipt.value and receipt.value.get("canonicalSha256"))
        self.assertEqual(journal.commits[0]["status"], "preflight")
        patch_event = next(item for item in journal.commits[-1]["events"] if item["operation"] == "patch-deployment-image" and item["stage"] == "intent")
        self.assertEqual(patch_event["requestSha256"], result["patch"]["requestSha256"])

    def test_receipt_binds_exact_public_https_probe_origin(self) -> None:
        self.assertNotIn("probe_base_url", inspect.signature(MODULE.KubernetesAdapter).parameters)
        self.assertNotIn("probe-base-url", inspect.getsource(MODULE.main))
        pin = MODULE.validate_artifact_pin(self.pin, expected_receipt_sha256=self.pin_sha)
        receipt = MODULE._receipt_base(
            pin,
            uid(99),
            mode="live",
            protected_revision=self.protected_revision,
            protected_hashes=self.protected_hashes,
        )
        self.assertEqual(receipt["probeBinding"]["kind"], "fixed-public-https-origin")
        self.assertEqual(receipt["probeBinding"]["transport"], "python-stdlib-direct-https")
        self.assertEqual(receipt["probeBinding"]["origin"], MODULE.WORKBENCH_PUBLIC_ORIGIN)
        self.assertEqual(receipt["probeBinding"]["hostname"], MODULE.WORKBENCH_PUBLIC_HOSTNAME)
        self.assertEqual(receipt["probeBinding"]["port"], 443)
        self.assertEqual(receipt["probeBinding"]["method"], "GET")
        self.assertEqual(receipt["probeBinding"]["expectedStatus"], 200)
        self.assertEqual(receipt["probeBinding"]["tlsVerification"], "default-ca-and-hostname")
        self.assertFalse(receipt["probeBinding"]["environmentProxyUse"])
        self.assertFalse(receipt["probeBinding"]["redirectsFollowed"])
        self.assertEqual(receipt["probeBinding"]["timeoutSeconds"], MODULE.WORKBENCH_PROBE_TIMEOUT_SECONDS)
        self.assertEqual(receipt["probeBinding"]["maxBodyBytes"], MODULE.WORKBENCH_PROBE_MAX_BODY_BYTES)
        self.assertEqual(receipt["probeBinding"]["allowedPaths"], list(MODULE.WORKBENCH_PROBE_PATHS))
        self.assertEqual(
            receipt["probeBinding"]["bindingSha256"],
            MODULE.WORKBENCH_PROBE_BINDING_SHA256,
        )

    def test_live_main_requires_no_probe_input_and_binds_adapter_internally(self) -> None:
        completed = {"status": "completed"}
        journal = Mock(); journal.load.return_value = None
        with (
            patch.object(MODULE, "JsonReceipt", return_value=object()),
            patch.object(MODULE, "JsonJournal", return_value=journal),
            patch.object(MODULE, "KubernetesAdapter", return_value=object()) as adapter,
            patch.object(MODULE, "validate_artifact_pin", return_value={}),
            patch.object(MODULE, "validate_protected_binding", return_value=(self.protected_revision, self.protected_hashes)),
            patch.object(MODULE, "run", return_value=completed) as execute,
            patch("builtins.print"),
        ):
            code = MODULE.main([
                "--artifact-pin", str(self.pin),
                "--kubeconfig", "/private/owner-only-kubeconfig",
                "--receipt", "/private/promotion-receipt.json",
                "--journal", "/private/promotion-journal.json",
                "--protected-revision", self.protected_revision,
                "--protected-hashes", json.dumps(self.protected_hashes),
            ])
        self.assertEqual(code, 0)
        adapter.assert_called_once_with("/private/owner-only-kubeconfig")
        execute.assert_called_once()

    def test_rollout_observation_outlives_the_declared_rollout_deadline(self) -> None:
        adapter = object.__new__(MODULE.KubernetesAdapter)
        adapter.kubeconfig = "/owner-only/staging.kubeconfig"
        adapter.kubectl = Path("/pinned/kubectl-v1.36.0")
        completed = subprocess.CompletedProcess([], 0, stdout="deployment successfully rolled out\n", stderr="")

        with patch.object(MODULE.subprocess, "run", return_value=completed) as execute:
            adapter.rollout_status(MODULE.DEPLOYMENT_TARGET, MODULE.ROLLOUT_TIMEOUT_SECONDS)

        command = execute.call_args.args[0]
        self.assertEqual(
            [item for item in command if item.startswith("--request-timeout=")],
            [
                f"--request-timeout={MODULE.ROLLOUT_TIMEOUT_SECONDS + MODULE.ROLLOUT_REQUEST_GRACE_SECONDS}s"
            ],
        )
        self.assertIn(f"--timeout={MODULE.ROLLOUT_TIMEOUT_SECONDS}s", command)
        self.assertEqual(
            execute.call_args.kwargs["timeout"],
            MODULE.ROLLOUT_TIMEOUT_SECONDS + MODULE.ROLLOUT_PROCESS_GRACE_SECONDS,
        )

    def test_ordinary_kubernetes_requests_keep_the_thirty_second_bound(self) -> None:
        adapter = object.__new__(MODULE.KubernetesAdapter)
        adapter.kubeconfig = "/owner-only/staging.kubeconfig"
        adapter.kubectl = Path("/pinned/kubectl-v1.36.0")
        completed = subprocess.CompletedProcess([], 0, stdout="{}", stderr="")

        with patch.object(MODULE.subprocess, "run", return_value=completed) as execute:
            adapter._run(["version"])

        self.assertEqual(
            [
                item
                for item in execute.call_args.args[0]
                if item.startswith("--request-timeout=")
            ],
            [f"--request-timeout={MODULE.KUBECTL_REQUEST_TIMEOUT_SECONDS}s"],
        )
        self.assertEqual(
            execute.call_args.kwargs["timeout"],
            MODULE.KUBECTL_PROCESS_TIMEOUT_SECONDS,
        )

    def test_rollout_timeout_cannot_exceed_the_protected_bound(self) -> None:
        adapter = object.__new__(MODULE.KubernetesAdapter)
        adapter.kubeconfig = "/owner-only/staging.kubeconfig"
        adapter.kubectl = Path("/pinned/kubectl-v1.36.0")

        for invalid in (0, True, MODULE.ROLLOUT_TIMEOUT_SECONDS + 1):
            with self.subTest(invalid=invalid):
                with (
                    patch.object(
                        MODULE.subprocess,
                        "run",
                        side_effect=AssertionError("invalid timeout reached kubectl"),
                    ),
                    self.assertRaisesRegex(MODULE.PromotionError, "protected bound"),
                ):
                    adapter.rollout_status(MODULE.DEPLOYMENT_TARGET, invalid)

    def test_probe_uses_fixed_direct_tls_https_origin_and_exact_paths(self) -> None:
        adapter = object.__new__(MODULE.KubernetesAdapter)
        adapter.kubeconfig = "/owner-only/staging.kubeconfig"
        adapter.kubectl = Path("/pinned/kubectl-v1.36.0")
        tls_context = Mock(check_hostname=True, verify_mode=MODULE.ssl.CERT_REQUIRED)
        requests: list[tuple[str, str, dict[str, str]]] = []
        connections: list[Any] = []

        class Response:
            status = 200

            def __init__(self, payload: dict[str, Any]) -> None:
                self.payload = payload
                self.read_limit: int | None = None

            def read(self, limit: int) -> bytes:
                self.read_limit = limit
                return json.dumps(self.payload).encode("utf-8")

        class Connection:
            def __init__(self, hostname: str, port: int, *, timeout: int, context: object) -> None:
                self.hostname = hostname
                self.port = port
                self.timeout = timeout
                self.context = context
                self.closed = False
                self.response: Response | None = None
                connections.append(self)

            def request(self, method: str, path: str, *, headers: dict[str, str]) -> None:
                requests.append((method, path, headers))
                payload = public_config() if path == MODULE.PROBE_CONFIG_PATH else public_feed()
                self.response = Response(payload)

            def getresponse(self) -> Response:
                assert self.response is not None
                return self.response

            def close(self) -> None:
                self.closed = True

        with (
            patch("ssl.create_default_context", return_value=tls_context) as create_context,
            patch("http.client.HTTPSConnection", Connection),
            patch.dict("os.environ", {"HTTPS_PROXY": "http://attacker.invalid:9999", "HTTP_PROXY": "http://attacker.invalid:9999"}),
            patch.object(MODULE.subprocess, "run", side_effect=AssertionError("functional probe used kubectl")),
        ):
            self.assertEqual(adapter.probe_get(MODULE.PROBE_CONFIG_PATH), public_config())
            self.assertEqual(adapter.probe_get(MODULE.PROBE_FEED_PATH), public_feed())

        create_context.assert_called_once_with()
        self.assertEqual(
            [(item.hostname, item.port, item.timeout, item.context) for item in connections],
            [
                (MODULE.WORKBENCH_PUBLIC_HOSTNAME, 443, MODULE.WORKBENCH_PROBE_TIMEOUT_SECONDS, tls_context),
                (MODULE.WORKBENCH_PUBLIC_HOSTNAME, 443, MODULE.WORKBENCH_PROBE_TIMEOUT_SECONDS, tls_context),
            ],
        )
        self.assertEqual(
            requests,
            [
                ("GET", MODULE.PROBE_CONFIG_PATH, {"Accept": "application/json", "Connection": "close"}),
                ("GET", MODULE.PROBE_FEED_PATH, {"Accept": "application/json", "Connection": "close"}),
            ],
        )
        self.assertTrue(all(item.closed for item in connections))
        self.assertTrue(all(item.response and item.response.read_limit == MODULE.WORKBENCH_PROBE_MAX_BODY_BYTES + 1 for item in connections))
        with self.assertRaises(MODULE.PromotionError):
            adapter.probe_get("/stadtstack-test/api/other")
        self.assertEqual(len(connections), 2)

    def test_probe_rejects_a_non_verifying_tls_context_before_connecting(self) -> None:
        adapter = object.__new__(MODULE.KubernetesAdapter)
        insecure_context = Mock(check_hostname=False, verify_mode=MODULE.ssl.CERT_NONE)
        with (
            patch.object(MODULE.ssl, "create_default_context", return_value=insecure_context),
            patch.object(MODULE.http.client, "HTTPSConnection", side_effect=AssertionError("connected with insecure TLS")),
        ):
            with self.assertRaisesRegex(MODULE.PromotionError, "TLS verification disabled"):
                adapter.probe_get(MODULE.PROBE_CONFIG_PATH)

    def test_probe_rejects_redirect_without_following_it(self) -> None:
        adapter = object.__new__(MODULE.KubernetesAdapter)
        context = Mock(check_hostname=True, verify_mode=MODULE.ssl.CERT_REQUIRED)
        response = Mock(status=302)
        connection = Mock()
        connection.getresponse.return_value = response
        with (
            patch.object(MODULE.ssl, "create_default_context", return_value=context),
            patch.object(MODULE.http.client, "HTTPSConnection", return_value=connection),
        ):
            with self.assertRaisesRegex(MODULE.PostconditionFailure, "returned HTTP 302"):
                adapter.probe_get(MODULE.PROBE_CONFIG_PATH)
        response.read.assert_not_called()
        connection.close.assert_called_once_with()

    def test_probe_rejects_a_body_larger_than_the_fixed_limit(self) -> None:
        adapter = object.__new__(MODULE.KubernetesAdapter)
        context = Mock(check_hostname=True, verify_mode=MODULE.ssl.CERT_REQUIRED)
        response = Mock(status=200)
        response.read.return_value = b"x" * (MODULE.WORKBENCH_PROBE_MAX_BODY_BYTES + 1)
        connection = Mock()
        connection.getresponse.return_value = response
        with (
            patch.object(MODULE.ssl, "create_default_context", return_value=context),
            patch.object(MODULE.http.client, "HTTPSConnection", return_value=connection),
        ):
            with self.assertRaisesRegex(MODULE.PostconditionFailure, "response exceeds bound"):
                adapter.probe_get(MODULE.PROBE_CONFIG_PATH)
        response.read.assert_called_once_with(MODULE.WORKBENCH_PROBE_MAX_BODY_BYTES + 1)
        connection.close.assert_called_once_with()

    def test_probe_classifies_a_timeout_as_transport_uncertain(self) -> None:
        adapter = object.__new__(MODULE.KubernetesAdapter)
        context = Mock(check_hostname=True, verify_mode=MODULE.ssl.CERT_REQUIRED)
        connection = Mock()
        connection.request.side_effect = TimeoutError("timed out")
        with (
            patch.object(MODULE.ssl, "create_default_context", return_value=context),
            patch.object(MODULE.http.client, "HTTPSConnection", return_value=connection),
        ):
            with self.assertRaisesRegex(MODULE.TransportUncertain, "transport failed"):
                adapter.probe_get(MODULE.PROBE_CONFIG_PATH)
        connection.close.assert_called_once_with()

    def test_dry_run_does_not_patch(self) -> None:
        result, kube, _journal, _receipt = self.invoke(FakeKubernetes(), dry_run=True)
        self.assertEqual(result["status"], "dry-run")
        self.assertEqual(kube.patch_calls, [])
        self.assertFalse(result["effects"]["clusterMutation"])

    def test_wrong_owner_fails_before_patch(self) -> None:
        kube = FakeKubernetes()
        kube.objects["deployment"]["metadata"]["labels"][MODULE.OWNER_LABEL_KEY] = "another-owner"
        result, kube, _journal, _receipt = self.invoke(kube)
        self.assertEqual(result["status"], "preflight-failed")
        self.assertEqual(kube.patch_calls, [])

    def test_literal_synthetic_personas_are_rejected_before_patch(self) -> None:
        kube = FakeKubernetes()
        env = kube.objects["deployment"]["spec"]["template"]["spec"]["containers"][0]["env"]
        env[7] = {"name": "SYNTHETIC_CITIZENS_JSON", "value": "[]"}
        result, kube, _journal, _receipt = self.invoke(kube)
        self.assertEqual(result["status"], "preflight-failed")
        self.assertEqual(kube.patch_calls, [])

    def test_service_selector_or_target_port_drift_fails_before_patch(self) -> None:
        for field, value in (("selector", {"app": "foreign"}), ("targetPort", "http"), ("targetPort", 18084)):
            kube = FakeKubernetes()
            if field == "selector":
                kube.objects["service"]["spec"]["selector"] = value
            else:
                kube.objects["service"]["spec"]["ports"][0][field] = value
            with self.subTest(field=field):
                result, kube, _journal, _receipt = self.invoke(kube)
                self.assertEqual(result["status"], "preflight-failed")
                self.assertEqual(kube.patch_calls, [])

    def test_endpoint_slice_foreign_backend_rolls_back_before_probes(self) -> None:
        kube = FakeKubernetes()
        kube.endpoint_slices = [endpoint_slice(pod_uid=uid(44))]
        result, kube, _journal, _receipt = self.invoke(kube)
        self.assertEqual(result["status"], "rolled-back")
        self.assertEqual(len(kube.patch_calls), 2)
        self.assertEqual(kube.patch_calls[-1][5]["value"], MODULE.OLD_IMAGE)

    def test_endpoint_slice_address_and_family_drift_roll_back_before_probes(self) -> None:
        duplicate = endpoint_slice(); duplicate["endpoints"][0]["addresses"] = ["10.0.0.12", "10.0.0.12"]
        cases = {
            "foreign": [endpoint_slice(address="10.0.0.99")],
            "missing": [endpoint_slice(address="")],
            "duplicate": [duplicate],
            "family": [endpoint_slice(address_type="IPv6")],
        }
        for label, slices in cases.items():
            kube = FakeKubernetes(); kube.endpoint_slices = slices
            with self.subTest(label=label):
                result, kube, _journal, _receipt = self.invoke(kube)
                self.assertEqual(result["status"], "rolled-back")
                self.assertEqual(len(kube.patch_calls), 2)
                self.assertEqual(kube.patch_calls[-1][5]["value"], MODULE.OLD_IMAGE)

    def test_rollout_failure_rolls_back_with_inverse_cas_patch(self) -> None:
        before = deployment()
        kube = FakeKubernetes()
        kube.rollout_failure = True
        result, kube, journal, receipt = self.invoke(kube)
        self.assertEqual(result["status"], "rolled-back")
        self.assertEqual(result["failure"], {"failureCode": "rollout_or_image_proof_failed"})
        self.assertEqual(len(kube.patch_calls), 2)
        self.assertEqual(kube.patch_calls[1][5]["value"], MODULE.OLD_IMAGE)
        self.assertEqual(kube.rollout_timeouts, [MODULE.ROLLOUT_TIMEOUT_SECONDS] * 2)
        self.assertTrue(result["effects"]["rollbackApplied"])
        self.assertEqual(kube.objects["deployment"]["spec"], before["spec"])
        self.assertEqual(result["rollback"]["status"], "rolled-back")
        self.assertEqual(
            result["rollback"]["podImageProof"]["expectedImage"],
            MODULE.OLD_IMAGE,
        )
        self.assertIsNone(result["probes"])
        self.assertEqual(receipt.value["status"], "rolled-back")
        self.assertEqual(journal.commits[-1]["status"], "rolled-back")

    def test_rollback_rollout_timeout_never_retries_a_mutation(self) -> None:
        before = deployment()
        kube = FakeKubernetes()
        kube.rollout_failure = True
        kube.rollback_rollout_failure = True

        result, kube, journal, receipt = self.invoke(kube)

        self.assertEqual(result["status"], "rollback-incomplete")
        self.assertEqual(len(kube.patch_calls), 2)
        self.assertEqual(kube.rollout_timeouts, [MODULE.ROLLOUT_TIMEOUT_SECONDS] * 2)
        self.assertTrue(result["effects"]["rollbackApplied"])
        self.assertEqual(kube.objects["deployment"]["spec"], before["spec"])
        self.assertEqual(
            result["rollback"],
            {
                "status": "rollback-verification-failed",
                "failureCode": "rollout_or_image_proof_failed",
            },
        )
        self.assertIsNone(result["probes"])
        self.assertEqual(receipt.value["status"], "rollback-incomplete")
        self.assertEqual(journal.commits[-1]["status"], "rollback-incomplete")

    def test_rollback_classification_requires_exact_old_environment(self) -> None:
        before = deployment()
        incomplete = copy.deepcopy(before)
        env = incomplete["spec"]["template"]["spec"]["containers"][0]["env"]
        incomplete["spec"]["template"]["spec"]["containers"][0]["env"] = [
            entry for entry in env
            if entry["name"] not in MODULE.FORBIDDEN_PUBLIC_MODE_ENV_SET
        ] + [{"name": MODULE.WORKBENCH_MODE_ENV_NAME, "value": MODULE.WORKBENCH_MODE_ENV_VALUE}]
        self.assertEqual(MODULE._classify_rollback_state(incomplete, before), "ambiguous")

    def test_operator_signal_after_patch_enters_rollback_and_terminal_receipt(self) -> None:
        kube = FakeKubernetes()
        original_patch = kube.patch

        def patch_then_interrupt(target: dict[str, str], operations: list[dict[str, Any]]) -> dict[str, Any]:
            response = original_patch(target, operations)
            if len(kube.patch_calls) == 1:
                raise MODULE.PromotionInterrupted(signal.SIGTERM)
            return response

        kube.patch = patch_then_interrupt  # type: ignore[method-assign]
        before = signal.getsignal(signal.SIGTERM)
        result, kube, journal, receipt = self.invoke(kube)
        self.assertEqual(result["status"], "rolled-back")
        self.assertEqual(result["failure"], {"failureCode": "operator_interrupted"})
        self.assertEqual(len(kube.patch_calls), 2)
        self.assertEqual(kube.objects["deployment"]["spec"]["template"]["spec"]["containers"][0]["image"], MODULE.OLD_IMAGE)
        self.assertEqual(journal.commits[-1]["status"], "rolled-back")
        self.assertEqual(receipt.value["status"], "rolled-back")
        self.assertEqual(signal.getsignal(signal.SIGTERM), before)

    def test_hard_interruption_resumes_same_journal_without_replaying_patch(self) -> None:
        kube = FakeKubernetes()
        journal = MODULE.MemoryJournal()
        first_receipt = MODULE.MemoryReceipt()
        original_patch = kube.patch

        def patch_then_die(target: dict[str, str], operations: list[dict[str, Any]]) -> dict[str, Any]:
            original_patch(target, operations)
            raise SystemExit("simulated hard termination")

        kube.patch = patch_then_die  # type: ignore[method-assign]
        with self.assertRaises(SystemExit):
            self.invoke(kube, journal=journal, receipt=first_receipt)
        self.assertEqual(len(kube.patch_calls), 1)
        self.assertIsNone(first_receipt.value)
        kube.patch = original_patch  # type: ignore[method-assign]
        resumed, kube, journal, resumed_receipt = self.invoke(kube, journal=journal, receipt=MODULE.MemoryReceipt())
        self.assertEqual(resumed["status"], "completed")
        self.assertEqual(len(kube.patch_calls), 1)
        self.assertEqual(resumed["operation"]["operationId"], uid(99))
        resume_events = [event for event in journal.state["events"] if event["operation"] == "resume"]
        self.assertEqual([event["stage"] for event in resume_events], ["before", "classified"])
        self.assertEqual(resume_events[-1]["classification"], "target-image")
        self.assertEqual(resumed_receipt.value["status"], "completed")

    def test_hard_interruption_reopens_same_durable_journal_path(self) -> None:
        kube = FakeKubernetes()
        receipt_path = self.root / "promotion.receipt"
        journal_path = self.root / "promotion.journal"
        original_patch = kube.patch

        def patch_then_die(target: dict[str, str], operations: list[dict[str, Any]]) -> dict[str, Any]:
            original_patch(target, operations)
            raise SystemExit("simulated hard termination")

        kube.patch = patch_then_die  # type: ignore[method-assign]
        with self.assertRaises(SystemExit):
            self.invoke(kube, journal=MODULE.JsonJournal(journal_path), receipt=MODULE.JsonReceipt(receipt_path))
        self.assertTrue(receipt_path.exists())
        self.assertEqual(receipt_path.stat().st_size, 0)
        persisted = MODULE.JsonJournal(journal_path).load()
        self.assertEqual(persisted["operationId"], uid(99))
        self.assertEqual(persisted["events"][-1]["stage"], "intent")

        kube.patch = original_patch  # type: ignore[method-assign]
        pin = MODULE.validate_artifact_pin(self.pin, expected_receipt_sha256=self.pin_sha)
        with (
            patch.object(MODULE, "validate_artifact_pin", return_value=pin),
            patch.object(MODULE, "validate_protected_binding", return_value=(self.protected_revision, self.protected_hashes)),
            patch.object(MODULE, "KubernetesAdapter", return_value=kube),
            patch("builtins.print"),
        ):
            code = MODULE.main([
                "--artifact-pin", str(self.pin),
                "--kubeconfig", "/private/owner-only-kubeconfig",
                "--receipt", str(receipt_path),
                "--journal", str(journal_path),
                "--protected-revision", self.protected_revision,
                "--protected-hashes", json.dumps(self.protected_hashes),
            ])
        self.assertEqual(code, 0)
        self.assertEqual(len(kube.patch_calls), 1)
        self.assertGreater(receipt_path.stat().st_size, 0)
        persisted_receipt = json.loads(receipt_path.read_text())
        self.assertEqual(persisted_receipt["operation"]["operationId"], uid(99))

    def test_existing_empty_receipt_requires_validated_restart_opt_in(self) -> None:
        receipt_path = self.root / "reserved.receipt"
        receipt_path.touch(mode=0o600); receipt_path.chmod(0o600)
        with self.assertRaises(MODULE.PromotionError):
            MODULE.JsonReceipt(receipt_path)
        accepted = MODULE.JsonReceipt(receipt_path, allow_existing_empty=True)
        self.assertIsNone(accepted.value)
        receipt_path.write_text("{}\n", encoding="utf-8")
        with self.assertRaises(MODULE.PromotionError):
            MODULE.JsonReceipt(receipt_path, allow_existing_empty=True)

    def test_main_rejects_empty_receipt_paired_with_invalid_nonterminal_journal(self) -> None:
        receipt_path = self.root / "invalid-restart.receipt"
        journal_path = self.root / "invalid-restart.journal"
        receipt_path.touch(mode=0o600); receipt_path.chmod(0o600)
        journal = MODULE.JsonJournal(journal_path)
        journal.commit({"schemaVersion": MODULE.JOURNAL_SCHEMA, "status": "preflight"})
        pin = MODULE.validate_artifact_pin(self.pin, expected_receipt_sha256=self.pin_sha)
        with (
            patch.object(MODULE, "validate_artifact_pin", return_value=pin),
            patch.object(MODULE, "validate_protected_binding", return_value=(self.protected_revision, self.protected_hashes)),
            patch.object(MODULE, "KubernetesAdapter") as adapter,
            self.assertRaisesRegex(MODULE.PromotionError, "resume journal binding drift"),
        ):
            MODULE.main([
                "--artifact-pin", str(self.pin),
                "--kubeconfig", "/private/owner-only-kubeconfig",
                "--receipt", str(receipt_path),
                "--journal", str(journal_path),
                "--protected-revision", self.protected_revision,
                "--protected-hashes", json.dumps(self.protected_hashes),
            ])
        adapter.assert_not_called()
        self.assertEqual(receipt_path.stat().st_size, 0)

    def test_resume_backend_drift_exact_cas_rolls_back_target_image(self) -> None:
        kube = FakeKubernetes()
        journal = MODULE.MemoryJournal()
        original_patch = kube.patch

        def patch_then_die(target: dict[str, str], operations: list[dict[str, Any]]) -> dict[str, Any]:
            original_patch(target, operations)
            raise SystemExit("simulated hard termination")

        kube.patch = patch_then_die  # type: ignore[method-assign]
        with self.assertRaises(SystemExit):
            self.invoke(kube, journal=journal, receipt=MODULE.MemoryReceipt())
        kube.patch = original_patch  # type: ignore[method-assign]
        kube.endpoint_slices = [endpoint_slice(pod_uid=uid(44))]
        resumed, kube, _journal, receipt = self.invoke(kube, journal=journal, receipt=MODULE.MemoryReceipt())
        self.assertEqual(resumed["status"], "rolled-back")
        self.assertEqual(len(kube.patch_calls), 2)
        self.assertEqual(kube.patch_calls[-1][5]["value"], MODULE.OLD_IMAGE)
        self.assertEqual(receipt.value["status"], "rolled-back")

    def test_spec_drift_blocks_unsafe_rollback_without_second_patch(self) -> None:
        kube = FakeKubernetes()
        kube.drift_after_apply = True
        result, kube, _journal, _receipt = self.invoke(kube)
        self.assertEqual(result["status"], "rollback-incomplete")
        self.assertEqual(len(kube.patch_calls), 1)
        self.assertFalse(result["effects"]["rollbackApplied"])
        self.assertEqual(kube.objects["deployment"]["spec"]["template"]["spec"]["containers"][0]["image"], MODULE.TARGET_IMAGE)

    def test_lost_patch_response_after_apply_is_classified_with_one_discovery_get(self) -> None:
        kube = FakeKubernetes()
        kube.raise_after_apply = True
        result, kube, _journal, _receipt = self.invoke(kube)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(kube.patch_calls), 1)
        deployment_gets = [item for item in kube.get_calls if item["kind"] == "Deployment"]
        # preflight + one classification GET + post-patch + post-rollout; no retry patch.
        self.assertEqual(len(deployment_gets), 4)
        self.assertEqual(result["uncertainOutcome"]["classification"], "applied")

    def test_lost_patch_response_before_apply_is_not_retried(self) -> None:
        kube = FakeKubernetes()
        kube.raise_before_apply = True
        result, kube, _journal, _receipt = self.invoke(kube)
        self.assertEqual(result["status"], "not-applied")
        self.assertEqual(len(kube.patch_calls), 1)
        self.assertEqual(result["uncertainOutcome"]["classification"], "not-applied")

    def test_public_probe_rejects_synthetic_records_and_rolls_back(self) -> None:
        kube = FakeKubernetes()
        kube.synthetic_feed = True
        result, kube, _journal, _receipt = self.invoke(kube)
        self.assertEqual(result["status"], "rolled-back")
        self.assertEqual(len(kube.patch_calls), 2)

    def test_preservation_drift_rolls_back_deployment_but_reports_incomplete(self) -> None:
        kube = FakeKubernetes()
        kube.service_drift_after_apply = True
        result, kube, _journal, _receipt = self.invoke(kube)
        self.assertEqual(result["status"], "rollback-incomplete")
        self.assertEqual(len(kube.patch_calls), 2)
        self.assertTrue(result["effects"]["rollbackApplied"])
        self.assertEqual(
            kube.objects["deployment"]["spec"]["template"]["spec"]["containers"][0]["image"],
            MODULE.OLD_IMAGE,
        )

    def test_artifact_pin_checksum_and_source_are_bound_before_cluster_contact(self) -> None:
        kube = FakeKubernetes()
        journal = MODULE.MemoryJournal()
        receipt = MODULE.MemoryReceipt()
        with self.assertRaises(MODULE.PromotionError):
            MODULE.run(
                kube=kube,
                artifact_pin=self.pin,
                receipt=receipt,
                journal=journal,
                artifact_receipt_sha256="sha256:" + "0" * 64,
                protected_revision=self.protected_revision,
                protected_hashes=self.protected_hashes,
            )
        self.assertEqual(kube.get_calls, [])
        self.assertIsNone(journal.state)

    def test_owner_references_are_rejected(self) -> None:
        value = deployment()
        value["metadata"]["ownerReferences"] = [{"uid": uid(55)}]
        with self.assertRaises(MODULE.PromotionError):
            MODULE.validate_workbench_deployment(value, expected_image=MODULE.OLD_IMAGE)

    def test_value_free_guard_only_allows_boolean_secret_effect_flag(self) -> None:
        MODULE._reject_secret_shaped({"effects": {"secretValuesRead": False}})
        MODULE._reject_secret_shaped({"environment": {"valueFrom": {"secretKeyRef": {"name": "x", "key": "y"}}}})
        with self.assertRaises(MODULE.PromotionError):
            MODULE._reject_secret_shaped({"effects": {"secretValuesRead": "false"}})
        with self.assertRaises(MODULE.PromotionError):
            MODULE._reject_secret_shaped({"effects": {"apiKey": "redacted"}})
        with self.assertRaises(MODULE.PromotionError):
            MODULE._reject_secret_shaped({"environment": {"valueFrom": {"configMapKeyRef": {"name": "x", "key": "y"}}}})

    def test_probe_schemas_reject_provenance_and_credential_shaped_extras(self) -> None:
        config_with_provenance = public_config()
        config_with_provenance["isSynthetic"] = False
        with self.assertRaises(MODULE.PostconditionFailure):
            MODULE.validate_config_probe(config_with_provenance)

        config_with_credential = public_config()
        config_with_credential["apiKey"] = "redacted"
        with self.assertRaises(MODULE.PromotionError):
            MODULE.validate_config_probe(config_with_credential)

        feed_with_provenance = public_feed()
        feed_with_provenance["sourceFixture"] = False
        with self.assertRaises(MODULE.PostconditionFailure):
            MODULE.validate_feed_probe(feed_with_provenance)

        feed_with_credential = public_feed()
        feed_with_credential["password"] = "redacted"
        with self.assertRaises(MODULE.PromotionError):
            MODULE.validate_feed_probe(feed_with_credential)

    def test_non_empty_ordinary_post_matches_closed_public_feed_schema(self) -> None:
        feed = {
            "schemaVersion": MODULE.PUBLIC_FEED_SCHEMA,
            "posts": [ordinary_post()],
            "authorityBinding": "none",
        }
        summary = MODULE.validate_feed_probe(feed)
        self.assertEqual(summary["postCount"], 1)
        self.assertFalse(summary["syntheticRecords"])

        topic_only_binding = copy.deepcopy(feed)
        topic_only_binding["posts"][0]["caseBinding"] = None
        with self.assertRaises(MODULE.PostconditionFailure):
            MODULE.validate_feed_probe(topic_only_binding)

        fixture_provenance = copy.deepcopy(feed)
        fixture_provenance["posts"][0]["sourceFixture"] = False
        with self.assertRaises(MODULE.PostconditionFailure):
            MODULE.validate_feed_probe(fixture_provenance)

        credential_extra = copy.deepcopy(feed)
        credential_extra["posts"][0]["apiToken"] = "redacted"
        with self.assertRaises(MODULE.PromotionError):
            MODULE.validate_feed_probe(credential_extra)

    def test_topic_records_keep_their_case_and_conversation_fields_closed(self) -> None:
        feed = {
            "schemaVersion": MODULE.PUBLIC_FEED_SCHEMA,
            "posts": [topic_post()],
            "authorityBinding": "none",
        }
        self.assertEqual(MODULE.validate_feed_probe(feed)["postCount"], 1)

        missing_topic_binding = copy.deepcopy(feed)
        del missing_topic_binding["posts"][0]["caseBinding"]
        with self.assertRaises(MODULE.PostconditionFailure):
            MODULE.validate_feed_probe(missing_topic_binding)

        missing_discussion_conversation = copy.deepcopy(feed)
        del missing_discussion_conversation["posts"][0]["discussions"][0]["sourceConversation"]
        with self.assertRaises(MODULE.PostconditionFailure):
            MODULE.validate_feed_probe(missing_discussion_conversation)

    def test_terminal_journal_failure_never_rolls_back_after_receipt_commit(self) -> None:
        kube = FakeKubernetes()
        journal = FailOnceJournal(fail_on_commit=7)
        result, kube, journal, receipt = self.invoke(kube, journal=journal)
        self.assertEqual(result["status"], "finalization-incomplete")
        self.assertEqual(result["finalization"]["stage"], "journal-terminal")
        self.assertTrue(result["finalization"]["receiptMayHaveCommitted"])
        self.assertTrue(result["finalization"]["recoveryJournalRecorded"])
        self.assertIsNotNone(receipt.value)
        self.assertEqual(len(kube.patch_calls), 1)
        self.assertEqual(kube.objects["deployment"]["spec"]["template"]["spec"]["containers"][0]["image"], MODULE.TARGET_IMAGE)
        self.assertEqual(journal.commits[-1]["events"][-1]["stage"], "recovery-needed")

    def test_receipt_sink_response_loss_is_recovery_state_without_rollback(self) -> None:
        kube = FakeKubernetes()
        receipt = CommitThenRaiseReceipt()
        result, kube, _journal, receipt = self.invoke(kube, receipt=receipt)
        self.assertEqual(result["status"], "finalization-incomplete")
        self.assertEqual(result["finalization"]["stage"], "receipt")
        self.assertTrue(result["finalization"]["receiptMayHaveCommitted"])
        self.assertIsNotNone(receipt.value)
        self.assertEqual(len(kube.patch_calls), 1)
        self.assertEqual(kube.objects["deployment"]["spec"]["template"]["spec"]["containers"][0]["image"], MODULE.TARGET_IMAGE)

    def test_durable_sinks_are_owner_only_and_canonical(self) -> None:
        receipt_path = self.root / "receipt.json"
        journal_path = self.root / "journal.json"
        receipt = MODULE.JsonReceipt(receipt_path)
        journal = MODULE.JsonJournal(journal_path)
        value = {"schemaVersion": "test", "status": "completed", "effects": {"secretValuesRead": False}}
        receipt.commit(value)
        journal.commit(value)
        self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(journal_path.stat().st_mode), 0o600)
        persisted_receipt = json.loads(receipt_path.read_text())
        persisted_journal = json.loads(journal_path.read_text())
        self.assertEqual(persisted_receipt["canonicalSha256"], MODULE.digest(value))
        self.assertEqual(persisted_journal["journalSha256"], MODULE.digest(value))
        reopened = MODULE.JsonJournal(journal_path)
        self.assertEqual(reopened.load(), value)
        with self.assertRaises(MODULE.PromotionError):
            receipt.commit(value)

    def test_service_and_network_policy_uid_or_spec_drift_is_not_mutated(self) -> None:
        kube = FakeKubernetes()
        kube.objects["service"]["spec"] = None
        result, kube, _journal, _receipt = self.invoke(kube)
        self.assertEqual(result["status"], "preflight-failed")
        self.assertEqual(kube.patch_calls, [])


if __name__ == "__main__":
    unittest.main()
