#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "tracer_data_plane_policy",
    ROOT / "scripts/tracer_data_plane_policy.py",
)
assert SPEC and SPEC.loader
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class TracerDataPlanePolicyTests(unittest.TestCase):
    def candidate(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name) / "candidate"
        shutil.copytree(
            ROOT / POLICY.RENDER_ROOT,
            root / POLICY.RENDER_ROOT,
        )
        return temporary, root

    def test_committed_render_matches_closed_policy(self) -> None:
        result = POLICY.verify_render(ROOT)
        self.assertEqual(result["status"], "passed")
        self.assertFalse(result["externalIngress"])
        self.assertFalse(result["persistentVolumeClaim"])
        self.assertFalse(result["secretValuesCommitted"])

    def test_postgrest_is_cluster_ip_only_and_all_ingress_is_pod_selected(self) -> None:
        service = POLICY.expected_postgrest_service()
        network = POLICY.expected_postgrest_network_policy()
        self.assertEqual(service["spec"]["type"], "ClusterIP")
        self.assertNotIn("externalIPs", service["spec"])
        self.assertNotIn("loadBalancerIP", service["spec"])
        self.assertEqual(
            network["spec"]["ingress"][0]["ports"],
            [{"port": 3000, "protocol": "TCP"}],
        )
        for source in network["spec"]["ingress"][0]["from"]:
            self.assertIn("namespaceSelector", source)
            self.assertIn("podSelector", source)
            self.assertNotIn("ipBlock", source)

    def test_postgrest_egress_is_only_exact_cluster_dns_and_postgres(self) -> None:
        network = POLICY.expected_postgrest_network_policy()
        self.assertEqual(
            network["spec"]["egress"],
            [
                {
                    "to": [{
                        "namespaceSelector": {
                            "matchLabels": {"kubernetes.io/metadata.name": "kube-system"}
                        },
                        "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
                    }],
                    "ports": [
                        {"port": 53, "protocol": "UDP"},
                        {"port": 53, "protocol": "TCP"},
                    ],
                },
                {
                    "to": [{"podSelector": {"matchLabels": POLICY.POSTGRES_LABELS}}],
                    "ports": [{"port": 5432, "protocol": "TCP"}],
                },
            ],
        )

    def test_postgres_is_explicitly_ephemeral_and_not_a_civic_authority(self) -> None:
        deployment = POLICY.expected_postgres_deployment()
        volume = next(
            item
            for item in deployment["spec"]["template"]["spec"]["volumes"]
            if item["name"] == "postgres-data"
        )
        self.assertEqual(volume, {"emptyDir": {"sizeLimit": "2Gi"}, "name": "postgres-data"})
        self.assertEqual(deployment["metadata"]["labels"]["stadtstack.io/authority"], "none")
        self.assertEqual(
            deployment["metadata"]["annotations"]["stadtstack.io/storage-truth"],
            "ephemeral-emptydir-recreated-baseline",
        )
        self.assertNotIn("PersistentVolumeClaim", json.dumps(deployment))
        container = deployment["spec"]["template"]["spec"]["containers"][0]
        environment = {item["name"]: item for item in container["env"]}
        self.assertEqual(environment["POSTGRES_USER"]["value"], "supabase_admin")
        for probe_name in ("livenessProbe", "readinessProbe", "startupProbe"):
            self.assertIn(
                "--username=supabase_admin",
                container[probe_name]["exec"]["command"],
            )
        self.assertIn(
            {
                "mountPath": "/docker-entrypoint-initdb.d/zz-roebel-tracer.sh",
                "name": "bootstrap",
                "readOnly": True,
                "subPath": "zz-roebel-tracer.sh",
            },
            container["volumeMounts"],
        )

    def test_bootstrap_runs_after_image_migrate_and_verifies_before_any_tracer_sql(self) -> None:
        kustomization = POLICY.kustomization_text()
        self.assertIn(f"namespace: {POLICY.NAMESPACE}\n", kustomization)
        order = [
            "zz-roebel-tracer.sh",
            "71-roebel-tracer-baseline.sql",
            "72-provision-roebel-vault.sh",
            "73-staging-participant-gateway.sql",
            "74-staging-participant-topic-tracer.sql",
        ]
        for item in order:
            self.assertIn(item, kustomization)
        verify = POLICY.bootstrap_verify_script()
        self.assertIn("sha256sum --check --strict", verify)
        self.assertIn("--username=supabase_admin", verify)
        self.assertNotIn("--username=postgres", verify)
        lines = verify.splitlines()
        baseline_line = next(
            line for line in lines
            if "--file=/roebel-tracer-bootstrap/71-roebel-tracer-baseline.sql" in line
        )
        self.assertTrue(baseline_line.startswith("psql "))
        self.assertNotIn("PGOPTIONS=", baseline_line)
        expected_migration_prefix = (
            f"PGOPTIONS='{POLICY.PARTICIPANT_MIGRATION_PGOPTIONS}' psql "
        )
        for filename in (
            "73-staging-participant-gateway.sql",
            "74-staging-participant-topic-tracer.sql",
        ):
            migration_line = next(
                line for line in lines
                if f"--file=/roebel-tracer-bootstrap/{filename}" in line
            )
            self.assertTrue(migration_line.startswith(expected_migration_prefix))
        self.assertEqual(verify.count(expected_migration_prefix), 2)
        self.assertLess(
            verify.rindex("71-roebel-tracer-baseline.sql"),
            verify.rindex("72-provision-roebel-vault.sh"),
        )
        self.assertLess(
            verify.rindex("72-provision-roebel-vault.sh"),
            verify.rindex("73-staging-participant-gateway.sql"),
        )
        for _filename, _path, digest in POLICY.PRODUCT_ARTIFACTS:
            self.assertIn(digest.removeprefix("sha256:"), verify)
        vault = POLICY.vault_bootstrap_script()
        self.assertIn("\\getenv roebel_rpc_secret", vault)
        self.assertIn("--username=supabase_admin", vault)
        self.assertNotIn("--username=postgres", vault)
        self.assertNotIn("ROEBEL_TRACER_RPC_SECRET=", vault)

    def test_secret_references_are_exact_and_values_are_absent(self) -> None:
        pin = POLICY.runtime_pin()
        self.assertEqual(pin["secretReference"]["keys"], list(POLICY.RUNTIME_SECRET_KEYS))
        self.assertFalse(pin["secretReference"]["valuesCommitted"])
        deployment = POLICY.expected_postgres_deployment()
        serialized = json.dumps(deployment, sort_keys=True)
        self.assertIn(POLICY.RUNTIME_SECRET, serialized)
        for forbidden in ("stringData", "BEGIN PRIVATE KEY", "service_role"):
            self.assertNotIn(forbidden, serialized)

    def test_mutation_public_ingress_is_rejected(self) -> None:
        temporary, root = self.candidate()
        self.addCleanup(temporary.cleanup)
        path = root / POLICY.RENDER_ROOT / "postgrest-service.json"
        service = json.loads(path.read_text())
        service["spec"]["type"] = "LoadBalancer"
        path.write_text(json.dumps(service, indent=2) + "\n")
        with self.assertRaisesRegex(POLICY.PolicyError, "postgrest-service.json drift"):
            POLICY.verify_render(root)

    def test_mutation_persistent_database_is_rejected(self) -> None:
        temporary, root = self.candidate()
        self.addCleanup(temporary.cleanup)
        path = root / POLICY.RENDER_ROOT / "postgres-deployment.json"
        deployment = json.loads(path.read_text())
        volumes = deployment["spec"]["template"]["spec"]["volumes"]
        volumes[0] = {
            "name": "postgres-data",
            "persistentVolumeClaim": {"claimName": "unexpected"},
        }
        path.write_text(json.dumps(deployment, indent=2) + "\n")
        with self.assertRaisesRegex(POLICY.PolicyError, "postgres-deployment.json drift"):
            POLICY.verify_render(root)

    def test_mutation_sql_byte_is_rejected(self) -> None:
        temporary, root = self.candidate()
        self.addCleanup(temporary.cleanup)
        path = root / POLICY.RENDER_ROOT / "bootstrap/71-roebel-tracer-baseline.sql"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(POLICY.PolicyError, "SQL artifact hash drift"):
            POLICY.verify_render(root)

    def test_runtime_pin_records_that_source_revision_is_still_pending(self) -> None:
        pin = POLICY.runtime_pin()
        self.assertIsNone(pin["productSource"]["sourceRevision"])
        self.assertFalse(pin["activationReady"])

    def test_repository_contract_keeps_the_inert_render_out_of_routine_promotions(self) -> None:
        boundary = POLICY.contract_boundary()
        self.assertFalse(boundary["activationReady"])
        self.assertFalse(boundary["normalReleaseSetPromotionMayChange"])
        self.assertFalse(boundary["network"]["externalIngress"])
        self.assertFalse(boundary["storage"]["persistentVolumeClaim"])


if __name__ == "__main__":
    unittest.main()
