#!/usr/bin/env python3
"""Closed, value-free render policy for the ephemeral Röbel tracer data plane.

The data plane is intentionally smaller than Supabase: one PostgreSQL process
and one PostgREST process, both reachable only through ClusterIP Services.  It
exists solely to unblock the staging product tracer while the collaborator-
owned Supabase project is unavailable.  The PostgreSQL data directory is an
``emptyDir`` by design; loss recreates the six-post mixed-feed baseline and is
not represented as durable civic state.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any


RENDER_ROOT = Path("reviewed-render/roebel-staging/tracer-data-plane")
NAMESPACE = "stadtstack-roebel-staging-lab"
POSTGRES_NAME = "roebel-tracer-postgres"
POSTGREST_NAME = "roebel-tracer-postgrest"
SERVICE_ACCOUNT_NAME = "roebel-tracer-data-plane"
BOOTSTRAP_CONFIG_MAP = "roebel-tracer-data-plane-bootstrap-v1"
RUNTIME_SECRET = "roebel-tracer-data-plane-runtime"
POSTGRES_PORT = 5432
POSTGREST_PORT = 3000
PARTICIPANT_MIGRATION_PGOPTIONS = (
    "-c search_path=pg_catalog,public,staging_participant_private"
)
POSTGREST_CLUSTER_URL = (
    "http://roebel-tracer-postgrest.stadtstack-roebel-staging-lab."
    "svc.cluster.local:3000"
)

POSTGRES_IMAGE = (
    "docker.io/supabase/postgres@"
    "sha256:af083ef64d0408c8f098ee6f5c364a59b26f36fbc0f3a334a62c5c1d57362e9b"
)
POSTGREST_IMAGE = (
    "docker.io/postgrest/postgrest@"
    "sha256:bea1c76a856fa39d1e542d25911cf95d02fe2bf971992d033044ff209f1504b8"
)

PRODUCT_REPOSITORY = "https://github.com/GiraeffleAeffle/Roebel-App.git"
PRODUCT_PROTECTED_REF = "refs/heads/main"
PRODUCT_SOURCE_REVISION: str | None = None
PRODUCT_ARTIFACTS = (
    (
        "71-roebel-tracer-baseline.sql",
        "supabase/staging_incluster_tracer_baseline_v1.sql",
        "sha256:8fe7fffca7a5b62720254eb4fade61ab7e2767e327af2b117c3c4635f45a9e32",
    ),
    (
        "73-staging-participant-gateway.sql",
        "supabase/migrations/20260825_staging_participant_gateway.sql",
        "sha256:ad050047a71bf2cc82361c16169627dc0a0a66a7982db804b1612624f0f97eab",
    ),
    (
        "74-staging-participant-topic-tracer.sql",
        "supabase/migrations/20260825_staging_participant_topic_tracer.sql",
        "sha256:739cbcb189e3b12913ebf28dae74c931eab3cfae514e476bea4071092aef242e",
    ),
)

RUNTIME_SECRET_KEYS = (
    "anon-jwt",
    "authenticator-password",
    "environment-arm",
    "jwt-secret",
    "pgsodium-root-key",
    "postgres-password",
    "postgrest-db-uri",
    "rpc-secret",
)

WEB_LABELS = {
    "app.kubernetes.io/component": "readonly-presentation",
    "app.kubernetes.io/name": "roebel-web-presentation",
    "app.kubernetes.io/part-of": "stadtstack",
    "stadtstack.io/authority": "none",
}
PARTICIPANT_LABELS = {
    "app.kubernetes.io/component": "staging-participant-gateway",
    "app.kubernetes.io/name": "roebel-staging-participant-gateway",
    "app.kubernetes.io/part-of": "stadtstack",
    "stadtstack.io/authority": "none",
    "stadtstack.io/civic-authority": "none",
    "stadtstack.io/environment": "staging",
}


class PolicyError(ValueError):
    """Raised when the reviewed render widens or drifts."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyError(message)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode()).hexdigest()


def bytes_sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def labels(component: str, name: str) -> dict[str, str]:
    return {
        "app.kubernetes.io/component": component,
        "app.kubernetes.io/name": name,
        "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
        "stadtstack.io/authority": "none",
        "stadtstack.io/civic-authority": "none",
        "stadtstack.io/data-lifecycle": "ephemeral-tracer",
        "stadtstack.io/environment": "staging",
    }


POSTGRES_LABELS = labels("tracer-database", POSTGRES_NAME)
POSTGREST_LABELS = labels("tracer-postgrest", POSTGREST_NAME)
SERVICE_ACCOUNT_LABELS = labels("tracer-data-plane", SERVICE_ACCOUNT_NAME)


def secret_env(name: str, key: str) -> dict[str, Any]:
    return {
        "name": name,
        "valueFrom": {
            "secretKeyRef": {
                "key": key,
                "name": RUNTIME_SECRET,
                "optional": False,
            }
        },
    }


def bootstrap_verify_script() -> str:
    checks = "\n".join(
        f"printf '%s  %s\\n' '{digest.removeprefix('sha256:')}' "
        f"'/roebel-tracer-bootstrap/{filename}'"
        for filename, _source, digest in PRODUCT_ARTIFACTS
    )
    return (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "test \"${ROEBEL_TRACER_ENVIRONMENT_ARM:-}\" = 'staging-only'\n"
        "test \"${#ROEBEL_TRACER_RPC_SECRET}\" -ge 32\n"
        "test \"${#ROEBEL_TRACER_AUTHENTICATOR_PASSWORD}\" -ge 24\n"
        "{\n"
        f"{checks}\n"
        "} | sha256sum --check --strict -\n"
        "psql_args=(--set=ON_ERROR_STOP=1 --no-password --no-psqlrc "
        "--username=supabase_admin --dbname=postgres)\n"
        "psql \"${psql_args[@]}\" --file=/roebel-tracer-bootstrap/71-roebel-tracer-baseline.sql\n"
        "bash /roebel-tracer-bootstrap/72-provision-roebel-vault.sh\n"
        f"PGOPTIONS='{PARTICIPANT_MIGRATION_PGOPTIONS}' psql \"${{psql_args[@]}}\" "
        "--file=/roebel-tracer-bootstrap/73-staging-participant-gateway.sql\n"
        f"PGOPTIONS='{PARTICIPANT_MIGRATION_PGOPTIONS}' psql \"${{psql_args[@]}}\" "
        "--file=/roebel-tracer-bootstrap/74-staging-participant-topic-tracer.sql\n"
    )


def vault_bootstrap_script() -> str:
    # psql's \getenv keeps secret values out of argv and committed bytes.
    # The temporary bootstrap server is isolated by NetworkPolicy and no
    # secret is echoed. The emptyDir guarantee makes name collisions fatal
    # evidence of image/bootstrap drift rather than an adoption path.
    return r'''#!/usr/bin/env bash
set -euo pipefail
psql --set=ON_ERROR_STOP=1 --no-password --no-psqlrc --username=supabase_admin --dbname=postgres <<'SQL'
\getenv roebel_environment_arm ROEBEL_TRACER_ENVIRONMENT_ARM
\getenv roebel_rpc_secret ROEBEL_TRACER_RPC_SECRET
\getenv roebel_authenticator_password ROEBEL_TRACER_AUTHENTICATOR_PASSWORD

select vault.create_secret(
  :'roebel_environment_arm',
  'roebel_staging_participant_environment_arm',
  'Röbel staging-only participant environment arm'
);
select vault.create_secret(
  :'roebel_rpc_secret',
  'roebel_staging_participant_rpc_secret',
  'Röbel staging-only participant RPC capability'
);
alter role authenticator login password :'roebel_authenticator_password';

do $$
begin
  if not exists (
    select 1 from vault.decrypted_secrets
    where name = 'roebel_staging_participant_environment_arm'
      and decrypted_secret = 'staging-only'
  ) then
    raise exception 'roebel tracer environment arm missing';
  end if;
  if not exists (
    select 1 from vault.decrypted_secrets
    where name = 'roebel_staging_participant_rpc_secret'
      and length(decrypted_secret) >= 32
  ) then
    raise exception 'roebel tracer RPC secret missing';
  end if;
end;
$$;
SQL
'''


def runtime_pin() -> dict[str, Any]:
    artifacts = [
        {"configMapFilename": filename, "path": path, "sha256": digest}
        for filename, path, digest in PRODUCT_ARTIFACTS
    ]
    return {
        "schemaVersion": "roebel_ephemeral_tracer_data_plane_pin_v1",
        "activationReady": PRODUCT_SOURCE_REVISION is not None,
        "authority": {
            "civicAuthority": "none",
            "municipalPublication": False,
            "treasuryMutation": False,
            "voteMutation": False,
        },
        "database": {
            "durability": "emptyDir-recreated-baseline",
            "durableCivicRecordsAllowed": False,
            "persistentVolumeClaim": False,
            "sizeLimit": "2Gi",
        },
        "images": {
            "postgres": {
                "humanTag": "15.8.1.085",
                "image": POSTGRES_IMAGE,
                "platformDigestKind": "oci-index",
            },
            "postgrest": {
                "humanTag": "v14.16",
                "image": POSTGREST_IMAGE,
                "platformDigestKind": "oci-index",
            },
        },
        "network": {
            "externalIngress": False,
            "postgrestClusterUrl": POSTGREST_CLUSTER_URL,
            "postgrestReaders": ["roebel-web-presentation"],
            "postgrestRpcCallers": ["roebel-staging-participant-gateway"],
            "postgresCallers": [POSTGREST_NAME],
        },
        "productSource": {
            "artifacts": artifacts,
            "protectedRef": PRODUCT_PROTECTED_REF,
            "repository": PRODUCT_REPOSITORY,
            "sourceRevision": PRODUCT_SOURCE_REVISION,
        },
        "secretReference": {
            "keys": list(RUNTIME_SECRET_KEYS),
            "name": RUNTIME_SECRET,
            "namespace": NAMESPACE,
            "valuesCommitted": False,
        },
    }


def contract_boundary() -> dict[str, Any]:
    """Return the public repository contract for this inert render."""
    return {
        "activationReady": PRODUCT_SOURCE_REVISION is not None,
        "authority": "none",
        "bootstrap": {
            "configMap": BOOTSTRAP_CONFIG_MAP,
            "hashVerificationBeforeSql": True,
            "productArtifacts": [
                {"path": path, "sha256": digest}
                for _filename, path, digest in PRODUCT_ARTIFACTS
            ],
            "vaultBeforeParticipantMigrations": True,
        },
        "images": {
            "postgres": POSTGRES_IMAGE,
            "postgrest": POSTGREST_IMAGE,
        },
        "network": {
            "externalIngress": False,
            "postgrestClusterUrl": POSTGREST_CLUSTER_URL,
            "postgresIngress": "postgrest-exact-pod-selector-only",
            "postgrestIngress": "web-and-participant-exact-pod-selectors-only",
        },
        "normalReleaseSetPromotionMayChange": False,
        "renderRoot": str(RENDER_ROOT),
        "runtimePin": str(RENDER_ROOT / "runtime-pin.json"),
        "schemaVersion": "roebel_ephemeral_tracer_data_plane_pin_v1",
        "secretReference": {
            "keys": list(RUNTIME_SECRET_KEYS),
            "name": RUNTIME_SECRET,
            "namespace": NAMESPACE,
            "valuesCommitted": False,
        },
        "storage": {
            "durability": "emptyDir-recreated-baseline",
            "persistentVolumeClaim": False,
            "sizeLimit": "2Gi",
        },
    }


def expected_service_account() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {
            "labels": SERVICE_ACCOUNT_LABELS,
            "name": SERVICE_ACCOUNT_NAME,
            "namespace": NAMESPACE,
        },
        "automountServiceAccountToken": False,
    }


def exec_probe(command: list[str], failure: int, period: int, timeout: int = 3) -> dict[str, Any]:
    return {
        "exec": {"command": command},
        "failureThreshold": failure,
        "periodSeconds": period,
        "successThreshold": 1,
        "timeoutSeconds": timeout,
    }


def expected_postgres_deployment() -> dict[str, Any]:
    mounts = [
        {"mountPath": "/var/lib/postgresql/data", "name": "postgres-data"},
        {
            "mountPath": "/etc/postgresql-custom/pgsodium_root.key",
            "name": "runtime-secret",
            "readOnly": True,
            "subPath": "pgsodium-root-key",
        },
        {
            "mountPath": "/roebel-tracer-bootstrap",
            "name": "bootstrap",
            "readOnly": True,
        },
        {
            "mountPath": "/docker-entrypoint-initdb.d/zz-roebel-tracer.sh",
            "name": "bootstrap",
            "readOnly": True,
            "subPath": "zz-roebel-tracer.sh",
        },
    ]
    container = {
        "env": [
            {"name": "PGDATA", "value": "/var/lib/postgresql/data/pgdata"},
            {"name": "POSTGRES_DB", "value": "postgres"},
            {"name": "POSTGRES_USER", "value": "supabase_admin"},
            secret_env("POSTGRES_PASSWORD", "postgres-password"),
            secret_env("ROEBEL_TRACER_AUTHENTICATOR_PASSWORD", "authenticator-password"),
            secret_env("ROEBEL_TRACER_ENVIRONMENT_ARM", "environment-arm"),
            secret_env("ROEBEL_TRACER_RPC_SECRET", "rpc-secret"),
        ],
        "image": POSTGRES_IMAGE,
        "imagePullPolicy": "IfNotPresent",
        "livenessProbe": exec_probe(
            ["/usr/bin/pg_isready", "--username=supabase_admin", "--dbname=postgres"],
            6,
            20,
            5,
        ),
        "name": "postgres",
        "ports": [{"containerPort": POSTGRES_PORT, "name": "postgres", "protocol": "TCP"}],
        "readinessProbe": exec_probe(
            ["/usr/bin/pg_isready", "--username=supabase_admin", "--dbname=postgres"],
            3,
            10,
            5,
        ),
        "resources": {
            "limits": {"cpu": "1", "ephemeral-storage": "3Gi", "memory": "1Gi"},
            "requests": {"cpu": "100m", "ephemeral-storage": "256Mi", "memory": "256Mi"},
        },
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": False,
        },
        "startupProbe": exec_probe(
            ["/usr/bin/pg_isready", "--username=supabase_admin", "--dbname=postgres"],
            60,
            2,
            5,
        ),
        "volumeMounts": mounts,
    }
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "annotations": {
                "stadtstack.io/bootstrap-artifacts-sha256": canonical_sha256(
                    [{"path": path, "sha256": digest} for _filename, path, digest in PRODUCT_ARTIFACTS]
                ),
                "stadtstack.io/storage-truth": "ephemeral-emptydir-recreated-baseline",
            },
            "labels": POSTGRES_LABELS,
            "name": POSTGRES_NAME,
            "namespace": NAMESPACE,
        },
        "spec": {
            "progressDeadlineSeconds": 300,
            "replicas": 1,
            "revisionHistoryLimit": 1,
            "selector": {"matchLabels": POSTGRES_LABELS},
            "strategy": {"type": "Recreate"},
            "template": {
                "metadata": {
                    "annotations": {
                        "stadtstack.io/storage-truth": "ephemeral-emptydir-recreated-baseline"
                    },
                    "labels": POSTGRES_LABELS,
                },
                "spec": {
                    "automountServiceAccountToken": False,
                    "containers": [container],
                    "restartPolicy": "Always",
                    "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
                    "serviceAccountName": SERVICE_ACCOUNT_NAME,
                    "terminationGracePeriodSeconds": 30,
                    "volumes": [
                        {"emptyDir": {"sizeLimit": "2Gi"}, "name": "postgres-data"},
                        {
                            "configMap": {
                                "defaultMode": 365,
                                "name": BOOTSTRAP_CONFIG_MAP,
                                "optional": False,
                            },
                            "name": "bootstrap",
                        },
                        {
                            "name": "runtime-secret",
                            "secret": {
                                "defaultMode": 292,
                                "optional": False,
                                "secretName": RUNTIME_SECRET,
                            },
                        },
                    ],
                },
            },
        },
    }


def expected_postgres_service() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"labels": POSTGRES_LABELS, "name": POSTGRES_NAME, "namespace": NAMESPACE},
        "spec": {
            "ports": [{"name": "postgres", "port": POSTGRES_PORT, "protocol": "TCP", "targetPort": "postgres"}],
            "selector": POSTGRES_LABELS,
            "type": "ClusterIP",
        },
    }


def expected_postgres_network_policy() -> dict[str, Any]:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"labels": POSTGRES_LABELS, "name": POSTGRES_NAME, "namespace": NAMESPACE},
        "spec": {
            "egress": [],
            "ingress": [{
                "from": [{"podSelector": {"matchLabels": POSTGREST_LABELS}}],
                "ports": [{"port": POSTGRES_PORT, "protocol": "TCP"}],
            }],
            "podSelector": {"matchLabels": POSTGRES_LABELS},
            "policyTypes": ["Ingress", "Egress"],
        },
    }


def tcp_probe(port: str, failure: int, period: int) -> dict[str, Any]:
    return {
        "failureThreshold": failure,
        "periodSeconds": period,
        "successThreshold": 1,
        "tcpSocket": {"port": port},
        "timeoutSeconds": 3,
    }


def expected_postgrest_deployment() -> dict[str, Any]:
    container = {
        "env": [
            secret_env("PGRST_DB_URI", "postgrest-db-uri"),
            {"name": "PGRST_DB_SCHEMAS", "value": "public"},
            {"name": "PGRST_DB_ANON_ROLE", "value": "anon"},
            secret_env("PGRST_JWT_SECRET", "jwt-secret"),
            {"name": "PGRST_SERVER_HOST", "value": "*4"},
            {"name": "PGRST_SERVER_PORT", "value": str(POSTGREST_PORT)},
        ],
        "image": POSTGREST_IMAGE,
        "imagePullPolicy": "IfNotPresent",
        "livenessProbe": tcp_probe("http", 3, 20),
        "name": "postgrest",
        "ports": [{"containerPort": POSTGREST_PORT, "name": "http", "protocol": "TCP"}],
        "readinessProbe": tcp_probe("http", 3, 10),
        "resources": {
            "limits": {"cpu": "250m", "ephemeral-storage": "64Mi", "memory": "192Mi"},
            "requests": {"cpu": "25m", "ephemeral-storage": "16Mi", "memory": "64Mi"},
        },
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
            "readOnlyRootFilesystem": True,
        },
        "startupProbe": tcp_probe("http", 60, 2),
    }
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"labels": POSTGREST_LABELS, "name": POSTGREST_NAME, "namespace": NAMESPACE},
        "spec": {
            "progressDeadlineSeconds": 300,
            "replicas": 1,
            "revisionHistoryLimit": 1,
            "selector": {"matchLabels": POSTGREST_LABELS},
            "strategy": {"type": "Recreate"},
            "template": {
                "metadata": {"labels": POSTGREST_LABELS},
                "spec": {
                    "automountServiceAccountToken": False,
                    "containers": [container],
                    "restartPolicy": "Always",
                    "securityContext": {
                        "runAsGroup": 65532,
                        "runAsNonRoot": True,
                        "runAsUser": 65532,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "serviceAccountName": SERVICE_ACCOUNT_NAME,
                    "terminationGracePeriodSeconds": 20,
                },
            },
        },
    }


def expected_postgrest_service() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"labels": POSTGREST_LABELS, "name": POSTGREST_NAME, "namespace": NAMESPACE},
        "spec": {
            "ports": [{"name": "http", "port": POSTGREST_PORT, "protocol": "TCP", "targetPort": "http"}],
            "selector": POSTGREST_LABELS,
            "type": "ClusterIP",
        },
    }


def expected_postgrest_network_policy() -> dict[str, Any]:
    reader_sources = [
        {
            "namespaceSelector": {
                "matchLabels": {"kubernetes.io/metadata.name": "stadtstack-roebel-web-preview"}
            },
            "podSelector": {"matchLabels": WEB_LABELS},
        },
        {
            "namespaceSelector": {
                "matchLabels": {"kubernetes.io/metadata.name": "stadtstack-roebel-web-preview"}
            },
            "podSelector": {"matchLabels": PARTICIPANT_LABELS},
        },
    ]
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"labels": POSTGREST_LABELS, "name": POSTGREST_NAME, "namespace": NAMESPACE},
        "spec": {
            "egress": [
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
                    "to": [{"podSelector": {"matchLabels": POSTGRES_LABELS}}],
                    "ports": [{"port": POSTGRES_PORT, "protocol": "TCP"}],
                },
            ],
            "ingress": [{
                "from": reader_sources,
                "ports": [{"port": POSTGREST_PORT, "protocol": "TCP"}],
            }],
            "podSelector": {"matchLabels": POSTGREST_LABELS},
            "policyTypes": ["Ingress", "Egress"],
        },
    }


def kustomization_text() -> str:
    return """apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: stadtstack-roebel-staging-lab
resources:
  - serviceaccount.json
  - postgres-deployment.json
  - postgres-service.json
  - postgres-networkpolicy.json
  - postgrest-deployment.json
  - postgrest-service.json
  - postgrest-networkpolicy.json
configMapGenerator:
  - name: roebel-tracer-data-plane-bootstrap-v1
    files:
      - zz-roebel-tracer.sh=bootstrap/zz-roebel-tracer.sh
      - 71-roebel-tracer-baseline.sql=bootstrap/71-roebel-tracer-baseline.sql
      - 72-provision-roebel-vault.sh=bootstrap/72-provision-roebel-vault.sh
      - 73-staging-participant-gateway.sql=bootstrap/73-staging-participant-gateway.sql
      - 74-staging-participant-topic-tracer.sql=bootstrap/74-staging-participant-topic-tracer.sql
generatorOptions:
  labels:
    app.kubernetes.io/component: tracer-bootstrap
    app.kubernetes.io/part-of: stadtstack-roebel-staging-lab
    stadtstack.io/authority: none
    stadtstack.io/civic-authority: none
    stadtstack.io/data-lifecycle: ephemeral-tracer
    stadtstack.io/environment: staging
"""


JSON_FILES = {
    "runtime-pin.json": runtime_pin,
    "serviceaccount.json": expected_service_account,
    "postgres-deployment.json": expected_postgres_deployment,
    "postgres-service.json": expected_postgres_service,
    "postgres-networkpolicy.json": expected_postgres_network_policy,
    "postgrest-deployment.json": expected_postgrest_deployment,
    "postgrest-service.json": expected_postgrest_service,
    "postgrest-networkpolicy.json": expected_postgrest_network_policy,
}


def expected_files() -> set[str]:
    return {
        *(str(RENDER_ROOT / filename) for filename in JSON_FILES),
        str(RENDER_ROOT / "kustomization.yaml"),
        str(RENDER_ROOT / "bootstrap/zz-roebel-tracer.sh"),
        str(RENDER_ROOT / "bootstrap/71-roebel-tracer-baseline.sql"),
        str(RENDER_ROOT / "bootstrap/72-provision-roebel-vault.sh"),
        str(RENDER_ROOT / "bootstrap/73-staging-participant-gateway.sql"),
        str(RENDER_ROOT / "bootstrap/74-staging-participant-topic-tracer.sql"),
    }


def verify_render(root: Path) -> dict[str, Any]:
    render = root / RENDER_ROOT
    require(render.is_dir(), "tracer data-plane render root missing")
    actual_files = {
        str(path.relative_to(root))
        for path in render.rglob("*")
        if path.is_file()
    }
    require(actual_files == expected_files(), "tracer data-plane file set drift")

    objects: dict[str, Any] = {}
    for filename, factory in JSON_FILES.items():
        actual = json.loads((render / filename).read_text())
        expected = factory()
        require(actual == expected, f"tracer data-plane {filename} drift")
        objects[filename] = actual

    require(
        (render / "kustomization.yaml").read_text() == kustomization_text(),
        "tracer data-plane Kustomization drift",
    )
    require(
        (render / "bootstrap/zz-roebel-tracer.sh").read_text()
        == bootstrap_verify_script(),
        "tracer bootstrap verifier drift",
    )
    require(
        (render / "bootstrap/72-provision-roebel-vault.sh").read_text()
        == vault_bootstrap_script(),
        "tracer Vault bootstrap drift",
    )
    for filename, _source, digest in PRODUCT_ARTIFACTS:
        observed = bytes_sha256((render / "bootstrap" / filename).read_bytes())
        require(observed == digest, f"tracer SQL artifact hash drift: {filename}")

    serialized = canonical_json(objects)
    for forbidden in (
        "BEGIN PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY",
        "AGE-SECRET-KEY-",
        "github_pat_",
        "service_role",
    ):
        require(forbidden not in serialized, f"secret-shaped value committed: {forbidden}")
    require("Ingress" not in {value.get("kind") for value in objects.values()}, "public Ingress forbidden")
    require("PersistentVolumeClaim" not in serialized, "persistent storage forbidden")

    return {
        "schemaVersion": "roebel_ephemeral_tracer_data_plane_verification_v1",
        "status": "passed",
        "activationReady": runtime_pin()["activationReady"],
        "renderCanonicalSha256": canonical_sha256(objects),
        "externalIngress": False,
        "persistentVolumeClaim": False,
        "secretValuesCommitted": False,
    }


def write_render(root: Path, product_root: Path) -> None:
    render = root / RENDER_ROOT
    bootstrap = render / "bootstrap"
    bootstrap.mkdir(parents=True, exist_ok=True)
    for filename, factory in JSON_FILES.items():
        (render / filename).write_text(json.dumps(factory(), indent=2) + "\n")
    (render / "kustomization.yaml").write_text(kustomization_text())
    (bootstrap / "zz-roebel-tracer.sh").write_text(bootstrap_verify_script())
    (bootstrap / "72-provision-roebel-vault.sh").write_text(vault_bootstrap_script())
    for filename, source, digest in PRODUCT_ARTIFACTS:
        source_path = product_root / source
        require(source_path.is_file(), f"product SQL artifact missing: {source}")
        require(bytes_sha256(source_path.read_bytes()) == digest, f"product SQL hash drift: {source}")
        shutil.copyfile(source_path, bootstrap / filename)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--product-root", type=Path)
    args = parser.parse_args()
    if args.write:
        require(args.product_root is not None, "--product-root is required with --write")
        write_render(args.root.resolve(), args.product_root.resolve())
    print(json.dumps(verify_render(args.root.resolve()), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
