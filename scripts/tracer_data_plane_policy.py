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
REVISION = re.compile(r"^[0-9a-f]{40}$")

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
INERT_PRODUCT_SOURCE_REVISION: str | None = None
LEGACY_PRODUCT_SOURCE_REVISION = "9a1bda15a67d36ef87ec674958a1b2b7ce3ea840"
PRODUCT_SOURCE_REVISION = "4c44ae3df1e37161156098899ccf192cd0bbe370"
LEGACY_PRODUCT_ARTIFACTS = (
    (
        "71-roebel-tracer-baseline.sql",
        "supabase/staging_incluster_tracer_baseline_v1.sql",
        "sha256:f8f9745c1783043334ef24b3cde801d19a609867d12d0c23612bda7c5206ca5a",
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
PRODUCT_ARTIFACTS = (
    *LEGACY_PRODUCT_ARTIFACTS,
    (
        "75-staging-citizen-adoption.sql",
        "supabase/migrations/20260901_staging_citizen_adoption.sql",
        "sha256:35e12ecc7e54e76f8e12b17e828970bc2d3bd4393f14f58fe9604dd00d398a2d",
    ),
)
SYNTHETIC_CITIZEN_ADOPTION_ARTIFACT = (
    "76-staging-synthetic-citizen-adoption.sql",
    "supabase/migrations/20260902_staging_synthetic_citizen_adoption.sql",
    "sha256:992e56a65af74b32e35d2211ac57714f32e2e72e4fb82ea59afeb7dbbcefb282",
)
SYNTHETIC_PRODUCT_ARTIFACTS = (
    *PRODUCT_ARTIFACTS,
    SYNTHETIC_CITIZEN_ADOPTION_ARTIFACT,
)
# Keep this module self-contained: the live verifier also compiles its exact
# Git blob with a synthetic __file__, without reading sibling modules.
IDENTITY_ROTATION_SOURCE_REVISION = "2961a04fb9b869bff35a411784c3fb4747eaf435"
IDENTITY_ROTATION_ARTIFACT = (
    "77-staging-synthetic-citizen-pass-v2.sql",
    "supabase/migrations/20260905_staging_synthetic_citizen_pass_v2.sql",
    "sha256:46aa0bd9efb89c837302f98a1ebd03151fc0f1828eb3212a79bc342ecc854f87",
)
ROTATED_SYNTHETIC_PRODUCT_ARTIFACTS = (
    *SYNTHETIC_PRODUCT_ARTIFACTS,
    IDENTITY_ROTATION_ARTIFACT,
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

FLUX_NAMESPACE = "flux-roebel-staging"
FLUX_SOURCE_NAME = "roebel-staging-operations"
FLUX_RECONCILER_NAME = "roebel-tracer-data-plane-reconciler"
FLUX_KUSTOMIZATION_NAME = "roebel-tracer-data-plane"
SECRET_MATERIALIZER_RUNNER = "scripts/materialize-tracer-data-plane-secrets.py"
LIVE_RUNNER = "scripts/run-tracer-data-plane-live.py"
SECRET_MATERIALIZATION_RECEIPT_SCHEMA = (
    "roebel_tracer_data_plane_secret_materialization_receipt_v1"
)
SECRET_TEARDOWN_RECEIPT_SCHEMA = "roebel_tracer_data_plane_secret_teardown_receipt_v1"
SECRET_MATERIALIZATION_JOURNAL_SCHEMA = (
    "roebel_tracer_data_plane_secret_materialization_journal_v1"
)
ACTIVATION_RECEIPT_SCHEMA = "roebel_tracer_data_plane_activation_receipt_v1"
PREVIEW_NAMESPACE = "stadtstack-roebel-web-preview"
WEB_FEED_SECRET = "roebel-tracer-feed-runtime"
WEB_FEED_SECRET_KEYS = ("supabase-anon-key",)
PARTICIPANT_POSTGREST_SECRET = "roebel-staging-participant-gateway-postgrest"
PARTICIPANT_POSTGREST_SECRET_KEYS = (
    "supabase-anon-key",
    "supabase-rpc-secret",
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


def bootstrap_verify_script(
    product_artifacts: tuple[tuple[str, str, str], ...] = PRODUCT_ARTIFACTS,
) -> str:
    checks = "\n".join(
        f"printf '%s  %s\\n' '{digest.removeprefix('sha256:')}' "
        f"'/roebel-tracer-bootstrap/{filename}'"
        for filename, _source, digest in product_artifacts
    )
    migrations = "".join(
        f"PGOPTIONS='{PARTICIPANT_MIGRATION_PGOPTIONS}' psql \"${{psql_args[@]}}\" "
        f"--file=/roebel-tracer-bootstrap/{filename}\n"
        for filename, _source, _digest in product_artifacts
        if filename not in {"71-roebel-tracer-baseline.sql"}
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
        f"{migrations}"
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


def _ephemeral_runtime_pin(
    source_revision: str | None = PRODUCT_SOURCE_REVISION,
    product_artifacts: tuple[tuple[str, str, str], ...] = PRODUCT_ARTIFACTS,
) -> dict[str, Any]:
    if product_artifacts == ROTATED_SYNTHETIC_PRODUCT_ARTIFACTS:
        require(
            source_revision == IDENTITY_ROTATION_SOURCE_REVISION,
            "rotated synthetic tracer source revision is not the reviewed publication",
        )
    elif product_artifacts == SYNTHETIC_PRODUCT_ARTIFACTS:
        require(
            isinstance(source_revision, str) and REVISION.fullmatch(source_revision),
            "synthetic tracer product source revision invalid",
        )
    else:
        require(
            source_revision in {
                INERT_PRODUCT_SOURCE_REVISION,
                LEGACY_PRODUCT_SOURCE_REVISION,
                PRODUCT_SOURCE_REVISION,
            },
            "tracer product source revision is not the approved predecessor or successor",
        )
    artifacts = [
        {"configMapFilename": filename, "path": path, "sha256": digest}
        for filename, path, digest in product_artifacts
    ]
    return {
        "schemaVersion": "roebel_ephemeral_tracer_data_plane_pin_v1",
        "activationReady": source_revision is not None,
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
            "sourceRevision": source_revision,
        },
        "secretReference": {
            "keys": list(RUNTIME_SECRET_KEYS),
            "name": RUNTIME_SECRET,
            "namespace": NAMESPACE,
            "valuesCommitted": False,
        },
    }


def secret_materialization_contract() -> dict[str, Any]:
    """Return the value-free, cross-namespace Secret binding contract."""
    return {
        "runner": SECRET_MATERIALIZER_RUNNER,
        "receiptSchemaVersion": SECRET_MATERIALIZATION_RECEIPT_SCHEMA,
        "teardownReceiptSchemaVersion": SECRET_TEARDOWN_RECEIPT_SCHEMA,
        "journalSchemaVersion": SECRET_MATERIALIZATION_JOURNAL_SCHEMA,
        "secretValueSource": "runner-csprng-only",
        "adoption": "forbidden",
        "createOrder": ["dataPlane", "webFeed", "participantPostgrest"],
        "initialState": "all-three-exact-secret-names-absent",
        "receiptContainsValues": False,
        "crashRecovery": {
            "journalBeforeFirstMutation": True,
            "journalBeforeNextMutation": "nonce-plus-each-created-uid-resourceVersion",
            "mode": "--recover-journal",
            "runner": SECRET_MATERIALIZER_RUNNER,
            "secretValuesIncluded": False,
        },
        "anonJwt": {
            "algorithm": "HS256",
            "encoding": "canonical-unpadded-base64url",
            "lifetimeDays": 365,
            "minimumRemainingDaysAtActivation": 30,
            "role": "anon",
            "signingSecretEncoding": "ascii-64-lower-hex",
        },
        "secrets": {
            "dataPlane": {
                "name": RUNTIME_SECRET,
                "namespace": NAMESPACE,
                "keys": list(RUNTIME_SECRET_KEYS),
            },
            "webFeed": {
                "name": WEB_FEED_SECRET,
                "namespace": PREVIEW_NAMESPACE,
                "keys": list(WEB_FEED_SECRET_KEYS),
            },
            "participantPostgrest": {
                "name": PARTICIPANT_POSTGREST_SECRET,
                "namespace": PREVIEW_NAMESPACE,
                "keys": list(PARTICIPANT_POSTGREST_SECRET_KEYS),
            },
        },
        "sharedValueBindings": [
            {
                "left": "dataPlane.anon-jwt",
                "right": "webFeed.supabase-anon-key",
            },
            {
                "left": "dataPlane.anon-jwt",
                "right": "participantPostgrest.supabase-anon-key",
            },
            {
                "left": "dataPlane.rpc-secret",
                "right": "participantPostgrest.supabase-rpc-secret",
            },
        ],
        "teardown": {
            "deleteOrder": ["participantPostgrest", "webFeed", "dataPlane"],
            "sourceReceiptRequired": True,
            "uidResourceVersionPreconditions": True,
            "requiredAbsentTargets": [
                *application_object_targets(),
                *[
                    {
                        "apiVersion": value["apiVersion"],
                        "kind": value["kind"],
                        "name": value["metadata"]["name"],
                        "namespace": value["metadata"]["namespace"],
                    }
                    for value in dormant_flux_objects(suspended=True).values()
                ],
            ],
            "requiredUnreferencedConsumers": [
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "name": "roebel-web-presentation",
                    "namespace": PREVIEW_NAMESPACE,
                    "secretName": WEB_FEED_SECRET,
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "name": "roebel-staging-participant-gateway",
                    "namespace": PREVIEW_NAMESPACE,
                    "secretName": PARTICIPANT_POSTGREST_SECRET,
                },
            ],
        },
        "valuesCommitted": False,
    }


def dormant_flux_objects(*, suspended: bool = True) -> dict[str, dict[str, Any]]:
    """Render the exact namespace-scoped reconciler bootstrap objects."""
    labels_value = {
        "app.kubernetes.io/part-of": "stadtstack",
        "stadtstack.io/authority": "none",
        "stadtstack.io/civic-authority": "none",
        "stadtstack.io/environment": "staging",
        "stadtstack.io/flux-tenant": "roebel-staging",
        "stadtstack.io/gitops-owner": "tracer-data-plane",
    }
    service_account = {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {
            "labels": labels_value,
            "name": FLUX_RECONCILER_NAME,
            "namespace": FLUX_NAMESPACE,
        },
        "automountServiceAccountToken": False,
    }
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {
            "labels": labels_value,
            "name": FLUX_RECONCILER_NAME,
            "namespace": NAMESPACE,
        },
        "rules": [
            {
                "apiGroups": [""],
                "resourceNames": [SERVICE_ACCOUNT_NAME],
                "resources": ["serviceaccounts"],
                "verbs": ["get", "patch", "update"],
            },
            {
                "apiGroups": [""],
                "resourceNames": [BOOTSTRAP_CONFIG_MAP],
                "resources": ["configmaps"],
                "verbs": ["get", "patch", "update"],
            },
            {
                "apiGroups": [""],
                "resourceNames": [POSTGRES_NAME, POSTGREST_NAME],
                "resources": ["services"],
                "verbs": ["get", "patch", "update"],
            },
            {
                "apiGroups": ["apps"],
                "resourceNames": [POSTGRES_NAME, POSTGREST_NAME],
                "resources": ["deployments"],
                "verbs": ["get", "patch", "update"],
            },
            {
                "apiGroups": ["apps"],
                "resources": ["replicasets"],
                "verbs": ["get", "list", "watch"],
            },
            {
                "apiGroups": ["networking.k8s.io"],
                "resourceNames": [POSTGRES_NAME, POSTGREST_NAME],
                "resources": ["networkpolicies"],
                "verbs": ["get", "patch", "update"],
            },
        ],
    }
    role_binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {
            "labels": labels_value,
            "name": FLUX_RECONCILER_NAME,
            "namespace": NAMESPACE,
        },
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": FLUX_RECONCILER_NAME,
        },
        "subjects": [
            {
                "kind": "ServiceAccount",
                "name": FLUX_RECONCILER_NAME,
                "namespace": FLUX_NAMESPACE,
            }
        ],
    }
    kustomization = {
        "apiVersion": "kustomize.toolkit.fluxcd.io/v1",
        "kind": "Kustomization",
        "metadata": {
            "labels": labels_value,
            "name": FLUX_KUSTOMIZATION_NAME,
            "namespace": FLUX_NAMESPACE,
        },
        "spec": {
            "deletionPolicy": "Orphan",
            "dependsOn": [],
            "force": False,
            "healthChecks": [
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "name": POSTGRES_NAME,
                    "namespace": NAMESPACE,
                },
                {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "name": POSTGREST_NAME,
                    "namespace": NAMESPACE,
                },
            ],
            "interval": "5m",
            "path": f"./{RENDER_ROOT}",
            "prune": False,
            "retryInterval": "30s",
            "serviceAccountName": FLUX_RECONCILER_NAME,
            "sourceRef": {
                "kind": "GitRepository",
                "name": FLUX_SOURCE_NAME,
                "namespace": FLUX_NAMESPACE,
            },
            "suspend": suspended,
            "targetNamespace": NAMESPACE,
            "timeout": "5m",
            "wait": True,
        },
    }
    return {
        "serviceAccount": service_account,
        "role": role,
        "roleBinding": role_binding,
        "kustomization": kustomization,
    }


def dormant_flux_contract() -> dict[str, Any]:
    objects = dormant_flux_objects(suspended=True)
    return {
        "objectOrder": ["serviceAccount", "role", "roleBinding", "kustomization"],
        "initialState": "all-four-exact-names-absent",
        "successState": "all-four-exact-uids-present-kustomization-suspended",
        "adoption": "forbidden",
        "sharedSourceMutation": "forbidden",
        "secretAccess": "forbidden",
        "applicationMutation": False,
        "civicAuthorityEffects": False,
        "objects": {
            name: {
                "apiVersion": value["apiVersion"],
                "kind": value["kind"],
                "name": value["metadata"]["name"],
                "namespace": value["metadata"]["namespace"],
                "semanticSha256": canonical_sha256(value),
            }
            for name, value in objects.items()
        },
        "runner": LIVE_RUNNER,
        "receiptSchemaVersion": ACTIVATION_RECEIPT_SCHEMA,
    }


def validate_activation_transition(previous: Any, candidate: Any) -> dict[str, Any]:
    """Admit only the exact null-to-protected-main source binding."""
    inert = runtime_pin(INERT_PRODUCT_SOURCE_REVISION, LEGACY_PRODUCT_ARTIFACTS)
    ready = runtime_pin(LEGACY_PRODUCT_SOURCE_REVISION, LEGACY_PRODUCT_ARTIFACTS)
    require(previous == inert, "tracer activation transition base drift")
    require(candidate == ready, "tracer activation transition candidate drift")
    require(previous["activationReady"] is False, "tracer activation predecessor ready")
    require(ready["activationReady"] is True, "tracer activation successor blocked")
    changed = []
    if previous["activationReady"] != ready["activationReady"]:
        changed.append("activationReady")
    if previous["productSource"]["sourceRevision"] != ready["productSource"]["sourceRevision"]:
        changed.append("productSource.sourceRevision")
    require(
        changed == ["activationReady", "productSource.sourceRevision"],
        "tracer activation transition changed field set drift",
    )
    return ready


def validate_citizen_adoption_transition(previous: Any, candidate: Any) -> dict[str, Any]:
    """Admit only the exact current-to-citizen-adoption bootstrap successor."""
    legacy = runtime_pin(LEGACY_PRODUCT_SOURCE_REVISION, LEGACY_PRODUCT_ARTIFACTS)
    successor = runtime_pin(PRODUCT_SOURCE_REVISION, PRODUCT_ARTIFACTS)
    require(previous == legacy, "tracer citizen-adoption transition base drift")
    require(candidate == successor, "tracer citizen-adoption transition candidate drift")
    require(previous["activationReady"] is True and successor["activationReady"] is True,
            "tracer citizen-adoption transition readiness drift")
    return successor


def validate_synthetic_citizen_adoption_transition(
    previous: Any,
    candidate: Any,
    source_revision: str,
) -> dict[str, Any]:
    """Admit the exact additive test-only migration at one product revision."""
    predecessor = runtime_pin(PRODUCT_SOURCE_REVISION, PRODUCT_ARTIFACTS)
    successor = runtime_pin(source_revision, SYNTHETIC_PRODUCT_ARTIFACTS)
    require(previous == predecessor, "synthetic tracer transition base drift")
    require(candidate == successor, "synthetic tracer transition candidate drift")
    require(
        previous["authority"] == successor["authority"]
        and previous["database"] == successor["database"]
        and previous["images"] == successor["images"]
        and previous["network"] == successor["network"]
        and previous["secretReference"] == successor["secretReference"],
        "synthetic tracer transition widened a protected boundary",
    )
    return successor


def _ephemeral_contract_boundary(
    product_artifacts: tuple[tuple[str, str, str], ...] = PRODUCT_ARTIFACTS,
) -> dict[str, Any]:
    """Return the public repository contract for this dormant render."""
    return {
        "activationReady": True,
        "authority": "none",
        "bootstrap": {
            "configMap": BOOTSTRAP_CONFIG_MAP,
            "hashVerificationBeforeSql": True,
            "productArtifacts": [
                {"path": path, "sha256": digest}
                for _filename, path, digest in product_artifacts
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
        "dormantFluxBootstrap": dormant_flux_contract(),
        "activation": {
            "applicationCreateOrder": list(application_object_order()),
            "applicationObjectCount": len(application_object_order()),
            "createBeforeUnsuspend": True,
            "failureRollback": "exact-operation-owned-uids-only",
            "journal": {
                "mode": "--recover-journal",
                "schemaVersion": "roebel_tracer_data_plane_activation_journal_v1",
                "uidResourceVersionPersistedBeforeNextMutation": True,
                "valuesIncluded": False,
            },
            "runner": LIVE_RUNNER,
            "waitsFor": [
                "flux-kustomization-ready-at-protected-operations-revision",
                "postgres-deployment-available",
                "postgrest-deployment-available",
                "service-endpointslices-ready",
            ],
        },
        "renderRoot": str(RENDER_ROOT),
        "runtimePin": str(RENDER_ROOT / "runtime-pin.json"),
        "schemaVersion": "roebel_ephemeral_tracer_data_plane_pin_v1",
        "secretReference": {
            "keys": list(RUNTIME_SECRET_KEYS),
            "name": RUNTIME_SECRET,
            "namespace": NAMESPACE,
            "valuesCommitted": False,
        },
        "secretMaterialization": secret_materialization_contract(),
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


def _ephemeral_postgres_deployment(
    product_artifacts: tuple[tuple[str, str, str], ...] = PRODUCT_ARTIFACTS,
) -> dict[str, Any]:
    bootstrap_artifacts_sha256 = canonical_sha256(
        [
            {"path": path, "sha256": digest}
            for _filename, path, digest in product_artifacts
        ]
    )
    template_annotations = {
        "stadtstack.io/storage-truth": "ephemeral-emptydir-recreated-baseline",
    }
    if product_artifacts in {PRODUCT_ARTIFACTS, SYNTHETIC_PRODUCT_ARTIFACTS}:
        template_annotations["stadtstack.io/bootstrap-artifacts-sha256"] = (
            bootstrap_artifacts_sha256
        )
    elif product_artifacts == ROTATED_SYNTHETIC_PRODUCT_ARTIFACTS:
        # The data lives in emptyDir. Rotating this annotation would recreate
        # the Pod and destroy it. Keep the entire predecessor Pod template;
        # update only Deployment metadata and the stable-name ConfigMap, then
        # apply migration 77 in-place. A future fresh Pod reads all migrations.
        template_annotations = expected_postgres_deployment(
            SYNTHETIC_PRODUCT_ARTIFACTS
        )["spec"]["template"]["metadata"]["annotations"]
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
            {"name": "PGDATA", "value": "/var/lib/postgresql/data"},
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
                "stadtstack.io/bootstrap-artifacts-sha256": bootstrap_artifacts_sha256,
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
                    "annotations": template_annotations,
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


RETAINED_SCHEMA = "roebel_retained_tracer_data_plane_pin_v1"
RETAINED_CLAIM = "roebel-tracer-postgres-data-v1"
RETAINED_STORAGE_CLASS = "hcloud-volumes"
RETAINED_SIZE = "10Gi"
RETAINED_RECORD_PATH = Path("reviewed-render/roebel-staging/tracer-storage-continuity-v1.json")
RESTORE_MARKER = "/var/lib/postgresql/data/.roebel-tracer-restored-v1"
RESTORE_MARKER_VALUE = "roebel-tracer-restored-v1"
RETAINED_PGDATA = "/var/lib/postgresql/data/pgdata"


def retained_storage() -> dict[str, Any]:
    return {
        "durability": "retained-pvc-restored-v1",
        "persistentVolumeClaim": True,
        "claimName": RETAINED_CLAIM,
        "namespace": NAMESPACE,
        "storageClassName": RETAINED_STORAGE_CLASS,
        "requestedStorage": RETAINED_SIZE,
        "accessModes": ["ReadWriteOnce"],
        "volumeMode": "Filesystem",
        "requiredReclaimPolicy": "Retain",
        "existingClaimRequired": True,
        "claimProvisionedByFlux": False,
        "restoreRequiredBeforeStartup": True,
        "emptyDatabaseBootstrapAllowed": False,
    }


def retained_transition_record() -> dict[str, Any]:
    """Value-free transition requirements; live evidence stays private."""
    return {
        "schemaVersion": "roebel_tracer_storage_continuity_v1",
        "authority": "none",
        "municipalRecordsAllowed": False,
        "storage": retained_storage(),
        "postgresImage": POSTGRES_IMAGE,
        "sourceProfile": "gnosis-staging-test-v2",
        "secretReferenceChanged": False,
        "networkPolicyChanged": False,
        "legacyImmutableSelectorPreserved": True,
        "privateEvidenceRequired": [
            "exact-source-pod-uid-and-current-protected-revision",
            "encrypted-database-roles-and-runtime-dependency-backup",
            "independent-decryption-and-archive-member-checksums",
            "owned-claim-uid-volume-binding-retain-policy-and-capacity",
            "isolated-restoration-with-no-application-service-selection",
            "all-source-table-hashes-sequences-roles-functions-and-acls-preserved",
            "restored-database-survives-a-pod-replacement",
            "postgrest-quiesced-and-source-witness-unchanged-before-cutover",
            "restore-process-stopped-before-application-mount",
            "ready-database-and-public-receipt-replay-before-reconciler-resume",
        ],
        "rollback": {
            "beforeCutover": "leave-original-pod-and-data-serving",
            "afterCutover": "preserve-restored-claim-and-use-reviewed-forward-recovery",
            "returnToEmptyDirAllowed": False,
            "deleteClaimOrVolumeAllowed": False,
        },
        "restoreMarker": {"path": RESTORE_MARKER, "value": RESTORE_MARKER_VALUE},
        "markerMeaning": "startup-guard-only-private-restore-proof-is-separate",
    }


def retained_enabled(root: Path) -> bool:
    return json.loads((root / RENDER_ROOT / "runtime-pin.json").read_text()).get("schemaVersion") == RETAINED_SCHEMA


def runtime_pin(source_revision=PRODUCT_SOURCE_REVISION, product_artifacts=PRODUCT_ARTIFACTS, *, retained=False):
    value = _ephemeral_runtime_pin(source_revision, product_artifacts)
    if retained:
        require(product_artifacts == ROTATED_SYNTHETIC_PRODUCT_ARTIFACTS, "retained storage requires the complete rotated identity")
        value["schemaVersion"] = RETAINED_SCHEMA
        value["database"] = {**retained_storage(), "durableCivicRecordsAllowed": False}
    return value


def contract_boundary(product_artifacts=PRODUCT_ARTIFACTS, *, retained=False):
    value = _ephemeral_contract_boundary(product_artifacts)
    if retained:
        require(product_artifacts == ROTATED_SYNTHETIC_PRODUCT_ARTIFACTS, "retained storage requires the complete rotated identity")
        value["schemaVersion"] = RETAINED_SCHEMA
        value["storage"] = retained_storage()
        value["storageTransitionRecord"] = str(RETAINED_RECORD_PATH)
    return value


def expected_postgres_deployment(product_artifacts=PRODUCT_ARTIFACTS, *, retained=False):
    value = _ephemeral_postgres_deployment(product_artifacts)
    if not retained:
        return value
    require(product_artifacts == ROTATED_SYNTHETIC_PRODUCT_ARTIFACTS, "retained storage requires the complete rotated identity")
    for metadata in (value["metadata"], value["spec"]["template"]["metadata"]):
        metadata["annotations"]["stadtstack.io/storage-truth"] = "retained-pvc-restored-v1"
    pod = value["spec"]["template"]["spec"]
    # This image's configuration overrides PGDATA unless data_directory is
    # explicit. Keep its configuration directory and pin the restored data path.
    pod["containers"][0]["args"] = ["postgres", "-D", "/etc/postgresql", "-c", f"data_directory={RETAINED_PGDATA}"]
    for item in pod["containers"][0]["env"]:
        if item["name"] == "PGDATA":
            item["value"] = RETAINED_PGDATA
    pod["volumes"][0] = {"name": "postgres-data", "persistentVolumeClaim": {"claimName": RETAINED_CLAIM, "readOnly": False}}
    pod["initContainers"] = [{
        "name": "require-restored-data",
        "image": POSTGRES_IMAGE,
        "imagePullPolicy": "IfNotPresent",
        "command": ["/bin/sh", "-ec", f'test -d {RETAINED_PGDATA}/base; test "$(cat {RETAINED_PGDATA}/PG_VERSION)" = 15; test "$(cat {RESTORE_MARKER})" = {RESTORE_MARKER_VALUE}'],
        "volumeMounts": [{"name": "postgres-data", "mountPath": "/var/lib/postgresql/data", "readOnly": True}],
        # The pinned image owns PGDATA as postgres (105:106). A root process
        # with every capability dropped cannot traverse its mode-0700 directory.
        "securityContext": {"runAsUser": 105, "runAsGroup": 106, "runAsNonRoot": True, "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
        "resources": {"requests": {"cpu": "5m", "memory": "16Mi"}, "limits": {"cpu": "100m", "memory": "32Mi"}},
    }]
    return value


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


def expected_bootstrap_config_map(
    root: Path,
    product_artifacts: tuple[tuple[str, str, str], ...] = PRODUCT_ARTIFACTS,
) -> dict[str, Any]:
    """Return the stable ConfigMap generated by the checked-in Kustomization."""
    bootstrap = root / RENDER_ROOT / "bootstrap"
    filenames = (
        "zz-roebel-tracer.sh",
        product_artifacts[0][0],
        "72-provision-roebel-vault.sh",
        *(filename for filename, _path, _digest in product_artifacts[1:]),
    )
    for filename in filenames:
        require((bootstrap / filename).is_file(), f"tracer bootstrap file missing: {filename}")
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "labels": {
                "app.kubernetes.io/component": "tracer-bootstrap",
                "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
                "stadtstack.io/authority": "none",
                "stadtstack.io/civic-authority": "none",
                "stadtstack.io/data-lifecycle": "ephemeral-tracer",
                "stadtstack.io/environment": "staging",
            },
            "name": BOOTSTRAP_CONFIG_MAP,
            "namespace": NAMESPACE,
        },
        "data": {
            filename: (bootstrap / filename).read_text()
            for filename in filenames
        },
    }


def application_object_order() -> tuple[str, ...]:
    """Closed create order: isolation first, workloads last."""
    return (
        "postgresNetworkPolicy",
        "postgrestNetworkPolicy",
        "serviceAccount",
        "bootstrapConfigMap",
        "postgresService",
        "postgrestService",
        "postgresDeployment",
        "postgrestDeployment",
    )


def application_object_targets() -> list[dict[str, str]]:
    identities = (
        ("networking.k8s.io/v1", "NetworkPolicy", POSTGRES_NAME),
        ("networking.k8s.io/v1", "NetworkPolicy", POSTGREST_NAME),
        ("v1", "ServiceAccount", SERVICE_ACCOUNT_NAME),
        ("v1", "ConfigMap", BOOTSTRAP_CONFIG_MAP),
        ("v1", "Service", POSTGRES_NAME),
        ("v1", "Service", POSTGREST_NAME),
        ("apps/v1", "Deployment", POSTGRES_NAME),
        ("apps/v1", "Deployment", POSTGREST_NAME),
    )
    return [
        {"apiVersion": api_version, "kind": kind, "name": name, "namespace": NAMESPACE}
        for api_version, kind, name in identities
    ]


def expected_application_objects(
    root: Path,
    product_artifacts: tuple[tuple[str, str, str], ...] | None = None,
) -> dict[str, dict[str, Any]]:
    if product_artifacts is None:
        rotation = root / RENDER_ROOT / "bootstrap" / IDENTITY_ROTATION_ARTIFACT[0]
        require(not rotation.is_symlink(), "tracer rotation bootstrap must not be a symlink")
        synthetic_migration = (
            root / RENDER_ROOT / "bootstrap" / SYNTHETIC_CITIZEN_ADOPTION_ARTIFACT[0]
        )
        citizen_migration = (
            root / RENDER_ROOT / "bootstrap" / PRODUCT_ARTIFACTS[-1][0]
        )
        require(
            not synthetic_migration.is_symlink(),
            "tracer synthetic-adoption bootstrap must not be a symlink",
        )
        require(
            not citizen_migration.is_symlink(),
            "tracer citizen-adoption bootstrap must not be a symlink",
        )
        if synthetic_migration.exists():
            require(
                synthetic_migration.is_file() and citizen_migration.is_file(),
                "tracer synthetic-adoption bootstrap requires the real-adoption predecessor",
            )
            product_artifacts = (
                ROTATED_SYNTHETIC_PRODUCT_ARTIFACTS if rotation.is_file()
                else SYNTHETIC_PRODUCT_ARTIFACTS
            )
        elif citizen_migration.exists():
            require(
                citizen_migration.is_file(),
                "tracer citizen-adoption bootstrap must be a regular file",
            )
            product_artifacts = PRODUCT_ARTIFACTS
        else:
            product_artifacts = LEGACY_PRODUCT_ARTIFACTS
    objects = {
        "postgresNetworkPolicy": expected_postgres_network_policy(),
        "postgrestNetworkPolicy": expected_postgrest_network_policy(),
        "serviceAccount": expected_service_account(),
        "bootstrapConfigMap": expected_bootstrap_config_map(root, product_artifacts),
        "postgresService": expected_postgres_service(),
        "postgrestService": expected_postgrest_service(),
        "postgresDeployment": expected_postgres_deployment(product_artifacts, retained=retained_enabled(root)),
        "postgrestDeployment": expected_postgrest_deployment(),
    }
    require(tuple(objects) == application_object_order(), "tracer application object order drift")
    return objects


def kustomization_text(
    product_artifacts: tuple[tuple[str, str, str], ...] = PRODUCT_ARTIFACTS,
) -> str:
    migration_lines = "\n".join(
        f"      - {filename}=bootstrap/{filename}"
        for filename, _path, _digest in product_artifacts[1:]
    )
    return f"""apiVersion: kustomize.config.k8s.io/v1beta1
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
      - {product_artifacts[0][0]}=bootstrap/{product_artifacts[0][0]}
      - 72-provision-roebel-vault.sh=bootstrap/72-provision-roebel-vault.sh
{migration_lines}
generatorOptions:
  disableNameSuffixHash: true
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


def expected_files(
    product_artifacts: tuple[tuple[str, str, str], ...] = PRODUCT_ARTIFACTS,
) -> set[str]:
    return {
        *(str(RENDER_ROOT / filename) for filename in JSON_FILES),
        str(RENDER_ROOT / "kustomization.yaml"),
        str(RENDER_ROOT / "bootstrap/zz-roebel-tracer.sh"),
        str(RENDER_ROOT / "bootstrap/72-provision-roebel-vault.sh"),
        *(
            str(RENDER_ROOT / "bootstrap" / filename)
            for filename, _path, _digest in product_artifacts
        ),
    }


def verify_render(root: Path) -> dict[str, Any]:
    render = root / RENDER_ROOT
    require(render.is_dir(), "tracer data-plane render root missing")
    rotation = render / "bootstrap" / IDENTITY_ROTATION_ARTIFACT[0]
    require(not rotation.is_symlink(), "tracer rotation bootstrap must not be a symlink")
    rotated = rotation.is_file()
    retained = retained_enabled(root)
    record = root / RETAINED_RECORD_PATH
    require(not record.is_symlink(), "retained storage record must not be a symlink")
    require(record.is_file() == retained, "retained storage requires its complete transition record")
    if retained:
        require(rotated, "retained storage requires the complete rotated identity")
        require(json.loads(record.read_text()) == retained_transition_record(), "retained storage transition record drift")
    synthetic = (render / "bootstrap/76-staging-synthetic-citizen-adoption.sql").is_file()
    successor = (render / "bootstrap/75-staging-citizen-adoption.sql").is_file()
    require(not synthetic or successor, "synthetic tracer migration lacks real-adoption predecessor")
    require(not rotated or synthetic, "tracer rotation lacks the v1 predecessor")
    if synthetic:
        product_artifacts = (
            ROTATED_SYNTHETIC_PRODUCT_ARTIFACTS if rotated else SYNTHETIC_PRODUCT_ARTIFACTS
        )
        runtime_value = json.loads((render / "runtime-pin.json").read_text())
        source_revision = runtime_value.get("productSource", {}).get("sourceRevision")
        require(
            isinstance(source_revision, str) and REVISION.fullmatch(source_revision),
            "synthetic tracer runtime source revision invalid",
        )
    else:
        product_artifacts = PRODUCT_ARTIFACTS if successor else LEGACY_PRODUCT_ARTIFACTS
        source_revision = (
            PRODUCT_SOURCE_REVISION if successor else LEGACY_PRODUCT_SOURCE_REVISION
        )
    actual_files = {
        str(path.relative_to(root))
        for path in render.rglob("*")
        if path.is_file()
    }
    require(actual_files == expected_files(product_artifacts), "tracer data-plane file set drift")

    objects: dict[str, Any] = {}
    for filename, factory in JSON_FILES.items():
        actual = json.loads((render / filename).read_text())
        if filename == "runtime-pin.json":
            expected = runtime_pin(source_revision, product_artifacts, retained=retained)
        elif filename == "postgres-deployment.json":
            expected = expected_postgres_deployment(product_artifacts, retained=retained)
        else:
            expected = factory()
        require(actual == expected, f"tracer data-plane {filename} drift")
        objects[filename] = actual

    require(
        (render / "kustomization.yaml").read_text() == kustomization_text(product_artifacts),
        "tracer data-plane Kustomization drift",
    )
    require(
        (render / "bootstrap/zz-roebel-tracer.sh").read_text()
        == bootstrap_verify_script(product_artifacts),
        "tracer bootstrap verifier drift",
    )
    require(
        (render / "bootstrap/72-provision-roebel-vault.sh").read_text()
        == vault_bootstrap_script(),
        "tracer Vault bootstrap drift",
    )
    for filename, _source, digest in product_artifacts:
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
    require("PersistentVolumeClaim" not in serialized, "claim provisioning in the application render is forbidden")

    return {
        "schemaVersion": "roebel_retained_tracer_data_plane_verification_v1" if retained else "roebel_ephemeral_tracer_data_plane_verification_v1",
        "status": "passed",
        "activationReady": runtime_pin(source_revision, product_artifacts)["activationReady"],
        "productSourceRevision": source_revision,
        "productArtifacts": [
            {"path": path, "sha256": digest}
            for _filename, path, digest in product_artifacts
        ],
        "renderCanonicalSha256": canonical_sha256(objects),
        "externalIngress": False,
        "persistentVolumeClaim": retained,
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
