#!/usr/bin/env python3
"""Fail-closed verifier for the public Röbel staging reviewed render.

For pull requests this exact script is loaded from the protected base branch
and receives the candidate checkout only as data. The candidate therefore
cannot weaken its own admission policy.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import ipaddress
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
IMMUTABLE_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
RFC3339_UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


def load_participant_gateway_policy_module():
    """Load policy beside this protected verifier, never from candidate data."""
    path = Path(__file__).with_name("staging_participant_gateway_policy.py")
    spec = importlib.util.spec_from_file_location("protected_participant_gateway_policy", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("protected participant gateway policy unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PARTICIPANT_POLICY = load_participant_gateway_policy_module()
CIVIC_PROJECTION_UPSTREAM_URL = PARTICIPANT_POLICY.WEB_CIVIC_PROJECTION_UPSTREAM_URL
WEB_PRESENTATION_LABELS = PARTICIPANT_POLICY.WEB_PRESENTATION_LABELS


def load_workbench_baseline_module():
    """Load the protected one-time workbench handover policy."""
    path = Path(__file__).with_name("workbench_baseline_handover.py")
    spec = importlib.util.spec_from_file_location("protected_workbench_baseline_handover", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("protected workbench baseline handover unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


WORKBENCH_BASELINE = load_workbench_baseline_module()


def load_tracer_data_plane_module():
    """Load the protected, value-free ephemeral tracer data-plane policy."""
    path = Path(__file__).with_name("tracer_data_plane_policy.py")
    spec = importlib.util.spec_from_file_location("protected_tracer_data_plane_policy", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("protected tracer data-plane policy unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TRACER_DATA_PLANE = load_tracer_data_plane_module()


def load_identity_rotation_policy():
    # Always resolve beside protected policy, never inside a candidate checkout.
    path = Path(__file__).with_name("staging_test_identity_rotation.py")
    spec = importlib.util.spec_from_file_location("protected_test_identity_rotation", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("protected test identity rotation policy unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


IDENTITY_ROTATION = load_identity_rotation_policy()

ELIGIBILITY_ISSUER_POLICY_PATH = (
    "policy/staging-participant-eligibility-issuer-materialization-policy.json"
)
ELIGIBILITY_ISSUER_MATERIALIZER_PATH = (
    "scripts/materialize-staging-participant-eligibility-issuer.py"
)
ELIGIBILITY_ISSUER_MATERIALIZER_TEST_PATH = (
    "scripts/test_materialize_staging_participant_eligibility_issuer.py"
)
ELIGIBILITY_ISSUER_DRY_RUN_PROJECTION_TRANSITION = {
    ELIGIBILITY_ISSUER_MATERIALIZER_PATH: {
        "predecessorSha256": "sha256:2f0f147d169b11ecbc2b288416d83531c9de45907ff32460d1615e2d43d70ee1",
        "successorSha256": "sha256:042f7ca54367cd1c92cd9ab4685fc2f20ef0af48ae8f7eec795f5fdf473bab44",
    },
    ELIGIBILITY_ISSUER_MATERIALIZER_TEST_PATH: {
        "predecessorSha256": "sha256:471b834e8e7cbea2d04df3e07caec4b2508ae7b919d2a1defbea7059d3af046f",
        "successorSha256": "sha256:09052236fc3d9d2419ef3141461e5743f7e89b274899a1a9d2ebdb13ffab2b7b",
    },
    "scripts/test_run_staging_participant_gateway_live.py": {
        "predecessorSha256": "sha256:c27d8688f01fe0cb9e2c2407d2e1ddcd20f54494f7103c7d2737121e8a65887e",
        "successorSha256": "sha256:fbba0df00287771040272ecc960dc4a43130d5cd7b49caeb3d53b6b3290225da",
    },
}
CITIZEN_ADOPTION_SQL_PATH = str(
    TRACER_DATA_PLANE.RENDER_ROOT / "bootstrap/75-staging-citizen-adoption.sql"
)

HEAD_SCHEMA = "roebel_staging_release_set_head_v1"
RENDER_SCHEMA = "roebel_staging_reviewed_render_v1"
RENDER_ROOT = "reviewed-render/roebel-staging"
COMPONENT_ORDER = ("public-mecky", "roebel-web-staging")
COMPONENTS = {
    "public-mecky": {
        "directory": "public-mecky",
        "repository": "ghcr.io/giraeffleaeffle/public-mecky",
        "namespace": "stadtstack-roebel-staging-lab",
        "name": "public-mecky",
        "container": "public-mecky",
    },
    "roebel-web-staging": {
        "directory": "web",
        "repository": "ghcr.io/giraeffleaeffle/roebel-web-staging",
        "namespace": "stadtstack-roebel-web-preview",
        "name": "roebel-web-presentation",
        "container": "web",
    },
}

# The current render remains the default admission shape.  The reviewed
# knowledge runtime is deliberately a second, closed shape: a promotion may
# either contain the complete current render or the complete future render,
# never a mixture of the two.  The future values below are policy-level
# identities; the source revision and image digest are bound by runtime-pin in
# the later render PR.
REVIEWED_PUBLIC_KNOWLEDGE_FILES = {
    f"{RENDER_ROOT}/reviewed-public-knowledge/deployment.json",
    f"{RENDER_ROOT}/reviewed-public-knowledge/service.json",
    f"{RENDER_ROOT}/reviewed-public-knowledge/networkpolicy.json",
    f"{RENDER_ROOT}/reviewed-public-knowledge/kustomization.yaml",
    f"{RENDER_ROOT}/reviewed-public-knowledge/runtime-pin.json",
}
REVIEWED_PUBLIC_KNOWLEDGE_NAMESPACE = "stadtstack-roebel-staging-lab"
REVIEWED_PUBLIC_KNOWLEDGE_NAME = "reviewed-public-knowledge"
REVIEWED_PUBLIC_KNOWLEDGE_IMAGE = "ghcr.io/giraeffleaeffle/stadtstack-reviewed-public-knowledge-runtime"
REVIEWED_PUBLIC_KNOWLEDGE_WORKFLOW = (
    "https://github.com/GiraeffleAeffle/stadtstack/"
    ".github/workflows/reviewed-knowledge-runtime-publish.yml@refs/heads/main"
)
REVIEWED_PUBLIC_KNOWLEDGE_BASE_URL = (
    "http://reviewed-public-knowledge.stadtstack-roebel-staging-lab."
    "svc.cluster.local:18080"
)
REVIEWED_PUBLIC_KNOWLEDGE_SOURCE_KINDS = "local_news,ratsinformation"
PUBLIC_MECKY_REVIEWED_WEB_SOURCE_BASE_URL = (
    "http://roebel-web-presentation.stadtstack-roebel-web-preview."
    "svc.cluster.local:8080"
)
PUBLIC_MECKY_REVIEWED_WEB_SOURCE_ENV = [
    {
        "name": "MECKY_REVIEWED_KNOWLEDGE_BASE_URL",
        "value": PUBLIC_MECKY_REVIEWED_WEB_SOURCE_BASE_URL,
    },
]
REVIEWED_PUBLIC_KNOWLEDGE_LABELS = {
    "app.kubernetes.io/component": "reviewed-public-knowledge",
    "app.kubernetes.io/name": "reviewed-public-knowledge",
    "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
    "stadtstack.io/authority": "none",
}
REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_SOURCE_REVISION = "642e2741d2fd3cb867c0e1c315f04ef8e29d787b"
REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_SOURCE_TAG = (
    "source-642e2741d2fd3cb867c0e1c315f04ef8e29d787b"
)
REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_IMAGE_DIGEST = (
    "sha256:7846fee172cfdad286773fa56c939d716ae32604cd0e47833f72536aa6a5c1dc"
)
REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_SLSA_DIGEST = (
    "sha256:5d7f4a80f77bc0b1c7e036303325bf68f4bbb6e8a4dbeaaa839abf7abd330aab"
)
REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_SPDX_DIGEST = (
    "sha256:052b53e71548f978fd00d22eb9dd20089dd58b05f6b9cc39590f3d8f25740bc4"
)
REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_AUTH_DIGEST = (
    "sha256:ec21c035eccb78eb5ca20ec95628eb351633621e09a130ac8d7e663714d40c7a"
)
REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_RECEIPT_DIGEST = (
    "sha256:21a4c33b36db0831fa65375f6e7af812b87502986d97d5a45e7eb8b19108b04f"
)
LEGACY_SYNTHETIC_EVIDENCE_ENV_NAMES = {
    "STADTSTACK_E2E_MODE",
    "STADTSTACK_E2E_SYNTHETIC_EVIDENCE_ALLOWED",
    "STADTSTACK_E2E_REVIEWED_EVIDENCE",
    "STADTSTACK_E2E_REVIEWED_EVIDENCE_SHA256",
}
PUBLIC_MECKY_LABELS = {
    "app.kubernetes.io/component": "public-mecky",
    "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
}
PUBLIC_MECKY_REVIEWED_WEB_SOURCE_TRANSITION_FILES = {
    f"{RENDER_ROOT}/integrity.json",
    f"{RENDER_ROOT}/network-boundary-migration.json",
    f"{RENDER_ROOT}/public-mecky/deployment.json",
    f"{RENDER_ROOT}/public-mecky/networkpolicy.json",
    f"{RENDER_ROOT}/web/networkpolicy.json",
}
PUBLIC_MECKY_NETWORK_POLICY_LABELS = {
    **PUBLIC_MECKY_LABELS,
    "stadtstack.io/authority": "none",
}
PUBLIC_MECKY_REVIEWED_EGRESS_DESTINATION_LABELS = {
    "app.kubernetes.io/component": "reviewed-public-knowledge",
    "app.kubernetes.io/name": "reviewed-public-knowledge",
    "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
    "stadtstack.io/authority": "none",
}

EXPECTED_FILES = {
    ".github/CODEOWNERS",
    ".github/workflows/automatic-promotion.yml",
    ".github/workflows/reviewed-render-admission.yml",
    ".github/workflows/staging-participant-gateway-activation.yml",
    ".github/workflows/staging-participant-flux-bootstrap.yml",
    ".gitignore",
    "LICENSE",
    "README.md",
    "contracts/stadtstack-case-image-resource-inventory-contract.json",
    "contracts/stadtstack-case-recovery-composition-contract.json",
    "contracts/stadtstack-case-runtime-contract.json",
    "policy/repository-contract.json",
    "policy/staging-participant-gateway-activation-policy.json",
    ELIGIBILITY_ISSUER_POLICY_PATH,
    "scripts/assemble-synthetic-citizen-pass-handoff.py",
    "scripts/render-release-set-promotion.py",
    "scripts/activate-staging-participant-gateway.py",
    "scripts/bootstrap-staging-participant-flux.py",
    "scripts/handover-staging-workbench-baseline.py",
    "scripts/workbench_baseline_recovery.py",
    "scripts/run-staging-participant-gateway-live.py",
    "scripts/materialize-staging-participant-gateway-secrets.py",
    ELIGIBILITY_ISSUER_MATERIALIZER_PATH,
    "scripts/handover-staging-participant-dormant-receipt.py",
    "scripts/staging_participant_dormant_receipt_handover.py",
    "scripts/promote-staging-workbench-image.py",
    "scripts/reset-staging-relay-fixtures.py",
    "scripts/staging_participant_flux_bootstrap.py",
    "scripts/staging_participant_gateway_policy.py",
    "scripts/tracer_data_plane_policy.py",
    "scripts/staging_test_identity_rotation.py",
    "scripts/test_staging_test_identity_rotation.py",
    "tests/fixtures/staging-synthetic-citizen-pass-v2.sql",
    "scripts/materialize-tracer-data-plane-secrets.py",
    "scripts/run-tracer-data-plane-live.py",
    "scripts/test_automatic_promotion_workflow.py",
    "scripts/test_assemble_synthetic_citizen_pass_handoff.py",
    "scripts/test_activate_staging_participant_gateway.py",
    "scripts/test_run_staging_participant_gateway_live.py",
    "scripts/test_materialize_staging_participant_gateway_secrets.py",
    ELIGIBILITY_ISSUER_MATERIALIZER_TEST_PATH,
    "scripts/test_staging_participant_dormant_receipt_handover.py",
    "scripts/test_promote_staging_workbench_image.py",
    "scripts/test_reset_staging_relay_fixtures.py",
    "scripts/test_staging_participant_flux_bootstrap.py",
    "scripts/test_staging_participant_gateway_policy.py",
    "scripts/test_tracer_data_plane_policy.py",
    "scripts/test_materialize_tracer_data_plane_secrets.py",
    "scripts/test_run_tracer_data_plane_live.py",
    "scripts/test_verify_case_staging_topology.py",
    "scripts/test_render_release_set_promotion.py",
    "scripts/test_verify_reviewed_render.py",
    "scripts/test_workbench_baseline_handover.py",
    "scripts/test_workbench_baseline_recovery.py",
    "scripts/verify-stadtstack-case-runtime-contract.py",
    "scripts/verify-case-staging-topology.py",
    "scripts/verify-reviewed-render.py",
    "scripts/workbench_baseline_handover.py",
    "scripts/verify-stadtstack-case-image-resource-inventory-contract.py",
    "scripts/verify-stadtstack-case-recovery-composition-contract.py",
    "tests/test_stadtstack_case_image_resource_inventory_contract.py",
    "tests/test_stadtstack_case_runtime_contract.py",
    "tests/test_stadtstack-case-recovery-composition-contract.py",
    "case-staging-topology/contract.json",
    "case-staging-topology/roebel-case-public-binding-default-deny-networkpolicy.json",
    "case-staging-topology/roebel-case-public-binding-allow-private-outbox-and-dns-egress-networkpolicy.json",
    "case-staging-topology/roebel-case-public-binding-allow-roebel-web-ingress-networkpolicy.json",
    "case-staging-topology/roebel-case-public-binding-service.json",
    "case-staging-topology/roebel-case-public-binding-serviceaccount.json",
    "case-staging-topology/roebel-case-steward-control-allow-private-outbox-from-public-networkpolicy.json",
    "case-staging-topology/roebel-case-steward-control-default-deny-networkpolicy.json",
    "case-staging-topology/roebel-case-steward-control-private-outbox-service.json",
    "case-staging-topology/roebel-case-steward-control-service.json",
    "case-staging-topology/roebel-case-steward-control-serviceaccount.json",
    f"{RENDER_ROOT}/head.json",
    f"{RENDER_ROOT}/integrity.json",
    f"{RENDER_ROOT}/live-preconditions.json",
    f"{RENDER_ROOT}/network-boundary-migration.json",
    f"{RENDER_ROOT}/public-mecky/deployment.json",
    f"{RENDER_ROOT}/public-mecky/kustomization.yaml",
    f"{RENDER_ROOT}/public-mecky/networkpolicy.json",
    f"{RENDER_ROOT}/public-mecky/service.json",
    f"{RENDER_ROOT}/web/deployment.json",
    f"{RENDER_ROOT}/web/ingress.json",
    f"{RENDER_ROOT}/web/kustomization.yaml",
    f"{RENDER_ROOT}/web/networkpolicy.json",
    WORKBENCH_BASELINE.NETWORK_POLICY_PATH,
    WORKBENCH_BASELINE.KUSTOMIZATION_PATH,
    *TRACER_DATA_PLANE.expected_files(TRACER_DATA_PLANE.LEGACY_PRODUCT_ARTIFACTS),
}

FUTURE_EXPECTED_FILES = EXPECTED_FILES | REVIEWED_PUBLIC_KNOWLEDGE_FILES

# The participant gateway is deliberately a fourth, independently pinned
# staging capability.  It is never folded into the normal Web/Mecky release
# set: the gateway has a writer capability while the public Web must remain
# read-only.  The complete subtree is admitted only alongside the reviewed
# public-knowledge runtime, and may later be composed with (but never hidden
# inside) the signed-Nostr tracer.
PARTICIPANT_GATEWAY_ROOT = PARTICIPANT_POLICY.GATEWAY_ROOT
PARTICIPANT_GATEWAY_FILES = set(PARTICIPANT_POLICY.ALL_RENDER_FILES)
PARTICIPANT_GATEWAY_EXPECTED_FILES = FUTURE_EXPECTED_FILES | PARTICIPANT_GATEWAY_FILES
PARTICIPANT_GATEWAY_NAME = PARTICIPANT_POLICY.GATEWAY_NAME
PARTICIPANT_GATEWAY_NAMESPACE = PARTICIPANT_POLICY.GATEWAY_NAMESPACE
PARTICIPANT_GATEWAY_PORT = PARTICIPANT_POLICY.GATEWAY_PORT
PARTICIPANT_GATEWAY_IMAGE = PARTICIPANT_POLICY.STATIC_ACTIVATION_POLICY["productPins"]["imageRepository"]
PARTICIPANT_GATEWAY_WORKFLOW = PARTICIPANT_POLICY.STATIC_ACTIVATION_POLICY["productPins"]["workflowIdentity"]
PARTICIPANT_GATEWAY_ORIGIN = PARTICIPANT_POLICY.STATIC_ACTIVATION_POLICY["endpoints"]["browserOrigin"]
PARTICIPANT_GATEWAY_LABELS = PARTICIPANT_POLICY.GATEWAY_LABELS
# The activation policy records the immutable decision that first admitted the
# writer. Runtime releases are a separate, append-only concern. Each entry
# advances only the four published-artifact leaves; every activation,
# database, topic, Secret, network, and authority fact remains inherited from
# its exact predecessor.
PARTICIPANT_GATEWAY_RUNTIME_RELEASES = (
    {
        "sourceRevision": "722c75a0ae2303edcaa8c8281af7d6fe3c53089b",
        "sourceTreeSha256": "sha256:06955333455bc805645ed1f956aa79dfea1b556be970da2182bb2e76b29b4a68",
        "manifestDigest": "sha256:2b77d59eed440df844c86c4adf0ae5f3577f7526d4b09160c2f1e5e731dc7f2b",
        "workflowSha256": "sha256:a0c55933682bd94cb29630c83d6f7168ea19e9eba66a40d8132e8a91823c96c5",
    },
    {
        "sourceRevision": "f2e5c93c8fb0127d3aacc33d4be1a1a63f707dc1",
        "sourceTreeSha256": "sha256:0325e742e595de75a694d6662ffe6d84cd38818239c3f334d4ce802ed48ca819",
        "manifestDigest": "sha256:ba12dea1ebffa2cb85b58f135882085c66c1675f4461f27af116b63737a95a57",
        "workflowSha256": "sha256:a0c55933682bd94cb29630c83d6f7168ea19e9eba66a40d8132e8a91823c96c5",
    },
    {
        "sourceRevision": "b81f273c8de5e825b60468df302f0e2057f51e2e",
        "sourceTreeSha256": "sha256:3b49a62498d560da36d0cb67121a1622260fb5690a51123e74c3c88712720974",
        "manifestDigest": "sha256:e8ba5a0dfce7340575abcd7e06e10f8153343571776b29f6ab3f54467ec80391",
        "workflowSha256": "sha256:a0c55933682bd94cb29630c83d6f7168ea19e9eba66a40d8132e8a91823c96c5",
    },
)
PARTICIPANT_GATEWAY_RUNTIME_RELEASE_TRANSITION_FILES = {
    f"{PARTICIPANT_GATEWAY_ROOT}/runtime-pin.json",
    f"{PARTICIPANT_GATEWAY_ROOT}/deployment.json",
    f"{RENDER_ROOT}/integrity.json",
    f"{RENDER_ROOT}/network-boundary-migration.json",
}
PARTICIPANT_ACTIVATION_POLICY_TRANSITION_FILES = {
    "policy/repository-contract.json",
    PARTICIPANT_POLICY.POLICY_PATH,
}
CIVIC_PROJECTION_ROUTE_TRANSITION_FILES = {
    "scripts/staging_participant_gateway_policy.py",
    "scripts/test_staging_participant_gateway_policy.py",
    "scripts/verify-reviewed-render.py",
    "scripts/test_verify_reviewed_render.py",
    f"{RENDER_ROOT}/integrity.json",
    f"{RENDER_ROOT}/network-boundary-migration.json",
    f"{RENDER_ROOT}/web/deployment.json",
    f"{RENDER_ROOT}/web/networkpolicy.json",
    f"{PARTICIPANT_GATEWAY_ROOT}/workbench-ingress/networkpolicy.json",
}
CURRENT_TRACER_FEED_ROUTE_TRANSITION_FILES = {
    f"{RENDER_ROOT}/integrity.json",
    f"{RENDER_ROOT}/network-boundary-migration.json",
    f"{RENDER_ROOT}/web/deployment.json",
    f"{RENDER_ROOT}/web/networkpolicy.json",
}
CITIZEN_ADOPTION_DATA_PLANE_TRANSITION_FILES = {
    "policy/repository-contract.json",
    CITIZEN_ADOPTION_SQL_PATH,
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/bootstrap/zz-roebel-tracer.sh",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/kustomization.yaml",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/postgres-deployment.json",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/runtime-pin.json",
}
CITIZEN_ADOPTION_GATEWAY_TRANSITION_FILES = {
    "policy/repository-contract.json",
    PARTICIPANT_POLICY.POLICY_PATH,
    f"{PARTICIPANT_GATEWAY_ROOT}/runtime-pin.json",
    f"{PARTICIPANT_GATEWAY_ROOT}/deployment.json",
    f"{PARTICIPANT_GATEWAY_ROOT}/ingress.json",
    f"{RENDER_ROOT}/integrity.json",
    f"{RENDER_ROOT}/network-boundary-migration.json",
}
CITIZEN_ADOPTION_GATEWAY_PRESERVED_RENDER_FILES = (
    PARTICIPANT_GATEWAY_FILES
    - {
        f"{PARTICIPANT_GATEWAY_ROOT}/runtime-pin.json",
        f"{PARTICIPANT_GATEWAY_ROOT}/deployment.json",
        f"{PARTICIPANT_GATEWAY_ROOT}/ingress.json",
    }
)

# Phase A admits only the inert in-cluster tracer capability.  In particular,
# none of the currently reconciled Web/Public-Mecky release inputs may change
# in this transaction.  The inert data-plane render, policy, two live
# executables, and their focused tests are additions; every other member is an
# exact predecessor-to-successor update.
TRACER_PHASE_A_ADDED_FILES = {
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/bootstrap/71-roebel-tracer-baseline.sql",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/bootstrap/72-provision-roebel-vault.sh",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/bootstrap/73-staging-participant-gateway.sql",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/bootstrap/74-staging-participant-topic-tracer.sql",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/bootstrap/zz-roebel-tracer.sh",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/kustomization.yaml",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/postgres-deployment.json",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/postgres-networkpolicy.json",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/postgres-service.json",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/postgrest-deployment.json",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/postgrest-networkpolicy.json",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/postgrest-service.json",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/runtime-pin.json",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/serviceaccount.json",
    "scripts/materialize-tracer-data-plane-secrets.py",
    "scripts/run-tracer-data-plane-live.py",
    "scripts/test_materialize_tracer_data_plane_secrets.py",
    "scripts/test_run_tracer_data_plane_live.py",
    "scripts/test_tracer_data_plane_policy.py",
    "scripts/tracer_data_plane_policy.py",
}
TRACER_PHASE_A_TRANSITION_FILES = {
    ".github/workflows/reviewed-render-admission.yml",
    "policy/repository-contract.json",
    PARTICIPANT_POLICY.POLICY_PATH,
    f"{RENDER_ROOT}/integrity.json",
    f"{RENDER_ROOT}/network-boundary-migration.json",
    f"{PARTICIPANT_GATEWAY_ROOT}/deployment.json",
    f"{PARTICIPANT_GATEWAY_ROOT}/networkpolicy.json",
    f"{PARTICIPANT_GATEWAY_ROOT}/runtime-pin.json",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/bootstrap/71-roebel-tracer-baseline.sql",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/bootstrap/72-provision-roebel-vault.sh",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/bootstrap/73-staging-participant-gateway.sql",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/bootstrap/74-staging-participant-topic-tracer.sql",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/bootstrap/zz-roebel-tracer.sh",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/kustomization.yaml",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/postgres-deployment.json",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/postgres-networkpolicy.json",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/postgres-service.json",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/postgrest-deployment.json",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/postgrest-networkpolicy.json",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/postgrest-service.json",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/runtime-pin.json",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/serviceaccount.json",
    "scripts/activate-staging-participant-gateway.py",
    "scripts/materialize-tracer-data-plane-secrets.py",
    "scripts/run-staging-participant-gateway-live.py",
    "scripts/run-tracer-data-plane-live.py",
    "scripts/staging_participant_gateway_policy.py",
    "scripts/test_activate_staging_participant_gateway.py",
    "scripts/test_materialize_tracer_data_plane_secrets.py",
    "scripts/test_run_staging_participant_gateway_live.py",
    "scripts/test_run_tracer_data_plane_live.py",
    "scripts/test_staging_participant_gateway_policy.py",
    "scripts/test_tracer_data_plane_policy.py",
    "scripts/test_verify_reviewed_render.py",
    "scripts/tracer_data_plane_policy.py",
    "scripts/verify-reviewed-render.py",
}
TRACER_PHASE_A_PRESERVED_ACTIVE_FILES = {
    f"{RENDER_ROOT}/head.json",
    f"{RENDER_ROOT}/live-preconditions.json",
    f"{RENDER_ROOT}/public-mecky/deployment.json",
    f"{RENDER_ROOT}/public-mecky/kustomization.yaml",
    f"{RENDER_ROOT}/public-mecky/networkpolicy.json",
    f"{RENDER_ROOT}/public-mecky/service.json",
    f"{RENDER_ROOT}/web/deployment.json",
    f"{RENDER_ROOT}/web/ingress.json",
    f"{RENDER_ROOT}/web/kustomization.yaml",
    f"{RENDER_ROOT}/web/networkpolicy.json",
}
TRACER_PHASE_B_TRANSITION_FILES = {
    f"{RENDER_ROOT}/head.json",
    f"{RENDER_ROOT}/integrity.json",
    f"{RENDER_ROOT}/live-preconditions.json",
    f"{RENDER_ROOT}/network-boundary-migration.json",
    f"{RENDER_ROOT}/public-mecky/deployment.json",
    f"{RENDER_ROOT}/web/deployment.json",
    f"{RENDER_ROOT}/web/networkpolicy.json",
}
TRACER_PHASE_A_HEAD = {
    "schemaVersion": HEAD_SCHEMA,
    "promotionRevision": "68b578eebc03761fe64a70f1f5e70145d1002a09",
    "releaseSetDigest": "sha256:32096568f4abe5d858d3ca0b0ddc7c0c4e192da1518a60bb9e91cd3597c9d92e",
    "components": [
        {
            "component": "public-mecky",
            "sourceRevision": "9a478809a3d64b9efea279b6ee088a1346b045b4",
            "manifestDigest": "sha256:aa66c9b8bb75989e1c47b628845523fa345a944b0a1a82bd17863f96c1f128e4",
        },
        {
            "component": "roebel-web-staging",
            "sourceRevision": "68b578eebc03761fe64a70f1f5e70145d1002a09",
            "manifestDigest": "sha256:d33111a5c76f14f3a23506168062d82d8afa3a60b38881c12847f781919e656f",
        },
    ],
}
TRACER_PHASE_B_WEB_SOURCE_REVISION = "9a1bda15a67d36ef87ec674958a1b2b7ce3ea840"
TRACER_PHASE_B_WEB_MANIFEST_DIGEST = (
    "sha256:ff0f3b3ca70de5e4ab0bad02723498444bf98e01d4794eef312ccadeb9954bc2"
)
TRACER_PHASE_B_RELEASE_SET_DIGEST = (
    "sha256:810e56e6f2e9d70db2b9aa110e5bbad49ff96d7c83a3a3fb8eb8ce89e53ddce8"
)
TRACER_FEED_URL_ENV = {
    "name": "ROEBEL_FEED_SUPABASE_URL",
    "value": TRACER_DATA_PLANE.POSTGREST_CLUSTER_URL,
}
TRACER_FEED_ANON_ENV = {
    "name": "ROEBEL_FEED_SUPABASE_ANON_KEY",
    "valueFrom": {
        "secretKeyRef": {
            "key": TRACER_DATA_PLANE.WEB_FEED_SECRET_KEYS[0],
            "name": TRACER_DATA_PLANE.WEB_FEED_SECRET,
            "optional": False,
        },
    },
}

# The browser-facing test identity contract set is deliberately separate from
# the participant gateway's real ADR-0023 eligibility verifier.  Only the
# three values below are application configuration.  Chain, authority, and
# runtime-code identities are reviewed invariants and must never be supplied
# by an untrusted runtime caller.
WEB_IDENTITY_CONTRACT_SET = {
    "schemaVersion": "roebel_web_staging_identity_contract_set_v1",
    "profile": "gnosis-staging-test-v1",
    "chainId": 100,
    "authority": "none",
    "contracts": {
        "attesterNft": {
            "address": "0x5983F6300bCE3D9C1336a858Bd73F259bB8330F3",
            "runtimeCodeKeccak256": (
                "0x3c12a034ea9c2749c786497b5d50dcfaa4eff84860819d788517145a2276ee51"
            ),
        },
        "citizenNft": {
            "address": "0x0Be374808A567c9088aC8208B90a4239432B3220",
            "runtimeCodeKeccak256": (
                "0x481949efe62483d881190ec16e7ac6ffd796b0e601ea952507fa6eee1986bafb"
            ),
        },
    },
}
WEB_IDENTITY_CONTRACT_SET_ENV = [
    {
        "name": "ROEBEL_PUBLIC_IDENTITY_CONTRACT_SET",
        "value": WEB_IDENTITY_CONTRACT_SET["profile"],
    },
    {
        "name": "ROEBEL_PUBLIC_ATTESTER_NFT_ADDRESS",
        "value": WEB_IDENTITY_CONTRACT_SET["contracts"]["attesterNft"]["address"],
    },
    {
        "name": "ROEBEL_PUBLIC_CITIZEN_NFT_ADDRESS",
        "value": WEB_IDENTITY_CONTRACT_SET["contracts"]["citizenNft"]["address"],
    },
]
WEB_IDENTITY_CONTRACT_SET_ENV_NAMES = {
    item["name"] for item in WEB_IDENTITY_CONTRACT_SET_ENV
}
WEB_IDENTITY_CONTRACT_SET_ANNOTATIONS = {
    "stadtstack.io/identity-contract-set": WEB_IDENTITY_CONTRACT_SET["profile"],
    "stadtstack.io/identity-contract-authority": WEB_IDENTITY_CONTRACT_SET["authority"],
    "stadtstack.io/identity-contract-set-sha256": (
        "sha256:af51165b7854caf2058ca7c645d74d8c8717d738ec879e806ecb860da1cae131"
    ),
    "stadtstack.io/identity-attester-runtime-code-keccak256": (
        WEB_IDENTITY_CONTRACT_SET["contracts"]["attesterNft"]["runtimeCodeKeccak256"]
    ),
    "stadtstack.io/identity-citizen-runtime-code-keccak256": (
        WEB_IDENTITY_CONTRACT_SET["contracts"]["citizenNft"]["runtimeCodeKeccak256"]
    ),
}
WEB_IDENTITY_CONTRACT_SET_TRANSITION_FILES = {
    f"{RENDER_ROOT}/head.json",
    f"{RENDER_ROOT}/integrity.json",
    f"{RENDER_ROOT}/live-preconditions.json",
    f"{RENDER_ROOT}/public-mecky/deployment.json",
    f"{RENDER_ROOT}/web/deployment.json",
}
SYNTHETIC_CITIZEN_ADOPTION_SQL_PATH = str(
    TRACER_DATA_PLANE.RENDER_ROOT
    / "bootstrap/76-staging-synthetic-citizen-adoption.sql"
)
IDENTITY_ROTATION_SQL_PATH = str(
    TRACER_DATA_PLANE.RENDER_ROOT / "bootstrap" / IDENTITY_ROTATION.MIGRATION_ARTIFACT[0]
)
IDENTITY_ROTATION_RECORD_PATH = f"{RENDER_ROOT}/test-identity-rotation-v2.json"
IDENTITY_ROTATION_FILES = {
    "policy/repository-contract.json",
    f"{RENDER_ROOT}/head.json", f"{RENDER_ROOT}/integrity.json",
    f"{RENDER_ROOT}/live-preconditions.json", f"{RENDER_ROOT}/network-boundary-migration.json",
    f"{RENDER_ROOT}/web/deployment.json", f"{RENDER_ROOT}/public-mecky/deployment.json",
    f"{PARTICIPANT_GATEWAY_ROOT}/runtime-pin.json",
    f"{PARTICIPANT_GATEWAY_ROOT}/deployment.json",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/runtime-pin.json",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/postgres-deployment.json",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/kustomization.yaml",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/bootstrap/zz-roebel-tracer.sh",
    IDENTITY_ROTATION_SQL_PATH, IDENTITY_ROTATION_RECORD_PATH,
}
SYNTHETIC_CITIZEN_PASS_TRANSITION_PATH = (
    f"{RENDER_ROOT}/synthetic-citizen-pass-transition.json"
)
SYNTHETIC_CITIZEN_PASS_POLICY_VERSION = (
    "roebel-test-citizen-nft-v2-staging-2026-09"
)
SYNTHETIC_CITIZEN_PASS_SOURCE_REVISION = (
    "1b004dc0a1b156baf639fcdd54ab5a1b5501a575"
)
SYNTHETIC_CITIZEN_PASS_GATEWAY_SOURCE_TREE_SHA256 = (
    "sha256:827fea9741a90f9d2eede3bea2074687cd464ad496de33dac441dce7c2f84f15"
)
SYNTHETIC_CITIZEN_PASS_GATEWAY_MANIFEST_DIGEST = (
    "sha256:c2920003a6e514d56c662731877e665d518b1a22bc921cd3d58c60c77651d7e2"
)
SYNTHETIC_CITIZEN_PASS_GATEWAY_WORKFLOW_SHA256 = (
    "sha256:6c4c09517f53e18a301630cecb341f9996ba74eaa1dc1126ef735eb1c6460ac3"
)
SYNTHETIC_CITIZEN_ADOPTION_MIGRATION_SHA256 = (
    "sha256:992e56a65af74b32e35d2211ac57714f32e2e72e4fb82ea59afeb7dbbcefb282"
)
SYNTHETIC_CITIZEN_ADOPTION_DATABASE_SCHEMA_SHA256 = (
    "sha256:bcaa0b098a99b145e5111c17e29e5e7d9e9eb0840ee27643b3c26db34118bd66"
)
SYNTHETIC_CITIZEN_PASS_ENV = [
    {
        "name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_SYNTHETIC_CITIZEN_ADOPTION",
        "value": "enabled",
    },
    {
        "name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_SYNTHETIC_CITIZEN_ADOPTION_POLICY_VERSION",
        "value": SYNTHETIC_CITIZEN_PASS_POLICY_VERSION,
    },
    {
        "name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_TEST_CITIZEN_NFT_ADDRESS",
        "value": "0x0be374808a567c9088ac8208b90a4239432b3220",
    },
    {
        "name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_TEST_CITIZEN_NFT_RUNTIME_CODE_KECCAK256",
        "value": "0x481949efe62483d881190ec16e7ac6ffd796b0e601ea952507fa6eee1986bafb",
    },
    {
        "name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_SYNTHETIC_CITIZEN_ADOPTION_MIGRATION_SHA256",
        "value": SYNTHETIC_CITIZEN_ADOPTION_MIGRATION_SHA256,
    },
    {
        "name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_SYNTHETIC_CITIZEN_ADOPTION_DATABASE_SCHEMA_SHA256",
        "value": SYNTHETIC_CITIZEN_ADOPTION_DATABASE_SCHEMA_SHA256,
    },
]
SYNTHETIC_CITIZEN_PASS_ENV_NAMES = {
    item["name"] for item in SYNTHETIC_CITIZEN_PASS_ENV
}
SYNTHETIC_CITIZEN_PASS_POST_ROUTES = (
    "/api/staging-participant/v1/synthetic-citizen-adoption/challenge",
    "/api/staging-participant/v1/synthetic-citizen-adoption/tracers",
)
SYNTHETIC_CITIZEN_PASS_DYNAMIC_GET_PREFIX = (
    "/api/staging-participant/v1/synthetic-citizen-adoption/by-suggestion/"
)
SYNTHETIC_CITIZEN_PASS_TRANSITION_FILES = {
    "policy/repository-contract.json",
    f"{RENDER_ROOT}/head.json",
    f"{RENDER_ROOT}/integrity.json",
    f"{RENDER_ROOT}/live-preconditions.json",
    f"{RENDER_ROOT}/network-boundary-migration.json",
    f"{RENDER_ROOT}/public-mecky/deployment.json",
    f"{RENDER_ROOT}/web/deployment.json",
    f"{PARTICIPANT_GATEWAY_ROOT}/runtime-pin.json",
    f"{PARTICIPANT_GATEWAY_ROOT}/deployment.json",
    f"{PARTICIPANT_GATEWAY_ROOT}/ingress.json",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/runtime-pin.json",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/postgres-deployment.json",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/kustomization.yaml",
    f"{TRACER_DATA_PLANE.RENDER_ROOT}/bootstrap/zz-roebel-tracer.sh",
    SYNTHETIC_CITIZEN_ADOPTION_SQL_PATH,
    SYNTHETIC_CITIZEN_PASS_TRANSITION_PATH,
}
PARTICIPANT_GATEWAY_CONFIG_SECRET = PARTICIPANT_POLICY.STATIC_ACTIVATION_POLICY["runtime"]["secretReferences"]["config"]["name"]
PARTICIPANT_GATEWAY_RUNTIME_SECRET = PARTICIPANT_POLICY.STATIC_ACTIVATION_POLICY["runtime"]["secretReferences"]["runtime"]["name"]
PARTICIPANT_GATEWAY_FLUX_NAMESPACE = PARTICIPANT_POLICY.FLUX_NAMESPACE
PARTICIPANT_GATEWAY_FLUX_SOURCE_NAME = PARTICIPANT_POLICY.FLUX_SOURCE_NAME
PARTICIPANT_GATEWAY_FLUX_KUSTOMIZATION = "roebel-staging-participant-gateway"
PARTICIPANT_GATEWAY_FLUX_SERVICE_ACCOUNT = "roebel-staging-participant-gateway-reconciler"
PARTICIPANT_GATEWAY_FLUX_ROLE = "roebel-staging-participant-gateway-reconciler"
PARTICIPANT_GATEWAY_FLUX_ROLE_BINDING = "roebel-staging-participant-gateway-reconciler"
PARTICIPANT_GATEWAY_WEB_FLUX_KUSTOMIZATION = "roebel-web-presentation"
PARTICIPANT_GATEWAY_WEB_FLUX_SERVICE_ACCOUNT = "roebel-web-reconciler"
PARTICIPANT_GATEWAY_DNS_TLS_EVIDENCE_SCHEMA = "roebel_staging_participant_gateway_dns_tls_evidence_v1"
PARTICIPANT_GATEWAY_ACTIVATION_RECEIPT_SCHEMA = "roebel_staging_participant_gateway_activation_receipt_v1"
PARTICIPANT_GATEWAY_ANONYMOUS_EMPTY_AUTH_CONFIG_SHA256 = (
    "sha256:e58c7564b64e92c6c8ebc3cb296e644b4f2409ace8882621e888924c0c598753"
)
# This deliberately inert, policy-owned template is the only permitted
# activation operation.  It is hashed into the approved evidence; a render PR
# cannot replace it with a different command or use its own receipt as proof.
PARTICIPANT_GATEWAY_VERIFICATION_TIME_OVERRIDE: datetime | None = None

def participant_gateway_activation_script_sha256() -> str:
    """Bind policy evidence to the committed guarded planner bytes."""
    return bytes_digest(Path(__file__).with_name("activate-staging-participant-gateway.py").read_bytes())


# Signed Nostr is a third, closed render shape layered on the already-admitted
# reviewed-public-knowledge render.  The files are deliberately not present in
# this policy/bootstrap change: a later activation must add all sixteen in one
# reviewed transaction, never stage one workload or relay independently.
SIGNED_NOSTR_ROOT = f"{RENDER_ROOT}/signed-nostr"
SIGNED_NOSTR_RUNTIME_PIN = f"{SIGNED_NOSTR_ROOT}/runtime-pin.json"
SIGNED_NOSTR_COMPONENTS = ("workbench", "citizen-relay", "agent-relay")
SIGNED_NOSTR_COMPONENT_FILES = {
    f"{SIGNED_NOSTR_ROOT}/{component}/{kind}"
    for component in SIGNED_NOSTR_COMPONENTS
    for kind in ("deployment.json", "service.json", "networkpolicy.json", "kustomization.yaml")
}
SIGNED_NOSTR_GNOSIS_PROXY_FILES = {
    f"{SIGNED_NOSTR_ROOT}/workbench/gnosis-proxy-deployment.json",
    f"{SIGNED_NOSTR_ROOT}/workbench/gnosis-proxy-service.json",
    f"{SIGNED_NOSTR_ROOT}/workbench/gnosis-proxy-networkpolicy.json",
}
SIGNED_NOSTR_FILES = (
    SIGNED_NOSTR_COMPONENT_FILES
    | SIGNED_NOSTR_GNOSIS_PROXY_FILES
    | {SIGNED_NOSTR_RUNTIME_PIN}
)
SIGNED_NOSTR_EXPECTED_FILES = FUTURE_EXPECTED_FILES | SIGNED_NOSTR_FILES
SIGNED_NOSTR_PARTICIPANT_GATEWAY_EXPECTED_FILES = SIGNED_NOSTR_EXPECTED_FILES | PARTICIPANT_GATEWAY_FILES
CITIZEN_ADOPTION_EXPECTED_FILES = EXPECTED_FILES | {CITIZEN_ADOPTION_SQL_PATH}
CITIZEN_ADOPTION_FUTURE_EXPECTED_FILES = (
    FUTURE_EXPECTED_FILES | {CITIZEN_ADOPTION_SQL_PATH}
)
CITIZEN_ADOPTION_PARTICIPANT_GATEWAY_EXPECTED_FILES = (
    PARTICIPANT_GATEWAY_EXPECTED_FILES | {CITIZEN_ADOPTION_SQL_PATH}
)
CITIZEN_ADOPTION_SIGNED_NOSTR_EXPECTED_FILES = (
    SIGNED_NOSTR_EXPECTED_FILES | {CITIZEN_ADOPTION_SQL_PATH}
)
CITIZEN_ADOPTION_SIGNED_NOSTR_PARTICIPANT_GATEWAY_EXPECTED_FILES = (
    SIGNED_NOSTR_PARTICIPANT_GATEWAY_EXPECTED_FILES | {CITIZEN_ADOPTION_SQL_PATH}
)
SYNTHETIC_CITIZEN_PASS_EXPECTED_FILES = (
    CITIZEN_ADOPTION_PARTICIPANT_GATEWAY_EXPECTED_FILES
    | {
        SYNTHETIC_CITIZEN_ADOPTION_SQL_PATH,
        SYNTHETIC_CITIZEN_PASS_TRANSITION_PATH,
    }
)
SYNTHETIC_CITIZEN_PASS_SIGNED_NOSTR_EXPECTED_FILES = (
    CITIZEN_ADOPTION_SIGNED_NOSTR_PARTICIPANT_GATEWAY_EXPECTED_FILES
    | {
        SYNTHETIC_CITIZEN_ADOPTION_SQL_PATH,
        SYNTHETIC_CITIZEN_PASS_TRANSITION_PATH,
    }
)
SIGNED_NOSTR_MUTABLE_EXISTING_FILES = {
    f"{RENDER_ROOT}/integrity.json",
    f"{RENDER_ROOT}/web/ingress.json",
    f"{RENDER_ROOT}/public-mecky/networkpolicy.json",
    f"{RENDER_ROOT}/network-boundary-migration.json",
}
SIGNED_NOSTR_NAMESPACE = "stadtstack-roebel-staging-lab"
SIGNED_NOSTR_WEB_NAMESPACE = "stadtstack-roebel-web-preview"
SIGNED_NOSTR_WORKFLOW = (
    "https://github.com/GiraeffleAeffle/Roebel-App/"
    ".github/workflows/roebel-e2e-runtime-publish.yml@refs/heads/main"
)
SIGNED_NOSTR_IMAGES = {
    "workbench": "ghcr.io/giraeffleaeffle/roebel-e2e-workbench",
    "citizen-relay": "ghcr.io/giraeffleaeffle/roebel-staging-relay",
    "agent-relay": "ghcr.io/giraeffleaeffle/roebel-staging-relay",
}
SIGNED_NOSTR_NAMES = {
    "workbench": "roebel-staging-workbench",
    "citizen-relay": "citizen-relay",
    "agent-relay": "agent-relay",
}
SIGNED_NOSTR_PORTS = {"workbench": 18083, "citizen-relay": 18081, "agent-relay": 18081}
SIGNED_NOSTR_GNOSIS_PROXY_NAME = "gnosis-private-rpc"
SIGNED_NOSTR_GNOSIS_PROXY_PORT = 8545
SIGNED_NOSTR_GNOSIS_UPSTREAM_HOST = "rpc.gnosischain.com"
SIGNED_NOSTR_GNOSIS_UPSTREAM_PORT = 443
SIGNED_NOSTR_GNOSIS_UPSTREAM_IPV4_CIDR = "34.111.230.52/32"
SIGNED_NOSTR_GNOSIS_ALLOWED_METHODS = (
    "eth_blockNumber",
    "eth_call",
    "eth_chainId",
    "eth_getCode",
)
SIGNED_NOSTR_FLUX_NAMESPACE = "flux-roebel-staging"
SIGNED_NOSTR_FLUX_SOURCE_NAME = "roebel-staging-operations"
SIGNED_NOSTR_PUBLISHER_COMPONENT_ORDER = ("roebel-e2e-workbench", "roebel-staging-relay")
SIGNED_NOSTR_ANONYMOUS_DIGEST_PULL_RECEIPT_SCHEMA = (
    "roebel_signed_nostr_anonymous_digest_pull_receipt_v1"
)
SIGNED_NOSTR_CLEAN_EMPTY_AUTH_CONFIG_SHA256 = (
    "sha256:ec21c035eccb78eb5ca20ec95628eb351633621e09a130ac8d7e663714d40c7a"
)
SIGNED_NOSTR_ACTIVATION_EVIDENCE_SCHEMA = "roebel_signed_nostr_activation_evidence_v1"
SIGNED_NOSTR_BOOTSTRAP_RECEIPT_SCHEMA = "roebel_signed_nostr_bootstrap_cas_receipt_v1"
SIGNED_NOSTR_LIVE_RECHECK_SCHEMA = "roebel_signed_nostr_activation_live_recheck_v1"
SIGNED_NOSTR_ROLLBACK_CONTRACT_SCHEMA = "roebel_signed_nostr_live_rollback_contract_v1"
SIGNED_NOSTR_DEACTIVATION_EVIDENCE_SCHEMA = "roebel_signed_nostr_deactivation_evidence_v1"
SIGNED_NOSTR_DNS_TLS_EVIDENCE_SCHEMA = "roebel_signed_nostr_dns_tls_evidence_v1"
SIGNED_NOSTR_ACTIVATION_COMPONENT_ORDER = SIGNED_NOSTR_PUBLISHER_COMPONENT_ORDER
SIGNED_NOSTR_FLUX_BINDING_ORDER = ("workbench", "citizen-relay", "agent-relay")
SIGNED_NOSTR_FLUX_PATHS = {
    "workbench": f"./{SIGNED_NOSTR_ROOT}/workbench",
    "citizen-relay": f"./{SIGNED_NOSTR_ROOT}/citizen-relay",
    "agent-relay": f"./{SIGNED_NOSTR_ROOT}/agent-relay",
}
SIGNED_NOSTR_FLUX_NAMESPACES = {
    "workbench": SIGNED_NOSTR_WEB_NAMESPACE,
    "citizen-relay": SIGNED_NOSTR_NAMESPACE,
    "agent-relay": SIGNED_NOSTR_NAMESPACE,
}
SIGNED_NOSTR_FLUX_KUSTOMIZATION_NAMES = {
    component: f"roebel-staging-signed-nostr-{component}"
    for component in SIGNED_NOSTR_FLUX_BINDING_ORDER
}
SIGNED_NOSTR_FLUX_SERVICE_ACCOUNT_NAMES = {
    component: f"roebel-signed-nostr-{component}-reconciler"
    for component in SIGNED_NOSTR_FLUX_BINDING_ORDER
}

# This policy constrains the prospective Gnosis address and Flux identities but
# deliberately contains no actual live receipt. A later, separately reviewed
# policy may set this constant to exactly one complete closed evidence record.
# It is intentionally None in this commit, which blocks every signed-Nostr
# render even if the candidate contains a well-formed record.
SIGNED_NOSTR_APPROVED_ACTIVATION_EVIDENCE: None | dict[str, Any] = None

# Deactivation is an independently reviewed live operation.  A future policy
# change must pin one completed teardown receipt here before a signed-Nostr
# render may be removed.  Keeping this closed prevents a Git-only rollback from
# silently orphaning active workloads or Flux identities.
SIGNED_NOSTR_APPROVED_DEACTIVATION_EVIDENCE: None | dict[str, Any] = None

# Tests may replace this protected-module value with one explicit UTC instant.
# Candidate data has no way to select the clock.  Production admission always
# uses the verifier host's current UTC time.
SIGNED_NOSTR_VERIFICATION_TIME_OVERRIDE: datetime | None = None

ALLOWED_PATCH_PATHS = {
    "/metadata/annotations/stadtstack.io~1source-revision",
    "/metadata/annotations/stadtstack.io~1release-set-sha256",
    "/spec/template/metadata/annotations/stadtstack.io~1source-revision",
    "/spec/template/spec/containers/0/image",
    "/spec/template/spec/containers/0/imagePullPolicy",
}


class VerificationError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(), object_pairs_hook=object_pairs)


def closed(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    require(set(value) == keys, f"{label} keys mismatch")
    return value


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def bytes_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def utc_timestamp(value: Any, label: str) -> datetime:
    require(isinstance(value, str) and RFC3339_UTC.fullmatch(value), f"{label} timestamp invalid")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise VerificationError(f"{label} timestamp invalid") from error


def duration_seconds(start: datetime, end: datetime) -> int:
    return int((end - start).total_seconds())


def signed_nostr_verification_time() -> datetime:
    value = SIGNED_NOSTR_VERIFICATION_TIME_OVERRIDE
    if value is None:
        return datetime.now(timezone.utc).replace(microsecond=0)
    require(
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() == timezone.utc.utcoffset(value),
        "signed-Nostr verification clock override must be UTC",
    )
    return value.replace(microsecond=0)


def participant_gateway_verification_time() -> datetime:
    value = PARTICIPANT_GATEWAY_VERIFICATION_TIME_OVERRIDE
    if value is None:
        return datetime.now(timezone.utc).replace(microsecond=0)
    require(
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() == timezone.utc.utcoffset(value),
        "participant gateway verification clock override must be UTC",
    )
    return value.replace(microsecond=0)


def iter_keys(value: Any):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from iter_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_keys(child)


def repository_files(root: Path) -> set[str]:
    files: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] == ".git":
            continue
        # The verifier is itself imported by the test suite.  Interpreter
        # bytecode is neither reviewed render input nor a repository artifact.
        if "__pycache__" in relative.parts or relative.suffix == ".pyc":
            continue
        require(not path.is_symlink(), f"symlink forbidden: {relative}")
        if path.is_file():
            require(path.is_file(), f"non-regular file forbidden: {relative}")
            files.add(str(relative))
    return files


def changed_repository_files(candidate_root: Path, base_root: Path) -> set[str]:
    """Return the exact added, removed, or byte-changed repository paths."""
    candidate_files = repository_files(candidate_root)
    base_files = repository_files(base_root)
    changed = candidate_files ^ base_files
    for relative in candidate_files & base_files:
        if (candidate_root / relative).read_bytes() != (base_root / relative).read_bytes():
            changed.add(relative)
    return changed


def verify_tracer_phase_a_file_boundary(candidate_root: Path, base_root: Path) -> None:
    """Admit the inert tracer capability without touching active release input."""
    for relative in sorted(TRACER_PHASE_A_PRESERVED_ACTIVE_FILES):
        require(
            (candidate_root / relative).read_bytes()
            == (base_root / relative).read_bytes(),
            f"Phase A changed active release file: {relative}",
        )
    changed = changed_repository_files(candidate_root, base_root)
    require(
        changed == TRACER_PHASE_A_TRANSITION_FILES,
        "Phase A changed file set drift "
        f"(missing={sorted(TRACER_PHASE_A_TRANSITION_FILES - changed)!r}, "
        f"unexpected={sorted(changed - TRACER_PHASE_A_TRANSITION_FILES)!r})",
    )
    require(
        TRACER_PHASE_A_ADDED_FILES
        == repository_files(candidate_root) - repository_files(base_root),
        "Phase A added file set drift",
    )


def verify_repository_file_set(root: Path) -> str:
    """Admit exactly one whole render shape and report which shape it is."""
    actual = repository_files(root)
    if actual == EXPECTED_FILES:
        return "current"
    if actual == FUTURE_EXPECTED_FILES:
        return "reviewed-public-knowledge"
    if actual == PARTICIPANT_GATEWAY_EXPECTED_FILES:
        return "reviewed-public-knowledge-participant-gateway"
    if actual == SIGNED_NOSTR_EXPECTED_FILES:
        return "signed-nostr"
    if actual == SIGNED_NOSTR_PARTICIPANT_GATEWAY_EXPECTED_FILES:
        return "signed-nostr-participant-gateway"
    if actual == CITIZEN_ADOPTION_EXPECTED_FILES:
        return "current"
    if actual == CITIZEN_ADOPTION_FUTURE_EXPECTED_FILES:
        return "reviewed-public-knowledge"
    if actual == CITIZEN_ADOPTION_PARTICIPANT_GATEWAY_EXPECTED_FILES:
        return "reviewed-public-knowledge-participant-gateway"
    if actual == CITIZEN_ADOPTION_SIGNED_NOSTR_EXPECTED_FILES:
        return "signed-nostr"
    if actual == CITIZEN_ADOPTION_SIGNED_NOSTR_PARTICIPANT_GATEWAY_EXPECTED_FILES:
        return "signed-nostr-participant-gateway"
    if actual == SYNTHETIC_CITIZEN_PASS_EXPECTED_FILES:
        return "reviewed-public-knowledge-participant-gateway"
    if actual == SYNTHETIC_CITIZEN_PASS_SIGNED_NOSTR_EXPECTED_FILES:
        return "signed-nostr-participant-gateway"
    if actual == SYNTHETIC_CITIZEN_PASS_EXPECTED_FILES | {
        IDENTITY_ROTATION_SQL_PATH, IDENTITY_ROTATION_RECORD_PATH
    }:
        return "reviewed-public-knowledge-participant-gateway"
    if actual == SYNTHETIC_CITIZEN_PASS_SIGNED_NOSTR_EXPECTED_FILES | {
        IDENTITY_ROTATION_SQL_PATH, IDENTITY_ROTATION_RECORD_PATH
    }:
        return "signed-nostr-participant-gateway"
    missing_current = sorted(EXPECTED_FILES - actual)
    unexpected = sorted(actual - EXPECTED_FILES)
    raise VerificationError(
        "repository file set drift "
        f"(missing={missing_current!r}, unexpected={unexpected!r})"
    )


def verify_case_staging_topology_with_protected_policy(root: Path) -> None:
    """Validate candidate topology data with the verifier beside this script.

    On pull_request_target this module is executed from the protected base
    checkout.  Resolving the sibling by ``__file__`` is therefore deliberate:
    candidate topology is data only and cannot select or execute its own
    policy module.
    """
    verifier_path = Path(__file__).with_name("verify-case-staging-topology.py")
    spec = importlib.util.spec_from_file_location("protected_case_topology_verifier", verifier_path)
    require(spec is not None and spec.loader is not None, "protected Case topology verifier unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        module.verify(root)
    except module.VerificationError as error:
        raise VerificationError(f"Case staging topology verification failed: {error}") from error


def verify_case_runtime_contract_with_protected_policy(root: Path) -> None:
    """Validate the candidate recovery inventory with protected-base policy."""
    verifier_path = Path(__file__).with_name("verify-stadtstack-case-runtime-contract.py")
    spec = importlib.util.spec_from_file_location("protected_case_runtime_contract_verifier", verifier_path)
    require(spec is not None and spec.loader is not None, "protected Case runtime contract verifier unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    errors = module.verify_contract(root)
    require(errors == [], f"Case runtime contract verification failed: {errors!r}")


def verify_case_recovery_composition_contract_with_protected_policy(root: Path) -> None:
    """Validate the inert recovery composition with protected-base policy."""
    verifier_path = Path(__file__).with_name("verify-stadtstack-case-recovery-composition-contract.py")
    spec = importlib.util.spec_from_file_location("protected_case_recovery_composition_verifier", verifier_path)
    require(spec is not None and spec.loader is not None, "protected Case recovery composition verifier unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    errors = module.verify_contract(root)
    require(errors == [], f"Case recovery composition contract verification failed: {errors!r}")


def verify_case_image_resource_inventory_contract_with_protected_policy(root: Path) -> None:
    """Validate the inert image/resource inventory with protected-base policy."""
    verifier_path = Path(__file__).with_name("verify-stadtstack-case-image-resource-inventory-contract.py")
    spec = importlib.util.spec_from_file_location("protected_case_image_resource_inventory_verifier", verifier_path)
    require(spec is not None and spec.loader is not None, "protected Case image/resource inventory verifier unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    errors = module.verify_contract(root)
    require(errors == [], f"Case image/resource inventory contract verification failed: {errors!r}")


def expected_eligibility_issuer_materialization_policy() -> dict[str, Any]:
    """Return the sole value-free issuer materialization boundary."""
    successor = PARTICIPANT_POLICY.APPROVED_NEXT_ACTIVATION_POLICY
    issuer = successor["runtime"]["citizenAdoption"]["eligibilityIssuer"]
    cluster = successor["clusterIdentity"]
    secret = issuer["secret"]
    return {
        "schemaVersion": (
            "roebel_staging_participant_eligibility_issuer_"
            "materialization_policy_v2"
        ),
        "authority": {
            "environment": "staging",
            "civicAuthority": "none",
            "citizenVerification": False,
            "municipalPublication": False,
            "proposalMutation": False,
            "voteMutation": False,
            "treasuryMutation": False,
        },
        "algorithm": "Ed25519",
        "keyId": issuer["keyId"],
        "clusterIdentity": copy.deepcopy(cluster),
        "httpBoundary": {"timeoutsSeconds": {"routeRequest": 15}},
        "target": {
            "apiVersion": "v1",
            "kind": "Secret",
            "namespace": secret["namespace"],
            "name": secret["name"],
            "type": "Opaque",
            "key": secret["key"],
            "immutable": True,
        },
        "input": {
            "transport": "owned-private-inherited-descriptor-only",
            "encoding": "exact-lowercase-64-hex-no-newline",
            "decodedBytes": 32,
            "sha256Commitment": issuer["privateKeySha256Commitment"],
        },
        "publicKey": {
            "derivation": "RFC8032-Ed25519-private-seed-to-public-key",
            "encoding": "lowercase-64-hex",
            "expected": issuer["publicKey"],
        },
        "materialization": {
            "operation": "create-only",
            "initialState": "exact-target-absent",
            "existingObject": "reject-no-adopt-no-recreate",
            "operationNonceAnnotation": (
                "stadtstack.io/eligibility-issuer-materialization-nonce"
            ),
            "dryRun": "server-before-create",
            "readSecretValues": False,
            "metadataOnlyRead": {
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
            "metadataCommitments": {
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
            "delete": False,
            "patch": False,
            "replace": False,
            "durableJournal": {
                "schemaVersion": (
                    "roebel_staging_participant_eligibility_issuer_"
                    "materialization_journal_v1"
                ),
                "reservation": "durable-before-create",
                "recovery": (
                    "same-protected-journal-and-operation-nonce-only"
                ),
                "postSendUncertain": (
                    "exact-live-projection-same-operation-nonce-only"
                ),
                "genericAdoption": False,
            },
        },
        "receipt": {
            "schemaVersion": (
                "roebel_staging_participant_eligibility_issuer_"
                "materialization_receipt_v1"
            ),
            "status": "materialized",
            "requiredFields": [
                "schemaVersion",
                "status",
                "protectedRevision",
                "protectedFileSha256",
                "policy",
                "clusterBinding",
                "target",
                "uid",
                "resourceVersion",
                "operationNonce",
                "keyId",
                "publicKey",
                "privateKeyCommitmentSha256",
                "keySet",
                "labels",
                "annotations",
                "createOutcome",
                "valuesRead",
                "receiptContainsValues",
                "authority",
            ],
            "verifyMode": "owned-private-inherited-descriptor",
            "containsPrivateKey": False,
            "containsSecretValue": False,
        },
    }


def verify_eligibility_issuer_materialization_policy(root: Path) -> dict[str, Any]:
    value = load_json(root / ELIGIBILITY_ISSUER_POLICY_PATH)
    require(
        value == expected_eligibility_issuer_materialization_policy(),
        "eligibility issuer materialization policy drift",
    )
    return copy.deepcopy(value)


def eligibility_issuer_contract_projection(
    issuer_policy: dict[str, Any],
) -> dict[str, Any]:
    """Project the exact value-free issuer boundary into the repository contract."""
    return {
        "policy": ELIGIBILITY_ISSUER_POLICY_PATH,
        "runner": ELIGIBILITY_ISSUER_MATERIALIZER_PATH,
        "schemaVersion": issuer_policy["schemaVersion"],
        "keyId": issuer_policy["keyId"],
        "publicKey": issuer_policy["publicKey"]["expected"],
        "privateKeySha256Commitment": issuer_policy["input"]["sha256Commitment"],
        "target": copy.deepcopy(issuer_policy["target"]),
        "materialization": copy.deepcopy(issuer_policy["materialization"]),
        "receipt": copy.deepcopy(issuer_policy["receipt"]),
        "authority": copy.deepcopy(issuer_policy["authority"]),
    }


def participant_gateway_http_contract(
    participant_policy: dict[str, Any],
) -> dict[str, Any]:
    successor = participant_policy == PARTICIPANT_POLICY.APPROVED_NEXT_ACTIVATION_POLICY
    routes = list(
        PARTICIPANT_POLICY.ROUTES
        if successor
        else PARTICIPANT_POLICY.LEGACY_ROUTES
    )
    post_routes = list(
        PARTICIPANT_POLICY.POST_ROUTES
        if successor
        else PARTICIPANT_POLICY.LEGACY_POST_ROUTES
    )
    result = {
        "exactGatewayPaths": routes,
        "methodPathMatrix": {
            "GET": [routes[0]],
            "OPTIONS": list(routes),
            "POST": post_routes,
        },
        "schemaVersion": (
            "roebel_staging_participant_gateway_runtime_pin_v4"
            if successor
            else "roebel_staging_participant_gateway_runtime_pin_v3"
        ),
    }
    if successor:
        result["dynamicGetPrefixes"] = list(PARTICIPANT_POLICY.DYNAMIC_GET_PREFIXES)
        result["routeProbeSamples"] = list(PARTICIPANT_POLICY.PUBLIC_GET_ROUTES)
        result["methodPathMatrix"]["GET"].extend(
            PARTICIPANT_POLICY.PUBLIC_GET_ROUTES
        )
    return result


def synthetic_citizen_pass_boundary() -> dict[str, Any]:
    """Return the closed, staging-only capability that cannot enter ADR-0023."""
    return {
        "schemaVersion": "roebel_staging_synthetic_citizen_pass_boundary_v1",
        "environment": "staging",
        "testOnly": True,
        "authorityBinding": "none",
        "policyVersion": SYNTHETIC_CITIZEN_PASS_POLICY_VERSION,
        "testCitizenNft": {
            "chainId": 100,
            "address": "0x0be374808a567c9088ac8208b90a4239432b3220",
            "runtimeCodeKeccak256": (
                "0x481949efe62483d881190ec16e7ac6ffd796b0e601ea952507fa6eee1986bafb"
            ),
        },
        "migrationSha256": SYNTHETIC_CITIZEN_ADOPTION_MIGRATION_SHA256,
        "databaseSchemaSha256": (
            SYNTHETIC_CITIZEN_ADOPTION_DATABASE_SCHEMA_SHA256
        ),
        "realCitizenEligibility": False,
        "civicCaseCreated": False,
        "administrativeEndorsement": False,
        "bindingVote": False,
        "treasuryEffect": False,
        "paymentEffect": False,
        "rollback": "restore-exact-predecessor-bytes-and-remove-76-artifact",
    }


def verify_participant_gateway_static_policy(root: Path, render_file_set: str) -> dict[str, Any]:
    """Treat candidate JSON as data under the protected sibling module."""
    try:
        value = PARTICIPANT_POLICY.validate_activation_policy(
            load_json(root / PARTICIPANT_POLICY.POLICY_PATH),
        )
        if render_file_set in {
            "reviewed-public-knowledge-participant-gateway",
            "signed-nostr-participant-gateway",
        }:
            PARTICIPANT_POLICY.assert_activation_ready(value)
        return value
    except PARTICIPANT_POLICY.PolicyError as error:
        raise VerificationError(str(error)) from error


def verify_workbench_baseline(root: Path) -> dict[str, Any]:
    """Validate the exact, inert baseline render owned by the handover runner."""
    try:
        return WORKBENCH_BASELINE.validate_render(root)
    except WORKBENCH_BASELINE.HandoverError as error:
        raise VerificationError(f"workbench baseline render verification failed: {error}") from error


def verify_tracer_data_plane(root: Path) -> dict[str, Any]:
    """Validate the inert data-plane render with the protected sibling policy."""
    try:
        return TRACER_DATA_PLANE.verify_render(root)
    except TRACER_DATA_PLANE.PolicyError as error:
        raise VerificationError(f"tracer data-plane render verification failed: {error}") from error


def verify_contract(root: Path, participant_policy: dict[str, Any]) -> dict[str, Any]:
    issuer_policy = verify_eligibility_issuer_materialization_policy(root)
    synthetic_citizen_pass = (root / SYNTHETIC_CITIZEN_ADOPTION_SQL_PATH).is_file()
    tracer_artifacts = (
        TRACER_DATA_PLANE.SYNTHETIC_PRODUCT_ARTIFACTS
        if synthetic_citizen_pass
        else (
            TRACER_DATA_PLANE.PRODUCT_ARTIFACTS
            if (root / CITIZEN_ADOPTION_SQL_PATH).is_file()
            else TRACER_DATA_PLANE.LEGACY_PRODUCT_ARTIFACTS
        )
    )
    rotated_identity = (root / IDENTITY_ROTATION_SQL_PATH).is_file()
    if rotated_identity:
        tracer_artifacts = TRACER_DATA_PLANE.ROTATED_SYNTHETIC_PRODUCT_ARTIFACTS
    synthetic_boundary = synthetic_citizen_pass_boundary()
    if rotated_identity:
        synthetic_boundary = IDENTITY_ROTATION.boundary(synthetic_boundary)
    gateway_http = participant_gateway_http_contract(participant_policy)
    if synthetic_citizen_pass:
        gateway_http["schemaVersion"] = (
            "roebel_staging_participant_gateway_runtime_pin_v5"
        )
        gateway_http["exactGatewayPaths"].extend(
            SYNTHETIC_CITIZEN_PASS_POST_ROUTES
        )
        gateway_http["methodPathMatrix"]["OPTIONS"].extend(
            SYNTHETIC_CITIZEN_PASS_POST_ROUTES
        )
        gateway_http["methodPathMatrix"]["POST"].extend(
            SYNTHETIC_CITIZEN_PASS_POST_ROUTES
        )
        gateway_http.setdefault("dynamicGetPrefixes", []).append(
            SYNTHETIC_CITIZEN_PASS_DYNAMIC_GET_PREFIX
        )
    contract = load_json(root / "policy/repository-contract.json")
    require(contract == {
        "schemaVersion": "roebel_staging_operations_repository_v1",
        "repository": "GiraeffleAeffle/roebel-staging-operations",
        "visibility": "public",
        "defaultBranch": "main",
        "environment": "roebel-staging",
        "reviewedRenderRoot": RENDER_ROOT,
        "componentOrder": list(COMPONENT_ORDER),
        "components": [
            {"component": component, **COMPONENTS[component]}
            for component in COMPONENT_ORDER
        ],
        "schemas": {"head": HEAD_SCHEMA, "reviewedRender": RENDER_SCHEMA},
        "publicMetadataBoundary": {
            "allowedKinds": ["ConfigMap", "Deployment", "Ingress", "Service", "NetworkPolicy", "ServiceAccount"],
            "secretObjectsAllowed": False,
            "secretValuesAllowed": False,
            "secretReferencesAllowed": True,
            "personalDataAllowed": False,
            "civicRecordsAllowed": False,
            "runtimeStatusAllowed": False,
        },
        "promotionBoundary": {
            "pullRequestMayChangeOnlyReviewedRender": True,
            "completePreviousHeadRequired": True,
            "immutableDigestRequired": True,
            "imagePullPolicy": "IfNotPresent",
            "noOpPromotionAllowed": False,
        },
        "signedNostrBoundary": {
            "activationEvidence": "pending-separate-review",
            "components": ["workbench", "citizen-relay", "agent-relay"],
            "normalReleaseSetPromotionMayChange": False,
            "publisherPinCanonicalChecksumRequired": True,
            "publisherPinSchema": "roebel_e2e_runtime_pin_v1",
            "renderRoot": SIGNED_NOSTR_ROOT,
            "runtimePin": SIGNED_NOSTR_RUNTIME_PIN,
            "schemaVersion": "roebel_signed_nostr_activation_render_pin_v1",
        },
        "ephemeralTracerDataPlaneBoundary": TRACER_DATA_PLANE.contract_boundary(
            tracer_artifacts,
        ),
        "stagingParticipantGatewayBoundary": {
            "activationPolicy": PARTICIPANT_POLICY.POLICY_PATH,
            "activationReady": participant_policy["activationReady"],
            "activationRequiresDormantFluxBootstrapReceipt": True,
            "component": "staging-participant-gateway",
            "dormantFluxBootstrap": {
                "exactObjectCount": len(PARTICIPANT_POLICY.DORMANT_BOOTSTRAP_OBJECT_ORDER),
                "initialState": "all-eight-exact-names-absent",
                "runner": "scripts/bootstrap-staging-participant-flux.py",
                "receiptSchemaVersion": PARTICIPANT_POLICY.DORMANT_BOOTSTRAP_RECEIPT_SCHEMA,
                "successState": "all-eight-exact-uids-present-both-kustomizations-suspended",
                "workflow": ".github/workflows/staging-participant-flux-bootstrap.yml",
            },
            "archivedDormantReceiptHandover": {
                "runner": "scripts/handover-staging-participant-dormant-receipt.py",
                "implementation": "scripts/staging_participant_dormant_receipt_handover.py",
                "archiveRevision": "08c4171573bb138845a9160e747f6ac56a3c754e",
                "archiveReceiptRawSha256": "sha256:32e244e5ba711aa8406a76d8dbf4fdd53289e52e2ced6ff27b77a7ae7577741f",
                "archiveReceiptCanonicalSha256": "sha256:ab90b49078f423c304b643b9354230611127d0ed6bda0d1022f3abc92772b081",
                "receiptSchemaVersion": "roebel_staging_participant_dormant_receipt_handover_v2",
                "currentCompatibility": "ordered-eight-object-plan-only",
                "currentPreservationRenders": {
                    "webIngress": {
                        "path": "reviewed-render/roebel-staging/web/ingress.json",
                        "fluxInventoryLabels": {
                            "kustomize.toolkit.fluxcd.io/name": "roebel-staging-web-workload",
                            "kustomize.toolkit.fluxcd.io/namespace": "flux-roebel-staging",
                        },
                    },
                    "existingWorkbenchNetworkPolicy": {
                        "path": "reviewed-render/roebel-staging/workbench-baseline/networkpolicy.json",
                        "fluxInventoryLabels": {
                            "kustomize.toolkit.fluxcd.io/name": "roebel-staging-workbench-baseline",
                            "kustomize.toolkit.fluxcd.io/namespace": "flux-roebel-staging",
                        },
                    },
                },
                "getOnlyEffects": {
                    "verbs": ["GET"],
                    "kubernetesGetCount": 12,
                    "resourceGetCount": 11,
                    "clusterMutationCount": 0,
                    "secretReads": False,
                    "civicAuthorityEffects": False,
                },
                "activationRequires": [
                    "dormant-bootstrap-handover-receipt",
                    "current-secret-materialization-receipt",
                ],
                "preservationBoundary": "current-policy-boundaries-only",
                "automaticRetry": False,
            },
            "eligibilityIssuerMaterialization": (
                eligibility_issuer_contract_projection(issuer_policy)
            ),
            "exactGatewayPaths": gateway_http["exactGatewayPaths"],
            **(
                {"dynamicGetPrefixes": gateway_http["dynamicGetPrefixes"]}
                if "dynamicGetPrefixes" in gateway_http
                else {}
            ),
            "methodPathMatrix": gateway_http["methodPathMatrix"],
            **(
                {"routeProbeSamples": gateway_http["routeProbeSamples"]}
                if "routeProbeSamples" in gateway_http
                else {}
            ),
            "normalReleaseSetPromotionMayChange": False,
            "secretMaterialization": {
                "runner": PARTICIPANT_POLICY.SECRET_MATERIALIZER_RUNNER,
                "inputTransport": "owned-private-inherited-descriptors-only",
                "exactSecretNames": [
                    PARTICIPANT_GATEWAY_CONFIG_SECRET,
                    PARTICIPANT_GATEWAY_RUNTIME_SECRET,
                ],
                "initialState": "both-exact-secret-names-absent",
                "createOrder": ["config", "runtime"],
                "adoption": "forbidden",
                "receiptSchemaVersion": PARTICIPANT_POLICY.SECRET_MATERIALIZATION_RECEIPT_SCHEMA,
                "receiptContainsValues": False,
                "teardown": {
                    "sourceReceiptRequired": True,
                    "afterParticipantDeactivationOnly": True,
                    "deleteOrder": ["runtime", "config"],
                    "uidResourceVersionPreconditions": True,
                    "receiptSchemaVersion": PARTICIPANT_POLICY.SECRET_TEARDOWN_RECEIPT_SCHEMA,
                },
            },
            "renderRoot": PARTICIPANT_GATEWAY_ROOT,
            "runtimePin": f"{PARTICIPANT_GATEWAY_ROOT}/runtime-pin.json",
            "schemaVersion": gateway_http["schemaVersion"],
            **(
                {"syntheticCitizenAdoption": synthetic_boundary}
                if synthetic_citizen_pass
                else {}
            ),
            "singleReplicaRequired": True,
            "trustedLiveFacts": "protected-local-runner-out-of-band-only",
            "workbenchIngressRenderRoot": PARTICIPANT_POLICY.WORKBENCH_INGRESS_ROOT,
        },
        "workbenchBaselineBoundary": {
            "adoption": "one-time-existing-uid-and-exact-digest-only",
            "beforeCanonicalSha256": WORKBENCH_BASELINE.BASELINE_BEFORE_DIGEST,
            "flux": {
                "activation": "cas-unsuspend-wait-ready-at-current-source-revision",
                "initialState": "suspended",
                "kustomization": WORKBENCH_BASELINE.FLUX_NAME,
                "namespace": WORKBENCH_BASELINE.FLUX_NAMESPACE,
                "resourceNames": [WORKBENCH_BASELINE.WORKBENCH_NAME],
                "role": WORKBENCH_BASELINE.RECONCILER_NAME,
                "roleBinding": WORKBENCH_BASELINE.RECONCILER_NAME,
                "serviceAccount": WORKBENCH_BASELINE.RECONCILER_NAME,
                "verbs": ["get", "patch", "update"],
                "apiGroup": "networking.k8s.io",
                "resource": "networkpolicies",
                "prune": False,
                "source": {
                    "apiGroup": "source.toolkit.fluxcd.io",
                    "kind": "GitRepository",
                    "name": WORKBENCH_BASELINE.SOURCE_NAME,
                    "namespace": WORKBENCH_BASELINE.FLUX_NAMESPACE,
                    "revisionBinding": "main@sha1:<protectedRevision>",
                },
                "successState": "kustomization-ready-current-revision-and-networkpolicy-reconciled",
                "inventoryMetadata": {
                    "labels": copy.deepcopy(WORKBENCH_BASELINE.FLUX_INVENTORY_LABELS),
                    "annotations": {
                        WORKBENCH_BASELINE.SSA_ANNOTATION: WORKBENCH_BASELINE.SSA_MODE,
                    },
                },
            },
            "handoverRunner": "scripts/handover-staging-workbench-baseline.py",
            "implementation": "scripts/workbench_baseline_handover.py",
            "failedTransactionRecovery": {
                "implementation": "scripts/workbench_baseline_recovery.py",
                "modeFlag": "--workbench-baseline-recovery",
                "originRevision": "3be9405c6bfd6b4caf0423b137f969aab3bef323",
                "sharedSourceUid": "0de8a05d-550f-429c-93c5-9b8c76b0bf9b",
                "evidence": {
                    "originJournalFileSha256": "sha256:70015e2728bf8e30491862687c3b507aa3d4d03e4f91b72cafb84ae3dcba30c0",
                    "originJournalEmbeddedSha256": "sha256:cd15195c7d1ce3209f65ab6b579d6c5926db4e730272e64da8894a9fc19d7a18",
                    "attemptReceiptSha256": "sha256:55a7cfac98cdb40aa49a46a00abbd47d8305cff4d001f8984c57a0c964d51ee9",
                    "inspectionSha256": "sha256:d7a94d4e27c18317ede34f6700a7c4a27081133bd7f881e46d5bd30466430755",
                },
                "mutationSurface": ["GET", "DELETE-with-uid-and-resourceVersion-preconditions"],
                "forbidden": ["create", "patch", "apply", "list", "secrets", "civic-authority-effects"],
                "deleteOrder": ["Kustomization", "RoleBinding", "Role", "ServiceAccount"],
                "automaticRetry": False,
                "resume": "same-journal-same-protected-revision-same-origin-evidence-and-exact-uids-only",
                "terminalReceiptFinalization": {
                    "outerModeFlag": "--workbench-baseline-recovery-finalize",
                    "innerModeFlag": "--terminal-finalize",
                    "terminalRecoveryRevision": "18b1780be9b2e1d8bad05e27f81f11d9b104ab06",
                    "terminalJournalFileSha256": "sha256:d6e16407761ecbf2d6ce29aab48f10f4420770a7b97b393b53b9753152f5f604",
                    "terminalJournalCanonicalSha256": "sha256:cdeab725635754bb4a220bc915e4ff69a46246b6336ca954681d7ff6e7497613",
                    "requiredSoleParentRevision": "9f7a7a1e96065e849a8b7a9879de1fadb9ec6e2f",
                    "preTransportJournalBinding": "exact-existing-private-file-only",
                    "mutationSurface": ["GET"],
                    "clusterMutationCount": 0,
                    "newDeletes": 0,
                    "historicalDeleteOnlyRecovery": True,
                    "deleteOnlyMutation": False,
                    "journalMutation": False,
                    "invalidJournal": "fail-before-transport",
                    "receiptProvenance": "terminal-recovery-and-finalization-revisions",
                },
            },
            "liveTransport": {
                "modeFlag": "--workbench-baseline-handover",
                "runner": "scripts/run-staging-participant-gateway-live.py",
                "transportAttemptReceipt": "workbench-baseline-transport-attempt.json",
                "explicitReceiptAndJournalRequired": True,
                "automaticRetry": False,
                "pinnedKubectl": "immutable-owner-only-snapshot-with-inherited-descriptor-proof",
                "participantRunners": "forbidden",
            },
            "journal": {
                "schemaVersion": WORKBENCH_BASELINE.JOURNAL_SCHEMA,
                "defaultPath": "<receipt>" + WORKBENCH_BASELINE.JOURNAL_DEFAULT_SUFFIX,
                "durability": WORKBENCH_BASELINE.JOURNAL_DURABILITY,
                "recovery": WORKBENCH_BASELINE.JOURNAL_RECOVERY,
                "finalization": WORKBENCH_BASELINE.JOURNAL_FINALIZATION,
            },
            "networkPolicy": {
                "name": WORKBENCH_BASELINE.WORKBENCH_NAME,
                "namespace": WORKBENCH_BASELINE.WORKBENCH_NAMESPACE,
                "uid": WORKBENCH_BASELINE.BASELINE_UID,
            },
            "nextOwner": WORKBENCH_BASELINE.NEW_OWNER,
            "previousOwner": WORKBENCH_BASELINE.OLD_OWNER,
            "receiptSchemaVersion": WORKBENCH_BASELINE.RECEIPT_SCHEMA,
            "renderRoot": WORKBENCH_BASELINE.BASELINE_ROOT,
            "rollback": "suspend-before-restore-owner-remove-transaction-ssa-and-flux-inventory-delete-only-owned-flux-identities",
            "schemaVersion": WORKBENCH_BASELINE.SCHEMA_VERSION,
            "ssaAnnotation": {
                "name": WORKBENCH_BASELINE.SSA_ANNOTATION,
                "value": WORKBENCH_BASELINE.SSA_MODE,
            },
            "mutations": {
                "networkPolicy": "owner-label-and-ssa-annotation-only-before-flux;inventory-labels-approved-after-reconcile",
                "deployment": "forbidden",
                "service": "forbidden",
                "secrets": "forbidden",
                "civicAuthorityEffects": False,
            },
        },
        "workbenchImagePromotionBoundary": {
            "modeFlag": "--workbench-image-promotion",
            "runner": "scripts/promote-staging-workbench-image.py",
            "transportRunner": "scripts/run-staging-participant-gateway-live.py",
            "transactionSchemaVersion": "roebel_staging_workbench_image_promotion_v2",
            "journalSchemaVersion": "roebel_staging_workbench_image_promotion_journal_v2",
            "receiptSchemaVersion": "roebel_staging_workbench_image_promotion_receipt_v2",
            "transportReceiptSchemaVersion": "roebel_staging_workbench_image_promotion_live_transport_receipt_v2",
            "protectedClosure": [
                "scripts/run-staging-participant-gateway-live.py",
                "scripts/promote-staging-workbench-image.py",
                "scripts/verify-reviewed-render.py",
                "policy/repository-contract.json",
            ],
            "artifactPin": {
                "schemaVersion": "roebel_e2e_runtime_pin_v1",
                "sourceRevision": "6b78c635f5b8f9603e16d3fe386eb8574df27740",
                "receiptSha256": "sha256:0398095ccdc3a054df42f94abdc75d348201695947ce0268ba81318d05947683",
                "targetImage": "ghcr.io/giraeffleaeffle/roebel-e2e-workbench@sha256:3e6e572b2a661a34fc981a65f3875dd3ba437f8c155be1f4ab0c30f4079ed529",
            },
            "environmentTransition": {
                "mode": "public-signed-only",
                "preservedByteForByte": True,
                "removedNames": [],
                "added": [],
            },
            "imageTransition": {
                "predecessorImage": "ghcr.io/giraeffleaeffle/roebel-e2e-workbench@sha256:03cc0dd35b81004ecc2a6045a16ea09184d2faa10a20bf7c83a825e7440170e2",
                "targetImage": "ghcr.io/giraeffleaeffle/roebel-e2e-workbench@sha256:3e6e572b2a661a34fc981a65f3875dd3ba437f8c155be1f4ab0c30f4079ed529",
                "forward": "image-only-exact-cas",
                "rollback": "target-to-predecessor-image-only-exact-cas",
            },
            "outputs": {
                "receipt": "explicit-owner-only-nonexisting-path-required",
                "journal": "explicit-owner-only-nonexisting-path-required",
                "distinctPaths": True,
            },
            "mutationSurface": [
                "GET Deployment/Service/NetworkPolicy",
                "PATCH Deployment image only with exact CAS",
                "GET rollout/pods/Service/EndpointSlice binding",
                "GET exact public HTTPS config and feed paths",
            ],
            "preservation": ["Service", "NetworkPolicy", "Secrets", "public-mode-environment-byte-for-byte", "civic-authority-effects"],
            "probeTransport": {
                "kind": "fixed-public-https-origin",
                "origin": "https://roebel-web.staging.agentcart.eu",
                "method": "GET",
                "tlsVerification": "default-ca-and-hostname",
                "environmentProxyUse": False,
                "redirectsFollowed": False,
                "timeoutSeconds": 15,
                "maxBodyBytes": 8388608,
                "allowedPaths": [
                    "/stadtstack-test/api/config",
                    "/stadtstack-test/api/feed?profile=public",
                ],
            },
            "forbidden": [
                "arbitrary probe URL",
                "kubectl apply/create/delete",
                "generic command execution",
                "secret value reads",
                "automatic mutation retry",
            ],
            "automaticRetry": False,
        },
        "ephemeralRelayFixtureResetBoundary": {
            "modeFlag": "--relay-fixture-reset",
            "runner": "scripts/reset-staging-relay-fixtures.py",
            "transportRunner": "scripts/run-staging-participant-gateway-live.py",
            "protectedClosure": [
                "scripts/run-staging-participant-gateway-live.py",
                "scripts/reset-staging-relay-fixtures.py",
                "scripts/verify-reviewed-render.py",
                "policy/repository-contract.json",
            ],
            "reason": "one-time-gated-removal-of-verified-synthetic-relay-state-and-republication-of-mecky-profile-before-participant-activation",
            "artifactPin": {
                "schemaVersion": "roebel_e2e_runtime_pin_v1",
                "sourceRevision": "36ac41d7049df815aaebbe4301c098a0ec7e4101",
                "receiptSha256": "sha256:08d2b65bb57434ba6f35d8083f32b22f43010e1222544a8ce074e208f95efd9b",
                "relayImage": "ghcr.io/giraeffleaeffle/roebel-staging-relay@sha256:6def2f468e3fad47cf17c0287a9215bbdc299b0d7d3b7fc58927b2f2169650ad",
                "publicMeckyImage": "ghcr.io/giraeffleaeffle/public-mecky@sha256:aa66c9b8bb75989e1c47b628845523fa345a944b0a1a82bd17863f96c1f128e4",
            },
            "namespace": "stadtstack-roebel-staging-lab",
            "relayDeleteTargets": [
                {
                    "deployment": "citizen-relay",
                    "deploymentUid": "86b9aada-2b27-428b-9c98-27376b965f58",
                    "store": "/relay/events.ndjson",
                    "additionalDestroyedStore": "/relay/admissions.ndjson",
                },
                {
                    "deployment": "agent-relay",
                    "deploymentUid": "d62fbb00-feed-40aa-ba72-180bfd80c4e7",
                    "store": "/relay/events.ndjson",
                    "additionalDestroyedStore": None,
                },
            ],
            "publicMeckyQuiescence": {
                "kustomization": "roebel-staging-public-mecky-workload",
                "kustomizationNamespace": "flux-roebel-staging",
                "kustomizationUid": "4d49b8eb-c84b-442a-a96e-26c94f24177a",
                "beforeSuspend": False,
                "temporarySuspend": True,
                "deployment": "public-mecky",
                "deploymentUid": "96987f99-0fb7-4149-a5e7-f0b7c469ab75",
                "beforeReplicas": 1,
                "temporaryReplicas": 0,
                "restoreReplicas": 1,
                "restoreSuspend": False,
            },
            "writeGate": {
                "kind": "Ingress",
                "name": "stadtstack-test-workbench",
                "uid": "02cc55b5-30c5-46dd-b819-727e53c58806",
                "annotation": "haproxy-ingress.github.io/config-backend-early",
                "before": "http-request deny deny_status 405 unless { method GET HEAD POST }\nhttp-request deny deny_status 404 unless { path_beg /stadtstack-test }",
                "gated": "http-request deny deny_status 405 unless { method GET HEAD }\nhttp-request deny deny_status 404 unless { path_beg /stadtstack-test }",
                "probeOrigin": "https://roebel-web.staging.agentcart.eu",
                "restoreRequired": True,
            },
            "preconditions": [
                "participant-gateway-kustomizations-suspended-and-workload-absent",
                "workbench-feed-nonempty-and-every-projected-entry-synthetic",
                "citizen-admissions-file-absent-or-zero-records",
                "exact-single-ready-controller-owned-pod-per-target",
                "exact-relay-image-and-128Mi-emptyDir-mounted-at-/relay",
                "service-endpoint-bound-to-captured-pod-uid",
                "public-mecky-exact-image-deployment-and-ready-controller-owned-pod",
                "deployment-service-networkpolicy-ingress-and-mecky-spec-digests-captured",
            ],
            "mutationSurface": [
                "GET-only-preflight-and-postcondition-reads",
                "fixed-no-shell-Pod-exec-returning-counts-hashes-and-booleans-only",
                "PATCH-exact-workbench-Ingress-write-gate-with-uid-resourceVersion-and-value-CAS",
                "PATCH-exact-public-mecky-Kustomization-suspend-false-to-true-and-back-with-CAS",
                "PATCH-exact-public-mecky-Deployment-replicas-1-to-0-and-back-with-CAS",
                "DELETE-exact-generated-Pod-path-with-uid-and-resourceVersion-preconditions",
                "PATCH-exact-workbench-Ingress-write-gate-restoration-with-uid-resourceVersion-and-value-CAS",
            ],
            "deleteOrder": ["citizen-relay", "agent-relay"],
            "outputs": {
                "receipt": "explicit-owner-only-nonexisting-path-required",
                "journal": "explicit-owner-only-nonexisting-path-required",
                "distinctPaths": True,
            },
            "preservation": [
                "Deployment-UID-generation-and-spec",
                "Service-UID-and-spec",
                "NetworkPolicy-UID-generation-and-spec",
                "public-mecky-Deployment-UID-generation-and-spec",
                "public-mecky-Kustomization-UID-spec-and-original-suspension",
                "workbench-Ingress-UID-spec-and-original-write-policy",
                "Kubernetes-Secrets",
                "civic-authority-effects",
            ],
            "success": [
                "old-pod-uids-absent",
                "different-ready-replacement-pod-uids",
                "service-endpoints-bound-to-replacements",
                "public-mecky-scaled-zero-before-relay-deletes-and-restored-to-one",
                "mecky-exact-signed-kind-0-profile-with-bot-true-and-zero-kind-1",
                "two-identical-empty-feed-observations",
                "write-gate-restored-and-public-route-proven",
                "preservation-digests-unchanged",
            ],
            "forbidden": [
                "caller-selected-namespace-target-selector-or-probe-url",
                "ordinary-kubectl-delete-without-preconditions",
                "force-delete-or-finalizer-removal",
                "generic-shell-or-caller-selected-exec-command",
                "Deployment-mutation-outside-exact-public-mecky-replicas-transition",
                "Kustomization-mutation-outside-exact-public-mecky-suspension-transition",
                "Service-NetworkPolicy-or-Secret-mutation",
                "Ingress-mutation-outside-the-exact-write-gate-annotation",
                "civic-authority-effects",
                "automatic-mutation-retry",
            ],
            "dataRollbackPossible": False,
            "writeGateRollbackRequired": True,
            "automaticRetry": False,
        },
        "requiredBranchProtection": {
            "requiredStatusChecks": ["reviewed-render-admission"],
            "requiredApprovingReviewCount": 1,
            "dismissStaleReviews": True,
            "requireCodeOwnerReviews": True,
            "requireConversationResolution": True,
            "requireLinearHistory": True,
            "allowForcePushes": False,
            "allowDeletions": False,
        },
    }, "repository contract drift")
    return contract


def verify_head(value: Any, label: str) -> dict[str, Any]:
    head = closed(value, {"schemaVersion", "promotionRevision", "releaseSetDigest", "components"}, label)
    require(head["schemaVersion"] == HEAD_SCHEMA, f"{label} schema drift")
    require(isinstance(head["promotionRevision"], str) and REVISION.fullmatch(head["promotionRevision"]), f"{label} promotion revision invalid")
    require(isinstance(head["releaseSetDigest"], str) and SHA256.fullmatch(head["releaseSetDigest"]), f"{label} release digest invalid")
    require(isinstance(head["components"], list) and len(head["components"]) == 2, f"{label} component count invalid")
    parsed = []
    for index, component in enumerate(head["components"]):
        item = closed(component, {"component", "sourceRevision", "manifestDigest"}, f"{label}.components[{index}]")
        require(item["component"] == COMPONENT_ORDER[index], f"{label} component order invalid")
        require(isinstance(item["sourceRevision"], str) and REVISION.fullmatch(item["sourceRevision"]), f"{label} source revision invalid")
        require(isinstance(item["manifestDigest"], str) and SHA256.fullmatch(item["manifestDigest"]), f"{label} manifest digest invalid")
        parsed.append(item)
    return head


def component_map(head: dict[str, Any]) -> dict[str, dict[str, str]]:
    return {item["component"]: item for item in head["components"]}


def verify_reviewed_public_knowledge_runtime_pin(value: Any) -> dict[str, Any]:
    pin = closed(
        value,
        {
            "schemaVersion",
            "component",
            "sourceRevision",
            "sourceTag",
            "imageRepository",
            "manifestDigest",
            "workflowIdentity",
            "slsaProvenance",
            "spdxSbom",
            "anonymousPublicPullReceipt",
            "authorityBinding",
            "deploymentEffect",
        },
        "reviewed-public-knowledge runtime-pin",
    )
    require(pin["schemaVersion"] == "stadtstack_reviewed_public_knowledge_runtime_pin_v1", "reviewed runtime-pin schema drift")
    require(pin["component"] == "reviewed-public-knowledge-runtime", "reviewed runtime-pin component invalid")
    require(isinstance(pin["sourceRevision"], str) and REVISION.fullmatch(pin["sourceRevision"]), "reviewed runtime source revision invalid")
    require(pin["sourceTag"] == f"source-{pin['sourceRevision']}", "reviewed runtime source tag invalid")
    require(pin["imageRepository"] == REVIEWED_PUBLIC_KNOWLEDGE_IMAGE, "reviewed runtime image repository invalid")
    require(isinstance(pin["manifestDigest"], str) and SHA256.fullmatch(pin["manifestDigest"]), "reviewed runtime manifest digest invalid")
    require(pin["workflowIdentity"] == REVIEWED_PUBLIC_KNOWLEDGE_WORKFLOW, "reviewed runtime workflow identity invalid")
    require(pin["sourceRevision"] == REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_SOURCE_REVISION, "reviewed runtime first-tracer source revision drift")
    require(pin["sourceTag"] == REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_SOURCE_TAG, "reviewed runtime first-tracer source tag drift")
    require(pin["manifestDigest"] == REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_IMAGE_DIGEST, "reviewed runtime first-tracer image digest drift")

    provenance = closed(
        pin["slsaProvenance"],
        {"issuer", "publisherIdentity", "predicateType", "repository", "gitRef", "sourceRevision", "subjectDigest", "attestationDigest"},
        "reviewed runtime SLSA provenance",
    )
    require(provenance["issuer"] == "https://token.actions.githubusercontent.com", "reviewed runtime provenance issuer invalid")
    require(provenance["publisherIdentity"] == REVIEWED_PUBLIC_KNOWLEDGE_WORKFLOW, "reviewed runtime provenance publisher invalid")
    require(provenance["predicateType"] == "https://slsa.dev/provenance/v1", "reviewed runtime provenance predicate invalid")
    require(provenance["repository"] == "GiraeffleAeffle/stadtstack", "reviewed runtime provenance repository invalid")
    require(provenance["gitRef"] == "refs/heads/main", "reviewed runtime provenance ref invalid")
    require(provenance["sourceRevision"] == pin["sourceRevision"], "reviewed runtime provenance revision invalid")
    require(provenance["subjectDigest"] == pin["manifestDigest"], "reviewed runtime provenance subject invalid")
    require(provenance["attestationDigest"] == REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_SLSA_DIGEST, "reviewed runtime first-tracer SLSA attestation drift")

    sbom = closed(
        pin["spdxSbom"],
        {"format", "predicateType", "repository", "gitRef", "sourceRevision", "subjectDigest", "attestationDigest"},
        "reviewed runtime SPDX SBOM",
    )
    require(sbom["format"] == "SPDX-2.3", "reviewed runtime SBOM format invalid")
    require(sbom["predicateType"] == "https://spdx.dev/Document/v2.3", "reviewed runtime SBOM predicate invalid")
    require(sbom["repository"] == "GiraeffleAeffle/stadtstack", "reviewed runtime SBOM repository invalid")
    require(sbom["gitRef"] == "refs/heads/main", "reviewed runtime SBOM ref invalid")
    require(sbom["sourceRevision"] == pin["sourceRevision"], "reviewed runtime SBOM revision invalid")
    require(sbom["subjectDigest"] == pin["manifestDigest"], "reviewed runtime SBOM subject invalid")
    require(sbom["attestationDigest"] == REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_SPDX_DIGEST, "reviewed runtime first-tracer SPDX attestation drift")

    receipt = closed(
        pin["anonymousPublicPullReceipt"],
        {
            "schemaVersion",
            "canonicalEncoding",
            "component",
            "imageRepository",
            "manifestDigest",
            "sourceRevision",
            "packageVisibility",
            "authContext",
            "authConfigCanonicalSha256",
            "resolverIdentity",
            "resolvedManifestDigest",
            "receiptDigest",
        },
        "reviewed runtime anonymous-public receipt",
    )
    require(receipt["schemaVersion"] == "stadtstack_reviewed_public_knowledge_anonymous_digest_pull_receipt_v1", "reviewed runtime receipt schema drift")
    require(receipt["canonicalEncoding"] == "canonical-json", "reviewed runtime receipt encoding invalid")
    require(receipt["component"] == pin["component"], "reviewed runtime receipt component invalid")
    require(receipt["imageRepository"] == pin["imageRepository"], "reviewed runtime receipt image invalid")
    require(receipt["manifestDigest"] == pin["manifestDigest"], "reviewed runtime receipt manifest invalid")
    require(receipt["sourceRevision"] == pin["sourceRevision"], "reviewed runtime receipt revision invalid")
    require(receipt["packageVisibility"] == "public", "reviewed runtime package visibility invalid")
    require(receipt["authContext"] == "clean-empty-auth-config", "reviewed runtime anonymous auth context invalid")
    require(receipt["authConfigCanonicalSha256"] == REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_AUTH_DIGEST, "reviewed runtime first-tracer anonymous auth drift")
    require(receipt["resolverIdentity"] == "oras-resolve-anonymous", "reviewed runtime resolver identity invalid")
    require(receipt["resolvedManifestDigest"] == pin["manifestDigest"], "reviewed runtime resolved digest invalid")
    require(receipt["receiptDigest"] == REVIEWED_PUBLIC_KNOWLEDGE_FIRST_TRACER_RECEIPT_DIGEST, "reviewed runtime first-tracer receipt digest drift")
    require(pin["authorityBinding"] == "none", "reviewed runtime authority binding invalid")
    require(pin["deploymentEffect"] is False, "reviewed runtime deployment effect invalid")
    return pin


def verify_reviewed_public_knowledge_deployment(value: Any, runtime_pin: dict[str, Any]) -> dict[str, Any]:
    deployment = closed(value, {"apiVersion", "kind", "metadata", "spec"}, "reviewed-public-knowledge Deployment")
    require(deployment["apiVersion"] == "apps/v1" and deployment["kind"] == "Deployment", "reviewed runtime Deployment kind invalid")
    metadata = closed(deployment["metadata"], {"labels", "name", "namespace"}, "reviewed runtime Deployment metadata")
    require(metadata["name"] == REVIEWED_PUBLIC_KNOWLEDGE_NAME and metadata["namespace"] == REVIEWED_PUBLIC_KNOWLEDGE_NAMESPACE, "reviewed runtime Deployment identity invalid")
    require(metadata["labels"] == REVIEWED_PUBLIC_KNOWLEDGE_LABELS, "reviewed runtime Deployment labels invalid")
    spec = closed(
        deployment["spec"],
        {"replicas", "selector", "template"},
        "reviewed runtime Deployment spec",
    )
    require(spec["replicas"] == 1, "reviewed runtime replicas invalid")
    require(spec["selector"] == {"matchLabels": REVIEWED_PUBLIC_KNOWLEDGE_LABELS}, "reviewed runtime selector invalid")
    template = closed(spec["template"], {"metadata", "spec"}, "reviewed runtime Pod template")
    template_metadata = closed(template["metadata"], {"labels"}, "reviewed runtime Pod metadata")
    require(template_metadata["labels"] == REVIEWED_PUBLIC_KNOWLEDGE_LABELS, "reviewed runtime Pod labels invalid")
    pod = closed(
        template["spec"],
        {"automountServiceAccountToken", "containers", "restartPolicy", "securityContext"},
        "reviewed runtime Pod spec",
    )
    require(pod["automountServiceAccountToken"] is False, "reviewed runtime ServiceAccount token must be disabled")
    require(pod["restartPolicy"] == "Always", "reviewed runtime restart policy invalid")
    require(pod["securityContext"] == {
        "fsGroup": 65532,
        "runAsGroup": 65532,
        "runAsNonRoot": True,
        "runAsUser": 65532,
        "seccompProfile": {"type": "RuntimeDefault"},
    }, "reviewed runtime Pod security context invalid")
    containers = pod["containers"]
    require(isinstance(containers, list) and len(containers) == 1 and isinstance(containers[0], dict), "reviewed runtime container set invalid")
    container = containers[0]
    require(set(container) <= {"env", "image", "imagePullPolicy", "livenessProbe", "name", "ports", "readinessProbe", "securityContext", "startupProbe"}, "reviewed runtime container fields widened")
    require(container.get("name") == "reviewed-public-knowledge", "reviewed runtime container name invalid")
    require(container.get("image") == f"{runtime_pin['imageRepository']}@{runtime_pin['manifestDigest']}", "reviewed runtime immutable image binding invalid")
    require(container.get("imagePullPolicy") == "IfNotPresent", "reviewed runtime pull policy invalid")
    require(container.get("env") == [], "reviewed runtime must not accept mutable environment configuration")
    require(container.get("ports") == [{"containerPort": 8080, "name": "http", "protocol": "TCP"}], "reviewed runtime port invalid")
    require(container.get("securityContext") == {
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
        "readOnlyRootFilesystem": True,
    }, "reviewed runtime container security context invalid")

    def tcp_probe(failure_threshold: int, period_seconds: int) -> dict[str, Any]:
        return {
            "failureThreshold": failure_threshold,
            "periodSeconds": period_seconds,
            "successThreshold": 1,
            "tcpSocket": {"port": "http"},
            "timeoutSeconds": 3,
        }

    require(container.get("readinessProbe") == tcp_probe(3, 10), "reviewed runtime readiness probe must be non-HTTP")
    require(container.get("livenessProbe") == tcp_probe(3, 20), "reviewed runtime liveness probe must be non-HTTP")
    require(container.get("startupProbe") == tcp_probe(30, 2), "reviewed runtime startup probe must be non-HTTP")
    return deployment


def verify_reviewed_public_knowledge_service(value: Any) -> dict[str, Any]:
    service = closed(value, {"apiVersion", "kind", "metadata", "spec"}, "reviewed-public-knowledge Service")
    require(service["apiVersion"] == "v1" and service["kind"] == "Service", "reviewed runtime Service kind invalid")
    metadata = closed(service["metadata"], {"labels", "name", "namespace"}, "reviewed runtime Service metadata")
    require(metadata["name"] == REVIEWED_PUBLIC_KNOWLEDGE_NAME and metadata["namespace"] == REVIEWED_PUBLIC_KNOWLEDGE_NAMESPACE, "reviewed runtime Service identity invalid")
    require(metadata["labels"] == REVIEWED_PUBLIC_KNOWLEDGE_LABELS, "reviewed runtime Service labels invalid")
    require(service["spec"] == {
        "ports": [{"name": "http", "port": 18080, "protocol": "TCP", "targetPort": "http"}],
        "selector": REVIEWED_PUBLIC_KNOWLEDGE_LABELS,
        "type": "ClusterIP",
    }, "reviewed runtime Service boundary invalid")
    return service


def verify_reviewed_public_knowledge_network_policy(value: Any) -> dict[str, Any]:
    policy = closed(value, {"apiVersion", "kind", "metadata", "spec"}, "reviewed-public-knowledge NetworkPolicy")
    require(policy["apiVersion"] == "networking.k8s.io/v1" and policy["kind"] == "NetworkPolicy", "reviewed runtime NetworkPolicy kind invalid")
    metadata = closed(policy["metadata"], {"labels", "name", "namespace"}, "reviewed runtime NetworkPolicy metadata")
    require(metadata["name"] == REVIEWED_PUBLIC_KNOWLEDGE_NAME and metadata["namespace"] == REVIEWED_PUBLIC_KNOWLEDGE_NAMESPACE, "reviewed runtime NetworkPolicy identity invalid")
    require(metadata["labels"] == REVIEWED_PUBLIC_KNOWLEDGE_LABELS, "reviewed runtime NetworkPolicy labels invalid")
    require(policy["spec"] == {
        "egress": [],
        "ingress": [{
            "from": [{
                "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": REVIEWED_PUBLIC_KNOWLEDGE_NAMESPACE}},
                "podSelector": {"matchLabels": {
                    "app.kubernetes.io/component": "public-mecky",
                    "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
                }},
            }],
            "ports": [{"port": 8080, "protocol": "TCP"}],
        }],
        "podSelector": {"matchLabels": REVIEWED_PUBLIC_KNOWLEDGE_LABELS},
        "policyTypes": ["Ingress", "Egress"],
    }, "reviewed runtime NetworkPolicy boundary invalid")
    return policy


def verify_reviewed_public_knowledge_kustomization(root: Path) -> str:
    expected = (
        "apiVersion: kustomize.config.k8s.io/v1beta1\n"
        "kind: Kustomization\n"
        "resources:\n"
        "  - deployment.json\n"
        "  - service.json\n"
        "  - networkpolicy.json\n"
    )
    value = (root / f"{RENDER_ROOT}/reviewed-public-knowledge/kustomization.yaml").read_text()
    require(value == expected, "reviewed runtime Flux path widened or ingress added")
    return value


def verify_reviewed_public_knowledge(root: Path) -> dict[str, Any]:
    runtime_pin = verify_reviewed_public_knowledge_runtime_pin(load_json(root / f"{RENDER_ROOT}/reviewed-public-knowledge/runtime-pin.json"))
    deployment = verify_reviewed_public_knowledge_deployment(load_json(root / f"{RENDER_ROOT}/reviewed-public-knowledge/deployment.json"), runtime_pin)
    service = verify_reviewed_public_knowledge_service(load_json(root / f"{RENDER_ROOT}/reviewed-public-knowledge/service.json"))
    network_policy = verify_reviewed_public_knowledge_network_policy(load_json(root / f"{RENDER_ROOT}/reviewed-public-knowledge/networkpolicy.json"))
    kustomization = verify_reviewed_public_knowledge_kustomization(root)
    return {
        "deployment": deployment,
        "service": service,
        "networkPolicy": network_policy,
        "kustomization": kustomization,
        "runtimePin": runtime_pin,
    }


def verify_deployment(
    root: Path,
    component: str,
    head: dict[str, Any],
    reviewed_knowledge: bool = False,
    reviewed_web_source: bool = False,
    civic_projection_route: bool = False,
    tracer_feed_route: bool = False,
    identity_contract_set: bool = False,
) -> dict[str, Any]:
    policy = COMPONENTS[component]
    path = root / RENDER_ROOT / policy["directory"] / "deployment.json"
    deployment = load_json(path)
    require(isinstance(deployment, dict), f"{component} Deployment must be an object")
    require(deployment.get("apiVersion") == "apps/v1" and deployment.get("kind") == "Deployment", f"{component} object kind invalid")
    require(set(deployment) == {"apiVersion", "kind", "metadata", "spec"}, f"{component} top-level shape invalid")
    metadata = deployment.get("metadata")
    require(isinstance(metadata, dict), f"{component} metadata invalid")
    require(metadata.get("namespace") == policy["namespace"] and metadata.get("name") == policy["name"], f"{component} identity invalid")
    require(not ({"uid", "resourceVersion", "managedFields", "creationTimestamp"} & set(metadata)), f"{component} runtime metadata forbidden")
    require("status" not in deployment, f"{component} runtime status forbidden")
    annotations = metadata.get("annotations")
    require(isinstance(annotations, dict), f"{component} annotations invalid")
    record = component_map(head)[component]
    require(annotations.get("stadtstack.io/source-revision") == record["sourceRevision"], f"{component} source annotation mismatch")
    require(annotations.get("stadtstack.io/release-set-sha256") == head["releaseSetDigest"], f"{component} release annotation mismatch")
    try:
        containers = deployment["spec"]["template"]["spec"]["containers"]
        pod_annotations = deployment["spec"]["template"]["metadata"]["annotations"]
    except (KeyError, TypeError):
        raise VerificationError(f"{component} Pod template invalid") from None
    require(isinstance(containers, list), f"{component} containers invalid")
    primary = [container for container in containers if isinstance(container, dict) and container.get("name") == policy["container"]]
    require(len(primary) == 1, f"{component} primary container invalid")
    expected_image = f"{policy['repository']}@{record['manifestDigest']}"
    require(primary[0].get("image") == expected_image, f"{component} image binding invalid")
    require(primary[0].get("imagePullPolicy") == "IfNotPresent", f"{component} pull policy invalid")
    require(isinstance(pod_annotations, dict) and pod_annotations.get("stadtstack.io/source-revision") == record["sourceRevision"], f"{component} Pod source annotation mismatch")

    keys = set(iter_keys(deployment))
    require(not ({"data", "stringData", "binaryData"} & keys), f"{component} Secret payload-shaped field forbidden")
    serialized = json.dumps(deployment, sort_keys=True)
    for forbidden in ("BEGIN PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", "AGE-SECRET-KEY-", "ghp_", "github_pat_"):
        require(forbidden not in serialized, f"{component} secret-shaped content forbidden")
    for container in containers:
        if not isinstance(container, dict):
            continue
        for env in container.get("env", []):
            if not isinstance(env, dict):
                continue
            name = env.get("name", "")
            if isinstance(name, str) and re.search(r"(?:SECRET|TOKEN|PASSWORD|API_KEY)$", name):
                require("value" not in env and "valueFrom" in env, f"{component} literal secret-shaped environment value forbidden: {name}")
    env = primary[0].get("env", [])
    require(isinstance(env, list), f"{component} environment invalid")
    names = [item.get("name") for item in env if isinstance(item, dict)]
    require(len(names) == len(env) and len(names) == len(set(names)), f"{component} environment names invalid or repeated")
    by_name = {item["name"]: item for item in env}
    if component == "public-mecky":
        expected_chat = {
            "MECKY_CHAT_PORT": "18084",
            "MECKY_CHAT_BIND_HOST": "0.0.0.0",
            "MECKY_CHAT_PER_MINUTE": "10",
            "MECKY_CHAT_PER_DAY": "100",
        }
        if not reviewed_knowledge:
            expected_chat.update({
                "STADTSTACK_E2E_MODE": "synthetic-reviewed",
                "STADTSTACK_E2E_SYNTHETIC_EVIDENCE_ALLOWED": "true",
            })
        else:
            for forbidden in LEGACY_SYNTHETIC_EVIDENCE_ENV_NAMES:
                require(forbidden not in by_name, f"public-mecky legacy synthetic evidence field present: {forbidden}")
            require(by_name.get("STADTSTACK_PUBLIC_BASE_URL") == {
                "name": "STADTSTACK_PUBLIC_BASE_URL",
                "value": REVIEWED_PUBLIC_KNOWLEDGE_BASE_URL,
            }, "public-mecky reviewed knowledge base URL invalid")
            require(by_name.get("MECKY_REVIEWED_SOURCE_KINDS") == {
                "name": "MECKY_REVIEWED_SOURCE_KINDS",
                "value": REVIEWED_PUBLIC_KNOWLEDGE_SOURCE_KINDS,
            }, "public-mecky reviewed source ordering invalid")
            for item in env:
                value_from = item.get("valueFrom", {}) if isinstance(item, dict) else {}
                config_map = value_from.get("configMapKeyRef", {}) if isinstance(value_from, dict) else {}
                require(config_map.get("name") != "reviewed-evidence", "public-mecky legacy synthetic evidence ConfigMap present")
        reviewed_web_env = PUBLIC_MECKY_REVIEWED_WEB_SOURCE_ENV[0]
        if reviewed_web_source:
            require(reviewed_knowledge, "public-mecky reviewed Web source requires reviewed knowledge mode")
            require(
                by_name.get(reviewed_web_env["name"]) == reviewed_web_env,
                "public-mecky reviewed Web knowledge origin invalid",
            )
        else:
            require(
                reviewed_web_env["name"] not in by_name,
                "public-mecky reviewed Web source is not admitted",
            )
        require(
            "MECKY_PUBLIC_INDEX_BASE_URL" not in by_name,
            "public-mecky public index is blocked until the exact signed event is queryable",
        )
        for name, value in expected_chat.items():
            require(by_name.get(name) == {"name": name, "value": value}, f"public-mecky {name} binding invalid")
        require(primary[0].get("ports") == [{"containerPort": 18084, "name": "mecky-chat", "protocol": "TCP"}], "public-mecky chat port invalid")
        expected_probe = {
            "failureThreshold": 3,
            "httpGet": {"path": "/healthz", "port": "mecky-chat", "scheme": "HTTP"},
            "periodSeconds": 10,
            "successThreshold": 1,
            "timeoutSeconds": 3,
        }
        require(primary[0].get("readinessProbe") == expected_probe, "public-mecky readiness probe invalid")
        require(primary[0].get("livenessProbe") == {**expected_probe, "periodSeconds": 20}, "public-mecky liveness probe invalid")
        require(primary[0].get("startupProbe") == {**expected_probe, "failureThreshold": 30, "periodSeconds": 2}, "public-mecky startup probe invalid")
    else:
        verify_web_identity_contract_set(
            deployment,
            by_name,
            identity_contract_set,
        )
        require(by_name.get("PUBLIC_MECKY_CHAT_URL") == {
            "name": "PUBLIC_MECKY_CHAT_URL",
            "value": "http://public-mecky.stadtstack-roebel-staging-lab.svc.cluster.local:18084",
        }, "Web Public Mecky URL invalid")
        projection = {
            "name": "STADTSTACK_CIVIC_PROJECTION_UPSTREAM_URL",
            "value": CIVIC_PROJECTION_UPSTREAM_URL,
        }
        if civic_projection_route:
            require(
                by_name.get("STADTSTACK_CIVIC_PROJECTION_UPSTREAM_URL") == projection,
                "Web civic projection upstream invalid",
            )
        else:
            require(
                "STADTSTACK_CIVIC_PROJECTION_UPSTREAM_URL" not in by_name,
                "Web civic projection route is not admitted",
            )
        if tracer_feed_route:
            require(
                by_name.get(TRACER_FEED_URL_ENV["name"]) == TRACER_FEED_URL_ENV,
                "Web tracer feed URL invalid",
            )
            require(
                by_name.get(TRACER_FEED_ANON_ENV["name"]) == TRACER_FEED_ANON_ENV,
                "Web tracer feed Secret reference invalid",
            )
        else:
            require(
                TRACER_FEED_URL_ENV["name"] not in by_name
                and TRACER_FEED_ANON_ENV["name"] not in by_name,
                "Web tracer feed route is not admitted",
            )
    return deployment


def web_civic_projection_route_enabled(root: Path) -> bool:
    deployment = load_json(root / RENDER_ROOT / "web/deployment.json")
    try:
        environment = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
    except (KeyError, IndexError, TypeError):
        return False
    return any(
        isinstance(item, dict)
        and item.get("name") == "STADTSTACK_CIVIC_PROJECTION_UPSTREAM_URL"
        for item in environment
    )


def web_tracer_feed_route_enabled(root: Path) -> bool:
    deployment = load_json(root / RENDER_ROOT / "web/deployment.json")
    try:
        environment = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
    except (KeyError, IndexError, TypeError):
        return False
    names = {
        item.get("name")
        for item in environment
        if isinstance(item, dict)
    }
    return bool(
        names & {TRACER_FEED_URL_ENV["name"], TRACER_FEED_ANON_ENV["name"]}
    )


def web_identity_contract_set_enabled(root: Path) -> bool:
    """Detect the reviewed test-contract capability, including partial drift."""
    deployment = load_json(root / RENDER_ROOT / "web/deployment.json")
    try:
        environment = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
        annotations = deployment["spec"]["template"]["metadata"]["annotations"]
    except (KeyError, IndexError, TypeError):
        return False
    names = {
        item.get("name")
        for item in environment
        if isinstance(item, dict)
    }
    return bool(
        names & WEB_IDENTITY_CONTRACT_SET_ENV_NAMES
        or set(annotations) & set(WEB_IDENTITY_CONTRACT_SET_ANNOTATIONS)
    )


def verify_web_identity_contract_set(
    deployment: dict[str, Any],
    by_name: dict[str, dict[str, Any]],
    enabled: bool,
) -> dict[str, Any] | None:
    """Require the profile and address pair atomically under no authority."""
    rotated = by_name.get("ROEBEL_PUBLIC_IDENTITY_CONTRACT_SET", {}).get("value") == IDENTITY_ROTATION.WEB_IDENTITY["profile"]
    identity = IDENTITY_ROTATION.WEB_IDENTITY if rotated else WEB_IDENTITY_CONTRACT_SET
    expected_env = IDENTITY_ROTATION.web_environment() if rotated else WEB_IDENTITY_CONTRACT_SET_ENV
    expected_annotations = IDENTITY_ROTATION.web_annotations() if rotated else WEB_IDENTITY_CONTRACT_SET_ANNOTATIONS
    pod_annotations = deployment["spec"]["template"]["metadata"]["annotations"]
    present_names = WEB_IDENTITY_CONTRACT_SET_ENV_NAMES & set(by_name)
    present_annotations = (
        set(WEB_IDENTITY_CONTRACT_SET_ANNOTATIONS) & set(pod_annotations)
    )
    if not enabled:
        require(
            not present_names and not present_annotations,
            "Web identity contract set is not admitted",
        )
        return None
    require(
        present_names == WEB_IDENTITY_CONTRACT_SET_ENV_NAMES,
        "Web identity contract set must configure profile and both addresses atomically",
    )
    require(
        [by_name[item["name"]] for item in expected_env]
        == expected_env,
        "Web identity contract set profile/address binding invalid",
    )
    require(
        {
            name: pod_annotations[name]
            for name in expected_annotations
            if name in pod_annotations
        }
        == expected_annotations,
        "Web identity contract set authority/code evidence invalid",
    )
    require(
        identity["chainId"] == 100
        and identity["authority"] == "none",
        "Web identity contract set reviewed invariant invalid",
    )
    require(
        expected_annotations[
            "stadtstack.io/identity-contract-set-sha256"
        ]
        == digest(identity),
        "Web identity contract set evidence checksum invalid",
    )
    return copy.deepcopy(identity)


def public_mecky_reviewed_web_source_enabled(root: Path) -> bool:
    deployment = load_json(root / RENDER_ROOT / "public-mecky/deployment.json")
    try:
        environment = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
    except (KeyError, IndexError, TypeError):
        return False
    return any(
        isinstance(item, dict)
        and item.get("name") == PUBLIC_MECKY_REVIEWED_WEB_SOURCE_ENV[0]["name"]
        for item in environment
    )


def verify_public_mecky_service(root: Path) -> dict[str, Any]:
    service = load_json(root / RENDER_ROOT / "public-mecky/service.json")
    require(service == {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "labels": {
                "app.kubernetes.io/component": "public-mecky",
                "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
                "stadtstack.io/authority": "none",
            },
            "name": "public-mecky",
            "namespace": "stadtstack-roebel-staging-lab",
        },
        "spec": {
            "ports": [{"name": "mecky-chat", "port": 18084, "protocol": "TCP", "targetPort": "mecky-chat"}],
            "selector": {
                "app.kubernetes.io/component": "public-mecky",
                "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
            },
            "type": "ClusterIP",
        },
    }, "Public Mecky Service drift")
    return service


def signed_nostr_labels(component: str) -> dict[str, str]:
    require(component in SIGNED_NOSTR_COMPONENTS, "signed-Nostr component invalid")
    return {
        "app.kubernetes.io/component": f"signed-nostr-{component}",
        "app.kubernetes.io/name": SIGNED_NOSTR_NAMES[component],
        "app.kubernetes.io/part-of": "roebel-signed-nostr-staging",
        "stadtstack.io/authority": "none",
    }


def signed_nostr_namespace(component: str) -> str:
    return SIGNED_NOSTR_WEB_NAMESPACE if component == "workbench" else SIGNED_NOSTR_NAMESPACE


def signed_nostr_pod_security_context() -> dict[str, Any]:
    return {
        "fsGroup": 65532,
        "runAsGroup": 65532,
        "runAsNonRoot": True,
        "runAsUser": 65532,
        "seccompProfile": {"type": "RuntimeDefault"},
    }


def signed_nostr_container_security_context() -> dict[str, Any]:
    return {
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
        "readOnlyRootFilesystem": True,
    }


def signed_nostr_gnosis_private_proxy_labels(name: str = SIGNED_NOSTR_GNOSIS_PROXY_NAME) -> dict[str, str]:
    return {
        "app.kubernetes.io/component": "gnosis-rpc-private-proxy",
        "app.kubernetes.io/name": name,
        "app.kubernetes.io/part-of": "roebel-signed-nostr-staging",
        "stadtstack.io/authority": "none",
    }


def expected_signed_nostr_gnosis_private_proxy_service() -> dict[str, Any]:
    """The only proxy shape a future activation record may claim.

    This is a ClusterIP service in the workbench namespace.  It deliberately
    contains no public address, external name, load balancer, IP block, or
    secret value.  The later protected exact-record constant selects the one
    real object; this function constrains its materialized shape first.
    """
    labels = signed_nostr_gnosis_private_proxy_labels()
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"labels": labels, "name": SIGNED_NOSTR_GNOSIS_PROXY_NAME, "namespace": SIGNED_NOSTR_WEB_NAMESPACE},
        "spec": {
            "ports": [{"name": "http", "port": SIGNED_NOSTR_GNOSIS_PROXY_PORT, "protocol": "TCP", "targetPort": "http"}],
            "selector": labels,
            "type": "ClusterIP",
        },
    }


def expected_signed_nostr_gnosis_private_proxy_deployment(image: str) -> dict[str, Any]:
    labels = signed_nostr_gnosis_private_proxy_labels()
    environment = [
        {"name": "ROEBEL_RUNTIME_ROLE", "value": "gnosis-rpc-proxy"},
        {"name": "GNOSIS_PROXY_BIND_HOST", "value": "0.0.0.0"},
        {"name": "GNOSIS_PROXY_PORT", "value": str(SIGNED_NOSTR_GNOSIS_PROXY_PORT)},
        {"name": "GNOSIS_PROXY_UPSTREAM_URL", "value": f"https://{SIGNED_NOSTR_GNOSIS_UPSTREAM_HOST}"},
        {"name": "GNOSIS_PROXY_EXPECTED_CHAIN_ID", "value": "0x64"},
        {"name": "GNOSIS_PROXY_ALLOWED_METHODS", "value": ",".join(SIGNED_NOSTR_GNOSIS_ALLOWED_METHODS)},
        {"name": "GNOSIS_PROXY_MAX_BODY_BYTES", "value": "131072"},
        {"name": "GNOSIS_PROXY_UPSTREAM_TIMEOUT_MS", "value": "5000"},
        {"name": "GNOSIS_PROXY_MAX_CONCURRENT", "value": "16"},
    ]
    container = {
        "env": environment,
        "image": image,
        "imagePullPolicy": "IfNotPresent",
        "livenessProbe": {"failureThreshold": 3, "httpGet": {"path": "/healthz", "port": "http", "scheme": "HTTP"}, "periodSeconds": 20, "successThreshold": 1, "timeoutSeconds": 3},
        "name": SIGNED_NOSTR_GNOSIS_PROXY_NAME,
        "ports": [{"containerPort": SIGNED_NOSTR_GNOSIS_PROXY_PORT, "name": "http", "protocol": "TCP"}],
        "readinessProbe": {"failureThreshold": 3, "httpGet": {"path": "/readyz", "port": "http", "scheme": "HTTP"}, "periodSeconds": 10, "successThreshold": 1, "timeoutSeconds": 6},
        "resources": {"limits": {"cpu": "150m", "ephemeral-storage": "64Mi", "memory": "96Mi"}, "requests": {"cpu": "10m", "ephemeral-storage": "32Mi", "memory": "32Mi"}},
        "securityContext": signed_nostr_container_security_context(),
        "startupProbe": {"failureThreshold": 30, "httpGet": {"path": "/readyz", "port": "http", "scheme": "HTTP"}, "periodSeconds": 2, "successThreshold": 1, "timeoutSeconds": 6},
    }
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"labels": labels, "name": SIGNED_NOSTR_GNOSIS_PROXY_NAME, "namespace": SIGNED_NOSTR_WEB_NAMESPACE},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": labels},
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "automountServiceAccountToken": False,
                    "containers": [container],
                    "restartPolicy": "Always",
                    "securityContext": signed_nostr_pod_security_context(),
                },
            },
        },
    }


def expected_signed_nostr_gnosis_private_proxy_network_policy() -> dict[str, Any]:
    labels = signed_nostr_gnosis_private_proxy_labels()
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"labels": labels, "name": SIGNED_NOSTR_GNOSIS_PROXY_NAME, "namespace": SIGNED_NOSTR_WEB_NAMESPACE},
        "spec": {
            "egress": [
                {
                    "to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}, "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}],
                    "ports": [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}],
                },
                {
                    "to": [{"ipBlock": {"cidr": SIGNED_NOSTR_GNOSIS_UPSTREAM_IPV4_CIDR}}],
                    "ports": [{"port": SIGNED_NOSTR_GNOSIS_UPSTREAM_PORT, "protocol": "TCP"}],
                },
            ],
            "ingress": [{
                "from": [{"podSelector": {"matchLabels": signed_nostr_labels("workbench")}}],
                "ports": [{"port": SIGNED_NOSTR_GNOSIS_PROXY_PORT, "protocol": "TCP"}],
            }],
            "podSelector": {"matchLabels": labels},
            "policyTypes": ["Ingress", "Egress"],
        },
    }


def expected_signed_nostr_workbench_network_policy() -> dict[str, Any]:
    """Canonical workbench policy with one private Gnosis hop."""
    workbench_labels = signed_nostr_labels("workbench")
    dns_egress = {
        "to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}, "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}],
        "ports": [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}],
    }
    relay_egress = [{
        "to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": SIGNED_NOSTR_NAMESPACE}}, "podSelector": {"matchLabels": signed_nostr_labels(relay)}}],
        "ports": [{"port": 18081, "protocol": "TCP"}],
    } for relay in ("citizen-relay", "agent-relay")]
    egress = [
        dns_egress,
        *relay_egress,
        {
            "to": [{"podSelector": {"matchLabels": signed_nostr_gnosis_private_proxy_labels()}}],
            "ports": [{"port": SIGNED_NOSTR_GNOSIS_PROXY_PORT, "protocol": "TCP"}],
        },
    ]
    return {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"labels": workbench_labels, "name": SIGNED_NOSTR_NAMES["workbench"], "namespace": SIGNED_NOSTR_WEB_NAMESPACE},
        "spec": {
            "egress": egress,
            "ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "ingress-system"}}}], "ports": [{"port": 18083, "protocol": "TCP"}]}],
            "podSelector": {"matchLabels": workbench_labels}, "policyTypes": ["Ingress", "Egress"],
        },
    }


def signed_nostr_flux_labels(component: str) -> dict[str, str]:
    require(component in SIGNED_NOSTR_FLUX_BINDING_ORDER, "signed-Nostr Flux component invalid")
    return {
        "app.kubernetes.io/component": f"signed-nostr-{component}-reconciler",
        "app.kubernetes.io/part-of": "roebel-signed-nostr-staging",
        "stadtstack.io/authority": "none",
    }


def signed_nostr_flux_resource_names(component: str) -> list[str]:
    names = [SIGNED_NOSTR_NAMES[component]]
    if component == "workbench":
        names.append(SIGNED_NOSTR_GNOSIS_PROXY_NAME)
    return sorted(names)


def expected_signed_nostr_flux_objects(
    component: str,
    *,
    suspended: bool = True,
) -> dict[str, dict[str, Any]]:
    target_namespace = SIGNED_NOSTR_FLUX_NAMESPACES[component]
    labels = signed_nostr_flux_labels(component)
    kustomization_name = SIGNED_NOSTR_FLUX_KUSTOMIZATION_NAMES[component]
    service_account_name = SIGNED_NOSTR_FLUX_SERVICE_ACCOUNT_NAMES[component]
    resource_names = signed_nostr_flux_resource_names(component)
    health_checks = [
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "name": name,
            "namespace": target_namespace,
        }
        for name in resource_names
    ]
    kustomization_spec: dict[str, Any] = {
        "deletionPolicy": "Orphan",
        "force": False,
        "healthChecks": health_checks,
        "interval": "1m",
        "path": SIGNED_NOSTR_FLUX_PATHS[component],
        "prune": False,
        "retryInterval": "30s",
        "serviceAccountName": service_account_name,
        "sourceRef": {
            "kind": "GitRepository",
            "name": SIGNED_NOSTR_FLUX_SOURCE_NAME,
            "namespace": SIGNED_NOSTR_FLUX_NAMESPACE,
        },
        # The one-time administrator bootstrap may create only this suspended
        # object.  A separately bound CAS/live recheck is required before the
        # exact same object may be unsuspended.
        "suspend": suspended,
        "targetNamespace": target_namespace,
        "timeout": "2m",
        "wait": True,
    }
    if component == "workbench":
        kustomization_spec["dependsOn"] = [
            {"name": SIGNED_NOSTR_FLUX_KUSTOMIZATION_NAMES[relay]}
            for relay in ("citizen-relay", "agent-relay")
        ]
    kustomization = {
        "apiVersion": "kustomize.toolkit.fluxcd.io/v1",
        "kind": "Kustomization",
        "metadata": {
            "labels": labels,
            "name": kustomization_name,
            "namespace": SIGNED_NOSTR_FLUX_NAMESPACE,
        },
        "spec": kustomization_spec,
    }
    service_account = {
        "apiVersion": "v1",
        "automountServiceAccountToken": False,
        "kind": "ServiceAccount",
        "metadata": {
            "labels": labels,
            "name": service_account_name,
            "namespace": SIGNED_NOSTR_FLUX_NAMESPACE,
        },
    }
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {
            "labels": labels,
            "name": service_account_name,
            "namespace": target_namespace,
        },
        "rules": [
            {
                "apiGroups": ["apps"],
                "resourceNames": resource_names,
                "resources": ["deployments"],
                "verbs": ["get", "patch", "update"],
            },
            {
                "apiGroups": [""],
                "resourceNames": resource_names,
                "resources": ["services"],
                "verbs": ["get", "patch", "update"],
            },
            {
                "apiGroups": ["networking.k8s.io"],
                "resourceNames": resource_names,
                "resources": ["networkpolicies"],
                "verbs": ["get", "patch", "update"],
            },
        ],
    }
    role_binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {
            "labels": labels,
            "name": service_account_name,
            "namespace": target_namespace,
        },
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": service_account_name,
        },
        "subjects": [{
            "kind": "ServiceAccount",
            "name": service_account_name,
            "namespace": SIGNED_NOSTR_FLUX_NAMESPACE,
        }],
    }
    return {
        "kustomization": kustomization,
        "serviceAccount": service_account,
        "role": role,
        "roleBinding": role_binding,
    }


def signed_nostr_object_target(value: dict[str, Any]) -> dict[str, str]:
    metadata = value["metadata"]
    return {
        "apiVersion": value["apiVersion"],
        "kind": value["kind"],
        "name": metadata["name"],
        "namespace": metadata["namespace"],
    }


def expected_signed_nostr_managed_objects(
    publisher_pin: dict[str, Any],
    *,
    suspended_flux: bool,
) -> list[dict[str, Any]]:
    """Return every exact live object owned by the signed-Nostr tracer.

    The ordering is part of the evidence contract.  Runtime and Flux identity
    objects share this one inventory so bootstrap, activation and teardown can
    never silently disagree about ownership.
    """
    images = {entry["component"]: entry for entry in publisher_pin["components"]}
    resources = expected_signed_nostr_resources({"images": images})
    managed: list[dict[str, Any]] = []

    runtime_keys = (
        ("deployment", "deployment"),
        ("service", "service"),
        ("networkpolicy", "networkPolicy"),
    )
    for component in SIGNED_NOSTR_COMPONENTS:
        for object_id, key in runtime_keys:
            value = resources[component][key]
            managed.append({
                "objectId": f"runtime/{component}/{object_id}",
                "class": "runtime",
                "object": value,
            })
        if component == "workbench":
            for object_id, key in (
                ("gnosis-proxy-deployment", "gnosisProxyDeployment"),
                ("gnosis-proxy-service", "gnosisProxyService"),
                ("gnosis-proxy-networkpolicy", "gnosisProxyNetworkPolicy"),
            ):
                value = resources[component][key]
                managed.append({
                    "objectId": f"runtime/{component}/{object_id}",
                    "class": "runtime",
                    "object": value,
                })

    for component in SIGNED_NOSTR_FLUX_BINDING_ORDER:
        flux = expected_signed_nostr_flux_objects(component, suspended=suspended_flux)
        for key in ("kustomization", "serviceAccount", "role", "roleBinding"):
            managed.append({
                "objectId": f"flux/{component}/{key}",
                "class": "flux-identity",
                "object": flux[key],
            })
    return managed


def verify_signed_nostr_live_preconditions(
    value: Any,
    managed: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    require(isinstance(value, list) and len(value) == len(managed), "signed-Nostr live precondition count invalid")
    parsed: list[dict[str, Any]] = []
    for index, (item, expected) in enumerate(zip(value, managed, strict=True)):
        precondition = closed(
            item,
            {
                "objectId",
                "target",
                "desiredObjectDigest",
                "state",
                "uid",
                "resourceVersion",
                "currentObjectDigest",
            },
            f"signed-Nostr live precondition[{index}]",
        )
        require(precondition["objectId"] == expected["objectId"], "signed-Nostr live precondition object order invalid")
        require(precondition["target"] == signed_nostr_object_target(expected["object"]), "signed-Nostr live precondition target invalid")
        desired_digest = digest(expected["object"])
        require(precondition["desiredObjectDigest"] == desired_digest, "signed-Nostr live precondition desired digest invalid")
        if precondition["state"] == "absent":
            require(
                precondition["uid"] is None
                and precondition["resourceVersion"] is None
                and precondition["currentObjectDigest"] is None,
                "signed-Nostr absent precondition must not claim live identity",
            )
        else:
            require(precondition["state"] == "present-exact", "signed-Nostr live precondition state invalid")
            require(isinstance(precondition["uid"], str) and UUID.fullmatch(precondition["uid"]), "signed-Nostr live precondition UID invalid")
            require(isinstance(precondition["resourceVersion"], str) and precondition["resourceVersion"].isdigit(), "signed-Nostr live precondition resourceVersion invalid")
            require(precondition["currentObjectDigest"] == desired_digest, "signed-Nostr present object is not exact and may not be adopted")
        parsed.append(precondition)
    return parsed


def verify_signed_nostr_bootstrap_receipt(
    value: Any,
    preconditions: list[dict[str, Any]],
    managed: list[dict[str, Any]],
) -> dict[str, Any]:
    receipt = closed(
        value,
        {
            "schemaVersion",
            "canonicalEncoding",
            "status",
            "operationId",
            "observedAt",
            "validUntil",
            "maxAgeSeconds",
            "preconditionsCanonicalSha256",
            "postconditions",
            "postconditionsCanonicalSha256",
            "kustomizationsInitiallySuspended",
            "authority",
            "effects",
        },
        "signed-Nostr one-time bootstrap receipt",
    )
    require(receipt["schemaVersion"] == SIGNED_NOSTR_BOOTSTRAP_RECEIPT_SCHEMA, "signed-Nostr bootstrap receipt schema invalid")
    require(receipt["canonicalEncoding"] == "canonical-json", "signed-Nostr bootstrap receipt encoding invalid")
    require(receipt["status"] == "completed-exact-cas", "signed-Nostr bootstrap receipt status invalid")
    require(isinstance(receipt["operationId"], str) and UUID.fullmatch(receipt["operationId"]), "signed-Nostr bootstrap operation id invalid")
    observed = utc_timestamp(receipt["observedAt"], "signed-Nostr bootstrap observedAt")
    valid_until = utc_timestamp(receipt["validUntil"], "signed-Nostr bootstrap validUntil")
    require(receipt["maxAgeSeconds"] == 300, "signed-Nostr bootstrap freshness budget invalid")
    require(0 < duration_seconds(observed, valid_until) <= receipt["maxAgeSeconds"], "signed-Nostr bootstrap receipt stale")
    require(receipt["preconditionsCanonicalSha256"] == digest(preconditions), "signed-Nostr bootstrap precondition checksum invalid")
    require(receipt["kustomizationsInitiallySuspended"] is True, "signed-Nostr bootstrap Kustomizations must start suspended")
    require(receipt["authority"] == "one-time-cluster-admin-exact-targets", "signed-Nostr bootstrap authority invalid")
    require(receipt["effects"] == {
        "clusterMutation": True,
        "civicMutation": False,
        "secretRead": False,
        "secretWrite": False,
        "wildcardAuthority": False,
        "ssaPatchUsedForAbsentTargets": False,
        "absenceGuardSource": "atomic-post-create-http-409-no-adopt",
        "presentGuardSource": "uid-resourceVersion-bound-no-op",
    }, "signed-Nostr bootstrap effects invalid")

    postconditions = receipt["postconditions"]
    require(isinstance(postconditions, list) and len(postconditions) == len(managed), "signed-Nostr bootstrap postcondition count invalid")
    for index, (postcondition_value, precondition, expected) in enumerate(zip(postconditions, preconditions, managed, strict=True)):
        postcondition = closed(
            postcondition_value,
            {
                "objectId",
                "target",
                "uid",
                "resourceVersion",
                "objectDigest",
                "action",
                "apiOperation",
                "requiredUid",
                "requiredResourceVersion",
                "conflictPolicy",
                "apiOutcome",
            },
            f"signed-Nostr bootstrap postcondition[{index}]",
        )
        require(postcondition["objectId"] == expected["objectId"], "signed-Nostr bootstrap postcondition object order invalid")
        require(postcondition["target"] == signed_nostr_object_target(expected["object"]), "signed-Nostr bootstrap postcondition target invalid")
        require(isinstance(postcondition["uid"], str) and UUID.fullmatch(postcondition["uid"]), "signed-Nostr bootstrap postcondition UID invalid")
        require(isinstance(postcondition["resourceVersion"], str) and postcondition["resourceVersion"].isdigit(), "signed-Nostr bootstrap postcondition resourceVersion invalid")
        require(postcondition["objectDigest"] == digest(expected["object"]), "signed-Nostr bootstrap postcondition object drift")
        if precondition["state"] == "absent":
            require(
                postcondition["action"] == "created-by-atomic-post-after-verified-absence"
                and postcondition["apiOperation"] == "POST-create"
                and postcondition["requiredUid"] is None
                and postcondition["requiredResourceVersion"] is None
                and postcondition["conflictPolicy"] == "fail-on-http-409-no-adopt"
                and postcondition["apiOutcome"] == "http-201-created",
                "signed-Nostr absent bootstrap is not atomic create-only",
            )
        else:
            require(
                postcondition["action"] == "retained-exact-owned-object-no-op"
                and postcondition["apiOperation"] == "none"
                and postcondition["requiredUid"] == precondition["uid"]
                and postcondition["requiredResourceVersion"] == precondition["resourceVersion"]
                and postcondition["conflictPolicy"] == "fail-on-uid-or-resourceVersion-mismatch-no-adopt"
                and postcondition["apiOutcome"] == "unchanged-after-atomic-precondition-recheck",
                "signed-Nostr present bootstrap CAS receipt invalid",
            )
            require(postcondition["uid"] == precondition["uid"], "signed-Nostr bootstrap adopted a different UID")
            require(
                postcondition["resourceVersion"] == precondition["resourceVersion"],
                "signed-Nostr bootstrap retained object resourceVersion drift",
            )
    require(receipt["postconditionsCanonicalSha256"] == digest(postconditions), "signed-Nostr bootstrap postcondition checksum invalid")
    return receipt


def verify_signed_nostr_dns_tls_evidence(value: Any, label: str) -> dict[str, Any]:
    evidence = closed(
        value,
        {
            "schemaVersion",
            "canonicalEncoding",
            "resolverIdentity",
            "resolutionMethod",
            "queriedHost",
            "queriedPort",
            "observedAt",
            "validUntil",
            "maxAgeSeconds",
            "addresses",
            "tlsCertificate",
        },
        label,
    )
    require(evidence["schemaVersion"] == SIGNED_NOSTR_DNS_TLS_EVIDENCE_SCHEMA, f"{label} schema invalid")
    require(evidence["canonicalEncoding"] == "canonical-json", f"{label} encoding invalid")
    require(evidence["resolverIdentity"] == "reviewed-doh-resolver", f"{label} resolver invalid")
    require(evidence["resolutionMethod"] == "dns-over-https-a-and-aaaa", f"{label} method invalid")
    require(evidence["queriedHost"] == SIGNED_NOSTR_GNOSIS_UPSTREAM_HOST, f"{label} host invalid")
    require(evidence["queriedPort"] == SIGNED_NOSTR_GNOSIS_UPSTREAM_PORT, f"{label} port invalid")
    observed = utc_timestamp(evidence["observedAt"], f"{label} observedAt")
    valid_until = utc_timestamp(evidence["validUntil"], f"{label} validUntil")
    require(evidence["maxAgeSeconds"] == 300, f"{label} freshness budget invalid")
    require(0 < duration_seconds(observed, valid_until) <= evidence["maxAgeSeconds"], f"{label} stale")

    addresses = closed(evidence["addresses"], {"a", "aaaa"}, f"{label} addresses")
    require(isinstance(addresses["a"], list) and isinstance(addresses["aaaa"], list), f"{label} address sets invalid")
    for family, address_set in ((4, addresses["a"]), (6, addresses["aaaa"])):
        require(all(isinstance(address, str) for address in address_set), f"{label} address set contains a non-string")
        require(address_set == sorted(set(address_set)), f"{label} {'A' if family == 4 else 'AAAA'} set must be sorted and unique")
        for address in address_set:
            try:
                valid = isinstance(address, str) and ipaddress.ip_address(address).version == family
            except ValueError:
                valid = False
            require(valid, f"{label} {'A' if family == 4 else 'AAAA'} address invalid")
    pinned = str(ipaddress.ip_network(SIGNED_NOSTR_GNOSIS_UPSTREAM_IPV4_CIDR, strict=True).network_address)
    require(addresses == {"a": [pinned], "aaaa": []}, f"{label} full resolution set does not equal the fail-closed /32")

    certificate = closed(
        evidence["tlsCertificate"],
        {"serverName", "issuer", "certificateSha256", "notBefore", "notAfter"},
        f"{label} TLS certificate",
    )
    require(certificate["serverName"] == SIGNED_NOSTR_GNOSIS_UPSTREAM_HOST, f"{label} TLS server name invalid")
    require(isinstance(certificate["issuer"], str) and certificate["issuer"].strip() == certificate["issuer"] and certificate["issuer"], f"{label} TLS issuer invalid")
    require(isinstance(certificate["certificateSha256"], str) and SHA256.fullmatch(certificate["certificateSha256"]), f"{label} TLS fingerprint invalid")
    not_before = utc_timestamp(certificate["notBefore"], f"{label} certificate notBefore")
    not_after = utc_timestamp(certificate["notAfter"], f"{label} certificate notAfter")
    require(not_before <= observed <= valid_until < not_after, f"{label} certificate is not valid for the complete evidence window")
    return evidence


def dns_tls_binding(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "resolverIdentity": value["resolverIdentity"],
        "resolutionMethod": value["resolutionMethod"],
        "queriedHost": value["queriedHost"],
        "queriedPort": value["queriedPort"],
        "addresses": value["addresses"],
        "tlsCertificate": value["tlsCertificate"],
    }


def rollback_boundary_digest_record(rollback: dict[str, Any]) -> dict[str, str]:
    return {
        "integritySha256": rollback["integritySha256"],
        "webIngressSha256": rollback["webIngressSha256"],
        "publicMeckyNetworkPolicySha256": rollback["publicMeckyNetworkPolicySha256"],
        "boundaryReceiptSha256": rollback["boundaryReceiptSha256"],
    }


def verify_signed_nostr_activation_live_recheck(
    value: Any,
    bootstrap: dict[str, Any],
    rollback: dict[str, Any],
    initial_dns_tls: dict[str, Any],
) -> dict[str, Any]:
    receipt = closed(
        value,
        {
            "schemaVersion",
            "canonicalEncoding",
            "status",
            "checkedAt",
            "validUntil",
            "maxAgeSeconds",
            "bootstrapReceiptCanonicalSha256",
            "objectStates",
            "objectStatesCanonicalSha256",
            "boundaryState",
            "dnsTlsRecheck",
        },
        "signed-Nostr activation live recheck",
    )
    require(receipt["schemaVersion"] == SIGNED_NOSTR_LIVE_RECHECK_SCHEMA, "signed-Nostr activation live recheck schema invalid")
    require(receipt["canonicalEncoding"] == "canonical-json", "signed-Nostr activation live recheck encoding invalid")
    require(receipt["status"] == "passed-no-drift", "signed-Nostr activation live recheck status invalid")
    checked = utc_timestamp(receipt["checkedAt"], "signed-Nostr activation live recheck checkedAt")
    valid_until = utc_timestamp(receipt["validUntil"], "signed-Nostr activation live recheck validUntil")
    require(receipt["maxAgeSeconds"] == 300, "signed-Nostr activation live recheck freshness budget invalid")
    require(0 < duration_seconds(checked, valid_until) <= receipt["maxAgeSeconds"], "signed-Nostr activation live recheck stale")
    require(receipt["bootstrapReceiptCanonicalSha256"] == digest(bootstrap), "signed-Nostr activation live recheck bootstrap binding invalid")
    require(receipt["objectStates"] == bootstrap["postconditions"], "signed-Nostr activation live object ownership drift")
    require(receipt["objectStatesCanonicalSha256"] == digest(receipt["objectStates"]), "signed-Nostr activation live state checksum invalid")
    require(receipt["boundaryState"] == rollback_boundary_digest_record(rollback), "signed-Nostr activation boundary live recheck drift")
    dns_recheck = verify_signed_nostr_dns_tls_evidence(receipt["dnsTlsRecheck"], "signed-Nostr activation DNS/TLS recheck")
    require(utc_timestamp(dns_recheck["observedAt"], "signed-Nostr activation DNS/TLS observedAt") == checked, "signed-Nostr DNS/TLS recheck is not activation-time evidence")
    require(utc_timestamp(dns_recheck["validUntil"], "signed-Nostr activation DNS/TLS validUntil") >= valid_until, "signed-Nostr DNS/TLS recheck expires before activation receipt")
    require(dns_tls_binding(dns_recheck) == dns_tls_binding(initial_dns_tls), "signed-Nostr activation DNS/TLS recheck changed resolution or certificate")
    return receipt


def verify_signed_nostr_reconcile_activation(
    value: Any,
    live_recheck: dict[str, Any],
    bootstrap: dict[str, Any],
    managed_suspended: list[dict[str, Any]],
    managed_active: list[dict[str, Any]],
) -> dict[str, Any]:
    receipt = closed(
        value,
        {
            "schemaVersion",
            "canonicalEncoding",
            "status",
            "operationId",
            "completedAt",
            "liveRecheckCanonicalSha256",
            "unsuspensions",
            "unsuspensionsCanonicalSha256",
            "effects",
        },
        "signed-Nostr reconcile activation receipt",
    )
    require(receipt["schemaVersion"] == "roebel_signed_nostr_reconcile_activation_receipt_v1", "signed-Nostr reconcile activation schema invalid")
    require(receipt["canonicalEncoding"] == "canonical-json", "signed-Nostr reconcile activation encoding invalid")
    require(receipt["status"] == "completed-after-live-recheck", "signed-Nostr reconcile activation status invalid")
    require(isinstance(receipt["operationId"], str) and UUID.fullmatch(receipt["operationId"]), "signed-Nostr reconcile activation operation id invalid")
    completed = utc_timestamp(receipt["completedAt"], "signed-Nostr reconcile activation completedAt")
    checked = utc_timestamp(live_recheck["checkedAt"], "signed-Nostr activation live recheck checkedAt")
    valid_until = utc_timestamp(live_recheck["validUntil"], "signed-Nostr activation live recheck validUntil")
    require(checked <= completed <= valid_until, "signed-Nostr reconcile activation occurred outside the live-preflight window")
    require(receipt["liveRecheckCanonicalSha256"] == digest(live_recheck), "signed-Nostr reconcile activation live-recheck binding invalid")
    require(receipt["effects"] == {
        "clusterMutation": True,
        "civicMutation": False,
        "secretRead": False,
        "secretWrite": False,
        "onlySuspendFieldChanged": True,
    }, "signed-Nostr reconcile activation effects invalid")

    suspended_by_id = {entry["objectId"]: entry for entry in managed_suspended}
    active_by_id = {entry["objectId"]: entry for entry in managed_active}
    post_by_id = {entry["objectId"]: entry for entry in bootstrap["postconditions"]}
    expected_ids = [f"flux/{component}/kustomization" for component in SIGNED_NOSTR_FLUX_BINDING_ORDER]
    unsuspensions = receipt["unsuspensions"]
    require(isinstance(unsuspensions, list) and len(unsuspensions) == len(expected_ids), "signed-Nostr reconcile activation count invalid")
    for index, (item, object_id) in enumerate(zip(unsuspensions, expected_ids, strict=True)):
        change = closed(
            item,
            {
                "objectId",
                "target",
                "requiredUid",
                "requiredResourceVersion",
                "beforeObjectDigest",
                "patch",
                "postResourceVersion",
                "afterObjectDigest",
            },
            f"signed-Nostr reconcile activation[{index}]",
        )
        before = suspended_by_id[object_id]["object"]
        after = active_by_id[object_id]["object"]
        live = post_by_id[object_id]
        require(change["objectId"] == object_id, "signed-Nostr reconcile activation object order invalid")
        require(change["target"] == signed_nostr_object_target(before), "signed-Nostr reconcile activation target invalid")
        require(change["requiredUid"] == live["uid"], "signed-Nostr reconcile activation UID drift")
        require(change["requiredResourceVersion"] == live["resourceVersion"], "signed-Nostr reconcile activation resourceVersion drift")
        require(change["beforeObjectDigest"] == digest(before) == live["objectDigest"], "signed-Nostr reconcile activation before digest invalid")
        require(change["patch"] == {"op": "replace", "path": "/spec/suspend", "expected": True, "value": False}, "signed-Nostr reconcile activation patch widened")
        require(isinstance(change["postResourceVersion"], str) and change["postResourceVersion"].isdigit(), "signed-Nostr reconcile activation post resourceVersion invalid")
        require(int(change["postResourceVersion"]) > int(change["requiredResourceVersion"]), "signed-Nostr reconcile activation resourceVersion did not advance")
        require(change["afterObjectDigest"] == digest(after), "signed-Nostr reconcile activation after digest invalid")
    require(receipt["unsuspensionsCanonicalSha256"] == digest(unsuspensions), "signed-Nostr reconcile activation checksum invalid")
    return receipt


def verify_signed_nostr_activation_admission_freshness(
    activation_evidence: dict[str, Any],
) -> None:
    """Require one current, coherently ordered activation preflight.

    Shape validation remains timeless so an already-active render can still be
    verified by later routine promotions.  This current-time check is invoked
    only for the reviewed-public-knowledge -> signed-Nostr transition that
    grants deployment authority.
    """
    lifecycle = activation_evidence["lifecycle"]
    bootstrap = lifecycle["bootstrapReceipt"]
    live_recheck = lifecycle["activationLiveRecheck"]
    reconcile = lifecycle["reconcileActivationReceipt"]
    initial_dns = activation_evidence["gnosisRpcEgress"]["upstream"]["dnsTlsEvidence"]
    now = signed_nostr_verification_time()
    bootstrap_observed = utc_timestamp(bootstrap["observedAt"], "signed-Nostr bootstrap observedAt")
    initial_dns_observed = utc_timestamp(initial_dns["observedAt"], "signed-Nostr reviewed DNS/TLS observedAt")
    checked = utc_timestamp(live_recheck["checkedAt"], "signed-Nostr activation live recheck checkedAt")
    completed = utc_timestamp(reconcile["completedAt"], "signed-Nostr reconcile activation completedAt")
    valid_until = utc_timestamp(live_recheck["validUntil"], "signed-Nostr activation live recheck validUntil")
    require(bootstrap_observed <= checked, "signed-Nostr activation live recheck predates bootstrap")
    require(initial_dns_observed <= checked, "signed-Nostr activation live recheck predates reviewed DNS/TLS evidence")
    require(
        checked <= completed <= now <= valid_until,
        "signed-Nostr activation evidence is future-dated or outside the current five-minute preflight",
    )


def expected_signed_nostr_rollback_contract(
    managed_suspended: list[dict[str, Any]],
    bootstrap: dict[str, Any],
    reconcile: dict[str, Any],
    rollback: dict[str, Any],
) -> dict[str, Any]:
    post_by_id = {entry["objectId"]: entry for entry in bootstrap["postconditions"]}
    active_kustomizations = {entry["objectId"]: entry for entry in reconcile["unsuspensions"]}
    runtime_targets: list[dict[str, Any]] = []
    identity_targets: list[dict[str, Any]] = []
    for entry in managed_suspended:
        object_id = entry["objectId"]
        post = post_by_id[object_id]
        target = signed_nostr_object_target(entry["object"])
        if entry["class"] == "runtime":
            runtime_targets.append({
                "objectId": object_id,
                "target": target,
                "requiredUid": post["uid"],
                "requiredObjectDigest": post["objectDigest"],
                "action": "scale-zero-then-delete" if target["kind"] == "Deployment" else "delete",
                "onUidMismatch": "stop-for-adoption-review",
            })
        else:
            current_digest = (
                active_kustomizations[object_id]["afterObjectDigest"]
                if object_id in active_kustomizations
                else post["objectDigest"]
            )
            identity_targets.append({
                "objectId": object_id,
                "target": target,
                "requiredUid": post["uid"],
                "requiredObjectDigest": current_digest,
                "postSuspendObjectDigest": post["objectDigest"] if target["kind"] == "Kustomization" else None,
                "action": "suspend-then-delete" if target["kind"] == "Kustomization" else "delete",
                "onUidMismatch": "stop-for-adoption-review",
            })
    return {
        "schemaVersion": SIGNED_NOSTR_ROLLBACK_CONTRACT_SCHEMA,
        "canonicalEncoding": "canonical-json",
        "sequence": [
            "suspend-exact-reconcilers",
            "restore-four-public-boundary-bytes",
            "scale-and-delete-exact-runtime-uids",
            "delete-exact-flux-rbac-uids",
            "verify-boundary-and-total-absence",
        ],
        "deleteAuthority": "one-time-cluster-admin-exact-targets",
        "routineReconcilerDeleteAllowed": False,
        "boundaryBaseline": rollback_boundary_digest_record(rollback),
        "runtimeTargets": runtime_targets,
        "identityTargets": identity_targets,
        "absenceVerificationTargets": [signed_nostr_object_target(entry["object"]) for entry in managed_suspended],
        "uidMismatchPolicy": "fail-closed-no-delete-no-adopt",
        "completionReceiptSchema": SIGNED_NOSTR_DEACTIVATION_EVIDENCE_SCHEMA,
        "civicAuthority": "none",
    }


def deactivation_step_payload(
    sequence: int,
    action: str,
    target: dict[str, Any] | None,
    required_uid: str | None,
    before_digest: str | None,
    result: str,
) -> dict[str, Any]:
    return {
        "sequence": sequence,
        "action": action,
        "target": target,
        "requiredUid": required_uid,
        "beforeObjectDigest": before_digest,
        "result": result,
    }


def expected_signed_nostr_deactivation_steps(contract: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    sequence = 1
    for target in contract["identityTargets"]:
        if target["target"]["kind"] != "Kustomization":
            continue
        payload = deactivation_step_payload(
            sequence,
            "suspend-exact-reconciler",
            target["target"],
            target["requiredUid"],
            target["requiredObjectDigest"],
            "suspended-and-verified",
        )
        steps.append({**payload, "receiptDigest": digest(payload)})
        sequence += 1
    payload = deactivation_step_payload(
        sequence,
        "restore-four-public-boundary-bytes",
        None,
        None,
        digest(contract["boundaryBaseline"]),
        "restored-and-verified",
    )
    steps.append({**payload, "receiptDigest": digest(payload)})
    sequence += 1
    for target in contract["runtimeTargets"]:
        payload = deactivation_step_payload(
            sequence,
            target["action"],
            target["target"],
            target["requiredUid"],
            target["requiredObjectDigest"],
            "absent-and-verified",
        )
        steps.append({**payload, "receiptDigest": digest(payload)})
        sequence += 1
    # Kustomizations are removed first after workloads are gone; RoleBindings,
    # Roles and ServiceAccounts then lose authority in deterministic order.
    identity_order = {"Kustomization": 0, "RoleBinding": 1, "Role": 2, "ServiceAccount": 3}
    for target in sorted(
        contract["identityTargets"],
        key=lambda item: (identity_order[item["target"]["kind"]], item["objectId"]),
    ):
        payload = deactivation_step_payload(
            sequence,
            "delete-exact-flux-identity",
            target["target"],
            target["requiredUid"],
            target["postSuspendObjectDigest"] or target["requiredObjectDigest"],
            "absent-and-verified",
        )
        steps.append({**payload, "receiptDigest": digest(payload)})
        sequence += 1
    return steps


def verify_signed_nostr_deactivation_evidence(
    value: Any,
    activation_evidence: dict[str, Any],
    rollback_contract: dict[str, Any],
) -> dict[str, Any]:
    receipt = closed(
        value,
        {
            "schemaVersion",
            "canonicalEncoding",
            "status",
            "startedAt",
            "completedAt",
            "validUntil",
            "maxAgeSeconds",
            "activationEvidenceCanonicalSha256",
            "rollbackContractCanonicalSha256",
            "stepReceipts",
            "boundaryVerification",
            "absenceVerification",
            "effects",
        },
        "signed-Nostr deactivation evidence",
    )
    require(receipt["schemaVersion"] == SIGNED_NOSTR_DEACTIVATION_EVIDENCE_SCHEMA, "signed-Nostr deactivation evidence schema invalid")
    require(receipt["canonicalEncoding"] == "canonical-json", "signed-Nostr deactivation encoding invalid")
    require(receipt["status"] == "completed-and-verified", "signed-Nostr deactivation status invalid")
    started = utc_timestamp(receipt["startedAt"], "signed-Nostr deactivation startedAt")
    completed = utc_timestamp(receipt["completedAt"], "signed-Nostr deactivation completedAt")
    valid_until = utc_timestamp(receipt["validUntil"], "signed-Nostr deactivation validUntil")
    now = signed_nostr_verification_time()
    require(0 <= duration_seconds(started, completed) <= 900, "signed-Nostr deactivation duration invalid")
    require(receipt["maxAgeSeconds"] == 300, "signed-Nostr deactivation freshness budget invalid")
    require(
        0 < duration_seconds(completed, valid_until) <= receipt["maxAgeSeconds"],
        "signed-Nostr deactivation validity window invalid",
    )
    require(
        started <= completed <= now <= valid_until,
        "signed-Nostr deactivation evidence is future-dated, expired, or replayed",
    )
    require(receipt["activationEvidenceCanonicalSha256"] == digest(activation_evidence), "signed-Nostr deactivation activation binding invalid")
    require(receipt["rollbackContractCanonicalSha256"] == digest(rollback_contract), "signed-Nostr deactivation contract binding invalid")
    require(receipt["stepReceipts"] == expected_signed_nostr_deactivation_steps(rollback_contract), "signed-Nostr deactivation step receipt set incomplete or drifted")
    require(receipt["boundaryVerification"] == {
        "verifiedAt": receipt["completedAt"],
        "status": "exact-baseline-restored",
        **rollback_contract["boundaryBaseline"],
    }, "signed-Nostr deactivation boundary verification invalid")
    require(receipt["absenceVerification"] == {
        "verifiedAt": receipt["completedAt"],
        "status": "all-exact-targets-absent",
        "targets": rollback_contract["absenceVerificationTargets"],
    }, "signed-Nostr deactivation absence verification invalid")
    require(receipt["effects"] == {
        "clusterMutation": True,
        "civicMutation": False,
        "secretRead": False,
        "secretWrite": False,
        "uidMismatchObserved": False,
        "unrelatedObjectMutation": False,
    }, "signed-Nostr deactivation effects invalid")
    return receipt


def verify_signed_nostr_runtime_pin(value: Any) -> dict[str, Any]:
    pin = closed(
        value,
        {
            "schemaVersion",
            "publisherPin",
            "publisherPinCanonicalSha256",
            "activationEvidence",
            "rollback",
        },
        "signed-Nostr runtime-pin",
    )
    require(pin["schemaVersion"] == "roebel_signed_nostr_activation_render_pin_v1", "signed-Nostr runtime-pin schema invalid")
    publisher = closed(
        pin["publisherPin"],
        {"schemaVersion", "sourceRevision", "components", "civicAuthority", "deploymentEffect"},
        "signed-Nostr publisher pin",
    )
    require(publisher["schemaVersion"] == "roebel_e2e_runtime_pin_v1", "signed-Nostr publisher pin schema invalid")
    require(isinstance(publisher["sourceRevision"], str) and REVISION.fullmatch(publisher["sourceRevision"]), "signed-Nostr source revision invalid")
    require(publisher["civicAuthority"] == "none" and publisher["deploymentEffect"] is False, "signed-Nostr authority binding invalid")
    require(
        pin["publisherPinCanonicalSha256"] == digest(publisher),
        "signed-Nostr publisher pin canonical checksum invalid",
    )
    rollback = closed(
        pin["rollback"],
        {"fromRender", "integritySha256", "webIngressSha256", "publicMeckyNetworkPolicySha256", "boundaryReceiptSha256"},
        "signed-Nostr rollback record",
    )
    require(rollback["fromRender"] == "reviewed-public-knowledge", "signed-Nostr rollback base invalid")
    for field in ("integritySha256", "webIngressSha256", "publicMeckyNetworkPolicySha256", "boundaryReceiptSha256"):
        require(isinstance(rollback[field], str) and SHA256.fullmatch(rollback[field]), f"signed-Nostr rollback {field} invalid")
    evidence = pin["activationEvidence"]
    if evidence == {
        "status": "pending-separate-review",
        "gnosisRpcEgress": None,
        "fluxIdentity": None,
        "anonymousDigestPullReceipts": None,
    }:
        # A temporary, explicitly closed placeholder is the only activation
        # evidence accepted by this bootstrap.  A later full record is parsed
        # below, but still cannot activate until it equals the protected
        # approved-policy constant.
        pass
    else:
        verify_signed_nostr_activation_evidence(
            evidence,
            publisher,
            pin["publisherPinCanonicalSha256"],
            rollback,
        )
    require(isinstance(publisher["components"], list) and len(publisher["components"]) == 2, "signed-Nostr runtime pin component count invalid")
    parsed: dict[str, dict[str, str]] = {}
    for index, entry in enumerate(publisher["components"]):
        component = closed(entry, {"component", "image", "manifestDigest", "provenance", "sbomAttestation", "workflowIdentity"}, f"signed-Nostr pin component[{index}]")
        expected = SIGNED_NOSTR_PUBLISHER_COMPONENT_ORDER[index]
        require(component["component"] == expected, "signed-Nostr runtime pin component order invalid")
        expected_image = SIGNED_NOSTR_IMAGES["workbench" if expected == "roebel-e2e-workbench" else "citizen-relay"]
        require(component["image"] == expected_image, "signed-Nostr runtime pin image repository invalid")
        require(isinstance(component["manifestDigest"], str) and SHA256.fullmatch(component["manifestDigest"]), "signed-Nostr runtime pin digest invalid")
        require(component["workflowIdentity"] == SIGNED_NOSTR_WORKFLOW, "signed-Nostr component workflow identity invalid")
        for key in ("provenance", "sbomAttestation"):
            proof = closed(component[key], {"id", "url"}, f"signed-Nostr {key}")
            require(isinstance(proof["id"], str) and proof["id"], f"signed-Nostr {key} id invalid")
            require(isinstance(proof["url"], str) and proof["url"].startswith("https://github.com/GiraeffleAeffle/Roebel-App/"), f"signed-Nostr {key} URL invalid")
        parsed[expected] = component
    return {"pin": pin, "publisherPin": publisher, "images": parsed}


def verify_signed_nostr_attestation_receipt(
    value: Any,
    publisher_receipt: dict[str, Any],
    manifest_digest: str,
    label: str,
) -> dict[str, str]:
    receipt = closed(
        value,
        {"receiptId", "receiptUrl", "attestationDigest", "subjectDigest"},
        label,
    )
    require(receipt["receiptId"] == publisher_receipt["id"], f"{label} id binding invalid")
    require(receipt["receiptUrl"] == publisher_receipt["url"], f"{label} URL binding invalid")
    require(isinstance(receipt["attestationDigest"], str) and SHA256.fullmatch(receipt["attestationDigest"]), f"{label} digest invalid")
    require(receipt["subjectDigest"] == manifest_digest, f"{label} subject binding invalid")
    return receipt


def verify_signed_nostr_object_receipt(
    value: Any,
    expected_object: dict[str, Any],
    label: str,
) -> dict[str, Any]:
    receipt = closed(value, {"object", "objectDigest"}, label)
    require(receipt["object"] == expected_object, f"{label} object invalid")
    require(
        isinstance(receipt["objectDigest"], str) and SHA256.fullmatch(receipt["objectDigest"]),
        f"{label} digest invalid",
    )
    require(receipt["objectDigest"] == digest(expected_object), f"{label} digest binding invalid")
    return receipt


def verify_signed_nostr_activation_evidence(
    value: Any,
    publisher_pin: dict[str, Any],
    publisher_pin_canonical_sha256: str,
    rollback_record: dict[str, Any],
) -> dict[str, Any]:
    """Validate the complete future activation record without authorizing it.

    The shape is deliberately closed.  The policy constant below performs the
    separate approval step: validation alone never turns a candidate record
    into authority to materialise the runtime.
    """
    evidence = closed(
        value,
        {
            "schemaVersion",
            "canonicalEncoding",
            "status",
            "publisherPinCanonicalSha256",
            "publisherSourceRevision",
            "publisherWorkflowIdentity",
            "components",
            "fluxBindings",
            "gnosisRpcEgress",
            "anonymousDigestPullReceipts",
            "lifecycle",
        },
        "signed-Nostr activation evidence",
    )
    require(evidence["schemaVersion"] == SIGNED_NOSTR_ACTIVATION_EVIDENCE_SCHEMA, "signed-Nostr activation evidence schema invalid")
    require(evidence["canonicalEncoding"] == "canonical-json", "signed-Nostr activation evidence canonical encoding invalid")
    require(evidence["status"] == "reviewed", "signed-Nostr activation evidence status invalid")
    require(evidence["publisherPinCanonicalSha256"] == publisher_pin_canonical_sha256, "signed-Nostr activation evidence publisher checksum binding invalid")
    require(evidence["publisherSourceRevision"] == publisher_pin["sourceRevision"], "signed-Nostr activation evidence source binding invalid")
    require(evidence["publisherWorkflowIdentity"] == SIGNED_NOSTR_WORKFLOW, "signed-Nostr activation evidence workflow binding invalid")

    require(isinstance(evidence["components"], list) and len(evidence["components"]) == 2, "signed-Nostr activation evidence component count invalid")
    publisher_components = {entry["component"]: entry for entry in publisher_pin["components"]}
    attestation_digests: set[str] = set()
    attestation_ids: set[str] = set()
    for index, item in enumerate(evidence["components"]):
        component = closed(
            item,
            {"component", "imageRepository", "manifestDigest", "provenance", "sbomAttestation"},
            f"signed-Nostr activation component[{index}]",
        )
        expected_name = SIGNED_NOSTR_ACTIVATION_COMPONENT_ORDER[index]
        require(component["component"] == expected_name, "signed-Nostr activation component order invalid")
        publisher_component = publisher_components[expected_name]
        require(component["imageRepository"] == publisher_component["image"], "signed-Nostr activation component image binding invalid")
        require(component["manifestDigest"] == publisher_component["manifestDigest"], "signed-Nostr activation component manifest binding invalid")
        provenance = verify_signed_nostr_attestation_receipt(component["provenance"], publisher_component["provenance"], publisher_component["manifestDigest"], f"signed-Nostr activation component[{index}] provenance")
        sbom = verify_signed_nostr_attestation_receipt(component["sbomAttestation"], publisher_component["sbomAttestation"], publisher_component["manifestDigest"], f"signed-Nostr activation component[{index}] SBOM")
        require(provenance["receiptId"] != sbom["receiptId"], "signed-Nostr activation component provenance/SBOM receipt id reused")
        require(provenance["attestationDigest"] != sbom["attestationDigest"], "signed-Nostr activation component provenance/SBOM digest reused")
        for receipt in (provenance, sbom):
            require(receipt["attestationDigest"] not in attestation_digests, "signed-Nostr activation attestation digest reused")
            require(receipt["receiptId"] not in attestation_ids, "signed-Nostr activation attestation receipt id reused")
            attestation_digests.add(receipt["attestationDigest"])
            attestation_ids.add(receipt["receiptId"])

    require(isinstance(evidence["fluxBindings"], list) and len(evidence["fluxBindings"]) == 3, "signed-Nostr Flux binding count invalid")
    for index, item in enumerate(evidence["fluxBindings"]):
        binding = closed(
            item,
            {"component", "kustomization", "serviceAccount", "role", "roleBinding"},
            f"signed-Nostr Flux binding[{index}]",
        )
        expected_component = SIGNED_NOSTR_FLUX_BINDING_ORDER[index]
        require(binding["component"] == expected_component, "signed-Nostr Flux binding component order invalid")
        expected_flux = expected_signed_nostr_flux_objects(expected_component)
        for kind in ("serviceAccount", "role", "roleBinding"):
            verify_signed_nostr_object_receipt(
                binding[kind],
                expected_flux[kind],
                f"signed-Nostr Flux binding[{index}] {kind}",
            )
        verify_signed_nostr_object_receipt(
            binding["kustomization"],
            expected_flux["kustomization"],
            f"signed-Nostr Flux binding[{index}] Kustomization",
        )

    gnosis = closed(
        evidence["gnosisRpcEgress"],
        {"chainId", "upstream", "privateProxy", "workbenchNetworkPolicy"},
        "signed-Nostr Gnosis RPC egress evidence",
    )
    require(gnosis["chainId"] == 100, "signed-Nostr Gnosis chain id invalid")
    upstream = closed(gnosis["upstream"], {"scheme", "host", "port", "pinnedIpv4Cidr", "allowedMethods", "dnsTlsEvidence"}, "signed-Nostr Gnosis upstream evidence")
    require({key: upstream[key] for key in ("scheme", "host", "port", "pinnedIpv4Cidr", "allowedMethods")} == {
        "scheme": "https",
        "host": SIGNED_NOSTR_GNOSIS_UPSTREAM_HOST,
        "port": SIGNED_NOSTR_GNOSIS_UPSTREAM_PORT,
        "pinnedIpv4Cidr": SIGNED_NOSTR_GNOSIS_UPSTREAM_IPV4_CIDR,
        "allowedMethods": list(SIGNED_NOSTR_GNOSIS_ALLOWED_METHODS),
    }, "signed-Nostr Gnosis upstream invalid")
    initial_dns_tls = verify_signed_nostr_dns_tls_evidence(
        upstream["dnsTlsEvidence"],
        "signed-Nostr reviewed DNS/TLS evidence",
    )
    private_proxy = closed(
        gnosis["privateProxy"],
        {"name", "namespace", "port", "runtimeRole", "deployment", "service", "networkPolicy"},
        "signed-Nostr Gnosis private proxy evidence",
    )
    require(private_proxy["name"] == SIGNED_NOSTR_GNOSIS_PROXY_NAME, "signed-Nostr Gnosis private proxy name invalid")
    require(private_proxy["namespace"] == SIGNED_NOSTR_WEB_NAMESPACE, "signed-Nostr Gnosis private proxy namespace invalid")
    require(private_proxy["port"] == SIGNED_NOSTR_GNOSIS_PROXY_PORT, "signed-Nostr Gnosis private proxy port invalid")
    require(private_proxy["runtimeRole"] == "gnosis-rpc-proxy", "signed-Nostr Gnosis private proxy runtime role invalid")
    workbench_publisher = publisher_components["roebel-e2e-workbench"]
    workbench_image = f"{workbench_publisher['image']}@{workbench_publisher['manifestDigest']}"
    verify_signed_nostr_object_receipt(private_proxy["deployment"], expected_signed_nostr_gnosis_private_proxy_deployment(workbench_image), "signed-Nostr Gnosis private proxy Deployment")
    verify_signed_nostr_object_receipt(private_proxy["service"], expected_signed_nostr_gnosis_private_proxy_service(), "signed-Nostr Gnosis private proxy Service")
    verify_signed_nostr_object_receipt(private_proxy["networkPolicy"], expected_signed_nostr_gnosis_private_proxy_network_policy(), "signed-Nostr Gnosis private proxy NetworkPolicy")
    verify_signed_nostr_object_receipt(gnosis["workbenchNetworkPolicy"], expected_signed_nostr_workbench_network_policy(), "signed-Nostr workbench NetworkPolicy")

    verify_signed_nostr_anonymous_digest_pull_receipts(
        evidence["anonymousDigestPullReceipts"],
        publisher_pin,
        publisher_pin_canonical_sha256,
    )

    managed_suspended = expected_signed_nostr_managed_objects(
        publisher_pin,
        suspended_flux=True,
    )
    managed_active = expected_signed_nostr_managed_objects(
        publisher_pin,
        suspended_flux=False,
    )
    lifecycle = closed(
        evidence["lifecycle"],
        {
            "livePreconditions",
            "bootstrapReceipt",
            "activationLiveRecheck",
            "reconcileActivationReceipt",
            "rollbackContract",
        },
        "signed-Nostr lifecycle evidence",
    )
    preconditions = verify_signed_nostr_live_preconditions(
        lifecycle["livePreconditions"],
        managed_suspended,
    )
    bootstrap = verify_signed_nostr_bootstrap_receipt(
        lifecycle["bootstrapReceipt"],
        preconditions,
        managed_suspended,
    )
    live_recheck = verify_signed_nostr_activation_live_recheck(
        lifecycle["activationLiveRecheck"],
        bootstrap,
        rollback_record,
        initial_dns_tls,
    )
    reconcile = verify_signed_nostr_reconcile_activation(
        lifecycle["reconcileActivationReceipt"],
        live_recheck,
        bootstrap,
        managed_suspended,
        managed_active,
    )
    require(
        lifecycle["rollbackContract"]
        == expected_signed_nostr_rollback_contract(
            managed_suspended,
            bootstrap,
            reconcile,
            rollback_record,
        ),
        "signed-Nostr rollback contract incomplete or drifted",
    )
    return evidence


def verify_signed_nostr_anonymous_digest_pull_receipts(
    value: Any,
    publisher_pin: dict[str, Any],
    publisher_pin_canonical_sha256: str,
) -> None:
    require(isinstance(value, list) and len(value) == 2, "signed-Nostr anonymous digest receipt count invalid")
    require(
        [entry["component"] for entry in publisher_pin["components"]] == list(SIGNED_NOSTR_PUBLISHER_COMPONENT_ORDER),
        "signed-Nostr publisher component order invalid",
    )
    publisher_components = {entry["component"]: entry for entry in publisher_pin["components"]}
    expected = {
        "roebel-e2e-workbench": "ghcr.io/giraeffleaeffle/roebel-e2e-workbench",
        "roebel-staging-relay": "ghcr.io/giraeffleaeffle/roebel-staging-relay",
    }
    seen: set[str] = set()
    for index, value_item in enumerate(value):
        receipt = closed(
            value_item,
            {
                "schemaVersion",
                "canonicalEncoding",
                "publisherPinCanonicalSha256",
                "component",
                "imageRepository",
                "manifestDigest",
                "sourceRevision",
                "authContext",
                "authConfigCanonicalSha256",
                "resolverIdentity",
                "resolvedManifestDigest",
                "receiptDigest",
            },
            f"signed-Nostr anonymous digest receipt[{index}]",
        )
        require(
            receipt["schemaVersion"] == SIGNED_NOSTR_ANONYMOUS_DIGEST_PULL_RECEIPT_SCHEMA,
            "signed-Nostr anonymous digest receipt schema invalid",
        )
        require(
            receipt["canonicalEncoding"] == "canonical-json",
            "signed-Nostr anonymous digest receipt canonical encoding invalid",
        )
        require(
            receipt["publisherPinCanonicalSha256"] == publisher_pin_canonical_sha256,
            "signed-Nostr anonymous digest receipt publisher checksum binding invalid",
        )
        component = receipt["component"]
        require(
            component == SIGNED_NOSTR_PUBLISHER_COMPONENT_ORDER[index],
            "signed-Nostr anonymous digest receipt component order invalid",
        )
        require(component in expected and component not in seen, "signed-Nostr anonymous digest receipt component invalid")
        seen.add(component)
        publisher = publisher_components[component]
        require(receipt["imageRepository"] == expected[component] == publisher["image"], "signed-Nostr anonymous digest receipt image invalid")
        require(receipt["manifestDigest"] == publisher["manifestDigest"], "signed-Nostr anonymous digest receipt manifest binding invalid")
        require(receipt["sourceRevision"] == publisher_pin["sourceRevision"], "signed-Nostr anonymous digest receipt source binding invalid")
        require(receipt["authContext"] == "clean-empty-auth-config", "signed-Nostr anonymous digest receipt auth context invalid")
        require(
            receipt["authConfigCanonicalSha256"] == SIGNED_NOSTR_CLEAN_EMPTY_AUTH_CONFIG_SHA256,
            "signed-Nostr anonymous digest receipt auth hash invalid",
        )
        require(receipt["resolverIdentity"] == "oras-resolve-anonymous", "signed-Nostr anonymous digest receipt resolver invalid")
        require(receipt["resolvedManifestDigest"] == publisher["manifestDigest"], "signed-Nostr anonymous digest receipt resolved digest invalid")
        require(
            receipt["receiptDigest"] == digest({key: item for key, item in receipt.items() if key != "receiptDigest"}),
            "signed-Nostr anonymous digest receipt checksum invalid",
        )
    require(seen == set(expected), "signed-Nostr anonymous digest receipt component set invalid")


def signed_nostr_runtime_image(component: str, runtime_pin: dict[str, Any]) -> str:
    source_component = "roebel-e2e-workbench" if component == "workbench" else "roebel-staging-relay"
    record = runtime_pin["images"][source_component]
    return f"{record['image']}@{record['manifestDigest']}"


def signed_nostr_relay_environment(component: str) -> list[dict[str, Any]]:
    base = [
        {"name": "RELAY_NAME", "value": component},
        {"name": "RELAY_PORT", "value": "18081"},
        {"name": "RELAY_BIND_HOST", "value": "0.0.0.0"},
        {"name": "RELAY_WEBSOCKET_PATH", "value": f"/{component}"},
        {"name": "RELAY_EVENT_STORE", "value": "/relay/events.ndjson"},
        {"name": "RELAY_MAX_EVENT_STORE_BYTES", "value": "67108864"},
        {"name": "RELAY_MAX_EVENT_COUNT", "value": "50000"},
        {
            "name": "RELAY_ALLOWED_PUBKEYS",
            "valueFrom": {"secretKeyRef": {"key": "MECKY_PUBKEY", "name": "roebel-signed-nostr-runtime", "optional": False}},
        },
    ]
    if component == "citizen-relay":
        base.extend([
            {"name": "RELAY_ADMISSION_STORE", "value": "/relay/admissions.ndjson"},
            {"name": "RELAY_MAX_ADMISSION_STORE_BYTES", "value": "16777216"},
            {"name": "RELAY_MAX_ADMISSION_COUNT", "value": "10000"},
            {
                "name": "RELAY_ADMISSION_TOKEN",
                "valueFrom": {"secretKeyRef": {"key": "CITIZEN_RELAY_ADMISSION_TOKEN", "name": "roebel-signed-nostr-runtime", "optional": False}},
            },
        ])
    return base


def expected_signed_nostr_resources(runtime_pin: dict[str, Any]) -> dict[str, Any]:
    """Return the whole future runtime shape without materialising manifests.

    The renderer remains unavailable while the evidence gate below is pending;
    this function exists so the protected verifier can constrain that later
    review to one exact topology rather than accepting arbitrary YAML.
    """
    resources: dict[str, Any] = {}
    for component in SIGNED_NOSTR_COMPONENTS:
        labels = signed_nostr_labels(component)
        namespace = signed_nostr_namespace(component)
        port = SIGNED_NOSTR_PORTS[component]
        if component == "workbench":
            environment = [
                {"name": "WORKBENCH_MODE", "value": "public-signed-only"},
                {
                    "name": "LEGACY_SYNTHETIC_PUBKEYS_JSON",
                    "value": "[\"21abe1bf2bf9a906d356488d107db36d505b55d54c20ab46792fcd31c4e1b88a\",\"7c6ed2e0b6ae1ea67523d055b1194e55036522c397e589c2bb20f0c68b558974\"]",
                },
                {"name": "WORKBENCH_PORT", "value": "18083"},
                {"name": "WORKBENCH_BIND_HOST", "value": "0.0.0.0"},
                {"name": "CITIZEN_RELAY_URL", "value": "ws://citizen-relay.stadtstack-roebel-staging-lab.svc.cluster.local:18081"},
                {"name": "AGENT_RELAY_URL", "value": "ws://agent-relay.stadtstack-roebel-staging-lab.svc.cluster.local:18081"},
                {"name": "GNOSIS_RPC_URL", "value": f"http://{SIGNED_NOSTR_GNOSIS_PROXY_NAME}.{SIGNED_NOSTR_WEB_NAMESPACE}.svc.cluster.local:{SIGNED_NOSTR_GNOSIS_PROXY_PORT}"},
                {"name": "MECKY_PUBKEY", "valueFrom": {"secretKeyRef": {"key": "MECKY_PUBKEY", "name": "roebel-signed-nostr-runtime", "optional": False}}},
                {"name": "CITIZEN_RELAY_ADMISSION_TOKEN", "valueFrom": {"secretKeyRef": {"key": "CITIZEN_RELAY_ADMISSION_TOKEN", "name": "roebel-signed-nostr-runtime", "optional": False}}},
            ]
            pod_extra: dict[str, Any] = {}
            container_extra: dict[str, Any] = {}
        else:
            environment = signed_nostr_relay_environment(component)
            pod_extra = {"volumes": [{"emptyDir": {"sizeLimit": "128Mi"}, "name": "relay-store"}]}
            container_extra = {"volumeMounts": [{"mountPath": "/relay", "name": "relay-store"}]}
        container = {
            "env": environment,
            "image": signed_nostr_runtime_image(component, runtime_pin),
            "imagePullPolicy": "IfNotPresent",
            "livenessProbe": {"failureThreshold": 3, "periodSeconds": 20, "successThreshold": 1, "tcpSocket": {"port": "http"}, "timeoutSeconds": 3},
            "name": SIGNED_NOSTR_NAMES[component],
            "ports": [{"containerPort": port, "name": "http", "protocol": "TCP"}],
            "readinessProbe": {"failureThreshold": 3, "periodSeconds": 10, "successThreshold": 1, "tcpSocket": {"port": "http"}, "timeoutSeconds": 3},
            "resources": {"limits": {"cpu": "250m", "ephemeral-storage": "128Mi", "memory": "112Mi"}, "requests": {"cpu": "10m", "ephemeral-storage": "64Mi", "memory": "32Mi"}},
            "securityContext": signed_nostr_container_security_context(),
            "startupProbe": {"failureThreshold": 30, "periodSeconds": 2, "successThreshold": 1, "tcpSocket": {"port": "http"}, "timeoutSeconds": 3},
            **container_extra,
        }
        deployment = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"labels": labels, "name": SIGNED_NOSTR_NAMES[component], "namespace": namespace},
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": labels},
                "template": {
                    "metadata": {"labels": labels},
                    "spec": {
                        "automountServiceAccountToken": False,
                        "containers": [container],
                        "restartPolicy": "Always",
                        "securityContext": signed_nostr_pod_security_context(),
                        **pod_extra,
                    },
                },
            },
        }
        service = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"labels": labels, "name": SIGNED_NOSTR_NAMES[component], "namespace": namespace},
            "spec": {"ports": [{"name": "http", "port": port, "protocol": "TCP", "targetPort": "http"}], "selector": labels, "type": "ClusterIP"},
        }
        resources[component] = {"deployment": deployment, "service": service}

    workbench_labels = signed_nostr_labels("workbench")
    relay_from = [
        {
            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": SIGNED_NOSTR_WEB_NAMESPACE}},
            "podSelector": {"matchLabels": workbench_labels},
        },
        {
            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": SIGNED_NOSTR_NAMESPACE}},
            "podSelector": {"matchLabels": PUBLIC_MECKY_LABELS},
        },
    ]
    workbench_image = signed_nostr_runtime_image("workbench", runtime_pin)
    resources["workbench"]["networkPolicy"] = expected_signed_nostr_workbench_network_policy()
    resources["workbench"]["gnosisProxyDeployment"] = expected_signed_nostr_gnosis_private_proxy_deployment(workbench_image)
    resources["workbench"]["gnosisProxyService"] = expected_signed_nostr_gnosis_private_proxy_service()
    resources["workbench"]["gnosisProxyNetworkPolicy"] = expected_signed_nostr_gnosis_private_proxy_network_policy()
    for relay in ("citizen-relay", "agent-relay"):
        labels = signed_nostr_labels(relay)
        resources[relay]["networkPolicy"] = {
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"labels": labels, "name": SIGNED_NOSTR_NAMES[relay], "namespace": SIGNED_NOSTR_NAMESPACE},
            "spec": {"egress": [], "ingress": [{"from": relay_from, "ports": [{"port": 18081, "protocol": "TCP"}]}], "podSelector": {"matchLabels": labels}, "policyTypes": ["Ingress", "Egress"]},
        }
    for component in SIGNED_NOSTR_COMPONENTS:
        extra = ""
        if component == "workbench":
            extra = (
                "  - gnosis-proxy-deployment.json\n"
                "  - gnosis-proxy-service.json\n"
                "  - gnosis-proxy-networkpolicy.json\n"
            )
        resources[component]["kustomization"] = (
            "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n"
            "  - deployment.json\n  - service.json\n  - networkpolicy.json\n"
            + extra
        )
    return resources


def expected_public_mecky_network_policy(
    reviewed_egress: bool,
    signed_nostr: bool = False,
    reviewed_web_source: bool = False,
) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "ingress": [{
            "from": [{
                "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "stadtstack-roebel-web-preview"}},
                "podSelector": {"matchLabels": {"app.kubernetes.io/name": "roebel-web-presentation"}},
            }],
            "ports": [{"port": 18084, "protocol": "TCP"}],
        }],
        "podSelector": {"matchLabels": PUBLIC_MECKY_LABELS},
        "policyTypes": ["Ingress"],
    }
    if reviewed_egress:
        spec = {
            "egress": [{
                "to": [{
                    "namespaceSelector": {"matchLabels": {
                        "kubernetes.io/metadata.name": REVIEWED_PUBLIC_KNOWLEDGE_NAMESPACE,
                    }},
                    "podSelector": {"matchLabels": PUBLIC_MECKY_REVIEWED_EGRESS_DESTINATION_LABELS},
                }],
                "ports": [{"port": 8080, "protocol": "TCP"}],
            }],
            **spec,
            "policyTypes": ["Ingress", "Egress"],
        }
    if signed_nostr:
        require(reviewed_egress, "signed-Nostr Public Mecky policy requires reviewed knowledge egress")
        spec = {
            **spec,
            "egress": [
                *spec["egress"],
                *[
                    {
                        "to": [{
                            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": SIGNED_NOSTR_NAMESPACE}},
                            "podSelector": {"matchLabels": signed_nostr_labels(relay)},
                        }],
                        "ports": [{"port": 18081, "protocol": "TCP"}],
                    }
                    for relay in ("citizen-relay", "agent-relay")
                ],
            ],
        }
    if reviewed_web_source:
        require(reviewed_egress, "reviewed Web source requires reviewed knowledge egress")
        spec = {
            **spec,
            "egress": [
                *spec["egress"],
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
            ],
        }
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "labels": PUBLIC_MECKY_NETWORK_POLICY_LABELS,
            "name": "public-mecky-chat-from-web",
            "namespace": "stadtstack-roebel-staging-lab",
        },
        "spec": spec,
    }


def verify_signed_nostr(root: Path) -> dict[str, Any]:
    runtime_pin = verify_signed_nostr_runtime_pin(load_json(root / SIGNED_NOSTR_RUNTIME_PIN))
    expected = expected_signed_nostr_resources(runtime_pin)
    actual: dict[str, Any] = {}
    for component in SIGNED_NOSTR_COMPONENTS:
        component_root = root / SIGNED_NOSTR_ROOT / component
        deployment = load_json(component_root / "deployment.json")
        service = load_json(component_root / "service.json")
        network_policy = load_json(component_root / "networkpolicy.json")
        kustomization = (component_root / "kustomization.yaml").read_text()
        require(deployment == expected[component]["deployment"], f"signed-Nostr {component} Deployment drift")
        require(service == expected[component]["service"], f"signed-Nostr {component} Service drift")
        require(network_policy == expected[component]["networkPolicy"], f"signed-Nostr {component} NetworkPolicy drift")
        require(kustomization == expected[component]["kustomization"], f"signed-Nostr {component} Flux path widened")
        actual[component] = {
            "deployment": deployment,
            "service": service,
            "networkPolicy": network_policy,
            "kustomization": kustomization,
        }
        if component == "workbench":
            proxy_deployment = load_json(component_root / "gnosis-proxy-deployment.json")
            proxy_service = load_json(component_root / "gnosis-proxy-service.json")
            proxy_policy = load_json(component_root / "gnosis-proxy-networkpolicy.json")
            require(proxy_deployment == expected[component]["gnosisProxyDeployment"], "signed-Nostr Gnosis proxy Deployment drift")
            require(proxy_service == expected[component]["gnosisProxyService"], "signed-Nostr Gnosis proxy Service drift")
            require(proxy_policy == expected[component]["gnosisProxyNetworkPolicy"], "signed-Nostr Gnosis proxy NetworkPolicy drift")
            actual[component]["gnosisProxyDeployment"] = proxy_deployment
            actual[component]["gnosisProxyService"] = proxy_service
            actual[component]["gnosisProxyNetworkPolicy"] = proxy_policy
    # Both relay Deployment images bind to the one relay digest from the pin;
    # this prevents a citizen/agent mixed build from entering staging.
    citizen_image = actual["citizen-relay"]["deployment"]["spec"]["template"]["spec"]["containers"][0]["image"]
    agent_image = actual["agent-relay"]["deployment"]["spec"]["template"]["spec"]["containers"][0]["image"]
    require(citizen_image == agent_image, "signed-Nostr relays must share one immutable digest")
    approved = SIGNED_NOSTR_APPROVED_ACTIVATION_EVIDENCE
    require(
        approved is not None,
        "signed-Nostr activation blocked: complete Gnosis, Flux, provenance, and anonymous-pull evidence require separate review",
    )
    require(
        runtime_pin["pin"]["activationEvidence"] == approved,
        "signed-Nostr activation evidence does not equal the exact approved policy record",
    )
    verify_signed_nostr_activation_evidence(
        approved,
        runtime_pin["publisherPin"],
        runtime_pin["pin"]["publisherPinCanonicalSha256"],
        runtime_pin["pin"]["rollback"],
    )
    return {"runtimePin": runtime_pin["pin"], "components": actual}


def verify_public_mecky_network_policy(
    root: Path,
    reviewed_knowledge: bool,
    signed_nostr: bool,
    reviewed_web_source: bool,
) -> tuple[dict[str, Any], bool, bool]:
    policy = load_json(root / RENDER_ROOT / "public-mecky/networkpolicy.json")
    legacy = expected_public_mecky_network_policy(False)
    reviewed = expected_public_mecky_network_policy(True)
    signed = expected_public_mecky_network_policy(True, True)
    reviewed_web = expected_public_mecky_network_policy(True, False, True)
    signed_web = expected_public_mecky_network_policy(True, True, True)
    require(
        policy in (legacy, reviewed, signed, reviewed_web, signed_web),
        "Public Mecky NetworkPolicy drift",
    )
    reviewed_egress = policy != legacy
    signed_egress = policy in (signed, signed_web)
    reviewed_web_egress = policy in (reviewed_web, signed_web)
    require(
        not reviewed_egress or reviewed_knowledge,
        "Public Mecky reviewed-runtime egress requires the complete reviewed runtime render",
    )
    require(not signed_egress or signed_nostr, "Public Mecky relay egress requires the complete signed-Nostr render")
    require(not signed_nostr or signed_egress, "signed-Nostr render requires exact Public Mecky relay egress")
    require(
        reviewed_web_source == reviewed_web_egress,
        "Public Mecky reviewed Web source requires exact matching egress",
    )
    return policy, reviewed_egress, reviewed_web_egress


def tracer_postgrest_web_egress() -> dict[str, Any]:
    return {
        "to": [{
            "namespaceSelector": {
                "matchLabels": {
                    "kubernetes.io/metadata.name": TRACER_DATA_PLANE.NAMESPACE,
                },
            },
            "podSelector": {
                "matchLabels": TRACER_DATA_PLANE.POSTGREST_LABELS,
            },
        }],
        "ports": [{"port": TRACER_DATA_PLANE.POSTGREST_PORT, "protocol": "TCP"}],
    }


def expected_web_network_policy(
    civic_projection_route: bool = False,
    tracer_feed_route: bool = False,
    reviewed_web_source: bool = False,
) -> dict[str, Any]:
    policy = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "labels": {
                "app.kubernetes.io/component": "readonly-presentation",
                "app.kubernetes.io/name": "roebel-web-presentation",
                "app.kubernetes.io/part-of": "stadtstack",
                "stadtstack.io/authority": "none",
            },
            "name": "roebel-web-presentation",
            "namespace": "stadtstack-roebel-web-preview",
        },
        "spec": {
            "egress": [
                {
                    "to": [{
                        "namespaceSelector": {
                            "matchLabels": {
                                "kubernetes.io/metadata.name": "kube-system"
                            }
                        },
                        "podSelector": {
                            "matchLabels": {"k8s-app": "kube-dns"}
                        },
                    }],
                    "ports": [
                        {"port": 53, "protocol": "UDP"},
                        {"port": 53, "protocol": "TCP"},
                    ],
                },
                {
                    "to": [{"ipBlock": {"cidr": "77.42.11.9/32"}}],
                    "ports": [{"port": 443, "protocol": "TCP"}],
                },
                {
                    "to": [{
                        "namespaceSelector": {
                            "matchLabels": {
                                "kubernetes.io/metadata.name": "stadtstack-roebel-staging-lab"
                            }
                        },
                        "podSelector": {
                            "matchLabels": {
                                "app.kubernetes.io/component": "public-mecky",
                                "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
                            }
                        },
                    }],
                    "ports": [{"port": 18084, "protocol": "TCP"}],
                },
            ],
            "ingress": [{
                "from": [
                    {"namespaceSelector": {
                        "matchLabels": {
                            "kubernetes.io/metadata.name": "ingress-system"
                        }
                    }},
                    {"ipBlock": {"cidr": "10.42.0.10/32"}},
                    {"ipBlock": {"cidr": "10.42.0.11/32"}},
                    {"ipBlock": {"cidr": "10.42.0.12/32"}},
                    {"ipBlock": {"cidr": "10.244.0.0/32"}},
                    {"ipBlock": {"cidr": "10.244.1.0/32"}},
                    {"ipBlock": {"cidr": "10.244.2.0/32"}},
                    {"ipBlock": {"cidr": "10.244.0.1/32"}},
                    {"ipBlock": {"cidr": "10.244.1.1/32"}},
                    {"ipBlock": {"cidr": "10.244.2.1/32"}},
                ],
                "ports": [{"port": 8080, "protocol": "TCP"}],
            }],
            "podSelector": {
                "matchLabels": {"app.kubernetes.io/name": "roebel-web-presentation"}
            },
            "policyTypes": ["Ingress", "Egress"],
        },
    }
    if tracer_feed_route:
        policy["spec"]["egress"].insert(0, tracer_postgrest_web_egress())
    if civic_projection_route:
        policy["spec"]["egress"].append({
            "to": [{
                "namespaceSelector": {
                    "matchLabels": {
                        "kubernetes.io/metadata.name": PARTICIPANT_POLICY.WORKBENCH_NAMESPACE
                    }
                },
                "podSelector": {
                    "matchLabels": PARTICIPANT_POLICY.WORKBENCH_SELECTOR
                },
            }],
            "ports": [{"port": PARTICIPANT_POLICY.WORKBENCH_PORT, "protocol": "TCP"}],
        })
    if reviewed_web_source:
        policy["spec"]["ingress"].append({
            "from": [{
                "namespaceSelector": {
                    "matchLabels": {
                        "kubernetes.io/metadata.name": "stadtstack-roebel-staging-lab",
                    },
                },
                "podSelector": {
                    "matchLabels": PUBLIC_MECKY_LABELS,
                },
            }],
            "ports": [{"port": 8080, "protocol": "TCP"}],
        })
    return policy


def verify_web_network_policy(
    root: Path,
    civic_projection_route: bool = False,
    tracer_feed_route: bool = False,
    reviewed_web_source: bool = False,
) -> dict[str, Any]:
    policy = load_json(root / RENDER_ROOT / "web/networkpolicy.json")
    require(
        policy == expected_web_network_policy(
            civic_projection_route,
            tracer_feed_route,
            reviewed_web_source,
        ),
        "Web NetworkPolicy drift",
    )
    return policy


def participant_gateway_secret_env(name: str, secret: str, key: str) -> dict[str, Any]:
    return {
        "name": name,
        "valueFrom": {"secretKeyRef": {"key": key, "name": secret, "optional": False}},
    }


def participant_gateway_target(kind: str, name: str, namespace: str) -> dict[str, str]:
    api_versions = {
        "Deployment": "apps/v1",
        "Ingress": "networking.k8s.io/v1",
        "GitRepository": "source.toolkit.fluxcd.io/v1",
        "Kustomization": "kustomize.toolkit.fluxcd.io/v1",
        "NetworkPolicy": "networking.k8s.io/v1",
        "Role": "rbac.authorization.k8s.io/v1",
        "RoleBinding": "rbac.authorization.k8s.io/v1",
        "Secret": "v1",
        "Service": "v1",
        "ServiceAccount": "v1",
    }
    api_version = api_versions.get(kind)
    require(api_version is not None, f"participant gateway target kind invalid: {kind}")
    return {"apiVersion": api_version, "kind": kind, "name": name, "namespace": namespace}


def expected_participant_gateway_flux_objects(*, suspended: bool = True) -> dict[str, dict[str, Any]]:
    return PARTICIPANT_POLICY.gateway_flux_objects(suspended=suspended)


def expected_participant_workbench_ingress_flux_objects(
    *, suspended: bool = True,
) -> dict[str, dict[str, Any]]:
    return PARTICIPANT_POLICY.workbench_ingress_flux_objects(suspended=suspended)


def _legacy_expected_participant_gateway_flux_objects(*, suspended: bool = True) -> dict[str, dict[str, Any]]:
    labels = {**PARTICIPANT_GATEWAY_LABELS, "stadtstack.io/gitops-owner": "participant-gateway", "stadtstack.io/flux-tenant": "roebel-staging"}
    service_account = {
        "apiVersion": "v1", "kind": "ServiceAccount",
        # Flux resolves spec.serviceAccountName in the Kustomization namespace,
        # never in targetNamespace.  The application workload ServiceAccount is
        # separately rendered in the target namespace.
        "metadata": {"labels": labels, "name": PARTICIPANT_GATEWAY_FLUX_SERVICE_ACCOUNT, "namespace": PARTICIPANT_GATEWAY_FLUX_NAMESPACE},
        "automountServiceAccountToken": False,
    }
    role = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
        "metadata": {"labels": labels, "name": PARTICIPANT_GATEWAY_FLUX_ROLE, "namespace": PARTICIPANT_GATEWAY_NAMESPACE},
        "rules": [
            {"apiGroups": [""], "resourceNames": [PARTICIPANT_GATEWAY_NAME], "resources": ["serviceaccounts", "services"], "verbs": ["get", "patch", "update"]},
            {"apiGroups": ["apps"], "resourceNames": [PARTICIPANT_GATEWAY_NAME], "resources": ["deployments"], "verbs": ["get", "patch", "update"]},
            {"apiGroups": ["networking.k8s.io"], "resourceNames": [PARTICIPANT_GATEWAY_NAME], "resources": ["networkpolicies"], "verbs": ["get", "patch", "update"]},
            {"apiGroups": ["networking.k8s.io"], "resourceNames": [PARTICIPANT_GATEWAY_NAME], "resources": ["ingresses"], "verbs": ["get", "patch", "update"]},
        ],
    }
    role_binding = {
        "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
        "metadata": {"labels": labels, "name": PARTICIPANT_GATEWAY_FLUX_ROLE_BINDING, "namespace": PARTICIPANT_GATEWAY_NAMESPACE},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": PARTICIPANT_GATEWAY_FLUX_ROLE},
        "subjects": [{"kind": "ServiceAccount", "name": PARTICIPANT_GATEWAY_FLUX_SERVICE_ACCOUNT, "namespace": PARTICIPANT_GATEWAY_FLUX_NAMESPACE}],
    }
    kustomization = {
        "apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization",
        "metadata": {"labels": labels, "name": PARTICIPANT_GATEWAY_FLUX_KUSTOMIZATION, "namespace": PARTICIPANT_GATEWAY_FLUX_NAMESPACE},
        "spec": {
            "deletionPolicy": "Orphan", "dependsOn": [], "force": False,
            "healthChecks": [{"apiVersion": "apps/v1", "kind": "Deployment", "name": PARTICIPANT_GATEWAY_NAME, "namespace": PARTICIPANT_GATEWAY_NAMESPACE}],
            "interval": "5m", "path": f"./{PARTICIPANT_GATEWAY_ROOT}",
            "prune": False, "retryInterval": "30s", "serviceAccountName": PARTICIPANT_GATEWAY_FLUX_SERVICE_ACCOUNT,
            "sourceRef": {"kind": "GitRepository", "name": PARTICIPANT_GATEWAY_FLUX_SOURCE_NAME, "namespace": PARTICIPANT_GATEWAY_FLUX_NAMESPACE},
            "timeout": "2m", "wait": True,
            # The policy bootstrap must not point an active controller at an
            # absent render path.  A separately receipt-bound CAS unsuspend is
            # the only later activation transition.
            "suspend": suspended, "targetNamespace": PARTICIPANT_GATEWAY_NAMESPACE,
        },
    }
    return {"kustomization": kustomization, "serviceAccount": service_account, "role": role, "roleBinding": role_binding}


def expected_participant_gateway_flux_source() -> dict[str, Any]:
    """Return the immutable projection of the shared, active Flux source.

    The participant boundary owns only its dedicated Kustomization.  It may
    never suspend, patch, or adopt this shared GitRepository.
    """
    return PARTICIPANT_POLICY.expected_shared_flux_source_projection()


def verify_participant_gateway_dns_tls_evidence(value: Any, endpoint: dict[str, Any], label: str) -> dict[str, Any]:
    evidence = closed(value, {"schemaVersion", "canonicalEncoding", "resolverIdentity", "resolutionMethod", "queriedHost", "queriedPort", "observedAt", "validUntil", "maxAgeSeconds", "addresses", "tlsCertificate"}, label)
    require(evidence["schemaVersion"] == PARTICIPANT_GATEWAY_DNS_TLS_EVIDENCE_SCHEMA, f"{label} schema invalid")
    require(evidence["canonicalEncoding"] == "canonical-json" and evidence["resolverIdentity"] == "reviewed-doh-resolver" and evidence["resolutionMethod"] == "dns-over-https-a-and-aaaa", f"{label} resolver identity invalid")
    origin = urlparse(endpoint["httpsOrigin"])
    require(evidence["queriedHost"] == origin.hostname and evidence["queriedPort"] == 443, f"{label} endpoint binding invalid")
    observed, valid_until = utc_timestamp(evidence["observedAt"], f"{label} observedAt"), utc_timestamp(evidence["validUntil"], f"{label} validUntil")
    require(evidence["maxAgeSeconds"] == 300 and 0 < duration_seconds(observed, valid_until) <= 300, f"{label} freshness window invalid")
    addresses = closed(evidence["addresses"], {"a", "aaaa"}, f"{label} addresses")
    expected_a = [str(ipaddress.ip_network(cidr, strict=True).network_address) for cidr in endpoint["ipv4Cidrs"]]
    require(addresses == {"a": expected_a, "aaaa": []}, f"{label} DNS answer does not equal reviewed /32 set")
    certificate = closed(evidence["tlsCertificate"], {"serverName", "issuer", "certificateSha256", "notBefore", "notAfter"}, f"{label} certificate")
    require(certificate["serverName"] == origin.hostname and isinstance(certificate["issuer"], str) and certificate["issuer"], f"{label} TLS identity invalid")
    require(isinstance(certificate["certificateSha256"], str) and SHA256.fullmatch(certificate["certificateSha256"]), f"{label} TLS digest invalid")
    require(utc_timestamp(certificate["notBefore"], f"{label} notBefore") <= observed <= valid_until < utc_timestamp(certificate["notAfter"], f"{label} notAfter"), f"{label} TLS validity invalid")
    return evidence


def participant_gateway_dns_tls_binding(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "resolverIdentity": value["resolverIdentity"],
        "resolutionMethod": value["resolutionMethod"],
        "queriedHost": value["queriedHost"],
        "queriedPort": value["queriedPort"],
        "addresses": value["addresses"],
        "tlsCertificate": value["tlsCertificate"],
    }


def verify_participant_gateway_flux_bootstrap(value: Any, operations_revision: str) -> dict[str, Any]:
    """Validate the one-time *suspended* Flux identity bootstrap.

    This is deliberately an evidence record, not a manifest.  The protected
    constant must bind its four exact objects and prove they were absent at
    collection time.  In particular it cannot authorise the participant
    reconciler to take ownership of the existing Web Ingress.
    """
    bootstrap = closed(
        value,
        {"objects", "resourceAbsenceReceipts", "bootstrapReceipt", "sourceReceipt", "webIngressReconciler"},
        "participant gateway Flux bootstrap",
    )
    expected = expected_participant_gateway_flux_objects(suspended=True)
    order = ("kustomization", "serviceAccount", "role", "roleBinding")
    objects = bootstrap["objects"]
    require(isinstance(objects, list) and len(objects) == len(order), "participant gateway Flux object count invalid")
    for object_id, value_item in zip(order, objects, strict=True):
        item = closed(value_item, {"objectId", "target", "object", "objectCanonicalSha256"}, f"participant gateway Flux {object_id}")
        require(item["objectId"] == object_id, "participant gateway Flux object order invalid")
        require(item["target"] == participant_gateway_target(
            expected[object_id]["kind"], expected[object_id]["metadata"]["name"], expected[object_id]["metadata"]["namespace"],
        ), "participant gateway Flux target invalid")
        require(item["object"] == expected[object_id], "participant gateway Flux object widened or drifted")
        require(item["objectCanonicalSha256"] == digest(expected[object_id]), "participant gateway Flux object digest invalid")

    receipts = bootstrap["resourceAbsenceReceipts"]
    require(isinstance(receipts, list) and len(receipts) == len(order), "participant gateway absence receipt count invalid")
    for object_id, value_item in zip(order, receipts, strict=True):
        expected_object = expected[object_id]
        item = closed(
            value_item,
            {"objectId", "target", "desiredObjectDigest", "state", "uid", "resourceVersion", "currentObjectDigest", "observedAt", "validUntil", "maxAgeSeconds", "apiOutcome", "receiptCanonicalSha256"},
            f"participant gateway absence receipt {object_id}",
        )
        require(item["objectId"] == object_id, "participant gateway absence receipt order invalid")
        require(item["target"] == participant_gateway_target(
            expected_object["kind"], expected_object["metadata"]["name"], expected_object["metadata"]["namespace"],
        ), "participant gateway absence receipt target invalid")
        require(item["desiredObjectDigest"] == digest(expected_object), "participant gateway absence desired object digest invalid")
        require(
            item["state"] == "absent" and item["uid"] is None and item["resourceVersion"] is None and item["currentObjectDigest"] is None,
            "participant gateway bootstrap must prove resource absence without adoption",
        )
        observed = utc_timestamp(item["observedAt"], f"participant gateway absence {object_id} observedAt")
        valid_until = utc_timestamp(item["validUntil"], f"participant gateway absence {object_id} validUntil")
        require(item["maxAgeSeconds"] == 300 and 0 < duration_seconds(observed, valid_until) <= 300, "participant gateway absence receipt freshness invalid")
        require(item["apiOutcome"] == "http-404-not-found", "participant gateway absence receipt API outcome invalid")
        canonical = {key: item[key] for key in item if key != "receiptCanonicalSha256"}
        require(item["receiptCanonicalSha256"] == digest(canonical), "participant gateway absence receipt digest invalid")

    receipt = closed(
        bootstrap["bootstrapReceipt"],
        {"status", "operationId", "completedAt", "validUntil", "maxAgeSeconds", "postconditions", "postconditionsCanonicalSha256"},
        "participant gateway suspended Flux bootstrap receipt",
    )
    require(receipt["status"] == "completed-suspended-create-only", "participant gateway bootstrap receipt status invalid")
    require(isinstance(receipt["operationId"], str) and UUID.fullmatch(receipt["operationId"]), "participant gateway bootstrap operation id invalid")
    completed = utc_timestamp(receipt["completedAt"], "participant gateway bootstrap completedAt")
    valid_until = utc_timestamp(receipt["validUntil"], "participant gateway bootstrap validUntil")
    require(receipt["maxAgeSeconds"] == 300 and 0 < duration_seconds(completed, valid_until) <= 300, "participant gateway bootstrap receipt freshness invalid")
    postconditions = receipt["postconditions"]
    require(isinstance(postconditions, list) and len(postconditions) == len(order), "participant gateway bootstrap postcondition count invalid")
    for object_id, value_item in zip(order, postconditions, strict=True):
        expected_object = expected[object_id]
        item = closed(
            value_item,
            {"objectId", "target", "uid", "resourceVersion", "objectCanonicalSha256", "apiOperation", "apiOutcome", "conflictPolicy"},
            f"participant gateway bootstrap postcondition {object_id}",
        )
        require(item["objectId"] == object_id, "participant gateway bootstrap postcondition order invalid")
        require(item["target"] == participant_gateway_target(expected_object["kind"], expected_object["metadata"]["name"], expected_object["metadata"]["namespace"]), "participant gateway bootstrap postcondition target invalid")
        require(isinstance(item["uid"], str) and UUID.fullmatch(item["uid"]), "participant gateway bootstrap postcondition UID invalid")
        require(isinstance(item["resourceVersion"], str) and item["resourceVersion"].isdigit(), "participant gateway bootstrap postcondition resourceVersion invalid")
        require(item["objectCanonicalSha256"] == digest(expected_object), "participant gateway bootstrap postcondition object drift")
        require(item["apiOperation"] == "POST-create" and item["apiOutcome"] == "http-201-created" and item["conflictPolicy"] == "fail-on-http-409-no-adopt", "participant gateway bootstrap postcondition not create-only")
    require(receipt["postconditionsCanonicalSha256"] == digest(postconditions), "participant gateway bootstrap postcondition checksum invalid")

    source = closed(bootstrap["sourceReceipt"], {"target", "uid", "resourceVersion", "liveObject", "liveObjectCanonicalSha256", "lastAppliedRevision"}, "participant gateway Flux GitRepository source receipt")
    require(source["target"] == participant_gateway_target("GitRepository", PARTICIPANT_GATEWAY_FLUX_SOURCE_NAME, PARTICIPANT_GATEWAY_FLUX_NAMESPACE), "participant gateway Flux source target invalid")
    require(isinstance(source["uid"], str) and UUID.fullmatch(source["uid"]) and isinstance(source["resourceVersion"], str) and source["resourceVersion"].isdigit(), "participant gateway Flux source identity invalid")
    expected_source = expected_participant_gateway_flux_source()
    require(source["liveObject"] == expected_source and source["liveObjectCanonicalSha256"] == digest(expected_source), "participant gateway Flux source URL/ref/verification drift")
    require(source["lastAppliedRevision"] == operations_revision, "participant gateway Flux source revision invalid")

    web = closed(bootstrap["webIngressReconciler"], {"kustomization", "serviceAccount"}, "participant gateway Web reconciler binding")
    expected_web_kustomization = participant_gateway_target("Kustomization", PARTICIPANT_GATEWAY_WEB_FLUX_KUSTOMIZATION, PARTICIPANT_GATEWAY_FLUX_NAMESPACE)
    expected_web_sa = participant_gateway_target("ServiceAccount", PARTICIPANT_GATEWAY_WEB_FLUX_SERVICE_ACCOUNT, PARTICIPANT_GATEWAY_FLUX_NAMESPACE)
    for key, target in (("kustomization", expected_web_kustomization), ("serviceAccount", expected_web_sa)):
        record = closed(web[key], {"target", "uid", "resourceVersion", "liveObjectSha256"}, f"participant gateway Web reconciler {key}")
        require(record["target"] == target, f"participant gateway Web reconciler {key} target invalid")
        require(isinstance(record["uid"], str) and UUID.fullmatch(record["uid"]), f"participant gateway Web reconciler {key} UID invalid")
        require(isinstance(record["resourceVersion"], str) and record["resourceVersion"].isdigit(), f"participant gateway Web reconciler {key} resourceVersion invalid")
        require(isinstance(record["liveObjectSha256"], str) and SHA256.fullmatch(record["liveObjectSha256"]), f"participant gateway Web reconciler {key} digest invalid")
    return bootstrap


def verify_participant_gateway_activation_transaction(value: Any, flux_bootstrap: dict[str, Any]) -> dict[str, Any]:
    """Check the pre-approved dormant-to-active transaction template.

    A postcondition cannot be known until the CAS patch happens.  It is audit
    output, never candidate-controlled activation evidence; only this
    protected precondition/template is admitted in the policy merge.
    """
    transaction = closed(
        value,
        {"scriptSha256", "receiptSchemaVersion", "precondition", "patch", "postconditionTemplate"},
        "participant gateway activation transaction",
    )
    suspended = expected_participant_gateway_flux_objects(suspended=True)["kustomization"]
    active = expected_participant_gateway_flux_objects(suspended=False)["kustomization"]
    postcondition = flux_bootstrap["bootstrapReceipt"]["postconditions"][0]
    require(transaction["scriptSha256"] == participant_gateway_activation_script_sha256(), "participant gateway activation script drift")
    require(transaction["receiptSchemaVersion"] == PARTICIPANT_GATEWAY_ACTIVATION_RECEIPT_SCHEMA, "participant gateway activation receipt schema invalid")
    precondition = closed(transaction["precondition"], {"target", "requiredUid", "requiredResourceVersion", "beforeObjectDigest"}, "participant gateway activation transaction precondition")
    require(precondition["target"] == participant_gateway_target("Kustomization", PARTICIPANT_GATEWAY_FLUX_KUSTOMIZATION, PARTICIPANT_GATEWAY_FLUX_NAMESPACE), "participant gateway activation target invalid")
    require(precondition["requiredUid"] == postcondition["uid"] and precondition["requiredResourceVersion"] == postcondition["resourceVersion"], "participant gateway activation CAS binding invalid")
    require(precondition["beforeObjectDigest"] == digest(suspended) == postcondition["objectCanonicalSha256"], "participant gateway activation before object invalid")
    require(transaction["patch"] == {"op": "replace", "path": "/spec/suspend", "expected": True, "value": False}, "participant gateway activation patch widened")
    require(transaction["postconditionTemplate"] == {
        "target": participant_gateway_target("Kustomization", PARTICIPANT_GATEWAY_FLUX_KUSTOMIZATION, PARTICIPANT_GATEWAY_FLUX_NAMESPACE),
        "requiredUid": postcondition["uid"],
        "requiredResourceVersion": postcondition["resourceVersion"],
        "beforeObjectDigest": digest(suspended),
        "afterObjectDigest": digest(active),
        "apiOperation": "PATCH-json-cas",
        "apiOutcome": "http-200-re-read-exact-active",
    }, "participant gateway activation postcondition template drift")
    return transaction


def verify_participant_gateway_activation_postcondition_receipt(value: Any, transaction: dict[str, Any]) -> dict[str, Any]:
    """Validate audit output from the protected activation script, if supplied."""
    receipt = closed(
        value,
        {"schemaVersion", "target", "requiredUid", "requiredResourceVersion", "beforeObjectDigest", "postResourceVersion", "afterObjectDigest", "apiOperation", "apiOutcome", "completedAt"},
        "participant gateway activation postcondition receipt",
    )
    template = transaction["postconditionTemplate"]
    require(receipt["schemaVersion"] == PARTICIPANT_GATEWAY_ACTIVATION_RECEIPT_SCHEMA, "participant gateway activation audit schema invalid")
    for key in ("target", "requiredUid", "requiredResourceVersion", "beforeObjectDigest", "afterObjectDigest", "apiOperation", "apiOutcome"):
        require(receipt[key] == template[key], f"participant gateway activation audit {key} drift")
    require(isinstance(receipt["postResourceVersion"], str) and receipt["postResourceVersion"].isdigit() and int(receipt["postResourceVersion"]) > int(receipt["requiredResourceVersion"]), "participant gateway activation audit post resourceVersion invalid")
    utc_timestamp(receipt["completedAt"], "participant gateway activation audit completedAt")
    return receipt


def verify_participant_gateway_ingress_cas(value: Any, rollback: dict[str, Any], label: str) -> dict[str, Any]:
    record = closed(
        value,
        {"target", "uid", "resourceVersion", "liveObjectSha256", "observedAt", "validUntil", "maxAgeSeconds", "apiOutcome"},
        label,
    )
    require(record["target"] == participant_gateway_target("Ingress", PARTICIPANT_GATEWAY_NAME, PARTICIPANT_GATEWAY_NAMESPACE), f"{label} target invalid")
    require(isinstance(record["uid"], str) and UUID.fullmatch(record["uid"]), f"{label} UID invalid")
    require(isinstance(record["resourceVersion"], str) and record["resourceVersion"].isdigit(), f"{label} resourceVersion invalid")
    require(record["liveObjectSha256"] == rollback["participantIngressSha256"], f"{label} live bytes do not match participant rollback baseline")
    observed = utc_timestamp(record["observedAt"], f"{label} observedAt")
    valid_until = utc_timestamp(record["validUntil"], f"{label} validUntil")
    require(record["maxAgeSeconds"] == 300 and 0 < duration_seconds(observed, valid_until) <= 300, f"{label} freshness invalid")
    require(record["apiOutcome"] == "http-200-exact-live-bytes", f"{label} API outcome invalid")
    return record


def verify_participant_gateway_secret_materialization(value: Any, label: str) -> dict[str, Any]:
    materialization = closed(value, {"config", "runtime"}, label)
    expected = {
        "config": (PARTICIPANT_GATEWAY_CONFIG_SECRET, ["allowed-wallets", "invite-sha256", "mecky-pubkey"]),
        "runtime": (PARTICIPANT_GATEWAY_RUNTIME_SECRET, ["session-key", "supabase-anon-key", "supabase-rpc-secret"]),
    }
    for name, (secret_name, keys) in expected.items():
        record = closed(
            materialization[name],
            {"target", "uid", "resourceVersion", "keySet", "state", "semanticChecks", "materializedAt", "validUntil", "maxAgeSeconds", "vaultArm", "receiptCanonicalSha256"},
            f"{label} {name} Secret",
        )
        require(record["target"] == participant_gateway_target("Secret", secret_name, PARTICIPANT_GATEWAY_NAMESPACE), f"{label} {name} Secret target invalid")
        require(isinstance(record["uid"], str) and UUID.fullmatch(record["uid"]), f"{label} {name} Secret UID invalid")
        require(isinstance(record["resourceVersion"], str) and record["resourceVersion"].isdigit(), f"{label} {name} Secret resourceVersion invalid")
        require(record["keySet"] == keys and record["state"] == "present-exact-keyset", f"{label} {name} Secret key set invalid")
        expected_semantics = (
            {"inviteSha256Is64LowerHex": True, "meckyPubkeyIs64LowerHex": True, "walletAllowListNonEmptyNormalized": True}
            if name == "config" else
            {"sessionHmacKeyAtLeast32Bytes": True, "sessionHmacKeyHighEntropy": True, "stagingSupabaseAnonCredentialValid": True, "stagingRpcSecretAccepted": True}
        )
        require(record["semanticChecks"] == expected_semantics, f"{label} {name} Secret semantic preflight invalid")
        observed = utc_timestamp(record["materializedAt"], f"{label} {name} Secret materializedAt")
        valid_until = utc_timestamp(record["validUntil"], f"{label} {name} Secret validUntil")
        require(record["maxAgeSeconds"] == 300 and 0 < duration_seconds(observed, valid_until) <= 300, f"{label} {name} Secret freshness invalid")
        require(record["vaultArm"] == "roebel_staging_participant_environment_arm=staging-only", f"{label} {name} Secret Vault arm invalid")
        canonical = {key: record[key] for key in record if key != "receiptCanonicalSha256"}
        require(record["receiptCanonicalSha256"] == digest(canonical), f"{label} {name} Secret receipt invalid")
    return materialization


def verify_participant_gateway_database_preflight(
    value: Any,
    runtime_pin: dict[str, Any],
    label: str,
) -> dict[str, Any]:
    preflight = closed(
        value,
        {
            "databaseProject",
            "environment",
            "vaultArm",
            "migrationSha256",
            "schemaSha256",
            "topicTracerMigrationSha256",
            "topicTracerDatabaseSchemaSha256",
            "observedAt",
            "validUntil",
            "maxAgeSeconds",
            "apiOutcome",
            "receiptCanonicalSha256",
        },
        label,
    )
    require(isinstance(preflight["databaseProject"], str) and re.fullmatch(r"[a-z0-9]{20}", preflight["databaseProject"]), f"{label} database project invalid")
    require(preflight["environment"] == "staging" and preflight["vaultArm"] == "roebel_staging_participant_environment_arm=staging-only", f"{label} staging/Vault binding invalid")
    require(
        {
            "migrationSha256": preflight["migrationSha256"],
            "schemaSha256": preflight["schemaSha256"],
            "topicTracerMigrationSha256": preflight["topicTracerMigrationSha256"],
            "topicTracerDatabaseSchemaSha256": preflight["topicTracerDatabaseSchemaSha256"],
        }
        == {
            "migrationSha256": runtime_pin["migrationSha256"],
            "schemaSha256": runtime_pin["databaseSchemaSha256"],
            "topicTracerMigrationSha256": runtime_pin["topicTracerMigrationSha256"],
            "topicTracerDatabaseSchemaSha256": runtime_pin["topicTracerDatabaseSchemaSha256"],
        },
        f"{label} pinned schema contract drift",
    )
    observed = utc_timestamp(preflight["observedAt"], f"{label} observedAt")
    valid_until = utc_timestamp(preflight["validUntil"], f"{label} validUntil")
    require(preflight["maxAgeSeconds"] == 300 and 0 < duration_seconds(observed, valid_until) <= 300, f"{label} freshness invalid")
    require(preflight["apiOutcome"] == "staging-schema-and-vault-arm-exact", f"{label} API outcome invalid")
    canonical = {key: preflight[key] for key in preflight if key != "receiptCanonicalSha256"}
    require(preflight["receiptCanonicalSha256"] == digest(canonical), f"{label} receipt invalid")
    return preflight


def verify_participant_gateway_gnosis_chain(value: Any, origin: str, label: str) -> dict[str, Any]:
    receipt = closed(value, {"httpsOrigin", "request", "response", "observedAt", "validUntil", "maxAgeSeconds", "receiptCanonicalSha256"}, label)
    require(receipt["httpsOrigin"] == origin, f"{label} origin invalid")
    require(receipt["request"] == {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}, f"{label} request invalid")
    require(receipt["response"] == {"jsonrpc": "2.0", "id": 1, "result": "0x64"}, f"{label} must prove Gnosis eth_chainId 0x64")
    observed = utc_timestamp(receipt["observedAt"], f"{label} observedAt")
    valid_until = utc_timestamp(receipt["validUntil"], f"{label} validUntil")
    require(receipt["maxAgeSeconds"] == 300 and 0 < duration_seconds(observed, valid_until) <= 300, f"{label} freshness invalid")
    canonical = {key: receipt[key] for key in receipt if key != "receiptCanonicalSha256"}
    require(receipt["receiptCanonicalSha256"] == digest(canonical), f"{label} receipt invalid")
    return receipt


def verify_participant_gateway_application_bootstrap(value: Any, runtime_pin: dict[str, Any]) -> dict[str, Any]:
    """Prove the application objects were create-only in safe order.

    The dormant Flux Kustomization never gets authority to create or adopt an
    absent application object.  A privileged, reviewed bootstrap instead uses
    one atomic POST per exact object and records the UID/RV/bytes Flux must
    later observe unchanged.
    """
    bootstrap = closed(value, {"resourceAbsenceReceipts", "postconditions", "postconditionsCanonicalSha256", "healthBeforeIngress"}, "participant gateway application bootstrap")
    resources = expected_participant_gateway_resources(runtime_pin)
    # NetworkPolicy must exist before any matching Pod. The dedicated Ingress
    # is the last create-only object and may appear only after the internal
    # Service/Deployment health receipt. The existing Web Ingress is not part
    # of this transaction and cannot be adopted or changed.
    order = (
        ("networkPolicy", "networkPolicy"),
        ("serviceAccount", "serviceAccount"),
        ("service", "service"),
        ("deployment", "deployment"),
        ("ingress", "ingress"),
    )
    for field in ("resourceAbsenceReceipts", "postconditions"):
        require(isinstance(bootstrap[field], list) and len(bootstrap[field]) == len(order), f"participant gateway application {field} count invalid")
    for (object_id, resource_key), absence_value, post_value in zip(order, bootstrap["resourceAbsenceReceipts"], bootstrap["postconditions"], strict=True):
        expected = resources[resource_key]
        target = participant_gateway_target(expected["kind"], expected["metadata"]["name"], expected["metadata"]["namespace"])
        absence = closed(
            absence_value,
            {"objectId", "target", "desiredObjectDigest", "state", "uid", "resourceVersion", "currentObjectDigest", "observedAt", "validUntil", "maxAgeSeconds", "apiOutcome", "receiptCanonicalSha256"},
            f"participant gateway application absence {object_id}",
        )
        require(absence["objectId"] == object_id and absence["target"] == target and absence["desiredObjectDigest"] == digest(expected), "participant gateway application absence target/digest invalid")
        require(absence["state"] == "absent" and absence["uid"] is None and absence["resourceVersion"] is None and absence["currentObjectDigest"] is None and absence["apiOutcome"] == "http-404-not-found", "participant gateway application absence must be exact no-adopt")
        observed = utc_timestamp(absence["observedAt"], f"participant gateway application absence {object_id} observedAt")
        valid_until = utc_timestamp(absence["validUntil"], f"participant gateway application absence {object_id} validUntil")
        require(absence["maxAgeSeconds"] == 300 and 0 < duration_seconds(observed, valid_until) <= 300, "participant gateway application absence freshness invalid")
        require(absence["receiptCanonicalSha256"] == digest({key: absence[key] for key in absence if key != "receiptCanonicalSha256"}), "participant gateway application absence digest invalid")
        post_keys = {"objectId", "target", "uid", "resourceVersion", "objectCanonicalSha256", "apiOperation", "apiOutcome", "conflictPolicy"}
        if object_id == "ingress":
            post_keys.add("createdAt")
        post = closed(post_value, post_keys, f"participant gateway application postcondition {object_id}")
        require(post["objectId"] == object_id and post["target"] == target, "participant gateway application postcondition target invalid")
        require(isinstance(post["uid"], str) and UUID.fullmatch(post["uid"]), "participant gateway application postcondition UID invalid")
        require(isinstance(post["resourceVersion"], str) and post["resourceVersion"].isdigit(), "participant gateway application postcondition resourceVersion invalid")
        require(post["objectCanonicalSha256"] == digest(expected), "participant gateway application postcondition object drift")
        require(post["apiOperation"] == "POST-create" and post["apiOutcome"] == "http-201-created" and post["conflictPolicy"] == "fail-on-http-409-no-adopt", "participant gateway application postcondition not create-only")
    require(bootstrap["postconditionsCanonicalSha256"] == digest(bootstrap["postconditions"]), "participant gateway application postcondition checksum invalid")
    health = closed(
        bootstrap["healthBeforeIngress"],
        {"target", "deploymentUid", "deploymentResourceVersion", "serviceTarget", "statusPath", "observedAt", "validUntil", "maxAgeSeconds", "apiOutcome", "receiptCanonicalSha256"},
        "participant gateway pre-Ingress health receipt",
    )
    deployment_post = bootstrap["postconditions"][3]
    require(health["target"] == deployment_post["target"] and health["deploymentUid"] == deployment_post["uid"] and health["deploymentResourceVersion"] == deployment_post["resourceVersion"], "participant gateway pre-Ingress health deployment binding invalid")
    require(health["serviceTarget"] == participant_gateway_target("Service", PARTICIPANT_GATEWAY_NAME, PARTICIPANT_GATEWAY_NAMESPACE), "participant gateway pre-Ingress health Service target invalid")
    require(health["statusPath"] == "/api/staging-participant/v1/status" and health["apiOutcome"] == "http-200-internal-status", "participant gateway pre-Ingress health outcome invalid")
    observed = utc_timestamp(health["observedAt"], "participant gateway pre-Ingress health observedAt")
    valid_until = utc_timestamp(health["validUntil"], "participant gateway pre-Ingress health validUntil")
    require(health["maxAgeSeconds"] == 300 and 0 < duration_seconds(observed, valid_until) <= 300, "participant gateway pre-Ingress health freshness invalid")
    require(health["receiptCanonicalSha256"] == digest({key: health[key] for key in health if key != "receiptCanonicalSha256"}), "participant gateway pre-Ingress health receipt invalid")
    ingress_post = bootstrap["postconditions"][4]
    require(utc_timestamp(health["observedAt"], "participant gateway pre-Ingress health observedAt") <= utc_timestamp(ingress_post["createdAt"], "participant gateway Ingress createdAt"), "participant gateway Ingress precedes health")
    return bootstrap


def verify_participant_gateway_publication_receipt(value: Any, runtime_pin: dict[str, Any], predicate_type: str, label: str) -> dict[str, Any]:
    receipt = closed(value, {"receiptId", "receiptUrl", "subjectImage", "subjectDigest", "sourceRevision", "workflowIdentity", "runner", "predicateType", "attestationDigest", "verifiedAt", "verification", "canonicalReceiptSha256"}, label)
    require(isinstance(receipt["receiptId"], str) and receipt["receiptId"].isdigit(), f"{label} receipt id invalid")
    require(receipt["receiptUrl"] == f"https://github.com/GiraeffleAeffle/Roebel-App/actions/runs/{receipt['receiptId']}", f"{label} receipt URL invalid")
    require(receipt["subjectImage"] == runtime_pin["imageRepository"] and receipt["subjectDigest"] == runtime_pin["manifestDigest"], f"{label} image subject invalid")
    require(receipt["sourceRevision"] == runtime_pin["sourceRevision"] and receipt["workflowIdentity"] == runtime_pin["workflowIdentity"], f"{label} source/workflow binding invalid")
    require(receipt["runner"] == "github-hosted", f"{label} runner invalid")
    require(receipt["predicateType"] == predicate_type, f"{label} predicate type invalid")
    require(isinstance(receipt["attestationDigest"], str) and SHA256.fullmatch(receipt["attestationDigest"]) and receipt["attestationDigest"] != "sha256:" + "0" * 64, f"{label} attestation digest invalid")
    utc_timestamp(receipt["verifiedAt"], f"{label} verifiedAt")
    require(receipt["verification"] == {"tool": "gh", "command": "attestation-verify", "result": "verified", "subjectDigest": runtime_pin["manifestDigest"]}, f"{label} must contain a successful attestation verification receipt")
    require(receipt["canonicalReceiptSha256"] == digest({key: receipt[key] for key in receipt if key != "canonicalReceiptSha256"}), f"{label} canonical receipt digest invalid")
    return receipt


def verify_participant_gateway_anonymous_pull_receipt(value: Any, runtime_pin: dict[str, Any]) -> dict[str, Any]:
    receipt = closed(value, {"subjectImage", "subjectDigest", "pullMode", "tool", "toolVersion", "resolverIdentity", "authContext", "authConfigSha256", "descriptor", "observedAt", "receiptCanonicalSha256"}, "participant gateway anonymous digest pull receipt")
    require(receipt["subjectImage"] == runtime_pin["imageRepository"] and receipt["subjectDigest"] == runtime_pin["manifestDigest"], "participant gateway anonymous pull subject invalid")
    require(receipt["pullMode"] == "anonymous-digest-pull", "participant gateway anonymous pull mode invalid")
    require(receipt["tool"] == "oras" and isinstance(receipt["toolVersion"], str) and receipt["toolVersion"], "participant gateway anonymous pull tool invalid")
    require(receipt["resolverIdentity"] == "oras-resolve-anonymous" and receipt["authContext"] == "isolated-empty-auth-config", "participant gateway anonymous pull identity invalid")
    require(receipt["authConfigSha256"] == PARTICIPANT_GATEWAY_ANONYMOUS_EMPTY_AUTH_CONFIG_SHA256, "participant gateway anonymous pull must pin the reviewed empty auth config")
    descriptor = closed(receipt["descriptor"], {"mediaType", "digest", "size"}, "participant gateway anonymous pull descriptor")
    require(descriptor["mediaType"] == "application/vnd.oci.image.manifest.v1+json" and descriptor["digest"] == runtime_pin["manifestDigest"] and isinstance(descriptor["size"], int) and descriptor["size"] > 0, "participant gateway anonymous pull descriptor invalid")
    utc_timestamp(receipt["observedAt"], "participant gateway anonymous pull observedAt")
    require(receipt["receiptCanonicalSha256"] == digest({key: receipt[key] for key in receipt if key != "receiptCanonicalSha256"}), "participant gateway anonymous pull receipt digest invalid")
    return receipt


def verify_participant_gateway_network_policy_inventory(value: Any) -> dict[str, Any]:
    """Require a complete, non-widening K8s and Cilium policy inventory.

    The participant policy is additive only.  A blanket selector in either
    API family would make the narrow Gateway NetworkPolicy impossible to
    reason about, so the activation bundle must record all three inventories
    and prove every selected policy has an exact matchLabels selector.
    """
    inventory = closed(
        value,
        {"schemaVersion", "namespace", "capturedAt", "validUntil", "maxAgeSeconds", "kubernetesNetworkPolicies", "ciliumNetworkPolicies", "ciliumClusterwideNetworkPolicies", "selectorWidening", "receiptCanonicalSha256"},
        "participant gateway network policy inventory",
    )
    require(inventory["schemaVersion"] == "roebel_staging_participant_gateway_network_policy_inventory_v1", "participant gateway network policy inventory schema invalid")
    require(inventory["namespace"] == PARTICIPANT_GATEWAY_NAMESPACE, "participant gateway network policy inventory namespace invalid")
    captured = utc_timestamp(inventory["capturedAt"], "participant gateway network policy inventory capturedAt")
    valid_until = utc_timestamp(inventory["validUntil"], "participant gateway network policy inventory validUntil")
    require(inventory["maxAgeSeconds"] == 300 and 0 < duration_seconds(captured, valid_until) <= 300, "participant gateway network policy inventory freshness invalid")
    require(inventory["selectorWidening"] is False, "participant gateway network policy selector widening observed")
    for family in ("kubernetesNetworkPolicies", "ciliumNetworkPolicies", "ciliumClusterwideNetworkPolicies"):
        records = inventory[family]
        require(isinstance(records, list), f"participant gateway {family} inventory invalid")
        seen: set[tuple[str, str, str]] = set()
        for index, record_value in enumerate(records):
            record = closed(record_value, {"target", "uid", "resourceVersion", "objectCanonicalSha256", "podSelector"}, f"participant gateway {family}[{index}]")
            target = closed(record["target"], {"apiVersion", "kind", "name", "namespace"}, f"participant gateway {family}[{index}] target")
            require(target["namespace"] in {PARTICIPANT_GATEWAY_NAMESPACE, ""}, f"participant gateway {family} target namespace invalid")
            require(isinstance(target["kind"], str) and target["kind"].endswith("NetworkPolicy"), f"participant gateway {family} target kind invalid")
            key = (target["apiVersion"], target["kind"], target["name"])
            require(key not in seen, f"participant gateway {family} duplicate policy inventory target")
            seen.add(key)
            require(isinstance(record["uid"], str) and UUID.fullmatch(record["uid"]), f"participant gateway {family} UID invalid")
            require(isinstance(record["resourceVersion"], str) and record["resourceVersion"].isdigit(), f"participant gateway {family} resourceVersion invalid")
            require(isinstance(record["objectCanonicalSha256"], str) and SHA256.fullmatch(record["objectCanonicalSha256"]), f"participant gateway {family} object digest invalid")
            selector = closed(record["podSelector"], {"matchLabels"}, f"participant gateway {family} pod selector")
            require(isinstance(selector["matchLabels"], dict) and selector["matchLabels"], f"participant gateway {family} has a broad or empty pod selector")
    require(inventory["receiptCanonicalSha256"] == digest({key: inventory[key] for key in inventory if key != "receiptCanonicalSha256"}), "participant gateway network policy inventory receipt invalid")
    return inventory


def verify_participant_gateway_activation_evidence(value: Any, runtime_pin: dict[str, Any]) -> dict[str, Any]:
    del value, runtime_pin
    raise VerificationError(
        "candidate-embedded participant activation evidence is forbidden; "
        "trusted live facts are runner-owned and out-of-band",
    )


def _legacy_verify_participant_gateway_activation_evidence(value: Any, runtime_pin: dict[str, Any]) -> dict[str, Any]:
    evidence = closed(
        value,
        {
            "schemaVersion", "status", "operationsRevision", "sourceRevision", "imageRepository", "manifestDigest",
            "workflowIdentity", "publication", "egress", "networkPolicyInventory", "fluxBootstrap", "applicationBootstrap", "ingressCas", "secretMaterialization",
            "databaseVaultPreflight", "gnosisChainCheck", "dnsTlsEvidence", "activationLiveRecheck", "activationTransaction", "rollback",
        },
        "staging participant gateway activation evidence",
    )
    require(evidence["schemaVersion"] == "roebel_staging_participant_gateway_activation_evidence_v1", "participant gateway evidence schema invalid")
    require(evidence["status"] == "approved-separate-review", "participant gateway evidence status invalid")
    require(isinstance(evidence["operationsRevision"], str) and REVISION.fullmatch(evidence["operationsRevision"]), "participant gateway operations revision invalid")
    require(evidence["sourceRevision"] == runtime_pin["sourceRevision"], "participant gateway evidence source revision invalid")
    require(evidence["imageRepository"] == runtime_pin["imageRepository"], "participant gateway evidence image repository invalid")
    require(evidence["manifestDigest"] == runtime_pin["manifestDigest"], "participant gateway evidence image digest invalid")
    require(evidence["workflowIdentity"] == runtime_pin["workflowIdentity"], "participant gateway evidence workflow invalid")
    publication = closed(evidence["publication"], {"slsaProvenance", "spdxSbom", "anonymousPull"}, "participant gateway publication evidence")
    verify_participant_gateway_publication_receipt(publication["slsaProvenance"], runtime_pin, "https://slsa.dev/provenance/v1", "participant gateway SLSA provenance")
    verify_participant_gateway_publication_receipt(publication["spdxSbom"], runtime_pin, "https://spdx.dev/Document", "participant gateway SPDX SBOM")
    verify_participant_gateway_anonymous_pull_receipt(publication["anonymousPull"], runtime_pin)
    verify_participant_gateway_network_policy_inventory(evidence["networkPolicyInventory"])
    egress = closed(evidence["egress"], {"gnosis", "supabase"}, "participant gateway egress evidence")
    for name in ("gnosis", "supabase"):
        endpoint = closed(egress[name], {"httpsOrigin", "ipv4Cidrs", "port"}, f"participant gateway {name} egress")
        parsed_origin = urlparse(endpoint["httpsOrigin"])
        require(
            parsed_origin.scheme == "https" and parsed_origin.hostname and parsed_origin.port in {None, 443}
            and not parsed_origin.username and not parsed_origin.password and parsed_origin.path in {"", "/"}
            and not parsed_origin.params and not parsed_origin.query and not parsed_origin.fragment,
            f"participant gateway {name} HTTPS origin invalid",
        )
        require(endpoint["httpsOrigin"] == f"https://{parsed_origin.hostname}", f"participant gateway {name} origin must be a canonical literal HTTPS origin")
        require(endpoint["port"] == 443, f"participant gateway {name} port invalid")
        cidrs = endpoint["ipv4Cidrs"]
        require(isinstance(cidrs, list) and 1 <= len(cidrs) <= 8 and cidrs == sorted(set(cidrs)), f"participant gateway {name} CIDR set invalid")
        for cidr in cidrs:
            try:
                parsed = ipaddress.ip_network(cidr, strict=True)
            except ValueError:
                parsed = None
            require(parsed is not None and parsed.version == 4 and parsed.prefixlen == 32, f"participant gateway {name} CIDR must be an exact IPv4 /32")
    flux = verify_participant_gateway_flux_bootstrap(evidence["fluxBootstrap"], evidence["operationsRevision"])
    rollback = closed(evidence["rollback"], {"previousIngressSha256", "participantIngressSha256", "deactivationSqlSha256"}, "participant gateway rollback evidence")
    require(isinstance(rollback["previousIngressSha256"], str) and SHA256.fullmatch(rollback["previousIngressSha256"]), "participant gateway rollback ingress invalid")
    require(rollback["participantIngressSha256"] == digest(expected_participant_gateway_ingress()), "participant gateway rollback dedicated Ingress bytes invalid")
    require(isinstance(rollback["deactivationSqlSha256"], str) and SHA256.fullmatch(rollback["deactivationSqlSha256"]), "participant gateway rollback SQL invalid")
    application = verify_participant_gateway_application_bootstrap(evidence["applicationBootstrap"], runtime_pin)
    ingress = verify_participant_gateway_ingress_cas(evidence["ingressCas"], rollback, "participant gateway Ingress CAS")
    secrets = verify_participant_gateway_secret_materialization(evidence["secretMaterialization"], "participant gateway Secret materialization")
    database = verify_participant_gateway_database_preflight(
        evidence["databaseVaultPreflight"],
        runtime_pin,
        "participant gateway database/Vault preflight",
    )
    chain = verify_participant_gateway_gnosis_chain(evidence["gnosisChainCheck"], egress["gnosis"]["httpsOrigin"], "participant gateway Gnosis chain check")
    initial_dns = closed(evidence["dnsTlsEvidence"], {"gnosis", "supabase"}, "participant gateway DNS/TLS evidence")
    initial_dns = {
        name: verify_participant_gateway_dns_tls_evidence(initial_dns[name], egress[name], f"participant gateway {name} DNS/TLS evidence")
        for name in ("gnosis", "supabase")
    }
    recheck = closed(
        evidence["activationLiveRecheck"],
        {"checkedAt", "validUntil", "maxAgeSeconds", "sharedSourceRebind", "fluxKustomizationCas", "applicationStates", "ingressCas", "secretMaterialization", "databaseVaultPreflight", "gnosisChainCheck", "dnsTlsEvidence"},
        "participant gateway activation live recheck",
    )
    checked = utc_timestamp(recheck["checkedAt"], "participant gateway activation live recheck checkedAt")
    valid_until = utc_timestamp(recheck["validUntil"], "participant gateway activation live recheck validUntil")
    require(recheck["maxAgeSeconds"] == 300 and 0 < duration_seconds(checked, valid_until) <= 300, "participant gateway activation live recheck freshness invalid")
    source_rebind = closed(recheck["sharedSourceRebind"], {"target", "uid", "resourceVersion", "liveObjectCanonicalSha256", "artifactRevision", "observedAt", "validUntil", "maxAgeSeconds", "apiOutcome"}, "participant gateway activation shared Flux source rebind")
    source = flux["sourceReceipt"]
    require(source_rebind["target"] == source["target"] and source_rebind["uid"] == source["uid"], "participant gateway activation shared Flux source identity drift")
    require(isinstance(source_rebind["resourceVersion"], str) and source_rebind["resourceVersion"].isdigit() and int(source_rebind["resourceVersion"]) >= int(source["resourceVersion"]), "participant gateway activation shared Flux source resourceVersion invalid")
    require(source_rebind["liveObjectCanonicalSha256"] == source["liveObjectCanonicalSha256"], "participant gateway activation shared Flux source spec drift")
    require(source_rebind["artifactRevision"] == evidence["operationsRevision"], "participant gateway activation shared Flux source is not rebound to the exact protected render revision")
    require(source_rebind["apiOutcome"] == "http-200-active-source-exact-artifact", "participant gateway activation shared Flux source rebind outcome invalid")
    source_observed = utc_timestamp(source_rebind["observedAt"], "participant gateway activation shared Flux source observedAt")
    source_valid = utc_timestamp(source_rebind["validUntil"], "participant gateway activation shared Flux source validUntil")
    require(source_rebind["maxAgeSeconds"] == 300 and source_observed <= checked <= source_valid, "participant gateway activation shared Flux source freshness invalid")
    kustomization_cas = closed(recheck["fluxKustomizationCas"], {"target", "uid", "resourceVersion", "liveObjectSha256", "observedAt", "validUntil", "maxAgeSeconds", "apiOutcome"}, "participant gateway activation Flux Kustomization CAS")
    flux_kustomization = flux["bootstrapReceipt"]["postconditions"][0]
    require(kustomization_cas["target"] == flux_kustomization["target"] and kustomization_cas["uid"] == flux_kustomization["uid"] and kustomization_cas["resourceVersion"] == flux_kustomization["resourceVersion"] and kustomization_cas["liveObjectSha256"] == flux_kustomization["objectCanonicalSha256"], "participant gateway activation Flux Kustomization CAS drift")
    require(kustomization_cas["apiOutcome"] == "http-200-exact-suspended-bytes", "participant gateway activation Flux Kustomization CAS outcome invalid")
    covers_kustomization_observed = utc_timestamp(kustomization_cas["observedAt"], "participant gateway activation Flux Kustomization observedAt")
    covers_kustomization_valid = utc_timestamp(kustomization_cas["validUntil"], "participant gateway activation Flux Kustomization validUntil")
    require(kustomization_cas["maxAgeSeconds"] == 300 and covers_kustomization_observed <= checked <= covers_kustomization_valid, "participant gateway activation Flux Kustomization CAS freshness invalid")
    require(recheck["applicationStates"] == application["postconditions"], "participant gateway activation application ownership drift")
    recheck_ingress = verify_participant_gateway_ingress_cas(recheck["ingressCas"], rollback, "participant gateway activation Ingress CAS")
    recheck_secrets = verify_participant_gateway_secret_materialization(recheck["secretMaterialization"], "participant gateway activation Secret materialization")
    recheck_database = verify_participant_gateway_database_preflight(
        recheck["databaseVaultPreflight"],
        runtime_pin,
        "participant gateway activation database/Vault preflight",
    )
    recheck_chain = verify_participant_gateway_gnosis_chain(recheck["gnosisChainCheck"], egress["gnosis"]["httpsOrigin"], "participant gateway activation Gnosis chain check")
    recheck_dns_value = closed(recheck["dnsTlsEvidence"], {"gnosis", "supabase"}, "participant gateway activation DNS/TLS recheck")
    for name in ("gnosis", "supabase"):
        current = verify_participant_gateway_dns_tls_evidence(recheck_dns_value[name], egress[name], f"participant gateway activation {name} DNS/TLS")
        require(participant_gateway_dns_tls_binding(current) == participant_gateway_dns_tls_binding(initial_dns[name]), f"participant gateway activation {name} DNS/TLS binding drift")
    def covers_checked(observed_at: str, receipt_valid_until: str, receipt_label: str) -> None:
        require(
            utc_timestamp(observed_at, f"{receipt_label} observed") <= checked <= utc_timestamp(receipt_valid_until, f"{receipt_label} validUntil"),
            f"{receipt_label} does not cover activation recheck time",
        )

    covers_checked(recheck_ingress["observedAt"], recheck_ingress["validUntil"], "participant gateway activation Ingress CAS")
    for name in ("config", "runtime"):
        covers_checked(recheck_secrets[name]["materializedAt"], recheck_secrets[name]["validUntil"], f"participant gateway activation {name} Secret")
        require(
            {key: recheck_secrets[name][key] for key in ("target", "uid", "resourceVersion", "keySet", "state", "vaultArm")}
            == {key: secrets[name][key] for key in ("target", "uid", "resourceVersion", "keySet", "state", "vaultArm")},
            f"participant gateway activation {name} Secret identity drift",
        )
    covers_checked(recheck_database["observedAt"], recheck_database["validUntil"], "participant gateway activation database/Vault preflight")
    require(
        {
            key: recheck_database[key]
            for key in (
                "databaseProject",
                "environment",
                "vaultArm",
                "migrationSha256",
                "schemaSha256",
                "topicTracerMigrationSha256",
                "topicTracerDatabaseSchemaSha256",
                "apiOutcome",
            )
        }
        == {
            key: database[key]
            for key in (
                "databaseProject",
                "environment",
                "vaultArm",
                "migrationSha256",
                "schemaSha256",
                "topicTracerMigrationSha256",
                "topicTracerDatabaseSchemaSha256",
                "apiOutcome",
            )
        },
        "participant gateway activation database/Vault binding drift",
    )
    covers_checked(recheck_chain["observedAt"], recheck_chain["validUntil"], "participant gateway activation Gnosis chain check")
    require(
        {key: recheck_chain[key] for key in ("httpsOrigin", "request", "response")}
        == {key: chain[key] for key in ("httpsOrigin", "request", "response")},
        "participant gateway activation Gnosis chain binding drift",
    )
    require(
        {key: recheck_ingress[key] for key in ("target", "uid", "resourceVersion", "liveObjectSha256", "apiOutcome")}
        == {key: ingress[key] for key in ("target", "uid", "resourceVersion", "liveObjectSha256", "apiOutcome")},
        "participant gateway activation Ingress CAS identity drift",
    )
    for name in ("gnosis", "supabase"):
        covers_checked(recheck_dns_value[name]["observedAt"], recheck_dns_value[name]["validUntil"], f"participant gateway activation {name} DNS/TLS")
    require(checked >= utc_timestamp(flux["resourceAbsenceReceipts"][0]["observedAt"], "participant gateway Flux absence observedAt"), "participant gateway activation recheck predates Flux absence evidence")
    verify_participant_gateway_activation_transaction(evidence["activationTransaction"], flux)
    return evidence


def verify_participant_gateway_activation_rollback_baseline(
    activation_evidence: dict[str, Any],
    protected_base_root: Path,
) -> None:
    """Bind the gateway teardown plan to the protected pre-activation ingress.

    The activation candidate cannot choose this baseline: in pull-request
    admission ``protected_base_root`` is the protected base checkout.  The
    structural evidence validation has already checked the field shape; this
    function establishes the byte-for-byte CAS binding.
    """
    expected = bytes_digest(
        (protected_base_root / RENDER_ROOT / "web/ingress.json").read_bytes(),
    )
    require(
        activation_evidence["rollback"]["previousIngressSha256"] == expected,
        "participant gateway activation rollback ingress baseline drift",
    )


def verify_participant_gateway_activation_admission_freshness(
    activation_evidence: dict[str, Any],
) -> None:
    """Require activation to happen within the one reviewed preflight window.

    The policy constant is immutable once bootstrapped, so it must contain the
    read-only evidence.  This clock check runs only on the transition that
    grants rendering authority; routine promotions remain reproducible after
    the receipt expires.
    """
    now = participant_gateway_verification_time()
    recheck = activation_evidence["activationLiveRecheck"]
    checked = utc_timestamp(recheck["checkedAt"], "participant gateway activation live recheck checkedAt")
    valid_until = utc_timestamp(recheck["validUntil"], "participant gateway activation live recheck validUntil")
    require(
        checked <= now <= valid_until,
        "participant gateway activation evidence is future-dated or outside the current five-minute preflight",
    )


def verify_participant_gateway_runtime_pin(
    value: Any,
    participant_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if (
        isinstance(value, dict)
        and value.get("schemaVersion")
        == "roebel_staging_participant_gateway_runtime_pin_v5"
    ):
        return validate_synthetic_citizen_pass_gateway_runtime_pin(
            value,
            participant_policy,
        )
    try:
        activation_pin = PARTICIPANT_POLICY.expected_runtime_pin(participant_policy)
    except PARTICIPANT_POLICY.PolicyError as error:
        raise VerificationError(str(error)) from error
    release_pins = participant_gateway_runtime_release_pins(participant_policy)
    require(
        value in (activation_pin, *release_pins),
        "staging participant gateway runtime pin drift",
    )
    require("activationEvidence" not in value, "participant runtime pin may not carry live activation evidence")
    return copy.deepcopy(value)


def expected_synthetic_citizen_pass_gateway_runtime_pin(
    release: dict[str, Any],
    participant_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Deepen the v4 real verifier with one incompatible synthetic capability."""
    effective_policy = (
        PARTICIPANT_POLICY.APPROVED_NEXT_ACTIVATION_POLICY
        if participant_policy is None
        else participant_policy
    )
    require(
        effective_policy == PARTICIPANT_POLICY.APPROVED_NEXT_ACTIVATION_POLICY,
        "synthetic citizen pass requires the protected v4 gateway predecessor",
    )
    release = closed(
        release,
        {"sourceRevision", "sourceTreeSha256", "workflowSha256", "manifestDigest"},
        "synthetic participant gateway release",
    )
    require(
        isinstance(release["sourceRevision"], str)
        and REVISION.fullmatch(release["sourceRevision"]),
        "synthetic participant gateway source revision invalid",
    )
    for field in ("sourceTreeSha256", "workflowSha256", "manifestDigest"):
        require(
            isinstance(release[field], str) and SHA256.fullmatch(release[field]),
            f"synthetic participant gateway {field} invalid",
        )
    if release == IDENTITY_ROTATION.GATEWAY_RELEASE:
        predecessor = expected_synthetic_citizen_pass_gateway_runtime_pin({
            "sourceRevision": SYNTHETIC_CITIZEN_PASS_SOURCE_REVISION,
            "sourceTreeSha256": SYNTHETIC_CITIZEN_PASS_GATEWAY_SOURCE_TREE_SHA256,
            "workflowSha256": SYNTHETIC_CITIZEN_PASS_GATEWAY_WORKFLOW_SHA256,
            "manifestDigest": SYNTHETIC_CITIZEN_PASS_GATEWAY_MANIFEST_DIGEST,
        }, participant_policy)
        return IDENTITY_ROTATION.gateway_runtime_pin(predecessor)
    require(
        release
        == {
            "sourceRevision": SYNTHETIC_CITIZEN_PASS_SOURCE_REVISION,
            "sourceTreeSha256": SYNTHETIC_CITIZEN_PASS_GATEWAY_SOURCE_TREE_SHA256,
            "workflowSha256": SYNTHETIC_CITIZEN_PASS_GATEWAY_WORKFLOW_SHA256,
            "manifestDigest": SYNTHETIC_CITIZEN_PASS_GATEWAY_MANIFEST_DIGEST,
        },
        "synthetic participant gateway protected publication binding invalid",
    )
    value = copy.deepcopy(PARTICIPANT_POLICY.expected_runtime_pin(effective_policy))
    value["schemaVersion"] = "roebel_staging_participant_gateway_runtime_pin_v5"
    value["sourceRevision"] = release["sourceRevision"]
    value["sourceTreeSha256"] = release["sourceTreeSha256"]
    value["workflowSha256"] = release["workflowSha256"]
    value["manifestDigest"] = release["manifestDigest"]
    value["syntheticCitizenAdoptionMigrationSha256"] = (
        SYNTHETIC_CITIZEN_ADOPTION_MIGRATION_SHA256
    )
    value["syntheticCitizenAdoptionDatabaseSchemaSha256"] = (
        SYNTHETIC_CITIZEN_ADOPTION_DATABASE_SCHEMA_SHA256
    )
    value["syntheticCitizenAdoption"] = synthetic_citizen_pass_boundary()
    return value


def validate_synthetic_citizen_pass_gateway_runtime_pin(
    value: Any,
    participant_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Reject every v5 byte not derived from the exact v4 predecessor."""
    require(isinstance(value, dict), "synthetic participant gateway pin invalid")
    release = {
        field: value.get(field)
        for field in (
            "sourceRevision",
            "sourceTreeSha256",
            "workflowSha256",
            "manifestDigest",
        )
    }
    expected = expected_synthetic_citizen_pass_gateway_runtime_pin(
        release,
        participant_policy,
    )
    require(value == expected, "synthetic participant gateway runtime pin drift")
    return copy.deepcopy(value)


def participant_gateway_runtime_release_pins(
    participant_policy: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], ...]:
    """Return the exact append-only runtime release lineage."""
    effective_policy = (
        PARTICIPANT_POLICY.STATIC_ACTIVATION_POLICY
        if participant_policy is None
        else participant_policy
    )
    if effective_policy == PARTICIPANT_POLICY.APPROVED_NEXT_ACTIVATION_POLICY:
        # The v4 runtime pin is a new product/schema lineage. Historical v3
        # releases may not overwrite it through the generic release lane.
        return ()
    try:
        activation_pin = PARTICIPANT_POLICY.expected_runtime_pin(effective_policy)
    except PARTICIPANT_POLICY.PolicyError as error:
        raise VerificationError(str(error)) from error
    predecessor = activation_pin
    lineage: list[dict[str, Any]] = []
    for release in PARTICIPANT_GATEWAY_RUNTIME_RELEASES:
        require(
            predecessor["workflowSha256"] == release["workflowSha256"],
            "participant gateway release workflow predecessor drift",
        )
        successor = copy.deepcopy(predecessor)
        for key in ("sourceRevision", "sourceTreeSha256", "manifestDigest", "workflowSha256"):
            successor[key] = release[key]
        require(
            successor not in (activation_pin, *lineage),
            "participant gateway release lineage duplicate",
        )
        lineage.append(successor)
        predecessor = successor
    require(lineage, "participant gateway release lineage missing")
    return tuple(copy.deepcopy(value) for value in lineage)


def expected_participant_gateway_runtime_release_predecessor_pin(
    participant_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the exact predecessor of the newest admitted runtime release."""
    try:
        activation_pin = PARTICIPANT_POLICY.expected_runtime_pin(participant_policy)
    except PARTICIPANT_POLICY.PolicyError as error:
        raise VerificationError(str(error)) from error
    lineage = participant_gateway_runtime_release_pins(participant_policy)
    require(lineage, "participant gateway runtime release lineage unavailable")
    return copy.deepcopy(lineage[-2] if len(lineage) > 1 else activation_pin)


def expected_participant_gateway_runtime_release_pin(
    participant_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the newest exact post-activation gateway runtime successor."""
    lineage = participant_gateway_runtime_release_pins(participant_policy)
    require(lineage, "participant gateway runtime release lineage unavailable")
    return copy.deepcopy(lineage[-1])


def participant_gateway_ingress_sources() -> list[dict[str, Any]]:
    return [
        {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "ingress-system"}}},
        *[{"ipBlock": {"cidr": cidr}} for cidr in (
            "10.42.0.10/32", "10.42.0.11/32", "10.42.0.12/32",
            "10.244.0.0/32", "10.244.1.0/32", "10.244.2.0/32",
            "10.244.0.1/32", "10.244.1.1/32", "10.244.2.1/32",
        )],
    ]


def expected_participant_gateway_ingress(
    participant_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        return PARTICIPANT_POLICY.expected_gateway_ingress(participant_policy)
    except PARTICIPANT_POLICY.PolicyError as error:
        raise VerificationError(str(error)) from error


def synthetic_gateway_early_allowlist() -> str:
    exact_paths = [
        *PARTICIPANT_POLICY.ROUTES,
        *SYNTHETIC_CITIZEN_PASS_POST_ROUTES,
    ]
    post_paths = [
        *PARTICIPANT_POLICY.POST_ROUTES,
        *SYNTHETIC_CITIZEN_PASS_POST_ROUTES,
    ]
    dynamic_get_prefixes = [
        *PARTICIPANT_POLICY.DYNAMIC_GET_PREFIXES,
        SYNTHETIC_CITIZEN_PASS_DYNAMIC_GET_PREFIX,
    ]
    return "\n".join([
        "http-request deny deny_status 404 if "
        + f"!{{ path {' '.join(exact_paths)} }} "
        + f"!{{ path_beg {' '.join(dynamic_get_prefixes)} }}",
        "http-request deny deny_status 405 if { method POST } "
        + " ".join(f"!{{ path {path} }}" for path in post_paths),
        "http-request deny deny_status 405 if { method OPTIONS } "
        + " ".join(f"!{{ path {path} }}" for path in exact_paths),
        "http-request deny deny_status 405 if { method HEAD }",
        "http-request deny deny_status 405 if { method GET } "
        + " ".join([
            f"!{{ path {exact_paths[0]} }}",
            *(f"!{{ path_beg {prefix} }}" for prefix in dynamic_get_prefixes),
        ]),
        "http-request deny deny_status 405 unless { method GET HEAD POST OPTIONS }",
        "stick-table type ip size 10k expire 60s store http_req_rate(1m)",
        "http-request track-sc0 src",
        "http-request deny deny_status 429 if { sc_http_req_rate(0) gt 30 }",
    ])


def expected_synthetic_citizen_pass_gateway_ingress() -> dict[str, Any]:
    value = expected_participant_gateway_ingress(
        PARTICIPANT_POLICY.APPROVED_NEXT_ACTIVATION_POLICY,
    )
    value["metadata"]["annotations"][
        "haproxy-ingress.github.io/config-backend-early"
    ] = synthetic_gateway_early_allowlist()
    return value


def expected_participant_gateway_resources(
    runtime_pin: dict[str, Any],
    participant_policy: dict[str, Any] | None = None,
    *,
    civic_projection_route: bool = False,
) -> dict[str, Any]:
    """Compatibility adapter to the single protected policy module."""
    try:
        expected = PARTICIPANT_POLICY.expected_gateway_resources(
            participant_policy,
            include_web_presentation=civic_projection_route,
        )
    except PARTICIPANT_POLICY.PolicyError as error:
        raise VerificationError(str(error)) from error
    activation_pin = expected["runtimePin"]
    release_pins = participant_gateway_runtime_release_pins(participant_policy)
    synthetic_pin = (
        runtime_pin.get("schemaVersion")
        == "roebel_staging_participant_gateway_runtime_pin_v5"
    )
    if synthetic_pin:
        validate_synthetic_citizen_pass_gateway_runtime_pin(
            runtime_pin,
            participant_policy,
        )
    require(
        runtime_pin in (activation_pin, *release_pins) or synthetic_pin,
        "participant runtime pin differs from protected policy or approved runtime release",
    )
    if runtime_pin != activation_pin:
        expected = copy.deepcopy(expected)
        expected["runtimePin"] = copy.deepcopy(runtime_pin)
        container = expected["deployment"]["spec"]["template"]["spec"]["containers"][0]
        environment = {item["name"]: item for item in container["env"]}
        require(
            len(environment) == len(container["env"]),
            "participant gateway deployment environment names are not unique",
        )
        environment["ROEBEL_STAGING_PARTICIPANT_GATEWAY_SOURCE_REVISION"]["value"] = runtime_pin["sourceRevision"]
        environment["ROEBEL_STAGING_PARTICIPANT_GATEWAY_MANIFEST_DIGEST"]["value"] = runtime_pin["manifestDigest"]
        container["image"] = runtime_pin["imageRepository"] + "@" + runtime_pin["manifestDigest"]
        if synthetic_pin:
            present = SYNTHETIC_CITIZEN_PASS_ENV_NAMES & set(environment)
            require(
                not present,
                "synthetic participant gateway predecessor environment is partial",
            )
            synthetic_environment = (
                IDENTITY_ROTATION.gateway_environment(SYNTHETIC_CITIZEN_PASS_ENV)
                if runtime_pin["sourceRevision"] == IDENTITY_ROTATION.SOURCE_REVISION
                else copy.deepcopy(SYNTHETIC_CITIZEN_PASS_ENV)
            )
            container["env"].extend(synthetic_environment)
            expected["ingress"] = expected_synthetic_citizen_pass_gateway_ingress()
    return {
        "deployment": expected["deployment"],
        "service": expected["service"],
        "networkPolicy": expected["networkPolicy"],
        "serviceAccount": expected["serviceAccount"],
        "ingress": expected["ingress"],
        "kustomization": expected["kustomization"],
        "workbenchIngressNetworkPolicy": expected["workbenchIngressNetworkPolicy"],
        "workbenchIngressKustomization": expected["workbenchIngressKustomization"],
    }


def _legacy_expected_participant_gateway_resources(runtime_pin: dict[str, Any]) -> dict[str, Any]:
    evidence = runtime_pin["activationEvidence"]
    egress = evidence["egress"]
    pod_security = {
        "fsGroup": 65532, "runAsGroup": 65532, "runAsNonRoot": True,
        "runAsUser": 65532, "seccompProfile": {"type": "RuntimeDefault"},
    }
    container_security = {
        "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
        "readOnlyRootFilesystem": True,
    }
    tcp_probe = lambda threshold, period: {
        "failureThreshold": threshold, "periodSeconds": period, "successThreshold": 1,
        "tcpSocket": {"port": "http"}, "timeoutSeconds": 3,
    }
    environment = [
        {"name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY", "value": "enabled"},
        {"name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_HOST", "value": "0.0.0.0"},
        {"name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_PORT", "value": str(PARTICIPANT_GATEWAY_PORT)},
        {"name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_ORIGIN", "value": PARTICIPANT_GATEWAY_ORIGIN},
        participant_gateway_secret_env("ROEBEL_STAGING_PARTICIPANT_GATEWAY_INVITE_SHA256", PARTICIPANT_GATEWAY_CONFIG_SECRET, "invite-sha256"),
        participant_gateway_secret_env("ROEBEL_STAGING_PARTICIPANT_GATEWAY_ALLOWED_WALLETS", PARTICIPANT_GATEWAY_CONFIG_SECRET, "allowed-wallets"),
        participant_gateway_secret_env("ROEBEL_STAGING_PARTICIPANT_GATEWAY_SESSION_KEY", PARTICIPANT_GATEWAY_RUNTIME_SECRET, "session-key"),
        # Origins are reviewed policy data, not credentials.  Keeping them
        # literal binds the Deployment and its NetworkPolicy to exactly the
        # DNS/TLS evidence above; Secrets retain only secret material.
        {"name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_GNOSIS_RPC_URL", "value": egress["gnosis"]["httpsOrigin"]},
        {"name": "ROEBEL_STAGING_PARTICIPANT_GATEWAY_SUPABASE_URL", "value": egress["supabase"]["httpsOrigin"]},
        participant_gateway_secret_env("ROEBEL_STAGING_PARTICIPANT_GATEWAY_SUPABASE_ANON_KEY", PARTICIPANT_GATEWAY_RUNTIME_SECRET, "supabase-anon-key"),
        participant_gateway_secret_env("ROEBEL_STAGING_PARTICIPANT_GATEWAY_SUPABASE_RPC_SECRET", PARTICIPANT_GATEWAY_RUNTIME_SECRET, "supabase-rpc-secret"),
    ]
    deployment = {
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"labels": PARTICIPANT_GATEWAY_LABELS, "name": PARTICIPANT_GATEWAY_NAME, "namespace": PARTICIPANT_GATEWAY_NAMESPACE},
        "spec": {
            "replicas": 1, "selector": {"matchLabels": PARTICIPANT_GATEWAY_LABELS},
            "strategy": {"type": "Recreate"},
            "template": {
                "metadata": {"labels": PARTICIPANT_GATEWAY_LABELS},
                "spec": {
                    "automountServiceAccountToken": False, "restartPolicy": "Always",
                    "serviceAccountName": PARTICIPANT_GATEWAY_NAME, "securityContext": pod_security,
                    "volumes": [{"emptyDir": {"sizeLimit": "64Mi"}, "name": "tmp"}],
                    "containers": [{
                        "env": environment,
                        "image": f"{runtime_pin['imageRepository']}@{runtime_pin['manifestDigest']}",
                        "imagePullPolicy": "IfNotPresent", "name": "staging-participant-gateway",
                        "ports": [{"containerPort": PARTICIPANT_GATEWAY_PORT, "name": "http", "protocol": "TCP"}],
                        "readinessProbe": tcp_probe(3, 10), "livenessProbe": tcp_probe(3, 20), "startupProbe": tcp_probe(30, 2),
                        "resources": {"limits": {"cpu": "200m", "memory": "128Mi"}, "requests": {"cpu": "50m", "memory": "64Mi"}},
                        "securityContext": container_security,
                        "volumeMounts": [{"mountPath": "/tmp", "name": "tmp"}],
                    }],
                },
            },
        },
    }
    service = {
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"labels": PARTICIPANT_GATEWAY_LABELS, "name": PARTICIPANT_GATEWAY_NAME, "namespace": PARTICIPANT_GATEWAY_NAMESPACE},
        "spec": {"ports": [{"name": "http", "port": PARTICIPANT_GATEWAY_PORT, "protocol": "TCP", "targetPort": "http"}], "selector": PARTICIPANT_GATEWAY_LABELS, "type": "ClusterIP"},
    }
    network_policy = {
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
        "metadata": {"labels": PARTICIPANT_GATEWAY_LABELS, "name": PARTICIPANT_GATEWAY_NAME, "namespace": PARTICIPANT_GATEWAY_NAMESPACE},
        "spec": {
            "podSelector": {"matchLabels": PARTICIPANT_GATEWAY_LABELS}, "policyTypes": ["Ingress", "Egress"],
            "ingress": [{"from": participant_gateway_ingress_sources(), "ports": [{"port": PARTICIPANT_GATEWAY_PORT, "protocol": "TCP"}]}],
            "egress": [
                {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}, "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}], "ports": [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}]},
                *[{"to": [{"ipBlock": {"cidr": cidr}}], "ports": [{"port": 443, "protocol": "TCP"}]} for endpoint in (egress["gnosis"], egress["supabase"]) for cidr in endpoint["ipv4Cidrs"]],
            ],
        },
    }
    service_account = {
        "apiVersion": "v1", "kind": "ServiceAccount",
        "metadata": {"labels": PARTICIPANT_GATEWAY_LABELS, "name": PARTICIPANT_GATEWAY_NAME, "namespace": PARTICIPANT_GATEWAY_NAMESPACE},
        "automountServiceAccountToken": False,
    }
    kustomization = (
        "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n"
        "  - serviceaccount.json\n  - deployment.json\n  - service.json\n  - networkpolicy.json\n  - ingress.json\n"
    )
    return {"deployment": deployment, "service": service, "networkPolicy": network_policy, "serviceAccount": service_account, "ingress": expected_participant_gateway_ingress(), "kustomization": kustomization}


def verify_participant_gateway(
    root: Path,
    participant_policy: dict[str, Any],
) -> dict[str, Any]:
    runtime_pin = verify_participant_gateway_runtime_pin(
        load_json(root / PARTICIPANT_GATEWAY_ROOT / "runtime-pin.json"),
        participant_policy,
    )
    actual = {
        "deployment": load_json(root / PARTICIPANT_GATEWAY_ROOT / "deployment.json"),
        "service": load_json(root / PARTICIPANT_GATEWAY_ROOT / "service.json"),
        "networkPolicy": load_json(root / PARTICIPANT_GATEWAY_ROOT / "networkpolicy.json"),
        "serviceAccount": load_json(root / PARTICIPANT_GATEWAY_ROOT / "serviceaccount.json"),
        "ingress": load_json(root / PARTICIPANT_GATEWAY_ROOT / "ingress.json"),
        "kustomization": (root / PARTICIPANT_GATEWAY_ROOT / "kustomization.yaml").read_text(),
        "workbenchIngressNetworkPolicy": load_json(
            root / PARTICIPANT_POLICY.WORKBENCH_INGRESS_ROOT / "networkpolicy.json",
        ),
        "workbenchIngressKustomization": (
            root / PARTICIPANT_POLICY.WORKBENCH_INGRESS_ROOT / "kustomization.yaml"
        ).read_text(),
    }
    legacy = expected_participant_gateway_resources(
        runtime_pin,
        participant_policy,
        civic_projection_route=False,
    )
    civic_projection = expected_participant_gateway_resources(
        runtime_pin,
        participant_policy,
        civic_projection_route=True,
    )
    if actual["workbenchIngressNetworkPolicy"] == legacy["workbenchIngressNetworkPolicy"]:
        expected = legacy
        civic_projection_route = False
    elif actual["workbenchIngressNetworkPolicy"] == civic_projection["workbenchIngressNetworkPolicy"]:
        expected = civic_projection
        civic_projection_route = True
    else:
        raise VerificationError("staging participant gateway workbench ingress policy drift")
    require(actual == expected, "staging participant gateway resource drift")
    return {
        "runtimePin": runtime_pin,
        "civicProjectionRoute": civic_projection_route,
        **actual,
    }


def expected_web_ingress(signed_nostr: bool, participant_gateway: bool = False) -> dict[str, Any]:
    # Participant routing is a separate, longer-prefix Ingress.  Keep this
    # compatibility parameter inert so every existing Web byte stays fixed.
    participant_gateway = False
    early = (
        "http-request deny deny_status 405 if { method POST } !{ path /api/chat/mecky }\n"
        "http-request deny deny_status 405 unless { method GET HEAD POST }\n"
        "http-request deny deny_status 404 if { path_beg /api } !{ path_beg /api/public-feed/ } !{ path_beg /api/civic/v1/ } !{ path /api/notifications/unread-count } !{ path /api/chat/mecky }"
    )
    paths = [
        {
            "backend": {"service": {
                "name": "roebel-supabase-read-gateway",
                "port": {"name": "http"},
            }},
            "path": "/supabase-read",
            "pathType": "Prefix",
        },
    ]
    if signed_nostr:
        early = (
            "http-request deny deny_status 405 if { method POST } !{ path /api/chat/mecky } !{ path /stadtstack-test/api/session/admit } !{ path /stadtstack-test/api/signed-event }\n"
            "http-request deny deny_status 405 unless { method GET HEAD POST }\n"
            "http-request deny deny_status 404 if { path_beg /api } !{ path_beg /api/public-feed/ } !{ path_beg /api/civic/v1/ } !{ path /api/notifications/unread-count } !{ path /api/chat/mecky }\n"
            "http-request deny deny_status 404 if { path_beg /stadtstack-test } !{ path /stadtstack-test/healthz } !{ path /stadtstack-test/api/config } !{ path /stadtstack-test/api/feed } !{ path /stadtstack-test/api/thread } !{ path /stadtstack-test/api/conversation } !{ path /stadtstack-test/api/session/admit } !{ path /stadtstack-test/api/signed-event }"
        )
        paths.append({
            "backend": {"service": {
                "name": "roebel-staging-workbench",
                "port": {"name": "http"},
            }},
            "path": "/stadtstack-test",
            "pathType": "Prefix",
        })
    if participant_gateway:
        participant_paths = (
            "/api/staging-participant/v1/status",
            "/api/staging-participant/v1/challenge",
            "/api/staging-participant/v1/session",
            "/api/staging-participant/v1/posts",
            "/api/staging-participant/v1/comments",
        )
        post_paths = participant_paths[1:]
        early_lines = early.split("\n")
        early_lines[0] += " " + " ".join(f"!{{ path {path} }}" for path in post_paths)
        early_lines.insert(
            1,
            "http-request deny deny_status 405 if { method OPTIONS } "
            + " ".join(f"!{{ path {path} }}" for path in participant_paths),
        )
        early_lines.insert(
            2,
            "http-request deny deny_status 405 if { path_beg /api/staging-participant/v1/ } { method HEAD }",
        )
        early_lines.insert(
            3,
            "http-request deny deny_status 405 if { method GET } { path_beg /api/staging-participant/v1/ } !{ path /api/staging-participant/v1/status }",
        )
        early_lines[4] = "http-request deny deny_status 405 unless { method GET HEAD POST OPTIONS }"
        api_line = next(
            index
            for index, line in enumerate(early_lines)
            if line.startswith("http-request deny deny_status 404 if { path_beg /api } ")
        )
        early_lines[api_line] += " !{ path_beg /api/staging-participant/v1/ }"
        participant_guard = (
            "http-request deny deny_status 404 if { path_beg /api/staging-participant/v1/ } "
            + " ".join(f"!{{ path {path} }}" for path in participant_paths)
        )
        early_lines.insert(api_line + 1, participant_guard)
        early_lines.extend([
            "stick-table type ip size 10k expire 60s store http_req_rate(1m)",
            "http-request track-sc0 src if { path_beg /api/staging-participant/v1/ }",
            "http-request deny deny_status 429 if { path_beg /api/staging-participant/v1/ } { sc_http_req_rate(0) gt 30 }",
        ])
        early = "\n".join(early_lines)
        paths.append({
            "backend": {"service": {
                "name": PARTICIPANT_GATEWAY_NAME,
                "port": {"name": "http"},
            }},
            "path": "/api/staging-participant/v1",
            "pathType": "Prefix",
        })
    paths.append({
        "backend": {"service": {
            "name": "roebel-web-presentation",
            "port": {"name": "http"},
        }},
        "path": "/",
        "pathType": "Prefix",
    })
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {
            "annotations": {
                "haproxy-ingress.github.io/config-backend": (
                    "http-response set-header X-Stadtstack-Public-Boundary roebel-web-readonly-presentation\n"
                    "http-response set-header X-Robots-Tag noindex,nofollow,noarchive\n"
                    "http-response set-header X-Frame-Options DENY\n"
                    "http-response set-header X-Content-Type-Options nosniff\n"
                    "http-response set-header Referrer-Policy no-referrer\n"
                    "http-response set-header Content-Security-Policy \"default-src 'self'; base-uri 'none'; form-action 'none'; object-src 'none'; frame-ancestors 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data: blob: https:; connect-src 'self' https://roebel-stadtstack.agentcart.eu https://embedded-wallet.thirdweb.com https://api.thirdweb.com https://100.rpc.thirdweb.com; frame-src https://embedded-wallet.thirdweb.com; worker-src 'self' blob:;\""
                ),
                "haproxy-ingress.github.io/config-backend-early": early,
            },
            "labels": {
                "app.kubernetes.io/component": "readonly-presentation",
                "app.kubernetes.io/name": "roebel-web-presentation",
                "app.kubernetes.io/part-of": "stadtstack",
                "stadtstack.io/authority": "none",
            },
            "name": "roebel-web-presentation",
            "namespace": "stadtstack-roebel-web-preview",
        },
        "spec": {
            "ingressClassName": "haproxy",
            "rules": [{
                "host": "roebel-web.staging.agentcart.eu",
                "http": {
                    "paths": paths
                },
            }],
            "tls": [{
                "hosts": ["roebel-web.staging.agentcart.eu"],
                "secretName": "roebel-web-presentation-tls",
            }],
        },
    }


def verify_web_ingress(root: Path, signed_nostr: bool, participant_gateway: bool = False) -> dict[str, Any]:
    ingress = load_json(root / RENDER_ROOT / "web/ingress.json")
    require(ingress == expected_web_ingress(signed_nostr, participant_gateway), "Web Ingress drift")
    return ingress


def bind_public_mecky_reviewed_web_source_boundary(
    receipt: dict[str, Any],
    public_mecky_network_policy: dict[str, Any],
) -> None:
    receipt["boundary"]["publicMeckyReviewedWebSource"] = {
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
        "knowledgeOrigin": PUBLIC_MECKY_REVIEWED_WEB_SOURCE_BASE_URL,
        "port": 8080,
        "protocol": "TCP",
        "publicIndexOrigin": None,
        "source": {
            "namespace": "stadtstack-roebel-staging-lab",
            "podSelector": PUBLIC_MECKY_LABELS,
        },
        "sourceKinds": REVIEWED_PUBLIC_KNOWLEDGE_SOURCE_KINDS,
    }
    policy_receipt = {
        "kind": "NetworkPolicy",
        "name": "public-mecky-chat-from-web",
        "namespace": "stadtstack-roebel-staging-lab",
        "sha256": digest(public_mecky_network_policy),
    }
    existing = [
        item
        for item in receipt["objects"]
        if item.get("kind") == "NetworkPolicy"
        and item.get("name") == "public-mecky-chat-from-web"
        and item.get("namespace") == "stadtstack-roebel-staging-lab"
    ]
    require(len(existing) <= 1, "Public Mecky boundary receipt repeated")
    if existing:
        existing[0].clear()
        existing[0].update(policy_receipt)
    else:
        receipt["objects"].append(policy_receipt)


def verify_network_boundary_migration(
    root: Path,
    web_network_policy: dict[str, Any],
    web_ingress: dict[str, Any],
    public_mecky_network_policy: dict[str, Any],
    signed_nostr: bool,
    participant_gateway: bool = False,
    participant_gateway_objects: dict[str, Any] | None = None,
    civic_projection_route: bool = False,
    tracer_feed_route: bool = False,
    reviewed_web_source: bool = False,
    participant_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    migration = load_json(root / RENDER_ROOT / "network-boundary-migration.json")
    if participant_gateway:
        require(participant_gateway_objects is not None, "participant gateway boundary objects unavailable")
        require(participant_policy is not None, "participant gateway policy unavailable")
        gateway_http = participant_gateway_http_contract(participant_policy)
        ingress_paths = gateway_http["exactGatewayPaths"]
        post_paths = gateway_http["methodPathMatrix"]["POST"]
        gateway_flux = expected_participant_gateway_flux_objects()
        workbench_flux = expected_participant_workbench_ingress_flux_objects()
        objects = [
            {"kind": "NetworkPolicy", "name": "roebel-web-presentation", "namespace": PARTICIPANT_GATEWAY_NAMESPACE, "sha256": digest(web_network_policy)},
            {"kind": "Ingress", "name": "roebel-web-presentation", "namespace": PARTICIPANT_GATEWAY_NAMESPACE, "sha256": digest(web_ingress)},
            {"kind": "ServiceAccount", "name": PARTICIPANT_GATEWAY_NAME, "namespace": PARTICIPANT_GATEWAY_NAMESPACE, "sha256": digest(participant_gateway_objects["serviceAccount"])},
            {"kind": "Deployment", "name": PARTICIPANT_GATEWAY_NAME, "namespace": PARTICIPANT_GATEWAY_NAMESPACE, "sha256": digest(participant_gateway_objects["deployment"])},
            {"kind": "Service", "name": PARTICIPANT_GATEWAY_NAME, "namespace": PARTICIPANT_GATEWAY_NAMESPACE, "sha256": digest(participant_gateway_objects["service"])},
            {"kind": "NetworkPolicy", "name": PARTICIPANT_GATEWAY_NAME, "namespace": PARTICIPANT_GATEWAY_NAMESPACE, "sha256": digest(participant_gateway_objects["networkPolicy"])},
            {"kind": "Ingress", "name": PARTICIPANT_GATEWAY_NAME, "namespace": PARTICIPANT_GATEWAY_NAMESPACE, "sha256": digest(participant_gateway_objects["ingress"])},
            {"kind": "NetworkPolicy", "name": PARTICIPANT_POLICY.WORKBENCH_INGRESS_POLICY_NAME, "namespace": PARTICIPANT_POLICY.WORKBENCH_NAMESPACE, "sha256": digest(participant_gateway_objects["workbenchIngressNetworkPolicy"])},
        ]
        expected = {
            "authority": "none",
            "boundary": {
                "ingress": {
                    "allowedMethods": ["GET", "POST", "OPTIONS"],
                    "exactGatewayPaths": ingress_paths,
                    "exactPostPaths": post_paths,
                    **(
                        {"dynamicGetPrefixes": gateway_http["dynamicGetPrefixes"]}
                        if "dynamicGetPrefixes" in gateway_http
                        else {}
                    ),
                    "gatewayMethodPathMatrix": gateway_http["methodPathMatrix"],
                    **(
                        {"routeProbeSamples": gateway_http["routeProbeSamples"]}
                        if "routeProbeSamples" in gateway_http
                        else {}
                    ),
                    "rateLimit": {
                        "aggregateClaimAllowed": False,
                        "requestsPerMinutePerSourceIp": 30,
                        "scope": "gateway-paths-only-per-controller-replica",
                    },
                    "resource": {"kind": "Ingress", "name": PARTICIPANT_GATEWAY_NAME, "namespace": PARTICIPANT_GATEWAY_NAMESPACE},
                },
                "participantGateway": {
                    "namespace": PARTICIPANT_GATEWAY_NAMESPACE,
                    "name": PARTICIPANT_GATEWAY_NAME,
                    "replicas": 1,
                    "serviceAccountToken": False,
                    "writerAuthority": "fixed-staging-rpcs-only",
                    "civicAuthority": "none",
                    "egress": "dns-plus-policy-pinned-gnosis-internal-postgrest-and-exact-workbench-only",
                    "internalPostgrest": {
                        "destinationNamespace": PARTICIPANT_POLICY.WORKBENCH_NAMESPACE,
                        "destinationPodLabels": PARTICIPANT_POLICY.TRACER_POSTGREST_LABELS,
                        "externalIngress": False,
                        "origin": PARTICIPANT_POLICY.TRACER_POSTGREST_ORIGIN,
                        "port": PARTICIPANT_POLICY.TRACER_POSTGREST_PORT,
                        "projectionSecret": {
                            "keys": list(TRACER_DATA_PLANE.PARTICIPANT_POSTGREST_SECRET_KEYS),
                            "name": TRACER_DATA_PLANE.PARTICIPANT_POSTGREST_SECRET,
                            "namespace": TRACER_DATA_PLANE.PREVIEW_NAMESPACE,
                            "valuesCommitted": False,
                        },
                    },
                },
                "tracerActivation": {
                    "applicationObjectCount": len(TRACER_DATA_PLANE.application_object_order()),
                    "createBeforeUnsuspend": True,
                    "runner": TRACER_DATA_PLANE.LIVE_RUNNER,
                    "secretMaterializerRunner": TRACER_DATA_PLANE.SECRET_MATERIALIZER_RUNNER,
                    "sharedSourceMutation": "forbidden",
                },
                "workbenchIngress": {
                    "name": PARTICIPANT_POLICY.WORKBENCH_INGRESS_POLICY_NAME,
                    "namespace": PARTICIPANT_POLICY.WORKBENCH_NAMESPACE,
                    "port": PARTICIPANT_POLICY.WORKBENCH_PORT,
                    "existingPolicyMutation": "forbidden",
                    "source": {
                        "namespace": PARTICIPANT_GATEWAY_NAMESPACE,
                        "podSelector": PARTICIPANT_GATEWAY_LABELS,
                    },
                },
                "signedNostr": "retained-exact" if signed_nostr else "not-present",
            },
            "effects": {"civicMutation": False, "clusterMutation": False, "secretRead": False, "secretWrite": False},
            "objects": objects,
            "rbacBootstrap": {
                "required": True,
                "transaction": "cas-unsuspend-both-or-suspend-both",
                "reconcilers": [
                    {
                        "kustomization": gateway_flux["kustomization"]["metadata"],
                        "roleNamespace": gateway_flux["role"]["metadata"]["namespace"],
                        "rules": gateway_flux["role"]["rules"],
                        "serviceAccount": gateway_flux["serviceAccount"]["metadata"],
                    },
                    {
                        "kustomization": workbench_flux["kustomization"]["metadata"],
                        "roleNamespace": workbench_flux["role"]["metadata"]["namespace"],
                        "rules": workbench_flux["role"]["rules"],
                        "serviceAccount": workbench_flux["serviceAccount"]["metadata"],
                    },
                ],
                "liveMutationPerformed": False,
            },
            "schemaVersion": "roebel_staging_participant_gateway_boundary_v1",
            "status": "approved-for-exact-staging-activation",
        }
        if civic_projection_route:
            gateway_source = {
                "namespace": PARTICIPANT_GATEWAY_NAMESPACE,
                "podSelector": PARTICIPANT_GATEWAY_LABELS,
            }
            web_source = {
                "namespace": PARTICIPANT_GATEWAY_NAMESPACE,
                "podSelector": WEB_PRESENTATION_LABELS,
            }
            expected["boundary"]["workbenchIngress"] = {
                "name": PARTICIPANT_POLICY.WORKBENCH_INGRESS_POLICY_NAME,
                "namespace": PARTICIPANT_POLICY.WORKBENCH_NAMESPACE,
                "port": PARTICIPANT_POLICY.WORKBENCH_PORT,
                "existingPolicyMutation": "forbidden",
                "sources": [gateway_source, web_source],
            }
            expected["boundary"]["webCivicProjection"] = {
                "authority": "none",
                "destinationNamespace": PARTICIPANT_POLICY.WORKBENCH_NAMESPACE,
                "destinationPodLabels": PARTICIPANT_POLICY.WORKBENCH_SELECTOR,
                "port": PARTICIPANT_POLICY.WORKBENCH_PORT,
                "protocol": "TCP",
                "source": web_source,
                "upstreamUrl": CIVIC_PROJECTION_UPSTREAM_URL,
            }
        if tracer_feed_route:
            expected["boundary"]["webTracerFeed"] = {
                "authority": "none",
                "credentialSecret": {
                    "key": TRACER_DATA_PLANE.WEB_FEED_SECRET_KEYS[0],
                    "name": TRACER_DATA_PLANE.WEB_FEED_SECRET,
                    "namespace": TRACER_DATA_PLANE.PREVIEW_NAMESPACE,
                    "valuesCommitted": False,
                },
                "destinationNamespace": TRACER_DATA_PLANE.NAMESPACE,
                "destinationPodLabels": TRACER_DATA_PLANE.POSTGREST_LABELS,
                "port": TRACER_DATA_PLANE.POSTGREST_PORT,
                "protocol": "TCP",
                "source": {
                    "namespace": PARTICIPANT_GATEWAY_NAMESPACE,
                    "podSelector": WEB_PRESENTATION_LABELS,
                },
                "upstreamUrl": TRACER_DATA_PLANE.POSTGREST_CLUSTER_URL,
            }
        if reviewed_web_source:
            bind_public_mecky_reviewed_web_source_boundary(
                expected,
                public_mecky_network_policy,
            )
        require(migration == expected, "participant gateway network-boundary receipt drift")
        return migration
    if signed_nostr:
        expected_signed_nostr = {
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
                    "resource": {"kind": "Ingress", "name": "roebel-web-presentation", "namespace": SIGNED_NOSTR_WEB_NAMESPACE},
                },
                "publicMeckyRelayEgress": {
                    "destinationNamespace": SIGNED_NOSTR_NAMESPACE,
                    "destinationPorts": [18081],
                    "relays": ["citizen-relay", "agent-relay"],
                    "resource": {"kind": "NetworkPolicy", "name": "public-mecky-chat-from-web", "namespace": SIGNED_NOSTR_NAMESPACE},
                },
                "relays": {
                    "ingress": "workbench-only",
                    "ingressClass": "none",
                    "namespace": SIGNED_NOSTR_NAMESPACE,
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
            "effects": {"civicMutation": False, "clusterMutation": False, "secretRead": False, "secretWrite": False},
            "objects": [
                {"kind": "NetworkPolicy", "name": "public-mecky-chat-from-web", "namespace": SIGNED_NOSTR_NAMESPACE, "sha256": digest(public_mecky_network_policy)},
                {"kind": "Ingress", "name": "roebel-web-presentation", "namespace": SIGNED_NOSTR_WEB_NAMESPACE, "sha256": digest(web_ingress)},
            ],
            "rbacBootstrap": {
                "createAllowed": False,
                "deleteAllowed": False,
                "listAllowed": False,
                "required": True,
                "roleNamespace": SIGNED_NOSTR_WEB_NAMESPACE,
                "serviceAccount": {"name": "roebel-web-reconciler", "namespace": "flux-roebel-staging"},
                "watchAllowed": False,
                "rules": [
                    {"apiGroups": ["networking.k8s.io"], "resourceNames": ["roebel-web-presentation"], "resources": ["networkpolicies"], "verbs": ["get", "patch", "update"]},
                    {"apiGroups": ["networking.k8s.io"], "resourceNames": ["roebel-web-presentation"], "resources": ["ingresses"], "verbs": ["get", "patch", "update"]},
                ],
                "liveMutationPerformed": False,
            },
            "schemaVersion": "roebel_staging_signed_nostr_boundary_v1",
            "status": "blocked_pending_separately_reviewed_signed_nostr_evidence",
        }
        if reviewed_web_source:
            bind_public_mecky_reviewed_web_source_boundary(
                expected_signed_nostr,
                public_mecky_network_policy,
            )
        require(migration == expected_signed_nostr, "signed-Nostr network-boundary receipt drift")
        return migration
    expected = {
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
                "sha256": digest(web_network_policy),
            },
            {
                "kind": "Ingress",
                "name": "roebel-web-presentation",
                "namespace": "stadtstack-roebel-web-preview",
                "sha256": digest(web_ingress),
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
    if reviewed_web_source:
        bind_public_mecky_reviewed_web_source_boundary(
            expected,
            public_mecky_network_policy,
        )
    require(migration == expected, "network-boundary migration receipt drift")
    return migration


def verify_kustomizations(
    root: Path,
    signed_nostr: bool,
    participant_gateway: bool = False,
    workbench_baseline: bool = True,
) -> None:
    public_expected = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - deployment.json\n  - service.json\n  - networkpolicy.json\n"
    web_expected = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - deployment.json\n  - networkpolicy.json\n  - ingress.json\n"
    require((root / RENDER_ROOT / "public-mecky/kustomization.yaml").read_text() == public_expected, "public-mecky Flux path widened")
    require((root / RENDER_ROOT / "web/kustomization.yaml").read_text() == web_expected, "roebel-web-staging Flux path widened")
    if workbench_baseline:
        try:
            WORKBENCH_BASELINE.validate_kustomization_text(
                (root / WORKBENCH_BASELINE.KUSTOMIZATION_PATH).read_text(),
            )
        except WORKBENCH_BASELINE.HandoverError as error:
            raise VerificationError(f"workbench baseline Flux path widened: {error}") from error
    if signed_nostr:
        for component in SIGNED_NOSTR_COMPONENTS:
            extra = ""
            if component == "workbench":
                extra = "  - gnosis-proxy-deployment.json\n  - gnosis-proxy-service.json\n  - gnosis-proxy-networkpolicy.json\n"
            expected = (
                "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n"
                "  - deployment.json\n  - service.json\n  - networkpolicy.json\n"
                + extra
            )
            require(
                (root / SIGNED_NOSTR_ROOT / component / "kustomization.yaml").read_text() == expected,
                f"signed-Nostr {component} Flux path widened",
            )
    if participant_gateway:
        expected = (
            "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n"
            "  - networkpolicy.json\n  - serviceaccount.json\n  - service.json\n  - deployment.json\n  - ingress.json\n"
        )
        require(
            (root / PARTICIPANT_GATEWAY_ROOT / "kustomization.yaml").read_text() == expected,
            "staging participant gateway Flux path widened",
        )
        reciprocal_expected = (
            "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n"
            "  - networkpolicy.json\n"
        )
        require(
            (root / PARTICIPANT_POLICY.WORKBENCH_INGRESS_ROOT / "kustomization.yaml").read_text()
            == reciprocal_expected,
            "staging participant reciprocal workbench Flux path widened",
        )


def expected_patch_value(component: str, path: str, head: dict[str, Any]) -> str:
    record = component_map(head)[component]
    if path in {
        "/metadata/annotations/stadtstack.io~1source-revision",
        "/spec/template/metadata/annotations/stadtstack.io~1source-revision",
    }:
        return record["sourceRevision"]
    if path == "/metadata/annotations/stadtstack.io~1release-set-sha256":
        return head["releaseSetDigest"]
    if path == "/spec/template/spec/containers/0/image":
        return f"{COMPONENTS[component]['repository']}@{record['manifestDigest']}"
    if path == "/spec/template/spec/containers/0/imagePullPolicy":
        return "IfNotPresent"
    raise VerificationError("unreachable patch path")


def verify_live_preconditions(root: Path, head: dict[str, Any]) -> dict[str, Any]:
    value = load_json(root / RENDER_ROOT / "live-preconditions.json")
    record = closed(value, {"previousEnvironmentHead", "requiredLivePreconditions", "patches"}, "live-preconditions")
    previous = verify_head(record["previousEnvironmentHead"], "previousEnvironmentHead")
    require(isinstance(record["requiredLivePreconditions"], list) and len(record["requiredLivePreconditions"]) == 2, "live precondition count invalid")
    require(isinstance(record["patches"], list) and len(record["patches"]) == 2, "patch count invalid")
    for index, component in enumerate(COMPONENT_ORDER):
        policy = COMPONENTS[component]
        precondition = closed(record["requiredLivePreconditions"][index], {"component", "currentImage", "resourceVersion", "target", "uid"}, f"precondition[{index}]")
        require(precondition["component"] == component, "precondition component order invalid")
        require(isinstance(precondition["currentImage"], str) and IMMUTABLE_IMAGE.fullmatch(precondition["currentImage"]), "precondition current image invalid")
        require(isinstance(precondition["resourceVersion"], str) and precondition["resourceVersion"].isdigit(), "precondition resourceVersion invalid")
        require(isinstance(precondition["uid"], str) and UUID.fullmatch(precondition["uid"]), "precondition uid invalid")
        expected_target = {"apiVersion": "apps/v1", "kind": "Deployment", "name": policy["name"], "namespace": policy["namespace"]}
        require(precondition["target"] == expected_target, "precondition target invalid")

        patch = closed(record["patches"][index], {"component", "operations", "target"}, f"patch[{index}]")
        require(patch["component"] == component and patch["target"] == expected_target, "patch target invalid")
        require(isinstance(patch["operations"], list), "patch operations invalid")
        seen: set[str] = set()
        for operation in patch["operations"]:
            item = closed(operation, {"op", "path", "value"}, f"{component} patch operation")
            require(item["op"] in {"add", "replace"}, "patch operation invalid")
            require(item["path"] in ALLOWED_PATCH_PATHS and item["path"] not in seen, "patch path invalid or repeated")
            require(item["value"] == expected_patch_value(component, item["path"], head), "patch value invalid")
            seen.add(item["path"])
    return {"previous": previous, "preconditions": record["requiredLivePreconditions"], "patches": record["patches"]}


def verify_tree(root: Path) -> dict[str, Any]:
    root = root.resolve()
    require(root.is_dir(), "repository root missing")
    render_file_set = verify_repository_file_set(root)
    participant_policy = verify_participant_gateway_static_policy(root, render_file_set)
    verify_contract(root, participant_policy)
    workbench_baseline = verify_workbench_baseline(root)
    tracer_data_plane = verify_tracer_data_plane(root)
    verify_case_staging_topology_with_protected_policy(root)
    verify_case_runtime_contract_with_protected_policy(root)
    verify_case_recovery_composition_contract_with_protected_policy(root)
    verify_case_image_resource_inventory_contract_with_protected_policy(root)
    head = verify_head(load_json(root / RENDER_ROOT / "head.json"), "head")
    integrity = closed(load_json(root / RENDER_ROOT / "integrity.json"), {"schemaVersion", "releaseSetDigest", "desiredRenderSha256", "networkBoundaryMigrationSha256"}, "integrity")
    require(integrity["schemaVersion"] == RENDER_SCHEMA, "integrity schema drift")
    require(integrity["releaseSetDigest"] == head["releaseSetDigest"], "integrity release binding invalid")
    require(isinstance(integrity["desiredRenderSha256"], str) and SHA256.fullmatch(integrity["desiredRenderSha256"]), "integrity checksum invalid")
    reviewed_knowledge = render_file_set in {
        "reviewed-public-knowledge", "reviewed-public-knowledge-participant-gateway",
        "signed-nostr", "signed-nostr-participant-gateway",
    }
    signed_nostr = render_file_set in {"signed-nostr", "signed-nostr-participant-gateway"}
    participant_gateway = render_file_set in {
        "reviewed-public-knowledge-participant-gateway", "signed-nostr-participant-gateway",
    }
    civic_projection_route = web_civic_projection_route_enabled(root)
    tracer_feed_route = web_tracer_feed_route_enabled(root)
    identity_contract_set = web_identity_contract_set_enabled(root)
    reviewed_web_source = public_mecky_reviewed_web_source_enabled(root)
    deployments = {
        component: verify_deployment(
            root,
            component,
            head,
            reviewed_knowledge,
            reviewed_web_source=reviewed_web_source and component == "public-mecky",
            civic_projection_route=civic_projection_route and component == "roebel-web-staging",
            tracer_feed_route=tracer_feed_route and component == "roebel-web-staging",
            identity_contract_set=(
                identity_contract_set and component == "roebel-web-staging"
            ),
        )
        for component in COMPONENT_ORDER
    }
    service = verify_public_mecky_service(root)
    (
        network_policy,
        public_mecky_reviewed_egress,
        public_mecky_reviewed_web_egress,
    ) = verify_public_mecky_network_policy(
        root,
        reviewed_knowledge,
        signed_nostr,
        reviewed_web_source,
    )
    web_network_policy = verify_web_network_policy(
        root,
        civic_projection_route,
        tracer_feed_route,
        reviewed_web_source,
    )
    participant_gateway_objects = (
        verify_participant_gateway(root, participant_policy)
        if participant_gateway
        else None
    )
    require(
        not civic_projection_route
        or (
            participant_gateway_objects is not None
            and participant_gateway_objects["civicProjectionRoute"] is True
        ),
        "Web civic projection route requires exact reciprocal workbench ingress",
    )
    require(
        civic_projection_route
        or participant_gateway_objects is None
        or participant_gateway_objects["civicProjectionRoute"] is False,
        "Workbench civic projection ingress requires the Web route",
    )
    web_ingress = verify_web_ingress(root, signed_nostr, participant_gateway)
    migration = verify_network_boundary_migration(
        root, web_network_policy, web_ingress, network_policy, signed_nostr,
        participant_gateway, participant_gateway_objects, civic_projection_route,
        tracer_feed_route, reviewed_web_source, participant_policy,
    )
    objects = [
        deployments["public-mecky"],
        service,
        network_policy,
        deployments["roebel-web-staging"],
        web_network_policy,
        web_ingress,
    ]
    checksum_payload: dict[str, Any] = {"nextEnvironmentHead": head, "objects": objects}
    reviewed_objects = None
    if reviewed_knowledge:
        reviewed_objects = verify_reviewed_public_knowledge(root)
        checksum_payload["reviewedPublicKnowledge"] = reviewed_objects
    signed_nostr_objects = None
    if signed_nostr:
        signed_nostr_objects = verify_signed_nostr(root)
        checksum_payload["signedNostr"] = signed_nostr_objects
    if participant_gateway:
        checksum_payload["stagingParticipantGateway"] = {
            key: value
            for key, value in participant_gateway_objects.items()
            if key != "civicProjectionRoute"
        }
    require(integrity["desiredRenderSha256"] == digest(checksum_payload), "reviewed render checksum mismatch")
    require(integrity["networkBoundaryMigrationSha256"] == digest(migration), "network-boundary migration checksum mismatch")
    verify_kustomizations(root, signed_nostr, participant_gateway, True)
    live = verify_live_preconditions(root, head)
    web_container = deployments["roebel-web-staging"]["spec"]["template"]["spec"]["containers"][0]
    selected_identity = verify_web_identity_contract_set(
        deployments["roebel-web-staging"],
        {item["name"]: item for item in web_container["env"]},
        identity_contract_set,
    )
    rotated_state = (
        selected_identity == IDENTITY_ROTATION.WEB_IDENTITY,
        (root / IDENTITY_ROTATION_SQL_PATH).is_file(),
        bool(participant_gateway_objects and participant_gateway_objects["runtimePin"]["sourceRevision"] == IDENTITY_ROTATION.SOURCE_REVISION),
    )
    require(rotated_state in {(False, False, False), (True, True, True)},
            "test identity rotation requires matching Web, gateway and database pins")
    return {
        "root": root,
        "head": head,
        "integrity": integrity,
        "objects": objects,
        "deployments": deployments,
        "migration": migration,
        "live": live,
        "renderFileSet": render_file_set,
        "publicMeckyReviewedEgress": public_mecky_reviewed_egress,
        "publicMeckyReviewedWebSource": (
            reviewed_web_source and public_mecky_reviewed_web_egress
        ),
        "reviewedPublicKnowledge": reviewed_objects,
        "signedNostr": signed_nostr_objects,
        "stagingParticipantGateway": participant_gateway_objects,
        "stagingParticipantGatewayPolicy": participant_policy,
        "workbenchBaseline": workbench_baseline,
        "workbenchBaselineEnabled": True,
        "tracerDataPlane": tracer_data_plane,
        "webTracerFeed": tracer_feed_route,
        "webIdentityContractSet": selected_identity,
    }


def expected_tracer_phase_b_head(base_head: dict[str, Any]) -> dict[str, Any]:
    require(base_head == TRACER_PHASE_A_HEAD, "Phase B predecessor Release Set drift")
    value = copy.deepcopy(base_head)
    value["promotionRevision"] = TRACER_PHASE_B_WEB_SOURCE_REVISION
    value["releaseSetDigest"] = TRACER_PHASE_B_RELEASE_SET_DIGEST
    value["components"][1]["sourceRevision"] = TRACER_PHASE_B_WEB_SOURCE_REVISION
    value["components"][1]["manifestDigest"] = TRACER_PHASE_B_WEB_MANIFEST_DIGEST
    return value


def expected_tracer_phase_b_public_mecky_deployment(
    base_deployment: dict[str, Any],
    successor_head: dict[str, Any],
) -> dict[str, Any]:
    value = copy.deepcopy(base_deployment)
    value["metadata"]["annotations"]["stadtstack.io/release-set-sha256"] = (
        successor_head["releaseSetDigest"]
    )
    return value


def expected_tracer_phase_b_web_deployment(
    base_deployment: dict[str, Any],
    successor_head: dict[str, Any],
) -> dict[str, Any]:
    value = copy.deepcopy(base_deployment)
    annotations = value["metadata"]["annotations"]
    annotations["stadtstack.io/release-set-sha256"] = successor_head["releaseSetDigest"]
    annotations["stadtstack.io/source-revision"] = TRACER_PHASE_B_WEB_SOURCE_REVISION
    template = value["spec"]["template"]
    template["metadata"]["annotations"]["stadtstack.io/source-revision"] = (
        TRACER_PHASE_B_WEB_SOURCE_REVISION
    )
    container = template["spec"]["containers"][0]
    container["image"] = (
        f"{COMPONENTS['roebel-web-staging']['repository']}@"
        f"{TRACER_PHASE_B_WEB_MANIFEST_DIGEST}"
    )
    environment = container["env"]
    names = [item["name"] for item in environment]
    require(
        TRACER_FEED_URL_ENV["name"] not in names
        and TRACER_FEED_ANON_ENV["name"] not in names,
        "Phase B predecessor already contains tracer feed environment",
    )
    insertion = names.index("ROEBEL_PUBLIC_THIRDWEB_CLIENT_ID")
    environment[insertion:insertion] = [
        copy.deepcopy(TRACER_FEED_URL_ENV),
        copy.deepcopy(TRACER_FEED_ANON_ENV),
    ]
    return value


def expected_tracer_phase_b_live_preconditions(
    base_root: Path,
    base: dict[str, Any],
    successor_head: dict[str, Any],
) -> dict[str, Any]:
    value = copy.deepcopy(load_json(base_root / RENDER_ROOT / "live-preconditions.json"))
    value["previousEnvironmentHead"] = copy.deepcopy(base["head"])
    for index, component in enumerate(COMPONENT_ORDER):
        policy = COMPONENTS[component]
        container = next(
            item
            for item in base["deployments"][component]["spec"]["template"]["spec"]["containers"]
            if item.get("name") == policy["container"]
        )
        value["requiredLivePreconditions"][index]["currentImage"] = container["image"]
        for operation in value["patches"][index]["operations"]:
            operation["value"] = expected_patch_value(
                component,
                operation["path"],
                successor_head,
            )
    return value


def verify_tracer_phase_b_transition(
    candidate: dict[str, Any],
    base: dict[str, Any],
) -> None:
    candidate_root: Path = candidate["root"]
    base_root: Path = base["root"]
    require(base["webTracerFeed"] is False, "Phase B predecessor feed route already active")
    require(candidate["webTracerFeed"] is True, "Phase B successor feed route missing")
    require(
        candidate["renderFileSet"] == base["renderFileSet"],
        "Phase B render shape drift",
    )
    require(
        changed_repository_files(candidate_root, base_root)
        == TRACER_PHASE_B_TRANSITION_FILES,
        "Phase B changed file set drift",
    )
    successor_head = expected_tracer_phase_b_head(base["head"])
    require(candidate["head"] == successor_head, "Phase B Release Set drift")
    require(
        candidate["deployments"]["public-mecky"]
        == expected_tracer_phase_b_public_mecky_deployment(
            base["deployments"]["public-mecky"],
            successor_head,
        ),
        "Phase B Public Mecky release-only transformation drift",
    )
    require(
        candidate["deployments"]["roebel-web-staging"]
        == expected_tracer_phase_b_web_deployment(
            base["deployments"]["roebel-web-staging"],
            successor_head,
        ),
        "Phase B Web feed transformation drift",
    )
    require(
        candidate["objects"][4]
        == expected_web_network_policy(True, True),
        "Phase B Web tracer PostgREST NetworkPolicy drift",
    )
    require(
        load_json(candidate_root / RENDER_ROOT / "live-preconditions.json")
        == expected_tracer_phase_b_live_preconditions(base_root, base, successor_head),
        "Phase B live preconditions drift",
    )


def expected_current_tracer_feed_web_deployment(
    base_deployment: dict[str, Any],
) -> dict[str, Any]:
    value = copy.deepcopy(base_deployment)
    environment = value["spec"]["template"]["spec"]["containers"][0]["env"]
    names = [item["name"] for item in environment]
    require(
        TRACER_FEED_URL_ENV["name"] not in names
        and TRACER_FEED_ANON_ENV["name"] not in names,
        "current tracer-feed predecessor already contains feed environment",
    )
    insertion = names.index("ROEBEL_PUBLIC_THIRDWEB_CLIENT_ID")
    environment[insertion:insertion] = [
        copy.deepcopy(TRACER_FEED_URL_ENV),
        copy.deepcopy(TRACER_FEED_ANON_ENV),
    ]
    return value


def verify_current_tracer_feed_transition(
    candidate: dict[str, Any],
    base: dict[str, Any],
) -> None:
    candidate_root: Path = candidate["root"]
    base_root: Path = base["root"]
    require(base["webTracerFeed"] is False, "current tracer-feed predecessor route already active")
    require(candidate["webTracerFeed"] is True, "current tracer-feed successor route missing")
    require(
        base["renderFileSet"] in {
            "reviewed-public-knowledge-participant-gateway",
            "signed-nostr-participant-gateway",
        }
        and candidate["renderFileSet"] == base["renderFileSet"],
        "current tracer-feed route requires the admitted participant data plane",
    )
    require(candidate["head"] == base["head"], "current tracer-feed route must preserve the Release Set head")
    require(
        candidate["publicMeckyReviewedEgress"] == base["publicMeckyReviewedEgress"],
        "current tracer-feed route may not change Public Mecky egress",
    )
    require(
        candidate["stagingParticipantGatewayPolicy"] == base["stagingParticipantGatewayPolicy"],
        "current tracer-feed route may not change participant policy",
    )
    require(
        (candidate_root / f"{RENDER_ROOT}/live-preconditions.json").read_bytes()
        == (base_root / f"{RENDER_ROOT}/live-preconditions.json").read_bytes(),
        "current tracer-feed route must preserve live preconditions",
    )
    require(
        candidate["deployments"]["public-mecky"] == base["deployments"]["public-mecky"],
        "current tracer-feed route may not change Public Mecky",
    )
    require(
        candidate["deployments"]["roebel-web-staging"]
        == expected_current_tracer_feed_web_deployment(
            base["deployments"]["roebel-web-staging"],
        ),
        "current tracer-feed Web transformation drift",
    )
    base_civic_route = bool(
        base["stagingParticipantGateway"]
        and base["stagingParticipantGateway"]["civicProjectionRoute"]
    )
    require(
        candidate["objects"][4]
        == expected_web_network_policy(
            base_civic_route,
            True,
            base["publicMeckyReviewedWebSource"],
        ),
        "current tracer-feed PostgREST NetworkPolicy drift",
    )
    candidate_files = repository_files(candidate_root)
    require(candidate_files == repository_files(base_root), "current tracer-feed route file set drift")
    for relative in sorted(candidate_files - CURRENT_TRACER_FEED_ROUTE_TRANSITION_FILES):
        require(
            (candidate_root / relative).read_bytes()
            == (base_root / relative).read_bytes(),
            f"current tracer-feed route changed protected file: {relative}",
        )


def verify_participant_gateway_runtime_release_transition(
    candidate: dict[str, Any],
    base: dict[str, Any],
) -> None:
    """Admit only the exact release render plus its deployment-bound receipt."""
    candidate_root: Path = candidate["root"]
    base_root: Path = base["root"]
    require(
        candidate["renderFileSet"] == base["renderFileSet"]
        and candidate["renderFileSet"] in {
            "reviewed-public-knowledge-participant-gateway",
            "signed-nostr-participant-gateway",
        },
        "participant gateway runtime release render shape drift",
    )
    require(candidate["head"] == base["head"], "participant gateway runtime release changed the Release Set head")
    require(
        candidate["stagingParticipantGatewayPolicy"] == base["stagingParticipantGatewayPolicy"],
        "participant gateway runtime release changed the activation policy",
    )
    require(
        candidate["publicMeckyReviewedEgress"] == base["publicMeckyReviewedEgress"],
        "participant gateway runtime release changed Public Mecky egress",
    )
    require(
        candidate["webTracerFeed"] == base["webTracerFeed"],
        "participant gateway runtime release changed the Web tracer feed",
    )
    require(
        candidate["stagingParticipantGateway"]["civicProjectionRoute"]
        == base["stagingParticipantGateway"]["civicProjectionRoute"],
        "participant gateway runtime release changed the civic projection route",
    )
    require(
        (candidate_root / f"{RENDER_ROOT}/live-preconditions.json").read_bytes()
        == (base_root / f"{RENDER_ROOT}/live-preconditions.json").read_bytes(),
        "participant gateway runtime release changed live preconditions",
    )
    predecessor = expected_participant_gateway_runtime_release_predecessor_pin(
        base["stagingParticipantGatewayPolicy"],
    )
    successor = expected_participant_gateway_runtime_release_pin(
        base["stagingParticipantGatewayPolicy"],
    )
    require(
        base["stagingParticipantGateway"]["runtimePin"] == predecessor,
        "participant gateway runtime release predecessor pin drift",
    )
    require(
        candidate["stagingParticipantGateway"]["runtimePin"] == successor,
        "participant gateway runtime release successor pin drift",
    )
    changed = changed_repository_files(candidate_root, base_root)
    require(
        changed == PARTICIPANT_GATEWAY_RUNTIME_RELEASE_TRANSITION_FILES,
        "participant gateway runtime release changed file set drift "
        f"(missing={sorted(PARTICIPANT_GATEWAY_RUNTIME_RELEASE_TRANSITION_FILES - changed)!r}, "
        f"unexpected={sorted(changed - PARTICIPANT_GATEWAY_RUNTIME_RELEASE_TRANSITION_FILES)!r})",
    )


def tracer_citizen_adoption_enabled(snapshot: dict[str, Any]) -> bool:
    tracer = snapshot["tracerDataPlane"]
    expected_legacy = [
        {"path": path, "sha256": digest}
        for _filename, path, digest in TRACER_DATA_PLANE.LEGACY_PRODUCT_ARTIFACTS
    ]
    expected_successor = [
        {"path": path, "sha256": digest}
        for _filename, path, digest in TRACER_DATA_PLANE.PRODUCT_ARTIFACTS
    ]
    expected_synthetic = [
        {"path": path, "sha256": digest}
        for _filename, path, digest in TRACER_DATA_PLANE.SYNTHETIC_PRODUCT_ARTIFACTS
    ]
    state = (
        tracer.get("productSourceRevision"),
        tracer.get("productArtifacts"),
    )
    if state == (
        TRACER_DATA_PLANE.LEGACY_PRODUCT_SOURCE_REVISION,
        expected_legacy,
    ):
        return False
    if state == (
        TRACER_DATA_PLANE.PRODUCT_SOURCE_REVISION,
        expected_successor,
    ):
        return True
    if (
        isinstance(state[0], str)
        and REVISION.fullmatch(state[0])
        and state[1] in (expected_synthetic, [
            {"path": path, "sha256": digest}
            for _filename, path, digest in TRACER_DATA_PLANE.ROTATED_SYNTHETIC_PRODUCT_ARTIFACTS
        ])
    ):
        return True
    raise VerificationError("tracer citizen-adoption state drift")


def tracer_synthetic_citizen_pass_enabled(snapshot: dict[str, Any]) -> bool:
    tracer = snapshot["tracerDataPlane"]
    expected = [
        {"path": path, "sha256": digest}
        for _filename, path, digest in TRACER_DATA_PLANE.SYNTHETIC_PRODUCT_ARTIFACTS
    ]
    return (
        isinstance(tracer.get("productSourceRevision"), str)
        and REVISION.fullmatch(tracer["productSourceRevision"]) is not None
        and tracer.get("productArtifacts") in (expected, [
            {"path": path, "sha256": digest}
            for _filename, path, digest in TRACER_DATA_PLANE.ROTATED_SYNTHETIC_PRODUCT_ARTIFACTS
        ])
    )


def gateway_synthetic_citizen_pass_enabled(snapshot: dict[str, Any]) -> bool:
    gateway = snapshot.get("stagingParticipantGateway")
    return bool(
        gateway
        and gateway["runtimePin"].get("schemaVersion")
        == "roebel_staging_participant_gateway_runtime_pin_v5"
    )


def verify_citizen_adoption_data_plane_transition(
    candidate: dict[str, Any],
    base: dict[str, Any],
) -> None:
    """Admit the sole standalone C1 six-file database successor."""
    candidate_root: Path = candidate["root"]
    base_root: Path = base["root"]
    require(
        not tracer_citizen_adoption_enabled(base)
        and tracer_citizen_adoption_enabled(candidate),
        "citizen-adoption data-plane transition direction drift",
    )
    require(
        candidate["renderFileSet"] == base["renderFileSet"]
        == "reviewed-public-knowledge-participant-gateway",
        "citizen-adoption data-plane transition render shape drift",
    )
    require(
        candidate["head"] == base["head"],
        "citizen-adoption data-plane transition changed the Release Set head",
    )
    require(
        candidate["stagingParticipantGatewayPolicy"]
        == base["stagingParticipantGatewayPolicy"]
        == PARTICIPANT_POLICY.STATIC_ACTIVATION_POLICY,
        "citizen-adoption data-plane transition changed participant policy",
    )
    try:
        TRACER_DATA_PLANE.validate_citizen_adoption_transition(
            load_json(
                base_root / TRACER_DATA_PLANE.RENDER_ROOT / "runtime-pin.json"
            ),
            load_json(
                candidate_root
                / TRACER_DATA_PLANE.RENDER_ROOT
                / "runtime-pin.json"
            ),
        )
    except TRACER_DATA_PLANE.PolicyError as error:
        raise VerificationError(str(error)) from error
    expected_gateway_pin = expected_participant_gateway_runtime_release_pin(
        PARTICIPANT_POLICY.STATIC_ACTIVATION_POLICY,
    )
    require(
        base["stagingParticipantGateway"] is not None
        and candidate["stagingParticipantGateway"] is not None
        and base["stagingParticipantGateway"]["runtimePin"]
        == candidate["stagingParticipantGateway"]["runtimePin"]
        == expected_gateway_pin,
        "citizen-adoption data-plane transition changed gateway runtime",
    )
    for field, label in (
        ("publicMeckyReviewedEgress", "Public Mecky egress"),
        ("publicMeckyReviewedWebSource", "Public Mecky Web source"),
        ("webTracerFeed", "Web tracer feed"),
        ("signedNostr", "signed-Nostr render"),
    ):
        require(
            candidate[field] == base[field],
            f"citizen-adoption data-plane transition changed {label}",
        )
    require(
        candidate["stagingParticipantGateway"]["civicProjectionRoute"]
        == base["stagingParticipantGateway"]["civicProjectionRoute"],
        "citizen-adoption data-plane transition changed civic projection route",
    )
    changed = changed_repository_files(candidate_root, base_root)
    require(
        changed == CITIZEN_ADOPTION_DATA_PLANE_TRANSITION_FILES,
        "citizen-adoption data-plane transition changed file set drift "
        f"(missing={sorted(CITIZEN_ADOPTION_DATA_PLANE_TRANSITION_FILES - changed)!r}, "
        f"unexpected={sorted(changed - CITIZEN_ADOPTION_DATA_PLANE_TRANSITION_FILES)!r})",
    )
    require(
        repository_files(candidate_root) - repository_files(base_root)
        == {CITIZEN_ADOPTION_SQL_PATH},
        "citizen-adoption data-plane transition added file set drift",
    )


def verify_citizen_adoption_gateway_transition(
    candidate: dict[str, Any],
    base: dict[str, Any],
) -> None:
    """Admit the sole standalone C2 seven-file gateway/policy successor."""
    candidate_root: Path = candidate["root"]
    base_root: Path = base["root"]
    require(
        tracer_citizen_adoption_enabled(base)
        and tracer_citizen_adoption_enabled(candidate),
        "citizen-adoption gateway transition requires the admitted C1 data plane",
    )
    try:
        PARTICIPANT_POLICY.validate_activation_policy_transition(
            base["stagingParticipantGatewayPolicy"],
            candidate["stagingParticipantGatewayPolicy"],
        )
    except PARTICIPANT_POLICY.PolicyError as error:
        raise VerificationError(str(error)) from error
    require(
        candidate["renderFileSet"] == base["renderFileSet"]
        == "reviewed-public-knowledge-participant-gateway",
        "citizen-adoption gateway transition render shape drift",
    )
    require(
        candidate["head"] == base["head"],
        "citizen-adoption gateway transition changed the Release Set head",
    )
    require(
        base["stagingParticipantGateway"] is not None
        and candidate["stagingParticipantGateway"] is not None,
        "citizen-adoption gateway transition requires the gateway render",
    )
    require(
        base["stagingParticipantGateway"]["runtimePin"]
        == expected_participant_gateway_runtime_release_pin(
            base["stagingParticipantGatewayPolicy"],
        ),
        "citizen-adoption gateway transition predecessor runtime drift",
    )
    require(
        candidate["stagingParticipantGateway"]["runtimePin"]
        == PARTICIPANT_POLICY.expected_runtime_pin(
            candidate["stagingParticipantGatewayPolicy"],
        ),
        "citizen-adoption gateway transition successor runtime drift",
    )
    for field, label in (
        ("publicMeckyReviewedEgress", "Public Mecky egress"),
        ("publicMeckyReviewedWebSource", "Public Mecky Web source"),
        ("webTracerFeed", "Web tracer feed"),
        ("signedNostr", "signed-Nostr render"),
    ):
        require(
            candidate[field] == base[field],
            f"citizen-adoption gateway transition changed {label}",
        )
    require(
        candidate["stagingParticipantGateway"]["civicProjectionRoute"]
        == base["stagingParticipantGateway"]["civicProjectionRoute"],
        "citizen-adoption gateway transition changed civic projection route",
    )
    changed = changed_repository_files(candidate_root, base_root)
    require(
        changed == CITIZEN_ADOPTION_GATEWAY_TRANSITION_FILES,
        "citizen-adoption gateway transition changed file set drift "
        f"(missing={sorted(CITIZEN_ADOPTION_GATEWAY_TRANSITION_FILES - changed)!r}, "
        f"unexpected={sorted(changed - CITIZEN_ADOPTION_GATEWAY_TRANSITION_FILES)!r})",
    )
    require(
        repository_files(candidate_root) == repository_files(base_root),
        "citizen-adoption gateway transition file set drift",
    )
    for relative in sorted(CITIZEN_ADOPTION_GATEWAY_PRESERVED_RENDER_FILES):
        require(
            (candidate_root / relative).read_bytes()
            == (base_root / relative).read_bytes(),
            f"citizen-adoption gateway transition changed preserved render: {relative}",
        )


def expected_web_identity_contract_set_deployment(
    base_deployment: dict[str, Any],
    successor_head: dict[str, Any],
) -> dict[str, Any]:
    """Add the selector only while advancing the immutable Web release."""
    value = copy.deepcopy(base_deployment)
    environment = value["spec"]["template"]["spec"]["containers"][0]["env"]
    names = [item["name"] for item in environment]
    require(
        not (set(names) & WEB_IDENTITY_CONTRACT_SET_ENV_NAMES),
        "Web identity contract set predecessor already contains identity environment",
    )
    insertion = names.index("ROEBEL_PUBLIC_GNOSIS_BUNDLER_URL")
    environment[insertion:insertion] = copy.deepcopy(WEB_IDENTITY_CONTRACT_SET_ENV)
    annotations = value["spec"]["template"]["metadata"]["annotations"]
    require(
        not (set(annotations) & set(WEB_IDENTITY_CONTRACT_SET_ANNOTATIONS)),
        "Web identity contract set predecessor already contains identity evidence",
    )
    annotations.update(copy.deepcopy(WEB_IDENTITY_CONTRACT_SET_ANNOTATIONS))
    record = component_map(successor_head)["roebel-web-staging"]
    value["metadata"]["annotations"]["stadtstack.io/source-revision"] = (
        record["sourceRevision"]
    )
    value["metadata"]["annotations"]["stadtstack.io/release-set-sha256"] = (
        successor_head["releaseSetDigest"]
    )
    value["spec"]["template"]["metadata"]["annotations"][
        "stadtstack.io/source-revision"
    ] = record["sourceRevision"]
    container = value["spec"]["template"]["spec"]["containers"][0]
    container["image"] = (
        f"{COMPONENTS['roebel-web-staging']['repository']}@{record['manifestDigest']}"
    )
    container["imagePullPolicy"] = "IfNotPresent"
    return value


def expected_synthetic_citizen_pass_transition_record(
    candidate_root: Path,
    base_root: Path,
    source_revision: str,
) -> dict[str, Any]:
    added = {
        SYNTHETIC_CITIZEN_ADOPTION_SQL_PATH,
        SYNTHETIC_CITIZEN_PASS_TRANSITION_PATH,
    }
    existing = sorted(SYNTHETIC_CITIZEN_PASS_TRANSITION_FILES - added)
    return {
        "schemaVersion": "roebel_staging_synthetic_citizen_pass_transition_v1",
        "environment": "staging",
        "testOnly": True,
        "authorityBinding": "none",
        "sourceRevision": source_revision,
        "capability": synthetic_citizen_pass_boundary(),
        "forward": {
            "atomicComponents": [
                "roebel-web-staging",
                "staging-participant-gateway",
                "ephemeral-tracer-data-plane",
            ],
            "migrationPath": SYNTHETIC_CITIZEN_ADOPTION_SQL_PATH,
        },
        "rollback": {
            "strategy": "restore-exact-predecessor-bytes-and-remove-added-files",
            "restoreFiles": [
                {
                    "path": path,
                    "predecessorSha256": bytes_digest((base_root / path).read_bytes()),
                    "successorSha256": bytes_digest((candidate_root / path).read_bytes()),
                }
                for path in existing
            ],
            "removeFiles": [
                SYNTHETIC_CITIZEN_ADOPTION_SQL_PATH,
                SYNTHETIC_CITIZEN_PASS_TRANSITION_PATH,
            ],
        },
    }


def expected_release_deployment(
    base_deployment: dict[str, Any],
    successor_head: dict[str, Any],
    component: str,
) -> dict[str, Any]:
    value = copy.deepcopy(base_deployment)
    record = component_map(successor_head)[component]
    value["metadata"]["annotations"]["stadtstack.io/source-revision"] = record[
        "sourceRevision"
    ]
    value["metadata"]["annotations"]["stadtstack.io/release-set-sha256"] = (
        successor_head["releaseSetDigest"]
    )
    value["spec"]["template"]["metadata"]["annotations"][
        "stadtstack.io/source-revision"
    ] = record["sourceRevision"]
    container = value["spec"]["template"]["spec"]["containers"][0]
    container["image"] = f"{COMPONENTS[component]['repository']}@{record['manifestDigest']}"
    container["imagePullPolicy"] = "IfNotPresent"
    return value


def expected_test_identity_rotation_record(candidate_root: Path, base_root: Path) -> dict[str, Any]:
    added = {IDENTITY_ROTATION_SQL_PATH, IDENTITY_ROTATION_RECORD_PATH}
    return {
        "schemaVersion": "roebel_staging_test_identity_rotation_v2",
        "sourceRevision": IDENTITY_ROTATION.SOURCE_REVISION,
        "environment": "staging", "testOnly": True, "authorityBinding": "none",
        "previousIdentity": WEB_IDENTITY_CONTRACT_SET,
        "nextIdentity": IDENTITY_ROTATION.WEB_IDENTITY,
        "gatewayRelease": IDENTITY_ROTATION.GATEWAY_RELEASE,
        "migration": {
            "path": IDENTITY_ROTATION_SQL_PATH,
            "sha256": IDENTITY_ROTATION.MIGRATION_ARTIFACT[2],
            "apply": "in-place-on-existing-postgres-pod",
            "postgresPodTemplateChanged": False,
            "historicalRowsPreserved": True,
            "liveExecutionReceiptRequired": True,
        },
        "rollback": "forward-only-schema-rotation-requires-reviewed-reverse-migration",
        "changedFiles": [
            {"path": path,
             "predecessorSha256": bytes_digest((base_root / path).read_bytes()),
             "successorSha256": bytes_digest((candidate_root / path).read_bytes())}
            for path in sorted(IDENTITY_ROTATION_FILES - added)
        ],
        "addedFiles": sorted(added),
    }


def verify_test_identity_rotation(candidate: dict[str, Any], base: dict[str, Any]) -> None:
    """Admit one exact forward rotation while retaining the emptyDir Pod."""
    require(base["webIdentityContractSet"] == WEB_IDENTITY_CONTRACT_SET
            and candidate["webIdentityContractSet"] == IDENTITY_ROTATION.WEB_IDENTITY,
            "test identity rotation must advance the registered v1 pair to v2")
    require(candidate["renderFileSet"] == base["renderFileSet"], "test identity rotation render shape drift")
    require(candidate["head"]["promotionRevision"] == IDENTITY_ROTATION.SOURCE_REVISION,
            "test identity rotation requires the reviewed app publication")
    require(component_map(candidate["head"])["roebel-web-staging"]["sourceRevision"] == IDENTITY_ROTATION.SOURCE_REVISION,
            "test identity rotation requires the matching Web source")
    require(candidate["head"] != base["head"], "test identity rotation requires a new release")
    for field in ("publicMeckyReviewedEgress", "publicMeckyReviewedWebSource", "webTracerFeed", "signedNostr", "stagingParticipantGatewayPolicy"):
        require(candidate[field] == base[field], f"test identity rotation changed {field}")
    expected_old_gateway = expected_synthetic_citizen_pass_gateway_runtime_pin({
        "sourceRevision": SYNTHETIC_CITIZEN_PASS_SOURCE_REVISION,
        "sourceTreeSha256": SYNTHETIC_CITIZEN_PASS_GATEWAY_SOURCE_TREE_SHA256,
        "workflowSha256": SYNTHETIC_CITIZEN_PASS_GATEWAY_WORKFLOW_SHA256,
        "manifestDigest": SYNTHETIC_CITIZEN_PASS_GATEWAY_MANIFEST_DIGEST,
    })
    require(base["stagingParticipantGateway"]["runtimePin"] == expected_old_gateway,
            "test identity rotation gateway predecessor drift")
    require(candidate["stagingParticipantGateway"]["runtimePin"] == IDENTITY_ROTATION.gateway_runtime_pin(expected_old_gateway),
            "test identity rotation gateway successor drift")
    for component in COMPONENT_ORDER:
        expected = expected_release_deployment(base["deployments"][component], candidate["head"], component)
        if component == "roebel-web-staging":
            container = expected["spec"]["template"]["spec"]["containers"][0]
            by_name = {item["name"]: item for item in container["env"]}
            for item in IDENTITY_ROTATION.web_environment():
                by_name[item["name"]].update(item)
            expected["spec"]["template"]["metadata"]["annotations"].update(IDENTITY_ROTATION.web_annotations())
        require(candidate["deployments"][component] == expected,
                f"test identity rotation {component} deployment drift")
    candidate_root, base_root = candidate["root"], base["root"]
    postgres_path = TRACER_DATA_PLANE.RENDER_ROOT / "postgres-deployment.json"
    require(load_json(candidate_root / postgres_path)["spec"]["template"] == load_json(base_root / postgres_path)["spec"]["template"],
            "test identity rotation must preserve the complete PostgreSQL Pod template")
    require(changed_repository_files(candidate_root, base_root) == IDENTITY_ROTATION_FILES,
            "test identity rotation changed file set drift")
    require(repository_files(candidate_root) - repository_files(base_root) == {IDENTITY_ROTATION_SQL_PATH, IDENTITY_ROTATION_RECORD_PATH},
            "test identity rotation added file set drift")
    require(load_json(candidate_root / IDENTITY_ROTATION_RECORD_PATH) == expected_test_identity_rotation_record(candidate_root, base_root),
            "test identity rotation transition record drift")
    require(candidate["live"]["previous"] == base["head"], "test identity rotation previous-head CAS drift")
    for index, component in enumerate(COMPONENT_ORDER):
        require(candidate["live"]["preconditions"][index]["currentImage"] == base["deployments"][component]["spec"]["template"]["spec"]["containers"][0]["image"],
                f"test identity rotation {component} image CAS drift")


def verify_synthetic_citizen_pass_transition(
    candidate: dict[str, Any],
    base: dict[str, Any],
) -> None:
    candidate_root: Path = candidate["root"]
    base_root: Path = base["root"]
    require(
        candidate["renderFileSet"] == base["renderFileSet"]
        and candidate["renderFileSet"]
        in {
            "reviewed-public-knowledge-participant-gateway",
            "signed-nostr-participant-gateway",
        },
        "synthetic citizen pass render shape drift",
    )
    require(
        base["webIdentityContractSet"] is None
        and candidate["webIdentityContractSet"] == WEB_IDENTITY_CONTRACT_SET,
        "synthetic citizen pass Web selector drift",
    )
    require(candidate["head"] != base["head"], "synthetic citizen pass requires a release")
    base_components = component_map(base["head"])
    candidate_components = component_map(candidate["head"])
    require(
        candidate_components["roebel-web-staging"]
        != base_components["roebel-web-staging"]
        and candidate_components["roebel-web-staging"]["sourceRevision"]
        == candidate["head"]["promotionRevision"],
        "synthetic citizen pass requires the promoted Web component",
    )
    expected_public = expected_release_deployment(
        base["deployments"]["public-mecky"],
        candidate["head"],
        "public-mecky",
    )
    require(
        candidate["deployments"]["public-mecky"] == expected_public,
        "synthetic citizen pass Public Mecky release drift",
    )
    require(
        candidate["deployments"]["roebel-web-staging"]
        == expected_web_identity_contract_set_deployment(
            base["deployments"]["roebel-web-staging"],
            candidate["head"],
        ),
        "synthetic citizen pass Web release drift",
    )
    require(
        candidate["stagingParticipantGatewayPolicy"]
        == base["stagingParticipantGatewayPolicy"]
        == PARTICIPANT_POLICY.APPROVED_NEXT_ACTIVATION_POLICY,
        "synthetic citizen pass changed the real gateway policy",
    )
    base_gateway = base["stagingParticipantGateway"]
    candidate_gateway = candidate["stagingParticipantGateway"]
    require(base_gateway is not None and candidate_gateway is not None, "synthetic citizen pass gateway missing")
    require(
        base_gateway["runtimePin"]
        == PARTICIPANT_POLICY.expected_runtime_pin(
            PARTICIPANT_POLICY.APPROVED_NEXT_ACTIVATION_POLICY,
        ),
        "synthetic citizen pass gateway predecessor drift",
    )
    release = {
        "sourceRevision": candidate_gateway["runtimePin"]["sourceRevision"],
        "sourceTreeSha256": candidate_gateway["runtimePin"]["sourceTreeSha256"],
        "workflowSha256": candidate_gateway["runtimePin"]["workflowSha256"],
        "manifestDigest": candidate_gateway["runtimePin"]["manifestDigest"],
    }
    require(
        release["sourceRevision"] == candidate["head"]["promotionRevision"],
        "synthetic citizen pass gateway source/release binding invalid",
    )
    require(
        candidate_gateway["runtimePin"]
        == expected_synthetic_citizen_pass_gateway_runtime_pin(
            release,
            candidate["stagingParticipantGatewayPolicy"],
        ),
        "synthetic citizen pass gateway pin drift",
    )
    try:
        TRACER_DATA_PLANE.validate_synthetic_citizen_adoption_transition(
            load_json(base_root / TRACER_DATA_PLANE.RENDER_ROOT / "runtime-pin.json"),
            load_json(candidate_root / TRACER_DATA_PLANE.RENDER_ROOT / "runtime-pin.json"),
            candidate["head"]["promotionRevision"],
        )
    except TRACER_DATA_PLANE.PolicyError as error:
        raise VerificationError(str(error)) from error
    for field, label in (
        ("publicMeckyReviewedEgress", "Public Mecky egress"),
        ("publicMeckyReviewedWebSource", "Public Mecky Web source"),
        ("webTracerFeed", "Web tracer feed"),
        ("signedNostr", "signed-Nostr render"),
    ):
        require(candidate[field] == base[field], f"synthetic citizen pass changed {label}")
    require(
        candidate_gateway["civicProjectionRoute"] == base_gateway["civicProjectionRoute"],
        "synthetic citizen pass changed civic projection routing",
    )
    require(
        changed_repository_files(candidate_root, base_root)
        == SYNTHETIC_CITIZEN_PASS_TRANSITION_FILES,
        "synthetic citizen pass changed file set drift",
    )
    require(
        repository_files(candidate_root) - repository_files(base_root)
        == {
            SYNTHETIC_CITIZEN_ADOPTION_SQL_PATH,
            SYNTHETIC_CITIZEN_PASS_TRANSITION_PATH,
        },
        "synthetic citizen pass added file set drift",
    )
    require(
        load_json(candidate_root / SYNTHETIC_CITIZEN_PASS_TRANSITION_PATH)
        == expected_synthetic_citizen_pass_transition_record(
            candidate_root,
            base_root,
            candidate["head"]["promotionRevision"],
        ),
        "synthetic citizen pass rollback record drift",
    )
    require(candidate["live"]["previous"] == base["head"], "synthetic citizen pass live CAS drift")
    for index, component in enumerate(COMPONENT_ORDER):
        base_container = next(
            item
            for item in base["deployments"][component]["spec"]["template"]["spec"]["containers"]
            if item.get("name") == COMPONENTS[component]["container"]
        )
        require(
            candidate["live"]["preconditions"][index]["currentImage"]
            == base_container["image"],
            f"synthetic citizen pass {component} live image CAS drift",
        )


def verify_web_identity_contract_set_transition(
    candidate: dict[str, Any],
    base: dict[str, Any],
) -> None:
    """Admit only the standalone, no-authority Web test-contract selector."""
    candidate_root: Path = candidate["root"]
    base_root: Path = base["root"]
    require(
        base["webIdentityContractSet"] is None,
        "Web identity contract set predecessor already active",
    )
    require(
        candidate["webIdentityContractSet"] == WEB_IDENTITY_CONTRACT_SET,
        "Web identity contract set successor drift",
    )
    require(
        candidate["renderFileSet"] == base["renderFileSet"],
        "Web identity contract set changed render shape",
    )
    require(candidate["head"] != base["head"], "Web identity contract set requires a new Web release")
    base_components = component_map(base["head"])
    candidate_components = component_map(candidate["head"])
    if candidate_components["public-mecky"] != base_components["public-mecky"]:
        require(
            candidate_components["public-mecky"]["sourceRevision"]
            == candidate["head"]["promotionRevision"],
            "Web identity contract set Public Mecky release provenance drift",
        )
    require(
        candidate_components["roebel-web-staging"]
        != base_components["roebel-web-staging"]
        and candidate_components["roebel-web-staging"]["sourceRevision"]
        == candidate["head"]["promotionRevision"],
        "Web identity contract set requires the exact promoted Web component",
    )
    expected_public = copy.deepcopy(base["deployments"]["public-mecky"])
    public_record = candidate_components["public-mecky"]
    expected_public["metadata"]["annotations"]["stadtstack.io/source-revision"] = (
        public_record["sourceRevision"]
    )
    expected_public["metadata"]["annotations"]["stadtstack.io/release-set-sha256"] = (
        candidate["head"]["releaseSetDigest"]
    )
    expected_public["spec"]["template"]["metadata"]["annotations"][
        "stadtstack.io/source-revision"
    ] = public_record["sourceRevision"]
    public_container = expected_public["spec"]["template"]["spec"]["containers"][0]
    public_container["image"] = (
        f"{COMPONENTS['public-mecky']['repository']}@{public_record['manifestDigest']}"
    )
    public_container["imagePullPolicy"] = "IfNotPresent"
    require(
        candidate["deployments"]["public-mecky"] == expected_public,
        "Web identity contract set Public Mecky release annotation drift",
    )
    require(
        candidate["deployments"]["roebel-web-staging"]
        == expected_web_identity_contract_set_deployment(
            base["deployments"]["roebel-web-staging"],
            candidate["head"],
        ),
        "Web identity contract set Deployment transformation drift",
    )
    for field, label in (
        ("publicMeckyReviewedEgress", "Public Mecky egress"),
        ("publicMeckyReviewedWebSource", "Public Mecky Web source"),
        ("webTracerFeed", "Web tracer feed"),
        ("signedNostr", "signed-Nostr render"),
        ("stagingParticipantGatewayPolicy", "participant gateway policy"),
    ):
        require(
            candidate[field] == base[field],
            f"Web identity contract set changed {label}",
        )
    require(
        candidate["stagingParticipantGateway"]
        == base["stagingParticipantGateway"],
        "Web identity contract set changed participant gateway projection",
    )
    require(
        candidate["live"]["previous"] == base["head"],
        "Web identity contract set previous-head CAS drift",
    )
    for index, component in enumerate(COMPONENT_ORDER):
        base_container = next(
            item
            for item in base["deployments"][component]["spec"]["template"]["spec"]["containers"]
            if item.get("name") == COMPONENTS[component]["container"]
        )
        require(
            candidate["live"]["preconditions"][index]["currentImage"]
            == base_container["image"],
            f"Web identity contract set {component} live image CAS drift",
        )
    require(
        (candidate_root / f"{RENDER_ROOT}/web/networkpolicy.json").read_bytes()
        == (base_root / f"{RENDER_ROOT}/web/networkpolicy.json").read_bytes(),
        "Web identity contract set changed Web NetworkPolicy bytes",
    )
    for relative in sorted(PARTICIPANT_GATEWAY_FILES):
        require(
            (candidate_root / relative).read_bytes()
            == (base_root / relative).read_bytes(),
            f"Web identity contract set changed participant gateway bytes: {relative}",
        )
    for relative in (
        PARTICIPANT_POLICY.POLICY_PATH,
        ELIGIBILITY_ISSUER_POLICY_PATH,
        "scripts/staging_participant_gateway_policy.py",
    ):
        require(
            (candidate_root / relative).read_bytes()
            == (base_root / relative).read_bytes(),
            f"Web identity contract set changed real eligibility policy bytes: {relative}",
        )
    changed = changed_repository_files(candidate_root, base_root)
    require(
        changed == WEB_IDENTITY_CONTRACT_SET_TRANSITION_FILES,
        "Web identity contract set changed file set drift "
        f"(missing={sorted(WEB_IDENTITY_CONTRACT_SET_TRANSITION_FILES - changed)!r}, "
        f"unexpected={sorted(changed - WEB_IDENTITY_CONTRACT_SET_TRANSITION_FILES)!r})",
    )
    require(
        repository_files(candidate_root) == repository_files(base_root),
        "Web identity contract set repository file set drift",
    )


def verify_transition(candidate: dict[str, Any], base: dict[str, Any]) -> None:
    candidate_root: Path = candidate["root"]
    base_root: Path = base["root"]
    changed_files = changed_repository_files(candidate_root, base_root)
    issuer_projection_files = set(
        ELIGIBILITY_ISSUER_DRY_RUN_PROJECTION_TRANSITION
    )
    if changed_files & issuer_projection_files:
        require(
            changed_files == issuer_projection_files,
            "eligibility issuer dry-run projection changed file set drift "
            f"(missing={sorted(issuer_projection_files - changed_files)!r}, "
            f"unexpected={sorted(changed_files - issuer_projection_files)!r})",
        )
        require(
            repository_files(candidate_root) == repository_files(base_root),
            "eligibility issuer dry-run projection repository file set drift",
        )
        candidate_snapshot = {
            key: value for key, value in candidate.items() if key != "root"
        }
        base_snapshot = {
            key: value for key, value in base.items() if key != "root"
        }
        require(
            candidate_snapshot == base_snapshot,
            "eligibility issuer dry-run projection render snapshot drift",
        )
        for relative, transition in sorted(
            ELIGIBILITY_ISSUER_DRY_RUN_PROJECTION_TRANSITION.items()
        ):
            require(
                bytes_digest((base_root / relative).read_bytes())
                == transition["predecessorSha256"],
                f"eligibility issuer dry-run projection predecessor byte drift: {relative}",
            )
            require(
                bytes_digest((candidate_root / relative).read_bytes())
                == transition["successorSha256"],
                f"eligibility issuer dry-run projection successor byte drift: {relative}",
            )
        return
    base_participant_gateway = base["renderFileSet"] in {
        "reviewed-public-knowledge-participant-gateway", "signed-nostr-participant-gateway",
    }
    candidate_participant_gateway = candidate["renderFileSet"] in {
        "reviewed-public-knowledge-participant-gateway", "signed-nostr-participant-gateway",
    }
    base_civic_projection_route = bool(
        base["stagingParticipantGateway"]
        and base["stagingParticipantGateway"]["civicProjectionRoute"]
    )
    candidate_civic_projection_route = bool(
        candidate["stagingParticipantGateway"]
        and candidate["stagingParticipantGateway"]["civicProjectionRoute"]
    )
    base_reviewed_web_source = base["publicMeckyReviewedWebSource"]
    candidate_reviewed_web_source = candidate["publicMeckyReviewedWebSource"]
    base_citizen_adoption = tracer_citizen_adoption_enabled(base)
    candidate_citizen_adoption = tracer_citizen_adoption_enabled(candidate)
    # A few focused transition-unit snapshots intentionally contain only the
    # fields relevant to their own historical transition. Treat the new field
    # as absent for those closed synthetic snapshots.
    base_identity_contract_set = base.get("webIdentityContractSet")
    candidate_identity_contract_set = candidate.get("webIdentityContractSet")
    base_synthetic_state = (
        base_identity_contract_set is not None,
        tracer_synthetic_citizen_pass_enabled(base),
        gateway_synthetic_citizen_pass_enabled(base),
    )
    candidate_synthetic_state = (
        candidate_identity_contract_set is not None,
        tracer_synthetic_citizen_pass_enabled(candidate),
        gateway_synthetic_citizen_pass_enabled(candidate),
    )
    admitted_synthetic_states = {
        (False, False, False),
        (True, True, True),
    }
    require(
        base_synthetic_state in admitted_synthetic_states
        and candidate_synthetic_state in admitted_synthetic_states,
        "synthetic citizen pass must transition Web, gateway, and migration atomically",
    )
    require(
        not (
            base_synthetic_state == (True, True, True)
            and candidate_synthetic_state == (False, False, False)
        ),
        "synthetic citizen pass cannot regress without exact rollback admission",
    )
    if (
        base_synthetic_state == (False, False, False)
        and candidate_synthetic_state == (True, True, True)
    ):
        verify_synthetic_citizen_pass_transition(candidate, base)
        return

    if base_identity_contract_set != candidate_identity_contract_set and base_identity_contract_set is not None:
        verify_test_identity_rotation(candidate, base)
        return

    require(
        not (
            base_identity_contract_set is not None
            and candidate_identity_contract_set is None
        ),
        "Web identity contract set cannot regress",
    )
    if (
        candidate_identity_contract_set is not None
        and base_identity_contract_set is None
    ):
        verify_web_identity_contract_set_transition(candidate, base)
        return

    require(
        not (base_citizen_adoption and not candidate_citizen_adoption),
        "citizen-adoption data-plane transition cannot regress",
    )
    if candidate_citizen_adoption and not base_citizen_adoption:
        verify_citizen_adoption_data_plane_transition(candidate, base)
        return

    if (
        candidate["stagingParticipantGatewayPolicy"]
        != base["stagingParticipantGatewayPolicy"]
    ):
        verify_citizen_adoption_gateway_transition(candidate, base)
        return

    require(
        not (base_reviewed_web_source and not candidate_reviewed_web_source),
        "Public Mecky reviewed Web source cannot regress",
    )
    if candidate_reviewed_web_source and not base_reviewed_web_source:
        require(
            candidate["renderFileSet"] == base["renderFileSet"],
            "Public Mecky reviewed Web source may not change the render shape",
        )
        require(
            candidate["head"] == base["head"],
            "Public Mecky reviewed Web source must preserve the Release Set head",
        )
        require(
            candidate["webTracerFeed"] == base["webTracerFeed"],
            "Public Mecky reviewed Web source may not change the tracer feed route",
        )
        require(
            candidate_civic_projection_route == base_civic_projection_route,
            "Public Mecky reviewed Web source may not change the civic projection route",
        )
        require(
            candidate["stagingParticipantGatewayPolicy"]
            == base["stagingParticipantGatewayPolicy"],
            "Public Mecky reviewed Web source may not change participant policy",
        )
        require(
            candidate["publicMeckyReviewedEgress"]
            == base["publicMeckyReviewedEgress"],
            "Public Mecky reviewed Web source must preserve reviewed-runtime egress",
        )
        base_gateway_pin = (
            base["stagingParticipantGateway"]["runtimePin"]
            if base_participant_gateway else None
        )
        candidate_gateway_pin = (
            candidate["stagingParticipantGateway"]["runtimePin"]
            if candidate_participant_gateway else None
        )
        require(
            candidate_gateway_pin == base_gateway_pin,
            "Public Mecky reviewed Web source may not change the gateway release",
        )
        expected_public = copy.deepcopy(base["deployments"]["public-mecky"])
        expected_public["spec"]["template"]["spec"]["containers"][0]["env"].extend(
            copy.deepcopy(PUBLIC_MECKY_REVIEWED_WEB_SOURCE_ENV)
        )
        require(
            candidate["deployments"]["public-mecky"] == expected_public,
            "Public Mecky reviewed Web source environment transform drift",
        )
        changed = changed_repository_files(candidate_root, base_root)
        require(
            changed == PUBLIC_MECKY_REVIEWED_WEB_SOURCE_TRANSITION_FILES,
            "Public Mecky reviewed Web source changed file set drift "
            f"(missing={sorted(PUBLIC_MECKY_REVIEWED_WEB_SOURCE_TRANSITION_FILES - changed)!r}, "
            f"unexpected={sorted(changed - PUBLIC_MECKY_REVIEWED_WEB_SOURCE_TRANSITION_FILES)!r})",
        )
        return

    require(
        not (base["webTracerFeed"] and not candidate["webTracerFeed"]),
        "Web tracer feed route cannot regress",
    )
    if candidate["webTracerFeed"] and not base["webTracerFeed"]:
        if base["head"] == TRACER_PHASE_A_HEAD:
            verify_tracer_phase_b_transition(candidate, base)
        else:
            verify_current_tracer_feed_transition(candidate, base)
        return

    require(
        not (base_civic_projection_route and not candidate_civic_projection_route),
        "Web civic projection route cannot regress",
    )
    if candidate_civic_projection_route and not base_civic_projection_route:
        require(
            base_participant_gateway and candidate_participant_gateway,
            "Web civic projection route requires the admitted participant gateway render",
        )
        require(
            candidate["renderFileSet"] == base["renderFileSet"],
            "Web civic projection route may not change the render shape",
        )
        require(
            candidate["head"] == base["head"],
            "Web civic projection route must preserve the Release Set head",
        )
        require(
            candidate["publicMeckyReviewedEgress"] == base["publicMeckyReviewedEgress"],
            "Web civic projection route may not change Public Mecky egress",
        )
        require(
            (candidate_root / f"{RENDER_ROOT}/live-preconditions.json").read_bytes()
            == (base_root / f"{RENDER_ROOT}/live-preconditions.json").read_bytes(),
            "Web civic projection route must preserve live preconditions",
        )
        candidate_files = repository_files(candidate_root)
        require(candidate_files == repository_files(base_root), "Web civic projection route file set drift")
        for relative in sorted(candidate_files - CIVIC_PROJECTION_ROUTE_TRANSITION_FILES):
            require(
                (candidate_root / relative).read_bytes() == (base_root / relative).read_bytes(),
                f"Web civic projection route changed protected file: {relative}",
            )
        return

    if candidate["stagingParticipantGatewayPolicy"] != base["stagingParticipantGatewayPolicy"]:
        try:
            PARTICIPANT_POLICY.validate_activation_policy_transition(
                base["stagingParticipantGatewayPolicy"],
                candidate["stagingParticipantGatewayPolicy"],
            )
        except PARTICIPANT_POLICY.PolicyError as error:
            raise VerificationError(str(error)) from error
        require(
            candidate["renderFileSet"] == base["renderFileSet"],
            "participant activation-policy transition may not add or remove a render",
        )
        require(
            candidate["head"] == base["head"],
            "participant activation-policy transition must preserve the Release Set head",
        )
        require(
            candidate["publicMeckyReviewedEgress"] == base["publicMeckyReviewedEgress"],
            "participant activation-policy transition may not change Public Mecky egress",
        )
        candidate_files = repository_files(candidate_root)
        require(
            candidate_files == repository_files(base_root),
            "participant activation-policy transition file set drift",
        )
        for relative in sorted(candidate_files - PARTICIPANT_ACTIVATION_POLICY_TRANSITION_FILES):
            require(
                (candidate_root / relative).read_bytes() == (base_root / relative).read_bytes(),
                f"participant activation-policy transition changed protected file: {relative}",
            )
        return

    base_gateway_pin = (
        base["stagingParticipantGateway"]["runtimePin"]
        if base_participant_gateway else None
    )
    candidate_gateway_pin = (
        candidate["stagingParticipantGateway"]["runtimePin"]
        if candidate_participant_gateway else None
    )
    if base_gateway_pin != candidate_gateway_pin:
        require(
            base_participant_gateway and candidate_participant_gateway,
            "participant gateway runtime release requires the admitted gateway render",
        )
        verify_participant_gateway_runtime_release_transition(candidate, base)
        return

    require(
        not (base["renderFileSet"] == "reviewed-public-knowledge" and candidate["renderFileSet"] == "current"),
        "reviewed-public-knowledge render set cannot regress to the legacy set",
    )
    require(
        not (base["renderFileSet"] == "signed-nostr" and candidate["renderFileSet"] == "current"),
        "signed-Nostr rollback must retain the reviewed-public-knowledge render",
    )
    require(
        not (base["publicMeckyReviewedEgress"] and not candidate["publicMeckyReviewedEgress"]),
        "Public Mecky reviewed-runtime egress cannot regress",
    )
    require(
        not (base_participant_gateway and not candidate_participant_gateway),
        "participant gateway deactivation is blocked pending separately reviewed exact teardown evidence",
    )

    if candidate_participant_gateway and not base_participant_gateway:
        require(
            base["renderFileSet"] in {"reviewed-public-knowledge", "signed-nostr"},
            "participant gateway activation requires the reviewed public-knowledge render",
        )
        require(
            not (
                base["renderFileSet"] == "reviewed-public-knowledge"
                and candidate["renderFileSet"] == "signed-nostr-participant-gateway"
            ),
            "participant gateway and signed-Nostr activation must be separate reviewed transitions",
        )
        require(candidate["head"] == base["head"], "participant gateway activation must preserve the Release Set head")
        require(
            candidate["stagingParticipantGatewayPolicy"]["activationReady"] is True,
            "participant gateway activation policy is not ready",
        )
        allowed_existing_changes = {
            f"{RENDER_ROOT}/integrity.json",
            f"{RENDER_ROOT}/network-boundary-migration.json",
        }
        protected = SIGNED_NOSTR_EXPECTED_FILES if base["renderFileSet"] == "signed-nostr" else FUTURE_EXPECTED_FILES
        for relative in protected:
            if relative in allowed_existing_changes:
                continue
            require(
                (candidate_root / relative).read_bytes() == (base_root / relative).read_bytes(),
                f"participant gateway activation changed existing file: {relative}",
            )
        return

    if (
        base["renderFileSet"] in {"reviewed-public-knowledge", "reviewed-public-knowledge-participant-gateway"}
        and candidate["renderFileSet"] in {"signed-nostr", "signed-nostr-participant-gateway"}
    ):
        require(candidate["head"] == base["head"], "signed-Nostr activation must preserve the Release Set head")
        verify_signed_nostr_activation_admission_freshness(
            candidate["signedNostr"]["runtimePin"]["activationEvidence"],
        )
        protected = PARTICIPANT_GATEWAY_EXPECTED_FILES if base_participant_gateway else FUTURE_EXPECTED_FILES
        for relative in protected:
            if relative in SIGNED_NOSTR_MUTABLE_EXISTING_FILES:
                continue
            require(
                (candidate_root / relative).read_bytes() == (base_root / relative).read_bytes(),
                f"signed-Nostr activation changed existing file: {relative}",
            )
        rollback = candidate["signedNostr"]["runtimePin"]["rollback"]
        expected_rollback = {
            "integritySha256": bytes_digest((base_root / f"{RENDER_ROOT}/integrity.json").read_bytes()),
            "webIngressSha256": bytes_digest((base_root / f"{RENDER_ROOT}/web/ingress.json").read_bytes()),
            "publicMeckyNetworkPolicySha256": bytes_digest((base_root / f"{RENDER_ROOT}/public-mecky/networkpolicy.json").read_bytes()),
            "boundaryReceiptSha256": bytes_digest((base_root / f"{RENDER_ROOT}/network-boundary-migration.json").read_bytes()),
        }
        require(
            {field: rollback[field] for field in expected_rollback} == expected_rollback,
            "signed-Nostr activation rollback baseline drift",
        )
        return

    require(
        not (
            base["renderFileSet"] == "signed-nostr-participant-gateway"
            and candidate["renderFileSet"] != "signed-nostr-participant-gateway"
        ),
        "combined signed-Nostr/participant gateway deactivation blocked pending separately reviewed exact teardown evidence",
    )

    if base["renderFileSet"] == "signed-nostr" and candidate["renderFileSet"] == "reviewed-public-knowledge":
        require(candidate["head"] == base["head"], "signed-Nostr rollback must preserve the Release Set head")
        activation_evidence = base["signedNostr"]["runtimePin"]["activationEvidence"]
        rollback_contract = activation_evidence["lifecycle"]["rollbackContract"]
        approved_deactivation = SIGNED_NOSTR_APPROVED_DEACTIVATION_EVIDENCE
        require(
            approved_deactivation is not None,
            "signed-Nostr deactivation blocked: completed exact-UID live teardown evidence requires separate review",
        )
        verify_signed_nostr_deactivation_evidence(
            approved_deactivation,
            activation_evidence,
            rollback_contract,
        )
        for relative in FUTURE_EXPECTED_FILES:
            if relative in SIGNED_NOSTR_MUTABLE_EXISTING_FILES:
                continue
            require(
                (candidate_root / relative).read_bytes() == (base_root / relative).read_bytes(),
                f"signed-Nostr rollback changed existing file: {relative}",
            )
        rollback = base["signedNostr"]["runtimePin"]["rollback"]
        expected_rollback = {
            "integritySha256": bytes_digest((candidate_root / f"{RENDER_ROOT}/integrity.json").read_bytes()),
            "webIngressSha256": bytes_digest((candidate_root / f"{RENDER_ROOT}/web/ingress.json").read_bytes()),
            "publicMeckyNetworkPolicySha256": bytes_digest((candidate_root / f"{RENDER_ROOT}/public-mecky/networkpolicy.json").read_bytes()),
            "boundaryReceiptSha256": bytes_digest((candidate_root / f"{RENDER_ROOT}/network-boundary-migration.json").read_bytes()),
        }
        require(
            {field: rollback[field] for field in expected_rollback} == expected_rollback,
            "signed-Nostr rollback did not restore the exact prior boundary",
        )
        return

    if base["renderFileSet"] == "current" and candidate["renderFileSet"] == "reviewed-public-knowledge":
        require(candidate["head"] == base["head"], "reviewed-public-knowledge activation must preserve the Release Set head")
        allowed_existing_changes = {
            f"{RENDER_ROOT}/integrity.json",
            f"{RENDER_ROOT}/public-mecky/deployment.json",
        }
        for relative in EXPECTED_FILES:
            if relative in allowed_existing_changes:
                continue
            require(
                (candidate_root / relative).read_bytes() == (base_root / relative).read_bytes(),
                f"reviewed-public-knowledge activation changed existing file: {relative}",
            )

        expected_public = copy.deepcopy(base["deployments"]["public-mecky"])
        expected_env = []
        base_env = expected_public["spec"]["template"]["spec"]["containers"][0]["env"]
        base_names = [item["name"] for item in base_env]
        require(LEGACY_SYNTHETIC_EVIDENCE_ENV_NAMES <= set(base_names), "protected base lacks the complete legacy synthetic environment")
        require("MECKY_REVIEWED_SOURCE_KINDS" not in base_names, "protected base already contains reviewed source ordering")
        for item in base_env:
            if item["name"] in LEGACY_SYNTHETIC_EVIDENCE_ENV_NAMES:
                continue
            transformed = copy.deepcopy(item)
            if transformed["name"] == "STADTSTACK_PUBLIC_BASE_URL":
                transformed["value"] = REVIEWED_PUBLIC_KNOWLEDGE_BASE_URL
            expected_env.append(transformed)
        expected_env.append({
            "name": "MECKY_REVIEWED_SOURCE_KINDS",
            "value": REVIEWED_PUBLIC_KNOWLEDGE_SOURCE_KINDS,
        })
        expected_public["spec"]["template"]["spec"]["containers"][0]["env"] = expected_env
        require(
            candidate["deployments"]["public-mecky"] == expected_public,
            "reviewed-public-knowledge activation Public Mecky transformation drift",
        )
        return

    if (
        base["renderFileSet"] == "reviewed-public-knowledge"
        and candidate["renderFileSet"] == "reviewed-public-knowledge"
        and candidate["head"] == base["head"]
        and not base["publicMeckyReviewedEgress"]
        and candidate["publicMeckyReviewedEgress"]
    ):
        allowed_changes = {
            f"{RENDER_ROOT}/integrity.json",
            f"{RENDER_ROOT}/public-mecky/networkpolicy.json",
            "scripts/render-release-set-promotion.py",
            "scripts/test_verify_reviewed_render.py",
            "scripts/verify-reviewed-render.py",
        }
        for relative in FUTURE_EXPECTED_FILES:
            if relative in allowed_changes:
                continue
            require(
                (candidate_root / relative).read_bytes() == (base_root / relative).read_bytes(),
                f"reviewed-runtime egress activation changed unrelated file: {relative}",
            )
        return

    require(
        candidate["publicMeckyReviewedEgress"] == base["publicMeckyReviewedEgress"],
        "Public Mecky reviewed-runtime egress must be a standalone exact transition",
    )

    for relative in EXPECTED_FILES:
        if not relative.startswith(RENDER_ROOT + "/"):
            require((candidate_root / relative).read_bytes() == (base_root / relative).read_bytes(), f"promotion changed protected policy file: {relative}")
    if base["renderFileSet"] in {"signed-nostr", "signed-nostr-participant-gateway"}:
        for relative in SIGNED_NOSTR_FILES:
            require(
                (candidate_root / relative).read_bytes() == (base_root / relative).read_bytes(),
                f"routine promotion changed signed-Nostr runtime file: {relative}",
            )
    if base_participant_gateway:
        for relative in PARTICIPANT_GATEWAY_FILES:
            require(
                (candidate_root / relative).read_bytes() == (base_root / relative).read_bytes(),
                f"routine promotion changed staging participant gateway runtime file: {relative}",
            )
    for relative in (
        f"{RENDER_ROOT}/network-boundary-migration.json",
        f"{RENDER_ROOT}/web/ingress.json",
        f"{RENDER_ROOT}/web/networkpolicy.json",
    ):
        require((candidate_root / relative).read_bytes() == (base_root / relative).read_bytes(), f"promotion changed protected network boundary: {relative}")

    previous = candidate["live"]["previous"]
    require(previous == base["head"], "candidate previous head does not equal protected base head")
    require(candidate["head"] != base["head"], "no-op promotion forbidden")
    base_components = component_map(base["head"])
    candidate_components = component_map(candidate["head"])
    changed = []
    for component in COMPONENT_ORDER:
        if candidate_components[component] == base_components[component]:
            continue
        changed.append(component)
    require(changed, "promotion must change at least one component")
    for component in changed:
        require(
            candidate_components[component]["sourceRevision"]
            == candidate["head"]["promotionRevision"],
            f"{component} changed component must bind to the promotion revision",
        )
    base_images = {
        component: next(container for container in base["deployments"][component]["spec"]["template"]["spec"]["containers"] if container.get("name") == COMPONENTS[component]["container"])["image"]
        for component in COMPONENT_ORDER
    }
    for index, component in enumerate(COMPONENT_ORDER):
        require(candidate["live"]["preconditions"][index]["currentImage"] == base_images[component], f"{component} live CAS image does not equal protected base image")


def verify(root: Path, base_root: Path | None = None) -> dict[str, Any]:
    candidate = verify_tree(root)
    if base_root is not None:
        base = verify_tree(base_root)
        verify_transition(candidate, base)
    return {
        "schemaVersion": "roebel_staging_operations_verification_v1",
        "status": "passed",
        "repository": "GiraeffleAeffle/roebel-staging-operations",
        "environment": "roebel-staging",
        "releaseSetDigest": candidate["head"]["releaseSetDigest"],
        "desiredRenderSha256": candidate["integrity"]["desiredRenderSha256"],
        "renderFileSet": candidate["renderFileSet"],
        "components": [
            {
                "component": item["component"],
                "sourceRevision": item["sourceRevision"],
                "manifestDigest": item["manifestDigest"],
            }
            for item in candidate["head"]["components"]
        ],
        "baseTransitionVerified": base_root is not None,
        "effects": {
            "secretRead": False,
            "secretWrite": False,
            "clusterMutation": False,
            "civicMutation": False,
        },
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--base-root", type=Path)
    args = parser.parse_args(argv)
    try:
        result = verify(args.root, args.base_root)
    except (OSError, json.JSONDecodeError, KeyError, TypeError, VerificationError) as error:
        print(f"reviewed-render verification failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
