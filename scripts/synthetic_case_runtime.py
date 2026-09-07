"""Review the pinned synthetic Case proposal without activating a workload.

Only the protected checkout supplies these pins. The candidate is data, and
an offline bootstrap plan is not permission to execute its remaining steps.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path


ROOT = Path("proposals/synthetic-case-runtime")
PINS = {
    "README.md": "b14482dd9134fa85088162c57e35a2c6670320b69d8611bd1eea77a442f92308",
    "control-binding.json": "a8c09f4518e7a939984ca8d9498a3c0026d4b408b3aad8018a7667b25642451a",
    "flux-bootstrap.json": "99b7f085179a2d350778af5ce7ea0c6ca061a7cb2216355c94fc8f0a0d2cebdf",
    "kustomization.yaml": "0ebeb1403260a4e9da358ae14b13cc531961d541a404d444dedac738826cd9df",
    "proposal.json": "bec4c269d65ce5593857eedff22b2ae81fe238ff8daff544a805ff33185d262e",
    "public-binding.json": "2da4fd604fc1a61fa061e0ef8262328bed0e4a4854c72b551f51fcfb97786643",
    "resources.json": "f4c4f5c3f428082ad6321ba9d8e07bd2b80b58bd7ef84b96b670211a16d9a69d",
    "topology.json": "3c8a8bd0d62a2d7499aa5e43549677853c43203aa16aa466a1b84eccd4b4afd5",
    "web-connection.json": "0ee648f1b78bad65ed3cdd7e9a92149d68621fff1f2d1570a6466a707b753c02",
}
FILES = {str(ROOT / name) for name in PINS} | {
    "scripts/synthetic_case_runtime.py", "scripts/test_synthetic_case_runtime.py",
}


def verify_proposal(v, root):
    """Admit only the independently pinned complete, inactive review bundle."""
    records = {}
    for name, expected in PINS.items():
        path = root / ROOT / name
        v.require(path.is_file() and not path.is_symlink(), "Case proposal requires regular files")
        v.require(path.stat().st_size <= 262144, "Case proposal artifact exceeds size bound")
        raw = path.read_bytes()
        v.require(hashlib.sha256(raw).hexdigest() == expected, f"Case proposal protected pin mismatch: {name}")
        if path.suffix == ".json":
            records[name] = json.loads(raw)
    proposal = records["proposal.json"]
    v.require(proposal["status"] == "review_only_runtime_activation_blocked", "Case activation is not admitted")
    v.require(proposal["fluxReconciliation"] is False and proposal["restoreActivation"] is False, "Case activation is not admitted")
    for name, expected in proposal["artifacts"].items():
        v.require(expected == "sha256:" + PINS[name], "Case artifact manifest mismatch")
    return records


def verify_transition(v, candidate_root, base_root):
    v.require(not v.changed_repository_files(candidate_root, base_root) & FILES,
              "promotion changed protected Case proposal files")


def bootstrap_review_plan(v, root, active_root):
    """Describe exact pending effects; never read a credential or run kubectl."""
    # Keep the currently admitted render separate from this inactive draft.
    # In particular, do not bypass its repository inventory to admit the draft.
    snapshot = v.verify_tree(active_root)
    records = verify_proposal(v, root)
    proposal = records["proposal.json"]
    connection = records["web-connection.json"]
    web = snapshot["deployments"]["roebel-web-staging"]["spec"]["template"]["spec"]["containers"][0]
    v.require(web["image"] == connection["webImage"], "Case proposal requires its published Web image")
    objects = records["resources.json"]["items"]
    def identity(obj):
        return {"apiVersion": obj["apiVersion"], "kind": obj["kind"], **{
            key: obj["metadata"][key] for key in ("namespace", "name")}}
    return {
        "schemaVersion": "roebel_synthetic_case_bootstrap_review_plan_v1",
        "runtimeActivationAdmitted": False,
        "executableDeploymentPlan": False,
        "effects": {"clusterMutation": False, "credentialRead": False, "caseAdmission": False},
        "reviewedOperationsPredecessor": proposal["operationsPredecessor"],
        "activeRenderSha256": snapshot["integrity"]["desiredRenderSha256"],
        "proposalFileSha256": {str(ROOT / name): "sha256:" + digest for name, digest in PINS.items()},
        "runtimeObjects": [{**identity(obj), "canonicalSha256": v.digest(obj)} for obj in objects],
        "fluxBootstrapObjects": [identity(obj) for obj in records["flux-bootstrap.json"]["items"]],
        "existingStorage": {
            "claim": records["control-binding.json"]["storage"],
            "volumeUid": proposal["storageVolumeUid"], "reclaimPolicy": "Retain",
            "createOrDelete": False, "historicalEmptyObservationIsFreshEvidence": False,
        },
        "separateCredentialProvisioning": {
            **proposal["privateConfigurationSecretReference"],
            "configurationSha256": proposal["privateConfigurationSha256"],
            "privateValueIncluded": False,
        },
        "requiredSequence": [
            "independent approval of the exact runtime transition and bootstrap implementation",
            "fresh cluster, source revision, current workloads, network, retained storage and reserved-name observations",
            "durable intent journal, create-only ownership and exact-UID receipts before any retry",
            "separate scoped credential provisioning; verify bytes without disclosing them",
            "tokenless identities, isolation policies, reviewed configuration and Services before runtime startup",
            "control startup and clean shutdown/restart on the existing claim; preserve all store evidence on failure",
            "public replay readiness before enabling the separately reviewed Web connection",
            "suspended Flux bootstrap; exact object ownership and restricted RBAC verification before explicit unsuspend",
            "explicit saved synthetic-adoption admission and independent public/browser receipt verification",
        ],
        "rollback": {
            "first": "suspend only the owned Case reconciler and stop the owned Case workloads",
            "objects": "restore or delete only transaction-owned non-storage objects using exact UID preconditions",
            "preserve": ["existing tracer database", "Case claim and volume", "Case store and shutdown evidence", "prior civic records"],
            "automaticRestore": False,
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--active-root", type=Path, required=True)
    args = parser.parse_args()
    path = Path(__file__).with_name("verify-reviewed-render.py")
    spec = importlib.util.spec_from_file_location("protected_case_plan_verifier", path)
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    print(json.dumps(bootstrap_review_plan(verifier, args.root, args.active_root), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
