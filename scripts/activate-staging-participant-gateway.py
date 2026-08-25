#!/usr/bin/env python3
"""Protected, deterministic participant activation planner.

It never contacts a cluster.  Execution stays blocked until a separately
reviewed runner with a receipt signer is introduced; this avoids treating a
candidate-supplied kubectl invocation as authority.
"""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path

ORDER = ["NetworkPolicy", "ServiceAccount", "Service", "Deployment", "Ingress"]

def canonical(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)

def plan(evidence: dict[str, object], revision: str) -> dict[str, object]:
    if evidence.get("status") != "approved-separate-review":
        raise ValueError("activation blocked: evidence is not separately approved")
    result = {"schemaVersion": "roebel_staging_participant_gateway_activation_plan_v1", "protectedRevision": revision, "createOrder": ORDER, "createConflictPolicy": "fail-on-http-409-no-adopt", "healthBeforeIngress": True, "rollback": "cas-resuspend-before-exact-uid-ingress-first-delete", "mode": "verify-plan-only"}
    result["planSha256"] = "sha256:" + hashlib.sha256(canonical(result).encode()).hexdigest()
    return result

def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--evidence", type=Path, required=True); parser.add_argument("--protected-revision", required=True); args = parser.parse_args()
    print(canonical(plan(json.loads(args.evidence.read_text()), args.protected_revision)))
    return 0
if __name__ == "__main__": raise SystemExit(main())
