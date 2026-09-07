"""Draft Case bootstrap coordinator; no CLI, Kubernetes transport or admission hook.

The adapter owns live observation and API semantics. This module owns ordered
creation and durable ownership receipts. A successful receipt keeps Flux
suspended and does not admit a citizen adoption or connect Web.
"""
from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import secrets

from scripts.staging_participant_flux_bootstrap import canonical_sha256
from scripts import synthetic_case_runtime

NONCE = "stadtstack.io/case-bootstrap-nonce"


class BootstrapStopped(RuntimeError):
    """Objects may exist; retain receipts/storage and inspect before continuing."""


class CreateConflict(RuntimeError):
    """The adapter observed a definite HTTP 409; never adopt that object."""


def _require(condition, message):
    if not condition:
        raise BootstrapStopped(message)


def _verifier():
    path = Path(__file__).with_name("verify-reviewed-render.py")
    spec = importlib.util.spec_from_file_location("case_bootstrap_protected_policy", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def target(obj):
    return {"apiVersion": obj["apiVersion"], "kind": obj["kind"],
            "namespace": obj["metadata"]["namespace"], "name": obj["metadata"]["name"]}


def build_plan(admitted_root):
    """Derive every object from the independently pinned admitted proposal."""
    verifier = _verifier()
    review = synthetic_case_runtime.bootstrap_review_plan(verifier, admitted_root, admitted_root)
    records = synthetic_case_runtime.verify_proposal(verifier, admitted_root)
    runtime = records["resources.json"]["items"]
    infrastructure = [o for o in runtime if o["kind"] != "Deployment"]
    # Isolation exists before either process. Control owns storage; public starts
    # only after the adapter has checked control startup and a clean restart.
    order = {"ServiceAccount": 0, "NetworkPolicy": 1, "ConfigMap": 2, "Service": 3}
    infrastructure.sort(key=lambda o: (order[o["kind"]], o["metadata"]["name"]))
    control = next(o for o in runtime if o["kind"] == "Deployment" and o["metadata"]["name"] == "roebel-case-steward-control")
    public = next(o for o in runtime if o["kind"] == "Deployment" and o["metadata"]["name"] == "roebel-case-public-binding")
    phases = [("isolation", infrastructure), ("control", [control]), ("public", [public]),
              ("suspended-flux", records["flux-bootstrap.json"]["items"])]
    objects = [{"phase": phase, "target": target(obj), "desired": copy.deepcopy(obj)}
               for phase, values in phases for obj in values]
    _require(len(objects) == 19, "Case bootstrap inventory mismatch")
    _require(all(o["target"]["kind"] not in {"Secret", "PersistentVolume", "PersistentVolumeClaim"} for o in objects), "storage/credential creation forbidden")
    plan = {"schemaVersion": "roebel_case_bootstrap_transaction_plan_v1",
            "review": review, "objects": objects}
    plan["planSha256"] = canonical_sha256(plan)
    return plan


def _bound_identity(adapter, observed, desired):
    _require(isinstance(observed, dict), "create outcome unresolved")
    _require(target(observed) == target(desired), "created target identity mismatch")
    _require(observed.get("metadata", {}).get("annotations", {}).get(NONCE) == desired["metadata"]["annotations"][NONCE], "create ownership unresolved")
    # The transport must reject unexpected semantics, permitting only reviewed
    # Kubernetes defaulting. This is not a permissive dictionary-subset check.
    adapter.require_exact(observed, desired)
    metadata = observed["metadata"]
    uid, version = metadata.get("uid"), metadata.get("resourceVersion")
    _require(isinstance(uid, str) and bool(uid), "created UID missing")
    _require(isinstance(version, str) and version.isdigit(), "created resourceVersion missing")
    return {"uid": uid, "resourceVersion": version}


def run_bootstrap(admitted_root, *, adapter, sink):
    """Run once through an injected adapter and a durable ReceiptSink.

    verify_preconditions must freshly verify source/cluster/namespaces, tracer
    preservation, retained claim/PV identity and private configuration checksum
    without returning private values. verify_control_restart and verify_public
    must inspect the exact owned deployment and Pod identities, not just health
    booleans. No live implementation is supplied or admitted by this draft.

    A failed or interrupted run never deletes objects/storage or resends a create.
    The nonce and pre-send intent remain available for separately reviewed recovery.
    """
    plan = build_plan(admitted_root)
    nonce = secrets.token_hex(32)
    state = {"schemaVersion": "roebel_case_bootstrap_transaction_receipt_v1",
             "planSha256": plan["planSha256"], "nonce": nonce, "status": "reserved",
             "objects": [], "checkpoint": None, "fluxSuspended": True,
             "webConnected": False, "caseAdmitted": False}
    sink.commit(state)
    try:
        adapter.verify_preconditions(copy.deepcopy(plan))
        for item in plan["objects"]:
            _require(adapter.get(item["target"]) is None, "reserved Case target already exists; adoption forbidden")
        state["status"] = "creating"
        sink.commit(state)
        for item in plan["objects"]:
            # Recheck preservation immediately before each mutation; absence is
            # finally enforced by create-only API semantics, never apply/upsert.
            adapter.verify_preconditions(copy.deepcopy(plan))
            desired = copy.deepcopy(item["desired"])
            annotations = desired["metadata"].setdefault("annotations", {})
            _require(NONCE not in annotations, "reserved nonce annotation collision")
            annotations[NONCE] = nonce
            record = {"target": item["target"], "phase": item["phase"],
                      "desiredSha256": canonical_sha256(desired), "state": "create-intent",
                      "uid": None, "resourceVersion": None}
            state["objects"].append(record)
            sink.commit(state)  # Must finish fsync before a request can leave.
            try:
                observed = adapter.create(desired)
            except CreateConflict:
                record["state"] = "conflict"
                raise BootstrapStopped("create conflict; adoption forbidden") from None
            except Exception:
                # Do not retry: an API timeout may have committed the object.
                observed = None
            if observed is None:
                observed = adapter.get(item["target"])
            identity = _bound_identity(adapter, observed, desired)
            _require(identity["uid"] not in {r["uid"] for r in state["objects"][:-1]}, "duplicate created UID")
            record.update(identity, state="created")
            sink.commit(state)
            if item["phase"] in {"control", "public"}:
                state["checkpoint"] = item["phase"] + "-verification-intent"
                sink.commit(state)
                if item["phase"] == "control":
                    adapter.verify_control_restart(copy.deepcopy(record), copy.deepcopy(plan))
                else:
                    adapter.verify_public(copy.deepcopy(record), copy.deepcopy(plan))
                state["checkpoint"] = item["phase"] + "-verified"
                sink.commit(state)
        # Bind every final UID and exact spec again. Keep ownership nonces until
        # a separate reviewed Flux handover; never silently strip recovery proof.
        for item, record in zip(plan["objects"], state["objects"], strict=True):
            desired = copy.deepcopy(item["desired"])
            desired["metadata"].setdefault("annotations", {})[NONCE] = nonce
            identity = _bound_identity(adapter, adapter.get(item["target"]), desired)
            _require(identity["uid"] == record["uid"], "final owned UID changed")
        adapter.verify_preconditions(copy.deepcopy(plan))
        state["status"] = "bootstrap-verified-flux-suspended"
        sink.commit(state)
        return copy.deepcopy(state)
    except Exception:
        # Avoid exporting exception text: adapters may see sensitive API errors.
        state["status"] = "stopped-preserve-owned-objects"
        try:
            sink.commit(state)
        except Exception:
            pass  # The last durable create intent remains the recovery boundary.
        raise BootstrapStopped("Case bootstrap stopped; preserve objects and inspect durable receipt") from None
