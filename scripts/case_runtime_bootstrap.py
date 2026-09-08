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
import re

from .staging_participant_flux_bootstrap import canonical_sha256
from . import synthetic_case_runtime

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
    """Derive objects from the render verified against the pinned proposal."""
    verifier = _verifier()
    review = synthetic_case_runtime.bootstrap_review_plan(verifier, admitted_root, admitted_root)
    records = synthetic_case_runtime.verify_proposal(verifier, admitted_root)
    runtime = verifier.load_json(admitted_root / 'reviewed-render/roebel-staging/case-runtime/resources.json')["items"]
    review['runtimeObjects']=[{**target(obj),'canonicalSha256':verifier.digest(obj)} for obj in runtime]
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


def validate_runtime_evidence(phase,evidence):
    fields=({'podUid','beforeContainerId','afterContainerId','exitCode','restartCount'} if phase=='control' else {'podUid','imageId'})
    _require(isinstance(evidence,dict) and set(evidence)==fields,'runtime evidence shape invalid')
    for key in fields-{'exitCode','restartCount'}:
        _require(isinstance(evidence[key],str) and 0<len(evidence[key])<=512 and all(ord(c)>=32 for c in evidence[key]),'runtime evidence identity invalid')
    if phase=='control':
        _require(evidence['exitCode']==0 and type(evidence['restartCount']) is int and evidence['restartCount']>0 and evidence['beforeContainerId']!=evidence['afterContainerId'],'clean restart evidence invalid')
    return copy.deepcopy(evidence)


def bind_recovery(plan, receipt):
    """Validate the exact plan and ordered ownership prefix before any API use."""
    state = copy.deepcopy(receipt)
    digest = state.pop("canonicalSha256", None)
    _require(digest == canonical_sha256(state), "recovery receipt checksum mismatch")
    _require(set(state) == {"schemaVersion", "planSha256", "nonce", "status", "objects", "checkpoint", "fluxSuspended", "webConnected", "caseAdmitted", "runtimeChecks"}, "recovery receipt shape mismatch")
    _require(state["schemaVersion"] == "roebel_case_bootstrap_transaction_receipt_v1" and state["planSha256"] == plan["planSha256"], "recovery plan mismatch")
    _require(isinstance(state["nonce"], str) and re.fullmatch(r"[0-9a-f]{64}", state["nonce"]), "recovery nonce invalid")
    _require(state["fluxSuspended"] is True and state["webConnected"] is False and state["caseAdmitted"] is False, "recovery effect boundary mismatch")
    _require(state["status"] in {"reserved", "creating", "stopped-preserve-owned-objects", "bootstrap-verified-flux-suspended"}, "recovery status invalid")
    _require(state["checkpoint"] in {None, "control-verification-intent", "control-verified", "public-verification-intent", "public-verified"}, "recovery checkpoint invalid")
    _require(isinstance(state["runtimeChecks"], dict) and set(state["runtimeChecks"]) <= {"control", "public"}, "recovery runtime evidence invalid")
    for phase,evidence in state["runtimeChecks"].items():validate_runtime_evidence(phase,evidence)
    records = state["objects"]
    _require(isinstance(records, list) and len(records) <= len(plan["objects"]), "recovery prefix invalid")
    uids = set()
    for index, record in enumerate(records):
        item = plan["objects"][index]
        desired = copy.deepcopy(item["desired"])
        desired["metadata"].setdefault("annotations", {})[NONCE] = state["nonce"]
        _require(set(record) == {"target", "phase", "desiredSha256", "state", "uid", "resourceVersion"}, "recovery object shape mismatch")
        _require(record["target"] == item["target"] and record["phase"] == item["phase"] and record["desiredSha256"] == canonical_sha256(desired), "recovery ordered object mismatch")
        _require(record["state"] in {"create-intent", "created"}, "conflicted transaction cannot be resumed")
        if record["state"] == "create-intent":
            _require(index == len(records)-1 and record["uid"] is None and record["resourceVersion"] is None, "recovery unresolved prefix invalid")
        else:
            _require(isinstance(record["uid"], str) and record["uid"] and record["uid"] not in uids and isinstance(record["resourceVersion"], str) and record["resourceVersion"].isdigit(), "recovery owned identity invalid")
            uids.add(record["uid"])
    return state


def run_bootstrap(admitted_root, *, adapter, sink, prior_receipt=None):
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
    if prior_receipt is None:
        state = {"schemaVersion": "roebel_case_bootstrap_transaction_receipt_v1",
                 "planSha256": plan["planSha256"], "nonce": secrets.token_hex(32), "status": "reserved",
                 "objects": [], "checkpoint": None, "fluxSuspended": True,
                 "webConnected": False, "caseAdmitted": False, "runtimeChecks": {}}
    else:
        state = bind_recovery(plan, prior_receipt)
    nonce = state["nonce"]
    sink.commit(state)
    try:
        adapter.verify_preconditions(copy.deepcopy(plan))
        for index, item in enumerate(plan["objects"]):
            observed = adapter.get(item["target"])
            if index >= len(state["objects"]):
                _require(observed is None, "reserved Case target already exists; adoption forbidden")
                continue
            record = state["objects"][index]
            desired = copy.deepcopy(item["desired"])
            desired["metadata"].setdefault("annotations", {})[NONCE] = nonce
            identity = _bound_identity(adapter, observed, desired)
            if record["uid"] is not None:
                _require(identity["uid"] == record["uid"], "recovery owned UID changed")
            # An unresolved absent create is deliberately not retried: a timed
            # out request can still arrive. Recovery requires exact observation.
            record.update(identity, state="created")
            sink.commit(state)
        state["status"] = "creating"
        sink.commit(state)
        for index, item in enumerate(plan["objects"]):
            # Recheck preservation immediately before each mutation; absence is
            # finally enforced by create-only API semantics, never apply/upsert.
            adapter.verify_preconditions(copy.deepcopy(plan))
            desired = copy.deepcopy(item["desired"])
            annotations = desired["metadata"].setdefault("annotations", {})
            _require(NONCE not in annotations, "reserved nonce annotation collision")
            annotations[NONCE] = nonce
            if index < len(state["objects"]):
                record = state["objects"][index]
            else:
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
                    state["runtimeChecks"]["control"] = validate_runtime_evidence("control",adapter.verify_control_restart(copy.deepcopy(record), copy.deepcopy(plan)))
                else:
                    state["runtimeChecks"]["public"] = validate_runtime_evidence("public",adapter.verify_public(copy.deepcopy(record), copy.deepcopy(plan)))
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
