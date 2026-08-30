import base64, contextlib, copy, datetime as dt, importlib.util, inspect, json, os, stat, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("activation", Path(__file__).with_name("activate-staging-participant-gateway.py"))
MODULE = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = MODULE; SPEC.loader.exec_module(MODULE)
REV = "a" * 40
MODULE.POLICY = MODULE.compile_verified_policy_module_v4(
    Path(__file__).with_name("staging_participant_gateway_policy.py").read_bytes(),
    REV,
)
MODULE.BOOTSTRAP = MODULE.compile_verified_bootstrap_module_v4(
    Path(__file__).with_name("staging_participant_flux_bootstrap.py").read_bytes(),
    REV,
)
TRACER_SPEC = importlib.util.spec_from_file_location(
    "participant_test_tracer_policy",
    Path(__file__).with_name("tracer_data_plane_policy.py"),
)
assert TRACER_SPEC and TRACER_SPEC.loader
TRACER_POLICY = importlib.util.module_from_spec(TRACER_SPEC)
TRACER_SPEC.loader.exec_module(TRACER_POLICY)
HANDOVER_SPEC = importlib.util.spec_from_file_location(
    "participant_test_handover_runner",
    Path(__file__).with_name("handover-staging-participant-dormant-receipt.py"),
)
assert HANDOVER_SPEC and HANDOVER_SPEC.loader
HANDOVER_RUNNER = importlib.util.module_from_spec(HANDOVER_SPEC)
HANDOVER_SPEC.loader.exec_module(HANDOVER_RUNNER)
def sha(x="a"): return "sha256:" + x * 64
def historical_secret_receipt():
    unsigned = {
        "schemaVersion": "roebel_staging_participant_secret_materialization_receipt_v1",
        "status": "materialized",
        "protectedRevision": MODULE.SECRET_RECEIPT_ORIGIN_REVISION,
        "activationPolicySha256": MODULE.SECRET_RECEIPT_ORIGIN_ACTIVATION_POLICY_SHA256,
        "protectedRunnerFileSha256": copy.deepcopy(MODULE.SECRET_RECEIPT_ORIGIN_RUNNER_FILE_SHA256),
        "createOrder": ["config", "runtime"],
        "secrets": copy.deepcopy(MODULE.SECRET_RECEIPT_ORIGIN_SECRET_RECORDS),
        "inputTransport": "owned-private-inherited-descriptors-only",
        "valuesInReceipt": False,
        "civicAuthorityEffects": False,
    }
    receipt = unsigned | {"canonicalSha256": MODULE.digest(unsigned)}
    return receipt, (MODULE.canonical(receipt) + "\n").encode("utf-8")
def object_(kind, name=MODULE.NAME, namespace=MODULE.NAMESPACE, uid="uid", rv="10", **extra):
    value = {"apiVersion": "v1", "kind": kind, "metadata": {"name": name, "namespace": namespace, "uid": uid, "resourceVersion": rv}}; value.update(extra); return value
def policy():
    return copy.deepcopy(MODULE.POLICY.STATIC_ACTIVATION_POLICY)
def ready_policy():
    return MODULE.POLICY.approved_next_activation_policy_descriptor()
def admitted(desired, uid="owned-uid", rv="10"):
    value = copy.deepcopy(desired); value.setdefault("metadata", {})["uid"] = uid; value["metadata"]["resourceVersion"] = rv
    return value
def dormant_ownership():
    gateway = MODULE.POLICY.gateway_flux_objects(suspended=True)
    workbench = MODULE.POLICY.workbench_ingress_flux_objects(suspended=True)
    desired = {
        "gateway.serviceAccount": gateway["serviceAccount"],
        "workbenchIngress.serviceAccount": workbench["serviceAccount"],
        "gateway.role": gateway["role"],
        "workbenchIngress.role": workbench["role"],
        "gateway.roleBinding": gateway["roleBinding"],
        "workbenchIngress.roleBinding": workbench["roleBinding"],
        "gateway.kustomization": gateway["kustomization"],
        "workbenchIngress.kustomization": workbench["kustomization"],
    }
    return {
        "schemaVersion": "roebel_staging_participant_flux_bootstrap_receipt_v1",
        "status": "dormant-ready",
        "receiptSha256": sha("b"),
        "protectedRevision": REV,
        "activationPolicySha256": MODULE.POLICY.activation_policy_sha256(ready_policy()),
        "objects": [
            {
                "logicalName": logical,
                "target": {
                    "apiVersion": desired[logical]["apiVersion"],
                    "kind": desired[logical]["kind"],
                    "namespace": desired[logical]["metadata"]["namespace"],
                    "name": desired[logical]["metadata"]["name"],
                },
                "uid": f"uid-{index}",
                "resourceVersion": "10",
                "desiredSemanticSha256": MODULE.POLICY.semantic_sha256(desired[logical]),
            }
            for index, logical in enumerate(MODULE.POLICY.DORMANT_BOOTSTRAP_OBJECT_ORDER)
        ],
        "bothKustomizationsSuspended": True,
    }

def tracer_activation_receipt(p):
    operation_nonce = "d" * 64
    secret_nonce = "e" * 64
    secret_contract = TRACER_POLICY.secret_materialization_contract()["secrets"]
    secret_records = {
        label: {
            "target": {
                "apiVersion": "v1", "kind": "Secret",
                "name": reference["name"], "namespace": reference["namespace"],
            },
            "uid": f"{label}-secret-uid",
            "resourceVersion": str(30 + index),
            "keySet": sorted(reference["keys"]),
            "ownershipNonce": secret_nonce,
            "valuesRead": False,
        }
        for index, (label, reference) in enumerate(secret_contract.items())
    }
    application = TRACER_POLICY.expected_application_objects(Path(__file__).resolve().parents[1])
    flux = TRACER_POLICY.dormant_flux_objects(suspended=True)
    desired = {
        **{f"application.{label}": value for label, value in application.items()},
        **{f"flux.{label}": value for label, value in flux.items()},
    }
    object_records = {
        label: {
            "target": {
                "apiVersion": value["apiVersion"], "kind": value["kind"],
                "namespace": value["metadata"]["namespace"], "name": value["metadata"]["name"],
            },
            "uid": f"tracer-object-{index}-uid",
            "resourceVersion": str(100 + index),
            "ownershipNonce": operation_nonce,
            "temporaryNonceRemoved": True,
        }
        for index, (label, value) in enumerate(desired.items())
    }
    cluster = {
        **copy.deepcopy(p["clusterIdentity"]),
        "kubeSystemNamespaceResourceVersion": "23",
        "credentialsIncluded": False,
        "kubeconfigPathIncluded": False,
    }
    return {
        "schemaVersion": MODULE.TRACER_ACTIVATION_RECEIPT_SCHEMA,
        "status": "activated",
        "protectedRevision": REV,
        "operationNonce": operation_nonce,
        "productSourceRevision": p["productPins"]["sourceRevision"],
        "protectedFileSha256": {
            path: MODULE.bytes_digest(path.encode())
            for path in MODULE.TRACER_RECEIPT_PROTECTED_PATHS
        },
        "clusterBinding": cluster,
        "sharedFluxSource": {"revision": f"main@sha1:{REV}", "ready": True, "mutation": False},
        "secretMaterializationReceiptSha256": sha("c"),
        "secretRecords": secret_records,
        "createOrder": list(desired),
        "objectRecords": object_records,
        "flux": {
            "uid": object_records["flux.kustomization"]["uid"],
            "lastAppliedRevision": f"main@sha1:{REV}",
            "ready": True,
        },
        "serviceBindings": {
            "postgres": {
                "serviceUid": "postgres-service-uid", "port": 5432,
                "readyEndpointAddresses": ["10.244.1.10"],
            },
            "postgrest": {
                "serviceUid": "postgrest-service-uid", "port": p["endpoints"]["supabase"]["port"],
                "readyEndpointAddresses": ["10.244.1.11"],
            },
        },
        "failureRollback": "exact-operation-owned-uids-only",
        "secretValuesRead": False,
        "civicAuthorityEffects": False,
        "signalsDeferredDuringFinalization": [],
        "functionalHttpRpcProof": {
            "status": "pending-participant-gateway-protected-preflight",
            "secretValuesRead": False,
        },
    }

def failed_activation_receipt_fixture():
    """Synthetic shape of the one pinned aaca3166 incident receipt."""
    cluster = {
        "apiOrigin": "https://10.255.240.11:6443",
        "apiServerSpkiSha256": "sha256:1507430795ee7c9cbeea9133dd3b1a809a500de5bcc4dd8e400163ac9471186a",
        "caCertificateSha256": "sha256:42fd39869882e3c25a1f37c090542d215ceb0f60a7d68f5603fb9a0583afee28",
        "credentialsIncluded": False,
        "kubeSystemNamespaceResourceVersion": "9",
        "kubeSystemNamespaceUid": "7bc769bc-e860-4d54-a0d5-d426f3a52420",
        "kubeconfigPathIncluded": False,
    }
    unsigned = {
        "schemaVersion": MODULE.RECEIPT_SCHEMA,
        "status": "rollback-incomplete",
        "protectedRevision": MODULE.FAILED_ACTIVATION_ORIGIN_REVISION,
        "failure": MODULE.FAILED_ACTIVATION_FAILURE,
        "protectedRunnerFileSha256": copy.deepcopy(MODULE.FAILED_ACTIVATION_RUNNER_FILE_SHA256),
        "objectCreateResults": copy.deepcopy(list(MODULE.FAILED_ACTIVATION_OBJECT_CREATE_RESULTS)),
        "rollback": {
            "status": "incomplete",
            "bothKustomizationsSuspended": False,
            "flux": {},
            "deleted": [
                {
                    "logicalName": "gateway.service",
                    "uid": MODULE.FAILED_ACTIVATION_OBJECT_UIDS["gateway.service"],
                    "deleteResourceVersion": "16386566",
                    "absent": True,
                    "foregroundPropagation": False,
                    "finalizersRemovedByRunner": False,
                },
                {"logicalName": "gateway.service", "absent": True, "alreadyAbsent": True},
            ],
            "finalChecks": {
                "clusterBindingBeforeRollback": copy.deepcopy(cluster),
                "exposureBreak": {
                    "reason": "always-remove-owned-service-before-flux",
                    "initialIngressAbsenceProved": False,
                    "serviceUid": MODULE.FAILED_ACTIVATION_OBJECT_UIDS["gateway.service"],
                    "serviceAbsent": True,
                    "unknownIngressUntouched": True,
                },
                "exposureBreakAfterFlux": {
                    "serviceUid": MODULE.FAILED_ACTIVATION_OBJECT_UIDS["gateway.service"],
                    "serviceAbsent": True,
                    "sameOwnedUidOnly": True,
                },
                "clusterBinding": copy.deepcopy(cluster),
            },
            "preservation": {
                "existingWorkbenchNetworkPolicy": {
                    "afterCanonicalSha256": "sha256:a125687ad4f00e2fbb921d6f5550f65daa267dfa627a24a598af0cbc1d27eb79",
                    "beforeCanonicalSha256": "sha256:a125687ad4f00e2fbb921d6f5550f65daa267dfa627a24a598af0cbc1d27eb79",
                    "byteIdenticalCanonicalJson": True,
                    "target": {
                        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
                        "name": "e2e-workbench", "namespace": "stadtstack-roebel-staging-lab",
                    },
                },
                "webIngress": {
                    "afterCanonicalSha256": "sha256:79d2057a3d6755df99f3364b626d6ff7143053f1d7bde581967b4dcbd194a0ec",
                    "beforeCanonicalSha256": "sha256:79d2057a3d6755df99f3364b626d6ff7143053f1d7bde581967b4dcbd194a0ec",
                    "byteIdenticalCanonicalJson": True,
                    "target": {
                        "apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
                        "name": "roebel-web-presentation", "namespace": "stadtstack-roebel-web-preview",
                    },
                },
            },
            "uncertainTarget": "gateway.deployment",
            "errors": [
                "gateway rollback suspension timeout",
                "post-send create outcome unresolved: gateway.deployment",
            ],
            "finalizersRemovedByRunner": False,
        },
        "termination": {
            "interrupted": False,
            "signal": None,
            "signalsDeferredDuringRollback": True,
        },
        "civicAuthorityEffects": False,
    }
    return unsigned | {"canonicalSha256": MODULE.digest(unsigned)}

def recovery_incident_ownership():
    return {
        "originProtectedRevision": MODULE.FAILED_ACTIVATION_ORIGIN_REVISION,
        "originRawSha256": MODULE.FAILED_ACTIVATION_RAW_SHA256,
        "originReceiptSha256": MODULE.FAILED_ACTIVATION_CANONICAL_SHA256,
        "operationNonce": MODULE.FAILED_ACTIVATION_OPERATION_NONCE,
        "objects": {
            logical: copy.deepcopy(record)
            for logical, record in zip(
                MODULE.FAILED_ACTIVATION_CREATED_ORDER,
                MODULE.FAILED_ACTIVATION_OBJECT_CREATE_RESULTS,
            )
        },
        "serviceExposureBreakProved": True,
        "ingressNeverCreated": True,
        "civicAuthorityEffects": False,
    }

def run29_recovery_incident_ownership():
    return {
        "originProtectedRevision": MODULE.RUN29_FAILED_ACTIVATION_ORIGIN_REVISION,
        "originRawSha256": MODULE.RUN29_FAILED_ACTIVATION_RAW_SHA256,
        "originReceiptSha256": MODULE.RUN29_FAILED_ACTIVATION_CANONICAL_SHA256,
        "operationNonce": MODULE.RUN29_FAILED_ACTIVATION_OPERATION_NONCE,
        "objects": {
            logical: copy.deepcopy(record)
            for logical, record in zip(
                MODULE.RUN29_FAILED_ACTIVATION_CREATED_ORDER,
                MODULE.RUN29_FAILED_ACTIVATION_OBJECT_CREATE_RESULTS,
            )
        },
        "serviceExposureBreakProved": False,
        "ingressNeverCreated": False,
        "civicAuthorityEffects": False,
    }

def incident_semantic_hash_fixture(incident, desired_by_logical):
    """Keep recovery classification tests pinned to the historical incident render."""
    hashes = {
        (
            desired["apiVersion"], desired["kind"],
            desired["metadata"]["namespace"], desired["metadata"]["name"],
        ): incident["objects"][logical]["semanticSha256"]
        for logical, desired in desired_by_logical.items()
        if logical in incident["objects"]
    }

    def semantic(value):
        metadata = value["metadata"]
        return hashes[(value["apiVersion"], value["kind"], metadata["namespace"], metadata["name"])]

    return semantic

def recovery_dormant_ownership():
    value = dormant_ownership()
    value["receiptProvenance"] = {"mode": "archived-v1+get-only-handover"}
    return value

def recovery_cluster(value, resource_version="10"):
    return {
        "apiOrigin": value["clusterIdentity"]["apiOrigin"],
        "caCertificateSha256": value["clusterIdentity"]["caCertificateSha256"],
        "apiServerSpkiSha256": value["clusterIdentity"]["apiServerSpkiSha256"],
        "kubeSystemNamespaceUid": value["clusterIdentity"]["kubeSystemNamespaceUid"],
        "kubeSystemNamespaceResourceVersion": resource_version,
        "credentialsIncluded": False,
        "kubeconfigPathIncluded": False,
    }

def recovery_flux(uid, resource_version="20"):
    return {
        "uid": uid,
        "resourceVersion": resource_version,
        "generation": 1,
        "observedGeneration": -1,
        "suspended": True,
        "reconcilingCurrentGeneration": False,
    }

def recovery_dependents_absent():
    return {
        "status": "deployment-foreground-dependents-absent",
        "resources": {
            resource: {"selector": copy.deepcopy(MODULE.POLICY.GATEWAY_LABELS), "count": 0}
            for resource in ("pods", "replicasets.apps")
        },
    }

def recovery_preservation(value, checksum=None):
    checksum = checksum or sha("c")
    return {
        label: {
            "target": copy.deepcopy(descriptor["target"]),
            "beforeCanonicalSha256": checksum,
            "afterCanonicalSha256": checksum,
            "byteIdenticalCanonicalJson": True,
        }
        for label, descriptor in value["preservation"].items()
    }

def valid_recovery_preflight(value, *, deployment_present=True):
    gateway_flux = recovery_flux("gateway-flux-uid", "20")
    workbench_flux = recovery_flux("workbench-flux-uid", "30")
    targets = {
        logical: {
            "state": "present-exact-receipt-owned",
            "uid": MODULE.FAILED_ACTIVATION_OBJECT_UIDS[logical],
            "resourceVersion": str(40 + index),
            "sourceReceiptSha256": MODULE.FAILED_ACTIVATION_CANONICAL_SHA256,
        }
        for index, logical in enumerate((
            "gateway.networkPolicy", "workbenchIngress.networkPolicy", "gateway.serviceAccount",
        ))
    }
    targets["gateway.service"] = {
        "state": "absent-exposure-break-proved",
        "uid": MODULE.FAILED_ACTIVATION_OBJECT_UIDS["gateway.service"],
        "sourceReceiptSha256": MODULE.FAILED_ACTIVATION_CANONICAL_SHA256,
    }
    targets["gateway.deployment"] = (
        {
            "state": "present-exact-failed-nonce-owned",
            "uid": "deployment-uid",
            "resourceVersion": "50",
            "operationNonce": MODULE.FAILED_ACTIVATION_OPERATION_NONCE,
        }
        if deployment_present else {
            "state": "absent-unresolved-create",
            "dependents": recovery_dependents_absent(),
        }
    )
    targets["gateway.ingress"] = {
        "state": "absent-never-created",
        "sourceReceiptSha256": MODULE.FAILED_ACTIVATION_CANONICAL_SHA256,
    }
    cluster = recovery_cluster(value)
    return {
        "clusterBinding": {"initial": cluster, "beforeRollback": copy.deepcopy(cluster)},
        "dormantReceipt": {
            "receiptSha256": sha("d"),
            "protectedRevision": REV,
            "kustomizationUids": {
                "gateway": gateway_flux["uid"],
                "workbenchIngress": workbench_flux["uid"],
            },
        },
        "flux": {"gateway": gateway_flux, "workbenchIngress": workbench_flux},
        "source": {
            "uid": "source-uid",
            "resourceVersion": "40",
            "generation": 2,
            "observedGeneration": 2,
            "artifactRevision": f"main@sha1:{REV}",
            "ready": True,
        },
        "targets": targets,
        "preservation": recovery_preservation(value),
    }

def valid_run29_recovery_preflight(value):
    revision = f"main@sha1:{MODULE.RUN29_FAILED_ACTIVATION_ORIGIN_REVISION}"
    gateway_flux = {
        "uid": "gateway-flux-uid", "resourceVersion": "16837627",
        "generation": 3, "observedGeneration": -1, "suspended": True,
        "incidentState": "suspended-after-exact-rbac-healthcheck-failure",
        "lastAttemptedRevision": revision, "lastAppliedRevision": None,
        "quietSeconds": 2, "checks": 2, "objectStableForQuietInterval": True,
    }
    workbench_flux = {
        "uid": "workbench-flux-uid", "resourceVersion": "16837661",
        "generation": 3, "observedGeneration": 3, "suspended": True,
        "incidentState": "suspended-after-successful-run29-reconcile",
        "lastAttemptedRevision": revision, "lastAppliedRevision": revision,
        "quietSeconds": 2, "checks": 2, "objectStableForQuietInterval": True,
    }
    targets = {
        logical: {
            "state": "present-exact-receipt-owned",
            "uid": MODULE.RUN29_FAILED_ACTIVATION_OBJECT_UIDS[logical],
            "resourceVersion": str(200 + index),
            "sourceReceiptSha256": MODULE.RUN29_FAILED_ACTIVATION_CANONICAL_SHA256,
        }
        for index, logical in enumerate(MODULE.RUN29_FAILED_ACTIVATION_CREATED_ORDER)
    }
    cluster = recovery_cluster(value)
    return {
        "clusterBinding": {"initial": cluster, "beforeRollback": copy.deepcopy(cluster)},
        "dormantReceipt": {
            "receiptSha256": sha("d"), "protectedRevision": REV,
            "kustomizationUids": {
                "gateway": gateway_flux["uid"],
                "workbenchIngress": workbench_flux["uid"],
            },
        },
        "flux": {"gateway": gateway_flux, "workbenchIngress": workbench_flux},
        "source": {
            "uid": "source-uid", "resourceVersion": "40",
            "generation": 2, "observedGeneration": 2,
            "artifactRevision": f"main@sha1:{REV}", "ready": True,
        },
        "targets": targets,
        "preservation": recovery_preservation(value),
    }

def valid_recovery_rollback(value, preflight):
    deployment_present = preflight["targets"]["gateway.deployment"]["state"] == "present-exact-failed-nonce-owned"
    deleted = [
        {"logicalName": "gateway.service", "absent": True, "alreadyAbsent": True},
        {"logicalName": "gateway.service", "absent": True, "alreadyAbsent": True},
    ]
    if deployment_present:
        deleted.append({
            "logicalName": "gateway.deployment",
            "uid": preflight["targets"]["gateway.deployment"]["uid"],
            "deleteResourceVersion": "60",
            "absent": True,
            "foregroundPropagation": True,
            "finalizersRemovedByRunner": False,
        })
    for logical in ("gateway.serviceAccount", "workbenchIngress.networkPolicy", "gateway.networkPolicy"):
        target = preflight["targets"][logical]
        if target["state"] == "present-exact-receipt-owned":
            deleted.append({
                "logicalName": logical,
                "uid": target["uid"],
                "deleteResourceVersion": "61",
                "absent": True,
                "foregroundPropagation": False,
                "finalizersRemovedByRunner": False,
            })
        else:
            deleted.append({"logicalName": logical, "absent": True, "alreadyAbsent": True})
    final = {
        "clusterBindingBeforeRollback": copy.deepcopy(preflight["clusterBinding"]["initial"]),
        "exposureBreak": {
            "reason": "always-remove-owned-service-before-flux",
            "initialIngressAbsenceProved": False,
            "serviceUid": MODULE.FAILED_ACTIVATION_OBJECT_UIDS["gateway.service"],
            "serviceAbsent": True,
            "unknownIngressUntouched": True,
        },
        "exposureBreakAfterFlux": {
            "serviceUid": MODULE.FAILED_ACTIVATION_OBJECT_UIDS["gateway.service"],
            "serviceAbsent": True,
            "sameOwnedUidOnly": True,
        },
        "absence": {
            "status": "all-six-names-absent-for-quiet-interval",
            "quietSeconds": value["httpBoundary"]["timeoutsSeconds"]["rollbackAbsenceQuiet"],
            "checks": 2,
        },
        "flux": copy.deepcopy(preflight["flux"]),
        "sharedSource": {
            "uid": preflight["source"]["uid"],
            "resourceVersion": preflight["source"]["resourceVersion"],
            "artifactRevision": preflight["source"]["artifactRevision"],
            "unchanged": True,
        },
        "clusterBinding": copy.deepcopy(preflight["clusterBinding"]["initial"]),
    }
    if deployment_present:
        final["deploymentDependents"] = recovery_dependents_absent()
    else:
        final["unboundDeploymentRuntime"] = {
            "deploymentNameAbsent": True,
            "dependents": recovery_dependents_absent(),
            "gatewayIsolationRetainedUntilProof": True,
        }
    return {
        "status": "complete",
        "bothKustomizationsSuspended": True,
        "flux": copy.deepcopy(preflight["flux"]),
        "deleted": deleted,
        "finalChecks": final,
        "preservation": recovery_preservation(value),
        "uncertainTarget": None,
        "errors": [],
        "finalizersRemovedByRunner": False,
    }

def valid_run29_recovery_rollback(value, preflight):
    order = [
        "gateway.ingress", "gateway.service", "gateway.service",
        "gateway.deployment", "gateway.serviceAccount",
        "workbenchIngress.networkPolicy", "gateway.networkPolicy",
    ]
    seen = {logical: 0 for logical in set(order)}
    deleted = []
    for logical in order:
        seen[logical] += 1
        target = preflight["targets"][logical]
        if logical == "gateway.service" and seen[logical] == 2:
            deleted.append({"logicalName": logical, "absent": True, "alreadyAbsent": True})
        elif target["state"] == "already-absent-receipt-owned":
            deleted.append({"logicalName": logical, "absent": True, "alreadyAbsent": True})
        else:
            deleted.append({
                "logicalName": logical,
                "uid": target["uid"],
                "deleteResourceVersion": str(int(target["resourceVersion"]) + 10),
                "absent": True,
                "foregroundPropagation": logical == "gateway.deployment",
                "finalizersRemovedByRunner": False,
            })
    final = {
        "clusterBindingBeforeRollback": copy.deepcopy(preflight["clusterBinding"]["initial"]),
        "exposureBreak": {
            "reason": "always-remove-owned-service-before-flux",
            "initialIngressAbsenceProved": True,
            "serviceUid": MODULE.RUN29_FAILED_ACTIVATION_OBJECT_UIDS["gateway.service"],
            "serviceAbsent": True,
            "unknownIngressUntouched": False,
        },
        "exposureBreakAfterFlux": {
            "serviceUid": MODULE.RUN29_FAILED_ACTIVATION_OBJECT_UIDS["gateway.service"],
            "serviceAbsent": True,
            "sameOwnedUidOnly": True,
        },
        "deploymentDependents": recovery_dependents_absent(),
        "absence": {
            "status": "all-six-names-absent-for-quiet-interval",
            "quietSeconds": value["httpBoundary"]["timeoutsSeconds"]["rollbackAbsenceQuiet"],
            "checks": 2,
        },
        "flux": copy.deepcopy(preflight["flux"]),
        "sharedSource": {
            "uid": preflight["source"]["uid"],
            "resourceVersion": preflight["source"]["resourceVersion"],
            "artifactRevision": preflight["source"]["artifactRevision"],
            "unchanged": True,
        },
        "clusterBinding": copy.deepcopy(preflight["clusterBinding"]["initial"]),
    }
    return {
        "status": "complete", "bothKustomizationsSuspended": True,
        "flux": copy.deepcopy(preflight["flux"]), "deleted": deleted,
        "finalChecks": final, "preservation": recovery_preservation(value),
        "uncertainTarget": None, "errors": [], "finalizersRemovedByRunner": False,
    }
def valid_database_status(value, *, pod_name="gateway-pod-a", pod_uid="pod-uid", before="10", after="11", image_id=None):
    """A complete private readiness receipt, including provenance and RBAC."""
    image = value["productPins"]["imageRepository"] + "@" + value["productPins"]["imageManifestDigest"]
    return MODULE.expected_database_status_v4(value) | {
        "probe": {
            "transport": "authenticated-kubernetes-pod-port-forward",
            "pod": pod_name,
            "loopbackOnly": True,
            "publicIngressUsed": False,
            "serviceProxyUsed": False,
            "redirectsAllowed": False,
            "path": "/status",
            "remotePort": MODULE.POLICY.GATEWAY_PORT,
            "podUid": pod_uid,
            "podImage": image,
            "podImageId": image_id or "docker-pullable://" + image,
            "podReadyAfter": True,
            "podResourceVersionBefore": before,
            "podResourceVersionAfter": after,
        },
        "rbac": {"getPods": True, "listPods": True, "createPodsPortforward": True},
    }
def valid_success_facts(value):
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0); nonce = "a" * 64
    sections = {name: {"ok": True} for name in MODULE.POLICY.trusted_live_facts_contract()["requiredSections"] if name != "protectedRevision"}
    facts = {"schemaVersion": MODULE.POLICY.TRUSTED_LIVE_FACTS_SCHEMA, "policySha256": MODULE.POLICY.activation_policy_sha256(value), "collectedAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "validUntil": (now + dt.timedelta(seconds=300)).strftime("%Y-%m-%dT%H:%M:%SZ"), "maxAgeSeconds": 300, "protectedRevision": REV, **sections}
    cluster = {
        "apiOrigin": value["clusterIdentity"]["apiOrigin"],
        "caCertificateSha256": value["clusterIdentity"]["caCertificateSha256"],
        "apiServerSpkiSha256": value["clusterIdentity"]["apiServerSpkiSha256"],
        "kubeSystemNamespaceUid": value["clusterIdentity"]["kubeSystemNamespaceUid"],
        "kubeSystemNamespaceResourceVersion": "10",
        "credentialsIncluded": False,
        "kubeconfigPathIncluded": False,
    }
    facts["clusterBinding"] = {name: copy.deepcopy(cluster) for name in ("initial", "beforeMutation", "beforeIngress", "beforeFluxUnsuspend", "beforeSuccess")}
    facts["publication"] = {"manifestDigest": value["productPins"]["imageManifestDigest"], "verificationLevel": "anonymous-registry-manifest-digest-only", "cryptographicPublicationProvenanceVerified": False}
    facts["database"] = valid_database_status(value)
    facts["operationReservation"] = {"operationNonce": nonce, "absencePreflight": {"status": "all-six-exact-target-names-absent", "targets": [{"absent": True}] * 6}}
    resources = MODULE.POLICY.expected_gateway_resources(value)
    desired_by_logical = {
        "gateway.networkPolicy": resources["networkPolicy"],
        "workbenchIngress.networkPolicy": MODULE.POLICY.expected_workbench_ingress_network_policy(include_web_presentation=True),
        "gateway.serviceAccount": resources["serviceAccount"],
        "gateway.service": resources["service"],
        "gateway.deployment": resources["deployment"],
        "gateway.ingress": resources["ingress"],
    }
    facts["objectCreateResults"] = []
    facts["semanticObjects"] = {}
    for index, (logical_name, desired) in enumerate(desired_by_logical.items(), start=1):
        uid = f"created-{index}-uid"
        facts["objectCreateResults"].append({
            "operationNonce": nonce,
            "temporaryNonceRemoved": True,
            "uid": uid,
            "target": {
                "apiVersion": desired["apiVersion"],
                "kind": desired["kind"],
                "name": desired["metadata"]["name"],
                "namespace": desired["metadata"]["namespace"],
            },
        })
        facts["semanticObjects"][logical_name] = {
            "uid": uid,
            "resourceVersion": str(100 + index),
            "semanticSha256": MODULE.POLICY.semantic_sha256(desired),
            "fluxTrackingState": "complete",
            "fluxTrackingLabels": MODULE.expected_flux_tracking_labels_v4(logical_name),
        }
    source = {"uid": "source-uid", "resourceVersion": "10", "artifactRevision": f"main@sha1:{REV}"}
    ownership = dormant_ownership()
    bootstrap_by_logical = {item["logicalName"]: item for item in ownership["objects"]}
    def ready_flux(owner, resource_version):
        desired = (
            MODULE.POLICY.gateway_flux_objects(suspended=False)
            if owner == "gateway"
            else MODULE.POLICY.workbench_ingress_flux_objects(suspended=False)
        )["kustomization"]
        return {
            "uid": bootstrap_by_logical[f"{owner}.kustomization"]["uid"],
            "resourceVersion": resource_version,
            "generation": 2,
            "observedGeneration": 2,
            "activeSpecSha256": MODULE.POLICY.canonical_sha256(desired["spec"]),
            "lastAppliedRevision": f"main@sha1:{REV}",
            "ready": True,
        }
    facts["fluxTransaction"] = {
        "bootstrapReceiptSha256": ownership["receiptSha256"],
        "bootstrapObjectIdentities": ownership["objects"],
        "casUnsuspended": {"gateway": "11", "workbenchIngress": "21"},
        "ready": {"gateway": ready_flux("gateway", "12"), "workbenchIngress": ready_flux("workbenchIngress", "22")},
        "finalReady": {"gateway": ready_flux("gateway", "13"), "workbenchIngress": ready_flux("workbenchIngress", "23")},
        "sourceBeforeCas": source,
        "sourceAfterReady": source | {"resourceVersion": "11"},
        "sourceBeforeSuccess": source | {"resourceVersion": "12"},
    }
    facts["preservation"] = {
        label: {
            "target": copy.deepcopy(descriptor["target"]),
            "beforeCanonicalSha256": sha(str(index)),
            "afterCanonicalSha256": sha(str(index)),
            "byteIdenticalCanonicalJson": True,
        }
        for index, (label, descriptor) in enumerate(value["preservation"].items(), start=1)
    }
    secret = {
        "status": "exact-keysets-present-without-reading-values",
        "secrets": {
            label: {
                "name": reference["name"],
                "namespace": reference["namespace"],
                "uid": f"{label}-secret-uid",
                "resourceVersion": str(30 + index),
                "keys": sorted(reference["keys"]),
                "valuesRead": False,
            }
            for index, (label, reference) in enumerate(value["runtime"]["secretReferences"].items())
        },
    }
    facts["secretMaterialization"] = {"beforeCreate": secret, "beforeIngress": copy.deepcopy(secret), "afterFlux": copy.deepcopy(secret)}
    facts["networkPolicyConflictScan"] = {"beforeCreate": {"ok": True}, "beforeIngress": {"ok": True}, "afterFlux": {"ok": True}}
    haproxy = {
        "uid": "haproxy-uid",
        "resourceVersion": "120",
        "generation": 2,
        "observedGeneration": 2,
        "desiredNumberScheduled": 3,
        "updatedNumberScheduled": 3,
        "numberAvailable": 3,
        "numberReady": 3,
        "rateLimit": value["httpBoundary"]["haproxyRateLimit"],
    }
    facts["haproxy"] = copy.deepcopy(haproxy)
    facts["routeMatrix"] = copy.deepcopy(value["httpBoundary"]["expectations"])
    deployment_uid = facts["semanticObjects"]["gateway.deployment"]["uid"]
    facts["postFluxApplication"] = {
        "preFluxDeploymentUid": deployment_uid,
        "sameDeploymentUid": True,
        "deployment": {
            "uid": deployment_uid,
            "resourceVersion": "121",
            "generation": 1,
            "observedGeneration": 1,
            "availableReplicas": value["runtime"]["replicas"],
        },
        "haproxy": copy.deepcopy(haproxy),
        "routeMatrix": copy.deepcopy(value["httpBoundary"]["expectations"]),
    }
    facts["rollback"] = {"status": "not-required", "finalizersRemovedByRunner": False}
    return facts
class Fake(MODULE.Runner):
    def __init__(self): self.calls = []
    def run(self, args, *, input_text=None, timeout=10):
        self.calls.append((args, input_text))
        if args and args[0] == "curl": return MODULE.Result(out="200" if "GET" in args else "405")
        if " create " in " " + " ".join(args) + " ":
            manifest = json.loads(input_text); manifest["metadata"] |= {"uid": manifest["kind"].lower() + "-uid", "resourceVersion": "10"}
            return MODULE.Result(out=json.dumps(manifest))
        return MODULE.Result()

class ExecutorTests(unittest.TestCase):
    def test_handover_preservation_digest_is_bound_before_and_after_every_mutation(self):
        value = ready_policy()
        snapshots = {}
        ownership = {"preservation": {}, "currentProtectedPreservation": {}}
        for index, (label, descriptor) in enumerate(value["preservation"].items(), start=1):
            checksum = sha(str(index))
            target = descriptor["target"]
            desired = {
                "apiVersion": target["apiVersion"],
                "kind": target["kind"],
                "metadata": {"name": target["name"], "namespace": target["namespace"]},
                "spec": {"fixture": label},
            }
            snapshots[label] = MODULE.PreservedV4(label, copy.deepcopy(target), copy.deepcopy(desired), checksum)
            ownership["preservation"][label] = {
                "target": copy.deepcopy(target),
                "canonicalSha256": checksum,
            }
            ownership["currentProtectedPreservation"][label] = {
                "target": copy.deepcopy(target),
                "desired": copy.deepcopy(desired),
                "desiredSemanticSha256": MODULE.POLICY.semantic_sha256(desired),
            }
        MODULE.require_current_preservation_binding_v4(snapshots, ownership, value)
        drifted = copy.deepcopy(ownership)
        drifted["preservation"]["webIngress"]["canonicalSha256"] = sha("f")
        with self.assertRaisesRegex(MODULE.ActivationError, "current preservation digest drift: webIngress"):
            MODULE.require_current_preservation_binding_v4(snapshots, drifted, value)

        # A caller can recompute the receipt's unkeyed checksum after replacing
        # only its full-object digest.  Even when that forged digest matches the
        # newly drifted live snapshot, the Git-derived desired object must win.
        resealed = copy.deepcopy(ownership)
        changed_snapshot = copy.deepcopy(snapshots)
        changed_live = copy.deepcopy(snapshots["webIngress"].value)
        changed_live["spec"]["unreviewedRoute"] = "/api/admin"
        changed_snapshot["webIngress"] = MODULE.PreservedV4(
            "webIngress",
            copy.deepcopy(value["preservation"]["webIngress"]["target"]),
            changed_live,
            MODULE.digest(changed_live),
        )
        resealed["preservation"]["webIngress"]["canonicalSha256"] = MODULE.digest(changed_live)
        with self.assertRaisesRegex(MODULE.ActivationError, "current protected webIngress semantic drift"):
            MODULE.require_current_preservation_binding_v4(changed_snapshot, resealed, value)

        source = inspect.getsource(MODULE.activate)
        self.assertLess(source.index("require_current_preservation_binding_v4"), source.index("mutation_started = True"))
        with (
            patch.object(MODULE, "_target_live", return_value={"fixture": "changed"}),
            patch.object(MODULE, "digest", return_value=sha("f")),
        ):
            with self.assertRaisesRegex(MODULE.ActivationError, "preserved webIngress changed"):
                MODULE.verify_preservation_v4(MODULE.Runner(), "fixture-kubeconfig", {"webIngress": snapshots["webIngress"]})

    def test_exact_historical_b790_secret_receipt_is_the_only_accepted_legacy_origin(self):
        value = ready_policy()
        receipt, raw = historical_secret_receipt()
        self.assertEqual(receipt["canonicalSha256"], MODULE.SECRET_RECEIPT_ORIGIN_CANONICAL_SHA256)
        self.assertEqual(MODULE.bytes_digest(raw), MODULE.SECRET_RECEIPT_ORIGIN_RAW_SHA256)
        actual = Path.home() / ".config/stadtstack/participant-live-receipts/participant-activation-20260828T191614Z-b790fa7-run1/participant-secret-materialization.json"
        if actual.is_file():
            # The local live evidence is value-free.  Equality proves this
            # fixture is the byte-exact artifact used by the continuation.
            self.assertEqual(actual.read_bytes(), raw)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            path.write_bytes(raw)
            os.chmod(path, 0o600)
            fd = os.open(path, os.O_RDONLY)
            try:
                ownership = MODULE.bind_secret_materialization_receipt_v4(value, REV, fd)
            finally:
                os.close(fd)
        self.assertEqual(ownership["secretRecords"], {
            label: {
                "target": copy.deepcopy(record["target"]),
                "uid": record["uid"],
                "resourceVersion": record["resourceVersion"],
                "keySet": copy.deepcopy(record["keySet"]),
                "valuesRead": False,
            }
            for label, record in MODULE.SECRET_RECEIPT_ORIGIN_SECRET_RECORDS.items()
        })
        self.assertEqual(
            ownership["receiptProvenance"],
            {
                "mode": "historical-b790-value-free-secret-materialization",
                "protectedRevision": MODULE.SECRET_RECEIPT_ORIGIN_REVISION,
                "rawSha256": MODULE.SECRET_RECEIPT_ORIGIN_RAW_SHA256,
                "canonicalSha256": MODULE.SECRET_RECEIPT_ORIGIN_CANONICAL_SHA256,
            },
        )

    def test_historical_secret_receipt_rejects_raw_and_all_closed_semantic_drift(self):
        value = ready_policy()
        base, raw = historical_secret_receipt()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            path.write_bytes(raw[:-1])
            os.chmod(path, 0o600)
            fd = os.open(path, os.O_RDONLY)
            try:
                with self.assertRaisesRegex(MODULE.ActivationError, "raw checksum"):
                    MODULE.bind_secret_materialization_receipt_v4(value, REV, fd)
            finally:
                os.close(fd)

        semantic_cases = []
        changed = copy.deepcopy(base); changed["unexpected"] = False
        semantic_cases.append((changed, "field closure"))
        changed = copy.deepcopy(base); changed["canonicalSha256"] = sha("8")
        semantic_cases.append((changed, "canonical checksum"))
        for field, replacement in (
            ("schemaVersion", "wrong"),
            ("status", "wrong"),
            ("protectedRevision", "0" * 40),
            ("activationPolicySha256", sha("7")),
            ("protectedRunnerFileSha256", {}),
            ("createOrder", ["runtime", "config"]),
            ("inputTransport", "wrong"),
            ("valuesInReceipt", True),
            ("civicAuthorityEffects", True),
        ):
            changed = copy.deepcopy(base); changed[field] = replacement
            semantic_cases.append((changed, "origin field"))
        for label, field, replacement in (
            ("config", "uid", "00000000-0000-0000-0000-000000000000"),
            ("config", "resourceVersion", "15906164"),
            ("config", "keySet", ["wrong"]),
            ("runtime", "ownershipNonce", "0" * 64),
            ("runtime", "valuesRead", True),
            ("runtime", "target", {}),
        ):
            changed = copy.deepcopy(base); changed["secrets"][label][field] = replacement
            semantic_cases.append((changed, "origin record"))
        changed = copy.deepcopy(base); changed["secrets"]["extra"] = copy.deepcopy(changed["secrets"]["config"])
        semantic_cases.append((changed, "origin record"))
        for candidate, expected_error in semantic_cases:
            with self.subTest(expected_error=expected_error):
                with self.assertRaisesRegex(MODULE.ActivationError, expected_error):
                    MODULE.bind_historical_secret_materialization_fields_v4(value, candidate)

    def test_historical_secret_receipt_requires_current_target_and_keyset_compatibility(self):
        receipt, raw = historical_secret_receipt()
        for label, field, replacement in (
            ("config", "name", "different-config"),
            ("config", "namespace", "different-namespace"),
            ("runtime", "keys", ["different-key"]),
        ):
            changed = ready_policy()
            changed["runtime"]["secretReferences"][label][field] = replacement
            with self.subTest(label=label, field=field):
                with self.assertRaisesRegex(MODULE.ActivationError, "current target/keyset compatibility"):
                    MODULE.bind_historical_secret_materialization_receipt_v4(changed, receipt, raw)

    def test_historical_secret_continuation_requires_exact_resource_versions(self):
        value = ready_policy()
        records = {}
        live = {}
        for label, reference in value["runtime"]["secretReferences"].items():
            resource_version = MODULE.SECRET_RECEIPT_ORIGIN_RESOURCE_VERSIONS.get(label, "15909999")
            if label in MODULE.SECRET_RECEIPT_ORIGIN_RESOURCE_VERSIONS:
                records[label] = {
                    "target": {
                        "apiVersion": "v1",
                        "kind": "Secret",
                        "namespace": reference["namespace"],
                        "name": reference["name"],
                    },
                    "uid": f"{label}-uid",
                    "resourceVersion": resource_version,
                    "keySet": sorted(reference["keys"]),
                    "valuesRead": False,
                }
            live[label] = {
                "name": reference["name"],
                "namespace": reference["namespace"],
                "uid": f"{label}-uid",
                "resourceVersion": resource_version,
                "keys": sorted(reference["keys"]),
                "valuesRead": False,
            }
        ownership = {
            "status": "materialized",
            "secretRecords": records,
            "civicAuthorityEffects": False,
            "receiptProvenance": {"mode": "historical-b790-value-free-secret-materialization"},
        }
        current = {"status": "exact-keysets-present-without-reading-values", "secrets": live}
        MODULE.require_secret_materialization_binding_v4(current, ownership, value)
        changed = copy.deepcopy(current)
        changed["secrets"]["config"]["resourceVersion"] = str(int(changed["secrets"]["config"]["resourceVersion"]) + 1)
        with self.assertRaisesRegex(MODULE.ActivationError, "identity/keyset drift"):
            MODULE.require_secret_materialization_binding_v4(changed, ownership, value)
        current_ownership = copy.deepcopy(ownership)
        current_ownership["receiptProvenance"] = {"mode": "current-protected-revision"}
        MODULE.require_secret_materialization_binding_v4(current, current_ownership, value)
        with self.assertRaisesRegex(MODULE.ActivationError, "identity/keyset drift"):
            MODULE.require_secret_materialization_binding_v4(changed, current_ownership, value)

    def test_fresh_bootstrap_reuse_binds_historical_secret_identity_before_mutation(self):
        value = ready_policy()
        current = {
            "status": "exact-keysets-present-without-reading-values",
            "secrets": {"fixture": {}},
        }
        ownership = {
            "status": "materialized",
            "secretRecords": {},
            "civicAuthorityEffects": False,
            "receiptProvenance": {"mode": "historical-b790-value-free-secret-materialization"},
        }
        snapshot = Mock(path=Path("/snapshot")); snapshot.close = Mock()
        cluster = {
            "apiOrigin": value["clusterIdentity"]["apiOrigin"],
            "caCertificateSha256": value["clusterIdentity"]["caCertificateSha256"],
            "apiServerSpkiSha256": value["clusterIdentity"]["apiServerSpkiSha256"],
            "kubeSystemNamespaceUid": value["clusterIdentity"]["kubeSystemNamespaceUid"],
        }
        secret_binding = patch.object(MODULE, "require_secret_materialization_binding_v4")
        patches = (
            patch.object(MODULE.POLICY, "assert_activation_ready", return_value=value),
            patch.object(MODULE, "render_v4", return_value={}),
            patch.object(MODULE, "snapshot_kubeconfig_v4", return_value=snapshot),
            patch.object(MODULE, "cluster_binding_v4", return_value=cluster),
            patch.object(MODULE, "anonymous_publication_v4", return_value={}),
            patch.object(MODULE, "endpoint_facts_v4", return_value={}),
            patch.object(MODULE, "preservation_v4", return_value={}),
            patch.object(MODULE, "flux_preflight_v4", return_value={}),
            patch.object(MODULE, "exact_absence_preflight_v4", return_value={}),
            patch.object(MODULE, "secret_materialization_v4", return_value=current),
            secret_binding,
            patch.object(MODULE, "require_tracer_activation_binding_v4"),
            patch.object(MODULE, "policy_union_v4", side_effect=MODULE.ActivationError("pre-mutation stop")),
        )
        sink = Mock()
        with tempfile.TemporaryDirectory() as directory:
            kube = Path(directory) / "kubeconfig"; kube.write_text("fixture")
            with contextlib.ExitStack() as stack:
                entered = [stack.enter_context(item) for item in patches]
                with self.assertRaisesRegex(MODULE.ActivationError, "pre-mutation stop"):
                    MODULE.activate(
                        value,
                        REV,
                        str(kube),
                        Fake(),
                        True,
                        sink,
                        {"runner": sha()},
                        dormant_ownership(),
                        ownership,
                        {},
                    )
        entered[patches.index(secret_binding)].assert_called_once_with(current, ownership, value)
        snapshot.close.assert_called_once()

    def test_fresh_bootstrap_secret_reuse_is_accepted_by_live_cli(self):
        value = ready_policy()
        bootstrap_module = Mock()
        bootstrap_value = {"status": "dormant-ready"}
        bootstrap_module.load_receipt_fd.return_value = bootstrap_value
        dormant = {"bound": "fresh-bootstrap"}
        secret = {"bound": "historical-secret"}
        tracer = {"bound": "tracer"}
        result = {"status": "activated", "civicAuthorityEffects": False}
        sink = Mock()
        order = []

        bind_tracer = Mock(side_effect=lambda *_: order.append("tracer") or tracer)
        bind_bootstrap = Mock(side_effect=lambda *_: order.append("bootstrap") or dormant)
        bind_secret = Mock(side_effect=lambda *_: order.append("secret") or secret)
        activate = Mock(side_effect=lambda *_: order.append("activate") or result)

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(MODULE, "sys", Mock(flags=Mock(isolated=1, safe_path=True))))
            stack.enter_context(patch.object(MODULE, "revision", return_value=REV))
            stack.enter_context(patch.object(MODULE, "trusted_git_v4", return_value=Mock(stdout=REV)))
            stack.enter_context(patch.object(MODULE, "protected_checkout", return_value={"runner": sha()}))
            stack.enter_context(patch.object(MODULE, "git_blob", return_value=b"verified"))
            stack.enter_context(patch.object(MODULE, "compile_verified_policy_module_v4", return_value=MODULE.POLICY))
            stack.enter_context(patch.object(MODULE, "compile_verified_bootstrap_module_v4", return_value=bootstrap_module))
            stack.enter_context(patch.object(MODULE, "bind_verified_policy_identity_v4"))
            stack.enter_context(patch.object(MODULE, "policy", return_value=value))
            stack.enter_context(patch.object(MODULE.POLICY, "assert_activation_ready"))
            stack.enter_context(patch.object(MODULE, "bind_tracer_activation_receipt_v4", bind_tracer))
            stack.enter_context(patch.object(MODULE, "bind_flux_bootstrap_receipt_value_v4", bind_bootstrap))
            stack.enter_context(patch.object(MODULE, "bind_secret_materialization_receipt_v4", bind_secret))
            stack.enter_context(patch.object(MODULE.ReceiptSink, "reserve", return_value=sink))
            stack.enter_context(patch.object(MODULE, "activate", activate))
            stack.enter_context(patch("builtins.print"))
            return_code = MODULE.main([
                "--live",
                "--expected-protected-revision", REV,
                "--kubeconfig", "/private/kubeconfig",
                "--flux-bootstrap-receipt-fd", "41",
                "--secret-materialization-receipt-fd", "42",
                "--tracer-data-plane-activation-receipt-fd", "43",
                "--receipt", "/private/activation.json",
            ])

        self.assertEqual(return_code, 0)
        self.assertEqual(order, ["tracer", "bootstrap", "secret", "activate"])
        bootstrap_module.load_receipt_fd.assert_called_once_with(41)
        bind_secret.assert_called_once_with(value, REV, 42)
        activate.assert_called_once_with(
            value,
            REV,
            "/private/kubeconfig",
            activate.call_args.args[3],
            True,
            sink,
            {"runner": sha()},
            dormant,
            secret,
            tracer,
        )

    def test_handover_prebound_closure_disables_git_blob_fallback(self):
        raw = b"protected-blob-fixture"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "blob"
            path.write_bytes(raw)
            path.chmod(0o600)
            fd = os.open(path, os.O_RDONLY)
            try:
                descriptors = [
                    json.dumps({
                        "revision": revision,
                        "path": logical_path,
                        "fd": fd,
                        "size": len(raw),
                        "sha256": MODULE.bytes_digest(raw),
                    })
                    for revision, logical_path in sorted(MODULE.required_handover_prebound_keys_v4(REV))
                ]
                blobs = MODULE.parse_prebound_git_blob_descriptors_v4(descriptors, REV)
            finally:
                os.close(fd)
        self.assertEqual(set(blobs), MODULE.required_handover_prebound_keys_v4(REV))
        self.assertIn((REV, MODULE.SECRET_MATERIALIZER_PATH), blobs)
        self.assertIn((MODULE.SECRET_RECEIPT_ORIGIN_REVISION, MODULE.SECRET_MATERIALIZER_PATH), blobs)
        tracer_closure = {(REV, path) for path in MODULE.TRACER_RECEIPT_PROTECTED_PATHS}
        self.assertTrue(tracer_closure <= set(blobs))
        for logical_path in MODULE.HANDOVER_CURRENT_PRESERVATION_PATHS:
            self.assertIn((REV, logical_path), blobs)
            self.assertNotIn((MODULE.HANDOVER_ARCHIVE_REVISION, logical_path), blobs)
        self.assertNotIn((REV, MODULE.SECRET_MATERIALIZER_PATH), MODULE.required_nested_handover_prebound_keys_v4(REV))
        self.assertNotIn((MODULE.SECRET_RECEIPT_ORIGIN_REVISION, MODULE.SECRET_MATERIALIZER_PATH), MODULE.required_nested_handover_prebound_keys_v4(REV))
        nested_expected = MODULE.required_nested_handover_prebound_keys_v4(REV)
        self.assertEqual(nested_expected, HANDOVER_RUNNER._required_prebound_keys(REV))
        self.assertEqual(
            tracer_closure & nested_expected,
            {
                (REV, "policy/repository-contract.json"),
                (REV, MODULE.POLICY_PATH),
                (REV, "scripts/activate-staging-participant-gateway.py"),
                (REV, MODULE.POLICY_MODULE_PATH),
            },
        )
        self.assertEqual(
            set(blobs) - nested_expected,
            (tracer_closure - nested_expected)
            | {
                (REV, MODULE.SECRET_MATERIALIZER_PATH),
                (MODULE.SECRET_RECEIPT_ORIGIN_REVISION, MODULE.SECRET_MATERIALIZER_PATH),
            },
        )
        handover_module = Mock()
        handover_module.bind_handover_receipt.return_value = {
            "protectedRevision": REV,
            "activationPolicySha256": MODULE.POLICY.activation_policy_sha256(ready_policy()),
            "civicAuthorityEffects": False,
        }

        def build_context(revision, archived_raw, nested_blobs):
            self.assertEqual(revision, REV)
            self.assertEqual(archived_raw, b"archived")
            self.assertEqual(set(nested_blobs), nested_expected)
            self.assertNotIn((REV, MODULE.SECRET_MATERIALIZER_PATH), nested_blobs)
            self.assertNotIn((MODULE.SECRET_RECEIPT_ORIGIN_REVISION, MODULE.SECRET_MATERIALIZER_PATH), nested_blobs)
            return {"policy": ready_policy(), "binding": {}, "handoverModule": handover_module}

        runner = Mock()
        runner.owned_receipt_raw.side_effect = [b"archived", b"handover"]
        runner.build_context.side_effect = build_context
        runner.json_object.return_value = {"status": "handover-ready"}
        with patch.object(MODULE, "_PREBOUND_GIT_BLOBS", blobs), patch.object(
            MODULE, "trusted_git_v4", side_effect=AssertionError("Git fallback forbidden")
        ) as git, patch.object(MODULE, "compile_verified_handover_runner_v4", return_value=runner):
            for key, expected in blobs.items():
                self.assertEqual(MODULE.git_blob(*key), expected)
            with self.assertRaisesRegex(MODULE.ActivationError, "was not prebound"):
                MODULE.git_blob(REV, "outside/exact/closure")
            ownership = MODULE.bind_handover_receipt_pair_v4(ready_policy(), REV, 11, 12, blobs)
            self.assertEqual(ownership["protectedRevision"], REV)
        git.assert_not_called()
        runner.build_context.assert_called_once()

    def test_missing_fixed_policy_blocks_before_any_runner_call(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(MODULE, "ROOT", Path(directory)):
            runner = Fake()
            with self.assertRaisesRegex(MODULE.ActivationError, "policy descriptor is not wired"):
                MODULE.policy(REV)
            self.assertEqual(runner.calls, [])
    def test_revision_and_policy_schema_are_closed(self):
        with self.assertRaisesRegex(MODULE.ActivationError, "lowercase"):
            MODULE.revision("A" * 40)
        value = policy(); value["httpBoundary"]["host"] = "example.test"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "policy").mkdir(); path = root / MODULE.POLICY_PATH; path.write_text(json.dumps(value))
            with patch.object(MODULE, "ROOT", root), patch.object(MODULE, "git_blob", return_value=path.read_bytes()):
                with self.assertRaisesRegex(MODULE.ActivationError, "policy drift"):
                    MODULE.policy(REV)

    def test_verified_policy_identity_must_match_runner_constants(self):
        MODULE.bind_verified_policy_identity_v4(MODULE.POLICY)
        drifted = Mock(**{
            "GATEWAY_NAMESPACE": MODULE.POLICY.GATEWAY_NAMESPACE,
            "FLUX_NAMESPACE": MODULE.POLICY.FLUX_NAMESPACE,
            "GATEWAY_NAME": "attacker-selected-gateway",
            "FLUX_SOURCE_NAME": MODULE.POLICY.FLUX_SOURCE_NAME,
            "WORKBENCH_NAMESPACE": MODULE.POLICY.WORKBENCH_NAMESPACE,
            "WORKBENCH_INGRESS_POLICY_NAME": MODULE.POLICY.WORKBENCH_INGRESS_POLICY_NAME,
            "POLICY_PATH": MODULE.POLICY.POLICY_PATH,
        })
        with self.assertRaisesRegex(MODULE.ActivationError, "runner/policy identity drift"):
            MODULE.bind_verified_policy_identity_v4(drifted)
    def test_inert_dry_run_reports_every_blocker_without_runner(self):
        value = policy(); hashes = {"runner": sha()}
        result = MODULE.dry_run_plan(value, REV, hashes)
        self.assertEqual(result["status"], "blocked-policy-incomplete")
        self.assertFalse(result["activationReady"])
        self.assertEqual(result["blockers"], list(MODULE.POLICY.activation_blockers(value)))
        self.assertFalse(result["kubernetesContacted"])
        self.assertEqual(result["protectedRunnerFileSha256"], hashes)
    def test_no_evidence_command_or_allowlist_surface_exists(self):
        source = Path(MODULE.__file__).read_text()
        self.assertNotIn("liveSemanticProjection", source)
        self.assertNotIn("preexistingSelectorAllowlist", source)
        self.assertNotIn("--evidence", source)
        self.assertNotIn("--render-root", source)
        self.assertNotIn("--gateway-url", source)

    def test_command_requires_isolated_mode_before_local_imports_and_policy_compilation(self):
        source = Path(MODULE.__file__).read_text()
        self.assertLess(source.index("runner_hashes = protected_checkout(rev)"), source.index("POLICY = compile_verified_policy_module_v4"))
        with tempfile.TemporaryDirectory() as directory:
            scripts = Path(directory) / "scripts"; scripts.mkdir()
            runner = scripts / "activate-staging-participant-gateway.py"; runner.write_text(source)
            marker = Path(directory) / "shadow-executed"
            (scripts / "secrets.py").write_text(f"from pathlib import Path\nPath({str(marker)!r}).write_text('unsafe')\n")
            args = [str(runner), "--dry-run", "--expected-protected-revision", REV, "--receipt", str(Path(directory) / "receipt.json")]
            unsafe = subprocess.run([sys.executable, *args], text=True, capture_output=True, check=False)
            self.assertEqual(unsafe.returncode, 2); self.assertIn("python3 -I", unsafe.stderr); self.assertFalse(marker.exists())
            isolated = subprocess.run([sys.executable, "-I", *args], text=True, capture_output=True, check=False)
            self.assertEqual(isolated.returncode, 2); self.assertIn("protected repository checkout", isolated.stderr); self.assertFalse(marker.exists())
    def test_empty_and_matching_selectors_are_rejected(self):
        self.assertTrue(MODULE._selector_matches_v4({}, MODULE.POLICY.GATEWAY_LABELS))
        self.assertTrue(MODULE._selector_matches_v4({"matchLabels": {"app.kubernetes.io/name": MODULE.NAME}}, MODULE.POLICY.GATEWAY_LABELS))
        self.assertTrue(MODULE._selector_matches_v4({"matchLabels": {"any:app.kubernetes.io/name": MODULE.NAME}}, MODULE.POLICY.GATEWAY_LABELS))
        self.assertFalse(MODULE._selector_matches_v4({"matchLabels": {"app.kubernetes.io/name": "other"}}, MODULE.POLICY.GATEWAY_LABELS))
        self.assertTrue(MODULE._selector_could_match_with_additional_labels_v4({"matchLabels": {"pod-template-hash": "future"}}, MODULE.POLICY.GATEWAY_LABELS))
        self.assertTrue(MODULE._selector_could_match_with_additional_labels_v4({"matchLabels": {"k8s:io.cilium.k8s.policy.serviceaccount": MODULE.NAME}}, MODULE.POLICY.GATEWAY_LABELS))
        self.assertFalse(MODULE._selector_could_match_with_additional_labels_v4({"matchLabels": {"app.kubernetes.io/name": "other"}}, MODULE.POLICY.GATEWAY_LABELS))
    def test_live_gate_fails_before_runner_or_kubeconfig_validation(self):
        value = policy()
        with self.assertRaisesRegex(MODULE.POLICY.PolicyError, "activation blocked"):
            MODULE.POLICY.assert_activation_ready(value)
        self.assertFalse(value["activationReady"])

    def test_exact_approved_successor_can_pass_the_future_gate_without_runner_code_changes(self):
        value = ready_policy()
        self.assertEqual(MODULE.POLICY.validate_activation_policy(value), value)
        self.assertEqual(MODULE.POLICY.assert_activation_ready(value), value)
        self.assertEqual(MODULE.POLICY.activation_blockers(value), ())

    def test_tracer_receipt_binds_current_revision_three_secrets_twelve_objects_and_two_services(self):
        value = ready_policy()
        receipt = tracer_activation_receipt(value)
        self.assertEqual(len(receipt["secretRecords"]), 3)
        self.assertEqual(len(receipt["objectRecords"]), 12)
        self.assertEqual(set(receipt["serviceBindings"]), {"postgres", "postgrest"})

        def bind(candidate):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "tracer-receipt.json"
                path.write_text(json.dumps(candidate), encoding="utf-8")
                path.chmod(0o600)
                fd = os.open(path, os.O_RDONLY)
                try:
                    with patch.object(MODULE, "git_blob", side_effect=lambda revision, relative: relative.encode()):
                        return MODULE.bind_tracer_activation_receipt_v4(value, REV, fd)
                finally:
                    os.close(fd)

        ownership = bind(receipt)
        self.assertEqual(ownership["originProtectedRevision"], REV)
        self.assertEqual(
            ownership["participantPostgrestSecret"],
            receipt["secretRecords"]["participantPostgrest"],
        )
        self.assertEqual(ownership["postgrestService"], receipt["serviceBindings"]["postgrest"])
        self.assertFalse(ownership["civicAuthorityEffects"])

        drift_cases = {
            "revision": lambda candidate: candidate.update(protectedRevision="f" * 40),
            "secret-set": lambda candidate: candidate["secretRecords"].pop("webFeed"),
            "object-set": lambda candidate: candidate["objectRecords"].pop("application.postgresService"),
            "service-set": lambda candidate: candidate["serviceBindings"].pop("postgres"),
        }
        for label, mutate in drift_cases.items():
            with self.subTest(label=label):
                changed = copy.deepcopy(receipt)
                mutate(changed)
                with self.assertRaises(MODULE.ActivationError):
                    bind(changed)

    def test_exact_run19_receipt_binds_only_across_the_closed_eighteen_hop_lineage(self):
        value = ready_policy()
        receipt = tracer_activation_receipt(value)
        receipt["protectedRevision"] = MODULE.TRACER_RECEIPT_ORIGIN_REVISION
        receipt["sharedFluxSource"]["revision"] = f"main@sha1:{MODULE.TRACER_RECEIPT_ORIGIN_REVISION}"
        receipt["flux"]["lastAppliedRevision"] = f"main@sha1:{MODULE.TRACER_RECEIPT_ORIGIN_REVISION}"
        current_hashes = {
            path: MODULE.bytes_digest(path.encode())
            for path in MODULE.TRACER_RECEIPT_PROTECTED_PATHS
        }
        origin_runner_hash = sha("9")
        receipt["protectedFileSha256"] = copy.deepcopy(current_hashes)
        receipt["protectedFileSha256"]["scripts/activate-staging-participant-gateway.py"] = origin_runner_hash
        receipt["protectedFileSha256"][MODULE.POLICY_MODULE_PATH] = sha("8")
        receipt["protectedFileSha256"][MODULE.POLICY_PATH] = sha("7")

        def bind(candidate, *, raw_sha=None, transitions=None):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "tracer-receipt.json"
                path.write_text(json.dumps(candidate), encoding="utf-8")
                path.chmod(0o600)
                raw = path.read_bytes()
                fd = os.open(path, os.O_RDONLY)
                try:
                    transition_values = transitions or [
                        set(MODULE.TRACER_RECEIPT_ORIGIN_TO_INTERMEDIATE_FILES),
                        set(MODULE.TRACER_RECEIPT_INTERMEDIATE_TO_SECOND_SUCCESSOR_FILES),
                        set(MODULE.TRACER_RECEIPT_SECOND_TO_THIRD_SUCCESSOR_FILES),
                        set(MODULE.TRACER_RECEIPT_THIRD_TO_FOURTH_SUCCESSOR_FILES),
                        set(MODULE.TRACER_RECEIPT_FOURTH_TO_FIFTH_SUCCESSOR_FILES),
                        set(MODULE.TRACER_RECEIPT_FIFTH_TO_SIXTH_SUCCESSOR_FILES),
                        set(MODULE.TRACER_RECEIPT_SIXTH_TO_SEVENTH_SUCCESSOR_FILES),
                        set(MODULE.TRACER_RECEIPT_SEVENTH_TO_EIGHTH_SUCCESSOR_FILES),
                        set(MODULE.TRACER_RECEIPT_EIGHTH_TO_NINTH_SUCCESSOR_FILES),
                        set(MODULE.TRACER_RECEIPT_NINTH_TO_TENTH_SUCCESSOR_FILES),
                        set(MODULE.TRACER_RECEIPT_TENTH_TO_ELEVENTH_SUCCESSOR_FILES),
                        set(MODULE.TRACER_RECEIPT_ELEVENTH_TO_TWELFTH_SUCCESSOR_FILES),
                        set(MODULE.TRACER_RECEIPT_TWELFTH_TO_THIRTEENTH_SUCCESSOR_FILES),
                        set(MODULE.TRACER_RECEIPT_THIRTEENTH_TO_FOURTEENTH_SUCCESSOR_FILES),
                        set(MODULE.TRACER_RECEIPT_FOURTEENTH_TO_FIFTEENTH_SUCCESSOR_FILES),
                        set(MODULE.TRACER_RECEIPT_FIFTEENTH_TO_SIXTEENTH_SUCCESSOR_FILES),
                        set(MODULE.TRACER_RECEIPT_SIXTEENTH_TO_SEVENTEENTH_SUCCESSOR_FILES),
                        set(MODULE.TRACER_RECEIPT_SEVENTEENTH_SUCCESSOR_TO_ACCEPTOR_FILES),
                    ]
                    with patch.object(MODULE, "git_blob", side_effect=lambda revision, relative: relative.encode()), patch.object(
                        MODULE, "exact_revision_transition_files_v4", side_effect=transition_values,
                    ), patch.object(
                        MODULE, "TRACER_RECEIPT_ORIGIN_RAW_SHA256",
                        raw_sha or MODULE.bytes_digest(raw),
                    ), patch.object(
                        MODULE, "TRACER_RECEIPT_ORIGIN_ACTIVATION_RUNNER_SHA256", origin_runner_hash,
                    ):
                        return MODULE.bind_tracer_activation_receipt_v4(value, REV, fd)
                finally:
                    os.close(fd)

        ownership = bind(receipt)
        self.assertEqual(
            ownership["receiptProvenance"],
            {
                "mode": "exact-run19-eighteen-hop-unchanged-tracer-plane",
                "originProtectedRevision": MODULE.TRACER_RECEIPT_ORIGIN_REVISION,
                "acceptedByProtectedRevision": REV,
                "allowedAppliedRevisions": [
                    MODULE.TRACER_RECEIPT_ORIGIN_REVISION,
                    MODULE.TRACER_RECEIPT_INTERMEDIATE_REVISION,
                    MODULE.TRACER_RECEIPT_SECOND_SUCCESSOR_REVISION,
                    MODULE.TRACER_RECEIPT_THIRD_SUCCESSOR_REVISION,
                    MODULE.TRACER_RECEIPT_FOURTH_SUCCESSOR_REVISION,
                    MODULE.TRACER_RECEIPT_FIFTH_SUCCESSOR_REVISION,
                    MODULE.TRACER_RECEIPT_SIXTH_SUCCESSOR_REVISION,
                    MODULE.TRACER_RECEIPT_SEVENTH_SUCCESSOR_REVISION,
                    MODULE.TRACER_RECEIPT_EIGHTH_SUCCESSOR_REVISION,
                    MODULE.TRACER_RECEIPT_NINTH_SUCCESSOR_REVISION,
                    MODULE.TRACER_RECEIPT_TENTH_SUCCESSOR_REVISION,
                    MODULE.TRACER_RECEIPT_ELEVENTH_SUCCESSOR_REVISION,
                    MODULE.TRACER_RECEIPT_TWELFTH_SUCCESSOR_REVISION,
                    MODULE.TRACER_RECEIPT_THIRTEENTH_SUCCESSOR_REVISION,
                    MODULE.TRACER_RECEIPT_FOURTEENTH_SUCCESSOR_REVISION,
                    MODULE.TRACER_RECEIPT_FIFTEENTH_SUCCESSOR_REVISION,
                    MODULE.TRACER_RECEIPT_SIXTEENTH_SUCCESSOR_REVISION,
                    MODULE.TRACER_RECEIPT_SEVENTEENTH_SUCCESSOR_REVISION,
                    REV,
                ],
            },
        )
        self.assertEqual(
            ownership["tracerFluxKustomization"]["uid"],
            receipt["objectRecords"]["flux.kustomization"]["uid"],
        )

        with self.assertRaisesRegex(MODULE.ActivationError, "exact approved run19"):
            bind(receipt, raw_sha=sha("0"))
        transition_sets = [
            set(MODULE.TRACER_RECEIPT_ORIGIN_TO_INTERMEDIATE_FILES),
            set(MODULE.TRACER_RECEIPT_INTERMEDIATE_TO_SECOND_SUCCESSOR_FILES),
            set(MODULE.TRACER_RECEIPT_SECOND_TO_THIRD_SUCCESSOR_FILES),
            set(MODULE.TRACER_RECEIPT_THIRD_TO_FOURTH_SUCCESSOR_FILES),
            set(MODULE.TRACER_RECEIPT_FOURTH_TO_FIFTH_SUCCESSOR_FILES),
            set(MODULE.TRACER_RECEIPT_FIFTH_TO_SIXTH_SUCCESSOR_FILES),
            set(MODULE.TRACER_RECEIPT_SIXTH_TO_SEVENTH_SUCCESSOR_FILES),
            set(MODULE.TRACER_RECEIPT_SEVENTH_TO_EIGHTH_SUCCESSOR_FILES),
            set(MODULE.TRACER_RECEIPT_EIGHTH_TO_NINTH_SUCCESSOR_FILES),
            set(MODULE.TRACER_RECEIPT_NINTH_TO_TENTH_SUCCESSOR_FILES),
            set(MODULE.TRACER_RECEIPT_TENTH_TO_ELEVENTH_SUCCESSOR_FILES),
            set(MODULE.TRACER_RECEIPT_ELEVENTH_TO_TWELFTH_SUCCESSOR_FILES),
            set(MODULE.TRACER_RECEIPT_TWELFTH_TO_THIRTEENTH_SUCCESSOR_FILES),
            set(MODULE.TRACER_RECEIPT_THIRTEENTH_TO_FOURTEENTH_SUCCESSOR_FILES),
            set(MODULE.TRACER_RECEIPT_FOURTEENTH_TO_FIFTEENTH_SUCCESSOR_FILES),
            set(MODULE.TRACER_RECEIPT_FIFTEENTH_TO_SIXTEENTH_SUCCESSOR_FILES),
            set(MODULE.TRACER_RECEIPT_SIXTEENTH_TO_SEVENTEENTH_SUCCESSOR_FILES),
            set(MODULE.TRACER_RECEIPT_SEVENTEENTH_SUCCESSOR_TO_ACCEPTOR_FILES),
        ]
        transition_messages = (
            "origin-to-intermediate file set drift",
            "intermediate-to-second-successor file set drift",
            "second-to-third-successor file set drift",
            "third-to-fourth-successor file set drift",
            "fourth-to-fifth-successor file set drift",
            "fifth-to-sixth-successor file set drift",
            "sixth-to-seventh-successor file set drift",
            "seventh-to-eighth-successor file set drift",
            "eighth-to-ninth-successor file set drift",
            "ninth-to-tenth-successor file set drift",
            "tenth-to-eleventh-successor file set drift",
            "eleventh-to-twelfth-successor file set drift",
            "twelfth-to-thirteenth-successor file set drift",
            "thirteenth-to-fourteenth-successor file set drift",
            "fourteenth-to-fifteenth-successor file set drift",
            "fifteenth-to-sixteenth-successor file set drift",
            "sixteenth-to-seventeenth-successor file set drift",
            "seventeenth-successor-to-acceptor file set drift",
        )
        for index, message in enumerate(transition_messages):
            for variant in (
                transition_sets[index] | {"README.md"},
                transition_sets[index] - {next(iter(transition_sets[index]))},
            ):
                changed = copy.deepcopy(transition_sets)
                changed[index] = variant
                with self.subTest(index=index, variant=variant), self.assertRaisesRegex(
                    MODULE.ActivationError, message
                ):
                    bind(receipt, transitions=changed)

        self.assertEqual(
            MODULE.TRACER_RECEIPT_SECOND_SUCCESSOR_REVISION,
            "f41bb1ac2ec27c6332a3b5614e65516349f239b0",
        )
        self.assertEqual(
            MODULE.TRACER_RECEIPT_THIRD_SUCCESSOR_REVISION,
            "89cc247c412374205d83433dcc5f774f8c705b1b",
        )
        self.assertEqual(
            MODULE.TRACER_RECEIPT_FOURTH_SUCCESSOR_REVISION,
            "93d9e5bb87acb18887250316fb0b7a1bdf4c7cfa",
        )
        self.assertEqual(
            MODULE.TRACER_RECEIPT_FIFTH_SUCCESSOR_REVISION,
            "7aa2db7f174742555ec0374725d2c80ee0350e8a",
        )
        self.assertEqual(
            MODULE.TRACER_RECEIPT_SIXTH_SUCCESSOR_REVISION,
            "720e058a61c185c8c64e2679e14d5dc8eea96ba0",
        )
        self.assertEqual(
            MODULE.TRACER_RECEIPT_SEVENTH_SUCCESSOR_REVISION,
            "2002f4da021de7188e86ae4cd7a724bf0e9da0db",
        )
        self.assertEqual(
            MODULE.TRACER_RECEIPT_EIGHTH_SUCCESSOR_REVISION,
            "1995dba981f9413ff5460328a02c79ab563129a5",
        )
        self.assertEqual(
            MODULE.TRACER_RECEIPT_NINTH_SUCCESSOR_REVISION,
            "01e115b6fd03dce7900946ac71e2d8f943a6fb74",
        )
        self.assertEqual(
            MODULE.TRACER_RECEIPT_TENTH_SUCCESSOR_REVISION,
            "38cdfbd9748c3481689599c53f4443af11a7df63",
        )
        self.assertEqual(
            MODULE.TRACER_RECEIPT_ELEVENTH_SUCCESSOR_REVISION,
            "890e001c76a94755d8f25ebfcf83593da24a082e",
        )
        self.assertEqual(
            MODULE.TRACER_RECEIPT_TWELFTH_SUCCESSOR_REVISION,
            "92dbe194d1ff3ba45844409d6f478b9012c5182c",
        )
        self.assertEqual(
            MODULE.TRACER_RECEIPT_THIRTEENTH_SUCCESSOR_REVISION,
            "4bea54c7823a7da3c60d5c57eb3ad8b1c8b01929",
        )
        self.assertEqual(
            MODULE.TRACER_RECEIPT_FOURTEENTH_SUCCESSOR_REVISION,
            "136f0ac1ca31c9beda8f7208ed01a12201460bd7",
        )
        self.assertEqual(
            MODULE.TRACER_RECEIPT_FIFTEENTH_SUCCESSOR_REVISION,
            "96795cc20a28e93a9ed00208bb2311efcdb8a1ae",
        )
        self.assertEqual(
            MODULE.TRACER_RECEIPT_SIXTEENTH_SUCCESSOR_REVISION,
            "4de9d00696a7c43694bf66edbf79d1fb1fd080de",
        )
        self.assertEqual(
            MODULE.TRACER_RECEIPT_SEVENTEENTH_SUCCESSOR_REVISION,
            "c126f1f680bd65079a941af61fb108ced777c0dc",
        )
        participant_pair = {
            "scripts/activate-staging-participant-gateway.py",
            "scripts/test_activate_staging_participant_gateway.py",
        }
        wrapper_pair = {
            "scripts/run-staging-participant-gateway-live.py",
            "scripts/test_run_staging_participant_gateway_live.py",
        }
        self.assertEqual(set(MODULE.TRACER_RECEIPT_ORIGIN_TO_INTERMEDIATE_FILES), participant_pair)
        self.assertEqual(
            set(MODULE.TRACER_RECEIPT_INTERMEDIATE_TO_SECOND_SUCCESSOR_FILES),
            participant_pair | wrapper_pair,
        )
        self.assertEqual(set(MODULE.TRACER_RECEIPT_SECOND_TO_THIRD_SUCCESSOR_FILES), participant_pair)
        self.assertEqual(set(MODULE.TRACER_RECEIPT_THIRD_TO_FOURTH_SUCCESSOR_FILES), wrapper_pair)
        self.assertEqual(set(MODULE.TRACER_RECEIPT_FOURTH_TO_FIFTH_SUCCESSOR_FILES), wrapper_pair)
        self.assertEqual(
            set(MODULE.TRACER_RECEIPT_FIFTH_TO_SIXTH_SUCCESSOR_FILES),
            participant_pair | wrapper_pair,
        )
        self.assertEqual(
            set(MODULE.TRACER_RECEIPT_SIXTH_TO_SEVENTH_SUCCESSOR_FILES),
            participant_pair | wrapper_pair,
        )
        self.assertEqual(
            set(MODULE.TRACER_RECEIPT_SEVENTH_TO_EIGHTH_SUCCESSOR_FILES),
            {
                "policy/staging-participant-gateway-activation-policy.json",
                "reviewed-render/roebel-staging/integrity.json",
                "reviewed-render/roebel-staging/network-boundary-migration.json",
                "reviewed-render/roebel-staging/staging-participant-gateway/networkpolicy.json",
                "reviewed-render/roebel-staging/staging-participant-gateway/runtime-pin.json",
                "scripts/activate-staging-participant-gateway.py",
                "scripts/run-staging-participant-gateway-live.py",
                "scripts/staging_participant_gateway_policy.py",
                "scripts/test_activate_staging_participant_gateway.py",
                "scripts/test_run_staging_participant_gateway_live.py",
                "scripts/test_staging_participant_gateway_policy.py",
            },
        )
        self.assertEqual(
            set(MODULE.TRACER_RECEIPT_EIGHTH_TO_NINTH_SUCCESSOR_FILES),
            participant_pair | wrapper_pair,
        )
        self.assertEqual(
            set(MODULE.TRACER_RECEIPT_NINTH_TO_TENTH_SUCCESSOR_FILES),
            participant_pair | wrapper_pair,
        )
        self.assertEqual(
            set(MODULE.TRACER_RECEIPT_TENTH_TO_ELEVENTH_SUCCESSOR_FILES),
            participant_pair | wrapper_pair,
        )
        self.assertEqual(
            set(MODULE.TRACER_RECEIPT_ELEVENTH_TO_TWELFTH_SUCCESSOR_FILES),
            {
                "scripts/bootstrap-staging-participant-flux.py",
                "scripts/run-staging-participant-gateway-live.py",
                "scripts/staging_participant_flux_bootstrap.py",
                "scripts/test_run_staging_participant_gateway_live.py",
                "scripts/test_staging_participant_flux_bootstrap.py",
            },
        )
        self.assertEqual(
            set(MODULE.TRACER_RECEIPT_TWELFTH_TO_THIRTEENTH_SUCCESSOR_FILES),
            {
                "scripts/bootstrap-staging-participant-flux.py",
                "scripts/run-staging-participant-gateway-live.py",
                "scripts/test_run_staging_participant_gateway_live.py",
                "scripts/test_staging_participant_flux_bootstrap.py",
            },
        )
        self.assertEqual(
            set(MODULE.TRACER_RECEIPT_THIRTEENTH_TO_FOURTEENTH_SUCCESSOR_FILES),
            {"scripts/test_run_staging_participant_gateway_live.py"},
        )
        self.assertEqual(
            set(MODULE.TRACER_RECEIPT_FOURTEENTH_TO_FIFTEENTH_SUCCESSOR_FILES),
            {"scripts/test_run_staging_participant_gateway_live.py"},
        )
        self.assertEqual(
            set(MODULE.TRACER_RECEIPT_FIFTEENTH_TO_SIXTEENTH_SUCCESSOR_FILES),
            {
                "scripts/bootstrap-staging-participant-flux.py",
                "scripts/test_staging_participant_flux_bootstrap.py",
            },
        )
        self.assertEqual(
            set(MODULE.TRACER_RECEIPT_SIXTEENTH_TO_SEVENTEENTH_SUCCESSOR_FILES),
            participant_pair | wrapper_pair | {
                "scripts/staging_participant_gateway_policy.py",
                "scripts/test_staging_participant_gateway_policy.py",
            },
        )
        self.assertEqual(
            set(MODULE.TRACER_RECEIPT_SEVENTEENTH_SUCCESSOR_TO_ACCEPTOR_FILES),
            participant_pair | wrapper_pair,
        )
        widened = copy.deepcopy(receipt)
        widened["protectedFileSha256"][MODULE.TRACER_POLICY_PATH] = sha("8")
        with self.assertRaisesRegex(MODULE.ActivationError, "protected path change drift"):
            bind(widened)
        for path in (
            "scripts/activate-staging-participant-gateway.py",
            MODULE.POLICY_MODULE_PATH,
            MODULE.POLICY_PATH,
        ):
            omitted = copy.deepcopy(receipt)
            omitted["protectedFileSha256"][path] = current_hashes[path]
            with self.subTest(omitted=path), self.assertRaisesRegex(
                MODULE.ActivationError,
                "origin activation-runner hash drift|protected path change drift",
            ):
                bind(omitted)
        source_drift = copy.deepcopy(receipt)
        source_drift["sharedFluxSource"]["revision"] = f"main@sha1:{REV}"
        with self.assertRaisesRegex(MODULE.ActivationError, "shared Flux source"):
            bind(source_drift)
        flux_drift = copy.deepcopy(receipt)
        flux_drift["flux"]["lastAppliedRevision"] = f"main@sha1:{REV}"
        with self.assertRaisesRegex(MODULE.ActivationError, "Flux readiness"):
            bind(flux_drift)

    def test_eighteenth_hop_rejects_wrong_or_merge_parent_before_reading_the_delta(self):
        parent = MODULE.TRACER_RECEIPT_SEVENTEENTH_SUCCESSOR_REVISION
        child = "c" * 40
        foreign = "d" * 40
        for label, lineage in (
            ("wrong-parent", f"{child} {foreign}\n"),
            ("merge-parent", f"{child} {parent} {foreign}\n"),
        ):
            result = MODULE.subprocess.CompletedProcess(
                args=[], returncode=0, stdout=lineage, stderr=""
            )
            with self.subTest(label=label), patch.object(
                MODULE, "trusted_git_v4", return_value=result
            ) as trusted, self.assertRaisesRegex(
                MODULE.ActivationError,
                "seventeenth-successor-to-acceptor protected parent drift",
            ):
                MODULE.exact_revision_transition_files_v4(
                    parent,
                    child,
                    "tracer receipt seventeenth-successor-to-acceptor",
                )
            self.assertEqual(trusted.call_count, 1)

    def test_live_tracer_binding_revalidates_kustomization_before_first_mutation(self):
        expected = TRACER_POLICY.dormant_flux_objects(suspended=False)["kustomization"]
        live = copy.deepcopy(expected)
        live["metadata"] |= {
            "uid": "tracer-kustomization-uid",
            "resourceVersion": "400",
            "generation": 7,
        }
        live["status"] = {
            "observedGeneration": 7,
            "lastAppliedRevision": f"main@sha1:{REV}",
            "lastAttemptedRevision": f"main@sha1:{REV}",
            "conditions": [{"type": "Ready", "status": "True", "observedGeneration": 7}],
        }
        secret = {
            "target": {
                "apiVersion": "v1", "kind": "Secret",
                "name": "postgrest-secret", "namespace": "tracer-namespace",
            },
            "uid": "postgrest-secret-uid", "resourceVersion": "30",
            "keySet": ["db-uri"], "valuesRead": False,
        }
        service = {
            "serviceUid": "postgrest-service-uid",
            "port": 3000,
            "readyEndpointAddresses": ["10.244.1.11"],
        }
        ownership = {
            "participantPostgrestSecret": secret,
            "postgrestService": service,
            "receiptProvenance": {
                "mode": "current-protected-revision",
                "originProtectedRevision": REV,
                "acceptedByProtectedRevision": REV,
                "allowedAppliedRevisions": [REV],
            },
            "tracerFluxKustomization": {
                "target": {
                    "apiVersion": "kustomize.toolkit.fluxcd.io/v1",
                    "kind": "Kustomization", "namespace": MODULE.FLUX_NAMESPACE,
                    "name": "roebel-tracer-data-plane",
                },
                "uid": "tracer-kustomization-uid", "resourceVersion": "100",
                "ownershipNonce": "d" * 64, "temporaryNonceRemoved": True,
            },
        }
        secrets = {"secrets": {"postgrest": {
            "name": "postgrest-secret", "namespace": "tracer-namespace",
            "uid": "postgrest-secret-uid", "resourceVersion": "30",
            "keys": ["db-uri"], "valuesRead": False,
        }}}
        endpoints = {"postgrest": {
            "serviceUid": "postgrest-service-uid",
            "readyEndpointAddresses": ["10.244.1.11"],
            "externalIngress": False,
        }}

        def require_live(candidate):
            runner = Mock(spec=MODULE.Runner)
            runner.run.return_value = MODULE.Result(out=json.dumps(candidate))
            with patch.object(MODULE, "git_blob", return_value=b"tracer-policy"), patch.object(
                MODULE, "compile_verified_tracer_policy_module_v4", return_value=TRACER_POLICY,
            ):
                MODULE.require_tracer_activation_binding_v4(
                    endpoints, secrets, ownership, runner, "/fixture/kubeconfig", REV,
                )
            self.assertEqual(len(runner.run.call_args_list), 1)
            self.assertIn("get", runner.run.call_args.args[0])

        require_live(live)
        drifts = {
            "identity/generation": lambda candidate: candidate["metadata"].update(uid="other"),
            "semantic drift": lambda candidate: candidate["spec"].update(suspend=True),
            "not Ready": lambda candidate: candidate["status"]["conditions"][0].update(status="False"),
            "revision drift": lambda candidate: candidate["status"].update(lastAppliedRevision=f"main@sha1:{'f' * 40}"),
        }
        for message, mutate in drifts.items():
            with self.subTest(message=message):
                changed = copy.deepcopy(live)
                mutate(changed)
                with self.assertRaisesRegex(MODULE.ActivationError, message):
                    require_live(changed)

        source = inspect.getsource(MODULE.activate)
        self.assertLess(
            source.index("require_tracer_activation_binding_v4("),
            source.index("mutation_started = True"),
        )

    def test_live_cli_requires_and_forwards_the_tracer_activation_receipt(self):
        parsed = MODULE.parse_args([
            "--expected-protected-revision", REV,
            "--live",
            "--kubeconfig", "/fixture/kubeconfig",
            "--flux-bootstrap-receipt-fd", "21",
            "--tracer-data-plane-activation-receipt-fd", "22",
        ])
        self.assertTrue(parsed.live)
        self.assertEqual(parsed.tracer_data_plane_activation_receipt_fd, 22)
        source = inspect.getsource(MODULE.main)
        start = source.index("require(a.live is True")
        ordinary = source[start:source.index("print(canonical(result)); return 0", start)]
        self.assertLess(
            ordinary.index("bind_tracer_activation_receipt_v4("),
            ordinary.index("sink = ReceiptSink.reserve"),
        )
        self.assertIn("tracer_activation_ownership,\n        )", ordinary)

    def test_live_activation_requires_bootstrap_receipt_before_runner_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            kube = Path(directory) / "kubeconfig"
            kube.write_text("not read")
            with self.assertRaisesRegex(MODULE.ActivationError, "requires exact dormant Flux bootstrap receipt"):
                MODULE.activate(
                    ready_policy(),
                    REV,
                    str(kube),
                    Fake(),
                    True,
                    Mock(),
                    {"runner": sha()},
                    None,
                )

    def test_flux_preflight_binds_all_eight_live_uids_to_bootstrap_receipt(self):
        value = ready_policy()
        objects = []
        live = []
        for owner, builder in (
            ("gateway", MODULE.POLICY.gateway_flux_objects),
            ("workbenchIngress", MODULE.POLICY.workbench_ingress_flux_objects),
        ):
            desired = builder(suspended=True)
            for key in ("serviceAccount", "role", "roleBinding", "kustomization"):
                observed = admitted(desired[key], f"{owner}-{key}-uid", "21")
                live.append(observed)
                objects.append({
                    "logicalName": f"{owner}.{key}",
                    "target": value["gitOps"]["reconcilers"][owner][key],
                    "uid": observed["metadata"]["uid"],
                    "resourceVersion": "20",
                    "desiredSemanticSha256": MODULE.POLICY.semantic_sha256(desired[key]),
                })
        ownership = {
            "status": "dormant-ready",
            "receiptSha256": sha("b"),
            "protectedRevision": REV,
            "activationPolicySha256": MODULE.POLICY.activation_policy_sha256(value),
            "objects": objects,
            "bothKustomizationsSuspended": True,
        }
        source = {"metadata": {"uid": "source", "resourceVersion": "1"}, "status": {"artifact": {"revision": f"main@sha1:{REV}"}}}
        with patch.object(MODULE, "shared_source_revision_v4", return_value=source), patch.object(
            MODULE,
            "_target_live",
            side_effect=live,
        ):
            result = MODULE.flux_preflight_v4(Fake(), "/snapshot", value, REV, ownership)
        self.assertEqual(result["bootstrapReceipt"]["receiptSha256"], sha("b"))
        self.assertEqual(set(result["owners"]), {"gateway", "workbenchIngress"})

        drifted = copy.deepcopy(ownership)
        drifted["objects"][0]["uid"] = "foreign"
        with patch.object(MODULE, "shared_source_revision_v4", return_value=source), patch.object(
            MODULE,
            "_target_live",
            side_effect=live,
        ):
            with self.assertRaisesRegex(MODULE.ActivationError, "no longer matches bootstrap receipt identity"):
                MODULE.flux_preflight_v4(Fake(), "/snapshot", value, REV, drifted)

    def test_duplicate_json_keys_are_rejected_at_every_object_boundary(self):
        with self.assertRaisesRegex(MODULE.ActivationError, "duplicate"):
            MODULE.obj('{"metadata":{},"metadata":{}}', "duplicate fixture")
        with self.assertRaisesRegex(MODULE.ActivationError, "duplicate"):
            MODULE.json_value('{"nested":{"key":1,"key":2}}', "duplicate nested fixture")

    def test_receipt_sink_is_reserved_0600_non_overwriting_and_durable(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "receipts" / "activation.json"
            sink = MODULE.ReceiptSink.reserve(target)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            sink.commit({"status": "test", "civicAuthorityEffects": False})
            committed = json.loads(target.read_text())
            self.assertEqual(committed["status"], "test")
            self.assertIn("canonicalSha256", committed)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                MODULE.ReceiptSink.reserve(target)

    def test_kubeconfig_snapshot_is_single_flattened_0600_file_and_rejects_url_tricks(self):
        pem = b"-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n"
        def flattened(server, proxy=None):
            cluster = {"server": server, "certificate-authority-data": base64.b64encode(pem).decode()}
            if proxy is not None: cluster["proxy-url"] = proxy
            return json.dumps({
                "apiVersion": "v1", "kind": "Config", "current-context": "ctx",
                "clusters": [{"name": "cluster", "cluster": cluster}],
                "contexts": [{"name": "ctx", "context": {"cluster": "cluster", "user": "user"}}],
                "users": [{"name": "user", "user": {"token": "secret-never-receipted"}}],
            })
        class Flatten(MODULE.Runner):
            def __init__(self, raw): self.raw = raw; self.calls = []
            def run(self, args, *, input_text=None, timeout=10): self.calls.append(args); return MODULE.Result(out=self.raw)
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "original"; original.write_text("not-read-by-test-runner")
            runner = Flatten(flattened("https://api.example.test:6443"))
            snapshot = MODULE.snapshot_kubeconfig_v4(str(original), runner)
            try:
                self.assertEqual(snapshot.api_origin, "https://api.example.test:6443")
                self.assertIsNone(snapshot.connect_proxy)
                self.assertEqual(stat.S_IMODE(snapshot.path.stat().st_mode), 0o600)
                self.assertEqual(len(runner.calls), 1)
                self.assertIn("--flatten", runner.calls[0]); self.assertIn("--raw", runner.calls[0])
            finally: snapshot.close()
            self.assertFalse(snapshot.path.exists())
            proxy_password = "a" * 64
            proxy_url = f"http://stadtstack-participant:{proxy_password}@127.0.0.1:16443"
            proxied = MODULE.snapshot_kubeconfig_v4(
                str(original),
                Flatten(flattened("https://api.example.test:6443", proxy_url)),
            )
            try:
                self.assertEqual(proxied.api_origin, "https://api.example.test:6443")
                self.assertEqual(proxied.connect_proxy.host, "127.0.0.1")
                self.assertEqual(proxied.connect_proxy.port, 16443)
                self.assertEqual(proxied.connect_proxy.origin, proxy_url)
                stored = json.loads(proxied.path.read_text())
                self.assertEqual(stored["clusters"][0]["cluster"]["proxy-url"], proxy_url)
            finally: proxied.close()
            for bad in ("https://user@api.example.test:6443", "https://api.example.test:6443/path", "https://api.example.test:6443?x=1", "https://api.example.test:6443#x"):
                with self.assertRaisesRegex(MODULE.ActivationError, "HTTPS origin"):
                    MODULE.snapshot_kubeconfig_v4(str(original), Flatten(flattened(bad)))
            for bad_proxy in (
                "http://127.0.0.1:16443", "https://127.0.0.1:16443", "http://localhost:16443", "http://127.0.0.2:16443",
                "http://[::1]:16443", "http://127.0.0.1", "http://127.0.0.1:0",
                "http://user@127.0.0.1:16443", "http://127.0.0.1:16443/",
                "http://127.0.0.1:16443?x=1", "http://127.0.0.1:16443#x",
                f"http://stadtstack-participant:{'b' * 63}@127.0.0.1:16443",
                f"http://wrong-user:{'b' * 64}@127.0.0.1:16443",
                123,
            ):
                with self.subTest(proxy=bad_proxy), self.assertRaisesRegex(MODULE.ActivationError, "loopback HTTP CONNECT proxy"):
                    MODULE.snapshot_kubeconfig_v4(
                        str(original),
                        Flatten(flattened("https://api.example.test:6443", bad_proxy)),
                    )

            failed_snapshot = Path(directory) / "failed-snapshot"
            def make_failed_snapshot(*_args, **_kwargs):
                failed_snapshot.mkdir(mode=0o700)
                return str(failed_snapshot)
            with patch.object(MODULE.tempfile, "mkdtemp", side_effect=make_failed_snapshot), patch.object(MODULE.os, "fsync", side_effect=OSError("injected fsync failure")):
                with self.assertRaisesRegex(OSError, "injected fsync failure"):
                    MODULE.snapshot_kubeconfig_v4(str(original), Flatten(flattened("https://api.example.test:6443")))
            self.assertFalse(failed_snapshot.exists(), "failed credential snapshot must be removed")

    def test_api_spki_probe_uses_exact_connect_authority_then_end_to_end_tls(self):
        class Connection:
            def __init__(self, response): self.response = bytearray(response); self.sent = b""; self.closed = False
            def sendall(self, value): self.sent += value
            def recv(self, size):
                self.asserted_size = size
                if not self.response: return b""
                value = bytes(self.response[:1]); del self.response[:1]; return value
            def close(self): self.closed = True
            def __enter__(self): return self
            def __exit__(self, *_args): self.close(); return False
        class Secured:
            def getpeercert(self, binary_form=False):
                self.binary_form = binary_form; return b"certificate-der"
            def __enter__(self): return self
            def __exit__(self, *_args): return False
        class Context:
            def __init__(self): self.wrapped = []
            def wrap_socket(self, connection, server_hostname):
                self.wrapped.append((connection, server_hostname)); return Secured()
        connection = Connection(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: wireproxy\r\n\r\n")
        context = Context()
        snapshot = Mock(
            hostname="10.255.240.11", port=6443, tls_server_name="kubernetes",
            ca_pem=b"-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n",
            connect_proxy=MODULE.LoopbackConnectProxy(
                f"http://stadtstack-participant:{'c' * 64}@127.0.0.1:53161",
                "127.0.0.1", 53161, "stadtstack-participant", "c" * 64,
            ),
        )
        openssl = [
            subprocess.CompletedProcess([], 0, b"public-key-pem", b""),
            subprocess.CompletedProcess([], 0, b"public-key-der", b""),
        ]
        with patch.object(MODULE.socket, "create_connection", return_value=connection) as connect, patch.object(
            MODULE.ssl, "create_default_context", return_value=context,
        ) as create_context, patch.object(MODULE.subprocess, "run", side_effect=openssl):
            result = MODULE._api_server_spki_v4(snapshot, 3)
        connect.assert_called_once_with(("127.0.0.1", 53161), timeout=3)
        proxy_authorization = base64.b64encode(("stadtstack-participant:" + "c" * 64).encode("ascii"))
        self.assertEqual(
            connection.sent,
            b"CONNECT 10.255.240.11:6443 HTTP/1.1\r\nHost: 10.255.240.11:6443\r\n"
            + b"Proxy-Authorization: Basic " + proxy_authorization + b"\r\n\r\n",
        )
        self.assertEqual(context.wrapped, [(connection, "kubernetes")])
        create_context.assert_called_once_with(cadata=snapshot.ca_pem.decode("ascii"))
        self.assertEqual(result, MODULE.bytes_digest(b"public-key-der"))
        self.assertTrue(connection.closed)

    def test_api_connect_proxy_rejects_non_success_incomplete_and_oversized_responses(self):
        class Connection:
            def __init__(self, response): self.response = bytearray(response); self.closed = False
            def sendall(self, _value): pass
            def recv(self, _size):
                if not self.response: return b""
                value = bytes(self.response[:1]); del self.response[:1]; return value
            def close(self): self.closed = True
        snapshot = Mock(
            hostname="10.255.240.11", port=6443,
            connect_proxy=MODULE.LoopbackConnectProxy(
                f"http://stadtstack-participant:{'d' * 64}@127.0.0.1:53161",
                "127.0.0.1", 53161, "stadtstack-participant", "d" * 64,
            ),
        )
        cases = (
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
            b"HTTP/1.1 301 Moved Permanently\r\n\r\n",
            b"HTTP/1.1 200 Connection Established\r\n",
            b"NOT HTTP\r\n\r\n",
            b"HTTP/1.1 2000 Not A Status\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nMalformed-Header\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX:" + b"a" * 8192 + b"\r\n\r\n",
        )
        for response in cases:
            connection = Connection(response)
            with self.subTest(response=response[:40]), patch.object(MODULE.socket, "create_connection", return_value=connection), self.assertRaises(MODULE.ActivationError):
                MODULE._api_tcp_transport_v4(snapshot, 3)
            self.assertTrue(connection.closed)

    def test_kubectl_subprocesses_ignore_ambient_proxy_environment(self):
        hostile = {
            "PATH": "/usr/bin", "HTTPS_PROXY": "http://attacker.invalid:8080",
            "http_proxy": "http://attacker.invalid:8080", "ALL_PROXY": "socks5://attacker.invalid:1080",
            "no_proxy": "*", "SAFE_MARKER": "retained",
        }
        binding = Mock(path=Path("/snapshot/kubectl"))
        process = Mock(returncode=0); process.communicate.return_value = ("ok", "")
        with patch.dict(MODULE.os.environ, hostile, clear=True), patch.object(
            MODULE,
            "kubectl_binding_v4",
            return_value=binding,
        ), patch.object(MODULE, "verified_popen", return_value=process) as spawn:
            result = MODULE.Runner().run(["kubectl", "version"])
        self.assertEqual(result.out, "ok")
        self.assertEqual(spawn.call_args.args[1], ["/snapshot/kubectl", "version"])
        child_env = spawn.call_args.kwargs["env"]
        self.assertEqual(child_env, {"PATH": "/usr/bin", "SAFE_MARKER": "retained"})
    def test_kubectl_read_timeouts_retry_but_mutations_remain_single_attempt(self):
        binding = Mock(path=Path("/snapshot/kubectl"))
        timed_out = Mock(returncode=124)
        timed_out.communicate.side_effect = subprocess.TimeoutExpired(["kubectl"], 10)
        succeeded = Mock(returncode=0)
        succeeded.communicate.return_value = ('{"kind":"PodList","items":[]}', "")
        with patch.object(MODULE, "kubectl_binding_v4", return_value=binding), patch.object(
            MODULE,
            "verified_popen",
            side_effect=[timed_out, succeeded],
        ) as spawn:
            result = MODULE.Runner().run(
                ["kubectl", "--kubeconfig", "/private/kube", "get", "pods", "-o", "json"],
                timeout=10,
            )
        self.assertEqual(result.code, 0)
        self.assertEqual(spawn.call_count, 2)

        mutation_timeout = Mock(returncode=124)
        mutation_timeout.communicate.side_effect = subprocess.TimeoutExpired(["kubectl"], 10)
        with patch.object(MODULE, "kubectl_binding_v4", return_value=binding), patch.object(
            MODULE,
            "verified_popen",
            return_value=mutation_timeout,
        ) as spawn:
            result = MODULE.Runner().run(
                ["kubectl", "--kubeconfig", "/private/kube", "patch", "deployment", "gateway"],
                timeout=10,
            )
        self.assertEqual(result.code, 124)
        self.assertEqual(spawn.call_count, 1)


    @unittest.skipUnless(
        sys.platform == "darwin" and Path("/private/tmp/wireproxy-v1.1.3-darwin-arm64/wireproxy").exists(),
        "Darwin suspended-spawn contract",
    )
    def test_verified_spawn_executes_only_the_bound_vnode(self):
        source = Path("/private/tmp/wireproxy-v1.1.3-darwin-arm64/wireproxy")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wireproxy"
            path.write_bytes(source.read_bytes()); path.chmod(0o500)
            binding = MODULE.bind_executable_snapshot(path, MODULE.bytes_digest(path.read_bytes()))
            try:
                process = MODULE.verified_popen(
                    binding,
                    [str(path), "--version"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    start_new_session=True,
                )
                stdout, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0)
                self.assertIn("wireproxy", stdout)
                self.assertEqual(stderr, "")
                replacement_path = Path(directory) / "replacement"
                replacement_path.write_bytes(b"attacker-selected pathname bytes"); replacement_path.chmod(0o500)
                replacement = MODULE.ExecutableBinding(
                    replacement_path,
                    binding.fd,
                    binding.device,
                    binding.inode,
                    binding.size,
                    binding.sha256,
                    owns_fd=False,
                )
                replacement_process = MODULE.verified_popen(
                    replacement,
                    [str(replacement.path), "--version"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    start_new_session=True,
                )
                replacement_stdout, replacement_stderr = replacement_process.communicate(timeout=10)
                self.assertEqual(replacement_process.returncode, 0)
                self.assertIn("wireproxy", replacement_stdout)
                self.assertEqual(replacement_stderr, "")
            finally:
                binding.close()

    @unittest.skipUnless(sys.platform == "darwin", "Darwin immutable-flag contract")
    def test_verified_process_cleanup_failure_overrides_signal_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root / "invocation"; path.write_bytes(b"exact")
            fd = os.open(path, os.O_RDWR); path.chmod(0o500); info = os.fstat(fd)
            MODULE._set_descriptor_flags(fd, stat.UF_IMMUTABLE)
            binding = MODULE.ExecutableBinding(path, fd, info.st_dev, info.st_ino, info.st_size, MODULE.bytes_digest(b"exact"))
            process = MODULE.VerifiedProcess(4242, ["fixture"], None, None, None, text=False, cleanup_binding=binding)
            process.returncode = -15
            MODULE._set_descriptor_flags(fd, 0)
            moved = root / "moved"; path.rename(moved)
            path.write_bytes(b"other")
            process._cleanup_materialization()
            self.assertEqual(process.returncode, 125)
            self.assertIsNotNone(process.cleanup_error)
            moved.unlink()

    def test_raw_delete_uses_direct_authenticated_tls_without_loopback_listener(self):
        class Secured:
            def __init__(self): self.sent = b""; self.closed = False
            def sendall(self, value): self.sent += value
            def close(self): self.closed = True
        class Context:
            def __init__(self, secured): self.secured = secured
            def wrap_socket(self, _raw, server_hostname): self.server_hostname = server_hostname; return self.secured
            def load_cert_chain(self, *_args): raise AssertionError("token fixture loaded a client key")
        class Response:
            status = 200
            def begin(self): pass
            def read(self, _limit): return b"{}"
        resource_path = f"/apis/networking.k8s.io/v1/namespaces/{MODULE.NAMESPACE}/networkpolicies/{MODULE.NAME}"
        payload = MODULE.canonical({
            "apiVersion": "v1",
            "kind": "DeleteOptions",
            "preconditions": {"uid": "owned-uid", "resourceVersion": "10"},
        })
        secured = Secured(); context = Context(secured); raw = Mock()
        snapshot = Mock(
            ca_pem=b"-----BEGIN CERTIFICATE-----\\nfixture\\n-----END CERTIFICATE-----",
            client_certificate_path=None,
            client_key_path=None,
            bearer_token="private-token",
            hostname="10.255.240.11",
            port=6443,
            tls_server_name="10.255.240.11",
        )
        with patch.object(MODULE.ssl, "create_default_context", return_value=context), patch.object(
            MODULE,
            "_api_tcp_transport_v4",
            return_value=raw,
        ), patch.object(MODULE.http.client, "HTTPResponse", return_value=Response()), patch.object(
            MODULE.subprocess,
            "Popen",
        ) as forbidden_listener:
            MODULE.raw_delete(snapshot, resource_path, payload)
        self.assertIn(f"DELETE {resource_path} HTTP/1.1".encode(), secured.sent)
        self.assertIn(b"Authorization: Bearer private-token", secured.sent)
        self.assertIn(payload.encode(), secured.sent)
        self.assertTrue(secured.closed)
        forbidden_listener.assert_not_called()
        with self.assertRaisesRegex(MODULE.ActivationError, "outside closed policy"):
            MODULE.raw_delete(snapshot, resource_path + "?watch=true", payload)
    def test_definite_create_conflict_is_never_treated_as_uncertain(self):
        class Conflict(MODULE.Runner):
            def run(self, args, *, input_text=None):
                return MODULE.Result(1, "", "Error from server (AlreadyExists): object exists")
        with self.assertRaises(MODULE.CreateConflictError):
            MODULE.checked(Conflict(), ["kubectl", "create"], "create NetworkPolicy", "{}")

    def test_only_transport_failure_enters_uncertain_create_class(self):
        class TimedOut(MODULE.Runner):
            def run(self, args, *, input_text=None):
                return MODULE.Result(124, "", "timeout after 30s")
        with self.assertRaises(MODULE.TransportUncertainError):
            MODULE.checked(TimedOut(), ["kubectl", "create"], "create NetworkPolicy", "{}")

    def test_v4_definite_409_never_discovers_or_adopts(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy()
        rendered = {"desired": desired, "path": "fixed", "blobSha256": sha()}
        class Conflict(MODULE.Runner):
            def run(self, args, *, input_text=None, timeout=10): return MODULE.Result(1, "", "HTTP 409 AlreadyExists")
        with patch.object(MODULE, "live_obj") as discover:
            with self.assertRaises(MODULE.CreateConflictError):
                MODULE.create_v4(Conflict(), "/tmp/kube", "workbenchIngress.networkPolicy", rendered, "a" * 64)
        discover.assert_not_called()

    def test_v4_transport_uncertainty_discovers_exact_uid_rv(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy(); nonce = "a" * 64
        observed = admitted(MODULE.POLICY.with_operation_nonce(desired, nonce))
        rendered = {"desired": desired, "path": "fixed", "blobSha256": sha()}
        class ServerError(MODULE.Runner):
            def run(self, args, *, input_text=None, timeout=10): return MODULE.Result(1, "", "HTTP 503")
        with patch.object(MODULE, "live_obj", return_value=observed) as discover:
            result = MODULE.create_v4(ServerError(), "/tmp/kube", "workbenchIngress.networkPolicy", rendered, nonce)
        discover.assert_called_once()
        self.assertTrue(result.receipt["discoveredAfterPostSendUncertainty"])
        self.assertEqual(result.receipt["uid"], "owned-uid")
        self.assertEqual(result.receipt["resourceVersion"], "10")

    def test_v4_malformed_success_response_discovers_and_owns_only_exact_nonce(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy(); nonce = "b" * 64
        observed = admitted(MODULE.POLICY.with_operation_nonce(desired, nonce))
        rendered = {"desired": desired, "path": "fixed", "blobSha256": sha()}
        class Malformed(MODULE.Runner):
            def run(self, args, *, input_text=None, timeout=10): return MODULE.Result(0, "{malformed", "")
        with patch.object(MODULE, "live_obj", return_value=observed):
            result = MODULE.create_v4(Malformed(), "/tmp/kube", "workbenchIngress.networkPolicy", rendered, nonce)
        self.assertEqual(result.receipt["outcome"], "post-send-uncertain-discovered")
        wrong = admitted(desired)
        with patch.object(MODULE, "live_obj", return_value=wrong):
            with self.assertRaisesRegex(MODULE.TransportUncertainError, "unresolved"):
                MODULE.create_v4(Malformed(), "/tmp/kube", "workbenchIngress.networkPolicy", rendered, nonce)

    def test_v4_deployment_http_201_and_nonce_removal_accept_matching_defaulted_service_account_alias(self):
        value = ready_policy(); nonce = "e" * 64
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            desired = MODULE.POLICY.expected_gateway_resources(value)["deployment"]
        rendered = {"desired": desired, "path": "fixed", "blobSha256": sha()}

        class DefaultingApi(MODULE.Runner):
            def run(self, args, *, input_text=None, timeout=10):
                candidate = json.loads(input_text)
                candidate["metadata"] |= {"uid": "deployment-uid", "resourceVersion": "31"}
                pod_spec = candidate["spec"]["template"]["spec"]
                pod_spec["serviceAccount"] = pod_spec["serviceAccountName"]
                return MODULE.Result(out=json.dumps(candidate))

        created = MODULE.create_v4(DefaultingApi(), "/tmp/kube", "gateway.deployment", rendered, nonce)
        self.assertEqual(created.receipt["outcome"], "http-201-created")
        self.assertEqual(created.observed["spec"]["template"]["spec"]["serviceAccount"], MODULE.NAME)

        current = admitted(MODULE.POLICY.with_operation_nonce(desired, nonce), "deployment-uid", "32")
        current["spec"]["template"]["spec"]["serviceAccount"] = MODULE.NAME
        after = admitted(desired, "deployment-uid", "33")
        after["spec"]["template"]["spec"]["serviceAccount"] = MODULE.NAME
        class NonceRemovalApi(MODULE.Runner):
            def run(self, args, *, input_text=None, timeout=10): return MODULE.Result(out=json.dumps(after))
        with patch.object(MODULE, "live_obj", return_value=current):
            MODULE.remove_operation_nonce_v4(NonceRemovalApi(), "/snapshot", created, nonce)
        self.assertTrue(created.receipt["temporaryNonceRemoved"])
        self.assertEqual(created.receipt["postNonceRemovalResourceVersion"], "33")

    def test_v4_deployment_nonce_removal_rebinds_controller_advanced_resource_version(self):
        value = ready_policy(); nonce = "f" * 64
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            desired = MODULE.POLICY.expected_gateway_resources(value)["deployment"]
        nonce_desired = MODULE.POLICY.with_operation_nonce(desired, nonce)
        created_observed = admitted(nonce_desired, "deployment-uid", "40")
        created = MODULE.CreatedV4(
            "gateway.deployment",
            desired,
            created_observed,
            {"operationNonce": nonce, "temporaryNonceRemoved": False},
        )

        class ControllerRaceApi(MODULE.Runner):
            def __init__(self):
                self.state = admitted(nonce_desired, "deployment-uid", "41")
                self.state["metadata"].setdefault("annotations", {})["deployment.kubernetes.io/revision"] = "1"
                self.state["spec"]["template"]["spec"]["serviceAccount"] = MODULE.NAME
                self.state["status"] = {"observedGeneration": 1}
                self.commands = []
            def run(self, args, *, input_text=None, timeout=10):
                self.assert_target(args)
                if "get" in args:
                    self.commands.append("GET")
                    return MODULE.Result(out=json.dumps(self.state))
                self.commands.append("PATCH")
                patch_body = json.loads(args[args.index("-p") + 1])
                self.assert_patch_shape(patch_body)
                if self.commands.count("PATCH") == 1:
                    self.state["metadata"]["resourceVersion"] = "42"
                metadata = self.state["metadata"]
                actual = (
                    metadata["uid"],
                    metadata["resourceVersion"],
                    metadata["annotations"][MODULE.POLICY.OPERATION_NONCE_ANNOTATION],
                )
                expected = tuple(item["value"] for item in patch_body[:3])
                if actual != expected:
                    return MODULE.Result(1, "", "The request is invalid: the server rejected our request due to an error in our request")
                metadata["annotations"].pop(MODULE.POLICY.OPERATION_NONCE_ANNOTATION)
                metadata["resourceVersion"] = "43"
                return MODULE.Result(out=json.dumps(self.state))
            def assert_target(self, args):
                self_test.assertEqual(args[0], "kubectl")
                self_test.assertEqual(args[args.index("-n") + 1], MODULE.NAMESPACE)
                verb = "get" if "get" in args else "patch"
                self_test.assertEqual(args[args.index(verb) + 1:args.index(verb) + 3], ["deployment", MODULE.NAME])
            def assert_patch_shape(self, patch_body):
                self_test.assertEqual([item["op"] for item in patch_body], ["test", "test", "test", "remove"])
                self_test.assertEqual(
                    [item["path"] for item in patch_body],
                    [
                        "/metadata/uid",
                        "/metadata/resourceVersion",
                        "/metadata/annotations/stadtstack.io~1participant-activation-nonce",
                        "/metadata/annotations/stadtstack.io~1participant-activation-nonce",
                    ],
                )

        self_test = self
        api = ControllerRaceApi()
        with patch.object(MODULE.time, "sleep"):
            MODULE.remove_operation_nonce_v4(api, "/snapshot", created, nonce)
        self.assertEqual(api.commands, ["GET", "PATCH", "GET", "PATCH"])
        self.assertTrue(created.receipt["temporaryNonceRemoved"])
        self.assertEqual(created.receipt["postNonceRemovalResourceVersion"], "43")
        self.assertNotIn(MODULE.POLICY.OPERATION_NONCE_ANNOTATION, api.state["metadata"]["annotations"])

    def test_v4_nonce_removal_discovers_lost_success_response_without_repatching(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy(); nonce = "9" * 64
        observed = admitted(MODULE.POLICY.with_operation_nonce(desired, nonce), "owned", "50")
        still_owned = admitted(MODULE.POLICY.with_operation_nonce(desired, nonce), "owned", "51")
        after = admitted(desired, "owned", "52")
        created = MODULE.CreatedV4(
            "workbenchIngress.networkPolicy",
            desired,
            observed,
            {"operationNonce": nonce, "temporaryNonceRemoved": False},
        )

        class LostResponseApi(MODULE.Runner):
            def __init__(self): self.patch_calls = 0
            def run(self, args, *, input_text=None, timeout=10):
                self.patch_calls += 1
                return MODULE.Result(124, "", "timeout after 10s")

        api = LostResponseApi()
        with patch.object(MODULE, "live_obj", side_effect=[still_owned, after]) as discover:
            MODULE.remove_operation_nonce_v4(api, "/snapshot", created, nonce)
        self.assertEqual(discover.call_count, 2)
        self.assertEqual(api.patch_calls, 1)
        self.assertTrue(created.receipt["temporaryNonceRemoved"])
        self.assertEqual(created.receipt["postNonceRemovalResourceVersion"], "52")

    def test_v4_nonce_removal_final_read_discovers_fourth_attempt_lost_success(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy(); nonce = "7" * 64
        nonce_desired = MODULE.POLICY.with_operation_nonce(desired, nonce)
        observed = admitted(nonce_desired, "owned", "90")
        created = MODULE.CreatedV4(
            "workbenchIngress.networkPolicy",
            desired,
            observed,
            {"operationNonce": nonce, "temporaryNonceRemoved": False},
        )

        class FourthAttemptLostResponseApi(MODULE.Runner):
            def __init__(self):
                self.patch_calls = 0
                self.state = copy.deepcopy(observed)
            def run(self, args, *, input_text=None, timeout=10):
                self.patch_calls += 1
                if self.patch_calls < 4:
                    self.state["metadata"]["resourceVersion"] = str(90 + self.patch_calls)
                    return MODULE.Result(1, "", "The request is invalid")
                self.state["metadata"]["annotations"].pop(MODULE.POLICY.OPERATION_NONCE_ANNOTATION)
                self.state["metadata"]["resourceVersion"] = "94"
                return MODULE.Result(124, "", "timeout after 10s")

        api = FourthAttemptLostResponseApi()
        with patch.object(MODULE, "live_obj", side_effect=lambda *_args: copy.deepcopy(api.state)) as discover, patch.object(MODULE.time, "sleep"):
            MODULE.remove_operation_nonce_v4(api, "/snapshot", created, nonce)
        self.assertEqual(discover.call_count, 5)
        self.assertEqual(api.patch_calls, 4)
        self.assertTrue(created.receipt["temporaryNonceRemoved"])
        self.assertEqual(created.receipt["postNonceRemovalResourceVersion"], "94")

    def test_v4_nonce_removal_refuses_first_read_nonce_absence_and_missing_create_rv(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy(); nonce = "3" * 64
        observed = admitted(MODULE.POLICY.with_operation_nonce(desired, nonce), "owned", "55")
        created = MODULE.CreatedV4(
            "workbenchIngress.networkPolicy",
            desired,
            observed,
            {"operationNonce": nonce, "temporaryNonceRemoved": False},
        )
        api = Mock(spec=MODULE.Runner)
        with patch.object(MODULE, "live_obj", return_value=admitted(desired, "owned", "56")):
            with self.assertRaisesRegex(MODULE.ActivationError, "disappeared before nonce-removal CAS"):
                MODULE.remove_operation_nonce_v4(api, "/snapshot", created, nonce)
        api.run.assert_not_called()
        missing_rv = copy.deepcopy(created); missing_rv.observed["metadata"].pop("resourceVersion")
        with self.assertRaisesRegex(MODULE.ActivationError, "preconditions absent"):
            MODULE.remove_operation_nonce_v4(api, "/snapshot", missing_rv, nonce)

    def test_v4_nonce_removal_rejects_rebound_semantic_drift_without_patch(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy(); nonce = "8" * 64
        observed = admitted(MODULE.POLICY.with_operation_nonce(desired, nonce), "owned", "60")
        drifted = admitted(MODULE.POLICY.with_operation_nonce(desired, nonce), "owned", "61")
        drifted["spec"]["policyTypes"] = ["Ingress", "Egress"]
        created = MODULE.CreatedV4(
            "workbenchIngress.networkPolicy",
            desired,
            observed,
            {"operationNonce": nonce, "temporaryNonceRemoved": False},
        )
        api = Mock(spec=MODULE.Runner)
        with patch.object(MODULE, "live_obj", return_value=drifted):
            with self.assertRaisesRegex(MODULE.ActivationError, "semantic drift"):
                MODULE.remove_operation_nonce_v4(api, "/snapshot", created, nonce)
        api.run.assert_not_called()

    def test_v4_nonce_removal_rejects_rebound_uid_and_nonce_drift_without_patch(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy(); nonce = "6" * 64
        observed = admitted(MODULE.POLICY.with_operation_nonce(desired, nonce), "owned", "70")
        created = MODULE.CreatedV4(
            "workbenchIngress.networkPolicy",
            desired,
            observed,
            {"operationNonce": nonce, "temporaryNonceRemoved": False},
        )
        wrong_uid = admitted(MODULE.POLICY.with_operation_nonce(desired, nonce), "foreign", "71")
        wrong_nonce = admitted(MODULE.POLICY.with_operation_nonce(desired, "5" * 64), "owned", "71")
        for rebound, message in ((wrong_uid, "UID changed"), (wrong_nonce, "ownership mismatch")):
            with self.subTest(message=message):
                api = Mock(spec=MODULE.Runner)
                with patch.object(MODULE, "live_obj", return_value=rebound):
                    with self.assertRaisesRegex(MODULE.ActivationError, message):
                        MODULE.remove_operation_nonce_v4(api, "/snapshot", created, nonce)
                api.run.assert_not_called()

    def test_v4_nonce_removal_controller_churn_is_bounded_to_four_cas_attempts(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy(); nonce = "4" * 64
        observed = admitted(MODULE.POLICY.with_operation_nonce(desired, nonce), "owned", "80")
        created = MODULE.CreatedV4(
            "workbenchIngress.networkPolicy",
            desired,
            observed,
            {"operationNonce": nonce, "temporaryNonceRemoved": False},
        )
        current = [admitted(MODULE.POLICY.with_operation_nonce(desired, nonce), "owned", str(rv)) for rv in range(81, 86)]
        api = Mock(spec=MODULE.Runner)
        api.run.return_value = MODULE.Result(1, "", "The request is invalid")
        with patch.object(MODULE, "live_obj", side_effect=current) as discover, patch.object(MODULE.time, "sleep"):
            with self.assertRaisesRegex(MODULE.ActivationError, "The request is invalid"):
                MODULE.remove_operation_nonce_v4(api, "/snapshot", created, nonce)
        self.assertEqual(discover.call_count, 5)
        self.assertEqual(api.run.call_count, 4)

    def test_v4_transport_uncertainty_without_discovery_stays_unresolved(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy()
        rendered = {"desired": desired, "path": "fixed", "blobSha256": sha()}
        class ServerError(MODULE.Runner):
            def run(self, args, *, input_text=None, timeout=10): return MODULE.Result(1, "", "HTTP 500")
        with patch.object(MODULE, "live_obj", side_effect=MODULE.ActivationError("not readable")):
            with self.assertRaisesRegex(MODULE.TransportUncertainError, "unresolved"):
                MODULE.create_v4(ServerError(), "/tmp/kube", "workbenchIngress.networkPolicy", rendered, "a" * 64)

    def test_v4_uncertain_create_is_boundedly_rediscovered_for_rollback(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy(); nonce = "d" * 64
        rendered = {"desired": desired, "path": "fixed", "blobSha256": sha()}
        observed = admitted(MODULE.POLICY.with_operation_nonce(desired, nonce), "owned", "17")
        with patch.object(MODULE, "get_optional", side_effect=[MODULE.ActivationError("temporary read failure"), observed]), patch.object(MODULE.time, "monotonic", side_effect=[0.0, 0.0, 0.1]), patch.object(MODULE.time, "sleep"):
            recovered = MODULE.rediscover_uncertain_create_v4(Fake(), "/snapshot", "workbenchIngress.networkPolicy", rendered, nonce, 1)
        self.assertIsNotNone(recovered); self.assertEqual(recovered.observed["metadata"]["uid"], "owned")
        self.assertTrue(recovered.receipt["recoveredDuringRollbackEntry"]); self.assertFalse(recovered.receipt["temporaryNonceRemoved"])

    def test_v4_exact_six_target_absence_preflight_is_closed_and_non_adopting(self):
        value = ready_policy()
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            resources = MODULE.POLICY.expected_gateway_resources(value)
            rendered = {
                "gateway.networkPolicy": {"desired": resources["networkPolicy"]},
                "workbenchIngress.networkPolicy": {"desired": MODULE.POLICY.expected_workbench_ingress_network_policy()},
                "gateway.serviceAccount": {"desired": resources["serviceAccount"]},
                "gateway.service": {"desired": resources["service"]},
                "gateway.deployment": {"desired": resources["deployment"]},
                "gateway.ingress": {"desired": resources["ingress"]},
            }
        with patch.object(MODULE, "get_optional", return_value=None) as lookup:
            receipt = MODULE.exact_absence_preflight_v4(Fake(), "/snapshot", rendered)
        self.assertEqual(receipt["status"], "all-six-exact-target-names-absent")
        self.assertEqual(len(receipt["targets"]), 6); self.assertEqual(lookup.call_count, 6)
        occupied = admitted(rendered["gateway.service"]["desired"], "foreign")
        with patch.object(MODULE, "get_optional", side_effect=[None, None, None, None, occupied, None]):
            with self.assertRaisesRegex(MODULE.ActivationError, "adoption forbidden"):
                MODULE.exact_absence_preflight_v4(Fake(), "/snapshot", rendered)

    def test_v4_nonce_removal_uses_uid_rv_nonce_cas_before_final_semantics(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy(); nonce = "c" * 64
        observed = admitted(MODULE.POLICY.with_operation_nonce(desired, nonce), "owned", "10")
        created = MODULE.CreatedV4("workbenchIngress.networkPolicy", desired, observed, {"operationNonce": nonce, "temporaryNonceRemoved": False})
        after = admitted(desired, "owned", "11")
        class CasApi(MODULE.Runner):
            def run(self, args, *, input_text=None, timeout=10):
                self.args = args
                return MODULE.Result(out=json.dumps(after))
        api = CasApi()
        with patch.object(MODULE, "live_obj", return_value=observed):
            MODULE.remove_operation_nonce_v4(api, "/snapshot", created, nonce)
        patch_body = json.loads(api.args[api.args.index("-p") + 1])
        self.assertEqual([op["op"] for op in patch_body], ["test", "test", "test", "remove"])
        self.assertEqual(patch_body[0]["value"], "owned"); self.assertEqual(patch_body[1]["value"], "10"); self.assertEqual(patch_body[2]["value"], nonce)
        self.assertTrue(created.receipt["temporaryNonceRemoved"])

    def test_v4_dual_cas_partial_failure_is_rolled_back_to_both_suspended(self):
        gateway = admitted(MODULE.POLICY.gateway_flux_objects(suspended=True)["kustomization"], "g", "10")
        workbench = admitted(MODULE.POLICY.workbench_ingress_flux_objects(suspended=True)["kustomization"], "w", "20")
        active_gateway = admitted(MODULE.POLICY.gateway_flux_objects(suspended=False)["kustomization"], "g", "11")
        source = {"metadata": {"uid": "source-uid", "resourceVersion": "1"}, "status": {"artifact": {"revision": f"main@sha1:{REV}"}}}
        bootstrap = {"owners": {"gateway": {"kustomization": gateway}, "workbenchIngress": {"kustomization": workbench}}, "source": source}
        with patch.object(MODULE, "cas_flux_v4", side_effect=[active_gateway, MODULE.ActivationError("second CAS failed")]):
            with self.assertRaisesRegex(MODULE.ActivationError, "second CAS"):
                MODULE.unsuspend_both_v4(Fake(), "/tmp/kube", policy(), bootstrap)
        current = [active_gateway, workbench]
        suspended_gateway = admitted(MODULE.POLICY.gateway_flux_objects(suspended=True)["kustomization"], "g", "12")
        quiescent = {"gateway": {"uid": "g", "suspended": True}, "workbenchIngress": {"uid": "w", "suspended": True}}
        source_after = {"metadata": {"uid": "source-uid", "resourceVersion": "2"}, "status": {"artifact": {"revision": f"main@sha1:{REV}"}}}
        with patch.object(MODULE, "_target_live", side_effect=current), patch.object(MODULE, "cas_flux_v4", side_effect=[suspended_gateway]) as suspend, patch.object(MODULE, "wait_both_suspended_v4", return_value=quiescent), patch.object(MODULE, "shared_source_revision_v4", return_value=source_after):
            result = MODULE.rollback_v4(Fake(), "/tmp/kube", policy(), [], bootstrap, None, None)
        self.assertEqual(result["status"], "complete")
        self.assertTrue(result["bothKustomizationsSuspended"])
        suspend.assert_called_once()

    def test_v4_flux_cas_removes_health_checks_and_sets_wait_false_without_rbac_widening(self):
        value = policy()
        before = admitted(MODULE.POLICY.gateway_flux_objects(suspended=True)["kustomization"], "g", "10")
        # Model a historical field still present immediately before the CAS.
        before["spec"]["healthChecks"] = [{
            "apiVersion": "apps/v1", "kind": "Deployment",
            "name": MODULE.NAME, "namespace": MODULE.NAMESPACE,
        }]
        after = admitted(MODULE.POLICY.gateway_flux_objects(suspended=False)["kustomization"], "g", "11")

        class CasApi(MODULE.Runner):
            def run(self, args, *, input_text=None, timeout=10):
                self.args = args
                return MODULE.Result(out=json.dumps(after))

        api = CasApi()
        result = MODULE.cas_flux_v4(api, "/snapshot", value, "gateway", before, False)
        patch_body = json.loads(api.args[api.args.index("-p") + 1])
        self.assertEqual(patch_body, {
            "metadata": {"resourceVersion": "10"},
            "spec": {"healthChecks": None, "suspend": False, "wait": False},
        })
        self.assertNotIn("healthChecks", result["spec"])
        self.assertFalse(result["spec"]["wait"])
        self.assertFalse(any(
            "replicasets" in rule.get("resources", [])
            for rule in MODULE.POLICY.gateway_flux_objects()["role"]["rules"]
        ))

    def test_v4_flux_tracking_normalizer_accepts_only_absent_or_one_complete_owner_pair(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy()
        absent = admitted(desired, "owned-policy-uid", "10")
        complete = copy.deepcopy(absent)
        complete["metadata"]["labels"].update(
            MODULE.expected_flux_tracking_labels_v4("workbenchIngress.networkPolicy")
        )
        normalized, state = MODULE.require_flux_tracking_semantics_v4(
            absent, desired, "workbenchIngress.networkPolicy", "absent-or-complete",
        )
        self.assertEqual(state, "absent")
        self.assertEqual(normalized, MODULE.POLICY.normalize_kubernetes_object(desired))
        normalized, state = MODULE.require_flux_tracking_semantics_v4(
            complete, desired, "workbenchIngress.networkPolicy", "complete",
        )
        self.assertEqual(state, "complete")
        self.assertEqual(normalized, MODULE.POLICY.normalize_kubernetes_object(desired))

        variants = {}
        partial = copy.deepcopy(absent)
        partial["metadata"]["labels"]["kustomize.toolkit.fluxcd.io/name"] = MODULE.WORKBENCH_POLICY_NAME
        variants["partial"] = partial
        wrong_owner = copy.deepcopy(complete)
        wrong_owner["metadata"]["labels"]["kustomize.toolkit.fluxcd.io/name"] = MODULE.NAME
        variants["wrong-owner"] = wrong_owner
        wrong_namespace = copy.deepcopy(complete)
        wrong_namespace["metadata"]["labels"]["kustomize.toolkit.fluxcd.io/namespace"] = "foreign"
        variants["wrong-namespace"] = wrong_namespace
        widened = copy.deepcopy(complete)
        widened["metadata"]["labels"]["unexpected.example/label"] = "true"
        variants["extra"] = widened
        for label, live in variants.items():
            with self.subTest(label=label), self.assertRaisesRegex(
                MODULE.ActivationError, "partial, wrong, or widened",
            ):
                MODULE.require_flux_tracking_semantics_v4(
                    live, desired, "workbenchIngress.networkPolicy", "absent-or-complete",
                )

    def test_v4_final_semantics_requires_and_records_the_exact_complete_flux_pair(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy()
        observed = admitted(desired, "owned-policy-uid", "10")
        created = MODULE.CreatedV4(
            "workbenchIngress.networkPolicy", desired, observed,
            {"operationNonce": "a" * 64, "temporaryNonceRemoved": True},
        )
        live = admitted(desired, "owned-policy-uid", "11")
        with patch.object(MODULE, "live_obj", return_value=live), self.assertRaisesRegex(
            MODULE.ActivationError, "must be complete",
        ):
            MODULE.semantic_postconditions_v4(Fake(), "/snapshot", [created])
        live["metadata"]["labels"].update(
            MODULE.expected_flux_tracking_labels_v4("workbenchIngress.networkPolicy")
        )
        with patch.object(MODULE, "live_obj", return_value=live):
            receipt = MODULE.semantic_postconditions_v4(Fake(), "/snapshot", [created])
        self.assertEqual(
            receipt["workbenchIngress.networkPolicy"]["fluxTrackingLabels"],
            MODULE.RUN29_FLUX_TRACKING_LABELS["workbenchIngress"],
        )
        self.assertEqual(
            receipt["workbenchIngress.networkPolicy"]["semanticSha256"],
            MODULE.POLICY.semantic_sha256(desired),
        )

    def test_v4_normal_rollback_accepts_only_no_flux_pair_or_the_complete_correct_pair(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy()
        for state in ("absent", "complete"):
            live = admitted(desired, "owned-policy-uid", "10")
            if state == "complete":
                live["metadata"]["labels"].update(
                    MODULE.expected_flux_tracking_labels_v4("workbenchIngress.networkPolicy")
                )
            created = MODULE.CreatedV4(
                "workbenchIngress.networkPolicy", desired, admitted(desired, "owned-policy-uid", "9"),
                {"uid": "owned-policy-uid", "operationNonce": "a" * 64, "temporaryNonceRemoved": True},
            )
            with self.subTest(state=state), patch.object(
                MODULE, "get_optional", side_effect=[live, None]
            ), patch.object(MODULE, "raw_delete") as delete:
                result = MODULE.delete_with_preconditions_v4(
                    Fake(), "/snapshot", created, 1, Mock(),
                )
            self.assertTrue(result["absent"])
            delete.assert_called_once()

    def test_v4_rollback_accepts_already_absent_owned_object(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy(); created = MODULE.CreatedV4("workbenchIngress.networkPolicy", desired, admitted(desired), {"uid": "owned-uid", "operationNonce": "a" * 64, "temporaryNonceRemoved": True})
        with patch.object(MODULE, "get_optional", return_value=None), patch.object(MODULE, "raw_delete") as delete:
            result = MODULE.delete_with_preconditions_v4(Fake(), "/tmp/kube", created, 1)
        self.assertTrue(result["absent"]); self.assertTrue(result["alreadyAbsent"]); delete.assert_not_called()

    def test_v4_rollback_reports_finalizers_without_removing_them(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy(); current = admitted(desired)
        terminating = admitted(desired); terminating["metadata"] |= {"deletionTimestamp": "2026-01-01T00:00:00Z", "finalizers": ["example.test/hold"]}
        created = MODULE.CreatedV4("workbenchIngress.networkPolicy", desired, current, {"uid": "owned-uid", "operationNonce": "a" * 64, "temporaryNonceRemoved": True})
        snapshot = Mock()
        with patch.object(MODULE, "get_optional", side_effect=[current, terminating]), patch.object(MODULE, "raw_delete") as delete:
            with self.assertRaisesRegex(MODULE.ActivationError, "blocked by finalizers"):
                MODULE.delete_with_preconditions_v4(Fake(), "/tmp/kube", created, 1, snapshot)
        called_snapshot, path, payload, _timeout = delete.call_args.args
        self.assertIs(called_snapshot, snapshot)
        self.assertIn(f"/namespaces/{MODULE.WORKBENCH_NAMESPACE}/networkpolicies/{MODULE.WORKBENCH_POLICY_NAME}", path)
        self.assertIn('"uid":"owned-uid"', payload); self.assertIn('"resourceVersion":"10"', payload)

    def test_v4_deployment_rollback_is_foreground_and_proves_runtime_dependents_absent(self):
        value = ready_policy()
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            desired = MODULE.POLICY.expected_gateway_resources(value)["deployment"]
        current = admitted(desired, "deployment-uid", "31")
        created = MODULE.CreatedV4("gateway.deployment", desired, current, {"uid": "deployment-uid", "operationNonce": "a" * 64, "temporaryNonceRemoved": True})
        snapshot = Mock()
        with patch.object(MODULE, "get_optional", side_effect=[current, None]), patch.object(MODULE, "raw_delete") as delete:
            receipt = MODULE.delete_with_preconditions_v4(Fake(), "/tmp/kube", created, 1, snapshot)
        called_snapshot, _path, raw_payload, _timeout = delete.call_args.args
        self.assertIs(called_snapshot, snapshot)
        payload = json.loads(raw_payload)
        self.assertEqual(payload["propagationPolicy"], "Foreground")
        self.assertEqual(payload["preconditions"], {"uid": "deployment-uid", "resourceVersion": "31"})
        self.assertTrue(receipt["foregroundPropagation"])
        with patch.object(MODULE, "checked", side_effect=[json.dumps({"items": []}), json.dumps({"items": []})]) as query:
            dependents = MODULE.deployment_dependents_absent_v4(Fake(), "/tmp/kube")
        self.assertEqual(dependents["status"], "deployment-foreground-dependents-absent")
        self.assertEqual(query.call_count, 2)

    def test_v4_unresolved_deployment_retains_gateway_isolation_until_runtime_absence(self):
        value = ready_policy()
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            resources = MODULE.POLICY.expected_gateway_resources(value)
        network_policy = MODULE.CreatedV4(
            "gateway.networkPolicy",
            resources["networkPolicy"],
            admitted(resources["networkPolicy"], "network-policy-uid", "20"),
            {"uid": "network-policy-uid", "operationNonce": "a" * 64, "temporaryNonceRemoved": True},
        )
        unresolved_live = admitted(resources["deployment"], "unbound-deployment-uid", "30")
        rendered = {"gateway.deployment": {"desired": resources["deployment"]}}
        # `None` models the definite-409 path, where no-adopt deliberately
        # clears `uncertain` but the racing Deployment is still not ours.
        for uncertain in ("gateway.deployment", None):
            with self.subTest(uncertain=uncertain), patch.object(MODULE, "get_optional", return_value=unresolved_live), patch.object(MODULE, "delete_with_preconditions_v4") as delete:
                result = MODULE.rollback_v4(
                    Fake(), "/tmp/kube", value, [network_policy], None, None,
                    uncertain, rendered=rendered,
                )
            self.assertEqual(result["status"], "incomplete")
            self.assertTrue(any("isolation retained" in error for error in result["errors"]))
            delete.assert_not_called()

    def test_v4_flux_ready_requires_generation_and_exact_revision(self):
        desired = MODULE.POLICY.gateway_flux_objects(suspended=False)["kustomization"]
        live = admitted(desired, "g", "11"); live["metadata"]["generation"] = 7
        live["status"] = {"observedGeneration": 7, "lastAppliedRevision": f"main@sha1:{REV}", "lastAttemptedRevision": f"main@sha1:{REV}", "conditions": [{"type": "Ready", "status": "True", "observedGeneration": 7}]}
        self.assertTrue(MODULE.flux_ready_v4(live, "gateway", "g", REV)["ready"])
        live["status"]["observedGeneration"] = 6
        with self.assertRaisesRegex(MODULE.ActivationError, "observedGeneration"):
            MODULE.flux_ready_v4(live, "gateway", "g", REV)
        live["status"]["observedGeneration"] = 7
        live["spec"]["healthChecks"] = []
        with self.assertRaisesRegex(MODULE.ActivationError, "active Kustomization semantics"):
            MODULE.flux_ready_v4(live, "gateway", "g", REV)

    def test_v4_final_flux_success_proof_rereads_both_reconcilers_and_source(self):
        gateway = admitted(MODULE.POLICY.gateway_flux_objects(suspended=False)["kustomization"], "g", "31")
        workbench = admitted(MODULE.POLICY.workbench_ingress_flux_objects(suspended=False)["kustomization"], "w", "41")
        for item in (gateway, workbench):
            item["metadata"]["generation"] = 2
            item["status"] = {
                "observedGeneration": 2,
                "lastAppliedRevision": f"main@sha1:{REV}",
                "lastAttemptedRevision": f"main@sha1:{REV}",
                "conditions": [{"type": "Ready", "status": "True", "observedGeneration": 2}],
            }
        source = {
            "metadata": {"uid": "source-uid", "resourceVersion": "51"},
            "status": {"artifact": {"revision": f"main@sha1:{REV}"}},
        }
        bootstrap = {
            "owners": {
                "gateway": {"kustomization": {"metadata": {"uid": "g"}}},
                "workbenchIngress": {"kustomization": {"metadata": {"uid": "w"}}},
            },
            "source": {"metadata": {"uid": "source-uid"}},
        }
        with patch.object(MODULE, "_target_live", side_effect=[gateway, workbench]) as read_flux, patch.object(
            MODULE, "shared_source_revision_v4", return_value=source,
        ) as read_source:
            proof = MODULE.final_flux_success_proof_v4(
                Fake(), "/snapshot", policy(), bootstrap, REV,
            )
        self.assertEqual(set(proof["ready"]), {"gateway", "workbenchIngress"})
        self.assertEqual(proof["source"]["uid"], "source-uid")
        self.assertEqual(read_flux.call_count, 2)
        read_source.assert_called_once()

        stale = copy.deepcopy(gateway)
        stale["status"]["lastAppliedRevision"] = f"main@sha1:{'f' * 40}"
        with patch.object(MODULE, "_target_live", side_effect=[stale, workbench]), patch.object(
            MODULE, "shared_source_revision_v4", return_value=source,
        ), self.assertRaisesRegex(MODULE.ActivationError, "applied revision"):
            MODULE.final_flux_success_proof_v4(Fake(), "/snapshot", policy(), bootstrap, REV)

    def test_v4_suspended_flux_accepts_never_observed_and_rejects_any_active_reconcile(self):
        desired = admitted(MODULE.POLICY.gateway_flux_objects(suspended=True)["kustomization"], "g", "11")
        desired["metadata"]["generation"] = 8
        desired["status"] = {"observedGeneration": 8, "conditions": [{"type": "Reconciling", "status": "False", "observedGeneration": 8}]}
        self.assertTrue(MODULE._flux_suspended_and_quiescent_v4(desired, "gateway", "g")["suspended"])
        active = copy.deepcopy(desired); active["status"]["conditions"][0]["status"] = "True"
        with self.assertRaisesRegex(MODULE.ActivationError, "still Reconciling"):
            MODULE._flux_suspended_and_quiescent_v4(active, "gateway", "g")
        never_observed = copy.deepcopy(desired); never_observed["status"] = {"observedGeneration": -1, "conditions": []}
        receipt = MODULE._flux_suspended_and_quiescent_v4(never_observed, "gateway", "g")
        self.assertEqual(receipt["observedGeneration"], -1)
        stale_active = copy.deepcopy(never_observed)
        stale_active["status"]["conditions"] = [{"type": "Reconciling", "status": "True", "observedGeneration": 7}]
        with self.assertRaisesRegex(MODULE.ActivationError, "still Reconciling"):
            MODULE._flux_suspended_and_quiescent_v4(stale_active, "gateway", "g")
        future = copy.deepcopy(never_observed); future["status"]["observedGeneration"] = 9
        with self.assertRaisesRegex(MODULE.ActivationError, "observedGeneration invalid"):
            MODULE._flux_suspended_and_quiescent_v4(future, "gateway", "g")
        boolean_generation = copy.deepcopy(never_observed); boolean_generation["metadata"]["generation"] = True
        with self.assertRaisesRegex(MODULE.ActivationError, "observedGeneration invalid"):
            MODULE._flux_suspended_and_quiescent_v4(boolean_generation, "gateway", "g")

    def test_v4_incident_recovery_requires_exact_never_reconciled_generation_one_flux(self):
        gateway = admitted(MODULE.POLICY.gateway_flux_objects(suspended=True)["kustomization"], "g", "10")
        workbench = admitted(MODULE.POLICY.workbench_ingress_flux_objects(suspended=True)["kustomization"], "w", "20")
        for current in (gateway, workbench):
            current["metadata"]["generation"] = 1
            current["status"] = {"observedGeneration": -1, "conditions": []}
        bootstrap = {"owners": {
            "gateway": {"kustomization": gateway},
            "workbenchIngress": {"kustomization": workbench},
        }}
        result = MODULE.recovery_flux_preflight_v4(bootstrap)
        self.assertEqual(result["gateway"]["observedGeneration"], -1)
        for generation, observed in ((2, -1), (1, 0)):
            with self.subTest(generation=generation, observed=observed):
                drifted = copy.deepcopy(bootstrap)
                current = drifted["owners"]["gateway"]["kustomization"]
                current["metadata"]["generation"] = generation
                current["status"]["observedGeneration"] = observed
                with self.assertRaisesRegex(MODULE.ActivationError, "exact dormant incident state"):
                    MODULE.recovery_flux_preflight_v4(drifted)

    def test_v4_run29_incident_flux_profile_binds_exact_suspended_generation_three_failure_state(self):
        revision = MODULE.RUN29_FAILED_ACTIVATION_ORIGIN_REVISION
        gateway = admitted(MODULE.POLICY.gateway_flux_objects(suspended=True)["kustomization"], "gateway-flux-uid", "16837627")
        gateway["metadata"]["generation"] = 3
        gateway["status"] = {
            "observedGeneration": -1,
            "lastAttemptedRevision": f"main@sha1:{revision}",
            "conditions": [
                {"type": "Reconciling", "status": "True", "observedGeneration": 3, "reason": "ProgressingWithRetry", "message": f"Running health checks for revision main@sha1:{revision} with a timeout of 2m0s"},
                {"type": "Ready", "status": "False", "observedGeneration": 2, "reason": "HealthCheckFailed", "message": MODULE.RUN29_GATEWAY_RBAC_FAILURE},
                {"type": "Healthy", "status": "False", "observedGeneration": 2, "reason": "HealthCheckFailed", "message": MODULE.RUN29_GATEWAY_RBAC_FAILURE},
            ],
        }
        workbench = admitted(MODULE.POLICY.workbench_ingress_flux_objects(suspended=True)["kustomization"], "workbench-flux-uid", "16837661")
        workbench["metadata"]["generation"] = 3
        workbench["status"] = {
            "observedGeneration": 3,
            "lastAppliedRevision": f"main@sha1:{revision}",
            "lastAttemptedRevision": f"main@sha1:{revision}",
            "conditions": [
                {"type": "Ready", "status": "True", "observedGeneration": 2, "reason": "ReconciliationSucceeded", "message": f"Applied revision: main@sha1:{revision}"},
                {"type": "Healthy", "status": "True", "observedGeneration": 2, "reason": "Succeeded", "message": "Health check passed in 24ms"},
            ],
        }
        gateway_projection = MODULE.run29_recovery_suspended_flux_state_v4(gateway, "gateway", "gateway-flux-uid")
        workbench_projection = MODULE.run29_recovery_suspended_flux_state_v4(workbench, "workbenchIngress", "workbench-flux-uid")
        self.assertEqual(gateway_projection["incidentState"], "suspended-after-exact-rbac-healthcheck-failure")
        self.assertEqual(workbench_projection["incidentState"], "suspended-after-successful-run29-reconcile")
        self.assertEqual(gateway_projection["generation"], workbench_projection["generation"])
        drifted = copy.deepcopy(gateway)
        drifted["status"]["conditions"][1]["message"] = "different failure"
        with self.assertRaisesRegex(MODULE.ActivationError, "exact RBAC failure"):
            MODULE.run29_recovery_suspended_flux_state_v4(drifted, "gateway", "gateway-flux-uid")

    def test_v4_run29_incident_flux_preflight_requires_two_second_exact_object_and_resource_version_stability(self):
        revision = MODULE.RUN29_FAILED_ACTIVATION_ORIGIN_REVISION
        gateway = admitted(MODULE.POLICY.gateway_flux_objects(suspended=True)["kustomization"], "gateway-flux-uid", "16837627")
        gateway["metadata"]["generation"] = 3
        gateway["status"] = {
            "observedGeneration": -1,
            "lastAttemptedRevision": f"main@sha1:{revision}",
            "conditions": [
                {"type": "Reconciling", "status": "True", "observedGeneration": 3, "reason": "ProgressingWithRetry", "message": f"Running health checks for revision main@sha1:{revision} with a timeout of 2m0s"},
                {"type": "Ready", "status": "False", "observedGeneration": 2, "reason": "HealthCheckFailed", "message": MODULE.RUN29_GATEWAY_RBAC_FAILURE},
                {"type": "Healthy", "status": "False", "observedGeneration": 2, "reason": "HealthCheckFailed", "message": MODULE.RUN29_GATEWAY_RBAC_FAILURE},
            ],
        }
        workbench = admitted(MODULE.POLICY.workbench_ingress_flux_objects(suspended=True)["kustomization"], "workbench-flux-uid", "16837661")
        workbench["metadata"]["generation"] = 3
        workbench["status"] = {
            "observedGeneration": 3,
            "lastAppliedRevision": f"main@sha1:{revision}",
            "lastAttemptedRevision": f"main@sha1:{revision}",
            "conditions": [
                {"type": "Ready", "status": "True", "observedGeneration": 2, "reason": "ReconciliationSucceeded", "message": f"Applied revision: main@sha1:{revision}"},
                {"type": "Healthy", "status": "True", "observedGeneration": 2, "reason": "Succeeded", "message": "Health check passed in 24ms"},
            ],
        }
        bootstrap = {"owners": {
            "gateway": {"kustomization": gateway},
            "workbenchIngress": {"kustomization": workbench},
        }}
        value = ready_policy(); incident = run29_recovery_incident_ownership()
        with (
            patch.object(MODULE, "_target_live", side_effect=[copy.deepcopy(gateway), copy.deepcopy(workbench)]),
            patch.object(MODULE.time, "sleep") as sleep,
        ):
            result = MODULE.recovery_flux_preflight_v4(
                bootstrap,
                r=Fake(),
                kubeconfig="/snapshot",
                p=value,
                incident=incident,
            )
        sleep.assert_called_once_with(value["httpBoundary"]["timeoutsSeconds"]["rollbackAbsenceQuiet"])
        self.assertTrue(result["gateway"]["objectStableForQuietInterval"])
        self.assertEqual(result["workbenchIngress"]["quietSeconds"], 2)
        drifted = copy.deepcopy(gateway); drifted["metadata"]["resourceVersion"] = "16837628"
        with (
            patch.object(MODULE, "_target_live", side_effect=[drifted, copy.deepcopy(workbench)]),
            patch.object(MODULE.time, "sleep"),
            self.assertRaisesRegex(MODULE.ActivationError, "object or resourceVersion changed"),
        ):
            MODULE.recovery_flux_preflight_v4(
                bootstrap,
                r=Fake(),
                kubeconfig="/snapshot",
                p=value,
                incident=incident,
            )

    def test_v4_wait_both_suspended_requires_full_protected_suspended_semantics(self):
        value = ready_policy()
        gateway = admitted(MODULE.POLICY.gateway_flux_objects(suspended=True)["kustomization"], "g", "10")
        workbench = admitted(MODULE.POLICY.workbench_ingress_flux_objects(suspended=True)["kustomization"], "w", "20")
        for current in (gateway, workbench):
            current["metadata"]["generation"] = 1
            current["status"] = {"observedGeneration": -1, "conditions": []}
        bootstrap = {"owners": {"gateway": {"kustomization": gateway}, "workbenchIngress": {"kustomization": workbench}}}
        with patch.object(MODULE, "_target_live", side_effect=[gateway, workbench]):
            result = MODULE.wait_both_suspended_v4(Fake(), "/snapshot", value, bootstrap, MODULE.time.monotonic() + 10.0)
        self.assertEqual(result["gateway"]["observedGeneration"], -1)
        drifted = copy.deepcopy(gateway); drifted["spec"]["path"] = "./foreign"
        with patch.object(MODULE, "_target_live", return_value=drifted):
            with self.assertRaisesRegex(MODULE.ActivationError, "suspended semantics"):
                MODULE.wait_both_suspended_v4(Fake(), "/snapshot", value, bootstrap, MODULE.time.monotonic() + 10.0)

    def test_v4_rollback_absence_requires_all_six_names_quiet_and_rejects_foreign_uid(self):
        rendered = {f"item-{index}": {"desired": {"kind": "Service", "metadata": {"namespace": "ns", "name": f"name-{index}"}}} for index in range(6)}
        owned = {name: f"uid-{index}" for index, name in enumerate(sorted(rendered))}
        with patch.object(MODULE, "get_optional", return_value=None), patch.object(MODULE.time, "monotonic", side_effect=[0.0, 0.0, 0.1, 0.1]), patch.object(MODULE.time, "sleep"):
            receipt = MODULE._all_targets_absent_quiet_v4(Fake(), "/snapshot", rendered, owned, 10.0, 0.05, 0.01)
        self.assertEqual(receipt["status"], "all-six-names-absent-for-quiet-interval")
        foreign = {"metadata": {"uid": "foreign"}}
        with patch.object(MODULE, "get_optional", side_effect=[foreign]), patch.object(MODULE.time, "monotonic", return_value=0.0):
            with self.assertRaisesRegex(MODULE.ActivationError, "unowned UID"):
                MODULE._all_targets_absent_quiet_v4(Fake(), "/snapshot", rendered, owned, 10.0, 1.0, 0.1)

    def test_v4_normalizer_ignores_only_real_deployment_revision_annotation(self):
        value = ready_policy()
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            desired = MODULE.POLICY.expected_gateway_resources(value)["deployment"]
        live = admitted(desired, "deployment-uid", "101")
        live["metadata"] |= {"generation": 4, "annotations": {"deployment.kubernetes.io/revision": "7"}}
        live["status"] = {"observedGeneration": 4}
        MODULE.POLICY.require_semantically_equal(live, desired, "real Deployment fixture")
        malformed = copy.deepcopy(live); malformed["metadata"]["annotations"]["deployment.kubernetes.io/revision"] = "latest"
        with self.assertRaisesRegex(MODULE.POLICY.PolicyError, "semantic drift"):
            MODULE.POLICY.require_semantically_equal(malformed, desired, "malformed revision")
        service = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "s", "namespace": "n", "annotations": {"deployment.kubernetes.io/revision": "7"}}, "spec": {}}
        normalized = MODULE.POLICY.normalize_kubernetes_object(service)
        self.assertIn("deployment.kubernetes.io/revision", normalized["metadata"]["annotations"])

    def test_v4_fixed_timeouts_fail_closed(self):
        class TimedOut(MODULE.Runner):
            def run(self, args, *, input_text=None): return MODULE.Result(124, "", "timeout after 30s")
        with self.assertRaises(MODULE.TransportUncertainError):
            MODULE.checked(TimedOut(), ["curl"], "bounded request")
        with patch.object(MODULE.time, "monotonic", side_effect=[0, 121]):
            with self.assertRaisesRegex(MODULE.ActivationError, "total timeout"):
                MODULE.route_matrix_v4(Fake(), policy())

    def test_v4_route_matrix_is_proxy_free_closed_and_checks_bodies_cors_and_deadline(self):
        value = policy(); origin = value["endpoints"]["browserOrigin"]; prefix = value["httpBoundary"]["prefix"]
        cors = {"access-control-allow-origin": origin, "access-control-allow-credentials": "true", "vary": "Origin"}
        status_body = {"available": True, "active": False, "walletAddress": None, "label": "Staging-Testteilnahme – keine Bürgerverifikation, kein Stimmrecht", "scope": None, "authority": "none"}
        method_denied = {
            "status": 405,
            "headers": {"cache-control": "no-cache", "connection": "close", "content-length": "147", "content-type": "text/html"},
            "body": "<html><body><h1>405 Method Not Allowed</h1>\nA request was made of a resource using a request method not supported by that resource.\n</body></html>\n",
        }
        not_found = {
            "status": 404,
            "headers": {"cache-control": "no-cache", "connection": "close", "content-length": "83", "content-type": "text/html"},
            "body": "<html><body><h1>404 Not Found</h1>\nThe resource could not be found.\n</body></html>\n",
        }
        def response(request_origin, method, path, headers, body, timeout):
            self.assertEqual(request_origin, origin); self.assertEqual(timeout, 10)
            if method == "GET" and path == prefix + "/status": return {"status": 200, "headers": cors | {"content-type": "application/json; charset=utf-8"}, "body": json.dumps(status_body)}
            if method == "OPTIONS" and path in MODULE.POLICY.ROUTES:
                preflight = cors | {"access-control-allow-methods": "GET" if path.endswith("/status") else "POST", "access-control-allow-headers": "content-type", "access-control-max-age": "600"}
                return {"status": 204, "headers": preflight, "body": ""}
            if method == "POST" and path in MODULE.POLICY.POST_ROUTES:
                if headers.get("Origin") == "https://attacker.invalid": return {"status": 403, "headers": {"content-type": "application/json"}, "body": '{"error":"origin_forbidden"}'}
                status, error = ((401, "admission_invalid") if path.endswith("/challenge") else (401, "challenge_invalid") if path.endswith("/session") else (401, "session_required"))
                return {"status": status, "headers": cors | {"content-type": "application/json"}, "body": json.dumps({"error": error})}
            if (method, path) in [("POST", prefix + "/status"), *[("GET", item) for item in MODULE.POLICY.POST_ROUTES], ("HEAD", prefix + "/status"), ("DELETE", prefix + "/status")]:
                denied = copy.deepcopy(method_denied)
                if method == "HEAD": denied["body"] = ""
                return denied
            if path == prefix + "/status?unexpected=1": return {"status": 404, "headers": {"content-type": "application/json"}, "body": '{"error":"not_found"}'}
            return copy.deepcopy(not_found)
        with patch.object(MODULE, "_route_request_v4", side_effect=response) as request:
            receipt = MODULE.route_matrix_v4(Fake(), value)
        expected_count = len(MODULE.POLICY.ROUTE_EXPECTATIONS)
        self.assertEqual(len(receipt), expected_count); self.assertEqual(request.call_count, expected_count)
        for path in (
            prefix + "/promote-source-post",
            prefix + "/sign-topic-suggestion",
        ):
            self.assertIn(
                {"case": "preflight", "method": "OPTIONS", "path": path, "status": 204},
                [{key: item[key] for key in ("case", "method", "path", "status")} for item in receipt],
            )
            self.assertIn(
                {"case": "unauthenticated-post", "method": "POST", "path": path, "status": 401},
                [{key: item[key] for key in ("case", "method", "path", "status")} for item in receipt],
            )
            self.assertIn(
                {"case": "method-denied", "method": "GET", "path": path, "status": 405},
                [{key: item[key] for key in ("case", "method", "path", "status")} for item in receipt],
            )
        with patch.object(MODULE, "_route_request_v4", return_value={"status": 200, "headers": cors | {"content-type": "application/json"}, "body": json.dumps(status_body)}), patch.object(MODULE.time, "monotonic", side_effect=[0, 0, 121]):
            with self.assertRaisesRegex(MODULE.ActivationError, "after request"):
                MODULE.route_matrix_v4(Fake(), value)

    def test_v4_route_matrix_waits_for_temporary_status_404_then_verifies_every_route(self):
        value = policy(); origin = value["endpoints"]["browserOrigin"]; prefix = value["httpBoundary"]["prefix"]
        cors = {"access-control-allow-origin": origin, "access-control-allow-credentials": "true", "vary": "Origin"}
        status_body = MODULE.expected_participant_http_status_v4()
        method_denied = {
            "status": 405,
            "headers": {"cache-control": "no-cache", "connection": "close", "content-length": "147", "content-type": "text/html"},
            "body": "<html><body><h1>405 Method Not Allowed</h1>\nA request was made of a resource using a request method not supported by that resource.\n</body></html>\n",
        }
        not_found = {
            "status": 404,
            "headers": {"cache-control": "no-cache", "connection": "close", "content-length": "83", "content-type": "text/html"},
            "body": "<html><body><h1>404 Not Found</h1>\nThe resource could not be found.\n</body></html>\n",
        }
        status_attempts = 0

        def response(request_origin, method, path, headers, body, timeout):
            nonlocal status_attempts
            self.assertEqual(request_origin, origin); self.assertEqual(timeout, 10)
            if method == "GET" and path == prefix + "/status":
                status_attempts += 1
                if status_attempts == 1:
                    return {"status": 404, "headers": {"content-type": "text/html"}, "body": "not found"}
                return {"status": 200, "headers": cors | {"content-type": "application/json"}, "body": json.dumps(status_body)}
            if method == "OPTIONS" and path in MODULE.POLICY.ROUTES:
                preflight = cors | {"access-control-allow-methods": "GET" if path.endswith("/status") else "POST", "access-control-allow-headers": "content-type", "access-control-max-age": "600"}
                return {"status": 204, "headers": preflight, "body": ""}
            if method == "POST" and path in MODULE.POLICY.POST_ROUTES:
                if headers.get("Origin") == "https://attacker.invalid": return {"status": 403, "headers": {"content-type": "application/json"}, "body": '{"error":"origin_forbidden"}'}
                status, error = ((401, "admission_invalid") if path.endswith("/challenge") else (401, "challenge_invalid") if path.endswith("/session") else (401, "session_required"))
                return {"status": status, "headers": cors | {"content-type": "application/json"}, "body": json.dumps({"error": error})}
            if (method, path) in [("POST", prefix + "/status"), *[("GET", item) for item in MODULE.POLICY.POST_ROUTES], ("HEAD", prefix + "/status"), ("DELETE", prefix + "/status")]:
                denied = copy.deepcopy(method_denied)
                if method == "HEAD": denied["body"] = ""
                return denied
            if path == prefix + "/status?unexpected=1": return {"status": 404, "headers": {"content-type": "application/json"}, "body": '{"error":"not_found"}'}
            return copy.deepcopy(not_found)

        with patch.object(MODULE, "_route_request_v4", side_effect=response) as request, patch.object(MODULE.time, "sleep") as sleep:
            receipt = MODULE.route_matrix_v4(Fake(), value)
        self.assertEqual(receipt, value["httpBoundary"]["expectations"])
        self.assertEqual(status_attempts, 2)
        self.assertEqual(request.call_count, len(MODULE.POLICY.ROUTE_EXPECTATIONS) + 1)
        sleep.assert_called_once_with(MODULE.PUBLIC_ROUTE_PROPAGATION_POLL_SECONDS)

    def test_v4_route_matrix_temporary_status_404_is_bounded_and_reports_only_safe_evidence(self):
        value = policy()
        not_routed = {"status": 404, "headers": {"content-type": "text/html"}, "body": "sensitive upstream body"}
        with patch.object(MODULE, "_route_request_v4", return_value=not_routed) as request, patch.object(
            MODULE.time, "monotonic", side_effect=[0.0, 0.0, 0.0, 121.0],
        ), patch.object(MODULE.time, "sleep") as sleep, self.assertRaisesRegex(
            MODULE.ActivationError, r"GET status route propagation timeout: attempts=1 lastStatus=404$",
        ) as raised:
            MODULE.route_matrix_v4(Fake(), value)
        self.assertNotIn("sensitive upstream body", str(raised.exception))
        self.assertEqual(request.call_count, 1)
        sleep.assert_not_called()

    def test_v4_method_denial_binds_haproxy_and_rejects_gateway_or_proxy_drift(self):
        exact = {
            "status": 405,
            "headers": {"cache-control": "no-cache", "connection": "close", "content-length": "147", "content-type": "text/html"},
            "body": MODULE.HAPROXY_METHOD_DENIED_BODY,
        }
        MODULE._require_haproxy_method_denied_v4(exact, "POST", "/status")
        head = exact | {"body": ""}
        MODULE._require_haproxy_method_denied_v4(head, "HEAD", "/status")
        drift_cases = {
            "gateway-json": {
                "status": 405,
                "headers": {
                    "access-control-allow-origin": "https://roebel-web.staging.agentcart.eu",
                    "content-type": "application/json",
                },
                "body": '{"error":"method_not_allowed"}',
            },
            "old-empty-assumption": {"status": 405, "headers": {}, "body": ""},
            "body": exact | {"body": exact["body"] + "drift"},
            "content-length": exact | {"headers": exact["headers"] | {"content-length": "148"}},
            "cache": exact | {"headers": exact["headers"] | {"cache-control": "public"}},
            "connection": exact | {"headers": exact["headers"] | {"connection": "keep-alive"}},
            "cors": exact | {"headers": exact["headers"] | {"vary": "Origin"}},
        }
        for label, observed in drift_cases.items():
            with self.subTest(label=label), self.assertRaises(MODULE.ActivationError):
                MODULE._require_haproxy_method_denied_v4(observed, "POST", "/status")
        with self.assertRaises(MODULE.ActivationError):
            MODULE._require_haproxy_method_denied_v4(exact, "HEAD", "/status")

    def test_v4_not_found_binds_haproxy_and_rejects_gateway_empty_cors_or_shape_drift(self):
        exact = {
            "status": 404,
            "headers": {"cache-control": "no-cache", "connection": "close", "content-length": "83", "content-type": "text/html"},
            "body": "<html><body><h1>404 Not Found</h1>\nThe resource could not be found.\n</body></html>\n",
        }
        for method, path in (
            ("GET", "/api/staging-participant/v1/unknown"),
            ("GET", "/api/staging-participant/v1/status/"),
            ("OPTIONS", "/api/staging-participant/v1/unknown"),
        ):
            with self.subTest(method=method, path=path):
                MODULE._require_haproxy_not_found_v4(exact, method, path)
        drift_cases = {
            "gateway-json": {"status": 404, "headers": {"content-type": "application/json"}, "body": '{"error":"not_found"}'},
            "old-empty-assumption": {"status": 404, "headers": {}, "body": ""},
            "body": exact | {"body": exact["body"] + "drift"},
            "content-length": exact | {"headers": exact["headers"] | {"content-length": "84"}},
            "cache": exact | {"headers": exact["headers"] | {"cache-control": "public"}},
            "connection": exact | {"headers": exact["headers"] | {"connection": "keep-alive"}},
            "content-type": exact | {"headers": exact["headers"] | {"content-type": "text/plain"}},
            "cors": exact | {"headers": exact["headers"] | {"access-control-allow-origin": "https://roebel-web.staging.agentcart.eu"}},
        }
        for label, observed in drift_cases.items():
            with self.subTest(label=label), self.assertRaises(MODULE.ActivationError):
                MODULE._require_haproxy_not_found_v4(observed, "GET", "/unknown")

    def test_v4_route_matrix_does_not_retry_an_invalid_200_contract_or_other_status(self):
        value = policy(); origin = value["endpoints"]["browserOrigin"]
        invalid_cases = (
            {"status": 200, "headers": {"content-type": "application/json"}, "body": "{}"},
            {"status": 503, "headers": {"content-type": "text/plain"}, "body": "unavailable"},
        )
        for observed in invalid_cases:
            with self.subTest(status=observed["status"]), patch.object(
                MODULE, "_route_request_v4", return_value=observed,
            ) as request, patch.object(MODULE.time, "sleep") as sleep, self.assertRaises(MODULE.ActivationError):
                MODULE.route_matrix_v4(Fake(), value)
            self.assertEqual(request.call_count, 1)
            sleep.assert_not_called()

    def test_v4_route_transport_disables_ambient_proxies(self):
        class Headers(dict):
            def items(self): return super().items()
        class Response:
            status = 200; headers = Headers({"content-type": "application/json"})
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def geturl(self): return "https://roebel-web.staging.agentcart.eu/test"
            def read(self, size): return b"{}"
        class Opener:
            def open(self, request, timeout): return Response()
        opener = Opener()
        with patch.object(MODULE.urllib.request, "build_opener", return_value=opener) as build:
            observed = MODULE._route_request_v4("https://roebel-web.staging.agentcart.eu", "GET", "/test", {}, None, 1)
        self.assertEqual(observed["status"], 200)
        proxy = build.call_args.args[0]
        self.assertIsInstance(proxy, MODULE.urllib.request.ProxyHandler); self.assertEqual(proxy.proxies, {})

    def test_v4_protected_executable_blob_drift_is_rejected(self):
        with patch.object(MODULE, "git_blob", return_value=b"definitely-not-the-local-file"):
            with self.assertRaisesRegex(MODULE.ActivationError, "differs from exact Git blob"):
                MODULE.protected_checkout(REV)

    def test_v4_protected_render_semantic_drift_is_rejected(self):
        value = ready_policy()
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            expected = MODULE._expected_render(value); blobs = {}
            for path, (encoding, desired) in expected.items():
                blobs[path] = desired.encode() if encoding == "text" else (json.dumps(desired) + "\n").encode()
            deployment_path = f"{MODULE.POLICY.GATEWAY_ROOT}/deployment.json"
            deployment = json.loads(blobs[deployment_path])
            deployment["spec"]["template"]["spec"]["containers"][0]["securityContext"]["privileged"] = True
            blobs[deployment_path] = (json.dumps(deployment) + "\n").encode()
            with patch.object(MODULE, "git_blob", side_effect=lambda revision, path: blobs[path]):
                with self.assertRaisesRegex(MODULE.ActivationError, "semantic drift"):
                    MODULE.render_v4(REV, value)

    def test_v4_protected_render_admits_only_the_exact_web_civic_projection_source(self):
        value = ready_policy()
        path = f"{MODULE.POLICY.WORKBENCH_INGRESS_ROOT}/networkpolicy.json"
        committed = json.loads((Path(__file__).parents[1] / path).read_text())
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            encoding, expected = MODULE._expected_render(value)[path]
        self.assertEqual(encoding, "object")
        MODULE.POLICY.require_semantically_equal(committed, expected, "committed reciprocal policy")
        sources = expected["spec"]["ingress"][0]["from"]
        self.assertEqual(len(sources), 2)
        self.assertEqual(
            sources[1],
            {
                "namespaceSelector": {
                    "matchLabels": {"kubernetes.io/metadata.name": MODULE.POLICY.GATEWAY_NAMESPACE},
                },
                "podSelector": {"matchLabels": MODULE.POLICY.WEB_PRESENTATION_LABELS},
            },
        )

    def test_v4_db_free_participant_status_preflight_uses_the_same_pod_tunnel_first(self):
        expected = {
            "available": True,
            "active": False,
            "walletAddress": None,
            "label": "Staging-Testteilnahme – keine Bürgerverifikation, kein Stimmrecht",
            "scope": None,
            "authority": "none",
        }
        probe = {
            "transport": "authenticated-kubernetes-pod-port-forward",
            "pod": "gateway-pod-a",
            "loopbackOnly": True,
            "publicIngressUsed": False,
            "serviceProxyUsed": False,
            "redirectsAllowed": False,
            "path": MODULE.POLICY.ROUTES[0],
            "remotePort": MODULE.POLICY.GATEWAY_PORT,
        }
        with patch.object(MODULE, "_pod_port_forward_get_v4", return_value=(json.dumps(expected), probe)) as request:
            result = MODULE.participant_http_status_preflight_v4("/tmp/kube", "gateway-pod-a", 10)
        self.assertEqual(result, probe)
        self.assertEqual(request.call_args.args[1:4], ("gateway-pod-a", MODULE.POLICY.GATEWAY_PORT, MODULE.POLICY.ROUTES[0]))
        with patch.object(MODULE, "_pod_port_forward_get_v4", return_value=(json.dumps(expected | {"authority": "municipal"}), probe)):
            with self.assertRaisesRegex(MODULE.ActivationError, "DB-free participant status contract drift"):
                MODULE.participant_http_status_preflight_v4("/tmp/kube", "gateway-pod-a", 10)

    @patch.object(MODULE, "participant_http_status_preflight_v4", return_value={"status": "ready"})
    def test_v4_internal_status_contract_is_closed_and_not_public_route(self, participant_preflight):
        value = ready_policy(); pins = value["productPins"]
        expected = MODULE.expected_database_status_v4(value)
        selected = {"name": "gateway-pod-a", "uid": "pod-uid", "resourceVersion": "10", "imageId": "docker-pullable://image@" + pins["imageManifestDigest"]}
        runtime = {"readyPodCount": value["runtime"]["replicas"], "pods": [selected]}
        exact_image = pins["imageRepository"] + "@" + pins["imageManifestDigest"]
        current = {
            "metadata": {"uid": "pod-uid", "resourceVersion": "11"},
            "spec": {"containers": [{"image": exact_image}]},
            "status": {"containerStatuses": [{"imageID": selected["imageId"], "ready": True}]},
        }
        probe = {
            "transport": "authenticated-kubernetes-pod-port-forward",
            "pod": selected["name"],
            "loopbackOnly": True,
            "publicIngressUsed": False,
            "serviceProxyUsed": False,
            "redirectsAllowed": False,
            "path": "/status",
            "remotePort": MODULE.POLICY.GATEWAY_PORT,
        }
        with patch.object(MODULE, "checked", return_value="") as authorization, patch.object(MODULE, "_pod_port_forward_get_v4", return_value=(json.dumps(expected), probe)) as request, patch.object(MODULE, "live_obj", return_value=current):
            result = MODULE.database_status_v4(Fake(), "/tmp/kube", value, runtime)
        self.assertEqual(result, valid_database_status(value, image_id=selected["imageId"]))
        participant_preflight.assert_called_with("/tmp/kube", "gateway-pod-a", value["httpBoundary"]["timeoutsSeconds"]["routeRequest"])
        self.assertFalse(result["probe"]["publicIngressUsed"])
        self.assertEqual(result["probe"]["podUid"], "pod-uid")
        self.assertEqual(result["probe"]["podImage"], exact_image)
        self.assertTrue(result["probe"]["podReadyAfter"])
        self.assertEqual(len(authorization.call_args_list), 3)
        self.assertTrue(all("auth" in call.args[1] and "can-i" in call.args[1] for call in authorization.call_args_list))
        args = request.call_args.args
        self.assertEqual(args[1:4], ("gateway-pod-a", MODULE.POLICY.GATEWAY_PORT, "/status"))
        self.assertNotIn(value["endpoints"]["browserOrigin"], json.dumps(request.call_args.args))
        with patch.object(MODULE, "checked", return_value=""), patch.object(MODULE, "_pod_port_forward_get_v4", return_value=(json.dumps(expected | {"extra": True}), probe)), patch.object(MODULE, "live_obj", return_value=current):
            with self.assertRaisesRegex(MODULE.ActivationError, "contract drift"):
                MODULE.database_status_v4(Fake(), "/tmp/kube", value, runtime)
        topic_drifts = {
            "municipalityId": "other-town",
            "sourceConversationTopic": "other-conversation",
            "topicPolicyVersion": "other-topic-v1",
            "topicTracerMigrationSha256": sha("0"),
            "topicTracerDatabaseSchemaSha256": sha("1"),
        }
        for key, drift in topic_drifts.items():
            with self.subTest(kind="drift", key=key), patch.object(MODULE, "checked", return_value=""), patch.object(MODULE, "_pod_port_forward_get_v4", return_value=(json.dumps(expected | {key: drift}), probe)), patch.object(MODULE, "live_obj", return_value=current):
                with self.assertRaisesRegex(MODULE.ActivationError, "contract drift"):
                    MODULE.database_status_v4(Fake(), "/tmp/kube", value, runtime)
        for key in topic_drifts:
            missing = copy.deepcopy(expected); missing.pop(key)
            with self.subTest(kind="missing", key=key), patch.object(MODULE, "checked", return_value=""), patch.object(MODULE, "_pod_port_forward_get_v4", return_value=(json.dumps(missing), probe)), patch.object(MODULE, "live_obj", return_value=current):
                with self.assertRaisesRegex(MODULE.ActivationError, "contract drift"):
                    MODULE.database_status_v4(Fake(), "/tmp/kube", value, runtime)
        for key in topic_drifts:
            extra = expected | {"unexpected" + key[:1].upper() + key[1:]: "unexpected"}
            with self.subTest(kind="extra", key=key), patch.object(MODULE, "checked", return_value=""), patch.object(MODULE, "_pod_port_forward_get_v4", return_value=(json.dumps(extra), probe)), patch.object(MODULE, "live_obj", return_value=current):
                with self.assertRaisesRegex(MODULE.ActivationError, "contract drift"):
                    MODULE.database_status_v4(Fake(), "/tmp/kube", value, runtime)
        changed = copy.deepcopy(current); changed["status"]["containerStatuses"][0]["imageID"] = "docker-pullable://wrong@" + pins["imageManifestDigest"]
        with patch.object(MODULE, "checked", return_value=""), patch.object(MODULE, "_pod_port_forward_get_v4", return_value=(json.dumps(expected), probe)), patch.object(MODULE, "live_obj", return_value=changed):
            with self.assertRaisesRegex(MODULE.ActivationError, "runtime pin changed"):
                MODULE.database_status_v4(Fake(), "/tmp/kube", value, runtime)

    def test_v4_database_status_failure_rechecks_db_free_route_and_classifies_gateway_healthy(self):
        value = ready_policy()
        selected = {"name": "gateway-pod-a", "uid": "pod-uid", "resourceVersion": "10", "imageId": "docker-pullable://image"}
        runtime = {"readyPodCount": value["runtime"]["replicas"], "pods": [selected]}
        with patch.object(MODULE, "checked", return_value=""), patch.object(
            MODULE, "participant_http_status_preflight_v4", side_effect=[{"status": "ready"}, {"status": "ready"}],
        ) as db_free, patch.object(
            MODULE, "_pod_port_forward_get_v4", side_effect=MODULE.ActivationError("internal participant readiness rejected: HTTP 503"),
        ) as db_backed:
            with self.assertRaises(MODULE.ActivationError) as raised:
                MODULE.database_status_v4(Fake(), "/tmp/kube", value, runtime)
        message = str(raised.exception)
        self.assertIn('"classification":"db-backed-failed"', message)
        self.assertIn('"dbFreeBefore":{"kind":"healthy"}', message)
        self.assertIn('"dbFreeAfter":{"kind":"healthy"}', message)
        self.assertIn('"kind":"http-rejected"', message)
        self.assertIn('"status":503', message)
        self.assertEqual(db_backed.call_count, 1)
        self.assertEqual(db_free.call_count, 2)
        self.assertEqual(db_free.call_args_list[1].kwargs, {"retry_timeout": False})

    def test_v4_database_status_failure_classifies_when_db_free_route_also_fails(self):
        value = ready_policy()
        selected = {"name": "gateway-pod-a", "uid": "pod-uid", "resourceVersion": "10", "imageId": "docker-pullable://image"}
        runtime = {"readyPodCount": value["runtime"]["replicas"], "pods": [selected]}
        with patch.object(MODULE, "checked", return_value=""), patch.object(
            MODULE, "participant_http_status_preflight_v4",
            side_effect=[{"status": "ready"}, MODULE.ActivationError("Authorization: Bearer must-not-leak")],
        ) as db_free, patch.object(
            MODULE, "_pod_port_forward_get_v4", side_effect=MODULE.ActivationError("internal participant readiness rejected: HTTP 503"),
        ):
            with self.assertRaises(MODULE.ActivationError) as raised:
                MODULE.database_status_v4(Fake(), "/tmp/kube", value, runtime)
        message = str(raised.exception)
        self.assertIn('"classification":"db-backed-failed"', message)
        self.assertIn('"dbFreeBefore":{"kind":"healthy"}', message)
        self.assertIn('"dbFreeAfter":{"errorType":"ActivationError","kind":"contract-failure"}', message)
        self.assertNotIn("Authorization", message)
        self.assertNotIn("must-not-leak", message)
        self.assertEqual(db_free.call_count, 2)
        self.assertEqual(db_free.call_args_list[1].kwargs, {"retry_timeout": False})

    def test_v4_runtime_pin_requires_exact_ready_pod_cardinality(self):
        value = ready_policy(); image = value["productPins"]["imageRepository"] + "@" + value["productPins"]["imageManifestDigest"]
        def pod(name):
            return {
                "metadata": {"name": name, "uid": name + "-uid", "resourceVersion": "10"},
                "spec": {"containers": [{"image": image}]},
                "status": {"containerStatuses": [{"ready": True, "imageID": "docker-pullable://" + image}]},
            }
        exact = {"items": [pod(f"pod-{index}") for index in range(value["runtime"]["replicas"])]}
        with patch.object(MODULE, "checked", return_value=json.dumps(exact)):
            receipt = MODULE.runtime_image_v4(Fake(), "/tmp/kube", value)
        self.assertEqual(receipt["readyPodCount"], value["runtime"]["replicas"])
        self.assertEqual(len(receipt["pods"]), value["runtime"]["replicas"])
        extra = {"items": exact["items"] + [pod("pod-extra")]}
        with patch.object(MODULE, "checked", return_value=json.dumps(extra)):
            with self.assertRaisesRegex(MODULE.ActivationError, "cardinality"):
                MODULE.runtime_image_v4(Fake(), "/tmp/kube", value)

    def test_v4_port_forward_is_loopback_bounded_and_process_group_cleaned(self):
        class Headers:
            def get_content_type(self): return "application/json"
        class Response:
            status = 200; headers = Headers()
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def geturl(self): return "http://127.0.0.1:41777/status"
            def read(self, size): self.size = size; return b'{"status":"ready"}'
        class Opener:
            def open(self, request, timeout):
                self.request, self.timeout = request, timeout
                return Response()
        class Process:
            pid = 4242
            def __init__(self):
                import os
                read_fd, write_fd = os.pipe(); os.write(write_fd, b"Forwarding from 127.0.0.1:41777 -> 18085\n"); os.close(write_fd)
                self.stdout = os.fdopen(read_fd, "rb", buffering=0)
            def poll(self): return None
        process, opener = Process(), Opener(); binding = Mock(path=Path("/snapshot/kubectl"))
        with patch.object(MODULE, "kubectl_binding_v4", return_value=binding), patch.object(
            MODULE,
            "verified_popen",
            return_value=process,
        ) as spawn, patch.object(MODULE.urllib.request, "build_opener", return_value=opener), patch.object(MODULE, "_terminate_process_group") as cleanup:
            body, receipt = MODULE._pod_port_forward_get_v4("/tmp/kube", "pod-a", 18085, "/status", startup_timeout=1, request_timeout=2)
        self.assertEqual(body, '{"status":"ready"}')
        self.assertTrue(receipt["loopbackOnly"]); self.assertFalse(receipt["publicIngressUsed"]); self.assertFalse(receipt["serviceProxyUsed"])
        command = spawn.call_args.args[1]
        self.assertIn("--address=127.0.0.1", command); self.assertIn("pod/pod-a", command); self.assertIn(":18085", command)
        self.assertFalse({"http_proxy", "https_proxy", "all_proxy", "no_proxy"} & {key.lower() for key in spawn.call_args.kwargs["env"]})
        self.assertEqual(opener.timeout, 2); cleanup.assert_called_once_with(process)

    def test_v4_port_forward_open_timeout_is_classified_with_bounded_process_evidence(self):
        class Process:
            pid = 4242
            def __init__(self):
                read_fd, write_fd = os.pipe()
                os.write(write_fd, b"Forwarding from 127.0.0.1:41777 -> 18085\n")
                os.close(write_fd)
                self.stdout = os.fdopen(read_fd, "rb", buffering=0)
            def poll(self): return None
        class Opener:
            calls = 0
            def open(self, request, timeout):
                self.calls += 1
                raise TimeoutError("untrusted timeout detail")
        processes, opener = [Process(), Process()], Opener()
        with patch.object(MODULE, "kubectl_binding_v4", return_value=Mock(path=Path("/snapshot/kubectl"))), patch.object(
            MODULE, "verified_popen", side_effect=processes,
        ) as spawn, patch.object(MODULE.urllib.request, "build_opener", return_value=opener), patch.object(MODULE, "_terminate_process_group"):
            with self.assertRaises(MODULE.ActivationError) as raised:
                MODULE._pod_port_forward_get_v4("/tmp/kube", "pod-a", 18085, "/status", startup_timeout=1, request_timeout=2)
        message = str(raised.exception)
        self.assertIn('"phase":"open"', message)
        self.assertIn('"requestBudgetSeconds":2', message)
        self.assertIn('"attempts":2', message)
        self.assertIn('"alive":true', message)
        self.assertNotIn("untrusted timeout detail", message)
        self.assertEqual(opener.calls, 2)
        self.assertEqual(spawn.call_count, 2)

    def test_v4_port_forward_timeout_retry_uses_fresh_stream_and_cleans_both_processes(self):
        class Headers:
            def get_content_type(self): return "application/json"
        class Response:
            status = 200; headers = Headers()
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def geturl(self): return "http://127.0.0.1:41778/status"
            def read(self, size): return b'{"status":"ready"}'
        class Process:
            def __init__(self, pid, port):
                self.pid = pid
                read_fd, write_fd = os.pipe()
                os.write(write_fd, f"Forwarding from 127.0.0.1:{port} -> 18085\n".encode())
                os.close(write_fd)
                self.stdout = os.fdopen(read_fd, "rb", buffering=0)
            def poll(self): return None
        class TimedOutOpener:
            def open(self, request, timeout): raise TimeoutError("first stream stalled")
        class SuccessfulOpener:
            def open(self, request, timeout): return Response()
        processes = [Process(4242, 41777), Process(4343, 41778)]
        with patch.object(MODULE, "kubectl_binding_v4", return_value=Mock(path=Path("/snapshot/kubectl"))), patch.object(
            MODULE, "verified_popen", side_effect=processes,
        ) as spawn, patch.object(
            MODULE.urllib.request, "build_opener", side_effect=[TimedOutOpener(), SuccessfulOpener()],
        ), patch.object(MODULE, "_terminate_process_group") as cleanup:
            body, receipt = MODULE._pod_port_forward_get_v4("/tmp/kube", "pod-a", 18085, "/status", startup_timeout=1, request_timeout=2)
        self.assertEqual(body, '{"status":"ready"}')
        self.assertEqual(receipt["path"], "/status")
        self.assertEqual(spawn.call_count, 2)
        self.assertEqual([call.args[0] for call in cleanup.call_args_list], processes)

    def test_v4_port_forward_response_read_timeout_is_classified_and_retried_once(self):
        class Headers:
            def get_content_type(self): return "application/json"
        class Response:
            status = 200; headers = Headers()
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def geturl(self): return "http://127.0.0.1:41777/status"
            def read(self, size): raise TimeoutError("untrusted read detail")
        class Opener:
            calls = 0
            def open(self, request, timeout): self.calls += 1; return Response()
        class Process:
            pid = 4242
            def __init__(self):
                read_fd, write_fd = os.pipe()
                os.write(write_fd, b"Forwarding from 127.0.0.1:41777 -> 18085\n")
                os.close(write_fd)
                self.stdout = os.fdopen(read_fd, "rb", buffering=0)
            def poll(self): return None
        processes, opener = [Process(), Process()], Opener()
        with patch.object(MODULE, "kubectl_binding_v4", return_value=Mock(path=Path("/snapshot/kubectl"))), patch.object(
            MODULE, "verified_popen", side_effect=processes,
        ) as spawn, patch.object(MODULE.urllib.request, "build_opener", return_value=opener), patch.object(MODULE, "_terminate_process_group"):
            with self.assertRaises(MODULE.ActivationError) as raised:
                MODULE._pod_port_forward_get_v4("/tmp/kube", "pod-a", 18085, "/status", startup_timeout=1, request_timeout=2)
        message = str(raised.exception)
        self.assertIn('"phase":"response-read"', message)
        self.assertIn('"requestBudgetSeconds":2', message)
        self.assertIn('"attempts":2', message)
        self.assertNotIn("untrusted read detail", message)
        self.assertEqual(opener.calls, 2)
        self.assertEqual(spawn.call_count, 2)

    def test_v4_port_forward_http_503_fails_closed_without_retry(self):
        class Process:
            pid = 4242
            def __init__(self):
                read_fd, write_fd = os.pipe()
                os.write(write_fd, b"Forwarding from 127.0.0.1:41777 -> 18085\n")
                os.close(write_fd)
                self.stdout = os.fdopen(read_fd, "rb", buffering=0)
            def poll(self): return None
        class Opener:
            calls = 0
            def open(self, request, timeout):
                self.calls += 1
                raise MODULE.urllib.error.HTTPError(request.full_url, 503, "untrusted", None, None)
        process, opener = Process(), Opener()
        with patch.object(MODULE, "kubectl_binding_v4", return_value=Mock(path=Path("/snapshot/kubectl"))), patch.object(
            MODULE, "verified_popen", return_value=process,
        ) as spawn, patch.object(MODULE.urllib.request, "build_opener", return_value=opener), patch.object(MODULE, "_terminate_process_group"):
            with self.assertRaisesRegex(MODULE.ActivationError, "rejected: HTTP 503"):
                MODULE._pod_port_forward_get_v4("/tmp/kube", "pod-a", 18085, "/status", startup_timeout=1, request_timeout=2)
        self.assertEqual(opener.calls, 1)
        self.assertEqual(spawn.call_count, 1)

    def test_v4_port_forward_url_error_is_classified_without_retry_or_detail_leak(self):
        class Process:
            pid = 4242
            def __init__(self):
                read_fd, write_fd = os.pipe()
                os.write(write_fd, b"Forwarding from 127.0.0.1:41777 -> 18085\n")
                os.close(write_fd)
                self.stdout = os.fdopen(read_fd, "rb", buffering=0)
            def poll(self): return None
        class Opener:
            calls = 0
            def open(self, request, timeout):
                self.calls += 1
                raise MODULE.urllib.error.URLError("credential-like untrusted URL detail")
        process, opener = Process(), Opener()
        with patch.object(MODULE, "kubectl_binding_v4", return_value=Mock(path=Path("/snapshot/kubectl"))), patch.object(
            MODULE, "verified_popen", return_value=process,
        ) as spawn, patch.object(MODULE.urllib.request, "build_opener", return_value=opener), patch.object(MODULE, "_terminate_process_group"):
            with self.assertRaises(MODULE.ActivationError) as raised:
                MODULE._pod_port_forward_get_v4("/tmp/kube", "pod-a", 18085, "/status", startup_timeout=1, request_timeout=2)
        message = str(raised.exception)
        self.assertIn('"phase":"open"', message)
        self.assertIn('"attempts":1', message)
        self.assertIn('"errorType":"URLError"', message)
        self.assertNotIn("credential-like", message)
        self.assertEqual(opener.calls, 1)
        self.assertEqual(spawn.call_count, 1)

    def test_v4_port_forward_response_read_os_error_is_classified_without_retry(self):
        class Headers:
            def get_content_type(self): return "application/json"
        class Response:
            status = 200; headers = Headers()
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def geturl(self): return "http://127.0.0.1:41777/status"
            def read(self, size): raise OSError(MODULE.errno.ECONNRESET, "untrusted read detail")
        class Opener:
            calls = 0
            def open(self, request, timeout): self.calls += 1; return Response()
        class Process:
            pid = 4242
            def __init__(self):
                read_fd, write_fd = os.pipe()
                os.write(write_fd, b"Forwarding from 127.0.0.1:41777 -> 18085\n")
                os.close(write_fd)
                self.stdout = os.fdopen(read_fd, "rb", buffering=0)
            def poll(self): return None
        process, opener = Process(), Opener()
        with patch.object(MODULE, "kubectl_binding_v4", return_value=Mock(path=Path("/snapshot/kubectl"))), patch.object(
            MODULE, "verified_popen", return_value=process,
        ) as spawn, patch.object(MODULE.urllib.request, "build_opener", return_value=opener), patch.object(MODULE, "_terminate_process_group"):
            with self.assertRaises(MODULE.ActivationError) as raised:
                MODULE._pod_port_forward_get_v4("/tmp/kube", "pod-a", 18085, "/status", startup_timeout=1, request_timeout=2)
        message = str(raised.exception)
        self.assertIn('"phase":"response-read"', message)
        self.assertIn('"attempts":1', message)
        self.assertIn('"errorType":"ConnectionResetError"', message)
        self.assertNotIn("untrusted read detail", message)
        self.assertEqual(opener.calls, 1)
        self.assertEqual(spawn.call_count, 1)

    def test_v4_port_forward_early_exit_includes_only_sanitized_bounded_output(self):
        class Process:
            pid = 4242
            def __init__(self):
                read_fd, write_fd = os.pipe()
                os.write(write_fd, b"fatal token=do-not-echo\n")
                os.close(write_fd)
                self.stdout = os.fdopen(read_fd, "rb", buffering=0)
            def poll(self): return 7
        process = Process()
        with patch.object(MODULE, "kubectl_binding_v4", return_value=Mock(path=Path("/snapshot/kubectl"))), patch.object(
            MODULE, "verified_popen", return_value=process,
        ), patch.object(MODULE, "_terminate_process_group"):
            with self.assertRaises(MODULE.ActivationError) as raised:
                MODULE._pod_port_forward_get_v4("/tmp/kube", "pod-a", 18085, "/status", startup_timeout=1, request_timeout=2)
        message = str(raised.exception)
        self.assertIn('"phase":"startup"', message)
        self.assertIn('"alive":false', message)
        self.assertIn('"exitCode":7', message)
        self.assertIn("<redacted kubectl output line>", message)
        self.assertNotIn("do-not-echo", message)

    def test_v4_port_forward_output_evidence_is_allowlisted_and_bounded(self):
        output = (
            b"Handling connection for 41777\n" * 1024
            + b"Authorization: Bearer credential-that-must-not-leak, suffix-must-not-leak; end\n"
        )
        sanitized = MODULE._sanitized_port_forward_output_tail_v4(output)
        self.assertLessEqual(len(sanitized), 2048)
        self.assertIn("<redacted kubectl output line>", sanitized)
        self.assertNotIn("Authorization", sanitized)
        self.assertNotIn("Bearer", sanitized)
        self.assertNotIn("credential-that-must-not-leak", sanitized)
        self.assertNotIn("suffix-must-not-leak", sanitized)

    def test_v4_port_forward_continuously_drains_output_flood_after_readiness(self):
        class Headers:
            def get_content_type(self): return "application/json"
        class Response:
            status = 200; headers = Headers()
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def geturl(self): return "http://127.0.0.1:41777/status"
            def read(self, size): return b'{"status":"ready"}'
        class Process:
            pid = 4242
            def __init__(self):
                read_fd, write_fd = os.pipe()
                self.stdout = os.fdopen(read_fd, "rb", buffering=0)
                self.writer_done = MODULE.threading.Event()
                self.writer_error = []
                def write_flood():
                    try:
                        pending = memoryview(
                            b"Forwarding from 127.0.0.1:41777 -> 18085\n" + b"kubectl-noise\n" * 65536
                        )
                        while pending:
                            pending = pending[os.write(write_fd, pending):]
                    except OSError as exc:
                        self.writer_error.append(exc)
                    finally:
                        os.close(write_fd)
                        self.writer_done.set()
                self.writer = MODULE.threading.Thread(target=write_flood, daemon=True)
                self.writer.start()
            def poll(self): return None
        class Opener:
            def __init__(self, process): self.process = process
            def open(self, request, timeout):
                if not self.process.writer_done.wait(timeout=2):
                    raise AssertionError("kubectl output pipe was not drained after readiness")
                return Response()
        process = Process()
        with patch.object(MODULE, "kubectl_binding_v4", return_value=Mock(path=Path("/snapshot/kubectl"))), patch.object(
            MODULE, "verified_popen", return_value=process,
        ), patch.object(MODULE.urllib.request, "build_opener", return_value=Opener(process)), patch.object(MODULE, "_terminate_process_group"):
            body, _ = MODULE._pod_port_forward_get_v4("/tmp/kube", "pod-a", 18085, "/status", startup_timeout=1, request_timeout=2)
        process.writer.join(timeout=1)
        self.assertEqual(body, '{"status":"ready"}')
        self.assertTrue(process.writer_done.is_set())
        self.assertEqual(process.writer_error, [])

    def test_v4_manual_policy_named_ports_and_ranges_are_conflicts(self):
        def policy_with(port, end_port=None):
            entry = {"port": port, "protocol": "TCP"}
            if end_port is not None: entry["endPort"] = end_port
            return {"spec": {"ingress": [{"ports": [entry]}]}}
        self.assertTrue(MODULE._allows_workbench_port(policy_with("workbench")))
        self.assertTrue(MODULE._allows_workbench_port(policy_with(18080, 18090)))
        self.assertFalse(MODULE._allows_workbench_port(policy_with(18084)))
        self.assertTrue(MODULE._allows_workbench_port({"spec": {"ingress": [{"ports": []}]}}))

    def test_v4_policy_union_accepts_exact_live_flannel_workbench_boundaries_without_cilium(self):
        labels = {
            "gateway": {"namespace": MODULE.NAMESPACE, "podCount": 0, "kubernetes": [MODULE.POLICY.GATEWAY_LABELS], "cilium": [MODULE.POLICY.GATEWAY_LABELS]},
            "workbench": {"namespace": MODULE.WORKBENCH_NAMESPACE, "podCount": 1, "kubernetes": [MODULE.POLICY.WORKBENCH_SELECTOR], "cilium": [MODULE.POLICY.WORKBENCH_SELECTOR]},
        }
        selector = {
            "matchLabels": {
                "app.kubernetes.io/component": "e2e-workbench",
                "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
            },
        }
        default_deny = admitted({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "default-deny-ingress", "namespace": MODULE.WORKBENCH_NAMESPACE},
            "spec": {"podSelector": {}, "policyTypes": ["Ingress"]},
        }, "deny-uid", "20")
        ingress_sources = [
            {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "ingress-system"}}},
            *[{"ipBlock": {"cidr": cidr}} for cidr in (
                "10.42.0.10/32", "10.42.0.11/32", "10.42.0.12/32",
                "10.244.0.0/32", "10.244.1.0/32", "10.244.2.0/32",
                "10.244.0.1/32", "10.244.1.1/32", "10.244.2.1/32",
            )],
        ]
        public_ingress = admitted({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            # Admission is deliberately capability-shaped, not name-whitelisted.
            "metadata": {"name": "renamed-public-workbench-ingress", "namespace": MODULE.WORKBENCH_NAMESPACE},
            "spec": {
                "podSelector": selector,
                "policyTypes": ["Ingress"],
                "ingress": [{"from": ingress_sources, "ports": [{"port": 18083, "protocol": "TCP"}]}],
            },
        }, "public-ingress-uid", "21")
        listings = [
            json.dumps({"items": [default_deny, public_ingress]}),
            json.dumps({"apiVersion": "v1", "kind": "APIGroupList", "groups": []}),
        ]
        with patch.object(MODULE, "_target_policy_label_sets_v4", return_value=labels), patch.object(
            MODULE,
            "checked",
            side_effect=listings,
        ):
            result = MODULE.policy_union_v4(Fake(), "/tmp/kube")
        self.assertEqual(result["status"], "no-additive-participant-allow-conflicts")
        self.assertEqual(result["ciliumApiDiscovery"], {"apiGroup": "cilium.io", "present": False})
        self.assertEqual(
            {item["name"]: item["classification"] for item in result["compatibleWorkbenchPolicies"]},
            {
                "default-deny-ingress": "no-ingress-allow-for-participant-port",
                "renamed-public-workbench-ingress": "exact-reviewed-public-ingress-boundary",
            },
        )

    def test_v4_policy_union_admits_only_explicit_egress_only_workbench_policy(self):
        labels = {
            "gateway": {"namespace": MODULE.NAMESPACE, "podCount": 0, "kubernetes": [MODULE.POLICY.GATEWAY_LABELS], "cilium": [MODULE.POLICY.GATEWAY_LABELS]},
            "workbench": {"namespace": MODULE.WORKBENCH_NAMESPACE, "podCount": 1, "kubernetes": [MODULE.POLICY.WORKBENCH_SELECTOR], "cilium": [MODULE.POLICY.WORKBENCH_SELECTOR]},
        }
        desired = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "cluster-dns-egress", "namespace": MODULE.WORKBENCH_NAMESPACE},
            "spec": {
                "podSelector": {},
                "policyTypes": ["Egress"],
                "egress": [{
                    "to": [{
                        "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
                        "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
                    }],
                    "ports": [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}],
                }],
            },
        }
        for explicit_ingress in (False, True):
            policy = admitted(desired, "dns-policy-uid", "9662150")
            if explicit_ingress:
                policy["spec"]["ingress"] = []
            listings = [
                json.dumps({"items": [policy]}),
                json.dumps({"apiVersion": "v1", "kind": "APIGroupList", "groups": []}),
            ]
            with self.subTest(explicit_ingress=explicit_ingress), patch.object(
                MODULE,
                "_target_policy_label_sets_v4",
                return_value=labels,
            ), patch.object(MODULE, "checked", side_effect=listings):
                result = MODULE.policy_union_v4(Fake(), "/tmp/kube")
                self.assertEqual(result["status"], "no-additive-participant-allow-conflicts")
                self.assertEqual(
                    result["compatibleWorkbenchEgressPolicies"],
                    [{
                        "namespace": MODULE.WORKBENCH_NAMESPACE,
                        "name": "cluster-dns-egress",
                        "uid": "dns-policy-uid",
                        "semanticSha256": MODULE.POLICY.semantic_sha256(policy),
                    }],
                )

    def test_v4_policy_union_rejects_participant_ingress_and_gateway_overlap(self):
        labels = {
            "gateway": {"namespace": MODULE.NAMESPACE, "podCount": 0, "kubernetes": [MODULE.POLICY.GATEWAY_LABELS], "cilium": [MODULE.POLICY.GATEWAY_LABELS]},
            "workbench": {"namespace": MODULE.WORKBENCH_NAMESPACE, "podCount": 1, "kubernetes": [MODULE.POLICY.WORKBENCH_SELECTOR], "cilium": [MODULE.POLICY.WORKBENCH_SELECTOR]},
        }
        base = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "foreign-policy", "namespace": MODULE.WORKBENCH_NAMESPACE},
            "spec": {"podSelector": {}, "policyTypes": ["Egress"], "egress": []},
        }
        unsafe = []
        participant_port = copy.deepcopy(base); participant_port["spec"]["ingress"] = [{"ports": [{"port": 18083, "protocol": "TCP"}]}]
        unsafe.append(("participant-port-all-sources", participant_port))
        empty_ports = copy.deepcopy(base); empty_ports["spec"]["ingress"] = [{"ports": []}]
        unsafe.append(("all-ports-all-sources", empty_ports))
        widened_public = copy.deepcopy(base)
        widened_public["spec"] = {
            "podSelector": {
                "matchLabels": {
                    "app.kubernetes.io/component": "e2e-workbench",
                    "app.kubernetes.io/part-of": "stadtstack-roebel-staging-lab",
                },
            },
            "policyTypes": ["Ingress"],
            "ingress": [{
                "from": [
                    {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "ingress-system"}}},
                    {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": MODULE.NAMESPACE}}},
                ],
                "ports": [{"port": 18083, "protocol": "TCP"}],
            }],
        }
        unsafe.append(("widened-public-boundary", widened_public))
        for label, desired in unsafe:
            policy = admitted(desired, f"{label}-uid", "10")
            with self.subTest(label=label), patch.object(
                MODULE,
                "_target_policy_label_sets_v4",
                return_value=labels,
            ), patch.object(MODULE, "checked", return_value=json.dumps({"items": [policy]})):
                with self.assertRaisesRegex(MODULE.ActivationError, "pre-existing NetworkPolicy selects workbench"):
                    MODULE.policy_union_v4(Fake(), "/tmp/kube")

        gateway = admitted(base, "gateway-egress-uid", "11")
        gateway["metadata"]["namespace"] = MODULE.NAMESPACE
        with patch.object(MODULE, "_target_policy_label_sets_v4", return_value=labels), patch.object(
            MODULE,
            "checked",
            return_value=json.dumps({"items": [gateway]}),
        ):
            with self.assertRaisesRegex(MODULE.ActivationError, "pre-existing NetworkPolicy can select gateway"):
                MODULE.policy_union_v4(Fake(), "/tmp/kube")

    def test_v4_policy_union_uses_runtime_cilium_identity_labels(self):
        labels = {
            "gateway": {
                "namespace": MODULE.NAMESPACE,
                "podCount": 1,
                "kubernetes": [MODULE.POLICY.GATEWAY_LABELS | {"pod-template-hash": "abc123"}],
                "cilium": [MODULE.POLICY.GATEWAY_LABELS | {
                    "pod-template-hash": "abc123",
                    "io.kubernetes.pod.namespace": MODULE.NAMESPACE,
                    "io.cilium.k8s.policy.serviceaccount": MODULE.NAME,
                }],
            },
            "workbench": {
                "namespace": MODULE.WORKBENCH_NAMESPACE,
                "podCount": 0,
                "kubernetes": [MODULE.POLICY.WORKBENCH_SELECTOR],
                "cilium": [MODULE.POLICY.WORKBENCH_SELECTOR | {"io.kubernetes.pod.namespace": MODULE.WORKBENCH_NAMESPACE}],
            },
        }
        cilium_policy = {
            "metadata": {"name": "unexpected-service-account-allow", "namespace": MODULE.NAMESPACE},
            "spec": {"endpointSelector": {"matchLabels": {"k8s:io.cilium.k8s.policy.serviceaccount": MODULE.NAME}}},
        }
        listings = [
            json.dumps({"items": []}),
            json.dumps({"apiVersion": "v1", "kind": "APIGroupList", "groups": [{"name": "cilium.io"}]}),
            json.dumps({"items": [cilium_policy]}),
        ]
        with patch.object(MODULE, "_target_policy_label_sets_v4", return_value=labels), patch.object(MODULE, "checked", side_effect=listings):
            with self.assertRaisesRegex(MODULE.ActivationError, "overlaps participant selectors"):
                MODULE.policy_union_v4(Fake(), "/tmp/kube")

    def test_v4_policy_union_exempts_owned_policy_only_by_uid_and_exact_semantics(self):
        desired = MODULE.POLICY.expected_workbench_ingress_network_policy()
        observed = admitted(desired, "owned-policy-uid", "10")
        binding = MODULE.CreatedV4("workbenchIngress.networkPolicy", desired, observed, {"operationNonce": "a" * 64})
        owned = {(MODULE.WORKBENCH_NAMESPACE, MODULE.WORKBENCH_POLICY_NAME): binding}
        labels = {
            "gateway": {"namespace": MODULE.NAMESPACE, "podCount": 0, "kubernetes": [MODULE.POLICY.GATEWAY_LABELS], "cilium": [MODULE.POLICY.GATEWAY_LABELS]},
            "workbench": {"namespace": MODULE.WORKBENCH_NAMESPACE, "podCount": 0, "kubernetes": [MODULE.POLICY.WORKBENCH_SELECTOR], "cilium": [MODULE.POLICY.WORKBENCH_SELECTOR]},
        }
        foreign = admitted(desired, "foreign-policy-uid", "11")
        with patch.object(MODULE, "_target_policy_label_sets_v4", return_value=labels), patch.object(MODULE, "checked", return_value=json.dumps({"items": [foreign]})):
            with self.assertRaisesRegex(MODULE.ActivationError, "owned NetworkPolicy UID drift"):
                MODULE.policy_union_v4(Fake(), "/tmp/kube", owned)
        widened = admitted(desired, "owned-policy-uid", "12"); widened["spec"]["ingress"][0]["ports"][0]["port"] = 18084
        with patch.object(MODULE, "_target_policy_label_sets_v4", return_value=labels), patch.object(MODULE, "checked", return_value=json.dumps({"items": [widened]})):
            with self.assertRaisesRegex(MODULE.ActivationError, "semantics"):
                MODULE.policy_union_v4(Fake(), "/tmp/kube", owned)
        with patch.object(MODULE, "_target_policy_label_sets_v4", return_value=labels), patch.object(MODULE, "checked", side_effect=[
            json.dumps({"items": []}),
            json.dumps({"apiVersion": "v1", "kind": "APIGroupList", "groups": []}),
        ]):
            with self.assertRaisesRegex(MODULE.ActivationError, "set absent or incomplete"):
                MODULE.policy_union_v4(Fake(), "/tmp/kube", owned)
        flux_owned = admitted(desired, "owned-policy-uid", "13")
        flux_owned["metadata"]["labels"].update(
            MODULE.expected_flux_tracking_labels_v4("workbenchIngress.networkPolicy")
        )
        with patch.object(MODULE, "_target_policy_label_sets_v4", return_value=labels), patch.object(MODULE, "checked", side_effect=[
            json.dumps({"items": [flux_owned]}),
            json.dumps({"apiVersion": "v1", "kind": "APIGroupList", "groups": []}),
        ]):
            receipt = MODULE.policy_union_v4(
                Fake(), "/tmp/kube", owned, flux_tracking_state="complete",
            )
        self.assertEqual(
            receipt["ownedNetworkPoliciesValidated"][0]["fluxTrackingLabels"],
            MODULE.RUN29_FLUX_TRACKING_LABELS["workbenchIngress"],
        )

    def test_v4_policy_union_fails_closed_on_malformed_api_group_discovery(self):
        labels = {
            "gateway": {"namespace": MODULE.NAMESPACE, "podCount": 0, "kubernetes": [MODULE.POLICY.GATEWAY_LABELS], "cilium": [MODULE.POLICY.GATEWAY_LABELS]},
            "workbench": {"namespace": MODULE.WORKBENCH_NAMESPACE, "podCount": 0, "kubernetes": [MODULE.POLICY.WORKBENCH_SELECTOR], "cilium": [MODULE.POLICY.WORKBENCH_SELECTOR]},
        }
        with patch.object(MODULE, "_target_policy_label_sets_v4", return_value=labels), patch.object(MODULE, "checked", side_effect=[
            json.dumps({"items": []}),
            json.dumps({"apiVersion": "v1", "kind": "APIGroupList", "groups": [{"preferredVersion": {"groupVersion": "cilium.io/v2"}}]}),
        ]):
            with self.assertRaisesRegex(MODULE.ActivationError, "API-group entry invalid"):
                MODULE.policy_union_v4(Fake(), "/tmp/kube")

    def test_v4_rollback_rechecks_ingress_absence_after_dual_suspend(self):
        desired = {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress", "metadata": {"name": MODULE.NAME, "namespace": MODULE.NAMESPACE}}
        ingress = MODULE.CreatedV4("gateway.ingress", desired, admitted(desired, "ingress-uid"), {"uid": "ingress-uid", "operationNonce": "a" * 64, "temporaryNonceRemoved": True})
        gateway = admitted(MODULE.POLICY.gateway_flux_objects(suspended=True)["kustomization"], "g", "10")
        workbench = admitted(MODULE.POLICY.workbench_ingress_flux_objects(suspended=True)["kustomization"], "w", "20")
        bootstrap = {"owners": {"gateway": {"kustomization": gateway}, "workbenchIngress": {"kustomization": workbench}}, "source": {"metadata": {"uid": "source"}, "status": {"artifact": {"revision": f"main@sha1:{REV}"}}}}
        recreated = {"metadata": {"uid": "replacement-uid", "resourceVersion": "99"}}
        quiescent = {"gateway": {"uid": "g", "suspended": True}, "workbenchIngress": {"uid": "w", "suspended": True}}
        with patch.object(MODULE, "delete_with_preconditions_v4", return_value={"absent": True}), patch.object(MODULE, "_target_live", side_effect=[gateway, workbench]), patch.object(MODULE, "wait_both_suspended_v4", return_value=quiescent), patch.object(MODULE, "get_optional", return_value=recreated):
            result = MODULE.rollback_v4(Fake(), "/tmp/kube", policy(), [ingress], bootstrap, None, None)
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(result["bothKustomizationsSuspended"])
        self.assertIn("unowned UID", result["errors"][0])

    def test_v4_unproved_ingress_absence_breaks_exposure_through_exact_owned_service(self):
        service_desired = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": MODULE.NAME, "namespace": MODULE.NAMESPACE}}
        service = MODULE.CreatedV4("gateway.service", service_desired, admitted(service_desired, "service-uid", "21"), {"operationNonce": "a" * 64, "temporaryNonceRemoved": True})
        service_deleted = {"logicalName": "gateway.service", "uid": "service-uid", "absent": True}
        with patch.object(MODULE, "delete_with_preconditions_v4", return_value=service_deleted) as delete:
            result = MODULE.rollback_v4(Fake(), "/tmp/kube", policy(), [service], None, None, None)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["finalChecks"]["exposureBreak"]["serviceUid"], "service-uid")
        self.assertTrue(result["finalChecks"]["exposureBreak"]["unknownIngressUntouched"])
        self.assertEqual(delete.call_count, 1); self.assertIs(delete.call_args.args[2], service)

        ingress_desired = {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress", "metadata": {"name": MODULE.NAME, "namespace": MODULE.NAMESPACE}}
        ingress = MODULE.CreatedV4("gateway.ingress", ingress_desired, admitted(ingress_desired, "ingress-uid", "31"), {"operationNonce": "a" * 64, "temporaryNonceRemoved": True})
        with patch.object(MODULE, "delete_with_preconditions_v4", side_effect=[MODULE.ActivationError("Ingress removal unproved"), service_deleted]) as delete:
            result = MODULE.rollback_v4(Fake(), "/tmp/kube", policy(), [service, ingress], None, None, None)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(delete.call_args_list[1].args[2], service)
        self.assertFalse(result["finalChecks"]["exposureBreak"]["unknownIngressUntouched"])

        gateway = admitted(MODULE.POLICY.gateway_flux_objects(suspended=True)["kustomization"], "g", "40")
        workbench = admitted(MODULE.POLICY.workbench_ingress_flux_objects(suspended=True)["kustomization"], "w", "50")
        bootstrap = {
            "owners": {"gateway": {"kustomization": gateway}, "workbenchIngress": {"kustomization": workbench}},
            "source": {"metadata": {"uid": "source"}, "status": {"artifact": {"revision": f"main@sha1:{REV}"}}},
        }
        ingress_deleted = {"logicalName": "gateway.ingress", "uid": "ingress-uid", "absent": True}
        replacement = {"metadata": {"uid": "replacement-ingress-uid", "resourceVersion": "99"}}
        quiescent = {"gateway": {"uid": "g", "suspended": True}, "workbenchIngress": {"uid": "w", "suspended": True}}
        with patch.object(MODULE, "delete_with_preconditions_v4", side_effect=[ingress_deleted, service_deleted, service_deleted]) as delete, patch.object(MODULE, "_target_live", side_effect=[gateway, workbench]), patch.object(MODULE, "wait_both_suspended_v4", return_value=quiescent), patch.object(MODULE, "get_optional", return_value=replacement):
            result = MODULE.rollback_v4(Fake(), "/tmp/kube", policy(), [service, ingress], bootstrap, None, None)
        self.assertEqual(result["status"], "incomplete")
        self.assertIs(delete.call_args_list[0].args[2], ingress)
        self.assertIs(delete.call_args_list[1].args[2], service)
        self.assertIs(delete.call_args_list[2].args[2], service)
        self.assertTrue(result["finalChecks"]["exposureBreak"]["initialIngressAbsenceProved"])
        self.assertTrue(result["finalChecks"]["exposureBreakAfterFlux"]["serviceAbsent"])
        self.assertIn("unowned UID", result["errors"][0])

    def test_v4_rollback_refuses_mutation_if_protected_cluster_identity_changes(self):
        desired = {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress", "metadata": {"name": MODULE.NAME, "namespace": MODULE.NAMESPACE}}
        ingress = MODULE.CreatedV4("gateway.ingress", desired, admitted(desired, "ingress-uid"), {"uid": "ingress-uid", "operationNonce": "a" * 64, "temporaryNonceRemoved": True})
        initial = {"apiOrigin": "https://api.example:6443", "caCertificateSha256": sha("1"), "apiServerSpkiSha256": sha("2"), "kubeSystemNamespaceUid": "cluster-a"}
        changed = initial | {"kubeSystemNamespaceUid": "cluster-b"}
        snapshot = Mock()
        with patch.object(MODULE, "cluster_binding_v4", return_value=changed), patch.object(MODULE, "delete_with_preconditions_v4") as delete:
            result = MODULE.rollback_v4(Fake(), "/tmp/kube", policy(), [ingress], None, None, None, snapshot=snapshot, initial_cluster=initial)
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("protected cluster identity changed before rollback", result["errors"][0])
        delete.assert_not_called()

    def test_v4_failed_activation_recovery_source_binds_exact_raw_receipt_and_incident(self):
        receipt = failed_activation_receipt_fixture()
        raw = (MODULE.canonical(receipt) + "\n").encode()
        self.assertEqual(receipt["canonicalSha256"], MODULE.FAILED_ACTIVATION_CANONICAL_SHA256)
        self.assertEqual(MODULE.bytes_digest(raw), MODULE.FAILED_ACTIVATION_RAW_SHA256)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "failed.json"; path.write_bytes(raw); path.chmod(0o600)
            fd = os.open(path, os.O_RDONLY)
            try:
                bound = MODULE.bind_failed_activation_recovery_source_v4(fd)
            finally:
                os.close(fd)
        self.assertEqual(bound["originProtectedRevision"], MODULE.FAILED_ACTIVATION_ORIGIN_REVISION)
        self.assertEqual(bound["operationNonce"], MODULE.FAILED_ACTIVATION_OPERATION_NONCE)
        self.assertEqual(list(bound["objects"]), list(MODULE.FAILED_ACTIVATION_CREATED_ORDER))
        self.assertTrue(bound["serviceExposureBreakProved"])
        self.assertTrue(bound["ingressNeverCreated"])

        drifted = copy.deepcopy(receipt); drifted["failure"] = "different failure"
        unsigned = {key: value for key, value in drifted.items() if key != "canonicalSha256"}
        drifted["canonicalSha256"] = MODULE.digest(unsigned)
        drifted_raw = (MODULE.canonical(drifted) + "\n").encode()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "drifted.json"; path.write_bytes(drifted_raw); path.chmod(0o600)
            fd = os.open(path, os.O_RDONLY)
            try:
                with (
                    patch.object(MODULE, "FAILED_ACTIVATION_RAW_SHA256", MODULE.bytes_digest(drifted_raw)),
                    patch.object(MODULE, "FAILED_ACTIVATION_CANONICAL_SHA256", drifted["canonicalSha256"]),
                    self.assertRaisesRegex(MODULE.ActivationError, "failure drift"),
                ):
                    MODULE.bind_failed_activation_recovery_source_v4(fd)
            finally:
                os.close(fd)

    def test_v4_run29_failed_activation_recovery_source_binds_exact_six_object_incident(self):
        receipt = copy.deepcopy(MODULE.RUN29_FAILED_ACTIVATION_RECEIPT)
        raw = (MODULE.canonical(receipt) + "\n").encode()
        self.assertEqual(
            MODULE.bytes_digest(raw),
            "sha256:3a257f8b8ce37138d73e61dc58e42e7a6ebfc7aba2f10648e689eb6e033d4122",
        )
        self.assertEqual(
            receipt["canonicalSha256"],
            "sha256:0c25965b6f3424806fb82035363e58365d12fc4da414879824b367d3e2a8f81f",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run29-failed.json"; path.write_bytes(raw); path.chmod(0o600)
            fd = os.open(path, os.O_RDONLY)
            try:
                bound = MODULE.bind_failed_activation_recovery_source_v4(fd)
            finally:
                os.close(fd)
        self.assertEqual(bound["originProtectedRevision"], "38cdfbd9748c3481689599c53f4443af11a7df63")
        self.assertEqual(bound["operationNonce"], "1aec660f1b635e1ae325fb35cb1fb7eb591eadb0a7f96cec36160eabe83a2e0b")
        self.assertEqual(list(bound["objects"]), [
            "gateway.networkPolicy",
            "workbenchIngress.networkPolicy",
            "gateway.serviceAccount",
            "gateway.service",
            "gateway.deployment",
            "gateway.ingress",
        ])
        self.assertFalse(bound["serviceExposureBreakProved"])
        self.assertFalse(bound["ingressNeverCreated"])
        self.assertFalse(bound["civicAuthorityEffects"])
        self.assertEqual(MODULE.validate_recovery_incident_binding_v4(bound), bound)

    def test_v4_run29_recovery_target_preflight_binds_all_six_uids_with_only_exact_flux_tracking_labels(self):
        value = ready_policy(); incident = run29_recovery_incident_ownership()
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            resources = MODULE.POLICY.expected_gateway_resources(value)
        desired_by_logical = {
            "gateway.networkPolicy": resources["networkPolicy"],
            "workbenchIngress.networkPolicy": MODULE.POLICY.expected_workbench_ingress_network_policy(include_web_presentation=True),
            "gateway.serviceAccount": resources["serviceAccount"],
            "gateway.service": resources["service"],
            "gateway.deployment": resources["deployment"],
            "gateway.ingress": resources["ingress"],
        }
        rendered = {
            logical: {
                "desired": desired,
                "path": incident["objects"][logical]["protectedRenderPath"],
                "blobSha256": incident["objects"][logical]["protectedRenderBlobSha256"],
            }
            for logical, desired in desired_by_logical.items()
        }
        live_by_target = {}
        for logical, desired in desired_by_logical.items():
            live = admitted(desired, incident["objects"][logical]["uid"], str(200 + len(live_by_target)))
            live.setdefault("metadata", {}).setdefault("labels", {}).update({
                "kustomize.toolkit.fluxcd.io/name": (
                    value["gitOps"]["reconcilers"]["workbenchIngress"]["kustomization"]["name"]
                    if logical == "workbenchIngress.networkPolicy"
                    else value["gitOps"]["reconcilers"]["gateway"]["kustomization"]["name"]
                ),
                "kustomize.toolkit.fluxcd.io/namespace": MODULE.FLUX_NAMESPACE,
            })
            metadata = desired["metadata"]
            live_by_target[(desired["kind"].lower(), metadata["namespace"], metadata["name"])] = live

        def lookup(_runner, _kube, kind, name, namespace):
            return copy.deepcopy(live_by_target.get((kind, namespace, name)))

        self.assertEqual(MODULE.RUN29_FAILED_ACTIVATION_LIVE_SEMANTIC_SHA256, {
            "gateway.networkPolicy": "sha256:c96474d0562ba53f1733ecc19ae92fc08f9cf133a3befcf79dfbc61cad54de1e",
            "workbenchIngress.networkPolicy": "sha256:b8e77edf5a370acd9d5330047d64f94402d985d98d1296551101022276bcb5e7",
            "gateway.serviceAccount": "sha256:0b9c5dcdbe3305748ee8074561f54adf8d643ebccb25b4cb414b530c2f75439c",
            "gateway.service": "sha256:0c76fa6419381a857ab725ded5302441a1f53981a0f8922b61b794dfef11bbc0",
            "gateway.deployment": "sha256:d9de8fbc26421aaba46fdec236725993a691d2dd4b2f745be6daa74ce2d5827f",
            "gateway.ingress": "sha256:3eec8aabc99efe45611a99daf848741c4e4f6c67b7e7e52fb3d96dfaab47a7f0",
        })
        fixture_live_hashes = {
            logical: MODULE.POLICY.semantic_sha256(live)
            for logical, live in zip(desired_by_logical, live_by_target.values())
        }
        with (
            patch.object(MODULE, "RUN29_FAILED_ACTIVATION_LIVE_SEMANTIC_SHA256", fixture_live_hashes),
            patch.object(MODULE, "get_optional", side_effect=lookup),
        ):
            bound = MODULE.bind_recovery_targets_v4(Fake(), "/snapshot", rendered, incident)
        self.assertEqual([item.logical_name for item in bound["created"]], list(MODULE.RUN29_FAILED_ACTIVATION_CREATED_ORDER))
        self.assertEqual(
            {logical: state["state"] for logical, state in bound["classifications"].items()},
            {logical: "present-exact-receipt-owned" for logical in MODULE.RUN29_FAILED_ACTIVATION_CREATED_ORDER},
        )

    def test_v4_run29_recovery_delete_rechecks_exact_uid_and_exact_flux_tracking_semantics(self):
        value = ready_policy()
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            desired = MODULE.POLICY.expected_gateway_resources(value)["ingress"]
        record = copy.deepcopy(run29_recovery_incident_ownership()["objects"]["gateway.ingress"])
        live = admitted(desired, record["uid"], "300")
        live.setdefault("metadata", {}).setdefault("labels", {}).update(
            MODULE.RUN29_FLUX_TRACKING_LABELS["gateway"]
        )
        created = MODULE.CreatedV4(
            "gateway.ingress",
            desired,
            copy.deepcopy(live),
            record | {
                "recoverySource": True,
                "recoveryIncidentRawSha256": MODULE.RUN29_FAILED_ACTIVATION_RAW_SHA256,
            },
        )
        with (
            patch.object(MODULE, "get_optional", side_effect=[copy.deepcopy(live), None]),
            patch.object(MODULE, "raw_delete") as delete,
        ):
            result = MODULE.delete_with_preconditions_v4(
                Fake(), "/snapshot", created, snapshot=Mock(),
            )
        self.assertEqual(result["uid"], record["uid"])
        self.assertTrue(result["absent"])
        delete.assert_called_once()

    def test_v4_recovery_target_preflight_binds_only_exact_incident_objects(self):
        value = ready_policy(); incident = recovery_incident_ownership()
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            resources = MODULE.POLICY.expected_gateway_resources(value)
        desired_by_logical = {
            "gateway.networkPolicy": resources["networkPolicy"],
            "workbenchIngress.networkPolicy": MODULE.POLICY.expected_workbench_ingress_network_policy(include_web_presentation=True),
            "gateway.serviceAccount": resources["serviceAccount"],
            "gateway.service": resources["service"],
            "gateway.deployment": resources["deployment"],
            "gateway.ingress": resources["ingress"],
        }
        semantic_patch = patch.object(
            MODULE.POLICY,
            "semantic_sha256",
            side_effect=incident_semantic_hash_fixture(incident, desired_by_logical),
        )
        semantic_patch.start()
        self.addCleanup(semantic_patch.stop)
        rendered = {}
        for logical, desired in desired_by_logical.items():
            origin = incident["objects"].get(logical)
            rendered[logical] = {
                "desired": desired,
                "path": origin["protectedRenderPath"] if origin else f"protected/{logical}.json",
                "blobSha256": origin["protectedRenderBlobSha256"] if origin else sha("7"),
            }
        live_by_target = {}
        for logical in ("gateway.networkPolicy", "workbenchIngress.networkPolicy", "gateway.serviceAccount"):
            desired = desired_by_logical[logical]; target = desired["metadata"]
            live_by_target[(desired["kind"].lower(), target["namespace"], target["name"])] = admitted(
                desired,
                incident["objects"][logical]["uid"],
                "200",
            )
        deployment = admitted(
            MODULE.POLICY.with_operation_nonce(desired_by_logical["gateway.deployment"], incident["operationNonce"]),
            "deployment-live-uid",
            "201",
        )
        deployment["spec"]["template"]["spec"]["serviceAccount"] = MODULE.NAME
        target = desired_by_logical["gateway.deployment"]["metadata"]
        live_by_target[("deployment", target["namespace"], target["name"])] = deployment

        def lookup(_runner, _kube, kind, name, namespace):
            return copy.deepcopy(live_by_target.get((kind, namespace, name)))

        with patch.object(MODULE, "get_optional", side_effect=lookup):
            bound = MODULE.bind_recovery_targets_v4(Fake(), "/snapshot", rendered, incident)
        self.assertEqual([item.logical_name for item in bound["created"]], [
            "gateway.networkPolicy",
            "workbenchIngress.networkPolicy",
            "gateway.serviceAccount",
            "gateway.service",
            "gateway.deployment",
        ])
        self.assertEqual(bound["classifications"]["gateway.service"]["state"], "absent-exposure-break-proved")
        self.assertEqual(bound["classifications"]["gateway.ingress"]["state"], "absent-never-created")
        self.assertEqual(bound["classifications"]["gateway.deployment"]["uid"], "deployment-live-uid")

        foreign = copy.deepcopy(live_by_target)
        service_account = desired_by_logical["gateway.serviceAccount"]; sa_meta = service_account["metadata"]
        foreign[("serviceaccount", sa_meta["namespace"], sa_meta["name"])]["metadata"]["uid"] = "foreign-uid"
        with patch.object(MODULE, "get_optional", side_effect=lambda _r, _k, kind, name, namespace: copy.deepcopy(foreign.get((kind, namespace, name)))):
            with self.assertRaisesRegex(MODULE.ActivationError, "incident UID drift"):
                MODULE.bind_recovery_targets_v4(Fake(), "/snapshot", rendered, incident)

        wrong_nonce = copy.deepcopy(live_by_target)
        wrong_nonce[("deployment", target["namespace"], target["name"])]["metadata"]["annotations"][MODULE.POLICY.OPERATION_NONCE_ANNOTATION] = "f" * 64
        with patch.object(MODULE, "get_optional", side_effect=lambda _r, _k, kind, name, namespace: copy.deepcopy(wrong_nonce.get((kind, namespace, name)))):
            with self.assertRaises(MODULE.ActivationError):
                MODULE.bind_recovery_targets_v4(Fake(), "/snapshot", rendered, incident)

        for logical in ("gateway.service", "gateway.ingress"):
            present = copy.deepcopy(live_by_target); desired = desired_by_logical[logical]; metadata = desired["metadata"]
            present[(desired["kind"].lower(), metadata["namespace"], metadata["name"])] = admitted(desired, "unexpected-uid", "300")
            with self.subTest(logical=logical), patch.object(MODULE, "get_optional", side_effect=lambda _r, _k, kind, name, namespace, values=present: copy.deepcopy(values.get((kind, namespace, name)))):
                with self.assertRaisesRegex(MODULE.ActivationError, "must remain absent"):
                    MODULE.bind_recovery_targets_v4(Fake(), "/snapshot", rendered, incident)

    def test_v4_recovery_target_preflight_is_idempotent_only_after_dependent_absence(self):
        value = ready_policy(); incident = recovery_incident_ownership()
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            resources = MODULE.POLICY.expected_gateway_resources(value)
        desired_by_logical = {
            "gateway.networkPolicy": resources["networkPolicy"],
            "workbenchIngress.networkPolicy": MODULE.POLICY.expected_workbench_ingress_network_policy(include_web_presentation=True),
            "gateway.serviceAccount": resources["serviceAccount"],
            "gateway.service": resources["service"],
            "gateway.deployment": resources["deployment"],
            "gateway.ingress": resources["ingress"],
        }
        semantic_patch = patch.object(
            MODULE.POLICY,
            "semantic_sha256",
            side_effect=incident_semantic_hash_fixture(incident, desired_by_logical),
        )
        semantic_patch.start()
        self.addCleanup(semantic_patch.stop)
        rendered = {
            logical: {
                "desired": desired,
                "path": incident["objects"][logical]["protectedRenderPath"] if logical in incident["objects"] else f"protected/{logical}.json",
                "blobSha256": incident["objects"][logical]["protectedRenderBlobSha256"] if logical in incident["objects"] else sha("8"),
            }
            for logical, desired in desired_by_logical.items()
        }
        dependent_proof = {"status": "deployment-foreground-dependents-absent"}
        with patch.object(MODULE, "get_optional", return_value=None), patch.object(MODULE, "deployment_dependents_absent_v4", return_value=dependent_proof):
            bound = MODULE.bind_recovery_targets_v4(Fake(), "/snapshot", rendered, incident)
        self.assertEqual([item.logical_name for item in bound["created"]], list(MODULE.FAILED_ACTIVATION_CREATED_ORDER))
        self.assertEqual(bound["classifications"]["gateway.deployment"]["dependents"], dependent_proof)
        with patch.object(MODULE, "get_optional", return_value=None), patch.object(
            MODULE, "deployment_dependents_absent_v4", side_effect=MODULE.ActivationError("participant pods remain")
        ):
            with self.assertRaisesRegex(MODULE.ActivationError, "pods remain"):
                MODULE.bind_recovery_targets_v4(Fake(), "/snapshot", rendered, incident)

    def test_v4_incident_recovery_rollback_order_keeps_gateway_isolation_last(self):
        value = ready_policy()
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            resources = MODULE.POLICY.expected_gateway_resources(value)
        desired = {
            "gateway.networkPolicy": resources["networkPolicy"],
            "workbenchIngress.networkPolicy": MODULE.POLICY.expected_workbench_ingress_network_policy(include_web_presentation=True),
            "gateway.serviceAccount": resources["serviceAccount"],
            "gateway.service": resources["service"],
            "gateway.deployment": resources["deployment"],
        }
        created = [
            MODULE.CreatedV4(logical, item, admitted(item, logical + "-uid", str(index + 10)), {"uid": logical + "-uid"})
            for index, (logical, item) in enumerate(desired.items())
        ]
        gateway = admitted(MODULE.POLICY.gateway_flux_objects(suspended=True)["kustomization"], "g", "40")
        workbench = admitted(MODULE.POLICY.workbench_ingress_flux_objects(suspended=True)["kustomization"], "w", "50")
        source = {"metadata": {"uid": "source", "resourceVersion": "1"}, "status": {"artifact": {"revision": f"main@sha1:{REV}"}}}
        bootstrap = {"owners": {"gateway": {"kustomization": gateway}, "workbenchIngress": {"kustomization": workbench}}, "source": source}
        quiescent = {"gateway": {"suspended": True}, "workbenchIngress": {"suspended": True}}
        deletion_order = []
        def remove(_runner, _kube, item, _timeout, _snapshot=None):
            deletion_order.append(item.logical_name)
            return {"logicalName": item.logical_name, "uid": item.observed["metadata"]["uid"], "absent": True, "foregroundPropagation": item.logical_name == "gateway.deployment"}
        with (
            patch.object(MODULE, "delete_with_preconditions_v4", side_effect=remove),
            patch.object(MODULE, "_target_live", side_effect=[gateway, workbench]),
            patch.object(MODULE, "wait_both_suspended_v4", side_effect=[quiescent, quiescent]),
            patch.object(MODULE, "deployment_dependents_absent_v4", return_value={"status": "deployment-foreground-dependents-absent"}),
            patch.object(MODULE, "_all_targets_absent_quiet_v4", return_value={"status": "all-six-names-absent-for-quiet-interval"}),
            patch.object(MODULE, "shared_source_revision_v4", return_value=source),
        ):
            result = MODULE.rollback_v4(Fake(), "/snapshot", value, created, bootstrap, None, None, rendered={str(i): {} for i in range(6)})
        self.assertEqual(result["status"], "complete")
        self.assertEqual(deletion_order, [
            "gateway.service", "gateway.service", "gateway.deployment",
            "gateway.serviceAccount", "workbenchIngress.networkPolicy", "gateway.networkPolicy",
        ])

    def test_v4_recovery_blocks_before_rollback_mutation_on_preflight_failure(self):
        value = ready_policy(); snapshot = Mock(path=Path("/snapshot")); snapshot.close = Mock()
        sink = Mock(); cluster = {"cluster": "bound"}; rollback = Mock()
        with tempfile.TemporaryDirectory() as directory:
            kube = Path(directory) / "kube"; kube.write_text("fixture")
            with (
                patch.object(MODULE.POLICY, "assert_activation_ready", return_value=value),
                patch.object(MODULE, "render_v4", return_value={}),
                patch.object(MODULE, "snapshot_kubeconfig_v4", return_value=snapshot),
                patch.object(MODULE, "cluster_binding_v4", return_value=cluster),
                patch.object(MODULE, "validate_bound_cluster_identity_v4", return_value=cluster),
                patch.object(MODULE, "require_same_cluster_identity_v4"),
                patch.object(MODULE, "preservation_v4", return_value={}),
                patch.object(MODULE, "require_current_preservation_binding_v4"),
                patch.object(MODULE, "flux_preflight_v4", return_value={"owners": {}}),
                patch.object(MODULE, "recovery_flux_preflight_v4", return_value={}),
                patch.object(MODULE, "bind_recovery_targets_v4", side_effect=MODULE.ActivationError("foreign UID")),
                patch.object(MODULE, "rollback_v4", rollback),
                self.assertRaisesRegex(MODULE.ActivationError, "recovery blocked"),
            ):
                MODULE.recover_incomplete_activation_v4(
                    value, REV, str(kube), Fake(), sink, {"runner": sha()}, recovery_dormant_ownership(), recovery_incident_ownership()
                )
        rollback.assert_not_called()
        self.assertEqual(sink.commit.call_args.args[0]["status"], "recovery-blocked")
        snapshot.close.assert_called_once()

    def test_v4_recovery_reuses_bounded_rollback_and_commits_success_without_activation(self):
        value = ready_policy(); snapshot = Mock(path=Path("/snapshot")); snapshot.close = Mock()
        sink = Mock(); cluster = recovery_cluster(value); preserved = {"webIngress": Mock(), "existingWorkbenchNetworkPolicy": Mock()}
        bootstrap = {"owners": {}, "source": {"status": {"artifact": {"revision": f"main@sha1:{REV}"}}}}
        preflight = valid_recovery_preflight(value)
        desired = {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "fixture", "namespace": MODULE.NAMESPACE}}
        created = [MODULE.CreatedV4(logical, desired, admitted(desired, logical + "-uid"), {"uid": logical + "-uid"}) for logical in (
            "gateway.networkPolicy", "workbenchIngress.networkPolicy", "gateway.serviceAccount", "gateway.service", "gateway.deployment"
        )]
        target_binding = {"created": created, "classifications": preflight["targets"]}
        rollback_receipt = valid_recovery_rollback(value, preflight)
        with tempfile.TemporaryDirectory() as directory:
            kube = Path(directory) / "kube"; kube.write_text("fixture")
            with (
                patch.object(MODULE.POLICY, "assert_activation_ready", return_value=value),
                patch.object(MODULE, "render_v4", return_value={}),
                patch.object(MODULE, "snapshot_kubeconfig_v4", return_value=snapshot),
                patch.object(MODULE, "cluster_binding_v4", return_value=cluster),
                patch.object(MODULE, "validate_bound_cluster_identity_v4", return_value=cluster),
                patch.object(MODULE, "require_same_cluster_identity_v4"),
                patch.object(MODULE, "preservation_v4", return_value=preserved),
                patch.object(MODULE, "require_current_preservation_binding_v4"),
                patch.object(MODULE, "flux_preflight_v4", return_value=bootstrap),
                patch.object(MODULE, "recovery_flux_preflight_v4", return_value=preflight["flux"]),
                patch.object(MODULE, "recovery_dormant_receipt_preflight_v4", return_value=preflight["dormantReceipt"]),
                patch.object(MODULE, "recovery_source_preflight_v4", return_value=preflight["source"]),
                patch.object(MODULE, "bind_recovery_targets_v4", return_value=target_binding),
                patch.object(MODULE, "verify_preservation_v4", return_value=preflight["preservation"]),
                patch.object(MODULE, "rollback_v4", return_value=rollback_receipt) as rollback,
            ):
                result = MODULE.recover_incomplete_activation_v4(
                    value, REV, str(kube), Fake(), sink, {"runner": sha()}, recovery_dormant_ownership(), recovery_incident_ownership()
                )
        self.assertEqual(result["status"], "recovered")
        self.assertFalse(result["automaticActivationRetry"])
        self.assertEqual([item.logical_name for item in rollback.call_args.args[3]], [item.logical_name for item in created])
        self.assertIsNone(rollback.call_args.args[6])
        self.assertEqual(sink.commit.call_args.args[0]["status"], "recovered")
        snapshot.close.assert_called_once()

    def test_v4_recovery_retry_commits_when_deployment_and_receipt_objects_are_already_absent(self):
        value = ready_policy(); snapshot = Mock(path=Path("/snapshot")); snapshot.close = Mock()
        sink = Mock(); cluster = recovery_cluster(value)
        preserved = {"webIngress": Mock(), "existingWorkbenchNetworkPolicy": Mock()}
        bootstrap = {"owners": {}, "source": {"status": {"artifact": {"revision": f"main@sha1:{REV}"}}}}
        preflight = valid_recovery_preflight(value, deployment_present=False)
        for logical in ("gateway.networkPolicy", "workbenchIngress.networkPolicy", "gateway.serviceAccount"):
            preflight["targets"][logical]["state"] = "already-absent-receipt-owned"
            preflight["targets"][logical].pop("resourceVersion")
        desired = {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "fixture", "namespace": MODULE.NAMESPACE}}
        created = [
            MODULE.CreatedV4(logical, desired, admitted(desired, logical + "-uid"), {"uid": logical + "-uid"})
            for logical in (
                "gateway.networkPolicy", "workbenchIngress.networkPolicy",
                "gateway.serviceAccount", "gateway.service",
            )
        ]
        target_binding = {"created": created, "classifications": preflight["targets"]}
        rollback_receipt = valid_recovery_rollback(value, preflight)
        self.assertNotIn("gateway.deployment", [item["logicalName"] for item in rollback_receipt["deleted"]])
        self.assertTrue(all(item.get("alreadyAbsent") is True for item in rollback_receipt["deleted"]))
        with tempfile.TemporaryDirectory() as directory:
            kube = Path(directory) / "kube"; kube.write_text("fixture")
            with (
                patch.object(MODULE.POLICY, "assert_activation_ready", return_value=value),
                patch.object(MODULE, "render_v4", return_value={}),
                patch.object(MODULE, "snapshot_kubeconfig_v4", return_value=snapshot),
                patch.object(MODULE, "cluster_binding_v4", return_value=cluster),
                patch.object(MODULE, "validate_bound_cluster_identity_v4", return_value=cluster),
                patch.object(MODULE, "require_same_cluster_identity_v4"),
                patch.object(MODULE, "preservation_v4", return_value=preserved),
                patch.object(MODULE, "require_current_preservation_binding_v4"),
                patch.object(MODULE, "flux_preflight_v4", return_value=bootstrap),
                patch.object(MODULE, "recovery_flux_preflight_v4", return_value=preflight["flux"]),
                patch.object(MODULE, "recovery_dormant_receipt_preflight_v4", return_value=preflight["dormantReceipt"]),
                patch.object(MODULE, "recovery_source_preflight_v4", return_value=preflight["source"]),
                patch.object(MODULE, "bind_recovery_targets_v4", return_value=target_binding),
                patch.object(MODULE, "verify_preservation_v4", return_value=preflight["preservation"]),
                patch.object(MODULE, "rollback_v4", return_value=rollback_receipt) as rollback,
            ):
                result = MODULE.recover_incomplete_activation_v4(
                    value, REV, str(kube), Fake(), sink, {"runner": sha()},
                    recovery_dormant_ownership(), recovery_incident_ownership(),
                )
        self.assertEqual(result["status"], "recovered")
        self.assertEqual([item.logical_name for item in rollback.call_args.args[3]], [item.logical_name for item in created])
        self.assertFalse(result["automaticActivationRetry"])
        self.assertEqual(sink.commit.call_args.args[0]["status"], "recovered")
        snapshot.close.assert_called_once()

    def test_v4_recovery_receipt_verifier_requires_complete_rollback_and_no_retry(self):
        value = ready_policy(); runner_hashes = {"runner": sha()}
        preflight = valid_recovery_preflight(value)
        rollback = valid_recovery_rollback(value, preflight)
        unsigned = {
            "schemaVersion": MODULE.RECOVERY_RECEIPT_SCHEMA,
            "status": "recovered",
            "protectedRevision": REV,
            "activationPolicySha256": MODULE.POLICY.activation_policy_sha256(value),
            "protectedRunnerFileSha256": runner_hashes,
            "recoveredIncident": recovery_incident_ownership(),
            "preflight": preflight,
            "rollback": rollback,
            "automaticActivationRetry": False,
            "civicAuthorityEffects": False,
        }
        receipt = unsigned | {"canonicalSha256": MODULE.digest(unsigned)}
        bound = MODULE.bind_recovery_receipt_v4(receipt, value, REV, runner_hashes)
        self.assertEqual(bound["status"], "recovered")
        self.assertFalse(bound["automaticActivationRetry"])
        self.assertEqual(bound["dormantHandoverReceiptSha256"], preflight["dormantReceipt"]["receiptSha256"])

        def resign(candidate):
            candidate["canonicalSha256"] = MODULE.digest({
                key: item for key, item in candidate.items() if key != "canonicalSha256"
            })
            return candidate

        drifts = (
            ("rollback incomplete", lambda item: item["rollback"].__setitem__("status", "incomplete")),
            ("rollback incomplete", lambda item: item["rollback"].__setitem__("civicAuthorityEffects", True)),
            ("final proof incomplete", lambda item: item["rollback"]["finalChecks"].__setitem__("civicAuthorityEffects", True)),
            ("exposure-break proof drift", lambda item: item["rollback"]["finalChecks"]["exposureBreak"].__setitem__("civicAuthorityEffects", True)),
            ("present target field set drift", lambda item: item["preflight"]["targets"]["gateway.networkPolicy"].__setitem__("civicAuthorityEffects", True)),
            ("deletion UID drift", lambda item: item["rollback"]["deleted"][-1].__setitem__("uid", "wrong-uid")),
            ("Service absence", lambda item: item["rollback"]["deleted"][0].__setitem__("foregroundPropagation", True)),
            ("deletion UID drift", lambda item: item["rollback"]["deleted"][-1].__setitem__("foregroundPropagation", True)),
            ("deletion UID drift", lambda item: item["rollback"]["deleted"][-1].__setitem__("finalizersRemovedByRunner", 0)),
            ("protected cluster binding drift", lambda item: item["rollback"]["finalChecks"]["clusterBinding"].__setitem__("apiOrigin", "https://wrong.invalid")),
            ("cluster resourceVersion moved backwards", lambda item: item["preflight"]["clusterBinding"]["initial"].__setitem__("kubeSystemNamespaceResourceVersion", "11")),
            ("exact dormant incident Flux state", lambda item: item["preflight"]["flux"]["gateway"].__setitem__("generation", True)),
            ("exact dormant incident Flux state", lambda item: item["preflight"]["flux"]["gateway"].__setitem__("resourceVersion", "0")),
            ("shared Source preflight drift", lambda item: item["preflight"]["source"].__setitem__("observedGeneration", True)),
            ("shared Source preflight drift", lambda item: item["preflight"]["source"].__setitem__("resourceVersion", "²")),
            ("shared Source preflight drift", lambda item: item["preflight"]["source"].__setitem__("resourceVersion", "0")),
            ("shared Source no longer binds preflight", lambda item: item["rollback"]["finalChecks"]["sharedSource"].__setitem__("resourceVersion", "39")),
            ("quiet absence proof drift", lambda item: item["rollback"]["finalChecks"]["absence"].pop("checks")),
        )
        for message, mutate in drifts:
            with self.subTest(message=message):
                drifted = copy.deepcopy(receipt); mutate(drifted); resign(drifted)
                with self.assertRaisesRegex(MODULE.ActivationError, message):
                    MODULE.bind_recovery_receipt_v4(drifted, value, REV, runner_hashes)

    def test_v4_run29_recovery_preflight_verifier_binds_profile_specific_flux_and_six_present_targets(self):
        value = ready_policy(); incident = run29_recovery_incident_ownership()
        preflight = valid_run29_recovery_preflight(value)
        self.assertEqual(
            MODULE.validate_recovery_preflight_receipt_v4(preflight, value, REV, incident),
            preflight,
        )
        drifted = copy.deepcopy(preflight)
        drifted["targets"]["gateway.ingress"]["sourceReceiptSha256"] = MODULE.FAILED_ACTIVATION_CANONICAL_SHA256
        with self.assertRaisesRegex(MODULE.ActivationError, "target ownership drift"):
            MODULE.validate_recovery_preflight_receipt_v4(drifted, value, REV, incident)

    def test_v4_run29_recovery_receipt_verifier_binds_ingress_service_and_all_six_owned_deletions(self):
        value = ready_policy(); runner_hashes = {"runner": sha()}
        incident = run29_recovery_incident_ownership()
        preflight = valid_run29_recovery_preflight(value)
        rollback = valid_run29_recovery_rollback(value, preflight)
        unsigned = {
            "schemaVersion": MODULE.RECOVERY_RECEIPT_SCHEMA,
            "status": "recovered",
            "protectedRevision": REV,
            "activationPolicySha256": MODULE.POLICY.activation_policy_sha256(value),
            "protectedRunnerFileSha256": runner_hashes,
            "recoveredIncident": incident,
            "preflight": preflight,
            "rollback": rollback,
            "automaticActivationRetry": False,
            "civicAuthorityEffects": False,
        }
        receipt = unsigned | {"canonicalSha256": MODULE.digest(unsigned)}
        bound = MODULE.bind_recovery_receipt_v4(receipt, value, REV, runner_hashes)
        self.assertEqual(bound["sourceFailedReceiptSha256"], MODULE.RUN29_FAILED_ACTIVATION_CANONICAL_SHA256)
        self.assertEqual(
            [item["logicalName"] for item in rollback["deleted"]],
            [
                "gateway.ingress", "gateway.service", "gateway.service",
                "gateway.deployment", "gateway.serviceAccount",
                "workbenchIngress.networkPolicy", "gateway.networkPolicy",
            ],
        )
        drifted = copy.deepcopy(receipt)
        drifted["rollback"]["deleted"][0]["uid"] = "foreign-ingress"
        drifted["canonicalSha256"] = MODULE.digest({
            key: item for key, item in drifted.items() if key != "canonicalSha256"
        })
        with self.assertRaisesRegex(MODULE.ActivationError, "deletion UID drift"):
            MODULE.bind_recovery_receipt_v4(drifted, value, REV, runner_hashes)

    def test_v4_success_receipt_rejects_incomplete_object_set(self):
        value = ready_policy(); facts = valid_success_facts(value)
        facts["objectCreateResults"] = facts["objectCreateResults"][:5]
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            with self.assertRaisesRegex(MODULE.ActivationError, "object receipt set incomplete"):
                MODULE.validate_success_facts_v4(facts, value, REV)

    def test_v4_complete_receipt_binds_flux_source_before_and_after(self):
        value = ready_policy(); facts = valid_success_facts(value)
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            MODULE.validate_success_facts_v4(facts, value, REV)
            facts["fluxTransaction"]["sourceAfterReady"]["artifactRevision"] = "main@sha1:" + "c" * 40
            with self.assertRaisesRegex(MODULE.ActivationError, "source proof"):
                MODULE.validate_success_facts_v4(facts, value, REV)

    def test_v4_success_receipt_rejects_forged_or_stale_flux_transaction_proofs(self):
        value = ready_policy(); exact = valid_success_facts(value)
        drifts = (
            ("CAS receipt", lambda facts: facts["fluxTransaction"].__setitem__("casUnsuspended", {})),
            ("Ready proof", lambda facts: facts["fluxTransaction"]["ready"].__setitem__("gateway", {})),
            ("Ready proof", lambda facts: facts["fluxTransaction"]["ready"]["gateway"].__setitem__("uid", "foreign")),
            ("Ready proof", lambda facts: facts["fluxTransaction"]["ready"]["gateway"].__setitem__("generation", True)),
            ("Ready proof", lambda facts: facts["fluxTransaction"]["ready"]["gateway"].__setitem__("activeSpecSha256", sha("f"))),
            ("Ready proof", lambda facts: facts["fluxTransaction"]["ready"]["gateway"].__setitem__("lastAppliedRevision", f"main@sha1:{'f' * 40}")),
            ("final Ready proof", lambda facts: facts["fluxTransaction"]["finalReady"]["gateway"].__setitem__("generation", 3)),
            ("source proof", lambda facts: facts["fluxTransaction"]["sourceBeforeCas"].__setitem__("resourceVersion", "not-decimal")),
            ("source proof", lambda facts: facts["fluxTransaction"]["sourceBeforeSuccess"].__setitem__("uid", "replacement-source")),
        )
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            MODULE.validate_success_facts_v4(exact, value, REV)
            for message, mutate in drifts:
                drifted = copy.deepcopy(exact); mutate(drifted)
                with self.subTest(message=message), self.assertRaisesRegex(
                    MODULE.ActivationError, message,
                ):
                    MODULE.validate_success_facts_v4(drifted, value, REV)

    def test_v4_success_receipt_deep_validates_haproxy_secrets_and_preservation(self):
        value = ready_policy(); exact = valid_success_facts(value)
        drifts = (
            ("HAProxy readiness", lambda facts: facts["haproxy"].__setitem__("generation", True)),
            ("HAProxy readiness", lambda facts: facts["postFluxApplication"]["haproxy"].__setitem__("numberReady", "3")),
            ("Secret receipt", lambda facts: facts["secretMaterialization"]["beforeCreate"]["secrets"]["config"].__setitem__("namespace", "foreign")),
            ("Secret receipt", lambda facts: facts["secretMaterialization"]["beforeCreate"]["secrets"]["config"].__setitem__("keys", [])),
            ("Secret receipt", lambda facts: facts["secretMaterialization"]["beforeCreate"]["secrets"]["config"].__setitem__("uid", "")),
            ("Secret receipt", lambda facts: facts["secretMaterialization"]["beforeCreate"]["secrets"]["config"].__setitem__("resourceVersion", "²")),
            ("Secret receipt", lambda facts: facts["secretMaterialization"]["beforeCreate"]["secrets"]["config"].__setitem__("valuesRead", True)),
            ("preservation receipt", lambda facts: facts["preservation"]["webIngress"].__setitem__("target", value["preservation"]["existingWorkbenchNetworkPolicy"]["target"])),
            ("preservation receipt", lambda facts: facts["preservation"]["webIngress"].__setitem__("afterCanonicalSha256", sha("f"))),
        )
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            MODULE.validate_success_facts_v4(exact, value, REV)
            for message, mutate in drifts:
                drifted = copy.deepcopy(exact); mutate(drifted)
                with self.subTest(message=message), self.assertRaisesRegex(
                    MODULE.ActivationError, message,
                ):
                    MODULE.validate_success_facts_v4(drifted, value, REV)

    def test_v4_success_receipt_binds_post_flux_health_routes_and_same_deployment_uid(self):
        value = ready_policy(); facts = valid_success_facts(value)
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            MODULE.validate_success_facts_v4(facts, value, REV)
            uid_drift = copy.deepcopy(facts)
            uid_drift["postFluxApplication"]["deployment"]["uid"] = "replacement-deployment-uid"
            with self.assertRaisesRegex(MODULE.ActivationError, "Deployment continuity"):
                MODULE.validate_success_facts_v4(uid_drift, value, REV)
            route_drift = copy.deepcopy(facts)
            route_drift["postFluxApplication"]["routeMatrix"] = []
            with self.assertRaisesRegex(MODULE.ActivationError, "route matrix"):
                MODULE.validate_success_facts_v4(route_drift, value, REV)
            label_drift = copy.deepcopy(facts)
            label_drift["semanticObjects"]["gateway.deployment"]["fluxTrackingLabels"][
                "kustomize.toolkit.fluxcd.io/name"
            ] = "wrong-owner"
            with self.assertRaisesRegex(MODULE.ActivationError, "Flux ownership/semantics"):
                MODULE.validate_success_facts_v4(label_drift, value, REV)

    def test_v4_durable_success_receipt_verifier_binds_checksum_files_policy_and_facts(self):
        value = ready_policy(); runner_hashes = {"scripts/runner.py": sha("1")}
        unsigned = {
            "schemaVersion": MODULE.RECEIPT_SCHEMA,
            "status": "activated",
            "protectedRevision": REV,
            "activationPolicySha256": MODULE.POLICY.activation_policy_sha256(value),
            "protectedRunnerFileSha256": runner_hashes,
            "trustedLiveFacts": valid_success_facts(value),
            "civicAuthorityEffects": False,
        }
        receipt = unsigned | {"canonicalSha256": MODULE.digest(unsigned)}
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            bound = MODULE.bind_success_receipt_v4(receipt, value, REV, runner_hashes)
        self.assertEqual(bound["status"], "activated")
        self.assertEqual(bound["receiptSha256"], receipt["canonicalSha256"])
        self.assertFalse(bound["civicAuthorityEffects"])

        corrupted = copy.deepcopy(receipt)
        corrupted["trustedLiveFacts"]["fluxTransaction"]["sourceAfterReady"]["artifactRevision"] = "main@sha1:" + "c" * 40
        corrupted["canonicalSha256"] = MODULE.digest({key: item for key, item in corrupted.items() if key != "canonicalSha256"})
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            with self.assertRaisesRegex(MODULE.ActivationError, "source proof"):
                MODULE.bind_success_receipt_v4(corrupted, value, REV, runner_hashes)

        wrong_hashes = copy.deepcopy(receipt)
        wrong_hashes["protectedRunnerFileSha256"] = {"scripts/runner.py": sha("2")}
        wrong_hashes["canonicalSha256"] = MODULE.digest({key: item for key, item in wrong_hashes.items() if key != "canonicalSha256"})
        with self.assertRaisesRegex(MODULE.ActivationError, "protected file drift"):
            MODULE.bind_success_receipt_v4(wrong_hashes, value, REV, runner_hashes)

        foreign_cluster = copy.deepcopy(receipt)
        for binding in foreign_cluster["trustedLiveFacts"]["clusterBinding"].values():
            binding["apiOrigin"] = "https://10.0.0.1:6443"
            binding["caCertificateSha256"] = sha("3")
            binding["apiServerSpkiSha256"] = sha("4")
            binding["kubeSystemNamespaceUid"] = "foreign-cluster"
        foreign_cluster["canonicalSha256"] = MODULE.digest({
            key: item for key, item in foreign_cluster.items() if key != "canonicalSha256"
        })
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            with self.assertRaisesRegex(MODULE.ActivationError, "protected binding drift"):
                MODULE.bind_success_receipt_v4(foreign_cluster, value, REV, runner_hashes)

    def test_v4_owned_receipt_loader_rejects_links_modes_size_and_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root / "activation.json"
            path.write_text('{"status":"activated"}'); path.chmod(0o600)
            self.assertEqual(MODULE.load_owned_receipt_v4(path, "fixture"), {"status": "activated"})
            linked = root / "linked.json"; os.link(path, linked)
            with self.assertRaisesRegex(MODULE.ActivationError, "nlink-one"):
                MODULE.load_owned_receipt_v4(path, "fixture")
            linked.unlink(); path.chmod(0o644)
            with self.assertRaisesRegex(MODULE.ActivationError, "0600"):
                MODULE.load_owned_receipt_v4(path, "fixture")
            path.chmod(0o600); path.write_text('{"status":"a","status":"b"}')
            with self.assertRaisesRegex(MODULE.ActivationError, "duplicate"):
                MODULE.load_owned_receipt_v4(path, "fixture")

    def test_v4_cli_has_effect_free_success_receipt_mode(self):
        parsed = MODULE.parse_args([
            "--expected-protected-revision",
            REV,
            "--verify-success-receipt-fd",
            "17",
        ])
        self.assertEqual(parsed.verify_success_receipt_fd, 17)
        self.assertFalse(parsed.live)

    def test_v4_cli_has_explicit_mutually_exclusive_recovery_and_verifier_modes(self):
        recover = MODULE.parse_args([
            "--expected-protected-revision", REV,
            "--recover-rollback-incomplete-receipt-fd", "21",
        ])
        self.assertEqual(recover.recover_rollback_incomplete_receipt_fd, 21)
        self.assertFalse(recover.live)
        verify = MODULE.parse_args([
            "--expected-protected-revision", REV,
            "--verify-recovery-receipt-fd", "22",
        ])
        self.assertEqual(verify.verify_recovery_receipt_fd, 22)
        source_verify = MODULE.parse_args([
            "--expected-protected-revision", REV,
            "--verify-failed-activation-recovery-source-fd", "23",
        ])
        self.assertEqual(source_verify.verify_failed_activation_recovery_source_fd, 23)
        with self.assertRaises(SystemExit):
            MODULE.parse_args([
                "--expected-protected-revision", REV,
                "--live",
                "--recover-rollback-incomplete-receipt-fd", "21",
            ])
        source = inspect.getsource(MODULE.main)
        start = source.index("if a.recover_rollback_incomplete_receipt_fd is not None:")
        end = source.index("require(a.live is True", start)
        recovery_branch = source[start:end]
        self.assertIn("bind_handover_receipt_pair_v4(", recovery_branch)
        self.assertIn("bind_failed_activation_recovery_source_v4(", recovery_branch)
        self.assertIn("recover_incomplete_activation_v4(", recovery_branch)
        self.assertIn("return 0", recovery_branch)
        self.assertNotIn("secret_materialization_ownership", recovery_branch)
        self.assertNotIn("activate(", recovery_branch)

    def test_v4_nonce_removal_failure_rolls_back_bound_create_without_rediscovery(self):
        value = ready_policy()
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            resources = MODULE.POLICY.expected_gateway_resources(value)
        rendered = {
            "gateway.networkPolicy": {"desired": resources["networkPolicy"], "path": "np", "blobSha256": sha()},
            "workbenchIngress.networkPolicy": {"desired": MODULE.POLICY.expected_workbench_ingress_network_policy(), "path": "wnp", "blobSha256": sha()},
            "gateway.serviceAccount": {"desired": resources["serviceAccount"], "path": "sa", "blobSha256": sha()},
            "gateway.service": {"desired": resources["service"], "path": "svc", "blobSha256": sha()},
            "gateway.deployment": {"desired": resources["deployment"], "path": "dep", "blobSha256": sha()},
            "gateway.ingress": {"desired": resources["ingress"], "path": "ing", "blobSha256": sha()},
        }
        snapshot = Mock(path=Path("/snapshot")); snapshot.close = Mock()
        cluster = {
            "apiOrigin": value["clusterIdentity"]["apiOrigin"],
            "caCertificateSha256": value["clusterIdentity"]["caCertificateSha256"],
            "apiServerSpkiSha256": value["clusterIdentity"]["apiServerSpkiSha256"],
            "kubeSystemNamespaceUid": value["clusterIdentity"]["kubeSystemNamespaceUid"],
        }
        desired = rendered["gateway.networkPolicy"]["desired"]
        created = MODULE.CreatedV4(
            "gateway.networkPolicy",
            desired,
            admitted(MODULE.POLICY.with_operation_nonce(desired, "7" * 64), "network-policy-uid", "70"),
            {"operationNonce": "7" * 64, "temporaryNonceRemoved": False},
        )
        sink = Mock()
        rollback_result = {"status": "complete", "finalizersRemovedByRunner": False}
        rediscover = patch.object(MODULE, "rediscover_uncertain_create_v4", return_value=None)
        rollback = patch.object(MODULE, "rollback_v4", return_value=rollback_result)
        patches = (
            patch.object(MODULE.POLICY, "assert_activation_ready", return_value=value),
            patch.object(MODULE, "render_v4", return_value=rendered),
            patch.object(MODULE, "snapshot_kubeconfig_v4", return_value=snapshot),
            patch.object(MODULE, "cluster_binding_v4", return_value=cluster),
            patch.object(MODULE, "anonymous_publication_v4", return_value={}),
            patch.object(MODULE, "endpoint_facts_v4", return_value={}),
            patch.object(MODULE, "preservation_v4", return_value={}),
            patch.object(MODULE, "flux_preflight_v4", return_value={}),
            patch.object(MODULE, "exact_absence_preflight_v4", return_value={"status": "all-six-exact-target-names-absent", "targets": [{}] * 6}),
            patch.object(MODULE, "secret_materialization_v4", return_value={}),
            patch.object(MODULE, "require_tracer_activation_binding_v4"),
            patch.object(MODULE, "policy_union_v4", return_value={}),
            patch.object(MODULE, "create_v4", return_value=created),
            patch.object(MODULE, "remove_operation_nonce_v4", side_effect=MODULE.ActivationError("nonce removal failed")),
            rediscover,
            rollback,
        )
        with tempfile.TemporaryDirectory() as directory:
            kube = Path(directory) / "kube"; kube.write_text("fixture")
            with contextlib.ExitStack() as stack:
                entered = [stack.enter_context(item) for item in patches]
                with self.assertRaisesRegex(MODULE.ActivationError, "rolled-back"):
                    MODULE.activate(value, REV, str(kube), Fake(), True, sink, {"runner": sha()}, dormant_ownership(), None, {})
        entered[-2].assert_not_called()
        rollback_call = entered[-1].call_args
        self.assertEqual(rollback_call.args[3], [created])
        self.assertIsNone(rollback_call.args[6])
        failure = sink.commit.call_args.args[0]
        self.assertEqual(len(failure["objectCreateResults"]), 1)
        snapshot.close.assert_called_once()

    def test_v4_operator_termination_after_mutation_enters_bounded_rollback_and_receipt(self):
        value = ready_policy()
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            resources = MODULE.POLICY.expected_gateway_resources(value)
        rendered = {
            "gateway.networkPolicy": {"desired": resources["networkPolicy"], "path": "np", "blobSha256": sha()},
            "workbenchIngress.networkPolicy": {"desired": MODULE.POLICY.expected_workbench_ingress_network_policy(), "path": "wnp", "blobSha256": sha()},
            "gateway.serviceAccount": {"desired": resources["serviceAccount"], "path": "sa", "blobSha256": sha()},
            "gateway.service": {"desired": resources["service"], "path": "svc", "blobSha256": sha()},
            "gateway.deployment": {"desired": resources["deployment"], "path": "dep", "blobSha256": sha()},
            "gateway.ingress": {"desired": resources["ingress"], "path": "ing", "blobSha256": sha()},
        }
        snapshot = Mock(path=Path("/snapshot")); snapshot.close = Mock()
        cluster = {"apiOrigin": value["clusterIdentity"]["apiOrigin"], "caCertificateSha256": value["clusterIdentity"]["caCertificateSha256"], "apiServerSpkiSha256": value["clusterIdentity"]["apiServerSpkiSha256"], "kubeSystemNamespaceUid": value["clusterIdentity"]["kubeSystemNamespaceUid"]}
        sink = Mock(); rollback = {"status": "complete", "finalizersRemovedByRunner": False}
        patches = (
            patch.object(MODULE.POLICY, "assert_activation_ready", return_value=value),
            patch.object(MODULE, "render_v4", return_value=rendered),
            patch.object(MODULE, "snapshot_kubeconfig_v4", return_value=snapshot),
            patch.object(MODULE, "cluster_binding_v4", return_value=cluster),
            patch.object(MODULE, "anonymous_publication_v4", return_value={}),
            patch.object(MODULE, "endpoint_facts_v4", return_value={}),
            patch.object(MODULE, "preservation_v4", return_value={}),
            patch.object(MODULE, "flux_preflight_v4", return_value={}),
            patch.object(MODULE, "exact_absence_preflight_v4", return_value={"status": "all-six-exact-target-names-absent", "targets": [{}] * 6}),
            patch.object(MODULE, "secret_materialization_v4", return_value={}),
            patch.object(MODULE, "require_tracer_activation_binding_v4"),
            patch.object(MODULE, "policy_union_v4", return_value={}),
            patch.object(MODULE, "create_v4", side_effect=MODULE.ActivationInterrupted(MODULE.signal.SIGTERM)),
            patch.object(MODULE, "rediscover_uncertain_create_v4", return_value=None),
            patch.object(MODULE, "rollback_v4", return_value=rollback),
        )
        with tempfile.TemporaryDirectory() as directory:
            kube = Path(directory) / "kube"; kube.write_text("fixture")
            with contextlib.ExitStack() as stack:
                entered = [stack.enter_context(item) for item in patches]
                with self.assertRaisesRegex(MODULE.ActivationError, "rolled-back"):
                    MODULE.activate(value, REV, str(kube), Fake(), True, sink, {"runner": sha()}, dormant_ownership(), None, {})
        failure = sink.commit.call_args.args[0]
        self.assertEqual(failure["status"], "rolled-back")
        self.assertEqual(failure["termination"], {"interrupted": True, "signal": MODULE.signal.SIGTERM, "signalsDeferredDuringRollback": True})
        entered[-1].assert_called_once(); snapshot.close.assert_called_once()

    def test_v4_success_receipt_persistence_failure_is_inside_transaction_and_rolls_back(self):
        value = ready_policy()
        with patch.object(MODULE.POLICY, "STATIC_ACTIVATION_POLICY", value):
            resources = MODULE.POLICY.expected_gateway_resources(value)
        rendered = {
            "gateway.networkPolicy": {"desired": resources["networkPolicy"], "path": "np", "blobSha256": sha()},
            "workbenchIngress.networkPolicy": {"desired": MODULE.POLICY.expected_workbench_ingress_network_policy(), "path": "wnp", "blobSha256": sha()},
            "gateway.serviceAccount": {"desired": resources["serviceAccount"], "path": "sa", "blobSha256": sha()},
            "gateway.service": {"desired": resources["service"], "path": "svc", "blobSha256": sha()},
            "gateway.deployment": {"desired": resources["deployment"], "path": "dep", "blobSha256": sha()},
            "gateway.ingress": {"desired": resources["ingress"], "path": "ing", "blobSha256": sha()},
        }
        snapshot = Mock(path=Path("/snapshot")); snapshot.close = Mock()
        source = {"metadata": {"uid": "source", "resourceVersion": "1"}, "status": {"artifact": {"revision": f"main@sha1:{REV}"}}}
        dormant = {"owners": {"gateway": {"kustomization": {"metadata": {"uid": "g"}}}, "workbenchIngress": {"kustomization": {"metadata": {"uid": "w"}}}}, "source": source}
        cluster = {"apiOrigin": value["clusterIdentity"]["apiOrigin"], "caCertificateSha256": value["clusterIdentity"]["caCertificateSha256"], "apiServerSpkiSha256": value["clusterIdentity"]["apiServerSpkiSha256"], "kubeSystemNamespaceUid": value["clusterIdentity"]["kubeSystemNamespaceUid"]}
        def create(_r, _kube, logical, item, nonce):
            desired = item["desired"]; observed = admitted(MODULE.POLICY.with_operation_nonce(desired, nonce), logical + "-uid")
            return MODULE.CreatedV4(logical, desired, observed, {"operationNonce": nonce, "temporaryNonceRemoved": False})
        def remove(_r, _kube, created, _nonce): created.receipt["temporaryNonceRemoved"] = True; created.observed = admitted(created.desired, created.logical_name + "-uid", "11")
        sink = Mock(); sink.commit.side_effect = [OSError("directory fsync failed"), None]
        rollback = {"status": "complete", "finalizersRemovedByRunner": False}
        rollback_patch = patch.object(MODULE, "rollback_v4", return_value=rollback)
        deployment_health = {
            "metadata": {
                "uid": "gateway.deployment-uid", "resourceVersion": "12", "generation": 1,
            },
            "status": {"observedGeneration": 1, "availableReplicas": value["runtime"]["replicas"]},
        }
        haproxy_health = {
            "uid": "haproxy-uid", "resourceVersion": "20", "observedGeneration": 1,
            "desiredNumberScheduled": 3, "updatedNumberScheduled": 3,
            "numberAvailable": 3, "numberReady": 3,
            "rateLimit": value["httpBoundary"]["haproxyRateLimit"],
        }
        policy_union_patch = patch.object(MODULE, "policy_union_v4", return_value={"ok": True})
        health_patch = patch.object(
            MODULE, "health_v4",
            return_value=(copy.deepcopy(deployment_health), copy.deepcopy(haproxy_health)),
        )
        route_patch = patch.object(MODULE, "route_matrix_v4", return_value=[{}])
        patches = (
            patch.object(MODULE.POLICY, "assert_activation_ready", return_value=value),
            patch.object(MODULE, "render_v4", return_value=rendered), patch.object(MODULE, "snapshot_kubeconfig_v4", return_value=snapshot),
            patch.object(MODULE, "cluster_binding_v4", return_value=cluster), patch.object(MODULE, "anonymous_publication_v4", return_value={"manifestDigest": value["productPins"]["imageManifestDigest"]}),
            patch.object(MODULE, "endpoint_facts_v4", return_value={"ok": True}), patch.object(MODULE, "preservation_v4", return_value={}),
            patch.object(MODULE, "flux_preflight_v4", return_value=dormant), patch.object(MODULE, "exact_absence_preflight_v4", return_value={"status": "all-six-exact-target-names-absent", "targets": [{}] * 6}),
            patch.object(
                MODULE,
                "secret_materialization_v4",
                return_value={"status": "same", "secrets": {"x": {}}},
            ),
            patch.object(MODULE, "require_tracer_activation_binding_v4"),
            policy_union_patch,
            patch.object(MODULE, "create_v4", side_effect=create), patch.object(MODULE, "remove_operation_nonce_v4", side_effect=remove),
            health_patch, patch.object(MODULE, "runtime_image_v4", return_value={"readyPodCount": 1, "pods": [{}]}),
            patch.object(MODULE, "database_status_v4", return_value=valid_database_status(value)), route_patch,
            patch.object(MODULE, "shared_source_revision_v4", return_value=source), patch.object(MODULE, "unsuspend_both_v4", return_value={"gateway": {"metadata": {"resourceVersion": "2"}}, "workbenchIngress": {"metadata": {"resourceVersion": "2"}}}),
            patch.object(MODULE, "wait_both_ready_v4", return_value={"gateway": {}, "workbenchIngress": {}}), patch.object(MODULE, "semantic_postconditions_v4", return_value={str(i): {} for i in range(6)}),
            patch.object(MODULE, "verify_preservation_v4", return_value={"webIngress": {"byteIdenticalCanonicalJson": True}, "existingWorkbenchNetworkPolicy": {"byteIdenticalCanonicalJson": True}}),
            patch.object(MODULE, "final_flux_success_proof_v4", return_value={
                "ready": {"gateway": {}, "workbenchIngress": {}},
                "source": {"uid": "source", "resourceVersion": "1", "artifactRevision": f"main@sha1:{REV}"},
            }),
            patch.object(MODULE, "validate_success_facts_v4"), rollback_patch,
        )
        with tempfile.TemporaryDirectory() as directory:
            kube = Path(directory) / "kube"; kube.write_text("fixture")
            with contextlib.ExitStack() as stack:
                entered = [stack.enter_context(item) for item in patches]
                with self.assertRaisesRegex(MODULE.ActivationError, "rolled-back"):
                    MODULE.activate(value, REV, str(kube), Fake(), True, sink, {"runner": sha()}, dormant_ownership(), None, {})
        self.assertEqual(sink.commit.call_count, 2)
        self.assertEqual(sink.commit.call_args_list[1].args[0]["status"], "rolled-back")
        self.assertEqual(entered[patches.index(health_patch)].call_count, 2)
        self.assertEqual(entered[patches.index(route_patch)].call_count, 2)
        self.assertEqual(
            entered[patches.index(policy_union_patch)].call_args_list[-1].kwargs,
            {"flux_tracking_state": "complete"},
        )
        entered[-1].assert_called_once(); snapshot.close.assert_called_once()

if __name__ == "__main__": unittest.main()
