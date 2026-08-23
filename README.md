# Röbel staging operations

This public repository is the value-free, reviewed desired-state source for
exactly two existing Röbel staging Deployments and the fixed, internal-only
Public Mecky chat network boundary:

- `stadtstack-roebel-web-preview/roebel-web-presentation`
- `stadtstack-roebel-staging-lab/public-mecky`
- `stadtstack-roebel-staging-lab/Service/public-mecky`
- `stadtstack-roebel-staging-lab/NetworkPolicy/public-mecky-chat-from-web`
- `stadtstack-roebel-web-preview/NetworkPolicy/roebel-web-presentation`
- `stadtstack-roebel-web-preview/Ingress/roebel-web-presentation`

It is deliberately not an infrastructure repository and not a civic record.
It contains immutable image digests, source revisions, checksums, Kubernetes
object identities, and references to existing ConfigMaps or Secrets. It may
not contain a Secret object, a Secret value, credentials, personal data,
posts, discussions, Civic Cases, municipal records, or runtime status.

## Inert Case staging runtime gate

`case-staging-topology/` is a closed-world `runtime_gate_v1` review contract
for the future control and public Case processes. It remains
`mode: inert_review_only`; both `reconciliationAllowed` and
`fluxKustomizationAllowed` are false. The contract has exactly three
ClusterIP services: admission (18085) and private outbox (18087) select only
control, while public binding (18086) selects only public. Capability-free
control and public probe ports are direct-only (18088/18089) and have no
Service.

The future control process is constrained to its tokenless ServiceAccount and
may reference only the already-provisioned control runtime Secret and state
PVC. The public process is separately tokenless and is explicitly forbidden
from Secret, PVC, and RBAC references. The control image and public image are
both deliberately blocked until exact immutable digests, provenance, and SPDX
SBOM evidence exist; this contract uses no image placeholder.

Default deny remains in force. Public may egress only to DNS and the control
private-outbox port; control accepts only public on that port. The gate reserves
an exact Röbel Web ingress peer on 18086, but the current protected Web policy
does not yet allow the matching egress, so the route is not live. Admission is
also intentionally default-denied because no staff gateway identity is pinned.
The reviewed Stadtstack control application module is pending admission until
its PR is merged; it is not represented as an admitted release on this
Operations branch. Its immutable release and exact deployment/storage
preflight are still pending, so no bind is authorized. The staging token-adapter
marker is staging-only and rejected for production.

`controlDeploymentPreflight` is a remote-but-owned Operations record. It fixes
the staging environment, `roebel-mueritz` municipality, namespace, tokenless
`roebel-case-steward-control` workload, its Recreate/no-overlap deployment
facts, `pod_network` listeners (18085/18087/18088), and the control-only
`/var/lib/stadtstack/case-control` root. The binding fixes marker file
`.stadtstack-control-storage-v1.json` and marker schema
`staging_case_control_storage_marker_v1`. It also reserves the exact PVC
identity, PV, StorageClass, singular access/volume mode, requested bytes,
filesystem uid/gid/mode/type/minimum-free-space, marker checksum/ownership,
release digest, Operations topology checksum, and independently pinned binding
checksum fields. Those live facts are deliberately `null` until a reviewed
cluster observation exists, and every null is listed in deterministic
`missingEvidence`; the status therefore remains `blocked`. Public workload
records never receive these storage fields.

The reviewed source binding and the deployment pin are separate: the nested
`binding.bindingChecksum` identifies the exact reviewed binding projection,
while the top-level `expectedBindingChecksum` is the independently pinned
checksum expected by the immutable deployment configuration. Both remain
`null` until the source and deployment review records exist; neither is a
runtime secret or a live cluster lookup.

The separate protected policy-migration ceremony must admit the reviewed
application release, exact storage preflight, Web-egress rule, deployable
composition, exact image evidence, and the required staff-gateway decision
before any Flux reference may be added. Routine image promotion preserves every
runtime-gate byte unchanged.

## Inert case-state recovery activation gate

`contracts/stadtstack-case-runtime-contract.json` records the next, separate
recovery ceremony. The outer record remains
`stadtstack_case_runtime_contract_v1` with `mode: inert_review_only`, an empty
allowed-kind set and both reconciliation flags false. Its
`recoveryActivationGate` evidence inventory has the distinct schema
`stadtstack_case_recovery_evidence_inventory_v1` and status `blocked`; it
cannot be confused with Stadtstack's opaque, data-free runtime gate. The
inventory is evidence, not a controller: it creates no Kubernetes object, Job,
PVC, Deployment, Secret, Flux object, bucket credential, or object-store
request.

The gate reserves the staging/`roebel-mueritz` scope and the exact source and
target PVC identity, target PV, UUIDv7 `recoveryOperationId`, independently
reviewed `controlDeploymentBindingChecksum`, and immutable
`restoreVerifierReleaseDigest`. Its catalog record keeps the
`catalogLocatorChecksum`, CAS generation, backup ID, and exact completion
receipt/encrypted-manifest object locator. Each locator pins bucket, key,
object version, and checksum; the completion receipt additionally pins its
key version. The operational signer is an active Ed25519 signer with purpose
`staging_case_recovery_attestation`; its key ID/version, DER SPKI and SHA-256
pin, and active-from/active-until window remain evidence-bound fields.

The policy limits recovery age to exactly 86400 seconds and restore duration
to exactly 14400 seconds. The seal binding reserves the shutdown-seal,
database, release, WAL-checkpoint, and recovery-evidence checksums. The
restore report requires the independently recomputed
`restoreReportChecksum` and the exact verifier release pin. The attestation
reserves its checksum, Ed25519 signature, issued/expiry window, seal, backup,
PVC, store, and signer pins.
Every live value is currently `null` and appears once, in deterministic order,
in `missingEvidence`; placeholders, partial evidence, ready status, and
reconciliation are rejected by the focused verifier and tests.

## Inert recovery composition review contract (v2)

`contracts/stadtstack-case-recovery-composition-contract.json` is the
Operations-side composition record for the same ceremony. It is intentionally
separate from the application evidence inventory: it describes how a future
review will connect the application protocols without becoming an activation
controller. Its status is `inert_review_only`; it has no allowed kinds, no
resource documents, no Secret or credential material, and no Flux object.

The protocol pins are the current v2 boundaries: `case_shutdown_seal_v2`,
`staging_case_recovery_attestation_v2`, `staging_case_recovery_gate_v2`,
`case_durable_deployment_claim_v1`, `case_store_bootstrap_v1`,
`case_open_epoch_v1`, and the `case_recovery_activation_v2` recovery marker.
The review stages are deliberately ordered:

1. Quiesce the source owner and obtain the canonical v2 shutdown seal.
2. Produce an encrypted bundle containing the exact SQLite bytes, canonical
   source deployment claim, canonical v2 seal, and pinned object locators and
   checksums.
3. Prove a fresh target claim with distinct PVC/PV identity and a pinned
   StorageClass; the source volume may not be reused.
4. Restore and verify in isolation, with no database creation, exact schema
   verification, baseline-dominance proof, and the v2 recovery marker.
5. Bind the restored control and public slots to the exact target claim.
6. Emit a future exact handoff receipt. This is a receipt shape only, not a
   Flux resource and not permission to reconcile.

All live stage and aggregate evidence remains `null` and is enumerated in
`missingEvidence`. The remaining blockers are the source PVC/claim and clean
seal, encrypted backup catalog and object-lock policy, restore verifier
release/SBOM, fresh target PVC/PV/StorageClass identity, isolated restore
report, control/public slot references, and the separately reviewed exact
handoff receipt. Until those facts are independently reviewed, this repository
cannot read credentials, mutate storage, create a restore job, activate a
workload, or hand anything to Flux. The protected-base render verifier checks
this contract on every tree and rejects duplicate keys, open shapes, resource
documents, secret-shaped values, malformed identifiers, and cross-binding
drift.

## Promotion flow

1. Protected CI in `GiraeffleAeffle/Roebel-App` builds each changed component
   once and publishes an immutable GHCR digest with provenance and SPDX SBOM.
2. A protected promotion transaction verifies that evidence, compares the
   complete previous environment head, renders only the two admitted
   Deployments, and opens a pull request here. The fixed Service, Mecky
   NetworkPolicy, Web NetworkPolicy, and Web Ingress are preserved.
3. The `reviewed-render-admission` check runs the verifier from the protected
   base branch against the pull-request data. A pull request cannot weaken its
   own verifier.
4. Human review admits the new Release Set. Flux may read only
   `reviewed-render/roebel-staging/{web,public-mecky}` and reconciles through
   exact-name, namespace-scoped service accounts.

The protected `automatic-release-set-promotion` workflow removes the laptop
handoff between steps 1 and 2. Every five minutes (or on manual dispatch) it
looks up the exact protected Röbel-App `main` revision, pulls that revision's
immutable Release Set from public GHCR, independently verifies both SLSA and
SPDX attestations, compares the complete previous head, renders the five
allowed Deployment fields, and opens or replaces one automation-owned pull
request. A missing publication is retried on the next poll; a stale CAS fails
closed. The workflow has no Kubernetes, Talos, runtime Secret, civic-data, or
treasury access. CODEOWNER approval and the protected-base verifier remain the
deployment authority. Auto-merge is armed only after the pull request exists;
it waits for that required approval and verifier instead of asking the reviewer
to return for a separate merge click.

The five-minute poll keeps the scheduled wait below five minutes without
putting a cluster credential in GitHub. A manual dispatch can start the same
verified path immediately when a person is already testing staging.

Build completion is not deployment authority. Git promotion cannot create or
change Secrets, namespaces, RBAC, storage, networking, Talos, Hetzner
resources, civic publication state, governance state, or treasury state.

## Repository invariants

- `main` is protected by the exact `reviewed-render-admission` check, stale
  review dismissal, CODEOWNERS review, conversation resolution, linear
  history, and force-push/deletion denial.
- Ordinary promotion pull requests may change only the generated environment
  head, integrity receipt, live preconditions and two Deployment image bindings
  below `reviewed-render/roebel-staging`. The fixed Service, Mecky
  NetworkPolicy, Web NetworkPolicy, Web Ingress, and boundary migration receipt
  are preserved byte-for-byte by routine promotions.
- The complete previous head is the compare-and-swap boundary.
- Images are exact `ghcr.io/...@sha256:...` references with
  `imagePullPolicy: IfNotPresent`; tags are rejected.
- The protected-base verifier rejects extra files, symlinks, Secret
  payload-shaped fields, literal values for secret-shaped environment names,
  runtime metadata, and every object except two exact Deployments, one
  ClusterIP Service, two exact NetworkPolicies, one exact Web Ingress, and the
  eleven separately verified inert Case runtime-gate records (two
  ServiceAccounts, three ClusterIP Services, five closed-world NetworkPolicies,
  and their contract).
  Ordinary promotions preserve all topology records byte-for-byte. The Public
  Mecky Service is ClusterIP-only; the Web Ingress admits only the exact
  GET/HEAD read surface plus `POST /api/chat/mecky`, and the Web egress admits
  only the exact Public Mecky namespace/pod selectors on TCP 18084 in addition
  to its existing DNS and exact HTTPS egress rules.

Run the same check locally:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v scripts/test_verify_reviewed_render.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/verify-reviewed-render.py --root .
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v scripts/test_verify_case_staging_topology.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/verify-case-staging-topology.py --root .
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests/test_stadtstack_case_runtime_contract.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/verify-stadtstack-case-runtime-contract.py --root .
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v tests/test_stadtstack-case-recovery-composition-contract.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/verify-stadtstack-case-recovery-composition-contract.py --root .
```

The source remains safe to read anonymously. Runtime credentials and civic
authority stay outside Git and outside Flux.

## Fixed network-boundary bootstrap

Adding the Public Mecky ClusterIP, the two exact network boundaries, and the
Web Ingress is a protected policy migration, not an ordinary image promotion.
The `network-boundary-migration.json` receipt binds the exact object digests,
the no-authority/no-civic-effects posture, and the one-time RBAC bootstrap
intent. The bootstrap must grant the existing
`flux-roebel-staging/roebel-web-reconciler` only named `get`, `patch`, and
`update` access to `NetworkPolicy/roebel-web-presentation` and
`Ingress/roebel-web-presentation` in `stadtstack-roebel-web-preview`; it must
not grant create, delete, list, watch, Secret, ConfigMap, or broader namespace
access. The migration must be reviewed and tested as one exact-head bootstrap,
merged without widening the routine automation identity, and followed by
immediate restoration of the normal review rule. After that bootstrap, every
later Release Set promotion is again admitted by the protected-base verifier
and cannot change either network object or the Ingress.
