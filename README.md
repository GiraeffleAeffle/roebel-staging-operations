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
   source deployment claim, canonical v2 seal, and separate pinned catalog,
   completion-receipt, and encrypted-manifest locators with object versions,
   checksums, and key versions where applicable.
3. Prove a fresh target claim with distinct PVC/PV identity and a pinned
   StorageClass; the source volume may not be reused.
4. Restore and verify in isolation, with no database creation, exact schema
   verification, baseline-dominance proof, and an immutable verifier image
   pinned to provenance and SPDX SBOM checksums. This stage proves the restored
   bytes and schema; it cannot activate the runtime or create a recovery marker.
5. Bind the restored control slot to the exact target claim/PVC/PV and its
   private-outbox binding. The public slot is explicitly PVC/PV/Secret/RBAC
   free and may reference only the exact control slot/private-outbox checksums.
6. Emit a future exact handoff receipt with the reviewed Operations revision
   and resource-inventory checksum. Its canonical JSON checksum covers those
   review pins together with the source and target claims, target PVC/PV,
   release, recovery policy, and recovery attestation. This is a receipt shape
   only, not a Flux resource and not permission to reconcile.
7. After a separately authorized reconciliation, require the owner lock, a
   renewed recovery gate, the exact reviewed handoff receipt, source-to-target
   claim rotation, and pre-bind freshness before the runtime may create the v2
   recovery marker. Ordinary-start bootstrap and open-epoch receipts remain
   forbidden, and an abort before every listener is ready remains non-sealing.

All live stage and aggregate evidence remains `null` and is enumerated in
`missingEvidence`. The remaining blockers are the source PVC/claim and clean
seal, encrypted backup catalog and object-lock policy, restore verifier
release/SBOM, fresh target PVC/PV/StorageClass identity, isolated restore
report, control/public slot references, and the separately reviewed exact
handoff receipt and runtime activation evidence. Until those facts are
independently reviewed, this repository
cannot read credentials, mutate storage, create a restore job, activate a
workload, or hand anything to Flux. The protected-base render verifier checks
this contract on every tree and rejects duplicate keys, open shapes, resource
documents, secret-shaped values, malformed identifiers, and cross-binding
drift.

## Inert Case image and resource inventory

`contracts/stadtstack-case-image-resource-inventory-contract.json` is the
manual admission record for the future Case control, public-binding, and
restore-verifier images. It deliberately does not extend the routine Röbel Web
and Public Mecky Release Set: a normal application promotion must never gain a
path to the stateful control process or the recovery verifier.

Each logical component remains blocked until one exact source revision,
immutable manifest/config/layer digest set, GitHub-OIDC SLSA provenance, and
SPDX 2.3 evidence are independently reviewed. Each GHCR package must be
publicly visible and an unauthenticated resolver must prove the exact
`@sha256` manifest can be pulled before Flux may consume it; no image-pull
Secret is admitted as a workaround. Control and public runtime repositories
must be distinct. The source and future publisher identity are
pinned to the public `GiraeffleAeffle/stadtstack` repository, not the Röbel App
publisher. The logical inventory preserves one-writer
control storage, a public slot with no PVC/PV/Secret/token/RBAC surface, and an
operator-only restore verifier with no source write mount, public ingress, or
user-facing endpoint.

Control is the sole exception to the no-reference rule: it may reference
exactly the preexisting `roebel-case-steward-control-runtime` Secret already
admitted by the topology contract, and only through container environment
`valueFrom` runtime configuration. It cannot be attached as an image-pull
credential. Both inert ServiceAccounts declare an empty `imagePullSecrets`
list, and every future Case workload forbids image-pull Secrets. The allowlist
is bound to that contract's canonical checksum. The inventory still forbids
creating a Secret, embedding credential material, or giving public binding or
restore verifier any Secret reference.

Anonymous pull proof is not a Boolean. A future admission must provide one
canonical receipt per component binding its name, public GHCR repository,
immutable manifest digest, exact source revision, clean empty registry-auth
context, anonymous ORAS resolver identity, and resolved digest. Its own
SHA-256 digest covers every receipt field except itself. Any repository,
revision, digest, resolver, auth-context, or receipt-checksum drift is rejected.

The future Flux handoff is data only: its namespace, reconciler identity,
source revision/path, exact resource-name allowlist checksum, inventory
checksum, and RBAC receipt are all absent. The contract contains no Kubernetes
or Flux document, credential value, live or unapproved Secret reference,
reconciliation permission, or live effect. Its canonical inventory checksum is the only value the recovery
composition may later accept as `resourceInventoryChecksum`.

This first policy expansion cannot truthfully self-admit: the currently
protected base does not contain the inventory verifier and its closed file set
rejects those new paths. Bootstrapping therefore requires one bounded
administrator merge of one exact, independently reviewed commit. Administrator
enforcement must be restored even if that merge fails, and the newly protected
`main` push verification must pass before any Case image publication,
resource rendering, Flux handoff, or activation is allowed. Every subsequent
inventory change is admitted only by the protected-base verifier; this
one-time transition is not a reusable bypass.

The provenance record is accepted only when its repository claim is
`GiraeffleAeffle/stadtstack`, its source digest equals the component's exact
40-character source revision, its Git ref is `refs/heads/main`, and its image
subject equals the immutable manifest digest. The recovery-bound inventory
checksum also covers the empty forbidden-resource and forbidden-secret
inventories, so later population cannot silently weaken that boundary.

## Reviewed public knowledge render migration (future complete set)

The verifier also defines one future, all-or-nothing render shape for the
standalone reviewed-knowledge runtime. It is admitted only when all five files
below exist together; a missing file, an unknown extra, or a mixed current and
future set fails closed:

```text
reviewed-render/roebel-staging/reviewed-public-knowledge/
  deployment.json
  service.json
  networkpolicy.json
  kustomization.yaml
  runtime-pin.json
```

The future runtime is a tokenless, non-root, read-only-root-filesystem
Deployment named `reviewed-public-knowledge` in
`stadtstack-roebel-staging-lab`. It uses one immutable digest of
`ghcr.io/giraeffleaeffle/stadtstack-reviewed-public-knowledge-runtime`, named
TCP port `http`/8080, non-HTTP TCP startup/readiness/liveness probes, no
ServiceAccount token, no added capabilities, no writable volumes, no Ingress,
and a ClusterIP Service on 18080 targeting the named container port. Its
NetworkPolicy allows ingress only from the `public-mecky` Pod in the same
namespace and denies all egress.

`runtime-pin.json` is a closed proof record. It binds the exact 40-character
source revision and `source-<revision>` tag to the protected
`reviewed-knowledge-runtime-publish.yml` workflow, GitHub-OIDC SLSA provenance,
SPDX-2.3 evidence, and a public-package ORAS pull receipt resolved with a
clean-empty auth configuration. The manifest digest and all evidence subject
digests must agree; authority binding is `none` and deployment effect is
false. The render checksum covers these five files as well as the existing
resources.

The first tracer is pinned to the independently verified values below; a
self-asserted but merely syntactically valid replacement is not admitted:

```text
sourceRevision:       642e2741d2fd3cb867c0e1c315f04ef8e29d787b
sourceTag:            source-642e2741d2fd3cb867c0e1c315f04ef8e29d787b
image manifest:       sha256:7846fee172cfdad286773fa56c939d716ae32604cd0e47833f72536aa6a5c1dc
SLSA attestation:     sha256:5d7f4a80f77bc0b1c7e036303325bf68f4bbb6e8a4dbeaaa839abf7abd330aab
SPDX attestation:     sha256:052b53e71548f978fd00d22eb9dd20089dd58b05f6b9cc39590f3d8f25740bc4
anonymous auth hash:  sha256:ec21c035eccb78eb5ca20ec95628eb351633621e09a130ac8d7e663714d40c7a
anonymous receipt:    sha256:21a4c33b36db0831fa65375f6e7af812b87502986d97d5a45e7eb8b19108b04f
```

Activating this future runtime is a distinct, head-preserving transition.
From the current render, the Release Set head and every existing file remain
byte-identical except `integrity.json` and the deterministic Public Mecky
environment transformation: remove the four legacy synthetic-evidence
entries, point `STADTSTACK_PUBLIC_BASE_URL` at the reviewed Service, and append
`MECKY_REVIEWED_SOURCE_KINDS`. Later future-set promotions are ordinary
head-changing promotions; regression to the current set is forbidden.

When this future set is present, Public Mecky must use exactly the internal
reviewed runtime URL on port 18080 and the ordered source kinds
`local_news,ratsinformation`. Legacy synthetic-evidence environment variables
and `reviewed-evidence` ConfigMap references are rejected. The verifier change
only establishes this admission policy; the actual runtime image publication,
reviewed render values, and one separately reviewed Flux activation remain
future work.

## Signed-Nostr staging runtime policy (blocked future activation)

The normal Röbel Web + Public Mecky Release Set stays two components. A
separate signed-Nostr tracer is deliberately outside that release set and its
automatic promotion. The protected verifier reserves exactly this future,
all-or-nothing render subtree:

```text
reviewed-render/roebel-staging/signed-nostr/
  runtime-pin.json
  workbench/{deployment,service,networkpolicy}.json + kustomization.yaml
  workbench/gnosis-proxy-{deployment,service,networkpolicy}.json
  citizen-relay/{deployment,service,networkpolicy}.json + kustomization.yaml
  agent-relay/{deployment,service,networkpolicy}.json + kustomization.yaml
```

There are no such manifests in this policy PR and no Flux source, namespace,
secret, RBAC, ServiceAccount, or live object is changed. The runtime pin is
a distinct `roebel_signed_nostr_activation_render_pin_v1`. It embeds the
publisher's complete, unchanged `roebel_e2e_runtime_pin_v1` and binds its
canonical JSON SHA-256, so the Operations-specific activation record cannot
collide with or weaken the publisher schema. Per-component immutable image,
source revision, provenance, SBOM, and workflow identity are read only from
that nested publisher pin. That nested self-checksum establishes record
integrity only; it is not evidence that the publisher artifacts are genuine.
A separate activation review must verify the publisher runtime-pin artifact and
its provenance/SBOM attestations themselves.

The activation evidence is currently required to state
`pending-separate-review` with null Gnosis-egress, Flux-identity, and anonymous
digest-pull evidence. The protected approved-policy constant is `None`, so even
an otherwise complete signed-Nostr render fails closed. No Gnosis private
proxy/resource or endpoint evidence is present in the current render, and the
existing reconcilers remain unchanged. A later evidence review must first add
one exact, closed `roebel_signed_nostr_activation_evidence_v1` record to the
protected policy and bind it byte-for-byte to the candidate runtime pin. That
record binds the publisher-pin canonical SHA-256, source revision and workflow;
both immutable images and their provenance/SBOM receipt IDs, URLs, attestation
digests and subjects; chain ID 100; the exact upstream host, port and `/32`;
the four read-only JSON-RPC methods; the private Gnosis proxy Deployment,
Service and NetworkPolicy digests; and the workbench NetworkPolicy digest. The
public upstream requires no Secret and none is admitted to the proxy.

The same closed record must include all live ownership and lifecycle evidence.
Every one of the twelve runtime/proxy objects and twelve Flux/RBAC identity
objects has an ordered precondition that says either `absent` with null live
identity or `present-exact` with its UID, resourceVersion and current canonical
object digest. A present object is adoptable only when that digest already
equals the reviewed desired object. The one-time administrator bootstrap uses
atomic API `POST` create for every absent target and fails on HTTP 409; it never
uses server-side apply as create-if-absent. A present-exact target is an
explicit no-op whose UID and resourceVersion must still equal the live
precondition. The bootstrap then records the resulting exact
UID/resourceVersion/digest for all 24 objects, with the three Kustomizations
still suspended. A second bounded live recheck
must observe the same objects, the same four public-boundary byte digests, and
fresh DNS/TLS evidence before three UID/resourceVersion-CAS patches may change
only `/spec/suspend` from true to false. The activation receipt must complete
inside the five-minute preflight window, and protected admission must itself
run after completion and before that window expires. Missing the routine RBAC
`create` verb is still not an absence guard: once bootstrap has established
exact ownership, Flux server-side-apply PATCH can rematerialize a deleted exact
named target. The atomic administrator create/no-op receipts, not that verb
list, are the initial absence/adoption boundary.

The current schema constrains that future Gnosis hop to one materialized,
tokenless proxy Deployment and ClusterIP Service in the workbench namespace.
It reuses the exact attested workbench digest with runtime role
`gnosis-rpc-proxy`, accepts only `eth_chainId`, `eth_blockNumber`,
`eth_getCode`, and bounded `eth_call`, and requires chain `0x64`. The proxy
NetworkPolicy permits DNS and TCP/443 only to
`rpc.gnosischain.com`'s separately reviewed `34.111.230.52/32`; the workbench
policy adds only the proxy Pod selector on TCP/8545. Public CIDR wildcards,
external names, load balancers, credentials, transaction methods, alternate
providers and arbitrary digest claims are rejected. Every object is
canonical-JSON digested inside the future record, then the entire record must
equal the separately protected approved-policy constant.

The host-to-address assertion is not a bare string. Initial review and the
activation-time recheck each bind a canonical five-minute receipt containing
the resolver identity and A+AAAA-over-HTTPS method, the complete sorted A and
AAAA result sets, observation and expiry timestamps, plus TLS server name,
issuer, certificate SHA-256, and certificate validity interval. Both receipts
must resolve to exactly `34.111.230.52` with no AAAA result and must carry the
same certificate identity; any rotation fails closed and requires a new
reviewed policy record.

That separate private/live review must also create and verify three new narrow,
separate Flux identities: workbench targets `stadtstack-roebel-web-preview`,
and citizen-relay plus agent-relay target `stadtstack-roebel-staging-lab`.
Their Kustomizations and impersonated ServiceAccounts live in the actual
`flux-roebel-staging` namespace; their exact named-resource Roles and
RoleBindings live in the target namespaces. Each record contains the complete
canonical suspended Kustomization, ServiceAccount, Role and RoleBinding object
plus its digest. Prune and force are false, deletion is orphaning, the routine
Roles contain only exact-name get/patch/update and no wildcard, delete, list,
watch, Secret, or ConfigMap verb, and workbench waits for both relays. Because
server-side-apply PATCH is create-capable for an absent exact name, the
one-time administrator bootstrap establishes initial ownership with atomic
POST-create/no-op receipts before those routine identities are unsuspended.
This policy change neither
creates those identities nor changes any existing reconciler.

The future record must also supply exactly two canonical anonymous digest receipts:
one each for `roebel-e2e-workbench` and `roebel-staging-relay`, bound to the
nested publisher pin's image, manifest digest, and source revision, with
`clean-empty-auth-config`, its fixed canonical SHA-256,
`sha256:ec21c035eccb78eb5ca20ec95628eb351633621e09a130ac8d7e663714d40c7a`,
`oras-resolve-anonymous`, and the same resolved digest. Each receipt uses the
closed `roebel_signed_nostr_anonymous_digest_pull_receipt_v1` schema and
`canonical-json` encoding, includes the parent publisher-pin canonical SHA-256,
and recomputes its receipt digest from every other field. The receipt order is
the publisher order (workbench, then relay). This
repository pins the reviewed upstream IP and complete prospective Flux
identities but does not create or activate them.

When that gate is separately opened, the verifier permits only one topology:
the workbench is a ClusterIP-only Deployment in
`stadtstack-roebel-web-preview` on port 18083; the citizen and agent relays
are ClusterIP-only Deployments in `stadtstack-roebel-staging-lab` on port
18081. Both relay Deployments must use the same immutable relay digest. Every
Pod is non-root, tokenless, read-only-root-filesystem, seccomp-default,
capability-free, and has no ServiceAccount, RBAC, PVC, image pull secret, or
Ingress. Relay state is the only writable volume: one 128 MiB `emptyDir` per
relay with 80 MiB of combined persisted-file budgets, leaving explicit
headroom below the 112 MiB aggregate application limit.

The public Ingress may add only `/stadtstack-test`, with GET/HEAD reads and
exactly `POST /stadtstack-test/api/session/admit` and
`POST /stadtstack-test/api/signed-event`; the existing
`POST /api/chat/mecky` remains unchanged. No other signed-Nostr write or
administrative/fixture route is admitted. Each of the five permitted staging
reads is exact-path only: `/stadtstack-test/healthz`, `/api/config`,
`/api/feed`, `/api/thread`, and `/api/conversation` beneath that prefix;
suffixes are rejected. The relays have no Ingress. Each relay permits TCP/18081
only from the exact workbench Pod and exact Public Mecky Pod selectors. Public
Mecky may gain egress only to the two exact relay Pods on TCP 18081; the
workbench may reach DNS, those exact relays and only the private proxy. The
proxy alone may reach the reviewed Gnosis `/32`; Gnosis egress remains blocked
until the separate exact activation record is approved.

Activation is head- and live-precondition-preserving. Apart from the sixteen
new files, it may change only `integrity.json`, the Web Ingress, the Public
Mecky NetworkPolicy, and the boundary receipt. The runtime pin records the raw
byte digests of those four prior files. It also binds the exact live rollback
contract: suspend the three exact-UID reconcilers, restore those four boundary
bytes, scale each exact-UID Deployment to zero before deletion, delete only the
remaining exact runtime/proxy UIDs, remove only the exact Flux/RBAC identity
UIDs, and finally prove both boundary restoration and total target absence. A
UID mismatch stops with no delete and no adoption. `prune: false` and
`deletionPolicy: Orphan` therefore cannot turn a Git rollback into an implicit
teardown. Deactivation remains blocked until a separately reviewed protected
constant contains the complete ordered live step receipts, boundary receipt,
and absence receipt. That receipt has a five-minute post-completion validity
window; protected admission rejects future-dated, expired, or replayed absence
evidence. Only then may Git remove all sixteen files while
preserving the Release Set head and every other existing file. Routine
Web/Mecky promotions must preserve every signed-Nostr file and boundary
byte-for-byte.

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
