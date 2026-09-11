# Offline administration-review migration operator

Status: source implementation and offline verification only. This directory is
not included by any Kustomization or live operator. CI runs its offline tests. The existing
19-object bootstrap and active reviewed render keep their existing meaning.

`scripts/run-case-review-migration.mjs` bridges private Operations files to the
already published Stadtstack PR 70 runtime. It uses the exact source revision
`fdb0b7f36c33d925be141d8e9037b48d17612df8` and control image
`ghcr.io/giraeffleaeffle/stadtstack-case-steward-control@sha256:5f0eeec46e1e00150ce5f370ba9749a0f4d6d652dac73839f25699771adb1d60`.
The CLI imports fixed modules from `/runtime/src`; it cannot select an
alternative runtime through its request. Selecting and attesting the actual
container image remains the responsibility of the protected Operations caller.

## Invocation contract

The trusted parent reserves four distinct regular files owned by the invoking
UID, with mode 0600, at most one hardlink and at most 1 MiB each. It opens the
inputs for reading and a **new, empty** result for writing, passing inherited
descriptor numbers of at least 3. No configuration or credential goes into
arguments, environment, stdout, stderr or public receipts.

The five base CLI arguments are `--request-fd`, `--expected-request-sha256`,
`--source-config-fd`, `--target-config-fd` and `--result-fd`. The independently
reviewed request hash must come from the protected Operations plan. Computing a
hash from arbitrary user input at invocation does not establish authorization.
Inputs may not be modified during an operation. The runner rereads their exact
byte pins at the public runtime's authority checks and before writing a result.

The request is a closed JSON object with these fields:

| Field | Meaning |
| --- | --- |
| `schemaVersion` | `roebel_case_review_migration_request_v1` |
| `mode` | `prepare`, `activate`, `capture-backup` or `verify-backup` |
| `sourceRevision`, `controlImageDigest` | Exact constants above |
| `sourceRootDir`, `caseId` | Canonical mounted source path and the admitted synthetic Case |
| `sourceSealChecksum`, `admissionReceiptChecksum` | Observed clean source seal and original immutable admission |
| `sourceConfigurationSha256`, `targetConfigurationSha256` | Exact private application-file bytes |
| `targetBinding` | Reviewed public-runtime v2 binding, including observed target PVC/PV identity and four listeners |
| `migrationPlan` | Activate only: independently pinned public-runtime migration plan, including source/target claims, candidate checksum and bounded UTC interval |

The source application is the original admission configuration. The target
preserves its credentials, policy, original actor records and network settings;
it adds the required departments, department roles and `administrationReview`.
Review bearer grants are independently scoped to registered actors and this
Case. They cannot reuse an admission credential. These are staging grants, not
proof of municipal employment. Existing runtime validators remain authoritative
for the Case, deployment, policy and role semantics.

`prepare` invokes the public runtime's isolated candidate preparation. It does
not attest or modify the target mount. `activate` performs the public runtime's
target storage preflight and reviewed migration. The result contains the
candidate or linked activation receipt and a checksum of the result envelope;
it is written and fsynced only to the private result descriptor. Stdout contains
only status and result checksum. A fixed error and exit 78 preserve privacy on
failure. The parent must retain and link the private result before handover.

## Encrypted Case backup and fixed migration worker

Backup is part of the same descriptor operator, using the same pinned source
and target configurations. `capture-backup` additionally requires the separately
pinned `sourceDeploymentClaimChecksum` and a new empty private `--archive-fd`.
For the first capture after shutdown, both seal/claim checksums may instead be
null with the additional pinned `sourceBindingChecksum`. This explicit discovery
mode reads the claim and seal from two matching bounded source snapshots,
verifies the binding, seal, Case and original admission, and returns the observed
checksums. It never opens the source as SQLite or changes source files. Other
modes require concrete seal and claim pins.
`verify-backup` requires that claim, `archiveSha256` from the capture result, and
an archive descriptor containing the decrypted bytes. Prepare/activate reject
an unexpected archive descriptor. The archive descriptor must be readable too,
because its contents are checked after writing; the other descriptor constraints
remain unchanged. The archive limit is 64 MiB, with at most 32 flat files and
32 MiB total decoded data. Larger stores need a separately reviewed limit or
streaming implementation before shutdown.

The archive preserves exact bytes and modes (0600/0640/0644) of owned regular
files inside the private 0700 Case root, including the storage marker and owner
SQLite file. It does not claim to preserve filesystem timestamps or group IDs.
It rejects symbolic/hard links, traversal, duplicate names, nonempty journal
sidecars and active transition markers. Public runtime seal verification binds
the closed database and original admission. Two source snapshots must agree.
Archive JSON/base64 is **plaintext**, never a public receipt or log payload.

`encrypt_and_verify_case_backup` on the Operations host consumes the independently
pinned capture result and owned archive. It runs a byte-pinned age executable
with one explicit X25519 recipient, saves ciphertext in a new private directory,
then decrypts through a private descriptor using the separately supplied identity.
No identity or configuration bytes appear in command arguments. Its verifier
must invoke the fixed-image `verify-backup` command against that decrypted file,
using the independently pinned verification request. That command restores into
a new private directory and runs the real runtime's full history/receipt replay
and migration preparation. It compares the restored files and rechecks the
original source, then removes only its throwaway restore/candidate directories.
The host rechecks both archives and records success only after runtime validation.
Ciphertext and the completion receipt are retained; the host's temporary decrypted
archive is removed on success or failure. The caller still owns and must clean up
its original plaintext capture after securely retaining verified ciphertext.

The host persists `backup-pending.json` after syncing the ciphertext and before
restore verification. Recovery explicitly supplies that retained receipt and
its independent checksum; it verifies the same capture, recipient, executable,
verification request, directory and ciphertext. It never encrypts again. Each
attempt decrypts into a fresh private file, leaving any file orphaned by a
process crash untouched. Its own temporary plaintext is removed on return.
The `verify_restored` callback must recover the existing worker exchange and
retrieve its retained result, not issue another restore invocation. A completed
backup receipt can also be reverified without replacement. Missing/unpinned
pending records or changed retained ciphertext remain stopped recovery states.
The real-age integration simulates a lost verification response, repeats recovery,
checks unchanged ciphertext bytes/inode/mtime and rejects altered recovery pins.

`compile_migration_worker` produces an **inactive** ConfigMap, deny-all policy and
one Pod using the existing published runtime image. It binds source/target
claims, the successor candidate, node identity, and the two exact configuration
references/hashes. It has no service-account token, service links, ingress,
egress, host mount or application listener. It copies the two pinned Secret
files into 0600 tmpfs files and waits for the protected operator's commands.
Both retained volumes are writable solely because the runtime needs ownership
locks during activation. Compiling or starting the worker is not permission to
invoke a migration. The live Adapter still must verify all stage receipts,
physical mount release, exact Pod/image/node/claim identities and current source
fencing before any descriptor invocation. Worker transport and recoverable runtime switch/restart/resume operations are
implemented locally. Their complete live driver and successor admission remain
incomplete.

The real SQLite integration includes capture, independent restore/replay,
source preservation and malformed-archive/descriptor failures. For the additional
real age host round trip (which also rejects a wrong identity, altered pins and
an existing output directory), set `CASE_REVIEW_TEST_AGE_BIN` and
`CASE_REVIEW_TEST_AGE_KEYGEN_BIN` to local absolute executable paths before running
`test_case_review_migration_integration.mjs`. Test keys are disposable; no live
identity or Case is used. Without those variables only the age-specific test is
skipped; SQLite capture/restore still runs in CI.

## Recovery and remaining Operations work

### Binding a target volume with WaitForFirstConsumer

The staging `hcloud-volumes` class uses `WaitForFirstConsumer` and already
retains PVs. The PVC operation correctly returns `awaiting-binding`; a separate
consumer must be scheduled before provisioning can finish.

`consumer-plan` compiles a separately pinned plan from the same storage nonce.
`consumer-advance` requires an independently pinned existing storage receipt
that owns the target PVC, plus its own fresh receipt output. It creates the
fixed deny-all NetworkPolicy before one `roebel-case-review-storage-check` Pod.
Durable intent precedes each create; uncertain outcomes are re-observed and
never blindly recreated. Conflicts, changed UIDs, injected Pod fields and failed
checks stop the operation. Recovery requires the same independently pinned
storage receipt and the consumer's prior receipt; use a new output each time.

Kubernetes can add `topology.kubernetes.io/region` and
`topology.kubernetes.io/zone` labels when binding the Pod to its Node, after
initial create/dry-run. The semantic validator accepts only those two labels
on a node-bound Pod with valid nonempty label values; every other label and the
reviewed affinity/security specification still must match. This supports
recovery of the same receipt-owned Pod without removing controller metadata or
recreating resources. See [Kubernetes Pod topology labels](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/).

The Pod uses the existing immutable control image with a fixed Node filesystem
check. It mounts only the target PVC read-only, runs as UID/GID 1000, has no
service-account token, Secrets, service links, writable root or network access,
and has a five-minute active deadline. Required Pod affinity schedules it on
the current Case control Pod's node, keeping the migration volumes compatible.
It checks ext4, at least 1 GiB available, and an empty root apart from lost+found.
It creates no directory or marker and never starts the application. CSI may
apply the requested fsGroup to the fresh target during mounting.

A fresh CSI disk cannot be formatted through the original read-only mount.
For that recovery only, paired `--predecessor-consumer-receipt` and
`--expected-predecessor-consumer-sha256` arguments compile a distinct v2 plan.
The plan embeds the pinned original consumer receipt and creates the fixed
`roebel-case-review-storage-check-v2` Pod and policy on the same owned claim.
The target mount permits writes so CSI can format the disk; the fixed check
program still only reads it. This is a separate plan and mount authorization.

Before each create and successful completion, the operator rechecks the source,
target and original Pod. An existing predecessor must have its receipt-owned
UID, unchanged reviewed semantics, a terminal phase and no running containers.
An absent predecessor is never recreated. A changed or active predecessor stops
the operation. The v2 transport may GET the original Pod but cannot modify or
delete it. The claim's ReadWriteOncePod access mode remains enforced. The v2
operation has its own durable receipts and cannot adopt existing v2 resources.
Optional `readOnly: false` fields may be omitted by Kubernetes; true remains
distinct and every other volume setting must match the pinned plan.

Resume the original storage operation after binding to obtain the actual
retained PV receipt. Resume the consumer to verify the exact Pod's successful
exit and image digest. These are separate proofs: neither permits migration.
The completed Pod and its policy remain as evidence; this operation has no
delete permission. Later handover must verify the Pod is terminal and the mount
released before starting another writer. Failed Pods are retained for diagnosis,
not automatically replaced. The source workload stays running during this phase.

Example inert plan command, with the same nonce as the storage plan:

```sh
python3 -I scripts/run-case-review-storage.py --mode consumer-plan \
  --expected-operations-revision "$REVIEWED_REVISION" --operation-id "$STORAGE_NONCE"
```

The `consumer-advance` invocation adds `--expected-plan-sha256`, `--kubeconfig`,
`--receipt`, `--storage-receipt` and `--expected-storage-receipt-sha256`.
For recovery also supply `--prior-receipt` and `--expected-prior-sha256`.
Plan generation is inert; source admission and exact live authorization remain
separate. No new protected inventory entry or CI permission is needed because
this extends the existing storage module, CLI and test file.

### Create-only target initialization

`initialize-plan` compiles the next separate operation from the original
storage nonce, an independently pinned retained-storage receipt and a verified
consumer receipt for that same claim. Pass `--storage-receipt` with
`--expected-storage-receipt-sha256`, and `--checked-consumer-receipt` with
`--expected-checked-consumer-sha256`. For a v2 check, also pass its original
`--predecessor-consumer-receipt` and `--expected-predecessor-consumer-sha256` so
the compiler reproduces the checked v2 plan. Plan mode remains offline and
rejects live kubeconfig/result inputs. `initialize-advance` adds the independently
reviewed initialization plan pin, bound kubeconfig and a fresh private receipt.

The compiler derives the v2 binding from the protected original binding and
the observed retained target. It fixes the PR70 image, fourth review listener,
target path, marker and immutable ConfigMap program. Callers cannot supply a
replacement program, Pod or binding. The target path is distinct from the
source path to support the later simultaneous migration mounts.

Each advance re-observes the source claim and the exact target claim/PV UID,
Retain policy and storage class. Both earlier check Pod names must be absent;
a terminal-but-retained Pod is insufficient. Retirement belongs to a separate
explicitly authorized operation. API absence is not physical mount-release
proof; the caller must establish that separately before starting a new writer.
The runtime filesystem proof and successful pinned-image termination are
required before this operation records `verified`.

The operation creates only a deny-all NetworkPolicy, an immutable ConfigMap
and one five-minute, non-root Pod, in that order. Durable intent precedes each
create. It owns no delete, patch, Secret, source mount or application endpoint.
The embedded program validates the exact binding/marker before writing, checks
filesystem capacity and an empty volume root apart from lost+found, then
creates only `case-control` and its marker at modes 0700/0600. It clears the
fsGroup-inherited setgid bit only on its own newly created directory. Existing
or partially initialized state is never repaired or overwritten automatically.

The separate initialization receipt records ConfigMap, Pod, policy, claim and
volume identities. Recovery uses a new result file and independently pinned
prior receipt. Lost responses are re-observed without duplicate creates;
conflicts, changed objects, failed Pods or disappeared effects stop. This phase
neither provisions review grants nor migrates the Case. Immutable private
configuration, source quiescence/seal, migration and reviewed handover follow.

### Retained target storage operation

`scripts/run-case-review-storage.py` provides a separate `plan` / `advance`
operation for the first rollout phase. Its fixed target is
`roebel-case-steward-review-state-v1` in `stadtstack-roebel-staging-lab`: 10 GiB,
`hcloud-volumes`, `ReadWriteOncePod`, filesystem storage. It requires the
original source claim identity and binding to remain unchanged. The target
starts empty; no data source, clone, workload or Secret is created by this
operation.

The protected caller reserves a fresh 32-byte hex operation ID, compiles and
reviews the plan, then independently pins its checksum. Live invocation also
requires an exact clean Operations revision, an explicit verified kubeconfig
and a new private receipt file. The existing cluster-binding check runs before
the storage transport can make a request. No ambient Kubernetes context is used.

Creation intent is durably recorded before the single PVC create. A lost create
response is resolved only by observing the exact ownership marker and claim
specification. A Pending claim returns `awaiting-binding`; it does not spin or
create a second claim. An unresolved create with no observable claim remains
stopped. A definite create conflict is terminal and cannot adopt an existing
claim, even if its name matches.

Once bound, the operation verifies a separate PV and its claim UID, storage
class, capacity, CSI driver and filesystem. If necessary, the only patch sets
that PV's reclaim policy from `Delete` to `Retain`, guarded by JSON Patch tests
of its UID, resourceVersion and previous policy. The source claim is rechecked
before writes and completion. An uncertain patch is re-observed; it is never
automatically rolled back to `Delete`. A completed receipt records the actual
claim and volume identities required by the later deployment binding.

Recovery requires the prior receipt and its independently supplied checksum,
plus a new output receipt. It re-observes the same claim and volume; changed
identities or a regressed retention policy stop. Neither failure nor recovery
deletes storage. A retained-volume receipt is not evidence that data was copied
or that a migration workload may start: quiescence, mounting, the target storage
marker, private configuration and reviewed activation remain separate phases.

The concrete source entrypoints are:

```sh
python3 -I scripts/run-case-review-storage.py --mode plan \
  --expected-operations-revision EXACT_REVIEWED_COMMIT --operation-id RESERVED_HEX_ID

python3 -I scripts/run-case-review-storage.py --mode advance \
  --expected-operations-revision EXACT_REVIEWED_COMMIT --operation-id RESERVED_HEX_ID \
  --expected-plan-sha256 REVIEWED_PLAN_SHA --kubeconfig PRIVATE_BOUND_KUBECONFIG \
  --receipt NEW_PRIVATE_RECEIPT
```

Add `--prior-receipt` and `--expected-prior-sha256` together for recovery.
The three storage source/test files are included in the protected inventory,
and the Python test runs from protected base in CI. A reviewed live invocation
still requires its own exact plan and authorization. Live observations belong in
private rollout receipts, not this source contract.

The control change adds exactly `scripts/case_review_storage.py`,
`scripts/run-case-review-storage.py` and `scripts/test_case_review_storage.py`
to `case_runtime_admission.py`'s `FILES`. In the existing admission workflow,
it adds `python3 -m unittest -v base/scripts/test_case_review_storage.py` to the
protected-base PR checks and the corresponding `candidate/scripts` command to
protected-main checks. No action version, dependency, permission, render or
existing bootstrap operation changes.

### Ordered review handover and inactive successor compiler

`scripts/case_review_handover.py` contains the separate nine-stage coordinator
and `compile_review_runtime`. Neither is a live CLI or permission to deploy.
The compiler reproduces the reviewed initializer, consumes an independently
pinned provisioning receipt, and creates an inactive successor render. Only the
control ConfigMap and Deployment change. The proposed reconciler Role gains
one exact ConfigMap name, with its existing verbs; no Secret permission,
Service, ingress or review NetworkPolicy is added. The old bootstrap and the
active render remain unchanged.

`advance_review_handover` requires an independently pinned, time-bounded full
plan with implementation/render/configuration hashes and actual resource UIDs.
Before any stage, its trusted Operations Adapter must verify that the complete
concrete implementation is ready and current stage ownership/fencing holds.
No partial adapter may approve source shutdown. Stages run in this order:

1. Fence the source Deployment and its reconciler.
2. Verify API and physical release of source and initializer mounts.
3. Verify an encrypted Case backup by restoring and comparing its exact files.
4. Prepare a candidate tied to the original seal, claim and admission.
5. Activate that candidate and record the target seal and unchanged source hash.
6. Verify the migration Pod and mounts are released.
7. Start the exact v2 runtime on the provisioned target and configuration.
8. Verify all four listeners, clean restart, original admission and source bytes.
9. Restore GitOps and verify the new render plus both retained volumes.

The Adapter provides `verify_ready`, `observe` and `perform`. It owns the
concrete Kubernetes compare-and-swap operations, encrypted archive verification,
pinned runtime invocations and durable stage receipts. `observe` verifies those
retained receipts; historical steps need not still describe current live state
(for example, the reconciler is intentionally resumed at the final stage).
`verify_ready` checks current state appropriate to the completed prefix. Receipt
summaries are closed and linked across stages; hashes alone do not certify that
a backup was restored or a mount released. No concrete live Adapter is supplied
by this source change. Live implementation, full rehearsal and admission of
the successor render remain required before use.

The coordinator commits intent before each stage. A lost response is checked
through the same owned stage receipt, never retried as another write. Recovery
requires a fresh output and independently pinned prior receipt. Pending work
without evidence returns `awaiting-evidence`; the concrete stage operator must
resolve it under its own receipt before the coordinator can continue. A failure
preserves both stores and the source fence; there is no automatic GitOps resume,
rollback or deletion. A complete receipt is recoverable even if the final
response was lost. The operation window is at most one hour; a new window or
changed plan requires separate recovery review, not editing an old receipt.

The coordinator/compiler tests are protected in the existing admission workflow.
They cover write ordering, lost responses at every stage, incomplete-stage
recovery, invalid backups/mount proofs, changed identities, stale plans and
receipt failures. Their success is source evidence, not a live migration claim.

The concrete `advance_source_fence` helper implements the first stage using
only GET and two UID/resourceVersion-guarded JSON patches: suspend the existing
Case Kustomization, then scale the existing control Deployment from one to zero.
It requires the parent coordinator's independently pinned intent, reproduces
the original render, and invokes the full prerequisite verifier with the current
sub-stage state before each write. It waits while Flux reports reconciliation
in progress. An unresolved patch is observed on recovery and never resent;
a changed UID, generation, owner or workload specification stops the stage.
Its linked sub-receipt never resumes Flux, deletes a Pod or changes RBAC.

This helper verifies desired fencing state only. [Flux suspension](https://fluxcd.io/flux/components/kustomize/kustomizations/#suspend)
pauses reconciliation; it is not a filesystem lock or proof of termination.
`release-mounts` must subsequently prove that no source writer remains and that
both RWOP mounts are physically released before migration. Current stage
fencing must be rechecked throughout import and handover. The complete live
Adapter remains unfinished, so this helper must not be invoked in staging yet.

`observe_mount_release` supplies the read-only part of the next stage. It
checks the original binding and claim identities, rejects incomplete Pod lists
or any Pod using either claim, and observes host mountinfo plus kubelet Pod
directories through the pinned node transport. `mountObserverPodUid` names a
separate ready Pod on the same pinned node; it must differ from both Pods being
retired. Its mount and directory must be visible, and its API identity/readiness
is checked again after the host read. Empty, wrong-node or stale views cannot
certify release. The returned private receipt contains a timestamp, evidence
and the host-view hash, without raw mount output. Pod retirement remains a
separately receipted operation; the helper sends no writes.

### Fixed worker command interface

The mounted descriptor operator now provides five fixed commands. All run under
`/work/private` with owned 0700 directories and 0600 regular files. Their only
content argument is a SHA-256 pin. Every command also requires
`--expected-worker-uid <Pod-UID>`, checked against the Downward API environment
before reading input or loading runtime code. Paths and arbitrary executable
code are not accepted.

- `--worker-invoke <request-sha256>` reads at most 1 MiB from stdin, reserves a
  directory for those exact request bytes, opens the existing private source and
  target configurations and fresh result/archive descriptors, then calls the
  same reviewed operator. The reservation is synced before runtime effects.
- `--worker-result <request-sha256>` reads the retained result, checking its
  request/configuration/image links and checksum. It does not rerun anything.
- `--worker-archive <capture-request-sha256>` exports only the captured archive
  linked by that verified result. Output must go directly to the parent's
  owned private file/pipe; never print it into a tool transcript or public log.
- `--worker-upload-archive <archive-sha256>` accepts at most 64 MiB of stdin into
  a fresh content-addressed private file for independent restore verification.
  It never overwrites an existing archive.
- `--worker-verify-archive <archive-sha256>` reads and hashes the retained upload
  without writing or loading runtime code. A lost upload response must be
  resolved here before invoking restore; uploading the archive again is forbidden.

Requests and result files remain private on failure. If a runtime effect happened
but no complete result was retained, the mailbox refuses another invocation of
those request bytes. This is a stopped recovery condition, not permission to
remove the reservation or try a new identity. A separately reviewed recovery
plan must resolve the runtime state; automatic retry after an uncertain effect
is intentionally absent. A lost transport response with a complete result is
recoverable through `--worker-result`.

`KubectlReviewWorkerTransport` supplies the fixed exec commands and checks the
ordered parent receipt, Case/configuration/image pins, prepared candidate and
migration window. Before and after exec it checks the cluster, node, exact worker
Pod/template, configuration/policy, retained volume identities, source fence and
exclusive Pod claim inventory. The worker's own UID check rejects a replacement
Pod even if its name is reused between the API check and exec. Expiry during
ownership reads prevents starting the command. Private result/archive bytes are
verified before writing to a fresh owned 0600 descriptor; diagnostics are not
returned. The runner captures output before the transport checks its size; worker
commands also bound their own output. This is not a streaming memory limit.

The parent Adapter must still supply complete readiness and private configuration
receipt verification. The initializer retirement and switch/restart/GitOps
operations below are implemented locally. Their complete live driver, successor
admission and full source-to-target rehearsal remain before source shutdown. The compiler embeds the changed runner; the
published runtime image remains unchanged.

Local tests exercise private result retrieval, reservation collisions, corrupt
results, wrong byte pins, archive upload and interruption after a runtime effect.
The real SQLite test captures an archive through the mailbox, exports it,
uploads it for verification, restores/replays it and confirms source preservation.
This validates the command functions; Kubernetes exec and the fixed `/runtime`
CLI imports have not been executed in a live worker. Seven transport tests use
a controlled Kubernetes API/exec runner to check the fixed command, replacement
Pod, changed image/template/volume/fence/policy, stage and candidate mismatch,
expiry during reads and private archive output. All 88 handover/storage Python
tests and 13 Node tests pass; the optional real-age test is skipped in this run.

### Worker resource lifecycle

`advance_worker_lifecycle` now creates the compiled deny-all NetworkPolicy,
immutable ConfigMap and Pod, in that order. Every create has a synced private
intent; recovery observes the existing object and pins its UID. An undelivered
or ambiguous create is never sent again automatically. An existing worker
inventory without an owned intent blocks creation before any policy change.
Readiness verifies the exact Pod, node, image and zero restarts.

Retirement requires the completed creation receipt and the parent's verified
backup and activation stages. It deletes only that worker Pod using both UID
and resourceVersion preconditions. Policy/code cleanup waits for API absence
plus the pinned node's physical mount/directory observation with a live positive
control. The extended `observe_mount_release` supplies this proof. Replacement
Pods and lingering mounts block progress; no application volume is deleted.
The fixed `KubectlWorkerLifecycleTransport` exposes only these three resources.

Nine new local lifecycle/mount tests cover lost create/delete responses,
undelivered requests, preexisting/replaced Pods, wrong parent/readiness,
delete preconditions, and API absence with mounts still held. These use a
controlled API runner, not a live cluster. The complete parent Adapter must
verify source fencing, retained bindings and exported private artifacts before
allowing lifecycle operations; these functions cannot authorize shutdown.

### Successor handover and clean restart

`advance_initializer_retirement` checks the exact verified initialization receipt,
completed Pod and parent source-fence stage. It sends one UID/resourceVersion
conditioned delete and recovers by observation. Its completion means API absence;
physical mount release remains a separate required proof.

`advance_review_runtime_transition` implements two operations. Start creates the
reviewed target ConfigMap, adds only that name to the existing reconciler Role,
and changes the existing zero-replica control Deployment to the exact candidate.
Restore resumes only the Case Kustomization, after the parent's clean-restart
stage. Each write has a private durable intent and exact preconditions. The
fixed `KubectlReviewTransitionTransport` cannot widen that resource inventory or
patch. An uncertain write is observed without another write; known Kubernetes
defaults are normalized during recovery. A rehashed candidate cannot add other
Role permissions.

`observe_review_runtime` checks the exact Deployment, owned ReplicaSet/Pod,
single volume consumer, image and readiness. `advance_review_runtime_restart`
records the container identity before one SIGTERM through the existing exact-Pod
transport, then requires the same Pod, one restart, a different container and
exit code zero. An uncertain signal is never repeated. Verified all-listener,
original-admission and source/public-service preservation evidence must come
from the complete parent's `verify_complete` observation before GitOps resumes.

The connected local tail rehearsal starts from six synthetic completed stage
receipts, runs the actual switch/restart/resume helpers, pauses on an uncertain
restart, and finishes the same coordinator receipt chain once that restart is
observed. It verifies that writes/signals are not repeated and GitOps does not
resume early. This is a controlled Kubernetes rehearsal of the final three
stages, not a full source-to-target live rehearsal. Separate tests against pinned
public runtime source exercise actual loopback listeners, role-scoped review,
original admission preservation, failed-bind cleanup and clean sealed restart.
All six of those runtime tests pass. Temporary loopback binding required the
normal local sandbox exception; no staging connection was used.

### Private worker driver and preflight

`build_review_worker_request` connects capture, restored-backup verification,
preparation and activation requests. Each next request verifies the preceding
result envelope and original Case/admission/configuration/image pins. The
activation uses the prepared candidate and discovered source seal/claim, within
the complete handover window.

`advance_review_worker_exchange` retains invocation intent before exec and
exports results/archives into fresh private files. Its durable receipt records
file names, sizes and hashes only; recovery rechecks their bytes, ownership and
mode. A lost response retrieves the existing result, never reinvokes a runtime
effect. Restore upload has its own intent and read-only verification. Missing
or late uploads/results pause the exchange; changed retained bytes cannot
complete it. The fixed Kubernetes transport still verifies each operation's
stage and actual worker identity. Driver tests exercise lost responses, late
delivery and altered retained artifacts using controlled worker responses.

`verify_review_private_configuration` reads separately pinned private source and
target descriptors before shutdown. It requires the complete scoped role set,
preserved source settings and distinct tokens; every review grant must cover
the entire handover window. It returns only hashes/counts, never grant contents.
The live readiness Adapter must additionally verify the corresponding cluster
Secret identities and bytes; local files alone are not that observation.

GitOps restore now also requires `verify_review_gitops_target`: a clean pinned
Operations checkout must differ from the implementation commit only in the
exact successor runtime resource file, preserving its file mode. The fixed
source controller must report that same main revision as ready. Old source,
extra tree changes, dirty checkout or an expired window prevent unsuspension.
This is separate from successor admission. Tests use actual disposable Git
commits and controlled source-controller responses; the connected tail uses a
controlled source-proof observation and is still not a full live rehearsal.

`review_migration_stage_evidence` translates owned runtime results into the
coordinator's backup/preparation/activation evidence. It verifies the encrypted
backup link, complete candidate checksum, original admission and source hash,
source/target deployment claims, activation window and matching recovery history.
Even recomputed outer checksums cannot join unrelated nested results. Its public
entry point still requires a valid Röbel handover plan. The real SQLite fixture
belongs to `example-city`: integration explicitly proves the public guard rejects
it, then tests the internal format translation without relabelling the fixture.
That is runtime-format evidence, not Röbel admission or a live handover proof.

The remaining integration is the concrete live driver: admission of the exact
successor, complete stage-aware readiness, original Case/public-service checks,
and composition/recovery of all private worker, encrypted backup and lifecycle
receipts. `verify_ready`/`verify_complete`
remain mandatory ports, not executable success defaults. Existing tests use
explicit controlled observations at those ports. No source shutdown is allowed
until that driver and a full rehearsal are ready.

### Migration and handover

The runner does not provision volumes, manage Secrets, stop workloads, change
RBAC, run GitOps or bind network listeners. Before live use, a separate reviewed
Operations transaction must:

1. Bind this runner's bytes, exact image, source baseline and private
   configuration hashes; precreate its immutable configuration and a separate
   target PVC, recording actual UIDs and PV identity.
2. Suspend the responsible reconciler with durable receipts, stop and cleanly
   seal the source, and prove its Pod is gone before mounting the original
   ReadWriteOncePod volume. Retain the original volume and backup.
3. Mount source and target at their reviewed paths in an isolated migration
   workload. Keep the original workload stopped for the whole handover; the
   runtime's process locks alone do not fence two deployments.
4. Run prepare, retain its private result, and construct the exact activation
   plan from the observed source/target claims and candidate checksum. Never
   guess a target PVC UID or copy the original storage marker onto the target.
5. Activate with a fresh reserved result file, retain its linked receipt, then
   start the normal v2 runtime. Verify the immutable public admission, review
   listener, restart/replay and source preservation before restoring GitOps.

After a lost result or interrupted import, retain both stores and use a **new**
result file. The public runtime permits only the same still-valid plan and
unchanged target. Its persisted intent blocks ordinary startup. An expired plan
requires a newly reviewed target from the retained source, preserving the
interrupted target; do not edit the intent or forge a seal. A target that has
reopened or progressed cannot be overwritten by replaying this import.

Candidate temporary directories belong to the migration workload. Retain them
until their receipts are captured, then clean only that workload's own temporary
storage. The runner never removes source or target directories, and never
overwrites an existing result.

## Verification

Run descriptor and failure-boundary tests with:

```sh
node --test scripts/test_case_review_migration.mjs
```

Run the real SQLite/runtime integration against a clean checkout of the pinned
public source tree with Node 22.18 or later:

```sh
CASE_REVIEW_TEST_SOURCE_ROOT=/absolute/path/to/stadtstack \
  node --test scripts/test_case_review_migration_integration.mjs
```

The integration refuses a different source tree or changed runtime sources. It
uses the public synthetic fixture and a simulated storage observation, not live
accounts or Kubernetes. It checks admission version 3, exact source bytes,
candidate activation, identical retry, ordinary runtime configuration and
refusal to replay after the target has reopened. It starts no HTTP listener.
The same invocation runs all descriptor tests. Seven tests pass locally.

The storage transaction and its bounded kubectl Adapter are exercised by
`python3 -m unittest -v scripts.test_case_review_storage`: twenty tests cover
durable intent, delayed binding, lost responses, ownership conflicts, guarded
retention, exact recovery, changed identities and forbidden transport requests.
They use synthetic API responses and real private receipt files; they do not
provision a live volume.

CI admission and the protected file inventory include this operator. This
source checkpoint is not an approved deployment or a substitute for the
remaining bounded Operations transaction and its live verification.

The CI integration is limited to:

- Add this README and the three new `.mjs` files to `case_runtime_admission.py`
  `FILES`, so later promotions cannot alter them through candidate execution.
- In `reviewed-render-admission.yml`, check out public Stadtstack revision
  `fdb0b7f36c33d925be141d8e9037b48d17612df8` with the existing pinned checkout
  action and credentials disabled. Use setup-node
  `820762786026740c76f36085b0efc47a31fe5020` and Node 22.18.0, then
  `npm ci --ignore-scripts` in that source checkout.
- Run the integration from `base/scripts` for pull requests and
  `candidate/scripts` after merging to protected main. The pull-request
  candidate remains data. Both paths use the separately pinned source checkout.
- Update the existing workflow-shape test for the additional checkout and
  assert the protected-base integration command and immutable source revision.

The existing protected base rejects changes to its own workflow and admission
inventory. This extension therefore requires an explicitly reviewed maintenance
merge; it does not relax that rule or change branch protection itself.
