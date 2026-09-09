# Offline administration-review migration operator

Status: source implementation and offline verification only. This directory is
not included by any Kustomization or live operator. CI runs its offline tests. The existing
19-object bootstrap and active reviewed render keep their existing meaning.

`scripts/run-case-review-migration.mjs` bridges private Operations files to the
already published Stadtstack PR 70 runtime. It uses the exact source revision
`fdb0b7f36c33d925be141d8e9037b48d17612df8` and control image
`ghcr.io/giraeffleaeffle/stadtstack-case-steward-control@sha256:5f0eeec46e1e00150ce5f370ba9749a0f4d6d652dac73839f25699771adb1d60`.
The CLI imports three fixed modules from `/runtime/src`; it cannot select an
alternative runtime through its request. Selecting and attesting the actual
container image remains the responsibility of the protected Operations caller.

## Invocation contract

The trusted parent reserves four distinct regular files owned by the invoking
UID, with mode 0600, at most one hardlink and at most 1 MiB each. It opens the
inputs for reading and a **new, empty** result for writing, passing inherited
descriptor numbers of at least 3. No configuration or credential goes into
arguments, environment, stdout, stderr or public receipts.

The five CLI arguments are `--request-fd`, `--expected-request-sha256`,
`--source-config-fd`, `--target-config-fd` and `--result-fd`. The independently
reviewed request hash must come from the protected Operations plan. Computing a
hash from arbitrary user input at invocation does not establish authorization.
Inputs may not be modified during an operation. The runner rereads their exact
byte pins at the public runtime's authority checks and before writing a result.

The request is a closed JSON object with these fields:

| Field | Meaning |
| --- | --- |
| `schemaVersion` | `roebel_case_review_migration_request_v1` |
| `mode` | `prepare` or `activate` |
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

## Recovery and remaining Operations work

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
