# Preserve the reviewed Case during the 7C runtime upgrade

This proposal upgrades the existing, synthetic Case at version 27 so its eight
accepted department responses can form a steward-confirmed Brief. The active
render remains at `review` until the storage transaction and runtime checks
succeed. The `brief` successor includes the already published Web/Mecky Release
Set, the exact new Case image, one immutable binding ConfigMap and one public
GET/HEAD route. Existing identity, configuration, roles and both retained Case
volumes are preserved. No municipal authority or external dispatch is created.

`transition.json` pins the current Case head, original public admission,
configuration bytes, PVC/PV and source/target deployment bindings. It is input
to an Operations worker, not a backup, a shutdown seal or evidence of activation.
`resources.json` is the exact target Case render; the old binding ConfigMap is
retained. The reconciler gains named get/patch/update access to only
`roebel-case-steward-brief-reviewed-v1`, with no Secret or volume permissions.

## Storage transition

The ordinary runtime continues to reject a mismatched deployment claim. The
historical version-3 review migration remains unchanged. Operations owns this
separate, same-volume transition:

1. Verify the live version-27 head, eight accepted reviews, configuration pin,
   original admission, volume identities and published image attestations.
2. Suspend the existing Case reconciler, stop its one writer and observe every
   writer Pod gone. A single temporary worker mounts the RWOP volume, uses the
   new digest-pinned image and has no service-account token or network access.
3. Capture the closed directory, including its seal, claim, owner database and
   private journal. Restore a disposable copy and replay every event/retry and
   public receipt with the new runtime. Encrypt the archive on the host, decrypt
   it independently, upload those recovered bytes and run `verify` again.
4. `activate` requires that verified archive and a fresh host observation of
   zero writers, suspended reconciliation and the one exact PVC consumer. It
   locks both owner databases and prepares a private sibling directory from the
   original archive. The municipal SQLite bytes are never edited or replaced
   with a replayed database. Only the claim, storage marker and materialization
   seal change, with a receipt preserving the complete source lineage.
5. An fsynced intent precedes two directory renames on that volume: original
   root to a retained directory, prepared candidate to the original path. Both
   parent directories are synced. A crash between renames leaves no valid root,
   so the existing preflight fails closed. Re-entry accepts only the same plan
   and exact bytes. It can finish an interrupted candidate copy; foreign data,
   symlinks, hard links, stale configuration or changed Case heads stop it.
6. Retire the temporary worker, activate the target binding/image, verify all
   four listeners and the unchanged Case/readiness/public admission, then prove
   a clean restart. Resume Flux only against the reviewed target render.
7. Apply the already approved synthetic Brief through the steward's checksum
   preview/confirmation. Verify the return through Röbel's public BFF and UI.

The retained source is a local recovery copy, not a substitute for the encrypted
backup. Recovery moves forward only. Once the target runtime has written an
event, an old upgrade plan cannot run again or roll that event back. A later
upgrade requires a separately specified lineage transition.

`case_runtime_upgrade.mjs` owns archive/replay/switch/recovery. Its runtime port
uses published Stadtstack verifiers and the real SQLite coordinator. The private
worker exchanges only pinned files; stdout contains result hashes, never an
archive or configuration. The host owns Kubernetes observations and encrypted
backup custody; a worker receipt alone does not prove those external actions.

The activated `brief` stage permits the existing five Release Set fields to
advance through the normal protected image promotion verifier. All other
Deployment fields, routes, network policies, identity and Case binding stay
pinned. This prevents the workspace setup from blocking subsequent Mecky image
updates. The Mecky transport repair remains ordered after this Web release;
its synthetic Brief reader is not enabled by this proposal.

## Verification

Run `CASE_UPGRADE_TEST_SOURCE_ROOT=/absolute/published-7C-checkout node --test
scripts/test_case_runtime_upgrade.mjs`. The fixed source tree is checked before
tests. Rehearsals create a real synthetic Case, assign/draft/accept all eight
departments, preserve version 27 through an upgrade and two restarts, then
create its Brief at version 28. Six child-process exits exercise recovery,
including a partially copied candidate and both directory renames. Additional
checks reject stale heads, changed policy/PVC, a held writer lock, unsafe files,
missing restored-archive verification and stale/overlapping worker observations.

The historical archive regression runs separately with
`node --test scripts/test_case_review_migration.mjs`. Hosted rehearsal uses
Node 22.18.0 and the exact published source. No local container build is needed.
