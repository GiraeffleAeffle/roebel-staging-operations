# Isolated synthetic Case runtime proposal

This is a review proposal for the first empty-store Case bootstrap. It is not
referenced by the active render, a Flux source path or a deployment runner.
The protected admission verifier must explicitly admit the complete proposal
before any runtime resource, staff credential or Web connection is activated.

The two published Stadtstack images supply a single-writer control process
and a separate public reader. The control binding pins the existing retained
10 GiB ReadWriteOncePod claim, its exact UID/PV, a 0700 directory owned by
UID/GID 1000, ext4 and at least 1 GiB free. The initial marker may be created
only in that empty directory; an existing marker must match exactly. The
source runtime then owns the bootstrap, journal, outbox and shutdown seal.
A restore to another volume or an image/claim change keeps its separate gate.

`resources.json` contains 15 objects: the already reserved tokenless identities,
internal Services and isolation policies; one control ledger-egress rule; two
immutable reviewed ConfigMaps; and two one-replica Deployments. Its
`kustomization.yaml` renders only that file. No Secret, PVC or civic record is
included. The control init container takes the pre-provisioned private
configuration through the existing env-only Secret reference, checks its
independent SHA-256 pin, removes that environment entry and writes a regular
runtime-owned 0600 file in memory. Public has no private configuration, PVC or
Secret reference. The control binding follows the actual source Interface,
which omits `imagePullSecrets`; the Pod and public binding separately enforce
empty image-pull Secret lists.

The pinned ledger connection uses HTTPS to the same fixed public ingress
address already allowed by the Web workload. Public replays only the control
outbox on 18087. Web reaches only the public reader on 18086 using the exact
source origin added in Röbel PR #105. `web-connection.json` describes those two
additions; it does not alter the active Web render. Operations PR #150 has
deployed that Web image, and the tests-only repair in PR #152 passes protected
main CI. This proposal now uses the resulting Operations predecessor
`c4f551bec08f91c8ae2ae718d2ae82016961c7ed`. Its active render matches that
revision exactly. The Case bindings, image digests, retained-volume identities
and historical empty-volume preflight evidence are unchanged. The preflight
remains a dated observation; activation still requires fresh live checks.

Staff admission stays network-denied. Its first test uses a bounded private
operator session tied to the exact control Pod UID and the existing assigned
staging account's scoped credential. That credential is absent from this
repository and from public Web. A later collaborator dashboard needs its own
reviewed staff identity integration. Initial admission can create only the
separately typed synthetic Case; municipal eligibility and department commands
remain unavailable.

`flux-bootstrap.json` proposes a suspended, prune-false Kustomization and a
reconciler with get/patch/update permissions on exactly these named runtime
objects. It has no create/delete, Secret, PVC or RBAC permission. The initial
resource creation and exact-UID ownership verification must be reviewed before
unsuspension; the reconciling account cannot bootstrap itself.

Verification for this proposal: both source binding Interfaces accept the
prepared records; the public composition rejects private credentials; the
staging-only control application composes locally without binding listeners;
ConfigMap and marker checksums match; the public Pod has no credential or
storage capability. Kustomize renders exactly 15 objects. The storage-only
preflight separately verified the retained empty claim and removed its
temporary probe identities. Private receipts and credential recovery evidence
remain outside this public repository.

The current protected verifier is intentionally unchanged and cannot admit
these new proposal paths. A green ordinary image promotion does not authorize
this runtime. Pending work is the exact protected admission transition,
private Secret provisioning, reviewed bootstrap/Flux ownership, mounted startup
and clean restart checks, then explicit test admission and a verified browser
receipt. No restoration or municipal authority is implied by this proposal.
