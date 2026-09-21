# Reviewed document catalogue activation

The document-knowledge stage mounts the owner-approved public catalogue at
`/run/roebel-public-knowledge` and enables community documents in Public Mecky.
The initial edition contains eleven attributed Bürgerrat recommendations and
the two unchanged news/council records. No original PDF scan or private contact
information is included. A null publication date preserves the unknown date.

The named ConfigMap is provisioned separately only after exact rollout approval.
Before provisioning, verify the namespace and existing workloads, perform server
dry-run, and require absence or the exact already-recorded object. Retain the
UID/resourceVersion and content checksums; never overwrite an unexpected edition.
Web receives a directory mount with readOnly=true and no subPath. Its service
account remains unmounted; no reconciler, network or Secret permission is added.

The ingress adds only GET/HEAD access to the three exact municipality/source
paths. The normal POST denial and every other API allowance remain unchanged.
Both application images must come from the verified Release Set. Activate only
after the exact ConfigMap content and all protected checks are verified.

Later source editions require owner review and one atomic compare-and-swap of
this named ConfigMap. Retain earlier editions outside the app. Kubernetes refresh
may be delayed across replicas; verify every Web replica before reporting an
edition active. Corrections and withdrawals must be re-read and stale citations
must show their changed/withdrawn state. Content edits need no image rebuild.

Acceptance: all three projection digests/ETags, readable current and changed
citations, several unrelated Mecky questions plus the signed Kugellager topic,
negative municipality/source/method checks, and preserved Case/Brief receipts.
The existing staff grants are not renewed. No discussion post or new civic
record is part of deployment verification.
