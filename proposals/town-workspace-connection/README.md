# Town Workspace staging rollout — step 7B

The original synthetic Case and public receipt are running. This proposal
connects that Case to the Town Workspace through an independent staging login.
The protected admission hook is pending specific authorization; no live
identity, session migration, network or workload change has been made.

## Prepared result

- Web PR107: `db2dc5112bb2b96db1143ef6986f8055b1a1cee1`, published image
  `ghcr.io/giraeffleaeffle/roebel-web-staging@sha256:210dae1009afaa40483c15cf842c8c5a0b54c9eb0ec7ec279bfb540aad7ba4c4`.
- Identity PR108: `8a47361269ecac65e08d17607b37547fd5d7a0b8`, published image
  `ghcr.io/giraeffleaeffle/roebel-id-staging@sha256:4a10e93438420da8934d380b08381734952457c1b17bcf97b4da5189f62e07c3`.
  Both publications have verified provenance and SBOM attestations.
- [Identity resources](../../reviewed-render/roebel-staging/identity/resources.json):
  one replica, Service, dedicated TLS certificate and ingress, exact outbound
  network paths and reciprocal PostgREST ingress. The hostname resolves to the
  existing staging ingress. The existing Gnosis RPC resolves to
  `34.111.230.52`, responds with chain 100, and is the only external issuer egress.
- [Dormant Flux bootstrap](flux-bootstrap.json): six resources, a tenant-labelled
  reconciler and only named get/patch/update permissions. Pod and ReplicaSet list
  permissions support health checks. No Secret, create, delete or wildcard rights.
- [Rollout](rollout.json): exact predecessor hashes and complete login/review
  successor files, including source/image bindings, ingress, network and checksums.
  [State](../../reviewed-render/roebel-staging/town-workspace.json) is `prepared`.
  Neither the new identity Kustomization nor these stages is linked to live Flux.

## Three activation gates

1. Provision only the independent identity: new private signing/cookie/client
   material and one explicitly allowlisted test wallet, restricted identity and
   session database JWTs, then the two additive migrations. Request the exact
   HTTPS certificate and verify discovery/JWKS. No collaborator credentials,
   production identity reads or wallet funds are required.
2. Activate the complete `login` stage. A real SIWE signature and OIDC code/S256
   callback must create a restricted persistent session. Verify the actual subject,
   rejected unknown wallets, replay/expiry handling and session continuity across
   the issuer restart and Web replicas.
3. Bind that verified subject to the existing unexpired synthetic review grants
   before the `review` stage. This adds only TCP18090 on the existing Case Service,
   the exact Web-to-Case NetworkPolicy and its name in the existing reconciler Role,
   and a read-only private review configuration in Web. The wallet and OIDC groups
   do not grant municipal authority. Open the original discussion and verify its
   receipt, department graph and available actions in the Town Workspace.

The operator must capture fresh UID/resourceVersion and specification checks at
activation. Resource versions in the published Release Set are historical
publication inputs, not permission to replay a stale live patch. The source
ledger, both retained volumes, existing Case and receipt must be preserved.
No Case handover, storage migration or maintenance helper from step 7A is repeated.

## Validation

- 101 identity source tests and 99 focused Web tests passed before publication.
- Both database migrations and their restricted-role access checks passed against
  staging inside rolled-back transactions. They are not committed migrations.
- 13 independent rollout tests pass: complete forward stages, partial-rollout and
  unrelated-change rejection, pinned SQL/RBAC, reciprocal networks, exact HTTP
  method/path permissions, read-only mounts and original Case preservation.
- Kubernetes server dry-run accepted all 16 proposed resources on 2026-09-13.
  The existing Web, Case and PostgreSQL specifications/UIDs/generations matched
  before and after. No resources were saved. Requests were serialized to respect
  the existing transport's connection limit.
- Protected-verifier integration and full admission checks remain pending. The
  automatic approval review rejected the hook because the identity/review boundary
  exceeds the previous narrow review-runtime authorization. The standalone module
  is inert until that protected hook is authorized and installed.

Signing keys, cookie keys, the OIDC client secret and one unfunded test wallet have
been generated in owner-only local storage. Private values are absent from this
repository. Restricted database JWTs and Kubernetes Secrets are not yet issued.

Step 7C follows: eight department packages, a reviewed Citizen Brief returned to
Röbel, and a public Mecky answer citing that same public context.

## Separate demo-account login stage

The inactive `demo-login` successor changes only the identity Deployment's
`STAGING_ALLOWED_WALLETS` Secret reference to `roebel-staging-demo-login-v1`.
The immutable one-key Secret is provisioned separately after an exact roster
review; it retains the existing operator and adds five labelled demo accounts.
The issuer's signing keys, cookies, OIDC client secret, database credential,
image, service, network policy and all Case/Workspace grants remain unchanged.
This is login admission only: it creates no department role, test NFT, Case,
public post or municipal authority. Citizens remain without review access.

The reviewed private roster contains six addresses. Its exact UTF-8 comma-joined
bytes (no trailing newline) have checksum `sha256:6be96e4a306b6f34eb4abda877c4871a3e86e44faf5f1b648ca70b98ad3014a0`. Before activation the operator
must verify the Secret is immutable, contains only `allowed-wallets`, and matches
this checksum. This document contains no private keys or login credentials.

Activation advances exactly from `multi-case` to `demo-login` and changes only
the two pinned files: the stage record and identity resource list. Verify all
five fresh signed callbacks, replay rejection and the absence of staff grants;
preserve the original account and Case/Brief. Adding the Bürgerrat Case and its
separate author, reviewer and steward scopes remains a subsequent reviewed step.
