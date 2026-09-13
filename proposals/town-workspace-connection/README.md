# Town Workspace connection — staging preparation

Step 7A is complete. This proposal prepares 7B: authenticated access to the
original synthetic Case through the Town Workspace in Röbel Web. It is not
referenced by a Kustomization and does not activate a deployment or change the
protected verifier. The existing Case, retained volumes and public receipt
remain the rollout's preservation inputs.

## Prepared and verified

- Röbel PR107 merged normally as `db2dc5112bb2b96db1143ef6986f8055b1a1cee1`.
  Its 99 focused tests, strict affected TypeScript, lint and required hosted
  CI passed. Publisher run `34707189131` completed, including provenance and SBOM.
- The new Web image is
  `ghcr.io/giraeffleaeffle/roebel-web-staging@sha256:210dae1009afaa40483c15cf842c8c5a0b54c9eb0ec7ec279bfb540aad7ba4c4`.
  The Release Set payload is
  `sha256:e9c69d57bf9d9b03a48b7a6b3d40d3e8187486590ab36e677663c68380709a5b`.
- The live staging catalog had no `workspace_sessions` table or dedicated role.
  The image's default table grants include `anon`, `authenticated` and
  `service_role`, so the migration explicitly revokes their session-table access.
- The exact [migration](workspace-sessions.sql) and
  [access rehearsal](rehearse-session-access.sql) passed on the existing staging
  PostgreSQL server in one transaction that was rolled back. CRUD succeeded;
  missing claims and wrong audience were denied; the dedicated role had no
  access to other public tables; broad API roles had no session access.
  The catalog matched its original state after rollback. No persistent schema
  change or real session was created.

## Independent Röbel ID for staging — 2026-09-13

The user requested an independent staging version to avoid waiting for the
collaborator's production provider configuration. This supersedes the earlier
production client-registration plan. The selected issuer is
`https://roebel-id.staging.agentcart.eu`; DNS resolves to the existing staging
address `77.42.11.9`. [oidc-registration.json](oidc-registration.json) registers
one relying party and the exact Web staging callback in this separate instance.
The production issuer and its client registrations are outside this rollout.

The new source profile uses a real SIWE browser-wallet signature and a private
allowlist of one to eight test wallets. It does not require the collaborator's
Thirdweb project or production Supabase readers. Claims identify only the
verified wallet, with empty groups and false citizen/attester flags. A separate
test wallet is not the existing citizen account and does not inherit its history
or civic rights. Existing email/Google wallet reuse remains a separate integration
check; an unauthenticated public-provider probe was inconclusive and completed
no login or message.

[identity-instance.json](identity-instance.json) records the non-executable
instance proposal. [identity-state.sql](identity-state.sql) and
[rehearse-identity-access.sql](rehearse-identity-access.sql) passed on the actual
staging PostgreSQL server in one transaction that rolled back. CRUD, grant-state
deletion, missing/wrong claims, broad-role denial and unrelated-table denial were
verified; the before/after catalog matched. This is not a committed migration.
Its JWT role is separate from the workspace session role, using
`iss=roebel-id-staging` and `aud=roebel-id-state-store` with bounded expiry.

Source PR108 merged normally as `8a47361269ecac65e08d17607b37547fd5d7a0b8`
with passing CI. Identity-only publisher run `34750456517` completed successfully.
The image is
`ghcr.io/giraeffleaeffle/roebel-id-staging@sha256:4a10e93438420da8934d380b08381734952457c1b17bcf97b4da5189f62e07c3`.
Its provenance and SBOM attestations independently verify against the exact
source and protected publisher identity. The image is published, not deployed.
The cluster has a ready `letsencrypt-prod` ClusterIssuer with the `haproxy`
HTTP01 solver. [identity-certificate.json](identity-certificate.json) prepares
its exact hostname certificate; no certificate has been requested yet.

The instance needs new persistent RSA keys, distinct cookie keys, its own client
secret, an explicitly selected test wallet, TLS and an admitted image/network
render. All credentials remain private. Run one replica while SIWE nonces are
process-local; restarting it invalidates pending challenges, while persistent
OAuth state and signing keys must survive. The browser must still prove the
complete callback flow before its subject is mapped to any synthetic role grant.

## Connection to prepare for admission

[connection.json](connection.json) binds the published image and the required
configuration, exact paths and network additions. It is a proposal, not an
executable resource manifest. The future reviewed render must combine it with
the verified Release Set metadata and be checked against Operations predecessor
`975cea8d58fa994cd69e607a93e4947741e74bb3` or a newly verified successor.

The runtime session key is a server-held PostgREST JWT for only
`roebel_workspace_session`. Its claims must include
`iss=roebel-town-workspace-staging`, `aud=roebel-workspace-session-store` and a
bounded expiry. It is separate from the OIDC client secret. The existing
PostgREST signing key stays inside the staging operator's private context;
Web receives only the restricted JWT. A production or general service-role key
is not the staging session credential.

The migration is additive and intentionally errors if its table or role already
exists. Run it with `psql --no-psqlrc --set=ON_ERROR_STOP=1` only after the exact
rollout is ready. An uncertain response requires a catalog check, not blind
re-execution. The rehearsal replaces the final `commit;` with its assertions and
`rollback;`; its notification cannot survive rollback.

Deploy login and session storage first, with review unavailable until the actual
OIDC callback has verified the test account's subject. Then bind that exact
subject to the existing, unexpired synthetic review grants and activate the
private review configuration. Wallet/Nostr identifiers and OIDC groups do not
automatically become municipal roles. The previously created test account may
exercise the explicit synthetic roles, as the user requested.

The single-name Case NetworkPolicy addition needs precreation and an exact
addition to the reconciler's existing named NetworkPolicy permission list.
No broad Secret access or resource-creation permission belongs in Flux.
The current protected policy still pins the old Web image and Case render;
the complete connection needs an exact admission extension before activation.

## Acceptance still pending

The browser must sign in through the registered callback, keep its session
across Web replicas, and display the same discussion, public admission receipt,
Case and department graph. Anonymous access and unassigned subjects must be
denied review; cross-origin writes and unrelated API paths must remain denied.
Logout must remove the stored session. Confirm image identity, reconciled
resources, original public Case receipt and retained storage after the rollout.

Step 7C follows with the eight department reviews, a reviewed Citizen Brief in
the citizen app, and a public Mecky answer citing that same public context.
