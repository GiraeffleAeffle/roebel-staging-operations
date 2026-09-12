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

## Röbel ID registration needed

[oidc-registration.json](oidc-registration.json) is the proposed client metadata,
not evidence that a client already exists. Public discovery was verified at
`https://id.roebel.app/.well-known/openid-configuration` on 2026-09-12.
The running issuer supports the app's authorization-code, `client_secret_basic`
and S256 flow. The exact staging callback is:

`https://roebel-web.staging.agentcart.eu/api/workspace/auth/callback`

The provider's current source supports adding a relying party using an extra
environment prefix. Its administrator can register this separate client with:

| Provider setting | Value |
| --- | --- |
| `FIRST_PARTY_RPS` | Preserve its existing list and append `TOWN_WORKSPACE_STAGING` once. |
| `TOWN_WORKSPACE_STAGING_CLIENT_ID` | `roebel-town-workspace-staging` |
| `TOWN_WORKSPACE_STAGING_CLIENT_SECRET` | A new private client secret, supplied to the staging operator through a private file. |
| `TOWN_WORKSPACE_STAGING_REDIRECT_URIS` | The exact HTTPS callback above. |
| `TOWN_WORKSPACE_STAGING_BRANDING` | `roebel` |
| `TOWN_WORKSPACE_STAGING_BRANDING_CONTEXT` | `Town Workspace · Staging / Testbetrieb` |

Existing Nextcloud, Matrix, Web and Ortis clients retain their settings. The
workspace currently logs out its own server session and cookie; it does not
require an IdP post-logout callback. No provider change has been made, and no
message has been sent to the provider administrator.

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
