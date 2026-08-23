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

## Inert Case staging topology foundation

`case-staging-topology/` is a separate, static contract for the next Case
transport slice. It reserves two deliberately disjoint internal identities and
ClusterIP service names—`roebel-case-steward-control` and
`roebel-case-public-binding`—with `automountServiceAccountToken: false` and a
per-capability default-deny ingress/egress policy. Its closed-world
`allowedKinds` list contains only `NetworkPolicy`, `Service`, and
`ServiceAccount`; every other kind is forbidden. These files are not in a Flux
Kustomization and therefore create nothing by themselves.

The contract intentionally has no Deployment, Pod template, image, Secret,
RBAC, Ingress, PVC, ConfigMap, storage mount, allowed network edge, or live
listener. In particular, it never grants a public workload access to SQLite.
A later application composition root must introduce each omitted concern in a
separate reviewed slice, starting from these deny-by-default identities and
network boundaries. The automatic image-promotion workflow cannot mutate this
topology contract.

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
  seven separately verified inert Case topology records (two ServiceAccounts,
  two ClusterIP Services, two default-deny NetworkPolicies, and their contract).
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
