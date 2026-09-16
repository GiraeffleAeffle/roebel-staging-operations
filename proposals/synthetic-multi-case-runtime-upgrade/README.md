# Upgrade the confirmed Case to the multi-Case runtime

This inactive proposal advances the current Brief runtime to published Stadtstack
source `9010479b00f58ff4623c26ef993365e47b168224`. It preserves B198 at version28,
its eight accepted responses and its confirmed Citizen Brief. The target image
adds explicit review routing for already admitted Cases. This transition does
not admit another Case, change configuration, add roles or publish discussion
content. The existing default Case and every grant retain their meanings.

`transition.json` pins the current version28 journal head, admission, unchanged
private configuration, source and target deployment bindings. `topology.json`
explains the target topology checksum. The independently pinned Town Workspace
bundle contains the exact successor resources. Activation advances only the
Workspace stage and Case resources: one new immutable binding ConfigMap and the
control Deployment's two image references, binding pin and ConfigMap reference.
Every old ConfigMap, public reader, security setting, Secret reference and volume
is retained. The reconciler receives named access only to the new binding map.

Use the existing offline same-volume upgrade algorithm: verify the live baseline,
fence the single writer, capture and independently restore an encrypted backup,
replay the exact archive with the new runtime, apply the bound plan, retire the
worker, activate the reviewed image/binding, verify all listeners and the unchanged
Case/Brief/admission, prove a clean restart, then resume reconciliation. Worker v2
has no network or service-account token and mounts only the existing Case volume
and configuration Secret. Preserve the retained original and all private receipts.
A completed or stale historical version27 transition must never be replayed.

The original confirmed return must remain
`sha256:ef7d43ff146dfd83acb259edaabf66ac65b1f61bff21b82987b9a3f925e1edbf`.
Staff access expires on September17; this proposal does not extend it.

After this upgrade, a second signed discussion must receive its own live admission
before it is named in additionalCaseIds. New independent-user grants and Mecky
bindings require their own exact configuration and content review. No municipal
approval, council decision, treasury action or external dispatch is implied.
