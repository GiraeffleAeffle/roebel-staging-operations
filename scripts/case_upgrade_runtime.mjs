/** Narrow port to the published Case runtime. Production callers fix root to
 * /runtime in the digest-pinned worker; only offline tests select a checkout.
 */
import { DatabaseSync } from "node:sqlite";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { canonical } from "./case_runtime_upgrade.mjs";

export async function loadCaseUpgradeRuntime(root) {
  const load = file => import(pathToFileURL(join(root, "src", file)).href);
  const [adapter, preflight, claim, seal, recovery] = await Promise.all([
    load("adapters/sqlite-atomic-topic-case-admission.ts"), load("staging-case-control-preflight.ts"),
    load("case-durable-deployment-claim.ts"), load("case-shutdown-seal.ts"), load("case-state-recovery-evidence.ts"),
  ]);
  const check = fact => { if (!fact) throw new Error("case_runtime_upgrade_replay_failed"); };
  return {
    verifyBinding: preflight.verifyStagingCaseControlReviewedBinding,
    verifyClaim: claim.verifyCaseDurableDeploymentClaim,
    verifySeal: seal.verifyCaseShutdownSeal,
    replay(rootDir, configuration, expectedSeal) {
      check(configuration.syntheticAdoption && configuration.requiredDepartmentIds?.length === 8 &&
        configuration.administrationReview?.caseId === expectedSeal.recoveryEvidence.orderedHeads[0]?.caseId && !configuration.citizenAdoption);
      let store, db;
      try {
        store = adapter.createSqliteAtomicTopicCaseAdmission({ rootDir,
          ...Object.fromEntries(["municipalityId", "policyVersion", "actorRegistry", "allowedSignerPubkeys", "allowedAgentPubkeys", "requiredDepartmentIds"]
            .map(k => [k, configuration[k]])), syntheticDepartmentReview: true,
          syntheticAdoption: { policy: configuration.syntheticAdoption.policy, now: () => new Date(),
            acceptance: { resolve: async () => { throw new Error("offline_upgrade_cannot_admit"); } } },
        });
        // Opening the real coordinator replays every event and retry record.
        for (const head of expectedSeal.recoveryEvidence.orderedHeads) store.caseCoordinators.open(head.caseId);
        const outboxEntries = store.outbox.replay({ limit: 2 });
        db = new DatabaseSync(join(rootDir, expectedSeal.databaseBasename), { readOnly: true });
        const integrity = db.prepare("PRAGMA integrity_check").all();
        check(integrity.length === 1 && integrity[0].integrity_check === "ok");
        const meta = db.prepare("SELECT config_fingerprint FROM atomic_municipality_meta WHERE municipality_id=?").get(configuration.municipalityId);
        check(meta?.config_fingerprint === expectedSeal.configFingerprint);
        const caseJournalHeads = db.prepare("SELECT case_id,case_version,head_checksum FROM atomic_case_meta ORDER BY case_id").all()
          .map(r => ({ caseId: r.case_id, caseVersion: r.case_version, journalHeadChecksum: r.head_checksum }));
        check(canonical(recovery.createCaseStateRecoveryEvidence({ caseJournalHeads, outboxEntries })) === canonical(expectedSeal.recoveryEvidence));
      } finally { try { db?.close(); } finally { store?.close(); } }
    },
  };
}
