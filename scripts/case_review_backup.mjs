/** Bounded sealed-Case archive. Encryption belongs to the Operations host.
 * This format contains private bytes: it must only travel through private
 * descriptors and must never be printed, logged or put in a ConfigMap.
 */
import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, fchmodSync, fsyncSync, lstatSync, mkdtempSync, openSync, readSync,
  readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

export const MAX_ARCHIVE_BYTES = 64 * 1024 * 1024;
const MAX_FILE_BYTES = 32 * 1024 * 1024;
const SEAL = "case-shutdown-seal-v2.json";
const CLAIM = "case-durable-deployment-claim-v1.json";
const forbidden = new Set(["case-open-epoch-v1.json", "case-store-bootstrap-v1.json",
  "case-recovery-activation-v2.json", "synthetic-review-migration-intent-v1.json"]);
const hash = (bytes) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const canonical = (value) => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` :
  value && typeof value === "object" ? `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}` : JSON.stringify(value);
function requireFact(ok) { if (!ok) throw new Error("case_review_backup_stopped"); }
function nameValid(name) { return typeof name === "string" &&
  (name === ".stadtstack-control-storage-v1.json" || /^[a-z0-9][a-z0-9.-]{0,199}$/.test(name)) && !forbidden.has(name); }
const identity = (s) => `${s.dev}:${s.ino}:${s.size}:${s.mtimeNs}:${s.ctimeNs}:${s.mode}:${s.uid}:${s.gid}:${s.nlink}`;
function exact(value, fields) {
  requireFact(value && Object.getPrototypeOf(value) === Object.prototype &&
    Object.keys(value).length === fields.length && Object.keys(value).every((k) => fields.includes(k)));
}

function snapshot(root) {
  requireFact(typeof root === "string" && root === resolve(root) && realpathSync(root) === root);
  const rootStat = lstatSync(root, { bigint: true });
  requireFact(rootStat.isDirectory() && rootStat.uid === BigInt(process.getuid()) && (rootStat.mode & 0o7777n) === 0o700n);
  const names = readdirSync(root).sort();
  requireFact(names.length >= 3 && names.length <= 32 && names.every(nameValid));
  let total = 0;
  const files = names.map((name) => {
    const path = join(root, name), before = lstatSync(path, { bigint: true });
    requireFact(before.isFile() && before.nlink === 1n && before.uid === rootStat.uid &&
      [0o600n, 0o640n, 0o644n].includes(before.mode & 0o7777n) && before.size <= BigInt(MAX_FILE_BYTES));
    total += Number(before.size); requireFact(total <= MAX_FILE_BYTES);
    const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      requireFact(identity(fstatSync(fd, { bigint: true })) === identity(before));
      const bytes = Buffer.alloc(Number(before.size));
      let offset = 0;
      while (offset < bytes.length) {
        const n = readSync(fd, bytes, offset, bytes.length - offset, offset); requireFact(n > 0); offset += n;
      }
      requireFact(readSync(fd, Buffer.alloc(1), 0, 1, bytes.length) === 0 &&
        identity(fstatSync(fd, { bigint: true })) === identity(before) && identity(lstatSync(path, { bigint: true })) === identity(before));
      return { name, mode: Number(before.mode & 0o7777n), byteLength: bytes.length, sha256: hash(bytes), base64: bytes.toString("base64") };
    } finally { closeSync(fd); }
  });
  requireFact(identity(lstatSync(root, { bigint: true })) === identity(rootStat) && canonical(readdirSync(root).sort()) === canonical(names));
  return files;
}

function evidence(files, preparation, expectedClaimChecksum, verifySeal) {
  const find = (name) => {
    const file = files.find((f) => f.name === name); requireFact(file); return Buffer.from(file.base64, "base64");
  };
  const seal = verifySeal(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(find(SEAL))));
  const claim = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(find(CLAIM)));
  const { claimChecksum, ...unsignedClaim } = claim;
  requireFact(claimChecksum === expectedClaimChecksum && hash(canonical(unsignedClaim)) === claimChecksum &&
    seal.deploymentClaimChecksum === claimChecksum && seal.sealChecksum === preparation.expectedSourceSealChecksum &&
    seal.recoveryEvidence.orderedHeads.length === 1 && seal.recoveryEvidence.orderedHeads[0].caseId === preparation.expectedCaseId &&
    seal.recoveryEvidence.orderedHeads[0].caseVersion === 3 && seal.recoveryEvidence.orderedBindingEvidence.length === 1 &&
    seal.recoveryEvidence.orderedBindingEvidence[0].receiptChecksum === preparation.expectedAdmissionReceiptChecksum);
  const database = find(seal.databaseBasename);
  requireFact(database.length === seal.databaseByteLength && hash(database) === seal.databaseSha256);
  for (const file of files) if (/-(wal|shm|journal)$/.test(file.name)) requireFact(file.byteLength === 0);
  return { sourceSealChecksum: seal.sealChecksum, sourceDeploymentClaimChecksum: claimChecksum,
    sourceDatabaseSha256: seal.databaseSha256, sourceFilesSha256: hash(canonical(files.map(({ base64, ...item }) => item))),
    caseId: preparation.expectedCaseId, caseVersion: 3, admissionReceiptChecksum: preparation.expectedAdmissionReceiptChecksum };
}

/** Source is never opened as SQLite. Caller must already fence all writers.
 * Public runtime seal verification plus two byte snapshots reject stale or
 * changing inputs; physical ownership remains the Operations caller's job.
 */
export function captureSealedCase(preparation, expectedClaimChecksum, verifySeal) {
  const files = snapshot(preparation.sourceRootDir);
  const facts = evidence(files, preparation, expectedClaimChecksum, verifySeal);
  requireFact(canonical(snapshot(preparation.sourceRootDir)) === canonical(files));
  const bytes = Buffer.from(canonical({ schemaVersion: "roebel_sealed_case_archive_v1", evidence: facts, files }) + "\n");
  requireFact(bytes.length <= MAX_ARCHIVE_BYTES);
  return { bytes, evidence: facts, archiveSha256: hash(bytes) };
}

/** Decrypted bytes are independently pinned by the capture receipt. Restore
 * only into a new private temporary directory, then replay via the fixed
 * runtime's real migration preparation. The ordinary runtime never opens the
 * restored source, and no existing path can be overwritten by archive names.
 */
export function verifyRestoredCase(bytes, expectedArchiveSha256, preparation, expectedClaimChecksum, runtime) {
  requireFact(Buffer.isBuffer(bytes) && bytes.length <= MAX_ARCHIVE_BYTES && hash(bytes) === expectedArchiveSha256);
  const archive = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  exact(archive, ["schemaVersion", "evidence", "files"]);
  requireFact(archive.schemaVersion === "roebel_sealed_case_archive_v1" && Array.isArray(archive.files) &&
    archive.files.length >= 3 && archive.files.length <= 32);
  const names = new Set(); let total = 0;
  for (const f of archive.files) {
    exact(f, ["name", "mode", "byteLength", "sha256", "base64"]);
    requireFact([0o600, 0o640, 0o644].includes(f.mode) && nameValid(f.name) && !names.has(f.name) && Number.isSafeInteger(f.byteLength) &&
      f.byteLength >= 0 && f.byteLength <= MAX_FILE_BYTES && typeof f.base64 === "string");
    names.add(f.name); total += f.byteLength; requireFact(total <= MAX_FILE_BYTES);
    const data = Buffer.from(f.base64, "base64");
    requireFact(data.toString("base64") === f.base64 && data.length === f.byteLength && hash(data) === f.sha256);
  }
  requireFact(canonical([...names]) === canonical([...names].sort()));
  const facts = evidence(archive.files, preparation, expectedClaimChecksum, runtime.verifySeal);
  requireFact(canonical(facts) === canonical(archive.evidence));
  const temporary = realpathSync(mkdtempSync(join(tmpdir(), "roebel-case-backup-restore-")));
  let candidate;
  try {
    for (const f of archive.files) {
      const path = join(temporary, f.name);
      writeFileSync(path, Buffer.from(f.base64, "base64"), { flag: "wx", mode: 0o600 });
      const fd = openSync(path, "r"); try { fchmodSync(fd, f.mode); fsyncSync(fd); } finally { closeSync(fd); }
    }
    const fd = openSync(temporary, "r"); try { fsyncSync(fd); } finally { closeSync(fd); }
    const before = snapshot(temporary);
    requireFact(canonical(before) === canonical(archive.files));
    candidate = runtime.prepare({ ...preparation, sourceRootDir: temporary });
    const receipt = candidate.receipt;
    requireFact(receipt.caseId === facts.caseId && receipt.caseVersion === 3 && receipt.admissionReceiptChecksum === facts.admissionReceiptChecksum &&
      receipt.sourceSealChecksum === facts.sourceSealChecksum && receipt.sourceDatabaseSha256 === facts.sourceDatabaseSha256 &&
      receipt.testOnly === true && receipt.authorityBinding === "none");
    requireFact(canonical(snapshot(temporary)) === canonical(before));
    // Also recheck the still-fenced original after the independent restore.
    const current = captureSealedCase(preparation, expectedClaimChecksum, runtime.verifySeal);
    requireFact(current.archiveSha256 === expectedArchiveSha256);
    return { ...facts, restoredFilesSha256: facts.sourceFilesSha256,
      archiveSha256: expectedArchiveSha256, restoredCandidateChecksum: receipt.candidateChecksum };
  } finally {
    rmSync(temporary, { recursive: true, force: true });
    // The fixed runtime owns this throwaway rehearsal candidate. Never clean
    // an arbitrary caller path, a retained volume or a real migration target.
    if (candidate?.candidateRootDir && dirname(candidate.candidateRootDir) === realpathSync(tmpdir()) &&
      candidate.candidateRootDir.startsWith(join(realpathSync(tmpdir()), "stadtstack-review-migration-"))) {
      rmSync(candidate.candidateRootDir, { recursive: true, force: true });
    }
  }
}
