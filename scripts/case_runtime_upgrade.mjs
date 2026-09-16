/** Offline, same-volume release transition for an already reviewed synthetic
 * Case. The caller fences Kubernetes writers and verifies encrypted backup
 * recovery. This module has no network, listener, credential or civic-write
 * capability. The original sealed directory is retained byte for byte.
 */
import { createHash } from "node:crypto";
import { closeSync, constants, fchmodSync, fsyncSync, lstatSync, mkdirSync, mkdtempSync,
  openSync, readFileSync, readdirSync, realpathSync, renameSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { MAX_ARCHIVE_BYTES, snapshotCaseFiles, validateCaseArchiveFiles } from "./case_review_backup.mjs";

const SEAL = "case-shutdown-seal-v2.json", CLAIM = "case-durable-deployment-claim-v1.json";
const OWNER = "stadtstack-case-state-owner.sqlite", RECEIPT = "case-runtime-upgrade-v1.json";
export const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` :
  value && typeof value === "object" ? `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}` : JSON.stringify(value);
export const hash = bytes => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const sum = value => hash(canonical(value));
const check = value => { if (!value) throw new Error("case_runtime_upgrade_stopped"); };
const same = (a, b) => canonical(a) === canonical(b);
function exact(value, keys) {
  check(value && Object.getPrototypeOf(value) === Object.prototype && Object.keys(value).length === keys.length && Object.keys(value).every(k => keys.includes(k)));
}
const manifest = files => files.map(({ base64, ...facts }) => facts);
const bytesOf = (files, name) => { const f = files.find(f => f.name === name); check(f); return Buffer.from(f.base64, "base64"); };
function jsonOf(files, name) {
  const bytes = bytesOf(files, name), value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  check(bytes.equals(Buffer.from(canonical(value) + "\n"))); return value;
}
function file(name, value) {
  const bytes = Buffer.from(canonical(value) + "\n");
  return { name, mode: 0o600, byteLength: bytes.length, sha256: hash(bytes), base64: bytes.toString("base64") };
}
function syncDirectory(root) {
  const fd = openSync(root, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}
function writeNew(path, bytes, mode = 0o600) {
  const fd = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, mode);
  try { writeFileSync(fd, bytes); fchmodSync(fd, mode); fsyncSync(fd); } finally { closeSync(fd); }
}
function restore(root, files, afterFile = () => {}) {
  validateCaseArchiveFiles(files);
  for (const f of files) { writeNew(join(root, f.name), Buffer.from(f.base64, "base64"), f.mode); afterFile(); }
  syncDirectory(root); check(same(snapshotCaseFiles(root), files));
}
function exists(path) {
  try { lstatSync(path); return true; } catch (error) { if (error.code === "ENOENT") return false; throw error; }
}
function privateDirectory(root) {
  check(root === resolve(root) && realpathSync(root) === root);
  const s = lstatSync(root);
  check(s.isDirectory() && s.uid === process.getuid() && (s.mode & 0o7777) === 0o700); return s;
}
function mkdirPrivate(root) {
  mkdirSync(root, { mode: 0o700 });
  const fd = openSync(root, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { fchmodSync(fd, 0o700); fsyncSync(fd); } finally { closeSync(fd); }
}
function privateBytes(path, maxBytes) {
  const s = lstatSync(path);
  check(s.isFile() && s.nlink === 1 && s.uid === process.getuid() && (s.mode & 0o7777) === 0o600 && s.size <= maxBytes);
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { return readFileSync(fd); } finally { closeSync(fd); }
}
function writeRecord(path, value) {
  const bytes = Buffer.from(canonical(value) + "\n"), pending = `${path}.pending`;
  if (exists(path)) { check(privateBytes(path, bytes.length).equals(bytes)); return; }
  if (exists(pending)) {
    const partial = privateBytes(pending, bytes.length);
    check(bytes.subarray(0, partial.length).equals(partial)); unlinkSync(pending); syncDirectory(dirname(path));
  }
  writeNew(pending, bytes); renameSync(pending, path); syncDirectory(dirname(path));
}
function completeCandidate(root, files, failpoint) {
  // Only this plan's private, never-activated candidate may be rebuilt. Reject
  // foreign entries and changed bytes, including symlinks and hard links.
  privateDirectory(root);
  for (const name of readdirSync(root)) {
    const expected = files.find(f => f.name === name); check(expected);
    const path = join(root, name), s = lstatSync(path);
    check(s.isFile() && s.nlink === 1 && s.uid === process.getuid() && (s.mode & 0o7777) === expected.mode && s.size <= expected.byteLength);
    const actual = readFileSync(path), bytes = Buffer.from(expected.base64, "base64");
    check(bytes.subarray(0, actual.length).equals(actual));
    if (actual.length !== bytes.length) unlinkSync(path);
  }
  for (const f of files) if (!exists(join(root, f.name))) {
    writeNew(join(root, f.name), Buffer.from(f.base64, "base64"), f.mode); failpoint("candidate-file");
  }
  syncDirectory(root); check(same(snapshotCaseFiles(root), files));
}
function bindings(source, target, runtime) {
  source = runtime.verifyBinding(source); target = runtime.verifyBinding(target);
  check(source.schemaVersion === "staging_case_control_deployment_binding_v2" && target.schemaVersion === source.schemaVersion &&
    source.releaseDigest !== target.releaseDigest && source.bindingChecksum !== target.bindingChecksum);
  const stable = b => { const c = structuredClone(b); delete c.bindingChecksum; delete c.releaseDigest;
    delete c.operationsTopologyChecksum; delete c.storage.marker.checksum; return c; };
  check(same(stable(source), stable(target))); // Same PVC, root, roles, listeners, UID and resources.
  return { source, target };
}
function marker(binding) {
  const value = { schemaVersion: "staging_case_control_storage_marker_v1" };
  for (const k of ["deploymentEnvironment", "municipalityId", "workloadName", "workload", "releaseDigest", "operationsTopologyChecksum", "deployment"]) value[k] = binding[k];
  Object.assign(value, structuredClone(binding.storage)); delete value.marker.checksum;
  check(hash(canonical(value) + "\n") === binding.storage.marker.checksum); return value;
}
function claim(binding, runtime) {
  const body = { schemaVersion: "case_durable_deployment_claim_v1", municipalityId: binding.municipalityId,
    releaseDigest: binding.releaseDigest, controlDeploymentBindingChecksum: binding.bindingChecksum,
    pvc: { namespace: binding.storage.pvcNamespace, name: binding.storage.pvcName, uid: binding.storage.pvcUid }, pvName: binding.storage.pvName };
  return runtime.verifyClaim({ ...body, claimChecksum: sum(body) });
}
function facts(files, binding, expected, runtime) {
  const seal = runtime.verifySeal(jsonOf(files, SEAL)), heldClaim = runtime.verifyClaim(jsonOf(files, CLAIM));
  check(same(heldClaim, claim(binding, runtime)) && seal.deploymentClaimChecksum === heldClaim.claimChecksum &&
    seal.sourceReleaseDigest === binding.releaseDigest && seal.municipalityId === binding.municipalityId &&
    expected.caseId.startsWith(`urn:stadtstack:synthetic-case:municipality:${binding.municipalityId}:`) &&
    same(seal.recoveryEvidence.orderedHeads, [expected.head]) && seal.recoveryEvidence.orderedBindingEvidence.length === 1 &&
    seal.recoveryEvidence.orderedBindingEvidence[0].receiptChecksum === expected.admissionReceiptChecksum &&
    same(jsonOf(files, binding.storage.marker.fileName), marker(binding)));
  const db = bytesOf(files, seal.databaseBasename);
  check(db.length === seal.databaseByteLength && hash(db) === seal.databaseSha256);
  for (const f of files) if (/-(wal|shm|journal)$/.test(f.name)) check(f.byteLength === 0);
  check(files.some(f => f.name === OWNER)); return { seal, claim: heldClaim };
}
function replay(files, configuration, expected, runtime) {
  const temporaryAlias = mkdtempSync(join(tmpdir(), "case-upgrade-replay-")), temporary = realpathSync(temporaryAlias);
  try { restore(temporary, files); runtime.replay(temporaryAlias, configuration, expected);
    // Replay may checkpoint its disposable copy; the source and activation
    // candidate are always restored from the original byte-pinned archive.
  } finally { rmSync(temporary, { recursive: true, force: true }); }
}
function parseArchive(bytes, pin) {
  check(Buffer.isBuffer(bytes) && bytes.length <= MAX_ARCHIVE_BYTES && hash(bytes) === pin);
  const a = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  exact(a, ["schemaVersion", "files"]); check(a.schemaVersion === "roebel_case_upgrade_archive_v1");
  return validateCaseArchiveFiles(a.files);
}
function previousUpgrade(files, sourceClaim, expected, runtime) {
  const current = files.find(f => f.name === RECEIPT), pin = expected.previousUpgradeReceiptChecksum;
  if (!current) { check(pin === undefined); return null; }
  const validPin = value => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
  const historyName = value => { check(validPin(value)); return `case-runtime-upgrade-history-${value.slice(7)}.json`; };
  check(validPin(pin));
  let value = jsonOf(files, RECEIPT), wantedPin = pin, wantedClaim = sourceClaim;
  const seen = new Set();
  while (true) {
    check(!seen.has(wantedPin) && seen.size < 32); seen.add(wantedPin);
    const linked = value.schemaVersion === "roebel_case_runtime_upgrade_v2";
    exact(value, ["schemaVersion", "authorityBinding", "testOnly", "sourceClaim", "sourceSeal",
      "targetClaim", "targetSeal", "archiveSha256", "receiptChecksum", ...(linked ? ["previousUpgradeReceiptChecksum"] : [])]);
    const { receiptChecksum, ...body } = value;
    check((linked || value.schemaVersion === "roebel_case_runtime_upgrade_v1") &&
      receiptChecksum === wantedPin && sum(body) === wantedPin && validPin(value.archiveSha256) &&
      value.authorityBinding === "none" && value.testOnly === true);
    const from = runtime.verifyClaim(value.sourceClaim), to = runtime.verifyClaim(value.targetClaim);
    const fromSeal = runtime.verifySeal(value.sourceSeal), toSeal = runtime.verifySeal(value.targetSeal);
    check(same(to, wantedClaim) && fromSeal.deploymentClaimChecksum === from.claimChecksum &&
      toSeal.deploymentClaimChecksum === to.claimChecksum && fromSeal.sourceReleaseDigest === from.releaseDigest &&
      toSeal.sourceReleaseDigest === to.releaseDigest && from.releaseDigest !== to.releaseDigest &&
      fromSeal.municipalityId === from.municipalityId && toSeal.municipalityId === to.municipalityId);
    const stableSeal = seal => { const c = { ...seal }; delete c.sealChecksum;
      delete c.sourceReleaseDigest; delete c.deploymentClaimChecksum; return c; };
    check(same(stableSeal(fromSeal), stableSeal(toSeal)));
    if (!linked) break;
    wantedPin = value.previousUpgradeReceiptChecksum; wantedClaim = from;
    value = jsonOf(files, historyName(wantedPin));
  }
  const name = historyName(pin);
  check(!files.some(f => f.name === name));
  return { pin, retained: { ...current, name } };
}
function materialize(files, source, target, expected, runtime, archiveSha256) {
  const old = facts(files, source, expected, runtime), targetClaim = claim(target, runtime);
  const previous = previousUpgrade(files, old.claim, expected, runtime);
  const { sealChecksum: _, ...body } = old.seal;
  // This is an Operations materialization seal, with explicit source lineage;
  // no claim that the new runtime already served traffic or wrote a Case event.
  body.sourceReleaseDigest = target.releaseDigest; body.deploymentClaimChecksum = targetClaim.claimChecksum;
  const targetSeal = runtime.verifySeal({ ...body, sealChecksum: sum(body) });
  const receiptBody = { schemaVersion: previous ? "roebel_case_runtime_upgrade_v2" : "roebel_case_runtime_upgrade_v1", authorityBinding: "none", testOnly: true,
    sourceClaim: old.claim, sourceSeal: old.seal, targetClaim, targetSeal, archiveSha256 };
  if (previous) receiptBody.previousUpgradeReceiptChecksum = previous.pin;
  const receipt = { ...receiptBody, receiptChecksum: sum(receiptBody) };
  const replacements = [file(CLAIM, targetClaim), file(SEAL, targetSeal), file(target.storage.marker.fileName, marker(target)), file(RECEIPT, receipt)];
  // A subsequent upgrade must name its exact previous receipt and preserve
  // every receipt in that verified chain, including its original bytes.
  const replaced = new Map(replacements.map(f => [f.name, f]));
  const targetFiles = [...files.filter(f => !replaced.has(f.name)), ...replacements,
    ...(previous ? [previous.retained] : [])];
  targetFiles.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
  validateCaseArchiveFiles(targetFiles); facts(targetFiles, target, expected, runtime);
  return { targetFiles, receipt };
}

/** Read-only capture and independently restored full replay before any move. */
export function prepareCaseRuntimeUpgrade(input, runtime) {
  const { source, target } = bindings(input.sourceBinding, input.targetBinding, runtime);
  check(input.sourceRootDir === source.storage.rootDir && input.expected.caseId === input.expected.head.caseId &&
    Number.isSafeInteger(input.expected.head.caseVersion) && input.expected.head.caseVersion >= 3);
  const files = snapshotCaseFiles(input.sourceRootDir);
  const old = facts(files, source, input.expected, runtime);
  replay(files, input.configuration, old.seal, runtime);
  const archive = Buffer.from(canonical({ schemaVersion: "roebel_case_upgrade_archive_v1", files }) + "\n");
  check(archive.length <= MAX_ARCHIVE_BYTES);
  const archiveSha256 = hash(archive);
  const { targetFiles, receipt } = materialize(files, source, target, input.expected, runtime, archiveSha256);
  replay(targetFiles, input.configuration, receipt.targetSeal, runtime);
  check(same(snapshotCaseFiles(input.sourceRootDir), files));
  const body = { schemaVersion: "roebel_case_runtime_upgrade_plan_v1", sourceBinding: source, targetBinding: target,
    expected: input.expected, configurationChecksum: sum(input.configuration), archiveSha256,
    sourceFiles: manifest(files), targetFiles: manifest(targetFiles), materializationReceiptChecksum: receipt.receiptChecksum };
  return { archive, plan: { ...body, planChecksum: sum(body) } };
}

/** Two renames on one retained volume. A durable intent outside the moved
 * directories makes every interruption discoverable. Missing root fails the
 * existing filesystem preflight. Old/new claim mismatch still fails normally.
 * Recovery only moves forward after exact source/candidate/receipt checks.
 * No automatic rollback after the new runtime could have written an event.
 */
export function verifyCaseRuntimeUpgrade({ plan, archive, configuration }, runtime) {
  const { planChecksum, ...body } = plan;
  exact(body, ["schemaVersion", "sourceBinding", "targetBinding", "expected", "configurationChecksum", "archiveSha256", "sourceFiles", "targetFiles", "materializationReceiptChecksum"]);
  check(plan.schemaVersion === "roebel_case_runtime_upgrade_plan_v1" && sum(body) === planChecksum && sum(configuration) === plan.configurationChecksum);
  const { source, target } = bindings(plan.sourceBinding, plan.targetBinding, runtime);
  const files = parseArchive(archive, plan.archiveSha256);
  const { targetFiles, receipt } = materialize(files, source, target, plan.expected, runtime, plan.archiveSha256);
  check(same(manifest(files), plan.sourceFiles) && same(manifest(targetFiles), plan.targetFiles) && receipt.receiptChecksum === plan.materializationReceiptChecksum);
  replay(files, configuration, receipt.sourceSeal, runtime); replay(targetFiles, configuration, receipt.targetSeal, runtime);
  return { source, target, files, targetFiles, receipt };
}

export function activateCaseRuntimeUpgrade(input, runtime, { assertFenced, failpoint = () => {} }) {
  const { plan } = input, { planChecksum } = plan;
  const { source, files, targetFiles, receipt } = verifyCaseRuntimeUpgrade(input, runtime);
  const root = source.storage.rootDir, parent = dirname(root), tag = `${basename(root)}-upgrade-${planChecksum.slice(7)}`;
  // Parent can be a kubelet fsGroup mount; it must be non-symlinked, owned and
  // not world-writable. Individual roots and the journal remain private 0700.
  check(parent === realpathSync(parent)); const ps = lstatSync(parent);
  check(ps.isDirectory() && (ps.uid === process.getuid() || (ps.uid === 0 && ps.gid === process.getgid())) && !(ps.mode & 0o002));
  const journal = join(parent, tag), candidate = join(journal, "candidate"), retained = join(journal, "retained-source");
  const intentPath = join(journal, "intent.json"), resultPath = join(journal, "result.json");
  const assertFiles = (path, expectedFiles) => { check(privateDirectory(path).dev === ps.dev); check(same(snapshotCaseFiles(path), expectedFiles)); };
  const oldLocks = [], heldPaths = new Set();
  const hold = path => {
    if (heldPaths.has(path)) return;
    const db = new DatabaseSync(join(path, OWNER), { timeout: 0 }); oldLocks.push(db);
    db.exec("PRAGMA busy_timeout=0; BEGIN EXCLUSIVE");
    const row = db.prepare("SELECT municipality_id FROM durable_store_binding WHERE singleton=1").get();
    check(row?.municipality_id === source.municipalityId);
    heldPaths.add(path);
  };
  const fence = () => { check(assertFenced() === true); };
  try {
    fence();
    if (!exists(journal)) { assertFiles(root, files); mkdirPrivate(journal); syncDirectory(parent); }
    privateDirectory(journal);
    if (!exists(intentPath)) {
      check(!exists(candidate) && !exists(retained) && !exists(resultPath)); assertFiles(root, files);
      writeRecord(intentPath, plan);
    }
    check(privateBytes(intentPath, Buffer.byteLength(canonical(plan) + "\n")).toString("utf8") === canonical(plan) + "\n"); failpoint("intent");
    if (exists(resultPath)) {
      assertFiles(retained, files); assertFiles(root, targetFiles); check(!exists(candidate));
      check(privateBytes(resultPath, Buffer.byteLength(canonical(receipt) + "\n")).toString("utf8") === canonical(receipt) + "\n"); fence(); return receipt;
    }
    if (!exists(retained)) {
      assertFiles(root, files); hold(root); assertFiles(root, files);
      if (!exists(candidate)) { mkdirPrivate(candidate); syncDirectory(journal); }
      completeCandidate(candidate, targetFiles, failpoint);
      assertFiles(candidate, targetFiles); hold(candidate); failpoint("candidate"); fence();
      assertFiles(root, files); assertFiles(candidate, targetFiles);
      renameSync(root, retained); syncDirectory(journal); syncDirectory(parent); failpoint("source-retained");
    } else { assertFiles(retained, files); hold(retained); }
    if (!exists(root)) {
      assertFiles(candidate, targetFiles); hold(candidate);
      fence(); renameSync(candidate, root); syncDirectory(journal); syncDirectory(parent); failpoint("target-installed");
    } else { check(!exists(candidate)); assertFiles(root, targetFiles); }
    assertFiles(retained, files); assertFiles(root, targetFiles); fence();
    writeRecord(resultPath, receipt); failpoint("receipt");
    return receipt;
  } catch { throw new Error("case_runtime_upgrade_stopped"); }
  finally { for (const db of oldLocks) {
    try { db.exec("ROLLBACK"); } catch { /* failed lock acquisition has no transaction */ }
    try { db.close(); } catch { /* preserve the bounded operation error */ }
  } }
}
