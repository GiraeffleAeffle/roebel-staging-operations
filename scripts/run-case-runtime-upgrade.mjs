/** Fixed-image, private-file worker entry point. It never reads Kubernetes or
 * exports the archive on stdout. The Operations host supplies a fresh fence
 * observation and an archive recovered from the encrypted backup.
 */
import { constants, closeSync, fsyncSync, lstatSync, openSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { canonical, hash, prepareCaseRuntimeUpgrade, verifyCaseRuntimeUpgrade, activateCaseRuntimeUpgrade } from "./case_runtime_upgrade.mjs";
import { loadCaseUpgradeRuntime } from "./case_upgrade_runtime.mjs";

export const UPGRADE_IMAGE = "ghcr.io/giraeffleaeffle/stadtstack-case-steward-control@sha256:267025b3592a02123063c7f744644a4b681914d93c3a1db1dc7b2c441bd20cad";
const MAX = 64 * 1024 * 1024;
const check = x => { if (!x) throw new Error("case_upgrade_worker_stopped"); };
function read(path, limit = 1_048_576) {
  const s = lstatSync(path); check(s.isFile() && s.nlink === 1 && s.uid === process.getuid() && (s.mode & 0o7777) === 0o600 && s.size > 0 && s.size <= limit);
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { const b = readFileSync(fd); check(b.length === s.size); return b; } finally { closeSync(fd); }
}
function save(path, value) {
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { writeFileSync(fd, Buffer.isBuffer(value) ? value : canonical(value) + "\n"); fsyncSync(fd); } finally { closeSync(fd); }
  const directory = openSync(dirname(path), "r"); try { fsyncSync(directory); } finally { closeSync(directory); }
}
function directory(path) {
  check(realpathSync(path) === path); const s = lstatSync(path);
  check(s.isDirectory() && s.uid === process.getuid() && (s.mode & 0o7777) === 0o700);
}
const pin = value => { check(/^sha256:[0-9a-f]{64}$/.test(value)); return value.slice(7); };
function same(a, b) { check(canonical(a) === canonical(b)); }

export function invokeCaseUpgradeWorker(root, requestPin, runtime, policy, assertFenced) {
  try {
    directory(root); pin(requestPin);
    const requestBytes = read(join(root, `request-${pin(requestPin)}.json`)); check(hash(requestBytes) === requestPin);
    const request = JSON.parse(requestBytes), configurationBytes = read(join(root, "configuration.json"));
    check(hash(configurationBytes) === policy.configurationSha256);
    const configuration = JSON.parse(configurationBytes), mode = request.mode;
    check(request.schemaVersion === "roebel_case_upgrade_worker_request_v1" && ["prepare", "verify", "activate"].includes(mode));
    same(Object.keys(request).sort(), (mode === "prepare" ? ["schemaVersion", "mode", "policyChecksum"] : ["schemaVersion", "mode", "policyChecksum", "planChecksum", "archiveSha256"]).sort());
    same(request.policyChecksum, hash(canonical(policy)));
    const output = join(root, `result-${pin(requestPin)}.json`);
    // Existing output is evidence to inspect, never a reason to execute twice.
    try { lstatSync(output); throw new Error("case_upgrade_worker_result_exists"); }
    catch (error) { if (error.code !== "ENOENT") throw error; }
    check(assertFenced() === true);
    let result;
    if (mode === "prepare") {
      const prepared = prepareCaseRuntimeUpgrade({ sourceRootDir: policy.sourceBinding.storage.rootDir,
        sourceBinding: policy.sourceBinding, targetBinding: policy.targetBinding, expected: policy.expected, configuration }, runtime);
      save(join(root, `archive-${pin(prepared.plan.archiveSha256)}.json`), prepared.archive);
      save(join(root, `plan-${pin(prepared.plan.planChecksum)}.json`), prepared.plan);
      result = { planChecksum: prepared.plan.planChecksum, archiveSha256: prepared.plan.archiveSha256 };
    } else {
      pin(request.planChecksum); pin(request.archiveSha256);
      const plan = JSON.parse(read(join(root, `plan-${pin(request.planChecksum)}.json`))),
        archive = read(join(root, `restored-${pin(request.archiveSha256)}.json`), MAX);
      same(plan.planChecksum, request.planChecksum); same(plan.archiveSha256, request.archiveSha256);
      same(plan.sourceBinding, policy.sourceBinding); same(plan.targetBinding, policy.targetBinding); same(plan.expected, policy.expected);
      const input = { plan, archive, configuration };
      const verifiedPath = join(root, `verified-${pin(plan.planChecksum)}.json`);
      const verified = { planChecksum: plan.planChecksum, archiveSha256: hash(archive), targetBindingChecksum: policy.targetBinding.bindingChecksum };
      if (mode === "verify") {
        verifyCaseRuntimeUpgrade(input, runtime); check(assertFenced() === true); save(verifiedPath, verified); result = verified;
      } else {
        same(JSON.parse(read(verifiedPath)), verified);
        const receipt = activateCaseRuntimeUpgrade(input, runtime, { assertFenced });
        result = { ...verified, materializationReceiptChecksum: receipt.receiptChecksum, caseVersion: receipt.targetSeal.recoveryEvidence.orderedHeads[0].caseVersion };
      }
    }
    const body = { schemaVersion: "roebel_case_upgrade_worker_result_v1", requestChecksum: requestPin, mode, image: UPGRADE_IMAGE, result };
    const response = { ...body, resultChecksum: hash(canonical(body)) }; save(output, response); return response;
  } catch { throw new Error("case_upgrade_worker_stopped"); }
}

/** Fresh receipt is created by the host from observed zero writers, a suspended
 * reconciler and this sole RWOP worker. It grants no runtime roles. */
export function verifyCaseUpgradeFence(value, { policyChecksum, workerUid }, now = Date.now()) {
  const { fenceChecksum, ...body } = value;
  check(fenceChecksum === hash(canonical(body)));
  same(Object.keys(body).sort(), ["schemaVersion", "policyChecksum", "workerUid", "observedAtUtc", "sourceDeploymentUid", "sourceReplicas", "sourcePodUids", "reconcilerSuspended", "pvcUid", "pvcConsumerUids"].sort());
  const observed = Date.parse(value.observedAtUtc);
  check(value.schemaVersion === "roebel_case_upgrade_fence_v1" && value.policyChecksum === policyChecksum && value.workerUid === workerUid &&
    /^[a-f0-9-]{36}$/.test(workerUid) && Number.isFinite(observed) && observed <= now && now - observed <= 60_000 &&
    value.sourceDeploymentUid === "89c06a66-9e48-43fa-9206-1bd2cd203cf8" && value.sourceReplicas === 0 &&
    value.reconcilerSuspended === true && value.pvcUid === "8c07f2d4-b767-4bdc-b386-b03b811e33e2");
  same(value.sourcePodUids, []); same(value.pvcConsumerUids, [workerUid]); return true;
}

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(resolve(process.argv[1]))).href) {
  try {
    check(process.argv.length === 4 && process.argv[2] === "--request-sha256" && process.getuid() === 1000 &&
      !process.env.NODE_OPTIONS && !process.env.NODE_PATH);
    const policy = JSON.parse(readFileSync("/reviewed/upgrade-policy.json")), policyChecksum = hash(canonical(policy));
    const workerUid = process.env.ROEBEL_UPGRADE_WORKER_UID;
    const fenced = () => verifyCaseUpgradeFence(JSON.parse(read("/work/private/fence.json")), { policyChecksum, workerUid });
    const result = invokeCaseUpgradeWorker("/work/private", process.argv[3], await loadCaseUpgradeRuntime("/runtime"), policy, fenced);
    process.stdout.write(JSON.stringify({ mode: result.mode, resultChecksum: result.resultChecksum }) + "\n");
  } catch { process.stderr.write("Case upgrade stopped; preserve the retained source, worker and private receipts.\n"); process.exitCode = 78; }
}
