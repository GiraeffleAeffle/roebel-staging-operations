/** Offline, descriptor-only bridge to the exact reviewed Stadtstack image.
 * Kubernetes fencing, provisioning and traffic handover belong to Operations.
 * This program never connects to a cluster, submits an adoption or binds HTTP.
 */
import { createHash } from "node:crypto";
import { constants, closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readSync, realpathSync, writeSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { captureSealedCase, captureNewlySealedCase, verifyRestoredCase, MAX_ARCHIVE_BYTES } from "./case_review_backup.mjs";

export const SOURCE_REVISION = "fdb0b7f36c33d925be141d8e9037b48d17612df8";
export const CONTROL_IMAGE_DIGEST = "sha256:5f0eeec46e1e00150ce5f370ba9749a0f4d6d652dac73839f25699771adb1d60";
const MAX_BYTES = 1_048_576;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const SOURCE_FIELDS = ["municipalityId", "policyVersion", "actorRegistry", "allowedSignerPubkeys", "allowedAgentPubkeys",
  "syntheticAdoption", "credentials", "admissionAllowedHosts", "outboxAllowedHosts", "probeAllowedHosts", "drainTimeoutMs"];
function fail() { throw new Error("case_review_migration_stopped"); }
function exact(value, fields) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype || Object.keys(value).length !== fields.length ||
    Object.keys(value).some((key) => !fields.includes(key))) fail();
  return value;
}
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  const encoded = JSON.stringify(value);
  if (encoded === undefined) fail();
  return encoded;
}
const digest = (bytes) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
function privateDescriptor(fd, { empty = false, maxBytes = MAX_BYTES } = {}) {
  if (!Number.isSafeInteger(fd) || fd < 3) fail();
  const stat = fstatSync(fd, { bigint: true });
  if (!stat.isFile() || stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o7777n) !== 0o600n || stat.nlink > 1n ||
    stat.size > BigInt(maxBytes) || (empty ? stat.size !== 0n : stat.size < 1n)) fail();
  return stat;
}
const identity = (stat) => `${stat.dev}:${stat.ino}`;
function pinnedBytes(fd, pin, maxBytes = MAX_BYTES) {
  if (typeof pin !== "string" || !SHA256.test(pin)) fail();
  const before = privateDescriptor(fd, { maxBytes });
  const bytes = Buffer.alloc(Number(before.size));
  let offset = 0;
  while (offset < bytes.length) {
    const size = readSync(fd, bytes, offset, bytes.length - offset, offset);
    if (size < 1) fail();
    offset += size;
  }
  const after = privateDescriptor(fd, { maxBytes });
  if (identity(before) !== identity(after) || before.size !== after.size || before.mtimeNs !== after.mtimeNs ||
    before.ctimeNs !== after.ctimeNs || readSync(fd, Buffer.alloc(1), 0, 1, bytes.length) !== 0 || digest(bytes) !== pin) fail();
  return bytes;
}
const pinnedJson = (fd, pin) => JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(pinnedBytes(fd, pin)));
function writePrivate(fd, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const written = writeSync(fd, bytes, offset, bytes.length - offset, offset);
    if (written < 1) fail();
    offset += written;
  }
  fsyncSync(fd);
}

function preparationFor(request, source, target, runtime) {
  exact(source, SOURCE_FIELDS);
  exact(target, [...SOURCE_FIELDS, "requiredDepartmentIds", "administrationReview"]);
  // The old admission identity, credential, signer policy and network settings
  // are preserved. Only the existing review extension may add actors/grants.
  for (const key of SOURCE_FIELDS.filter((field) => field !== "actorRegistry")) {
    if (canonical(source[key]) !== canonical(target[key])) fail();
  }
  exact(source.syntheticAdoption, ["policy", "acceptanceBaseUrl"]);
  if (!Array.isArray(source.actorRegistry) || !Array.isArray(target.actorRegistry) || !Array.isArray(target.requiredDepartmentIds) ||
    !Array.isArray(source.credentials)) fail();
  const ids = new Set();
  for (const actor of target.actorRegistry) {
    if (!actor || typeof actor.actorId !== "string" || ids.has(actor.actorId)) fail();
    ids.add(actor.actorId);
  }
  for (const actor of source.actorRegistry) {
    if (canonical(target.actorRegistry.find((item) => item.actorId === actor.actorId)) !== canonical(actor)) fail();
  }
  const review = exact(target.administrationReview, ["caseId", "grants", "allowedHosts"]);
  if (review.caseId !== request.caseId || !Array.isArray(review.grants) || !Array.isArray(review.allowedHosts) || !review.allowedHosts.length) fail();
  runtime.validateGrants({ deploymentEnvironment: "staging", grants: review.grants });
  for (const grant of review.grants) {
    if (grant.caseId !== request.caseId || !target.actorRegistry.some((actor) => actor.actorId === grant.actor.actorId && actor.actorClass === grant.actor.actorClass) ||
      source.credentials.some((credential) => credential.token === grant.token)) fail();
  }
  const one = (actorClass, departmentId) => {
    if (target.actorRegistry.filter((actor) => actor.actorClass === actorClass && actor.departmentId === departmentId).length !== 1) fail();
  };
  for (const role of ["case_steward", "administration", "public"]) one(role);
  for (const department of target.requiredDepartmentIds) { one("department_agent", department); one("department_reviewer", department); }
  const sourceIds = new Set(source.actorRegistry.map((actor) => actor.actorId));
  return {
    sourceRootDir: request.sourceRootDir, expectedSourceSealChecksum: request.sourceSealChecksum,
    expectedCaseId: request.caseId, expectedAdmissionReceiptChecksum: request.admissionReceiptChecksum,
    sourceConfig: {
      municipalityId: source.municipalityId, policyVersion: source.policyVersion, actorRegistry: source.actorRegistry,
      allowedSignerPubkeys: source.allowedSignerPubkeys, allowedAgentPubkeys: source.allowedAgentPubkeys,
      syntheticAdoption: { policy: source.syntheticAdoption.policy, now: () => new Date(),
        // Full historical replay needs the verification shape, never a new
        // acceptance lookup. A regression attempting one fails offline.
        acceptance: { resolve: async () => { fail(); } } },
    },
    additionalActors: target.actorRegistry.filter((actor) => !sourceIds.has(actor.actorId)),
    requiredDepartmentIds: target.requiredDepartmentIds,
  };
}

/** The injectable port is for tests; the CLI below fixes all runtime imports.
 * Private result descriptors are reserved before invoking any runtime effect.
 * An uncertain result requires a new output descriptor, never blind overwrite.
 */
export function runReviewMigration({ requestFd, expectedRequestSha256, sourceConfigFd, targetConfigFd, resultFd, archiveFd }, runtime) {
  try {
    const descriptors = [requestFd, sourceConfigFd, targetConfigFd, resultFd];
    const stats = descriptors.map((fd, index) => privateDescriptor(fd, { empty: index === 3 }));
    if (new Set(descriptors).size !== 4 || new Set(stats.map(identity)).size !== 4) fail();
    const readRequest = () => {
      const request = pinnedJson(requestFd, expectedRequestSha256);
      const fields = ["schemaVersion", "mode", "sourceRevision", "controlImageDigest", "sourceRootDir", "caseId", "sourceSealChecksum",
        "admissionReceiptChecksum", "sourceConfigurationSha256", "targetConfigurationSha256", "targetBinding"];
      if (request.mode === "capture-backup" && request.sourceSealChecksum === null) fields.push("sourceBindingChecksum");
      if (request.mode === "activate") fields.push("migrationPlan");
      if (["capture-backup", "verify-backup"].includes(request.mode)) fields.push("sourceDeploymentClaimChecksum");
      if (request.mode === "verify-backup") fields.push("archiveSha256");
      exact(request, fields);
      if (request.schemaVersion !== "roebel_case_review_migration_request_v1" || !["prepare", "activate", "capture-backup", "verify-backup"].includes(request.mode) ||
        request.sourceRevision !== SOURCE_REVISION || request.controlImageDigest !== CONTROL_IMAGE_DIGEST ||
        typeof request.sourceRootDir !== "string" || request.sourceRootDir !== resolve(request.sourceRootDir) ||
        typeof request.caseId !== "string" || !request.caseId.startsWith("urn:stadtstack:synthetic-case:municipality:") ||
        !(SHA256.test(request.sourceSealChecksum) || request.mode === "capture-backup" && request.sourceSealChecksum === null &&
          request.sourceDeploymentClaimChecksum === null && typeof request.sourceBindingChecksum === "string" && SHA256.test(request.sourceBindingChecksum)) || !SHA256.test(request.admissionReceiptChecksum) ||
        request.targetBinding?.schemaVersion !== "staging_case_control_deployment_binding_v2" ||
        request.targetBinding.releaseDigest !== CONTROL_IMAGE_DIGEST || !SHA256.test(request.targetBinding.bindingChecksum)) fail();
      return request;
    };
    const request = readRequest();
    const backup = ["capture-backup", "verify-backup"].includes(request.mode);
    let archiveStat, archiveWritten = false, capturedArchiveSha256;
    if (backup) {
      if (!(request.mode === "capture-backup" && request.sourceSealChecksum === null) &&
        (typeof request.sourceDeploymentClaimChecksum !== "string" || !SHA256.test(request.sourceDeploymentClaimChecksum))) fail();
      archiveStat = privateDescriptor(archiveFd, { empty: request.mode === "capture-backup", maxBytes: MAX_ARCHIVE_BYTES });
      if (descriptors.includes(archiveFd) || stats.some((stat) => identity(stat) === identity(archiveStat))) fail();
    } else if (archiveFd !== undefined) fail();
    const readConfigurations = () => {
      const source = pinnedJson(sourceConfigFd, request.sourceConfigurationSha256);
      const target = pinnedJson(targetConfigFd, request.targetConfigurationSha256);
      return preparationFor(request, source, target, runtime);
    };
    const preparation = readConfigurations();
    const fresh = () => {
      readRequest();
      // Each full JSON document is independently byte-pinned. Revalidate those
      // bytes, not the reconstructed verifier functions or their serialization.
      readConfigurations();
      // Input and output handles must still refer to the reserved private files.
      descriptors.forEach((fd, index) => {
        if (identity(privateDescriptor(fd, { empty: index === 3 })) !== identity(stats[index])) fail();
      });
      if (backup && identity(privateDescriptor(archiveFd, { empty: request.mode === "capture-backup" && !archiveWritten,
        maxBytes: MAX_ARCHIVE_BYTES })) !== identity(archiveStat)) fail();
      if (archiveWritten) pinnedBytes(archiveFd, capturedArchiveSha256, MAX_ARCHIVE_BYTES);
    };
    fresh();
    let result;
    if (request.mode === "capture-backup") {
      const captured = request.sourceSealChecksum === null
        ? captureNewlySealedCase(preparation, request.sourceBindingChecksum, runtime.verifySeal)
        : captureSealedCase(preparation, request.sourceDeploymentClaimChecksum, runtime.verifySeal);
      fresh();
      writePrivate(archiveFd, captured.bytes);
      capturedArchiveSha256 = captured.archiveSha256; archiveWritten = true;
      result = { ...captured.evidence, archiveSha256: captured.archiveSha256 };
    } else if (request.mode === "verify-backup") {
      result = verifyRestoredCase(pinnedBytes(archiveFd, request.archiveSha256, MAX_ARCHIVE_BYTES), request.archiveSha256,
        preparation, request.sourceDeploymentClaimChecksum, runtime);
    } else result = request.mode === "prepare" ? runtime.prepare(preparation) : runtime.activate({
      preparation,
      reviewedBindingSource: { read: () => { fresh(); return readRequest().targetBinding; } },
      bindingPinSource: { read: () => { fresh(); return request.targetBinding.bindingChecksum; } },
      migration: {
        reviewedMigrationSource: { read: () => { fresh(); return readRequest().migrationPlan; } },
        migrationPinSource: { read: () => { fresh(); return request.migrationPlan.planChecksum; } },
        clock: { now: () => { fresh(); return new Date().toISOString(); } },
      },
    });
    fresh();
    const body = { schemaVersion: "roebel_case_review_migration_result_v1", mode: request.mode,
      requestSha256: expectedRequestSha256, sourceRevision: SOURCE_REVISION, controlImageDigest: CONTROL_IMAGE_DIGEST,
      sourceConfigurationSha256: request.sourceConfigurationSha256, targetConfigurationSha256: request.targetConfigurationSha256, result };
    const bytes = Buffer.from(`${canonical({ ...body, resultSha256: digest(canonical(body)) })}\n`);
    if (bytes.length > MAX_BYTES) fail();
    writePrivate(resultFd, bytes);
    return { status: { prepare: "candidate-prepared", activate: "target-sealed", "capture-backup": "private-archive-captured",
      "verify-backup": "restored-case-verified" }[request.mode], resultSha256: digest(canonical(body)) };
  } catch { fail(); }
}

/** Fixed worker mailbox. The caller must still verify live fencing, Pod/image
 * identity and ordered parent receipts before invoking any effect. A reserved
 * invocation is never executed twice, even when its result is missing. */
function workerRoot(root) {
  if (typeof root !== "string" || realpathSync(root) !== root) fail();
  const stat = lstatSync(root);
  if (!stat.isDirectory() || stat.uid !== process.getuid() || (stat.mode & 0o7777) !== 0o700) fail();
}
function pinName(pin) { if (typeof pin !== "string" || !SHA256.test(pin)) fail(); return pin.slice(7); }
function openPrivate(path, create = false) {
  return openSync(path, (create ? constants.O_CREAT | constants.O_EXCL | constants.O_RDWR : constants.O_RDONLY) | constants.O_NOFOLLOW, 0o600);
}
function syncDirectory(path) { const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW); try { fsyncSync(fd); } finally { closeSync(fd); } }
function storePrivate(path, bytes) { const fd = openPrivate(path, true); try { writePrivate(fd, bytes); } finally { closeSync(fd); } }

export function uploadWorkerArchive(root, pin, bytes) {
  try {
    workerRoot(root); pinName(pin);
    if (!Buffer.isBuffer(bytes) || !bytes.length || bytes.length > MAX_ARCHIVE_BYTES || digest(bytes) !== pin) fail();
    storePrivate(`${root}/archive-${pinName(pin)}`, bytes); syncDirectory(root);
    return { status: "private-archive-stored", archiveSha256: pin };
  } catch { fail(); }
}

export function verifyWorkerArchive(root, pin) {
  let fd;
  try {
    workerRoot(root); fd = openPrivate(`${root}/archive-${pinName(pin)}`);
    pinnedBytes(fd, pin, MAX_ARCHIVE_BYTES);
    return { status: "private-archive-stored", archiveSha256: pin };
  } catch { fail(); }
  finally { if (fd !== undefined) closeSync(fd); }
}

export function invokeWorkerRequest(root, requestBytes, expectedRequestSha256, runtime) {
  const opened = [];
  try {
    workerRoot(root); const name = pinName(expectedRequestSha256);
    if (!Buffer.isBuffer(requestBytes) || !requestBytes.length || requestBytes.length > MAX_BYTES || digest(requestBytes) !== expectedRequestSha256) fail();
    const request = JSON.parse(new TextDecoder("utf-8", {fatal:true}).decode(requestBytes));
    if (!["prepare", "activate", "capture-backup", "verify-backup"].includes(request.mode)) fail();
    // This durable reservation remains on all failures. Never unlink or reuse it.
    const invocation = `${root}/request-${name}`;
    mkdirSync(invocation, {mode:0o700}); syncDirectory(root);
    storePrivate(`${invocation}/request.json`, requestBytes);
    const open = (path, create = false) => { const fd = openPrivate(path, create); opened.push(fd); return fd; };
    const args = { requestFd: open(`${invocation}/request.json`), expectedRequestSha256,
      sourceConfigFd: open(`${root}/source.json`), targetConfigFd: open(`${root}/target.json`), resultFd: open(`${invocation}/result.json`, true) };
    if (request.mode === "capture-backup") args.archiveFd = open(`${invocation}/archive`, true);
    if (request.mode === "verify-backup") args.archiveFd = open(`${root}/archive-${pinName(request.archiveSha256)}`);
    syncDirectory(invocation);
    const result = runReviewMigration(args, runtime);
    syncDirectory(invocation);
    return result;
  } catch { fail(); }
  finally { for (const fd of opened) closeSync(fd); }
}

export function readWorkerOutput(root, requestPin, kind = "result") {
  const opened = [];
  try {
    workerRoot(root); const invocation = `${root}/request-${pinName(requestPin)}`; workerRoot(invocation);
    if (!["result", "archive"].includes(kind)) fail();
    const open = path => { const fd = openPrivate(path); opened.push(fd); return fd; };
    const request = pinnedJson(open(`${invocation}/request.json`), requestPin);
    const resultFd = open(`${invocation}/result.json`), stat = privateDescriptor(resultFd);
    const bytes = Buffer.alloc(Number(stat.size));
    let offset = 0;
    while(offset < bytes.length) { const n=readSync(resultFd,bytes,offset,bytes.length-offset,offset); if(n<1)fail(); offset+=n; }
    const result = JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes));
    const {resultSha256, ...body} = result;
    if (resultSha256 !== digest(canonical(body)) || body.schemaVersion !== "roebel_case_review_migration_result_v1" ||
      body.requestSha256 !== requestPin || body.mode !== request.mode || body.sourceRevision !== SOURCE_REVISION ||
      body.controlImageDigest !== CONTROL_IMAGE_DIGEST || body.sourceConfigurationSha256 !== request.sourceConfigurationSha256 ||
      body.targetConfigurationSha256 !== request.targetConfigurationSha256) fail();
    // Re-read and pin complete bytes, including inode metadata, before export.
    const verified = pinnedBytes(resultFd, digest(bytes));
    if (kind === "result") return verified;
    if (request.mode !== "capture-backup") fail();
    return pinnedBytes(open(`${invocation}/archive`), body.result.archiveSha256, MAX_ARCHIVE_BYTES);
  } catch { fail(); }
  finally { for (const fd of opened) closeSync(fd); }
}

async function boundedInput(limit) {
  const chunks = []; let length = 0;
  for await (const chunk of process.stdin) { length += chunk.length; if(length > limit)fail(); chunks.push(chunk); }
  if (!length) fail(); return Buffer.concat(chunks, length);
}

function parseArguments(args) {
  const names = ["request-fd", "expected-request-sha256", "source-config-fd", "target-config-fd", "result-fd", "archive-fd"];
  if (![10, 12].includes(args.length)) fail();
  const found = new Map();
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index].slice(2), value = args[index + 1];
    if (!args[index].startsWith("--") || !names.includes(name) || found.has(name)) fail();
    if (name !== "expected-request-sha256" && !/^[1-9][0-9]*$/.test(value)) fail();
    found.set(name, name === "expected-request-sha256" ? value : Number(value));
  }
  if (names.slice(0, 5).some((name) => !found.has(name))) fail();
  return { requestFd: found.get("request-fd"), expectedRequestSha256: found.get("expected-request-sha256"),
    sourceConfigFd: found.get("source-config-fd"), targetConfigFd: found.get("target-config-fd"), resultFd: found.get("result-fd"), archiveFd: found.get("archive-fd") };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.env.NODE_OPTIONS || process.env.NODE_PATH || Object.keys(process.env).some((name) => name.startsWith("STADTSTACK_CASE_"))) fail();
    const cli = process.argv.slice(2);
    const worker = cli.length === 4 && cli[2] === "--expected-worker-uid" && ["--worker-invoke", "--worker-result", "--worker-archive", "--worker-upload-archive", "--worker-verify-archive"].includes(cli[0]);
    if (worker) {
      pinName(cli[1]);
      if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(cli[3]) ||
        process.env.ROEBEL_REVIEW_WORKER_UID !== cli[3]) fail();
    }
    if (worker && ["--worker-result", "--worker-archive"].includes(cli[0])) {
      process.stdout.write(readWorkerOutput("/work/private", cli[1], cli[0] === "--worker-result" ? "result" : "archive"));
    } else if (worker && cli[0] === "--worker-verify-archive") {
      process.stdout.write(`${JSON.stringify(verifyWorkerArchive("/work/private", cli[1]))}\n`);
    } else if (worker && cli[0] === "--worker-upload-archive") {
      process.stdout.write(`${JSON.stringify(uploadWorkerArchive("/work/private", cli[1], await boundedInput(MAX_ARCHIVE_BYTES)))}\n`);
    } else {
      const args = worker ? null : parseArguments(cli);
      const adapter = await import("file:///runtime/src/adapters/sqlite-atomic-topic-case-admission.ts");
      const control = await import("file:///runtime/src/staging-case-control-runtime.ts");
      const authentication = await import("file:///runtime/src/staging-administration-authenticator.ts");
      const seal = await import("file:///runtime/src/case-shutdown-seal.ts");
      const runtime = {
        prepare: adapter.prepareSyntheticDepartmentReviewMigration,
        activate: control.activateOperationsBoundSyntheticReviewMigration,
        validateGrants: authentication.createStagingAdministrationAuthenticator,
        verifySeal: seal.verifyCaseShutdownSeal,
      };
      const result = worker ? invokeWorkerRequest("/work/private", await boundedInput(MAX_BYTES), cli[1], runtime) : runReviewMigration(args, runtime);
      process.stdout.write(`${JSON.stringify(result)}\n`);
    }
  } catch {
    process.stderr.write("Case review migration stopped; preserve source, target and private receipts.\n");
    process.exitCode = 78;
  }
}
