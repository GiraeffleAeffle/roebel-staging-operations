/** Offline, descriptor-only bridge to the exact reviewed Stadtstack image.
 * Kubernetes fencing, provisioning and traffic handover belong to Operations.
 * This program never connects to a cluster, submits an adoption or binds HTTP.
 */
import { createHash } from "node:crypto";
import { fstatSync, fsyncSync, readSync, writeSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

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
function privateDescriptor(fd, { empty = false } = {}) {
  if (!Number.isSafeInteger(fd) || fd < 3) fail();
  const stat = fstatSync(fd, { bigint: true });
  if (!stat.isFile() || stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o7777n) !== 0o600n || stat.nlink > 1n ||
    stat.size > BigInt(MAX_BYTES) || (empty ? stat.size !== 0n : stat.size < 1n)) fail();
  return stat;
}
const identity = (stat) => `${stat.dev}:${stat.ino}`;
function pinnedJson(fd, pin) {
  if (typeof pin !== "string" || !SHA256.test(pin)) fail();
  const before = privateDescriptor(fd);
  const bytes = Buffer.alloc(Number(before.size));
  let offset = 0;
  while (offset < bytes.length) {
    const size = readSync(fd, bytes, offset, bytes.length - offset, offset);
    if (size < 1) fail();
    offset += size;
  }
  const after = privateDescriptor(fd);
  if (identity(before) !== identity(after) || before.size !== after.size || before.mtimeNs !== after.mtimeNs ||
    before.ctimeNs !== after.ctimeNs || readSync(fd, Buffer.alloc(1), 0, 1, bytes.length) !== 0 || digest(bytes) !== pin) fail();
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
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
export function runReviewMigration({ requestFd, expectedRequestSha256, sourceConfigFd, targetConfigFd, resultFd }, runtime) {
  try {
    const descriptors = [requestFd, sourceConfigFd, targetConfigFd, resultFd];
    const stats = descriptors.map((fd, index) => privateDescriptor(fd, { empty: index === 3 }));
    if (new Set(descriptors).size !== 4 || new Set(stats.map(identity)).size !== 4) fail();
    const readRequest = () => {
      const request = pinnedJson(requestFd, expectedRequestSha256);
      const fields = ["schemaVersion", "mode", "sourceRevision", "controlImageDigest", "sourceRootDir", "caseId", "sourceSealChecksum",
        "admissionReceiptChecksum", "sourceConfigurationSha256", "targetConfigurationSha256", "targetBinding"];
      if (request.mode === "activate") fields.push("migrationPlan");
      exact(request, fields);
      if (request.schemaVersion !== "roebel_case_review_migration_request_v1" || !["prepare", "activate"].includes(request.mode) ||
        request.sourceRevision !== SOURCE_REVISION || request.controlImageDigest !== CONTROL_IMAGE_DIGEST ||
        typeof request.sourceRootDir !== "string" || request.sourceRootDir !== resolve(request.sourceRootDir) ||
        typeof request.caseId !== "string" || !request.caseId.startsWith("urn:stadtstack:synthetic-case:municipality:") ||
        !SHA256.test(request.sourceSealChecksum) || !SHA256.test(request.admissionReceiptChecksum) ||
        request.targetBinding?.schemaVersion !== "staging_case_control_deployment_binding_v2" ||
        request.targetBinding.releaseDigest !== CONTROL_IMAGE_DIGEST || !SHA256.test(request.targetBinding.bindingChecksum)) fail();
      return request;
    };
    const request = readRequest();
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
    };
    fresh();
    const result = request.mode === "prepare" ? runtime.prepare(preparation) : runtime.activate({
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
    let offset = 0;
    while (offset < bytes.length) {
      const written = writeSync(resultFd, bytes, offset, bytes.length - offset, offset);
      if (written < 1) fail();
      offset += written;
    }
    fsyncSync(resultFd);
    return { status: request.mode === "prepare" ? "candidate-prepared" : "target-sealed", resultSha256: digest(canonical(body)) };
  } catch { fail(); }
}

function parseArguments(args) {
  const names = ["request-fd", "expected-request-sha256", "source-config-fd", "target-config-fd", "result-fd"];
  if (args.length !== names.length * 2) fail();
  const found = new Map();
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index].slice(2), value = args[index + 1];
    if (!args[index].startsWith("--") || !names.includes(name) || found.has(name)) fail();
    if (name !== "expected-request-sha256" && !/^[1-9][0-9]*$/.test(value)) fail();
    found.set(name, name === "expected-request-sha256" ? value : Number(value));
  }
  return { requestFd: found.get("request-fd"), expectedRequestSha256: found.get("expected-request-sha256"),
    sourceConfigFd: found.get("source-config-fd"), targetConfigFd: found.get("target-config-fd"), resultFd: found.get("result-fd") };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.env.NODE_OPTIONS || process.env.NODE_PATH || Object.keys(process.env).some((name) => name.startsWith("STADTSTACK_CASE_"))) fail();
    const args = parseArguments(process.argv.slice(2));
    const adapter = await import("file:///runtime/src/adapters/sqlite-atomic-topic-case-admission.ts");
    const control = await import("file:///runtime/src/staging-case-control-runtime.ts");
    const authentication = await import("file:///runtime/src/staging-administration-authenticator.ts");
    process.stdout.write(`${JSON.stringify(runReviewMigration(args, {
      prepare: adapter.prepareSyntheticDepartmentReviewMigration,
      activate: control.activateOperationsBoundSyntheticReviewMigration,
      validateGrants: authentication.createStagingAdministrationAuthenticator,
    }))}\n`);
  } catch {
    process.stderr.write("Case review migration stopped; preserve source, target and private receipts.\n");
    process.exitCode = 78;
  }
}
