import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { closeSync, fchmodSync, ftruncateSync, linkSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { canonical, CONTROL_IMAGE_DIGEST, runReviewMigration, SOURCE_REVISION } from "./run-case-review-migration.mjs";

export const hash = (bytes) => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
export const departments = ["planning", "traffic", "environment", "finance", "legal", "public-order", "social-affairs", "public-works"];
export const caseId = "urn:stadtstack:synthetic-case:municipality:roebel-mueritz:00000000-0000-4000-8000-000000000001";
export function configurations() {
  const steward = { actorId: "example:steward", actorClass: "case_steward" };
  const source = { municipalityId: "roebel-mueritz", policyVersion: "fixture", actorRegistry: [steward],
    allowedSignerPubkeys: [], allowedAgentPubkeys: [], syntheticAdoption: { policy: {}, acceptanceBaseUrl: "https://example.invalid/acceptance" },
    credentials: [{ token: Buffer.alloc(32, 1).toString("base64url"), principal: { ...steward, municipalityIds: ["roebel-mueritz"] } }],
    admissionAllowedHosts: ["127.0.0.1"], outboxAllowedHosts: ["127.0.0.1"], probeAllowedHosts: ["127.0.0.1"], drainTimeoutMs: 500 };
  const target = structuredClone(source);
  target.actorRegistry.push({ actorId: "example:administration", actorClass: "administration" }, { actorId: "example:public", actorClass: "public" },
    ...departments.flatMap((departmentId) => ["department_agent", "department_reviewer"].map((actorClass) => ({ actorId: `example:${departmentId}:${actorClass}`, actorClass, departmentId }))));
  target.requiredDepartmentIds = departments;
  target.administrationReview = { caseId, allowedHosts: ["127.0.0.1"], grants: [{ token: Buffer.alloc(32, 2).toString("base64url"), caseId,
    actor: steward, notBefore: 0, expiresAt: 9_000_000_000_000 }] };
  return { source, target };
}
export function files(t, { mode = "prepare", source, target, request: override = {} } = {}) {
  const root = mkdtempSync(join(tmpdir(), "case-review-descriptors-"));
  const descriptors = [];
  t.after(() => { descriptors.forEach(closeSync); rmSync(root, { recursive: true, force: true }); });
  const fd = (name, bytes) => {
    const path = join(root, name); writeFileSync(path, bytes, { mode: 0o600 });
    const value = openSync(path, "r+"); descriptors.push(value); return value;
  };
  const defaults = configurations(); source ??= defaults.source; target ??= defaults.target;
  const sourceBytes = canonical(source), targetBytes = canonical(target);
  const request = { schemaVersion: "roebel_case_review_migration_request_v1", mode, sourceRevision: SOURCE_REVISION,
    controlImageDigest: CONTROL_IMAGE_DIGEST, sourceRootDir: root, caseId,
    sourceSealChecksum: hash("seal"), admissionReceiptChecksum: hash("admission"),
    sourceConfigurationSha256: hash(sourceBytes), targetConfigurationSha256: hash(targetBytes),
    targetBinding: { schemaVersion: "staging_case_control_deployment_binding_v2", releaseDigest: CONTROL_IMAGE_DIGEST, bindingChecksum: hash("binding") },
    ...(mode === "activate" ? { migrationPlan: { planChecksum: hash("plan") } } : {}), ...override };
  const requestBytes = canonical(request);
  const args = { requestFd: fd("request", requestBytes), expectedRequestSha256: hash(requestBytes), sourceConfigFd: fd("source", sourceBytes),
    targetConfigFd: fd("target", targetBytes), resultFd: fd("result", "") };
  return { root, args, request, source, target, result: () => JSON.parse(readFileSync(join(root, "result"), "utf8")),
    replace: (name, value) => writeFileSync(join(root, name), typeof value === "string" ? value : canonical(value)) };
}
const fakeRuntime = (effects = []) => ({ validateGrants: () => {}, prepare: (input) => { effects.push(input); return { candidateRootDir: "/private/example", receipt: { candidateChecksum: hash("candidate") } }; },
  activate: (input) => { effects.push(input); input.reviewedBindingSource.read(); input.bindingPinSource.read(); input.migration.reviewedMigrationSource.read();
    input.migration.migrationPinSource.read(); input.migration.clock.now(); return { activationChecksum: hash("activation") }; } });
const stopped = (run) => assert.throws(run, { message: "case_review_migration_stopped" });

test("prepare and activate persist linked private receipts; public result contains no configuration or paths", (t) => {
  for (const mode of ["prepare", "activate"]) {
    const h = files(t, { mode }), effects = [];
    const result = runReviewMigration(h.args, fakeRuntime(effects));
    const { resultSha256, ...body } = h.result();
    assert.equal(resultSha256, hash(canonical(body)));
    assert.equal(body.requestSha256, h.args.expectedRequestSha256);
    assert.equal(effects.length, 1);
    assert.deepEqual(Object.keys(result).sort(), ["resultSha256", "status"]);
    assert.equal(result.status, mode === "prepare" ? "candidate-prepared" : "target-sealed");
    for (const token of [h.source.credentials[0].token, h.target.administrationReview.grants[0].token]) assert.equal(canonical(h.result()).includes(token), false);
    const before = readFileSync(join(h.root, "result"));
    stopped(() => runReviewMigration(h.args, fakeRuntime(effects)));
    assert.equal(effects.length, 1); assert.deepEqual(readFileSync(join(h.root, "result")), before);
  }
});

test("wrong byte pins and changed source policy stop before runtime effects", (t) => {
  const h = files(t), effects = [];
  for (const name of ["request", "source", "target"]) {
    const before = readFileSync(join(h.root, name)); h.replace(name, `${before}\n`);
    stopped(() => runReviewMigration(h.args, fakeRuntime(effects))); writeFileSync(join(h.root, name), before);
  }
  assert.equal(effects.length, 0);
  const { source, target } = configurations(); target.policyVersion = "replacement-policy";
  const changed = files(t, { source, target }); stopped(() => runReviewMigration(changed.args, fakeRuntime(effects)));
  assert.equal(effects.length, 0);
});

test("private descriptor ownership shape, aliases, hardlinks and nonempty result fail before effects", (t) => {
  for (const fault of ["mode", "alias", "hardlink", "nonempty", "large", "standard-stream"]) {
    const h = files(t), effects = [];
    if (fault === "mode") fchmodSync(h.args.sourceConfigFd, 0o640);
    if (fault === "alias") h.args.resultFd = h.args.requestFd;
    if (fault === "hardlink") linkSync(join(h.root, "source"), join(h.root, "source-copy"));
    if (fault === "nonempty") h.replace("result", "retained-result");
    if (fault === "large") ftruncateSync(h.args.sourceConfigFd, 1_048_577);
    if (fault === "standard-stream") h.args.sourceConfigFd = 0;
    stopped(() => runReviewMigration(h.args, fakeRuntime(effects))); assert.equal(effects.length, 0, fault);
  }
});

test("replacement roles, wrong Case grants and admission-token reuse are refused", (t) => {
  for (const fault of ["steward", "reviewer", "case", "token"]) {
    const { source, target } = configurations();
    if (fault === "steward") target.actorRegistry[0].actorId = "example:replacement";
    if (fault === "reviewer") target.actorRegistry = target.actorRegistry.filter((actor) => actor.actorId !== "example:planning:department_reviewer");
    if (fault === "case") target.administrationReview.grants[0].caseId = "another-case";
    if (fault === "token") target.administrationReview.grants[0].token = source.credentials[0].token;
    const h = files(t, { source, target }), effects = [];
    stopped(() => runReviewMigration(h.args, fakeRuntime(effects))); assert.equal(effects.length, 0, fault);
  }
});

test("changed request and configurations are rechecked at activation authority reads", (t) => {
  for (const name of ["request", "source", "target"]) {
    const h = files(t, { mode: "activate" }), runtime = fakeRuntime();
    runtime.activate = (input) => {
      h.replace(name, `${readFileSync(join(h.root, name))}\n`);
      input.migration.clock.now(); assert.fail("changed private input was accepted");
    };
    stopped(() => runReviewMigration(h.args, runtime)); assert.equal(readFileSync(join(h.root, "result")).length, 0);
  }
});

test("runtime failures and accidental acceptance lookup expose only a fixed error", async (t) => {
  const h = files(t), runtime = fakeRuntime();
  runtime.prepare = () => { throw new Error(h.source.credentials[0].token); };
  stopped(() => runReviewMigration(h.args, runtime));
  let preparation;
  runtime.prepare = (input) => { preparation = input; return { candidate: true }; };
  runReviewMigration(h.args, runtime);
  await assert.rejects(preparation.sourceConfig.syntheticAdoption.acceptance.resolve(), { message: "case_review_migration_stopped" });
});
