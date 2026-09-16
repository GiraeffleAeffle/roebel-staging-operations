/** Real SQLite/journal tests; disposable synthetic data only, no cluster. */
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, linkSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { canonical, hash, prepareCaseRuntimeUpgrade, activateCaseRuntimeUpgrade } from "./case_runtime_upgrade.mjs";
import { loadCaseUpgradeRuntime } from "./case_upgrade_runtime.mjs";
import { snapshotCaseFiles } from "./case_review_backup.mjs";
import { invokeCaseUpgradeWorker, verifyCaseUpgradeFence } from "./run-case-runtime-upgrade.mjs";

const sourceRoot = process.env.CASE_UPGRADE_TEST_SOURCE_ROOT;
const sourceRevision = process.env.CASE_UPGRADE_TEST_SOURCE_REVISION ?? "e44dfd20367287724fe9b42d84144574c957ea23";
const multiCaseRevision = "9010479b00f58ff4623c26ef993365e47b168224";
assert.ok(["e44dfd20367287724fe9b42d84144574c957ea23", multiCaseRevision].includes(sourceRevision));
assert.ok(sourceRoot && sourceRoot === resolve(sourceRoot), "Set CASE_UPGRADE_TEST_SOURCE_ROOT to the published 7C source checkout");
assert.equal(execFileSync("git", ["-C", sourceRoot, "rev-parse", "HEAD^{tree}"], { encoding: "utf8" }).trim(),
  execFileSync("git", ["-C", sourceRoot, "rev-parse", `${sourceRevision}^{tree}`], { encoding: "utf8" }).trim());
assert.equal(execFileSync("git", ["-C", sourceRoot, "diff", "HEAD", "--", "src", "test/fixtures"], { encoding: "utf8" }), "");
const runtime = await loadCaseUpgradeRuntime(sourceRoot);
const load = f => import(pathToFileURL(join(sourceRoot, "src", f)).href);
const [adapter, preflight, claims, continuation, auth, review] = await Promise.all([
  load("adapters/sqlite-atomic-topic-case-admission.ts"), load("staging-case-control-preflight.ts"), load("case-durable-deployment-claim.ts"),
  load("durable-case-continuation.ts"), load("staging-administration-authenticator.ts"), load("administration-review-service.ts"),
]);
const departments = ["planning", "traffic", "environment", "finance", "legal", "public-order", "social-affairs", "public-works"];
const steward = { actorId: "example:steward", actorClass: "case_steward" };
const administration = { actorId: "example:administration", actorClass: "administration" };
const publicReader = { actorId: "example:public", actorClass: "public" };
const agent = id => ({ actorId: `example:${id}:agent`, actorClass: "department_agent" });
const reviewer = id => ({ actorId: `example:${id}:reviewer`, actorClass: "department_reviewer" });
const registry = [steward, administration, publicReader, ...departments.flatMap(departmentId =>
  [{ ...agent(departmentId), departmentId }, { ...reviewer(departmentId), departmentId }])];
const json = value => canonical(value) + "\n";
const sum = value => hash(canonical(value));
const vector = JSON.parse(readFileSync(join(sourceRoot, "test/fixtures/synthetic-adoption-roebel-v1.json"), "utf8"));
const resourceList = JSON.parse(readFileSync(new URL("../reviewed-render/roebel-staging/case-runtime/resources.json", import.meta.url), "utf8"));
const sourceMap = sourceRevision === multiCaseRevision ? "roebel-case-steward-brief-reviewed-v1" : "roebel-case-steward-review-reviewed-v1";
const deployed = resourceList.items.find(i => i.kind === "ConfigMap" && i.metadata.name === sourceMap);
const targetImage = sourceRevision === multiCaseRevision
  ? "sha256:1acde64fb2e79cd4635dfa5e8dd6f9ca2922a78a97938499fa3db159c776d230"
  : "sha256:267025b3592a02123063c7f744644a4b681914d93c3a1db1dc7b2c441bd20cad";
function bindingAt(rootDir, target = false, source = deployed) {
  const b = JSON.parse(source.data["reviewed-binding.json"]);
  b.municipalityId = vector.policy.municipalityId;
  b.storage.rootDir = rootDir;
  if (target) { b.releaseDigest = targetImage;
    b.operationsTopologyChecksum = hash("fixture-target-topology"); }
  const marker = { schemaVersion: "staging_case_control_storage_marker_v1" };
  for (const key of ["deploymentEnvironment", "municipalityId", "workloadName", "workload", "releaseDigest", "operationsTopologyChecksum", "deployment"]) marker[key] = b[key];
  Object.assign(marker, structuredClone(b.storage)); delete marker.marker.checksum;
  b.storage.marker.checksum = hash(json(marker)); delete b.bindingChecksum; b.bindingChecksum = sum(b);
  return { binding: b, marker };
}
function proof(binding) {
  const s = binding.storage, markerText = readFileSync(join(s.rootDir, s.marker.fileName), "utf8");
  return preflight.createStagingCaseControlDeploymentProof({ reviewedBinding: binding, expectedBindingChecksum: binding.bindingChecksum,
    storageObserver: { observe: () => ({ rootDir: s.rootDir, rootKind: "directory", rootIsSymbolicLink: false,
      rootUid: s.uid, rootGid: s.gid, rootMode: Number.parseInt(s.mode, 8), filesystemType: BigInt(s.filesystemType), availableBytes: BigInt(s.minAvailableBytes),
      markerPath: join(s.rootDir, s.marker.fileName), markerKind: "file", markerIsSymbolicLink: false, markerUid: s.marker.uid, markerGid: s.marker.gid,
      markerMode: Number.parseInt(s.marker.mode, 8), markerText }) } });
}
function application(store, configuration, caseId) {
  const roleAuthenticator = auth.createStagingAdministrationAuthenticator({ deploymentEnvironment: "staging", grants: configuration.administrationReview.grants });
  const c = continuation.createDurableCaseContinuation({ caseKind: "synthetic_case", municipalityId: configuration.municipalityId,
    policyVersion: configuration.policyVersion, caseCoordinators: store.caseCoordinators, roleAuthenticator,
    actors: { caseSteward: steward, administrationReader: administration, publicReader },
    departments: departments.map(departmentId => ({ departmentId, agent: agent(departmentId), reviewer: reviewer(departmentId) })) });
  const service = review.createAdministrationReviewService({ deploymentEnvironment: "staging", caseId, continuation: c });
  const send = async (actor, operation, payload, expectedCaseVersion) => {
    const response = await service.respond({ method: operation ? "POST" : "GET", path: review.ADMINISTRATION_REVIEW_PATH,
      authorization: `Bearer ${configuration.administrationReview.grants.find(g => g.actor.actorId === actor.actorId).token}`,
      body: operation ? JSON.stringify({ schemaVersion: "administration_review_request_v1", operation, payload, expectedCaseVersion }) : null });
    assert.equal(response.status, 200, response.body); return JSON.parse(response.body);
  };
  return { send, view: () => send(steward), service };
}
async function fixture(t, source = deployed) {
  const parent = realpathSync(mkdtempSync(join(tmpdir(), "case-upgrade-test-"))), root = join(parent, "case-control");
  mkdirSync(root, { mode: 0o700 }); t.after(() => rmSync(parent, { recursive: true, force: true }));
  const old = bindingAt(root, false, source), next = bindingAt(root, true);
  writeFileSync(join(root, old.binding.storage.marker.fileName), json(old.marker), { mode: 0o600 });
  const options = { rootDir: root, municipalityId: vector.policy.municipalityId, policyVersion: vector.policy.policyVersion,
    actorRegistry: registry, allowedSignerPubkeys: [], allowedAgentPubkeys: vector.policy.allowedAgentPubkeys,
    requiredDepartmentIds: departments, syntheticDepartmentReview: true,
    syntheticAdoption: { policy: vector.policy, now: () => new Date(vector.verifiedAt * 1000), acceptance: { resolve: async () => vector.projection } } };
  const open = binding => adapter.createSqliteAtomicTopicCaseAdmission({ ...options,
    durableState: { mode: "durable_single_writer", sourceReleaseDigest: binding.releaseDigest }, deploymentClaimToken: claims.createCaseDurableDeploymentClaimToken(proof(binding)) });
  let store = open(old.binding); t.after(() => store.close());
  const admission = await store.admission.admitSyntheticAdoption({ schemaVersion: "atomic_synthetic_adoption_admission_v1",
    municipalityId: options.municipalityId, policyVersion: options.policyVersion, actorBinding: steward, expectedCaseVersion: 0, bundle: vector.bundle });
  const configuration = { municipalityId: options.municipalityId, policyVersion: options.policyVersion, actorRegistry: registry,
    allowedSignerPubkeys: [], allowedAgentPubkeys: options.allowedAgentPubkeys, requiredDepartmentIds: departments,
    syntheticAdoption: { policy: vector.policy, acceptanceBaseUrl: "https://example.invalid/acceptance" },
    administrationReview: { caseId: admission.caseId, allowedHosts: ["127.0.0.1"], grants: registry.filter(a => a.actorClass !== "public").map((a, i) => ({
      actor: { actorId: a.actorId, actorClass: a.actorClass }, caseId: admission.caseId, token: Buffer.alloc(32, i + 1).toString("base64url"),
      notBefore: Date.now() - 1000, expiresAt: Date.now() + 600_000 })) } };
  const app = application(store, configuration, admission.caseId);
  const initial = await app.view(); let version = 3;
  for (const id of departments) {
    await app.send(steward, "assign", { departmentPackage: { id: `package:${id}`, departmentId: id, suggestionId: initial.suggestion.id,
      request: `Assess synthetic ${id} evidence.`, assignedAgentActorId: agent(id).actorId, assignedReviewerActorId: reviewer(id).actorId, authorityBinding: "none" } }, version++);
    const assigned = (await app.view()).departmentPackages.find(p => p.departmentId === id);
    await app.send(agent(id), "draft", { packageId: assigned.id, packageChecksum: assigned.packageChecksum,
      draft: { schemaVersion: "department_draft_v1", id: `draft:${id}`, publicSummary: `Synthetic assessment: ${id} evidence remains missing.`,
        publicCitations: [`synthetic://${id}/evidence`], privateEvidenceRefs: [`synthetic://${id}/private`], authorityBinding: "none" } }, version++);
    const drafted = (await app.view()).departmentPackages.find(p => p.departmentId === id);
    await app.send(reviewer(id), "review", { review: { packageId: drafted.id, draftArtifactChecksum: drafted.draft.artifactChecksum,
      decision: "accepted", reviewedAt: "2026-09-14T08:00:00.000Z" } }, version++);
  }
  const view = await app.view(); assert.equal(view.caseVersion, 27);
  const seal = store.sealAndClose();
  const input = { sourceRootDir: root, sourceBinding: old.binding, targetBinding: next.binding, configuration,
    expected: { caseId: admission.caseId, head: seal.recoveryEvidence.orderedHeads[0], admissionReceiptChecksum: admission.receiptChecksum } };
  return { parent, root, input, seal, configuration, view, admission, open: b => { store = open(b); return store; } };
}

test("preserves v27 and all eight reviews, restarts normally, then confirms the demo Brief", async t => {
  const h = await fixture(t), before = snapshotCaseFiles(h.root), prepared = prepareCaseRuntimeUpgrade(h.input, runtime);
  assert.deepEqual(snapshotCaseFiles(h.root), before);
  const args = { ...prepared, configuration: h.configuration }, fence = { assertFenced: () => true };
  const receipt = activateCaseRuntimeUpgrade(args, runtime, fence);
  assert.deepEqual(activateCaseRuntimeUpgrade(args, runtime, fence), receipt);
  const retained = join(h.parent, `case-control-upgrade-${prepared.plan.planChecksum.slice(7)}`, "retained-source");
  assert.deepEqual(snapshotCaseFiles(retained), before);
  assert.deepEqual(readFileSync(join(h.root, h.seal.databaseBasename)), readFileSync(join(retained, h.seal.databaseBasename)));
  for (let cycle = 0; cycle < 2; cycle++) {
    const store = h.open(h.input.targetBinding), app = application(store, h.configuration, h.admission.caseId);
    assert.deepEqual(await app.view(), h.view);
    assert.deepEqual(store.outbox.replay({ limit: 2 })[0].receipt, h.admission); store.sealAndClose();
  }
  const store = h.open(h.input.targetBinding), app = application(store, h.configuration, h.admission.caseId);
  const preview = await app.send(steward, "prepare_brief", { briefId: "brief:upgrade-test" }, 27);
  await app.send(steward, "apply_brief", { briefId: preview.briefId, preparationChecksum: preview.preparationChecksum }, 27);
  const response = await app.service.respond({ method: "GET", path: review.SYNTHETIC_CITIZEN_BRIEF_PATH, body: null });
  assert.equal(response.status, 200); const returned = JSON.parse(response.body);
  assert.equal(returned.status, "current"); assert.equal(returned.caseVersion, 28);
  assert.equal(returned.brief.responses.length, 8);
  store.sealAndClose();
  // Never roll back or overwrite a new event using an old upgrade receipt.
  assert.throws(() => activateCaseRuntimeUpgrade(args, runtime, fence));
  assert.deepEqual(snapshotCaseFiles(retained), before);
});

for (const point of ["intent", "candidate-file", "candidate", "source-retained", "target-installed", "receipt"]) {
  test(`process interruption after ${point} resumes only the same verified transition`, async t => {
    const h = await fixture(t), prepared = prepareCaseRuntimeUpgrade(h.input, runtime);
    const request = join(h.parent, "request.json"), archive = join(h.parent, "archive.json");
    writeFileSync(request, json({ plan: prepared.plan, configuration: h.configuration }), { mode: 0o600 });
    writeFileSync(archive, prepared.archive, { mode: 0o600 });
    const worker = `import {readFileSync} from 'node:fs';
      import {activateCaseRuntimeUpgrade} from ${JSON.stringify(new URL("./case_runtime_upgrade.mjs", import.meta.url).href)};
      import {loadCaseUpgradeRuntime} from ${JSON.stringify(new URL("./case_upgrade_runtime.mjs", import.meta.url).href)};
      const input=JSON.parse(readFileSync(process.argv[1])); input.archive=readFileSync(process.argv[2]);
      activateCaseRuntimeUpgrade(input,await loadCaseUpgradeRuntime(process.argv[3]),{assertFenced:()=>true,failpoint:p=>{if(p===process.argv[4])process.exit(91)}});`;
    const result = spawnSync(process.execPath, ["--input-type=module", "-e", worker, request, archive, sourceRoot, point], { encoding: "utf8", timeout: 30000 });
    assert.equal(result.status, 91, result.stderr);
    const receipt = activateCaseRuntimeUpgrade({ ...prepared, configuration: h.configuration }, runtime, { assertFenced: () => true });
    assert.equal(receipt.targetSeal.recoveryEvidence.orderedHeads[0].caseVersion, 27);
    const store = h.open(h.input.targetBinding);
    assert.deepEqual(await application(store, h.configuration, h.admission.caseId).view(), h.view); store.sealAndClose();
  });
}

test("stale Case, changed policy, volume, private file or fencing failure cannot move source", async t => {
  const h = await fixture(t), before = snapshotCaseFiles(h.root), prepared = prepareCaseRuntimeUpgrade(h.input, runtime);
  for (const change of [
    { expected: { ...h.input.expected, head: { ...h.input.expected.head, caseVersion: 26 } } },
    { configuration: { ...h.configuration, policyVersion: "changed-policy" } },
    { expected: { ...h.input.expected, admissionReceiptChecksum: hash("foreign") } },
  ]) assert.throws(() => prepareCaseRuntimeUpgrade({ ...h.input, ...change }, runtime));
  const changed = structuredClone(h.input.targetBinding); changed.storage.pvcUid = "00000000-0000-4000-8000-000000000003";
  delete changed.bindingChecksum; changed.bindingChecksum = sum(changed);
  assert.throws(() => prepareCaseRuntimeUpgrade({ ...h.input, targetBinding: changed }, runtime));
  const args = { ...prepared, configuration: h.configuration };
  assert.throws(() => activateCaseRuntimeUpgrade(args, runtime, { assertFenced: () => false }));
  assert.deepEqual(snapshotCaseFiles(h.root), before); assert.deepEqual(readdirSync(h.parent), ["case-control"]);
  const owner = new DatabaseSync(join(h.root, "stadtstack-case-state-owner.sqlite"));
  owner.exec("BEGIN EXCLUSIVE");
  try { assert.throws(() => activateCaseRuntimeUpgrade(args, runtime, { assertFenced: () => true })); }
  finally { owner.exec("ROLLBACK"); owner.close(); }
  assert.deepEqual(snapshotCaseFiles(h.root), before);
  const seal = join(h.root, "case-shutdown-seal-v2.json"), data = readFileSync(seal);
  for (const attack of ["symlink", "hardlink", "permissions", "bytes"]) {
    rmSync(seal);
    if (attack === "symlink" || attack === "hardlink") {
      const path = join(h.parent, attack); writeFileSync(path, data, { mode: 0o600 });
      if (attack === "symlink") symlinkSync(path, seal); else linkSync(path, seal);
    } else { writeFileSync(seal, attack === "bytes" ? Buffer.concat([data, Buffer.from(" ")]) : data, { mode: attack === "permissions" ? 0o666 : 0o600 });
      if (attack === "permissions") chmodSync(seal, 0o666); }
    assert.throws(() => prepareCaseRuntimeUpgrade(h.input, runtime));
  }
  rmSync(seal); writeFileSync(seal, data, { mode: 0o600 });
  assert.deepEqual(snapshotCaseFiles(h.root), before);
});

test("private worker requires a restored archive before activation and never exports its bytes", async t => {
  const h = await fixture(t), work = join(h.parent, "worker"); mkdirSync(work, { mode: 0o700 });
  const configurationBytes = Buffer.from(json(h.configuration));
  writeFileSync(join(work, "configuration.json"), configurationBytes, { mode: 0o600 });
  const policy = { sourceBinding: h.input.sourceBinding, targetBinding: h.input.targetBinding, expected: h.input.expected,
    configurationSha256: hash(configurationBytes) }, policyChecksum = sum(policy);
  const invoke = (mode, extra = {}) => {
    const req = { schemaVersion: "roebel_case_upgrade_worker_request_v1", mode, policyChecksum, ...extra }, bytes = Buffer.from(json(req)), requestPin = hash(bytes);
    writeFileSync(join(work, `request-${requestPin.slice(7)}.json`), bytes, { mode: 0o600 });
    return () => invokeCaseUpgradeWorker(work, requestPin, runtime, policy, () => true);
  };
  const prepare = invoke("prepare"), prepared = prepare();
  assert.throws(prepare); // A saved result cannot cause a second capture.
  const { planChecksum, archiveSha256 } = prepared.result, pins = { planChecksum, archiveSha256 };
  const activate = invoke("activate", pins); assert.throws(activate);
  const archive = readFileSync(join(work, `archive-${archiveSha256.slice(7)}.json`));
  writeFileSync(join(work, `restored-${archiveSha256.slice(7)}.json`), archive, { mode: 0o600 });
  assert.throws(activate); // Restored bytes alone are not a verified restore.
  invoke("verify", pins)(); const applied = activate(); assert.equal(applied.result.caseVersion, 27);
  assert.equal(applied.image, "ghcr.io/giraeffleaeffle/stadtstack-case-steward-control@" + targetImage);
  assert.throws(activate);
  assert.ok(!JSON.stringify(applied).includes(h.configuration.administrationReview.grants[0].token));
  assert.ok(!JSON.stringify(applied).includes("privateEvidenceRefs"));
  const store = h.open(h.input.targetBinding); assert.deepEqual(await application(store, h.configuration, h.admission.caseId).view(), h.view); store.sealAndClose();
});

test("fence requires this sole consumer, zero writers, suspended reconciliation and fresh time", () => {
  const expected = { policyChecksum: hash("policy"), workerUid: "00000000-0000-4000-8000-000000000007" }, now = Date.parse("2026-09-14T10:00:00Z");
  const body = { schemaVersion: "roebel_case_upgrade_fence_v1", ...expected, observedAtUtc: "2026-09-14T09:59:59.000Z",
    sourceDeploymentUid: "89c06a66-9e48-43fa-9206-1bd2cd203cf8", sourceReplicas: 0, sourcePodUids: [], reconcilerSuspended: true,
    pvcUid: "8c07f2d4-b767-4bdc-b386-b03b811e33e2", pvcConsumerUids: [expected.workerUid] };
  const signed = v => ({ ...v, fenceChecksum: sum(v) });
  assert.equal(verifyCaseUpgradeFence(signed(body), expected, now), true);
  for (const change of [{ sourceReplicas: 1 }, { sourcePodUids: ["still-running"] }, { reconcilerSuspended: false },
    { pvcConsumerUids: [expected.workerUid, "another-pod"] }, { observedAtUtc: "2026-09-14T09:58:59.000Z" },
    { observedAtUtc: "2026-09-14T10:00:01.000Z" }, { pvcUid: "other-volume" }, { sourceDeploymentUid: "recreated-deployment" }]) {
    assert.throws(() => verifyCaseUpgradeFence(signed({ ...body, ...change }), expected, now));
  }
});

if (sourceRevision === multiCaseRevision) test("a second upgrade retains its pinned predecessor receipt and the confirmed Brief through two restarts", async t => {
  const historical = resourceList.items.find(i => i.kind === "ConfigMap" && i.metadata.name === "roebel-case-steward-review-reviewed-v1");
  const h = await fixture(t, historical), briefBinding = bindingAt(h.root).binding;
  const original = snapshotCaseFiles(h.root);
  const first = prepareCaseRuntimeUpgrade({ ...h.input, targetBinding: briefBinding }, runtime);
  const prior = activateCaseRuntimeUpgrade({ ...first, configuration: h.configuration }, runtime, { assertFenced: () => true });
  const receiptPath = join(h.root, "case-runtime-upgrade-v1.json"), priorBytes = readFileSync(receiptPath);
  let store = h.open(briefBinding), app = application(store, h.configuration, h.admission.caseId);
  const preview = await app.send(steward, "prepare_brief", { briefId: "brief:already-confirmed" }, 27);
  await app.send(steward, "apply_brief", { briefId: preview.briefId, preparationChecksum: preview.preparationChecksum }, 27);
  const beforeView = await app.view();
  const beforeBrief = await app.service.respond({ method: "GET", path: review.SYNTHETIC_CITIZEN_BRIEF_PATH, body: null });
  assert.equal(JSON.parse(beforeBrief.body).caseVersion, 28);
  const seal = store.sealAndClose();
  const input = { ...h.input, sourceBinding: briefBinding,
    expected: { ...h.input.expected, head: seal.recoveryEvidence.orderedHeads[0], previousUpgradeReceiptChecksum: prior.receiptChecksum } };
  const before = snapshotCaseFiles(h.root);
  const { previousUpgradeReceiptChecksum: _, ...missingPin } = input.expected;
  for (const expected of [missingPin, { ...input.expected, previousUpgradeReceiptChecksum: hash("wrong predecessor") }]) {
    assert.throws(() => prepareCaseRuntimeUpgrade({ ...input, expected }, runtime));
    assert.deepEqual(snapshotCaseFiles(h.root), before);
  }
  const damaged = JSON.parse(priorBytes); damaged.archiveSha256 = hash("changed archive");
  writeFileSync(receiptPath, json(damaged));
  assert.throws(() => prepareCaseRuntimeUpgrade(input, runtime));
  writeFileSync(receiptPath, priorBytes);
  const prepared = prepareCaseRuntimeUpgrade(input, runtime);
  const receipt = activateCaseRuntimeUpgrade({ ...prepared, configuration: h.configuration }, runtime, { assertFenced: () => true });
  assert.equal(receipt.schemaVersion, "roebel_case_runtime_upgrade_v2");
  assert.equal(receipt.previousUpgradeReceiptChecksum, prior.receiptChecksum);
  assert.equal(receipt.targetSeal.recoveryEvidence.orderedHeads[0].caseVersion, 28);
  assert.deepEqual(readFileSync(join(h.root, `case-runtime-upgrade-history-${prior.receiptChecksum.slice(7)}.json`)), priorBytes);
  const retained = join(h.parent, `case-control-upgrade-${prepared.plan.planChecksum.slice(7)}`, "retained-source");
  assert.deepEqual(snapshotCaseFiles(retained), before);
  assert.deepEqual(snapshotCaseFiles(join(h.parent, `case-control-upgrade-${first.plan.planChecksum.slice(7)}`, "retained-source")), original);
  assert.deepEqual(readFileSync(join(h.root, seal.databaseBasename)), readFileSync(join(retained, seal.databaseBasename)));
  for (let cycle = 0; cycle < 2; cycle++) {
    store = h.open(input.targetBinding); app = application(store, h.configuration, h.admission.caseId);
    assert.deepEqual(await app.view(), beforeView);
    assert.deepEqual(await app.service.respond({ method: "GET", path: review.SYNTHETIC_CITIZEN_BRIEF_PATH, body: null }), beforeBrief);
    assert.deepEqual(store.outbox.replay({ limit: 2 })[0].receipt, h.admission);
    store.sealAndClose();
  }
});
