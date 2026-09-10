/** Explicit offline integration against the pinned public source checkout.
 * No cluster, real account, listener or mounted-volume attestation is used.
 * CASE_REVIEW_TEST_SOURCE_ROOT=/path/to/pinned/source node --test this-file
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync, statSync, statfsSync, chownSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { configurations, files, hash } from "./test_case_review_migration.mjs";
import { canonical, CONTROL_IMAGE_DIGEST, runReviewMigration } from "./run-case-review-migration.mjs";

const sourceRoot = process.env.CASE_REVIEW_TEST_SOURCE_ROOT;
if (!sourceRoot || sourceRoot !== resolve(sourceRoot)) throw new Error("Set the absolute pinned public source checkout for this integration test.");
const git = (...args) => execFileSync("git", ["-C", sourceRoot, ...args], { encoding: "utf8" }).trim();
assert.equal(git("rev-parse", "HEAD^{tree}"), "009eff02efce05ceaabcc6d3389f732157d69ca6");
assert.equal(git("diff", "HEAD", "--", "src", "test/fixtures/synthetic-adoption-roebel-v1.json"), "");
const load = (name) => import(pathToFileURL(join(sourceRoot, "src", name)).href);
const adapter = await load("adapters/sqlite-atomic-topic-case-admission.ts");
const control = await load("staging-case-control-runtime.ts");
const preflight = await load("staging-case-control-preflight.ts");
const claims = await load("case-durable-deployment-claim.ts");
const authentication = await load("staging-administration-authenticator.ts");
const checksum = (value) => hash(canonical(value));
const snapshot = (root) => Object.fromEntries(readdirSync(root).sort().map((name) => [name, hash(readFileSync(join(root, name)))]));

function fixtureBinding(rootDir, target, municipalityId) {
  const { bindingChecksum: _, ...value } = JSON.parse(readFileSync(new URL("../proposals/synthetic-case-runtime/control-binding.json", import.meta.url), "utf8"));
  value.storage.rootDir = rootDir;
  value.municipalityId = municipalityId;
  if (target) {
    value.schemaVersion = "staging_case_control_deployment_binding_v2";
    value.releaseDigest = CONTROL_IMAGE_DIGEST;
    value.storage.pvcName = "synthetic-review-fixture";
    value.storage.pvcUid = "00000000-0000-4000-8000-000000000002";
    value.storage.pvName = "pvc-synthetic-review-fixture";
    value.listeners.push({ id: "administration-review", port: 18090, bindScope: "pod_network" });
  }
  const marker = {};
  for (const key of ["deploymentEnvironment", "municipalityId", "workloadName", "workload", "releaseDigest", "operationsTopologyChecksum", "deployment"]) marker[key] = value[key];
  Object.assign(marker, value.storage);
  marker.schemaVersion = "staging_case_control_storage_marker_v1";
  marker.marker = { ...value.storage.marker }; delete marker.marker.checksum;
  const markerText = `${canonical(marker)}\n`;
  value.storage.marker.checksum = hash(markerText);
  const binding = { ...value, bindingChecksum: checksum(value) };
  const storage = binding.storage;
  const observation = { rootDir, rootKind: "directory", rootIsSymbolicLink: false,
    rootUid: storage.uid, rootGid: storage.gid, rootMode: Number.parseInt(storage.mode, 8),
    filesystemType: BigInt(storage.filesystemType), availableBytes: BigInt(storage.minAvailableBytes),
    markerPath: `${rootDir}/${storage.marker.fileName}`, markerKind: "file", markerIsSymbolicLink: false,
    markerUid: storage.marker.uid, markerGid: storage.marker.gid, markerMode: Number.parseInt(storage.marker.mode, 8), markerText };
  return { binding, storageObserver: { observe: () => observation } };
}

test("descriptor operator prepares, activates and retries the actual sealed Case without altering the source", async (t) => {
  const temporaryRoot = realpathSync(mkdtempSync(join(tmpdir(), "case-review-integration-")));
  t.after(() => rmSync(temporaryRoot, { recursive: true, force: true }));
  const originalRoot = join(temporaryRoot, "source"), targetRoot = join(temporaryRoot, "target");
  mkdirSync(originalRoot, { mode: 0o700 }); mkdirSync(targetRoot, { mode: 0o700 });
  const vector = JSON.parse(readFileSync(join(sourceRoot, "test/fixtures/synthetic-adoption-roebel-v1.json"), "utf8"));
  const { source, target } = configurations();
  source.municipalityId = vector.policy.municipalityId;
  source.credentials[0].principal.municipalityIds = [source.municipalityId];
  source.policyVersion = vector.policy.policyVersion;
  source.allowedAgentPubkeys = vector.policy.allowedAgentPubkeys;
  source.syntheticAdoption.policy = vector.policy;
  const old = fixtureBinding(originalRoot, false, source.municipalityId), next = fixtureBinding(targetRoot, true, source.municipalityId);
  const proof = preflight.createStagingCaseControlDeploymentProof({ reviewedBinding: old.binding,
    expectedBindingChecksum: old.binding.bindingChecksum, storageObserver: old.storageObserver });
  const seed = adapter.createSqliteAtomicTopicCaseAdmission({ municipalityId: source.municipalityId, policyVersion: source.policyVersion,
    actorRegistry: source.actorRegistry, allowedSignerPubkeys: source.allowedSignerPubkeys, allowedAgentPubkeys: source.allowedAgentPubkeys,
    syntheticAdoption: { policy: vector.policy, now: () => new Date(vector.verifiedAt * 1000), acceptance: { resolve: async () => vector.projection } },
    rootDir: originalRoot, durableState: { mode: "durable_single_writer", sourceReleaseDigest: old.binding.releaseDigest },
    deploymentClaimToken: claims.createCaseDurableDeploymentClaimToken(proof) });
  t.after(() => seed.close());
  const admitted = await seed.admission.admitSyntheticAdoption({ schemaVersion: "atomic_synthetic_adoption_admission_v1",
    municipalityId: source.municipalityId, policyVersion: source.policyVersion, actorBinding: source.actorRegistry[0], expectedCaseVersion: 0, bundle: vector.bundle });
  const seal = seed.sealAndClose(), originalBytes = snapshot(originalRoot);
  for (const [key, value] of Object.entries(source)) if (key !== "actorRegistry") target[key] = structuredClone(value);
  target.administrationReview.caseId = admitted.caseId;
  target.administrationReview.grants[0].caseId = admitted.caseId;
  const request = { sourceRootDir: originalRoot, caseId: admitted.caseId, sourceSealChecksum: seal.sealChecksum,
    admissionReceiptChecksum: admitted.receiptChecksum, targetBinding: next.binding };
  const runtime = { prepare: adapter.prepareSyntheticDepartmentReviewMigration,
    validateGrants: authentication.createStagingAdministrationAuthenticator,
    activate: (input) => control.activateOperationsBoundSyntheticReviewMigration({ ...input, storageObserver: next.storageObserver }) };
  const prepare = files(t, { source, target, request });
  runReviewMigration(prepare.args, runtime);
  const candidate = prepare.result().result;
  t.after(() => rmSync(candidate.candidateRootDir, { recursive: true, force: true }));
  assert.equal(candidate.receipt.caseVersion, 3);
  assert.equal(candidate.receipt.admissionReceiptChecksum, admitted.receiptChecksum);
  assert.deepEqual(snapshot(originalRoot), originalBytes);
  const claim = { schemaVersion: "case_durable_deployment_claim_v1", municipalityId: source.municipalityId,
    releaseDigest: next.binding.releaseDigest, controlDeploymentBindingChecksum: next.binding.bindingChecksum,
    pvc: { namespace: next.binding.storage.pvcNamespace, name: next.binding.storage.pvcName, uid: next.binding.storage.pvcUid }, pvName: next.binding.storage.pvName };
  const planBody = { schemaVersion: "staging_synthetic_review_migration_plan_v1", deploymentEnvironment: "staging",
    municipalityId: source.municipalityId, caseId: admitted.caseId, sourceDeploymentClaimChecksum: seal.deploymentClaimChecksum,
    targetDeploymentClaimChecksum: checksum(claim), candidateChecksum: candidate.receipt.candidateChecksum,
    notBeforeUtc: new Date(Date.now() - 1000).toISOString(), expiresAtUtc: new Date(Date.now() + 60_000).toISOString() };
  const migrationPlan = { ...planBody, planChecksum: checksum(planBody) };
  const activation = files(t, { mode: "activate", source, target, request: { ...request, migrationPlan } });
  assert.equal(runReviewMigration(activation.args, runtime).status, "target-sealed");
  assert.deepEqual(snapshot(originalRoot), originalBytes);
  const targetBytes = snapshot(targetRoot);
  assert.equal(Object.hasOwn(targetBytes, "synthetic-review-migration-intent-v1.json"), false);
  const retry = files(t, { mode: "activate", source, target, request: { ...request, migrationPlan } });
  runReviewMigration(retry.args, runtime);
  assert.deepEqual(retry.result().result, activation.result().result);
  assert.deepEqual(snapshot(targetRoot), targetBytes);
  assert.deepEqual(snapshot(originalRoot), originalBytes);
  // Opening the ordinary runtime proves the captured private application has
  // the same fingerprints as the migrated target; no listeners are started.
  const ordinary = control.createOperationsBoundStagingCaseControlRuntime({
    reviewedBindingSource: { read: () => next.binding }, bindingPinSource: { read: () => next.binding.bindingChecksum },
    storageObserver: next.storageObserver, application: target });
  t.after(() => ordinary.close());
  await ordinary.close();
  const reopenedBytes = snapshot(targetRoot);
  const staleRetry = files(t, { mode: "activate", source, target, request: { ...request, migrationPlan } });
  assert.throws(() => runReviewMigration(staleRetry.args, runtime), { message: "case_review_migration_stopped" });
  assert.deepEqual(snapshot(targetRoot), reopenedBytes);
  assert.deepEqual(snapshot(originalRoot), originalBytes);
});


test("compiled initializer passes actual filesystem proof and refuses existing or mismatched targets", async (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "case-initializer-integration-")));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const operationsRoot = resolve(new URL("..", import.meta.url).pathname);
  const program = execFileSync("python3", ["-c", "from scripts.case_review_storage import INITIALIZER_PROGRAM; print(INITIALIZER_PROGRAM,end='')"], { cwd: operationsRoot, encoding: "utf8" });
  const localProgram = program.replace("'/runtime/src/staging-case-control-preflight.ts'", JSON.stringify(pathToFileURL(join(sourceRoot,"src/staging-case-control-preflight.ts")).href));
  assert.notEqual(program, localProgram);
  const modulePath = join(root,"initialize.mjs");writeFileSync(modulePath,localProgram,{mode:0o600,flag:"wx"});
  const { initialize } = await import(pathToFileURL(modulePath).href);
  function fixture(name, change = () => {}) {
    const parent = join(root,name);mkdirSync(parent,{mode:0o700});chownSync(parent,process.getuid(),process.getgid());
    const {bindingChecksum:_,...binding} = fixtureBinding(join(parent,"case-control"),true,"roebel-mueritz").binding;
    Object.assign(binding.storage,{uid:process.getuid(),gid:process.getgid(),filesystemType:"0x"+statfsSync(parent,{bigint:true}).type.toString(16)});
    Object.assign(binding.storage.marker,{uid:process.getuid(),gid:process.getgid()});change(binding);
    const marker = {};
    for(const key of ["deploymentEnvironment","municipalityId","workloadName","workload","releaseDigest","operationsTopologyChecksum","deployment"]) marker[key]=binding[key];
    Object.assign(marker,binding.storage);marker.schemaVersion="staging_case_control_storage_marker_v1";
    marker.marker={...binding.storage.marker};delete marker.marker.checksum;
    const text=canonical(marker)+"\n";binding.storage.marker.checksum=hash(text);
    binding.bindingChecksum=checksum(binding);return {binding,parent,text};
  }
  const good=fixture("success");mkdirSync(join(good.parent,"lost+found"));
  assert.equal(initialize(good.binding,good.binding.bindingChecksum,good.text).status,"target-marker-initialized");
  assert.equal(statSync(good.binding.storage.rootDir).mode&0o7777,0o700);
  assert.equal(statSync(join(good.binding.storage.rootDir,good.binding.storage.marker.fileName)).mode&0o7777,0o600);
  const before=snapshot(good.binding.storage.rootDir);
  assert.throws(()=>initialize(good.binding,good.binding.bindingChecksum,good.text));
  assert.deepEqual(snapshot(good.binding.storage.rootDir),before);
  for(const fault of ["content","pin","marker","filesystem","symlink"]) {
    const item=fixture(fault,b=>{if(fault==="filesystem") b.storage.filesystemType="0x12345678";});
    if(fault==="content")writeFileSync(join(item.parent,"preserved"),"evidence");
    if(fault==="symlink")symlinkSync(root,join(item.parent,"lost+found"));
    const entries=readdirSync(item.parent);
    assert.throws(()=>initialize(item.binding,fault==="pin"?hash("wrong"):item.binding.bindingChecksum,fault==="marker"?item.text+" ":item.text));
    assert.deepEqual(readdirSync(item.parent),entries);
    if(fault==="content")assert.equal(readFileSync(join(item.parent,"preserved"),"utf8"),"evidence");
  }
});
