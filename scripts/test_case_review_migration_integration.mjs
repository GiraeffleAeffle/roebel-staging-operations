/** Explicit offline integration against the pinned public source checkout.
 * No cluster, real account, listener or mounted-volume attestation is used.
 * CASE_REVIEW_TEST_SOURCE_ROOT=/path/to/pinned/source node --test this-file
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { closeSync, openSync, linkSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync, statSync, statfsSync, chownSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { configurations, files, hash } from "./test_case_review_migration.mjs";
import { canonical, CONTROL_IMAGE_DIGEST, runReviewMigration, invokeWorkerRequest, readWorkerOutput, uploadWorkerArchive } from "./run-case-review-migration.mjs";

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
const sealVerifier = await load("case-shutdown-seal.ts");
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
  writeFileSync(join(originalRoot, old.binding.storage.marker.fileName), old.storageObserver.observe().markerText, { mode: 0o600 });
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
    verifySeal: sealVerifier.verifyCaseShutdownSeal,
    validateGrants: authentication.createStagingAdministrationAuthenticator,
    activate: (input) => control.activateOperationsBoundSyntheticReviewMigration({ ...input, storageObserver: next.storageObserver }) };
  const prepare = files(t, { source, target, request });
  runReviewMigration(prepare.args, runtime);
  const candidate = prepare.result().result;
  t.after(() => rmSync(candidate.candidateRootDir, { recursive: true, force: true }));
  assert.equal(candidate.receipt.caseVersion, 3);
  assert.equal(candidate.receipt.admissionReceiptChecksum, admitted.receiptChecksum);
  assert.deepEqual(snapshot(originalRoot), originalBytes);
  let backupIntegration;
  await t.test("backup round trip replays the restored real Case and preserves every source file", async (t) => {
    const capture = files(t, { mode: "capture-backup", source, target, request: { ...request,
      sourceDeploymentClaimChecksum: seal.deploymentClaimChecksum } });
    const archivePath = join(temporaryRoot, "captured.archive"), archiveFd = openSync(archivePath, "wx+", 0o600);
    t.after(() => closeSync(archiveFd));
    const captured = runReviewMigration({ ...capture.args, archiveFd }, runtime);
    assert.equal(captured.status, "private-archive-captured");
    await t.test("fresh shutdown seal discovery captures the exact pinned Case without prior seal knowledge", () => {
      const discovered = files(t, { mode: "capture-backup", source, target, request: { ...request,
        sourceSealChecksum: null, sourceDeploymentClaimChecksum: null, sourceBindingChecksum: old.binding.bindingChecksum } });
      const path = join(temporaryRoot, "discovered.archive"), fd = openSync(path, "wx+", 0o600); t.after(() => closeSync(fd));
      runReviewMigration({ ...discovered.args, archiveFd: fd }, runtime);
      assert.deepEqual(discovered.result().result, capture.result().result);
      assert.deepEqual(readFileSync(path), readFileSync(archivePath));
      for (const changed of [ { sourceBindingChecksum: hash("foreign-binding") }, { caseId: admitted.caseId + "-foreign" },
                              { admissionReceiptChecksum: hash("foreign-admission") } ]) {
        const bad = files(t, { mode: "capture-backup", source, target, request: { ...request,
          sourceSealChecksum: null, sourceDeploymentClaimChecksum: null, sourceBindingChecksum: old.binding.bindingChecksum, ...changed } });
        const output = join(bad.root,"archive"), outputFd = openSync(output,"wx+",0o600); t.after(() => closeSync(outputFd));
        assert.throws(() => runReviewMigration({ ...bad.args, archiveFd: outputFd }, runtime));
        assert.equal(readFileSync(output).length,0);
      }
      assert.deepEqual(snapshot(originalRoot), originalBytes);
    });
    const archive = readFileSync(archivePath), archiveSha256 = hash(archive);
    assert.equal(capture.result().result.archiveSha256, archiveSha256);
    const verify = files(t, { mode: "verify-backup", source, target, request: { ...request,
      sourceDeploymentClaimChecksum: seal.deploymentClaimChecksum, archiveSha256 } });
    assert.equal(runReviewMigration({ ...verify.args, archiveFd }, runtime).status, "restored-case-verified");
    assert.equal(verify.result().result.restoredFilesSha256, capture.result().result.sourceFilesSha256);
    assert.equal(verify.result().result.admissionReceiptChecksum, admitted.receiptChecksum);
    backupIntegration={capture:capture.result(),request:verify.request,result:verify.result()};
    assert.deepEqual(snapshot(originalRoot), originalBytes);

    await t.test("worker mailbox captures and restores actual SQLite through pinned private inputs", () => {
      const mailbox = join(temporaryRoot, "worker-mailbox"); mkdirSync(mailbox,{mode:0o700});
      writeFileSync(join(mailbox,"source.json"),canonical(source),{mode:0o600});
      writeFileSync(join(mailbox,"target.json"),canonical(target),{mode:0o600});
      const captureBytes=Buffer.from(canonical(capture.request)), capturePin=hash(captureBytes);
      const outcome=invokeWorkerRequest(mailbox,captureBytes,capturePin,runtime);
      const result=JSON.parse(readWorkerOutput(mailbox,capturePin));
      assert.equal(outcome.resultSha256,result.resultSha256);
      const exported=readWorkerOutput(mailbox,capturePin,"archive");
      assert.equal(hash(exported),result.result.archiveSha256);
      uploadWorkerArchive(mailbox,hash(exported),exported);
      const verifyBytes=Buffer.from(canonical({...verify.request,archiveSha256:hash(exported)})),verifyPin=hash(verifyBytes);
      assert.equal(invokeWorkerRequest(mailbox,verifyBytes,verifyPin,runtime).status,"restored-case-verified");
      const restored=JSON.parse(readWorkerOutput(mailbox,verifyPin));
      assert.equal(restored.result.restoredFilesSha256,result.result.sourceFilesSha256);
      assert.deepEqual(snapshot(originalRoot),originalBytes);
      assert.throws(()=>invokeWorkerRequest(mailbox,captureBytes,capturePin,runtime));
    });

    await t.test("real age encryption restores and replays the Case through the host backup operator", {
      skip: !process.env.CASE_REVIEW_TEST_AGE_BIN || !process.env.CASE_REVIEW_TEST_AGE_KEYGEN_BIN,
    }, () => {
      const age = realpathSync(process.env.CASE_REVIEW_TEST_AGE_BIN), keygen = realpathSync(process.env.CASE_REVIEW_TEST_AGE_KEYGEN_BIN);
      const key = join(temporaryRoot, "test-age.key"), wrongKey = join(temporaryRoot, "wrong-age.key");
      for (const path of [key, wrongKey]) execFileSync(keygen, ["-o", path], { stdio: "pipe" });
      const recipient = execFileSync(keygen, ["-y", key], { encoding: "utf8", stdio: "pipe" }).trim();
      const restored = files(t, { mode: "verify-backup", source, target, request: { ...request,
        sourceDeploymentClaimChecksum: seal.deploymentClaimChecksum, archiveSha256 } });
      const driver = join(temporaryRoot, "verify-restored.mjs");
      writeFileSync(driver, `import {runReviewMigration} from ${JSON.stringify(new URL("./run-case-review-migration.mjs", import.meta.url).href)};
import {prepareSyntheticDepartmentReviewMigration} from ${JSON.stringify(pathToFileURL(join(sourceRoot,"src/adapters/sqlite-atomic-topic-case-admission.ts")).href)};
import {createStagingAdministrationAuthenticator} from ${JSON.stringify(pathToFileURL(join(sourceRoot,"src/staging-administration-authenticator.ts")).href)};
import {verifyCaseShutdownSeal} from ${JSON.stringify(pathToFileURL(join(sourceRoot,"src/case-shutdown-seal.ts")).href)};
const args = JSON.parse(process.argv[2]);
process.stdout.write(JSON.stringify(runReviewMigration(args,{prepare:prepareSyntheticDepartmentReviewMigration,validateGrants:createStagingAdministrationAuthenticator,verifySeal:verifyCaseShutdownSeal})));`, { mode: 0o600 });
      const specPath = join(temporaryRoot, "host-spec.json");
      writeFileSync(specPath, canonical({ capture: capture.result(), archivePath, output: join(temporaryRoot, "encrypted-backup"),
        age, ageSha256: hash(readFileSync(age)), recipient, key, wrongKey, node: process.execPath, driver,
        verifyDirectory: restored.root, verifyRequestSha256: restored.args.expectedRequestSha256 }), { mode: 0o600 });
      const script = `import json, os, pathlib, subprocess, sys
from scripts.case_review_handover import encrypt_and_verify_case_backup, BootstrapStopped
s=json.loads(pathlib.Path(sys.argv[1]).read_text())
def verify(path, pin):
    assert pin == s['capture']['result']['archiveSha256']
    directory=pathlib.Path(s['verifyDirectory'])
    handles=[os.open(directory/name, os.O_RDONLY) for name in ('request','source','target')]
    handles += [os.open(directory/'result',os.O_RDWR),os.open(path,os.O_RDONLY)]
    try:
        args=dict(zip(('requestFd','sourceConfigFd','targetConfigFd','resultFd','archiveFd'),handles))
        args['expectedRequestSha256']=s['verifyRequestSha256']
        result=subprocess.run([s['node'],s['driver'],json.dumps(args)],pass_fds=handles,capture_output=True,timeout=30)
        assert result.returncode == 0, 'restored runtime verification failed'
        return json.loads((directory/'result').read_text())
    finally:
        for fd in handles: os.close(fd)
kwargs=dict(capture=s['capture'],expected_capture_sha256=s['capture']['resultSha256'],archive_path=s['archivePath'],
    output_directory=s['output'],age_binary=s['age'],expected_age_sha256=s['ageSha256'],recipient=s['recipient'],
    identity_path=s['key'],expected_verification_request_sha256=s['verifyRequestSha256'],verify_restored=verify)
result=encrypt_and_verify_case_backup(**kwargs)
out=pathlib.Path(s['output'])
assert (out/'case-backup.age').is_file() and (out/'backup-verified.json').is_file()
assert not list(out.glob('*restored.archive'))
assert result['restoredFilesSha256']==s['capture']['result']['sourceFilesSha256']
assert result['encryptedArchiveSha256']!=result['archiveSha256']
for fault in ('wrong-key','wrong-capture','wrong-binary','existing-output','cipher-replaced'):
    changed=kwargs | {'output_directory':s['output']+'-'+fault}
    if fault=='wrong-key': changed['identity_path']=s['wrongKey']
    if fault=='wrong-capture': changed['expected_capture_sha256']='sha256:'+'0'*64
    if fault=='wrong-binary': changed['expected_age_sha256']='sha256:'+'0'*64
    if fault=='existing-output': changed['output_directory']=s['output']
    if fault=='cipher-replaced':
        def replace_cipher(path,pin):
            cipher=path.parent/'case-backup.age'
            cipher.unlink();cipher.write_bytes(b'replaced')
            return json.loads((pathlib.Path(s['verifyDirectory'])/'result').read_text())
        changed['verify_restored']=replace_cipher
    try: encrypt_and_verify_case_backup(**changed)
    except BootstrapStopped: pass
    else: raise AssertionError('backup fault accepted')
    if fault!='existing-output':
        failed=pathlib.Path(changed['output_directory'])
        assert not (failed/'backup-verified.json').exists()
        assert not list(failed.glob('*restored.archive'))
assert (out/'backup-verified.json').is_file()
# Simulate loss after real verification has committed its private result. The
# worker recovery callback reads that result; it must not rerun the SQLite step.
recover=kwargs | {'output_directory':s['output']+'-recover'}
calls=[]
def lost_result(path,pin):
    calls.append('lost')
    # The real verification above already produced this same exact request's
    # retained result. Treat it as a response lost in the worker exchange.
    assert pathlib.Path(path).read_bytes()==pathlib.Path(s['archivePath']).read_bytes()
    raise TimeoutError('private response lost')
recover['verify_restored']=lost_result
try: encrypt_and_verify_case_backup(**recover)
except BootstrapStopped: pass
else: raise AssertionError('missing verification accepted')
recovery_out=pathlib.Path(recover['output_directory'])
pending=json.loads((recovery_out/'backup-pending.json').read_text())
cipher=recovery_out/'case-backup.age';before=cipher.stat();cipher_bytes=cipher.read_bytes()
assert not (recovery_out/'backup-verified.json').exists()
recover |= dict(pending_receipt=pending,expected_pending_sha256=pending['canonicalSha256'])
def retained_result(path,pin):
    calls.append('retrieve')
    assert pathlib.Path(path).read_bytes()==pathlib.Path(s['archivePath']).read_bytes()
    return json.loads((pathlib.Path(s['verifyDirectory'])/'result').read_text())
recover['verify_restored']=retained_result
for attempt in range(2):
    recovered=encrypt_and_verify_case_backup(**recover)
    assert recovered['archiveSha256']==result['archiveSha256']
    assert cipher.read_bytes()==cipher_bytes
    assert (cipher.stat().st_ino,cipher.stat().st_mtime_ns)==(before.st_ino,before.st_mtime_ns)
    assert not list(recovery_out.glob('*restored.archive'))
assert calls==['lost','retrieve','retrieve']
for fault in ('wrong-pending','changed-request','changed-cipher'):
    changed=recover.copy()
    if fault=='wrong-pending':changed['expected_pending_sha256']='sha256:'+'0'*64
    if fault=='changed-request':changed['expected_verification_request_sha256']='sha256:'+'0'*64
    if fault=='changed-cipher':cipher.write_bytes(b'changed')
    count=len(calls)
    try: encrypt_and_verify_case_backup(**changed)
    except BootstrapStopped:pass
    else:raise AssertionError('backup recovery fault accepted')
    assert len(calls)==count
print(json.dumps({'status':'encrypted-backup-restored-and-replayed','negativeCases':8,'ciphertextReused':True,'backupReceipt':result}))
`;
      const result = JSON.parse(execFileSync("python3", ["-c", script, specPath], { encoding: "utf8", stdio: "pipe" }));
      assert.equal(result.status, "encrypted-backup-restored-and-replayed");
      backupIntegration.backupReceipt=result.backupReceipt;
      assert.deepEqual(snapshot(originalRoot), originalBytes);
    });

    for (const fault of ["hash", "path", "duplicate", "database", "missing-marker", "nonempty-result", "alias"]) {
      const changed = JSON.parse(archive);
      if (fault === "path") changed.files[0].name = "../outside";
      if (fault === "duplicate") changed.files.push(changed.files[0]);
      if (fault === "database") {
        const file = changed.files.find((f) => f.name === seal.databaseBasename);
        const bytes = Buffer.from(file.base64, "base64"); bytes[0] ^= 1;
        file.base64 = bytes.toString("base64"); file.sha256 = hash(bytes);
      }
      if (fault === "missing-marker") changed.files = changed.files.filter((f) => !f.name.startsWith("."));
      const bytes = Buffer.from(canonical(changed) + "\n"), path = join(temporaryRoot, fault + ".archive");
      writeFileSync(path, bytes, { mode: 0o600 }); const fd = openSync(path, "r"); t.after(() => closeSync(fd));
      const h = files(t, { mode: "verify-backup", source, target, request: { ...request,
        sourceDeploymentClaimChecksum: seal.deploymentClaimChecksum, archiveSha256: fault === "hash" ? hash("wrong") : hash(bytes) } });
      if (fault === "nonempty-result") h.replace("result", "preserved");
      assert.throws(() => runReviewMigration({ ...h.args, archiveFd: fault === "alias" ? h.args.requestFd : fd }, runtime),
        { message: "case_review_migration_stopped" }, fault);
      assert.deepEqual(snapshot(originalRoot), originalBytes);
    }
    // Symlinks/hardlinks must not escape into a captured backup, even if they
    // refer to the same valid database. Active epochs must also block capture.
    for (const fault of ["symlink", "hardlink", "epoch"]) {
      const path = join(originalRoot, fault === "epoch" ? "case-open-epoch-v1.json" : "unexpected");
      if (fault === "symlink") symlinkSync(archivePath, path);
      if (fault === "hardlink") linkSync(join(originalRoot, seal.databaseBasename), path);
      if (fault === "epoch") writeFileSync(path, "{}", { mode: 0o600 });
      try {
        const h = files(t, { mode: "capture-backup", source, target, request: { ...request, sourceDeploymentClaimChecksum: seal.deploymentClaimChecksum } });
        const fd = openSync(join(temporaryRoot, fault + ".output"), "wx+", 0o600); t.after(() => closeSync(fd));
        assert.throws(() => runReviewMigration({ ...h.args, archiveFd: fd }, runtime), { message: "case_review_migration_stopped" });
      } finally { rmSync(path); }
    }
    const changedSource = files(t, { mode: "verify-backup", source, target, request: { ...request,
      sourceDeploymentClaimChecksum: seal.deploymentClaimChecksum, archiveSha256 } });
    const markerPath=join(originalRoot, old.binding.storage.marker.fileName), markerBytes=readFileSync(markerPath);
    try {
      assert.throws(() => runReviewMigration({ ...changedSource.args, archiveFd }, { ...runtime,
        prepare(input) {
          const candidate=runtime.prepare(input);
          writeFileSync(markerPath, Buffer.concat([markerBytes,Buffer.from("\n")]));
          return candidate;
        },
      }), { message: "case_review_migration_stopped" });
      assert.equal(readFileSync(join(changedSource.root,"result")).length,0);
    } finally { writeFileSync(markerPath,markerBytes); }
    assert.deepEqual(snapshot(originalRoot),originalBytes);
  });
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
  await t.test("real example-city runtime results translate to stage evidence behind the Röbel-only guard", {skip:!backupIntegration?.backupReceipt}, () => {
    const input=join(temporaryRoot,"stage-evidence.private.json");
    writeFileSync(input,canonical({backup:backupIntegration,sourceBinding:old.binding,
      preparation:{request:prepare.request,result:prepare.result()},activation:{request:activation.request,result:activation.result()}}),{mode:0o600});
    const script=`import copy,json,pathlib,sys
from scripts.case_review_handover import review_migration_stage_evidence, _review_migration_result_evidence, BootstrapStopped
from scripts.test_case_review_handover import fixture,sha
s=json.loads(pathlib.Path(sys.argv[1]).read_text());plan,_=fixture()
a=s['activation']['request'];plan['caseId']=a['caseId'];plan['notBeforeUtc']=a['migrationPlan']['notBeforeUtc'];plan['expiresAtUtc']=a['migrationPlan']['expiresAtUtc']
plan['pins'].update(sourceBindingSha256=s['sourceBinding']['bindingChecksum'],targetBindingSha256=a['targetBinding']['bindingChecksum'],
    targetDeploymentClaimChecksum=a['migrationPlan']['targetDeploymentClaimChecksum'],migrationImageDigest=a['controlImageDigest'],
    sourceConfigurationSha256=a['sourceConfigurationSha256'],targetConfigurationSha256=a['targetConfigurationSha256'],admissionReceiptChecksum=a['admissionReceiptChecksum'])
plan['identities']['targetPvcUid']=a['targetBinding']['storage']['pvcUid'];plan['planSha256']=sha({k:v for k,v in plan.items() if k!='planSha256'})
# The public entry point must keep rejecting this foreign-municipality fixture.
try:review_migration_stage_evidence(plan,'verify-backup',request=s['backup']['request'],result=s['backup']['result'],previous={},backup_receipt=s['backup']['backupReceipt'])
except BootstrapStopped:pass
else:raise AssertionError('foreign municipality admitted')
previous={}
for step,source in [('verify-backup','backup'),('prepare-migration','preparation'),('activate-migration','activation')]:
    item=s[source];args=dict(request=item['request'],result=item['result'],previous=previous)
    if step=='verify-backup':args['backup_receipt']=item['backupReceipt']
    previous[step]=_review_migration_result_evidence(plan,step,**args)
assert previous['activate-migration']['candidateChecksum']==previous['prepare-migration']['candidateChecksum']
assert previous['activate-migration']['sourceDatabaseSha256']==previous['verify-backup']['sourceDatabaseSha256']
# Rehashing a forged envelope or nested receipt must not break the links.
for fault in ('foreign-request','foreign-candidate','foreign-claim','foreign-recovery','changed-backup','expired-seal'):
    step='activate-migration';item=copy.deepcopy(s['activation']);extra={}
    if fault=='foreign-request':item['request']['caseId']+='-foreign'
    if fault=='foreign-candidate':
        c=item['result']['result']['candidate'];c['admissionReceiptChecksum']=sha('foreign');c['candidateChecksum']=sha({k:v for k,v in c.items() if k!='candidateChecksum'})
    if fault=='foreign-claim':
        c=item['result']['result']['targetClaim'];c['pvc']['uid']='00000000-0000-4000-8000-000000009999';c['claimChecksum']=sha({k:v for k,v in c.items() if k!='claimChecksum'})
    if fault in ('foreign-recovery','expired-seal'):
        c=item['result']['result']['targetSeal']
        if fault=='foreign-recovery':c['recoveryEvidence']={'changed':True}
        else:c['closedAtUtc']=plan['expiresAtUtc']
        c['sealChecksum']=sha({k:v for k,v in c.items() if k!='sealChecksum'})
    if fault=='changed-backup':
        step='verify-backup';item=copy.deepcopy(s['backup']);b=item['backupReceipt'];b['sourceDatabaseSha256']=sha('foreign');b['receiptSha256']=sha({k:v for k,v in b.items() if k!='receiptSha256'});extra={'backup_receipt':b}
    else:
        body=item['result']['result'];body['activationChecksum']=sha({k:v for k,v in body.items() if k!='activationChecksum'})
    item['result']['requestSha256']=sha(item['request']);item['result']['resultSha256']=sha({k:v for k,v in item['result'].items() if k!='resultSha256'})
    try:_review_migration_result_evidence(plan,step,request=item['request'],result=item['result'],previous=previous,**extra)
    except BootstrapStopped:pass
    else:raise AssertionError('changed stage evidence accepted')
print(json.dumps({'status':'real-backup-prepare-activation-linked','negativeCases':6}))
`;
    const result=JSON.parse(execFileSync("python3",["-c",script,input],{encoding:"utf8",stdio:"pipe"}));
    assert.equal(result.status,"real-backup-prepare-activation-linked");
  });
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
