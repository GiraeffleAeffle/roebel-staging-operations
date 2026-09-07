"""Check the inactive review boundary and actual init script with disposable files."""

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


policy = load("case_proposal_test_policy", "synthetic_case_runtime.py")
verifier = load("case_proposal_test_verifier", "verify-reviewed-render.py")

# Run the exact manifest command on real disposable files. Only absolute mount
# paths and the host's UID/GID are mapped; Kubernetes mount validation is not
# claimed by this local rehearsal. No actual credential is used.
INIT_HARNESS = r"""
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const vm = require('node:vm'), crypto = require('node:crypto'), assert = require('node:assert/strict');
// Own the disposable fixture's file-creation mode.
process.umask(0o077);
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'case-init-rehearsal-'));
const roots = {'/var/lib/stadtstack': temporary+'/state', '/reviewed': temporary+'/reviewed', '/run/stadtstack-control': temporary+'/run'};
const map = value => typeof value === 'string' ? Object.entries(roots).reduce((p,[from,to]) => p === from || p.startsWith(from+'/') ? to+p.slice(from.length) : p, value) : value;
const state = temporary+'/state/case-control', privateDir = temporary+'/run/private';
const marker = state+'/.stadtstack-control-storage-v1.json', config = privateDir+'/application.json';
// macOS temporary directories inherit their parent's group, which may differ
// from process.getgid(). Map the fixture's real ownership to the container IDs.
const fixtureOwner = fs.statSync(temporary);
const actualUid = fixtureOwner.uid, actualGid = fixtureOwner.gid;
// Model Linux setgid inheritance explicitly: macOS may clear this directory bit.
let inheritedSetgid = ['inherited-setgid','prior-setgid'].includes(input.scenario);
const mappedFs = new Proxy(fs, {get(target, key) {
  if (key === 'lstatSync' || key === 'fstatSync') return p => {
    const st = fs[key](map(p));
    return Object.assign(Object.create(Object.getPrototypeOf(st)), st, {
      uid: st.uid === actualUid ? 1000 : st.uid, gid: st.gid === actualGid ? 1000 : st.gid,
      mode: st.mode | (inheritedSetgid && fs.existsSync(privateDir) && st.ino === fs.lstatSync(privateDir).ino ? 0o2000 : 0),
    });
  };
  if (key === 'fchmodSync') return (fd,mode) => {
    assert.equal(fs.fstatSync(fd).ino,fs.lstatSync(privateDir).ino);
    assert.equal(mode,0o700); fs.fchmodSync(fd,mode); inheritedSetgid=false;
  };
  return typeof target[key] === 'function' ? (...args) => target[key](...args.map(map)) : target[key];
}});
const raw = JSON.stringify({testConfiguration: 'synthetic-only-no-credential'});
function run(value=raw, digest=crypto.createHash('sha256').update(value).digest('hex')) {
  const env = {ROEBEL_CASE_PRIVATE_CONFIG: value, ROEBEL_CASE_PRIVATE_CONFIG_SHA256: digest};
  try { vm.runInNewContext(input.script, {require: name => name === 'node:fs' ? mappedFs : require(name), process:{env}, Buffer}, {timeout:2000}); }
  finally { if (input.scenario !== 'old-retry') assert.equal(env.ROEBEL_CASE_PRIVATE_CONFIG, undefined); }
}
try {
  for (const p of Object.values(roots)) fs.mkdirSync(p);
  fs.mkdirSync(state, {mode:0o700});
  fs.writeFileSync(temporary+'/reviewed/storage-marker.json', input.marker);
  if (['retry','old-retry','changed-config','broad-config','symlink-config','hardlink-config'].includes(input.scenario)) run();
  if (input.scenario === 'retry' || input.scenario === 'old-retry') {
    const before = [fs.statSync(config).mtimeMs,fs.statSync(marker).mtimeMs];
    if (input.scenario === 'old-retry') assert.throws(() => run(), /EEXIST/);
    else { run(); assert.equal(fs.readFileSync(config,'utf8'),raw); assert.deepEqual([fs.statSync(config).mtimeMs,fs.statSync(marker).mtimeMs],before); }
  } else if (input.scenario === 'invalid-digest' || input.scenario === 'invalid-json' || input.scenario === 'invalid-shape') {
    assert.throws(() => input.scenario === 'invalid-digest' ? run(raw,'0'.repeat(64)) : run(input.scenario === 'invalid-json' ? 'not-json' : '[]'), /private_configuration_invalid/);
    assert.equal(fs.existsSync(marker),false); assert.equal(fs.existsSync(privateDir),false);
  } else if (input.scenario === 'inherited-setgid' || input.scenario === 'prior-setgid') {
    if (input.scenario === 'prior-setgid') { fs.mkdirSync(privateDir,{mode:0o700}); fs.chmodSync(privateDir,0o2700); }
    run(); assert.equal(inheritedSetgid,false); assert.equal(fs.statSync(privateDir).mode & 0o7777,0o700);
    assert.equal(fs.statSync(config).mode & 0o7777,0o600);
    assert.equal(fs.readFileSync(config,'utf8'),raw); run();
  } else if (input.scenario === 'broad-directory' || input.scenario === 'symlink-directory') {
    if (input.scenario === 'broad-directory') { fs.mkdirSync(privateDir); fs.chmodSync(privateDir,0o2750); }
    else { fs.mkdirSync(temporary+'/other'); fs.symlinkSync(temporary+'/other',privateDir); }
    assert.throws(() => run(),/private_configuration_directory_invalid/);
    assert.equal(fs.existsSync(config),false);
  } else if (input.scenario === 'partial-directory') {
    fs.mkdirSync(privateDir,{mode:0o700}); run(); assert.equal(fs.readFileSync(config,'utf8'),raw);
  } else if (input.scenario === 'changed-config') {
    fs.writeFileSync(config,'changed'); assert.throws(() => run(),/private_configuration_retry_invalid/); assert.equal(fs.readFileSync(config,'utf8'),'changed');
  } else if (input.scenario === 'broad-config') {
    fs.chmodSync(config,0o644); assert.throws(() => run(),/private_configuration_retry_invalid/); assert.equal(fs.statSync(config).mode & 0o777,0o644);
  } else if (input.scenario === 'symlink-config' || input.scenario === 'hardlink-config') {
    const other = temporary+'/other';
    if (input.scenario === 'symlink-config') { fs.renameSync(config,other); fs.symlinkSync(other,config); }
    else fs.linkSync(config,other);
    assert.throws(() => run(),/private_configuration_retry_invalid/); assert.equal(fs.readFileSync(other,'utf8'),raw);
  } else if (input.scenario === 'unmarked-data') {
    fs.writeFileSync(state+'/prior-store','preserve'); assert.throws(() => run(),/storage_bootstrap_not_empty/); assert.equal(fs.existsSync(marker),false);
  } else if (input.scenario === 'changed-marker') {
    fs.writeFileSync(marker,'changed',{mode:0o600}); assert.throws(() => run(),/storage_marker_invalid/); assert.equal(fs.readFileSync(marker,'utf8'),'changed');
  } else if (input.scenario === 'broad-root') {
    fs.chmodSync(state,0o750); assert.throws(() => run(),/storage_identity_invalid/); assert.equal(fs.existsSync(marker),false);
  } else throw Error('unknown rehearsal scenario');
  process.stdout.write(JSON.stringify({scenario:input.scenario,status:'passed'})+'\n');
} finally {fs.rmSync(temporary,{recursive:true,force:true});}
"""


class SyntheticCaseProposalTests(unittest.TestCase):
    def candidate(self):
        temporary = tempfile.TemporaryDirectory(prefix="case-proposal-data-")
        self.addCleanup(temporary.cleanup)
        candidate = Path(temporary.name)
        shutil.copytree(ROOT, candidate, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns('.git', '__pycache__', '*.pyc'))
        return candidate

    def test_reviewed_bundle_is_complete_and_runtime_activation_remains_blocked(self):
        records = policy.verify_proposal(verifier, ROOT)
        self.assertFalse(records["proposal.json"]["fluxReconciliation"])
        self.assertFalse(records["proposal.json"]["restoreActivation"])
        self.assertEqual(len(records["resources.json"]["items"]),15)

    def test_candidate_cannot_reauthorize_a_changed_image_with_its_own_hash(self):
        candidate = self.candidate()
        path = candidate / policy.ROOT / "resources.json"
        path.write_bytes(path.read_bytes().replace(b'sha256:0c074f77', b'sha256:1c074f77'))
        proposal = candidate / policy.ROOT / "proposal.json"
        value = json.loads(proposal.read_text())
        value["artifacts"]["resources.json"] = 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()
        proposal.write_text(json.dumps(value))
        with self.assertRaisesRegex(verifier.VerificationError, "protected pin mismatch"):
            verifier.verify_tree(candidate)

    def test_partial_or_symlinked_bundle_is_rejected(self):
        candidate = self.candidate()
        path = candidate / policy.ROOT / "control-binding.json"
        path.unlink()
        with self.assertRaises(verifier.VerificationError): verifier.verify_tree(candidate)
        path.symlink_to(ROOT / policy.ROOT / "control-binding.json")
        with self.assertRaisesRegex(verifier.VerificationError,"symlink|regular files"): verifier.verify_tree(candidate)

    def test_transition_rejects_candidate_policy_code_without_executing_it(self):
        base, candidate = self.candidate(), self.candidate()
        (candidate/'scripts/synthetic_case_runtime.py').write_text("raise RuntimeError('must never execute candidate policy')")
        with self.assertRaisesRegex(verifier.VerificationError,"protected Case proposal"):
            verifier.verify_transition(verifier.verify_tree(candidate),verifier.verify_tree(base))

    def test_transition_preserves_an_identical_bundle(self):
        policy.verify_transition(verifier,self.candidate(),self.candidate())


class SyntheticCaseInitializerTests(unittest.TestCase):
    def test_exact_init_command_handles_retry_and_rejects_unsafe_state(self):
        items=json.loads((ROOT / policy.ROOT / 'resources.json').read_text())['items']
        deployment=next(o for o in items if o['kind']=='Deployment' and o['metadata']['name']=='roebel-case-steward-control')
        script=deployment['spec']['template']['spec']['initContainers'][0]['command'][2]
        marker=next(o for o in items if o['kind']=='ConfigMap' and o['metadata']['name']=='roebel-case-steward-control-reviewed')['data']['storage-marker.json']
        scenarios=('inherited-setgid','prior-setgid','broad-directory','symlink-directory','retry','partial-directory','invalid-digest','invalid-json','invalid-shape','changed-config','broad-config','symlink-config','hardlink-config','unmarked-data','changed-marker','broad-root')
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                result=subprocess.run(['node','-e',INIT_HARNESS],input=json.dumps({'script':script,'marker':marker,'scenario':scenario}),text=True,capture_output=True,timeout=10)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(json.loads(result.stdout)['status'],'passed')


if __name__ == '__main__':
    unittest.main()
