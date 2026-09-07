"""Saved-test admission and post-restart replay, using only synthetic data."""
import copy
import hashlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import json
import subprocess
import unittest
from unittest import mock
from . import case_runtime_saved_adoption as saved
from . import case_runtime_bootstrap as core
from . import test_case_runtime_bootstrap as bootfixtures
from . import test_case_runtime_kubernetes as fixtures


def receipt():
    value={'schemaVersion':'public_synthetic_case_binding_receipt_v1','rootEventId':saved.ROOT_EVENT,'candidateEventId':saved.PROOF_EVENT,'participantSuggestionEventId':saved.SUGGESTION_EVENT,
        'topicId':'synthetic-fixture','candidateId':'fixture','sourceAnswerEventId':'1'*64,'caseId':'urn:stadtstack:synthetic-case:municipality:roebel-mueritz:01900000-0000-7000-8000-000000000000','caseVersion':1,'caseEventIds':['01900000-0000-7000-8000-000000000001'],
        'journalHeadChecksum':'sha256:'+'2'*64,'admissionEventChecksum':'sha256:'+'3'*64,'authorityBinding':'none','openDeskWrite':False,'candidateKind':'synthetic_citizen_adoption_tracer_v1','environment':'staging','testOnly':True,'civicCaseCreated':False,'syntheticCaseCreated':True,
        'adopterPubkey':'4'*64,'testPolicyVersion':'synthetic-fixture','adoptionAcceptanceReceiptChecksum':'sha256:'+'5'*64,'sourceAnswerReceiptId':'fixture','administrativeEndorsement':False,'bindingVote':False,'councilDecision':False,'treasuryEffect':False,'paymentEffect':False}
    value['receiptChecksum']=core.canonical_sha256(value)
    return value


class SavedAdoptionTests(unittest.TestCase):
    setUpClass=classmethod(bootfixtures.CaseBootstrapTests.setUpClass.__func__)
    environment=bootfixtures.CaseBootstrapTests.environment
    adapter_environment=fixtures.KubernetesTests.adapter_environment

    def setup_runtime(self):
        sink,_=self.environment();adapter,api=self.adapter_environment()
        core.run_bootstrap(self.root,adapter=adapter,sink=sink)
        return adapter,api,json.loads(sink.path.read_text())

    def test_admission_stays_synthetic_and_is_verified_after_restart(self):
        adapter,api,boot=self.setup_runtime();sink,_=self.environment();expected=receipt();calls=[]
        def execute(name,uid,component,bundle):
            calls.append(component)
            if component=='control':return copy.deepcopy(expected)
            return {'found':True,'receipt':copy.deepcopy(expected)} if 'control' in calls else {'found':False}
        api.exec_case_request=execute
        with mock.patch.object(saved,'BUNDLE_SHA256',hashlib.sha256(b'fixture').hexdigest()):
            result=saved.run_saved_adoption(adapter.plan,boot,b'fixture',adapter=adapter,sink=sink)
        self.assertEqual(result['status'],'saved-synthetic-case-publicly-verified')
        self.assertEqual(calls,['public','control','public'])
        self.assertEqual(result['restart']['exitCode'],0)

    def test_existing_receipt_does_not_send_another_admission(self):
        adapter,api,boot=self.setup_runtime();sink,_=self.environment();calls=[]
        def execute(name,uid,component,bundle):
            calls.append(component);return {'found':True,'receipt':receipt()}
        api.exec_case_request=execute
        with mock.patch.object(saved,'BUNDLE_SHA256',hashlib.sha256(b'fixture').hexdigest()):
            saved.run_saved_adoption(adapter.plan,boot,b'fixture',adapter=adapter,sink=sink)
        self.assertEqual(calls,['public','public'])

    def test_authority_claim_or_changed_receipt_is_rejected(self):
        for field,value in [('testOnly',False),('civicCaseCreated',True),('rootEventId','0'*64)]:
            result=receipt();result[field]=value
            with self.assertRaises(core.BootstrapStopped):saved.check_receipt(result)

    def test_saved_admission_cli_scope_requires_bundle_but_not_recovery_receipt(self):
        spec=importlib.util.spec_from_file_location('case_cli_scope',Path(__file__).with_name('run-case-runtime.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        args=SimpleNamespace(mode='admit-saved-test',configuration_fd=None,bundle_fd=5,prior_receipt=None,bootstrap_receipt='owned-bootstrap.json')
        module.validate_scope(args)
        args.configuration_fd=6
        with self.assertRaises(RuntimeError):module.validate_scope(args)
        args.configuration_fd=None;args.bootstrap_receipt=None
        with self.assertRaises(RuntimeError):module.validate_scope(args)

    def test_exact_pod_scripts_parse_as_modules(self):
        for script in (saved.ADMIT_JS,saved.READ_JS):
            result=subprocess.run(['node','--input-type=module','--check'],input=script,text=True,capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
