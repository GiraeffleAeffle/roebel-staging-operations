"""Pinned private configuration provisioning without real credentials."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from . import test_case_runtime_kubernetes as fixtures
from . import test_case_runtime_bootstrap as bootfixtures
from . import case_runtime_bootstrap as core
from . import case_runtime_configuration as config


class ConfigurationTests(unittest.TestCase):
    setUpClass=classmethod(bootfixtures.CaseBootstrapTests.setUpClass.__func__)
    environment=bootfixtures.CaseBootstrapTests.environment
    adapter_environment=fixtures.KubernetesTests.adapter_environment

    def provision(self,adapter,sink,raw=b'synthetic-fixture'):
        with tempfile.TemporaryFile() as stream:
            os.fchmod(stream.fileno(),0o600);stream.write(raw);stream.flush()
            return config.provision_configuration(adapter.plan,stream.fileno(),adapter=adapter,sink=sink)

    def test_pinned_configuration_created_once_and_values_never_in_receipt(self):
        adapter,api=self.adapter_environment();api.objects.pop(api.secret_path)
        sink,_=self.environment()
        result=self.provision(adapter,sink)
        self.assertEqual(result['status'],'provisioned')
        self.assertTrue(result['uid'])
        self.assertEqual(len([c for c in api.calls if c[0]=='POST']),1)
        self.assertNotIn('synthetic-fixture',sink.path.read_text())
        self.assertNotIn('data',json.loads(sink.path.read_text()))

    def test_changed_bytes_and_existing_secret_are_never_written(self):
        for fault in ('bytes','exists'):
            with self.subTest(fault=fault):
                adapter,api=self.adapter_environment();sink,_=self.environment()
                with self.assertRaises(core.BootstrapStopped):self.provision(adapter,sink,b'wrong' if fault=='bytes' else b'synthetic-fixture')
                self.assertFalse(any(c[0]=='POST' for c in api.calls))

    def test_lost_success_response_is_bound_without_second_create(self):
        adapter,api=self.adapter_environment();api.objects.pop(api.secret_path);sink,_=self.environment()
        request=api.request
        def timeout(method,path,payload):
            result=request(method,path,payload)
            if method=='POST':raise TimeoutError('private server output')
            return result
        api.request=timeout
        self.assertEqual(self.provision(adapter,sink)['status'],'provisioned')
        self.assertEqual(len([c for c in api.calls if c[0]=='POST']),1)
        self.assertNotIn('private server output',sink.path.read_text())
