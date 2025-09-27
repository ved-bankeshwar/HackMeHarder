import unittest
import os
import sys
import ast
import yaml
import json  

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from SAST.vulnerability_scanner import CodeVulnerabilityVisitor, DeserializationAnalyzer
from SAST.secrets_scanner import scan_file_for_secrets

RULES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'rules.yaml'))
with open(RULES_PATH, 'r') as f:
    ALL_RULES = yaml.safe_load(f)

# --- Mock vulnerable code ---
MOCK_VULNERABLE_CODE = """
import hashlib
import pickle
from flask import request, render_template_string, redirect
from lxml import etree

aws_key = "AWS_KEY_AKIAIOSFODNN7EXAMPLE" # Regex match
random_key = "a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0" # High entropy

def weak_crypto():
    hashed_pass = hashlib.md5(b"password").hexdigest()

def insecure_deserialization(data):
    return pickle.load(data)

def xss_vulnerability():
    user_input = request.args.get('name')
    return render_template_string(f"<h1>Hello {user_input}</h1>")

def path_traversal_vulnerability():
    filename = request.args.get('file')
    with open(filename, 'r') as f:
        return f.read()

def unvalidated_redirect_vulnerability():
    target = request.args.get('url')
    return redirect(target)

def xxe_vulnerability(xml_file):
    return etree.parse(xml_file)
"""

class TestSastScanners(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.all_rules = ALL_RULES
        cls.vulnerable_filepath = os.path.join(os.path.dirname(__file__), 'test_vulnerable_code.py')
        with open(cls.vulnerable_filepath, 'w') as f:
            f.write(MOCK_VULNERABLE_CODE)
        with open(cls.vulnerable_filepath, 'r') as f:
            cls.vulnerable_tree = ast.parse(f.read(), filename=cls.vulnerable_filepath)

    @classmethod
    def tearDownClass(cls):
        os.remove(cls.vulnerable_filepath)

    def test_01_secret_scanner_regex(self):
        findings = scan_file_for_secrets(
            self.vulnerable_filepath, self.all_rules.get('secret_rules', [])
        )
        print("\n[SECRETS] findings:")
        print(json.dumps(findings, indent=2))
        self.assertTrue(len(findings) > 0)

    def test_02_weak_crypto_scanner(self):
        visitor = CodeVulnerabilityVisitor(
            self.vulnerable_filepath, self.all_rules.get('weak_crypto_rules', [])
        )
        visitor.visit(self.vulnerable_tree)
        print("\n[WEAK-CRYPTO] findings:")
        print(json.dumps(visitor.findings, indent=2))
        self.assertTrue(len(visitor.findings) > 0)

    def test_03_deserialization_scanner(self):
        analyzer = DeserializationAnalyzer(self.vulnerable_filepath)
        analyzer.visit(self.vulnerable_tree)
        print("\n[DESERIALIZATION] findings:")
        print(json.dumps(analyzer.vulnerabilities, indent=2))
        self.assertTrue(len(analyzer.vulnerabilities) > 0)

    def test_04_xss_scanner(self):
        xss_rules = []
        sources = self.all_rules.get('xss_rules', {}).get('sources', [])
        sinks = self.all_rules.get('xss_rules', {}).get('sinks', [])

        for source in sources:
            for sink in sinks:
                xss_rules.append({
                    'id': f"xss-{source}-{sink}",
                    'type': 'xss',
                    'source': source,
                    'sink': sink,
                    'description': f"Possible XSS from {source} to {sink}",
                    'severity': 'High'
                })

        visitor = CodeVulnerabilityVisitor(self.vulnerable_filepath, xss_rules)
        visitor.visit(self.vulnerable_tree)
        print("\n[XSS] findings:")
        print(json.dumps(visitor.findings, indent=2))
        self.assertTrue(len(visitor.findings) > 0)

    def test_05_path_traversal_scanner(self):
        pt_rules = self.all_rules.get('path_traversal_rules', {})
        visitor = CodeVulnerabilityVisitor(self.vulnerable_filepath, pt_rules)
        visitor.visit(self.vulnerable_tree)
        print("\n[PATH-TRAVERSAL] findings:")
        print(json.dumps(visitor.findings, indent=2))
        self.assertIsNotNone(visitor.findings)
