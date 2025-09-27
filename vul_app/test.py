import unittest
import os
import sys
import ast
import yaml
import json  
import re
from SAST.vulnerability_scanner import CodeVulnerabilityVisitor, DeserializationAnalyzer
from SAST.vulnerability_scanner import PathTraversalVisitor, scan_path_traversal_file as path_traversal_scan
from SAST.vulnerability_scanner import UnvalidatedRedirectVisitor, scan_unvalidated_redirect_file as unvalidated_redirect_scan


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

aws_key = "AWS_KEY_AKIAIOSFODNN7EXAMPLE"  # Secret regex match
random_key = "a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0"  # High entropy

def weak_crypto():
    hashed_pass = hashlib.md5(b"password").hexdigest()

def insecure_deserialization(data):
    return pickle.load(data)

def xss_vulnerability():
    return render_template_string(request.args.get('name'))

def path_traversal_vulnerability():
    return open(request.args.get('file')).read()

def unvalidated_redirect_vulnerability():
    return redirect(request.args.get('url'))

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
        xss_config = self.all_rules.get('xss_rules', {}) or {}
        explicit_rules = xss_config.get('rules', []) or []
        
        # Base XSS rule for our test
        xss_rules = [{
            "id": "xss-render-template-string",
            "type": "xss",
            "sink": "render_template_string",
            "node_type": "Call",
            "description": "XSS: Use of render_template_string can be dangerous with user input.",
            "severity": "High",
            # CORRECTED PATTERN: Simply look for the dangerous function call.
            "pattern": r"render_template_string\([^\)]*\)", 
            "match_type": "regex"
        }]

        # This part can remain if you need to load other rules from YAML
        for r in explicit_rules:
            if 'pattern' not in r:
                src = r.get('source', '')
                sink = r.get('sink', '')
                if src and sink:
                    r['pattern'] = rf"{src}\..*{sink}"
                else:
                    r['pattern'] = ".*" # fallback
            xss_rules.append(r)

        # Run visitor on vulnerable AST
        visitor = CodeVulnerabilityVisitor(self.vulnerable_filepath, xss_rules)
        visitor.visit(self.vulnerable_tree)
        
        print("\n[XSS] findings:")
        print(json.dumps(visitor.findings, indent=2))
        self.assertTrue(len(visitor.findings) > 0)


    def test_05_path_traversal_scanner(self):
        pt_rules = self.all_rules.get('taint_analysis_rules', {}).get('path_traversal', {})
        findings = path_traversal_scan(self.vulnerable_filepath, self.vulnerable_tree, pt_rules)
        print("\n[PATH-TRAVERSAL] findings:")
        print(json.dumps(findings, indent=2))
        self.assertTrue(len(findings) > 0)

    def test_06_xxe_scanner(self):
        xxe_rules = {
            "insecure": self.all_rules.get('insecure_parsing_rules', []),
            "safe": self.all_rules.get('safe_xml_modules', [])
        }
        findings = xxe_scan(self.vulnerable_filepath, self.vulnerable_tree, xxe_rules)
        print("\n[XXE] findings:")
        print(json.dumps(findings, indent=2))
        self.assertTrue(len(findings) > 0)

    def test_07_unvalidated_redirect_scanner(self):
        ur_rules = self.all_rules.get('taint_analysis_rules', {}).get('unvalidated_redirect', {})
        findings = unvalidated_redirect_scan(self.vulnerable_filepath, self.vulnerable_tree, ur_rules)
        print("\n[UNVALIDATED REDIRECT] findings:")
        print(json.dumps(findings, indent=2))
        self.assertTrue(len(findings) > 0)