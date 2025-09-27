import unittest
import os
import sys
import ast

# --- THE FIX: Adjust Python's Import Path ---
# This line finds the absolute path of the current test file.
# Then it goes up two directories (from /SAST/vul_app/ to /SAST/)
# and adds that SAST directory to the list of places Python looks for modules.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

# Now, these imports will work because Python knows to look in the SAST folder
from SAST import secrets_scanner
from SAST import vulnerability_scanner

# --- Preloaded Rules for a Self-Contained Test ---
MOCK_RULES = {
    'secret_rules': [
        {
            'id': 'aws-secret-access-key',
            'description': 'AWS Secret Access Key found',
            'severity': 'Critical',
            'regex': r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z\\/+]{40}['\"]"
        }
    ],
    'weak_crypto_rules': [
        {
            'id': 'weak-crypto-md5',
            'description': 'Use of weak hashing algorithm MD5.',
            'pattern': 'hashlib.md5',
            'severity': 'High'
        }
    ],
    'xss_rules': {
        'sources': ['request.args.get'],
        'sinks': ['render_template_string']
    },
    'path_traversal_rules': {
        'sources': ['request.args.get'],
        'sinks': ['open']
    },
    'unvalidated_redirect_rules': {
        'sources': ['request.args.get'],
        'sinks': ['redirect']
    },
    'xxe_rules': {
        'insecure': [
            {
                'id': 'xxe-lxml',
                'pattern': 'lxml.etree.parse',
                'description': 'lxml.etree.parse is vulnerable to XXE.',
                'severity': 'High'
            }
        ],
        'safe': []
    }
}


MOCK_VULNERABLE_CODE = """
import hashlib
import pickle
import os
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
        cls.all_rules = MOCK_RULES
        cls.vulnerable_filepath = 'test_vulnerable_code.py'
        with open(cls.vulnerable_filepath, 'w') as f:
            f.write(MOCK_VULNERABLE_CODE)
        with open(cls.vulnerable_filepath, 'r') as f:
            cls.vulnerable_tree = ast.parse(f.read(), filename=cls.vulnerable_filepath)

    @classmethod
    def tearDownClass(cls):
        os.remove(cls.vulnerable_filepath)

    def test_01_secret_scanner_regex(self):
        findings = secrets_scanner.scan_file_for_secrets(
            self.vulnerable_filepath, self.all_rules.get('secret_rules', [])
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['rule_id'], 'aws-secret-access-key')

    def test_02_weak_crypto_scanner(self):
        visitor = vulnerability_scanner.CodeVulnerabilityVisitor(
            self.vulnerable_filepath, self.all_rules.get('weak_crypto_rules', [])
        )
        visitor.visit(self.vulnerable_tree)
        self.assertEqual(len(visitor.findings), 1)
        self.assertEqual(visitor.findings[0]['rule_id'], 'weak-crypto-md5')

    def test_03_deserialization_scanner(self):
        analyzer = vulnerability_scanner.DeserializationAnalyzer(self.vulnerable_filepath)
        analyzer.visit(self.vulnerable_tree)
        self.assertEqual(len(analyzer.vulnerabilities), 1)
        self.assertEqual(analyzer.vulnerabilities[0]['type'], 'Insecure Deserialization')

    # Add other tests here...

if __name__ == '__main__':
    unittest.main()