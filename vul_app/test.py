# test.py: A deliberately vulnerable Flask application for testing the SAST scanner.

import os
import pickle
import hashlib
import subprocess
from flask import Flask, request, redirect
from markupsafe import Markup
import xml.etree.ElementTree as ET
# The defusedxml import has been removed.

# A mock database cursor for the SQLi example
class MockCursor:
    def execute(self, query): print(f"Executing: {query}")
db_cursor = MockCursor()

app = Flask(__name__)

# === 1. Hardcoded Secrets (Regex/Entropy Scanner) ===
# This should be found by your regex rules
GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz1234567890" 
SLACK_TOKEN = "xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx"

# This should be found by your entropy scanner
GENERIC_HIGH_ENTROPY_KEY = "80d2556b-4f79-459f-a864-46a2a6b472e9-a447a126"

# === 2. Command Injection (Taint Analysis) ===
@app.route('/command')
def command_injection():
    hostname = request.args.get('host') # Source
    os.system(f"ping -c 1 {hostname}")   # Sink
    return "Pinged."

# === 3. SQL Injection (Taint Analysis) ===
@app.route('/users')
def sql_injection():
    user_id = request.args.get('id') # Source
    db_cursor.execute(f"SELECT * FROM users WHERE id = {user_id}") # Sink
    return "User data."

# === 4. Path Traversal (Taint Analysis) ===
@app.route('/files')
def path_traversal():
    filename = request.args.get('file') # Source
    with open(filename, 'r') as f:      # Sink
        return f.read()

# === 5. Cross-Site Scripting (XSS) (Taint Analysis) ===
@app.route('/search')
def cross_site_scripting():
    query = request.args.get('q')           # Source
    return Markup(f"<h1>Results: {query}</h1>") # Sink

# === 6. Unvalidated Redirect (Taint Analysis) ===
@app.route('/redirect')
def unvalidated_redirect():
    target_url = request.args.get('url') # Source
    return redirect(target_url)          # Sink

# === 7. Weak Cryptography (Pattern Matching) ===
def get_weak_user_hash(data):
    # This call should be flagged by your pattern scanner
    return hashlib.md5(data.encode()).hexdigest()

# === 8. Insecure Deserialization (Pattern Matching) ===
@app.route('/deserialize')
def insecure_deserialization():
    data = request.args.get('data')
    # This call should be flagged
    return pickle.loads(data)

# === 9. XML External Entity - XXE (Pattern Matching) ===
def process_xxe(xml_string):
    # This call should be flagged as it uses the unsafe standard library
    root = ET.fromstring(xml_string)
    return "Processed."

# === 10. SAFE Code (To test for false positives) ===
def this_is_a_safe_function_md5():
    # Your advanced AST scanner should know this is NOT hashlib.md5
    print("This is a safe, user-defined function.")

# NOTE: Commenting out this function because it depends on the 'defusedxml' library.
# This was the test case for your safelist feature.
# def safe_xml_parsing(xml_string):
#     root = SafeET.fromstring(xml_string)
#     return "Safely processed."

if __name__ == '__main__':
    print("This is a test file for SAST scanning.")