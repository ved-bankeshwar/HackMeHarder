import os
import sys
import requests
from urllib.parse import urljoin

# Add project root to path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

# Import the SAST runner that provides DAST targets
try:
    from sast_runner import run_sast
except ImportError:
    print("Error: Could not import 'run_sast' from 'sast_runner.py'.")
    sys.exit(1)

# --- DAST Analysis Logic (from your provided code) ---

def is_vulnerable_to_sqli(response):
    """Checks for common SQL error messages in the response body."""
    sql_errors = [
        "you have an error in your sql syntax;", "warning: mysql_fetch_array()",
        "unclosed quotation mark after the character string", "quoted string not properly terminated",
        "sql command not properly ended", "oracle driver error", "microsoft ole db provider for odbc drivers error"
    ]
    response_text = response.text.lower()
    for error in sql_errors:
        if error in response_text:
            return (True, f"Detected SQL Error fingerprint: '{error}'")
    return (False, None)

def is_vulnerable_to_xss(response, payload):
    """Checks if a payload is reflected in the response without proper HTML escaping."""
    if payload in response.text:
        escaped_payload = payload.replace("<", "&lt;").replace(">", "&gt;")
        if escaped_payload in response.text:
            return (False, None)
        return (True, f"Payload '{payload}' was reflected in the response without proper escaping.")
    return (False, None)

def is_vulnerable_to_path_traversal(response):
    """Checks for content from sensitive system files."""
    sensitive_content_fingerprints = ["root:x:0:0", "[fonts]"]
    response_text = response.text
    for fingerprint in sensitive_content_fingerprints:
        if fingerprint in response_text:
            return (True, f"Detected sensitive file content: '{fingerprint}'")
    return (False, None)

def is_vulnerable_to_redirect(response, payload):
    """Checks if the application redirects to a URL containing the payload."""
    if response.is_redirect:
        location_header = response.headers.get('Location', '')
        if payload in location_header:
            return (True, f"Application redirected to a malicious URL: {location_header}")
    return (False, None)

# --- Payloads for different attack types ---
PAYLOADS = {
    "XSS": ["<script>alert('SAST_DAST_CONFIRMED')</script>"],
    "SQLi": ["' OR 1=1 --"],
    "PathTraversal": ["../../../../../../../../etc/passwd"],
    "UnvalidatedRedirect": ["http://evil-site.com/"]
}

# --- Main Correlation Function ---

def run_full_scan(directory: str, base_url: str):
    """
    Runs a full correlated scan:
    1. Runs SAST to identify potential vulnerabilities and entry points.
    2. Runs targeted DAST attacks using the integrated analysis engine to confirm them.
    """
    print("\n--- Starting Full Correlated Scan ---")

    # 1. Run SAST to get potential DAST targets
    dast_targets = run_sast(directory)

    if not dast_targets:
        print("\n[+] SAST found no potential targets for DAST confirmation.")
        return

    print(f"\n[*] SAST identified {len(dast_targets)} potential target(s) for DAST confirmation.")
    confirmed_vulnerabilities = []
    session = requests.Session()

    # 2. Iterate through targets and run DAST confirmation
    for target in dast_targets:
        vuln_type = target.get("type")
        relative_url = target.get("url")
        method = target.get("method", "GET").upper()
        param = target.get("param")
        sast_details = target.get("sast_details", {})

        if not all([vuln_type, relative_url, method, param]):
            continue

        payloads = PAYLOADS.get(vuln_type, [])
        if not payloads:
            continue
        
        target_url = urljoin(base_url, relative_url)
        print(f"\n--- Testing SAST Finding ---")
        print(f"  File: {sast_details.get('file', 'N/A')}, Line: {sast_details.get('line', 'N/A')}")
        print(f"  Type: {vuln_type}, Target: {method} {target_url}, Parameter: {param}")
        print("--------------------------")

        is_confirmed = False
        for payload in payloads:
            try:
                params, data = ({param: payload}, {}) if method == "GET" else ({}, {param: payload})
                response = session.request(method, target_url, params=params, data=data, timeout=5, allow_redirects=True)
                
                vulnerable, reason = (False, None)
                if vuln_type == "XSS":
                    vulnerable, reason = is_vulnerable_to_xss(response, payload)
                elif vuln_type == "SQLi":
                    vulnerable, reason = is_vulnerable_to_sqli(response)
                elif vuln_type == "PathTraversal":
                    vulnerable, reason = is_vulnerable_to_path_traversal(response)
                elif vuln_type == "UnvalidatedRedirect":
                    response_no_redirect = session.request(method, target_url, params=params, data=data, timeout=5, allow_redirects=False)
                    vulnerable, reason = is_vulnerable_to_redirect(response_no_redirect, payload)
                
                if vulnerable:
                    vuln_name = "Cross-Site Scripting" if vuln_type == "XSS" else vuln_type
                    print(f"[+] CONFIRMED: {vuln_name} is exploitable.")
                    print(f"    Reason: {reason}")
                    confirmed_vulnerabilities.append(target)
                    is_confirmed = True
                    break

            except requests.exceptions.RequestException as e:
                print(f"[!] DAST request failed for target {target_url}: {e}")
                break

        if not is_confirmed:
            print(f"[-] INFO: SAST finding of {vuln_type} could not be confirmed by DAST.")

    print("\n--- Correlated Scan Finished ---")

