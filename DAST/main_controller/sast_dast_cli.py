import os
import sys
import json
import argparse
from urllib.parse import urlparse
from typing import List, Dict, Any, Tuple, Callable

# Add the project root to the Python path to allow for absolute imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, project_root)

# --- Import the actual modules from your project structure ---
from DAST.crawlers.index import crawl
from DAST.attack_payload.attack_engine import send_malicious_requests
from DAST.attack_payload.payloads import PAYLOADS
from DAST.analysis_engine.index import (
    is_vulnerable_to_sqli,
    is_vulnerable_to_xss,
    is_vulnerable_to_path_traversal,
    is_vulnerable_to_redirect,
    is_vulnerable_to_cmd_injection  # Added support for Command Injection
)

# --- SAST Integration ---
# This assumes your SAST tool's entry point is a function in SAST/SAST_check.py
# The function should accept a source code path and return a list of vulnerability dictionaries.
try:
    # Correctly importing the 'sast_check' function and aliasing it.
    from SAST_check import sast_check as run_sast_scan
except ImportError:
    print("[!] Warning: SAST module could not be imported. The --hybrid-scan feature will not work.")
    print("    Please ensure your SAST tool has a callable 'sast_check' function in SAST/SAST_check.py.")
    run_sast_scan = None

# --- Vulnerability Type Mapping ---
# Maps verbose SAST types to the internal DAST types.
SAST_TO_DAST_TYPE_MAPPING = {
    "SQL Injection": "SQLi",
    "Cross-Site Scripting": "XSS",
    "Path Traversal": "PathTraversal",
    "Unvalidated Redirect": "UnvalidatedRedirect",
    "Command Injection": "CommandInjection",
}

def normalize_sast_finding_type(sast_type: str) -> str:
    """Normalizes the vulnerability type from SAST output to a DAST-compatible type."""
    return SAST_TO_DAST_TYPE_MAPPING.get(sast_type, sast_type)


def analyze_vulnerability(result: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Dynamically selects the correct analysis function based on the vulnerability type.
    """
    vul_type = result['vul_type']
    response = result['response']
    payload = result['payload']

    analysis_functions: Dict[str, Callable[..., Tuple[bool, str]]] = {
        "SQLi": is_vulnerable_to_sqli,
        "XSS": lambda r, p: is_vulnerable_to_xss(r, p),
        "PathTraversal": is_vulnerable_to_path_traversal,
        "UnvalidatedRedirect": lambda r, p: is_vulnerable_to_redirect(r, p),
        "CommandInjection": is_vulnerable_to_cmd_injection,  # Added handler
    }

    analyzer = analysis_functions.get(vul_type)
    if not analyzer:
        return False, "No analysis function defined for this vulnerability type."

    # Call analyzer based on its required arguments
    if vul_type in ["XSS", "UnvalidatedRedirect"]:
        return analyzer(response, payload)
    else:
        return analyzer(response)


def run_full_scan(target_url: str):
    """
    Runs a comprehensive DAST scan by crawling and attacking all found endpoints.
    """
    print("--- DAST Full Scan Starting ---")
    print(f"🎯 Target: {target_url}")
    print("--------------------------\n")

    attackable_targets = crawl(target_url)
    if not attackable_targets:
        print("[!] No attackable form endpoints found. Exiting.")
        return

    vulnerability_checks = list(PAYLOADS.keys())
    vulnerabilities_found = []
    parsed_uri = urlparse(target_url)
    base_domain = f"{parsed_uri.scheme}://{parsed_uri.netloc}"

    for target in attackable_targets:
        for vul_type in vulnerability_checks:
            attack_results = send_malicious_requests(target, vul_type, base_domain=base_domain)
            for result in attack_results:
                is_vuln, reason = analyze_vulnerability(result)
                if is_vuln:
                    print(f"  [+] VULNERABILITY CONFIRMED: {vul_type} at {result['target_url']}")
                    vulnerabilities_found.append({
                        'type': vul_type,
                        'url': result['target_url'],
                        'param': result['target_param'],
                        'payload': result['payload'],
                        'reason': reason
                    })
    print_report(vulnerabilities_found)


def run_sast_confirmation_scan(sast_findings: List[Dict[str, Any]], base_domain: str):
    """
    Runs a targeted DAST scan to confirm findings from a SAST report.
    """
    print("--- DAST Confirmation Scan Starting ---")
    print(f"[*] Confirming {len(sast_findings)} vulnerabilities reported by SAST.")
    print(f"[*] Targeting application at: {base_domain}")
    print("---------------------------------------\n")
    
    confirmed_vulnerabilities = []

    for finding in sast_findings:
        sast_vul_type = finding.get("type")
        # Normalize the type to match DAST's internal naming
        vul_type = normalize_sast_finding_type(sast_vul_type)
        
        target_url = finding.get("url")
        method = finding.get("method")
        param = finding.get("param")

        if not all([vul_type, sast_vul_type, target_url, method, param]):
            print(f"[-] Skipping invalid SAST finding due to missing data: {finding}")
            continue
        
        target_for_dast = {'url': target_url, 'method': method, 'params': [param]}
        
        print(f"[*] Attempting to confirm '{sast_vul_type}' at {method} {target_url} with param '{param}'...")

        attack_results = send_malicious_requests(target_for_dast, vul_type, base_domain=base_domain)
        
        is_confirmed = False
        for result in attack_results:
            is_vuln, reason = analyze_vulnerability(result)
            if is_vuln:
                print(f"  [+] CONFIRMED: {sast_vul_type} vulnerability at {result['target_url']}")
                confirmed_vulnerabilities.append({
                    'type': sast_vul_type,  # Report with the original SAST name
                    'url': result['target_url'],
                    'param': result['target_param'],
                    'payload': result['payload'],
                    'reason': reason,
                    'sast_details': finding.get('sast_details', {})
                })
                is_confirmed = True
                break
        
        if not is_confirmed:
            print(f"  [-] NOT CONFIRMED: SAST finding for {sast_vul_type} at {target_url} appears to be a false positive.")

    print_report(confirmed_vulnerabilities, is_confirmation=True)


def load_sast_results_from_file(file_path: str) -> List[Dict[str, Any]]:
    """Loads and parses SAST results from a JSON file."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[!] Error: SAST results file not found at '{file_path}'.")
    except json.JSONDecodeError:
        print(f"[!] Error: Could not parse JSON from '{file_path}'. Please check the file format.")
    return []


def print_report(vulnerabilities: List[Dict[str, Any]], is_confirmation: bool = False):
    """
    Prints a clean, final report of all vulnerabilities found.
    """
    scan_type = "Confirmation" if is_confirmation else "Full"
    
    print(f"\n--- {scan_type} Scan Complete ---")
    if vulnerabilities:
        title = "CONFIRMED VULNERABILITIES" if is_confirmation else "VULNERABILITIES FOUND"
        print(f"🎉 {title} ({len(vulnerabilities)}) 🎉")
        for vul in vulnerabilities:
            print("---------------------------------")
            print(f"Vulnerability: {vul['type']}")
            print(f"URL: {vul['url']}")
            print(f"Parameter: {vul['param']}")
            print(f"Payload Used: {vul['payload']}")
            print(f"Reason: {vul['reason']}")
            if 'sast_details' in vul and vul['sast_details']:
                sast = vul['sast_details']
                print(f"SAST Origin: {sast.get('file')}, Line: {sast.get('line')}")
        print("---------------------------------")
    else:
        message = "No SAST findings could be confirmed." if is_confirmation else "No vulnerabilities detected."
        print(f"✅ {message}")


def main():
    """
    The main DAST CLI controller. Orchestrates the entire scanning process.
    """
    parser = argparse.ArgumentParser(description="🚀 SAST+DAST Hybrid Security Scanner.")
    parser.add_argument("--url", type=str, required=True, help="The target base URL to scan (e.g., http://127.0.0.1:5000).")
    
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--full-scan", action='store_true', help="Run a full, unguided DAST scan (crawl and attack).")
    mode.add_argument("--sast-confirm", type=str, metavar="FILE_PATH", help="Path to a SAST results JSON file to confirm vulnerabilities.")
    mode.add_argument("--hybrid-scan", type=str, metavar="SOURCE_PATH", help="Run SAST on a source directory, then confirm findings with DAST.")
    
    args = parser.parse_args()
    target_url = args.url

    # --- Start Scan ---
    if args.full_scan:
        run_full_scan(target_url)
    elif args.sast_confirm:
        sast_findings = load_sast_results_from_file(args.sast_confirm)
        if sast_findings:
            run_sast_confirmation_scan(sast_findings, base_domain=target_url)
    elif args.hybrid_scan:
        if not run_sast_scan:
            print("[!] Cannot run hybrid scan because the SAST module is not available.")
            return
        
        print("--- Starting Hybrid Scan ---")
        print("[1/2] Running SAST on source code...")
        sast_findings = run_sast_scan(args.hybrid_scan)
        
        if not sast_findings:
            print("[*] SAST scan completed. No potential vulnerabilities found to confirm.")
            return
            
        print("\n[2/2] SAST scan complete. Passing findings to DAST for confirmation...")
        run_sast_confirmation_scan(sast_findings, base_domain=target_url)

if __name__ == '__main__':
    main()

