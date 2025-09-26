import os
import sys

import argparse
from urllib.parse import urlparse
from typing import List, Dict, Any, Tuple, Callable
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, project_root)

# --- Import the actual modules from your project structure ---
# Member 1's Crawler
from DAST.crawlers.index import crawl

# Member 2's Attack Engine and Payloads
from DAST.attack_payload.attack_engine import send_malicious_requests
from DAST.attack_payload.payloads import PAYLOADS

# Member 3's Analysis Engine
from DAST.analysis_engine.index import (
    is_vulnerable_to_sqli,
    is_vulnerable_to_xss,
    is_vulnerable_to_path_traversal,
    is_vulnerable_to_redirect
)

def analyze_vulnerability(result: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Dynamically selects the correct analysis function based on the vulnerability type.
    This acts as a bridge to the analysis engine (Member 3's work).

    Args:
        result: A dictionary containing the response, payload, and vulnerability type.

    Returns:
        A tuple (is_vulnerable, reason).
    """
    vul_type = result['vul_type']
    response = result['response']
    payload = result['payload']

    # --- Mapping from vulnerability type string to the correct analysis function ---
    analysis_functions: Dict[str, Callable[..., Tuple[bool, str]]] = {
        "SQLi": is_vulnerable_to_sqli,
        "XSS": lambda r, p: is_vulnerable_to_xss(r, p), # Use lambda to match signature
        "PathTraversal": is_vulnerable_to_path_traversal,
        "UnvalidatedRedirect": lambda r, p: is_vulnerable_to_redirect(r, p)
    }

    # Get the specific analysis function for the current vulnerability type
    analyzer = analysis_functions.get(vul_type)

    if not analyzer:
        return False, "No analysis function defined for this vulnerability type."

    # Some functions need the payload, some don't. We call them accordingly.
    if vul_type in ["XSS", "UnvalidatedRedirect"]:
        return analyzer(response, payload)
    else:
        # The functions for SQLi and Path Traversal only need the response object.
        return analyzer(response)


def main():
    """
    The main DAST CLI controller. Orchestrates the entire scanning process.
    """
    parser = argparse.ArgumentParser(description="🚀 Lightweight DAST CLI for web application security.")
    parser.add_argument("--url", type=str, required=True, help="The target URL to scan (e.g., http://testphp.vulnweb.com/).")

    args = parser.parse_args()
    target_url = args.url

    # --- Start Scan ---
    print(f"--- DAST Scan Starting ---")
    print(f"🎯 Target: {target_url}")
    print("--------------------------\n")

    # Step 1: Call the Crawler (Member 1) to discover attack surfaces
    attackable_targets = crawl(target_url)

    if not attackable_targets:
        print("[!] No attackable form endpoints found. Exiting.")
        return

    vulnerability_checks = list(PAYLOADS.keys())
    vulnerabilities_found = []

    # Step 2: Loop through each discovered target and each vulnerability type
    for target in attackable_targets:
        for vul_type in vulnerability_checks:

            # Step 3: Call the Attack Engine (Member 2) to send malicious requests
            # The base_domain is derived from the initial target URL
            parsed_uri = urlparse(target_url)
            base_domain = f"{parsed_uri.scheme}://{parsed_uri.netloc}"
            attack_results = send_malicious_requests(target, vul_type, base_domain=base_domain)

            # Step 4: Pass each result to the integrated Analysis Engine (Member 3)
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

    # Step 5: Print a clean, final report
    print("\n--- Scan Complete ---")
    if vulnerabilities_found:
        print(f"🎉 VULNERABILITIES FOUND ({len(vulnerabilities_found)}) 🎉")
        for vul in vulnerabilities_found:
            print("---------------------------------")
            print(f"Vulnerability: {vul['type']}")
            print(f"URL: {vul['url']}")
            print(f"Parameter: {vul['param']}")
            print(f"Payload Used: {vul['payload']}")
            print(f"Reason: {vul['reason']}")
        print("---------------------------------")
    else:
        print("✅ No vulnerabilities detected. The application appears secure.")


if __name__ == '__main__':
    main()