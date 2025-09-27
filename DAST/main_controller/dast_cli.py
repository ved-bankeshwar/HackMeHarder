# DAST/main_controller/dast_cli.py
from DAST.crawlers.index import crawl
from DAST.attack_payload.attack_engine import send_malicious_requests
from DAST.attack_payload.payloads import PAYLOADS
from DAST.analysis_engine.index import (
    is_vulnerable_to_sqli,
    is_vulnerable_to_xss,
    is_vulnerable_to_path_traversal,
    is_vulnerable_to_redirect
)

from typing import List, Dict, Any, Tuple, Callable
from urllib.parse import urlparse
import os
import sys


project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)




def analyze_vulnerability(result: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Dynamically selects the correct analysis function based on result['vul_type'].
    Returns (is_vulnerable, reason).
    """
    vul_type = result.get('vul_type')
    response = result.get('response')
    payload = result.get('payload')

    analysis_functions: Dict[str, Callable[..., Tuple[bool, str]]] = {
        "SQLi": is_vulnerable_to_sqli,
        "XSS": lambda r, p: is_vulnerable_to_xss(r, p),
        "PathTraversal": is_vulnerable_to_path_traversal,
        "UnvalidatedRedirect": lambda r, p: is_vulnerable_to_redirect(r, p),
    }

    analyzer = analysis_functions.get(vul_type)
    if not analyzer:
        return False, "No analysis function defined for this vulnerability type."

  
    if vul_type in ["XSS", "UnvalidatedRedirect"]:
        return analyzer(response, payload)
    else:
        return analyzer(response)

def run_dast(target_url: str) -> List[Dict[str, Any]]:
    """
    Programmatic entrypoint for DAST scanning.
    - target_url: full URL with scheme (http/https)
    Returns: list of vulnerability dicts (empty if none)
    """
    print("--- DAST Scan Starting ---")
    print(f" Target: {target_url}")
    print("--------------------------\n")

    # Step 1: discover endpoints
    attackable_targets = crawl(target_url)
    if not attackable_targets:
        print("[!] No attackable form endpoints found. Exiting.")
        return []

    vulnerability_checks = list(PAYLOADS.keys())
    vulnerabilities_found: List[Dict[str, Any]] = []

    parsed_uri = urlparse(target_url)
    base_domain = f"{parsed_uri.scheme}://{parsed_uri.netloc}"

    # Step 2: iterate endpoints and vulnerability types
    for target in attackable_targets:
        for vul_type in vulnerability_checks:
            attack_results = send_malicious_requests(target, vul_type, base_domain=base_domain)

            # Step 3: analyze each attack result
            for result in attack_results:
                is_vuln, reason = analyze_vulnerability(result)

                if is_vuln:
                    print(f"  [+] VULNERABILITY CONFIRMED: {vul_type} at {result.get('target_url')}")
                    vulnerabilities_found.append({
                        'type': vul_type,
                        'url': result.get('target_url'),
                        'param': result.get('target_param'),
                        'payload': result.get('payload'),
                        'reason': reason
                    })

    print("\n--- Scan Complete ---")
    if vulnerabilities_found:
        print(f" VULNERABILITIES FOUND ({len(vulnerabilities_found)}) ")
        for vul in vulnerabilities_found:
            print("---------------------------------")
            print(f"Vulnerability: {vul['type']}")
            print(f"URL: {vul['url']}")
            print(f"Parameter: {vul['param']}")
            print(f"Payload Used: {vul['payload']}")
            print(f"Reason: {vul['reason']}")
            print("---------------------------------")
    else:
        print(" No vulnerabilities detected. The application appears secure.")

    return vulnerabilities_found

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Lightweight DAST CLI for web application security.")
    parser.add_argument("--url", type=str, required=True, help="The target URL to scan (e.g., http://testphp.vulnweb.com/).")
    args = parser.parse_args()
    run_dast(args.url)

if __name__ == '__main__':
    main()
