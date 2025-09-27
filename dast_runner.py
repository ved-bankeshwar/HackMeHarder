import os
import sys
import requests
from typing import List, Dict, Any, Optional

# Add the DAST directory to the Python path for module imports
#sys.path.append(os.path.join(os.path.dirname(__file__), 'DAST'))

try:
    from DAST.crawlers.index import crawl_site
    from DAST.attack_payload.attack_engine import perform_targeted_scan
    from DAST.analysis_engine.index import analyze_responses
except ImportError as e:
    print(f"[!] Error: Failed to import DAST modules. Make sure they are in the DAST/ directory. Details: {e}")
    sys.exit(1)

def run_dast(target_url: str, sast_findings: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """
    Executes a Dynamic Application Security Testing (DAST) scan on a target URL.

    This function orchestrates the DAST process:
    1. If SAST findings are provided, it runs a targeted DAST scan to confirm them.
    2. If no SAST findings are provided, it performs a broad scan:
        a. Crawls the website to discover pages and entry points.
        b. Launches a series of generic attacks against discovered points.
        c. Analyzes the responses for evidence of vulnerabilities.

    Args:
        target_url: The base URL of the web application to be tested.
        sast_findings: An optional list of dictionaries, each representing a SAST finding.

    Returns:
        A list of dictionaries, where each dictionary is a confirmed DAST vulnerability.
    """
    print(f"[*] Starting DAST scan for target: {target_url}")
    
    # Simple check to ensure the target URL is reachable
    try:
        response = requests.get(target_url, timeout=10, allow_redirects=True)
        if response.status_code >= 400:
            print(f"[!] Error: Target URL is unreachable. Status code: {response.status_code}")
            return []
    except requests.RequestException as e:
        print(f"[!] Error: Could not connect to target URL '{target_url}'. Details: {e}")
        return []

    if sast_findings:
        # --- Targeted Scan (Confirmation Mode) ---
        print("[*] SAST findings provided. Running in confirmation mode.")
        
        # In a real tool, this would involve complex logic to map SAST findings
        # (e.g., file path, line number) to live URL endpoints and parameters.
        # For this hackathon, we'll simulate this by passing findings to an attack engine.
        
        confirmed_vulns = perform_targeted_scan(target_url, sast_findings)
        
    else:
        # --- Broad Scan (Discovery Mode) ---
        print("[*] No SAST findings provided. Running in discovery mode.")
        
        # 1. Crawl the website to find links and forms
        print("[*] Step 1: Crawling the website...")
        discovered_endpoints = crawl_site(target_url)
        if not discovered_endpoints:
            print("[-] Crawler found no actionable endpoints. Halting scan.")
            return []
        print(f"[+] Crawler discovered {len(discovered_endpoints)} endpoints.")

        # 2. For this simplified version, we will pass endpoints to the attack engine.
        # A full implementation would have a more extensive attack phase here.
        print("[*] Step 2: Launching attacks (simulation)...")
        # In this context, we pass an empty list for sast_findings to signify discovery.
        attack_results = perform_targeted_scan(target_url, [])

        # 3. Analyze results
        print("[*] Step 3: Analyzing attack responses...")
        confirmed_vulns = analyze_responses(attack_results)

    if confirmed_vulns:
        print(f"[+] DAST scan complete. Found {len(confirmed_vulns)} confirmed vulnerabilities.")
    else:
        print("[-] DAST scan complete. No vulnerabilities confirmed.")
        
    return sorted(confirmed_vulns, key=lambda x: x.get('endpoint'))


if __name__ == '__main__':
    import json
    
    # This is a dummy test. A real DAST scan needs a running web application.
    print("[!] DAST Runner - Direct Execution Test Mode")
    
    # Example: To test this, you would need a vulnerable web app running.
    # For instance, a simple Flask app with an XSS vulnerability.
    TEST_TARGET = "http://127.0.0.1:5000" # Assume a local test app is running
    
    print(f"[*] Running a demo DAST scan on: {TEST_TARGET}")

    # To simulate the full SAST+DAST flow, you could run SAST first
    # and feed its output here. For now, we run a discovery scan.
    results = run_dast(TEST_TARGET)
    
    if results:
        print("\n--- DAST RUNNER TEST RESULTS ---")
        print(json.dumps(results, indent=2))
        print("----------------------------")
