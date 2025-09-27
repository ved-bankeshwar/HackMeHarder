# dast_runner.py

import sys
import os
import requests

# Adjust path to import from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    # --- FIX: Import the Crawler CLASS, not the old 'crawl' function ---
    from DAST.crawlers.index import Crawler
    from DAST.attack_payload.attack_engine import AttackEngine
    from DAST.analysis_engine.index import analyze_response
except ImportError as e:
    print(f"[!] Error: Failed to import DAST modules. Make sure they are in the DAST/ directory. Details: {e}")
    sys.exit(1)

def run_dast(target_url, sast_findings=None):
    """
    Runs the DAST scan.
    - If sast_findings is None, runs in discovery mode.
    - If sast_findings is provided, runs in targeted confirmation mode.
    """
    print(f"[*] Starting DAST scan for target: {target_url}")
    vulnerabilities_found = []

    # --- FIX: Instantiate and run the new Crawler class ---
    if not sast_findings:
        print("[*] No SAST findings provided. Running in discovery mode.")
        print("[*] Step 1: Crawling the website...")
        
        crawler = Crawler(target_url)
        endpoints = crawler.run() # This now returns all discovered links

        if not endpoints:
            print("[-] Crawler found no actionable endpoints. Halting scan.")
            return []
        
        # In discovery mode, we create generic targets for the attack engine
        attack_targets = [{'url': url, 'params': None, 'method': 'GET'} for url in endpoints]

    else:
        print(f"[*] Received {len(sast_findings)} targets from SAST. Running in targeted mode.")
        attack_targets = sast_findings
    
    print("\n[*] Step 2: Launching attacks...")
    attack_engine = AttackEngine(target_url)
    attack_results = attack_engine.run_attacks(attack_targets)
    
    print("\n[*] Step 3: Analyzing results...")
    for result in attack_results:
        confirmed_vuln = analyze_response(result)
        if confirmed_vuln:
            vulnerabilities_found.append(confirmed_vuln)
            print(f"  [+] VULNERABILITY FOUND: {confirmed_vuln['type']} at {confirmed_vuln['url']} with payload: {confirmed_vuln['payload']}")

    if not vulnerabilities_found:
        print("[-] No vulnerabilities confirmed by DAST.")

    return vulnerabilities_found

if __name__ == '__main__':
    # Example of running the DAST scanner directly
    if len(sys.argv) < 2:
        print("Usage: python dast_runner.py <target_url>")
        sys.exit(1)
    
    target = sys.argv[1]
    run_dast(target)