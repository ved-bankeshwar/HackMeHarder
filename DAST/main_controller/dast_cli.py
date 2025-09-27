# DAST/main_controller/dast_cli.py

import argparse
import sys
import os

# Adjusting the path to be able to import from parent directories
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

try:
    # --- FIX: Import the Crawler CLASS, not the old 'crawl' function ---
    from DAST.crawlers.index import Crawler
    from DAST.attack_payload.attack_engine import AttackEngine
    from DAST.analysis_engine.index import analyze_response
except ImportError as e:
    print(f"[!] Error: Failed to import DAST modules. Details: {e}")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="DAST tool for web application security testing.")
    parser.add_argument("url", help="The base URL of the web application to test.")
    args = parser.parse_args()

    target_url = args.url

    print(f"[*] Starting DAST scan for target: {target_url}")

    # --- FIX: Instantiate and run the new Crawler class ---
    print("[*] Step 1: Crawling the website...")
    crawler = Crawler(target_url)
    endpoints = crawler.run()
    
    if not endpoints:
        print("[-] Crawler found no actionable endpoints. Halting scan.")
        return
    
    attack_targets = [{'url': url, 'params': None, 'method': 'GET'} for url in endpoints]

    print("\n[*] Step 2: Launching attacks...")
    attack_engine = AttackEngine(target_url)
    attack_results = attack_engine.run_attacks(attack_targets)

    print("\n[*] Step 3: Analyzing results...")
    vulnerabilities_found = []
    for result in attack_results:
        confirmed_vuln = analyze_response(result)
        if confirmed_vuln:
            vulnerabilities_found.append(confirmed_vuln)
            print(f"  [+] VULNERABILITY FOUND: {confirmed_vuln['type']} at {confirmed_vuln['url']}")

    if not vulnerabilities_found:
        print("\n[-] No vulnerabilities found.")

if __name__ == "__main__":
    main()