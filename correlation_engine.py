# /correlation_engine.py
from SAST_check import sast_scan_directory
from DAST.attack_payload.attack_engine import send_malicious_requests
from DAST.main_controller.dast_cli import analyze_vulnerability
import os
import sys
import json
import logging
from urllib.parse import urlparse

# --- Set up structured logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# --- Add project root to sys.path to allow imports ---
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)



# Maps the verbose SAST type from rules.yaml to the short DAST type used in PAYLOADS
SAST_TO_DAST_TYPE_MAPPING = {
    "SQL Injection": "SQLi",
    "Cross-Site Scripting": "XSS",
    "Path Traversal": "PathTraversal",
    "Command Injection": "CommandInjection",
}

def run_correlated_scan(repo_path: str, target_url: str) -> list:
    """
    Orchestrates the SAST -> DAST pipeline with structured logging.
    """
    logger.info("--- 🚀 Starting Correlated SAST + DAST Scan ---")
    
    # --- Step 1: Run SAST to get potential targets ---
    sast_findings = sast_scan_directory(repo_path)
    
    if not sast_findings:
        logger.info("[✅] SAST scan completed. No potential web vulnerabilities found to confirm.")
        return []
        
    logger.info(f"SAST scan complete. Found {len(sast_findings)} potential targets.")
    logger.info("--- 🎯 Starting DAST confirmation phase ---")

    # --- Step 2: Run targeted DAST to confirm findings ---
    confirmed_vulnerabilities = []
    parsed_uri = urlparse(target_url)
    base_domain = f"{parsed_uri.scheme}://{parsed_uri.netloc}"

    for i, finding in enumerate(sast_findings, 1):
        sast_vul_type = finding.get("type")
        
        logger.info(f"Processing SAST finding {i}/{len(sast_findings)}: '{sast_vul_type}' in file '{finding.get('file')}'")
        logger.debug(f"Raw SAST finding details: {finding}")

        # --- FIX IS HERE ---
        # Check if the finding has the necessary web context to be actionable by DAST.
        required_keys = ['url', 'method', 'param']
        if not all(key in finding for key in required_keys):
            logger.warning(f"Skipping finding for '{sast_vul_type}': It is not a web-related finding with a URL and parameter.")
            continue
        # --- END FIX ---

        dast_vul_type = SAST_TO_DAST_TYPE_MAPPING.get(sast_vul_type)
        if not dast_vul_type:
            logger.warning(f"Skipping SAST finding '{sast_vul_type}': No DAST module mapping found.")
            continue

        # Construct the precise target for the DAST engine
        target_for_dast = {
            'url': finding.get('url'),
            'method': finding.get('method'),
            'params': [finding.get('param')]
        }
        logger.debug(f"Constructed DAST Target: {target_for_dast}")

        logger.info(f"-> Testing for '{sast_vul_type}' at {target_for_dast['method']} {target_for_dast['url']} (param: {finding.get('param')})")

        # Run the attack
        attack_results = send_malicious_requests(target_for_dast, dast_vul_type, base_domain=base_domain)
        
        is_confirmed = False
        for result in attack_results:
            is_vuln, reason = analyze_vulnerability(result)
            if is_vuln:
                logger.info(f"[+] CONFIRMED: {sast_vul_type} vulnerability found!")
                confirmed_vulnerabilities.append({
                    'type': sast_vul_type,
                    'url': result.get('target_url'),
                    'param': result.get('target_param'),
                    'payload_used': result.get('payload'),
                    'confirmation_reason': reason,
                    'sast_origin': {
                        'file': finding.get('file'),
                        'line': finding.get('line'),
                    }
                })
                is_confirmed = True
                break  # Move to the next SAST finding once confirmed
        
        if not is_confirmed:
            logger.info(f"[-] NOT CONFIRMED: SAST finding for '{sast_vul_type}' appears to be a false positive or is not reachable.")

    return confirmed_vulnerabilities

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description="Run a correlated SAST+DAST scan.")
    parser.add_argument("repo_path", help="The local path to the code repository.")
    parser.add_argument("target_url", help="The live URL of the application to test.")
    args = parser.parse_args()

    confirmed_vulns = run_correlated_scan(args.repo_path, args.target_url)

    # Final Report
    logger.info("--- ✅ Correlated Scan Report ---")
    if confirmed_vulns:
        logger.info(f"🎉 Found {len(confirmed_vulns)} confirmed vulnerabilities:")
        # Pretty print the final JSON report
        print(json.dumps(confirmed_vulns, indent=2))
    else:
        logger.info("✅ No SAST findings could be confirmed by DAST.")