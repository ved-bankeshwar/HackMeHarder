import requests
import json
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse, urljoin
from .payloads import PAYLOADS # Import the payloads from the canvas file


def send_malicious_requests(
    target: Dict[str, Any], 
    vul_type: str, 
    base_domain: str = "http://127.0.0.1:5000"
) -> List[Dict[str, Any]]:
    """
    Sends all relevant payloads for a specific vulnerability type to a single target endpoint.

    Args:
        target: A dictionary from the Crawler, e.g.,
                {'url': '/search', 'method': 'GET', 'params': ['q']}
        vul_type: The type of vulnerability to test ('SQLi', 'XSS', etc.).
        base_domain: The base URL of the running application, e.g., 'http://127.0.0.1:5000'.

    Returns:
        A list of dictionaries, where each dictionary contains the requests.Response object
        and the context of the attack (payload, URL, etc.).
    """
    
    full_url = urljoin(base_domain, target.get('url', ''))
    method = target.get('method', 'GET').upper()
    param_names = target.get('params', [])
    
    results: List[Dict[str, Any]] = []
    payload_list = PAYLOADS.get(vul_type, [])

    if not param_names or not payload_list:
        print(f"[-] Skipping target {target['url']}: No parameters or payloads defined for {vul_type}.")
        return results

    print(f"[>] Attacking {full_url} ({method}) for {vul_type}...")

    # Iterate over all parameters and payloads to test all combinations
    for param_name in param_names:
        for payload in payload_list:
            
            # --- 💥 Build the Request Data 💥 ---
            # Create a dictionary to hold all parameters for the request.
            # Fill other parameters with benign data to avoid interfering.
            request_data = {p: "DAST_BENIGN_DATA" for p in param_names}
            
            # Inject the payload into the current target parameter.
            request_data[param_name] = payload
            
            response = None
            
            # 3. Send the Request
            try:
                if method == "GET":
                    # For GET requests, parameters go in the URL
                    response = requests.get(full_url, params=request_data, timeout=5, allow_redirects=False)
                elif method == "POST":
                    # For POST requests, parameters go in the request body
                    response = requests.post(full_url, data=request_data, timeout=5, allow_redirects=False)
                
                # 4. Collate Result for the Analysis Engine (Member 3)
                if response is not None:
                    results.append({
                        'response': response,
                        'payload': payload,
                        'target_url': full_url,
                        'target_param': param_name,
                        'vul_type': vul_type
                    })

            except requests.exceptions.RequestException as e:
                print(f"  [!] Connection Error on {full_url}: {e}")
                
    return results

# ----------------------------------------------------------------------
# INDEPENDENT TESTING BLOCK (MEMBER 2 FOCUS)
# Member 2 uses this to test their module without the rest of the team.
# ----------------------------------------------------------------------

# Add this to DAST/attack_payload/attack_engine.py (after send_malicious_requests)

from typing import Optional
from ..crawlers.index import crawl  # local import; uses your existing crawler

def perform_targeted_scan(target_url: str, sast_findings: Optional[list]) -> list:
    """
    Perform a targeted DAST confirmation scan.
    - target_url: base URL (e.g. 'http://127.0.0.1:5000' or 'http://localhost:5000')
    - sast_findings: list of findings from SAST (may be empty or None)
    Returns: list of attack result dicts (same shape as send_malicious_requests returns)
    """
    results = []

    # Defensive normalization
    if sast_findings is None:
        sast_findings = []

    # --- Targeted mode: try to confirm SAST findings ---
    if sast_findings:
        print(f"[*] Running targeted confirmation for {len(sast_findings)} SAST finding(s).")
        session = requests.Session()

        for finding in sast_findings:
            # Normalize a few common keys used in your repo's SAST output:
            vul_type = finding.get("vul_type") or finding.get("type") or finding.get("vulnerability") or finding.get("name")
            rel_url = finding.get("url") or finding.get("relative_url") or finding.get("endpoint") or finding.get("path")
            param = finding.get("param") or finding.get("params") or finding.get("parameter")
            method = (finding.get("method") or "GET").upper()

            # If the finding is not mappable to an HTTP target, skip it.
            if not rel_url or not vul_type or not param:
                # skip but log; some SAST findings are code-only and cannot be targeted directly
                print(f"[-] Skipping SAST finding (not mappable to HTTP): {finding}")
                continue

            full_endpoint = urljoin(target_url, rel_url)
            # Build a "target" dict compatible with send_malicious_requests:
            target = {"url": rel_url, "method": method, "params": [param] if isinstance(param, str) else list(param)}

            # Use send_malicious_requests for this specific vulnerability type
            try:
                attack_results = send_malicious_requests(target, vul_type, base_domain=target_url)
                results.extend(attack_results)
            except Exception as e:
                print(f"[!] Error while performing targeted requests for {full_endpoint}: {e}")
                continue

        return results

    # --- Discovery mode: no SAST findings provided ---
    print("[*] No SAST findings provided — running discovery-mode attacks.")
    try:
        discovered = crawl(target_url)
    except Exception as e:
        print(f"[!] Crawler failed: {e}. Discovery aborted.")
        return []

    # For each discovered endpoint, try each payload type
    for endpoint in discovered:
        for vul_type in PAYLOADS.keys():
            try:
                res = send_malicious_requests(endpoint, vul_type, base_domain=target_url)
                results.extend(res)
            except Exception as e:
                print(f"[!] Error attacking {endpoint.get('url')}: {e}")
                continue

    return results


if __name__ == '__main__':
    print("--- Running DAST Attack Engine Mock Tests ---")
    
    # Mock Targets (Simulate the output of the Crawler - Member 1)
    mock_targets = [
        {'url': '/search', 'method': 'GET', 'params': ['q']},
        {'url': '/login', 'method': 'POST', 'params': ['username', 'password']},
        {'url': '/download', 'method': 'GET', 'params': ['filename']},
        {'url': '/redirect', 'method': 'GET', 'params': ['next_url']},
    ]

    # Target vulnerabilities from our defined set
    vulnerability_checks = ["SQLi", "XSS", "PathTraversal", "UnvalidatedRedirect"]

    all_results = []
    
    # Simulate the main loop of the Main Controller (Member 4)
    # The base_domain here must point to the sandbox/test server
    BASE_URL = "http://localhost:5000"
    print(f"Testing against a mock application running at {BASE_URL}")

    for target in mock_targets:
        for vul_type in vulnerability_checks:
            results = send_malicious_requests(target, vul_type, base_domain=BASE_URL) 
            all_results.extend(results)

    print("\n--- Summary of Requests Sent ---")
    print(f"Total requests generated: {len(all_results)}")
    
    if all_results:
        # Print a sample of the data structure to confirm it's correct
        print("\nExample result structure (passed to Analysis Engine):")
        example = all_results[0]
        print(json.dumps(example, indent=2, default=str)) # Use default=str to handle response object
