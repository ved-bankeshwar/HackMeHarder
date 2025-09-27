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
                    response = requests.get(full_url, params=request_data, timeout=30, allow_redirects=False)
                elif method == "POST":
                    # For POST requests, parameters go in the request body
                    response = requests.post(full_url, data=request_data, timeout=30, allow_redirects=False)
                
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
