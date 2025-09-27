import re

def is_vulnerable_to_sqli(response):
    """
    Analyzes an HTTP response to check for signs of SQL injection.
    
    This is a basic check looking for common database error messages in the response body.

    Args:
        response: A requests.Response object from the HTTP request.

    Returns:
        A tuple (bool, str or None). 
        - (True, "Reason for vulnerability") if a vulnerability is detected.
        - (False, None) if no vulnerability is detected.
    """
    sql_errors = [
        "you have an error in your sql syntax;",
        "warning: mysql_fetch_array()",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "sql command not properly ended",
        "oracle driver error",
        "microsoft ole db provider for odbc drivers error"
    ]

    response_text = response.text.lower()
    for error in sql_errors:
        if error in response_text:
            return (True, f"Detected SQL Error fingerprint: '{error}'")
            
    return (False, None)


def is_vulnerable_to_xss(response, payload):
    """
    Analyzes an HTTP response to check for signs of reflected XSS.

    It checks if the payload sent is reflected in the response body without proper
    HTML entity encoding (e.g., '<' should become '&lt;').

    Args:
        response: A requests.Response object from the HTTP request.
        payload (str): The payload that was injected.

    Returns:
        A tuple (bool, str or None).
    """
    if payload in response.text:
        escaped_payload = payload.replace("<", "&lt;").replace(">", "&gt;")
        if escaped_payload in response.text:
            return (False, None)
        return (True, f"Payload '{payload}' was reflected in the response without proper escaping.")

    return (False, None)


def is_vulnerable_to_path_traversal(response):
    """
    Analyzes an HTTP response for signs of a successful path traversal attack.

    It checks for well-known content from sensitive system files.

    Args:
        response: A requests.Response object from the HTTP request.

    Returns:
        A tuple (bool, str or None).
    """
    # Fingerprints for common sensitive files
    # 'root:x:0:0' is a classic indicator from /etc/passwd
    # '[fonts]' is from C:\Windows\win.ini
    sensitive_content_fingerprints = [
        "root:x:0:0",
        "[fonts]"
    ]
    
    response_text = response.text
    for fingerprint in sensitive_content_fingerprints:
        if fingerprint in response_text:
            return (True, f"Detected sensitive file content: '{fingerprint}'")

    return (False, None)


def is_vulnerable_to_redirect(response, payload):
    """
    Analyzes an HTTP response for signs of an unvalidated redirect.

    It checks if the server responded with a redirect (3xx status code) to the
    malicious payload URL.

    Args:
        response: A requests.Response object from the HTTP request.
        payload (str): The external URL that was injected.

    Returns:
        A tuple (bool, str or None).
    """
    # Response.is_redirect is a handy property from the requests library
    # that checks if the status code is in the 3xx range.
    if response.is_redirect:
        # Check the 'Location' header to see where it's redirecting to.
        location_header = response.headers.get('Location', '')
        if payload in location_header:
            return (True, f"Application redirected to a malicious URL: {location_header}")

    return (False, None)

def analyze_responses(results):
    """
    Runs all analysis checks on the list of attack results.

    Args:
        results (list): list of dicts returned by send_malicious_requests,
                        each containing keys: 'response', 'payload', 'target_url', 'target_param', 'vul_type'

    Returns:
        list: confirmed vulnerabilities (each as a dict)
    """
    confirmed = []

    for result in results:
        vul_type = result.get("vul_type")
        response = result.get("response")
        payload = result.get("payload")

        if vul_type == "SQLi":
            is_vuln, reason = is_vulnerable_to_sqli(response)
        elif vul_type == "XSS":
            is_vuln, reason = is_vulnerable_to_xss(response, payload)
        elif vul_type == "PathTraversal":
            is_vuln, reason = is_vulnerable_to_path_traversal(response)
        elif vul_type == "UnvalidatedRedirect":
            is_vuln, reason = is_vulnerable_to_redirect(response, payload)
        else:
            is_vuln, reason = (False, None)

        if is_vuln:
            confirmed.append({
                "type": vul_type,
                "url": result.get("target_url"),
                "param": result.get("target_param"),
                "payload": payload,
                "reason": reason
            })

    return confirmed



# This block allows the script to be run directly for testing by Member 3
if __name__ == "__main__":
    # We need a more advanced mock to handle status codes and headers for redirect tests
    class MockResponse:
        def __init__(self, text, status_code=200, headers=None):
            self.text = text
            self.status_code = status_code
            self.headers = headers or {}
        
        @property
        def is_redirect(self):
            return self.status_code in (301, 302, 303, 307, 308)

    print("--- RUNNING ANALYSIS ENGINE TESTS ---")

    # --- SQLi Tests ---
    sqli_response = MockResponse("<html><body>You have an error in your SQL syntax; check the manual</body></html>")
    is_vuln, reason = is_vulnerable_to_sqli(sqli_response)
    print(f"SQLi Test (Positive): Vulnerable = {is_vuln}, Reason = {reason}")
    assert is_vuln

    safe_response = MockResponse("<html><body>Welcome to our website!</body></html>")
    is_vuln, reason = is_vulnerable_to_sqli(safe_response)
    print(f"SQLi Test (Negative): Vulnerable = {is_vuln}, Reason = {reason}")
    assert not is_vuln

    # --- XSS Tests ---
    xss_payload = "<script>alert('hack')</script>"
    xss_response = MockResponse(f"<html><body>Your search for '{xss_payload}' returned 0 results.</body></html>")
    is_vuln, reason = is_vulnerable_to_xss(xss_response, xss_payload)
    print(f"XSS Test (Positive): Vulnerable = {is_vuln}, Reason = {reason}")
    assert is_vuln

    escaped_xss_response = MockResponse("<html><body>Your search for '&lt;script&gt;alert('hack')&lt;/script&gt;' returned 0 results.</body></html>")
    is_vuln, reason = is_vulnerable_to_xss(escaped_xss_response, xss_payload)
    print(f"XSS Test (Negative, Escaped): Vulnerable = {is_vuln}, Reason = {reason}")
    assert not is_vuln
    
    # --- Path Traversal Tests ---
    path_trav_response = MockResponse("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
    is_vuln, reason = is_vulnerable_to_path_traversal(path_trav_response)
    print(f"Path Traversal Test (Positive): Vulnerable = {is_vuln}, Reason = {reason}")
    assert is_vuln
    
    is_vuln, reason = is_vulnerable_to_path_traversal(safe_response)
    print(f"Path Traversal Test (Negative): Vulnerable = {is_vuln}, Reason = {reason}")
    assert not is_vuln

    # --- Unvalidated Redirect Tests ---
    redirect_payload = "http://evil-site.com"
    redirect_headers = {'Location': redirect_payload}
    redirect_response = MockResponse("Redirecting...", status_code=302, headers=redirect_headers)
    is_vuln, reason = is_vulnerable_to_redirect(redirect_response, redirect_payload)
    print(f"Redirect Test (Positive): Vulnerable = {is_vuln}, Reason = {reason}")
    assert is_vuln
    
    safe_redirect_response = MockResponse("Redirecting...", status_code=302, headers={'Location': '/safe-local-page'})
    is_vuln, reason = is_vulnerable_to_redirect(safe_redirect_response, redirect_payload)
    print(f"Redirect Test (Negative): Vulnerable = {is_vuln}, Reason = {reason}")
    assert not is_vuln
    
    print("\n--- ALL TESTS PASSED ---")

