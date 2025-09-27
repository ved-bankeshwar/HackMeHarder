
def is_vulnerable_to_sqli(response):
    
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
    
    if payload in response.text:
        escaped_payload = payload.replace("<", "&lt;").replace(">", "&gt;")
        if escaped_payload in response.text:
            return (False, None)
        return (True, f"Payload '{payload}' was reflected in the response without proper escaping.")

    return (False, None)


def is_vulnerable_to_path_traversal(response):
    
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
    

    if response.is_redirect:

        location_header = response.headers.get('Location', '')
        if payload in location_header:
            return (True, f"Application redirected to a malicious URL: {location_header}")

    return (False, None)



if __name__ == "__main__":
    
    class MockResponse:
        def __init__(self, text, status_code=200, headers=None):
            self.text = text
            self.status_code = status_code
            self.headers = headers or {}
        
        @property
        def is_redirect(self):
            return self.status_code in (301, 302, 303, 307, 308)

   

  
    sqli_response = MockResponse("<html><body>You have an error in your SQL syntax; check the manual</body></html>")
    is_vuln, reason = is_vulnerable_to_sqli(sqli_response)
    print(f"SQLi Test (Positive): Vulnerable = {is_vuln}, Reason = {reason}")
    assert is_vuln

    safe_response = MockResponse("<html><body>Welcome to our website!</body></html>")
    is_vuln, reason = is_vulnerable_to_sqli(safe_response)
    print(f"SQLi Test (Negative): Vulnerable = {is_vuln}, Reason = {reason}")
    assert not is_vuln

    xss_payload = "<script>alert('hack')</script>"
    xss_response = MockResponse(f"<html><body>Your search for '{xss_payload}' returned 0 results.</body></html>")
    is_vuln, reason = is_vulnerable_to_xss(xss_response, xss_payload)
    print(f"XSS Test (Positive): Vulnerable = {is_vuln}, Reason = {reason}")
    assert is_vuln

    escaped_xss_response = MockResponse("<html><body>Your search for '&lt;script&gt;alert('hack')&lt;/script&gt;' returned 0 results.</body></html>")
    is_vuln, reason = is_vulnerable_to_xss(escaped_xss_response, xss_payload)
    print(f"XSS Test (Negative, Escaped): Vulnerable = {is_vuln}, Reason = {reason}")
    assert not is_vuln
    

    path_trav_response = MockResponse("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
    is_vuln, reason = is_vulnerable_to_path_traversal(path_trav_response)
    print(f"Path Traversal Test (Positive): Vulnerable = {is_vuln}, Reason = {reason}")
    assert is_vuln
    
    is_vuln, reason = is_vulnerable_to_path_traversal(safe_response)
    print(f"Path Traversal Test (Negative): Vulnerable = {is_vuln}, Reason = {reason}")
    assert not is_vuln


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

