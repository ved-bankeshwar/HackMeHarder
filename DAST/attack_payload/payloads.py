
PAYLOADS = {
    "SQLi": [
        "' OR 1=1 --",              
        "'",                        
        "\" OR 1=1 --"             
    ],
    "XSS": [
        "<script>alert('XSS-DAST')</script>",
        "\"><img src=x onerror=alert('XSS')>"
    ],
    "PathTraversal": [
        "../../../../../../etc/passwd",
        "../../../../../../etc/hosts"
    ],
    "UnvalidatedRedirect": [
        "https://www.google.com/search?q=DAST+confirmation",
        "https://example.com/malicious-redirect"
    ]
}
