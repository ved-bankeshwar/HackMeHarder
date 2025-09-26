
PAYLOADS = {
    "SQLi": [
        "' OR 1=1 --",              # Authentication Bypass (Tautology)
        "'",                        # Simple Single Quote (Error Trigger)
        "\" OR 1=1 --"              # Double Quote (Alternate Tautology)
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
