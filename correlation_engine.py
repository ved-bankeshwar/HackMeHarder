from typing import List, Dict, Any

def correlate_findings(sast_results: List[Dict[str, Any]], dast_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Correlates findings from SAST and DAST scans to produce a unified report.

    This engine identifies:
    1. Confirmed Positives: Vulnerabilities found by SAST and confirmed by DAST.
    2. SAST-Only Findings: Potential vulnerabilities flagged by SAST but not found by DAST (potential False Positives).
    3. DAST-Only Findings: Vulnerabilities found only by DAST, often related to runtime or configuration issues.

    Args:
        sast_results: A list of findings from the SAST scan.
        dast_results: A list of findings from the DAST scan.

    Returns:
        A dictionary containing categorized lists of findings.
    """
    print("\n[*] Correlating SAST and DAST findings...")

    # For this hackathon, our correlation logic will be straightforward:
    # We match based on the vulnerability 'type' and a 'cwe' if available.
    # A real-world engine would need more sophisticated matching (e.g., endpoint mapping).
    
    sast_findings_set = { (f.get('type'), f.get('cwe')) for f in sast_results }
    dast_findings_set = { (f.get('type'), f.get('cwe')) for f in dast_results }

    # Convert full findings to a map for easy lookup
    sast_map = { (f.get('type'), f.get('cwe')): f for f in sast_results }
    dast_map = { (f.get('type'), f.get('cwe')): f for f in dast_results }

    confirmed_keys = sast_findings_set.intersection(dast_findings_set)
    
    confirmed_positives = [dast_map[key] for key in confirmed_keys]
    sast_only = [sast_map[key] for key in sast_findings_set - dast_findings_set]
    dast_only = [dast_map[key] for key in dast_findings_set - sast_findings_set]
    
    report = {
        "confirmed_positives": confirmed_positives,
        "sast_only_findings": sast_only,
        "dast_only_findings": dast_only
    }
    
    print(f"[+] Correlation complete.")
    print(f"  - Confirmed Positives: {len(confirmed_positives)}")
    print(f"  - SAST-Only (Potential False Positives): {len(sast_only)}")
    print(f"  - DAST-Only (Runtime Issues): {len(dast_only)}")
    
    return report

if __name__ == '__main__':
    import json

    print("[!] Correlation Engine - Direct Execution Test Mode")

    # --- Test Data ---
    mock_sast = [
        {'type': 'SQL Injection', 'cwe': 'CWE-89', 'file': 'db.py', 'line': 25},
        {'type': 'Command Injection', 'cwe': 'CWE-78', 'file': 'utils.py', 'line': 10},
        {'type': 'Hardcoded Secret', 'cwe': 'CWE-798', 'file': 'config.py', 'line': 5}
    ]
    
    mock_dast = [
        {'type': 'SQL Injection', 'cwe': 'CWE-89', 'endpoint': '/api/users', 'param': 'id'},
        {'type': 'Cross-Site Scripting (XSS)', 'cwe': 'CWE-79', 'endpoint': '/profile', 'param': 'name'}
    ]
    
    final_report = correlate_findings(mock_sast, mock_dast)
    
    print("\n--- CORRELATION ENGINE TEST RESULTS ---")
    print(json.dumps(final_report, indent=2))
    print("-----------------------------------")
