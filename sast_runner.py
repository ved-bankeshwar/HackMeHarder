import os
import sys
import yaml
import ast
from typing import List, Dict, Any

# Ensure the SAST directory is in the Python path to allow for direct imports
# This makes the runner script more robust, regardless of where it's called from.
sys.path.append(os.path.join(os.path.dirname(__file__), 'SAST'))

try:
    import SAST.secrets_scanner as secrets_scanner
    import SAST.vulnerability_scanner as vulnerability_scanner
except ImportError as e:
    print(f"[!] Error: Failed to import scanner modules. Make sure they are in the SAST/ directory. Details: {e}")
    sys.exit(1)


def load_all_rules(filepath: str = 'rules.yaml') -> Dict[str, Any]:
    """
    Loads all scanning rules from the specified YAML file.

    Args:
        filepath: The path to the rules.yaml file.

    Returns:
        A dictionary containing all the loaded rules. Returns an empty dict if not found.
    """
    if not os.path.exists(filepath):
        print(f"[!] Error: Rules file not found at '{filepath}'.", file=sys.stderr)
        return {}
    try:
        with open(filepath, 'r') as f:
            return yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        print(f"[!] Error parsing YAML rules file '{filepath}': {e}", file=sys.stderr)
        return {}


def run_sast(directory_path: str) -> List[Dict[str, Any]]:
    """
    Executes a full SAST scan on a given directory.

    This function orchestrates the entire SAST process:
    1. Loads all rules from the rules file.
    2. Finds all Python files in the target directory.
    3. Runs the secrets scanner on each file.
    4. Runs the code vulnerability (AST) scanner on each file.
    5. Deduplicates and returns all findings.

    Args:
        directory_path: The absolute or relative path to the source code directory.

    Returns:
        A list of dictionaries, where each dictionary represents a unique vulnerability finding.
    """
    all_rules = load_all_rules()
    if not all_rules:
        print("[!] Halting scan due to missing or invalid rules.")
        return []

    # 1. Find all target Python files
    target_files = [
        os.path.join(root, file)
        for root, _, files in os.walk(directory_path)
        for file in files
        if file.endswith(".py")
    ]

    if not target_files:
        print(f"[-] No Python files found in '{directory_path}'.")
        return []

    print(f"[*] Found {len(target_files)} Python file(s) to analyze.")
    all_findings = []

    # 2. Run scanners on each file
    for file_path in target_files:
        print(f"  -> Scanning {file_path}")

        # Run the secrets scanner (regex-based)
        secret_rules = all_rules.get('secret_rules', [])
        findings = secrets_scanner.scan_file_for_secrets(file_path, secret_rules)
        all_findings.extend(findings)

        # Run the code vulnerability scanner (AST-based)
        # The scan_file function in vulnerability_scanner handles AST parsing and visiting
        findings = vulnerability_scanner.scan_file(file_path, all_rules)
        all_findings.extend(findings)
    
    # 3. Deduplicate findings to ensure a clean report
    if all_findings:
        # Use the deduplication utility from the vulnerability scanner
        unique_findings = vulnerability_scanner.deduplicate_findings(all_findings)
        print(f"[*] Scan complete. Found {len(unique_findings)} unique potential vulnerabilities.")
        return sorted(unique_findings, key=lambda x: (x.get('file'), x.get('line')))
    
    print("[*] Scan complete. No issues found.")
    return []

# This block allows for direct testing of the runner script
if __name__ == '__main__':
    import json
    
    # Check if a path is provided, otherwise use the current directory's 'DAST' folder for testing
    if len(sys.argv) > 1:
        target_path = sys.argv[1]
    else:
        # Use a default test path relative to this script for demonstration
        target_path = os.path.join(os.path.dirname(__file__), 'DAST')
        print(f"[!] No target directory provided. Running a demo scan on: {target_path}")

    if not os.path.isdir(target_path):
        print(f"[!] Error: The specified path '{target_path}' is not a valid directory.")
        sys.exit(1)
        
    results = run_sast(target_path)
    
    if results:
        print("\n--- SAST RUNNER TEST RESULTS ---")
        print(json.dumps(results, indent=2))
        print("----------------------------")
