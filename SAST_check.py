import os
import sys
import json
import yaml
import ast
import argparse
from SAST import secrets_scanner, vulnerability_scanner

def load_all_rules(filepath='rules.yaml'):
    try:
        with open(filepath, 'r') as f: return yaml.safe_load(f) or {}
    except FileNotFoundError:
        print(f"Error: Rules file '{filepath}' not found.", file=sys.stderr)
        return {}

def main():
    parser = argparse.ArgumentParser(description="A Unified SAST Scanner.")
    parser.add_argument("target", help="The target file or directory to scan.")
    parser.add_argument("--rules", default="rules.yaml", help="Path to the YAML rule file.")
    args = parser.parse_args()

    all_rules = load_all_rules(args.rules)
    if not all_rules: sys.exit(1)

    if os.path.isfile(args.target):
        target_files = [args.target] if args.target.endswith('.py') else []
    else:
        target_files = [os.path.join(r, f) for r, d, fs in os.walk(args.target) for f in fs if f.endswith('.py')]

    all_findings = []
    print(f"[*] Scanning {len(target_files)} Python file(s)...")

    for file_path in target_files:
        # Run secrets scanner
        findings = secrets_scanner.scan(file_path, all_rules.get('regex_rules', []))
        all_findings.extend(findings)

        # Run AST code scanner
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                tree = ast.parse(f.read(), filename=file_path)
                findings = vulnerability_scanner.scan(file_path, tree, all_rules)
                all_findings.extend(findings)
        except Exception: pass

    if all_findings:
        print(f"\n[+] Found {len(all_findings)} total vulnerabilities:")
        all_findings.sort(key=lambda x: (x.get('file'), x.get('line')))
        print(json.dumps(all_findings, indent=2))
    else:
        print("\n[-] No vulnerabilities found.")

if __name__ == '__main__':
    main()