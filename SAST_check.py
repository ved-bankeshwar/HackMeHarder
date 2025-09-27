# /SAST_check.py
import os
import ast
import json
import argparse
import yaml
from SAST.vulnerability_scanner import FlaskTaintAnalyzer

def load_rules(filepath=None):
    if not filepath:
        filepath = os.path.join(os.path.dirname(__file__), 'rules.yaml')
    if not os.path.exists(filepath):
        filepath = os.path.join(os.path.dirname(__file__), '..', 'rules.yaml')
        if not os.path.exists(filepath):
            print(f"[!] Error: Rule file 'rules.yaml' not found.")
            return {}
    with open(filepath, 'r') as f:
        return yaml.safe_load(f)

def sast_scan_directory(directory_path: str) -> list:
    all_findings = []
    all_rules = load_rules()
    print(f"[*] Starting SAST scan in directory: {directory_path}")
    excluded_dirs = {'venv', '.venv', 'env', '__pycache__'}

    for root, dirs, files in os.walk(directory_path):
        dirs[:] = [d for d in dirs if d not in excluded_dirs]
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                print(f"  -> Analyzing: {file_path}")
                try:
                    with open(file_path, "r", encoding='utf-8') as source_file:
                        source_code = source_file.read()
                        tree = ast.parse(source_code, filename=file_path)
                        
                        # Use the single, powerful analyzer
                        analyzer = FlaskTaintAnalyzer(file_path, all_rules.get('taint_analysis_rules'))
                        analyzer.visit(tree)
                        all_findings.extend(analyzer.findings)
                            
                except Exception as e:
                    print(f"     [!] Could not parse or analyze {file_path}. Skipping. Error: {e}")
    
    unique_finding_strings = {json.dumps(d, sort_keys=True) for d in all_findings}
    unique_findings = [json.loads(s) for s in unique_finding_strings]
    
    print(f"[*] SAST scan finished. Found {len(unique_findings)} potential vulnerabilities.")
    return unique_findings

def main():
    parser = argparse.ArgumentParser(description="SAST scanner for Python web applications.")
    parser.add_argument("path", type=str, help="The source code directory to scan.")
    args = parser.parse_args()
    
    if not os.path.isdir(args.path):
        print(f"[!] Error: Provided path '{args.path}' is not a valid directory.")
        return
        
    findings = sast_scan_directory(args.path)
    
    if findings:
        print("\n--- SAST Scan Report ---")
        print(json.dumps(findings, indent=2))
    else:
        print("\n[+] No potential web vulnerabilities found by SAST.")

if __name__ == "__main__":
    main()