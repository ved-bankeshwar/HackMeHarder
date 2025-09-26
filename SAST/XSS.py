import ast
import os
import yaml
import json
import argparse

# --- Taint Analysis Scanner for XSS ---
class XSSAnalyzer(ast.NodeVisitor):
    """
    Performs taint analysis for XSS vulnerabilities.
    It now dynamically loads sources and sinks from a rules dictionary.
    """
    def __init__(self, file_path, rules):
        self.vulnerabilities = []
        self.file_path = file_path
        # Dynamically load sources and sinks from the provided rules
        self.sources = rules.get('sources', [])
        self.sinks = rules.get('sinks', [])

    def visit_FunctionDef(self, node):
        """
        Analyzes each function independently to track how tainted data flows.
        """
        tainted_variables = set()

        # First pass: Find all variables that become "tainted" by a source.
        for sub_node in ast.walk(node):
            if isinstance(sub_node, ast.Assign):
                value_str = ast.unparse(sub_node.value)
                if any(source in value_str for source in self.sources):
                    for target in sub_node.targets:
                        if isinstance(target, ast.Name):
                            tainted_variables.add(target.id)

        # Second pass: Check if any tainted variable is used in a sink.
        for sub_node in ast.walk(node):
            if isinstance(sub_node, ast.Call):
                call_name = ast.unparse(sub_node.func)
                if call_name in self.sinks:
                    for arg in sub_node.args:
                        if isinstance(arg, ast.Name) and arg.id in tainted_variables:
                            vuln = {
                                "type": "Cross-Site Scripting (XSS)",
                                "file": self.file_path,
                                "line": sub_node.lineno,
                                "code": ast.unparse(sub_node).strip(),
                                "severity": "High",
                                "detail": f"Tainted variable '{arg.id}' flows from a user-controlled source to the dangerous sink '{call_name}'."
                            }
                            self.vulnerabilities.append(vuln)
                            break
        self.generic_visit(node)

# --- Rule-Based Scanner for Patterns ---
class RuleBasedScanner(ast.NodeVisitor):
    """
    A simple scanner that looks for specific function call patterns defined in the rules.
    Used for Weak Crypto and Insecure Deserialization checks.
    """
    def __init__(self, file_path, rules):
        self.vulnerabilities = []
        self.file_path = file_path
        self.rules = rules

    def visit_Call(self, node):
        # unparse the function call to get a string representation (e.g., "hashlib.md5")
        call_name = ast.unparse(node.func)
        for rule in self.rules:
            if rule.get('pattern') == call_name:
                vuln = {
                    "type": rule.get('id', 'Pattern Match'),
                    "file": self.file_path,
                    "line": node.lineno,
                    "code": ast.unparse(node).strip(),
                    "severity": rule.get('severity', 'N/A'),
                    "detail": rule.get('description', 'A function call matching a dangerous pattern was found.')
                }
                self.vulnerabilities.append(vuln)
        self.generic_visit(node)

# --- Core Scanner Logic ---
def load_all_rules(filepath='rules.yaml'):
    """Loads the entire rule file into a dictionary."""
    try:
        with open(filepath, 'r') as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        print(f"Error: Rules file not found at {filepath}")
        return {}
    except Exception as e:
        print(f"Error loading or parsing rules file: {e}")
        return {}

def scan_file(filepath, all_rules):
    """
    Scans a single Python file for vulnerabilities using all available analyzers.
    """
    all_findings = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            tree = ast.parse(content, filename=filepath)

            # --- Run the XSS taint analyzer ---
            xss_rules = all_rules.get('xss_rules', {})
            if xss_rules:
                xss_analyzer = XSSAnalyzer(filepath, xss_rules)
                xss_analyzer.visit(tree)
                all_findings.extend(xss_analyzer.vulnerabilities)

            # --- Run the pattern-based scanner ---
            pattern_rules = all_rules.get('weak_crypto_rules', []) + all_rules.get('insecure_deserialization_rules', [])
            if pattern_rules:
                rule_scanner = RuleBasedScanner(filepath, pattern_rules)
                rule_scanner.visit(tree)
                all_findings.extend(rule_scanner.vulnerabilities)

            return all_findings
    except Exception as e:
        print(f"Could not parse or read file {filepath}: {e}")
        return []

def main():
    """
    Main function to run the SAST scanner.
    """
    parser = argparse.ArgumentParser(description="SAST tool for detecting XSS, Weak Crypto, and other vulnerabilities.")
    parser.add_argument("target", help="The target file or directory to scan.")
    parser.add_argument("--rules", default="rules.yaml", help="Path to the YAML rule file.")
    args = parser.parse_args()

    print(f"[*] Loading SAST rules from '{args.rules}'...")
    all_rules = load_all_rules(args.rules)

    if not all_rules:
        print("[!] Rules file is empty or could not be loaded. Aborting.")
        return

    all_findings = []
    if os.path.isfile(args.target):
        target_files = [args.target]
    elif os.path.isdir(args.target):
        target_files = [os.path.join(root, file)
                        for root, _, files in os.walk(args.target)
                        for file in files if file.endswith('.py')]
    else:
        print(f"[!] Error: Target '{args.target}' is not a valid file or directory.")
        return

    print(f"[*] Starting scan on {len(target_files)} file(s)...")
    for target_file in target_files:
        findings = scan_file(target_file, all_rules)
        if findings:
            all_findings.extend(findings)

    if all_findings:
        print(f"\n[+] Analysis Complete. Found {len(all_findings)} total potential vulnerabilities:")
        # Sort results by file and line number for readability
        all_findings.sort(key=lambda x: (x.get('file'), x.get('line')))
        print(json.dumps(all_findings, indent=2))
    else:
        print("\n[-] Analysis Complete. No vulnerabilities found.")

if __name__ == '__main__':
    main()