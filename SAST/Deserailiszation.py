import ast
import os
import yaml
import json

# --- Taint Analysis & Direct Check Analyzers ---

class DeserializationAnalyzer(ast.NodeVisitor):
    """
    Finds calls to insecure deserialization functions by tracking imports and aliases.
    """
    def __init__(self, file_path):
        self.vulnerabilities = []
        self.file_path = file_path
        self.aliases = {}
        self.dangerous_deserializers = {
            'pickle': ['load', 'loads'],
            '_pickle': ['load', 'loads'], # cPickle is _pickle in Python 3
            'shelve': ['open'],
            'yaml': ['load'] # yaml.load is unsafe by default, recommend safe_load
        }

    def visit_Import(self, node):
        for alias in node.names:
            self.aliases[alias.asname or alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module
        for alias in node.names:
            full_name = f"{module}.{alias.name}" if module else alias.name
            self.aliases[alias.asname or alias.name] = full_name
        self.generic_visit(node)

    def visit_Call(self, node):
        full_name_of_call = None
        func = node.func

        if isinstance(func, ast.Name):
            # Handles calls like `loads(...)` after `from pickle import loads`
            full_name_of_call = self.aliases.get(func.id, func.id)
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            # Handles calls like `pickle.loads(...)` or `p.loads(...)`
            base_name = func.value.id
            attribute_name = func.attr
            resolved_base = self.aliases.get(base_name, base_name)
            full_name_of_call = f"{resolved_base}.{attribute_name}"

        if full_name_of_call:
            parts = full_name_of_call.split('.')
            if len(parts) == 2:
                module, function = parts
                if module in self.dangerous_deserializers and function in self.dangerous_deserializers[module]:
                    self.add_vulnerability(node, full_name_of_call)
        
        self.generic_visit(node)

    def add_vulnerability(self, node, call_name):
        """Helper function to create and add a vulnerability finding."""
        detail = f"Call to insecure deserialization function '{call_name}' detected. Un-trusted data can lead to RCE."
        vuln = {
            "type": "Insecure Deserialization",
            "file": self.file_path,
            "line": node.lineno,
            "detail": detail
        }
        # Avoid adding duplicate findings for the same line
        if not any(v['line'] == vuln['line'] and v['type'] == vuln['type'] for v in self.vulnerabilities):
            self.vulnerabilities.append(vuln)


# --- Core Scanner Logic ---

def scan_file(filepath):
    all_findings = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            tree = ast.parse(content, filename=filepath)
            
            # Run all analyzers on the file
            analyzers = [
                DeserializationAnalyzer(filepath),
                
            ]
            
            for analyzer in analyzers:
                analyzer.visit(tree)
                all_findings.extend(analyzer.vulnerabilities)

            return all_findings
    except Exception as e:
        print(f"Could not parse or read file {filepath}: {e}")
        return []

def main():
    # In your CLI, this list of files would come from user input
    target_files = ['test.py']
    
    all_findings = []
    for target_file in target_files:
        if not os.path.exists(target_file):
            print(f"[!] Test file not found: {target_file}. Skipping.")
            continue
            
        print(f"\n[*] Scanning file: {target_file}...")
        findings = scan_file(target_file)
        if findings:
            all_findings.extend(findings)
        else:
            print(f"[-] No vulnerabilities found in {target_file}.")

    if all_findings:
        print(f"\n[+] Analysis Complete. Found {len(all_findings)} total potential vulnerabilities:")
        print(json.dumps(all_findings, indent=2))
    else:
        print("\n[-] Analysis Complete. No vulnerabilities found.")

if __name__ == '__main__':
    main()

