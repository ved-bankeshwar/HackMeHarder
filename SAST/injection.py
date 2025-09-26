import ast
import os
import sys
import yaml 

class ASTAnalyzer(ast.NodeVisitor):
   #Creates a Tree of the code to be analyzed.
    def __init__(self, file_path, rules):
        self.vulnerabilities = []
        self.file_path = file_path
        self.rules = rules 

    def visit_Call(self, node):
        
        for rule in self.rules:
            detection_logic = rule.get('detection', {})
            
            if detection_logic.get('node_type') == 'Call':
                if self.node_matches_rule(node, detection_logic):
                    vuln = {
                        "type": rule.get('name', 'Unnamed Rule'),
                        "file": self.file_path,
                        "line": node.lineno,
                        "code": ast.unparse(node).strip()
                    }
                    self.vulnerabilities.append(vuln)

        
        self.generic_visit(node)

    def node_matches_rule(self, node, detection_logic):

        if detection_logic.get('function_is_attribute'):
            if not isinstance(node.func, ast.Attribute):
                return False

            props = detection_logic.get('function_call_properties', {})
            func_value = node.func.value


            if 'object_name' in props:
                if not (isinstance(func_value, ast.Name) and func_value.id == props['object_name']):
                    return False
            

            if 'function_name' in props:
                if node.func.attr != props['function_name']:
                    return False

            if 'keyword_argument' in props:
                kw_props = props['keyword_argument']
                found_kw = False
                for kw in node.keywords:
                    if (kw.arg == kw_props['name'] and 
                        isinstance(kw.value, ast.Constant) and 
                        kw.value.value == kw_props['value']):
                        found_kw = True
                        break
                if not found_kw:
                    return False
        

        if 'argument_properties' in detection_logic:
            for arg_prop in detection_logic['argument_properties']:
                arg_pos = arg_prop.get('position', 0)
                if len(node.args) > arg_pos:
                    arg_node = node.args[arg_pos]
                    if arg_prop.get('is_formatted_string'):
                        if not (isinstance(arg_node, ast.JoinedStr) or isinstance(arg_node, ast.BinOp)):
                            return False
                else:
                    return False


        return True


def load_rules(filepath='rules_injection.yaml'):

    if not os.path.exists(filepath):
        print(f"[!] Error: Rule file '{filepath}' not found. Aborting.")
        sys.exit(1)
    with open(filepath, 'r') as f:
        return yaml.safe_load(f)

def scan_directory(directory_path, rules):
    
    all_vulnerabilities = []
    print(f"[*] Starting scan in directory: {directory_path}\n")

    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                print(f"  -> Analyzing: {file_path}")
                try:
                    with open(file_path, "r", encoding='utf-8') as source_file:
                        source_code = source_file.read()
                        tree = ast.parse(source_code, filename=file_path)
                        analyzer = ASTAnalyzer(file_path, rules)
                        analyzer.visit(tree)
                        all_vulnerabilities.extend(analyzer.vulnerabilities)
                except Exception as e:
                    print(f"     [!] Could not parse or analyze {file_path}. Skipping. Error: {e}")

    return all_vulnerabilities

def print_report(vulnerabilities):
 
    print("\n" + "="*50)
    print("          SAST SCAN REPORT")
    print("="*50)

    if not vulnerabilities:
        print("\n[+] No vulnerabilities found. Great job!")
        return

    for vuln in vulnerabilities:
        print(f"\n[!] Vulnerability: {vuln['type']}")
        print(f"    File: {vuln['file']}")
        print(f"    Line: {vuln['line']}")
        print(f"    Code: {vuln['code']}")
    
    print("\n" + "="*50)
    print(f"Scan finished. Total vulnerabilities found: {len(vulnerabilities)}")
    print("="*50)

def main():

    rules = load_rules('rules_injection.yaml')
    print(f"[*] Successfully loaded {len(rules)} rules.")

    if len(sys.argv) < 2:
        target_dir = "."
    else:
        target_dir = sys.argv[1]

    if not os.path.isdir(target_dir):
        print(f"Error: Directory '{target_dir}' not found.")
        sys.exit(1)
        
    found_vulns = scan_directory(target_dir, rules)
    print_report(found_vulns)

if __name__ == "__main__":
    main()

