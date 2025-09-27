import ast
import json
import os
import yaml
import re
import sys
import argparse

# ========================= Combined Analyzer ========================= #
class CombinedAnalyzer(ast.NodeVisitor):
    def __init__(self, file_path, all_rules):
        self.file_path = file_path
        self.findings = []

        # Initialize sub-analyzers
        # xss_rules is a dict (with sources/sinks)
        self.xss = XSSAnalyzer(file_path, all_rules.get('xss_rules', {}))

        # rule-based scanner uses weak_crypto + insecure_deserialization rule lists
        self.rule_based = RuleBasedScanner(
            file_path,
            all_rules.get('weak_crypto_rules', []) + all_rules.get('insecure_deserialization_rules', [])
        )

        # Use the proper sub-sections for taint-analysis related checks
        taint_rules = all_rules.get('taint_analysis_rules', {}) or {}
        self.path_traversal_rules = taint_rules.get('path_traversal', {}) or {}
        self.unvalidated_redirect_rules = taint_rules.get('unvalidated_redirect', {}) or {}
        self.sql_injection_rules = taint_rules.get('sql_injection', {}) or {}
        self.command_injection_rules = taint_rules.get('command_injection', {}) or {}

        # XXE rules (insecure parsers + safe list)
        self.xx_rules = {
            'insecure': all_rules.get('insecure_parsing_rules', []),
            'safe': all_rules.get('safe_xml_modules', [])
        }

        # Pre-scan deserialization once per file
        try:
            self.findings.extend(scan_deserialization_file(self.file_path))
        except Exception as e:
            print(f"[!] DeserializationAnalyzer failed: {e}")

        self._full_tree_scanned = False

    def visit(self, node):
            # Node-level analyzers
            for analyzer in [self.xss, self.rule_based]:
                analyzer.visit(node)

            # Full-file analyzers (run once per file)
            if not self._full_tree_scanned:
                # XXE needs the full tree (we pass xx_rules as { 'insecure': [...], 'safe': [...] })
                self.findings.extend(scan_xxe_file(self.file_path, node, self.xx_rules))

                # Taint-based rules (path traversal, unvalidated redirect, sql, command)
                self.findings.extend(scan_path_traversal_file(self.file_path, node, self.path_traversal_rules))
                self.findings.extend(scan_unvalidated_redirect_file(self.file_path, node, self.unvalidated_redirect_rules))

                self.findings.extend(scan_sql_injection_file(self.file_path, node, self.sql_injection_rules))
                self.findings.extend(scan_command_injection_file(self.file_path, node, self.command_injection_rules))
                
                self._full_tree_scanned = True

            super().visit(node)

# ========================= Code Vulnerability Visitor ========================= #
class CodeVulnerabilityVisitor(ast.NodeVisitor):
    def __init__(self, filepath, rules):
        self.findings = []
        self.filepath = filepath
        self.rules_map = {}
        for rule in rules:
            key = rule.get('pattern') or rule.get('id')
            if key:
                self.rules_map[key] = rule
        self.aliases = {}

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
        full_name = None
        if isinstance(node.func, ast.Name):
            full_name = self.aliases.get(node.func.id, node.func.id)
        elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            base_name = node.func.value.id
            full_name = f"{self.aliases.get(base_name, base_name)}.{node.func.attr}"

        if full_name and full_name in self.rules_map:
            rule = self.rules_map[full_name]
            self.findings.append({
                "type": "SAST-WeakCrypto",
                "rule_id": rule["id"],
                "description": rule["description"],
                "file": self.filepath,
                "line": node.lineno,
                "severity": rule["severity"]
            })

        self.generic_visit(node)

# ========================= Deserialization Analyzer ========================= #
class DeserializationAnalyzer(ast.NodeVisitor):
    def __init__(self, file_path):
        self.vulnerabilities = []
        self.file_path = file_path
        self.aliases = {}
        self.dangerous_deserializers = {
            'pickle': ['load', 'loads'],
            '_pickle': ['load', 'loads'],
            'shelve': ['open'],
            'yaml': ['load']
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
            full_name_of_call = self.aliases.get(func.id, func.id)
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            base_name = func.value.id
            full_name_of_call = f"{self.aliases.get(base_name, base_name)}.{func.attr}"

        if full_name_of_call:
            parts = full_name_of_call.split('.')
            if len(parts) == 2:
                module, function = parts
                if module in self.dangerous_deserializers and function in self.dangerous_deserializers[module]:
                    self.add_vulnerability(node, full_name_of_call)

        self.generic_visit(node)

    def add_vulnerability(self, node, call_name):
        detail = f"Call to insecure deserialization function '{call_name}' detected. Un-trusted data can lead to RCE."
        vuln = {
            "type": "Insecure Deserialization",
            "file": self.file_path,
            "line": node.lineno,
            "detail": detail
        }
        if not any(v['line'] == vuln['line'] and v['type'] == vuln['type'] for v in self.vulnerabilities):
            self.vulnerabilities.append(vuln)

def scan_deserialization_file(filepath):
    all_findings = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            tree = ast.parse(content, filename=filepath)
            analyzer = DeserializationAnalyzer(filepath)
            analyzer.visit(tree)
            all_findings.extend(analyzer.vulnerabilities)
    except Exception as e:
        print(f"Could not parse or read file {filepath}: {e}")
    return all_findings

# ========================= XXE Visitor ========================= #
class XXEVisitor(ast.NodeVisitor):
    def __init__(self, filepath, insecure_rules, safelist):
        self.findings = []
        self.filepath = filepath
        self.safelist = safelist
        self.imports = {}
        self.exact_rules = {}
        self.startswith_rules = {}
        self.regex_rules = {}

        for rule in insecure_rules:
            pattern = rule['pattern']
            match_type = rule.get('match_type', 'exact')
            if match_type == 'exact':
                self.exact_rules[pattern] = rule
            elif match_type == 'startswith':
                self.startswith_rules[pattern] = rule
            elif match_type == 'regex':
                self.regex_rules[re.compile(pattern)] = rule

    def visit_Import(self, node):
        for alias in node.names: self.imports[alias.asname or alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module
        for alias in node.names:
            full_name = f"{module}.{alias.name}" if module else alias.name
            self.imports[alias.asname or alias.name] = full_name
        self.generic_visit(node)

    def visit_Call(self, node):
        fqn = self._get_fqn_from_call(node)
        if not fqn:
            self.generic_visit(node)
            return
        if any(fqn.startswith(safe_module) for safe_module in self.safelist):
            self.generic_visit(node)
            return
        rule_to_report = None
        if fqn in self.exact_rules: rule_to_report = self.exact_rules[fqn]
        if not rule_to_report:
            for pattern, rule in self.startswith_rules.items():
                if fqn.startswith(pattern):
                    rule_to_report = rule
                    break
        if not rule_to_report:
            for pattern_obj, rule in self.regex_rules.items():
                if pattern_obj.search(fqn):
                    rule_to_report = rule
                    break
        if rule_to_report:
            self.findings.append({
                "type": "SAST-XXE", "rule_id": rule_to_report["id"],
                "description": rule_to_report["description"],
                "file": self.filepath, "line": node.lineno,
                "severity": rule_to_report["severity"]
            })
        self.generic_visit(node)

    def _resolve_attribute_chain(self, node):
        if isinstance(node, ast.Attribute): return self._resolve_attribute_chain(node.value) + [node.attr]
        elif isinstance(node, ast.Name): return [node.id]
        else: return []

    def _get_fqn_from_call(self, node):
        if isinstance(node.func, ast.Attribute):
            chain = self._resolve_attribute_chain(node.func)
            if not chain: return None
            base_object = chain[0]
            module_name = self.imports.get(base_object, base_object)
            return f"{module_name}.{'.'.join(chain[1:])}" if len(chain) > 1 else module_name
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id
            return self.imports.get(func_name, func_name)
        return None

def scan_xxe_file(filepath, tree, rules):
    insecure_rules = rules.get('insecure', [])
    safelist = rules.get('safe', [])
    visitor = XXEVisitor(filepath, insecure_rules, safelist)
    visitor.visit(tree)
    return visitor.findings

# ========================= Path Traversal ========================= #
class PathTraversalVisitor(ast.NodeVisitor):
    def __init__(self, filepath, rules):
        self.findings = []
        self.filepath = filepath
        self.taint_rules = rules
        self.global_taints = set()
        self.tainted_variables = set()
        self.imports = {}

    def visit_Import(self, node):
        for alias in node.names: self.imports[alias.asname or alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module
        for alias in node.names:
            full_name = f"{module}.{alias.name}" if module else alias.name
            self.imports[alias.asname or alias.name] = full_name
        self.generic_visit(node)

    def visit_Assign(self, node):
        if isinstance(node.value, ast.Call):
            call_fqn = self._get_fqn(node.value)
            if call_fqn in self.taint_rules.get('sources', []):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_variables.add(target.id)
        self.generic_visit(node)

    def visit_Call(self, node):
        call_fqn = self._get_fqn(node)
        if call_fqn in self.taint_rules.get('sinks', []):
            for arg in node.args:
                if self._is_tainted(arg):
                    self.findings.append({
                        "type": "SAST-PathTraversal",
                        "file": self.filepath,
                        "line": node.lineno,
                        "detail": f"Tainted variable used in sink '{call_fqn}'"
                    })
        self.generic_visit(node)

    def _is_tainted(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.tainted_variables or node.id in self.global_taints
        elif isinstance(node, ast.BinOp):
            return self._is_tainted(node.left) or self._is_tainted(node.right)
        elif isinstance(node, ast.Call):
            return any(self._is_tainted(arg) for arg in node.args)
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self._is_tainted(elt) for elt in node.elts)
        elif isinstance(node, ast.Subscript):
            return self._is_tainted(node.value)
        elif isinstance(node, ast.Attribute):
            return self._is_tainted(node.value)
        return False

    def _get_fqn(self, node):
        if isinstance(node.func, ast.Name):
            return self.imports.get(node.func.id, node.func.id)
        elif isinstance(node.func, ast.Attribute):
            chain = []
            curr = node.func
            while isinstance(curr, ast.Attribute):
                chain.insert(0, curr.attr)
                curr = curr.value
            if isinstance(curr, ast.Name):
                base = self.imports.get(curr.id, curr.id)
                chain.insert(0, base)
                return ".".join(chain)
        return None

def scan_path_traversal_file(filepath, tree, rules):
    visitor = PathTraversalVisitor(filepath, rules)
    visitor.visit(tree)
    return visitor.findings

# ========================= Unvalidated Redirect ========================= #
class UnvalidatedRedirectVisitor(ast.NodeVisitor):
    def __init__(self, filepath, rules):
        self.findings = []
        self.filepath = filepath
        self.taint_rules = rules
        self.global_taints = set()
        self.imports = {}
        self.tainted_variables = set()

    def visit_Import(self, node):
        for alias in node.names: self.imports[alias.asname or alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module
        for alias in node.names:
            full_name = f"{module}.{alias.name}" if module else alias.name
            self.imports[alias.asname or alias.name] = full_name
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        local_taints = set()
        for sub_node in ast.walk(node):
            if isinstance(sub_node, ast.Assign):
                if isinstance(sub_node.value, ast.Name) and sub_node.value.id in self.global_taints:
                    for target in sub_node.targets:
                        if isinstance(target, ast.Name):
                            local_taints.add(target.id)
                elif isinstance(sub_node.value, ast.Call):
                    call_fqn = self._get_fqn_from_call(sub_node.value)
                    if call_fqn in self.taint_rules.get('sources', []):
                        for target in sub_node.targets:
                            if isinstance(target, ast.Name):
                                local_taints.add(target.id)
        self.global_taints.update(local_taints)
        self.generic_visit(node)

    def visit_Assign(self, node):
        if isinstance(node.value, ast.Call):
            call_fqn = self._get_fqn_from_call(node.value)
            if call_fqn in self.taint_rules.get('sources', []):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_variables.add(target.id)
        self.generic_visit(node)

    def visit_Call(self, node):
        call_fqn = self._get_fqn_from_call(node)
        if call_fqn in self.taint_rules.get('sinks', []):
            for arg in node.args:
                if self._is_arg_tainted(arg):
                    rule = self.taint_rules
                    self.findings.append({
                        "type": "SAST-UnvalidatedRedirect",
                        "rule_id": rule.get("id", "unvalidated-redirect"),
                        "description": f"{rule.get('description', '')} A tainted variable was used in sink '{call_fqn}'.",
                        "file": self.filepath,
                        "line": node.lineno,
                        "severity": rule.get("severity", "Medium")
                    })
                    break
        self.generic_visit(node)

    def _is_arg_tainted(self, arg_node):
        if isinstance(arg_node, ast.Name):
            return arg_node.id in self.tainted_variables or arg_node.id in self.global_taints
        elif isinstance(arg_node, ast.BinOp):
            return self._is_arg_tainted(arg_node.left) or self._is_arg_tainted(arg_node.right)
        elif isinstance(arg_node, ast.Call):
            return any(self._is_arg_tainted(arg) for arg in arg_node.args)
        elif isinstance(arg_node, (ast.List, ast.Tuple, ast.Set)):
            return any(self._is_arg_tainted(elt) for elt in arg_node.elts)
        elif isinstance(arg_node, ast.Subscript):
            return self._is_arg_tainted(arg_node.value)
        elif isinstance(arg_node, ast.Attribute):
            return self._is_arg_tainted(arg_node.value)
        return False

    def _get_fqn_from_call(self, node):
        if isinstance(node.func, ast.Attribute):
            chain = self._resolve_attribute_chain(node.func)
            if not chain: return None
            base_object = chain[0]
            module_name = self.imports.get(base_object, base_object)
            return f"{module_name}.{'.'.join(chain[1:])}"
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id
            return self.imports.get(func_name, func_name)
        return None

    def _resolve_attribute_chain(self, node):
        if isinstance(node, ast.Attribute): return self._resolve_attribute_chain(node.value) + [node.attr]
        elif isinstance(node, ast.Name): return [node.id]
        else: return []

def scan_unvalidated_redirect_file(filepath, tree, rules):
    visitor = UnvalidatedRedirectVisitor(filepath, rules)
    visitor.visit(tree)
    return visitor.findings

# ========================= XSS Analyzer ========================= #
class XSSAnalyzer(ast.NodeVisitor):
    def __init__(self, file_path, rules):
        self.vulnerabilities = []
        self.file_path = file_path
        self.global_taints = set()
        self.sources = rules.get('sources', [])
        self.sinks = rules.get('sinks', [])

    def visit_FunctionDef(self, node):
        local_taints = set()
        for sub_node in ast.walk(node):
            if isinstance(sub_node, ast.Assign):
                if isinstance(sub_node.value, ast.Name) and sub_node.value.id in self.global_taints:
                    for target in sub_node.targets:
                        if isinstance(target, ast.Name):
                            local_taints.add(target.id)
                else:
                    try:
                        rhs_str = ast.unparse(sub_node.value)
                        if any(src in rhs_str for src in self.sources):
                            for target in sub_node.targets:
                                if isinstance(target, ast.Name):
                                    local_taints.add(target.id)
                    except Exception:
                        continue
        self.global_taints.update(local_taints)
        self.generic_visit(node)

    def visit_Call(self, node):
        try:
            func_name = ast.unparse(node.func)
            for sink in self.sinks:
                if sink in func_name:
                    for arg in node.args:
                        if self._is_tainted(arg):
                            self.vulnerabilities.append({
                                "type": "SAST-XSS",
                                "file": self.file_path,
                                "line": node.lineno,
                                "sink": func_name,
                                "detail": "Tainted variable passed to sink"
                            })
        except Exception:
            pass
        self.generic_visit(node)

    def _is_tainted(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.global_taints
        elif isinstance(node, ast.BinOp):
            return self._is_tainted(node.left) or self._is_tainted(node.right)
        elif isinstance(node, ast.Call):
            return any(self._is_tainted(arg) for arg in node.args)
        elif isinstance(node, (ast.List, ast.Tuple)):
            return any(self._is_tainted(elt) for elt in node.elts)
        elif isinstance(node, ast.Subscript):
            return self._is_tainted(node.value)
        return False

# ========================= Rule-Based Scanner ========================= #
class RuleBasedScanner(ast.NodeVisitor):
    def __init__(self, file_path, rules):
        self.vulnerabilities = []
        self.file_path = file_path
        self.rules_map = {r['pattern']: r for r in rules}
        self.imports = {}

    def visit_Import(self, node):
        for alias in node.names:
            self.imports[alias.asname or alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module
        for alias in node.names:
            full_name = f"{module}.{alias.name}" if module else alias.name
            self.imports[alias.asname or alias.name] = full_name
        self.generic_visit(node)

    def visit_Call(self, node):
        fqn = self._get_fqn_from_call(node)
        if fqn and fqn in self.rules_map:
            rule = self.rules_map[fqn]
            self.vulnerabilities.append({
                "type": rule.get('id', 'Pattern Match'),
                "file": self.file_path,
                "line": node.lineno,
                "code": ast.unparse(node).strip(),
                "severity": rule.get('severity', 'N/A'),
                "detail": rule.get('description', '')
            })
        self.generic_visit(node)

    def _get_fqn_from_call(self, node):
        if isinstance(node.func, ast.Name):
            return self.imports.get(node.func.id, node.func.id)
        elif isinstance(node.func, ast.Attribute):
            chain = []
            curr = node.func
            while isinstance(curr, ast.Attribute):
                chain.insert(0, curr.attr)
                curr = curr.value
            if isinstance(curr, ast.Name):
                base = self.imports.get(curr.id, curr.id)
                chain.insert(0, base)
                return ".".join(chain)
        return None

# ========================= Helper Functions ========================= #
def deduplicate_findings(findings):
    seen = set()
    unique = []
    for f in findings:
        key = (f["file"], f.get("line"), f.get("type"), f.get("rule_id"))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique

def scan_file(filepath, all_rules):
    all_findings = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read(), filename=filepath)
            combined = CombinedAnalyzer(filepath, all_rules)
            combined.visit(tree)
            all_findings.extend(combined.findings)
    except Exception as e:
        print(f"[!] Failed to read or parse file {filepath}: {e}")
    return deduplicate_findings(all_findings)

def load_rules(filepath=None):
    if not filepath:
        filepath = os.path.join(os.getcwd(), "rules.yaml")
    if not os.path.exists(filepath):
        print(f"[!] Error: Rule file '{filepath}' not found.")
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
                    all_vulnerabilities.extend(scan_file(file_path, rules))
                except Exception as e:
                    print(f"     [!] Could not analyze {file_path}. Error: {e}")
    return all_vulnerabilities

# ========================= SQL Injection Visitor ========================= #
class SQLInjectionVisitor(ast.NodeVisitor):
    """
    Taint-based SQL Injection detection.
    Expects rules to be a dict with keys:
      - 'sources': list of fully-qualified source patterns (e.g. 'request.args.get')
      - 'sinks': list of sink patterns (e.g. 'cursor.execute')
      - 'id', 'description', 'severity' optionally for reporting
    """
    def __init__(self, filepath, rules):
        self.findings = []
        self.filepath = filepath
        self.taint_rules = rules or {}
        self.imports = {}
        self.tainted_variables = set()

    def visit_Import(self, node):
        for alias in node.names:
            self.imports[alias.asname or alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module
        for alias in node.names:
            full_name = f"{module}.{alias.name}" if module else alias.name
            self.imports[alias.asname or alias.name] = full_name
        self.generic_visit(node)

    def visit_Assign(self, node):
        # If RHS is a call to a source, mark LHS as tainted
        if isinstance(node.value, ast.Call):
            call_fqn = self._get_fqn_from_call(node.value)
            if call_fqn in self.taint_rules.get('sources', []):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_variables.add(target.id)
        # Also handle direct assignment from previously tainted variable: a = b
        if isinstance(node.value, ast.Name):
            if node.value.id in self.tainted_variables:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_variables.add(target.id)
        self.generic_visit(node)

    def visit_Call(self, node):
        call_fqn = self._get_fqn_from_call(node)
        if not call_fqn:
            self.generic_visit(node)
            return

        # If this call is a sink, check its first positional arg for taint/unsafe concatenation
        if call_fqn in self.taint_rules.get('sinks', []):
            # check args
            for arg in node.args:
                if self._is_tainted_expr(arg) or self._is_probably_unsafe_string(arg):
                    rule = self.taint_rules
                    self.findings.append({
                        "type": "SAST-SQLInjection",
                        "rule_id": rule.get("id", "sql-injection"),
                        "description": rule.get("description", f"Potential SQL injection via sink {call_fqn}"),
                        "file": self.filepath,
                        "line": node.lineno,
                        "severity": rule.get("severity", "Critical")
                    })
                    break
        self.generic_visit(node)

    def _is_tainted_expr(self, node):
        # Recursively check if expression contains a tainted variable
        if isinstance(node, ast.Name):
            return node.id in self.tainted_variables
        elif isinstance(node, ast.BinOp):
            return self._is_tainted_expr(node.left) or self._is_tainted_expr(node.right)
        elif isinstance(node, ast.Call):
            return any(self._is_tainted_expr(a) for a in node.args)
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self._is_tainted_expr(e) for e in node.elts)
        elif isinstance(node, ast.Subscript):
            return self._is_tainted_expr(node.value)
        elif isinstance(node, ast.JoinedStr):
            # f-strings contain formatted values; check values
            for value in node.values:
                if self._is_tainted_expr(value):
                    return True
            return False
        return False

    def _is_probably_unsafe_string(self, node):
        # Heuristic: binary concatenation or formatted strings used to build SQL
        if isinstance(node, ast.BinOp):
            # if either side is a string literal and the other side uses a Name or Call, treat as suspicious
            if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str) and self._is_tainted_expr(node.right):
                return True
            if isinstance(node.right, ast.Constant) and isinstance(node.right.value, str) and self._is_tainted_expr(node.left):
                return True
            # if both sides are non-constant but join into a combined expression, consider unsafe if any side tainted
            return self._is_tainted_expr(node.left) or self._is_tainted_expr(node.right)
        if isinstance(node, ast.JoinedStr):  # f-string
            return self._is_tainted_expr(node)
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            # string literal alone is not unsafe
            return False
        return False

    def _get_fqn_from_call(self, node):
        if isinstance(node.func, ast.Attribute):
            chain = []
            cur = node.func
            while isinstance(cur, ast.Attribute):
                chain.insert(0, cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                base = self.imports.get(cur.id, cur.id)
                chain.insert(0, base)
                fqn = ".".join(chain)
                print(f"[DEBUG] Call FQN: {fqn}")
                return fqn
        elif isinstance(node.func, ast.Name):
            fqn = self.imports.get(node.func.id, node.func.id)
            print(f"[DEBUG] Call FQN: {fqn}")
            return fqn
        return None

def scan_sql_injection_file(filepath, tree, rules):
    """
    rules is expected to be a dict like the one in rules.yaml:
      taint_analysis_rules:
        sql_injection: { id, description, sources: [...], sinks: [...], severity: ... }
    """
    visitor = SQLInjectionVisitor(filepath, rules)
    visitor.visit(tree)
    return visitor.findings

# ========================= Command Injection Visitor ========================= #
class CommandInjectionVisitor(ast.NodeVisitor):
    """
    Detects command injection:
      - os.system(...) with tainted input
      - subprocess.run/call/Popen with shell=True or with tainted args
    Rules expected similar to SQL: { 'sources': [...], 'sinks': [...], 'id'... }
    """
    def __init__(self, filepath, rules):
        self.findings = []
        self.filepath = filepath
        self.taint_rules = rules or {}
        self.imports = {}
        self.tainted_variables = set()

    def visit_Import(self, node):
        for alias in node.names:
            self.imports[alias.asname or alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module
        for alias in node.names:
            full_name = f"{module}.{alias.name}" if module else alias.name
            self.imports[alias.asname or alias.name] = full_name
        self.generic_visit(node)

    def visit_Assign(self, node):
        # Mark taint when RHS is source or tainted name
        if isinstance(node.value, ast.Call):
            fqn = self._get_fqn_from_call(node.value)
            if fqn in self.taint_rules.get('sources', []):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_variables.add(target.id)
        if isinstance(node.value, ast.Name) and node.value.id in self.tainted_variables:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_variables.add(target.id)
        self.generic_visit(node)

    def visit_Call(self, node):
        call_fqn = self._get_fqn_from_call(node)
        if not call_fqn:
            self.generic_visit(node)
            return

        # Direct sinks: os.system, subprocess.*
        sinks = self.taint_rules.get('sinks', [])
        if call_fqn in sinks:
            # if any arg is tainted -> report
            for arg in node.args:
                if self._is_tainted_expr(arg):
                    self._report(node, f"Argument to {call_fqn} appears tainted")
                    break
            # also check for shell=True in kwargs (dangerous)
            for kw in node.keywords:
                if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._report(node, f"{call_fqn} called with shell=True")
                    break

        # subprocess.run with shell=True even if args not tainted is dangerous (flag)
        if call_fqn in ('subprocess.run', 'subprocess.Popen', 'subprocess.call') or call_fqn.endswith('.subprocess.run'):
            # check shell kwarg
            for kw in node.keywords:
                if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._report(node, "subprocess called with shell=True (possible command injection)")
                    break

        self.generic_visit(node)

    def _is_tainted_expr(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.tainted_variables
        elif isinstance(node, ast.BinOp):
            return self._is_tainted_expr(node.left) or self._is_tainted_expr(node.right)
        elif isinstance(node, ast.Call):
            return any(self._is_tainted_expr(a) for a in node.args)
        elif isinstance(node, ast.JoinedStr):
            return any(self._is_tainted_expr(v) for v in node.values if isinstance(v, (ast.FormattedValue, ast.Name)))
        elif isinstance(node, (ast.List, ast.Tuple)):
            return any(self._is_tainted_expr(e) for e in node.elts)
        elif isinstance(node, ast.Subscript):
            return self._is_tainted_expr(node.value)
        return False

    def _get_fqn_from_call(self, node):
        if isinstance(node.func, ast.Attribute):
            chain = []
            cur = node.func
            while isinstance(cur, ast.Attribute):
                chain.insert(0, cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                base = self.imports.get(cur.id, cur.id)
                chain.insert(0, base)
                return ".".join(chain)
        elif isinstance(node.func, ast.Name):
            return self.imports.get(node.func.id, node.func.id)
        return None

    def _report(self, node, detail):
        rule = self.taint_rules or {}
        self.findings.append({
            "type": "SAST-CommandInjection",
            "rule_id": rule.get("id", "command-injection"),
            "description": rule.get("description", detail),
            "file": self.filepath,
            "line": node.lineno,
            "severity": rule.get("severity", "Critical")
        })



def scan_command_injection_file(filepath, tree, rules):
    visitor = CommandInjectionVisitor(filepath, rules)
    visitor.visit(tree)
    return visitor.findings