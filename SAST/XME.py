import ast
import re
import json

class XXEVisitor(ast.NodeVisitor):
    def __init__(self, filepath, insecure_rules, safelist):
        self.findings = []
        self.filepath = filepath
        self.safelist = safelist
        self.imports = {}

        # --- NEW: Pre-sort and pre-compile rules for efficiency ---
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
                # Pre-compile the regex for speed
                self.regex_rules[re.compile(pattern)] = rule

    # ... (visit_Import, visit_ImportFrom, and _get_fqn_from_call helpers remain the same) ...
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

        # --- NEW: Check against all three match types ---
        rule_to_report = None
        
        # 1. Check exact matches (fastest)
        if fqn in self.exact_rules:
            rule_to_report = self.exact_rules[fqn]
        
        # 2. Check startswith matches
        if not rule_to_report:
            for pattern, rule in self.startswith_rules.items():
                if fqn.startswith(pattern):
                    rule_to_report = rule
                    break
        
        # 3. Check regex matches (most flexible)
        if not rule_to_report:
            for pattern_obj, rule in self.regex_rules.items():
                if pattern_obj.search(fqn):
                    rule_to_report = rule
                    break

        if rule_to_report:
            self.findings.append({
                "type": "SAST-XXE", "rule_id": rule_to_report["id"], "description": rule_to_report["description"],
                "file": self.filepath, "line": node.lineno, "severity": rule_to_report["severity"]
            })
        
        self.generic_visit(node)

    def _get_fqn_from_call(self, node):
        # ... (This logic is unchanged) ...
        fully_qualified_name = ""
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
        if isinstance(node, ast.Attribute):
            return self._resolve_attribute_chain(node.value) + [node.attr]
        elif isinstance(node, ast.Name):
            return [node.id]
        else:
            return []

def scan(filepath, tree, rules):
    """Public scan function. Expects rules to be a dict with keys 'insecure' and 'safe'."""
    insecure_rules = rules.get('insecure', [])
    safelist = rules.get('safe', [])
    visitor = XXEVisitor(filepath, insecure_rules, safelist)
    visitor.visit(tree)
    return visitor.findings