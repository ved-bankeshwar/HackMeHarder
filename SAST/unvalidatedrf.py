import ast

class UnvalidatedRedirectVisitor(ast.NodeVisitor):
    """
    Performs taint analysis to find Unvalidated Redirect vulnerabilities.
    """
    def __init__(self, filepath, rules):
        self.findings = []
        self.filepath = filepath
        self.taint_rules = rules # Expects {'sources': [...], 'sinks': [...]}
        self.imports = {}
        self.tainted_variables = set()

    # --- Import visitors for alias tracking ---
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
        """Reset tainted variables for each new function scope."""
        self.tainted_variables = set()
        self.generic_visit(node)

    def visit_Assign(self, node):
        """Checks if a variable is being tainted by a dangerous source."""
        if isinstance(node.value, ast.Call):
            call_fqn = self._get_fqn_from_call(node.value)
            if call_fqn in self.taint_rules.get('sources', []):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_variables.add(target.id)
        self.generic_visit(node)

    def visit_Call(self, node):
        """Checks if a redirect sink is called with a tainted variable."""
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
        """Recursively checks if any variable in an expression is tainted."""
        if isinstance(arg_node, ast.Name): return arg_node.id in self.tainted_variables
        elif isinstance(arg_node, ast.BinOp): return self._is_arg_tainted(arg_node.left) or self._is_arg_tainted(arg_node.right)
        elif isinstance(arg_node, ast.Call): return any(self._is_arg_tainted(arg) for arg in arg_node.args)
        # ... (add other expression types like Subscript, List, etc. as needed) ...
        return False

    def _get_fqn_from_call(self, node):
        """Helper to resolve the fully qualified name of a Call node."""
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

def scan(filepath, tree, rules):
    """Public scan function for this module."""
    visitor = UnvalidatedRedirectVisitor(filepath, rules)
    visitor.visit(tree)
    return visitor.findings