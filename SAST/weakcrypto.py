import ast
import json
import os
import yaml

class CodeVulnerabilityVisitor(ast.NodeVisitor):
    def __init__(self, filepath, rules):
        self.findings = []
        self.filepath = filepath
        self.rules_map = {rule['pattern']: rule for rule in rules}
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
            if node.func.id in self.aliases:
                full_name = self.aliases[node.func.id]
            else:
                full_name = node.func.id  

        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                base_name = node.func.value.id
                if base_name in self.aliases:
                    full_name = f"{self.aliases[base_name]}.{node.func.attr}"
                else:
                    full_name = f"{base_name}.{node.func.attr}"
            else:
                full_name = node.func.attr

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
