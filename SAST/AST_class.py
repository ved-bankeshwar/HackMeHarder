import ast

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
