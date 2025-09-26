import ast

class XSSAnalyzer(ast.NodeVisitor):
   
    def __init__(self, file_path):
        self.vulnerabilities = []
        self.file_path = file_path
       
        self.sources = [
            'request.args',
            'request.form',
            'request.values',
            'request.data',
            'request.json'
        ]
       
        self.sinks = [
            'render_template_string', 
            'Markup' 
        ]

    def visit_FunctionDef(self, node):
        
        tainted_variables = set()

        
        for sub_node in ast.walk(node):
            if isinstance(sub_node, ast.Assign):
                
                value_node = sub_node.value
                
            
                unparsed_value = ast.unparse(value_node)
                if any(source in unparsed_value for source in self.sources):
        
                    for target in sub_node.targets:
                        if isinstance(target, ast.Name):
                            tainted_variables.add(target.id)

      
        for sub_node in ast.walk(node):
            if isinstance(sub_node, ast.Call):
                call_name = ""
                if isinstance(sub_node.func, ast.Name):
                    call_name = sub_node.func.id
                elif isinstance(sub_node.func, ast.Attribute):
                    call_name = sub_node.func.attr
                
          
                if call_name in self.sinks:
            
                    for arg in sub_node.args:
                        if isinstance(arg, ast.Name) and arg.id in tainted_variables:
                            vuln = {
                                "type": "Cross-Site Scripting (XSS)",
                                "file": self.file_path,
                                "line": sub_node.lineno,
                                "code": ast.unparse(sub_node).strip(),
                                "detail": f"Tainted variable '{arg.id}' is used in a dangerous sink '{call_name}'."
                            }
                            self.vulnerabilities.append(vuln)
                           
                            break


        return
