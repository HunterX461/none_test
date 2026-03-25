class ControlFlowGraph:
    def __init__(self, ast):
        self.ast = ast
        self.nodes = []
        self.edges = []
    
    def build(self):
        """Build a control flow graph from the AST."""
        self._traverse_ast(self.ast)
        return self.nodes, self.edges
    
    def _traverse_ast(self, node, parent=None):
        """Traverse AST and build CFG nodes and edges."""
        if isinstance(node, dict):
            node_type = node.get("nodeType")
            if node_type in ["If", "FunctionDefinition", "For", "While"]:
                node_id = id(node)
                self.nodes.append({"id": node_id, "type": node_type})
                if parent:
                    self.edges.append({"from": parent, "to": node_id})
                for key, value in node.items():
                    if isinstance(value, (dict, list)):
                        self._traverse_ast(value, node_id)
        elif isinstance(node, list):
            for item in node:
                self._traverse_ast(item, parent)