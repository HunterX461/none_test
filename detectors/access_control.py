def analyze_ast_for_access_control(node, file_name, results, current_function=None):
    if isinstance(node, dict):
        node_type = node.get("nodeType")
        
        # Track which function we are inside
        if node_type == "FunctionDefinition":
            current_function = node.get("name", "fallback")
            visibility = node.get("visibility")
            modifiers = node.get("modifiers", [])
            
            # If function is public/external and has no modifiers, flag it
            if visibility in ["public", "external"] and len(modifiers) == 0:
                source_info = node.get("src", "0:0:0").split(":")
                results.append({
                    "type": "Missing Access Control",
                    "description": f"Function '{current_function}' is {visibility} but lacks access control modifiers.",
                    "file": file_name,
                    "function": current_function,
                    "offset": source_info[0]
                })

        for key, value in node.items():
            if isinstance(value, (dict, list)):
                analyze_ast_for_access_control(value, file_name, results, current_function)
            
    elif isinstance(node, list):
        for item in node:
            analyze_ast_for_access_control(item, file_name, results, current_function)