def analyze_ast_for_tx_origin(node, file_name, results, current_function=None):
    """Detects usage of tx.origin for authentication (phishing vulnerability)."""
    if isinstance(node, dict):
        node_type = node.get("nodeType")
        if node_type == "FunctionDefinition":
            current_function = node.get("name", "fallback")
        if node_type == "MemberAccess" and node.get("memberName") == "origin":
            source_info = node.get("src", "0:0:0").split(":")
            results.append({"type": "Tx.origin Authentication", "description": f"Usage of tx.origin detected in function '{current_function}'. This is vulnerable to phishing attacks. Use msg.sender instead.", "file": file_name, "function": current_function, "offset": source_info[0]})
        for key, value in node.items():
            if isinstance(value, (dict, list)):
                analyze_ast_for_tx_origin(value, file_name, results, current_function)
    elif isinstance(node, list):
        for item in node:
            analyze_ast_for_tx_origin(item, file_name, results, current_function)