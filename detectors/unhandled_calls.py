def analyze_ast_for_low_level_calls(node, file_name, results):
    if isinstance(node, dict):
        node_type = node.get("nodeType")
        if node_type == "MemberAccess" and node.get("memberName") == "call":
            source_info = node.get("src", "0:0:0").split(":")
            offset = source_info[0]
            results.append({
                "type": "Low-Level Call",
                "description": "Found a low-level .call() which can lead to reentrancy if state is updated after it.",
                "file": file_name,
                "offset": offset
            })
        for key, value in node.items():
            analyze_ast_for_low_level_calls(value, file_name, results)
    elif isinstance(node, list):
        for item in node:
            analyze_ast_for_low_level_calls(item, file_name, results)