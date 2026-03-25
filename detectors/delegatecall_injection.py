def detect_unsafe_delegatecall(ast_node):
    unsafe_delegatecalls = []
    if isinstance(ast_node, dict):
        if ast_node.get("nodeType") == "MemberAccess" and ast_node.get("memberName") == "delegatecall":
            unsafe_delegatecalls.append({"type": "Unsafe Delegatecall", "severity": "CRITICAL", "description": "delegatecall detected with potentially unvalidated target address"})
        for key, value in ast_node.items() if isinstance(ast_node, dict) else enumerate(ast_node if isinstance(ast_node, list) else []):
            if isinstance(value, (dict, list)):
                unsafe_delegatecalls.extend(detect_unsafe_delegatecall(value))
    return unsafe_delegatecalls;