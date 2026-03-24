import json
import subprocess
import sys
import os

def generate_ast(solidity_file):
    print(f"[*] Generating AST for {solidity_file}...")
    try:
        result = subprocess.run(
            ["solc", "--ast-compact-json", solidity_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        output = result.stdout
        parts = output.split("======")
        for i in range(len(parts)):
            if solidity_file in parts[i]:
                ast_json_str = parts[i+1].strip()
                return json.loads(ast_json_str)
    except subprocess.CalledProcessError as e:
        print(f"[-] solc failed: {e.stderr}")
        sys.exit(1)
    except json.JSONDecodeError:
        print("[-] Failed to parse solc AST output.")
        sys.exit(1)