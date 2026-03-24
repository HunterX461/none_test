import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analyzer.ast_parser import generate_ast
from detectors.unhandled_calls import analyze_ast_for_low_level_calls

def get_line_from_offset(file_path, offset):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
        return content[:int(offset)].count('\n') + 1

def scan_file(sol_file):
    ast = generate_ast(sol_file)
    if not ast:
        print("[-] Could not generate AST.")
        return

    results = []
    print("[*] Analyzing logic tree...")
    analyze_ast_for_low_level_calls(ast, sol_file, results)
    
    if results:
        print("\n[!] Vulnerabilities Found:")
        for res in results:
            line_num = get_line_from_offset(sol_file, res["offset"])
            print(f"  -> {res['type']} in {res['file']} at Line {line_num}: {res['description']}")
    else:
        print("\n[+] No obvious logical vulnerabilities found in AST.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m cli.main <path_to_solidity_file>")
        sys.exit(1)
        
    target = sys.argv[1]
    if os.path.isfile(target):
        scan_file(target)
    else:
        print("[-] Target must be a valid .sol file.")