import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.ast_parser import generate_ast
from detectors.unhandled_calls import analyze_ast_for_low_level_calls
from detectors.access_control import analyze_ast_for_access_control
from detectors.tx_origin import analyze_ast_for_tx_origin
from detectors.delegatecall_injection import detect_unsafe_delegatecall
from analyzer.chaining_engine import VulnerabilityChainer

def scan_file(sol_file):
    ast = generate_ast(sol_file)
    if not ast:
        print("[-] Could not generate AST. Make sure solc is installed.")
        return

    results = []
    print(f"[*] Scanning {sol_file} for isolated weaknesses...")
    
    # Run all detectors
    print("[*] Running: Low-Level .call() detection...")
    analyze_ast_for_low_level_calls(ast, sol_file, results)
    
    print("[*] Running: Access Control detection...")
    analyze_ast_for_access_control(ast, sol_file, results)
    
    print("[*] Running: tx.origin phishing detection...")
    analyze_ast_for_tx_origin(ast, sol_file, results)
    
    print("[*] Running: Unsafe delegatecall detection...")
    delegatecall_findings = detect_unsafe_delegatecall(ast)
    if delegatecall_findings:
        results.extend(delegatecall_findings)
    
    print(f"[*] Found {len(results)} isolated weaknesses. Sending to Chaining Engine...\n")

    # Initialize the creative Chaining Engine
    if results:
        chainer = VulnerabilityChainer(results)
        chainer.analyze()
        chainer.print_chains()
    else:
        print("[+] No vulnerabilities detected! Contract appears safe.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m cli.main <path_to_solidity_file>")
        sys.exit(1)
        
    target = sys.argv[1]
    if os.path.isfile(target):
        scan_file(target)
    else:
        print("[-] Target must be a valid .sol file.")
