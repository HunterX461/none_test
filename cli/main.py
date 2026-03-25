import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.ast_parser import generate_ast
from analyzer.dependency_mapper import DependencyMapper
from detectors.llm_logic_analyzer import LLMLogicAnalyzer
from detectors.unhandled_calls import analyze_ast_for_low_level_calls
from detectors.access_control import analyze_ast_for_access_control
from detectors.tx_origin import analyze_ast_for_tx_origin
from detectors.delegatecall_injection import detect_unsafe_delegatecall

class RepoScanner:
    def __init__(self, target_path, use_llm=True):
        self.target_path = target_path
        self.sol_files = []
        self.all_findings = {}
        self.dependency_map = {}
        self.dependency_mapper = DependencyMapper(target_path)
        self.use_llm = use_llm
        self.llm_analyzer = None
        
        if use_llm:
            print("\n[*] Initializing LLM analyzer...")
            self.llm_analyzer = LLMLogicAnalyzer()
        
    def find_all_sol_files(self):
        print(f"\n[*] Searching for Solidity files in {self.target_path}...")
        for root, dirs, files in os.walk(self.target_path):
            for file in files:
                if file.endswith('.sol'):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, self.target_path)
                    self.sol_files.append(full_path)
                    print(f"    [+] Found: {rel_path}")
        
        if not self.sol_files:
            print("[-] No .sol files found!")
            return False
        
        print(f"[+] Total: {len(self.sol_files)} files\n")
        return True
    
    def build_dependency_graph(self):
        print("[*] Building dependency graph...")
        for sol_file in self.sol_files:
            try:
                with open(sol_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    imports = self.dependency_mapper.extract_imports(content)
                    if imports:
                        self.dependency_map[sol_file] = imports
            except Exception as e:
                pass
        print()
    
    def scan_file(self, sol_file):
        """Scan file with BOTH pattern detectors AND LLM"""
        results = []
        
        # Read source code first
        try:
            with open(sol_file, 'r', encoding='utf-8', errors='ignore') as f:
                source_code = f.read()
        except:
            return results
        
        # Pattern-based detection
        ast = generate_ast(sol_file)
        if ast:
            analyze_ast_for_low_level_calls(ast, sol_file, results)
            analyze_ast_for_access_control(ast, sol_file, results)
            analyze_ast_for_tx_origin(ast, sol_file, results)
            delegatecall_findings = detect_unsafe_delegatecall(ast)
            if delegatecall_findings:
                results.extend(delegatecall_findings)
        
        # LLM-based detection
        if self.use_llm and self.llm_analyzer:
            print(f"    [*] Running LLM analysis...")
            llm_findings = self.llm_analyzer.analyze_contract(source_code, os.path.basename(sol_file))
            if llm_findings:
                print(f"    [!] LLM found {len(llm_findings)} issues")
                results.extend(llm_findings)
        
        return results
    
    def scan_all_files(self):
        """Scan all files"""
        print("[*] Scanning all files...\n")
        
        # Only scan src/ files with LLM (skip tests and scripts for speed)
        src_files = [f for f in self.sol_files if '/src/' in f and not f.endswith('.t.sol')]
        script_files = [f for f in self.sol_files if '/src/' not in f]
        
        print(f"[*] Priority: {len(src_files)} source files + {len(script_files)} other files\n")
        
        for i, sol_file in enumerate(src_files + script_files, 1):
            rel_path = os.path.relpath(sol_file, self.target_path)
            print(f"[{i}/{len(self.sol_files)}] {rel_path}...", end=" ")
            
            findings = self.scan_file(sol_file)
            if findings:
                self.all_findings[sol_file] = findings
                print(f"[!] {len(findings)} issues\n")
            else:
                print("[+] Clean")
        
        print(f"\n[+] Scan complete!\n")
    
    def print_report(self):
        """Print report"""
        print("="*80)
        print("    🛡️ WEB3 LOGIC SCANNER - AUDIT REPORT")
        print("="*80 + "\n")
        
        print(f"Repository: {self.target_path}")
        print(f"Files scanned: {len(self.sol_files)}")
        print(f"Issues found: {len(self.all_findings)} files\n")
        
        if self.all_findings:
            print("[*] FINDINGS:\n")
            for file, findings in self.all_findings.items():
                print(f"  📁 {os.path.basename(file)}")
                for f in findings:
                    print(f"     [{f.get('source', '?')}] {f.get('type', '?')}: {f.get('description', '')[:70]}...")
                print()
        else:
            print("[+] No issues detected!\n")
    
    def run(self):
        if not self.find_all_sol_files():
            return
        self.build_dependency_graph()
        self.scan_all_files()
        self.print_report()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python cli/main.py <repo_directory> [--no-llm]")
        sys.exit(1)
    
    target = sys.argv[1]
    use_llm = "--no-llm" not in sys.argv
    
    if os.path.isdir(target):
        scanner = RepoScanner(target, use_llm=use_llm)
        scanner.run()
    else:
        print("[-] Target must be a directory.")
