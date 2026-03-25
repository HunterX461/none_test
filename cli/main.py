import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.ast_parser import generate_ast
from analyzer.dependency_mapper import DependencyMapper
from detectors.unhandled_calls import analyze_ast_for_low_level_calls
from detectors.access_control import analyze_ast_for_access_control
from detectors.tx_origin import analyze_ast_for_tx_origin
from detectors.delegatecall_injection import detect_unsafe_delegatecall
from detectors.llm_logic_analyzer import LLMLogicAnalyzer
from analyzer.chaining_engine import VulnerabilityChainer

class RepoScanner:
    def __init__(self, target_path, use_llm=True):
        self.target_path = target_path
        self.sol_files = []
        self.all_findings = {}
        self.dependency_map = {}
        self.dependency_mapper = DependencyMapper(target_path)
        self.use_llm = use_llm
        self.llm_analyzer = LLMLogicAnalyzer() if use_llm else None
        
    def find_all_sol_files(self):
        """Recursively find all .sol files"""
        print(f"[*] Searching for Solidity files in {self.target_path}...")
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
        """Extract import dependencies"""
        print("[*] Building dependency graph...")
        for sol_file in self.sol_files:
            try:
                with open(sol_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    imports = self.dependency_mapper.extract_imports(content)
                    if imports:
                        self.dependency_map[sol_file] = imports
                        print(f"    [{os.path.basename(sol_file)}] imports {len(imports)} files")
            except Exception as e:
                pass
        print()
    
    def scan_file(self, sol_file):
        """Scan single file for vulnerabilities"""
        ast = generate_ast(sol_file)
        if not ast:
            return []
        
        results = []
        analyze_ast_for_low_level_calls(ast, sol_file, results)
        analyze_ast_for_access_control(ast, sol_file, results)
        analyze_ast_for_tx_origin(ast, sol_file, results)
        
        delegatecall_findings = detect_unsafe_delegatecall(ast)
        if delegatecall_findings:
            results.extend(delegatecall_findings)
        
        # Add LLM analysis if enabled
        if self.use_llm and self.llm_analyzer:
            try:
                with open(sol_file, 'r', encoding='utf-8', errors='ignore') as f:
                    source_code = f.read()
                    llm_findings = self.llm_analyzer.analyze_contract(source_code, os.path.basename(sol_file))
                    results.extend(llm_findings)
            except Exception as e:
                pass
        
        return results
    
    def scan_all_files(self):
        """Scan all files and collect findings"""
        print("[*] Scanning all files for vulnerabilities...\n")
        
        for i, sol_file in enumerate(self.sol_files, 1):
            rel_path = os.path.relpath(sol_file, self.target_path)
            print(f"[{i}/{len(self.sol_files)}] {rel_path}...", end=" ")
            
            findings = self.scan_file(sol_file)
            if findings:
                self.all_findings[sol_file] = findings
                print(f"[!] {len(findings)} issues")
            else:
                print("[+] Clean")
        
        print(f"\n[+] Scan complete!\n")
    
    def analyze_cross_file_chains(self):
        """Detect vulnerabilities that chain across files"""
        print("[*] Analyzing cross-file vulnerability chains...\n")
        
        cross_file_chains = []
        
        for file1, findings1 in self.all_findings.items():
            imports = self.dependency_map.get(file1, [])
            
            for imported in imports:
                for file2 in self.sol_files:
                    if imported in file2 or file2.endswith(imported):
                        if file2 in self.all_findings:
                            findings2 = self.all_findings[file2]
                            
                            chain = {
                                "file1": os.path.basename(file1),
                                "file2": os.path.basename(file2),
                                "file1_vulns": len(findings1),
                                "file2_vulns": len(findings2),
                                "severity": "HIGH"
                            }
                            cross_file_chains.append(chain)
                            break
        
        return cross_file_chains
    
    def print_report(self):
        """Print comprehensive report"""
        print("="*80)
        print("    🛡️ WEB3 LOGIC SCANNER - REPOSITORY AUDIT REPORT")
        print("="*80 + "\n")
        
        print(f"Repository: {self.target_path}")
        print(f"Files scanned: {len(self.sol_files)}")
        print(f"Issues found in: {len(self.all_findings)} files\n")
        
        if self.all_findings:
            print("[*] VULNERABILITY FINDINGS:\n")
            for file, findings in self.all_findings.items():
                print(f"  📁 {os.path.basename(file)}")
                for finding in findings:
                    severity = finding.get('severity', 'MEDIUM')
                    ftype = finding.get('type', 'Issue')
                    desc = finding.get('description', '')[:60]
                    source = finding.get('source', 'PATTERN')
                    print(f"     [{source}] [{severity}] {ftype}")
                    print(f"        → {desc}...")
                print()
        else:
            print("[+] No vulnerabilities detected!\n")
        
        cross_chains = self.analyze_cross_file_chains()
        if cross_chains:
            print("\n" + "🔥"*40)
            print("    CRITICAL CROSS-FILE EXPLOIT CHAINS")
            print("🔥"*40 + "\n")
            
            for chain in cross_chains:
                print(f"[HIGH] {chain['file1']} → {chain['file2']}")
                print(f"  {chain['file1_vulns']} + {chain['file2_vulns']} vulnerabilities = Attack Vector\n")
    
    def run(self):
        """Execute complete scan"""
        if not self.find_all_sol_files():
            return
        
        self.build_dependency_graph()
        self.scan_all_files()
        self.print_report()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m cli.main <repo_directory> [--no-llm]")
        sys.exit(1)
    
    target = sys.argv[1]
    use_llm = "--no-llm" not in sys.argv
    
    if os.path.isdir(target):
        scanner = RepoScanner(target, use_llm=use_llm)
        scanner.run()
    else:
        print("[-] Target must be a directory.")
