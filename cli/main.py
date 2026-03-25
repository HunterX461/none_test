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
    def __init__(self, target_path, model="mistral"):
        self.target_path = target_path
        self.sol_files = []
        self.all_findings = {}
        self.dependency_map = {}
        self.dependency_mapper = DependencyMapper(target_path)
        self.llm_analyzer = LLMLogicAnalyzer(model=model)
        self.current_model = model
        
    def find_all_sol_files(self):
        print(f"\n[*] Searching for Solidity files...")
        for root, dirs, files in os.walk(self.target_path):
            for file in files:
                if file.endswith('.sol'):
                    full_path = os.path.join(root, file)
                    self.sol_files.append(full_path)
        
        print(f"[+] Found {len(self.sol_files)} total files")
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
            except:
                pass
    
    def scan_file(self, sol_file):
        results = []
        
        try:
            with open(sol_file, 'r', encoding='utf-8', errors='ignore') as f:
                source_code = f.read()
        except:
            return results
        
        # Pattern detection
        ast = generate_ast(sol_file)
        if ast:
            analyze_ast_for_low_level_calls(ast, sol_file, results)
            analyze_ast_for_access_control(ast, sol_file, results)
            analyze_ast_for_tx_origin(ast, sol_file, results)
            delegatecall_findings = detect_unsafe_delegatecall(ast)
            if delegatecall_findings:
                results.extend(delegatecall_findings)
        
        # LLM detection
        llm_findings = self.llm_analyzer.analyze_contract(source_code, os.path.basename(sol_file))
        if llm_findings:
            results.extend(llm_findings)
        
        return results
    
    def scan_main_files_only(self):
        """Scan ONLY the 9 main source files"""
        scan_files = [f for f in self.sol_files if '/src/' in f and '/interfaces/' not in f and not f.endswith('.t.sol')]
        
        print(f"\n[*] Scanning {len(scan_files)} MAIN CONTRACT FILES with {self.current_model}...\n")
        
        for i, sol_file in enumerate(scan_files, 1):
            rel_path = os.path.relpath(sol_file, self.target_path)
            print(f"[{i}/{len(scan_files)}] {rel_path}...", end=" ")
            
            findings = self.scan_file(sol_file)
            if findings:
                self.all_findings[sol_file] = findings
                print(f"[!] {len(findings)} issues\n")
            else:
                print("[+] Clean")
        
        print(f"\n[+] Main files scan complete!\n")
        return len(self.all_findings) > 0
    
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
        """Print detailed report"""
        print("="*80)
        print("    🛡️ WEB3 LOGIC SCANNER - DETAILED AUDIT REPORT")
        print("="*80 + "\n")
        
        print(f"Repository: {self.target_path}")
        print(f"Model Used: {self.current_model}")
        print(f"Main contracts scanned: 9")
        print(f"Vulnerabilities found: {len(self.all_findings)} files\n")
        
        if self.all_findings:
            print("[*] DETAILED VULNERABILITY FINDINGS:\n")
            total_issues = 0
            for file, findings in self.all_findings.items():
                print(f"  📁 {os.path.basename(file)}")
                print(f"     Total Issues: {len(findings)}\n")
                for idx, f in enumerate(findings, 1):
                    src = f.get('source', 'UNKNOWN')
                    typ = f.get('type', 'Issue')
                    desc = f.get('description', 'N/A')
                    sev = f.get('severity', 'MEDIUM')
                    print(f"     [{idx}] Type: {typ}")
                    print(f"         Source: [{src}]")
                    print(f"         Severity: {sev}")
                    print(f"         Description: {desc}\n")
                    total_issues += 1
                print()
            
            # Cross-file chains
            cross_chains = self.analyze_cross_file_chains()
            if cross_chains:
                print("\n" + "🔥"*40)
                print("    CRITICAL CROSS-FILE EXPLOIT CHAINS")
                print("🔥"*40 + "\n")
                
                for chain in cross_chains:
                    print(f"[CHAIN] {chain['file1']} → {chain['file2']}")
                    print(f"        {chain['file1_vulns']} + {chain['file2_vulns']} vulnerabilities")
                    print(f"        Risk: Can be chained for larger attack surface\n")
            
            print(f"\n[!] TOTAL ISSUES FOUND: {total_issues}")
        else:
            print("[+] No vulnerabilities detected in main contract files!\n")
    
    def switch_model(self, new_model):
        """Switch to a different model"""
        print(f"\n[*] Switching from {self.current_model} to {new_model}...")
        self.current_model = new_model
        self.llm_analyzer = LLMLogicAnalyzer(model=new_model)
        self.all_findings = {}  # Clear previous findings
    
    def run(self):
        self.find_all_sol_files()
        self.build_dependency_graph()
        
        # STEP 1: Scan with Mistral (accurate)
        has_vulns = self.scan_main_files_only()
        self.print_report()
        
        # STEP 2: If no vulns found, ask user
        if not has_vulns:
            print("\n" + "="*80)
            print("[?] No vulnerabilities found with Mistral.")
            print("[?] Do you want to scan again with neural-chat (faster, less accurate)?")
            user_input = input("    Enter 'yes' to continue with neural-chat, or 'no' to exit: ").strip().lower()
            
            if user_input == 'yes':
                print("\n[*] Downloading neural-chat model if needed...\n")
                self.switch_model("neural-chat")
                has_vulns_2 = self.scan_main_files_only()
                self.print_report()
                
                if not has_vulns_2:
                    print("\n[+] Both Mistral and Neural-Chat found NO issues!")
                    print("[+] Your smart contracts appear to be secure! ✅\n")
            else:
                print("\n[+] Scan complete. No further analysis.\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python cli/main.py <repo_directory>")
        sys.exit(1)
    
    scanner = RepoScanner(sys.argv[1], model="mistral")
    scanner.run()
