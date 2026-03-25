import requests
import json

class LLMLogicAnalyzer:
    def __init__(self, model="mistral", base_url="http://localhost:11434"):
        self.model = model
        self.base_url = base_url
        self.api_url = f"{base_url}/api/generate"
    
    def analyze_contract(self, source_code, file_name):
        """Analyze Solidity contract using LLM for logic vulnerabilities"""
        
        code_snippet = source_code[:2000]
        
        prompt = f"You are a senior Solidity security auditor. Analyze this smart contract for logic vulnerabilities.\n\nFILE: {file_name}\n\nSOLIDITY CODE:\n{code_snippet}\n\nLook for:\n1. Reentrancy\n2. Missing access control\n3. State mutation issues\n4. Integer overflow\n5. Unbounded loops\n6. Unsafe delegatecall\n7. tx.origin usage\n8. Division before multiplication\n9. Unsafe external calls\n\nReturn ONLY JSON with this format:\n" + "{" + '"vulnerabilities": [{"type": "...", "severity": "HIGH/MEDIUM/LOW", "description": "..."}]' + "}"
        
        try:
            print(f"    [LLM] Analyzing {file_name}...")
            response = requests.post(
                self.api_url,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "temperature": 0.3
                },
                timeout=120
            )
            
            if response.status_code != 200:
                return []
            
            result = response.json()
            response_text = result.get("response", "").strip()
            
            try:
                json_start = response_text.find("{")
                json_end = response_text.rfind("}") + 1
                
                if json_start != -1 and json_end > json_start:
                    json_str = response_text[json_start:json_end]
                    parsed = json.loads(json_str)
                    
                    findings = []
                    for vuln in parsed.get("vulnerabilities", []):
                        finding = {
                            "type": vuln.get("type", "Logic Vulnerability"),
                            "description": vuln.get("description", ""),
                            "file": file_name,
                            "severity": vuln.get("severity", "MEDIUM"),
                            "source": "LLM"
                        }
                        findings.append(finding)
                    
                    return findings
            except json.JSONDecodeError:
                return []
        
        except requests.exceptions.ConnectionError:
            print(f"    [!] Ollama not running at {self.base_url}")
            return []
        except Exception as e:
            return []
