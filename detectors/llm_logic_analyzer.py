import requests
import json
import sys

class LLMLogicAnalyzer:
    def __init__(self, model="mistral", base_url="http://localhost:11434"):
        self.model = model
        self.base_url = base_url
        self.api_url = f"{base_url}/api/generate"
        self.test_connection()
    
    def test_connection(self):
        """Test if Ollama is running"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                print(f"[+] Ollama connected successfully")
                models = response.json().get("models", [])
                print(f"[+] Available models: {[m.get('name') for m in models]}")
            else:
                print(f"[-] Ollama returned status {response.status_code}")
        except Exception as e:
            print(f"[-] ERROR: Cannot connect to Ollama at {self.base_url}")
            print(f"[-] Make sure Ollama is running: ollama serve")
            sys.exit(1)
    
    def analyze_contract(self, source_code, file_name):
        """Analyze Solidity contract using LLM"""
        
        if not source_code or len(source_code.strip()) < 50:
            return []
        
        code_snippet = source_code[:1500]
        
        prompt = f"Analyze this Solidity code for security issues:\n\n{code_snippet}\n\nList any vulnerabilities found in JSON format with 'vulnerabilities' key."
        
        try:
            response = requests.post(
                self.api_url,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "temperature": 0.2
                },
                timeout=60
            )
            
            if response.status_code != 200:
                print(f"    [!] LLM API error: {response.status_code}")
                return []
            
            result = response.json()
            response_text = result.get("response", "").strip()
            
            print(f"    [LLM] Response received for {file_name}")
            
            try:
                json_start = response_text.find("{")
                json_end = response_text.rfind("}") + 1
                
                if json_start != -1 and json_end > json_start:
                    json_str = response_text[json_start:json_end]
                    parsed = json.loads(json_str)
                    
                    findings = []
                    for vuln in parsed.get("vulnerabilities", []):
                        if isinstance(vuln, dict):
                            finding = {
                                "type": vuln.get("type", "Security Issue"),
                                "description": str(vuln.get("description", ""))[:100],
                                "file": file_name,
                                "severity": vuln.get("severity", "MEDIUM"),
                                "source": "LLM"
                            }
                            findings.append(finding)
                    
                    if findings:
                        print(f"    [!] LLM found {len(findings)} issues")
                    
                    return findings
            except json.JSONDecodeError as e:
                print(f"    [!] Could not parse JSON: {str(e)[:50]}")
                return []
        
        except requests.exceptions.Timeout:
            print(f"    [!] LLM timeout for {file_name} - taking too long")
            return []
        except requests.exceptions.ConnectionError:
            print(f"    [!] Ollama connection lost")
            return []
        except Exception as e:
            print(f"    [!] LLM error: {str(e)[:60]}")
            return []
