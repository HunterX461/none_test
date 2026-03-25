import requests
import json

class LLMLogicAnalyzer:
    def __init__(self, model="mistral", base_url="http://localhost:11434"):
        self.model = model
        self.base_url = base_url
        self.api_url = f"{base_url}/api/generate"
    
    def analyze_contract(self, source_code, file_name):
        """Analyze Solidity contract using LLM for logic vulnerabilities"""
        
        code_snippet = source_code[:3000]
        
        prompt = """You are a senior Solidity security auditor. Analyze this smart contract for logic vulnerabilities.

FILE: """ + file_name + """

SOLIDITY CODE:
```solidity
""" + code_snippet + """
