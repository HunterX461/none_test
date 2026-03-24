class VulnerabilityChainer:
    def __init__(self, findings):
        self.findings = findings
        self.chains = []

    def analyze(self):
        access_issues = [f for f in self.findings if f['type'] == 'Missing Access Control']
        call_issues = [f for f in self.findings if f['type'] == 'Low-Level Call']

        for access in access_issues:
            for call in call_issues:
                if access.get('function') == call.get('function') and access.get('function') is not None:
                    self.chains.append({
                        "severity": "CRITICAL",
                        "title": "Unprotected Low-Level Call Chain",
                        "description": f"Attacker can freely call the unprotected function '{access['function']}' which executes a low-level .call(). This could lead to a complete drain of funds or reentrancy.",
                        "components": [access, call]
                    })
                    
        return self.chains

    def print_chains(self):
        if not self.chains:
            print("\n[+] No critical vulnerability chains found. Smart contract looks safe from known chains!")
            return

        print("\n" + "🔥"*25)
        print("   CRITICAL EXPLOIT CHAINS DETECTED")
        print("🔥"*25)
        for chain in self.chains:
            print(f"\n[{chain['severity']}] {chain['title']}")
            print(f"Details: {chain['description']}")
            print("Chained from isolated weaknesses:")
            for comp in chain['components']:
                print(f"  -> {comp['type']} (File: {comp['file']})")