# 🛡️ Web3 Logic Scanner (AST-Based)

Welcome to the **Web3 Logic Scanner**! This is a high-end, human-like smart contract vulnerability scanner. Unlike basic scanners that rely on regex (which produces high false positives), this tool parses Solidity code into an **Abstract Syntax Tree (AST)** to deeply understand the *logic* and *control flow* of the smart contract.

It doesn't just find isolated bugs—it uses a **Chaining Engine** to link weaknesses together (e.g., Unprotected Function + Low-Level Call = Critical Fund Drain) just like a real human auditor would!

## ✨ Features
- **AST Parsing:** Understands the exact hierarchical structure of Solidity contracts.
- **Logic Detectors:** Custom modules to detect low-level `.call` usage, missing access controls, and more.
- **Vulnerability Chaining:** Cross-references isolated warnings to detect complex exploit paths.
- **Modular Architecture:** Extremely easy to add new vulnerability rules or integrate with AI/LLMs.

---

## 🚀 Getting Started (For Newbies!)

### Prerequisites
You need **Python 3** and the **Solidity Compiler (`solc`)** installed on your machine.

1. **Install Python 3:** Download from [python.org](https://www.python.org/downloads/).
2. **Install `solc` (Solidity Compiler):**
   - **Mac:** `brew install solidity`
   - **Linux:** `sudo apt install solc`
   - **NPM (Global):** `npm install -g solc`

### Installation
Clone this repository to your local machine:
```bash
git clone https://github.com/HunterX461/none_test.git
cd none_test
```

### How to Run a Scan
To scan a smart contract, run the main CLI tool and point it to a `.sol` file. 

From the root directory of the project, run:
```bash
python cli/main.py path/to/your/contract.sol
```

### Example Output
```text
[*] Generating AST for Vulnerable.sol...
[*] Scanning Vulnerable.sol for isolated weaknesses...
[*] Found 2 isolated weaknesses. Sending to Chaining Engine...

🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥
   CRITICAL EXPLOIT CHAINS DETECTED
🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥

[CRITICAL] Unprotected Low-Level Call Chain
Details: Attacker can freely call the unprotected function 'withdrawAll' which executes a low-level .call(). This could lead to a complete drain of funds or reentrancy.
Chained from isolated weaknesses:
  -> Missing Access Control (File: Vulnerable.sol)
  -> Low-Level Call (File: Vulnerable.sol)
```

## 🧠 How to Add Your Own Detectors
Want to make the tool even smarter? 
1. Create a new python file in the `detectors/` folder (e.g., `flashloan_attack.py`).
2. Write a function that searches the `node` dictionary for specific AST properties.
3. Import your function into `cli/main.py` and pass it the `ast` object!

---
*Built with ❤️ for Web3 Security.*