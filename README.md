




<img width="1021" height="553" alt="Screenshot 2026-07-10 121139" src="https://github.com/user-attachments/assets/5c2f9d91-c34e-4527-b40a-ccba722dfb4c" />

# 🧠 LWID 2.0 — Autonomous Multi‑Agent Red Team AI

**LWID 2.0** is a state‑of‑the‑art autonomous penetration testing assistant built on Microsoft’s AutoGen framework. 

It orchestrates a team of specialized AI agents to perform reconnaissance, vulnerability research, exploit adaptation, and post‑exploitation with minimal human intervention. By combining the advanced reasoning capabilities of DeepSeek (with optional Anthropic Claude support) and a hard‑coded deterministic tactical engine, LWID 2.0 ensures agents follow the optimal attack flow without getting stuck in loops or making poor strategic decisions.

> ⚠️ **IMPORTANT: LEGAL & ETHICAL DISCLAIMER**
> This tool is designed **exclusively** for authorized security testing, CTF competitions, and educational purposes. You must only use LWID 2.0 on systems you own or have explicit, documented permission to test. The authors hold no responsibility for any misuse or damage caused by this software.

---

## ✨ Key Features

*   **🧠 Multi‑Agent Architecture:** A coordinated swarm consisting of a Lead Planner, Researcher, Exploit Adapter, Executor, and Archivist.
*   **🔁 Persistent Memory:** Features a structured Knowledge Base (KB) with automatic compression and summarization to prevent LLM context overflow during long operations.
*   **🧩 Tactical Engine:** A deterministic Python rule engine that overrides the LLM’s strategy when necessary, enforcing logical attack paths (e.g., *Reverse shell check → Privilege escalation → Loot collection*).
*   **🛠 Rich Toolset:** Executes shell commands on Kali, runs interactive tools inside persistent `tmux` sessions, queries `searchsploit`, adapts exploits for various architectures (x86, ARM, MIPS), and analyzes target files.
*   **🧹 Exploit Sanitization:** Automatically strips malicious payloads from public PoCs, rewrites them to Python 3 or POSIX `sh`, and safely injects target-specific parameters (IP, port, credentials).
*   **💾 Session Persistence:** Saves the full state (Knowledge Base, command history, conversation context) to disk, allowing you to resume complex operations after interruptions.
*   **🕹️ Human‑in‑the‑Loop (HITL):** A robust Operator Menu allows you to pause execution, inject custom directives, inspect the KB, and strictly control the number of autonomous steps the agents can take.

---

## 🤖 Agent Roles

| Agent | Responsibility |
| :--- | :--- |
| **Lead Planner** | Strategic decision‑maker. Uses DeepSeek (or Claude) to dictate the next action based on the current Knowledge Base and tactical directives. |
| **Researcher** | Queries the local Exploit‑DB, extracts PoC code, and utilizes an LLM to filter and summarize viable exploits for the specific target. |
| **Exploit Adapter**| Sanitizes raw exploit code, removes malware/backdoors, rewrites code for target compatibility (e.g., Python 3 or POSIX shell for ARM/MIPS), and injects target IP/port/creds. |
| **Executor** | A thin proxy that forwards commands to the MCP workbench (HexStrike) and returns `stdout`/`stderr`. |
| **Archivist** | LLM‑powered memory compressor; continuously updates the Knowledge Base with new findings and maintains monotonic state flags. |

---

## 🚀 Installation & Quick Start

### Prerequisites
*   Python 3.10+
*   **Kali Linux** or **Parrot OS** (Recommended) with `searchsploit` installed:
    ```bash
    sudo apt update && sudo apt install exploitdb
    ```
*   **HexStrike MCP server** (or compatible) running on `http://127.0.0.1:8888` (adjustable in config).
*   API keys for DeepSeek (and Anthropic, if used).

### Setup Instructions

**1. Clone the repository**
```bash
git clone [https://github.com/Vad1mIL/LWID2.git](https://github.com/Vad1mIL/LWID2.git)
cd LWID2

2. Create a virtual environment

Bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
3. Install dependencies

Bash
pip install -r requirements.txt
4. Set up environment variables
Create a .env file in the project root directory:

Фрагмент кода
DEEPSEEK_API_KEY=your_deepseek_api_key
ANTHROPIC_API_KEY=your_anthropic_key  # Optional
Usage
Start the HexStrike MCP server (if not already running as a service), then launch LWID 2.0:

Bash
python main.py
You will be prompted to define the target and objective:

Plaintext
[TARGET] Enter target (IP/URL) and task: 10.10.10.5 — get root
The system will initiate the autonomous loop.

Operator Menu
You can intervene at any time by typing standard commands or free-text directives. Any free‑text input is treated as an operator directive and injected directly into the agent’s context.

/auto N — Run N autonomous steps.

/task N — Enter a multi‑line operator directive (end with END), then run N steps.

/db — Display the current Knowledge Base.

/phase — Show the current tactical phase, history length, and executed commands.

/history — Show the last 10 conversation messages.

/exit — Save the current state and terminate the session.

⚙️ Under the Hood
Models: DeepSeek (Chat & Reasoning), Anthropic Claude (Optional for Lead Planner).

External Tools: searchsploit, HexStrike MCP, tmux.

Runtime: Python asyncio with subprocess and HTTP sessions.

Persistence: diskcache for LLM caching, JSON for session state management.

📄 License
Distributed under the MIT License. See LICENSE for more information.

🙏 Acknowledgements
Microsoft AutoGen

Exploit-DB & the searchsploit utility

HexStrike for the MCP workbench

Made with ❤️ for the CTF & Red Team community.
