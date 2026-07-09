# 🧠 LWID 2.0 — Autonomous Multi‑Agent Red Team AI

**LWID 2.0** is a state‑of‑the‑art autonomous penetration testing assistant built on Microsoft’s AutoGen framework.  
It orchestrates a team of specialised AI agents (Lead Planner, Researcher, Exploit Adapter, Executor) to perform **reconnaissance, vulnerability research, exploit adaptation, and post‑exploitation** with minimal human intervention.

The system combines the reasoning power of **DeepSeek** (and optionally Anthropic Claude) with a **hard‑coded tactical engine** that enforces the correct attack flow — preventing the agent from getting stuck in loops or making poor strategic decisions.

> **⚠️ IMPORTANT**: This tool is designed **exclusively for authorised security testing, CTF competitions, and educational purposes**.  
> Use it only on systems you own or have explicit permission to test. The authors are not responsible for any misuse.

---

## ✨ Features

- 🧠 **Multi‑Agent Architecture** — Lead Planner (strategy), Researcher (exploit DB), Exploit Adapter (code sanitisation), Executor (shell proxy), Archivist (memory compression).
- 🔁 **Persistent Memory** — Structured Knowledge Base (KB) with automatic compression and summarisation to prevent context overflow.
- 🧩 **Tactical Engine** — A deterministic Python rule engine overrides the LLM’s strategy, ensuring the agent always follows the optimal attack path (e.g., reverse shell check → privilege escalation → loot collection).
- 🛠 **Rich Toolset** — Execute shell commands on Kali, run interactive tools inside persistent `tmux` sessions, search Exploit‑DB, adapt exploits for different architectures (x86, ARM, MIPS), download/analyse files, and more.
- 🧹 **Exploit Sanitisation** — Automatically strips malicious payloads, rewrites PoCs to Python 3 or POSIX `sh`, and substitutes target-specific parameters (IP, port, credentials).
- 💾 **Session Persistence** — Saves full state (KB, command history, conversation) to disk; resume operations after interruptions.
- 🕹️ **Human‑in‑the‑Loop** — Operator menu to pause, inject directives, inspect the KB, and control the number of autonomous steps.

---



### Agent Roles

| Agent | Responsibility |
|-------|----------------|
| **Lead Planner** | Strategic decision‑maker. Uses DeepSeek (or Claude) to choose the next action based on current KB and tactical directives. |
| **Researcher** | Queries local Exploit‑DB, extracts PoC code, and uses an LLM to filter and summarise viable exploits for the target. |
| **Exploit Adapter** | Sanitises raw exploit code, removes malware, rewrites for Python 3 or POSIX shell (ARM/MIPS targets), and injects target IP/port/creds. |
| **Executor** | Thin proxy that forwards commands to the MCP workbench (HexStrike) and returns stdout/stderr. |
| **Archivist** | LLM‑powered memory compressor; updates the Knowledge Base with new findings and maintains monotonic state flags. |

---

## 🚀 Installation

### Prerequisites

- **Python 3.10+**
- **Kali Linux / Parrot OS** (recommended) with `searchsploit` installed:
  ```bash
  sudo apt update && sudo apt install exploitdb
HexStrike MCP server (or compatible) running on http://127.0.0.1:8888 (adjustable).

API keys for DeepSeek (and optionally Anthropic).

Steps
Clone the repository

bash
git clone https://github.com/Vad1mIL/LWID2.git
cd LWID2
Create a virtual environment

bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
Install dependencies

bash
pip install -r requirements.txt
Set up environment variables
Create a .env file in the project root:

env
DEEPSEEK_API_KEY=your_deepseek_api_key
# ANTHROPIC_API_KEY=your_anthropic_key   # optional
Start the HexStrike MCP server (if not already running)

bash
hexstrike-mcp --server http://127.0.0.1:8888
🖥 Usage
Run the orchestrator:

bash
python main.py
You will be prompted to enter the target description, e.g.:

text
[TARGET] Enter target (IP/URL) and task: 10.10.10.5 — get root
The system will then start the autonomous loop. You can intervene at any time using the Operator Menu:

/auto N — run N autonomous steps.

/task N — enter a multi‑line operator directive (end with END), then run N steps.

/db — display the current Knowledge Base.

/phase — show current phase, history length, executed commands.

/history — show last 10 conversation messages.

/exit — save state and quit.

Any free‑text input will be treated as an operator directive and injected into the agent’s context.



Models: DeepSeek (chat & reasoning), Anthropic Claude (optional for Lead Planner).

External Tools: searchsploit, HexStrike MCP, tmux.

Async Runtime: Python asyncio with subprocess and HTTP sessions.

Persistence: diskcache for LLM caching, JSON for session state.


📄 License
Distributed under the MIT License. See LICENSE for more information.

🙏 Acknowledgements
AutoGen by Microsoft.
Exploit-DB and the searchsploit utility.
HexStrike for the MCP workbench.
Made with ❤️ for the CTF & Red Team community.
