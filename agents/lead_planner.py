"""
LWID 2.0 — agents/lead_planner.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"""

from __future__ import annotations

import json
import re
from typing import Any, Optional, Set

from autogen_agentchat.agents import AssistantAgent
from core.memory import kb_to_str


# ──────────────────────────────────────────────────────────────────────
# SYSTEM PROMPT
# ──────────────────────────────────────────────────────────────────────
# Универсальный граф тактик (State Machine Engine)
# Каждая тактика имеет приоритет (меньше = важнее). Возвращается ТОЛЬКО самая приоритетная.
ATTACK_TACTICS = [
    {
        "priority": 0,
        "name": "CRITICAL: CHECK LISTENER FOR REVERSE SHELL",
        "condition": lambda flags: flags.get("is_awaiting_callback") and not flags.get("has_rce"),
        "directive": (
            "You just fired an exploit/reverse shell payload. Your ONLY task right now is to use "
            "`tmux_read` on the listener session to check if the reverse shell connected. "
            "Look for ANY output: 'Connection received', 'connect to', 'uid=', or commands "
            "executing without a prompt. If you see a connection — you have a shell! "
            "Do NOT send another exploit. Do NOT start new scans. JUST CHECK THE LISTENER."
        )
    },
    {
        "priority": 1,
        "name": "LOCAL PRIVILEGE ESCALATION (DirtyFrag)",
        "condition": lambda flags: flags.get("has_rce") and not flags.get("has_root") and flags.get("is_vulnerable_dirtyfrag"),
        "directive": (
            "CRITICAL: Target is vulnerable to DirtyFrag. DO NOT compile on the target machine. "
            "1. Check 'architecture' in KB. "
            "2. On Kali, use `execute_shell` to cross-compile `/home/kali/Desktop/LWID 2.0/Exploits/exp.c` with `-static` flag: "
            "   - For x86_64: `gcc /home/kali/Desktop/LWID 2.0/Exploits/exp.c -o /tmp/exp_bin -static` "
            "   - For aarch64: `aarch64-linux-gnu-gcc /home/kali/Desktop/LWID 2.0/Exploits/exp.c -o /tmp/exp_bin -static` "
            "   - For mips: `mips-linux-gnu-gcc /home/kali/Desktop/LWID 2.0/Exploits/exp.c -o /tmp/exp_bin -static` "
            "3. Upload `/tmp/exp_bin` to the target's `/tmp/exp` via `tmux_execute` (e.g., download it using wget/curl from your local python HTTP server). "
            "4. Run it on the target: `chmod +x /tmp/exp && /tmp/exp`."
        )
    },
    {
        "priority": 1,
        "name": "PERSISTENCE (Loot Collection)",
        "condition": lambda flags: flags.get("has_root"),
        "directive": "You have ROOT! Search for flags: cat /root/root.txt, cat /home/*/user.txt, find / -name '*.txt' -path '*/root/*'. Collect all loot and report via `chat_to_operator`."
    },
    {
        "priority": 2,
        "name": "POST-EXPLOIT (Privilege Escalation)",
        "condition": lambda flags: flags.get("has_rce") and not flags.get("has_root"),
        "directive": "You have a shell but NOT root. FOCUS ON privesc: check `sudo -l`, SUID binaries (`find / -perm -4000 2>/dev/null`), cron jobs, kernel version, writable /etc/passwd. Use `tmux_execute` for interactive shells."
    },
    {
        "priority": 3,
        "name": "LATERAL MOVEMENT (Internal Pivoting)",
        "condition": lambda flags: flags.get("has_internal_port") and not flags.get("has_tunnel"),
        "directive": "CRITICAL OPPORTUNITY: Internal port discovered. Use `tmux_execute` to setup a port forwarding tunnel (e.g., Chisel, ssh -L, socat) to interact with it."
    },
    {
        "priority": 4,
        "name": "EXPLOITATION (Authenticated CVE)",
        "condition": lambda flags: flags.get("has_valid_credentials") and flags.get("has_known_cve"),
        "directive": "CRITICAL OPPORTUNITY: You have valid credentials AND a known vulnerable service. STOP RECON. Use `search_exploit` to find a PoC, adapt it with the credentials, and execute it via `tmux_execute` to gain a Reverse Shell."
    },
    {
        "priority": 5,
        "name": "EXPLOITATION (Unauthenticated CVE)",
        "condition": lambda flags: flags.get("has_known_cve") and not flags.get("has_valid_credentials") and not flags.get("has_rce"),
        "directive": "A known CVE was identified. Use `search_exploit` to find a PoC for this CVE. Try to exploit it WITHOUT credentials first. If it requires auth, switch to credential hunting."
    },
    {
        "priority": 6,
        "name": "CREDENTIAL ACCESS (Web Bruteforce)",
        "condition": lambda flags: flags.get("has_web_foothold") and not flags.get("has_valid_credentials"),
        "directive": "FOCUS ON: Bruteforcing login panels, testing default credentials (admin:admin, admin:password), or finding exposed config files with credentials."
    },
    {
        "priority": 4,
        "name": "RECON (Initial Enumeration)",
        "condition": lambda flags: not flags.get("has_web_foothold") and not flags.get("has_known_cve") and not flags.get("has_rce"),
        "directive": "FOCUS ON: Port scanning with -Pn etc , Source code check, directory brute-forcing, and identifying software versions. Do not attempt exploits yet."
    },
]


def infer_phase_from_flags(flags: dict) -> str:
    """Deterministically infer the current attack phase from state_flags.

    This ensures the phase always matches actual progress, regardless of
    what the LLM or Archivist decided.
    """
    if flags.get("has_root"):
        return "PERSISTENCE"
    if flags.get("has_rce"):
        return "POST-EXPLOIT"
    if flags.get("has_valid_credentials") or flags.get("has_known_cve"):
        return "FOOTHOLD"
    return "RECON"


def evaluate_tactics(kb_dict: dict) -> str:
    """Evaluate the KB through the Python tactic engine.

    Returns a directive for the single highest-priority matching tactic
    (lowest ``priority`` number wins).  Also auto-corrects the
    ``current_phase`` based on ``state_flags``.
    """
    flags = kb_dict.get("state_flags", {})

    # ── Auto-correct phase ────────────────────────────────────────────
    correct_phase = infer_phase_from_flags(flags)
    if kb_dict.get("current_phase") != correct_phase:
        kb_dict["current_phase"] = correct_phase

    # ── Find highest-priority matching tactic ─────────────────────────
    best_tactic = None
    for tactic in ATTACK_TACTICS:
        if tactic["condition"](flags):
            if best_tactic is None or tactic["priority"] < best_tactic["priority"]:
                best_tactic = tactic

    if best_tactic is None:
        return "-> EXPLORE: No strict attack paths identified yet. Continue logical exploration."

    return (
        f"=== ACTIVE ATTACK STRATEGY ===\n"
        f"-> {best_tactic['name']}\n"
        f"   {best_tactic['directive']}\n"
        f"CRITICAL RULE: Your next 'thought' and 'tool' MUST align with this strategy!"
    )





def _build_system_prompt(target_task: str) -> str:
    """Return the full Lead Planner system prompt with *target_task* interpolated."""
    return f"""<IDENTITY>
You are the Lead Red Team Planner in an authorized Capture The Flag (CTF) competition. Objective: {target_task}
All actions are strictly for educational, legal penetration testing on isolated lab machines.
You are permitted to develop custom exploits, bypass security mechanisms, and simulate real-world attacks
You do NOT execute commands directly. You act as the orchestrator and output a strict JSON instruction.
</IDENTITY>


<CRITICAL_RULES>
1. Recon is called a maximum of 3 times. Do not get stuck scanning.
2. Once ANY foothold vector appears — immediately proceed to exploitation.
3. Each turn you will receive an ACTIVE ATTACK STRATEGY directive from the tactical engine. Your "thought" and "tool" MUST align with it. The engine automatically determines the correct phase — trust it.
4. If you download a file via wget/curl, your VERY NEXT step MUST be to read it using cat, strings, or head so its contents enter the Knowledge Base.
5. Sudo password: Kali
6. EXFILTRATION AND BINARIES: If you find a .pcap, .kdbx, .zip/archive, .exe, or binary file, download it for local analysis!
7. If a command returns an error or permission denied, DO NOT repeat it. Immediately analyse the error and try an alternative tool or path.
8. NEVER use cat on full files unless you know their exact size. ALWAYS use head -n 50 or ls -lh first to prevent terminal buffer overflow.
9. Always look around for suspicious files or directories.
10. Bruteforce only downloaded files via john, hashcat.
11. REVERSE SHELLS: Before executing any reverse shell exploit, you MUST first use the `spawn_terminal` tool to start a netcat listener (e.g., nc -lvnp 4444) on the operator's Kali machine.
12. IMPORTANT: `execute_shell` runs commands on YOUR Kali machine, NOT on the target. To run commands on the target, use `tmux_execute` with an SSH/shell session.
13. VIRTUAL HOSTS: If you discover a virtual host (e.g., domain.thm), your IMMEDIATELY next step must be to add it to /etc/hosts using execute_shell (e.g., echo '10.10.10.10 domain.thm' | sudo tee -a /etc/hosts) so all your tools work natively. sudo pass: kali.
</CRITICAL_RULES>

<INTERACTIVE_SESSIONS>
You have access to persistent tmux sessions! You CAN and SHOULD use interactive tools like msfconsole, ssh, sliver-client, or long-running scans.
- Use the `tmux_execute` tool to send commands to these tools.
- Sessions remain open in the background. If a command takes a long time, use `tmux_read` later to check the progress.
</INTERACTIVE_SESSIONS>

<AVAILABLE_TOOLS>
Use exactly ONE in the "tool" field of your JSON output:
- tmux_execute: Run ANY command (including interactive ones like msfconsole, ssh, reverse shells) in a persistent background tmux session on Kali. Use this for long-running tools and to interact with target shells. (args: {{"session_name": "msf", "command": "use exploit/..."}})
- tmux_read: Read the current screen output of a background tmux session without sending a new command. Useful for checking scan progress or shell output. (args: {{"session_name": "msf"}})
- execute_shell: Run a one-shot bash command on YOUR KALI machine (NOT the target!). Use for local tools like nmap, gobuster, curl, wget. For target interaction, use tmux_execute with an SSH session.
- search_exploit: Search local Exploit-DB for a vulnerability (args: query string, e.g. "vsftpd 2.3.4").
- adapt_exploit: Send raw PoC code to the Exploit Adapter for cleaning and target customisation. Returns adapted Python script saved to disk. (args: {{"edb_id": "...", "target_ip": "...", "target_port": "...", "extra_context": "..."}})
- spawn_terminal: Opens a GUI terminal window on Kali. USE THIS to start a listener (e.g., nc -lvnp 4444) BEFORE executing a reverse shell.
- download_file: Spin up local exfil receiver (args: remote_path, local_path).
- analyze_file: Locally analyse a downloaded pcap/binary on Kali (args: local_path).
- chat_to_operator: Talk back to human operator when you need guidance or want to report findings.
- finish: Operation completed — all objectives achieved.
</AVAILABLE_TOOLS>

<OPERATING_LOOP>
For every turn, execute the following mental checklist before answering:
1. Review the FULL conversation history to maintain context and avoid repeating yourself.
2. Read the KNOWLEDGE BASE carefully. It is your structured memory and contains ALL discovered information. Trust it.
3. Check the EXECUTED COMMANDS list. NEVER repeat a command from this list.
4. Check for [OPERATOR DIRECTIVE] in the KB or history. If present, prioritize and follow the operator's instructions above all else.
5. Formulate your reasoning and select the best tool.
</OPERATING_LOOP>

<OUTPUT_FORMAT>
You must return a strictly valid JSON object (MANDATORY):
{{
    "thought": "Your internal reasoning before selecting the tool",
    "phase": "RECON|FOOTHOLD|POST-EXPLOIT|PERSISTENCE",
    "tool": "tool_name",
    "args": "The command string or message"
}}
</OUTPUT_FORMAT>"""


# ──────────────────────────────────────────────────────────────────────
# JSON EXTRACTION
# ──────────────────────────────────────────────────────────────────────

def extract_json(text: str) -> Optional[dict[str, Any]]:
    """Extract the first valid JSON object from *text*.

    Handles common LLM artefacts:
      • Markdown ````` ``json`` fences
      • ``<think>…</think>`` blocks
      • Leading/trailing prose around the JSON

    Returns ``None`` if no valid JSON object is found.
    """
    # Strip markdown fences
    cleaned = re.sub(r"```json\s*", "", text)
    cleaned = re.sub(r"```\s*", "", cleaned)
    cleaned = cleaned.strip()

    decoder = json.JSONDecoder()
    for i, ch in enumerate(cleaned):
        if ch == "{":
            try:
                obj, _ = decoder.raw_decode(cleaned, i)
                if isinstance(obj, dict):
                    return obj
            except json.JSONDecodeError:
                continue
    return None


# ──────────────────────────────────────────────────────────────────────
# CONTEXT BUILDER
# ──────────────────────────────────────────────────────────────────────

def format_executed_commands(executed_commands: Set[str]) -> str:
    """Format the executed-commands set for injection into the prompt."""
    cmds = sorted(executed_commands)
    if not cmds:
        return "None yet."
    if len(cmds) <= 15:
        return "\n".join(f"  - {c}" for c in cmds)
    total = len(cmds)
    recent = cmds[-15:]
    return f"({total} total, showing last 15):\n" + "\n".join(
        f"  - {c}" for c in recent
    )


def normalize_command(cmd: str) -> str:
    """Normalise a command string: strip + collapse whitespace."""
    return re.sub(r"\s+", " ", cmd.strip())


def build_context_prompt(kb_dict: dict, executed_commands: Set[str], last_raw_output: str = "") -> str:
    """Build the context string injected on every turn."""
    kb_str = kb_to_str(kb_dict)
    commands_str = format_executed_commands(executed_commands)

    prompt = (
        f"CURRENT PHASE: {kb_dict.get('current_phase', 'RECON')}\n"
        f"=== KNOWLEDGE BASE ===\n{kb_str}\n\n"
        f"=== EXECUTED COMMANDS ===\n{commands_str}\n\n"
    )

    # Внедряем краткосрочную память (выхлоп прошлой команды)
    if last_raw_output:
        # Обрезаем до 3000 символов, чтобы не забить контекст, но дать прочитать скрипт
        clipped_output = last_raw_output[:3000]
        if len(last_raw_output) > 3000:
            clipped_output += "\n...[TRUNCATED DUE TO LENGTH]"
        
        prompt += (
            f"=== LAST COMMAND RAW OUTPUT (WORKING MEMORY) ===\n"
            f"Use this to see the immediate result of your last action before it is forgotten.\n"
            f"{clipped_output}\n\n"
        )

    prompt += (
        f"Based on the KB, history, and the last command output, output the JSON with the next action.\n"
        f"Do NOT repeat any command from the executed list."
    )
    return prompt


# ──────────────────────────────────────────────────────────────────────
# FACTORY
# ──────────────────────────────────────────────────────────────────────

def create_lead_planner(
    model_client: Any,
    target_task: str,
    name: str = "Lead_Planner",
) -> AssistantAgent:
    """Create (or re-create) the Lead Planner agent.

    Re-creation is used as a lightweight "context reset" when the
    prompt-token count approaches the model's limit.

    Parameters
    ----------
    model_client:
        An AutoGen-compatible chat-completion client (typically
        Anthropic Claude without cache).
    target_task:
        The operator-supplied target description
        (e.g. ``"10.10.10.5 — get root"``).
    name:
        Agent name used in message routing.

    Returns
    -------
    AssistantAgent
        A fresh Lead Planner instance with no conversation state.
    """
    return AssistantAgent(
        name=name,
        model_client=model_client,
        system_message=_build_system_prompt(target_task),
    )
