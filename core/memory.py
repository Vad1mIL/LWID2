"""
LWID 2.0 — core/memory.py
~~~~~~~~~~~~~~~~~~~~~~~~~~
Knowledge Base management, Archivist (LLM-driven log compression),
history summarization, and resilient LLM call wrapper.

This module is the single source of truth for the operation's structured
memory.  Every piece of discovered information (ports, creds, vulns, flags)
lives inside the KB dict whose schema is defined by ``EMPTY_KB``.
"""

from __future__ import annotations

import asyncio
import json
import re
from copy import deepcopy
from typing import Any, Callable, Coroutine, List, Tuple

from autogen_core.models import UserMessage

# ──────────────────────────────────────────────────────────────────────
# KNOWLEDGE BASE SCHEMA
# ──────────────────────────────────────────────────────────────────────

EMPTY_KB: dict[str, Any] = {
    "target_info": {"ip": "", "os": "", "hostname": "", "architecture": "unknown", "shell_type": "unknown"},
    "open_ports": [],
    "discovered_paths": [],
    "credentials_found": [],
    "vulnerabilities": [],
    "footholds": [],
    "privilege_escalation_vectors": [],
    "flags_found": [],
    "current_phase": "RECON",
    "failed_commands": [],
    "operator_directives": [],
    "notes": "",
    "state_flags": {
        "has_web_foothold": False,          # Есть ли доступ к веб-панели (без кредов)
        "has_valid_credentials": False,     # Найдены ли рабочие логин/пароль
        "has_known_cve": False,             # Найдено ли уязвимое ПО с CVE
        "has_rce": False,                   # Есть ли выполнение кода
        "has_root": False,                  # Получен ли рут
        "has_internal_port": False,         # Обнаружен ли внутренний порт
        "has_tunnel": False,                # Настроен ли туннель/проброс порта
        "is_vulnerable_dirtyfrag": False,   # Уязвим ли к DirtyFrag (kernel < 6.10)
        "is_awaiting_callback": False,      # Ожидается ли обратный коннект (reverse shell)
    },
}

# Hard cap on serialised KB size (characters) before forced trimming.
KB_MAX_SIZE: int = 12_000


# ──────────────────────────────────────────────────────────────────────
# ARCHIVIST PROMPT
# ──────────────────────────────────────────────────────────────────────

ARCHIVIST_PROMPT: str = """You are a Cybersecurity Archivist in the LWID 2.0 AI project.
Your task: analyse command output and update the current knowledge base (JSON).

RULES:
1. If the log is empty, contains only timeouts, syntax errors, or has no exploitation value — RETURN THE CURRENT JSON UNCHANGED.
2. Never copy raw log chunks into the base. Synthesise information.
3. Extract only dry facts: creds, paths, open ports, service versions, flags.
4. If a command FAILED or returned "permission denied" / "connection refused" — add it to "failed_commands" array (max 20 entries, remove oldest if exceeded).
5. If operator gave a directive — keep it in "operator_directives" array (max 5 latest).
6. Update "current_phase" if evidence suggests phase transition (e.g., got shell → "POST-EXPLOIT").
7. Keep "notes" under 500 characters. Summarise, don't copy logs.
7b. REVERSE SHELL / DUMB SHELL DETECTION: If you see ANY of the following patterns in netcat/listener/tmux output, you MUST immediately set "has_rce": true:
   - "Connection received", "connect to [", "Connection from"
   - "uid=", "whoami" output showing a username
   - Commands executing without a visible bash/sh prompt (a 'dumb shell')
   - Any output that looks like a remote system responding to commands
   Do NOT ignore silent or prompt-less connections — they are valid shells!
8. ALWAYS preserve and update the "state_flags" object based on evidence in the logs:
   - "has_web_foothold": true if a web login panel, CMS admin page, or web app is discovered
   - "has_valid_credentials": true if working username/password pair is confirmed
   - "has_known_cve": true if a specific CVE or known vulnerability is identified for a running service
   - "has_rce": true if remote code execution is achieved (shell, command injection, etc.)
   - "has_root": true if root/SYSTEM/admin privileges are obtained
   - "has_internal_port": true if an internal-only port or service is discovered (e.g., 127.0.0.1:8080 on target)
   - "has_tunnel": true if a port forwarding tunnel (chisel, ssh -L, socat) is established
   - "is_vulnerable_dirtyfrag": true IF `uname -r` shows a Linux kernel version released before late 2024 (e.g., 5.x or 6.x older than 6.10), AND you have a basic user shell (has_rce is true).
   - "is_awaiting_callback": This flag is managed automatically by the system. Do NOT change it manually.
   Once a flag is set to true, NEVER set it back to false unless explicitly instructed.
9. DETECT TARGET ARCHITECTURE AND SHELL TYPE from indirect evidence in logs:
   - "architecture": detect from `uname -m` output (x86_64, armv7l, mips, aarch64), `file` command on binaries (ELF 32-bit MIPS, ELF 64-bit ARM), or Nmap OS detection. Set to "x86_64", "x86", "arm", "arm64", "mips", "mipsel", or "unknown".
   - "shell_type": detect from `echo $0`, `$SHELL`, presence of BusyBox (`busybox --help`, `/bin/busybox`), or limited command set. Set to "bash", "sh", "ash", "busybox", "powershell", or "unknown".
   These fields go inside "target_info". Update them as soon as evidence appears.
10. YOU MUST use STRICTLY this key structure:
{{
  "target_info": {{"ip": "", "os": "", "hostname": "", "architecture": "unknown", "shell_type": "unknown"}},
  "open_ports": [{{"port": 0, "service": "", "version": ""}}],
  "discovered_paths": [],
  "credentials_found": [{{"user": "", "password_or_hash": "", "service": ""}}],
  "vulnerabilities": [],
  "footholds": [],
  "privilege_escalation_vectors": [],
  "flags_found": [],
  "current_phase": "RECON|FOOTHOLD|POST-EXPLOIT|PERSISTENCE",
  "failed_commands": [],
  "operator_directives": [],
  "notes": "Brief conclusions for Planner (max 3-4 sentences. Do NOT copy logs here!)",
  "state_flags": {{
    "has_web_foothold": false,
    "has_valid_credentials": false,
    "has_known_cve": false,
    "has_rce": false,
    "has_root": false,
    "has_internal_port": false,
    "has_tunnel": false,
    "is_vulnerable_dirtyfrag": false,
    "is_awaiting_callback": false
  }}
}}

CURRENT KNOWLEDGE BASE:
{current_kb}

NEW LOGS:
{new_logs}

Return ONLY valid JSON. No reasoning before or after."""

# ──────────────────────────────────────────────────────────────────────
# HISTORY SUMMARISATION PROMPT
# ──────────────────────────────────────────────────────────────────────

SUMMARIZE_HISTORY_PROMPT: str = """You are a concise summariser for a Red Team AI operation.
Below is a conversation history between the Planner and the system.
Summarise the KEY decisions, findings, and current attack direction in 300-500 words.
Focus on: what was tried, what worked, what failed, current strategy.
Do NOT include raw command outputs. Only strategic summary.

CONVERSATION HISTORY:
{history_text}

Return ONLY the summary text, no JSON, no markdown."""


# ──────────────────────────────────────────────────────────────────────
# RESILIENT LLM CALL WRAPPER
# ──────────────────────────────────────────────────────────────────────

async def safe_llm_call(
    coro_func: Callable[[], Coroutine[Any, Any, Any]],
    *,
    max_retries: int = 3,
    label: str = "LLM",
) -> Any:
    """Call an async LLM function with retry + exponential back-off.

    Parameters
    ----------
    coro_func:
        A zero-argument callable that returns a coroutine
        (e.g. ``lambda: client.create(...)``).
    max_retries:
        How many times to retry on transient errors.
    label:
        Human-readable name for log messages.

    Raises
    ------
    asyncio.CancelledError
        Re-raised immediately (operator abort).
    Exception
        After exhausting retries, or on non-retryable errors
        (context overflow).
    """
    for attempt in range(max_retries):
        try:
            return await coro_func()
        except asyncio.CancelledError:
            raise  # never swallow operator cancellation
        except Exception as exc:
            err_str = str(exc).lower()
            # Context-overflow errors won't fix themselves on retry.
            if "prompt is too long" in err_str or "too many tokens" in err_str:
                raise
            if attempt == max_retries - 1:
                raise
            wait = 2 ** (attempt + 1)
            print(
                f"[RETRY {label}] Attempt {attempt + 1}/{max_retries} "
                f"failed: {exc}. Waiting {wait}s…"
            )
            await asyncio.sleep(wait)


# ──────────────────────────────────────────────────────────────────────
# KB VALIDATION & SERIALISATION
# ──────────────────────────────────────────────────────────────────────

def validate_kb(kb_input: str | dict) -> dict[str, Any]:
    """Parse *kb_input* into a well-formed KB dict.

    If the input is already a ``dict`` it is used directly; if it is a
    JSON string it is decoded first.  Missing keys are back-filled from
    ``EMPTY_KB`` so downstream code can always rely on the full schema.

    FIX #14/#15: Deep-merges nested dicts (especially ``state_flags``)
    so that new flags added to ``EMPTY_KB`` are always present.
    """
    if isinstance(kb_input, dict):
        kb = kb_input
    else:
        try:
            kb = json.loads(kb_input)
            if not isinstance(kb, dict):
                raise ValueError("KB root is not a dict")
        except (json.JSONDecodeError, ValueError):
            print("[⚠️  KB REPAIR]: Knowledge base was corrupted. Resetting to empty structure.")
            return deepcopy(EMPTY_KB)

    # Back-fill any missing keys with defaults.
    for key, default_val in EMPTY_KB.items():
        if key not in kb:
            if isinstance(default_val, (list, dict)):
                kb[key] = deepcopy(default_val)
            else:
                kb[key] = default_val
        elif isinstance(default_val, dict) and isinstance(kb[key], dict):
            # FIX #14/#15: Deep-merge nested dicts — fill missing sub-keys
            for sub_key, sub_default in default_val.items():
                if sub_key not in kb[key]:
                    kb[key][sub_key] = sub_default
    return kb


def kb_to_str(kb: dict[str, Any]) -> str:
    """Serialise a KB dict to a compact, human-readable JSON string."""
    return json.dumps(kb, ensure_ascii=False, indent=2)


def ensure_kb_size(kb: dict[str, Any]) -> dict[str, Any]:
    """Trim oversized arrays and notes so the KB stays under ``KB_MAX_SIZE``."""
    serialised = kb_to_str(kb)
    if len(serialised) <= KB_MAX_SIZE:
        return kb

    print(f"[📦 KB COMPRESS]: KB size {len(serialised)} > {KB_MAX_SIZE}. Trimming…")

    # Trim discovered_paths to 30 most recent
    if len(kb.get("discovered_paths", [])) > 30:
        kb["discovered_paths"] = kb["discovered_paths"][:30]

    # Trim failed_commands to 15 most recent
    if len(kb.get("failed_commands", [])) > 15:
        kb["failed_commands"] = kb["failed_commands"][-15:]

    # Trim operator_directives to 3 most recent
    if len(kb.get("operator_directives", [])) > 3:
        kb["operator_directives"] = kb["operator_directives"][-3:]

    # Truncate notes to 400 chars
    notes = kb.get("notes", "")
    if len(notes) > 400:
        kb["notes"] = notes[:400] + "…"

    return kb


# ──────────────────────────────────────────────────────────────────────
# MCP OUTPUT CLEANER
# ──────────────────────────────────────────────────────────────────────

def clean_mcp_output(raw_str: str) -> str:
    """Extract human-readable text from MCP JSON wrapper.

    The MCP executor often returns ``{"stdout": "…", "stderr": "…"}``.
    This helper unwraps that; if the string is not JSON it is returned
    as-is.
    """
    try:
        data = json.loads(raw_str)
        return (data.get("stdout", "") + data.get("stderr", "")).strip()
    except (json.JSONDecodeError, TypeError, AttributeError):
        return raw_str


# ──────────────────────────────────────────────────────────────────────
# ARCHIVIST — LLM-DRIVEN KB UPDATE
# ──────────────────────────────────────────────────────────────────────

async def update_knowledge_base(
    new_logs: str,
    current_kb: str | dict,
    client: Any,
) -> Tuple[str, int, int]:
    """Feed *new_logs* to the Archivist LLM and return an updated KB.

    Parameters
    ----------
    new_logs:
        Raw command output (may be MCP JSON or plain text).
    current_kb:
        Current KB as JSON string **or** dict.
    client:
        An AutoGen-compatible model client with a ``.create()`` method.

    Returns
    -------
    tuple[str, int, int]
        ``(updated_kb_json, prompt_tokens, completion_tokens)``
    """
    prompt_tokens: int = 0
    comp_tokens: int = 0

    if not new_logs or len(new_logs.strip()) < 5:
        kb_str = kb_to_str(validate_kb(current_kb)) if isinstance(current_kb, dict) else current_kb
        return kb_str, prompt_tokens, comp_tokens

    # 1. Pre-process: unwrap MCP JSON envelope
    try:
        parsed_mcp = json.loads(new_logs)
        out = parsed_mcp.get("stdout", "").strip()
        err = parsed_mcp.get("stderr", "").strip()
        parts: list[str] = []
        if out:
            parts.append(f"STDOUT:\n{out}")
        if err:
            parts.append(f"STDERR:\n{err}")
        new_logs = "\n".join(parts) if parts else "No useful output."
    except (json.JSONDecodeError, TypeError, AttributeError):
        pass

    # 2. Hard cap on log length to avoid blowing the Archivist context
    if len(new_logs) > 4_000:
        new_logs = new_logs[:4_000] + "\n…[TRUNCATED DUE TO LENGTH]"

    # 3. Validate current KB before sending
    kb_dict = validate_kb(current_kb)
    current_kb_str = kb_to_str(kb_dict)

    # 4. Build prompt
    prompt = (
        ARCHIVIST_PROMPT
        .replace("{current_kb}", current_kb_str)
        .replace("{new_logs}", new_logs)
    )

    try:
        response = await safe_llm_call(
            lambda: client.create(messages=[UserMessage(content=prompt, source="user")]),
            max_retries=3,
            label="Archivist",
        )
        content: str = response.content

        if hasattr(response, "usage") and response.usage:
            prompt_tokens = response.usage.prompt_tokens
            comp_tokens = response.usage.completion_tokens

        # 5. Post-process: strip <think> tags and markdown fences
        content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL | re.IGNORECASE)
        content = re.sub(r"^```json\s*", "", content, flags=re.MULTILINE | re.IGNORECASE)
        content = re.sub(r"^```\s*", "", content, flags=re.MULTILINE)
        content = content.strip()

        # 6. Validate returned JSON
        new_kb = json.loads(content)
        if not isinstance(new_kb, dict):
            raise ValueError("Archivist returned non-dict JSON")

        # Back-fill missing keys from the previous KB
        for key, default_val in EMPTY_KB.items():
            if key not in new_kb:
                new_kb[key] = kb_dict.get(key, default_val)

        # 6b. Monotonic latch for state_flags — once true, never revert to false
        old_flags = kb_dict.get("state_flags", {})
        new_flags = new_kb.get("state_flags", {})
        if isinstance(old_flags, dict) and isinstance(new_flags, dict):
            # Флаги, которые могут быть ошибкой или устареть — разрешаем сброс
            volatile_flags = {"has_known_cve", "has_web_foothold", "is_awaiting_callback"}

            for flag_key, old_val in old_flags.items():
                if flag_key in volatile_flags:
                    continue  # Архивариус имеет право менять их в False
                
                # Для RCE, Root и Туннелей — только вверх
                if old_val is True and new_flags.get(flag_key) is not True:
                    new_flags[flag_key] = True

            # Auto-clear is_awaiting_callback when has_rce becomes True
            if new_flags.get("has_rce") and new_flags.get("is_awaiting_callback"):
                new_flags["is_awaiting_callback"] = False
                print("[FLAG] is_awaiting_callback auto-cleared (has_rce=True)")
            new_kb["state_flags"] = new_flags

            # Auto-clear is_awaiting_callback when has_rce becomes True
            if new_flags.get("has_rce") and new_flags.get("is_awaiting_callback"):
                new_flags["is_awaiting_callback"] = False
                print("[FLAG] is_awaiting_callback auto-cleared (has_rce=True)")
            new_kb["state_flags"] = new_flags

        # 7. Size control
        new_kb = ensure_kb_size(new_kb)

        return kb_to_str(new_kb), prompt_tokens, comp_tokens

    except json.JSONDecodeError:
        print("\n[⚠️  Archivist]: LLM returned invalid JSON. Keeping KB unchanged.")
        return current_kb_str, prompt_tokens, comp_tokens
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        print(f"\n[⚠️  Archivist API Error]: {exc}")
        return current_kb_str, prompt_tokens, comp_tokens


# ──────────────────────────────────────────────────────────────────────
# HISTORY SUMMARISATION
# ──────────────────────────────────────────────────────────────────────

async def summarize_history(messages: List[Any], client: Any) -> str:
    """Compress a list of ``TextMessage`` objects into a short summary.

    Used when the sliding-window history exceeds the configured
    threshold so the Lead Planner can keep operating without context
    overflow.

    Parameters
    ----------
    messages:
        List of ``TextMessage`` (or similar) objects with ``.source``
        and ``.content`` attributes.
    client:
        An AutoGen-compatible model client.

    Returns
    -------
    str
        A 300-500 word strategic summary.
    """
    history_text = ""
    for msg in messages:
        role = getattr(msg, "source", "unknown")
        content = getattr(msg, "content", str(msg))
        # Cap each message to save tokens
        if len(content) > 500:
            content = content[:500] + "…"
        history_text += f"[{role}]: {content}\n\n"

    # Global cap
    if len(history_text) > 6_000:
        history_text = history_text[:6_000] + "\n…[TRUNCATED]"

    prompt = SUMMARIZE_HISTORY_PROMPT.replace("{history_text}", history_text)

    try:
        response = await safe_llm_call(
            lambda: client.create(messages=[UserMessage(content=prompt, source="user")]),
            max_retries=2,
            label="Summariser",
        )
        content: str = response.content
        # Strip possible <think> tags
        content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL | re.IGNORECASE)
        return content.strip()
    except Exception as exc:
        print(f"[⚠️  Summariser Error]: {exc}")
        return "Previous history summarisation failed. Continue based on Knowledge Base."
