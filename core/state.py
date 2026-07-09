"""
LWID 2.0 — core/state.py
~~~~~~~~~~~~~~~~~~~~~~~~~
Session persistence: save and load the full operation state
(Knowledge Base, executed commands, conversation history) to/from
a JSON file on disk.

File naming convention:
    ``state_<sanitised_target>.json``

The module gracefully handles missing files, corrupt JSON, and
schema drift by falling back to empty defaults.
"""

from __future__ import annotations

import json
import os
import re
from copy import deepcopy
from typing import Any, List, Set, Tuple

from autogen_agentchat.messages import TextMessage

from core.memory import EMPTY_KB, kb_to_str, validate_kb


# ──────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────

def _safe_filename(target: str) -> str:
    """Derive a filesystem-safe filename from the target string."""
    sanitised = re.sub(r"[^a-zA-Z0-9_\-.]", "_", target[:50])
    return f"state_{sanitised}.json"


def _serialize_history(messages: List[Any]) -> List[dict[str, str]]:
    """Convert a list of ``TextMessage`` objects to plain dicts."""
    serialised: list[dict[str, str]] = []
    for msg in messages:
        serialised.append(
            {
                "content": msg.content if hasattr(msg, "content") else str(msg),
                "source": msg.source if hasattr(msg, "source") else "unknown",
            }
        )
    return serialised


def _deserialize_history(raw: List[dict[str, str]]) -> List[TextMessage]:
    """Reconstruct ``TextMessage`` objects from serialised dicts."""
    messages: list[TextMessage] = []
    for entry in raw:
        messages.append(
            TextMessage(
                content=entry.get("content", ""),
                source=entry.get("source", "user"),
            )
        )
    return messages


# ──────────────────────────────────────────────────────────────────────
# PUBLIC API
# ──────────────────────────────────────────────────────────────────────

def save_state(
    target: str,
    kb_dict: dict[str, Any],
    executed_commands: Set[str],
    lead_history: List[Any] | None = None,
) -> None:
    """Persist the current operation state to disk.

    Parameters
    ----------
    target:
        The target string (IP / URL / task description) used to derive
        the filename.
    kb_dict:
        The current Knowledge Base dictionary.
    executed_commands:
        Set of normalised command strings already executed.
    lead_history:
        Optional list of ``TextMessage`` objects representing the
        Lead Planner conversation history.
    """
    filename = _safe_filename(target)

    state: dict[str, Any] = {
        "knowledge_base": kb_to_str(kb_dict),
        "executed_commands": sorted(executed_commands),
        "lead_history": _serialize_history(lead_history) if lead_history else [],
    }

    try:
        with open(filename, "w", encoding="utf-8") as fh:
            json.dump(state, fh, ensure_ascii=False, indent=2)
    except OSError as exc:
        print(f"[⚠️  STATE] Failed to save state to {filename}: {exc}")


def load_state(
    target: str,
) -> Tuple[dict[str, Any], Set[str], List[TextMessage]]:
    """Load a previously saved operation state from disk.

    Parameters
    ----------
    target:
        The target string used when the state was saved.

    Returns
    -------
    tuple[dict, set, list]
        ``(kb_dict, executed_commands, lead_history_messages)``

        If no state file exists, returns fresh defaults:
        ``(deepcopy(EMPTY_KB), set(), [])``.
    """
    filename = _safe_filename(target)

    if not os.path.exists(filename):
        return deepcopy(EMPTY_KB), set(), []

    try:
        with open(filename, "r", encoding="utf-8") as fh:
            state = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[⚠️  STATE] Failed to load {filename}: {exc}. Starting fresh.")
        return deepcopy(EMPTY_KB), set(), []

    print(f"\n\033[92m[STATE] Loaded previous progress from {filename}\033[0m")

    # --- Knowledge Base ---
    kb_raw = state.get("knowledge_base", "{}")
    kb_dict = validate_kb(kb_raw)

    # --- Executed commands ---
    executed: set[str] = set(state.get("executed_commands", []))

    # --- Conversation history ---
    history: list[TextMessage] = _deserialize_history(
        state.get("lead_history", [])
    )

    return kb_dict, executed, history
