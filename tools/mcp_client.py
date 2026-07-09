"""
LWID 2.0 — tools/mcp_client.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
MCP (Model Context Protocol) integration layer.

Responsibilities:
  • Generate the ``fast_mcp.py`` wrapper script that monkey-patches
    the HexStrike MCP client for instant startup.
  • Build ``StdioServerParams`` for the MCP subprocess.
  • Provide a factory for the **Executor** agent — a thin proxy that
    forwards shell commands to the MCP workbench and returns raw output.
"""

from __future__ import annotations

import os
import sys
from typing import Any

from autogen_agentchat.agents import AssistantAgent
from autogen_ext.tools.mcp import McpWorkbench, StdioServerParams

# ──────────────────────────────────────────────────────────────────────
# FAST-MCP WRAPPER (written to disk at runtime)
# ──────────────────────────────────────────────────────────────────────

_WRAPPER_CODE: str = """\
import sys
import hexstrike_mcp
try:
    def fast_init(self, server_url, timeout=300):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.session = __import__("requests").Session()
    hexstrike_mcp.HexStrikeClient.__init__ = fast_init
    hexstrike_mcp.HexStrikeClient.check_health = (
        lambda self: {"status": "healthy", "version": "6.0.0"}
    )
except AttributeError as e:
    print(
        f"[WARN] Monkey-patch failed (hexstrike_mcp API changed?): {e}",
        file=sys.stderr,
    )
if __name__ == "__main__":
    hexstrike_mcp.main()
"""

# ──────────────────────────────────────────────────────────────────────
# EXECUTOR SYSTEM PROMPT
# ──────────────────────────────────────────────────────────────────────

EXECUTOR_SYSTEM_PROMPT: str = (
    "You are a strict proxy. Execute the exact command provided by the "
    "user using MCP tools. Return ONLY the raw output. No explanations."
)

# ──────────────────────────────────────────────────────────────────────
# PUBLIC API
# ──────────────────────────────────────────────────────────────────────


def write_fast_mcp_wrapper(path: str = "fast_mcp.py") -> str:
    """Write the ``fast_mcp.py`` monkey-patch wrapper to *path*.

    Returns the absolute path of the written file so callers can
    reference it in ``StdioServerParams``.
    """
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_WRAPPER_CODE)
    return os.path.abspath(path)


def create_mcp_server_params(
    wrapper_path: str = "fast_mcp.py",
    server_url: str = "http://127.0.0.1:8888",
    read_timeout: int = 600,
) -> StdioServerParams:
    """Build ``StdioServerParams`` for the MCP subprocess.

    Parameters
    ----------
    wrapper_path:
        Path to the ``fast_mcp.py`` wrapper script.
    server_url:
        URL of the running HexStrike API server.
    read_timeout:
        Maximum seconds to wait for a response from the MCP process.

    Returns
    -------
    StdioServerParams
        Ready-to-use params for ``McpWorkbench``.
    """
    return StdioServerParams(
        command=sys.executable,
        args=[wrapper_path, "--server", server_url],
        env={
            **os.environ,
            "PYTHONUNBUFFERED": "1",
            "PYTHONIOENCODING": "utf-8",
        },
        read_timeout_seconds=read_timeout,
    )


def create_mcp_workbench(
    server_url: str = "http://127.0.0.1:8888",
    read_timeout: int = 600,
) -> McpWorkbench:
    """Create an ``McpWorkbench`` instance ready for ``async with``.

    This also writes the ``fast_mcp.py`` wrapper to disk.

    Usage::

        async with create_mcp_workbench() as mcp:
            executor = create_executor_agent(model_client, mcp)
            ...

    Parameters
    ----------
    server_url:
        URL of the running HexStrike API server.
    read_timeout:
        Maximum seconds to wait for MCP responses.

    Returns
    -------
    McpWorkbench
        An async-context-manager workbench.
    """
    wrapper_path = write_fast_mcp_wrapper()
    params = create_mcp_server_params(
        wrapper_path=wrapper_path,
        server_url=server_url,
        read_timeout=read_timeout,
    )
    return McpWorkbench(params)


def create_executor_agent(
    model_client: Any,
    mcp_workbench: McpWorkbench,
    name: str = "executor",
) -> AssistantAgent:
    """Factory: create the **Executor** proxy agent.

    The Executor receives a single shell command from the orchestrator,
    forwards it to the MCP workbench, and returns the raw stdout/stderr.

    Parameters
    ----------
    model_client:
        An AutoGen-compatible chat-completion client (typically
        DeepSeek with disk cache).
    mcp_workbench:
        An already-entered ``McpWorkbench`` instance.
    name:
        Agent name (used in message routing).

    Returns
    -------
    AssistantAgent
        A stateless proxy agent bound to the MCP workbench.
    """
    return AssistantAgent(
        name=name,
        model_client=model_client,
        workbench=mcp_workbench,
        system_message=EXECUTOR_SYSTEM_PROMPT,
    )
