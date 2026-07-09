"""
LWID 2.0 — agents/researcher.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"""

from __future__ import annotations

import asyncio
from typing import Any, List, Optional

from autogen_agentchat.agents import AssistantAgent
from autogen_core.models import UserMessage

from core.memory import safe_llm_call
from tools.exploit_tools import (
    ExploitEntry,
    SearchResult,
    read_exploit_code,
    searchsploit_extract,
    searchsploit_search,
)

# ──────────────────────────────────────────────────────────────────────
# SYSTEM PROMPT
# ──────────────────────────────────────────────────────────────────────

RESEARCHER_SYSTEM_PROMPT: str = """<IDENTITY>
You are the Red Team Vulnerability Researcher in the LWID 2.0 pipeline.
Your job is to analyze search results from Exploit-DB and the raw source code of Proof of Concept (PoC) exploits, then provide a concise, actionable summary for the Lead Planner.
</IDENTITY>

<CRITICAL_RULES>
- You do NOT execute code or write new exploits. You only analyze existing ones.
- Focus ONLY on the most promising and relevant exploits that match the 'target_context'.
- Ruthlessly filter out exploits that are clearly for the wrong OS, architecture, or service version.
- Be concise and factual. The Lead Planner needs dry intelligence, not an essay.
- If no viable exploits are found, explicitly state that the search was a dead end.
</CRITICAL_RULES>

<OPERATING_LOOP>
For every analysis request, follow these steps:
1. Analyze the 'target_context' to understand the environment (OS, service versions).
2. Review the 'search_summary' to filter the list of found exploits.
3. Read the 'poc_snippets' (the actual source code) of the top candidates.
4. Evaluate viability: Does it require authentication? Does it match our target version?
5. Formulate your final structured response.
</OPERATING_LOOP>

<OUTPUT_FORMAT>
You must return a strictly formatted markdown response containing EXACTLY these sections:

### 1. Viable Candidates
(List the EDB-IDs and titles of exploits that have the highest chance of success. If none, write "None".)

### 2. PoC Analysis
(Briefly explain how the best candidate works, what language it is written in, and what arguments/parameters it requires to run.)

### 3. Recommendation
(Give a clear, 1-sentence recommendation to the Lead Planner on which EDB-ID to pass to the Exploit Adapter, or advise to move on if nothing fits.)
</OUTPUT_FORMAT>"""


# ──────────────────────────────────────────────────────────────────────
# LLM ANALYSIS PROMPT
# ──────────────────────────────────────────────────────────────────────

_ANALYSIS_PROMPT_TEMPLATE: str = """<TASK>
Please analyze the following Exploit-DB search results and raw Proof of Concept (PoC) snippets based on your system instructions.
</TASK>

<ENVIRONMENT_CONTEXT>
- Search Query Used: {query}
- Target Context: {target_context}
</ENVIRONMENT_CONTEXT>

<SEARCH_RESULTS>
{search_summary}
</SEARCH_RESULTS>

<POC_SNIPPETS>
{poc_snippets}
</POC_SNIPPETS>

<INSTRUCTIONS>
Review the data above. Strictly follow your system prompt rules and return ONLY the required Markdown structure:
1. Viable Candidates
2. PoC Analysis
3. Recommendation
</INSTRUCTIONS>"""


# ──────────────────────────────────────────────────────────────────────
# FACTORY
# ──────────────────────────────────────────────────────────────────────

def create_researcher(
    model_client: Any,
    name: str = "Researcher",
) -> AssistantAgent:
    """Create the Researcher agent.

    Parameters
    ----------
    model_client:
        An AutoGen-compatible chat-completion client (typically
        DeepSeek with disk cache).
    name:
        Agent name for message routing.

    Returns
    -------
    AssistantAgent
    """
    return AssistantAgent(
        name=name,
        model_client=model_client,
        system_message=RESEARCHER_SYSTEM_PROMPT,
    )


# ──────────────────────────────────────────────────────────────────────
# HIGH-LEVEL RESEARCH PIPELINE
# ──────────────────────────────────────────────────────────────────────

async def run_research(
    query: str,
    model_client: Any,
    *,
    target_context: str = "",
    top_n: int = 5,
    extract_dir: str = "/tmp/exploits",
    max_code_chars: int = 4_000,
) -> str:
    """Execute the full research pipeline and return an LLM analysis.

    Parameters
    ----------
    query:
        Free-text search string for ``searchsploit``
        (e.g. ``"vsftpd 2.3.4"``).
    model_client:
        LLM client used for the analysis step.
    target_context:
        A short string describing the target (from KB) so the LLM can
        judge relevance.
    top_n:
        How many top results to extract and read.
    extract_dir:
        Where to copy exploit files on disk.
    max_code_chars:
        Per-file character limit when reading PoC source.

    Returns
    -------
    str
        The LLM's structured analysis, or an error/fallback message.
    """
    # ── Step 1: Search ────────────────────────────────────────────────
    result: SearchResult = await searchsploit_search(query)

    if result.error:
        return f"[Researcher] searchsploit error: {result.error}"
    if result.count == 0:
        return f"[Researcher] No exploits found for '{query}'."

    # ── Step 2: Extract & read top-N PoCs ─────────────────────────────
    entries_to_review: List[ExploitEntry] = result.entries[:top_n]
    poc_snippets_parts: list[str] = []

    for entry in entries_to_review:
        if not entry.edb_id:
            continue

        file_path = await searchsploit_extract(
            entry.edb_id, output_dir=extract_dir
        )

        if file_path.startswith("[ERROR]"):
            poc_snippets_parts.append(
                f"--- EDB-{entry.edb_id}: {entry.title} ---\n"
                f"(extraction failed: {file_path})\n"
            )
            continue

        code = await read_exploit_code(file_path, max_chars=max_code_chars)
        poc_snippets_parts.append(
            f"--- EDB-{entry.edb_id}: {entry.title} ---\n"
            f"File: {file_path}\n"
            f"{code}\n"
        )

    poc_snippets = "\n".join(poc_snippets_parts) if poc_snippets_parts else "(no PoC code extracted)"

    # ── Step 3: LLM analysis ──────────────────────────────────────────
    prompt = _ANALYSIS_PROMPT_TEMPLATE.format(
        query=query,
        target_context=target_context or "No additional context.",
        search_summary=result.summary(max_entries=top_n),
        poc_snippets=poc_snippets[:12_000],  # hard cap for context safety
    )

    try:
        response = await safe_llm_call(
            lambda: model_client.create(
                messages=[UserMessage(content=prompt, source="user")]
            ),
            max_retries=2,
            label="Researcher",
        )
        analysis: str = response.content

        # Strip <think> tags if present
        import re
        analysis = re.sub(
            r"<think>.*?</think>", "", analysis, flags=re.DOTALL | re.IGNORECASE
        )
        return analysis.strip()

    except Exception as exc:
        # Graceful fallback: return the raw search summary
        return (
            f"[Researcher] LLM analysis failed ({exc}). "
            f"Raw results:\n{result.summary(max_entries=top_n)}"
        )
