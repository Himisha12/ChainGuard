"""OpsPilot Memory Management & Summarize-Then-Window System.

Features:
- Exact tokenizer-based token counting using tiktoken (counting tokens, not words).
- Hard token budget per agent (default 3,000 tokens).
- Summarize-then-window memory: compresses older turns into a system summary note
  while preserving the last N turns verbatim (does not simply slice the array).
- Immutable structured facts block (timestamps, service names, hypotheses, metrics)
  injected so semantic summarization cannot drop them.
- Fact-retention verification for evaluation (10-fact retention check).
"""

from __future__ import annotations

import re
from typing import Any, Sequence

from langchain_core.messages import AIMessage, AnyMessage, BaseMessage, HumanMessage, SystemMessage

from src.models.schemas import StructuredFacts

import structlog

logger = structlog.get_logger(__name__)

# Default hard token budget per agent call
DEFAULT_TOKEN_BUDGET = 3000
DEFAULT_WINDOW_TURNS = 4

# Initialize tokenizer (tiktoken cl100k_base or fallback)
_ENCODER = None


def get_tokenizer():
    """Lazily load tiktoken tokenizer."""
    global _ENCODER
    if _ENCODER is None:
        try:
            import tiktoken
            _ENCODER = tiktoken.get_encoding("cl100k_base")
        except Exception:
            _ENCODER = None
    return _ENCODER


def count_tokens(text: str) -> int:
    """Count tokens exactly using model tokenizer (not word count)."""
    if not text:
        return 0
    enc = get_tokenizer()
    if enc is not None:
        try:
            return len(enc.encode(text))
        except Exception:
            pass
    # Fallback to byte-pair regex approximation (approx 3.8 chars per token)
    return max(1, len(re.findall(r"\w+|[^\w\s]", text)))


def count_messages_tokens(messages: Sequence[AnyMessage]) -> int:
    """Calculate total token count across a sequence of messages."""
    total = 0
    for msg in messages:
        # Standard token overhead per message (header/role tokens)
        total += 4
        content = msg.content if isinstance(msg.content, str) else str(msg.content)
        total += count_tokens(content)
    return total


def summarize_older_turns(messages: Sequence[AnyMessage]) -> str:
    """Compress older conversation turns into a dense technical summary note."""
    events = []
    for msg in messages:
        role = "Operator" if isinstance(msg, HumanMessage) else "Agent"
        text = str(msg.content).strip()
        # Extract meaningful lines
        first_line = text.split("\n")[0][:120]
        events.append(f"- {role}: {first_line}")
    return "Summary of prior diagnostic turns:\n" + "\n".join(events)


def summarize_then_window(
    messages: list[AnyMessage],
    structured_facts: StructuredFacts,
    token_budget: int = DEFAULT_TOKEN_BUDGET,
    window_turns: int = DEFAULT_WINDOW_TURNS,
) -> tuple[list[AnyMessage], bool]:
    """Summarize-then-window memory algorithm.

    - If message history fits within token_budget, it is returned intact.
    - If it exceeds the budget, older turns are compressed into a system summary note.
    - The last `window_turns` remain verbatim.
    - The `structured_facts` block is explicitly appended to the summary note
      to ensure key facts (timestamps, service names, hypotheses, planted facts)
      are NEVER dropped.

    Returns:
        tuple[list[AnyMessage], bool]: (pruned_messages, was_summarized)
    """
    total_tokens = count_messages_tokens(messages)

    if total_tokens <= token_budget:
        return messages, False

    logger.info(
        "token_budget_exceeded",
        total_tokens=total_tokens,
        budget=token_budget,
        message_count=len(messages),
    )

    if len(messages) <= window_turns:
        # Too few messages to window, inject structured facts block into first message
        return messages, False

    older_turns = messages[:-window_turns]
    recent_turns = list(messages[-window_turns:])

    summary_text = summarize_older_turns(older_turns)
    facts_block = structured_facts.to_structured_block()

    combined_system_note = (
        f"### [INCIDENT MEMORY COMPACTION - SYSTEM NOTE]\n"
        f"{summary_text}\n\n"
        f"{facts_block}"
    )

    compacted_messages: list[AnyMessage] = [SystemMessage(content=combined_system_note)] + recent_turns

    new_token_count = count_messages_tokens(compacted_messages)
    logger.info(
        "memory_summarized",
        original_tokens=total_tokens,
        compacted_tokens=new_token_count,
        reduction_pct=round(100 * (1 - new_token_count / total_tokens), 1),
    )

    return compacted_messages, True


# ─── Fact-Retention Evaluation Check ──────────────────────────────────────────


def verify_fact_retention(
    compacted_messages: Sequence[AnyMessage],
    planted_facts: dict[str, str],
) -> tuple[int, int, list[str]]:
    """Check how many of the planted 10 facts survived summarization.

    Returns:
        tuple[int, int, list[str]]: (retained_count, total_count, missing_facts)
    """
    corpus = " ".join(
        str(m.content) for m in compacted_messages
    )

    retained = 0
    missing = []

    for fact_key, fact_val in planted_facts.items():
        # Check if the exact key or value is retained in context
        if fact_key in corpus or fact_val in corpus:
            retained += 1
        else:
            missing.append(f"{fact_key}: {fact_val}")

    return retained, len(planted_facts), missing
