"""LangGraph state definition with typed reducers (D17).

Nodes only return dict updates, never mutate state directly.
Uses append-only reducers for findings and messages.
"""

from __future__ import annotations

import operator
from dataclasses import dataclass, field
from typing import Annotated, Any, Optional, Sequence

from langchain_core.messages import AnyMessage, BaseMessage
from langgraph.graph.message import add_messages

from src.models.schemas import (
    Finding,
    ParsedDependency,
    ScanStatus,
    TraceEntry,
    UpgradePlan,
)


def append_findings(
    existing: list[Finding], new: list[Finding] | Finding
) -> list[Finding]:
    """Append-only reducer for findings list.

    Ensures findings are never overwritten, only appended.
    Deduplicates by finding ID.
    """
    if isinstance(new, Finding):
        new = [new]
    existing_ids = {f.id for f in existing}
    for finding in new:
        if finding.id not in existing_ids:
            existing.append(finding)
            existing_ids.add(finding.id)
    return existing


def append_trace(
    existing: list[TraceEntry], new: list[TraceEntry] | TraceEntry
) -> list[TraceEntry]:
    """Append-only reducer for trace entries."""
    if isinstance(new, TraceEntry):
        new = [new]
    existing.extend(new)
    return existing


def append_dependencies(
    existing: list[ParsedDependency], new: list[ParsedDependency] | ParsedDependency
) -> list[ParsedDependency]:
    """Append-only reducer for parsed dependencies."""
    if isinstance(new, ParsedDependency):
        new = [new]
    existing_keys = {(d.name, d.source_file) for d in existing}
    for dep in new:
        key = (dep.name, dep.source_file)
        if key not in existing_keys:
            existing.append(dep)
            existing_keys.add(key)
    return existing


def replace_value(existing: Any, new: Any) -> Any:
    """Simple replacement reducer — last write wins."""
    return new


@dataclass
class ScanState:
    """Typed state for the ChainGuard scan graph (D17).

    Each field uses a reducer:
    - add_messages: LangGraph's built-in message reducer for the conversation trace
    - append_findings: append-only, deduplicates by ID
    - append_trace: append-only execution trace
    - append_dependencies: append-only, deduplicates by (name, source_file)
    - replace_value: last-write-wins for scalars

    Nodes return dict updates like:
        return {"findings": [new_finding], "status": ScanStatus.ANALYZING}
    """

    # ── Core identifiers ──
    scan_id: str = ""
    thread_id: str = ""
    user_id: str = ""
    project_name: str = "unnamed"

    # ── Input ──
    file_content: str = ""
    file_type: str = "requirements.txt"

    # ── Parsed data ──
    dependencies: Annotated[list[ParsedDependency], append_dependencies] = field(
        default_factory=list
    )

    # ── Agent findings (append-only) ──
    findings: Annotated[list[Finding], append_findings] = field(default_factory=list)

    # ── Upgrade plan ──
    upgrade_plan: Optional[UpgradePlan] = None

    # ── Approval state (HITL) ──
    approval_action: Optional[str] = None  # "approve" | "reject" | "edit"
    approval_feedback: str = ""

    # ── Conversation / agent messages ──
    messages: Annotated[list[AnyMessage], add_messages] = field(default_factory=list)

    # ── Execution trace (append-only) ──
    trace: Annotated[list[TraceEntry], append_trace] = field(default_factory=list)

    # ── Status ──
    status: ScanStatus = ScanStatus.PENDING
    error: str = ""

    # ── Routing ──
    current_worker: str = ""
    next_action: str = ""

    # ── Retry tracking ──
    retry_count: int = 0

    # ── Token tracking ──
    total_tokens: int = 0
    total_latency_ms: float = 0.0
    node_tokens: dict[str, dict[str, Any]] = field(default_factory=dict)

    # ── Iteration tracking for ReAct loop ──
    iteration_count: int = 0
