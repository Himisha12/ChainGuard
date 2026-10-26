"""OpsPilot LangGraph State Definition with Typed Reducers.

Enforces:
- Structured facts preservation
- Append-only message history
- Bounded context worker aggregation
- HITL approval state (3 modes: approve, reject, edit)
"""

from __future__ import annotations

import operator
from dataclasses import dataclass, field
from typing import Annotated, Any, Optional

from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages

from src.models.schemas import IncidentStatus, PendingApproval, Severity, StructuredFacts


def merge_dicts(existing: dict[str, Any], new: dict[str, Any] | None) -> dict[str, Any]:
    """Merge worker result dictionaries."""
    if new is None:
        return existing
    merged = dict(existing)
    merged.update(new)
    return merged


def replace_value(existing: Any, new: Any) -> Any:
    """Last write wins scalar reducer."""
    return new


@dataclass
class OpsPilotState:
    """Typed state for the OpsPilot incident response graph."""

    # ── Identifiers ──
    incident_id: str = ""
    thread_id: str = ""
    user_id: str = "operator"
    tenant_id: str = "default-tenant"

    # ── Incident Profile ──
    service_name: str = ""
    description: str = ""
    severity: Severity = Severity.HIGH
    status: IncidentStatus = IncidentStatus.TRIAGING

    # ── Immutable Structured Facts ──
    structured_facts: StructuredFacts = field(default_factory=StructuredFacts)

    # ── Conversation / Trace History ──
    messages: Annotated[list[AnyMessage], add_messages] = field(default_factory=list)

    # ── Bounded Context Worker Aggregation ──
    worker_results: Annotated[dict[str, Any], merge_dicts] = field(default_factory=dict)
    current_worker: str = "triage"
    next_action: str = ""

    # ── Human-in-the-Loop & Approval ──
    pending_approval: Optional[PendingApproval] = None
    approval_action: Optional[str] = None  # "approve" | "reject" | "edit"
    approval_edits: Optional[dict[str, Any]] = None
    rejection_reason: Optional[str] = None
    operator_name: str = "operator"

    # ── Loop Caps & Escalation Tracking ──
    reject_count: int = 0
    verify_retry_count: int = 0
    escalation_reason: Optional[str] = None

    # ── Execution Metadata & Time-Travel ──
    active_checkpoint_id: str = ""
    branch_name: str = "main"
    error: str = ""
    iteration_count: int = 0
    token_budget: int = 3000

