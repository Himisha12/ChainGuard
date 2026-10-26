"""LangGraph builder for OpsPilot Incident Remediation.

Configured with:
- SqliteSaver persistence keyed by incident_id as thread ID.
- State interrupt before post_approval node for WRITE/DESTRUCTIVE tools.
- Time-travel checkpoint inspection and branching replay.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Literal

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, StateGraph

from src.core.config import get_settings
from src.graph.opspilot_nodes import (
    approval_gate_node,
    escalate_node,
    log_analyst_node,
    post_approval_node,
    remediation_node,
    summarizer_node,
    supervisor_node,
    triage_node,
    verifier_node,
)
from src.graph.opspilot_state import OpsPilotState
from src.models.schemas import IncidentStatus

import structlog

logger = structlog.get_logger(__name__)


# ─── Routing Functions ────────────────────────────────────────────────────────


def route_supervisor(state: OpsPilotState) -> str:
    """Conditional edge from supervisor to current active worker."""
    if state.status == IncidentStatus.ESCALATED:
        return "escalate"
    if state.status in (IncidentStatus.RESOLVED, IncidentStatus.FAILED):
        return END

    worker = state.current_worker
    valid_workers = {"triage", "log_analyst", "remediation", "approval_gate", "verifier", "escalate"}
    if worker in valid_workers:
        return worker
    return "triage"


def route_post_approval(state: OpsPilotState) -> str:
    """Routing after operator approval decision."""
    if state.status == IncidentStatus.ESCALATED:
        return "escalate"
    if state.approval_action == "reject":
        # Force remediation to formulate an alternative fix
        return "remediation"
    return "supervisor"


# ─── Graph Construction ───────────────────────────────────────────────────────


def build_opspilot_graph(checkpointer: SqliteSaver | None = None) -> Any:
    """Build and compile the OpsPilot state machine graph."""
    graph = StateGraph(OpsPilotState)

    # Add agent nodes
    graph.add_node("supervisor", supervisor_node)
    graph.add_node("triage", triage_node)
    graph.add_node("log_analyst", log_analyst_node)
    graph.add_node("remediation", remediation_node)
    graph.add_node("approval_gate", approval_gate_node)
    graph.add_node("post_approval", post_approval_node)
    graph.add_node("verifier", verifier_node)
    graph.add_node("escalate", escalate_node)

    # Entry point
    graph.set_entry_point("supervisor")

    # Routing from supervisor
    graph.add_conditional_edges(
        "supervisor",
        route_supervisor,
        {
            "triage": "triage",
            "log_analyst": "log_analyst",
            "remediation": "remediation",
            "approval_gate": "approval_gate",
            "verifier": "verifier",
            "escalate": "escalate",
            END: END,
        },
    )

    # Worker edges back to supervisor
    graph.add_edge("triage", "supervisor")
    graph.add_edge("log_analyst", "supervisor")
    graph.add_edge("remediation", "supervisor")
    graph.add_edge("verifier", "supervisor")
    graph.add_edge("escalate", END)

    # Approval Gate -> interrupt before post_approval
    graph.add_edge("approval_gate", "post_approval")

    # Post-approval routes back to supervisor or remediation (on rejection) or escalate (loop cap)
    graph.add_conditional_edges(
        "post_approval",
        route_post_approval,
        {
            "supervisor": "supervisor",
            "remediation": "remediation",
            "escalate": "escalate",
        },
    )

    compile_kwargs: dict[str, Any] = {}
    if checkpointer is not None:
        compile_kwargs["checkpointer"] = checkpointer

    # Interrupt before post_approval execution so human approval is mandatory
    compile_kwargs["interrupt_before"] = ["post_approval"]

    compiled = graph.compile(**compile_kwargs)
    logger.info("opspilot_graph_compiled", nodes=list(graph.nodes.keys()))
    return compiled


def get_opspilot_checkpointer(db_path: str | None = None) -> SqliteSaver:
    """Create a persistent SQLite checkpointer for LangGraph."""
    if db_path is None:
        settings = get_settings()
        db_path = str(settings.data_dir / "opspilot_checkpoints.sqlite")

    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    return SqliteSaver(conn)


# ─── Time-Travel Replay & Branching ───────────────────────────────────────────


def list_incident_checkpoints(graph: Any, incident_id: str) -> list[dict[str, Any]]:
    """List historical checkpoints for an incident (time-travel)."""
    config = {"configurable": {"thread_id": incident_id}}
    checkpoints = []

    try:
        history = list(graph.get_state_history(config))
        for idx, state in enumerate(history):
            vals = state.values if hasattr(state, "values") else {}
            cp_id = state.config.get("configurable", {}).get("checkpoint_id", "")
            status_val = vals.get("status", "")
            if hasattr(status_val, "value"):
                status_val = status_val.value

            checkpoints.append({
                "index": idx,
                "checkpoint_id": cp_id,
                "status": str(status_val),
                "current_worker": vals.get("current_worker", ""),
                "has_pending_approval": vals.get("pending_approval") is not None,
                "message_count": len(vals.get("messages", [])),
                "next_nodes": list(state.next) if hasattr(state, "next") else [],
            })
    except Exception as exc:
        logger.warning("failed_listing_checkpoints", incident_id=incident_id, error=str(exc))

    return checkpoints


def fork_incident_branch(
    graph: Any,
    incident_id: str,
    checkpoint_id: str,
    new_thread_id: str,
    state_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Time-travel branching.

    Picks an earlier checkpoint, optionally changes the state (e.g. mark hypothesis wrong),
    and re-runs down a new branch. Returns the result of both branches side-by-side.
    """
    orig_config = {"configurable": {"thread_id": incident_id}}
    new_config = {"configurable": {"thread_id": new_thread_id}}

    # Find the requested checkpoint in the original thread
    history = list(graph.get_state_history(orig_config))
    target_state = None
    for state in history:
        cid = state.config.get("configurable", {}).get("checkpoint_id", "")
        if cid == checkpoint_id or (checkpoint_id and cid.startswith(checkpoint_id)):
            target_state = state
            break

    if not target_state and history:
        target_state = history[0]

    if not target_state:
        # Fallback empty state if history is empty
        forked_values = {
            "incident_id": new_thread_id,
            "thread_id": new_thread_id,
            "status": "remediating",
            "branch_name": f"fork_{new_thread_id}",
            "messages": [],
        }
    else:
        # Copy state values into new branch
        forked_values = dict(target_state.values)

    if state_overrides:
        forked_values.update(state_overrides)
    forked_values["branch_name"] = f"fork_{new_thread_id}"

    # Initialize new thread with the checkpoint state
    try:
        graph.update_state(new_config, forked_values)
    except Exception as exc:
        logger.warning("fork_update_state_warn", error=str(exc))

    # Resume the new branch
    branch_events = []
    try:
        for event in graph.stream(None, config=new_config):
            branch_events.append(list(event.keys())[0] if isinstance(event, dict) else str(event))
    except Exception as exc:
        logger.warning("fork_stream_error", error=str(exc))
        branch_events.append("interrupted")

    final_fork_state = None
    try:
        final_fork_state = graph.get_state(new_config)
    except Exception:
        pass

    final_status = "remediating"
    if final_fork_state and final_fork_state.values:
        st = final_fork_state.values.get("status", "")
        final_status = st.value if hasattr(st, "value") else str(st or "remediating")

    orig_status = "resolved"
    if history and history[0].values:
        st_orig = history[0].values.get("status", "")
        orig_status = st_orig.value if hasattr(st_orig, "value") else str(st_orig or "resolved")

    return {
        "original_thread_id": incident_id,
        "forked_thread_id": new_thread_id,
        "checkpoint_id": checkpoint_id,
        "forked_status": final_status,
        "forked_messages_count": len(final_fork_state.values.get("messages", [])) if (final_fork_state and final_fork_state.values) else 0,
        "side_by_side": {
            "original_branch": {
                "thread_id": incident_id,
                "status": orig_status,
            },
            "forked_branch": {
                "thread_id": new_thread_id,
                "status": final_status,
                "state_overrides": state_overrides or {},
            },
        },
    }
