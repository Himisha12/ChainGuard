"""LangGraph builder: wires nodes, edges, conditional routing (D16, D17).

Builds the complete ChainGuard scan graph with:
- Conditional routing from supervisor (D16)
- Verifier → Planner retry cycle capped at 2 (D17)
- HITL interrupt at approval gate (D20)
- SQLite checkpointer for persistence (D18)
"""

from __future__ import annotations

from typing import Any, Literal

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, StateGraph

from src.core.config import get_settings
from src.graph.nodes import (
    approval_gate_node,
    error_handler_node,
    investigator_node,
    parser_node,
    planner_node,
    post_approval_node,
    risk_assessor_node,
    supervisor_node,
    verifier_node,
)
from src.graph.state import ScanState
from src.models.schemas import ScanStatus

import structlog

logger = structlog.get_logger(__name__)


# ─── Conditional Edge Functions ───────────────────────────────────────────────


def route_from_supervisor(state: ScanState) -> str:
    """Conditional routing from supervisor (D16, D17).

    Routes to the appropriate worker or gate based on current_worker.
    Tool errors route to the fallback error handler.
    """
    if state.error:
        return "error_handler"

    next_worker = state.current_worker

    valid_targets = {
        "parser", "risk_assessor", "investigator",
        "planner", "verifier", "approval_gate",
    }

    if next_worker in valid_targets:
        return next_worker
    else:
        return "approval_gate"


def route_after_verifier(state: ScanState) -> str:
    """Route after verification — retry cycle or proceed (D17).

    Verifier → Planner retry loop, capped at max_retries.
    """
    settings = get_settings()

    if state.next_action == "needs_revision" and state.retry_count < settings.agent.max_retries:
        logger.info(
            "verifier_retry",
            retry_count=state.retry_count,
            max_retries=settings.agent.max_retries,
        )
        return "supervisor"  # Goes back through supervisor to planner

    return "approval_gate"


def route_after_approval(state: ScanState) -> str:
    """Route after approval decision (D20)."""
    if state.status == ScanStatus.APPROVED:
        return END
    elif state.status == ScanStatus.REJECTED:
        return END
    elif state.approval_action == "edit":
        return "supervisor"  # Re-route through supervisor for verification
    else:
        return END


def route_after_risk_assessor(state: ScanState) -> str:
    """Route after risk assessment — go back to supervisor for routing."""
    if state.status == ScanStatus.FAILED:
        return "error_handler"
    return "supervisor"


# ─── Graph Builder ────────────────────────────────────────────────────────────


def build_scan_graph(
    checkpointer: SqliteSaver | None = None,
) -> StateGraph:
    """Build the complete ChainGuard scan state graph.

    Architecture:
    ```
    START → supervisor → [conditional routing]
                ├→ parser → supervisor
                ├→ risk_assessor → supervisor
                ├→ investigator → supervisor
                ├→ planner → supervisor
                ├→ verifier → [retry cycle or approval]
                ├→ approval_gate → [interrupt] → post_approval → END
                └→ error_handler → END
    ```
    """
    # Create the graph with typed state
    graph = StateGraph(ScanState)

    # ── Add nodes ──
    graph.add_node("supervisor", supervisor_node)
    graph.add_node("parser", parser_node)
    graph.add_node("risk_assessor", risk_assessor_node)
    graph.add_node("investigator", investigator_node)
    graph.add_node("planner", planner_node)
    graph.add_node("verifier", verifier_node)
    graph.add_node("approval_gate", approval_gate_node)
    graph.add_node("post_approval", post_approval_node)
    graph.add_node("error_handler", error_handler_node)

    # ── Entry point ──
    graph.set_entry_point("supervisor")

    # ── Conditional routing from supervisor (D16) ──
    graph.add_conditional_edges(
        "supervisor",
        route_from_supervisor,
        {
            "parser": "parser",
            "risk_assessor": "risk_assessor",
            "investigator": "investigator",
            "planner": "planner",
            "verifier": "verifier",
            "approval_gate": "approval_gate",
            "error_handler": "error_handler",
        },
    )

    # ── Worker → back to supervisor ──
    graph.add_edge("parser", "supervisor")
    graph.add_edge("investigator", "supervisor")
    graph.add_edge("planner", "supervisor")

    # ── Risk assessor routing ──
    graph.add_conditional_edges(
        "risk_assessor",
        route_after_risk_assessor,
        {
            "supervisor": "supervisor",
            "error_handler": "error_handler",
        },
    )

    # ── Verifier → retry cycle (D17) ──
    graph.add_conditional_edges(
        "verifier",
        route_after_verifier,
        {
            "supervisor": "supervisor",
            "approval_gate": "approval_gate",
        },
    )

    # ── Approval gate interrupt (D20) ──
    # The interrupt is handled at compile time
    graph.add_edge("approval_gate", "post_approval")

    # ── Post-approval routing (D20) ──
    graph.add_conditional_edges(
        "post_approval",
        route_after_approval,
        {
            END: END,
            "supervisor": "supervisor",
        },
    )

    # ── Error handler → END ──
    graph.add_edge("error_handler", END)

    # ── Compile with checkpointer and interrupt ──
    compile_kwargs: dict[str, Any] = {}
    if checkpointer:
        compile_kwargs["checkpointer"] = checkpointer

    # HITL interrupt before approval processing (D20)
    compile_kwargs["interrupt_before"] = ["post_approval"]

    compiled = graph.compile(**compile_kwargs)

    logger.info("graph_compiled", nodes=list(graph.nodes.keys()))

    return compiled


def get_checkpointer() -> SqliteSaver:
    """Create a SQLite checkpointer for graph persistence (D18).

    Scans paused for approval survive restarts and resume by thread_id.
    """
    import sqlite3
    from pathlib import Path

    settings = get_settings()
    db_path = settings.database.checkpoint_db

    # Ensure directory exists
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path, check_same_thread=False)
    return SqliteSaver(conn)
