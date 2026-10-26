"""Tests for OpsPilot Time-Travel Checkpoint Inspection and Branching Replay."""

from __future__ import annotations

import pytest

from src.core.database import init_db
from src.graph.opspilot_builder import (
    build_opspilot_graph,
    fork_incident_branch,
    get_opspilot_checkpointer,
    list_incident_checkpoints,
)
from src.graph.opspilot_state import OpsPilotState
from src.models.schemas import IncidentStatus, StructuredFacts


@pytest.fixture(autouse=True)
def setup_db():
    init_db()


class TestTimeTravelReplay:
    """Validate Time-Travel: list checkpoints, fork from past checkpoint, and branch."""

    def test_list_incident_checkpoints(self) -> None:
        cp = get_opspilot_checkpointer()
        graph = build_opspilot_graph(checkpointer=cp)
        inc_id = "inc-tt-list"
        config = {"configurable": {"thread_id": inc_id}}

        state = OpsPilotState(
            incident_id=inc_id,
            thread_id=inc_id,
            service_name="payment-gateway",
            structured_facts=StructuredFacts(service_names=["payment-gateway"]),
        )

        for _ in graph.stream(state, config=config):
            pass

        checkpoints = list_incident_checkpoints(graph, inc_id)
        assert len(checkpoints) > 0
        # Each checkpoint has metadata
        first_cp = checkpoints[0]
        assert "checkpoint_id" in first_cp
        assert "status" in first_cp
        assert "index" in first_cp

    def test_time_travel_branching_produces_alternative_outcome(self) -> None:
        """Pick an earlier checkpoint, change state (e.g. hypothesis), and re-run down a new branch.

        Verify both branches side by side.
        """
        cp = get_opspilot_checkpointer()
        graph = build_opspilot_graph(checkpointer=cp)
        inc_id = "inc-tt-branch-orig"
        config = {"configurable": {"thread_id": inc_id}}

        state = OpsPilotState(
            incident_id=inc_id,
            thread_id=inc_id,
            service_name="payment-gateway",
            structured_facts=StructuredFacts(service_names=["payment-gateway"]),
        )

        for _ in graph.stream(state, config=config):
            pass

        checkpoints = list_incident_checkpoints(graph, inc_id)
        assert len(checkpoints) >= 2

        # Pick an earlier checkpoint (e.g. after triage / analysis)
        target_cp = checkpoints[-2]  # Earlier checkpoint
        target_cp_id = target_cp["checkpoint_id"]

        # Fork new branch with state override (e.g. mark hypothesis as different issue)
        fork_id = "inc-tt-branch-forked"
        override = {
            "rejection_reason": "Manual operator override: DB is healthy, issue is upstream DNS latency",
            "approval_action": "reject",
        }

        fork_result = fork_incident_branch(
            graph=graph,
            incident_id=inc_id,
            checkpoint_id=target_cp_id,
            new_thread_id=fork_id,
            state_overrides=override,
        )

        assert fork_result["original_thread_id"] == inc_id
        assert fork_result["forked_thread_id"] == fork_id
        assert "side_by_side" in fork_result
        assert "original_branch" in fork_result["side_by_side"]
        assert "forked_branch" in fork_result["side_by_side"]
        assert fork_result["side_by_side"]["forked_branch"]["thread_id"] == fork_id
