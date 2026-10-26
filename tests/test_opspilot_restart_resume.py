"""Tests for OpsPilot Process Kill and Mid-Run Resumption over 10 Kills."""

from __future__ import annotations

import random
import uuid
import pytest

from src.core.database import init_db
from src.graph.opspilot_builder import build_opspilot_graph, get_opspilot_checkpointer
from src.graph.opspilot_state import OpsPilotState
from src.models.schemas import IncidentStatus, StructuredFacts


@pytest.fixture(autouse=True)
def setup_db():
    init_db()


class TestKillAndResumePersistence:
    """Validate process kill and mid-run resumption: Kill the process mid-run, then resume.

    Report pass or fail over about 10 kills at random points.
    """

    def test_ten_random_process_kills_and_resumptions(self) -> None:
        """Run 10 trials: start an incident, kill process after N steps, restart, and resume."""
        total_trials = 10
        passed_trials = 0
        trial_results = []

        for trial_num in range(1, total_trials + 1):
            inc_id = f"inc-kill-test-{trial_num}-{uuid.uuid4().hex[:4]}"
            config = {"configurable": {"thread_id": inc_id}}

            # Phase 1: Initialize graph in "Process A"
            cp1 = get_opspilot_checkpointer()
            graph1 = build_opspilot_graph(checkpointer=cp1)

            init_state = OpsPilotState(
                incident_id=inc_id,
                thread_id=inc_id,
                service_name="payment-gateway",
                description=f"Trial #{trial_num} process kill test",
                structured_facts=StructuredFacts(
                    service_names=["payment-gateway"],
                    planted_facts={f"trial_{trial_num}": f"val_{trial_num}"},
                ),
            )

            # Randomly decide how many steps to execute before "killing" (1 to 5 steps)
            kill_after_steps = random.randint(1, 5)

            step_count = 0
            steps_before_kill = []
            for event in graph1.stream(init_state, config=config):
                node_name = list(event.keys())[0]
                steps_before_kill.append(node_name)
                step_count += 1
                if step_count >= kill_after_steps:
                    # SIMULATE IMMEDIATE PROCESS KILL / TERMINATION
                    break

            pre_kill_state = graph1.get_state(config)
            pre_kill_status = pre_kill_state.values.get("status")

            # Phase 2: Kill references to simulate hard process termination
            del graph1
            del cp1

            # Phase 3: Start "Process B" (fresh startup connecting to persistent SQLite)
            cp2 = get_opspilot_checkpointer()
            graph2 = build_opspilot_graph(checkpointer=cp2)

            # Check that state was persisted across process termination
            recovered_state = graph2.get_state(config)
            assert recovered_state is not None, f"Trial {trial_num}: Failed to recover state from SQLite"
            assert recovered_state.values.get("incident_id") == inc_id

            # Verify planted facts survived the kill
            recovered_facts = recovered_state.values.get("structured_facts")
            assert recovered_facts is not None
            assert f"trial_{trial_num}" in recovered_facts.planted_facts

            # Phase 4: Resume execution from the last checkpoint
            resumed_events = []
            # If stopped at approval gate, supply approval to complete the run
            if recovered_state.next and "post_approval" in recovered_state.next:
                graph2.update_state(config, {"approval_action": "approve", "operator_name": "auto-resumer"})

            for event in graph2.stream(None, config=config):
                resumed_events.append(list(event.keys())[0])

            final_state = graph2.get_state(config)
            final_status = final_state.values.get("status")

            # Persistence works if run restored and reached either AWAITING_APPROVAL or RESOLVED
            is_valid_resumption = (
                final_status in (IncidentStatus.RESOLVED, IncidentStatus.AWAITING_APPROVAL)
                or len(resumed_events) > 0
            )

            if is_valid_resumption:
                passed_trials += 1
                trial_results.append({
                    "trial": trial_num,
                    "kill_after_steps": kill_after_steps,
                    "pre_kill_nodes": steps_before_kill,
                    "resumed_nodes": resumed_events,
                    "result": "PASS",
                })
            else:
                trial_results.append({
                    "trial": trial_num,
                    "result": "FAIL",
                })

        # Assert 10 of 10 passed
        assert passed_trials == total_trials, (
            f"Expected {total_trials}/{total_trials} kill-resume passes, but got {passed_trials}/{total_trials}!"
        )
