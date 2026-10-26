"""Tests for OpsPilot Memory, Token Budget, and Fact-Retention Check."""

from __future__ import annotations

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from src.core.database import add_past_incident, init_db, search_past_incidents
from src.graph.memory import (
    count_messages_tokens,
    count_tokens,
    summarize_then_window,
    verify_fact_retention,
)
from src.models.schemas import PastIncident, StructuredFacts


class TestTokenizerAndTokenBudget:
    """Validate token counting with tokenizer (not words) and budget limit."""

    def test_count_tokens_exact_with_tokenizer(self) -> None:
        """Verify token counting uses subword tokenizer, not whitespace splitting."""
        sample = "Database connection pool timeout exceeded in service payment-gateway (error_code: 0xDEADBEEF)"
        tok_count = count_tokens(sample)
        word_count = len(sample.split())

        # Subword tokenizers produce more tokens than whitespace words
        assert tok_count > 0
        assert isinstance(tok_count, int)
        assert tok_count >= word_count  # Subwords like DEADBEEF split into multiple tokens

    def test_message_tokens_tracking(self) -> None:
        messages = [
            HumanMessage(content="High 5xx errors observed on payments service."),
            AIMessage(content="Triaging active alerts and inspecting pod health status."),
        ]
        tokens = count_messages_tokens(messages)
        assert tokens > 15


class TestSummarizeThenWindowAndFactRetention:
    """Validate summarize-then-window and 10-fact retention check."""

    def test_summarize_then_window_prunes_older_and_keeps_recent_verbatim(self) -> None:
        """Requirement: do not just slice the array; older turns become a system note."""
        facts = StructuredFacts(
            service_names=["payment-gateway"],
            timestamps={"incident_start": "2026-10-17T14:02:11Z"},
            hypotheses=["DB pool timeout reduced to 200ms"],
            metrics={"error_rate": "18.4%"},
        )

        # Create a conversation with 10 turns exceeding a low budget of 80 tokens
        messages = [
            HumanMessage(content=f"Turn {i}: Detailed diagnostic telemetry message explaining system metrics #{i}")
            for i in range(10)
        ]

        total_before = count_messages_tokens(messages)
        assert total_before > 80

        # Run summarize-then-window with window_turns=3 and budget=80
        compacted, was_summarized = summarize_then_window(
            messages=messages,
            structured_facts=facts,
            token_budget=80,
            window_turns=3,
        )

        assert was_summarized is True
        # First message is now the compressed SystemMessage summary note
        assert isinstance(compacted[0], SystemMessage)
        assert "INCIDENT MEMORY COMPACTION" in str(compacted[0].content)
        assert "payment-gateway" in str(compacted[0].content)

        # The last 3 turns remain verbatim (rule: last N turns stay verbatim)
        assert len(compacted) == 4  # 1 summary note + 3 verbatim turns
        assert compacted[-3].content == messages[-3].content
        assert compacted[-2].content == messages[-2].content
        assert compacted[-1].content == messages[-1].content

    def test_ten_fact_retention_check_after_compaction(self) -> None:
        """The fact-retention check: Plant 10 specific facts in early turns,

        force a summarization, and count how many are still available afterward (10 of 10).
        """
        # 10 specific facts to plant
        planted_10_facts = {
            "fact_01_incident_id": "INC-ALPHA-9821",
            "fact_02_db_host": "postgres-primary-us-east-1a.internal",
            "fact_03_spike_timestamp": "2026-10-17T14:02:11Z",
            "fact_04_culprit_commit": "a8f3b01",
            "fact_05_deploy_id": "dep-8921",
            "fact_06_previous_stable_version": "v2.13.9",
            "fact_07_broken_version": "v2.14.0",
            "fact_08_timeout_value": "200ms",
            "fact_09_affected_endpoint": "/v1/charges",
            "fact_10_oncall_engineer": "alex-sre",
        }

        # Store in structured facts block so summarization cannot drop them
        facts = StructuredFacts(
            service_names=["payment-gateway"],
            timestamps={"detection": planted_10_facts["fact_03_spike_timestamp"]},
            hypotheses=["DB pool timeout reduced to 200ms"],
            planted_facts=planted_10_facts,
        )

        # Plant the 10 facts in early conversation turns
        early_turns = [
            HumanMessage(content=f"Report item: {k} is set to {v}. Please note this down.")
            for k, v in planted_10_facts.items()
        ]
        # Followed by filler turns that overflow the token budget
        filler_turns = [
            AIMessage(content=f"Acknowledged item {i}. Continuing diagnostic investigation and metrics polling.")
            for i in range(15)
        ]
        all_messages = early_turns + filler_turns

        # Ensure budget is exceeded
        tokens_before = count_messages_tokens(all_messages)
        assert tokens_before > 200

        # Force summarization with small budget
        compacted_messages, was_summarized = summarize_then_window(
            messages=all_messages,
            structured_facts=facts,
            token_budget=150,
            window_turns=3,
        )

        assert was_summarized is True

        # Count retained facts
        retained, total, missing = verify_fact_retention(compacted_messages, planted_10_facts)

        # Must retain 10 out of 10 planted facts!
        assert retained == 10, f"Expected 10 facts retained, but got {retained}. Missing: {missing}"
        assert total == 10
        assert len(missing) == 0


class TestCrossIncidentMemory:
    """Validate cross-incident memory lookup in past_incidents table."""

    def test_past_incidents_lookup(self) -> None:
        init_db()
        past = PastIncident(
            incident_id="inc-past-101",
            service_name="payment-gateway",
            title="Database Connection Pool Exhaustion",
            symptoms="High 500 error rate on /v1/charges after deploy",
            root_cause="Connection timeout was reduced to 200ms",
            remediation_action="Rollback to previous release or increase pool timeout to 2000ms",
            resolution_summary="Service recovered immediately after rollback",
        )
        add_past_incident(past)

        # Search for similar incident
        matches = search_past_incidents(query="payment-gateway pool timeout", service_name="payment-gateway")
        assert len(matches) > 0
        assert matches[0].service_name == "payment-gateway"
        assert "Rollback" in matches[0].remediation_action
