"""Tests for LangGraph state machine, reducers, and routing (D16, D17, D18, D20)."""

from __future__ import annotations

import pytest
from langchain_core.messages import AIMessage

from src.graph.builder import build_scan_graph, route_from_supervisor, route_after_verifier
from src.graph.nodes import parser_node, risk_assessor_node, supervisor_node
from src.graph.state import (
    ScanState,
    append_dependencies,
    append_findings,
    append_trace,
)
from src.models.schemas import (
    Finding,
    ParsedDependency,
    RiskAssessment,
    ScanStatus,
    Severity,
    TraceEntry,
    UpgradeAction,
    UpgradePlan,
    Vulnerability,
)


class TestStateReducers:
    """Test typed reducers in ScanState (D17)."""

    def test_append_findings_reducer_deduplicates(self) -> None:
        v1 = Vulnerability(
            vuln_id="CVE-2023-1111",
            package_name="test-pkg",
            affected_versions="<1.0",
        )
        f1 = Finding(
            id="find-1",
            dependency=ParsedDependency(name="test-pkg", current_version="0.9", source_file="req.txt", line_number=1),
            vulnerability=v1,
            risk_assessment=RiskAssessment(risk_score=7.0, risk_level=Severity.HIGH, reasoning="test"),
        )
        f2 = Finding(
            id="find-2",
            dependency=ParsedDependency(name="other-pkg", current_version="1.0", source_file="req.txt", line_number=2),
            vulnerability=v1,
            risk_assessment=RiskAssessment(risk_score=4.0, risk_level=Severity.MEDIUM, reasoning="test"),
        )

        existing = [f1]
        result = append_findings(existing, [f1, f2])
        # f1 is duplicate by id, f2 is new
        assert len(result) == 2
        assert result[0].id == "find-1"
        assert result[1].id == "find-2"

    def test_append_dependencies_reducer_deduplicates(self) -> None:
        d1 = ParsedDependency(name="flask", current_version="2.0.0", source_file="req.txt", line_number=1)
        d2 = ParsedDependency(name="flask", current_version="2.0.0", source_file="req.txt", line_number=1)
        d3 = ParsedDependency(name="requests", current_version="2.25.0", source_file="req.txt", line_number=2)

        existing = [d1]
        result = append_dependencies(existing, [d2, d3])
        assert len(result) == 2
        assert result[0].name == "flask"
        assert result[1].name == "requests"

    def test_append_trace_reducer_preserves_order(self) -> None:
        t1 = TraceEntry(node="node1", action="action1", detail="d1")
        t2 = TraceEntry(node="node2", action="action2", detail="d2")
        result = append_trace([t1], t2)
        assert len(result) == 2
        assert result[0].node == "node1"
        assert result[1].node == "node2"


class TestSupervisorRouting:
    """Test conditional routing logic in supervisor (D16, D17)."""

    def test_routes_to_parser_when_no_deps(self) -> None:
        state = ScanState(file_content="flask==2.3.0", dependencies=[])
        update = supervisor_node(state)
        assert update["current_worker"] == "parser"
        assert route_from_supervisor(ScanState(current_worker="parser")) == "parser"

    def test_routes_to_risk_assessor_when_deps_exist(self) -> None:
        dep = ParsedDependency(name="flask", current_version="2.0.0", source_file="req.txt", line_number=1)
        state = ScanState(dependencies=[dep], findings=[], status=ScanStatus.PARSING)
        update = supervisor_node(state)
        assert update["current_worker"] == "risk_assessor"

    def test_routes_to_error_handler_on_error(self) -> None:
        state = ScanState(error="Something failed in parser")
        assert route_from_supervisor(state) == "error_handler"

    def test_verifier_retry_cycle_routing(self) -> None:
        # Retry count < max_retries (2) -> routes to supervisor (cycle)
        state_retry = ScanState(next_action="needs_revision", retry_count=1)
        assert route_after_verifier(state_retry) == "supervisor"

        # Retry count >= max_retries (2) -> proceeds to approval gate
        state_max = ScanState(next_action="needs_revision", retry_count=2)
        assert route_after_verifier(state_max) == "approval_gate"


class TestGraphCompilationAndExecution:
    """Test full LangGraph compilation and execution."""

    def test_graph_compiles_with_all_nodes(self) -> None:
        graph = build_scan_graph()
        assert graph is not None
        assert "supervisor" in graph.nodes
        assert "parser" in graph.nodes
        assert "risk_assessor" in graph.nodes
        assert "planner" in graph.nodes
        assert "verifier" in graph.nodes
        assert "approval_gate" in graph.nodes
        assert "post_approval" in graph.nodes

    def test_parser_node_execution(self) -> None:
        state = ScanState(
            file_content="requests==2.25.0\nflask==2.0.0\n",
            file_type="requirements.txt",
        )
        update = parser_node(state)
        assert len(update["dependencies"]) == 2
        assert update["status"] == ScanStatus.ANALYZING

    def test_risk_assessor_node_execution(self) -> None:
        dep = ParsedDependency(name="requests", current_version="2.25.0", source_file="req.txt", line_number=1)
        state = ScanState(dependencies=[dep])
        update = risk_assessor_node(state)
        assert len(update["findings"]) > 0
        assert update["findings"][0].vulnerability.package_name == "requests"
