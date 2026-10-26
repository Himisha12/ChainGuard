"""Tests for OpsPilot Domain Tools, MCP Server, and Tool-Count Rules."""

from __future__ import annotations

import pytest

from src.models.schemas import RiskTier
from src.tools.mcp_server import MCPStdioClient, process_message
from src.tools.opspilot_tools import (
    AGENT_ALLOWED_TOOLS,
    DOMAIN_TOOLS,
    MAX_TOOLS_PER_AGENT,
    assert_tool_count_rule,
    execute_tool_with_gate,
    get_agent_tools,
    reset_mock_services,
)


@pytest.fixture(autouse=True)
def reset_cluster_state():
    reset_mock_services()


class TestToolCountRule:

    """Validate rule: No agent receives more than 4 tools."""

    def test_all_agents_have_four_or_fewer_tools(self) -> None:
        """Assert in unit test that every agent has <= 4 tools."""
        assert_tool_count_rule()
        for agent_name, tools in AGENT_ALLOWED_TOOLS.items():
            count = len(tools)
            assert count <= MAX_TOOLS_PER_AGENT, (
                f"Agent '{agent_name}' has {count} tools, exceeding limit of {MAX_TOOLS_PER_AGENT}"
            )

    def test_agent_tool_counts_exact(self) -> None:
        """Verify the exact toolsets specified for OpsPilot."""
        assert len(get_agent_tools("triage")) == 2
        assert set(get_agent_tools("triage")) == {"get_alerts", "get_service_status"}

        assert len(get_agent_tools("log_analyst")) == 3
        assert set(get_agent_tools("log_analyst")) == {"read_logs", "query_metrics", "get_recent_deploys"}

        assert len(get_agent_tools("remediation")) == 4
        assert set(get_agent_tools("remediation")) == {"propose_fix", "rollback_deploy", "restart_service", "update_config"}

        assert len(get_agent_tools("verifier")) == 2
        assert set(get_agent_tools("verifier")) == {"get_service_status", "run_health_check"}


class TestRiskTieredApprovalGates:
    """Validate risk-tiered gates: READ auto-runs, WRITE/DESTRUCTIVE pause."""

    def test_read_tools_auto_run(self) -> None:
        """Read-only tools execute immediately without pause or approval."""
        res1 = execute_tool_with_gate("get_service_status", {"service_name": "payment-gateway"}, incident_id="inc-test")
        assert res1["success"] is True
        assert res1["executed"] is True
        assert res1["risk_tier"] == RiskTier.READ.value

        res2 = execute_tool_with_gate("read_logs", {"service_name": "payment-gateway", "lines": 5}, incident_id="inc-test")
        assert res2["success"] is True
        assert res2["executed"] is True
        assert res2["risk_tier"] == RiskTier.READ.value

    def test_write_and_destructive_tools_pause_for_approval(self) -> None:
        """WRITE and DESTRUCTIVE tools pause and require approval."""
        # WRITE
        res_write = execute_tool_with_gate("restart_service", {"service_name": "payment-gateway"}, incident_id="inc-gate-1")
        assert res_write["success"] is False
        assert res_write["status"] == "APPROVAL_REQUIRED"
        assert res_write["risk_tier"] == RiskTier.WRITE.value
        assert "approval_id" in res_write

        # DESTRUCTIVE
        res_dest = execute_tool_with_gate("rollback_deploy", {"service_name": "payment-gateway", "target_version": "v2.13.9"}, incident_id="inc-gate-2")
        assert res_dest["success"] is False
        assert res_dest["status"] == "APPROVAL_REQUIRED"
        assert res_dest["risk_tier"] == RiskTier.DESTRUCTIVE.value
        assert "approval_id" in res_dest


class TestDynamicToolDiscoveryOverStdio:
    """Validate dynamic tool discovery: agent connects over stdio, calls list_tools, filters."""

    def test_client_dynamic_discovery_and_filtering(self) -> None:
        client = MCPStdioClient(process_func=process_message)

        # 1. Calls list_tools dynamically
        all_tools = client.list_tools()
        all_names = [t["name"] for t in all_tools]
        assert "get_alerts" in all_names
        assert "rollback_deploy" in all_names
        assert "read_logs" in all_names

        # 2. Triage agent filters to its allowed set
        triage_tools = client.discover_tools_for_agent("triage")
        assert len(triage_tools) == 2
        assert {t["name"] for t in triage_tools} == {"get_alerts", "get_service_status"}

        # 3. Log analyst filters to its allowed set
        analyst_tools = client.discover_tools_for_agent("log_analyst")
        assert len(analyst_tools) == 3
        assert {t["name"] for t in analyst_tools} == {"read_logs", "query_metrics", "get_recent_deploys"}

        # 4. Remediation filters to its allowed set
        remediation_tools = client.discover_tools_for_agent("remediation")
        assert len(remediation_tools) == 4
        assert {t["name"] for t in remediation_tools} == {"propose_fix", "rollback_deploy", "restart_service", "update_config"}

        # 5. Verifier filters to its allowed set
        verifier_tools = client.discover_tools_for_agent("verifier")
        assert len(verifier_tools) == 2
        assert {t["name"] for t in verifier_tools} == {"get_service_status", "run_health_check"}

    def test_mcp_tool_execution_over_protocol(self) -> None:
        client = MCPStdioClient(process_func=process_message)
        call_res = client.call_tool("get_service_status", {"service_name": "payment-gateway"})
        assert "content" in call_res
        import json
        data = json.loads(call_res["content"][0]["text"])
        assert data["service"] == "payment-gateway"
        assert data["status"] == "degraded"
