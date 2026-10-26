"""Tests for raw SDK baseline agent (D16)."""

from __future__ import annotations

import json
import pytest

from src.agents.baseline_agent import TOOLS, execute_tool


class TestBaselineAgentTools:
    """Test raw tool executions in baseline agent."""

    def test_parse_dependencies_tool(self) -> None:
        content = "flask==2.3.0\nrequests==2.31.0\n"
        result_str = execute_tool("parse_dependencies", {"file_content": content})
        data = json.loads(result_str)
        assert len(data) == 2
        assert data[0]["name"] == "flask"

    def test_check_vulnerabilities_tool(self) -> None:
        result_str = execute_tool(
            "check_vulnerabilities",
            {"package_name": "requests", "version": "2.25.0"},
        )
        data = json.loads(result_str)
        assert len(data) > 0
        assert any("CVE-2023-32681" in v["vuln_id"] for v in data)

    def test_unknown_tool_returns_error(self) -> None:
        result_str = execute_tool("unknown_tool", {})
        data = json.loads(result_str)
        assert "error" in data

    def test_tool_definitions_conform_to_schema(self) -> None:
        assert len(TOOLS) == 2
        tool_names = [t["function"]["name"] for t in TOOLS]
        assert "parse_dependencies" in tool_names
        assert "check_vulnerabilities" in tool_names
