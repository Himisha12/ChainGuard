"""Tests for Model Context Protocol (MCP) server (D19)."""

from __future__ import annotations

import json
import pytest

from src.tools.mcp_server import TOOLS, handle_call_tool, process_message


class TestMCPServer:
    """Test MCP protocol messages and tool execution."""

    def test_mcp_initialize(self) -> None:
        init_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"clientInfo": {"name": "test-client", "version": "1.0"}},
        }
        res = process_message(init_req)
        assert res is not None
        assert res["id"] == 1
        assert "serverInfo" in res["result"]
        assert res["result"]["serverInfo"]["name"] == "chainguard-mcp"

    def test_mcp_tools_list(self) -> None:
        list_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        res = process_message(list_req)
        assert res is not None
        tools = res["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        assert "parse_dependency_file" in tool_names
        assert "lookup_vulnerabilities" in tool_names
        assert "compute_risk_score" in tool_names
        assert "query_dependency_impact" in tool_names
        assert "hybrid_search_advisories" in tool_names
        assert "sanitize_manifest_input" in tool_names

    def test_mcp_call_parse_dependency(self) -> None:
        content = "flask==2.3.0\nrequests==2.31.0\n"
        call_req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "parse_dependency_file",
                "arguments": {"content": content},
            },
        }
        res = process_message(call_req)
        assert res is not None
        assert "content" in res["result"]
        data = json.loads(res["result"]["content"][0]["text"])
        assert len(data) == 2
        assert data[0]["name"] == "flask"

    def test_mcp_call_lookup_vulnerabilities(self) -> None:
        call_req = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "lookup_vulnerabilities",
                "arguments": {"package_name": "requests", "version": "2.25.0"},
            },
        }
        res = process_message(call_req)
        assert res is not None
        data = json.loads(res["result"]["content"][0]["text"])
        assert len(data) > 0
        assert any("CVE-2023-32681" in v["vuln_id"] for v in data)
