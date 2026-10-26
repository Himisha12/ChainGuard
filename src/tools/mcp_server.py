"""Model Context Protocol (MCP) Server for ChainGuard (D19).

Exposes ChainGuard's vulnerability analysis, parsing, risk scoring,
and dependency graph tools over standard JSON-RPC 2.0 stdio protocol.
Any MCP-compliant client (Claude Desktop, Cursor, Antigravity) can connect and
invoke these security tools directly.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Callable

from src.guardrails.sanitizer import sanitize_input
from src.models.schemas import ParsedDependency, Vulnerability
from src.rag.hybrid_search import HybridVulnSearch
from src.tools.dep_graph import DependencyGraph
from src.tools.parsers import parse_file, parse_requirements_txt
from src.tools.risk_scorer import compute_risk_score
from src.tools.vuln_lookup import lookup_vulnerabilities

# MCP Protocol Version
MCP_PROTOCOL_VERSION = "2024-11-05"

# Tool definitions in MCP standard schema
TOOLS = [
    {
        "name": "parse_dependency_file",
        "description": "Parse a requirements.txt or pyproject.toml file and extract structured dependencies with versions, extras, and line numbers.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "Raw text content of the dependency file",
                },
                "file_type": {
                    "type": "string",
                    "enum": ["requirements.txt", "pyproject.toml"],
                    "description": "File format type",
                    "default": "requirements.txt",
                },
            },
            "required": ["content"],
        },
    },
    {
        "name": "lookup_vulnerabilities",
        "description": "Lookup known security vulnerabilities and CVEs for a Python package and version specifier.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package_name": {
                    "type": "string",
                    "description": "Name of the PyPI package to inspect",
                },
                "version": {
                    "type": "string",
                    "description": "Installed version or version specifier (e.g. '2.3.0', '==1.19.0', or '*')",
                    "default": "*",
                },
            },
            "required": ["package_name"],
        },
    },
    {
        "name": "compute_risk_score",
        "description": "Calculate composite risk score (0-10), severity tier, and check for major breaking version upgrades.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package_name": {"type": "string"},
                "current_version": {"type": "string"},
                "vuln_id": {"type": "string"},
                "cvss_score": {"type": "number", "minimum": 0, "maximum": 10},
                "fixed_version": {"type": "string"},
                "dependent_count": {"type": "integer", "default": 0},
            },
            "required": ["package_name", "current_version", "vuln_id"],
        },
    },
    {
        "name": "query_dependency_impact",
        "description": "Analyze dependency graph to determine what downstream packages break if a package is upgraded.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {
                    "type": "string",
                    "description": "Package name to analyze impact for",
                },
                "manifest_content": {
                    "type": "string",
                    "description": "Manifest content (requirements.txt) to construct local graph from",
                },
            },
            "required": ["package"],
        },
    },
    {
        "name": "hybrid_search_advisories",
        "description": "Perform BM25 + dense semantic hybrid search with Reciprocal Rank Fusion over local CVE vulnerability advisories.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query or natural language description (e.g., 'SQL injection in django', 'remote code execution')",
                },
                "top_k": {"type": "integer", "default": 5},
            },
            "required": ["query"],
        },
    },
    {
        "name": "sanitize_manifest_input",
        "description": "Scan dependency file comments for prompt injection attacks and redact API keys, passwords, or PII.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "Raw manifest content to validate and sanitize",
                }
            },
            "required": ["content"],
        },
    },
    # ─── OpsPilot Incident Sandbox Tools ───
    {
        "name": "get_alerts",
        "description": "Retrieve active Prometheus/PagerDuty alerts for a service or entire cluster.",
        "inputSchema": {
            "type": "object",
            "properties": {"service_name": {"type": "string", "default": ""}},
        },
    },
    {
        "name": "get_service_status",
        "description": "Inspect current service health status, error rate, p99 latency, and active version.",
        "inputSchema": {
            "type": "object",
            "properties": {"service_name": {"type": "string"}},
            "required": ["service_name"],
        },
    },
    {
        "name": "read_logs",
        "description": "Read recent stdout/stderr log lines for a service.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "service_name": {"type": "string"},
                "lines": {"type": "integer", "default": 50},
            },
            "required": ["service_name"],
        },
    },
    {
        "name": "query_metrics",
        "description": "Query telemetry metrics (error_rate, p99_latency, cpu_usage).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "service_name": {"type": "string"},
                "metric": {"type": "string", "default": "error_rate"},
            },
            "required": ["service_name"],
        },
    },
    {
        "name": "get_recent_deploys",
        "description": "Inspect recent deployment history, commit hash, and deployer.",
        "inputSchema": {
            "type": "object",
            "properties": {"service_name": {"type": "string"}},
            "required": ["service_name"],
        },
    },
    {
        "name": "propose_fix",
        "description": "Formulate and register a candidate remediation proposal (read-only planning).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "service_name": {"type": "string"},
                "action": {"type": "string"},
                "details": {"type": "string", "default": ""},
            },
            "required": ["service_name", "action"],
        },
    },
    {
        "name": "run_health_check",
        "description": "Execute end-to-end synthetic health and canary probes.",
        "inputSchema": {
            "type": "object",
            "properties": {"service_name": {"type": "string"}},
            "required": ["service_name"],
        },
    },
    {
        "name": "restart_service",
        "description": "Restart service pods/containers gracefully (WRITE action).",
        "inputSchema": {
            "type": "object",
            "properties": {"service_name": {"type": "string"}},
            "required": ["service_name"],
        },
    },
    {
        "name": "update_config",
        "description": "Update live configuration parameters (WRITE action).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "service_name": {"type": "string"},
                "config_key": {"type": "string"},
                "config_value": {"type": "string"},
            },
            "required": ["service_name", "config_key", "config_value"],
        },
    },
    {
        "name": "rollback_deploy",
        "description": "Roll back service to a previous deployment version (DESTRUCTIVE action).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "service_name": {"type": "string"},
                "target_version": {"type": "string"},
            },
            "required": ["service_name", "target_version"],
        },
    },
]



def handle_call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute requested tool and format output as MCP text response."""
    try:
        if name == "parse_dependency_file":
            content = arguments.get("content", "")
            file_type = arguments.get("file_type", "requirements.txt")
            deps = parse_file(content, file_type)
            result = [d.model_dump() for d in deps]

        elif name == "lookup_vulnerabilities":
            pkg = arguments.get("package_name", "")
            ver = arguments.get("version", "*")
            vulns = lookup_vulnerabilities(pkg, ver)
            result = [v.model_dump() for v in vulns]

        elif name == "compute_risk_score":
            dep = ParsedDependency(
                name=arguments.get("package_name", ""),
                current_version=arguments.get("current_version", "*"),
                source_file="mcp_call",
                line_number=1,
            )
            vuln = Vulnerability(
                vuln_id=arguments.get("vuln_id", "UNKNOWN"),
                package_name=dep.name,
                affected_versions="*",
                fixed_version=arguments.get("fixed_version"),
                cvss_score=arguments.get("cvss_score", 5.0),
            )
            assessment = compute_risk_score(
                dep, vuln, dependent_count=arguments.get("dependent_count", 0)
            )
            result = assessment.model_dump()

        elif name == "query_dependency_impact":
            pkg = arguments.get("package", "")
            manifest = arguments.get("manifest_content", "")
            graph = DependencyGraph()
            if manifest:
                parsed = parse_requirements_txt(manifest)
                graph.build_from_parsed(parsed)
            impact = graph.impact_analysis(pkg)
            result = impact

        elif name == "hybrid_search_advisories":
            query = arguments.get("query", "")
            top_k = arguments.get("top_k", 5)
            engine = HybridVulnSearch()
            from src.tools.vuln_lookup import VULN_DB_PATH

            engine.index_from_file(VULN_DB_PATH)
            matches = engine.search(query, top_k=top_k)
            result = [
                {
                    "vuln_id": m.doc_id,
                    "title": m.title,
                    "rrf_score": round(m.rrf_score, 4),
                    "bm25_rank": m.bm25_rank,
                    "dense_rank": m.dense_rank,
                    "metadata": m.metadata,
                }
                for m in matches
            ]

        elif name == "sanitize_manifest_input":
            content = arguments.get("content", "")
            sanitized, report = sanitize_input(content)
            result = {
                "sanitized_content": sanitized,
                "is_safe": report.get("is_safe", True),
                "injections_found": len(report.get("injections", [])),
                "secrets_redacted": len(report.get("secrets_redacted", [])),
                "details": report,
            }
        elif name in [
            "get_alerts", "get_service_status", "read_logs", "query_metrics",
            "get_recent_deploys", "propose_fix", "run_health_check",
            "restart_service", "update_config", "rollback_deploy",
        ]:
            from src.tools.opspilot_tools import DOMAIN_TOOLS
            result = DOMAIN_TOOLS[name].handler(**arguments)
        else:
            return {
                "isError": True,
                "content": [{"type": "text", "text": f"Unknown tool: {name}"}],
            }


        return {
            "content": [{"type": "text", "text": json.dumps(result, indent=2)}]
        }
    except Exception as exc:
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"Error executing tool {name}: {exc}"}],
        }


def process_message(message: dict[str, Any]) -> dict[str, Any] | None:
    """Handle a single MCP JSON-RPC 2.0 message."""
    msg_id = message.get("id")
    method = message.get("method")
    params = message.get("params", {})

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {"listChanged": False},
                },
                "serverInfo": {
                    "name": "chainguard-mcp",
                    "version": "0.1.0",
                },
            },
        }

    elif method == "notifications/initialized":
        return None

    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {"tools": TOOLS},
        }

    elif method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        call_result = handle_call_tool(tool_name, arguments)
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": call_result,
        }

    elif method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

    else:
        if msg_id is not None:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }
        return None


def run_stdio_server() -> None:
    """Run MCP server in standard input/output streaming loop."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            res = process_message(req)
            if res is not None:
                sys.stdout.write(json.dumps(res) + "\n")
                sys.stdout.flush()
        except json.JSONDecodeError:
            err = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error"},
            }
            sys.stdout.write(json.dumps(err) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    run_stdio_server()


# ─── Dynamic Tool Discovery Client ───────────────────────────────────────────


class MCPStdioClient:
    """Dynamic tool discovery client connecting to MCP server over stdio.

    Each agent connects over stdio at startup, calls tools/list to dynamically
    discover tools, and filters to its own allowed domain toolset.
    """

    def __init__(
        self,
        process_func: Callable[[dict[str, Any]], dict[str, Any] | None] = process_message,
    ) -> None:
        self.process_func = process_func

    def list_tools(self) -> list[dict[str, Any]]:
        """Call tools/list to dynamically discover all server tools."""
        req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        res = self.process_func(req)
        if res and "result" in res and "tools" in res["result"]:
            return res["result"]["tools"]
        return []

    def discover_tools_for_agent(self, agent_name: str) -> list[dict[str, Any]]:
        """Discover tools dynamically and filter to the agent's domain whitelist."""
        from src.tools.opspilot_tools import get_agent_tools

        allowed = set(get_agent_tools(agent_name))
        all_tools = self.list_tools()
        return [t for t in all_tools if t["name"] in allowed]

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Execute tool call over JSON-RPC."""
        req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
        res = self.process_func(req)
        if res and "result" in res:
            return res["result"]
        return {"isError": True, "error": "No response from MCP server"}

