"""Raw SDK baseline agent: plain Python against the Ollama API (D16).

This is a minimal agent written WITHOUT any framework — just direct
HTTP calls to the Ollama API with native tool schemas.

Compare this with the LangGraph version to see the benefit of the
framework (state management, persistence, conditional routing, etc).

Usage:
    python -m src.agents.baseline_agent data/sample_projects/vulnerable_requirements.txt
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any

import httpx

from src.tools.parsers import parse_requirements_txt
from src.tools.vuln_lookup import lookup_vulnerabilities
from src.tools.risk_scorer import compute_risk_score

# ─── Native Tool Schemas for Ollama API ──────────────────────────────────────

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "parse_dependencies",
            "description": "Parse a requirements.txt file and extract all dependency names and versions.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_content": {
                        "type": "string",
                        "description": "Raw content of the requirements.txt file",
                    }
                },
                "required": ["file_content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_vulnerabilities",
            "description": "Look up known CVEs for a Python package and version.",
            "parameters": {
                "type": "object",
                "properties": {
                    "package_name": {
                        "type": "string",
                        "description": "Name of the Python package",
                    },
                    "version": {
                        "type": "string",
                        "description": "Current version of the package",
                    },
                },
                "required": ["package_name"],
            },
        },
    },
]


# ─── Tool Execution ──────────────────────────────────────────────────────────


def execute_tool(name: str, args: dict[str, Any]) -> str:
    """Execute a tool by name and return the result as a string."""
    if name == "parse_dependencies":
        deps = parse_requirements_txt(args["file_content"])
        return json.dumps([d.model_dump() for d in deps], indent=2)

    elif name == "check_vulnerabilities":
        vulns = lookup_vulnerabilities(
            args["package_name"], args.get("version", "*")
        )
        return json.dumps([v.model_dump() for v in vulns], indent=2)

    else:
        return json.dumps({"error": f"Unknown tool: {name}"})


# ─── ReAct Loop ──────────────────────────────────────────────────────────────


def run_baseline_agent(
    file_content: str,
    ollama_base_url: str = "http://localhost:11434",
    model: str = "llama3.1:8b",
    max_iterations: int = 6,
) -> dict[str, Any]:
    """Run the baseline agent using the raw Ollama API.

    Implements a simple ReAct loop:
    1. Send messages + tools to Ollama
    2. If the model calls a tool, execute it and add the result
    3. Repeat until the model stops calling tools or max_iterations hit

    This is intentionally simple — no state management, no persistence,
    no conditional routing. Compare with the LangGraph version.
    """
    messages: list[dict[str, str]] = [
        {
            "role": "system",
            "content": (
                "You are a dependency vulnerability scanner. "
                "First, parse the requirements file to extract dependencies. "
                "Then, check each dependency for known vulnerabilities. "
                "Finally, provide a summary of findings with recommended actions."
            ),
        },
        {
            "role": "user",
            "content": f"Scan this requirements file for vulnerabilities:\n\n{file_content}",
        },
    ]

    results: dict[str, Any] = {
        "iterations": 0,
        "tool_calls": [],
        "final_response": "",
        "total_tokens": 0,
        "total_latency_ms": 0,
    }

    for iteration in range(max_iterations):
        results["iterations"] = iteration + 1

        start = time.time()

        # Call Ollama API directly
        try:
            response = httpx.post(
                f"{ollama_base_url}/api/chat",
                json={
                    "model": model,
                    "messages": messages,
                    "tools": TOOLS,
                    "stream": False,
                },
                timeout=120.0,
            )
            response.raise_for_status()
            data = response.json()
        except httpx.ConnectError:
            print("[Baseline Agent] Ollama not available. Running in offline mode.")
            # Offline fallback: run tools directly
            deps = parse_requirements_txt(file_content)
            all_vulns = []
            for dep in deps:
                vulns = lookup_vulnerabilities(dep.name, dep.current_version)
                for v in vulns:
                    assessment = compute_risk_score(dep, v)
                    all_vulns.append({
                        "package": dep.name,
                        "version": dep.current_version,
                        "vuln_id": v.vuln_id,
                        "severity": v.severity.value,
                        "cvss": v.cvss_score,
                        "fix": v.fixed_version,
                    })

            results["final_response"] = (
                f"Scanned {len(deps)} dependencies. "
                f"Found {len(all_vulns)} vulnerabilities.\n"
                + json.dumps(all_vulns, indent=2)
            )
            return results
        except Exception as e:
            results["final_response"] = f"Error: {str(e)}"
            return results

        latency = (time.time() - start) * 1000
        results["total_latency_ms"] += latency

        # Track tokens
        if "eval_count" in data:
            results["total_tokens"] += data.get("eval_count", 0)

        msg = data.get("message", {})
        messages.append(msg)

        # Check for tool calls
        tool_calls = msg.get("tool_calls", [])
        if not tool_calls:
            # No more tool calls — we're done
            results["final_response"] = msg.get("content", "")
            break

        # Execute each tool call
        for tc in tool_calls:
            func = tc.get("function", {})
            tool_name = func.get("name", "")
            tool_args = func.get("arguments", {})

            print(f"  [Tool Call] {tool_name}({json.dumps(tool_args)[:100]}...)")

            tool_result = execute_tool(tool_name, tool_args)
            results["tool_calls"].append({
                "name": tool_name,
                "args": tool_args,
                "result_length": len(tool_result),
            })

            # Add tool result back to messages
            messages.append({
                "role": "tool",
                "content": tool_result,
            })

    return results


# ─── CLI Entry Point ─────────────────────────────────────────────────────────


def main() -> None:
    """Run the baseline agent from command line."""
    if len(sys.argv) < 2:
        print("Usage: python -m src.agents.baseline_agent <requirements_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    with open(file_path) as f:
        content = f.read()

    print(f"[Baseline Agent] Scanning: {file_path}")
    print(f"[Baseline Agent] Max iterations: 6")
    print()

    results = run_baseline_agent(content)

    print(f"\n{'='*60}")
    print(f"[Results]")
    print(f"  Iterations: {results['iterations']}")
    print(f"  Tool calls: {len(results['tool_calls'])}")
    print(f"  Total tokens: {results['total_tokens']}")
    print(f"  Total latency: {results['total_latency_ms']:.0f}ms")
    print(f"\n{results['final_response']}")


if __name__ == "__main__":
    main()
