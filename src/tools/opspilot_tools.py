"""OpsPilot domain-specific tools with risk tiers and gate enforcement.

Tools are labeled READ, WRITE, or DESTRUCTIVE:
- READ tools auto-run without operator intervention.
- WRITE and DESTRUCTIVE tools require operator approval stored in SQLite.
- Tool-count rule: No agent receives more than 4 tools (enforced in code).
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any, Callable, Optional

from src.core.database import create_pending_approval, get_pending_approval, update_pending_approval_status
from src.models.schemas import PendingApproval, RiskTier

import structlog

logger = structlog.get_logger(__name__)


# ─── Mock Cluster / Telemetry State ──────────────────────────────────────────

_INITIAL_MOCK_SERVICES = {
    "payment-gateway": {
        "status": "degraded",
        "version": "v2.14.0",
        "previous_version": "v2.13.9",
        "error_rate": "18.4%",
        "p99_latency": "1420ms",
        "cpu_usage": "92%",
        "active_alerts": ["HighErrorRate: 5xx > 15%", "PaymentGatewayLatencyP99Exceeded"],
        "recent_deploy": {
            "deploy_id": "dep-8921",
            "version": "v2.14.0",
            "deployed_at": "12 minutes ago",
            "deployed_by": "ci-runner",
            "commit": "a8f3b01: update database connection pool timeout to 200ms",
        },
        "logs": [
            "2026-10-17 14:02:11 [INFO] Service starting v2.14.0",
            "2026-10-17 14:02:14 [INFO] Connecting to postgres-primary pool size=50",
            "2026-10-17 14:03:02 [ERROR] DBTimeoutException: timeout after 200ms acquiring connection",
            "2026-10-17 14:03:03 [ERROR] HTTP 500 POST /v1/charges pool exhausted",
            "2026-10-17 14:03:15 [WARN] Circuit breaker tripped for payments-db",
        ],
    },
    "auth-service": {
        "status": "healthy",
        "version": "v1.8.2",
        "previous_version": "v1.8.1",
        "error_rate": "0.02%",
        "p99_latency": "42ms",
        "cpu_usage": "35%",
        "active_alerts": [],
        "recent_deploy": {"deploy_id": "dep-8890", "version": "v1.8.2", "deployed_at": "2 hours ago"},
        "logs": ["2026-10-17 12:00:00 [INFO] Auth service healthy"],
    },
    "notification-worker": {
        "status": "healthy",
        "version": "v3.0.1",
        "previous_version": "v3.0.0",
        "error_rate": "0.1%",
        "p99_latency": "110ms",
        "cpu_usage": "40%",
        "active_alerts": [],
        "recent_deploy": {"deploy_id": "dep-8710", "version": "v3.0.1", "deployed_at": "1 day ago"},
        "logs": ["2026-10-17 08:00:00 [INFO] Worker polling queue"],
    },
}

_MOCK_SERVICES = copy.deepcopy(_INITIAL_MOCK_SERVICES)


def reset_mock_services() -> None:
    """Reset mock services telemetry and logs back to initial degraded state."""
    global _MOCK_SERVICES
    _MOCK_SERVICES = copy.deepcopy(_INITIAL_MOCK_SERVICES)



# ─── Tool Definitions & Implementation ────────────────────────────────────────


@dataclass(frozen=True)
class ToolSpec:
    """Definition of an OpsPilot tool with risk tier and handler."""

    name: str
    risk_tier: RiskTier
    description: str
    handler: Callable[..., dict[str, Any]]


# 1. READ tools
def tool_get_alerts(service_name: str = "") -> dict[str, Any]:
    """Retrieve active alerts for a service or entire cluster."""
    if service_name and service_name in _MOCK_SERVICES:
        return {
            "service": service_name,
            "alerts": _MOCK_SERVICES[service_name]["active_alerts"],
            "count": len(_MOCK_SERVICES[service_name]["active_alerts"]),
        }
    all_alerts = {}
    for s_name, data in _MOCK_SERVICES.items():
        if data["active_alerts"]:
            all_alerts[s_name] = data["active_alerts"]
    return {"alerts": all_alerts, "count": sum(len(a) for a in all_alerts.values())}


def tool_get_service_status(service_name: str) -> dict[str, Any]:
    """Inspect current service health status and active version."""
    svc = _MOCK_SERVICES.get(service_name)
    if not svc:
        return {"error": f"Unknown service: {service_name}", "status": "unknown"}
    return {
        "service": service_name,
        "status": svc["status"],
        "version": svc["version"],
        "error_rate": svc["error_rate"],
        "p99_latency": svc["p99_latency"],
    }


def tool_read_logs(service_name: str, lines: int = 50) -> dict[str, Any]:
    """Read recent stdout/stderr log lines for a service."""
    svc = _MOCK_SERVICES.get(service_name)
    if not svc:
        return {"error": f"Unknown service: {service_name}", "logs": []}
    return {
        "service": service_name,
        "lines": svc["logs"][-lines:],
        "count": len(svc["logs"][-lines:]),
    }


def tool_query_metrics(service_name: str, metric: str = "error_rate") -> dict[str, Any]:
    """Query telemetry metrics (error_rate, p99_latency, cpu_usage)."""
    svc = _MOCK_SERVICES.get(service_name)
    if not svc:
        return {"error": f"Unknown service: {service_name}"}
    val = svc.get(metric, "N/A")
    return {
        "service": service_name,
        "metric": metric,
        "value": val,
        "timestamp": "2026-10-17T14:05:00Z",
    }


def tool_get_recent_deploys(service_name: str) -> dict[str, Any]:
    """Inspect recent deployment history and changes."""
    svc = _MOCK_SERVICES.get(service_name)
    if not svc:
        return {"error": f"Unknown service: {service_name}"}
    return {
        "service": service_name,
        "current_version": svc["version"],
        "recent_deploy": svc["recent_deploy"],
    }


def tool_propose_fix(service_name: str, action: str, details: str = "") -> dict[str, Any]:
    """Formulate and register a candidate remediation proposal (read-only planning)."""
    return {
        "service": service_name,
        "proposed_action": action,
        "details": details,
        "status": "ready_for_review",
    }


def tool_run_health_check(service_name: str) -> dict[str, Any]:
    """Execute end-to-end synthetic health and canary probes."""
    svc = _MOCK_SERVICES.get(service_name)
    if not svc:
        return {"status": "unhealthy", "error": "Service not found"}
    is_healthy = svc["status"] == "healthy"
    return {
        "service": service_name,
        "healthy": is_healthy,
        "synthetic_probes_passed": 10 if is_healthy else 2,
        "total_probes": 10,
    }


# 2. WRITE tools
def tool_restart_service(service_name: str) -> dict[str, Any]:
    """Restart service pods/containers gracefully (WRITE action)."""
    svc = _MOCK_SERVICES.get(service_name)
    if svc:
        svc["logs"].append("2026-10-17 14:10:00 [INFO] Graceful restart triggered by OpsPilot")
    return {
        "service": service_name,
        "action": "restart_service",
        "result": "success",
        "restarted_instances": 3,
    }


def tool_update_config(service_name: str, config_key: str, config_value: str) -> dict[str, Any]:
    """Update live configuration parameters (WRITE action)."""
    svc = _MOCK_SERVICES.get(service_name)
    if svc:
        svc["logs"].append(f"2026-10-17 14:10:05 [INFO] Config updated: {config_key}={config_value}")
    return {
        "service": service_name,
        "action": "update_config",
        "config_key": config_key,
        "config_value": config_value,
        "result": "success",
    }


# 3. DESTRUCTIVE tools
def tool_rollback_deploy(service_name: str, target_version: str) -> dict[str, Any]:
    """Roll back service to a previous deployment version (DESTRUCTIVE action)."""
    svc = _MOCK_SERVICES.get(service_name)
    if svc:
        prev = svc["version"]
        svc["version"] = target_version
        svc["status"] = "healthy"
        svc["error_rate"] = "0.05%"
        svc["p99_latency"] = "48ms"
        svc["active_alerts"] = []
        svc["logs"].append(f"2026-10-17 14:11:00 [INFO] Rollback completed from {prev} to {target_version}")
    return {
        "service": service_name,
        "action": "rollback_deploy",
        "from_version": svc.get("previous_version", "v2.14.0") if svc else "unknown",
        "target_version": target_version,
        "result": "rollback_completed",
        "current_status": "healthy",
    }


# ─── Registry of All Tools & Risk Tiers ───────────────────────────────────────

DOMAIN_TOOLS: dict[str, ToolSpec] = {
    # READ
    "get_alerts": ToolSpec("get_alerts", RiskTier.READ, "Retrieve active alerts", tool_get_alerts),
    "get_service_status": ToolSpec("get_service_status", RiskTier.READ, "Inspect service health", tool_get_service_status),
    "read_logs": ToolSpec("read_logs", RiskTier.READ, "Read recent logs", tool_read_logs),
    "query_metrics": ToolSpec("query_metrics", RiskTier.READ, "Query service metrics", tool_query_metrics),
    "get_recent_deploys": ToolSpec("get_recent_deploys", RiskTier.READ, "Inspect recent deploys", tool_get_recent_deploys),
    "propose_fix": ToolSpec("propose_fix", RiskTier.READ, "Propose remediation action", tool_propose_fix),
    "run_health_check": ToolSpec("run_health_check", RiskTier.READ, "Run synthetic health probes", tool_run_health_check),
    # WRITE
    "restart_service": ToolSpec("restart_service", RiskTier.WRITE, "Gracefully restart service pods", tool_restart_service),
    "update_config": ToolSpec("update_config", RiskTier.WRITE, "Update service configuration", tool_update_config),
    # DESTRUCTIVE
    "rollback_deploy": ToolSpec("rollback_deploy", RiskTier.DESTRUCTIVE, "Roll back service version", tool_rollback_deploy),
}


# ─── Domain-Specific Toolsets ─────────────────────────────────────────────────

AGENT_ALLOWED_TOOLS: dict[str, list[str]] = {
    "triage": ["get_alerts", "get_service_status"],
    "log_analyst": ["read_logs", "query_metrics", "get_recent_deploys"],
    "remediation": ["propose_fix", "rollback_deploy", "restart_service", "update_config"],
    "verifier": ["get_service_status", "run_health_check"],
}

# Rule: No agent receives more than 4 tools
MAX_TOOLS_PER_AGENT = 4


def get_agent_tools(agent_name: str) -> list[str]:
    """Return allowed tool names for a specific agent role, enforced in code."""
    allowed = AGENT_ALLOWED_TOOLS.get(agent_name, [])
    if len(allowed) > MAX_TOOLS_PER_AGENT:
        raise ValueError(f"Agent {agent_name} exceeds max tool count of {MAX_TOOLS_PER_AGENT} (has {len(allowed)})")
    return allowed


def assert_tool_count_rule() -> None:
    """Validate that every agent respects the max 4 tools constraint."""
    for agent, tools in AGENT_ALLOWED_TOOLS.items():
        assert len(tools) <= MAX_TOOLS_PER_AGENT, (
            f"Agent '{agent}' has {len(tools)} tools, which exceeds the max allowed {MAX_TOOLS_PER_AGENT}!"
        )


# ─── Risk-Tiered Approval Gate Enforcement ───────────────────────────────────


def execute_tool_with_gate(
    tool_name: str,
    tool_args: dict[str, Any],
    incident_id: str,
    approved_by: Optional[str] = None,
    approval_id: Optional[str] = None,
) -> dict[str, Any]:
    """Execute a tool with strict risk-tier gate enforcement.

    Invariants:
    1. READ tools execute automatically without pause.
    2. WRITE and DESTRUCTIVE tools require an existing approved approval record in SQLite.
    3. 'Skip approval' prompt injections are rejected: tool-level code gating ignores prompt claims.
    """
    if tool_name not in DOMAIN_TOOLS:
        return {"error": f"Tool '{tool_name}' not recognized", "success": False}

    spec = DOMAIN_TOOLS[tool_name]

    # Tier 1: READ tools run automatically
    if spec.risk_tier == RiskTier.READ:
        res = spec.handler(**tool_args)
        return {"success": True, "result": res, "risk_tier": spec.risk_tier.value, "executed": True}

    # Tier 2 & 3: WRITE and DESTRUCTIVE tools require persisted approval
    if not approved_by or not approval_id:
        # Check if an approval already exists in database
        approval = PendingApproval(
            incident_id=incident_id,
            tool_name=tool_name,
            tool_args=tool_args,
            risk_tier=spec.risk_tier,
            status="pending",
            proposed_by="remediation_agent",
        )
        create_pending_approval(approval)
        logger.info(
            "approval_gate_paused",
            incident_id=incident_id,
            tool=tool_name,
            risk_tier=spec.risk_tier.value,
            approval_id=approval.id,
        )
        return {
            "success": False,
            "status": "APPROVAL_REQUIRED",
            "approval_id": approval.id,
            "tool_name": tool_name,
            "risk_tier": spec.risk_tier.value,
            "message": f"Action '{tool_name}' requires human approval ({spec.risk_tier.value} tier). Execution paused.",
            "executed": False,
        }

    # Verify authorization record in database
    existing_approval = get_pending_approval(approval_id)
    if not existing_approval or existing_approval.status != "approved":
        logger.warning(
            "unauthorized_tool_attempt",
            tool=tool_name,
            approval_id=approval_id,
            status=existing_approval.status if existing_approval else "none",
        )
        return {
            "success": False,
            "error": f"Execution of {tool_name} rejected: No valid approved record for approval_id={approval_id}",
            "executed": False,
        }

    # If args were edited during approval, use the edited args
    exec_args = tool_args
    if hasattr(existing_approval, "tool_args") and existing_approval.tool_args:
        exec_args = existing_approval.tool_args

    # Authorized! Run the tool
    res = spec.handler(**exec_args)
    return {
        "success": True,
        "result": res,
        "risk_tier": spec.risk_tier.value,
        "executed": True,
        "approved_by": approved_by,
        "approval_id": approval_id,
    }
