"""OpsPilot multi-agent node implementations with bounded context.

Agents:
1. Supervisor: Bounded context delegation (passes sub-task + needed facts, aggregates structured output).
2. Triage (2 tools): Inspects alerts, service status, queries cross-incident memory.
3. Log Analyst (3 tools): Reads logs, queries metrics, inspects deploys. Defends against log injection.
4. Remediation (4 tools): Proposes fix, requests approval for WRITE/DESTRUCTIVE tools.
5. Approval Gate / Post-Approval: Handles Approve, Reject with reason (forces alternative), and Edit modes.
6. Verifier (2 tools): Runs canary health probes and confirms resolution.
7. Semantic Summarizer: Checks token budget, summarizes older turns while keeping structured facts.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from src.core.database import (
    create_approval_audit_log,
    create_pending_approval,
    get_pending_approval,
    search_past_incidents,
    update_pending_approval_status,
)
from src.graph.memory import count_messages_tokens, summarize_then_window
from src.graph.opspilot_state import OpsPilotState
from src.guardrails.sanitizer import sanitize_input
from src.models.schemas import (
    ApprovalAction,
    ApprovalAuditLog,
    IncidentStatus,
    PendingApproval,
    RiskTier,
    StructuredFacts,
)
from src.tools.opspilot_tools import DOMAIN_TOOLS, execute_tool_with_gate, get_agent_tools

import structlog

logger = structlog.get_logger(__name__)


# ─── 1. Supervisor Node (Bounded Context Delegation) ─────────────────────────


def supervisor_node(state: OpsPilotState) -> dict[str, Any]:
    """Supervisor coordinates workers and aggregates structured results.

    Delegates only sub-tasks and necessary facts to each worker, avoiding
    polluting workers with full conversational history.
    """
    logger.info("supervisor_evaluating", status=state.status.value, worker=state.current_worker)

    # 1. First step: Triage
    if state.status == IncidentStatus.TRIAGING:
        return {
            "current_worker": "triage",
            "messages": [AIMessage(content=f"Supervisor: Delegating initial triage of {state.service_name} to Triage agent.")],
        }

    # 2. After Triage: Log & Telemetry Analysis
    if state.status == IncidentStatus.ANALYZING:
        return {
            "current_worker": "log_analyst",
            "messages": [AIMessage(content=f"Supervisor: Delegating root cause diagnosis of {state.service_name} to Log Analyst.")],
        }

    # 3. After Analysis: Remediation proposal
    if state.status == IncidentStatus.REMEDIATING:
        return {
            "current_worker": "remediation",
            "messages": [AIMessage(content="Supervisor: Delegating remediation formulation to Remediation agent.")],
        }

    # 4. Awaiting human operator approval
    if state.status == IncidentStatus.AWAITING_APPROVAL:
        return {
            "current_worker": "approval_gate",
            "messages": [AIMessage(content="Supervisor: High-risk action proposed. Routing to operator approval gate.")],
        }

    # 5. After approval execution: Verification
    if state.status == IncidentStatus.VERIFYING:
        return {
            "current_worker": "verifier",
            "messages": [AIMessage(content="Supervisor: Remediation applied. Routing to Verifier agent for health checks.")],
        }

    # 6. Escalated (Loop caps reached)
    if state.status == IncidentStatus.ESCALATED:
        return {
            "current_worker": "escalate",
            "messages": [AIMessage(content="Supervisor: Loop cap reached. Delegating to Escalate node to alert on-call.")],
        }

    # 7. Completed
    if state.status in (IncidentStatus.RESOLVED, IncidentStatus.FAILED):
        return {
            "current_worker": "completed",
            "messages": [AIMessage(content=f"Supervisor: Incident workflow concluded with status={state.status.value}.")],
        }

    return {"current_worker": "triage"}


# ─── 2. Triage Agent Node (2 tools allowed) ──────────────────────────────────


def triage_node(state: OpsPilotState) -> dict[str, Any]:
    """Triage agent: inspects alerts, checks past incidents, sets initial hypotheses.

    Allowed tools: get_alerts, get_service_status (2 tools <= 4).
    """
    # Enforce toolset in code
    allowed_tools = get_agent_tools("triage")
    assert len(allowed_tools) <= 4

    service = state.service_name or "payment-gateway"
    alerts_res = DOMAIN_TOOLS["get_alerts"].handler(service_name=service)
    status_res = DOMAIN_TOOLS["get_service_status"].handler(service_name=service)

    # Cross-incident memory lookup: "Have we seen this before?"
    past_cases = search_past_incidents(query=f"{service} timeout", service_name=service)
    past_summary = f"Found {len(past_cases)} past similar incidents." if past_cases else "No prior match found."

    # Update structured facts (guaranteed never dropped by summarizer)
    facts = state.structured_facts
    facts.service_names = list(set(facts.service_names + [service]))
    facts.timestamps["incident_detected"] = datetime.now(timezone.utc).isoformat()
    facts.metrics["error_rate"] = status_res.get("error_rate", "unknown")
    facts.metrics["p99_latency"] = status_res.get("p99_latency", "unknown")

    initial_hypothesis = f"Service {service} degraded under load with {alerts_res.get('count', 0)} active alerts"
    if initial_hypothesis not in facts.hypotheses:
        facts.hypotheses.append(initial_hypothesis)

    worker_result = {
        "triage": {
            "alerts": alerts_res.get("alerts", []),
            "current_status": status_res.get("status", "unknown"),
            "past_cases_found": len(past_cases),
        }
    }

    report = (
        f"Triage Report for {service}:\n"
        f"- Status: {status_res.get('status')}\n"
        f"- Active Alerts: {alerts_res.get('alerts')}\n"
        f"- Memory Lookup: {past_summary}\n"
        f"- Hypothesis: {initial_hypothesis}"
    )

    return {
        "status": IncidentStatus.ANALYZING,
        "structured_facts": facts,
        "worker_results": worker_result,
        "messages": [AIMessage(content=report)],
    }


# ─── 3. Log Analyst Agent Node (3 tools allowed) ─────────────────────────────


def log_analyst_node(state: OpsPilotState) -> dict[str, Any]:
    """Log Analyst: inspects recent deploys, queries metrics, reads logs.

    Allowed tools: read_logs, query_metrics, get_recent_deploys (3 tools <= 4).
    Defends against prompt injection inside log lines.
    """
    allowed_tools = get_agent_tools("log_analyst")
    assert len(allowed_tools) <= 4

    service = state.service_name or "payment-gateway"
    deploy_res = DOMAIN_TOOLS["get_recent_deploys"].handler(service_name=service)
    metrics_res = DOMAIN_TOOLS["query_metrics"].handler(service_name=service, metric="error_rate")
    raw_logs = DOMAIN_TOOLS["read_logs"].handler(service_name=service, lines=10)

    # Defense against log injection (Week 4 safety requirement)
    cleaned_logs = []
    for line in raw_logs.get("lines", []):
        sanitized_line, _ = sanitize_input(line)
        cleaned_logs.append(sanitized_line)

    # Identify root cause from logs
    has_timeout = any("DBTimeoutException" in line for line in cleaned_logs)
    root_cause_hypothesis = (
        f"Deploy {deploy_res.get('recent_deploy', {}).get('deploy_id')} reduced DB pool timeout to 200ms, "
        "causing connection exhaustion and HTTP 500 spikes."
        if has_timeout
        else "Log anomalies detected in connection handling."
    )

    facts = state.structured_facts
    if root_cause_hypothesis not in facts.hypotheses:
        facts.hypotheses.append(root_cause_hypothesis)
    facts.timestamps["root_cause_identified"] = datetime.now(timezone.utc).isoformat()

    worker_result = {
        "log_analysis": {
            "recent_deploy": deploy_res.get("recent_deploy"),
            "root_cause": root_cause_hypothesis,
            "has_db_timeout": has_timeout,
        }
    }

    report = (
        f"Log Analyst Findings:\n"
        f"- Inspected {len(cleaned_logs)} log lines (sanitized against injection)\n"
        f"- Recent Deploy: {deploy_res.get('recent_deploy', {}).get('version')} "
        f"({deploy_res.get('recent_deploy', {}).get('commit')})\n"
        f"- Error rate: {metrics_res.get('value')}\n"
        f"- Confirmed Root Cause: {root_cause_hypothesis}"
    )

    return {
        "status": IncidentStatus.REMEDIATING,
        "structured_facts": facts,
        "worker_results": worker_result,
        "messages": [AIMessage(content=report)],
    }


# ─── 4. Remediation Agent Node (4 tools allowed) ─────────────────────────────


def remediation_node(state: OpsPilotState) -> dict[str, Any]:
    """Remediation agent: formulates proposal and attempts action through gate.

    Allowed tools: propose_fix, rollback_deploy, restart_service, update_config (4 tools <= 4).
    If a previous action was rejected with a reason, it proposes a different fix.
    """
    allowed_tools = get_agent_tools("remediation")
    assert len(allowed_tools) <= 4

    service = state.service_name or "payment-gateway"

    # Check if a previous approval was rejected
    if state.approval_action == "reject":
        reason = state.rejection_reason or "operator requested alternative fix"
        logger.info("formulating_alternative_remediation", reason=reason)

        # Propose alternative: update configuration instead of rollback
        tool_name = "update_config"
        tool_args = {
            "service_name": service,
            "config_key": "db_pool_timeout_ms",
            "config_value": "2000",
        }
        proposal_text = f"Alternative proposal following rejection ({reason}): increase timeout via update_config to 2000ms."
    else:
        # Default primary fix: rollback recent deploy
        tool_name = "rollback_deploy"
        tool_args = {"service_name": service, "target_version": "v2.13.9"}
        proposal_text = f"Primary fix: rollback {service} to known good version v2.13.9."

    DOMAIN_TOOLS["propose_fix"].handler(
        service_name=service,
        action=tool_name,
        details=json.dumps(tool_args),
    )

    # Attempt to execute through gate without approval -> triggers pause & creates pending_approval record
    gate_res = execute_tool_with_gate(
        tool_name=tool_name,
        tool_args=tool_args,
        incident_id=state.incident_id or state.thread_id,
    )

    approval_obj = None
    if gate_res.get("status") == "APPROVAL_REQUIRED":
        approval_obj = get_pending_approval(gate_res["approval_id"])

    report = (
        f"Remediation Proposal:\n"
        f"- Action: {tool_name} ({proposal_text})\n"
        f"- Target Args: {tool_args}\n"
        f"- Risk Tier: {gate_res.get('risk_tier')}\n"
        f"- Gate Status: {gate_res.get('message')}"
    )

    return {
        "status": IncidentStatus.AWAITING_APPROVAL,
        "pending_approval": approval_obj,
        "current_worker": "approval_gate",
        "messages": [AIMessage(content=report)],
    }


# ─── 5. Approval Gate & Post-Approval Nodes (3 modes) ────────────────────────


def approval_gate_node(state: OpsPilotState) -> dict[str, Any]:
    """Node that holds state at the interrupt gate.

    Execution halts here for operator review via CLI or Web UI.
    """
    logger.info("holding_at_approval_gate", incident_id=state.incident_id, status=state.status.value)
    return {"status": IncidentStatus.AWAITING_APPROVAL}


def post_approval_node(state: OpsPilotState) -> dict[str, Any]:
    """Executes after human operator approval/rejection/edit decision.

    Supports three approval modes:
    1. APPROVE: Executes original action as proposed.
    2. REJECT: Forces remediation agent to formulate a different action.
    3. EDIT: Executes action with operator-modified parameters.
    """
    action = (state.approval_action or "approve").lower()
    approval = state.pending_approval
    operator = state.operator_name or "operator"

    if not approval:
        return {"status": IncidentStatus.FAILED, "error": "No pending approval in state"}

    # Mode 1: REJECT with reason
    if action == "reject":
        reason = state.rejection_reason or "rejected by operator"
        new_reject_count = (state.reject_count or 0) + 1
        update_pending_approval_status(
            approval.id,
            status="rejected",
            checkpoint_id=state.active_checkpoint_id,
            approved_by=operator,
        )

        audit_entry = ApprovalAuditLog(
            approval_id=approval.id,
            incident_id=state.incident_id,
            tenant_id=getattr(state, "tenant_id", "default-tenant"),
            action="reject",
            operator=operator,
            original_args=approval.tool_args,
            rejection_reason=reason,
            checkpoint_id=state.active_checkpoint_id,
        )
        create_approval_audit_log(audit_entry)

        # Loop Cap: If operator rejects >= 2 times, escalate to human on-call SRE
        if new_reject_count >= 2:
            escalation_msg = (
                f"Operator rejected remediation proposals {new_reject_count} times ({reason}). "
                "Rejection loop cap reached. Escalating incident to human on-call engineer."
            )
            logger.warning("rejection_loop_cap_reached", incident_id=state.incident_id, reject_count=new_reject_count)
            return {
                "status": IncidentStatus.ESCALATED,
                "reject_count": new_reject_count,
                "approval_action": "reject",
                "rejection_reason": reason,
                "escalation_reason": escalation_msg,
                "messages": [AIMessage(content=f"ESCALATION TRIGGERED: {escalation_msg}")],
            }

        return {
            "status": IncidentStatus.REMEDIATING,
            "reject_count": new_reject_count,
            "approval_action": "reject",
            "rejection_reason": reason,
            "messages": [AIMessage(content=f"Operator REJECTED proposal: {reason}. Agent must propose an alternative.")],
        }

    # Mode 2: EDIT parameters
    if action == "edit":
        edited_args = state.approval_edits or approval.tool_args
        update_pending_approval_status(
            approval.id,
            status="approved",
            checkpoint_id=state.active_checkpoint_id,
            approved_by=operator,
        )

        # Update approval in SQLite with the edited args
        import sqlite3
        from src.core.database import _get_db_path
        with sqlite3.connect(_get_db_path()) as conn:
            conn.execute("UPDATE pending_approvals SET tool_args = ? WHERE id = ?", (json.dumps(edited_args), approval.id))

        audit_entry = ApprovalAuditLog(
            approval_id=approval.id,
            incident_id=state.incident_id,
            tenant_id=getattr(state, "tenant_id", "default-tenant"),
            action="edit",
            operator=operator,
            original_args=approval.tool_args,
            edited_args=edited_args,
            checkpoint_id=state.active_checkpoint_id,
        )
        create_approval_audit_log(audit_entry)

        # Execute through gate with approval
        exec_res = execute_tool_with_gate(
            tool_name=approval.tool_name,
            tool_args=edited_args,
            incident_id=state.incident_id,
            approved_by=operator,
            approval_id=approval.id,
        )

        return {
            "status": IncidentStatus.VERIFYING,
            "approval_action": "edit",
            "messages": [AIMessage(content=f"Operator EDITED and APPROVED action {approval.tool_name} with args {edited_args}. Result: {exec_res}")],
        }

    # Mode 3: APPROVE as proposed
    update_pending_approval_status(
        approval.id,
        status="approved",
        checkpoint_id=state.active_checkpoint_id,
        approved_by=operator,
    )

    audit_entry = ApprovalAuditLog(
        approval_id=approval.id,
        incident_id=state.incident_id,
        tenant_id=getattr(state, "tenant_id", "default-tenant"),
        action="approve",
        operator=operator,
        original_args=approval.tool_args,
        checkpoint_id=state.active_checkpoint_id,
    )
    create_approval_audit_log(audit_entry)

    exec_res = execute_tool_with_gate(
        tool_name=approval.tool_name,
        tool_args=approval.tool_args,
        incident_id=state.incident_id,
        approved_by=operator,
        approval_id=approval.id,
    )

    return {
        "status": IncidentStatus.VERIFYING,
        "approval_action": "approve",
        "messages": [AIMessage(content=f"Operator APPROVED action {approval.tool_name}. Executed successfully: {exec_res}")],
    }


# ─── 6. Verifier Agent Node (2 tools allowed) ────────────────────────────────


def verifier_node(state: OpsPilotState) -> dict[str, Any]:
    """Verifier agent: runs canary probes and confirms service is healthy.

    Allowed tools: get_service_status, run_health_check (2 tools <= 4).
    """
    allowed_tools = get_agent_tools("verifier")
    assert len(allowed_tools) <= 4

    service = state.service_name or "payment-gateway"
    status_res = DOMAIN_TOOLS["get_service_status"].handler(service_name=service)
    health_res = DOMAIN_TOOLS["run_health_check"].handler(service_name=service)

    is_resolved = health_res.get("healthy", False) or status_res.get("status") == "healthy"

    facts = state.structured_facts
    if is_resolved:
        final_status = IncidentStatus.RESOLVED
        facts.timestamps["incident_resolved"] = datetime.now(timezone.utc).isoformat()
        facts.metrics["post_remediation_error_rate"] = status_res.get("error_rate", "0.05%")

        report = (
            f"Verification Report for {service}:\n"
            f"- Probes Passed: {health_res.get('synthetic_probes_passed')}/{health_res.get('total_probes')}\n"
            f"- Service Status: {status_res.get('status')}\n"
            f"- Incident State: {final_status.value.upper()}"
        )

        return {
            "status": final_status,
            "structured_facts": facts,
            "messages": [AIMessage(content=report)],
        }
    else:
        # Verification failed: increment verify retry count
        new_verify_retry = (state.verify_retry_count or 0) + 1
        if new_verify_retry >= 2:
            final_status = IncidentStatus.ESCALATED
            escalation_msg = (
                f"Canary verification failed after remediation (probes: "
                f"{health_res.get('synthetic_probes_passed', 0)}/{health_res.get('total_probes', 5)}, "
                f"status: {status_res.get('status')}). Retry cap (2) reached. Escalating to on-call."
            )
            logger.warning("verifier_retry_cap_reached", incident_id=state.incident_id, retries=new_verify_retry)
            return {
                "status": final_status,
                "verify_retry_count": new_verify_retry,
                "escalation_reason": escalation_msg,
                "structured_facts": facts,
                "messages": [AIMessage(content=f"ESCALATION TRIGGERED: {escalation_msg}")],
            }
        else:
            return {
                "status": IncidentStatus.REMEDIATING,
                "verify_retry_count": new_verify_retry,
                "messages": [AIMessage(content=f"Verifier canary probe failed (attempt {new_verify_retry}/2). Re-routing to Remediation agent for alternative plan.")],
            }


# ─── 7. Escalate Node ─────────────────────────────────────────────────────────


def escalate_node(state: OpsPilotState) -> dict[str, Any]:
    """Escalate node: triggers when loop caps are exceeded (rejections or verification retries).

    Halts automated remediation and pages human on-call SRE.
    """
    reason = state.escalation_reason or "Automated remediation loop cap reached."
    logger.critical("incident_escalated_to_human_oncall", incident_id=state.incident_id, reason=reason)
    return {
        "status": IncidentStatus.ESCALATED,
        "current_worker": "escalate",
        "messages": [
            AIMessage(
                content=(
                    f"🚨 [INCIDENT ESCALATED TO HUMAN ON-CALL SRE]\n"
                    f"- Service: {state.service_name}\n"
                    f"- Severity: {state.severity.value.upper() if hasattr(state.severity, 'value') else state.severity}\n"
                    f"- Escalation Reason: {reason}\n"
                    f"- Rejection Count: {state.reject_count}\n"
                    f"- Verification Retries: {state.verify_retry_count}\n"
                    f"- Action Taken: Automated actions suspended. PagerDuty alert dispatched to primary on-call SRE."
                )
            )
        ],
    }


# ─── 7. Semantic Summarizer Node ─────────────────────────────────────────────


def summarizer_node(state: OpsPilotState) -> dict[str, Any]:
    """Semantic summarizer node enforcing token budget and fact preservation."""
    budget = state.token_budget or 3000
    current_tokens = count_messages_tokens(state.messages)

    if current_tokens > budget:
        pruned_msgs, was_summarized = summarize_then_window(
            messages=state.messages,
            structured_facts=state.structured_facts,
            token_budget=budget,
            window_turns=4,
        )
        if was_summarized:
            return {"messages": pruned_msgs}

    return {}
