"""LangGraph node implementations for the ChainGuard scan graph.

Each node is a pure function: takes ScanState, returns a dict update.
Nodes never mutate state directly (D17).
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from src.core.config import get_settings
from src.core.llm import get_model
from src.graph.state import ScanState
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
from src.prompts.templates import (
    INVESTIGATOR_SYSTEM,
    PARSER_SYSTEM,
    PLANNER_SYSTEM,
    RISK_ASSESSOR_SYSTEM,
    SUPERVISOR_SYSTEM,
    VERIFIER_SYSTEM,
    format_prompt,
)
from src.tools.parsers import parse_file
from src.tools.risk_scorer import compute_risk_score
from src.tools.vuln_lookup import lookup_vulnerabilities

import structlog

logger = structlog.get_logger(__name__)


# ─── Supervisor Node ─────────────────────────────────────────────────────────


def supervisor_node(state: ScanState) -> dict[str, Any]:
    """Supervisor routes to the next worker based on current state (D19).

    Routing logic:
    - No dependencies parsed → parser
    - Dependencies but no findings checked → risk_assessor
    - Findings but no plan → planner
    - Plan but not verified → verifier
    - Plan verified → approval gate
    - Critical findings → deep investigation path
    """
    start_time = time.time()
    settings = get_settings()

    trace_entry = TraceEntry(
        node="supervisor",
        action="routing",
        detail="",
        timestamp=datetime.utcnow(),
    )

    # Determine next worker based on state
    if not state.dependencies:
        next_worker = "parser"
        trace_entry.detail = "No dependencies found, routing to parser"
    elif not state.findings and state.status in (ScanStatus.PENDING, ScanStatus.PARSING):
        next_worker = "risk_assessor"
        trace_entry.detail = f"Have {len(state.dependencies)} deps, routing to risk_assessor"
    elif state.findings and state.upgrade_plan is None:
        # Check for critical findings
        critical = [f for f in state.findings if f.vulnerability.severity == Severity.CRITICAL]
        if critical and state.status != ScanStatus.ANALYZING:
            next_worker = "investigator"
            trace_entry.detail = f"Found {len(critical)} critical findings, deep investigation"
        else:
            next_worker = "planner"
            trace_entry.detail = f"Have {len(state.findings)} findings, routing to planner"
    elif state.upgrade_plan and state.status == ScanStatus.PLANNING:
        next_worker = "verifier"
        trace_entry.detail = "Plan created, routing to verifier"
    elif state.status == ScanStatus.VERIFYING and state.next_action == "needs_revision":
        if state.retry_count < settings.agent.max_retries:
            next_worker = "planner"
            trace_entry.detail = f"Revision needed, retry {state.retry_count + 1}/{settings.agent.max_retries}"
        else:
            next_worker = "approval_gate"
            trace_entry.detail = "Max retries reached, proceeding to approval"
    else:
        next_worker = "approval_gate"
        trace_entry.detail = "Routing to approval gate"

    latency = (time.time() - start_time) * 1000
    trace_entry.latency_ms = latency

    logger.info("supervisor_routing", next_worker=next_worker, detail=trace_entry.detail)

    return {
        "current_worker": next_worker,
        "next_action": next_worker,
        "trace": [trace_entry],
        "messages": [AIMessage(content=f"[Supervisor] Routing to: {next_worker}. {trace_entry.detail}")],
    }


# ─── Parser Node ──────────────────────────────────────────────────────────────


def parser_node(state: ScanState) -> dict[str, Any]:
    """Parse the dependency file and extract all dependencies (D11, D19)."""
    start_time = time.time()

    trace_entry = TraceEntry(
        node="parser",
        action="parsing",
        detail="",
        timestamp=datetime.utcnow(),
    )

    try:
        deps = parse_file(state.file_content, state.file_type)
        trace_entry.detail = f"Parsed {len(deps)} dependencies from {state.file_type}"

        logger.info("parser_complete", dep_count=len(deps), file_type=state.file_type)

        latency = (time.time() - start_time) * 1000
        trace_entry.latency_ms = latency

        return {
            "dependencies": deps,
            "status": ScanStatus.ANALYZING,
            "trace": [trace_entry],
            "messages": [
                AIMessage(
                    content=f"[Parser] Parsed {len(deps)} dependencies from {state.file_type}:\n"
                    + "\n".join(f"  - {d.name} {d.current_version}" for d in deps[:20])
                    + ("\n  ..." if len(deps) > 20 else "")
                )
            ],
        }

    except Exception as e:
        trace_entry.detail = f"Parse error: {str(e)}"
        logger.error("parser_error", error=str(e))

        return {
            "status": ScanStatus.FAILED,
            "error": f"Failed to parse {state.file_type}: {str(e)}",
            "trace": [trace_entry],
            "messages": [AIMessage(content=f"[Parser] Error: {str(e)}")],
        }


# ─── Risk Assessor Node ──────────────────────────────────────────────────────


def risk_assessor_node(state: ScanState) -> dict[str, Any]:
    """Check each dependency for vulnerabilities and assess risk (D10, D19)."""
    start_time = time.time()
    findings: list[Finding] = []

    trace_entry = TraceEntry(
        node="risk_assessor",
        action="vulnerability_scan",
        detail="",
        timestamp=datetime.utcnow(),
    )

    for dep in state.dependencies:
        # Look up vulnerabilities
        vulns = lookup_vulnerabilities(dep.name, dep.current_version)

        for vuln in vulns:
            # Compute risk score
            assessment = compute_risk_score(dep, vuln)

            finding = Finding(
                dependency=dep,
                vulnerability=vuln,
                risk_assessment=assessment,
                recommended_version=vuln.fixed_version,
            )
            findings.append(finding)

    latency = (time.time() - start_time) * 1000
    trace_entry.latency_ms = latency
    trace_entry.detail = (
        f"Scanned {len(state.dependencies)} deps, found {len(findings)} vulnerabilities"
    )

    logger.info(
        "risk_assessor_complete",
        deps_scanned=len(state.dependencies),
        findings=len(findings),
    )

    # Build summary message
    if findings:
        summary_lines = ["[Risk Assessor] Vulnerability scan complete:"]
        for f in findings[:10]:
            severity = f.vulnerability.severity.value.upper()
            score = f.risk_assessment.risk_score if f.risk_assessment else "N/A"
            summary_lines.append(
                f"  ⚠ {f.dependency.name} {f.dependency.current_version} — "
                f"{f.vulnerability.vuln_id} ({severity}, score: {score})"
            )
        if len(findings) > 10:
            summary_lines.append(f"  ... and {len(findings) - 10} more")
        msg = "\n".join(summary_lines)
    else:
        msg = "[Risk Assessor] No vulnerabilities found in scanned dependencies."

    return {
        "findings": findings,
        "status": ScanStatus.PLANNING if findings else ScanStatus.COMPLETED,
        "trace": [trace_entry],
        "messages": [AIMessage(content=msg)],
    }


# ─── Planner Node ────────────────────────────────────────────────────────────


def planner_node(state: ScanState) -> dict[str, Any]:
    """Create an upgrade plan from findings (D16 Plan-and-Execute, D19)."""
    start_time = time.time()

    trace_entry = TraceEntry(
        node="planner",
        action="plan_creation",
        detail="",
        timestamp=datetime.utcnow(),
    )

    # Build upgrade actions from findings
    actions: list[UpgradeAction] = []
    seen_packages: dict[str, UpgradeAction] = {}

    for finding in state.findings:
        pkg = finding.dependency.name
        if pkg in seen_packages:
            # Add finding ID to existing action
            seen_packages[pkg].finding_ids.append(finding.id)
            continue

        action = UpgradeAction(
            package_name=pkg,
            from_version=finding.dependency.current_version,
            to_version=finding.recommended_version or "latest",
            finding_ids=[finding.id],
            is_breaking=(
                finding.risk_assessment.is_breaking_change
                if finding.risk_assessment
                else False
            ),
            notes=(
                f"Fixes {finding.vulnerability.vuln_id} "
                f"({finding.vulnerability.severity.value})"
            ),
        )
        actions.append(action)
        seen_packages[pkg] = action

    # Sort: non-breaking first, then by severity
    actions.sort(key=lambda a: (a.is_breaking, -len(a.finding_ids)))

    # Risk summary
    critical_count = sum(
        1 for f in state.findings
        if f.vulnerability.severity == Severity.CRITICAL
    )
    high_count = sum(
        1 for f in state.findings
        if f.vulnerability.severity == Severity.HIGH
    )

    plan = UpgradePlan(
        actions=actions,
        risk_summary=(
            f"{len(state.findings)} vulnerabilities across {len(actions)} packages. "
            f"{critical_count} critical, {high_count} high severity. "
            f"{sum(1 for a in actions if a.is_breaking)} potentially breaking changes."
        ),
        total_findings=len(state.findings),
        estimated_effort="low" if len(actions) <= 3 else ("medium" if len(actions) <= 10 else "high"),
    )

    latency = (time.time() - start_time) * 1000
    trace_entry.latency_ms = latency
    trace_entry.detail = f"Created plan with {len(actions)} upgrade actions"

    logger.info("planner_complete", actions=len(actions))

    # Build plan message
    plan_lines = [f"[Planner] Upgrade plan ({len(actions)} actions):"]
    for a in actions:
        breaking_flag = " ⚠ BREAKING" if a.is_breaking else ""
        plan_lines.append(
            f"  {a.package_name}: {a.from_version} → {a.to_version}{breaking_flag} — {a.notes}"
        )
    plan_lines.append(f"\nRisk: {plan.risk_summary}")

    return {
        "upgrade_plan": plan,
        "status": ScanStatus.PLANNING,
        "trace": [trace_entry],
        "messages": [AIMessage(content="\n".join(plan_lines))],
    }


# ─── Verifier Node ───────────────────────────────────────────────────────────


def verifier_node(state: ScanState) -> dict[str, Any]:
    """Validate the upgrade plan (D17 cycles — Verifier → Planner retry)."""
    start_time = time.time()

    trace_entry = TraceEntry(
        node="verifier",
        action="plan_verification",
        detail="",
        timestamp=datetime.utcnow(),
    )

    issues: list[str] = []

    if state.upgrade_plan is None:
        issues.append("No upgrade plan to verify")
    else:
        plan = state.upgrade_plan

        # Check 1: Every finding has a corresponding action
        addressed_finding_ids = set()
        for action in plan.actions:
            addressed_finding_ids.update(action.finding_ids)

        unaddressed = [
            f for f in state.findings if f.id not in addressed_finding_ids
        ]
        if unaddressed:
            issues.append(
                f"{len(unaddressed)} findings not addressed in plan: "
                + ", ".join(f.vulnerability.vuln_id for f in unaddressed[:5])
            )

        # Check 2: No empty upgrade targets
        empty_targets = [a for a in plan.actions if not a.to_version or a.to_version == "latest"]
        if empty_targets:
            issues.append(
                f"{len(empty_targets)} actions have unresolved target versions: "
                + ", ".join(a.package_name for a in empty_targets[:5])
            )

        # Check 3: Breaking changes are flagged
        for action in plan.actions:
            if action.is_breaking and "BREAKING" not in action.notes.upper():
                issues.append(f"Breaking change for {action.package_name} not noted")

    latency = (time.time() - start_time) * 1000
    trace_entry.latency_ms = latency

    if issues:
        trace_entry.detail = f"Verification FAILED: {'; '.join(issues)}"
        logger.warning("verifier_failed", issues=issues)

        return {
            "status": ScanStatus.VERIFYING,
            "next_action": "needs_revision",
            "retry_count": state.retry_count + 1,
            "trace": [trace_entry],
            "messages": [AIMessage(content=f"[Verifier] NEEDS_REVISION:\n" + "\n".join(f"  - {i}" for i in issues))],
        }
    else:
        trace_entry.detail = "Plan VERIFIED — all checks passed"
        logger.info("verifier_passed")

        return {
            "status": ScanStatus.AWAITING_APPROVAL,
            "next_action": "verified",
            "trace": [trace_entry],
            "messages": [AIMessage(content="[Verifier] VERIFIED — plan passes all checks. Routing to approval gate.")],
        }


# ─── Investigator Node (ReAct loop) ──────────────────────────────────────────


def investigator_node(state: ScanState) -> dict[str, Any]:
    """Deep investigation using ReAct loop for critical findings (D16).

    Thought → Tool Call → Observation → Repeat, capped at max_iterations.
    """
    start_time = time.time()
    settings = get_settings()
    max_iterations = settings.agent.max_iterations  # Hard cap = 6

    trace_entries: list[TraceEntry] = []
    additional_findings: list[Finding] = []

    # Find critical findings to investigate
    critical = [
        f for f in state.findings
        if f.vulnerability.severity == Severity.CRITICAL
    ]

    investigation_notes: list[str] = []

    for i, finding in enumerate(critical[:3]):  # Investigate top 3 critical
        iteration = 0
        while iteration < max_iterations:
            iteration += 1

            # Thought
            thought = (
                f"Iteration {iteration}/{max_iterations}: "
                f"Investigating {finding.dependency.name} — "
                f"{finding.vulnerability.vuln_id}"
            )

            # Tool Call: Look for related vulnerabilities
            related_vulns = lookup_vulnerabilities(
                finding.dependency.name, finding.dependency.current_version
            )

            # Observation
            observation = f"Found {len(related_vulns)} related vulnerabilities"

            trace_entries.append(TraceEntry(
                node="investigator",
                action=f"react_cycle_{iteration}",
                detail=f"Thought: {thought} | Observation: {observation}",
                timestamp=datetime.utcnow(),
            ))

            investigation_notes.append(
                f"  [{finding.dependency.name}] {thought} → {observation}"
            )

            # If we've gathered enough info, break
            if iteration >= 2:  # Minimum 2 cycles per finding
                break

    latency = (time.time() - start_time) * 1000

    msg_lines = [f"[Investigator] Deep investigation complete ({len(critical)} critical findings):"]
    msg_lines.extend(investigation_notes)

    return {
        "status": ScanStatus.ANALYZING,
        "trace": trace_entries,
        "iteration_count": state.iteration_count + sum(1 for _ in trace_entries),
        "messages": [AIMessage(content="\n".join(msg_lines))],
    }


# ─── Approval Gate Node (HITL) ───────────────────────────────────────────────


def approval_gate_node(state: ScanState) -> dict[str, Any]:
    """Human-in-the-loop approval gate (D20).

    This node triggers an interrupt. The graph pauses here until
    a human approves, rejects, or edits the plan.
    """
    trace_entry = TraceEntry(
        node="approval_gate",
        action="awaiting_approval",
        detail="Plan ready for human review. Interrupt triggered.",
        timestamp=datetime.utcnow(),
    )

    logger.info("approval_gate_reached", scan_id=state.scan_id)

    return {
        "status": ScanStatus.AWAITING_APPROVAL,
        "trace": [trace_entry],
        "messages": [
            AIMessage(
                content="[Approval Gate] Upgrade plan ready for review. "
                "Please approve, reject, or edit the plan."
            )
        ],
    }


# ─── Post-Approval Node ──────────────────────────────────────────────────────


def post_approval_node(state: ScanState) -> dict[str, Any]:
    """Process the approval decision (D20)."""
    trace_entry = TraceEntry(
        node="post_approval",
        action="processing_decision",
        detail="",
        timestamp=datetime.utcnow(),
    )

    if state.approval_action == "approve":
        trace_entry.detail = "Plan APPROVED by human"
        return {
            "status": ScanStatus.APPROVED,
            "trace": [trace_entry],
            "messages": [AIMessage(content="[Post-Approval] Plan approved. Scan complete.")],
        }
    elif state.approval_action == "reject":
        trace_entry.detail = f"Plan REJECTED: {state.approval_feedback}"
        return {
            "status": ScanStatus.REJECTED,
            "trace": [trace_entry],
            "messages": [AIMessage(content=f"[Post-Approval] Plan rejected: {state.approval_feedback}")],
        }
    elif state.approval_action == "edit":
        trace_entry.detail = "Plan EDITED by human — restarting verification"
        return {
            "status": ScanStatus.VERIFYING,
            "next_action": "needs_revision",
            "trace": [trace_entry],
            "messages": [AIMessage(content="[Post-Approval] Edited plan submitted for re-verification.")],
        }
    else:
        trace_entry.detail = "No approval action specified"
        return {
            "status": ScanStatus.AWAITING_APPROVAL,
            "trace": [trace_entry],
            "messages": [AIMessage(content="[Post-Approval] Awaiting approval action.")],
        }


# ─── Fallback / Error Handler ────────────────────────────────────────────────


def error_handler_node(state: ScanState) -> dict[str, Any]:
    """Handle errors in the graph (D16 conditional routing)."""
    trace_entry = TraceEntry(
        node="error_handler",
        action="error_handling",
        detail=f"Error encountered: {state.error}",
        timestamp=datetime.utcnow(),
    )

    logger.error("graph_error", error=state.error, scan_id=state.scan_id)

    return {
        "status": ScanStatus.FAILED,
        "trace": [trace_entry],
        "messages": [AIMessage(content=f"[Error Handler] Scan failed: {state.error}")],
    }
