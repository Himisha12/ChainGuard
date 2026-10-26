"""OpsPilot CLI Interface: Operator Terminal & Safety Management.

Commands:
- opspilot approvals list [--incident-id ID] [--status STATUS]
- opspilot approve <id> [--action approve|reject|edit] [--reason REASON] [--edits JSON]
- opspilot incident create [SERVICE] [--service SERVICE] [--desc DESC] [--severity SEVERITY]
- opspilot timetravel list <incident_id>
- opspilot timetravel fork <incident_id> <checkpoint_id> [--new-id ID] [--overrides JSON]
- opspilot audit list [--incident-id ID]
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from typing import Any

from src.core.database import (
    create_pending_approval,
    get_pending_approval,
    init_db,
    list_approval_audit_logs,
    list_pending_approvals,
)
from src.graph.opspilot_builder import (
    build_opspilot_graph,
    fork_incident_branch,
    get_opspilot_checkpointer,
    list_incident_checkpoints,
)
from src.graph.opspilot_state import OpsPilotState
from src.models.schemas import IncidentStatus, StructuredFacts


def cmd_approvals_list(args: argparse.Namespace) -> None:
    """List pending approvals from SQLite (survives restarts)."""
    init_db()
    approvals = list_pending_approvals(incident_id=args.incident_id, status=args.status)
    if not approvals:
        print(f"No approvals found matching status='{args.status}'.")
        return

    print(f"\nFound {len(approvals)} approval(s):")
    print("-" * 80)
    print(f"{'ID':<38} {'INCIDENT':<14} {'TOOL':<18} {'TIER':<12} {'STATUS'}")
    print("-" * 80)
    for a in approvals:
        print(f"{a.id:<38} {a.incident_id:<14} {a.tool_name:<18} {a.risk_tier.value:<12} {a.status}")
    print("-" * 80)


def cmd_approve(args: argparse.Namespace) -> None:
    """Approve, reject, or edit a pending action and resume the paused graph."""
    init_db()
    approval = get_pending_approval(args.approval_id)
    if not approval:
        print(f"Error: Approval with ID '{args.approval_id}' not found.")
        sys.exit(1)

    if approval.status != "pending":
        print(f"Warning: Approval '{args.approval_id}' already has status '{approval.status}'.")

    action = args.action.lower()
    edits = None
    if args.edits:
        try:
            edits = json.loads(args.edits)
        except json.JSONDecodeError:
            print("Error: --edits must be valid JSON string.")
            sys.exit(1)

    cp = get_opspilot_checkpointer()
    graph = build_opspilot_graph(checkpointer=cp)
    config = {"configurable": {"thread_id": approval.incident_id}}

    # Resume the graph with operator decision
    update_payload: dict[str, Any] = {
        "approval_action": action,
        "operator_name": args.operator,
        "rejection_reason": args.reason,
    }
    if edits:
        update_payload["approval_edits"] = edits

    graph.update_state(config, update_payload)

    print(f"Resuming incident '{approval.incident_id}' with action='{action}' by '{args.operator}'...")
    events = []
    for ev in graph.stream(None, config=config):
        events.append(list(ev.keys())[0])

    final_state = graph.get_state(config)
    st = final_state.values.get("status")
    if hasattr(st, "value"):
        st = st.value
    print(f"Workflow resumed through steps: {events}")
    print(f"Incident '{approval.incident_id}' status: {st}")


def cmd_incident_create(args: argparse.Namespace) -> None:
    """Trigger a new OpsPilot incident workflow."""
    init_db()
    inc_id = args.id or f"inc-{uuid.uuid4().hex[:6]}"
    service = args.service_pos or args.service or "payment-gateway"
    desc = args.description or "Elevated 5xx error rate detected after recent deploy"
    severity_val = getattr(args, "severity", "critical") or "critical"

    cp = get_opspilot_checkpointer()
    graph = build_opspilot_graph(checkpointer=cp)
    config = {"configurable": {"thread_id": inc_id}}

    state = OpsPilotState(
        incident_id=inc_id,
        thread_id=inc_id,
        service_name=service,
        description=desc,
        severity=severity_val,
        structured_facts=StructuredFacts(service_names=[service]),
    )

    print(f"Starting OpsPilot incident response for {service} (ID: {inc_id}, Severity: {severity_val})...")
    events = []
    for ev in graph.stream(state, config=config):
        events.append(list(ev.keys())[0])

    final_state = graph.get_state(config)
    st = final_state.values.get("status")
    if hasattr(st, "value"):
        st = st.value

    print(f"Executed steps: {events}")
    print(f"Current Status: {st}")
    if final_state.next:
        print(f"Paused at Interrupt! Awaiting operator approval before: {final_state.next}")
        pending = list_pending_approvals(incident_id=inc_id, status="pending")
        if pending:
            print(f"Pending Approval ID: {pending[0].id} (tool: {pending[0].tool_name}, tier: {pending[0].risk_tier.value})")


def cmd_timetravel_list(args: argparse.Namespace) -> None:
    """List checkpoints for an incident (time-travel inspection)."""
    init_db()
    target_id = args.incident_id
    if not target_id:
        import sqlite3
        from src.core.database import _get_db_path
        with sqlite3.connect(_get_db_path()) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT incident_id FROM pending_approvals ORDER BY created_at DESC LIMIT 1").fetchone()
            if not row:
                row = conn.execute("SELECT incident_id FROM approval_audit_log ORDER BY timestamp DESC LIMIT 1").fetchone()
            if row:
                target_id = row["incident_id"]

    if not target_id:
        print("No incident_id specified and no past incidents found in database.")
        print("Usage: opspilot timetravel list <incident_id>")
        return

    cp = get_opspilot_checkpointer()
    graph = build_opspilot_graph(checkpointer=cp)
    cps = list_incident_checkpoints(graph, target_id)

    if not cps:
        print(f"No checkpoints found for incident '{target_id}'.")
        return

    print(f"\nCheckpoints for Incident '{target_id}':")
    print("-" * 80)
    print(f"{'INDEX':<6} {'CHECKPOINT ID':<38} {'STATUS':<20} {'WORKER'}")
    print("-" * 80)
    for c in cps:
        print(f"{c['index']:<6} {c['checkpoint_id']:<38} {c['status']:<20} {c['current_worker']}")
    print("-" * 80)


def cmd_timetravel_fork(args: argparse.Namespace) -> None:
    """Fork and replay an alternative branch from a past checkpoint."""
    init_db()
    cp = get_opspilot_checkpointer()
    graph = build_opspilot_graph(checkpointer=cp)

    new_id = args.new_id or f"{args.incident_id}-fork-{uuid.uuid4().hex[:4]}"
    overrides = {}
    if args.overrides:
        try:
            overrides = json.loads(args.overrides)
        except json.JSONDecodeError:
            print("Error: --overrides must be valid JSON.")
            sys.exit(1)

    result = fork_incident_branch(
        graph=graph,
        incident_id=args.incident_id,
        checkpoint_id=args.checkpoint_id,
        new_thread_id=new_id,
        state_overrides=overrides,
    )

    print(f"\nSuccessfully forked branch '{new_id}' from checkpoint '{args.checkpoint_id}'!")
    print("\n--- Side-by-Side Comparison ---")
    print(json.dumps(result["side_by_side"], indent=2))


def cmd_audit_list(args: argparse.Namespace) -> None:
    """Inspect the immutable approval audit log."""
    init_db()
    logs = list_approval_audit_logs(incident_id=args.incident_id)
    if not logs:
        print("No audit log records found.")
        return

    print(f"\nApproval Audit Log ({len(logs)} entries):")
    print("-" * 90)
    print(f"{'TIMESTAMP':<22} {'INCIDENT':<14} {'OPERATOR':<10} {'ACTION':<8} {'ORIGINAL ARGS'}")
    print("-" * 90)
    for l in logs:
        ts = l.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        args_str = json.dumps(l.original_args)[:32]
        print(f"{ts:<22} {l.incident_id:<14} {l.operator:<10} {l.action:<8} {args_str}")
    print("-" * 90)


def main() -> None:
    """CLI Entrypoint for OpsPilot."""
    parser = argparse.ArgumentParser(
        prog="opspilot",
        description="OpsPilot: Autonomous SRE Incident Response with HITL Safety Gates",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # approvals list
    p_app = subparsers.add_parser("approvals", help="Manage pending approvals")
    p_app_sub = p_app.add_subparsers(dest="subcommand")
    p_app_list = p_app_sub.add_parser("list", help="List approvals")
    p_app_list.add_argument("--incident-id", help="Filter by incident ID")
    p_app_list.add_argument("--status", default="pending", help="Filter by status (default: pending)")

    # approve <id>
    p_approve = subparsers.add_parser("approve", help="Approve, reject, or edit a pending action")
    p_approve.add_argument("approval_id", help="UUID of the pending approval")
    p_approve.add_argument("--action", default="approve", choices=["approve", "reject", "edit"], help="Approval mode")
    p_approve.add_argument("--reason", default="", help="Rejection reason if action is reject")
    p_approve.add_argument("--edits", default="", help="JSON string of modified arguments if action is edit")
    p_approve.add_argument("--operator", default="cli_operator", help="Operator username")

    # incident create
    p_inc = subparsers.add_parser("incident", help="Manage incidents")
    p_inc_sub = p_inc.add_subparsers(dest="subcommand")
    p_inc_create = p_inc_sub.add_parser("create", help="Create and run an incident")
    p_inc_create.add_argument("service_pos", nargs="?", default=None, help="Affected service name (positional, e.g. payment-gateway)")
    p_inc_create.add_argument("--id", help="Explicit incident ID")
    p_inc_create.add_argument("--service", default=None, help="Affected service name")
    p_inc_create.add_argument("--desc", "--description", dest="description", help="Incident description / symptoms")
    p_inc_create.add_argument("--severity", default="critical", choices=["critical", "high", "medium", "low"], help="Incident severity (default: critical)")

    # timetravel list / fork
    p_tt = subparsers.add_parser("timetravel", help="Time-travel checkpoint inspection and branching")
    p_tt_sub = p_tt.add_subparsers(dest="subcommand")
    p_tt_list = p_tt_sub.add_parser("list", help="List checkpoints for an incident")
    p_tt_list.add_argument("incident_id", nargs="?", default=None, help="Incident ID (optional: defaults to latest incident)")
    p_tt_fork = p_tt_sub.add_parser("fork", help="Fork alternative branch from a checkpoint")
    p_tt_fork.add_argument("incident_id", help="Original incident ID")
    p_tt_fork.add_argument("checkpoint_id", help="Checkpoint ID to branch from")
    p_tt_fork.add_argument("--new-id", help="New incident ID for the forked branch")
    p_tt_fork.add_argument("--overrides", help="JSON dictionary of state overrides")

    # audit list
    p_audit = subparsers.add_parser("audit", help="Audit log inspection")
    p_audit_sub = p_audit.add_subparsers(dest="subcommand")
    p_audit_list = p_audit_sub.add_parser("list", help="List audit entries")
    p_audit_list.add_argument("--incident-id", help="Filter by incident ID")

    args = parser.parse_args()

    if args.command == "approvals":
        if args.subcommand == "list":
            cmd_approvals_list(args)
        else:
            p_app.print_help()
    elif args.command == "approve":
        cmd_approve(args)
    elif args.command == "incident":
        if args.subcommand == "create":
            cmd_incident_create(args)
        else:
            p_inc.print_help()
    elif args.command == "timetravel":
        if args.subcommand == "list":
            cmd_timetravel_list(args)
        elif args.subcommand == "fork":
            cmd_timetravel_fork(args)
        else:
            p_tt.print_help()
    elif args.command == "audit":
        if args.subcommand == "list":
            cmd_audit_list(args)
        else:
            p_audit.print_help()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
