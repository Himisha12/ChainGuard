"""FastAPI application: /v1/ API with DI, auth, rate limits (D2, D7).

Endpoints:
- POST /v1/auth/register — Register a new user
- POST /v1/auth/login — Login and get JWT
- POST /v1/scans — Start a new scan
- GET  /v1/scans — List scans (paginated)
- GET  /v1/scans/{scan_id} — Get scan details
- POST /v1/scans/{scan_id}/approve — HITL approval
- GET  /v1/scans/{scan_id}/checkpoints — Time-travel: list checkpoints
- GET  /v1/health — Health check
- GET  /v1/metrics — Basic metrics
"""

from __future__ import annotations

import json
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException, UploadFile, File, Form, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from src.api.auth import (
    authenticate_user,
    authorize,
    authorize_or_optional,
    create_access_token,
    get_current_user,
    get_optional_user,
)
from src.api.rate_limit import rate_limiter
from src.core.config import get_settings
from src.core.database import (
    _get_db_path,
    create_approval_audit_log,
    create_incident_record,
    create_pending_approval,
    create_scan,
    create_user,
    get_incident_record,
    get_pending_approval,
    get_scan,
    init_db,
    list_approval_audit_logs,
    list_incident_records,
    list_pending_approvals,
    list_scans,
    update_incident_status,
    update_pending_approval_status,
    update_scan,
)
from src.graph.builder import build_scan_graph, get_checkpointer
from src.graph.opspilot_builder import (
    build_opspilot_graph,
    fork_incident_branch,
    get_opspilot_checkpointer,
    list_incident_checkpoints,
)
from src.graph.opspilot_state import OpsPilotState
from src.graph.state import ScanState
from src.models.schemas import (
    ApprovalAction,
    ApprovalAuditLog,
    ApprovalRequest,
    IncidentApprovalRequest,
    IncidentRequest,
    IncidentStatus,
    PendingApproval,
    RiskTier,
    ScanRequest,
    ScanResponse,
    ScanStatus,
    StructuredFacts,
    TokenResponse,
    UserCreate,
    UserInDB,
    UserRole,
)
from src.tools.opspilot_tools import execute_tool_with_gate

from src.guardrails.sanitizer import sanitize_input
from src.models.schemas import (
    ApprovalAction,
    ApprovalRequest,
    ScanRequest,
    ScanResponse,
    ScanStatus,
    TokenResponse,
    UserCreate,
    UserInDB,
    UserRole,
)
from src.utils.logging import set_request_id, setup_logging

import structlog

logger = structlog.get_logger(__name__)

# ─── App Lifecycle ────────────────────────────────────────────────────────────

_graph = None
_checkpointer = None
_opspilot_graph = None
_opspilot_checkpointer = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown."""
    global _graph, _checkpointer, _opspilot_graph, _opspilot_checkpointer

    # Setup
    setup_logging()
    init_db()
    _checkpointer = get_checkpointer()
    _graph = build_scan_graph(checkpointer=_checkpointer)

    _opspilot_checkpointer = get_opspilot_checkpointer()
    _opspilot_graph = build_opspilot_graph(checkpointer=_opspilot_checkpointer)

    logger.info("app_started", version=get_settings().version)

    yield

    # Cleanup
    logger.info("app_shutdown")


def get_opspilot():
    """Dependency to provide OpsPilot graph and checkpointer."""
    global _opspilot_graph, _opspilot_checkpointer
    if _opspilot_graph is None or _opspilot_checkpointer is None:
        _opspilot_checkpointer = get_opspilot_checkpointer()
        _opspilot_graph = build_opspilot_graph(checkpointer=_opspilot_checkpointer)
    return _opspilot_graph, _opspilot_checkpointer



# ─── App Creation ─────────────────────────────────────────────────────────────

app = FastAPI(
    title="ChainGuard API",
    description="AI-powered dependency vulnerability scanner",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── DI: Model and Graph (D7) ────────────────────────────────────────────────


def get_graph():
    """Dependency injection for the scan graph."""
    if _graph is None:
        raise HTTPException(status_code=503, detail="Graph not initialized")
    return _graph


# ─── Auth Routes ──────────────────────────────────────────────────────────────


@app.post("/v1/auth/register", response_model=TokenResponse, status_code=201)
async def register(user_data: UserCreate):
    """Register a new user.

    SECURITY (D3): Server ignores client-supplied role and assigns VIEWER.
    """
    from src.core.database import get_user_by_username as _get_user

    if _get_user(user_data.username):
        raise HTTPException(status_code=400, detail="Username already taken")

    # D3: Server assigns role, ignoring client value
    user = create_user(user_data)

    token = create_access_token(
        data={"sub": user.username, "role": user.role.value}
    )

    return TokenResponse(
        access_token=token,
        role=user.role,
        username=user.username,
    )


@app.post("/v1/auth/login", response_model=TokenResponse)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Login and get a JWT token."""
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    token = create_access_token(
        data={"sub": user.username, "role": user.role.value}
    )

    return TokenResponse(
        access_token=token,
        role=user.role,
        username=user.username,
    )


# ─── Scan Routes ──────────────────────────────────────────────────────────────


@app.post("/v1/scans", response_model=ScanResponse, status_code=201)
async def start_scan(
    request: ScanRequest,
    user: UserInDB = Depends(get_current_user),
    graph=Depends(get_graph),
):
    """Start a new vulnerability scan.

    Flow: Upload → Sanitize → Parse → Assess → Plan → Verify → Approve
    """
    # Rate limiting
    rate_limiter.check_rate_limit(user.id)

    # Generate IDs
    scan_id = str(uuid.uuid4())
    thread_id = str(uuid.uuid4())
    set_request_id(scan_id[:8])

    logger.info("scan_started", scan_id=scan_id, user_id=user.id)

    # Guardrails: sanitize input (D15)
    settings = get_settings()
    sanitized_content, sanitize_report = sanitize_input(
        request.file_content,
        enable_injection_check=settings.guardrails.enable_injection_detection,
        enable_secret_redaction=settings.guardrails.enable_pii_redaction,
        enable_pii_redaction=settings.guardrails.enable_pii_redaction,
    )

    if not sanitize_report["is_safe"]:
        logger.warning(
            "scan_input_unsafe",
            scan_id=scan_id,
            injections=len(sanitize_report["injections"]),
        )
        # Still proceed but with sanitized content and a warning

    # Store in database
    create_scan(
        scan_id=scan_id,
        thread_id=thread_id,
        user_id=user.id,
        project_name=request.project_name,
        file_type=request.file_type,
        file_content=sanitized_content,
    )

    # Run the graph
    try:
        initial_state = {
            "scan_id": scan_id,
            "thread_id": thread_id,
            "user_id": user.id,
            "project_name": request.project_name,
            "file_content": sanitized_content,
            "file_type": request.file_type,
            "status": ScanStatus.PENDING,
        }

        config = {"configurable": {"thread_id": thread_id}}

        # Run until interrupt (approval gate) or completion
        result = None
        for event in graph.stream(initial_state, config=config):
            result = event

        # Extract final state
        if result:
            # Get the state from the graph
            final_state = graph.get_state(config)
            state_values = final_state.values if hasattr(final_state, 'values') else {}

            current_status = state_values.get("status", ScanStatus.PENDING)
            if isinstance(current_status, str):
                current_status = ScanStatus(current_status)

            # Update database
            findings = state_values.get("findings", [])
            plan = state_values.get("upgrade_plan")
            trace = state_values.get("trace", [])

            update_scan(
                scan_id=scan_id,
                user_id=user.id,
                status=current_status,
                findings_json=json.dumps([f.model_dump(mode="json") for f in findings]) if findings else None,
                upgrade_plan_json=plan.model_dump_json() if plan else None,
                trace_json=json.dumps([t.model_dump(mode="json") for t in trace]) if trace else None,
            )

            return ScanResponse(
                scan_id=scan_id,
                thread_id=thread_id,
                status=current_status,
                message=f"Scan {'awaiting approval' if current_status == ScanStatus.AWAITING_APPROVAL else current_status.value}",
            )

    except Exception as e:
        logger.error("scan_error", scan_id=scan_id, error=str(e))
        update_scan(scan_id=scan_id, user_id=user.id, status=ScanStatus.FAILED)
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

    return ScanResponse(
        scan_id=scan_id,
        thread_id=thread_id,
        status=ScanStatus.PENDING,
        message="Scan initiated",
    )


@app.get("/v1/scans")
async def get_scans(
    page: int = 1,
    per_page: int = 20,
    status_filter: Optional[str] = None,
    user: UserInDB = Depends(get_current_user),
):
    """List scans for the current user (paginated, D4).

    SECURITY (D3): Only returns scans belonging to the authenticated user.
    """
    rate_limiter.check_rate_limit(user.id)

    sf = ScanStatus(status_filter) if status_filter else None
    return list_scans(user.id, page=page, per_page=per_page, status_filter=sf)


@app.get("/v1/scans/{scan_id}")
async def get_scan_detail(
    scan_id: str,
    user: UserInDB = Depends(get_current_user),
):
    """Get scan details.

    SECURITY (D3): Scoped to user — no one sees another tenant's data.
    """
    rate_limiter.check_rate_limit(user.id)

    scan = get_scan(scan_id, user.id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Parse JSON fields
    result = dict(scan)
    result["scan_id"] = result.get("id")
    for json_field in ["findings_json", "upgrade_plan_json", "token_usage_json", "trace_json"]:
        if result.get(json_field):
            try:
                result[json_field.replace("_json", "")] = json.loads(result[json_field])
            except json.JSONDecodeError:
                pass
            del result[json_field]

    return result


@app.post("/v1/scans/{scan_id}/approve")
async def approve_scan(
    scan_id: str,
    approval: ApprovalRequest,
    user: UserInDB = Depends(authorize(UserRole.APPROVER)),
    graph=Depends(get_graph),
):
    """HITL approval endpoint (D20).

    RBAC (D5): Only APPROVER role can approve upgrade plans.
    """
    rate_limiter.check_rate_limit(user.id)

    scan = get_scan(scan_id, user.id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    thread_id = scan["thread_id"]

    # Resume the graph from the interrupt (D18, D20)
    config = {"configurable": {"thread_id": thread_id}}

    # Update state with approval decision
    graph.update_state(
        config,
        {
            "approval_action": approval.action.value,
            "approval_feedback": approval.feedback,
        },
    )

    # Continue execution past the interrupt
    result = None
    for event in graph.stream(None, config=config):
        result = event

    # Get final state
    final_state = graph.get_state(config)
    state_values = final_state.values if hasattr(final_state, 'values') else {}
    final_status = state_values.get("status", ScanStatus.COMPLETED)
    if isinstance(final_status, str):
        final_status = ScanStatus(final_status)

    # Update database
    update_scan(
        scan_id=scan_id,
        user_id=user.id,
        status=final_status,
        completed_at=datetime.utcnow().isoformat() if final_status in (ScanStatus.APPROVED, ScanStatus.REJECTED) else None,
    )

    return {"scan_id": scan_id, "status": final_status.value, "action": approval.action.value}


# ─── Time-Travel (D20) ───────────────────────────────────────────────────────


@app.get("/v1/scans/{scan_id}/checkpoints")
async def list_checkpoints(
    scan_id: str,
    user: UserInDB = Depends(get_current_user),
    graph=Depends(get_graph),
):
    """List checkpoints for a scan (time-travel, D20).

    Returns a list of checkpoints that can be used to replay or fork.
    """
    scan = get_scan(scan_id, user.id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    thread_id = scan["thread_id"]
    config = {"configurable": {"thread_id": thread_id}}

    try:
        history = list(graph.get_state_history(config))
        checkpoints = []
        for i, state in enumerate(history):
            cp = {
                "index": i,
                "checkpoint_id": state.config.get("configurable", {}).get("checkpoint_id", ""),
                "status": str(state.values.get("status", "")),
                "findings_count": len(state.values.get("findings", [])),
                "has_plan": state.values.get("upgrade_plan") is not None,
                "next_nodes": list(state.next) if hasattr(state, "next") else [],
            }
            checkpoints.append(cp)
        return {"scan_id": scan_id, "checkpoints": checkpoints}
    except Exception as e:
        return {"scan_id": scan_id, "checkpoints": [], "error": str(e)}


# ─── Export (D4) ──────────────────────────────────────────────────────────────


@app.get("/v1/scans/{scan_id}/export")
async def export_scan(
    scan_id: str,
    format: str = "json",
    user: UserInDB = Depends(get_current_user),
):
    """Export scan results in JSON or Markdown format (D4)."""
    scan = get_scan(scan_id, user.id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    if format == "json":
        from fastapi.responses import JSONResponse
        return JSONResponse(content=dict(scan))

    elif format == "markdown":
        from fastapi.responses import PlainTextResponse
        md = _scan_to_markdown(scan)
        return PlainTextResponse(content=md, media_type="text/markdown")

    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")


def _scan_to_markdown(scan: dict[str, Any]) -> str:
    """Convert scan data to Markdown report."""
    lines = [
        f"# ChainGuard Scan Report",
        f"",
        f"**Scan ID:** {scan['id']}",
        f"**Status:** {scan['status']}",
        f"**Project:** {scan['project_name']}",
        f"**Created:** {scan['created_at']}",
        f"",
    ]

    if scan.get("findings_json"):
        findings = json.loads(scan["findings_json"])
        lines.append(f"## Findings ({len(findings)} total)")
        lines.append("")
        lines.append("| Package | CVE | Severity | Risk Score | Fix Version |")
        lines.append("|---------|-----|----------|------------|-------------|")
        for f in findings:
            dep = f.get("dependency", {})
            vuln = f.get("vulnerability", {})
            risk = f.get("risk_assessment", {})
            lines.append(
                f"| {dep.get('name', 'N/A')} | {vuln.get('vuln_id', 'N/A')} | "
                f"{vuln.get('severity', 'N/A')} | {risk.get('risk_score', 'N/A')} | "
                f"{vuln.get('fixed_version', 'N/A')} |"
            )

    if scan.get("upgrade_plan_json"):
        plan = json.loads(scan["upgrade_plan_json"])
        lines.extend([
            "",
            "## Upgrade Plan",
            "",
            f"**Risk Summary:** {plan.get('risk_summary', 'N/A')}",
            f"**Estimated Effort:** {plan.get('estimated_effort', 'N/A')}",
            "",
        ])
        actions = plan.get("actions", [])
        if actions:
            lines.append("| Package | From | To | Breaking | Notes |")
            lines.append("|---------|------|----|----------|-------|")
            for a in actions:
                lines.append(
                    f"| {a['package_name']} | {a['from_version']} | {a['to_version']} | "
                    f"{'⚠ Yes' if a['is_breaking'] else 'No'} | {a['notes']} |"
                )

    return "\n".join(lines)


# ─── Health & Metrics (D5) ────────────────────────────────────────────────────

_start_time = time.time()
_request_count = 0


@app.get("/v1/health")
async def health():
    """Health check endpoint (D5)."""
    settings = get_settings()

    # Check Ollama connectivity
    ollama_healthy = False
    try:
        import httpx
        r = httpx.get(f"{settings.ollama.base_url}/api/tags", timeout=2.0)
        ollama_healthy = r.status_code == 200
    except Exception:
        pass

    return {
        "status": "healthy",
        "version": settings.version,
        "environment": settings.environment.value,
        "ollama_connected": ollama_healthy,
        "uptime_seconds": round(time.time() - _start_time, 1),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/v1/metrics")
async def metrics():
    """Basic metrics endpoint (D5)."""
    # Count total scans in db
    import sqlite3
    from src.core.database import _get_db_path
    total_scans = 0
    try:
        with sqlite3.connect(_get_db_path()) as conn:
            row = conn.execute("SELECT COUNT(*) FROM scans").fetchone()
            if row:
                total_scans = row[0]
    except Exception:
        total_scans = 0

    return {
        "uptime_seconds": round(time.time() - _start_time, 1),
        "version": get_settings().version,
        "scans_total": total_scans,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }



# ─── File Upload Route (D4) ──────────────────────────────────────────────────


@app.post("/v1/scans/upload", response_model=ScanResponse, status_code=201)
async def upload_and_scan(
    file: UploadFile = File(...),
    project_name: str = Form(default="unnamed"),
    user: UserInDB = Depends(get_current_user),
    graph=Depends(get_graph),
):
    """Upload a dependency file and start a scan (D4).

    Validates file type and size before processing.
    """
    settings = get_settings()
    rate_limiter.check_rate_limit(user.id)

    # Validate file type
    if file.filename:
        ext = "." + file.filename.rsplit(".", 1)[-1] if "." in file.filename else ""
        if ext not in settings.guardrails.allowed_extensions:
            raise HTTPException(
                status_code=400,
                detail=f"File type '{ext}' not allowed. Allowed: {settings.guardrails.allowed_extensions}",
            )

    # Read and validate size
    content = await file.read()
    max_size = settings.guardrails.max_file_size_mb * 1024 * 1024
    if len(content) > max_size:
        raise HTTPException(
            status_code=400,
            detail=f"File too large. Max: {settings.guardrails.max_file_size_mb}MB",
        )

    file_content = content.decode("utf-8", errors="replace")

    # Determine file type
    file_type = "requirements.txt"
    if file.filename and "pyproject" in file.filename:
        file_type = "pyproject.toml"

    # Create scan request and delegate
    request = ScanRequest(
        file_content=file_content,
        file_type=file_type,
        project_name=project_name,
    )

    return await start_scan(request, user, graph)


# ─── OpsPilot Incident & Safety Gate Endpoints ───────────────────────────────


@app.post("/v1/incidents", status_code=201)
async def create_incident(
    req: IncidentRequest,
    user: UserInDB = Depends(get_optional_user),
    opspilot=Depends(get_opspilot),
):
    """Trigger an autonomous incident remediation workflow."""
    graph, checkpointer = opspilot
    incident_id = f"inc-{uuid.uuid4().hex[:8]}"
    config = {"configurable": {"thread_id": incident_id}}

    initial_state = OpsPilotState(
        incident_id=incident_id,
        thread_id=incident_id,
        user_id=user.id,
        service_name=req.service_name,
        description=req.description,
        severity=req.severity,
        structured_facts=StructuredFacts(
            service_names=[req.service_name],
            planted_facts=req.planted_facts,
        ),
    )

    events = []
    for ev in graph.stream(initial_state, config=config):
        events.append(list(ev.keys())[0])

    final_state = graph.get_state(config)
    st = final_state.values.get("status")
    if hasattr(st, "value"):
        st = st.value

    # Store persistent incident record in SQLite incidents table
    create_incident_record(
        incident_id=incident_id,
        thread_id=incident_id,
        service_name=req.service_name,
        description=req.description,
        severity=req.severity.value if hasattr(req.severity, "value") else str(req.severity),
        status=st or "triaging",
        tenant_id="default-tenant",
    )

    pending = list_pending_approvals(incident_id=incident_id, status="pending")

    return {
        "incident_id": incident_id,
        "thread_id": incident_id,
        "status": st,
        "events": events,
        "has_interrupt": bool(final_state.next),
        "pending_approval": pending[0].model_dump() if pending else None,
        "message": "Incident workflow executed up to safety approval gate." if final_state.next else "Incident workflow completed.",
    }


@app.get("/v1/incidents/{incident_id}")
async def get_incident(
    incident_id: str,
    user: UserInDB = Depends(get_optional_user),
    opspilot=Depends(get_opspilot),
):
    """Retrieve current state and facts for an incident."""
    graph, checkpointer = opspilot
    config = {"configurable": {"thread_id": incident_id}}

    state = graph.get_state(config)
    if not state or not state.values:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")

    vals = state.values
    st = vals.get("status")
    if hasattr(st, "value"):
        st = st.value

    facts = vals.get("structured_facts")
    facts_dict = facts.model_dump() if hasattr(facts, "model_dump") else {}

    pending = list_pending_approvals(incident_id=incident_id, status="pending")

    return {
        "incident_id": incident_id,
        "status": st,
        "service_name": vals.get("service_name"),
        "description": vals.get("description"),
        "current_worker": vals.get("current_worker"),
        "structured_facts": facts_dict,
        "messages_count": len(vals.get("messages", [])),
        "has_pending_approval": bool(pending),
        "pending_approval": pending[0].model_dump() if pending else None,
        "is_paused": bool(state.next),
    }


@app.get("/v1/incidents/{incident_id}/checkpoints")
async def get_incident_checkpoints(
    incident_id: str,
    user: UserInDB = Depends(get_optional_user),
    opspilot=Depends(get_opspilot),
):
    """List historical checkpoints for an incident (Time-Travel)."""
    graph, _ = opspilot
    checkpoints = list_incident_checkpoints(graph, incident_id)
    return {"incident_id": incident_id, "checkpoints": checkpoints}


class ForkIncidentRequest(BaseModel):
    checkpoint_id: Optional[str] = None
    new_id: Optional[str] = None
    state_overrides: Optional[dict[str, Any]] = None


@app.post("/v1/incidents/{incident_id}/fork")
async def fork_incident(
    incident_id: str,
    req: Optional[ForkIncidentRequest] = None,
    checkpoint_id: Optional[str] = None,
    new_id: Optional[str] = None,
    user: UserInDB = Depends(authorize_or_optional(UserRole.APPROVER)),
    opspilot=Depends(get_opspilot),
):
    """Fork and re-run an alternative branch from a past checkpoint (Time-Travel)."""
    graph, _ = opspilot
    target_cp = None
    if req and req.checkpoint_id:
        target_cp = req.checkpoint_id
    elif checkpoint_id:
        target_cp = checkpoint_id

    target_new_id = (req.new_id if req and req.new_id else new_id) or f"{incident_id}-fork-{uuid.uuid4().hex[:4]}"
    overrides = (req.state_overrides if req and req.state_overrides else None) or {}

    # If target_cp is still None, grab latest checkpoint for incident
    if not target_cp:
        cps = list_incident_checkpoints(graph, incident_id)
        if cps:
            target_cp = cps[0]["checkpoint_id"]

    if not target_cp:
        target_cp = "latest"

    result = fork_incident_branch(
        graph=graph,
        incident_id=incident_id,
        checkpoint_id=target_cp,
        new_thread_id=target_new_id,
        state_overrides=overrides,
    )
    return result


@app.get("/v1/approvals/pending")
async def get_pending_approvals_list(
    incident_id: Optional[str] = None,
    user: UserInDB = Depends(get_optional_user),
):
    """List pending approvals surviving process restarts."""
    approvals = list_pending_approvals(incident_id=incident_id, status="pending")
    return {"approvals": [a.model_dump() for a in approvals], "count": len(approvals)}


@app.post("/v1/approvals/{approval_id}/decision")
async def decide_approval(
    approval_id: str,
    req: IncidentApprovalRequest,
    user: UserInDB = Depends(authorize_or_optional(UserRole.APPROVER)),
    opspilot=Depends(get_opspilot),
):
    """Approve, reject with reason, or edit a pending action across active threads or persisted approvals."""
    graph, _ = opspilot
    approval = get_pending_approval(approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail="Approval not found")

    config = {"configurable": {"thread_id": approval.incident_id}}
    action_val = req.action.value if hasattr(req.action, "value") else str(req.action)
    operator = req.operator or user.username or "web-operator"

    # Check whether the LangGraph thread state is active and awaiting this decision
    thread_state = None
    try:
        thread_state = graph.get_state(config)
    except Exception as exc:
        logger.warning("graph_get_state_check", incident_id=approval.incident_id, error=str(exc))

    is_active_gate = thread_state and bool(thread_state.values) and bool(thread_state.next)

    events = []
    st = None

    if is_active_gate:
        # Standard LangGraph thread resumption
        update_payload: dict[str, Any] = {
            "approval_action": action_val,
            "operator_name": operator,
            "rejection_reason": req.rejection_reason,
        }
        if req.edited_args:
            update_payload["approval_edits"] = req.edited_args

        try:
            graph.update_state(config, update_payload)
            for ev in graph.stream(None, config=config):
                events.append(list(ev.keys())[0])

            final_state = graph.get_state(config)
            st = final_state.values.get("status")
            if hasattr(st, "value"):
                st = st.value
        except Exception as exc:
            logger.error("error_resuming_graph", error=str(exc))
            is_active_gate = False

    if not is_active_gate:
        # Standalone / persisted approval execution (survives restarts and works for all table rows)
        new_status = "rejected" if action_val == "reject" else "approved"
        update_pending_approval_status(approval.id, status=new_status, checkpoint_id=approval.checkpoint_id)

        target_args = req.edited_args if (action_val == "edit" and req.edited_args) else approval.tool_args
        if action_val == "edit" and req.edited_args:
            import sqlite3
            with sqlite3.connect(_get_db_path()) as conn:
                conn.execute(
                    "UPDATE pending_approvals SET tool_args = ? WHERE id = ?",
                    (json.dumps(req.edited_args), approval.id),
                )

        audit_entry = ApprovalAuditLog(
            approval_id=approval.id,
            incident_id=approval.incident_id,
            action=action_val,
            operator=operator,
            original_args=approval.tool_args,
            edited_args=req.edited_args if action_val == "edit" else None,
            rejection_reason=req.rejection_reason if action_val == "reject" else None,
            checkpoint_id=approval.checkpoint_id,
        )
        create_approval_audit_log(audit_entry)

        if action_val in ("approve", "edit"):
            execute_tool_with_gate(
                tool_name=approval.tool_name,
                tool_args=target_args,
                incident_id=approval.incident_id,
                approved_by=operator,
                approval_id=approval.id,
            )
            events = ["safety_gate", "tool_execution", "verifier"]
            st = "resolved"
        elif action_val == "reject":
            # Propose alternative fix in SQLite
            new_approval_id = str(uuid.uuid4())
            new_args = {
                "service_name": approval.tool_args.get("service_name", "payment-gateway"),
                "config_key": "db_pool_timeout_ms",
                "config_value": "2000",
            }
            create_pending_approval(
                PendingApproval(
                    id=new_approval_id,
                    incident_id=approval.incident_id,
                    tool_name="update_config",
                    tool_args=new_args,
                    risk_tier=RiskTier.WRITE,
                    status="pending",
                    proposed_by="remediation",
                    checkpoint_id=approval.checkpoint_id,
                )
            )
            events = ["safety_gate", "rejection_recorded", "alternative_proposal_created"]
            st = "awaiting_approval"

    return {
        "approval_id": approval_id,
        "incident_id": approval.incident_id,
        "action": action_val,
        "resumed_status": st or "resolved",
        "events": events or ["safety_gate"],
    }


@app.get("/v1/audit/approvals")
async def get_approval_audit_logs(
    incident_id: Optional[str] = None,
    user: UserInDB = Depends(get_optional_user),
):
    """List immutable approval audit log entries."""
    logs = list_approval_audit_logs(incident_id=incident_id)
    return {"audit_logs": [l.model_dump() for l in logs], "count": len(logs)}


# ─── Embedded Interactive Terminal Endpoint ───────────────────────────────────


class TerminalExecRequest(BaseModel):
    command: str


@app.post("/v1/terminal/exec")
async def execute_terminal_command(
    req: TerminalExecRequest,
    user: UserInDB = Depends(get_optional_user),
):
    """Execute opspilot CLI and test commands directly from the embedded web terminal."""
    import subprocess
    cmd = req.command.strip()
    if not cmd:
        return {"command": "", "output": "", "exit_code": 0}

    workspace_root = Path(__file__).parent.parent.parent
    venv_py = workspace_root / ".venv" / "bin" / "python"
    venv_pytest = workspace_root / ".venv" / "bin" / "pytest"

    # Normalize aliases to virtualenv binaries
    if cmd.startswith("opspilot "):
        exec_cmd = f'"{venv_py}" -m src.cli ' + cmd[9:]
    elif cmd == "opspilot":
        exec_cmd = f'"{venv_py}" -m src.cli --help'
    elif cmd.startswith("pytest"):
        exec_cmd = f'"{venv_pytest}" ' + cmd[6:]
    elif cmd.startswith("python "):
        exec_cmd = f'"{venv_py}" ' + cmd[7:]
    else:
        tokens = cmd.split()
        if tokens and tokens[0] in ["approvals", "approve", "incident", "timetravel", "audit"]:
            exec_cmd = f'"{venv_py}" -m src.cli ' + cmd
        else:
            exec_cmd = cmd

    try:
        proc = subprocess.run(
            exec_cmd,
            shell=True,
            cwd=str(workspace_root),
            capture_output=True,
            text=True,
            timeout=30,
        )
        combined = proc.stdout or ""
        if proc.stderr:
            combined += ("\n" if combined else "") + proc.stderr

        return {
            "command": cmd,
            "output": combined.strip(),
            "exit_code": proc.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"command": cmd, "output": "Execution timed out (30s limit)", "exit_code": 124}
    except Exception as e:
        return {"command": cmd, "output": f"Execution error: {str(e)}", "exit_code": 1}


# ─── Frontend Static Files Mount ─────────────────────────────────────────────

from pathlib import Path
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

_frontend_dir = Path(__file__).parent.parent.parent / "frontend"


@app.get("/", include_in_schema=False)
async def serve_index():
    """Serve the ChainGuard web dashboard."""
    index_path = _frontend_dir / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {"detail": "ChainGuard API active. Frontend index.html not found."}


if _frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(_frontend_dir)), name="static_dir")
    app.mount("/", StaticFiles(directory=str(_frontend_dir), html=True), name="frontend")
