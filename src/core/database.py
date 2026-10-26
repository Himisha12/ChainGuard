"""SQLite database layer for scan history and user management (D4, D18).

Provides:
- User CRUD with password hashing
- Scan history with pagination
- Indexes for performance (D4)
- Tenant isolation (D3)
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import bcrypt

from src.core.config import get_settings
from src.models.schemas import (
    ApprovalAuditLog,
    IncidentRecord,
    IncidentStatus,
    PastIncident,
    PendingApproval,
    RiskTier,
    ScanResult,
    ScanStatus,
    UserCreate,
    UserInDB,
    UserRole,
)

import structlog

logger = structlog.get_logger(__name__)


def hash_password(password: str) -> str:
    """Hash password using bcrypt with 72-byte truncation safety."""
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify password against bcrypt hash."""
    try:
        pwd_bytes = plain.encode("utf-8")[:72]
        return bcrypt.checkpw(pwd_bytes, hashed.encode("utf-8"))
    except Exception:
        return False


def _get_db_path() -> str:
    """Get the database file path."""
    settings = get_settings()
    db_path = settings.data_dir / "chainguard.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return str(db_path)


def init_db() -> None:
    """Initialize the database schema with indexes."""
    db_path = _get_db_path()

    with sqlite3.connect(db_path) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer',
                created_at TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                thread_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                project_name TEXT NOT NULL DEFAULT 'unnamed',
                status TEXT NOT NULL DEFAULT 'pending',
                file_type TEXT NOT NULL DEFAULT 'requirements.txt',
                file_content TEXT,
                findings_json TEXT,
                upgrade_plan_json TEXT,
                token_usage_json TEXT,
                trace_json TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            -- Incidents table tracking SRE incident lifecycle
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                thread_id TEXT NOT NULL,
                service_name TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'high',
                status TEXT NOT NULL DEFAULT 'triaging',
                tenant_id TEXT NOT NULL DEFAULT 'default-tenant',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            -- Persisted pending approvals table
            -- Surpasses process restarts: approvals survive restarts and can be handled hours later
            CREATE TABLE IF NOT EXISTS pending_approvals (
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL DEFAULT 'default-tenant',
                tool_name TEXT NOT NULL,
                tool_args TEXT NOT NULL,
                risk_tier TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                proposed_by TEXT NOT NULL DEFAULT 'remediation_agent',
                approved_by TEXT DEFAULT NULL,
                decided_at TEXT DEFAULT NULL,
                checkpoint_id TEXT DEFAULT '',
                created_at TEXT NOT NULL
            );

            -- Append-only approval audit log
            CREATE TABLE IF NOT EXISTS approval_audit_log (
                id TEXT PRIMARY KEY,
                approval_id TEXT NOT NULL,
                incident_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL DEFAULT 'default-tenant',
                action TEXT NOT NULL,
                operator TEXT NOT NULL DEFAULT 'operator',
                original_args TEXT NOT NULL,
                edited_args TEXT,
                rejection_reason TEXT,
                checkpoint_id TEXT DEFAULT '',
                timestamp TEXT NOT NULL
            );

            -- Past resolved incidents for cross-incident memory lookup
            CREATE TABLE IF NOT EXISTS past_incidents (
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                service_name TEXT NOT NULL,
                title TEXT NOT NULL,
                symptoms TEXT NOT NULL,
                root_cause TEXT NOT NULL,
                remediation_action TEXT NOT NULL,
                resolution_summary TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            -- Indexes for performance
            CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
            CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
            CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
            CREATE INDEX IF NOT EXISTS idx_scans_thread_id ON scans(thread_id);
            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

            CREATE INDEX IF NOT EXISTS idx_incidents_tenant ON incidents(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
            CREATE INDEX IF NOT EXISTS idx_incidents_thread ON incidents(thread_id);

            CREATE INDEX IF NOT EXISTS idx_pending_approvals_incident_id ON pending_approvals(incident_id);
            CREATE INDEX IF NOT EXISTS idx_pending_approvals_status ON pending_approvals(status);
            CREATE INDEX IF NOT EXISTS idx_approval_audit_incident ON approval_audit_log(incident_id);
            CREATE INDEX IF NOT EXISTS idx_approval_audit_timestamp ON approval_audit_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_past_incidents_service ON past_incidents(service_name);
        """)

        # Seamless SQLite column migrations for existing databases
        cursor = conn.cursor()
        pa_cols = [r[1] for r in cursor.execute("PRAGMA table_info(pending_approvals)").fetchall()]
        if "tenant_id" not in pa_cols:
            cursor.execute("ALTER TABLE pending_approvals ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default-tenant'")
        if "approved_by" not in pa_cols:
            cursor.execute("ALTER TABLE pending_approvals ADD COLUMN approved_by TEXT DEFAULT NULL")
        if "decided_at" not in pa_cols:
            cursor.execute("ALTER TABLE pending_approvals ADD COLUMN decided_at TEXT DEFAULT NULL")

        audit_cols = [r[1] for r in cursor.execute("PRAGMA table_info(approval_audit_log)").fetchall()]
        if "tenant_id" not in audit_cols:
            cursor.execute("ALTER TABLE approval_audit_log ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default-tenant'")
        conn.commit()

    logger.info("database_initialized", path=db_path)


# ─── User Operations ─────────────────────────────────────────────────────────


def create_user(user: UserCreate) -> UserInDB:
    """Create a new user with hashed password.

    SECURITY (D3): The server assigns the role, ignoring any
    client-supplied role to prevent privilege escalation.
    """
    db_path = _get_db_path()
    user_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()

    # CRITICAL (D3): Server assigns role, never trusts client
    # Default new users to VIEWER
    assigned_role = UserRole.VIEWER

    hashed = hash_password(user.password)

    user_in_db = UserInDB(
        id=user_id,
        username=user.username,
        hashed_password=hashed,
        role=assigned_role,
        created_at=datetime.utcnow(),
    )

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO users (id, username, hashed_password, role, created_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, user.username, hashed, assigned_role.value, now),
        )

    logger.info("user_created", user_id=user_id, username=user.username, role=assigned_role.value)
    return user_in_db


def get_user_by_username(username: str) -> Optional[UserInDB]:
    """Look up a user by username."""
    db_path = _get_db_path()

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

    if row is None:
        return None

    return UserInDB(
        id=row["id"],
        username=row["username"],
        hashed_password=row["hashed_password"],
        role=UserRole(row["role"]),
        created_at=datetime.fromisoformat(row["created_at"]),
        is_active=bool(row["is_active"]),
    )


# ─── Scan Operations ─────────────────────────────────────────────────────────


def create_scan(
    scan_id: str,
    thread_id: str,
    user_id: str,
    project_name: str,
    file_type: str,
    file_content: str,
) -> None:
    """Create a new scan record."""
    db_path = _get_db_path()
    now = datetime.utcnow().isoformat()

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """INSERT INTO scans
            (id, thread_id, user_id, project_name, status, file_type, file_content, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, thread_id, user_id, project_name, ScanStatus.PENDING.value, file_type, file_content, now),
        )

    logger.info("scan_created", scan_id=scan_id, user_id=user_id)


def update_scan(
    scan_id: str,
    user_id: str,
    status: Optional[ScanStatus] = None,
    findings_json: Optional[str] = None,
    upgrade_plan_json: Optional[str] = None,
    token_usage_json: Optional[str] = None,
    trace_json: Optional[str] = None,
    completed_at: Optional[str] = None,
) -> None:
    """Update a scan record.

    SECURITY (D3): Requires user_id to enforce tenant isolation.
    """
    db_path = _get_db_path()
    updates: list[str] = []
    params: list[Any] = []

    if status is not None:
        updates.append("status = ?")
        params.append(status.value)
    if findings_json is not None:
        updates.append("findings_json = ?")
        params.append(findings_json)
    if upgrade_plan_json is not None:
        updates.append("upgrade_plan_json = ?")
        params.append(upgrade_plan_json)
    if token_usage_json is not None:
        updates.append("token_usage_json = ?")
        params.append(token_usage_json)
    if trace_json is not None:
        updates.append("trace_json = ?")
        params.append(trace_json)
    if completed_at is not None:
        updates.append("completed_at = ?")
        params.append(completed_at)

    if not updates:
        return

    # CRITICAL (D3): Always filter by user_id for tenant isolation
    query = f"UPDATE scans SET {', '.join(updates)} WHERE id = ? AND user_id = ?"
    params.extend([scan_id, user_id])

    with sqlite3.connect(db_path) as conn:
        conn.execute(query, params)


def get_scan(scan_id: str, user_id: str) -> Optional[dict[str, Any]]:
    """Get a scan by ID, scoped to the user (D3 tenant isolation)."""
    db_path = _get_db_path()

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ? AND user_id = ?",
            (scan_id, user_id),
        ).fetchone()

    if row is None:
        return None

    return dict(row)


def list_scans(
    user_id: str,
    page: int = 1,
    per_page: int = 20,
    status_filter: Optional[ScanStatus] = None,
) -> dict[str, Any]:
    """List scans for a user with pagination (D4).

    Returns paginated results with total count.
    """
    db_path = _get_db_path()
    offset = (page - 1) * per_page

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row

        # Count query
        count_query = "SELECT COUNT(*) FROM scans WHERE user_id = ?"
        count_params: list[Any] = [user_id]
        if status_filter:
            count_query += " AND status = ?"
            count_params.append(status_filter.value)

        total = conn.execute(count_query, count_params).fetchone()[0]

        # Data query
        data_query = "SELECT * FROM scans WHERE user_id = ?"
        data_params: list[Any] = [user_id]
        if status_filter:
            data_query += " AND status = ?"
            data_params.append(status_filter.value)
        data_query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        data_params.extend([per_page, offset])
        rows = conn.execute(data_query, data_params).fetchall()

    scan_dicts = []
    for row in rows:
        d = dict(row)
        d["scan_id"] = d.get("id")
        scan_dicts.append(d)

    return {
        "scans": scan_dicts,
        "items": scan_dicts,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page,
    }


# ─── OpsPilot Approvals & Persistence ─────────────────────────────────────────


def create_pending_approval(approval: PendingApproval) -> PendingApproval:
    """Store a pending approval in SQLite so it survives restarts."""
    db_path = _get_db_path()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """INSERT INTO pending_approvals
            (id, incident_id, tenant_id, tool_name, tool_args, risk_tier, status, proposed_by, approved_by, decided_at, checkpoint_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                approval.id,
                approval.incident_id,
                getattr(approval, "tenant_id", "default-tenant"),
                approval.tool_name,
                json.dumps(approval.tool_args),
                approval.risk_tier.value if hasattr(approval.risk_tier, 'value') else str(approval.risk_tier),
                approval.status,
                approval.proposed_by,
                approval.approved_by,
                approval.decided_at.isoformat() if approval.decided_at else None,
                approval.checkpoint_id,
                approval.created_at.isoformat(),
            ),
        )
    logger.info("pending_approval_created", id=approval.id, incident_id=approval.incident_id, tool=approval.tool_name)
    return approval


def get_pending_approval(approval_id: str) -> Optional[PendingApproval]:
    """Retrieve a single pending approval by ID."""
    db_path = _get_db_path()
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM pending_approvals WHERE id = ?", (approval_id,)).fetchone()
    if not row:
        return None
    r_dict = dict(row)
    decided_at = datetime.fromisoformat(r_dict["decided_at"]) if r_dict.get("decided_at") else None
    return PendingApproval(
        id=r_dict["id"],
        incident_id=r_dict["incident_id"],
        tenant_id=r_dict.get("tenant_id", "default-tenant"),
        tool_name=r_dict["tool_name"],
        tool_args=json.loads(r_dict["tool_args"]),
        risk_tier=RiskTier(r_dict["risk_tier"]),
        status=r_dict["status"],
        proposed_by=r_dict["proposed_by"],
        approved_by=r_dict.get("approved_by"),
        decided_at=decided_at,
        checkpoint_id=r_dict.get("checkpoint_id") or "",
        created_at=datetime.fromisoformat(r_dict["created_at"]),
    )


def list_pending_approvals(
    incident_id: Optional[str] = None,
    status: Optional[str] = "pending",
    tenant_id: Optional[str] = None,
) -> list[PendingApproval]:
    """List pending approvals, optionally filtered by incident_id, status, or tenant_id."""
    db_path = _get_db_path()
    query = "SELECT * FROM pending_approvals WHERE 1=1"
    params: list[Any] = []
    if incident_id:
        query += " AND incident_id = ?"
        params.append(incident_id)
    if status:
        query += " AND status = ?"
        params.append(status)
    if tenant_id:
        query += " AND tenant_id = ?"
        params.append(tenant_id)
    query += " ORDER BY created_at DESC"

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query, params).fetchall()

    approvals = []
    for r in rows:
        r_dict = dict(r)
        decided_at = datetime.fromisoformat(r_dict["decided_at"]) if r_dict.get("decided_at") else None
        approvals.append(
            PendingApproval(
                id=r_dict["id"],
                incident_id=r_dict["incident_id"],
                tenant_id=r_dict.get("tenant_id", "default-tenant"),
                tool_name=r_dict["tool_name"],
                tool_args=json.loads(r_dict["tool_args"]),
                risk_tier=RiskTier(r_dict["risk_tier"]),
                status=r_dict["status"],
                proposed_by=r_dict["proposed_by"],
                approved_by=r_dict.get("approved_by"),
                decided_at=decided_at,
                checkpoint_id=r_dict.get("checkpoint_id") or "",
                created_at=datetime.fromisoformat(r_dict["created_at"]),
            )
        )
    return approvals


def update_pending_approval_status(
    approval_id: str,
    status: str,
    checkpoint_id: str = "",
    approved_by: Optional[str] = None,
) -> None:
    """Update approval state (e.g. approved, rejected, edited) and record decider identity."""
    db_path = _get_db_path()
    now_iso = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(db_path) as conn:
        updates = ["status = ?", "decided_at = ?"]
        params: list[Any] = [status, now_iso]
        if checkpoint_id:
            updates.append("checkpoint_id = ?")
            params.append(checkpoint_id)
        if approved_by:
            updates.append("approved_by = ?")
            params.append(approved_by)
        params.append(approval_id)
        conn.execute(f"UPDATE pending_approvals SET {', '.join(updates)} WHERE id = ?", params)


def create_approval_audit_log(entry: ApprovalAuditLog) -> ApprovalAuditLog:
    """Record append-only operator decision in the audit log."""
    db_path = _get_db_path()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """INSERT INTO approval_audit_log
            (id, approval_id, incident_id, tenant_id, action, operator, original_args, edited_args, rejection_reason, checkpoint_id, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                entry.id,
                entry.approval_id,
                entry.incident_id,
                getattr(entry, "tenant_id", "default-tenant"),
                entry.action,
                entry.operator,
                json.dumps(entry.original_args),
                json.dumps(entry.edited_args) if entry.edited_args else None,
                entry.rejection_reason,
                entry.checkpoint_id,
                entry.timestamp.isoformat(),
            ),
        )
    logger.info("approval_audited", action=entry.action, approval_id=entry.approval_id, operator=entry.operator)
    return entry


def list_approval_audit_logs(
    incident_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> list[ApprovalAuditLog]:
    """Retrieve append-only audit history, optionally filtered by incident or tenant."""
    db_path = _get_db_path()
    query = "SELECT * FROM approval_audit_log WHERE 1=1"
    params: list[Any] = []
    if incident_id:
        query += " AND incident_id = ?"
        params.append(incident_id)
    if tenant_id:
        query += " AND tenant_id = ?"
        params.append(tenant_id)
    query += " ORDER BY timestamp DESC"

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query, params).fetchall()

    return [
        ApprovalAuditLog(
            id=r["id"],
            approval_id=r["approval_id"],
            incident_id=r["incident_id"],
            tenant_id=dict(r).get("tenant_id", "default-tenant"),
            action=r["action"],
            operator=r["operator"],
            original_args=json.loads(r["original_args"]) if r["original_args"] else {},
            edited_args=json.loads(r["edited_args"]) if r["edited_args"] else None,
            rejection_reason=r["rejection_reason"],
            checkpoint_id=r["checkpoint_id"] or "",
            timestamp=datetime.fromisoformat(r["timestamp"]),
        )
        for r in rows
    ]


# ─── Incidents Table Lifecycle CRUD ───────────────────────────────────────────


def create_incident_record(
    incident_id: str,
    thread_id: str,
    service_name: str,
    description: str,
    severity: str = "high",
    status: str = "triaging",
    tenant_id: str = "default-tenant",
) -> IncidentRecord:
    """Create a persistent incident record in SQLite."""
    db_path = _get_db_path()
    now_iso = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """INSERT INTO incidents
            (id, thread_id, service_name, description, severity, status, tenant_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (incident_id, thread_id, service_name, description, severity, status, tenant_id, now_iso, now_iso),
        )
    return IncidentRecord(
        id=incident_id,
        thread_id=thread_id,
        service_name=service_name,
        description=description,
        status=IncidentStatus(status) if status in [s.value for s in IncidentStatus] else IncidentStatus.TRIAGING,
        tenant_id=tenant_id,
    )


def get_incident_record(incident_id: str) -> Optional[dict[str, Any]]:
    """Retrieve an incident record by ID."""
    db_path = _get_db_path()
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    return dict(row) if row else None


def update_incident_status(incident_id: str, status: str) -> None:
    """Update lifecycle status of an incident record."""
    db_path = _get_db_path()
    now_iso = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?",
            (status, now_iso, incident_id),
        )


def list_incident_records(tenant_id: Optional[str] = None) -> list[dict[str, Any]]:
    """List all incidents sorted by creation date."""
    db_path = _get_db_path()
    query = "SELECT * FROM incidents"
    params: list[Any] = []
    if tenant_id:
        query += " WHERE tenant_id = ?"
        params.append(tenant_id)
    query += " ORDER BY created_at DESC"
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


# ─── Past Incidents for Cross-Incident Memory ─────────────────────────────────


def add_past_incident(incident: PastIncident) -> PastIncident:
    """Save resolved incident for cross-incident retrieval."""
    db_path = _get_db_path()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """INSERT INTO past_incidents
            (id, incident_id, service_name, title, symptoms, root_cause, remediation_action, resolution_summary, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                incident.id,
                incident.incident_id,
                incident.service_name,
                incident.title,
                incident.symptoms,
                incident.root_cause,
                incident.remediation_action,
                incident.resolution_summary,
                incident.created_at.isoformat(),
            ),
        )
    return incident


def list_past_incidents(service_name: Optional[str] = None) -> list[PastIncident]:
    """Retrieve past incidents."""
    db_path = _get_db_path()
    query = "SELECT * FROM past_incidents"
    params: list[Any] = []
    if service_name:
        query += " WHERE service_name = ?"
        params.append(service_name)
    query += " ORDER BY created_at DESC"

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query, params).fetchall()

    return [
        PastIncident(
            id=r["id"],
            incident_id=r["incident_id"],
            service_name=r["service_name"],
            title=r["title"],
            symptoms=r["symptoms"],
            root_cause=r["root_cause"],
            remediation_action=r["remediation_action"],
            resolution_summary=r["resolution_summary"],
            created_at=datetime.fromisoformat(r["created_at"]),
        )
        for r in rows
    ]


def search_past_incidents(query: str, service_name: Optional[str] = None) -> list[PastIncident]:
    """Hybrid / keyword lookup: 'Have we seen this before?'"""
    incidents = list_past_incidents(service_name=service_name)
    if not query:
        return incidents[:5]
    terms = [t.lower() for t in query.split() if len(t) > 2]
    scored: list[tuple[float, PastIncident]] = []
    for inc in incidents:
        text = f"{inc.service_name} {inc.title} {inc.symptoms} {inc.root_cause} {inc.remediation_action}".lower()
        score = sum(1.0 for term in terms if term in text)
        if score > 0:
            scored.append((score, inc))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [item[1] for item in scored[:5]]

