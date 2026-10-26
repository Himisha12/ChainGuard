"""Pydantic v2 schemas for all ChainGuard data structures.

Strict typing with model_config and Field constraints throughout (D6).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, model_validator


# ─── Enums ────────────────────────────────────────────────────────────────────


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class ScanStatus(str, Enum):
    """Scan lifecycle states."""

    PENDING = "pending"
    PARSING = "parsing"
    ANALYZING = "analyzing"
    PLANNING = "planning"
    VERIFYING = "verifying"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    COMPLETED = "completed"
    FAILED = "failed"


class UserRole(str, Enum):
    """RBAC roles (D5)."""

    VIEWER = "viewer"
    ANALYST = "analyst"
    APPROVER = "approver"


class ApprovalAction(str, Enum):
    """HITL approval actions (D20)."""

    APPROVE = "approve"
    REJECT = "reject"
    EDIT = "edit"


class RiskTier(str, Enum):
    """Risk tier for tools determining approval gate requirement (D20)."""

    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"


class IncidentStatus(str, Enum):
    """Lifecycle states for OpsPilot incident remediation."""

    TRIAGING = "triaging"
    ANALYZING = "analyzing"
    REMEDIATING = "remediating"
    AWAITING_APPROVAL = "awaiting_approval"
    VERIFYING = "verifying"
    RESOLVED = "resolved"
    FAILED = "failed"
    ESCALATED = "escalated"


# ─── Dependency Models ────────────────────────────────────────────────────────


class ParsedDependency(BaseModel):
    """A single parsed dependency from a requirements file."""

    model_config = {"strict": True}

    name: str = Field(..., min_length=1, description="Package name")
    current_version: str = Field(..., description="Currently installed version specifier")
    extras: list[str] = Field(default_factory=list, description="Optional extras")
    source_file: str = Field(..., description="File this dependency was parsed from")
    line_number: int = Field(..., ge=1, description="Line number in source file")


class Vulnerability(BaseModel):
    """A known vulnerability for a package."""

    model_config = {"strict": True}

    vuln_id: str = Field(..., description="Vulnerability ID (e.g. CVE-2024-1234)")
    package_name: str = Field(..., description="Affected package name")
    affected_versions: str = Field(..., description="Affected version range")
    fixed_version: Optional[str] = Field(None, description="Version that fixes the issue")
    severity: Severity = Field(default=Severity.UNKNOWN, description="Severity level")
    description: str = Field(default="", description="Vulnerability description")
    source: str = Field(default="bundled", description="Data source (bundled, osv, etc.)")
    cvss_score: Optional[float] = Field(
        None, ge=0.0, le=10.0, description="CVSS score if available"
    )


class RiskAssessment(BaseModel):
    """Risk assessment for a vulnerability finding."""

    model_config = {"strict": True}

    risk_score: float = Field(..., ge=0.0, le=10.0, description="Computed risk score (0-10)")
    risk_level: Severity = Field(..., description="Risk level classification")
    reasoning: str = Field(..., description="Agent's reasoning for the risk score")
    is_breaking_change: bool = Field(
        default=False, description="Whether the fix introduces breaking changes"
    )
    affected_dependents: list[str] = Field(
        default_factory=list, description="Packages depending on the affected package"
    )


class Finding(BaseModel):
    """A complete finding: dependency + vulnerability + risk assessment."""

    model_config = {"strict": True}

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Finding ID")
    dependency: ParsedDependency
    vulnerability: Vulnerability
    risk_assessment: Optional[RiskAssessment] = None
    recommended_version: Optional[str] = Field(None, description="Recommended upgrade version")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class UpgradeAction(BaseModel):
    """A proposed upgrade action."""

    model_config = {"strict": True}

    package_name: str = Field(..., description="Package to upgrade")
    from_version: str = Field(..., description="Current version")
    to_version: str = Field(..., description="Proposed target version")
    finding_ids: list[str] = Field(
        default_factory=list, description="Finding IDs this upgrade addresses"
    )
    is_breaking: bool = Field(default=False, description="Whether this is a breaking change")
    notes: str = Field(default="", description="Additional notes from the planner")


class UpgradePlan(BaseModel):
    """Complete upgrade plan requiring HITL approval."""

    model_config = {"strict": True}

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Plan ID")
    actions: list[UpgradeAction] = Field(default_factory=list, description="Ordered upgrade steps")
    risk_summary: str = Field(default="", description="Summary of overall risk")
    total_findings: int = Field(default=0, ge=0, description="Total findings addressed")
    estimated_effort: str = Field(default="unknown", description="Estimated effort to apply")
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ─── API Models ───────────────────────────────────────────────────────────────


class ScanRequest(BaseModel):
    """Request to initiate a scan."""

    file_content: str = Field(..., min_length=1, description="Contents of the dependency file")
    file_type: str = Field(
        default="requirements.txt",
        description="Type of dependency file",
    )
    project_name: str = Field(default="unnamed", description="Project name for tracking")


class ScanResponse(BaseModel):
    """Response from initiating a scan."""

    scan_id: str = Field(..., description="Unique scan identifier")
    thread_id: str = Field(..., description="LangGraph thread ID for resumption")
    status: ScanStatus = Field(default=ScanStatus.PENDING)
    message: str = Field(default="Scan initiated")


class ApprovalRequest(BaseModel):
    """HITL approval/rejection request (D20)."""

    action: ApprovalAction = Field(..., description="Approval action")
    feedback: str = Field(default="", description="Feedback if rejecting or editing")
    edited_plan: Optional[UpgradePlan] = Field(
        None, description="Edited plan if action is EDIT"
    )


class ScanResult(BaseModel):
    """Complete scan result."""

    scan_id: str
    status: ScanStatus
    findings: list[Finding] = Field(default_factory=list)
    upgrade_plan: Optional[UpgradePlan] = None
    token_usage: TokenUsage = Field(default_factory=lambda: TokenUsage())
    trace: list[TraceEntry] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None


# ─── Observability Models ─────────────────────────────────────────────────────


class TokenUsage(BaseModel):
    """Token and latency tracking per scan (D10)."""

    total_prompt_tokens: int = Field(default=0, ge=0)
    total_completion_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)
    total_latency_ms: float = Field(default=0.0, ge=0.0)
    node_breakdown: dict[str, NodeTokenUsage] = Field(default_factory=dict)


class NodeTokenUsage(BaseModel):
    """Token usage for a single graph node."""

    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)
    latency_ms: float = Field(default=0.0, ge=0.0)
    invocations: int = Field(default=0, ge=0)


class TraceEntry(BaseModel):
    """A single trace entry for the agent execution trace."""

    node: str = Field(..., description="Graph node name")
    action: str = Field(..., description="What happened")
    detail: str = Field(default="", description="Detail or observation")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    tokens_used: int = Field(default=0, ge=0)
    latency_ms: float = Field(default=0.0, ge=0.0)


# ─── Auth Models ──────────────────────────────────────────────────────────────


class UserCreate(BaseModel):
    """User registration."""

    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    role: UserRole = Field(default=UserRole.VIEWER)


class UserInDB(BaseModel):
    """User stored in database."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    hashed_password: str
    role: UserRole = Field(default=UserRole.VIEWER)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = True


class TokenResponse(BaseModel):
    """JWT token response."""

    access_token: str
    token_type: str = "bearer"
    role: UserRole
    username: str


# ─── OpsPilot Incident Models ─────────────────────────────────────────────────


class StructuredFacts(BaseModel):
    """Immutable structured facts preserved across summarization.

    Guarantees timestamps, service names, hypotheses, and key metrics are
    never dropped even when dialogue history is compressed.
    """

    model_config = {"strict": False}

    timestamps: dict[str, str] = Field(
        default_factory=dict, description="Crucial incident milestones (e.g. alert_fired, detection)"
    )
    service_names: list[str] = Field(
        default_factory=list, description="All affected service names"
    )
    hypotheses: list[str] = Field(
        default_factory=list, description="Active and tested root cause hypotheses"
    )
    metrics: dict[str, Any] = Field(
        default_factory=dict, description="Observed metric values (error rate, p99 latency)"
    )
    planted_facts: dict[str, str] = Field(
        default_factory=dict, description="Specific verification facts for fact-retention evaluation"
    )

    def to_structured_block(self) -> str:
        """Render facts into an unalterable markdown structured block."""
        lines = [
            "### [STRUCTURED INCIDENT FACTS - PRESERVED ACROSS COMPACTION]",
            f"- Services: {', '.join(self.service_names) if self.service_names else 'None'}",
            "- Timestamps: " + (", ".join(f"{k}={v}" for k, v in self.timestamps.items()) if self.timestamps else "None"),
            "- Hypotheses: " + (", ".join(self.hypotheses) if self.hypotheses else "None"),
            "- Metrics: " + (", ".join(f"{k}={v}" for k, v in self.metrics.items()) if self.metrics else "None"),
        ]
        if self.planted_facts:
            lines.append("- Planted Retention Facts:")
            for k, v in sorted(self.planted_facts.items()):
                lines.append(f"  * {k}: {v}")
        return "\n".join(lines)


class PendingApproval(BaseModel):
    """Approval request stored in SQLite to survive restarts."""

    model_config = {"strict": False}

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = Field(..., description="Thread / incident identifier")
    tenant_id: str = Field(default="default-tenant", description="Tenant isolation identifier")
    tool_name: str = Field(..., description="Action to execute (e.g. rollback_deploy)")
    tool_args: dict[str, Any] = Field(default_factory=dict)
    risk_tier: RiskTier = Field(..., description="WRITE or DESTRUCTIVE")
    status: str = Field(default="pending", description="pending | approved | rejected | edited")
    proposed_by: str = Field(default="remediation_agent")
    approved_by: Optional[str] = Field(None, description="Username/identity of deciding operator")
    decided_at: Optional[datetime] = Field(None, description="Timestamp when decision was made")
    checkpoint_id: str = Field(default="")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ApprovalAuditLog(BaseModel):
    """Append-only audit trail for every operator approval action."""

    model_config = {"strict": False}

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    approval_id: str
    incident_id: str
    tenant_id: str = Field(default="default-tenant", description="Tenant isolation identifier")
    action: str = Field(..., description="approve | reject | edit")
    operator: str = Field(default="operator")
    original_args: dict[str, Any] = Field(default_factory=dict)
    edited_args: Optional[dict[str, Any]] = None
    rejection_reason: Optional[str] = None
    checkpoint_id: str = Field(default="")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class IncidentRecord(BaseModel):
    """Persistent incident lifecycle record stored in SQLite."""

    model_config = {"strict": False}

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    thread_id: str = Field(..., description="LangGraph thread identifier")
    service_name: str = Field(..., description="Target service under remediation")
    description: str = Field(..., description="Incident description / error symptom")
    severity: Severity = Field(default=Severity.HIGH)
    status: IncidentStatus = Field(default=IncidentStatus.TRIAGING)
    tenant_id: str = Field(default="default-tenant")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class PastIncident(BaseModel):
    """Historical resolved incident for cross-incident memory lookup."""

    model_config = {"strict": False}

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str
    service_name: str
    title: str
    symptoms: str
    root_cause: str
    remediation_action: str
    resolution_summary: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class IncidentRequest(BaseModel):
    """Payload to trigger an OpsPilot incident workflow."""

    service_name: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    severity: Severity = Field(default=Severity.HIGH)
    planted_facts: dict[str, str] = Field(default_factory=dict)


class IncidentApprovalRequest(BaseModel):
    """Operator action on a pending tool approval."""

    action: ApprovalAction
    rejection_reason: Optional[str] = None
    edited_args: Optional[dict[str, Any]] = None
    operator: str = "operator"


# ─── Forward reference update ─────────────────────────────────────────────────

# Rebuild models that have forward references
ScanResult.model_rebuild()

