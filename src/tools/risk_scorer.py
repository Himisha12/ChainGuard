"""Risk scoring tool for vulnerability assessment (D10).

Computes a composite risk score based on CVSS, version gap,
dependency graph position, and breaking-change likelihood.
"""

from __future__ import annotations

from src.models.schemas import (
    Finding,
    ParsedDependency,
    RiskAssessment,
    Severity,
    Vulnerability,
)


def compute_risk_score(
    dependency: ParsedDependency,
    vulnerability: Vulnerability,
    dependent_count: int = 0,
) -> RiskAssessment:
    """Compute a risk assessment for a vulnerability finding.

    Factors:
    - CVSS score (0-10): direct severity
    - Version gap: distance between current and fixed version
    - Dependency fanout: how many packages depend on this one
    - Breaking change heuristic: major version bump = likely breaking

    Args:
        dependency: The parsed dependency.
        vulnerability: The vulnerability found.
        dependent_count: Number of packages that depend on this one.

    Returns:
        RiskAssessment with score, level, and reasoning.
    """
    # Base score from CVSS
    base_score = vulnerability.cvss_score if vulnerability.cvss_score else _severity_to_score(
        vulnerability.severity
    )

    # Adjust for dependency fanout
    fanout_multiplier = min(1.0 + (dependent_count * 0.1), 1.5)

    # Check for breaking changes (major version bump)
    is_breaking = _check_breaking_change(
        dependency.current_version, vulnerability.fixed_version
    )
    breaking_penalty = 0.5 if is_breaking else 0.0

    # Compute final score
    final_score = min(10.0, (base_score * fanout_multiplier) + breaking_penalty)
    final_score = round(final_score, 1)

    # Determine risk level
    risk_level = _score_to_severity(final_score)

    # Build reasoning
    reasoning_parts = [
        f"Base CVSS: {base_score:.1f}",
        f"Dependency fanout: {dependent_count} dependents (×{fanout_multiplier:.1f})",
    ]
    if is_breaking:
        reasoning_parts.append("Major version bump detected — likely breaking change (+0.5)")
    reasoning_parts.append(f"Final risk score: {final_score:.1f} ({risk_level.value})")

    return RiskAssessment(
        risk_score=final_score,
        risk_level=risk_level,
        reasoning=". ".join(reasoning_parts),
        is_breaking_change=is_breaking,
        affected_dependents=[],  # Populated later by knowledge graph
    )


def _severity_to_score(severity: Severity) -> float:
    """Convert severity enum to a base score."""
    mapping = {
        Severity.CRITICAL: 9.5,
        Severity.HIGH: 7.5,
        Severity.MEDIUM: 5.0,
        Severity.LOW: 2.5,
        Severity.UNKNOWN: 5.0,
    }
    return mapping.get(severity, 5.0)


def _score_to_severity(score: float) -> Severity:
    """Convert a numeric score to severity level."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _check_breaking_change(current_version: str, fixed_version: str | None) -> bool:
    """Heuristic: major version bump = likely breaking change."""
    if not fixed_version or current_version in ("*", "editable", ""):
        return False

    try:
        from packaging.version import Version

        # Extract just the version number from specifier
        current_clean = current_version.lstrip(">=<~!=").split(",")[0].strip()
        current_v = Version(current_clean)
        fixed_v = Version(fixed_version)
        return fixed_v.major > current_v.major
    except Exception:
        return False
