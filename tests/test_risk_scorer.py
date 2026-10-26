"""Tests for risk scoring engine (D10)."""

from __future__ import annotations

import pytest

from src.models.schemas import ParsedDependency, Severity, Vulnerability
from src.tools.risk_scorer import (
    _check_breaking_change,
    _score_to_severity,
    _severity_to_score,
    compute_risk_score,
)


class TestBreakingChangeDetection:
    """Test semver breaking change heuristics."""

    def test_major_version_bump_is_breaking(self) -> None:
        assert _check_breaking_change("1.9.0", "2.0.0") is True
        assert _check_breaking_change("==2.3.0", "3.0.0") is True
        assert _check_breaking_change(">=0.14.0", "1.0.0") is True

    def test_minor_or_patch_bump_is_not_breaking(self) -> None:
        assert _check_breaking_change("2.3.0", "2.3.1") is False
        assert _check_breaking_change("2.2.0", "2.3.0") is False

    def test_unknown_or_missing_version(self) -> None:
        assert _check_breaking_change("*", "2.0.0") is False
        assert _check_breaking_change("2.0.0", None) is False


class TestRiskScoreComputation:
    """Test composite risk score calculation."""

    def test_high_cvss_calculation(self) -> None:
        dep = ParsedDependency(
            name="flask",
            current_version="2.0.0",
            source_file="requirements.txt",
            line_number=1,
        )
        vuln = Vulnerability(
            vuln_id="CVE-2023-30861",
            package_name="flask",
            affected_versions="<2.3.2",
            fixed_version="2.3.2",
            severity=Severity.HIGH,
            cvss_score=7.5,
        )
        assessment = compute_risk_score(dep, vuln, dependent_count=0)
        assert assessment.risk_score >= 7.0
        assert assessment.risk_level in (Severity.HIGH, Severity.CRITICAL)
        assert "Base CVSS: 7.5" in assessment.reasoning

    def test_fanout_multiplier_increases_score(self) -> None:
        dep = ParsedDependency(
            name="urllib3",
            current_version="1.26.4",
            source_file="requirements.txt",
            line_number=5,
        )
        vuln = Vulnerability(
            vuln_id="CVE-2023-43804",
            package_name="urllib3",
            affected_versions="<1.26.5",
            fixed_version="1.26.5",
            severity=Severity.MEDIUM,
            cvss_score=5.0,
        )
        score_no_fanout = compute_risk_score(dep, vuln, dependent_count=0).risk_score
        score_with_fanout = compute_risk_score(dep, vuln, dependent_count=4).risk_score
        assert score_with_fanout > score_no_fanout

    def test_breaking_bump_adds_penalty(self) -> None:
        dep = ParsedDependency(
            name="django",
            current_version="3.2.0",
            source_file="requirements.txt",
            line_number=3,
        )
        vuln = Vulnerability(
            vuln_id="CVE-2024-27351",
            package_name="django",
            affected_versions="<4.2.11",
            fixed_version="4.2.11",  # Major bump 3 -> 4
            severity=Severity.HIGH,
            cvss_score=7.5,
        )
        assessment = compute_risk_score(dep, vuln, dependent_count=0)
        assert assessment.is_breaking_change is True
        assert "Major version bump detected" in assessment.reasoning
