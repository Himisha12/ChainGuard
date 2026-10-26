"""Tests for vulnerability lookup tool (D2, D10)."""

from __future__ import annotations

import pytest

from src.models.schemas import Severity
from src.tools.vuln_lookup import (
    _is_version_affected,
    _severity_from_cvss,
    lookup_vulnerabilities,
)


class TestSeverityMapping:
    """Test CVSS to Severity enum conversion."""

    def test_critical(self) -> None:
        assert _severity_from_cvss(9.5) == Severity.CRITICAL
        assert _severity_from_cvss(9.0) == Severity.CRITICAL

    def test_high(self) -> None:
        assert _severity_from_cvss(8.2) == Severity.HIGH
        assert _severity_from_cvss(7.0) == Severity.HIGH

    def test_medium(self) -> None:
        assert _severity_from_cvss(5.5) == Severity.MEDIUM
        assert _severity_from_cvss(4.0) == Severity.MEDIUM

    def test_low(self) -> None:
        assert _severity_from_cvss(2.1) == Severity.LOW

    def test_none_or_unknown(self) -> None:
        assert _severity_from_cvss(None) == Severity.UNKNOWN


class TestVersionAffected:
    """Test version range matching."""

    def test_version_in_range(self) -> None:
        assert _is_version_affected("2.0.0", "<2.3.2") is True
        assert _is_version_affected("1.25.0", "<1.26.5") is True

    def test_version_out_of_range(self) -> None:
        assert _is_version_affected("3.0.0", "<2.3.2") is False

    def test_wildcard_or_empty(self) -> None:
        assert _is_version_affected("*", "<2.0.0") is True
        assert _is_version_affected("", "<2.0.0") is True
        assert _is_version_affected("editable", "<2.0.0") is True


class TestBundledLookup:
    """Test vulnerability lookup against the bundled database."""

    def test_known_vulnerable_requests(self) -> None:
        vulns = lookup_vulnerabilities("requests", "2.25.0")
        assert len(vulns) > 0
        cve_ids = [v.vuln_id for v in vulns]
        assert "CVE-2023-32681" in cve_ids
        assert vulns[0].package_name == "requests"

    def test_clean_package_no_vulns(self) -> None:
        vulns = lookup_vulnerabilities("nonexistent-safe-pkg", "1.0.0")
        assert len(vulns) == 0

    def test_case_insensitivity(self) -> None:
        vulns_upper = lookup_vulnerabilities("Flask", "2.0.0")
        vulns_lower = lookup_vulnerabilities("flask", "2.0.0")
        assert len(vulns_upper) == len(vulns_lower)
        assert len(vulns_upper) > 0
