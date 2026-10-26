"""Vulnerability lookup tool using bundled JSON data (D2, D10).

Offline-first with bundled vulnerability database. Optional live OSV.dev
lookup behind a feature flag.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from src.core.config import get_settings
from src.models.schemas import Severity, Vulnerability

# Path to bundled vulnerability data
VULN_DB_PATH = Path(__file__).parent.parent.parent / "data" / "vuln_db.json"


def _load_bundled_db() -> dict[str, list[dict[str, Any]]]:
    """Load the bundled vulnerability database."""
    if not VULN_DB_PATH.exists():
        return {}
    with open(VULN_DB_PATH) as f:
        return json.load(f)


def _severity_from_cvss(score: float | None) -> Severity:
    """Convert CVSS score to severity level."""
    if score is None:
        return Severity.UNKNOWN
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _is_version_affected(version_str: str, affected_range: str) -> bool:
    """Check if a specific version is within the affected range.

    Handles common version specifier formats.
    """
    # Clean up version string
    version_str = version_str.strip().lstrip("=<>~!")

    # Handle wildcard/unspecified
    if version_str in ("*", "", "editable"):
        return True  # Assume affected if version unknown

    try:
        version = Version(version_str)
    except InvalidVersion:
        return True  # Assume affected if can't parse

    try:
        specifier = SpecifierSet(affected_range)
        return version in specifier
    except InvalidSpecifier:
        # Try to parse as simple range like ">=1.0,<2.0"
        return True  # Assume affected if can't parse range


def lookup_vulnerabilities(
    package_name: str,
    version: str = "*",
) -> list[Vulnerability]:
    """Look up known vulnerabilities for a package.

    Uses the bundled database first. If the OSV feature flag is enabled
    and the bundled DB has no results, falls back to OSV.dev API.

    Args:
        package_name: Name of the package to check.
        version: Current version specifier.

    Returns:
        List of matching Vulnerability objects.
    """
    results: list[Vulnerability] = []

    # 1. Check bundled database
    db = _load_bundled_db()
    package_vulns = db.get(package_name.lower(), [])

    for vuln_data in package_vulns:
        affected_range = vuln_data.get("affected_versions", "")

        # Check if current version is affected
        if version != "*" and affected_range:
            if not _is_version_affected(version, affected_range):
                continue

        vuln = Vulnerability(
            vuln_id=vuln_data.get("id", "UNKNOWN"),
            package_name=package_name,
            affected_versions=affected_range,
            fixed_version=vuln_data.get("fixed_version"),
            severity=_severity_from_cvss(vuln_data.get("cvss_score")),
            description=vuln_data.get("description", ""),
            source="bundled",
            cvss_score=vuln_data.get("cvss_score"),
        )
        results.append(vuln)

    # 2. Optional: OSV.dev live lookup (behind feature flag)
    settings = get_settings()
    if settings.features.enable_osv_lookup and not results:
        osv_results = _lookup_osv(package_name, version)
        results.extend(osv_results)

    return results


def _lookup_osv(package_name: str, version: str) -> list[Vulnerability]:
    """Query OSV.dev API for vulnerabilities (D2 - optional, behind feature flag)."""
    try:
        response = httpx.post(
            "https://api.osv.dev/v1/query",
            json={
                "package": {"name": package_name, "ecosystem": "PyPI"},
                "version": version if version != "*" else None,
            },
            timeout=10.0,
        )
        response.raise_for_status()
        data = response.json()
    except Exception:
        return []

    results: list[Vulnerability] = []
    for vuln_data in data.get("vulns", []):
        vuln = Vulnerability(
            vuln_id=vuln_data.get("id", "UNKNOWN"),
            package_name=package_name,
            affected_versions=_extract_affected_range(vuln_data),
            fixed_version=_extract_fixed_version(vuln_data),
            severity=Severity.UNKNOWN,
            description=vuln_data.get("summary", ""),
            source="osv",
        )
        results.append(vuln)

    return results


def _extract_affected_range(vuln_data: dict[str, Any]) -> str:
    """Extract affected version range from OSV format."""
    for affected in vuln_data.get("affected", []):
        for rng in affected.get("ranges", []):
            events = rng.get("events", [])
            introduced = None
            fixed = None
            for event in events:
                if "introduced" in event:
                    introduced = event["introduced"]
                if "fixed" in event:
                    fixed = event["fixed"]
            if introduced and fixed:
                return f">={introduced},<{fixed}"
            if introduced:
                return f">={introduced}"
    return ""


def _extract_fixed_version(vuln_data: dict[str, Any]) -> str | None:
    """Extract fixed version from OSV format."""
    for affected in vuln_data.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None
