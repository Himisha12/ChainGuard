"""LangChain tool definitions for agent use (D10).

These wrap the raw tool functions with Pydantic schemas for structured
tool calling with retry on validation failure.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import tool
from pydantic import BaseModel, Field

from src.tools.parsers import parse_file
from src.tools.vuln_lookup import lookup_vulnerabilities
from src.tools.risk_scorer import compute_risk_score
from src.models.schemas import ParsedDependency, Severity, Vulnerability


# ─── Tool Input Schemas (Pydantic, D10) ──────────────────────────────────────


class ParseFileInput(BaseModel):
    """Input schema for the parse_dependencies tool."""

    file_content: str = Field(..., description="Raw content of the dependency file")
    file_type: str = Field(
        default="requirements.txt",
        description="Type of file: 'requirements.txt' or 'pyproject.toml'",
    )


class VulnLookupInput(BaseModel):
    """Input schema for the vulnerability lookup tool."""

    package_name: str = Field(..., description="Name of the Python package to check")
    version: str = Field(default="*", description="Current version specifier")


class RiskScoreInput(BaseModel):
    """Input schema for the risk scoring tool."""

    package_name: str = Field(..., description="Package name")
    current_version: str = Field(..., description="Current version")
    vuln_id: str = Field(..., description="Vulnerability ID")
    cvss_score: float | None = Field(None, description="CVSS score if known")
    severity: str = Field(default="unknown", description="Severity level")
    fixed_version: str | None = Field(None, description="Fixed version if known")
    affected_versions: str = Field(default="", description="Affected version range")
    source_file: str = Field(default="requirements.txt", description="Source file")
    line_number: int = Field(default=1, description="Line number")


# ─── Tool Definitions ────────────────────────────────────────────────────────


@tool(args_schema=ParseFileInput)
def parse_dependencies(file_content: str, file_type: str = "requirements.txt") -> dict[str, Any]:
    """Parse a Python dependency file and extract all dependencies with versions.

    Supports requirements.txt and pyproject.toml formats.
    Returns a list of parsed dependencies with names, versions, and line numbers.
    """
    try:
        deps = parse_file(file_content, file_type)
        return {
            "success": True,
            "dependencies": [dep.model_dump() for dep in deps],
            "count": len(deps),
        }
    except Exception as e:
        return {"success": False, "error": str(e), "dependencies": [], "count": 0}


@tool(args_schema=VulnLookupInput)
def check_vulnerabilities(package_name: str, version: str = "*") -> dict[str, Any]:
    """Check a Python package for known vulnerabilities.

    Searches the bundled vulnerability database for known CVEs affecting
    the specified package and version. Returns vulnerability details
    including severity, CVSS scores, and fix information.
    """
    try:
        vulns = lookup_vulnerabilities(package_name, version)
        return {
            "success": True,
            "package": package_name,
            "version": version,
            "vulnerabilities": [v.model_dump() for v in vulns],
            "count": len(vulns),
        }
    except Exception as e:
        return {"success": False, "error": str(e), "vulnerabilities": [], "count": 0}


@tool(args_schema=RiskScoreInput)
def assess_risk(
    package_name: str,
    current_version: str,
    vuln_id: str,
    cvss_score: float | None = None,
    severity: str = "unknown",
    fixed_version: str | None = None,
    affected_versions: str = "",
    source_file: str = "requirements.txt",
    line_number: int = 1,
) -> dict[str, Any]:
    """Assess the risk of a specific vulnerability for a dependency.

    Computes a risk score based on CVSS, version distance, dependency
    fanout, and breaking-change likelihood. Returns a risk assessment
    with score, level, and reasoning.
    """
    try:
        dep = ParsedDependency(
            name=package_name,
            current_version=current_version,
            source_file=source_file,
            line_number=line_number,
        )
        vuln = Vulnerability(
            vuln_id=vuln_id,
            package_name=package_name,
            affected_versions=affected_versions,
            fixed_version=fixed_version,
            severity=Severity(severity) if severity in [s.value for s in Severity] else Severity.UNKNOWN,
            cvss_score=cvss_score,
        )
        assessment = compute_risk_score(dep, vuln)
        return {
            "success": True,
            "risk_score": assessment.risk_score,
            "risk_level": assessment.risk_level.value,
            "reasoning": assessment.reasoning,
            "is_breaking_change": assessment.is_breaking_change,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


# Collect all tools for agent use
ALL_TOOLS = [parse_dependencies, check_vulnerabilities, assess_risk]
