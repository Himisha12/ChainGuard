"""Dependency file parsers for requirements.txt and pyproject.toml (D11).

Handles messy/legacy formats: comments, inline options, editable installs,
version specifiers, extras, and environment markers.
"""

from __future__ import annotations

import re
from typing import Any

from src.models.schemas import ParsedDependency


def parse_requirements_txt(content: str, source_file: str = "requirements.txt") -> list[ParsedDependency]:
    """Parse a requirements.txt file, handling common edge cases.

    Handles:
    - Version specifiers: ==, >=, <=, ~=, !=, >, <
    - Extras: package[extra1,extra2]
    - Comments and inline comments
    - -r/-c includes (noted but skipped)
    - Editable installs (-e)
    - Environment markers (;)
    - Line continuations (\\)
    - Empty lines and whitespace
    """
    dependencies: list[ParsedDependency] = []

    # Join line continuations
    content = content.replace("\\\n", "")

    for line_num, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()

        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        # Skip options and flags (-r, -c, -i, --index-url, etc.)
        if line.startswith("-") and not line.startswith("-e"):
            continue

        # Handle editable installs
        if line.startswith("-e"):
            # Extract package name from URL or path
            editable_part = line[2:].strip()
            match = re.search(r"#egg=(.+?)(?:&|$)", editable_part)
            if match:
                dep = ParsedDependency(
                    name=match.group(1).strip(),
                    current_version="editable",
                    source_file=source_file,
                    line_number=line_num,
                )
                dependencies.append(dep)
            continue

        # Remove inline comments
        line = re.split(r"\s+#", line, maxsplit=1)[0].strip()

        # Remove environment markers for parsing (but we could store them)
        line = line.split(";")[0].strip()

        # Parse package name, extras, and version
        # Pattern: package_name[extras]version_specifier
        match = re.match(
            r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"  # Package name
            r"(\[([^\]]+)\])?"  # Optional extras
            r"\s*(.*)$",  # Version specifier
            line,
        )

        if not match:
            continue

        name = match.group(1).strip()
        extras_str = match.group(4)
        version_part = match.group(5).strip()

        extras = [e.strip() for e in extras_str.split(",")] if extras_str else []

        # Clean up version specifier
        version = version_part if version_part else ""

        dep = ParsedDependency(
            name=name,
            current_version=version,
            extras=extras,
            source_file=source_file,
            line_number=line_num,
        )
        dependencies.append(dep)

    return dependencies


def parse_pyproject_toml(content: str, source_file: str = "pyproject.toml") -> list[ParsedDependency]:
    """Parse dependencies from pyproject.toml (D11).

    Handles both [project.dependencies] and [tool.poetry.dependencies].
    """
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
        except ImportError:
            import toml as tomllib  # type: ignore

    dependencies: list[ParsedDependency] = []

    try:
        data = tomllib.loads(content)
    except Exception:
        return dependencies

    # PEP 621 style: [project.dependencies]
    project_deps = data.get("project", {}).get("dependencies", [])
    for i, dep_str in enumerate(project_deps):
        parsed = _parse_pep508(dep_str, source_file, line_number=i + 1)
        if parsed:
            dependencies.append(parsed)

    # Optional dependencies
    optional_deps = data.get("project", {}).get("optional-dependencies", {})
    for group, deps in optional_deps.items():
        for i, dep_str in enumerate(deps):
            parsed = _parse_pep508(dep_str, source_file, line_number=i + 1)
            if parsed:
                parsed.extras = [group]
                dependencies.append(parsed)

    # Poetry style: [tool.poetry.dependencies]
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for i, (name, version_info) in enumerate(poetry_deps.items(), start=1):
        if name.lower() == "python":
            continue
        if isinstance(version_info, str):
            version = version_info
        elif isinstance(version_info, dict):
            version = version_info.get("version", "*")
        else:
            version = "*"
        dep = ParsedDependency(
            name=name,
            current_version=version,
            source_file=source_file,
            line_number=i,
        )
        dependencies.append(dep)

    return dependencies


def _parse_pep508(spec: str, source_file: str, line_number: int) -> ParsedDependency | None:
    """Parse a PEP 508 dependency specifier."""
    # Remove environment markers
    spec = spec.split(";")[0].strip()

    match = re.match(
        r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"
        r"(\[([^\]]+)\])?"
        r"\s*(.*)$",
        spec,
    )

    if not match:
        return None

    name = match.group(1).strip()
    extras_str = match.group(4)
    version = match.group(5).strip() or "*"
    extras = [e.strip() for e in extras_str.split(",")] if extras_str else []

    return ParsedDependency(
        name=name,
        current_version=version,
        extras=extras,
        source_file=source_file,
        line_number=line_number,
    )


def parse_file(content: str, file_type: str) -> list[ParsedDependency]:
    """Route to the appropriate parser based on file type."""
    parsers = {
        "requirements.txt": parse_requirements_txt,
        "pyproject.toml": parse_pyproject_toml,
    }

    parser = parsers.get(file_type)
    if parser is None:
        raise ValueError(f"Unsupported file type: {file_type}. Supported: {list(parsers.keys())}")

    return parser(content, source_file=file_type)
