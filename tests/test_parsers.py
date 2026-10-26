"""Tests for the dependency parsers (D11)."""

from __future__ import annotations

import pytest

from src.tools.parsers import parse_requirements_txt, parse_pyproject_toml, parse_file


class TestRequirementsTxtParser:
    """Test requirements.txt parsing with edge cases."""

    def test_basic_pinned_versions(self) -> None:
        content = "flask==2.3.0\nrequests==2.31.0\n"
        deps = parse_requirements_txt(content)
        assert len(deps) == 2
        assert deps[0].name == "flask"
        assert deps[0].current_version == "==2.3.0"
        assert deps[1].name == "requests"

    def test_version_specifiers(self) -> None:
        content = "flask>=2.0.0\nrequests~=2.28\ndjango!=4.0.0\nnumpy<=1.26\n"
        deps = parse_requirements_txt(content)
        assert len(deps) == 4
        assert deps[0].current_version == ">=2.0.0"
        assert deps[1].current_version == "~=2.28"

    def test_comments_and_empty_lines(self) -> None:
        content = """
# This is a comment
flask==2.3.0

# Another comment
requests==2.31.0
"""
        deps = parse_requirements_txt(content)
        assert len(deps) == 2

    def test_inline_comments(self) -> None:
        content = "flask==2.3.0  # web framework\nrequests>=2.28  # HTTP\n"
        deps = parse_requirements_txt(content)
        assert len(deps) == 2
        assert deps[0].name == "flask"

    def test_extras(self) -> None:
        content = "uvicorn[standard]==0.30.0\ncelery[redis,msgpack]>=5.0\n"
        deps = parse_requirements_txt(content)
        assert len(deps) == 2
        assert deps[0].extras == ["standard"]
        assert deps[1].extras == ["redis", "msgpack"]

    def test_no_version(self) -> None:
        content = "flask\nrequests\n"
        deps = parse_requirements_txt(content)
        assert len(deps) == 2
        assert deps[0].current_version == ""

    def test_options_skipped(self) -> None:
        content = "-r base.txt\n--index-url https://pypi.org/simple\nflask==2.3.0\n"
        deps = parse_requirements_txt(content)
        assert len(deps) == 1
        assert deps[0].name == "flask"

    def test_editable_installs(self) -> None:
        content = "-e git+https://github.com/user/repo.git#egg=mypackage\nflask==2.3.0\n"
        deps = parse_requirements_txt(content)
        assert len(deps) == 2
        assert deps[0].name == "mypackage"
        assert deps[0].current_version == "editable"

    def test_environment_markers(self) -> None:
        content = 'pywin32>=300; sys_platform == "win32"\nflask==2.3.0\n'
        deps = parse_requirements_txt(content)
        assert len(deps) == 2

    def test_line_continuations(self) -> None:
        content = "flask\\\n==2.3.0\nrequests==2.31.0\n"
        deps = parse_requirements_txt(content)
        # After joining, should parse flask==2.3.0
        assert any(d.name == "flask" for d in deps)

    def test_line_numbers_tracked(self) -> None:
        content = "flask==2.3.0\nrequests==2.31.0\n"
        deps = parse_requirements_txt(content)
        assert deps[0].line_number == 1
        assert deps[1].line_number == 2

    def test_source_file_tracked(self) -> None:
        deps = parse_requirements_txt("flask==2.3.0", source_file="my_reqs.txt")
        assert deps[0].source_file == "my_reqs.txt"


class TestPyprojectTomlParser:
    """Test pyproject.toml parsing."""

    def test_pep621_dependencies(self) -> None:
        content = """
[project]
name = "myproject"
dependencies = [
    "flask>=2.0.0",
    "requests~=2.28",
]
"""
        deps = parse_pyproject_toml(content)
        assert len(deps) == 2
        assert deps[0].name == "flask"

    def test_optional_dependencies(self) -> None:
        content = """
[project]
name = "myproject"
dependencies = ["flask>=2.0.0"]

[project.optional-dependencies]
dev = ["pytest>=8.0", "ruff>=0.1"]
"""
        deps = parse_pyproject_toml(content)
        assert len(deps) == 3

    def test_poetry_style(self) -> None:
        content = """
[tool.poetry.dependencies]
python = "^3.11"
flask = "^2.3"
requests = {version = "^2.28", optional = true}
"""
        deps = parse_pyproject_toml(content)
        assert len(deps) == 2  # python is skipped
        assert deps[0].name == "flask"

    def test_invalid_toml(self) -> None:
        content = "this is not valid toml {{{}"
        deps = parse_pyproject_toml(content)
        assert len(deps) == 0


class TestParseFile:
    """Test the routing function."""

    def test_routes_to_requirements(self) -> None:
        deps = parse_file("flask==2.3.0\n", "requirements.txt")
        assert len(deps) == 1

    def test_routes_to_pyproject(self) -> None:
        content = '[project]\ndependencies = ["flask>=2.0"]\n'
        deps = parse_file(content, "pyproject.toml")
        assert len(deps) == 1

    def test_unsupported_file_type(self) -> None:
        with pytest.raises(ValueError, match="Unsupported file type"):
            parse_file("content", "package.json")
