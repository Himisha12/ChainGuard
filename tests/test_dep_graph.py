"""Tests for dependency knowledge graph (D13)."""

from __future__ import annotations

import pytest

from src.models.schemas import ParsedDependency
from src.tools.dep_graph import DependencyGraph


class TestDependencyGraph:
    """Test knowledge graph traversal, impact queries, and topological sorting."""

    def test_add_and_query_dependents(self) -> None:
        graph = DependencyGraph()
        graph.add_dependency("flask", "2.3.0", depends_on=["werkzeug"])
        graph.add_dependency("my-service", "1.0.0", depends_on=["flask"])

        # flask depends on werkzeug -> who depends on werkzeug? flask
        dependents = graph.get_dependents("werkzeug")
        assert "flask" in dependents

        # my-service depends on flask -> who depends on flask? my-service
        dependents_flask = graph.get_dependents("flask")
        assert "my-service" in dependents_flask

    def test_transitive_dependents_blast_radius(self) -> None:
        graph = DependencyGraph()
        # A depends on B, B depends on C
        graph.add_dependency("pkg_a", "1.0", depends_on=["pkg_b"])
        graph.add_dependency("pkg_b", "1.0", depends_on=["pkg_c"])
        graph.add_dependency("pkg_c", "1.0", depends_on=[])

        transitive = graph.get_transitive_dependents("pkg_c")
        assert "pkg_b" in transitive
        assert "pkg_a" in transitive
        assert graph.get_impact_score("pkg_c") >= 2

    def test_build_from_parsed_dependencies(self) -> None:
        graph = DependencyGraph()
        deps = [
            ParsedDependency(name="flask", current_version="2.3.0", source_file="req.txt", line_number=1),
            ParsedDependency(name="jinja2", current_version="3.1.0", source_file="req.txt", line_number=2),
            ParsedDependency(name="werkzeug", current_version="2.3.0", source_file="req.txt", line_number=3),
        ]
        graph.build_from_parsed(deps)

        # Flask depends on werkzeug and jinja2
        dependents = graph.get_dependents("jinja2")
        assert "flask" in dependents

    def test_upgrade_order_topological_sort(self) -> None:
        graph = DependencyGraph()
        # app -> service -> library
        graph.add_dependency("app", "1.0", depends_on=["service"])
        graph.add_dependency("service", "1.0", depends_on=["library"])
        graph.add_dependency("library", "1.0", depends_on=[])

        order = graph.get_upgrade_order(["app", "library", "service"])
        # library must be upgraded before service, service before app
        assert order.index("library") < order.index("service")
        assert order.index("service") < order.index("app")

    def test_impact_analysis_report(self) -> None:
        graph = DependencyGraph()
        graph.add_dependency("api", "1.0", depends_on=["core"])
        analysis = graph.impact_analysis("core")
        assert analysis["package"] == "core"
        assert "api" in analysis["direct_dependents"]
        assert analysis["safe_upgrade"] is False
