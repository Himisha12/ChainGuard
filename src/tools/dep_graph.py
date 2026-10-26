"""Knowledge graph for dependency relationships (D13).

Uses NetworkX to model package → depends-on → package relationships.
Enables traversal to answer "what breaks if I upgrade X?".
"""

from __future__ import annotations

from typing import Any

import networkx as nx

from src.models.schemas import ParsedDependency

import structlog

logger = structlog.get_logger(__name__)


class DependencyGraph:
    """NetworkX-based dependency knowledge graph.

    Nodes are packages, edges represent depends-on relationships.
    Supports traversal queries for impact analysis.
    """

    def __init__(self) -> None:
        self._graph = nx.DiGraph()

    def add_dependency(self, package: str, version: str, depends_on: list[str] | None = None) -> None:
        """Add a package and its dependencies to the graph."""
        self._graph.add_node(package, version=version)
        if depends_on:
            for dep in depends_on:
                self._graph.add_edge(package, dep, relation="depends_on")

    def build_from_parsed(self, dependencies: list[ParsedDependency]) -> None:
        """Build graph from parsed dependencies.

        Note: This only adds the direct dependencies. For full transitive
        graph, you'd need to resolve the dependency tree (e.g., via pip).
        """
        for dep in dependencies:
            self._graph.add_node(
                dep.name.lower(),
                version=dep.current_version,
                source_file=dep.source_file,
            )

        # Add known common dependency relationships
        _add_known_relationships(self._graph)

    def get_dependents(self, package: str) -> list[str]:
        """Get all packages that depend on the given package.

        Answers: "What breaks if I upgrade X?"
        """
        package = package.lower()
        if package not in self._graph:
            return []

        # Find all predecessors (packages that depend on this one)
        return list(self._graph.predecessors(package))

    def get_dependencies(self, package: str) -> list[str]:
        """Get all packages that the given package depends on."""
        package = package.lower()
        if package not in self._graph:
            return []

        return list(self._graph.successors(package))

    def get_transitive_dependents(self, package: str) -> list[str]:
        """Get all transitive dependents (full impact analysis).

        Answers: "What is the full blast radius of upgrading X?"
        """
        package = package.lower()
        if package not in self._graph:
            return []

        # BFS to find all ancestors
        return list(nx.ancestors(self._graph, package))

    def get_impact_score(self, package: str) -> int:
        """Get impact score: number of transitive dependents."""
        return len(self.get_transitive_dependents(package))

    def impact_analysis(self, package: str) -> dict[str, Any]:
        """Perform full blast radius and impact analysis for upgrading a package."""
        direct = self.get_dependents(package)
        transitive = self.get_transitive_dependents(package)
        return {
            "package": package,
            "direct_dependents": direct,
            "transitive_dependents": transitive,
            "impact_score": len(transitive),
            "safe_upgrade": len(transitive) == 0,
        }

    def get_upgrade_order(self, packages: list[str]) -> list[str]:
        """Determine safe upgrade order for a set of packages.

        Returns packages ordered so dependencies are upgraded first.
        Uses topological sort on the subgraph.
        """
        packages_lower = [p.lower() for p in packages]
        subgraph = self._graph.subgraph(
            [p for p in packages_lower if p in self._graph]
        )

        try:
            return list(reversed(list(nx.topological_sort(subgraph))))
        except nx.NetworkXUnfeasible:
            # Cycle detected — return as-is
            return packages_lower

    def to_dict(self) -> dict[str, Any]:
        """Serialize graph for API responses."""
        return {
            "nodes": [
                {"id": n, **self._graph.nodes[n]}
                for n in self._graph.nodes
            ],
            "edges": [
                {"from": u, "to": v, **self._graph.edges[u, v]}
                for u, v in self._graph.edges
            ],
            "node_count": self._graph.number_of_nodes(),
            "edge_count": self._graph.number_of_edges(),
        }


def _add_known_relationships(graph: nx.DiGraph) -> None:
    """Add known common Python dependency relationships.

    This is a simplified version — a full implementation would
    resolve the actual dependency tree.
    """
    known_deps: dict[str, list[str]] = {
        "flask": ["werkzeug", "jinja2", "click"],
        "django": ["sqlparse", "asgiref"],
        "requests": ["urllib3", "certifi", "charset-normalizer", "idna"],
        "fastapi": ["starlette", "pydantic"],
        "aiohttp": ["multidict", "yarl", "aiosignal"],
    }

    for package, deps in known_deps.items():
        if package in graph:
            for dep in deps:
                if dep in graph:
                    graph.add_edge(package, dep, relation="depends_on")
