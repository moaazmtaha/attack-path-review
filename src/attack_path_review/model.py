from __future__ import annotations

from dataclasses import dataclass, replace
import re
from typing import Any, Iterable, Mapping


IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class GraphValidationError(ValueError):
    """Raised when an attack-path graph is unsafe or internally inconsistent."""

    def __init__(self, issues: Iterable[str]) -> None:
        self.issues = tuple(issues)
        super().__init__("; ".join(self.issues))


@dataclass(frozen=True, slots=True)
class Node:
    id: str
    label: str
    kind: str
    criticality: int = 0
    entry: bool = False
    crown_jewel: bool = False
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Edge:
    id: str
    source: str
    target: str
    relationship: str
    likelihood: float = 0.5
    effort: int = 5
    controls: tuple[str, ...] = ()
    enabled: bool = True


@dataclass(frozen=True, slots=True)
class Graph:
    nodes: Mapping[str, Node]
    edges: tuple[Edge, ...]
    title: str = "Attack-path review"

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> Graph:
        issues: list[str] = []
        if document.get("schema_version") != 1:
            issues.append("schema_version must be 1")

        raw_nodes = document.get("nodes")
        raw_edges = document.get("edges")
        if not isinstance(raw_nodes, list) or not raw_nodes:
            issues.append("nodes must be a non-empty array")
            raw_nodes = []
        if not isinstance(raw_edges, list):
            issues.append("edges must be an array")
            raw_edges = []

        nodes: dict[str, Node] = {}
        for index, raw in enumerate(raw_nodes):
            prefix = f"nodes[{index}]"
            if not isinstance(raw, dict):
                issues.append(f"{prefix} must be an object")
                continue
            node_id = raw.get("id")
            if not isinstance(node_id, str) or not IDENTIFIER.fullmatch(node_id):
                issues.append(f"{prefix}.id must be a stable 1-128 character identifier")
                continue
            if node_id in nodes:
                issues.append(f"duplicate node id: {node_id}")
                continue
            label = raw.get("label")
            kind = raw.get("kind")
            if not isinstance(label, str) or not label.strip():
                issues.append(f"{prefix}.label must be non-empty text")
                label = node_id
            if not isinstance(kind, str) or not kind.strip():
                issues.append(f"{prefix}.kind must be non-empty text")
                kind = "unknown"
            criticality = raw.get("criticality", 0)
            if isinstance(criticality, bool) or not isinstance(criticality, int) or not 0 <= criticality <= 10:
                issues.append(f"{prefix}.criticality must be an integer from 0 to 10")
                criticality = 0
            entry = raw.get("entry", False)
            crown_jewel = raw.get("crown_jewel", False)
            if not isinstance(entry, bool):
                issues.append(f"{prefix}.entry must be boolean")
                entry = False
            if not isinstance(crown_jewel, bool):
                issues.append(f"{prefix}.crown_jewel must be boolean")
                crown_jewel = False
            tags = _text_tuple(raw.get("tags", []), f"{prefix}.tags", issues)
            nodes[node_id] = Node(
                id=node_id,
                label=label.strip(),
                kind=kind.strip(),
                criticality=criticality,
                entry=entry,
                crown_jewel=crown_jewel,
                tags=tags,
            )

        edges: list[Edge] = []
        edge_ids: set[str] = set()
        for index, raw in enumerate(raw_edges):
            prefix = f"edges[{index}]"
            if not isinstance(raw, dict):
                issues.append(f"{prefix} must be an object")
                continue
            edge_id = raw.get("id")
            if not isinstance(edge_id, str) or not IDENTIFIER.fullmatch(edge_id):
                issues.append(f"{prefix}.id must be a stable 1-128 character identifier")
                continue
            if edge_id in edge_ids:
                issues.append(f"duplicate edge id: {edge_id}")
                continue
            edge_ids.add(edge_id)
            source = raw.get("source")
            target = raw.get("target")
            relationship = raw.get("relationship")
            if not isinstance(source, str) or source not in nodes:
                issues.append(f"{prefix}.source references an unknown node")
                continue
            if not isinstance(target, str) or target not in nodes:
                issues.append(f"{prefix}.target references an unknown node")
                continue
            if source == target:
                issues.append(f"{prefix} must not be a self-loop")
                continue
            if not isinstance(relationship, str) or not relationship.strip():
                issues.append(f"{prefix}.relationship must be non-empty text")
                relationship = "reaches"
            likelihood = raw.get("likelihood", 0.5)
            if isinstance(likelihood, bool) or not isinstance(likelihood, (int, float)) or not 0 <= likelihood <= 1:
                issues.append(f"{prefix}.likelihood must be a number from 0 to 1")
                likelihood = 0.5
            effort = raw.get("effort", 5)
            if isinstance(effort, bool) or not isinstance(effort, int) or not 1 <= effort <= 10:
                issues.append(f"{prefix}.effort must be an integer from 1 to 10")
                effort = 5
            controls = _text_tuple(raw.get("controls", []), f"{prefix}.controls", issues)
            enabled = raw.get("enabled", True)
            if not isinstance(enabled, bool):
                issues.append(f"{prefix}.enabled must be boolean")
                enabled = True
            edges.append(
                Edge(
                    id=edge_id,
                    source=source,
                    target=target,
                    relationship=relationship.strip(),
                    likelihood=float(likelihood),
                    effort=effort,
                    controls=controls,
                    enabled=enabled,
                )
            )

        if nodes and not any(node.entry for node in nodes.values()):
            issues.append("at least one node must have entry=true")
        if nodes and not any(node.crown_jewel for node in nodes.values()):
            issues.append("at least one node must have crown_jewel=true")
        if any(node.entry and node.crown_jewel for node in nodes.values()):
            issues.append("a node cannot be both an entry and a crown jewel")
        if issues:
            raise GraphValidationError(issues)
        return cls(
            nodes=nodes,
            edges=tuple(sorted(edges, key=lambda edge: edge.id)),
            title=str(document.get("title") or "Attack-path review").strip(),
        )

    def adjacency(
        self,
        *,
        excluded_edges: frozenset[str] = frozenset(),
        excluded_nodes: frozenset[str] = frozenset(),
    ) -> Mapping[str, tuple[Edge, ...]]:
        result: dict[str, list[Edge]] = {node_id: [] for node_id in self.nodes if node_id not in excluded_nodes}
        for edge in self.edges:
            if (
                edge.enabled
                and edge.id not in excluded_edges
                and edge.source not in excluded_nodes
                and edge.target not in excluded_nodes
            ):
                result[edge.source].append(edge)
        return {
            node_id: tuple(sorted(outgoing, key=lambda edge: (edge.effort, edge.target, edge.id)))
            for node_id, outgoing in result.items()
        }

    def with_edge_disabled(self, edge_id: str) -> Graph:
        return replace(
            self,
            edges=tuple(replace(edge, enabled=False) if edge.id == edge_id else edge for edge in self.edges),
        )


def _text_tuple(raw: Any, field: str, issues: list[str]) -> tuple[str, ...]:
    if not isinstance(raw, list) or any(not isinstance(item, str) or not item.strip() for item in raw):
        issues.append(f"{field} must be an array of non-empty strings")
        return ()
    return tuple(dict.fromkeys(item.strip() for item in raw))
