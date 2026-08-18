from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass
import heapq
from typing import Iterable, Mapping

from .model import Edge, Graph


@dataclass(frozen=True, slots=True)
class PathResult:
    source: str
    target: str
    nodes: tuple[str, ...]
    edges: tuple[str, ...]
    effort: int
    likelihood: float
    exposure: float


@dataclass(frozen=True, slots=True)
class ChokePoint:
    kind: str
    id: str
    path_count: int
    coverage: float
    exposure_share: float


@dataclass(frozen=True, slots=True)
class MitigationImpact:
    edge_id: str
    paths_removed: int
    remaining_paths: int
    max_exposure_reduction: float
    exposure_sum_reduction: float


def enumerate_attack_paths(
    graph: Graph,
    *,
    max_depth: int = 8,
    max_paths: int = 200,
    excluded_edges: frozenset[str] = frozenset(),
    excluded_nodes: frozenset[str] = frozenset(),
) -> tuple[PathResult, ...]:
    """Enumerate bounded, loop-free paths ordered by cumulative effort."""

    if max_depth < 1:
        raise ValueError("max_depth must be at least 1")
    if not 1 <= max_paths <= 10_000:
        raise ValueError("max_paths must be between 1 and 10000")

    entries = sorted(node.id for node in graph.nodes.values() if node.entry and node.id not in excluded_nodes)
    targets = {node.id for node in graph.nodes.values() if node.crown_jewel and node.id not in excluded_nodes}
    adjacency = graph.adjacency(excluded_edges=excluded_edges, excluded_nodes=excluded_nodes)
    queue: list[tuple[int, tuple[str, ...], tuple[str, ...], float]] = []
    for entry in entries:
        heapq.heappush(queue, (0, (entry,), (), 1.0))

    results: list[PathResult] = []
    explored = 0
    exploration_limit = max(10_000, max_paths * max_depth * 50)
    while queue and len(results) < max_paths:
        effort, node_path, edge_path, likelihood = heapq.heappop(queue)
        explored += 1
        if explored > exploration_limit:
            break
        current = node_path[-1]
        if current in targets and edge_path:
            criticality = graph.nodes[current].criticality
            exposure = round(min(100.0, 100.0 * likelihood * (0.4 + 0.6 * criticality / 10)), 2)
            results.append(
                PathResult(
                    source=node_path[0],
                    target=current,
                    nodes=node_path,
                    edges=edge_path,
                    effort=effort,
                    likelihood=round(likelihood, 6),
                    exposure=exposure,
                )
            )
            continue
        if len(edge_path) >= max_depth:
            continue
        for edge in adjacency.get(current, ()):
            if edge.target in node_path:
                continue
            heapq.heappush(
                queue,
                (
                    effort + edge.effort,
                    node_path + (edge.target,),
                    edge_path + (edge.id,),
                    likelihood * edge.likelihood,
                ),
            )

    return tuple(sorted(results, key=lambda path: (-path.exposure, path.effort, path.nodes, path.edges)))


def rank_choke_points(paths: Iterable[PathResult]) -> tuple[ChokePoint, ...]:
    path_list = tuple(paths)
    if not path_list:
        return ()
    edge_counts: Counter[str] = Counter()
    node_counts: Counter[str] = Counter()
    edge_exposure: defaultdict[str, float] = defaultdict(float)
    node_exposure: defaultdict[str, float] = defaultdict(float)
    total_exposure = sum(path.exposure for path in path_list) or 1.0

    for path in path_list:
        for edge_id in set(path.edges):
            edge_counts[edge_id] += 1
            edge_exposure[edge_id] += path.exposure
        for node_id in set(path.nodes[1:-1]):
            node_counts[node_id] += 1
            node_exposure[node_id] += path.exposure

    points = [
        ChokePoint(
            kind="edge",
            id=item_id,
            path_count=count,
            coverage=round(count / len(path_list), 4),
            exposure_share=round(edge_exposure[item_id] / total_exposure, 4),
        )
        for item_id, count in edge_counts.items()
    ]
    points.extend(
        ChokePoint(
            kind="node",
            id=item_id,
            path_count=count,
            coverage=round(count / len(path_list), 4),
            exposure_share=round(node_exposure[item_id] / total_exposure, 4),
        )
        for item_id, count in node_counts.items()
    )
    return tuple(sorted(points, key=lambda point: (-point.coverage, -point.exposure_share, point.kind, point.id)))


def minimum_edge_cut(graph: Graph) -> tuple[str, ...]:
    """Return enabled edge IDs in a minimum global entry-to-crown-jewel cut."""

    source = "__apr_super_source__"
    sink = "__apr_super_sink__"
    entries = [node.id for node in graph.nodes.values() if node.entry]
    targets = [node.id for node in graph.nodes.values() if node.crown_jewel]
    enabled = [edge for edge in graph.edges if edge.enabled]
    if not entries or not targets or not enabled:
        return ()

    capacity: defaultdict[tuple[str, str], int] = defaultdict(int)
    neighbors: defaultdict[str, set[str]] = defaultdict(set)

    def add_arc(left: str, right: str, value: int) -> None:
        capacity[(left, right)] += value
        neighbors[left].add(right)
        neighbors[right].add(left)

    for edge in enabled:
        add_arc(edge.source, edge.target, 1)
    infinite = len(enabled) + 1
    for entry in entries:
        add_arc(source, entry, infinite)
    for target in targets:
        add_arc(target, sink, infinite)

    residual: defaultdict[tuple[str, str], int] = defaultdict(int, capacity)
    while True:
        parent: dict[str, str | None] = {source: None}
        pending = deque([source])
        while pending and sink not in parent:
            current = pending.popleft()
            for adjacent in sorted(neighbors[current]):
                if adjacent not in parent and residual[(current, adjacent)] > 0:
                    parent[adjacent] = current
                    pending.append(adjacent)
        if sink not in parent:
            break
        flow = infinite
        cursor = sink
        while parent[cursor] is not None:
            previous = parent[cursor]
            assert previous is not None
            flow = min(flow, residual[(previous, cursor)])
            cursor = previous
        cursor = sink
        while parent[cursor] is not None:
            previous = parent[cursor]
            assert previous is not None
            residual[(previous, cursor)] -= flow
            residual[(cursor, previous)] += flow
            cursor = previous

    reachable = {source}
    pending = deque([source])
    while pending:
        current = pending.popleft()
        for adjacent in sorted(neighbors[current]):
            if adjacent not in reachable and residual[(current, adjacent)] > 0:
                reachable.add(adjacent)
                pending.append(adjacent)

    return tuple(
        sorted(
            edge.id
            for edge in enabled
            if edge.source in reachable and edge.target not in reachable
        )
    )


def simulate_single_edge_mitigations(
    graph: Graph,
    baseline_paths: Iterable[PathResult],
    *,
    max_depth: int,
    max_paths: int,
) -> tuple[MitigationImpact, ...]:
    baseline = tuple(baseline_paths)
    if not baseline:
        return ()
    candidate_ids = sorted({edge_id for path in baseline for edge_id in path.edges})
    baseline_max = max(path.exposure for path in baseline)
    baseline_sum = sum(path.exposure for path in baseline)
    impacts: list[MitigationImpact] = []
    for edge_id in candidate_ids:
        remaining = enumerate_attack_paths(
            graph,
            max_depth=max_depth,
            max_paths=max_paths,
            excluded_edges=frozenset({edge_id}),
        )
        remaining_max = max((path.exposure for path in remaining), default=0.0)
        remaining_sum = sum(path.exposure for path in remaining)
        impacts.append(
            MitigationImpact(
                edge_id=edge_id,
                paths_removed=sum(edge_id in path.edges for path in baseline),
                remaining_paths=len(remaining),
                max_exposure_reduction=round(max(0.0, baseline_max - remaining_max), 2),
                exposure_sum_reduction=round(max(0.0, baseline_sum - remaining_sum), 2),
            )
        )
    return tuple(
        sorted(
            impacts,
            key=lambda impact: (
                -impact.paths_removed,
                -impact.exposure_sum_reduction,
                -impact.max_exposure_reduction,
                impact.edge_id,
            ),
        )
    )


def edge_lookup(graph: Graph) -> Mapping[str, Edge]:
    return {edge.id: edge for edge in graph.edges}
