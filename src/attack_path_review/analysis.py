from __future__ import annotations

from dataclasses import dataclass

from .algorithms import (
    ChokePoint,
    MitigationImpact,
    PathResult,
    enumerate_attack_paths,
    minimum_edge_cut,
    rank_choke_points,
    simulate_single_edge_mitigations,
)
from .model import Graph


@dataclass(frozen=True, slots=True)
class AnalysisConfig:
    max_depth: int = 8
    max_paths: int = 200
    critical_exposure: float = 5.0

    def __post_init__(self) -> None:
        if not 1 <= self.max_depth <= 32:
            raise ValueError("max_depth must be between 1 and 32")
        if not 1 <= self.max_paths <= 10_000:
            raise ValueError("max_paths must be between 1 and 10000")
        if not 0 <= self.critical_exposure <= 100:
            raise ValueError("critical_exposure must be between 0 and 100")


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    graph: Graph
    config: AnalysisConfig
    paths: tuple[PathResult, ...]
    choke_points: tuple[ChokePoint, ...]
    minimum_cut_edges: tuple[str, ...]
    mitigations: tuple[MitigationImpact, ...]

    @property
    def critical_paths(self) -> tuple[PathResult, ...]:
        return tuple(path for path in self.paths if path.exposure >= self.config.critical_exposure)


def analyze(graph: Graph, config: AnalysisConfig) -> AnalysisResult:
    paths = enumerate_attack_paths(graph, max_depth=config.max_depth, max_paths=config.max_paths)
    return AnalysisResult(
        graph=graph,
        config=config,
        paths=paths,
        choke_points=rank_choke_points(paths),
        minimum_cut_edges=minimum_edge_cut(graph),
        mitigations=simulate_single_edge_mitigations(
            graph,
            paths,
            max_depth=config.max_depth,
            max_paths=config.max_paths,
        ),
    )
