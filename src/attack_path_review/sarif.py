from __future__ import annotations

from pathlib import Path
from typing import Any

from .analysis import AnalysisResult


def sarif_document(result: AnalysisResult, *, source_path: Path) -> dict[str, Any]:
    source_uri = source_path.as_posix() if not source_path.is_absolute() else source_path.name
    findings: list[dict[str, Any]] = []
    for index, path in enumerate(result.critical_paths, 1):
        route = " -> ".join(path.nodes)
        findings.append(
            {
                "ruleId": "APR001",
                "level": "error" if path.exposure >= min(100, 2 * result.config.critical_exposure) else "warning",
                "message": {
                    "text": f"Critical attack path #{index}: {route} (exposure {path.exposure:.2f}, effort {path.effort})."
                },
                "locations": [_location(source_uri)],
                "properties": {
                    "exposure": path.exposure,
                    "likelihood": path.likelihood,
                    "effort": path.effort,
                    "edges": list(path.edges),
                },
            }
        )
    for edge_id in result.minimum_cut_edges:
        findings.append(
            {
                "ruleId": "APR002",
                "level": "note",
                "message": {"text": f"Edge {edge_id} is part of the minimum entry-to-crown-jewel cut."},
                "locations": [_location(source_uri)],
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "attack-path-review",
                        "informationUri": "https://github.com/moaazmtaha/attack-path-review",
                        "semanticVersion": "0.1.0",
                        "rules": [
                            {
                                "id": "APR001",
                                "name": "critical-attack-path",
                                "shortDescription": {"text": "A bounded path exceeds the configured exposure threshold."},
                                "defaultConfiguration": {"level": "warning"},
                            },
                            {
                                "id": "APR002",
                                "name": "minimum-cut-edge",
                                "shortDescription": {"text": "An edge belongs to the minimum global entry-to-target cut."},
                                "defaultConfiguration": {"level": "note"},
                            },
                        ],
                    }
                },
                "results": findings,
            }
        ],
    }


def _location(uri: str) -> dict[str, Any]:
    return {"physicalLocation": {"artifactLocation": {"uri": uri}}}
