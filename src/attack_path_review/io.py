from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .model import Graph, GraphValidationError


MAX_INPUT_BYTES = 10 * 1024 * 1024


def load_graph(path: Path) -> Graph:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise GraphValidationError([f"cannot read {path}: {exc}"]) from exc
    if size > MAX_INPUT_BYTES:
        raise GraphValidationError([f"input exceeds the {MAX_INPUT_BYTES // (1024 * 1024)} MiB limit"])
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GraphValidationError([f"invalid JSON in {path}: {exc}"]) from exc
    if not isinstance(document, dict):
        raise GraphValidationError(["graph root must be a JSON object"])
    return Graph.from_dict(document)


def write_json(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
