from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from html import escape
import json
from pathlib import Path
from typing import Any

from .algorithms import edge_lookup
from .analysis import AnalysisResult


def result_document(result: AnalysisResult, *, source: str) -> dict[str, Any]:
    graph = result.graph
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "summary": {
            "title": graph.title,
            "nodes": len(graph.nodes),
            "enabled_edges": sum(edge.enabled for edge in graph.edges),
            "paths": len(result.paths),
            "critical_paths": len(result.critical_paths),
            "maximum_exposure": max((path.exposure for path in result.paths), default=0.0),
            "minimum_cut_size": len(result.minimum_cut_edges),
            "path_limit_reached": len(result.paths) == result.config.max_paths,
        },
        "configuration": asdict(result.config),
        "paths": [asdict(path) for path in result.paths],
        "choke_points": [asdict(point) for point in result.choke_points],
        "minimum_cut_edges": list(result.minimum_cut_edges),
        "mitigations": [asdict(impact) for impact in result.mitigations],
    }


def html_report(result: AnalysisResult, *, source: str) -> str:
    graph = result.graph
    lookup = edge_lookup(graph)
    summary = result_document(result, source=source)["summary"]

    path_rows = "".join(
        "<tr>"
        f"<td>{index}</td>"
        f"<td>{path.exposure:.2f}</td>"
        f"<td>{path.likelihood:.4f}</td>"
        f"<td>{path.effort}</td>"
        f"<td>{escape(' → '.join(graph.nodes[node].label for node in path.nodes))}</td>"
        "</tr>"
        for index, path in enumerate(result.paths, 1)
    ) or '<tr><td colspan="5">No bounded path reaches a crown jewel.</td></tr>'

    mitigation_rows = "".join(
        "<tr>"
        f"<td><code>{escape(impact.edge_id)}</code></td>"
        f"<td>{escape(lookup[impact.edge_id].relationship)}</td>"
        f"<td>{impact.paths_removed}</td>"
        f"<td>{impact.remaining_paths}</td>"
        f"<td>{impact.exposure_sum_reduction:.2f}</td>"
        "</tr>"
        for impact in result.mitigations[:20]
    ) or '<tr><td colspan="5">No reachable path to mitigate.</td></tr>'

    cut = ", ".join(f"<code>{escape(item)}</code>" for item in result.minimum_cut_edges) or "None"
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    title = escape(graph.title)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title} — attack-path review</title>
  <style>
    :root {{ color-scheme: light dark; --ink:#17212b; --paper:#f6f4ee; --line:#c9c4b8; --accent:#b5412e; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:var(--paper); color:var(--ink); font:15px/1.55 ui-monospace, SFMono-Regular, Consolas, monospace; }}
    main {{ width:min(1100px, calc(100% - 32px)); margin:40px auto 80px; }}
    h1 {{ font:700 clamp(28px,5vw,54px)/1.05 Georgia,serif; margin:.2em 0; max-width:18ch; }}
    h2 {{ margin-top:42px; font-size:18px; }}
    .kicker {{ color:var(--accent); letter-spacing:.08em; text-transform:uppercase; }}
    .meta {{ color:#615e57; }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:10px; margin:28px 0; }}
    .metric {{ border:1px solid var(--line); padding:16px; background:rgba(255,255,255,.3); }}
    .metric strong {{ display:block; font:700 30px/1 Georgia,serif; margin-bottom:8px; }}
    .scroll {{ overflow:auto; border:1px solid var(--line); }}
    table {{ width:100%; border-collapse:collapse; min-width:720px; }}
    th,td {{ text-align:left; padding:10px 12px; border-bottom:1px solid var(--line); vertical-align:top; }}
    th {{ background:rgba(0,0,0,.05); }}
    code {{ color:var(--accent); }}
    footer {{ margin-top:48px; padding-top:16px; border-top:1px solid var(--line); color:#615e57; }}
    @media (prefers-color-scheme:dark) {{ :root {{--ink:#eee9dc;--paper:#141719;--line:#464a4d;--accent:#ff8e72;}} .meta,footer {{color:#b8b3aa;}} }}
  </style>
</head>
<body><main>
  <p class="kicker">Offline attack-path analysis</p>
  <h1>{title}</h1>
  <p class="meta">Source: {escape(source)} · Generated {generated}</p>
  <section class="grid" aria-label="Analysis summary">
    <div class="metric"><strong>{summary['paths']}</strong>bounded paths</div>
    <div class="metric"><strong>{summary['critical_paths']}</strong>critical paths</div>
    <div class="metric"><strong>{summary['maximum_exposure']:.2f}</strong>maximum exposure</div>
    <div class="metric"><strong>{summary['minimum_cut_size']}</strong>minimum-cut edges</div>
  </section>
  <h2>Minimum edge cut</h2><p>{cut}</p>
  <h2>Ranked paths</h2><div class="scroll"><table>
    <thead><tr><th>#</th><th>Exposure</th><th>Likelihood</th><th>Effort</th><th>Route</th></tr></thead>
    <tbody>{path_rows}</tbody>
  </table></div>
  <h2>Single-edge mitigation analysis</h2><div class="scroll"><table>
    <thead><tr><th>Edge</th><th>Relationship</th><th>Paths removed</th><th>Paths left</th><th>Exposure reduced</th></tr></thead>
    <tbody>{mitigation_rows}</tbody>
  </table></div>
  <footer>Generated locally by attack-path-review. No network collection or active testing is performed.</footer>
</main></body></html>
"""


def dot_graph(result: AnalysisResult) -> str:
    graph = result.graph
    path_edges = {edge_id for path in result.critical_paths for edge_id in path.edges}
    cut_edges = set(result.minimum_cut_edges)

    def quoted(value: str) -> str:
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'

    lines = ["digraph attack_path_review {", "  rankdir=LR;", "  graph [bgcolor=transparent];"]
    for node in sorted(graph.nodes.values(), key=lambda item: item.id):
        shape = "doubleoctagon" if node.crown_jewel else "box" if node.entry else "ellipse"
        lines.append(f"  {quoted(node.id)} [label={quoted(node.label)}, shape={shape}];")
    for edge in graph.edges:
        if not edge.enabled:
            continue
        attributes = [f"label={quoted(edge.relationship)}"]
        if edge.id in cut_edges:
            attributes.extend(['color="#b5412e"', "penwidth=3"])
        elif edge.id in path_edges:
            attributes.extend(['color="#c47b20"', "penwidth=2"])
        lines.append(f"  {quoted(edge.source)} -> {quoted(edge.target)} [{', '.join(attributes)}];")
    lines.append("}")
    return "\n".join(lines) + "\n"


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")
