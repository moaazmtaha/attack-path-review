from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .analysis import AnalysisConfig, analyze
from .io import load_graph, write_json
from .model import GraphValidationError
from .report import dot_graph, html_report, result_document, write_text
from .sarif import sarif_document


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="attack-path-review",
        description="Analyze a user-supplied trust graph without scanning or network access.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate", help="Validate the graph and exit.")
    validate.add_argument("input", type=Path)

    analyze_parser = subparsers.add_parser("analyze", help="Analyze paths and write portable reports.")
    analyze_parser.add_argument("input", type=Path)
    analyze_parser.add_argument("--out-dir", type=Path, default=Path("attack-path-report"))
    analyze_parser.add_argument("--max-depth", type=int, default=8)
    analyze_parser.add_argument("--max-paths", type=int, default=200)
    analyze_parser.add_argument("--critical-exposure", type=float, default=5.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        graph = load_graph(args.input)
        if args.command == "validate":
            print(f"valid: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
            return 0

        config = AnalysisConfig(
            max_depth=args.max_depth,
            max_paths=args.max_paths,
            critical_exposure=args.critical_exposure,
        )
        result = analyze(graph, config)
        out_dir: Path = args.out_dir
        source = str(args.input)
        write_json(out_dir / "report.json", result_document(result, source=source))
        write_text(out_dir / "report.html", html_report(result, source=source))
        write_text(out_dir / "graph.dot", dot_graph(result))
        write_json(out_dir / "results.sarif", sarif_document(result, source_path=args.input))
        print(
            f"analyzed {len(graph.nodes)} nodes and {sum(edge.enabled for edge in graph.edges)} enabled edges; "
            f"found {len(result.paths)} paths ({len(result.critical_paths)} critical)"
        )
        print(f"reports: {out_dir.resolve()}")
        return 0
    except (GraphValidationError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
