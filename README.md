# attack-path-review

`attack-path-review` answers a narrow question: given a trust graph you already understand, which bounded routes to important systems deserve attention first, and which single control change buys the most reduction?

It is an offline Python command-line tool. It does not discover assets, authenticate to infrastructure, scan hosts, or execute attack techniques. You supply a small JSON graph; it validates the model and produces ranked paths, choke points, a global minimum edge cut, and single-edge mitigation comparisons.

## What it calculates

- Loop-free entry-to-crown-jewel paths, bounded by depth and count.
- A transparent exposure score combining path likelihood and target criticality.
- Nodes and edges shared by the largest share of modeled paths.
- A minimum entry-to-target edge cut using an Edmonds–Karp residual network.
- The change in path count and aggregate exposure when each reachable edge is disabled.
- JSON, standalone HTML, Graphviz DOT, and SARIF 2.1.0 output.

The tool is intended for review and prioritization, not as proof that a path is exploitable. A graph is a set of assumptions; stale or optimistic assumptions produce a misleading report.

## Quick start

Python 3.11 or newer is required. Runtime analysis uses only the standard library.

```console
python -m pip install -e .
attack-path-review validate examples/hybrid-lab.json
attack-path-review analyze examples/hybrid-lab.json --out-dir report
```

Open `report/report.html` for the human-readable view. `report/results.sarif` can be uploaded to systems that consume SARIF, and `report/graph.dot` can be rendered with Graphviz if it is installed:

```console
dot -Tsvg report/graph.dot -o report/graph.svg
```

## Input model

Nodes describe identities, services, systems, trust boundaries, or other review units. Mark at least one node as an entry point and one as a crown jewel. Directed edges describe a modeled transition.

```json
{
  "schema_version": 1,
  "title": "Small review",
  "nodes": [
    {"id": "contractor", "label": "Contractor account", "kind": "identity", "entry": true},
    {"id": "prod", "label": "Production", "kind": "environment", "criticality": 10, "crown_jewel": true}
  ],
  "edges": [
    {"id": "e1", "source": "contractor", "target": "prod", "relationship": "deploy role", "likelihood": 0.2, "effort": 7, "controls": ["approval"]}
  ]
}
```

`likelihood` is a reviewer-supplied value from 0 to 1. `effort` is an integer from 1 (easy) to 10 (hard). `criticality` is an integer from 0 to 10. These are local decision aids, not calibrated probabilities.

See [docs/model.md](docs/model.md) for the field and scoring notes, or [schema/attack-path.schema.json](schema/attack-path.schema.json) for a machine-readable JSON Schema. A more representative example and generated outputs are under [examples](examples).

## Operational limits

Path enumeration is deliberately bounded. The default is 200 paths with at most eight edges each; the hard path limit is 10,000 and input files are capped at 10 MiB. The default critical-exposure threshold is 5 because multiplying uncertainty across multi-step paths produces small values quickly; set it from local review history rather than treating it as a universal boundary. If the report says the path limit was reached, narrow the graph or increase `--max-paths` deliberately.

The minimum cut treats every enabled edge as unit cost. Use the mitigation table alongside the cut: the cut answers how many modeled transitions separate all entries from all targets, while mitigation simulation estimates the effect of each edge under the selected depth and path bounds.

## Development

```console
python -m unittest discover -s tests -v
python -m compileall -q src tests
```

Security reports are handled as described in [SECURITY.md](SECURITY.md). Contributions should include a focused test and avoid adding network behavior to the analyzer.
