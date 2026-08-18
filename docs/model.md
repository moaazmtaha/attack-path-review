# Graph model and scoring

The input is a UTF-8 JSON object no larger than 10 MiB. Unknown properties are ignored so teams can keep annotations next to the fields used by the analyzer.

## Root

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `schema_version` | integer | yes | Must be `1`. |
| `title` | string | no | Human-readable review title. |
| `nodes` | array | yes | One or more node objects. |
| `edges` | array | yes | Zero or more directed edge objects. |

At least one node must have `entry: true`, and at least one must have `crown_jewel: true`.

## Nodes

`id` is a stable identifier of 1–128 letters, digits, dots, underscores, colons, or hyphens. `label` and `kind` are non-empty strings. `criticality` is an integer from 0 to 10. `entry` and `crown_jewel` are booleans. `tags` is an optional array of non-empty strings.

## Edges

Each edge has a unique `id`, existing `source` and `target` node IDs, and a non-empty `relationship`. Self-loops are rejected. `likelihood` is a number from 0 to 1, `effort` is an integer from 1 to 10, `controls` is an array of strings, and `enabled` defaults to true.

## Exposure

For a path with edge likelihoods `l₁ ... lₙ` and a target criticality `c`, the reported score is:

```text
likelihood = l₁ × ... × lₙ
exposure   = 100 × likelihood × (0.4 + 0.6 × c / 10)
```

The score is rounded to two decimal places and capped at 100. Multiplication intentionally penalizes long chains with several uncertain transitions. The 0.4 floor keeps a reachable low-criticality target visible. This is a prioritization heuristic, not a frequency estimate or risk certification.

Paths are explored by ascending cumulative effort and then returned by descending exposure. Enumeration stops at a crown jewel, at the configured edge depth, or at the configured path limit. Nodes cannot repeat within a path.

## Choke points and cuts

Choke-point coverage is the fraction of enumerated paths containing a node or edge. Exposure share is the same calculation weighted by each path's exposure.

The minimum edge cut is calculated across all marked entries and crown jewels. Every enabled edge has capacity one; therefore, the result minimizes the number of transitions to break rather than a monetary or operational cost.
