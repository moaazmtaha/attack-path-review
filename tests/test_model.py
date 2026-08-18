from __future__ import annotations

import unittest

from attack_path_review.model import Graph, GraphValidationError


def valid_document() -> dict:
    return {
        "schema_version": 1,
        "title": "Unit graph",
        "nodes": [
            {"id": "entry", "label": "Entry", "kind": "identity", "entry": True},
            {"id": "target", "label": "Target", "kind": "system", "criticality": 10, "crown_jewel": True},
        ],
        "edges": [
            {"id": "edge", "source": "entry", "target": "target", "relationship": "access", "likelihood": 0.5, "effort": 2}
        ],
    }


class GraphValidationTests(unittest.TestCase):
    def test_parses_valid_graph(self) -> None:
        graph = Graph.from_dict(valid_document())
        self.assertEqual(graph.title, "Unit graph")
        self.assertEqual(graph.nodes["target"].criticality, 10)

    def test_collects_multiple_errors(self) -> None:
        document = valid_document()
        document["schema_version"] = 2
        document["nodes"][0]["id"] = "bad id"
        with self.assertRaises(GraphValidationError) as context:
            Graph.from_dict(document)
        self.assertGreaterEqual(len(context.exception.issues), 3)

    def test_rejects_self_loop(self) -> None:
        document = valid_document()
        document["edges"][0]["target"] = "entry"
        with self.assertRaisesRegex(GraphValidationError, "self-loop"):
            Graph.from_dict(document)

    def test_rejects_boolean_numeric_fields(self) -> None:
        document = valid_document()
        document["edges"][0]["likelihood"] = True
        with self.assertRaisesRegex(GraphValidationError, "likelihood"):
            Graph.from_dict(document)

    def test_rejects_entry_that_is_also_target(self) -> None:
        document = valid_document()
        document["nodes"][0]["crown_jewel"] = True
        with self.assertRaisesRegex(GraphValidationError, "both an entry and a crown jewel"):
            Graph.from_dict(document)


if __name__ == "__main__":
    unittest.main()
