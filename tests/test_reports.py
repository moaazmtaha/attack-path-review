from __future__ import annotations

import unittest

from attack_path_review.analysis import AnalysisConfig, analyze
from attack_path_review.model import Graph
from attack_path_review.report import dot_graph, html_report, result_document


def hostile_graph() -> Graph:
    return Graph.from_dict(
        {
            "schema_version": 1,
            "title": "<script>alert(1)</script>",
            "nodes": [
                {"id": "entry", "label": "<b>Entry</b>", "kind": "identity", "entry": True},
                {"id": "target", "label": "Target", "kind": "system", "criticality": 10, "crown_jewel": True},
            ],
            "edges": [
                {"id": "edge", "source": "entry", "target": "target", "relationship": "quote \" slash \\", "likelihood": 0.9, "effort": 1}
            ],
        }
    )


class ReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.result = analyze(hostile_graph(), AnalysisConfig(critical_exposure=20))

    def test_html_escapes_graph_content(self) -> None:
        report = html_report(self.result, source="<input>")
        self.assertNotIn("<script>alert(1)</script>", report)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", report)
        self.assertIn("&lt;input&gt;", report)

    def test_dot_escapes_quotes_and_backslashes(self) -> None:
        dot = dot_graph(self.result)
        self.assertIn('label="quote \\" slash \\\\"', dot)

    def test_json_document_is_structured(self) -> None:
        document = result_document(self.result, source="fixture.json")
        self.assertEqual(document["schema_version"], 1)
        self.assertEqual(document["summary"]["critical_paths"], 1)


if __name__ == "__main__":
    unittest.main()
