from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from attack_path_review.cli import main


class CliTests(unittest.TestCase):
    def test_analyze_writes_all_formats(self) -> None:
        source = Path(__file__).parents[1] / "examples" / "hybrid-lab.json"
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "out"
            code = main(["analyze", str(source), "--out-dir", str(output)])
            self.assertEqual(code, 0)
            self.assertEqual(
                {path.name for path in output.iterdir()},
                {"report.json", "report.html", "graph.dot", "results.sarif"},
            )
            sarif = json.loads((output / "results.sarif").read_text(encoding="utf-8"))
            self.assertEqual(sarif["version"], "2.1.0")

    def test_invalid_document_returns_usage_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "bad.json"
            source.write_text("[]", encoding="utf-8")
            self.assertEqual(main(["validate", str(source)]), 2)


if __name__ == "__main__":
    unittest.main()
