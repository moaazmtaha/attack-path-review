# Contributing

Open an issue before a large behavioral change so the graph semantics stay understandable. Small fixes can go directly to a pull request.

Changes should include focused `unittest` coverage, pass `python -m compileall -q src tests`, and avoid hidden network access or telemetry. Keep report output self-contained and escape all user-controlled content. Document scoring or schema changes in `docs/model.md`.

By contributing, you agree that your contribution is licensed under the MIT License.
