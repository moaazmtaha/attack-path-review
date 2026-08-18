from __future__ import annotations

import unittest

from attack_path_review.algorithms import (
    enumerate_attack_paths,
    minimum_edge_cut,
    rank_choke_points,
    simulate_single_edge_mitigations,
)
from attack_path_review.model import Graph


def diamond_graph() -> Graph:
    return Graph.from_dict(
        {
            "schema_version": 1,
            "nodes": [
                {"id": "a", "label": "A", "kind": "entry", "entry": True},
                {"id": "b", "label": "B", "kind": "middle"},
                {"id": "c", "label": "C", "kind": "middle"},
                {"id": "d", "label": "D", "kind": "target", "criticality": 10, "crown_jewel": True},
            ],
            "edges": [
                {"id": "ab", "source": "a", "target": "b", "relationship": "r", "likelihood": 0.8, "effort": 1},
                {"id": "ac", "source": "a", "target": "c", "relationship": "r", "likelihood": 0.6, "effort": 1},
                {"id": "bd", "source": "b", "target": "d", "relationship": "r", "likelihood": 0.5, "effort": 1},
                {"id": "cd", "source": "c", "target": "d", "relationship": "r", "likelihood": 0.5, "effort": 1},
                {"id": "bc", "source": "b", "target": "c", "relationship": "cycle-half", "likelihood": 0.5, "effort": 2},
                {"id": "cb", "source": "c", "target": "b", "relationship": "cycle-half", "likelihood": 0.5, "effort": 2}
            ],
        }
    )


class AlgorithmTests(unittest.TestCase):
    def test_enumerates_loop_free_paths_deterministically(self) -> None:
        graph = diamond_graph()
        first = enumerate_attack_paths(graph, max_depth=4, max_paths=20)
        second = enumerate_attack_paths(graph, max_depth=4, max_paths=20)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 4)
        self.assertTrue(all(len(path.nodes) == len(set(path.nodes)) for path in first))
        self.assertEqual(first[0].exposure, 40.0)

    def test_depth_bound_changes_reachable_set(self) -> None:
        paths = enumerate_attack_paths(diamond_graph(), max_depth=2, max_paths=20)
        self.assertEqual({path.edges for path in paths}, {("ab", "bd"), ("ac", "cd")})

    def test_minimum_edge_cut_has_two_edges(self) -> None:
        cut = minimum_edge_cut(diamond_graph())
        self.assertIn(cut, (("ab", "ac"), ("bd", "cd")))

    def test_choke_points_are_ranked(self) -> None:
        paths = enumerate_attack_paths(diamond_graph(), max_depth=2, max_paths=20)
        points = rank_choke_points(paths)
        self.assertEqual(points[0].coverage, 0.5)
        self.assertEqual(len(points), 6)

    def test_mitigation_reduces_paths(self) -> None:
        graph = diamond_graph()
        paths = enumerate_attack_paths(graph, max_depth=2, max_paths=20)
        impacts = simulate_single_edge_mitigations(graph, paths, max_depth=2, max_paths=20)
        self.assertEqual({impact.paths_removed for impact in impacts}, {1})
        self.assertEqual({impact.remaining_paths for impact in impacts}, {1})

    def test_disabled_edge_is_not_traversed_or_cut(self) -> None:
        graph = diamond_graph().with_edge_disabled("ac")
        paths = enumerate_attack_paths(graph, max_depth=2, max_paths=20)
        self.assertEqual({path.edges for path in paths}, {("ab", "bd")})
        self.assertEqual(minimum_edge_cut(graph), ("ab",))

    def test_excluded_node_removes_route(self) -> None:
        paths = enumerate_attack_paths(
            diamond_graph(), max_depth=4, max_paths=20, excluded_nodes=frozenset({"b"})
        )
        self.assertEqual({path.edges for path in paths}, {("ac", "cd")})

    def test_path_count_bound_is_enforced(self) -> None:
        paths = enumerate_attack_paths(diamond_graph(), max_depth=4, max_paths=1)
        self.assertEqual(len(paths), 1)

    def test_rejects_invalid_enumeration_bounds(self) -> None:
        with self.assertRaisesRegex(ValueError, "max_depth"):
            enumerate_attack_paths(diamond_graph(), max_depth=0)
        with self.assertRaisesRegex(ValueError, "max_paths"):
            enumerate_attack_paths(diamond_graph(), max_paths=10_001)


if __name__ == "__main__":
    unittest.main()
