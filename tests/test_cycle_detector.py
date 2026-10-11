"""Unit tests for agent session cycle detection and graph validation."""
import unittest

from bse.defense.cycle_detector import (
    CyclicSessionGraphError,
    detect_cycles,
    validate_acyclic_entries,
)


class TestCycleDetector(unittest.TestCase):
    def test_acyclic_chain_passes(self):
        entries = [
            {"uuid": "node-1", "parentUuid": None},
            {"uuid": "node-2", "parentUuid": "node-1"},
            {"uuid": "node-3", "parentUuid": "node-2"},
        ]
        self.assertEqual(detect_cycles(entries), [])
        validate_acyclic_entries(entries)

    def test_direct_circular_dependency_detected(self):
        entries = [
            {"uuid": "node-A", "parentUuid": "node-B"},
            {"uuid": "node-B", "parentUuid": "node-A"},
        ]
        cycles = detect_cycles(entries)
        self.assertGreater(len(cycles), 0)
        with self.assertRaises(CyclicSessionGraphError) as ctx:
            validate_acyclic_entries(entries)
        self.assertIn("Adversarial or malformed cyclic reference detected", str(ctx.exception))
        self.assertGreaterEqual(len(ctx.exception.cycle_path), 2)

    def test_self_referencing_node_detected(self):
        entries = [{"uuid": "node-X", "parentUuid": "node-X"}]
        cycles = detect_cycles(entries)
        self.assertEqual(len(cycles), 1)
        self.assertEqual(cycles[0], ["node-X", "node-X"])
        with self.assertRaises(CyclicSessionGraphError):
            validate_acyclic_entries(entries)

    def test_complex_dag_with_branching_and_late_cycle(self):
        entries = [
            {"uuid": "root", "parentUuid": None},
            {"uuid": "branch1", "parentUuid": "root"},
            {"uuid": "branch2", "parentUuid": "root"},
            {"uuid": "cycle-1", "parentUuid": "cycle-2"},
            {"uuid": "cycle-2", "parentUuid": "cycle-3"},
            {"uuid": "cycle-3", "parentUuid": "cycle-1"},
        ]
        cycles = detect_cycles(entries)
        self.assertEqual(len(cycles), 1)
        self.assertEqual(set(cycles[0]), {"cycle-1", "cycle-2", "cycle-3"})

    def test_null_ids_are_rejected_without_silently_omitting_nodes(self):
        entries = [
            {"uuid": None, "parentUuid": "child"},
            {"uuid": "child", "parentUuid": "None"},
            {"uuid": "None", "parentUuid": None},
        ]
        with self.assertRaisesRegex(ValueError, "Node entry missing valid non-empty identifier"):
            detect_cycles(entries)

    def test_missing_empty_and_null_node_identifiers_fail_closed(self):
        for entry in ({}, {"uuid": None}, {"uuid": ""}, {"uuid": " \t\n"}, None, []):
            for validate in (detect_cycles, validate_acyclic_entries):
                with self.subTest(entry=entry, validator=validate.__name__):
                    with self.assertRaisesRegex(ValueError, "Node entry missing valid non-empty identifier"):
                        validate([{"uuid": "valid-root"}, entry])

    def test_custom_id_key_requires_valid_nodes_and_allows_absent_parents(self):
        self.assertEqual(detect_cycles([
            {"node": 0}, {"node": "child", "parent": 0},
        ], id_key="node", parent_key="parent"), [])
        with self.assertRaisesRegex(ValueError, "Node entry missing valid non-empty identifier"):
            detect_cycles([{"uuid": "wrong-key"}], id_key="node")

    def test_zero_ids_and_parents_use_the_same_normalization(self):
        entries = [
            {"uuid": 0, "parentUuid": "child"},
            {"uuid": "child", "parentUuid": 0},
        ]
        self.assertEqual(detect_cycles(entries), [["0", "child", "0"]])

    def test_duplicate_ids_are_rejected_including_roots(self):
        for entries in (
            [{"uuid": "root"}, {"uuid": "root", "parentUuid": "child"}],
            [{"uuid": 0}, {"uuid": "0"}],
        ):
            with self.subTest(entries=entries), self.assertRaisesRegex(ValueError, "Duplicate graph uuid"):
                detect_cycles(entries)

    def test_unsupported_identifier_types_are_rejected_consistently(self):
        for invalid in (False, True, 1.5, [], {}):
            for field in ("uuid", "parentUuid"):
                entry = {"uuid": "node", field: invalid}
                with self.subTest(field=field, invalid=invalid), self.assertRaises(ValueError):
                    detect_cycles([entry])

    def test_exception_reports_all_disjoint_cycles(self):
        entries = [
            {"uuid": "a", "parentUuid": "b"},
            {"uuid": "b", "parentUuid": "a"},
            {"uuid": "x", "parentUuid": "x"},
        ]
        with self.assertRaises(CyclicSessionGraphError) as ctx:
            validate_acyclic_entries(entries)
        self.assertEqual(ctx.exception.cycles, [["a", "b", "a"], ["x", "x"]])
        self.assertEqual(ctx.exception.cycle_path, ["a", "b", "a"])
        self.assertIn("a -> b -> a", str(ctx.exception))
        self.assertIn("x -> x", str(ctx.exception))

    def test_unsupported_parent_is_rejected_before_its_equality_hook_runs(self):
        class AlwaysEqual:
            def __eq__(self, other):
                raise AssertionError("Unsupported identifiers must not be compared")

        with self.assertRaisesRegex(ValueError, "Graph identifiers must be strings or integers"):
            detect_cycles([{"uuid": "node", "parentUuid": AlwaysEqual()}])


if __name__ == "__main__":
    unittest.main()
