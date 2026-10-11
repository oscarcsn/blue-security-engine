"""Unit tests for cgroup v2 parsing and bubblewrap argument construction."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bse.isolation.bubblewrap import BubblewrapBuilder
from bse.isolation.cgroups import CgroupLimits


class TestIsolation(unittest.TestCase):
    @staticmethod
    def mount_operations(argv):
        operations = []
        for i, arg in enumerate(argv):
            if arg == "--ro-bind":
                operations.append(tuple(argv[i:i + 3]))
            elif arg == "--tmpfs":
                operations.append(tuple(argv[i:i + 2]))
        return operations

    def test_interleaved_mounts_preserve_call_order(self):
        builder = BubblewrapBuilder()
        builder.add_ro_bind("/synthetic/root", "/work")
        builder.add_tmpfs("/work")
        builder.add_ro_bind("/synthetic/allowed", "/work/allowed")
        builder.add_tmpfs("/work/allowed")
        argv = builder.build_argv(["python3", "-V"])
        selected = [op for op in self.mount_operations(argv) if op[-1].startswith("/work")]
        self.assertEqual(selected, [
            ("--ro-bind", "/synthetic/root", "/work"),
            ("--tmpfs", "/work"),
            ("--ro-bind", "/synthetic/allowed", "/work/allowed"),
            ("--tmpfs", "/work/allowed"),
        ])
        self.assertEqual(builder.build_argv(["python3", "-V"]), argv)

    def test_default_mask_can_be_reapplied_after_bind(self):
        builder = BubblewrapBuilder()
        builder.add_ro_bind("/synthetic/home", "/home")
        builder.add_tmpfs("/home")
        builder.add_ro_bind("/synthetic/allowed", "/home/allowed")
        selected = [op for op in self.mount_operations(builder.build_argv(["python3", "-V"]))
                    if op[-1] in ("/home", "/home/allowed")]
        self.assertEqual(selected, [
            ("--tmpfs", "/home"),
            ("--ro-bind", "/synthetic/home", "/home"),
            ("--tmpfs", "/home"),
            ("--ro-bind", "/synthetic/allowed", "/home/allowed"),
        ])

    def test_malformed_cpu_max_returns_unknown_limits(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            inspector = CgroupLimits(cgroup_root=root)
            for value in ("broken 100000", "25000 broken", "max broken", "25000", ""):
                with self.subTest(value=value):
                    (root / "cpu.max").write_text(value, encoding="ascii")
                    self.assertEqual(inspector.get_cpu_quota_and_period(), (None, None))
            (root / "cpu.max").write_text("max 100000", encoding="ascii")
            self.assertEqual(inspector.get_cpu_quota_and_period(), (None, 100000))

    def test_cgroup_limits_mock(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            (tmp_path / "memory.max").write_text("268435456\n")
            (tmp_path / "memory.swap.max").write_text("0\n")
            (tmp_path / "cpu.max").write_text("25000 100000\n")
            (tmp_path / "pids.max").write_text("16\n")

            inspector = CgroupLimits(cgroup_root=tmp_path)
            self.assertEqual(inspector.get_memory_max_bytes(), 268435456)
            self.assertEqual(inspector.get_swap_max_bytes(), 0)
            quota, period = inspector.get_cpu_quota_and_period()
            self.assertEqual(quota, 25000)
            self.assertEqual(period, 100000)
            self.assertEqual(inspector.get_pids_max(), 16)

            summary = inspector.inspect_all()
            self.assertEqual(summary["cpu_percentage"], 25.0)
            self.assertEqual(summary["memory_max_bytes"], 268435456)

    def test_bubblewrap_builder_invariants(self):
        builder = BubblewrapBuilder(bwrap_binary="/usr/bin/bwrap")
        builder.add_ro_bind("/test/src", "/lab/src")
        builder.set_env("LAB_ENV", "isolated")

        argv = builder.build_argv(["python3", "-c", "print('hello')"])

        self.assertEqual(argv[0], "/usr/bin/bwrap")
        self.assertIn("--unshare-all", argv)
        self.assertIn("--die-with-parent", argv)
        self.assertIn("--new-session", argv)
        self.assertIn("--cap-drop", argv)
        self.assertIn("ALL", argv)
        self.assertIn("--clearenv", argv)
        self.assertIn("--tmpfs", argv)
        self.assertIn("/home", argv)
        self.assertIn("--ro-bind", argv)
        self.assertIn("/test/src", argv)
        self.assertIn("/lab/src", argv)
        self.assertEqual(argv[-4:], ["--", "python3", "-c", "print('hello')"])


class TestCgroupInspection(unittest.TestCase):
    @staticmethod
    def write_limits(root, memory="max", swap="max", cpu="max 100000", pids="max"):
        root.mkdir(parents=True, exist_ok=True)
        for name, value in (("memory.max", memory), ("memory.swap.max", swap),
                            ("cpu.max", cpu), ("pids.max", pids)):
            (root / name).write_text(value + "\n", encoding="ascii")

    def test_limit_parsers_reject_noncanonical_or_nonascii_integers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            inspector = CgroupLimits(root)
            getters = {"memory.max": inspector.get_memory_max_bytes,
                       "memory.swap.max": inspector.get_swap_max_bytes,
                       "pids.max": inspector.get_pids_max}
            for filename, getter in getters.items():
                for value in ("+5", "1_000", "-1", "01", "٠", "1.5", "maxx", "5\n6", "\u00a0",
                              " 5", "5 ", "\t5", "5\t", "5\n\n"):
                    with self.subTest(filename=filename, value=value):
                        (root / filename).write_text(value, encoding="utf-8")
                        self.assertIsNone(getter())
                        self.assertEqual(inspector.inspect_all()["controller_states"][filename], "invalid")

    def test_zero_is_a_valid_memory_swap_and_pids_limit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            self.write_limits(root, memory="0", swap="0", pids="0")
            inspector = CgroupLimits(root)
            report = inspector.inspect_all()
            for field in ("memory_max_bytes", "swap_max_bytes", "pids_max"):
                self.assertEqual(report[field], 0)
                self.assertEqual(report["effective_" + field], 0)
            self.assertEqual(inspector.get_memory_max_bytes(), 0)
            self.assertEqual(inspector.get_swap_max_bytes(), 0)
            self.assertEqual(inspector.get_pids_max(), 0)

    def test_cpu_parser_requires_positive_canonical_quota_and_period(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            inspector = CgroupLimits(root)
            for value in ("0 1000", "1 0", "max max", "+1 10", "1 +10", "01 10",
                          "1 01", "١ 1", "1_0 10", "1\t10", "1  10", "1 -10"):
                with self.subTest(value=value):
                    (root / "cpu.max").write_text(value, encoding="utf-8")
                    self.assertEqual(inspector.get_cpu_quota_and_period(), (None, None))
                    self.assertEqual(inspector.inspect_all()["controller_states"]["cpu.max"], "invalid")
            (root / "cpu.max").write_text("max 100000\n", encoding="ascii")
            self.assertEqual(inspector.get_cpu_quota_and_period(), (None, 100000))
            self.assertEqual(inspector.inspect_all()["controller_states"]["cpu.max"], "max")

    def test_missing_max_and_invalid_are_distinct_report_states(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "memory.max").write_text("max", encoding="ascii")
            (root / "memory.swap.max").write_text("broken", encoding="ascii")
            report = CgroupLimits(root).inspect_all()
            self.assertEqual(report["controller_states"]["memory.max"], "max")
            self.assertEqual(report["controller_states"]["memory.swap.max"], "invalid")
            self.assertEqual(report["controller_states"]["pids.max"], "unavailable")
            self.assertEqual(report["reported"]["memory.max"], "max")
            self.assertEqual(report["reported"]["memory.swap.max"], "broken")
            self.assertIsNone(report["reported"]["pids.max"])

    def test_controller_invalid_encoding_is_reported_not_raised(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            for filename in ("memory.max", "memory.swap.max", "cpu.max", "pids.max"):
                (root / filename).write_bytes(b"\xff")
            inspector = CgroupLimits(root)
            self.assertEqual(inspector.get_cpu_quota_and_period(), (None, None))
            self.assertTrue(all(state == "invalid" for state in inspector.inspect_all()["controller_states"].values()))

    def test_cpu_unrepresentable_percentage_is_invalid_without_overflow(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            for length in (308, 401):
                with self.subTest(length=length):
                    (root / "cpu.max").write_text("1" + "0" * length + " 1", encoding="ascii")
                    report = CgroupLimits(root).inspect_all()
                    self.assertIsNone(report["cpu_percentage"])
                    self.assertIsNone(report["effective_cpu_percentage"])
                    self.assertEqual(report["controller_states"]["cpu.max"], "invalid")

    def test_cpu_huge_integers_with_finite_ratio_preserve_percentage(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            number = "1" + "0" * 400
            (root / "cpu.max").write_text(number + " " + number, encoding="ascii")
            report = CgroupLimits(root).inspect_all()
            self.assertEqual(report["cpu_percentage"], 100.0)
            self.assertEqual(report["controller_states"]["cpu.max"], "limited")

    def test_cpu_percentage_underflow_is_invalid(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "cpu.max").write_text("1 1" + "0" * 400, encoding="ascii")
            report = CgroupLimits(root).inspect_all()
            self.assertIsNone(report["cpu_percentage"])
            self.assertEqual(report["controller_states"]["cpu.max"], "invalid")

    def test_proc_invalid_encoding_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            proc = root / "proc-record"
            proc.write_bytes(b"0::/\xff\n")
            with patch.object(CgroupLimits, "_PROC_CGROUP", proc), patch.object(CgroupLimits, "_CGROUP_MOUNT", root):
                inspector = CgroupLimits()
                self.assertIsNone(inspector.root)
                self.assertEqual(inspector.inspect_all()["resolution_status"], "invalid_proc_record")

    def test_proc_missing_file_has_no_mount_root_fallback(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            self.write_limits(root, memory="123")
            with patch.object(CgroupLimits, "_PROC_CGROUP", root / "missing"), patch.object(CgroupLimits, "_CGROUP_MOUNT", root):
                inspector = CgroupLimits()
                self.assertIsNone(inspector.get_memory_max_bytes())
                self.assertIsNone(inspector.root)
                self.assertEqual(inspector.inspect_all()["resolution_status"], "unavailable_proc_record")

    def test_proc_malformed_and_dotdot_records_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            proc = root / "proc-record"
            for value in ("not-record", "0:cpu:/", "0::", "00::/", "0::/\n0::/", "0::/../..",
                          "0::/a/../b", "0::/./a", "0:://a", "0::/\x00", "0::a", "0::/\r", "0::/\v"):
                with self.subTest(value=value):
                    proc.write_text(value, encoding="ascii")
                    with patch.object(CgroupLimits, "_PROC_CGROUP", proc), patch.object(CgroupLimits, "_CGROUP_MOUNT", root):
                        inspector = CgroupLimits()
                        self.assertIsNone(inspector.root)
                        self.assertTrue(inspector.inspect_all()["resolution_status"].startswith("invalid"))

    def test_autodetected_missing_path_does_not_read_root_limits(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            self.write_limits(root, memory="123")
            proc = root / "proc-record"
            proc.write_text("0::/absent\n", encoding="ascii")
            with patch.object(CgroupLimits, "_PROC_CGROUP", proc), patch.object(CgroupLimits, "_CGROUP_MOUNT", root):
                inspector = CgroupLimits()
                self.assertIsNone(inspector.root)
                self.assertIsNone(inspector.get_memory_max_bytes())
                self.assertEqual(inspector.inspect_all()["resolution_status"], "unavailable_cgroup_path")

    def test_autodetected_symlink_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            mount, outside = root / "mount", root / "outside"
            mount.mkdir()
            self.write_limits(outside, memory="999")
            (mount / "escape").symlink_to(outside, target_is_directory=True)
            proc = root / "proc-record"
            proc.write_text("0::/escape\n", encoding="ascii")
            with patch.object(CgroupLimits, "_PROC_CGROUP", proc), patch.object(CgroupLimits, "_CGROUP_MOUNT", mount):
                inspector = CgroupLimits()
                self.assertIsNone(inspector.root)
                self.assertEqual(inspector.inspect_all()["resolution_status"], "invalid_cgroup_path")

    def test_namespace_root_does_not_claim_host_limit_visibility(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            self.write_limits(root, memory="123")
            proc = root / "proc-record"
            proc.write_text("0::/\n", encoding="ascii")
            with patch.object(CgroupLimits, "_PROC_CGROUP", proc), patch.object(CgroupLimits, "_CGROUP_MOUNT", root):
                report = CgroupLimits().inspect_all()
            self.assertEqual(report["resolution_status"], "resolved_namespace_root")
            self.assertEqual(report["effective_scope"], "visible_cgroup_mount_only")
            self.assertEqual(report["visible_effective_complete"], {
                "memory.max": True, "memory.swap.max": True,
                "cpu.max": True, "pids.max": True,
            })
            self.assertEqual(report["effective_complete"], report["visible_effective_complete"])
            self.assertEqual(report["effective_controller_states"]["cpu.max"], "max")
            self.assertIsNone(report["effective_cpu_percentage"])
            self.assertFalse(report["host_limits_verified"])
            self.assertFalse(report["enforcement_verified"])

    def test_namespace_root_missing_or_invalid_records_are_not_visibly_complete(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            self.write_limits(root, memory="123", cpu="broken")
            (root / "pids.max").unlink()
            proc = root / "proc-record"
            proc.write_text("0::/\n", encoding="ascii")
            with patch.object(CgroupLimits, "_PROC_CGROUP", proc), patch.object(CgroupLimits, "_CGROUP_MOUNT", root):
                report = CgroupLimits().inspect_all()
            self.assertEqual(report["resolution_status"], "resolved_namespace_root")
            self.assertEqual(report["effective_scope"], "visible_cgroup_mount_only")
            self.assertEqual(report["visible_effective_complete"], {
                "memory.max": True, "memory.swap.max": True,
                "cpu.max": False, "pids.max": False,
            })
            self.assertEqual(report["effective_complete"], report["visible_effective_complete"])
            self.assertEqual(report["effective_controller_states"]["cpu.max"], "invalid")
            self.assertEqual(report["effective_controller_states"]["pids.max"], "unavailable")
            self.assertFalse(report["host_limits_verified"])
            self.assertFalse(report["enforcement_verified"])

    def test_effective_limits_take_minimum_of_visible_ancestors(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mount = Path(tmpdir) / "mount"
            parent, leaf = mount / "team", mount / "team/job"
            self.write_limits(mount, memory="1000", swap="max", cpu="max 100000", pids="100")
            self.write_limits(parent, memory="500", swap="0", cpu="20000 100000", pids="50")
            self.write_limits(leaf, memory="800", swap="5", cpu="100000 200000", pids="16")
            proc = Path(tmpdir) / "proc-record"
            proc.write_text("0::/team/job\n", encoding="ascii")
            with patch.object(CgroupLimits, "_PROC_CGROUP", proc), patch.object(CgroupLimits, "_CGROUP_MOUNT", mount):
                report = CgroupLimits().inspect_all()
            self.assertEqual(report["cpu_percentage"], 50.0)
            self.assertEqual(report["effective_cpu_percentage"], 20.0)
            self.assertEqual(report["effective_cpu_quota_us"], 20000)
            self.assertEqual(report["effective_cpu_period_us"], 100000)
            self.assertEqual(report["effective_memory_max_bytes"], 500)
            self.assertEqual(report["effective_swap_max_bytes"], 0)
            self.assertEqual(report["effective_pids_max"], 16)
            self.assertEqual(report["visible_ancestor_paths"], [str(leaf), str(parent), str(mount)])
            self.assertTrue(all(report["visible_effective_complete"].values()))
            self.assertEqual(report["effective_complete"], report["visible_effective_complete"])

    def test_missing_or_invalid_ancestor_makes_effective_limit_unknown(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mount = Path(tmpdir) / "mount"
            leaf = mount / "job"
            self.write_limits(mount, memory="500", cpu="broken")
            self.write_limits(leaf, memory="800", cpu="25000 100000")
            (mount / "memory.max").unlink()
            with patch.object(CgroupLimits, "_CGROUP_MOUNT", mount):
                report = CgroupLimits(leaf).inspect_all()
            self.assertIsNone(report["effective_memory_max_bytes"])
            self.assertEqual(report["known_memory_max_bytes"], 800)
            self.assertEqual(report["effective_controller_states"]["memory.max"], "unavailable")
            self.assertFalse(report["effective_complete"]["memory.max"])
            self.assertFalse(report["visible_effective_complete"]["memory.max"])
            self.assertIsNone(report["effective_cpu_percentage"])
            self.assertEqual(report["known_cpu_percentage"], 25.0)
            self.assertEqual(report["effective_controller_states"]["cpu.max"], "invalid")
            self.assertFalse(report["effective_complete"]["cpu.max"])
            self.assertFalse(report["visible_effective_complete"]["cpu.max"])
            self.assertEqual(report["effective_complete"], report["visible_effective_complete"])

    def test_explicit_fixture_outside_mount_does_not_inherit_parent_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            mount, parent, leaf = root / "mount", root / "fixture", root / "fixture/job"
            mount.mkdir()
            self.write_limits(parent, memory="1", cpu="1 100000", pids="1")
            self.write_limits(leaf, memory="999", cpu="25000 100000", pids="16")
            with patch.object(CgroupLimits, "_CGROUP_MOUNT", mount):
                report = CgroupLimits(leaf).inspect_all()
            self.assertEqual(report["effective_scope"], "explicit_root_only")
            self.assertEqual(report["effective_memory_max_bytes"], 999)
            self.assertEqual(report["effective_cpu_percentage"], 25.0)
            self.assertEqual(report["visible_ancestor_paths"], [str(leaf)])
            self.assertTrue(all(report["visible_effective_complete"].values()))
            self.assertEqual(report["effective_complete"], report["visible_effective_complete"])
            self.assertFalse(report["host_limits_verified"])
            self.assertFalse(report["enforcement_verified"])


if __name__ == "__main__":
    unittest.main()
