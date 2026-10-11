"""Read cgroups v2 limits without asserting that a supervisor enforces them."""
from __future__ import annotations

from fractions import Fraction
import math
from pathlib import Path
import re
from typing import Any, Dict, Optional, Tuple


_CANONICAL_UINT = re.compile(r"(?:0|[1-9][0-9]*)", re.ASCII)
_CANONICAL_CPU = re.compile(r"(max|[1-9][0-9]*) ([1-9][0-9]*)", re.ASCII)
_CONTROLLERS = ("memory.max", "memory.swap.max", "cpu.max", "pids.max")


class CgroupLimits:
    """Inspect reported limits and ancestors visible in the current cgroup mount.

    An explicit root outside the cgroup mount is a single-root fixture/API view.
    Missing files are not interpreted as unlimited. Namespace visibility cannot
    establish host limits or enforcement for a process and all its descendants.
    """

    _CGROUP_MOUNT = Path("/sys/fs/cgroup")
    _PROC_CGROUP = Path("/proc/self/cgroup")

    def __init__(self, cgroup_root: Optional[Path] = None) -> None:
        self._explicit_root = cgroup_root is not None
        if cgroup_root is not None:
            self.root: Optional[Path] = Path(cgroup_root)
            self.resolution_status = "explicit"
        else:
            self.root, self.resolution_status = self._resolve_cgroup()

    @classmethod
    def _resolve_cgroup(cls) -> Tuple[Optional[Path], str]:
        """Resolve one canonical unified record, with no fallback to mount root."""
        try:
            lines = cls._PROC_CGROUP.read_bytes().decode("ascii").split("\n")
            if lines and lines[-1] == "":
                lines.pop()
        except (UnicodeError, ValueError):
            return None, "invalid_proc_record"
        except OSError:
            return None, "unavailable_proc_record"
        unified = []
        for line in lines:
            if any(ord(char) < 32 or ord(char) == 127 for char in line):
                return None, "invalid_proc_record"
            parts = line.split(":", 2)
            if len(parts) != 3 or _CANONICAL_UINT.fullmatch(parts[0]) is None:
                return None, "invalid_proc_record"
            hierarchy, controllers, path = parts
            if hierarchy == "0":
                if controllers or not path.startswith("/"):
                    return None, "invalid_proc_record"
                unified.append(path)
            elif not controllers or not path.startswith("/"):
                return None, "invalid_proc_record"
        if len(unified) != 1:
            return None, "invalid_proc_record" if unified else "unavailable_v2_record"
        subpath = unified[0]
        components = subpath.split("/")[1:]
        if subpath != "/" and (any(part in ("", ".", "..") for part in components)
                                or any(ord(char) < 32 or ord(char) == 127 for char in subpath)):
            return None, "invalid_cgroup_path"
        try:
            mount = cls._CGROUP_MOUNT.resolve(strict=True)
            candidate = (mount / subpath.lstrip("/")).resolve(strict=True)
            candidate.relative_to(mount)
            if not candidate.is_dir():
                return None, "unavailable_cgroup_path"
        except ValueError:
            return None, "invalid_cgroup_path"
        except (OSError, RuntimeError):
            return None, "unavailable_cgroup_path"
        return candidate, "resolved_namespace_root" if subpath == "/" else "resolved"

    @classmethod
    def _resolve_current_cgroup(cls) -> Optional[Path]:
        """Compatibility helper: return None when autodetection cannot resolve."""
        return cls._resolve_cgroup()[0]

    @staticmethod
    def _read_record(root: Optional[Path], filename: str) -> Tuple[Optional[str], str]:
        if root is None:
            return None, "unavailable"
        try:
            return (root / filename).read_bytes().decode("ascii").removesuffix("\n"), "read"
        except (UnicodeError, ValueError):
            return None, "invalid"
        except OSError:
            return None, "unavailable"

    def _read_controller_file(self, filename: str) -> Optional[str]:
        return self._read_record(self.root, filename)[0]

    @staticmethod
    def _parse_limit(value: str) -> Tuple[Optional[int], str]:
        if value == "max":
            return None, "max"
        if _CANONICAL_UINT.fullmatch(value) is None:
            return None, "invalid"
        try:
            return int(value), "limited"
        except ValueError:
            return None, "invalid"

    @staticmethod
    def _parse_cpu(value: str) -> Tuple[Optional[int], Optional[int], str]:
        match = _CANONICAL_CPU.fullmatch(value)
        if match is None:
            return None, None, "invalid"
        try:
            period = int(match[2])
            quota = None if match[1] == "max" else int(match[1])
        except ValueError:
            return None, None, "invalid"
        return quota, period, "max" if quota is None else "limited"

    @staticmethod
    def _cpu_percentage(quota: Optional[int], period: Optional[int]) -> Optional[float]:
        if quota is None or period is None:
            return None
        try:
            percent = float(Fraction(quota * 100, period))
            return round(percent, 2) if math.isfinite(percent) and percent > 0 else None
        except (OverflowError, ValueError, ZeroDivisionError):
            return None

    def _get_limit(self, filename: str) -> Optional[int]:
        raw, state = self._read_record(self.root, filename)
        return self._parse_limit(raw)[0] if state == "read" and raw is not None else None

    def get_memory_max_bytes(self) -> Optional[int]:
        return self._get_limit("memory.max")

    def get_swap_max_bytes(self) -> Optional[int]:
        return self._get_limit("memory.swap.max")

    def get_pids_max(self) -> Optional[int]:
        return self._get_limit("pids.max")

    def get_cpu_quota_and_period(self) -> Tuple[Optional[int], Optional[int]]:
        raw, state = self._read_record(self.root, "cpu.max")
        if state != "read" or raw is None:
            return None, None
        quota, period, _ = self._parse_cpu(raw)
        return quota, period

    @classmethod
    def _snapshot(cls, root: Optional[Path]) -> Dict[str, Any]:
        reported: Dict[str, Optional[str]] = {}
        states: Dict[str, str] = {}
        values: Dict[str, Optional[int]] = {}
        quota = period = None
        percentage = None
        for filename in _CONTROLLERS:
            raw, state = cls._read_record(root, filename)
            reported[filename] = raw
            if state == "read" and raw is not None:
                if filename == "cpu.max":
                    quota, period, state = cls._parse_cpu(raw)
                    percentage = cls._cpu_percentage(quota, period)
                    if state == "limited" and percentage is None:
                        state = "invalid"
                else:
                    values[filename], state = cls._parse_limit(raw)
            else:
                values[filename] = None
            states[filename] = state
        return {
            "reported": reported, "controller_states": states,
            "memory_max_bytes": values.get("memory.max"),
            "swap_max_bytes": values.get("memory.swap.max"),
            "cpu_quota_us": quota, "cpu_period_us": period,
            "cpu_percentage": percentage, "pids_max": values.get("pids.max"),
        }

    def _visible_ancestors(self) -> Tuple[Tuple[Path, ...], str]:
        if self.root is None:
            return (), "unresolved"
        try:
            mount = self._CGROUP_MOUNT.resolve(strict=True)
            current = self.root.resolve(strict=True)
            current.relative_to(mount)
        except (OSError, ValueError, RuntimeError):
            return ((self.root,), "explicit_root_only") if self._explicit_root else ((), "unavailable_visible_hierarchy")
        ancestors = [current]
        while ancestors[-1] != mount:
            ancestors.append(ancestors[-1].parent)
        return tuple(ancestors), "visible_cgroup_mount_only"

    def inspect_all(self) -> Dict[str, Any]:
        """Report current readings and conservative effective visible limits.

        Effective values are unknown when any inspected ancestor is unavailable
        or invalid; known_* fields expose partial observed limits separately.
        visible_effective_complete describes readable, valid controller records
        only within effective_scope, including valid unlimited (max) records.
        effective_complete is a deprecated compatibility alias of that map.
        Even a complete visible hierarchy cannot reveal hidden host ancestors
        or verify that an execution supervisor enforces limits.
        """
        current = self._snapshot(self.root)
        roots, scope = self._visible_ancestors()
        snapshots = [current, *(self._snapshot(root) for root in roots[1:])] if roots else []
        effective_states: Dict[str, str] = {}
        effective: Dict[str, Any] = {}
        known: Dict[str, Any] = {}
        field_names = {"memory.max": "memory_max_bytes", "memory.swap.max": "swap_max_bytes",
                       "pids.max": "pids_max"}
        for filename in _CONTROLLERS:
            states = [snapshot["controller_states"][filename] for snapshot in snapshots]
            state = ("invalid" if "invalid" in states else
                     "unavailable" if not states or "unavailable" in states else
                     "limited" if "limited" in states else "max")
            effective_states[filename] = state
            if filename == "cpu.max":
                limited = [snapshot for snapshot in snapshots
                           if snapshot["controller_states"][filename] == "limited"]
                lowest = min(limited, key=lambda row: Fraction(row["cpu_quota_us"], row["cpu_period_us"])) if limited else None
                for field in ("cpu_quota_us", "cpu_period_us", "cpu_percentage"):
                    known[field] = lowest[field] if lowest else None
                    effective[field] = known[field] if state == "limited" else None
            else:
                field = field_names[filename]
                values = [snapshot[field] for snapshot in snapshots
                          if snapshot["controller_states"][filename] == "limited"]
                known[field] = min(values) if values else None
                effective[field] = known[field] if state == "limited" else None
        visible_effective_complete = {
            key: state in ("limited", "max")
            for key, state in effective_states.items()
        }
        return {
            "cgroup_path": str(self.root) if self.root is not None else None,
            **current,
            "resolution_status": self.resolution_status,
            "effective_scope": scope,
            "visible_ancestor_paths": [str(root) for root in roots],
            "ancestor_controller_states": {str(root): snapshot["controller_states"]
                                           for root, snapshot in zip(roots, snapshots)},
            "effective_controller_states": effective_states,
            "visible_effective_complete": visible_effective_complete,
            # Preserve existing consumers; this alias has no broader scope.
            "effective_complete": dict(visible_effective_complete),
            **{"effective_" + key: value for key, value in effective.items()},
            **{"known_" + key: value for key, value in known.items()},
            "host_limits_verified": False,
            "enforcement_verified": False,
        }
