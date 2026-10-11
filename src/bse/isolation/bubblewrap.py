"""Bubblewrap argument builder preserving caller-specified mount order."""
from __future__ import annotations

import os
from typing import Dict, List, Tuple


class BubblewrapBuilder:
    """Construct bubblewrap arguments; caller mounts are applied in call order."""

    def __init__(self, bwrap_binary: str = "/usr/bin/bwrap") -> None:
        self.bwrap_binary = bwrap_binary
        self._mounts: List[Tuple[str, ...]] = [
            ("--tmpfs", "/tmp"), ("--tmpfs", "/home"), ("--tmpfs", "/run"),
        ]
        self.env_vars: Dict[str, str] = {
            "PATH": "/usr/bin:/bin",
            "HOME": "/tmp",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        self.chdir: str = "/tmp"

    def add_ro_bind(self, source: str, destination: str) -> BubblewrapBuilder:
        self._mounts.append(("--ro-bind", source, destination))
        return self

    def add_tmpfs(self, path: str) -> BubblewrapBuilder:
        # Reapplying an overlay is meaningful after an intervening bind.
        self._mounts.append(("--tmpfs", path))
        return self

    @property
    def ro_binds(self) -> List[Tuple[str, str]]:
        """Return a snapshot; use add_ro_bind to schedule a mount."""
        return [(mount[1], mount[2]) for mount in self._mounts if mount[0] == "--ro-bind"]

    @property
    def tmpfs_mounts(self) -> List[str]:
        """Return a snapshot; use add_tmpfs to schedule an overlay."""
        return [mount[1] for mount in self._mounts if mount[0] == "--tmpfs"]

    def set_env(self, key: str, value: str) -> BubblewrapBuilder:
        self.env_vars[key] = value
        return self

    def build_argv(self, child_command: List[str]) -> List[str]:
        """Generate bwrap argv without reordering caller mounts."""
        argv = [
            self.bwrap_binary,
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--cap-drop", "ALL",
            "--clearenv",
        ]

        # Bind critical runtime libraries read-only if present
        for sys_path in ("/usr", "/bin", "/lib", "/lib64"):
            if os.path.exists(sys_path):
                argv.extend(["--ro-bind", sys_path, sys_path])

        if os.path.isfile("/etc/ld.so.cache"):
            argv.extend(["--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache"])

        # Virtual filesystems
        argv.extend(["--dev", "/dev", "--proc", "/proc"])

        # Bubblewrap applies mounts sequentially, so preserve every call.
        for mount in self._mounts:
            argv.extend(mount)

        # Environment configuration
        for k, v in self.env_vars.items():
            argv.extend(["--setenv", k, v])

        argv.extend(["--chdir", self.chdir])
        argv.append("--")
        argv.extend(child_command)

        return argv
