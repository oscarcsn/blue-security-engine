"""Gate the fixed CI worker before package imports or backend execution.

This checks visible kernel state against a root-created read-only policy.
It does not resist an operator who can rewrite this trusted CI configuration.
"""

import json
import os
from pathlib import Path
import socket
import sys


CAPS = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
NAMESPACES = ("user", "mnt", "pid", "net", "ipc", "uts", "cgroup")


def require(condition, message):
    if not condition:
        raise RuntimeError("CI admission denied: " + message)


def mount_options(path):
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) > 6 and fields[4] == path:
            return set(fields[5].split(","))
    raise RuntimeError("CI admission denied: mount missing: " + path)


def await_admission():
    policy_path = Path("/policy/profile.json")
    require("ro" in mount_options("/policy"), "policy must be read-only")
    policy = json.loads(policy_path.read_text())
    require(set(policy) == {"nonce", "uid", "host_namespaces", "limits", "scratch", "apparmor_profile"}, "policy shape")
    require(type(policy["uid"]) is int and os.getuid() == os.geteuid() == policy["uid"] != 0, "worker identity")
    require(type(policy["nonce"]) is str and len(policy["nonce"]) == 32, "nonce")
    expected_env = {"HOME": "/tmp/home", "TMPDIR": "/tmp", "PATH": "/usr/bin", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1", "PWD": "/source"}
    if dict(os.environ) != expected_env:
        print(json.dumps({"ci_environment_mismatch": {"extra_keys": sorted(set(os.environ) - set(expected_env)),
              "missing_keys": sorted(set(expected_env) - set(os.environ)),
              "different_value_keys": sorted(name for name in set(expected_env) & set(os.environ) if os.environ[name] != expected_env[name])}}), flush=True)
        raise RuntimeError("CI admission denied: clean worker environment")
    expected_profile = policy["apparmor_profile"]
    require(expected_profile in (None, "bwrap", "bse-ci-bwrap"), "AppArmor profile policy")
    if expected_profile is not None:
        actual_profile = Path("/proc/self/attr/current").read_text().strip()
        require(actual_profile in (expected_profile + " (enforce)", expected_profile + " (unconfined)"), "Expected bwrap AppArmor attachment")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    require(all(int(status[name].strip(), 16) == 0 for name in CAPS), "capabilities")
    require(status["NoNewPrivs"].strip() == "1", "NoNewPrivileges")
    namespaces = {name: os.readlink("/proc/self/ns/" + name) for name in NAMESPACES}
    require(set(policy["host_namespaces"]) == set(NAMESPACES), "namespace policy")
    require(all(namespaces[name] != policy["host_namespaces"][name] for name in NAMESPACES), "private namespaces")
    limits = {name: (Path("/sys/fs/cgroup") / name).read_text().strip() for name in policy["limits"]}
    require(limits == {"memory.max": "805306368", "memory.swap.max": "0", "memory.oom.group": "1", "cpu.max": "25000 100000", "pids.max": "48"}, "aggregate limits")
    require(limits == policy["limits"], "limit policy mismatch")
    for path in ("/source", "/policy", "/deps", "/sys/fs/cgroup", "/usr", "/etc/passwd", "/etc/group"):
        require("ro" in mount_options(path), "read-only mount: " + path)
    scratch = os.statvfs("/tmp")
    require(scratch.f_blocks * scratch.f_frsize == policy["scratch"]["bytes"] == 67108864, "scratch byte limit")
    require(scratch.f_files == policy["scratch"]["inodes"] == 2048, "scratch inode limit")
    require(not list(Path("/home").iterdir()) and not list(Path("/root").iterdir()), "Host homes must be completely absent")
    for path in ("/home/runner", "/root/.ssh", "/etc/ssh", "/run/tailscale", "/run/docker.sock"):
        require(not os.path.lexists(path), "host credentials or administrative socket visible")
    devices = [line.split(":", 1)[0].strip() for line in Path("/proc/net/dev").read_text().splitlines()[2:] if ":" in line]
    require(devices == ["lo"], "network interface isolation")
    routes = Path("/proc/net/route").read_text().splitlines()[1:]
    require(not any(len(line.split()) > 1 and line.split()[1] == "00000000" for line in routes), "default route")
    # systemd blocks INET families even within the already-private network.
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
        except OSError:
            continue
        else:
            sock.close()
            raise RuntimeError("CI admission denied: INET family available")
    print(json.dumps({"event": "ready", "nonce": policy["nonce"], "uid": os.getuid(), "limits": limits, "namespaces": namespaces, "apparmor_profile": expected_profile}), flush=True)
    line = sys.stdin.readline(128)
    require(line == "GO " + policy["nonce"] + "\n", "supervisor gate")
    sys.stdin.close()
    Path("/tmp/home").mkdir(mode=0o700)
    return policy
