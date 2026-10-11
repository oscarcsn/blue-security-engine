"""Trusted administrator for one fixed offline CI profile on GitHub Linux.

This is not a general runner or a sandbox resistant to repository operators.
It must never be used to execute BSE on the productive hp workstation.
Only the staged worker executes package code, after the kernel-state gate.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time


LIMITS = {"memory.max": "805306368", "memory.swap.max": "0", "cpu.max": "25000 100000", "pids.max": "48"}
NAMESPACES = ("user", "mnt", "pid", "net", "ipc", "uts", "cgroup")
MAX_OUTPUT = 524288


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def unit_state(unit):
    result = subprocess.run(
        ["/usr/bin/systemctl", "show", unit,
         "--property=LoadState,InvocationID,ControlGroup,MainPID,ActiveState,SubState,Description,Result,ExecMainStatus"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=8, check=False,
    )
    require(len(result.stdout) <= 16384, "Unbounded unit metadata")
    fields = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    require(fields.get("LoadState") is not None, "Cannot inspect own unit")
    return fields


def cgroup_path(value):
    require(type(value) is str and re.fullmatch(r"/(?:[A-Za-z0-9_.:-]+/)*[A-Za-z0-9_.:-]+", value), "Unexpected cgroup path")
    require(all(part not in (".", "..") for part in value.split("/")), "Invalid cgroup path")
    return Path("/sys/fs/cgroup") / value.lstrip("/")


def sealed_copy(source, destination, *, exclude=()):
    require(source.is_dir() and not source.is_symlink(), "Snapshot source must be a directory")
    destination.mkdir(mode=0o755)
    hashes = {}
    total = 0
    count = 0
    for parent, directories, files in os.walk(source, followlinks=False):
        directories[:] = sorted(name for name in directories if name not in exclude)
        relative = Path(parent).relative_to(source)
        target_parent = destination / relative
        for name in directories:
            child = Path(parent) / name
            require(not child.is_symlink(), "Source directory symlink rejected")
            (target_parent / name).mkdir(mode=0o755)
        for name in sorted(files):
            child = Path(parent) / name
            info = child.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "Source must contain regular, non-hardlinked files")
            count += 1
            total += info.st_size
            require(count <= 256 and total <= 16777216, "Snapshot exceeds fixed source budget")
            fd = os.open(child, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                observed = os.fstat(stream.fileno())
                require((observed.st_dev, observed.st_ino, observed.st_size) == (info.st_dev, info.st_ino, info.st_size), "Source changed while staging")
                data = stream.read(info.st_size + 1)
            require(len(data) == info.st_size, "Source length changed while staging")
            output = target_parent / name
            output.write_bytes(data)
            output.chmod(0o444)
            hashes[(relative / name).as_posix()] = hashlib.sha256(data).hexdigest()
    for parent, directories, files in os.walk(destination, topdown=False):
        Path(parent).chmod(0o555)
    return hashes


def launch(stage):
    """Trusted unit helper; this function imports no package/backend code."""
    require(os.getuid() != 0, "Worker unit cannot run as root")
    records = Path("/proc/self/cgroup").read_text().splitlines()
    require(len(records) == 1 and records[0].startswith("0::"), "cgroup v2 required")
    own_cgroup = cgroup_path(records[0][3:])
    require({name: (own_cgroup / name).read_text().strip() for name in LIMITS} == LIMITS, "Unit limits unavailable or mismatched")
    scratch = stage / "scratch"
    fs = os.statvfs(scratch)
    require(fs.f_blocks * fs.f_frsize == 67108864 and fs.f_files == 2048, "Unit scratch quota mismatch")
    argv = [
        "/usr/bin/bwrap", "--unshare-all", "--unshare-cgroup", "--die-with-parent",
        "--new-session", "--cap-drop", "ALL", "--clearenv",
        "--uid", str(os.getuid()), "--gid", str(os.getgid()),
        "--ro-bind", "/usr", "/usr",
    ]
    for name in ("bin", "sbin", "lib", "lib64"):
        path = Path("/") / name
        if path.is_symlink():
            argv += ["--symlink", os.readlink(path), str(path)]
        elif path.exists():
            argv += ["--ro-bind", str(path), str(path)]
    argv += [
        "--proc", "/proc", "--dev", "/dev", "--dir", "/home", "--dir", "/root", "--dir", "/etc", "--dir", "/run",
        "--ro-bind", str(stage / "policy/passwd"), "/etc/passwd",
        "--ro-bind", str(stage / "policy/group"), "/etc/group",
        "--dir", "/sys", "--dir", "/sys/fs", "--ro-bind", str(own_cgroup), "/sys/fs/cgroup",
        "--ro-bind", str(stage / "source"), "/source",
        "--ro-bind", str(stage / "policy"), "/policy",
        "--ro-bind", str(stage / "deps"), "/deps",
        "--bind", str(scratch), "/tmp",
        "--setenv", "HOME", "/tmp/home", "--setenv", "TMPDIR", "/tmp",
        "--setenv", "PATH", "/usr/bin", "--setenv", "LANG", "C.UTF-8",
        "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
        "--chdir", "/source", "--remount-ro", "/",
        "--", "/usr/bin/python3", "-I", "-B", "/policy/worker.py",
    ]
    os.execv(argv[0], argv)


def interrupted(signum, frame):
    raise RuntimeError("CI interrupted by signal " + str(signum))


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--workspace")
    parser.add_argument("--dependencies")
    parser.add_argument("--python-minor", choices=("3.10", "3.12"), default="3.12")
    parser.add_argument("--launch")
    args = parser.parse_args()
    if args.launch is not None:
        require(args.workspace is None and args.dependencies is None, "Closed helper arguments")
        stage = Path(args.launch)
        require(re.fullmatch(r"/run/bse-ci-[0-9a-f]{32}", str(stage)) is not None, "Fixed staging path required")
        return launch(stage)
    require(os.geteuid() == 0 and args.workspace and args.dependencies, "Root CI administrator requires fixed workspace/dependencies")
    uid = int(os.environ.get("SUDO_UID", "0"))
    gid = int(os.environ.get("SUDO_GID", "0"))
    require(uid > 0 and gid > 0 and pwd.getpwuid(uid).pw_name == "runner", "Only the GitHub-hosted runner account is supported")
    require(Path("/opt/hostedtoolcache").is_dir(), "This controller requires the specialized ephemeral GitHub runner")
    require(f"{sys.version_info.major}.{sys.version_info.minor}" == args.python_minor, "System Python differs from matrix expectation")
    require(Path("/sys/fs/cgroup/cgroup.controllers").is_file(), "Unified cgroup v2 required")
    require(Path("/usr/bin/bwrap").is_file(), "Bubblewrap unavailable")
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupted)
    nonce = secrets.token_hex(16)
    unit = "bse-ci-" + nonce + ".service"
    description = "BSE fixed CI " + nonce
    stage = Path("/run/bse-ci-" + nonce)
    record = {"status": "FAIL", "nonce": nonce, "unit": unit, "python": sys.version.split()[0], "gate_released": False,
              "scope": "Fixed own-package offline CI; trusted configuration, not an arbitrary runner"}
    process = None
    invocation = None
    control_group = None
    stage_identity = None
    output = bytearray()
    result_record = None
    try:
        require(unit_state(unit)["LoadState"] == "not-found", "Own unit name must be unused")
        stage.mkdir(mode=0o755)
        stage_identity = (stage.stat().st_dev, stage.stat().st_ino)
        workspace = Path(args.workspace).resolve(strict=True)
        dependencies = Path(args.dependencies).resolve(strict=True)
        require(workspace.is_relative_to(Path("/home/runner/work")), "Workspace must be in the hosted runner work tree")
        require(dependencies.is_relative_to(Path("/home/runner/work/_temp")), "Prepared dependencies must be in runner temporary storage")
        record["source_sha256"] = sealed_copy(workspace, stage / "source", exclude=(".git", ".github", "__pycache__", "build", "dist"))
        record["policy_sha256"] = sealed_copy(workspace / ".github/ci", stage / "policy", exclude=("__pycache__",))
        record["dependency_sha256"] = sealed_copy(dependencies, stage / "deps")
        require((stage / "policy/worker.py").is_file() and (stage / "policy/admission.py").is_file(), "Fixed policy worker missing")
        (stage / "scratch").mkdir(mode=0o755)
        policy = {"nonce": nonce, "uid": uid, "host_namespaces": {name: os.readlink("/proc/self/ns/" + name) for name in NAMESPACES},
                  "limits": LIMITS, "scratch": {"bytes": 67108864, "inodes": 2048}}
        (stage / "policy").chmod(0o755)
        (stage / "policy/profile.json").write_text(json.dumps(policy) + "\n")
        (stage / "policy/profile.json").chmod(0o444)
        # Minimal synthetic identity records; never copy host passwd/group.
        (stage / "policy/passwd").write_text(f"runner:x:{uid}:{gid}:CI worker:/tmp/home:/usr/sbin/nologin\n")
        (stage / "policy/group").write_text(f"runner:x:{gid}:\n")
        (stage / "policy/passwd").chmod(0o444)
        (stage / "policy/group").chmod(0o444)
        (stage / "policy").chmod(0o555)
        properties = [
            "User=" + str(uid), "Group=" + str(gid), "Description=" + description,
            "MemoryAccounting=yes", "MemoryMax=768M", "MemorySwapMax=0", "MemoryOOMGroup=yes",
            "CPUAccounting=yes", "CPUQuota=25%", "CPUQuotaPeriodSec=100ms",
            "TasksAccounting=yes", "TasksMax=48", "RuntimeMaxSec=240s", "TimeoutStopSec=5s", "KillMode=control-group",
            "NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities=", "UMask=0077",
            "PrivateNetwork=yes", "PrivateDevices=yes", "ProtectSystem=strict", "ProtectHome=yes",
            "RestrictAddressFamilies=AF_UNIX AF_NETLINK",
            "TemporaryFileSystem=" + str(stage / "scratch") + ":rw,size=64M,nr_inodes=2048,nodev,nosuid,mode=1777",
        ]
        argv = ["/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--unit=" + unit]
        for property_value in properties:
            argv += ["--property=" + property_value]
        argv += ["--", "/usr/bin/python3", "-I", "-B", str(stage / "policy/controller.py"), "--launch", str(stage)]
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, start_new_session=True)
        deadline = time.monotonic() + 260
        admission_deadline = time.monotonic() + 30
        pending = bytearray()
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        try:
            while selector.get_map():
                now = time.monotonic()
                require(now < deadline, "External CI deadline exceeded")
                require(record["gate_released"] or now < admission_deadline, "Worker preflight deadline exceeded")
                for key, mask in selector.select(timeout=0.2):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    output.extend(chunk)
                    require(len(output) <= MAX_OUTPUT, "CI output budget exceeded")
                    pending.extend(chunk)
                    while b"\n" in pending:
                        line, _, tail = pending.partition(b"\n")
                        pending = bytearray(tail)
                        text = line.decode("utf-8", errors="replace")
                        print(text, flush=True)
                        if not text.startswith('{"event":'):
                            continue
                        event = json.loads(text)
                        require(type(event) is dict, "Invalid event metadata")
                        if event.get("event") == "ready":
                            require(not record["gate_released"] and event.get("nonce") == nonce and type(event.get("uid")) is int and event["uid"] == uid, "Worker ready identity mismatch")
                            require(event.get("limits") == LIMITS, "Worker ready limit mismatch")
                            require(type(event.get("namespaces")) is dict and set(event["namespaces"]) == set(NAMESPACES)
                                    and all(event["namespaces"][name] != policy["host_namespaces"][name] for name in NAMESPACES), "Worker ready namespace mismatch")
                            state = unit_state(unit)
                            invocation = state.get("InvocationID")
                            require(state.get("Description") == description and state.get("ActiveState") == "active" and re.fullmatch(r"[0-9a-f]{32}", invocation or ""), "Own active unit identity unavailable")
                            control_group = state.get("ControlGroup")
                            own = cgroup_path(control_group)
                            require({name: (own / name).read_text().strip() for name in LIMITS} == LIMITS, "External aggregate limits mismatch")
                            record["invocation_id"] = invocation
                            record["control_group"] = control_group
                            record["verified_limits"] = LIMITS
                            process.stdin.write(("GO " + nonce + "\n").encode("ascii"))
                            process.stdin.flush()
                            process.stdin.close()
                            record["gate_released"] = True
                        elif event.get("event") == "result":
                            require(record["gate_released"] and result_record is None, "Unexpected result event")
                            result_record = event
                        else:
                            raise RuntimeError("Unknown fixed worker event")
            if pending:
                print(pending.decode("utf-8", errors="replace"), flush=True)
            code = process.wait(timeout=8)
            record["systemd_run_exit"] = code
            require(code == 0 and result_record is not None and result_record.get("status") == "PASS", "Worker validation failed")
            record["worker_result"] = result_record
            record["status"] = "PASS"
        finally:
            selector.close()
    except Exception as exc:
        record["status"] = "FAIL"
        record["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        record["output_bytes"] = len(output)
        record["output_sha256"] = hashlib.sha256(output).hexdigest()
        cleanup_errors = []
        try:
            state = unit_state(unit)
            if state["LoadState"] != "not-found" and state.get("ActiveState") not in ("inactive", "failed"):
                require(state.get("Description") == description, "Cleanup refuses unrelated description")
                require(re.fullmatch(r"[0-9a-f]{32}", state.get("InvocationID", "")) is not None, "Cleanup requires invocation identity")
                if invocation is not None:
                    require(state["InvocationID"] == invocation, "Cleanup refuses changed InvocationID")
                subprocess.run(["/usr/bin/systemctl", "stop", unit], stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=12, check=True)
            cleanup_deadline = time.monotonic() + 8
            while True:
                state = unit_state(unit)
                inactive = state["LoadState"] == "not-found" or (state.get("ActiveState") in ("inactive", "failed") and not state.get("ControlGroup"))
                removed = control_group is None or not cgroup_path(control_group).exists()
                if inactive and removed:
                    break
                require(time.monotonic() < cleanup_deadline, "Own unit processes or aggregate cgroup remain")
                time.sleep(0.1)
            record["unit_cleanup"] = True
        except Exception as exc:
            cleanup_errors.append(type(exc).__name__ + ": " + str(exc))
        if process is not None:
            try:
                if process.stdin is not None and not process.stdin.closed:
                    process.stdin.close()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=5)
            except Exception as exc:
                cleanup_errors.append(type(exc).__name__ + ": " + str(exc))
        try:
            if stage_identity is not None:
                require(record.get("unit_cleanup") is True, "Preserve staging while unit cleanup is unresolved")
                require(not stage.is_symlink() and (stage.stat().st_dev, stage.stat().st_ino) == stage_identity, "Staging identity changed")
                shutil.rmtree(stage)
                record["staging_cleanup"] = not stage.exists()
            else:
                record["staging_cleanup"] = True
        except Exception as exc:
            cleanup_errors.append(type(exc).__name__ + ": " + str(exc))
        record["cleanup_errors"] = cleanup_errors
        if cleanup_errors:
            record["status"] = "FAIL"
    print(json.dumps({"ci_receipt": record}, sort_keys=True), flush=True)
    return 0 if record["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
