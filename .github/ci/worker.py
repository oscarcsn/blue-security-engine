"""The fixed BSE CI payload: 99 unit tests, offline packaging and installed demos.

No package imports, tests or backend executions occur before admission.
All writes stay in the private, size-limited /tmp filesystem.
"""

import configparser
import email.parser
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import unittest
import zipfile


sys.path.insert(0, "/policy")
from admission import await_admission, require


def invoke(argv, *, cwd, env):
    result = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=60, check=False)
    require(len(result.stdout.encode()) + len(result.stderr.encode()) <= 262144, "Subprocess output budget")
    if result.returncode != 0:
        print(result.stdout[-8000:], flush=True)
        print(result.stderr[-8000:], file=sys.stderr, flush=True)
        raise RuntimeError("Fixed offline packaging command failed: " + repr(argv[1:3]))
    return result.stdout


def build(source, output, kind, env):
    code = "import json; from setuptools import build_meta; name=build_meta.build_" + kind + "(" + repr(str(output)) + "); print(json.dumps({'built':name}))"
    text = invoke(["/usr/bin/python3", "-B", "-c", code], cwd=source, env=env)
    records = [json.loads(line) for line in text.splitlines() if line.startswith('{"built":')]
    require(len(records) == 1 and type(records[0]) is dict and type(records[0].get("built")) is str, "One backend artifact required")
    name = records[0]["built"]
    require(Path(name).name == name and name not in (".", ".."), "Artifact filename")
    artifact = output / name
    require(artifact.is_file() and not artifact.is_symlink(), "Build artifact missing")
    return artifact


def extract_sdist(archive_path, output, required):
    names = set()
    roots = set()
    count = 0
    total = 0
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive:
            count += 1
            total += member.size
            require(count <= 256 and total <= 8388608 and member.size <= 4194304, "sdist inspection budget")
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and ".." not in path.parts and path.parts, "sdist path")
            require(member.isdir() or member.isfile(), "sdist links/special files rejected")
            roots.add(path.parts[0])
            target = output.joinpath(*path.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            relative = PurePosixPath(*path.parts[1:]).as_posix()
            require(relative not in names, "Duplicate sdist file")
            names.add(relative)
            stream = archive.extractfile(member)
            require(stream is not None, "Unreadable sdist member")
            with stream:
                data = stream.read(member.size + 1)
            require(len(data) == member.size, "sdist size")
            target.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as out:
                out.write(data)
            require(hashlib.sha256(target.read_bytes()).digest() == hashlib.sha256(data).digest(), "sdist transfer integrity")
    require(len(roots) == 1 and required <= names, "sdist contents missing")
    return output / next(iter(roots))


def packaging():
    # Preparation fetched these trusted wheels outside the jail; verify again.
    from bootstrap import WHEELS
    require(set(path.name for path in Path("/deps").iterdir()) == set(WHEELS), "Pinned dependency set")
    for name, record in WHEELS.items():
        path = Path("/deps") / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == record["size"], "Pinned wheel type/size")
        require(hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"], "Pinned wheel digest")
    work = Path("/tmp/packaging")
    work.mkdir()
    empty = work / "empty"
    empty.mkdir()
    tools = work / "tools"
    clean_env = {"PATH": "/usr/bin", "LANG": "C.UTF-8", "HOME": "/tmp/home", "TMPDIR": "/tmp", "PYTHONDONTWRITEBYTECODE": "1"}
    pip_env = dict(clean_env, PYTHONPATH="/deps/pip-25.3-py3-none-any.whl", PIP_CONFIG_FILE="/dev/null")
    invoke(["/usr/bin/python3", "-B", "-m", "pip", "--isolated", "--disable-pip-version-check",
            "install", "--no-index", "--no-deps", "--no-compile", "--no-cache-dir", "--target", str(tools),
            *[str(Path("/deps") / name) for name in WHEELS]], cwd=empty, env=pip_env)
    build_env = dict(clean_env, PYTHONPATH=str(tools))
    source = work / "source"
    shutil.copytree("/source", source)
    for path in [source, *source.rglob("*")]:
        require(not path.is_symlink() and path.stat().st_uid == os.getuid(), "Private build source ownership/type")
        path.chmod(0o700 if path.is_dir() else 0o600)
    original_hashes = {p.relative_to("/source").as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in Path("/source").rglob("*") if p.is_file()}
    copied_hashes = {p.relative_to(source).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in source.rglob("*") if p.is_file()}
    require(original_hashes == copied_hashes, "Source copy integrity")
    output = work / "artifacts"
    output.mkdir()
    sdist = build(source, output, "sdist", build_env)
    unpacked = work / "unpacked"
    unpacked.mkdir()
    required = {"demo.py", "pyproject.toml", "MANIFEST.in", "README.md", "SECURITY.md", "LICENSE", "PKG-INFO",
                "src/bse/demo.py", "src/bse/py.typed", "VALIDATION.md", "VALIDATION.json", "CONTRIBUTING.md",
                "CHANGELOG.md", "docs/DESIGN.md"}
    required.update(p.relative_to(source).as_posix() for p in (source / "tests").glob("test_*.py"))
    rebuilt = extract_sdist(sdist, unpacked, required)
    wheel = build(rebuilt, output, "wheel", build_env)
    with zipfile.ZipFile(wheel) as archive:
        entries = archive.infolist()
        require(len(entries) <= 256 and sum(e.file_size for e in entries) <= 8388608, "wheel inspection budget")
        names = set(archive.namelist())
        require(len(names) == len(entries), "Duplicate wheel names")
        require(all(not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts for name in names), "wheel paths")
        require({"bse/demo.py", "bse/py.typed"} <= names, "wheel demo/typing resource")
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        require(len(metadata_names) == 1, "wheel metadata count")
        dist_info = str(PurePosixPath(metadata_names[0]).parent)
        require({dist_info + "/" + name for name in ("METADATA", "WHEEL", "RECORD", "entry_points.txt")} <= names, "wheel distribution metadata")
        require(any(name.startswith(dist_info + "/") and name.endswith("/LICENSE") for name in names), "wheel license")
        metadata = email.parser.Parser().parsestr(archive.read(metadata_names[0]).decode("utf-8"))
        require(metadata["Name"] == "blue-security-engine" and metadata["Version"] == "0.1.0", "wheel identity")
        require(not metadata.get_all("Requires-Dist"), "Unexpected runtime dependencies")
        entry_points = configparser.ConfigParser()
        entry_points.read_string(archive.read(dist_info + "/entry_points.txt").decode("utf-8"))
        require(entry_points["console_scripts"]["bse-demo"] == "bse.demo:main", "console entry point")
    installed = work / "installed"
    install_env = dict(clean_env, PYTHONPATH=str(tools), PIP_CONFIG_FILE="/dev/null")
    invoke(["/usr/bin/python3", "-B", "-m", "pip", "--isolated", "--disable-pip-version-check",
            "install", "--no-index", "--no-deps", "--no-compile", "--no-cache-dir", "--target", str(installed), str(wheel)],
           cwd=empty, env=install_env)
    with zipfile.ZipFile(wheel) as archive:
        for name in archive.namelist():
            if name.startswith("bse/") and not name.endswith("/"):
                require(hashlib.sha256(archive.read(name)).digest() == hashlib.sha256((installed / name).read_bytes()).digest(), "wheel install integrity")
    smoke_env = dict(clean_env, PYTHONPATH=str(installed))
    probe = "from pathlib import Path; from importlib import resources,metadata; import bse; assert Path(bse.__file__).resolve().is_relative_to(Path(" + repr(str(installed)) + ")); assert resources.files('bse').joinpath('py.typed').is_file(); assert metadata.version('blue-security-engine')=='0.1.0'"
    invoke(["/usr/bin/python3", "-B", "-c", probe], cwd=empty, env=smoke_env)
    for argv in (["/usr/bin/python3", "-B", "-m", "bse.demo"], [str(installed / "bin/bse-demo")]):
        text = invoke(argv, cwd=empty, env=smoke_env)
        require("DEMO CHECKS PASSED" in text and "HMAC=OK" in text and "DEMO CHECKS FAILED" not in text, "Installed demo verification")
    return {"sdist_to_wheel": True, "source_copy_integrity": True, "sdist_transfer_integrity": True,
            "wheel_install_integrity": True, "installed_py_typed": True, "module_demo": "PASS", "console_demo": "PASS",
            "sdist_sha256": hashlib.sha256(sdist.read_bytes()).hexdigest(), "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest()}


def main():
    await_admission()
    sys.path[:0] = ["/source/src", "/source"]
    suite = unittest.defaultTestLoader.discover("/source/tests")
    require(suite.countTestCases() == 99, "Expected exactly 99 package unit tests")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    require(result.wasSuccessful() and result.testsRun == 99 and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses, "All 99 unit tests must pass without skips")
    packaged = packaging()
    print(json.dumps({"event": "result", "status": "PASS", "unit_tests": result.testsRun, "skipped": 0,
                      "packaging": packaged, "execution": "offline inside admitted Bubblewrap/cgroup worker"}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
