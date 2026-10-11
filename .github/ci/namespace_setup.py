"""Prepare a targeted Bubblewrap AppArmor profile on ephemeral GitHub CI only.

Ubuntu's documented userns exception is scoped to /usr/bin/bwrap. This does
not disable AppArmor, change a sysctl or grant capabilities to the worker.
Profiles and this trusted provisioning code remain outside target control.
"""

import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess


METADATA = Path("/run/bse-ci-apparmor.json")
PROFILE = b"abi <abi/4.0>,\nprofile bse-ci-bwrap /usr/bin/bwrap flags=(unconfined) {\n  userns,\n}\n"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def restriction():
    path = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    value = path.read_text().strip() if path.exists() else "0"
    require(value in ("0", "1"), "Unexpected userns restriction flag")
    return value


def loaded_profiles():
    path = Path("/sys/kernel/security/apparmor/profiles")
    data = path.read_bytes()
    require(len(data) <= 262144, "AppArmor profile inventory budget")
    return data.decode().splitlines()


def main():
    uid = int(os.environ.get("SUDO_UID", "0"))
    require(os.geteuid() == 0 and uid > 0 and pwd.getpwuid(uid).pw_name == "runner"
            and Path("/opt/hostedtoolcache").is_dir(), "Only the ephemeral GitHub-hosted runner may prepare namespaces")
    flag = restriction()
    enabled_path = Path("/sys/module/apparmor/parameters/enabled")
    enabled = enabled_path.exists() and enabled_path.read_text().strip() == "Y"
    record = {"userns_restrict": flag, "apparmor_enabled": enabled, "profile": None,
              "profile_source_sha256": None, "profile_created": False, "profile_loaded": False}
    if flag == "1":
        require(enabled, "Userns restriction requires active AppArmor")
        existing = Path("/etc/apparmor.d/bwrap")
        profiles = loaded_profiles()
        if existing.exists():
            info = existing.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                    and not info.st_mode & 0o022 and info.st_size <= 65536, "Installed bwrap profile ownership/type")
            data = existing.read_bytes()
            profile_path = existing
            name = "bwrap"
        elif any(line in ("bwrap (enforce)", "bwrap (unconfined)") for line in profiles):
            profile_path = None
            data = None
            name = "bwrap"
        else:
            name = "bse-ci-bwrap"
            profile_path = Path("/etc/apparmor.d/bse-ci-bwrap")
            if profile_path.exists():
                info = profile_path.lstat()
                require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                        and not info.st_mode & 0o022 and profile_path.read_bytes() == PROFILE,
                        "Refuse replacing an unrelated AppArmor profile")
            else:
                fd = os.open(profile_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(PROFILE)
                record["profile_created"] = True
            data = PROFILE
        if profile_path is not None:
            parser = Path("/usr/sbin/apparmor_parser")
            require(parser.is_file(), "AppArmor parser unavailable")
            result = subprocess.run([str(parser), "--replace", str(profile_path)],
                                    stdin=subprocess.DEVNULL, capture_output=True, timeout=15, check=False,
                                    env={"PATH": "/usr/bin:/usr/sbin", "LANG": "C.UTF-8"})
            require(result.returncode == 0, "Targeted bwrap profile loading failed")
        require(any(line in (name + " (enforce)", name + " (unconfined)") for line in loaded_profiles()),
                "Expected AppArmor profile was not loaded")
        record.update(profile=name, profile_source_sha256=hashlib.sha256(data).hexdigest() if data is not None else None,
                      profile_loaded=True)
    fd = os.open(METADATA, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    with os.fdopen(fd, "w") as stream:
        stream.write(json.dumps(record) + "\n")
    print(json.dumps({"ci_namespace_preparation": record}), flush=True)


if __name__ == "__main__":
    main()
