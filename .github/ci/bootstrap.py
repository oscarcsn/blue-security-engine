"""Download pinned trusted tools; run only on the ephemeral CI host, not hp.

The package and build backend are never executed by this preparation step.
The fixed wheels are verified against SHA-256 from PyPI's release metadata.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import urllib.request


WHEELS = {
    "pip-25.3-py3-none-any.whl": {
        "url": "https://files.pythonhosted.org/packages/44/3c/d717024885424591d5376220b5e836c2d5293ce2011523c9de23ff7bf068/pip-25.3-py3-none-any.whl",
        "sha256": "9655943313a94722b7774661c21049070f6bbb0a1516bf02f7c8d5d9201514cd",
        "size": 1778622,
    },
    "setuptools-80.9.0-py3-none-any.whl": {
        "url": "https://files.pythonhosted.org/packages/a3/dc/17031897dae0efacfea57dfd3a82fdd2a2aeb58e0ff71b77b87e44edc772/setuptools-80.9.0-py3-none-any.whl",
        "sha256": "062d34222ad13e0cc312a4c02d73f059e86a4acbfbdea8f8f76b28c99f306922",
        "size": 1201486,
    },
    "wheel-0.45.1-py3-none-any.whl": {
        "url": "https://files.pythonhosted.org/packages/0b/2c/87f3254fd8ffd29e4c02732eee68a83a1d3c346ae39bc6822dcbcb697f2b/wheel-0.45.1-py3-none-any.whl",
        "sha256": "708e7481cc80179af0e556bbf0cc00b8444c7321e2700b8d8580231d13017248",
        "size": 72494,
    },
}


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    destination = Path(args.output)
    destination.mkdir(mode=0o700)
    for name, record in WHEELS.items():
        with urllib.request.urlopen(record["url"], timeout=30) as response:
            data = response.read(record["size"] + 1)
        if len(data) != record["size"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise RuntimeError("Pinned wheel verification failed: " + name)
        fd = os.open(destination / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
    print(json.dumps({"trusted_tools_prepared": list(WHEELS), "package_executed": False}))


if __name__ == "__main__":
    main()
