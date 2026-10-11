#!/usr/bin/env python3
"""Source-tree entry point for the demo also shipped as ``bse.demo``."""

from bse.demo import EvidenceManifest, main, run_demo

__all__ = ["EvidenceManifest", "main", "run_demo"]


if __name__ == "__main__":
    raise SystemExit(main())
