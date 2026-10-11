#!/usr/bin/env python3
"""Non-interactive BSE examples using synthetic data and generated configuration."""
import json
import secrets
import sys
import tempfile
from pathlib import Path

from bse import (
    BubblewrapBuilder,
    CyclicSessionGraphError,
    EvidenceManifest,
    LengthPrefixedKeySerializer,
    detect_cycles,
    validate_acyclic_entries,
)


def run_demo() -> bool:
    print("=" * 72)
    print("  BLUE SECURITY ENGINE (BSE) — SYNTHETIC EXAMPLES")
    print("  These examples do not launch or verify a sandbox.")
    print("=" * 72)

    # 1. Validate a synthetic cyclic graph.
    print("\n[1] GRAPH VALIDATION:")
    cyclic_entries = [
        {"uuid": "task-alpha", "parentUuid": "task-beta"},
        {"uuid": "task-beta", "parentUuid": "task-alpha"},
    ]
    cycles = detect_cycles(cyclic_entries)
    print("  [-] Synthetic cyclic graph: task-alpha <-> task-beta")
    if cycles:
        print(f"  [+] Detected cycle path: {' -> '.join(cycles[0])}")
    cycle_blocked = False
    try:
        validate_acyclic_entries(cyclic_entries)
    except CyclicSessionGraphError as exc:
        cycle_blocked = True
        print(f"  [+] Cycle rejected: {exc}")

    # 2. Distinguish synthetic composite keys without delimiter ambiguity.
    print("\n[2] COMPOSITE-KEY ENCODING:")
    naive_a = "tenant/UUID_A" + "/" + "UUID_B"
    naive_b = "tenant" + "/" + "UUID_A" + "/" + "UUID_B"
    print(f"  [-] Naive string concatenation collision: {naive_a} == {naive_b} ({naive_a == naive_b})")

    bse_key_a = LengthPrefixedKeySerializer.serialize("tenant/UUID_A", "UUID_B")
    bse_key_b = LengthPrefixedKeySerializer.serialize("tenant", "UUID_A", "UUID_B")
    print(f"  [+] Encoded key A: {bse_key_a}")
    print(f"  [+] Encoded key B: {bse_key_b}")
    keys_separated = bse_key_a != bse_key_b
    print(f"  [+] Composite keys differ: {keys_separated}")
    print("  Tenant authorization remains the application's responsibility.")

    # 3. Authenticate an integrity and telemetry manifest.
    print("\n[3] INTEGRITY & TELEMETRY MANIFEST WITH HMAC AUTHENTICATION:")
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        sample = tmp / "security_audit_receipt.json"
        sample.write_text('{"event": "synthetic_demo"}', encoding="utf-8")

        manifest = EvidenceManifest(task_id="BSE-DEMO", operator="synthetic-demo")
        digest = manifest.add_artifact("audit_receipt", sample)
        print(f"  [+] Artifact registered: audit_receipt")
        print(f"  [+] SHA-256 Digest: {digest}")

        export_file = tmp / "manifest.json"
        key = secrets.token_bytes(32)
        manifest.export_json(export_file, hmac_key=key)
        manifest_data = json.loads(export_file.read_text(encoding="utf-8"))
        integrity = EvidenceManifest.verify_manifest(manifest_data, hmac_key=key, require_signature=True)
        manifest_valid = integrity["valid"] and integrity["hmac"]["valid"] is True
        status = "PASS" if manifest_valid else "FAIL"
        print(f"  [+] Integrity & Telemetry Manifest with HMAC Authentication: {status} "
              f"(Integrity={integrity['valid']}, HMAC={integrity['hmac']['status']})")

    # 4. Bubblewrap Sandbox Argument Generation
    print("\n[4] BUBBLEWRAP CONFIGURATION:")
    builder = BubblewrapBuilder()
    builder.add_ro_bind(str(Path(__file__).resolve().parent.parent), "/lab")
    builder.set_env("PYTHONPATH", "/lab")
    argv = builder.build_argv([sys.executable, "-B", "-m", "bse.demo"])
    print(f"  [+] Generated argument count: {len(argv)}")
    flags_present = all(flag in argv for flag in ("--unshare-all", "--cap-drop", "ALL", "--clearenv", "--tmpfs", "/home"))
    print(f"  [+] Required configuration flags generated: {flags_present}")
    print("  Configuration only; no sandbox was launched.")

    success = bool(cycles and cycle_blocked and keys_separated and manifest_valid and flags_present)
    print("\n" + "=" * 72)
    print("  DEMO CHECKS PASSED" if success else "  DEMO CHECKS FAILED")
    print("=" * 72)
    return success


def main() -> int:
    """Return the actual result for the installed console entry point."""
    return 0 if run_demo() else 1


if __name__ == "__main__":
    raise SystemExit(main())
