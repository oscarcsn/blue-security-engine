# Design and trust boundaries

BSE exposes small Python utilities. It does not provide a service endpoint,
authentication system or execution supervisor. The caller decides where
untrusted data enters and which controls must precede its use.

## Session records and keys

`validate_acyclic_entries(entries)` validates parent-linked records before the
application traverses them. Node identifiers accept strings or integers,
including zero, and are normalized to strings; duplicate normalized values
are rejected. Missing, null, empty and whitespace-only node identifiers are
invalid. Parent links may be absent or reference a node outside the supplied
set. Graph validation does not prove referential completeness or intercept
subsequent application mutations.

`LengthPrefixedKeySerializer` accepts exact `str` components and encodes their
UTF-8 byte lengths. The optional `subpath=None` means absence; an empty string
or the string `"None"` is a different component. Deserialization rejects
noncanonical lengths, truncated payloads and invalid UTF-8 boundaries.

`SafeSessionStore` is an asynchronous in-memory reference adapter, not a
persistent database. Appends require a plain list of plain dict records.
Validation and deep copying occur before storage mutation. Loads return deep
copies. This detaches JSON-like nested values and other values that honor
`copy.deepcopy`; custom Python copy behavior is not a same-process security
boundary. The caller supplies tenant authorization and input budgets, and
validates nested values before copying them.

## Artifact manifests

`EvidenceManifest(task_id, operator)` requires a nonempty operator. Artifact
registration captures path, SHA-256, size and time; telemetry includes BSE
version, hostname, platform, Python version and user ID. Review this metadata
before sharing a manifest. A standards-reference string is metadata, not
independent certification.

Example for a synthetic scratch directory inside an approved isolated runtime:

```python
import secrets
import tempfile
from pathlib import Path
from bse import EvidenceManifest

with tempfile.TemporaryDirectory() as scratch:
    artifact = Path(scratch) / "sample.txt"
    artifact.write_text("synthetic event\n", encoding="utf-8")
    manifest = EvidenceManifest("example", operator="local-reviewer")
    manifest.add_artifact("sample", artifact)
    key = secrets.token_bytes(32)  # Synthetic; keep real keys outside manifests.
    data = manifest.to_dict(hmac_key=key)
    report = EvidenceManifest.verify_manifest(data, hmac_key=key)
    assert report["authenticated"] and report["valid"]
```

Creation and export accept optional HMAC keys; verification requires a signature
by default. HMAC-SHA256 covers canonical JSON of the complete payload except
the `signature` field. The key is not retained on the manifest or exported.
Keys must be nonempty bytes and should be chosen and stored by the application.

The verification result separates:

- `authenticated`: whether the payload passed HMAC verification, even when an
  artifact subsequently fails.
- `valid`: whether required authentication, operator metadata and artifact
  checks passed.
- `verification_mode`: `hmac` or `checksum_only`.
- `hmac` and `artifacts`: structured validity and failure status.

`require_signature` must be an exact bool. Its default `True` rejects missing
signatures and invalid/missing keys before opening artifact paths. Only an
explicit `require_signature=False` with an unsigned payload and no key permits
checksum-only verification. A signed payload still requires a key in that mode.
An empty artifact map can pass checksum-only validation without authenticating
anything.

Artifact records require an exact nonnegative integer `size_bytes`. Hashing
uses one `O_NOFOLLOW | O_NONBLOCK` descriptor, requires a regular file and reads
at most the expected size plus one byte. Descriptor and final-path metadata
are compared for observed change. Statuses include `OK`, `FILE_NOT_FOUND`,
`HASH_MISMATCH`, `SIZE_MISMATCH`, `FILE_CHANGED` and `INVALID_RECORD`.

Final-component symlinks and special files are rejected. Parent directories
and their ancestors must be trusted. These checks do not prevent changes after
verification; large legitimate files can still require substantial work, so
the caller supplies aggregate time and resource budgets.

`export_json` serializes a snapshot to a temporary file in the destination
directory, closes it and uses `os.replace`. It checks existing and dangling
destination symlinks and cleans up its temporary on errors. A symlink check
can race, but replacement does not follow a final destination symlink.
The replacement takes the temporary file's restrictive permissions. Atomic
replacement is not an fsync-based crash-durability guarantee.

## Linux isolation helpers

`BubblewrapBuilder.build_argv(command)` emits namespace, capability,
environment and filesystem arguments; it does not execute them. Default
tmpfs mounts cover `/tmp`, `/home` and `/run`. Every caller mount is applied
in call order, so a later bind can expose a previously masked path. The
caller must review the final sequence and enforce the execution policy.

`CgroupLimits.inspect_all()` reads memory, swap, CPU and PID controllers
and ancestors visible within the cgroup mount. It distinguishes `limited`,
`max`, `unavailable` and `invalid`. Unknown readings remain unknown;
`known_*` fields expose only partial observed limits.

`visible_effective_complete` is scoped by `effective_scope`, either the
visible cgroup mount or an explicit single-root fixture. A complete reading
can contain `max` and can hide host ancestors. The deprecated
`effective_complete` alias has the same restricted meaning.
`host_limits_verified` and `enforcement_verified` remain false.

The external supervisor must enforce finite aggregate limits for descendants,
verify the intended namespace/network/filesystem boundary independently of
the target, and perform cleanup. Those duties are not supplied by this package.
