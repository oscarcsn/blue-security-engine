"""Integrity & Telemetry Manifest with HMAC Authentication."""
from __future__ import annotations

import copy
import datetime
import hashlib
import hmac
import json
import os
import platform
import re
import stat
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union


_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}\Z")


class _ArtifactSizeMismatch(ValueError):
    """The descriptor size or bounded byte count differs from the expected size."""


class _ArtifactChanged(ValueError):
    """The artifact descriptor metadata or final path changed while hashing."""


def _stat_fingerprint(info: os.stat_result) -> Tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
        info.st_mtime_ns, info.st_ctime_ns,
    )


def _hash_regular_file(
    file_path: Union[str, Path], *, expected_size: Optional[int] = None,
) -> Tuple[str, int]:
    """Hash one nonblocking, no-follow descriptor with a size-derived read budget.

    Only the final path component is protected by O_NOFOLLOW. The parent and
    ancestors must be trusted. Metadata checks detect observed changes during
    hashing; they do not freeze the file against later writes.
    """
    if expected_size is not None:
        if type(expected_size) is not int:
            raise TypeError("expected_size must be an exact integer")
        if expected_size < 0:
            raise ValueError("expected_size must not be negative")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(file_path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Artifact must be a regular file")
        size = before.st_size if expected_size is None else expected_size
        if before.st_size != size:
            raise _ArtifactSizeMismatch("Artifact size differs before hashing")

        hasher = hashlib.sha256()
        count = 0
        while count < size + 1:
            chunk = os.read(descriptor, min(65536, size + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            hasher.update(chunk)

        after = os.fstat(descriptor)
        if count != size or after.st_size != size:
            raise _ArtifactSizeMismatch("Artifact grew or was truncated while hashing")
        if _stat_fingerprint(before) != _stat_fingerprint(after):
            raise _ArtifactChanged("Artifact descriptor changed while hashing")
        path_after = os.stat(file_path, follow_symlinks=False)
        if _stat_fingerprint(after) != _stat_fingerprint(path_after):
            raise _ArtifactChanged("Artifact path changed while hashing")
        return hasher.hexdigest(), size
    finally:
        os.close(descriptor)


def _validate_operator(operator: str) -> None:
    if not isinstance(operator, str):
        raise TypeError("operator must be a string")
    if not operator.strip():
        raise ValueError("operator must not be empty")


def _validate_hmac_key(key: Optional[bytes]) -> None:
    if key is not None:
        if not isinstance(key, bytes):
            raise TypeError("hmac_key must be bytes")
        if not key:
            raise ValueError("hmac_key must not be empty")


def _canonical_payload(data: Dict[str, Any]) -> bytes:
    payload = {key: value for key, value in data.items() if key != "signature"}
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


class EvidenceManifest:
    """Integrity & Telemetry Manifest with HMAC Authentication."""

    def __init__(self, task_id: str, operator: str) -> None:
        _validate_operator(operator)
        self.task_id = task_id
        self.operator = operator
        self.created_at_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.artifacts: Dict[str, Dict[str, Any]] = {}
        self.telemetry: Dict[str, Any] = self._capture_environment()

    @staticmethod
    def compute_sha256(
        file_path: Union[str, Path], *, expected_size: Optional[int] = None,
    ) -> str:
        """Hash a stable regular file, reading at most expected size plus one byte.

        With no expected size, use the initial descriptor size. Final symlinks
        and special files are rejected; parent directories must be trusted.
        """
        digest, _ = _hash_regular_file(file_path, expected_size=expected_size)
        return digest

    def _capture_environment(self) -> Dict[str, Any]:
        """Record non-sensitive operating environment telemetry for evidentiary context."""
        # bse imports this module during initialization; defer the version import.
        from .. import __version__

        return {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "uid": os.geteuid(),
            "bse_version": __version__,
            "hostname": platform.node(),
            "standard_reference": "ISO/IEC 27037:2012",
        }

    def add_artifact(self, label: str, file_path: Union[str, Path]) -> str:
        """Record a consistent hash and size from one stable regular-file descriptor."""
        p = Path(file_path).absolute()
        digest, size = _hash_regular_file(p)
        self.artifacts[label] = {
            "path": str(p),
            "size_bytes": size,
            "sha256": digest,
            "recorded_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        return digest

    def to_dict(self, *, hmac_key: Optional[bytes] = None) -> Dict[str, Any]:
        """Return a snapshot, optionally authenticated with a caller-held key.

        HMAC authenticates the complete payload except ``signature``. The key
        is neither retained on the manifest nor included in the output.
        """
        _validate_operator(self.operator)
        _validate_hmac_key(hmac_key)
        data: Dict[str, Any] = {
            "task_id": self.task_id,
            "operator": self.operator,
            "created_at_utc": self.created_at_utc,
            "telemetry": copy.deepcopy(self.telemetry),
            "artifacts": copy.deepcopy(self.artifacts),
        }
        if hmac_key is not None:
            data["signature"] = {
                "algorithm": "HMAC-SHA256",
                "digest": hmac.new(
                    hmac_key, _canonical_payload(data), hashlib.sha256,
                ).hexdigest(),
            }
        return data

    def export_json(
        self, destination: Union[str, Path], *, hmac_key: Optional[bytes] = None,
    ) -> None:
        """Atomically export a snapshot; never export its optional HMAC key.

        Reject final destination symlinks, including dangling links, with
        ``ValueError``. Serialize and close a temporary in the same directory
        before replacing the destination, preserving old content on failure.

        The parent directory and its ancestors must be trusted. Symlink checks
        can race, but ``os.replace`` never follows a final destination symlink.
        The replacement uses the temporary file's permissions. Atomic
        replacement does not promise crash durability or confinement against a
        hostile parent directory.
        """
        data = self.to_dict(hmac_key=hmac_key)
        dest = Path(destination)
        if dest.is_symlink():
            raise ValueError("Manifest destination must not be a symlink")
        dest.parent.mkdir(parents=True, exist_ok=True)
        temporary: Optional[Path] = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=dest.parent,
                prefix=".bse-manifest-", suffix=".tmp", delete=False,
            ) as handle:
                temporary = Path(handle.name)
                json.dump(data, handle, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
            if dest.is_symlink():
                raise ValueError("Manifest destination must not be a symlink")
            os.replace(temporary, dest)
            temporary = None
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    @classmethod
    def verify_manifest(
        cls, manifest_data: Dict[str, Any], *, hmac_key: Optional[bytes] = None,
        require_signature: bool = True,
    ) -> Dict[str, Any]:
        """Verify authentication and artifact hashes with explicit failure reasons.

        Authentication is required by default. Unsigned manifests permit
        checksum verification only with explicit ``require_signature=False``
        and no supplied key. Supplying a key requires a signature; a signature
        requires a key. On authentication failure, artifact records are rejected
        without opening their paths. HMAC is shared-key authentication, not a
        digital signature.

        ``require_signature=True`` rejects unsigned manifests even without a
        supplied key, preventing signature removal from downgrading verification.
        This policy argument must be an exact bool; other types raise TypeError
        before filesystem access. ``authenticated`` reports only payload HMAC
        authentication, independently of artifact validity. ``verification_mode``
        is ``hmac`` when HMAC verification is required or attempted, and ``checksum_only``
        for explicit False with an unsigned payload and no key. Checksum-only
        ``valid=True`` reports matching hashes, without authenticating metadata.
        Empty artifact mappings are allowed.

        Each artifact requires an exact nonnegative integer ``size_bytes``.
        SIZE_MISMATCH rejects a differing initial size before reading, or growth
        and truncation during bounded hashing. FILE_CHANGED reports observed
        descriptor metadata or path changes. Parent directories must be trusted.
        Invalid keys return ``INVALID_KEY`` when ``require_signature=True``;
        with explicit False, they raise ``TypeError`` or ``ValueError``.
        """
        if type(require_signature) is not bool:
            raise TypeError("require_signature must be an exact bool")
        verification_mode = "hmac" if (
            require_signature or hmac_key is not None
            or (isinstance(manifest_data, dict) and "signature" in manifest_data)
        ) else "checksum_only"
        key_valid = True
        try:
            _validate_hmac_key(hmac_key)
        except (TypeError, ValueError):
            if not require_signature:
                raise
            key_valid = False
        if not isinstance(manifest_data, dict):
            return {
                "valid": False, "artifacts": {},
                "authenticated": False, "verification_mode": verification_mode,
                "hmac": {
                    "valid": False,
                    "status": "INVALID_SIGNATURE" if key_valid else "INVALID_KEY",
                },
            }

        hmac_result: Dict[str, Any] = {"valid": None, "status": "NOT_PRESENT"}
        if not key_valid:
            hmac_result = {"valid": False, "status": "INVALID_KEY"}
        elif "signature" not in manifest_data:
            if require_signature:
                hmac_result = {"valid": False, "status": "MISSING_SIGNATURE"}
            elif hmac_key is not None:
                hmac_result = {"valid": False, "status": "SIGNATURE_REQUIRED"}
        elif hmac_key is None:
            hmac_result = {"valid": False, "status": "KEY_REQUIRED"}
        else:
            signature = manifest_data["signature"]
            digest = signature.get("digest") if isinstance(signature, dict) else None
            if (
                not isinstance(signature, dict)
                or signature.get("algorithm") != "HMAC-SHA256"
                or not isinstance(digest, str)
                or _SHA256_RE.fullmatch(digest) is None
            ):
                hmac_result = {"valid": False, "status": "INVALID_SIGNATURE"}
            else:
                try:
                    expected = hmac.new(
                        hmac_key, _canonical_payload(manifest_data), hashlib.sha256,
                    ).hexdigest()
                except (TypeError, ValueError, UnicodeError, RecursionError):
                    hmac_result = {"valid": False, "status": "INVALID_SIGNATURE"}
                else:
                    matches = hmac.compare_digest(expected, digest.lower())
                    hmac_result = {"valid": matches, "status": "OK" if matches else "HASH_MISMATCH"}

        records = manifest_data.get("artifacts")
        results: Dict[str, Dict[str, Any]] = {}
        operator = manifest_data.get("operator")
        metadata_valid = isinstance(operator, str) and bool(operator.strip())
        records_valid = isinstance(records, dict)
        if records_valid:
            for label, info in records.items():
                status = "INVALID_RECORD"
                if (
                    hmac_result["valid"] is not False
                    and isinstance(label, str) and isinstance(info, dict)
                ):
                    path_str = info.get("path")
                    recorded_hash = info.get("sha256")
                    recorded_size = info.get("size_bytes")
                    if (
                        isinstance(path_str, str) and bool(path_str.strip())
                        and "\x00" not in path_str
                        and isinstance(recorded_hash, str)
                        and _SHA256_RE.fullmatch(recorded_hash) is not None
                        and type(recorded_size) is int and recorded_size >= 0
                    ):
                        try:
                            path = Path(path_str)
                            current_hash = cls.compute_sha256(path, expected_size=recorded_size)
                            status = (
                                "OK" if hmac.compare_digest(current_hash, recorded_hash.lower())
                                else "HASH_MISMATCH"
                            )
                        except FileNotFoundError:
                            status = "FILE_NOT_FOUND"
                        except _ArtifactSizeMismatch:
                            status = "SIZE_MISMATCH"
                        except _ArtifactChanged:
                            status = "FILE_CHANGED"
                        except (OSError, ValueError):
                            status = "INVALID_RECORD"
                results[label] = {"valid": status == "OK", "status": status}

        return {
            "valid": (
                metadata_valid and records_valid and hmac_result["valid"] is not False
                and all(result["valid"] for result in results.values())
            ),
            "authenticated": hmac_result["valid"] is True,
            "verification_mode": verification_mode,
            "artifacts": results,
            "hmac": hmac_result,
        }
