"""Synthetic checks for manifest integrity and default shared-key authentication."""
import copy
import hashlib
import hmac
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from bse import __version__
from bse.forensics.manifest import EvidenceManifest


class TestEvidenceManifest(unittest.TestCase):
    def test_evidence_manifest_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            manifest = EvidenceManifest(task_id="TEST-MANIFEST", operator="Synthetic Operator")

            # Create test artifact
            sample_file = tmp_path / "artifact_evidence.bin"
            sample_file.write_bytes(b"\xde\xad\xbe\xef" * 256)

            digest = manifest.add_artifact("primary_log", sample_file)
            self.assertEqual(len(digest), 64)

            export_target = tmp_path / "manifest.json"
            manifest.export_json(export_target)
            self.assertTrue(export_target.is_file())

            loaded = json.loads(export_target.read_text(encoding="utf-8"))
            self.assertEqual(loaded["task_id"], "TEST-MANIFEST")
            self.assertEqual(loaded["artifacts"]["primary_log"]["sha256"], digest)

            # Verify integrity (untampered)
            integrity = EvidenceManifest.verify_manifest(loaded, require_signature=False)
            self.assertTrue(integrity["valid"])
            self.assertEqual(integrity["artifacts"]["primary_log"], {"valid": True, "status": "OK"})
            self.assertEqual(integrity["hmac"], {"valid": None, "status": "NOT_PRESENT"})

            # Tamper with file
            sample_file.write_bytes(b"\xca\xfe\xba\xbe" * 256)
            integrity_tampered = EvidenceManifest.verify_manifest(loaded, require_signature=False)
            self.assertFalse(integrity_tampered["valid"])
            self.assertEqual(integrity_tampered["artifacts"]["primary_log"], {"valid": False, "status": "HASH_MISMATCH"})

    def test_operator_required_and_nonempty(self):
        with self.assertRaises(TypeError):
            EvidenceManifest(task_id="synthetic-task")
        for invalid in ("", " \t\n"):
            with self.subTest(operator=invalid), self.assertRaises(ValueError):
                EvidenceManifest("synthetic-task", operator=invalid)
        for invalid in (None, 42):
            with self.subTest(operator=invalid), self.assertRaises(TypeError):
                EvidenceManifest("synthetic-task", operator=invalid)

    def test_environment_records_version_and_hostname(self):
        with patch("bse.forensics.manifest.platform.node", return_value="synthetic-lab"):
            manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
        self.assertEqual(manifest.telemetry["bse_version"], __version__)
        self.assertEqual(manifest.telemetry["hostname"], "synthetic-lab")

    def test_signature_policy_requires_exact_bool_before_filesystem_access(self):
        class IntegerSubclass(int):
            pass

        class StringSubclass(str):
            pass

        class Uncoercible:
            def __bool__(self):
                raise AssertionError("Signature policy must not be coerced")

        data = {"operator": "Synthetic Operator", "artifacts": {"artifact": {
            "path": "synthetic-artifact.bin", "sha256": "0" * 64, "size_bytes": 0,
        }}}
        for invalid in (None, 0, 1, "", "yes", [], IntegerSubclass(0), StringSubclass(""), Uncoercible()):
            with self.subTest(value_type=type(invalid).__name__):
                with patch("bse.forensics.manifest.os.open") as open_artifact:
                    with patch("bse.forensics.manifest.os.stat") as path_stat:
                        with self.assertRaisesRegex(TypeError, "require_signature must be an exact bool"):
                            EvidenceManifest.verify_manifest(data, require_signature=invalid)
                        path_stat.assert_not_called()
                    open_artifact.assert_not_called()

    def test_verification_modes_distinguish_authentication_from_artifact_integrity(self):
        key = b"synthetic-signing-key"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "artifact.bin"
            path.write_bytes(b"abc")
            manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
            manifest.add_artifact("artifact", path)
            unsigned = manifest.to_dict()
            checksum = EvidenceManifest.verify_manifest(unsigned, require_signature=False)
            self.assertTrue(checksum["valid"])
            self.assertFalse(checksum["authenticated"])
            self.assertEqual(checksum["verification_mode"], "checksum_only")
            signed = manifest.to_dict(hmac_key=key)
            for require_signature in (False, True):
                with self.subTest(require_signature=require_signature):
                    authenticated = EvidenceManifest.verify_manifest(
                        signed, hmac_key=key, require_signature=require_signature,
                    )
                    self.assertTrue(authenticated["valid"])
                    self.assertTrue(authenticated["authenticated"])
                    self.assertEqual(authenticated["verification_mode"], "hmac")
            for data, supplied_key in ((unsigned, None), (signed, None), (signed, b"wrong-synthetic-key")):
                rejected = EvidenceManifest.verify_manifest(data, hmac_key=supplied_key)
                self.assertFalse(rejected["valid"])
                self.assertFalse(rejected["authenticated"])
                self.assertEqual(rejected["verification_mode"], "hmac")
            path.write_bytes(b"xyz")
            altered_artifact = EvidenceManifest.verify_manifest(signed, hmac_key=key)
            self.assertFalse(altered_artifact["valid"])
            self.assertTrue(altered_artifact["authenticated"])
            self.assertEqual(altered_artifact["verification_mode"], "hmac")
            self.assertEqual(altered_artifact["artifacts"]["artifact"]["status"], "HASH_MISMATCH")
        minimal = EvidenceManifest.verify_manifest(
            {"operator": "Synthetic Operator", "artifacts": {}}, require_signature=False,
        )
        self.assertTrue(minimal["valid"])
        self.assertFalse(minimal["authenticated"])
        self.assertEqual(minimal["verification_mode"], "checksum_only")
        invalid_payload = EvidenceManifest.verify_manifest(None)
        self.assertFalse(invalid_payload["authenticated"])
        self.assertEqual(invalid_payload["verification_mode"], "hmac")

    def test_missing_and_malformed_sizes_are_rejected_before_filesystem_access(self):
        class IntegerSubclass(int):
            pass

        key = b"synthetic-signing-key"
        invalid_sizes = (None, False, True, -1, 3.0, "3", IntegerSubclass(3))
        for present, invalid in ((False, None),) + tuple((True, value) for value in invalid_sizes):
            manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
            record = {"path": "synthetic-artifact.bin", "sha256": "0" * 64}
            if present:
                record["size_bytes"] = invalid
            manifest.artifacts["artifact"] = record
            for supplied_key in (None, key):
                data = manifest.to_dict(hmac_key=supplied_key)
                with self.subTest(size_present=present, value_type=type(invalid).__name__, signed=supplied_key is not None):
                    with patch("bse.forensics.manifest.os.open") as open_artifact:
                        with patch("bse.forensics.manifest.os.stat") as path_stat:
                            result = EvidenceManifest.verify_manifest(
                                data, hmac_key=supplied_key, require_signature=supplied_key is not None,
                            )
                            path_stat.assert_not_called()
                        open_artifact.assert_not_called()
                    self.assertFalse(result["valid"])
                    self.assertEqual(result["artifacts"]["artifact"], {"valid": False, "status": "INVALID_RECORD"})

    def test_size_mismatch_is_detected_before_any_content_read(self):
        key = b"synthetic-signing-key"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "artifact.bin"
            path.write_bytes(b"abc")
            manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
            manifest.add_artifact("artifact", path)
            signed = manifest.to_dict(hmac_key=key)
            for replacement in (b"a", b"abcd"):
                path.write_bytes(replacement)
                with self.subTest(size=len(replacement)):
                    with patch("bse.forensics.manifest.os.read") as read_artifact:
                        result = EvidenceManifest.verify_manifest(signed, hmac_key=key)
                        read_artifact.assert_not_called()
                    self.assertFalse(result["valid"])
                    self.assertTrue(result["authenticated"])
                    self.assertEqual(result["artifacts"]["artifact"]["status"], "SIZE_MISMATCH")

    def test_growing_file_has_a_size_derived_read_budget(self):
        key = b"synthetic-signing-key"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "artifact.bin"
            path.write_bytes(b"abc")
            manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
            manifest.add_artifact("artifact", path)
            signed = manifest.to_dict(hmac_key=key)
            actual_read = os.read
            first_read = True

            def grow_after_first_read(descriptor, count):
                nonlocal first_read
                chunk = actual_read(descriptor, count)
                if first_read:
                    first_read = False
                    with path.open("ab") as handle:
                        handle.write(b"x" * 20)
                return chunk

            with patch("bse.forensics.manifest.os.read", side_effect=grow_after_first_read) as read_artifact:
                result = EvidenceManifest.verify_manifest(signed, hmac_key=key)
            self.assertFalse(result["valid"])
            self.assertEqual(result["artifacts"]["artifact"]["status"], "SIZE_MISMATCH")
            self.assertEqual([call.args[1] for call in read_artifact.call_args_list], [4, 1])
            self.assertEqual(path.stat().st_size, 23)

    def test_truncated_file_is_rejected_during_bounded_hashing(self):
        key = b"synthetic-signing-key"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "artifact.bin"
            path.write_bytes(b"abc")
            manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
            manifest.add_artifact("artifact", path)
            signed = manifest.to_dict(hmac_key=key)
            actual_read = os.read
            first_read = True

            def truncate_after_first_read(descriptor, count):
                nonlocal first_read
                chunk = actual_read(descriptor, count)
                if first_read:
                    first_read = False
                    path.write_bytes(b"")
                return chunk

            with patch("bse.forensics.manifest.os.read", side_effect=truncate_after_first_read) as read_artifact:
                result = EvidenceManifest.verify_manifest(signed, hmac_key=key)
            self.assertFalse(result["valid"])
            self.assertEqual(result["artifacts"]["artifact"]["status"], "SIZE_MISMATCH")
            self.assertEqual([call.args[1] for call in read_artifact.call_args_list], [4, 1])
            self.assertEqual(path.stat().st_size, 0)

    def test_same_size_descriptor_metadata_change_is_rejected(self):
        key = b"synthetic-signing-key"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "artifact.bin"
            path.write_bytes(b"abc")
            manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
            manifest.add_artifact("artifact", path)
            signed = manifest.to_dict(hmac_key=key)
            initial = path.stat()
            changed = SimpleNamespace(**{
                field: getattr(initial, field) for field in (
                    "st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns",
                )
            })
            changed.st_mtime_ns += 1
            with patch("bse.forensics.manifest.os.fstat", side_effect=(initial, changed)) as descriptor_stat:
                result = EvidenceManifest.verify_manifest(signed, hmac_key=key)
                self.assertEqual(descriptor_stat.call_count, 2)
            self.assertFalse(result["valid"])
            self.assertEqual(result["artifacts"]["artifact"]["status"], "FILE_CHANGED")

    def test_replaced_path_is_rejected_even_with_matching_content(self):
        key = b"synthetic-signing-key"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "artifact.bin"
            path.write_bytes(b"abc")
            manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
            manifest.add_artifact("artifact", path)
            signed = manifest.to_dict(hmac_key=key)
            initial = path.stat()
            actual_read = os.read
            first_read = True

            def replace_after_first_read(descriptor, count):
                nonlocal first_read
                chunk = actual_read(descriptor, count)
                if first_read:
                    first_read = False
                    path.unlink()
                    path.write_bytes(b"abc")
                return chunk

            # Keep descriptor metadata constant to exercise the independent path check.
            with patch("bse.forensics.manifest.os.fstat", return_value=initial):
                with patch("bse.forensics.manifest.os.read", side_effect=replace_after_first_read):
                    result = EvidenceManifest.verify_manifest(signed, hmac_key=key)
            self.assertFalse(result["valid"])
            self.assertEqual(result["artifacts"]["artifact"]["status"], "FILE_CHANGED")
            self.assertEqual(path.read_bytes(), b"abc")

    def test_final_artifact_symlinks_are_rejected_without_reading(self):
        key = b"synthetic-signing-key"
        for victim_exists in (False, True):
            with self.subTest(victim_exists=victim_exists), tempfile.TemporaryDirectory() as tmpdir:
                parent = Path(tmpdir)
                victim = parent / "victim.bin"
                content = b"synthetic victim"
                if victim_exists:
                    victim.write_bytes(content)
                link = parent / "artifact-link.bin"
                link.symlink_to(victim)
                manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
                with patch("bse.forensics.manifest.os.read") as read_artifact:
                    with self.assertRaises(OSError):
                        manifest.add_artifact("artifact", link)
                    self.assertEqual(manifest.artifacts, {})
                    with self.assertRaises(OSError):
                        EvidenceManifest.compute_sha256(link)
                    manifest.artifacts["artifact"] = {
                        "path": str(link), "size_bytes": len(content),
                        "sha256": hashlib.sha256(content).hexdigest(),
                    }
                    result = EvidenceManifest.verify_manifest(manifest.to_dict(hmac_key=key), hmac_key=key)
                    read_artifact.assert_not_called()
                self.assertFalse(result["valid"])
                self.assertTrue(result["authenticated"])
                self.assertEqual(result["artifacts"]["artifact"]["status"], "INVALID_RECORD")
                self.assertTrue(link.is_symlink())
                if victim_exists:
                    self.assertEqual(victim.read_bytes(), content)
                else:
                    self.assertFalse(victim.exists())

    def test_fifo_artifacts_are_rejected_without_blocking_or_reading(self):
        key = b"synthetic-signing-key"
        with tempfile.TemporaryDirectory() as tmpdir:
            fifo = Path(tmpdir) / "synthetic.fifo"
            os.mkfifo(fifo)
            manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
            actual_open = os.open

            def guarded_open(path, flags):
                # A regression must fail this assertion before opening a blocking FIFO.
                self.assertTrue(flags & os.O_NONBLOCK)
                self.assertTrue(flags & os.O_NOFOLLOW)
                return actual_open(path, flags)

            with patch("bse.forensics.manifest.os.open", side_effect=guarded_open) as open_artifact:
                with patch("bse.forensics.manifest.os.read") as read_artifact:
                    with self.assertRaisesRegex(ValueError, "Artifact must be a regular file"):
                        manifest.add_artifact("artifact", fifo)
                    self.assertEqual(manifest.artifacts, {})
                    with self.assertRaisesRegex(ValueError, "Artifact must be a regular file"):
                        EvidenceManifest.compute_sha256(fifo)
                    manifest.artifacts["artifact"] = {
                        "path": str(fifo), "size_bytes": 0,
                        "sha256": hashlib.sha256(b"").hexdigest(),
                    }
                    result = EvidenceManifest.verify_manifest(manifest.to_dict(hmac_key=key), hmac_key=key)
                    read_artifact.assert_not_called()
                self.assertEqual(open_artifact.call_count, 3)
            self.assertFalse(result["valid"])
            self.assertEqual(result["artifacts"]["artifact"]["status"], "INVALID_RECORD")

    def test_regular_file_hashing_uses_one_descriptor_and_multiple_chunks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "artifact.bin"
            content = b"x" * 65537
            path.write_bytes(content)
            manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
            actual_open, actual_read, actual_close = os.open, os.read, os.close
            with patch("bse.forensics.manifest.os.open", wraps=actual_open) as open_artifact:
                with patch("bse.forensics.manifest.os.read", wraps=actual_read) as read_artifact:
                    with patch("bse.forensics.manifest.os.close", wraps=actual_close) as close_artifact:
                        digest = manifest.add_artifact("artifact", path)
                        open_artifact.assert_called_once()
                        descriptor = read_artifact.call_args_list[0].args[0]
                        close_artifact.assert_called_once_with(descriptor)
            self.assertEqual({call.args[0] for call in read_artifact.call_args_list}, {descriptor})
            self.assertEqual([call.args[1] for call in read_artifact.call_args_list], [65536, 2, 1])
            self.assertEqual(digest, hashlib.sha256(content).hexdigest())
            self.assertEqual(manifest.artifacts["artifact"]["size_bytes"], len(content))
            self.assertEqual(manifest.artifacts["artifact"]["sha256"], digest)

    def test_empty_regular_artifact_accepts_integer_zero_size(self):
        key = b"synthetic-signing-key"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "empty-artifact.bin"
            path.write_bytes(b"")
            manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
            digest = manifest.add_artifact("artifact", path)
            self.assertEqual(digest, hashlib.sha256(b"").hexdigest())
            self.assertEqual(manifest.artifacts["artifact"]["size_bytes"], 0)
            result = EvidenceManifest.verify_manifest(manifest.to_dict(hmac_key=key), hmac_key=key)
            self.assertTrue(result["valid"])
            self.assertTrue(result["authenticated"])
            self.assertEqual(result["artifacts"]["artifact"], {"valid": True, "status": "OK"})

    def test_add_artifact_does_not_register_a_file_that_grows_during_hashing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "artifact.bin"
            path.write_bytes(b"abc")
            manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
            actual_read = os.read
            first_read = True

            def grow_after_first_read(descriptor, count):
                nonlocal first_read
                chunk = actual_read(descriptor, count)
                if first_read:
                    first_read = False
                    with path.open("ab") as handle:
                        handle.write(b"x" * 20)
                return chunk

            with patch("bse.forensics.manifest.os.read", side_effect=grow_after_first_read) as read_artifact:
                with self.assertRaisesRegex(ValueError, "grew or was truncated"):
                    manifest.add_artifact("artifact", path)
            self.assertEqual([call.args[1] for call in read_artifact.call_args_list], [4, 1])
            self.assertEqual(manifest.artifacts, {})

    def test_missing_file_and_invalid_read_have_distinct_statuses(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "artifact.bin"
            path.write_bytes(b"synthetic artifact")
            manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
            manifest.add_artifact("artifact", path)
            data = manifest.to_dict()
            with patch.object(EvidenceManifest, "compute_sha256", side_effect=PermissionError("synthetic refusal")):
                unreadable = EvidenceManifest.verify_manifest(data, require_signature=False)
            self.assertFalse(unreadable["valid"])
            self.assertEqual(unreadable["artifacts"]["artifact"]["status"], "INVALID_RECORD")
            with patch.object(EvidenceManifest, "compute_sha256", side_effect=FileNotFoundError("synthetic disappearance")):
                vanished_during_read = EvidenceManifest.verify_manifest(data, require_signature=False)
            self.assertFalse(vanished_during_read["valid"])
            self.assertEqual(vanished_during_read["artifacts"]["artifact"]["status"], "FILE_NOT_FOUND")
            path.unlink()
            missing = EvidenceManifest.verify_manifest(data, require_signature=False)
            self.assertFalse(missing["valid"])
            self.assertEqual(missing["artifacts"]["artifact"]["status"], "FILE_NOT_FOUND")

    def test_surrogate_path_is_invalid_record_in_checksum_mode(self):
        manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
        data = manifest.to_dict()
        data["artifacts"] = {
            "artifact": {"path": "synthetic-artifact-\ud800.bin", "sha256": "0" * 64, "size_bytes": 0},
        }
        result = EvidenceManifest.verify_manifest(data, require_signature=False)
        self.assertFalse(result["valid"])
        self.assertEqual(result["hmac"], {"valid": None, "status": "NOT_PRESENT"})
        self.assertEqual(result["artifacts"]["artifact"], {"valid": False, "status": "INVALID_RECORD"})

    def test_file_read_unicode_encoding_error_is_invalid_record(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "artifact.bin"
            path.write_bytes(b"synthetic artifact")
            manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
            manifest.add_artifact("artifact", path)
            data = manifest.to_dict()
            encoding_error = UnicodeEncodeError("utf-8", "\ud800", 0, 1, "synthetic surrogate")
            with patch("bse.forensics.manifest.os.open", side_effect=encoding_error) as open_artifact:
                result = EvidenceManifest.verify_manifest(data, require_signature=False)
                open_artifact.assert_called_once_with(
                    Path(data["artifacts"]["artifact"]["path"]),
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0),
                )
            self.assertFalse(result["valid"])
            self.assertEqual(result["artifacts"]["artifact"], {"valid": False, "status": "INVALID_RECORD"})

    def test_invalid_artifact_records_fail_closed(self):
        manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
        for record in (None, [], {}, {"path": 42, "sha256": "a" * 64}, {"path": "ignored", "sha256": "invalid"}):
            data = manifest.to_dict()
            data["artifacts"] = {"artifact": record}
            with self.subTest(record=record):
                result = EvidenceManifest.verify_manifest(data, require_signature=False)
                self.assertFalse(result["valid"])
                self.assertEqual(result["artifacts"]["artifact"]["status"], "INVALID_RECORD")
        data = manifest.to_dict()
        data["artifacts"] = []
        self.assertFalse(EvidenceManifest.verify_manifest(data, require_signature=False)["valid"])
        data = manifest.to_dict()
        data["operator"] = " "
        self.assertFalse(EvidenceManifest.verify_manifest(data, require_signature=False)["valid"])

    def test_signed_export_uses_canonical_payload_and_does_not_export_key(self):
        key = b"synthetic-key-never-persisted"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "artifact.bin"
            path.write_bytes(b"synthetic signed artifact")
            manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operador \u00e1")
            manifest.add_artifact("artifact", path)
            data = manifest.to_dict(hmac_key=key)
            payload = {name: value for name, value in data.items() if name != "signature"}
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
            expected = hmac.new(key, canonical, hashlib.sha256).hexdigest()
            self.assertEqual(data["signature"], {"algorithm": "HMAC-SHA256", "digest": expected})
            export = Path(tmpdir) / "manifest.json"
            manifest.export_json(export, hmac_key=key)
            serialized = export.read_text(encoding="utf-8")
            self.assertNotIn(key.decode("ascii"), serialized)
            self.assertEqual(json.loads(serialized), data)
            verified = EvidenceManifest.verify_manifest(json.loads(serialized), hmac_key=key)
            self.assertTrue(verified["valid"])
            self.assertEqual(verified["hmac"], {"valid": True, "status": "OK"})
            self.assertNotIn("signature", manifest.to_dict())
            self.assertNotIn("hmac_key", vars(manifest))

    def test_export_nonserializable_payload_preserves_destination_and_cleans_temporary(self):
        for preexisting in (False, True):
            with self.subTest(preexisting=preexisting), tempfile.TemporaryDirectory() as tmpdir:
                parent = Path(tmpdir)
                destination = parent / "manifest.json"
                old_content = b"synthetic original manifest"
                if preexisting:
                    destination.write_bytes(old_content)
                manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
                manifest.telemetry["nonserializable"] = {1, 2}
                with self.assertRaises(TypeError):
                    manifest.export_json(destination)
                if preexisting:
                    self.assertEqual(destination.read_bytes(), old_content)
                else:
                    self.assertFalse(destination.exists())
                self.assertEqual(set(parent.iterdir()), {destination} if preexisting else set())

    def test_export_partial_write_failure_preserves_destination_and_cleans_temporary(self):
        def fail_after_partial_write(data, handle, **kwargs):
            handle.write('{"partial":')
            handle.flush()
            raise OSError("synthetic partial write failure")

        for preexisting in (False, True):
            with self.subTest(preexisting=preexisting), tempfile.TemporaryDirectory() as tmpdir:
                parent = Path(tmpdir)
                destination = parent / "manifest.json"
                old_content = b"synthetic original manifest"
                if preexisting:
                    destination.write_bytes(old_content)
                manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
                with patch("bse.forensics.manifest.json.dump", side_effect=fail_after_partial_write) as dump:
                    with self.assertRaises(OSError):
                        manifest.export_json(destination)
                    dump.assert_called_once()
                if preexisting:
                    self.assertEqual(destination.read_bytes(), old_content)
                else:
                    self.assertFalse(destination.exists())
                self.assertEqual(set(parent.iterdir()), {destination} if preexisting else set())

    def test_export_replace_failure_preserves_destination_and_cleans_temporary(self):
        for preexisting in (False, True):
            with self.subTest(preexisting=preexisting), tempfile.TemporaryDirectory() as tmpdir:
                parent = Path(tmpdir)
                destination = parent / "manifest.json"
                old_content = b"synthetic original manifest"
                if preexisting:
                    destination.write_bytes(old_content)
                manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")

                def fail_replace(source, target):
                    self.assertEqual(Path(source).parent, parent)
                    self.assertEqual(Path(target), destination)
                    self.assertEqual(json.loads(Path(source).read_text(encoding="utf-8")), manifest.to_dict())
                    raise PermissionError("synthetic replace refusal")

                with patch("bse.forensics.manifest.os.replace", side_effect=fail_replace) as replace:
                    with self.assertRaises(PermissionError):
                        manifest.export_json(destination)
                    replace.assert_called_once()
                if preexisting:
                    self.assertEqual(destination.read_bytes(), old_content)
                else:
                    self.assertFalse(destination.exists())
                self.assertEqual(set(parent.iterdir()), {destination} if preexisting else set())

    def test_export_rejects_existing_and_dangling_destination_symlinks(self):
        for victim_exists in (False, True):
            with self.subTest(victim_exists=victim_exists), tempfile.TemporaryDirectory() as tmpdir:
                parent = Path(tmpdir)
                victim = parent / "victim.bin"
                victim_content = b"synthetic victim remains intact"
                if victim_exists:
                    victim.write_bytes(victim_content)
                destination = parent / "manifest.json"
                destination.symlink_to(victim)
                expected_paths = {destination, victim} if victim_exists else {destination}
                manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
                with patch("bse.forensics.manifest.json.dump") as dump:
                    with patch("bse.forensics.manifest.os.replace") as replace:
                        with self.assertRaises(ValueError):
                            manifest.export_json(destination)
                        replace.assert_not_called()
                    dump.assert_not_called()
                self.assertTrue(destination.is_symlink())
                if victim_exists:
                    self.assertEqual(victim.read_bytes(), victim_content)
                else:
                    self.assertFalse(victim.exists())
                self.assertEqual(set(parent.iterdir()), expected_paths)

    def test_export_atomically_replaces_destination_and_cleans_temporary(self):
        key = b"synthetic-signing-key"
        with tempfile.TemporaryDirectory() as tmpdir:
            parent = Path(tmpdir)
            destination = parent / "manifest.json"
            old_content = b"synthetic original manifest"
            destination.write_bytes(old_content)
            manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
            expected = manifest.to_dict(hmac_key=key)
            actual_replace = os.replace

            def inspect_and_replace(source, target):
                self.assertEqual(destination.read_bytes(), old_content)
                self.assertEqual(Path(source).parent, parent)
                self.assertNotEqual(Path(source), destination)
                self.assertEqual(Path(target), destination)
                self.assertEqual(json.loads(Path(source).read_text(encoding="utf-8")), expected)
                actual_replace(source, target)

            with patch("bse.forensics.manifest.os.replace", side_effect=inspect_and_replace) as replace:
                manifest.export_json(destination, hmac_key=key)
                replace.assert_called_once()
            loaded = json.loads(destination.read_text(encoding="utf-8"))
            self.assertEqual(loaded, expected)
            self.assertTrue(EvidenceManifest.verify_manifest(loaded, hmac_key=key)["valid"])
            self.assertEqual(set(parent.iterdir()), {destination})

    def test_export_rechecks_destination_symlink_after_serialization(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            parent = Path(tmpdir)
            destination = parent / "manifest.json"
            victim = parent / "victim.bin"
            victim_content = b"synthetic victim remains intact"
            victim.write_bytes(victim_content)
            manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
            actual_dump = json.dump

            def write_then_introduce_symlink(data, handle, **kwargs):
                actual_dump(data, handle, **kwargs)
                destination.symlink_to(victim)

            with patch("bse.forensics.manifest.json.dump", side_effect=write_then_introduce_symlink):
                with patch("bse.forensics.manifest.os.replace") as replace:
                    with self.assertRaises(ValueError):
                        manifest.export_json(destination)
                    replace.assert_not_called()
            self.assertTrue(destination.is_symlink())
            self.assertEqual(victim.read_bytes(), victim_content)
            self.assertEqual(set(parent.iterdir()), {destination, victim})

    def test_export_replace_does_not_follow_symlink_created_after_final_check(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            parent = Path(tmpdir)
            destination = parent / "manifest.json"
            victim = parent / "victim.bin"
            victim_content = b"synthetic victim remains intact"
            victim.write_bytes(victim_content)
            manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
            expected = manifest.to_dict()
            actual_replace = os.replace

            def introduce_symlink_then_replace(source, target):
                destination.symlink_to(victim)
                actual_replace(source, target)

            with patch("bse.forensics.manifest.os.replace", side_effect=introduce_symlink_then_replace) as replace:
                manifest.export_json(destination)
                replace.assert_called_once()
            self.assertFalse(destination.is_symlink())
            self.assertEqual(json.loads(destination.read_text(encoding="utf-8")), expected)
            self.assertEqual(victim.read_bytes(), victim_content)
            self.assertEqual(set(parent.iterdir()), {destination, victim})

    def test_wrong_key_missing_key_and_signature_removal_fail_closed(self):
        key = b"synthetic-signing-key"
        manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
        signed = manifest.to_dict(hmac_key=key)
        cases = [
            (signed, b"different-synthetic-key", "HASH_MISMATCH"),
            (signed, None, "KEY_REQUIRED"),
            (manifest.to_dict(), key, "SIGNATURE_REQUIRED"),
        ]
        for data, supplied_key, status in cases:
            with self.subTest(status=status):
                result = EvidenceManifest.verify_manifest(data, hmac_key=supplied_key, require_signature=False)
                self.assertFalse(result["valid"])
                self.assertEqual(result["hmac"], {"valid": False, "status": status})

    def test_valid_signature_does_not_hide_artifact_changes(self):
        key = b"synthetic-signing-key"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "artifact.bin"
            path.write_bytes(b"original synthetic evidence")
            manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
            manifest.add_artifact("artifact", path)
            signed = manifest.to_dict(hmac_key=key)
            path.write_bytes(b"modified synthetic evidence")
            result = EvidenceManifest.verify_manifest(signed, hmac_key=key)
            self.assertFalse(result["valid"])
            self.assertEqual(result["hmac"], {"valid": True, "status": "OK"})
            self.assertEqual(result["artifacts"]["artifact"]["status"], "HASH_MISMATCH")

    def test_rewritten_path_and_hash_are_rejected_without_reading(self):
        key = b"synthetic-signing-key"
        with tempfile.TemporaryDirectory() as tmpdir:
            original = Path(tmpdir) / "original.bin"
            replacement = Path(tmpdir) / "replacement.bin"
            original.write_bytes(b"original synthetic evidence")
            replacement.write_bytes(b"replacement synthetic evidence")
            manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
            manifest.add_artifact("artifact", original)
            tampered = manifest.to_dict(hmac_key=key)
            tampered["artifacts"]["artifact"]["path"] = str(replacement)
            tampered["artifacts"]["artifact"]["sha256"] = hashlib.sha256(replacement.read_bytes()).hexdigest()
            with patch.object(EvidenceManifest, "compute_sha256") as compute:
                result = EvidenceManifest.verify_manifest(tampered, hmac_key=key)
                compute.assert_not_called()
            self.assertFalse(result["valid"])
            self.assertEqual(result["hmac"]["status"], "HASH_MISMATCH")
            self.assertEqual(result["artifacts"]["artifact"]["status"], "INVALID_RECORD")

    def test_metadata_tampering_is_covered_by_signature(self):
        key = b"synthetic-signing-key"
        manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
        signed = manifest.to_dict(hmac_key=key)
        for field, value in (("task_id", "rewritten-task"), ("operator", "Rewritten Operator"), ("created_at_utc", "rewritten-time")):
            tampered = copy.deepcopy(signed)
            tampered[field] = value
            with self.subTest(field=field):
                result = EvidenceManifest.verify_manifest(tampered, hmac_key=key)
                self.assertFalse(result["valid"])
                self.assertEqual(result["hmac"]["status"], "HASH_MISMATCH")
        tampered = copy.deepcopy(signed)
        tampered["telemetry"]["hostname"] = "rewritten-host"
        self.assertEqual(EvidenceManifest.verify_manifest(tampered, hmac_key=key)["hmac"]["status"], "HASH_MISMATCH")

    def test_malformed_signature_and_noncanonical_payload_are_rejected(self):
        key = b"synthetic-signing-key"
        manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
        for signature in (None, "invalid", {}, {"algorithm": "SHA256", "digest": "a" * 64}, {"algorithm": "HMAC-SHA256", "digest": "not-hex"}):
            data = manifest.to_dict()
            data["signature"] = signature
            with self.subTest(signature=signature):
                result = EvidenceManifest.verify_manifest(data, hmac_key=key)
                self.assertFalse(result["valid"])
                self.assertEqual(result["hmac"]["status"], "INVALID_SIGNATURE")
        tampered = manifest.to_dict(hmac_key=key)
        tampered["telemetry"]["invalid_number"] = float("nan")
        self.assertEqual(EvidenceManifest.verify_manifest(tampered, hmac_key=key)["hmac"]["status"], "INVALID_SIGNATURE")
        # Encoder depth limits vary across Python versions. Both a supported
        # payload with a wrong digest and an encoder failure must reject reads.
        deep = None
        for _ in range(sys.getrecursionlimit() + 50):
            deep = [deep]
        circular = []
        circular.append(circular)
        for label, value in (("overly_deep", deep), ("circular", circular)):
            data = {
                "operator": "Synthetic Operator",
                "telemetry": {label: value},
                "signature": {"algorithm": "HMAC-SHA256", "digest": "0" * 64},
                "artifacts": {"synthetic": {
                    "path": "/tmp/synthetic-artifact-must-not-be-read",
                    "sha256": "0" * 64, "size_bytes": 0,
                }},
            }
            with self.subTest(payload=label):
                with patch.object(EvidenceManifest, "compute_sha256") as read_artifact:
                    result = EvidenceManifest.verify_manifest(data, hmac_key=key)
                read_artifact.assert_not_called()
                self.assertFalse(result["valid"])
                self.assertFalse(result["authenticated"])
                self.assertIn(result["hmac"]["status"], ("INVALID_SIGNATURE", "HASH_MISMATCH"))
                self.assertEqual(result["artifacts"]["synthetic"]["status"], "INVALID_RECORD")
        # Exercise the exception contract independently of the runtime's depth
        # threshold: an encoder error must be a structured authentication failure.
        data["telemetry"] = {"synthetic": "flat"}
        with patch("bse.forensics.manifest.json.dumps", side_effect=RecursionError("synthetic encoder budget")):
            with patch.object(EvidenceManifest, "compute_sha256") as read_artifact:
                result = EvidenceManifest.verify_manifest(data, hmac_key=key)
        read_artifact.assert_not_called()
        self.assertFalse(result["valid"])
        self.assertFalse(result["authenticated"])
        self.assertEqual(result["hmac"]["status"], "INVALID_SIGNATURE")
        self.assertEqual(result["artifacts"]["synthetic"]["status"], "INVALID_RECORD")
        manifest.telemetry["invalid_number"] = float("nan")
        with self.assertRaises(ValueError):
            manifest.to_dict(hmac_key=key)

    def test_invalid_keys_are_configuration_errors(self):
        manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
        for method, args, kwargs in (
            (manifest.to_dict, (), {}),
            (EvidenceManifest.verify_manifest, (manifest.to_dict(),), {"require_signature": False}),
        ):
            with self.assertRaises(ValueError):
                method(*args, hmac_key=b"", **kwargs)
            with self.assertRaises(TypeError):
                method(*args, hmac_key="not-bytes", **kwargs)
        with tempfile.TemporaryDirectory() as tmpdir:
            destination = Path(tmpdir) / "never-created.json"
            with self.assertRaises(ValueError):
                manifest.export_json(destination, hmac_key=b"")
            self.assertFalse(destination.exists())

    def test_default_verification_accepts_signed_manifest_and_valid_key(self):
        key = b"synthetic-signing-key"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "artifact.bin"
            path.write_bytes(b"synthetic strict evidence")
            manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
            manifest.add_artifact("artifact", path)
            signed = manifest.to_dict(hmac_key=key)
            with patch.object(
                EvidenceManifest, "compute_sha256", wraps=EvidenceManifest.compute_sha256,
            ) as compute:
                result = EvidenceManifest.verify_manifest(
                    signed, hmac_key=key,
                )
                compute.assert_called_once_with(
                    Path(signed["artifacts"]["artifact"]["path"]),
                    expected_size=signed["artifacts"]["artifact"]["size_bytes"],
                )
            self.assertTrue(result["valid"])
            self.assertEqual(result["hmac"], {"valid": True, "status": "OK"})
            self.assertEqual(result["artifacts"]["artifact"], {"valid": True, "status": "OK"})

    def test_default_rejects_unsigned_and_stripped_manifests_before_reads(self):
        key = b"synthetic-signing-key"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "artifact.bin"
            path.write_bytes(b"synthetic default evidence")
            manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
            manifest.add_artifact("artifact", path)
            unsigned = manifest.to_dict()
            stripped = manifest.to_dict(hmac_key=key)
            del stripped["signature"]
            for label, data in (("unsigned", unsigned), ("stripped", stripped)):
                for supplied_key in (None, key):
                    with self.subTest(manifest=label, key_present=supplied_key is not None):
                        with patch.object(EvidenceManifest, "compute_sha256") as compute:
                            with patch("bse.forensics.manifest.Path.stat") as path_stat:
                                result = EvidenceManifest.verify_manifest(data, hmac_key=supplied_key)
                                path_stat.assert_not_called()
                            compute.assert_not_called()
                        self.assertFalse(result["valid"])
                        self.assertEqual(result["hmac"], {"valid": False, "status": "MISSING_SIGNATURE"})
                        self.assertEqual(result["artifacts"]["artifact"]["status"], "INVALID_RECORD")

    def test_strict_signature_removal_cannot_downgrade_to_unsigned(self):
        key = b"synthetic-signing-key"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "artifact.bin"
            path.write_bytes(b"synthetic strict evidence")
            manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
            manifest.add_artifact("artifact", path)
            stripped = manifest.to_dict(hmac_key=key)
            del stripped["signature"]
            for supplied_key in (None, key):
                with self.subTest(key_present=supplied_key is not None):
                    with patch.object(EvidenceManifest, "compute_sha256") as compute:
                        result = EvidenceManifest.verify_manifest(
                            stripped, hmac_key=supplied_key, require_signature=True,
                        )
                        compute.assert_not_called()
                    self.assertFalse(result["valid"])
                    self.assertEqual(result["hmac"], {"valid": False, "status": "MISSING_SIGNATURE"})
                    self.assertEqual(result["artifacts"]["artifact"]["status"], "INVALID_RECORD")
            self.assertTrue(EvidenceManifest.verify_manifest(stripped, require_signature=False)["valid"])

    def test_strict_invalid_keys_return_structured_failure_without_reads(self):
        key = b"synthetic-signing-key"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "artifact.bin"
            path.write_bytes(b"synthetic strict evidence")
            manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
            manifest.add_artifact("artifact", path)
            for data in (manifest.to_dict(), manifest.to_dict(hmac_key=key)):
                for invalid_key in (b"", "not-bytes", bytearray(b"synthetic"), 42):
                    with self.subTest(signature_present="signature" in data, key_type=type(invalid_key).__name__):
                        with patch.object(EvidenceManifest, "compute_sha256") as compute:
                            result = EvidenceManifest.verify_manifest(
                                data, hmac_key=invalid_key, require_signature=True,
                            )
                            compute.assert_not_called()
                        self.assertFalse(result["valid"])
                        self.assertEqual(result["hmac"], {"valid": False, "status": "INVALID_KEY"})
                        self.assertEqual(result["artifacts"]["artifact"]["status"], "INVALID_RECORD")

    def test_strict_missing_key_wrong_key_and_tampering_do_not_read_artifacts(self):
        key = b"synthetic-signing-key"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "artifact.bin"
            path.write_bytes(b"synthetic strict evidence")
            manifest = EvidenceManifest("synthetic-task", operator="Synthetic Operator")
            manifest.add_artifact("artifact", path)
            signed = manifest.to_dict(hmac_key=key)
            tampered = copy.deepcopy(signed)
            tampered["operator"] = "Rewritten Synthetic Operator"
            cases = (
                (signed, None, "KEY_REQUIRED"),
                (signed, b"different-synthetic-key", "HASH_MISMATCH"),
                (tampered, key, "HASH_MISMATCH"),
            )
            for data, supplied_key, status in cases:
                with self.subTest(status=status, key_present=supplied_key is not None):
                    with patch.object(EvidenceManifest, "compute_sha256") as compute:
                        result = EvidenceManifest.verify_manifest(
                            data, hmac_key=supplied_key, require_signature=True,
                        )
                        compute.assert_not_called()
                    self.assertFalse(result["valid"])
                    self.assertEqual(result["hmac"], {"valid": False, "status": status})
                    self.assertEqual(result["artifacts"]["artifact"]["status"], "INVALID_RECORD")


if __name__ == "__main__":
    unittest.main()
