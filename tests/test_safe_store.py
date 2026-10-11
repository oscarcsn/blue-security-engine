"""Unit tests for injective key serialization and hardened multi-tenant storage."""
import unittest
from unittest.mock import patch

from bse.defense.safe_store import (
    InjectiveKeyError,
    LengthPrefixedKeySerializer,
    SafeSessionStore,
)


class TestSafeStore(unittest.IsolatedAsyncioTestCase):
    def test_roundtrip_two_part_key(self):
        p = "enterprise-org"
        s = "session-1234-uuid"
        encoded = LengthPrefixedKeySerializer.serialize(p, s)
        res_p, res_s, res_sub = LengthPrefixedKeySerializer.deserialize(encoded)
        self.assertEqual(res_p, p)
        self.assertEqual(res_s, s)
        self.assertIsNone(res_sub)

    def test_roundtrip_three_part_key(self):
        p = "enterprise-org"
        s = "session-1234-uuid"
        sub = "subagent-alpha"
        encoded = LengthPrefixedKeySerializer.serialize(p, s, sub)
        res_p, res_s, res_sub = LengthPrefixedKeySerializer.deserialize(encoded)
        self.assertEqual(res_p, p)
        self.assertEqual(res_s, s)
        self.assertEqual(res_sub, sub)

    def test_collision_resistance_against_slash_delimiter(self):
        key_a = LengthPrefixedKeySerializer.serialize(
            project_key="tenant/UUID_A",
            session_id="UUID_B",
        )
        key_b = LengthPrefixedKeySerializer.serialize(
            project_key="tenant",
            session_id="UUID_A",
            subpath="UUID_B",
        )
        self.assertNotEqual(key_a, key_b)

    def test_non_string_key_components_are_rejected_without_coercion(self):
        class StringSubclass(str):
            pass

        class Uncoercible:
            def __str__(self):
                raise AssertionError("Key parts must not be coerced")

        invalid_values = (None, False, 0, 1.5, b"tenant", [], {}, StringSubclass("tenant"), Uncoercible())
        for invalid in invalid_values:
            for index in (0, 1, 2):
                # None is the documented absence marker for optional subpath.
                if index == 2 and invalid is None:
                    continue
                parts = ["project", "session", "subpath"]
                parts[index] = invalid
                with self.subTest(index=index, value_type=type(invalid).__name__):
                    with self.assertRaisesRegex(TypeError, "All key parts must be str instances"):
                        LengthPrefixedKeySerializer.serialize(*parts)

    def test_literal_none_is_distinct_from_absent_optional_subpath(self):
        absent = LengthPrefixedKeySerializer.serialize("None", "None")
        explicit_absent = LengthPrefixedKeySerializer.serialize("None", "None", None)
        literal = LengthPrefixedKeySerializer.serialize("None", "None", "None")
        self.assertEqual(absent, explicit_absent)
        self.assertNotEqual(absent, literal)
        self.assertEqual(LengthPrefixedKeySerializer.deserialize(literal), ("None", "None", "None"))

    async def test_invalid_keys_cannot_append_or_load_existing_string_scope(self):
        store = SafeSessionStore()
        await store.append("None", "session", [{"marker": "synthetic-original"}])
        with self.assertRaises(TypeError):
            await store.append(None, "session", [{"marker": "synthetic-invalid"}])
        with self.assertRaises(TypeError):
            await store.load(None, "session")
        self.assertEqual(await store.load("None", "session"), [{"marker": "synthetic-original"}])

    async def test_safe_session_store_isolation(self):
        store = SafeSessionStore()

        # Scope 1: tenant/A as project, B as session
        await store.append("tenant/UUID_A", "UUID_B", [{"marker": "scope-A"}])

        # Scope 2: tenant as project, A as session, B as subpath
        await store.append("tenant", "UUID_A", [{"marker": "scope-B"}], subpath="UUID_B")

        entries_a = await store.load("tenant/UUID_A", "UUID_B")
        entries_b = await store.load("tenant", "UUID_A", subpath="UUID_B")

        self.assertEqual(entries_a, [{"marker": "scope-A"}])
        self.assertEqual(entries_b, [{"marker": "scope-B"}])
        self.assertNotEqual(entries_a, entries_b)

    def test_malformed_key_handling(self):
        with self.assertRaises(InjectiveKeyError):
            LengthPrefixedKeySerializer.deserialize("invalid:missing:format")

    def test_negative_length_is_rejected(self):
        with self.assertRaises(InjectiveKeyError):
            LengthPrefixedKeySerializer.deserialize("-1:-1:")

    def test_signed_length_is_rejected(self):
        with self.assertRaises(InjectiveKeyError):
            LengthPrefixedKeySerializer.deserialize("+6:tenant:1:s")

    def test_underscored_length_is_rejected(self):
        with self.assertRaises(InjectiveKeyError):
            LengthPrefixedKeySerializer.deserialize("0_6:tenant:1:s")

    def test_trailing_delimiter_is_rejected(self):
        with self.assertRaises(InjectiveKeyError):
            LengthPrefixedKeySerializer.deserialize("1:a:1:b:")

    def test_leading_zero_length_is_rejected(self):
        with self.assertRaises(InjectiveKeyError):
            LengthPrefixedKeySerializer.deserialize("06:tenant:1:s")

    def test_unicode_delimiters_and_empty_parts_roundtrip(self):
        for parts in (("", "", None), ("租户:/", "séance", "")):
            with self.subTest(parts=parts):
                encoded = LengthPrefixedKeySerializer.serialize(*parts)
                self.assertEqual(LengthPrefixedKeySerializer.deserialize(encoded), parts)

    def test_split_utf8_payload_is_rejected_as_key_error(self):
        with self.assertRaises(InjectiveKeyError):
            LengthPrefixedKeySerializer.deserialize("1:é:1:s")

    async def test_loaded_nested_values_are_detached_from_storage(self):
        store = SafeSessionStore()
        await store.append("project", "session", [{"nested": {"items": ["original"]}}])
        loaded = await store.load("project", "session")
        loaded[0]["nested"]["items"].append("caller-change")
        loaded.append({"extra": True})
        self.assertEqual(await store.load("project", "session"), [{"nested": {"items": ["original"]}}])
        self.assertIsNone(await store.load("project", "missing"))

    async def test_appended_nested_values_are_detached_from_callers_input(self):
        store = SafeSessionStore()
        entries = [{"nested": {"items": ["original"]}}]
        await store.append("project", "session", entries)
        entries[0]["nested"]["items"].append("caller-change")
        entries[0]["extra"] = True
        entries.clear()
        self.assertEqual(await store.load("project", "session"), [{"nested": {"items": ["original"]}}])

        # Appending to an existing key must detach the new batch as well.
        second = {"nested": {"items": ["second"]}}
        await store.append("project", "session", [second])
        second["nested"]["items"].clear()
        self.assertEqual(await store.load("project", "session"), [
            {"nested": {"items": ["original"]}},
            {"nested": {"items": ["second"]}},
        ])

    async def test_invalid_append_batches_leave_missing_and_existing_sessions_unchanged(self):
        invalid_batches = (None, "abc", b"abc", {}, (), [{"valid": True}, None], [1])
        for batch in invalid_batches:
            with self.subTest(batch_type=type(batch).__name__):
                store = SafeSessionStore()
                original = [{"nested": {"items": ["original"]}}]
                await store.append("project", "existing", original)
                for session in ("missing", "existing"):
                    with self.assertRaisesRegex(TypeError, "Entries must be a list of dict records"):
                        await store.append("project", session, batch)
                self.assertIsNone(await store.load("project", "missing"))
                self.assertEqual(await store.load("project", "existing"), original)

    async def test_failed_deepcopy_leaves_missing_and_existing_sessions_unchanged(self):
        store = SafeSessionStore()
        original = [{"marker": "original"}]
        await store.append("project", "existing", original)
        with patch("bse.defense.safe_store.deepcopy", side_effect=ValueError("copy failed")):
            for session in ("missing", "existing"):
                with self.assertRaisesRegex(ValueError, "copy failed"):
                    await store.append("project", session, [{"marker": "new"}])
        self.assertIsNone(await store.load("project", "missing"))
        self.assertEqual(await store.load("project", "existing"), original)

    async def test_empty_valid_batch_creates_an_explicit_empty_session(self):
        store = SafeSessionStore()
        await store.append("project", "empty", [])
        self.assertEqual(await store.load("project", "empty"), [])


if __name__ == "__main__":
    unittest.main()
