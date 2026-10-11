"""Injective key serialization and hardened multi-tenant session storage."""
from __future__ import annotations

from copy import deepcopy
import re
from typing import Any, Dict, List, Optional, Tuple


class InjectiveKeyError(ValueError):
    """Raised when key serialization fails or encounters malformed representations."""
    pass


class LengthPrefixedKeySerializer:
    """Length-prefixed serializer for unambiguous composite string keys.

    Prevents separator collision vulnerabilities where keys containing '/' or delimiter characters
    cross boundary scopes (e.g. project_key="tenant/sub" + session_id="123" colliding with
    project_key="tenant" + session_id="sub" + subpath="123").
    """

    DELIMITER = ":"

    @classmethod
    def serialize(
        cls,
        project_key: str,
        session_id: str,
        subpath: Optional[str] = None,
    ) -> str:
        """Encode exact strings; None denotes only an absent optional subpath."""
        components = (project_key, session_id) if subpath is None else (
            project_key, session_id, subpath,
        )
        if any(type(part) is not str for part in components):
            raise TypeError("All key parts must be str instances")
        p_bytes = project_key.encode("utf-8")
        s_bytes = session_id.encode("utf-8")
        
        parts = [
            f"{len(p_bytes)}:{project_key}",
            f"{len(s_bytes)}:{session_id}",
        ]
        if subpath is not None:
            sub_bytes = subpath.encode("utf-8")
            parts.append(f"{len(sub_bytes)}:{subpath}")
            
        return cls.DELIMITER.join(parts)

    @classmethod
    def deserialize(cls, encoded: str) -> Tuple[str, str, Optional[str]]:
        """Decode a length-prefixed key string into its constituent components."""
        idx = 0
        parsed_components: List[str] = []
        raw_bytes = encoded.encode("utf-8")
        
        while idx < len(raw_bytes):
            sep_idx = raw_bytes.find(b":", idx)
            if sep_idx == -1:
                raise InjectiveKeyError(f"Malformed key at offset {idx}: delimiter missing")
            prefix = raw_bytes[idx:sep_idx]
            if re.fullmatch(rb"(?:0|[1-9][0-9]*)", prefix) is None:
                raise InjectiveKeyError(f"Non-canonical length prefix at offset {idx}")
            try:
                length = int(prefix)
            except ValueError as exc:
                raise InjectiveKeyError(f"Invalid length prefix at offset {idx}") from exc
                
            start_payload = sep_idx + 1
            end_payload = start_payload + length
            if end_payload > len(raw_bytes):
                raise InjectiveKeyError("Truncated key payload does not match declared length")
                
            try:
                payload = raw_bytes[start_payload:end_payload].decode("utf-8", "strict")
            except UnicodeDecodeError as exc:
                raise InjectiveKeyError("Key length splits an invalid UTF-8 payload") from exc
            parsed_components.append(payload)
            
            idx = end_payload
            if idx < len(raw_bytes):
                if raw_bytes[idx:idx+1] != b":":
                    raise InjectiveKeyError(f"Expected delimiter at offset {idx}")
                if idx + 1 == len(raw_bytes):
                    raise InjectiveKeyError("Trailing delimiter is not canonical")
                idx += 1

        if len(parsed_components) == 2:
            return parsed_components[0], parsed_components[1], None
        elif len(parsed_components) == 3:
            return parsed_components[0], parsed_components[1], parsed_components[2]
        else:
            raise InjectiveKeyError(f"Unexpected number of key components: {len(parsed_components)}")


class SafeSessionStore:
    """Hardened reference session store backed by length-prefixed key isolation."""

    def __init__(self) -> None:
        self._storage: Dict[str, List[Dict[str, Any]]] = {}

    def _render_key(
        self,
        project_key: str,
        session_id: str,
        subpath: Optional[str] = None,
    ) -> str:
        return LengthPrefixedKeySerializer.serialize(project_key, session_id, subpath)

    async def append(
        self,
        project_key: str,
        session_id: str,
        entries: List[Dict[str, Any]],
        subpath: Optional[str] = None,
    ) -> None:
        """Store a plain list of dict records, detached from the caller's input.

        Validate and copy the complete batch before changing the stored session.
        Invalid batches or copy failures leave both absent and existing keys alone.
        """
        if type(entries) is not list or any(type(entry) is not dict for entry in entries):
            raise TypeError("Entries must be a list of dict records")
        key = self._render_key(project_key, session_id, subpath)
        copied_entries = deepcopy(entries)
        if key not in self._storage:
            self._storage[key] = []
        self._storage[key].extend(copied_entries)

    async def load(
        self,
        project_key: str,
        session_id: str,
        subpath: Optional[str] = None,
    ) -> Optional[List[Dict[str, Any]]]:
        """Return a deep copy so edits to loaded entries cannot mutate stored data."""
        key = self._render_key(project_key, session_id, subpath)
        data = self._storage.get(key)
        return deepcopy(data) if data is not None else None
