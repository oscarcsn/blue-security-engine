"""Cycle detection and validation for agentic session graphs and message hierarchies."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set


class CyclicSessionGraphError(ValueError):
    """Raised when an unhandled circular reference is identified in session metadata."""

    def __init__(
        self,
        message: str,
        cycle_path: Optional[List[str]] = None,
        *,
        cycles: Optional[List[List[str]]] = None,
    ) -> None:
        super().__init__(message)
        self.cycles = [list(cycle) for cycle in cycles] if cycles is not None else (
            [list(cycle_path)] if cycle_path else []
        )
        # Keep the first-cycle attribute for existing callers.
        self.cycle_path = list(self.cycles[0]) if self.cycles else []


def _normalize_identifier(value: Any) -> Optional[str]:
    """Treat None/empty strings as absent; accept strings and integers, including 0."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError("Graph identifiers must be strings or integers, not booleans")
    if value == "":
        return None
    return str(value)


def detect_cycles(
    entries: List[Dict[str, Any]],
    id_key: str = "uuid",
    parent_key: str = "parentUuid",
) -> List[List[str]]:
    """Detect all circular dependency chains in an agent message/progress sequence.

    Complexity: O(V + E) where V is the number of entries and E is parent links.
    Every node needs a nonempty identifier. Duplicate normalized identifiers
    and unsupported identifier types are rejected; parents may be absent.
    """
    adjacency: Dict[str, str] = {}
    seen_ids: Set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Node entry missing valid non-empty identifier")
        node_id = _normalize_identifier(entry.get(id_key))
        if node_id is None or not node_id.strip():
            raise ValueError("Node entry missing valid non-empty identifier")
        if node_id in seen_ids:
            raise ValueError(f"Duplicate graph uuid: {node_id!r}")
        seen_ids.add(node_id)
        parent_id = _normalize_identifier(entry.get(parent_key))
        if parent_id is not None:
            adjacency[node_id] = parent_id

    visited_global: Set[str] = set()
    cycles: List[List[str]] = []

    for start_node in adjacency:
        if start_node in visited_global:
            continue

        trail: List[str] = []
        trail_set: Set[str] = set()
        curr: Optional[str] = start_node

        while curr and curr in adjacency:
            if curr in trail_set:
                cycle_start_idx = trail.index(curr)
                detected = trail[cycle_start_idx:] + [curr]
                cycles.append(detected)
                break

            if curr in visited_global:
                break

            trail.append(curr)
            trail_set.add(curr)
            curr = adjacency.get(curr)

        visited_global.update(trail_set)

    return cycles


def validate_acyclic_entries(
    entries: List[Dict[str, Any]],
    id_key: str = "uuid",
    parent_key: str = "parentUuid",
) -> None:
    """Validate that session entries form a strict acyclic graph.

    Raises:
        CyclicSessionGraphError: If any circular reference is detected.
    """
    cycles = detect_cycles(entries, id_key=id_key, parent_key=parent_key)
    if cycles:
        cycle_str = "; ".join(" -> ".join(cycle) for cycle in cycles)
        raise CyclicSessionGraphError(
            f"Adversarial or malformed cyclic reference detected: {cycle_str}",
            cycles=cycles,
        )
