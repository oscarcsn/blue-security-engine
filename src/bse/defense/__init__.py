"""Defensive algorithms and data structures for agentic runtimes."""

from bse.defense.cycle_detector import (
    CyclicSessionGraphError,
    detect_cycles,
    validate_acyclic_entries,
)
from bse.defense.safe_store import (
    InjectiveKeyError,
    LengthPrefixedKeySerializer,
    SafeSessionStore,
)

__all__ = [
    "CyclicSessionGraphError",
    "InjectiveKeyError",
    "LengthPrefixedKeySerializer",
    "SafeSessionStore",
    "detect_cycles",
    "validate_acyclic_entries",
]
