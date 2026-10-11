"""BSE defensive engineering and digital-preservation practices inspired by ISO/IEC 27037."""

__version__ = "0.1.0"
__author__ = "Oscar Cisneros Hernández"

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
from bse.forensics.manifest import EvidenceManifest
from bse.isolation.bubblewrap import BubblewrapBuilder
from bse.isolation.cgroups import CgroupLimits

__all__ = [
    "__version__",
    "__author__",
    "BubblewrapBuilder",
    "CgroupLimits",
    "CyclicSessionGraphError",
    "EvidenceManifest",
    "InjectiveKeyError",
    "LengthPrefixedKeySerializer",
    "SafeSessionStore",
    "detect_cycles",
    "validate_acyclic_entries",
]
