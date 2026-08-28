"""Zone-0 path matching. Mirrors docs/S-00-overview.md sec 4's table exactly.

If that table changes, this list must change with it in the same PR —
see the "Zone-0 path list" note in the plan that introduced this file.
"""
import fnmatch

ZONE_0_PATTERNS = [
    ".github/**",
    "src/sign/**",
    "conformance/**",
    "docs/S-00-overview.md",
    "docs/S-01-threat-model.md",
    "docs/S-02-schema.md",
    "schemas/**",
    "journal/**",
]


def is_zone_zero(path: str) -> bool:
    """True if `path` falls under any zone-0 pattern from S-00 sec 4."""
    return any(fnmatch.fnmatch(path, pattern) for pattern in ZONE_0_PATTERNS)
