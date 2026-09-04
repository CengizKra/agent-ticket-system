"""Zone-0 path matching. Mirrors docs/S-00-overview.md sec 4's table exactly.

If that table changes, this list must change with it in the same PR —
see the "Zone-0 path list" note in the plan that introduced this file.
"""
import fnmatch
import posixpath

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


def is_safe_relative_path(path: object) -> bool:
    """True only for an already-normalized, relative, forward-slash path
    with no traversal or absolute component. Glob matching against
    ZONE_0_PATTERNS or a grant's scope.paths is only meaningful on a path
    in this exact form — anything else (backslashes, '..', a leading '/',
    a non-normalized form like 'a//b' or './a') must be rejected by the
    caller rather than matched, since matching it could disagree with
    what the string actually resolves to on disk.
    """
    if not isinstance(path, str) or not path:
        return False
    if "\\" in path:
        return False
    if path.startswith("/"):
        return False
    normalized = posixpath.normpath(path)
    if normalized != path or normalized == "." or normalized.startswith(".."):
        return False
    return True


def is_zone_zero(path: object) -> bool:
    """True if `path` falls under any zone-0 pattern from S-00 sec 4.

    An unsafe path (see is_safe_relative_path) is always treated as
    zone-0 — fail closed, per docs/S-04-verifier.md sec 1: this verifier
    trusts neither the repository nor the agents, so a path it cannot
    confidently classify as safe must be treated as the most restricted
    case, not the least.
    """
    if not is_safe_relative_path(path):
        return True
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in ZONE_0_PATTERNS)
