"""Loads grant JSON files from journal/grants/<hex-digest>.json.

See the "Grant storage" note in the plan that introduced this convention
(docs/S-02-schema.md defines the grant's shape, not its storage path).
"""
import json
import re
from pathlib import Path

_SHA256_REF = re.compile(r"^sha256:([0-9a-f]{64})$")


def load_grant(grants_dir: Path, grant_ref: str) -> dict | None:
    """Load the grant referenced by `grant_ref` (e.g. 'sha256:41ab...').

    Returns None if the reference is malformed or no such file exists.
    """
    match = _SHA256_REF.match(grant_ref)
    if match is None:
        return None
    path = grants_dir / f"{match.group(1)}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))
