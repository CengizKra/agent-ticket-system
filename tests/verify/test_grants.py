import json
from pathlib import Path

from verify.grants import load_grant

GRANT = {"ticket": "17", "requested_by": "alice"}


def test_loads_grant_by_hash(tmp_path):
    grants_dir = tmp_path / "grants"
    grants_dir.mkdir()
    (grants_dir / ("b" * 64 + ".json")).write_text(json.dumps(GRANT), encoding="utf-8")
    assert load_grant(grants_dir, "sha256:" + "b" * 64) == GRANT


def test_returns_none_when_file_missing(tmp_path):
    grants_dir = tmp_path / "grants"
    grants_dir.mkdir()
    assert load_grant(grants_dir, "sha256:" + "c" * 64) is None


def test_returns_none_for_malformed_reference(tmp_path):
    grants_dir = tmp_path / "grants"
    grants_dir.mkdir()
    assert load_grant(grants_dir, "not-a-hash") is None
