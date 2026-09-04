import json
from pathlib import Path

from verify.grant_checks import run_grant_checks


def _write_grant(grants_dir: Path, grant_hash_hex: str, **overrides) -> str:
    grants_dir.mkdir(parents=True, exist_ok=True)
    grant = {
        "issued_at": "2026-08-27T10:00:00Z",
        "expires_at": "2026-08-27T14:00:00Z",
        "issued_by": {"login": "cengiz"},
        "requested_by": "alice",
        "scope": {"paths": ["src/verify/**", "tests/**"], "max_actions": 2},
    }
    grant.update(overrides)
    (grants_dir / f"{grant_hash_hex}.json").write_text(json.dumps(grant), encoding="utf-8")
    return "sha256:" + grant_hash_hex


def _agent_entry(seq: int, grant_ref: str | None, ts: str = "2026-08-27T11:00:00Z", paths: list[str] | None = None):
    return {
        "seq": seq, "ts": ts,
        "actor": {"kind": "agent", "id": "coder"},
        "subject": {"grant": grant_ref},
        "detail": {"paths": paths or ["src/verify/checks.py"]},
    }


def test_valid_agent_entry_has_no_failures(tmp_path):
    grants_dir = tmp_path / "grants"
    grant_ref = _write_grant(grants_dir, "a" * 64)
    results = run_grant_checks([_agent_entry(1, grant_ref)], grants_dir)
    assert results == []


def test_v08_reports_missing_grant_reference(tmp_path):
    grants_dir = tmp_path / "grants"
    grants_dir.mkdir()
    results = run_grant_checks([_agent_entry(1, None)], grants_dir)
    assert any(r.check_id == "V-08" and r.seq == 1 for r in results)


def test_v08_reports_grant_file_not_found(tmp_path):
    grants_dir = tmp_path / "grants"
    grants_dir.mkdir()
    results = run_grant_checks([_agent_entry(1, "sha256:" + "b" * 64)], grants_dir)
    assert any(r.check_id == "V-08" and r.seq == 1 for r in results)


def test_v09_reports_ts_outside_grant_window(tmp_path):
    grants_dir = tmp_path / "grants"
    grant_ref = _write_grant(grants_dir, "c" * 64)
    results = run_grant_checks([_agent_entry(1, grant_ref, ts="2026-08-27T20:00:00Z")], grants_dir)
    assert any(r.check_id == "V-09" and r.seq == 1 for r in results)


def test_v10_reports_grant_exhausted(tmp_path):
    grants_dir = tmp_path / "grants"
    grant_ref = _write_grant(grants_dir, "d" * 64, scope={"paths": ["src/**"], "max_actions": 1})
    entries = [_agent_entry(1, grant_ref), _agent_entry(2, grant_ref)]
    results = run_grant_checks(entries, grants_dir)
    assert any(r.check_id == "V-10" and r.seq == 2 for r in results)


def test_v11_reports_self_approval(tmp_path):
    grants_dir = tmp_path / "grants"
    _write_grant(grants_dir, "e" * 64, issued_by={"login": "alice"}, requested_by="alice")
    results = run_grant_checks([], grants_dir)
    assert any(r.check_id == "V-11" for r in results)


def test_v12_reports_path_outside_scope(tmp_path):
    grants_dir = tmp_path / "grants"
    grant_ref = _write_grant(grants_dir, "f" * 64)
    results = run_grant_checks([_agent_entry(1, grant_ref, paths=["docs/S-00-overview.md"])], grants_dir)
    assert any(r.check_id == "V-12" and r.seq == 1 for r in results)


def test_v13_reports_zone_zero_touched_by_agent(tmp_path):
    grants_dir = tmp_path / "grants"
    grant_ref = _write_grant(grants_dir, "0" * 63 + "1", scope={"paths": ["src/sign/**"], "max_actions": 5})
    results = run_grant_checks([_agent_entry(1, grant_ref, paths=["src/sign/keyless.py"])], grants_dir)
    assert any(r.check_id == "V-13" and r.seq == 1 for r in results)


def test_malformed_grant_reports_v08_instead_of_crashing(tmp_path):
    grants_dir = tmp_path / "grants"
    grants_dir.mkdir(parents=True, exist_ok=True)
    (grants_dir / ("6" * 64 + ".json")).write_text(json.dumps({"issued_at": "2026-08-27T10:00:00Z"}), encoding="utf-8")
    results = run_grant_checks([_agent_entry(1, "sha256:" + "6" * 64)], grants_dir)
    assert any(r.check_id == "V-08" and r.seq == 1 for r in results)


def test_non_dict_actor_does_not_crash(tmp_path):
    grants_dir = tmp_path / "grants"
    grants_dir.mkdir()
    entry = {"seq": 1, "ts": "2026-08-27T11:00:00Z", "actor": "agent", "subject": {"grant": None}, "detail": {}}
    results = run_grant_checks([entry], grants_dir)
    assert results == []


def test_non_string_grant_reference_reports_v08_instead_of_crashing(tmp_path):
    grants_dir = tmp_path / "grants"
    grants_dir.mkdir()
    entry = _agent_entry(1, grant_ref=None)
    entry["subject"]["grant"] = 12345  # adversarial: not a string, would crash a bare regex .match()
    results = run_grant_checks([entry], grants_dir)
    assert any(r.check_id == "V-08" and r.seq == 1 for r in results)


def test_corrupt_grant_json_reports_v08_instead_of_crashing(tmp_path):
    grants_dir = tmp_path / "grants"
    grants_dir.mkdir(parents=True, exist_ok=True)
    (grants_dir / ("7" * 64 + ".json")).write_text("{not valid json", encoding="utf-8")
    results = run_grant_checks([_agent_entry(1, "sha256:" + "7" * 64)], grants_dir)
    assert any(r.check_id == "V-08" and r.seq == 1 for r in results)


def test_traversal_path_fails_both_v12_and_v13_despite_matching_grant_scope(tmp_path):
    grants_dir = tmp_path / "grants"
    grant_ref = _write_grant(grants_dir, "8" * 64, scope={"paths": ["src/**"], "max_actions": 5})
    results = run_grant_checks(
        [_agent_entry(1, grant_ref, paths=["src/verify/../sign/keyless.py"])], grants_dir
    )
    check_ids = {r.check_id for r in results if r.seq == 1}
    assert "V-12" in check_ids
    assert "V-13" in check_ids


def test_self_approval_check_does_not_crash_on_non_dict_grant_json(tmp_path):
    grants_dir = tmp_path / "grants"
    grants_dir.mkdir()
    (grants_dir / ("a" * 63 + "9.json")).write_text(json.dumps(["not", "a", "dict"]), encoding="utf-8")
    results = run_grant_checks([], grants_dir)
    assert results == []


def test_self_approval_check_does_not_crash_on_string_issued_by(tmp_path):
    grants_dir = tmp_path / "grants"
    grants_dir.mkdir()
    (grants_dir / ("b" * 63 + "9.json")).write_text(json.dumps({"issued_by": "cengiz", "requested_by": "cengiz"}), encoding="utf-8")
    results = run_grant_checks([], grants_dir)
    assert results == []  # issued_by is a string, not a dict — can't determine login, must not crash or false-positive


def test_self_approval_check_no_false_positive_on_empty_grant(tmp_path):
    grants_dir = tmp_path / "grants"
    grants_dir.mkdir()
    (grants_dir / ("c" * 63 + "9.json")).write_text("{}", encoding="utf-8")
    results = run_grant_checks([], grants_dir)
    assert results == []
