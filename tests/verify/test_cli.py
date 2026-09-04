import json
from pathlib import Path

import pytest

from journal.canon import entry_hash, GENESIS_PREV
from verify.cli import main


def _genesis():
    return {
        "v": 1, "seq": 0, "prev": GENESIS_PREV, "ts": "2026-08-27T10:00:00Z",
        "run": {"workflow_run_id": 0, "attempt": 0}, "idempotency_key": "genesis",
        "actor": {"kind": "human", "id": "bootstrap", "identity": "cengiz"},
        "subject": {"ticket": None, "grant": None}, "action": "journal.genesis",
        "inputs": [], "outputs": [], "result": "ok",
        "sig": {"alg": "ed25519", "bundle": "x", "rekor_index": 0},
    }


def _write_journal(tmp_path: Path, entries: list[dict]) -> Path:
    path = tmp_path / "journal.jsonl"
    path.write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")
    return path


def test_without_skip_crypto_flag_exits_2_with_explanation(tmp_path, capsys):
    path = _write_journal(tmp_path, [_genesis()])
    exit_code = main(["verify", str(path)])
    assert exit_code == 2
    stderr = capsys.readouterr().err
    assert "V-05" in stderr
    assert "Plan 2" in stderr


def test_valid_genesis_only_journal_passes_with_skip_crypto(tmp_path, capsys):
    path = _write_journal(tmp_path, [_genesis()])
    exit_code = main(["verify", str(path), "--skip-crypto"])
    assert exit_code == 0


def test_broken_seq_fails_with_exit_1_and_reports_check_id(tmp_path, capsys):
    genesis = _genesis()
    bad = {**genesis, "seq": 5, "prev": entry_hash(genesis)}
    path = _write_journal(tmp_path, [genesis, bad])
    exit_code = main(["verify", str(path), "--skip-crypto"])
    assert exit_code == 1
    assert "V-02" in capsys.readouterr().out


def test_unreadable_journal_exits_2(tmp_path, capsys):
    exit_code = main(["verify", str(tmp_path / "does-not-exist.jsonl"), "--skip-crypto"])
    assert exit_code == 2


def test_json_output_is_valid_json_with_failures_list(tmp_path, capsys):
    genesis = _genesis()
    bad = {**genesis, "seq": 5, "prev": entry_hash(genesis)}
    path = _write_journal(tmp_path, [genesis, bad])
    main(["verify", str(path), "--skip-crypto", "--json"])
    report = json.loads(capsys.readouterr().out)
    assert report["exit_code"] == 1
    assert any(f["check_id"] == "V-02" for f in report["failures"])


def test_malformed_argv_returns_an_int_instead_of_raising_system_exit(capsys):
    # missing the required journal_path argument
    exit_code = main(["verify"])
    assert isinstance(exit_code, int)
    assert exit_code != 0


def test_directory_instead_of_file_exits_2_cleanly(tmp_path, capsys):
    exit_code = main(["verify", str(tmp_path), "--skip-crypto"])
    assert exit_code == 2
    assert "error:" in capsys.readouterr().err


def test_note_about_skipped_checks_appears_even_on_a_failing_run(tmp_path, capsys):
    genesis = _genesis()
    bad = {**genesis, "seq": 5, "prev": entry_hash(genesis)}
    path = _write_journal(tmp_path, [genesis, bad])
    main(["verify", str(path), "--skip-crypto"])
    stdout = capsys.readouterr().out
    assert "NOTE:" in stdout
    assert "V-05" in stdout
