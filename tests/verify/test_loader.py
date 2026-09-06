import pytest
from pathlib import Path

from verify.loader import load_journal, JournalLoadError


def _write(tmp_path: Path, lines: list[str]) -> Path:
    p = tmp_path / "journal.jsonl"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def test_loads_each_line_as_a_dict(tmp_path):
    path = _write(tmp_path, ['{"seq": 0}', '{"seq": 1}'])
    entries = load_journal(path)
    assert entries == [{"seq": 0}, {"seq": 1}]


def test_skips_blank_lines(tmp_path):
    path = _write(tmp_path, ['{"seq": 0}', '', '{"seq": 1}'])
    entries = load_journal(path)
    assert entries == [{"seq": 0}, {"seq": 1}]


def test_since_filters_by_seq(tmp_path):
    path = _write(tmp_path, ['{"seq": 0}', '{"seq": 1}', '{"seq": 2}'])
    entries = load_journal(path, since=1)
    assert entries == [{"seq": 1}, {"seq": 2}]


def test_raises_with_line_number_on_invalid_json(tmp_path):
    path = _write(tmp_path, ['{"seq": 0}', 'not json'])
    with pytest.raises(JournalLoadError, match="line 2"):
        load_journal(path)


def test_non_dict_line_raises_journal_load_error(tmp_path):
    path = _write(tmp_path, ['{"seq": 0}', '"just a string"'])
    with pytest.raises(JournalLoadError, match="line 2"):
        load_journal(path)


def test_json_array_line_raises_journal_load_error(tmp_path):
    path = _write(tmp_path, ['{"seq": 0}', '[1, 2, 3]'])
    with pytest.raises(JournalLoadError, match="line 2"):
        load_journal(path)


def test_nan_constant_raises_journal_load_error(tmp_path):
    path = _write(tmp_path, ['{"seq": 0, "detail": {"x": NaN}}'])
    with pytest.raises(JournalLoadError, match="disallowed JSON constant"):
        load_journal(path)


def test_since_with_non_int_seq_does_not_crash(tmp_path):
    path = _write(tmp_path, ['{"seq": "not-an-int"}', '{"seq": 5}'])
    entries = load_journal(path, since=1)
    assert entries == [{"seq": 5}]
