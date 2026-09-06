"""Reads journal/journal.jsonl into a list of dicts. See docs/S-04-verifier.md sec 2."""
import json
from pathlib import Path


class JournalLoadError(Exception):
    pass


def load_journal(path: Path, since: int | None = None) -> list[dict]:
    """Read a JSON Lines journal file into a list of dicts, in file order.

    Blank lines are skipped. If `since` is given, only entries with
    seq >= since are returned (S-04 --since option). Every line must
    decode to a JSON object (dict) — S-02 sec 3 defines a journal entry
    as an object, so anything else is an invalid journal, not a data
    point for the checks below to interpret.
    """
    entries = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, raw_line in enumerate(f, start=1):
            raw_line = raw_line.strip()
            if not raw_line:
                continue

            def _reject_constant(name: str, _line_no: int = line_no) -> None:
                raise JournalLoadError(
                    f"line {_line_no}: disallowed JSON constant '{name}' (NaN/Infinity are not valid per RFC 8785)"
                )

            try:
                obj = json.loads(raw_line, parse_constant=_reject_constant)
            except json.JSONDecodeError as e:
                raise JournalLoadError(f"line {line_no}: invalid JSON ({e})") from e
            if not isinstance(obj, dict):
                raise JournalLoadError(f"line {line_no}: expected a JSON object, got {type(obj).__name__}")
            entries.append(obj)
    if since is not None:
        entries = [e for e in entries if isinstance(e.get("seq"), int) and e.get("seq") >= since]
    return entries
