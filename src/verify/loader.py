"""Reads journal/journal.jsonl into a list of dicts. See docs/S-04-verifier.md sec 2."""
import json
from pathlib import Path


class JournalLoadError(Exception):
    pass


def load_journal(path: Path, since: int | None = None) -> list[dict]:
    """Read a JSON Lines journal file into a list of dicts, in file order.

    Blank lines are skipped. If `since` is given, only entries with
    seq >= since are returned (S-04 --since option).
    """
    entries = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, raw_line in enumerate(f, start=1):
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                entries.append(json.loads(raw_line))
            except json.JSONDecodeError as e:
                raise JournalLoadError(f"line {line_no}: invalid JSON ({e})") from e
    if since is not None:
        entries = [e for e in entries if e.get("seq", -1) >= since]
    return entries
