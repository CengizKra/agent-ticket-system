"""V-01, V-02, V-03, V-04, V-14, V-15, V-16 from docs/S-04-verifier.md sec 3."""
from datetime import datetime

from journal.canon import GENESIS_PREV, entry_hash
from journal.schema import validate_entry
from verify.result import CheckResult


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _check_schema(entries: list[dict]) -> list[CheckResult]:
    """V-01 (generic) and V-03 (inputs/outputs must be hash-only)."""
    results = []
    for entry in entries:
        for path, message in validate_entry(entry):
            check_id = "V-03" if path.startswith("inputs") or path.startswith("outputs") else "V-01"
            results.append(CheckResult(check_id, entry.get("seq"), f"{path}: {message}"))
    return results


def _check_seq(entries: list[dict]) -> list[CheckResult]:
    """V-02: seq is gapless and strictly ascending."""
    results = []
    for prev_entry, entry in zip(entries, entries[1:]):
        prev_seq, seq = prev_entry.get("seq"), entry.get("seq")
        if not isinstance(prev_seq, int) or not isinstance(seq, int):
            continue
        if seq != prev_seq + 1:
            results.append(CheckResult("V-02", seq, f"expected seq {prev_seq + 1}, got {seq}"))
    return results


def _check_prev_hash(entries: list[dict]) -> list[CheckResult]:
    """V-04: each entry's prev matches entry_hash of its predecessor."""
    results = []
    for prev_entry, entry in zip(entries, entries[1:]):
        expected = entry_hash(prev_entry)
        actual = entry.get("prev")
        if actual != expected:
            results.append(CheckResult("V-04", entry.get("seq"), f"expected prev {expected}, got {actual}"))
    return results


def _check_idempotency_unique(entries: list[dict]) -> list[CheckResult]:
    """V-14: idempotency_key occurs at most once."""
    seen: dict[str, int | None] = {}
    results = []
    for entry in entries:
        key = entry.get("idempotency_key")
        if key in seen:
            results.append(
                CheckResult("V-14", entry.get("seq"), f"duplicate idempotency_key '{key}' (first at seq {seen[key]})")
            )
        else:
            seen[key] = entry.get("seq")
    return results


def _check_genesis(entries: list[dict]) -> list[CheckResult]:
    """V-15: the first entry of a full run is a valid genesis entry."""
    if not entries:
        return []
    genesis = entries[0]
    results = []
    if genesis.get("seq") != 0:
        results.append(CheckResult("V-15", genesis.get("seq"), "genesis entry must have seq 0"))
    if genesis.get("prev") != GENESIS_PREV:
        results.append(CheckResult("V-15", genesis.get("seq"), "genesis entry must have prev of 64 zeros"))
    actor = genesis.get("actor")
    if not isinstance(actor, dict) or actor.get("kind") != "human":
        results.append(CheckResult("V-15", genesis.get("seq"), "genesis entry actor.kind must be 'human'"))
    return results


def _check_ts_monotonic(entries: list[dict]) -> list[CheckResult]:
    """V-16: ts is non-decreasing across the sequence."""
    results = []
    for prev_entry, entry in zip(entries, entries[1:]):
        try:
            prev_ts, ts = _parse_ts(prev_entry["ts"]), _parse_ts(entry["ts"])
        except (KeyError, ValueError, TypeError, AttributeError):
            continue  # malformed or wrong-typed ts is already reported by V-01
        if ts < prev_ts:
            results.append(CheckResult("V-16", entry.get("seq"), f"ts {entry['ts']} precedes previous ts {prev_entry['ts']}"))
    return results


def run_structural_checks(entries: list[dict], *, is_full_run: bool) -> list[CheckResult]:
    """Run V-01, V-02, V-03, V-04, V-14, V-16 always; V-15 only on a full run
    (i.e. when --since was not used and entries[0] is expected to be genesis).
    """
    results = [
        *_check_schema(entries),
        *_check_seq(entries),
        *_check_prev_hash(entries),
        *_check_idempotency_unique(entries),
        *_check_ts_monotonic(entries),
    ]
    if is_full_run:
        results.extend(_check_genesis(entries))
    return results
