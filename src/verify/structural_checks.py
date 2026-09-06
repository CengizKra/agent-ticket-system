"""V-01, V-02, V-03, V-04, V-14, V-15, V-16 from docs/S-04-verifier.md sec 3."""
from datetime import datetime

import rfc8785

from journal.canon import GENESIS_PREV, entry_hash
from journal.schema import validate_entry
from verify.result import CheckResult


def _parse_ts(ts: str) -> datetime:
    parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"'{ts}' has no timezone offset; S-02 sec 3 requires ts in RFC 3339 UTC")
    return parsed


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
        try:
            expected = entry_hash(prev_entry)
        except (rfc8785.CanonicalizationError, TypeError, ValueError, OverflowError) as e:
            results.append(CheckResult("V-04", entry.get("seq"), f"could not compute hash of predecessor entry: {e}"))
            continue
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
        if not isinstance(key, str):
            continue  # missing/wrong-typed key is already reported by V-01 (schema requires a string)
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
    """V-16: every present ts must be a well-formed, timezone-aware
    timestamp, and non-decreasing across the sequence.

    Tracks the last successfully-parsed timestamp rather than only
    comparing adjacent pairs, so a single malformed ts in the middle of
    the journal cannot break the monotonicity chain around it — that gap
    was how this check used to be silently bypassable.
    """
    results = []
    last_good_ts = None
    last_good_raw = None
    for entry in entries:
        raw_ts = entry.get("ts")
        if raw_ts is None:
            continue  # missing ts is already reported by V-01 (schema requires it)
        try:
            ts = _parse_ts(raw_ts)
        except (ValueError, TypeError, AttributeError):
            results.append(CheckResult("V-16", entry.get("seq"), f"ts '{raw_ts}' is not a valid RFC 3339 UTC timestamp"))
            continue  # don't let a malformed ts anchor the comparison or silently break the chain
        if last_good_ts is not None and ts < last_good_ts:
            results.append(CheckResult("V-16", entry.get("seq"), f"ts {raw_ts} precedes previous valid ts {last_good_raw}"))
        last_good_ts = ts
        last_good_raw = raw_ts
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
