"""Shared result type for all verifier checks. See docs/S-04-verifier.md."""
from dataclasses import dataclass


@dataclass(frozen=True)
class CheckResult:
    """A single failure found by a check. Absence of a CheckResult for a
    given check_id across a run means that check passed."""

    check_id: str
    seq: int | None
    message: str
