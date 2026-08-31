"""V-08 through V-13 from docs/S-04-verifier.md sec 3."""
import fnmatch
import json
from datetime import datetime
from pathlib import Path

from verify.grants import load_grant
from verify.result import CheckResult
from verify.zones import is_zone_zero


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _check_grant_reference_and_window_and_scope(entries: list[dict], grants_dir: Path) -> list[CheckResult]:
    """V-08 (grant exists), V-09 (ts in window), V-10 (max_actions), V-12 (paths in scope), V-13 (no zone 0).

    Any entry or grant shape this function can't safely read (non-dict
    actor/subject/detail, or a grant file missing the fields this check
    needs) is treated as a V-08 failure rather than raising — this
    verifier trusts neither the repository nor the agents (S-04 sec 1),
    so malformed input must produce a clean report, not a crash.
    """
    results = []
    grant_use_counts: dict[str, int] = {}
    for entry in entries:
        actor = entry.get("actor")
        if not isinstance(actor, dict) or actor.get("kind") != "agent":
            continue
        seq = entry.get("seq")
        subject = entry.get("subject")
        grant_ref = subject.get("grant") if isinstance(subject, dict) else None
        if grant_ref is None:
            results.append(CheckResult("V-08", seq, "agent entry has no grant reference"))
            continue
        try:
            grant = load_grant(grants_dir, grant_ref)
        except (TypeError, ValueError, AttributeError) as e:
            results.append(CheckResult("V-08", seq, f"referenced grant {grant_ref} could not be loaded: {e}"))
            continue
        if grant is None:
            results.append(CheckResult("V-08", seq, f"referenced grant {grant_ref} not found"))
            continue

        try:
            grant_use_counts[grant_ref] = grant_use_counts.get(grant_ref, 0) + 1

            ts = entry.get("ts")
            if ts is not None:
                issued, expires, actual = _parse_ts(grant["issued_at"]), _parse_ts(grant["expires_at"]), _parse_ts(ts)
                if not (issued <= actual <= expires):
                    results.append(
                        CheckResult("V-09", seq, f"ts {ts} outside grant window [{grant['issued_at']}, {grant['expires_at']}]")
                    )

            max_actions = grant["scope"]["max_actions"]
            if grant_use_counts[grant_ref] > max_actions:
                results.append(CheckResult("V-10", seq, f"grant {grant_ref} exceeded max_actions={max_actions}"))

            allowed_paths = grant["scope"]["paths"]
            detail = entry.get("detail")
            paths = detail.get("paths", []) if isinstance(detail, dict) else []
            for path in paths:
                if not any(fnmatch.fnmatch(path, pattern) for pattern in allowed_paths):
                    results.append(CheckResult("V-12", seq, f"path '{path}' not covered by grant scope.paths"))
                if is_zone_zero(path):
                    results.append(CheckResult("V-13", seq, f"agent entry touches zone-0 path '{path}'"))
        except (KeyError, TypeError, ValueError, AttributeError) as e:
            results.append(CheckResult("V-08", seq, f"referenced grant {grant_ref} is malformed: {e}"))
    return results


def _check_self_approval(grants_dir: Path) -> list[CheckResult]:
    """V-11: no grant's issued_by.login equals its own requested_by."""
    results = []
    if not grants_dir.exists():
        return results
    for grant_file in sorted(grants_dir.glob("*.json")):
        try:
            grant = json.loads(grant_file.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            # Skip malformed or unreadable grant files; V-08 will catch them when referenced
            continue
        if grant.get("issued_by", {}).get("login") == grant.get("requested_by"):
            results.append(CheckResult("V-11", None, f"grant {grant_file.stem} self-approved by {grant.get('requested_by')}"))
    return results


def run_grant_checks(entries: list[dict], grants_dir: Path) -> list[CheckResult]:
    """Run V-08, V-09, V-10, V-11, V-12, V-13."""
    return [
        *_check_grant_reference_and_window_and_scope(entries, grants_dir),
        *_check_self_approval(grants_dir),
    ]
