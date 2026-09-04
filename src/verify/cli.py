"""Verifier CLI. See docs/S-04-verifier.md sec 2 for the invocation contract.

Usage: verify journal/journal.jsonl [--offline] [--since SEQ] [--json]
                                     --skip-crypto [--grants-dir DIR]

--skip-crypto is required in this build: V-05, V-06, and V-07 (signature,
identity, and Rekor checks) are not implemented yet (Plan 2). Running
without acknowledging that is refused rather than silently treated as a
pass — see the "Scope Note" in the plan that introduced this CLI.
"""
import argparse
import json
import sys
from pathlib import Path

from verify.grant_checks import run_grant_checks
from verify.loader import JournalLoadError, load_journal
from verify.structural_checks import run_structural_checks

_NOT_IMPLEMENTED_CHECKS = ["V-05", "V-06", "V-07"]


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="verify")
    parser.add_argument("journal_path", type=Path)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--since", type=int, default=None)
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--skip-crypto", action="store_true")
    parser.add_argument("--grants-dir", type=Path, default=None)
    return parser.parse_args(argv[1:])


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv
    try:
        args = _parse_args(argv)
    except SystemExit as e:
        # argparse calls sys.exit() on malformed argv (missing arg, unknown
        # flag, -h/--help). main() must always return an int, never raise —
        # Task 9 calls it in-process under pytest and expects a return value.
        return e.code if isinstance(e.code, int) else 2

    if not args.skip_crypto:
        print(
            f"error: {', '.join(_NOT_IMPLEMENTED_CHECKS)} are not implemented in this build (Plan 2). "
            "Pass --skip-crypto to acknowledge this and run the implemented checks only.",
            file=sys.stderr,
        )
        return 2

    grants_dir = args.grants_dir or args.journal_path.parent / "grants"

    try:
        entries = load_journal(args.journal_path, since=args.since)
    except (JournalLoadError, OSError, UnicodeDecodeError) as e:
        # OSError covers FileNotFoundError/IsADirectoryError/PermissionError;
        # UnicodeDecodeError isn't an OSError subclass, listed separately.
        print(f"error: {e}", file=sys.stderr)
        return 2

    failures = [
        *run_structural_checks(entries, is_full_run=args.since is None),
        *run_grant_checks(entries, grants_dir),
    ]
    exit_code = 1 if failures else 0

    if args.as_json:
        report = {
            "exit_code": exit_code,
            "skipped_checks": _NOT_IMPLEMENTED_CHECKS,
            "failures": [
                {"check_id": f.check_id, "seq": f.seq, "message": f.message} for f in failures
            ],
        }
        print(json.dumps(report))
    else:
        if not failures:
            print("OK: all implemented checks passed.")
        print(f"NOTE: {', '.join(_NOT_IMPLEMENTED_CHECKS)} were not run (--skip-crypto).")
        for f in failures:
            print(f"FAIL {f.check_id} (seq={f.seq}): {f.message}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
