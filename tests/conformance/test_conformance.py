import json
import subprocess
import sys
from pathlib import Path

import pytest

from verify.cli import main

CONFORMANCE_DIR = Path(__file__).resolve().parents[2] / "conformance"
GRANTS_DIR = CONFORMANCE_DIR / "grants"
# bad-self-approval.jsonl's grant lives in its own directory (see the comment
# next to SELF_APPROVAL_GRANTS_DIR in generate_fixtures.py): V-11 scans every
# grant file in --grants-dir unconditionally, so keeping it out of the shared
# GRANTS_DIR is what keeps V-11 from also firing on every other fixture.
SELF_APPROVAL_GRANTS_DIR = CONFORMANCE_DIR / "grants-self-approval"

EXPECTED_CHECK_FOR_FIXTURE = {
    "bad-schema.jsonl": "V-01",
    "bad-seq-gap.jsonl": "V-02",
    "bad-plaintext-input.jsonl": "V-03",
    "bad-prev-hash.jsonl": "V-04",
    "bad-missing-grant.jsonl": "V-08",
    "bad-expired-grant.jsonl": "V-09",
    "bad-grant-exhausted.jsonl": "V-10",
    "bad-self-approval.jsonl": "V-11",
    "bad-path-out-of-scope.jsonl": "V-12",
    "bad-zone-zero.jsonl": "V-13",
    "bad-duplicate-key.jsonl": "V-14",
    "bad-genesis.jsonl": "V-15",
    "bad-time-travel.jsonl": "V-16",
}


def _run(fixture_name: str) -> dict:
    grants_dir = SELF_APPROVAL_GRANTS_DIR if fixture_name == "bad-self-approval.jsonl" else GRANTS_DIR
    exit_code = main(["verify", str(CONFORMANCE_DIR / fixture_name), "--skip-crypto", "--json", "--grants-dir", str(grants_dir)])
    return exit_code


def test_good_fixture_passes(capsys):
    exit_code = _run("good.jsonl")
    report = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert report["failures"] == []


@pytest.mark.parametrize("fixture_name,expected_check_id", EXPECTED_CHECK_FOR_FIXTURE.items())
def test_bad_fixture_fails_with_exactly_the_expected_check(fixture_name, expected_check_id, capsys):
    exit_code = _run(fixture_name)
    report = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    check_ids = {f["check_id"] for f in report["failures"]}
    assert check_ids == {expected_check_id}, f"{fixture_name}: expected only {expected_check_id}, got {check_ids}"
