# Verifier Core Logic Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the journal canonicalization/hashing layer and the verifier's structural and grant checks (V-01–V-04, V-08–V-16 — 13 of the 16 checks in S-04), with a CLI that runs them against `journal/journal.jsonl` and a conformance suite proving each check fails for the right reason and no other.

**Architecture:** `src/journal/` holds canonicalization (RFC 8785 / JCS) and hashing, used by both the verifier and (later) the signer. `src/verify/` holds the verifier: a journal loader, a zone-0 path matcher, a grants-directory loader, two check modules (structural, grant-related), and a CLI that aggregates their results into the exit codes S-04 defines. Cryptographic signature and Rekor verification (V-05, V-06, V-07) are explicitly out of scope for this plan — see "Scope Note" below — and the CLI must refuse to claim full conformance without an explicit `--skip-crypto` acknowledgment.

**Tech Stack:** Python 3.12+, `pytest`, `jsonschema` (Draft 2020-12), `rfc8785` (pure-Python RFC 8785 JCS implementation, no transitive dependencies).

**Spec:** `docs/S-04-verifier.md` (check list and CLI contract), `docs/S-02-schema.md` (journal entry and grant format, canonicalization rules), `docs/S-00-overview.md` (zone model), `docs/S-01-threat-model.md` (T-03, T-04, T-06, T-07, T-09, T-14 — what several of these checks defend against).

## Scope Note — Read Before Starting

S-04 defines 16 checks (V-01–V-16). Three of them — V-05 (signature verifies against certificate), V-06 (certificate identity matches `actor.identity`), V-07 (Rekor entry exists) — require a real Sigstore-signed artifact, which cannot be produced by an automated coding agent; it needs an interactive OAuth login that only a human can perform (same bootstrapping problem as the genesis entry in S-00 §3). That integration is Plan 2, tracked separately, not part of this plan.

This plan's verifier therefore implements 13 of the 16 checks for real, and treats V-05/V-06/V-07 as **not yet implemented** — not as silently passing. Concretely: the CLI requires a `--skip-crypto` flag to run at all; without it, it exits immediately with an error telling the caller those three checks aren't implemented yet and pointing at Plan 2. This is a deliberate, temporary, loudly-visible limitation, not a shortcut — a verifier that quietly reported "all checks passed" while skipping three security-critical checks would violate the project's own rule in `CLAUDE.md`: "Don't dress up security claims."

**Grant storage.** S-02 defines the *shape* of a grant but not where a grant's full JSON lives on disk — only that journal entries reference it by `grant_hash`. This plan introduces the convention `journal/grants/<hex-digest>.json`, one file per grant, named by its `grant_hash` with the `sha256:` prefix stripped. `journal/**` is zone 0 (see the S-00 correction below), so this directory inherits the same human-only-write rule as the journal file itself.

**Zone-0 path list.** S-00 §4's table is the source of truth for which paths are zone 0. This plan's `src/verify/zones.py` hardcodes that same list as Python glob patterns; it is not itself the source of truth. If S-00 §4 ever changes, `zones.py` must change with it in the same pull request — the conformance suite's `bad-zone-zero.jsonl` fixture (Task 9) will fail if the two drift apart in a way that matters.

## Global Constraints

- Python 3.12+, `pytest` for all tests.
- JCS canonicalization only via the `rfc8785` package — never hand-rolled key sorting (`CLAUDE.md`, "Never build canonicalization yourself").
- All hashes are `sha256:` followed by lowercase hex, per S-02 §2.
- `entry_hash` and `grant_hash` are computed over JCS bytes **excluding** the `sig` field, per S-02 §2.
- The action vocabulary (`journal.genesis`, `ticket.received`, …) is the closed list in S-02 §5 — do not invent new action names in test fixtures.
- Check IDs V-01 through V-16 and their meanings are fixed by S-04 §3 — do not rename or renumber them.
- A failure report must always name the sequence number (or `null` if not entry-scoped, e.g. a grant-only check), the check ID, and expected vs. actual value (S-04 §2).
- This plan does not implement V-05, V-06, or V-07 — see Scope Note above. Do not add stub logic that makes them silently "pass".

---

## Task 1: JCS Canonicalization and Hashing

**Files:**
- Create: `pyproject.toml`
- Create: `src/journal/__init__.py`
- Create: `src/journal/canon.py`
- Test: `tests/journal/test_canon.py`

**Interfaces:**
- Produces: `canonicalize(obj: dict) -> bytes`, `sha256_hex(data: bytes) -> str`, `content_digest(data: bytes) -> str`, `entry_hash(entry: dict) -> str`, `grant_hash(grant: dict) -> str`, `GENESIS_PREV: str`. All of `src/verify/**` (Tasks 3–9) import these from `journal.canon`.

- [ ] **Step 1: Create the project scaffolding**

```toml
# pyproject.toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "agentic-governance-workflow"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "jsonschema>=4.23",
    "rfc8785>=0.0.1",
]

[project.optional-dependencies]
dev = ["pytest>=8.0"]

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
pythonpath = ["src"]
```

- [ ] **Step 2: Install dependencies**

Run: `pip install -e ".[dev]"`
Expected: installs `jsonschema`, `rfc8785`, `pytest` without errors.

- [ ] **Step 3: Write the failing test**

```python
# tests/journal/test_canon.py
from journal.canon import canonicalize, sha256_hex, content_digest, entry_hash, grant_hash, GENESIS_PREV


def test_canonicalize_sorts_keys_and_strips_whitespace():
    assert canonicalize({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_canonicalize_is_deterministic_regardless_of_input_order():
    assert canonicalize({"z": 1, "a": {"y": 2, "x": 3}}) == canonicalize({"a": {"x": 3, "y": 2}, "z": 1})


def test_sha256_hex_has_expected_prefix_and_length():
    digest = sha256_hex(b"hello")
    assert digest.startswith("sha256:")
    assert len(digest) == len("sha256:") + 64
    assert digest == "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_content_digest_matches_sha256_hex():
    assert content_digest(b"issue text") == sha256_hex(b"issue text")


def test_entry_hash_excludes_sig_field():
    entry_with_sig = {"seq": 1, "action": "code.changed", "sig": {"alg": "ed25519", "bundle": "x", "rekor_index": 1}}
    entry_without_sig = {"seq": 1, "action": "code.changed"}
    assert entry_hash(entry_with_sig) == entry_hash(entry_without_sig)


def test_entry_hash_changes_when_a_non_sig_field_changes():
    a = {"seq": 1, "action": "code.changed"}
    b = {"seq": 2, "action": "code.changed"}
    assert entry_hash(a) != entry_hash(b)


def test_grant_hash_excludes_sig_field():
    grant_with_sig = {"ticket": "17", "sig": {"alg": "ed25519", "bundle": "x", "rekor_index": 1}}
    grant_without_sig = {"ticket": "17"}
    assert grant_hash(grant_with_sig) == grant_hash(grant_without_sig)


def test_genesis_prev_is_64_zero_hex_chars_with_prefix():
    assert GENESIS_PREV == "sha256:" + "0" * 64
```

- [ ] **Step 4: Run test to verify it fails**

Run: `pytest tests/journal/test_canon.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'journal'` (or `journal.canon`).

- [ ] **Step 5: Write minimal implementation**

```python
# src/journal/__init__.py
```

```python
# src/journal/canon.py
"""RFC 8785 (JCS) canonicalization and hashing for journal entries and grants.

See docs/S-02-schema.md sections 1-2 for the rules this implements.
"""
import hashlib

import rfc8785

GENESIS_PREV = "sha256:" + "0" * 64


def canonicalize(obj: dict) -> bytes:
    """Return the JCS (RFC 8785) canonical byte representation of a JSON-compatible dict."""
    return rfc8785.dumps(obj)


def sha256_hex(data: bytes) -> str:
    """Return a SHA-256 digest formatted as 'sha256:<64 lowercase hex chars>'."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def content_digest(data: bytes) -> str:
    """SHA-256 over raw bytes (issue text, a diff, a file). S-02 sec 2."""
    return sha256_hex(data)


def entry_hash(entry: dict) -> str:
    """SHA-256 over the JCS bytes of a journal entry WITHOUT its 'sig' field. S-02 sec 2."""
    stripped = {k: v for k, v in entry.items() if k != "sig"}
    return sha256_hex(canonicalize(stripped))


def grant_hash(grant: dict) -> str:
    """SHA-256 over the JCS bytes of a grant WITHOUT its 'sig' field. S-02 sec 2."""
    stripped = {k: v for k, v in grant.items() if k != "sig"}
    return sha256_hex(canonicalize(stripped))
```

- [ ] **Step 6: Run test to verify it passes**

Run: `pytest tests/journal/test_canon.py -v`
Expected: 8 passed.

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml src/journal/__init__.py src/journal/canon.py tests/journal/test_canon.py
git commit -m "feat: add JCS canonicalization and hashing helpers"
```

---

## Task 2: Schema Validation Wrapper

**Files:**
- Create: `src/journal/schema.py`
- Test: `tests/journal/test_schema.py`

**Interfaces:**
- Consumes: `schemas/journal-entry.schema.json`, `schemas/grant.schema.json` (already exist, unchanged).
- Produces: `validate_entry(entry: dict) -> list[tuple[str, str]]`, `validate_grant(grant: dict) -> list[tuple[str, str]]`. Each tuple is `(json_path, message)`, e.g. `("inputs/0", "'not-a-hash' does not match '^sha256:[0-9a-f]{64}$'")`. An empty list means valid. Task 6 imports both functions.

- [ ] **Step 1: Write the failing test**

```python
# tests/journal/test_schema.py
from journal.schema import validate_entry, validate_grant

VALID_ENTRY = {
    "v": 1,
    "seq": 0,
    "prev": "sha256:" + "0" * 64,
    "ts": "2026-08-27T10:00:00Z",
    "run": {"workflow_run_id": 1, "attempt": 1},
    "idempotency_key": "genesis",
    "actor": {"kind": "human", "id": "bootstrap", "identity": "cengiz"},
    "subject": {"ticket": None, "grant": None},
    "action": "journal.genesis",
    "inputs": [],
    "outputs": [],
    "result": "ok",
    "sig": {"alg": "ed25519", "bundle": "cGxhY2Vob2xkZXI=", "rekor_index": 0},
}

VALID_GRANT = {
    "v": 1,
    "ticket": "17",
    "issued_at": "2026-08-27T10:00:00Z",
    "expires_at": "2026-08-27T14:00:00Z",
    "issued_by": {"kind": "human", "login": "cengiz", "environment": "approval", "approval_run_id": 1},
    "requested_by": "some-other-user",
    "ticket_digest": "sha256:" + "a" * 64,
    "scope": {"agents": ["coder"], "paths": ["src/**"], "zones": [1, 2], "max_actions": 20},
    "sig": {"alg": "ed25519", "bundle": "cGxhY2Vob2xkZXI=", "rekor_index": 0},
}


def test_valid_entry_has_no_errors():
    assert validate_entry(VALID_ENTRY) == []


def test_entry_with_plaintext_input_is_rejected_at_the_inputs_path():
    bad = {**VALID_ENTRY, "inputs": ["not-a-hash"]}
    errors = validate_entry(bad)
    assert len(errors) == 1
    path, message = errors[0]
    assert path == "inputs/0"


def test_entry_missing_required_field_is_rejected():
    bad = {k: v for k, v in VALID_ENTRY.items() if k != "action"}
    errors = validate_entry(bad)
    assert any("action" in message for _, message in errors)


def test_valid_grant_has_no_errors():
    assert validate_grant(VALID_GRANT) == []


def test_grant_with_zone_zero_is_rejected():
    bad = {**VALID_GRANT, "scope": {**VALID_GRANT["scope"], "zones": [0]}}
    errors = validate_grant(bad)
    assert len(errors) == 1
    assert errors[0][0] == "scope/zones/0"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/journal/test_schema.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'journal.schema'`.

- [ ] **Step 3: Write minimal implementation**

```python
# src/journal/schema.py
"""JSON Schema validation for journal entries and grants. See docs/S-02-schema.md."""
import json
from pathlib import Path

from jsonschema import Draft202012Validator

_SCHEMAS_DIR = Path(__file__).resolve().parents[2] / "schemas"


def _load_validator(filename: str) -> Draft202012Validator:
    schema = json.loads((_SCHEMAS_DIR / filename).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


_ENTRY_VALIDATOR = _load_validator("journal-entry.schema.json")
_GRANT_VALIDATOR = _load_validator("grant.schema.json")


def _errors(validator: Draft202012Validator, instance: dict) -> list[tuple[str, str]]:
    return [
        ("/".join(str(p) for p in error.path), error.message)
        for error in validator.iter_errors(instance)
    ]


def validate_entry(entry: dict) -> list[tuple[str, str]]:
    """Validate a journal entry against schemas/journal-entry.schema.json.

    Returns a list of (json_path, message) tuples; empty means valid.
    """
    return _errors(_ENTRY_VALIDATOR, entry)


def validate_grant(grant: dict) -> list[tuple[str, str]]:
    """Validate a grant against schemas/grant.schema.json.

    Returns a list of (json_path, message) tuples; empty means valid.
    """
    return _errors(_GRANT_VALIDATOR, grant)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/journal/test_schema.py -v`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add src/journal/schema.py tests/journal/test_schema.py
git commit -m "feat: add JSON Schema validation wrapper for entries and grants"
```

---

## Task 3: Journal Loader and Shared Check Result Type

**Files:**
- Create: `src/verify/__init__.py`
- Create: `src/verify/result.py`
- Create: `src/verify/loader.py`
- Test: `tests/verify/test_loader.py`

**Interfaces:**
- Produces: `CheckResult` dataclass (`check_id: str`, `seq: int | None`, `message: str`) in `verify.result`. `load_journal(path: Path, since: int | None = None) -> list[dict]` in `verify.loader` — raises `JournalLoadError` (also defined here) on unparseable JSON lines, naming the line number. Tasks 6, 7, 8 import both.

- [ ] **Step 1: Write the failing test**

```python
# tests/verify/test_loader.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/verify/test_loader.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'verify'`.

- [ ] **Step 3: Write minimal implementation**

```python
# src/verify/__init__.py
```

```python
# src/verify/result.py
"""Shared result type for all verifier checks. See docs/S-04-verifier.md."""
from dataclasses import dataclass


@dataclass(frozen=True)
class CheckResult:
    """A single failure found by a check. Absence of a CheckResult for a
    given check_id across a run means that check passed."""

    check_id: str
    seq: int | None
    message: str
```

```python
# src/verify/loader.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/verify/test_loader.py -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/verify/__init__.py src/verify/result.py src/verify/loader.py tests/verify/test_loader.py
git commit -m "feat: add journal loader and shared check result type"
```

---

## Task 4: Zone-0 Path Matching

**Files:**
- Create: `src/verify/zones.py`
- Test: `tests/verify/test_zones.py`

**Interfaces:**
- Produces: `is_zone_zero(path: str) -> bool` in `verify.zones`. Task 7 (V-13) imports this.

- [ ] **Step 1: Write the failing test**

```python
# tests/verify/test_zones.py
from verify.zones import is_zone_zero


def test_github_workflows_is_zone_zero():
    assert is_zone_zero(".github/workflows/govern.yml") is True


def test_github_codeowners_is_zone_zero():
    assert is_zone_zero(".github/CODEOWNERS") is True


def test_sign_source_is_zone_zero():
    assert is_zone_zero("src/sign/keyless.py") is True


def test_conformance_fixtures_are_zone_zero():
    assert is_zone_zero("conformance/bad-schema.jsonl") is True


def test_schemas_are_zone_zero():
    assert is_zone_zero("schemas/grant.schema.json") is True


def test_journal_is_zone_zero():
    assert is_zone_zero("journal/journal.jsonl") is True
    assert is_zone_zero("journal/grants/abcd1234.json") is True


def test_overview_and_threat_model_and_schema_doc_are_zone_zero():
    assert is_zone_zero("docs/S-00-overview.md") is True
    assert is_zone_zero("docs/S-01-threat-model.md") is True
    assert is_zone_zero("docs/S-02-schema.md") is True


def test_verifier_source_is_not_zone_zero():
    assert is_zone_zero("src/verify/cli.py") is False


def test_tests_directory_is_not_zone_zero():
    assert is_zone_zero("tests/verify/test_zones.py") is False


def test_zone_2_doc_is_not_zone_zero():
    assert is_zone_zero("docs/S-05-agents.md") is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/verify/test_zones.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'verify.zones'`.

- [ ] **Step 3: Write minimal implementation**

```python
# src/verify/zones.py
"""Zone-0 path matching. Mirrors docs/S-00-overview.md sec 4's table exactly.

If that table changes, this list must change with it in the same PR —
see the "Zone-0 path list" note in the plan that introduced this file.
"""
import fnmatch

ZONE_0_PATTERNS = [
    ".github/**",
    "src/sign/**",
    "conformance/**",
    "docs/S-00-overview.md",
    "docs/S-01-threat-model.md",
    "docs/S-02-schema.md",
    "schemas/**",
    "journal/**",
]


def is_zone_zero(path: str) -> bool:
    """True if `path` falls under any zone-0 pattern from S-00 sec 4."""
    return any(fnmatch.fnmatch(path, pattern) for pattern in ZONE_0_PATTERNS)
```

**Note on `fnmatch` and `**`:** Python's `fnmatch` treats `**` the same as `*` (it has no special "match across directory separators" behavior) — but since `fnmatch.fnmatch` matches the whole string, not path segments, a single `*` already matches across `/` here, so `.github/**` correctly matches `.github/workflows/govern.yml`. This is verified by Step 4.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/verify/test_zones.py -v`
Expected: 10 passed.

- [ ] **Step 5: Commit**

```bash
git add src/verify/zones.py tests/verify/test_zones.py
git commit -m "feat: add zone-0 path matcher mirroring S-00 sec 4"
```

---

## Task 5: Grants Directory Loader

**Files:**
- Create: `src/verify/grants.py`
- Test: `tests/verify/test_grants.py`

**Interfaces:**
- Produces: `load_grant(grants_dir: Path, grant_ref: str) -> dict | None` in `verify.grants`. Returns `None` if `grant_ref` isn't a well-formed `sha256:` hash or the file doesn't exist. Tasks 7 and 8 import this.

- [ ] **Step 1: Write the failing test**

```python
# tests/verify/test_grants.py
import json
from pathlib import Path

from verify.grants import load_grant

GRANT = {"ticket": "17", "requested_by": "alice"}


def test_loads_grant_by_hash(tmp_path):
    grants_dir = tmp_path / "grants"
    grants_dir.mkdir()
    (grants_dir / ("b" * 64 + ".json")).write_text(json.dumps(GRANT), encoding="utf-8")
    assert load_grant(grants_dir, "sha256:" + "b" * 64) == GRANT


def test_returns_none_when_file_missing(tmp_path):
    grants_dir = tmp_path / "grants"
    grants_dir.mkdir()
    assert load_grant(grants_dir, "sha256:" + "c" * 64) is None


def test_returns_none_for_malformed_reference(tmp_path):
    grants_dir = tmp_path / "grants"
    grants_dir.mkdir()
    assert load_grant(grants_dir, "not-a-hash") is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/verify/test_grants.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'verify.grants'`.

- [ ] **Step 3: Write minimal implementation**

```python
# src/verify/grants.py
"""Loads grant JSON files from journal/grants/<hex-digest>.json.

See the "Grant storage" note in the plan that introduced this convention
(docs/S-02-schema.md defines the grant's shape, not its storage path).
"""
import json
import re
from pathlib import Path

_SHA256_REF = re.compile(r"^sha256:([0-9a-f]{64})$")


def load_grant(grants_dir: Path, grant_ref: str) -> dict | None:
    """Load the grant referenced by `grant_ref` (e.g. 'sha256:41ab...').

    Returns None if the reference is malformed or no such file exists.
    """
    match = _SHA256_REF.match(grant_ref)
    if match is None:
        return None
    path = grants_dir / f"{match.group(1)}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/verify/test_grants.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/verify/grants.py tests/verify/test_grants.py
git commit -m "feat: add grants directory loader"
```

---

## Task 6: Structural Checks (V-01, V-02, V-03, V-04, V-14, V-15, V-16)

**Files:**
- Create: `src/verify/structural_checks.py`
- Test: `tests/verify/test_structural_checks.py`

**Interfaces:**
- Consumes: `journal.canon.entry_hash`, `journal.canon.GENESIS_PREV`, `journal.schema.validate_entry`, `verify.result.CheckResult`.
- Produces: `run_structural_checks(entries: list[dict], *, is_full_run: bool) -> list[CheckResult]` in `verify.structural_checks`. `is_full_run` is `True` when `--since` was not passed (i.e. entry 0 is expected to be the genesis entry); Task 8 (CLI) passes this through. Task 9 imports this function.

- [ ] **Step 1: Write the failing test**

```python
# tests/verify/test_structural_checks.py
from journal.canon import entry_hash, GENESIS_PREV
from verify.structural_checks import run_structural_checks


def _genesis():
    return {
        "v": 1, "seq": 0, "prev": GENESIS_PREV, "ts": "2026-08-27T10:00:00Z",
        "run": {"workflow_run_id": 0, "attempt": 0}, "idempotency_key": "genesis",
        "actor": {"kind": "human", "id": "bootstrap", "identity": "cengiz"},
        "subject": {"ticket": None, "grant": None}, "action": "journal.genesis",
        "inputs": [], "outputs": [], "result": "ok",
        "sig": {"alg": "ed25519", "bundle": "x", "rekor_index": 0},
    }


def _next(prev_entry: dict, **overrides) -> dict:
    entry = {
        "v": 1, "seq": prev_entry["seq"] + 1, "prev": entry_hash(prev_entry),
        "ts": "2026-08-27T11:00:00Z", "run": {"workflow_run_id": 1, "attempt": 1},
        "idempotency_key": f"17:{prev_entry['seq'] + 1}",
        "actor": {"kind": "job", "id": "signer", "identity": "signer-job"},
        "subject": {"ticket": "17", "grant": None}, "action": "ticket.received",
        "inputs": [], "outputs": [], "result": "ok",
        "sig": {"alg": "ed25519", "bundle": "x", "rekor_index": 1},
    }
    entry.update(overrides)
    return entry


def test_valid_two_entry_chain_has_no_failures():
    genesis = _genesis()
    second = _next(genesis)
    results = run_structural_checks([genesis, second], is_full_run=True)
    assert results == []


def test_v01_reports_generic_schema_violation():
    genesis = _genesis()
    bad = _next(genesis)
    del bad["action"]
    results = run_structural_checks([genesis, bad], is_full_run=True)
    assert any(r.check_id == "V-01" and r.seq == 1 for r in results)


def test_v03_reports_plaintext_input_separately_from_v01():
    genesis = _genesis()
    bad = _next(genesis, inputs=["not-a-hash"])
    results = run_structural_checks([genesis, bad], is_full_run=True)
    assert any(r.check_id == "V-03" and r.seq == 1 for r in results)
    assert not any(r.check_id == "V-01" and r.seq == 1 for r in results)


def test_v02_reports_seq_gap():
    genesis = _genesis()
    bad = _next(genesis, seq=2, idempotency_key="17:2")
    results = run_structural_checks([genesis, bad], is_full_run=True)
    assert any(r.check_id == "V-02" for r in results)


def test_v04_reports_prev_hash_mismatch():
    genesis = _genesis()
    bad = _next(genesis, prev="sha256:" + "f" * 64)
    results = run_structural_checks([genesis, bad], is_full_run=True)
    assert any(r.check_id == "V-04" and r.seq == 1 for r in results)


def test_v14_reports_duplicate_idempotency_key():
    genesis = _genesis()
    second = _next(genesis)
    third = _next(second, idempotency_key=second["idempotency_key"])
    results = run_structural_checks([genesis, second, third], is_full_run=True)
    assert any(r.check_id == "V-14" and r.seq == 2 for r in results)


def test_v15_reports_genesis_not_seq_zero():
    genesis = _genesis()
    genesis["seq"] = 1
    results = run_structural_checks([genesis], is_full_run=True)
    assert any(r.check_id == "V-15" for r in results)


def test_v15_is_skipped_when_not_a_full_run():
    non_genesis_first = _next(_genesis())  # seq=1, doesn't look like genesis, and that's fine mid-journal
    results = run_structural_checks([non_genesis_first], is_full_run=False)
    assert not any(r.check_id == "V-15" for r in results)


def test_v16_reports_timestamp_going_backwards():
    genesis = _genesis()
    bad = _next(genesis, ts="2026-08-27T09:00:00Z")  # before genesis's 10:00:00Z
    results = run_structural_checks([genesis, bad], is_full_run=True)
    assert any(r.check_id == "V-16" and r.seq == 1 for r in results)


def test_non_string_ts_does_not_crash_the_run():
    genesis = _genesis()
    bad = _next(genesis, ts=12345)  # adversarial/malformed: not a string
    results = run_structural_checks([genesis, bad], is_full_run=True)
    assert any(r.check_id == "V-01" and r.seq == 1 for r in results)  # schema check still flags it


def test_non_dict_actor_in_genesis_does_not_crash_and_reports_v15():
    genesis = _genesis()
    genesis["actor"] = "human"  # adversarial/malformed: not a dict
    results = run_structural_checks([genesis], is_full_run=True)
    assert any(r.check_id == "V-15" for r in results)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/verify/test_structural_checks.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'verify.structural_checks'`.

- [ ] **Step 3: Write minimal implementation**

```python
# src/verify/structural_checks.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/verify/test_structural_checks.py -v`
Expected: 11 passed.

- [ ] **Step 5: Commit**

```bash
git add src/verify/structural_checks.py tests/verify/test_structural_checks.py
git commit -m "feat: add structural checks V-01, V-02, V-03, V-04, V-14, V-15, V-16"
```

---

## Task 7: Grant Checks (V-08, V-09, V-10, V-11, V-12, V-13)

**Files:**
- Create: `src/verify/grant_checks.py`
- Test: `tests/verify/test_grant_checks.py`

**Interfaces:**
- Consumes: `verify.grants.load_grant`, `verify.zones.is_zone_zero`, `verify.result.CheckResult`.
- Produces: `run_grant_checks(entries: list[dict], grants_dir: Path) -> list[CheckResult]` in `verify.grant_checks`. Task 8 imports this and passes the same `grants_dir` it was invoked with.

- [ ] **Step 1: Write the failing test**

```python
# tests/verify/test_grant_checks.py
import json
from pathlib import Path

from verify.grant_checks import run_grant_checks


def _write_grant(grants_dir: Path, grant_hash_hex: str, **overrides) -> str:
    grants_dir.mkdir(parents=True, exist_ok=True)
    grant = {
        "issued_at": "2026-08-27T10:00:00Z",
        "expires_at": "2026-08-27T14:00:00Z",
        "issued_by": {"login": "cengiz"},
        "requested_by": "alice",
        "scope": {"paths": ["src/verify/**", "tests/**"], "max_actions": 2},
    }
    grant.update(overrides)
    (grants_dir / f"{grant_hash_hex}.json").write_text(json.dumps(grant), encoding="utf-8")
    return "sha256:" + grant_hash_hex


def _agent_entry(seq: int, grant_ref: str | None, ts: str = "2026-08-27T11:00:00Z", paths: list[str] | None = None):
    return {
        "seq": seq, "ts": ts,
        "actor": {"kind": "agent", "id": "coder"},
        "subject": {"grant": grant_ref},
        "detail": {"paths": paths or ["src/verify/checks.py"]},
    }


def test_valid_agent_entry_has_no_failures(tmp_path):
    grants_dir = tmp_path / "grants"
    grant_ref = _write_grant(grants_dir, "a" * 64)
    results = run_grant_checks([_agent_entry(1, grant_ref)], grants_dir)
    assert results == []


def test_v08_reports_missing_grant_reference(tmp_path):
    grants_dir = tmp_path / "grants"
    grants_dir.mkdir()
    results = run_grant_checks([_agent_entry(1, None)], grants_dir)
    assert any(r.check_id == "V-08" and r.seq == 1 for r in results)


def test_v08_reports_grant_file_not_found(tmp_path):
    grants_dir = tmp_path / "grants"
    grants_dir.mkdir()
    results = run_grant_checks([_agent_entry(1, "sha256:" + "b" * 64)], grants_dir)
    assert any(r.check_id == "V-08" and r.seq == 1 for r in results)


def test_v09_reports_ts_outside_grant_window(tmp_path):
    grants_dir = tmp_path / "grants"
    grant_ref = _write_grant(grants_dir, "c" * 64)
    results = run_grant_checks([_agent_entry(1, grant_ref, ts="2026-08-27T20:00:00Z")], grants_dir)
    assert any(r.check_id == "V-09" and r.seq == 1 for r in results)


def test_v10_reports_grant_exhausted(tmp_path):
    grants_dir = tmp_path / "grants"
    grant_ref = _write_grant(grants_dir, "d" * 64, scope={"paths": ["src/**"], "max_actions": 1})
    entries = [_agent_entry(1, grant_ref), _agent_entry(2, grant_ref)]
    results = run_grant_checks(entries, grants_dir)
    assert any(r.check_id == "V-10" and r.seq == 2 for r in results)


def test_v11_reports_self_approval(tmp_path):
    grants_dir = tmp_path / "grants"
    _write_grant(grants_dir, "e" * 64, issued_by={"login": "alice"}, requested_by="alice")
    results = run_grant_checks([], grants_dir)
    assert any(r.check_id == "V-11" for r in results)


def test_v12_reports_path_outside_scope(tmp_path):
    grants_dir = tmp_path / "grants"
    grant_ref = _write_grant(grants_dir, "f" * 64)
    results = run_grant_checks([_agent_entry(1, grant_ref, paths=["docs/S-00-overview.md"])], grants_dir)
    assert any(r.check_id == "V-12" and r.seq == 1 for r in results)


def test_v13_reports_zone_zero_touched_by_agent(tmp_path):
    grants_dir = tmp_path / "grants"
    grant_ref = _write_grant(grants_dir, "0" * 63 + "1", scope={"paths": ["src/sign/**"], "max_actions": 5})
    results = run_grant_checks([_agent_entry(1, grant_ref, paths=["src/sign/keyless.py"])], grants_dir)
    assert any(r.check_id == "V-13" and r.seq == 1 for r in results)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/verify/test_grant_checks.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'verify.grant_checks'`.

- [ ] **Step 3: Write minimal implementation**

```python
# src/verify/grant_checks.py
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
    """V-08 (grant exists), V-09 (ts in window), V-10 (max_actions), V-12 (paths in scope), V-13 (no zone 0)."""
    results = []
    grant_use_counts: dict[str, int] = {}
    for entry in entries:
        if entry.get("actor", {}).get("kind") != "agent":
            continue
        seq = entry.get("seq")
        grant_ref = entry.get("subject", {}).get("grant")
        if grant_ref is None:
            results.append(CheckResult("V-08", seq, "agent entry has no grant reference"))
            continue
        grant = load_grant(grants_dir, grant_ref)
        if grant is None:
            results.append(CheckResult("V-08", seq, f"referenced grant {grant_ref} not found"))
            continue

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
        for path in entry.get("detail", {}).get("paths", []):
            if not any(fnmatch.fnmatch(path, pattern) for pattern in allowed_paths):
                results.append(CheckResult("V-12", seq, f"path '{path}' not covered by grant scope.paths"))
            if is_zone_zero(path):
                results.append(CheckResult("V-13", seq, f"agent entry touches zone-0 path '{path}'"))
    return results


def _check_self_approval(grants_dir: Path) -> list[CheckResult]:
    """V-11: no grant's issued_by.login equals its own requested_by."""
    results = []
    if not grants_dir.exists():
        return results
    for grant_file in sorted(grants_dir.glob("*.json")):
        grant = json.loads(grant_file.read_text(encoding="utf-8"))
        if grant.get("issued_by", {}).get("login") == grant.get("requested_by"):
            results.append(CheckResult("V-11", None, f"grant {grant_file.stem} self-approved by {grant.get('requested_by')}"))
    return results


def run_grant_checks(entries: list[dict], grants_dir: Path) -> list[CheckResult]:
    """Run V-08, V-09, V-10, V-11, V-12, V-13."""
    return [
        *_check_grant_reference_and_window_and_scope(entries, grants_dir),
        *_check_self_approval(grants_dir),
    ]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/verify/test_grant_checks.py -v`
Expected: 8 passed.

- [ ] **Step 5: Commit**

```bash
git add src/verify/grant_checks.py tests/verify/test_grant_checks.py
git commit -m "feat: add grant checks V-08 through V-13"
```

---

## Task 8: Verifier CLI

**Files:**
- Create: `src/verify/cli.py`
- Test: `tests/verify/test_cli.py`
- Modify: `pyproject.toml` (add console script entry point)

**Interfaces:**
- Consumes: `verify.loader.load_journal`, `verify.structural_checks.run_structural_checks`, `verify.grant_checks.run_grant_checks`.
- Produces: `main(argv: list[str] | None = None) -> int` in `verify.cli` (returns the process exit code; a thin `if __name__ == "__main__"` wrapper calls `sys.exit(main())`). Task 9's conformance test runner invokes `main()` directly rather than shelling out, so it can run in-process under pytest.

- [ ] **Step 1: Write the failing test**

```python
# tests/verify/test_cli.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/verify/test_cli.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'verify.cli'`.

- [ ] **Step 3: Write minimal implementation**

```python
# src/verify/cli.py
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
    args = _parse_args(argv)

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
    except (JournalLoadError, FileNotFoundError) as e:
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
```

- [ ] **Step 4: Add the console script entry point**

```toml
# pyproject.toml — add this section
[project.scripts]
verify = "verify.cli:main"
```

Run: `pip install -e ".[dev]"`
Expected: reinstalls cleanly, `verify` command becomes available on PATH (not required for tests, which call `main()` directly, but needed for manual/CI invocation per S-04 sec 2).

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/verify/test_cli.py -v`
Expected: 5 passed.

- [ ] **Step 6: Commit**

```bash
git add src/verify/cli.py pyproject.toml tests/verify/test_cli.py
git commit -m "feat: add verifier CLI with --skip-crypto acknowledgment for deferred checks"
```

---

## Task 9: Conformance Suite

**Files:**
- Create: `tests/conformance/generate_fixtures.py`
- Create: `conformance/good.jsonl`, `conformance/grants/*.json` (generated)
- Create: `conformance/bad-schema.jsonl`, `bad-seq-gap.jsonl`, `bad-plaintext-input.jsonl`, `bad-prev-hash.jsonl`, `bad-missing-grant.jsonl`, `bad-expired-grant.jsonl`, `bad-grant-exhausted.jsonl`, `bad-self-approval.jsonl`, `bad-path-out-of-scope.jsonl`, `bad-zone-zero.jsonl`, `bad-duplicate-key.jsonl`, `bad-genesis.jsonl`, `bad-time-travel.jsonl` (generated)
- Test: `tests/conformance/test_conformance.py`

**Interfaces:**
- Consumes: `verify.cli.main`, `journal.canon.entry_hash`.
- Produces: nothing further consumes this — it is the acceptance test for the whole plan.

This task generates fixtures with a script rather than hand-typed JSON because each entry's `prev` is a real SHA-256 hash of its predecessor — computing that by hand is impractical and error-prone. The generator builds a valid chain first, then applies exactly one deliberate mutation per bad fixture, recomputing downstream hashes so that **only** the targeted check fails — matching S-04 §4's requirement that a fixture "must name the matching check ID" and no other.

- [ ] **Step 1: Write the failing test**

```python
# tests/conformance/test_conformance.py
import json
import subprocess
import sys
from pathlib import Path

import pytest

from verify.cli import main

CONFORMANCE_DIR = Path(__file__).resolve().parents[2] / "conformance"
GRANTS_DIR = CONFORMANCE_DIR / "grants"

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
    exit_code = main(["verify", str(CONFORMANCE_DIR / fixture_name), "--skip-crypto", "--json", "--grants-dir", str(GRANTS_DIR)])
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/conformance/test_conformance.py -v`
Expected: FAIL — `good.jsonl` and the `bad-*.jsonl` files don't exist yet (`FileNotFoundError` surfaced as exit code 2, which fails the `assert exit_code == 0`/`== 1` assertions).

- [ ] **Step 3: Write the fixture generator**

```python
# tests/conformance/generate_fixtures.py
"""Generates conformance/*.jsonl and conformance/grants/*.json.

Run this once (`python tests/conformance/generate_fixtures.py`) whenever
the fixtures need regenerating. conformance/ is zone 0 (docs/S-00-overview.md
sec 4) — regenerating and committing these files is a human action, same
as everything else in that zone.
"""
import json
from pathlib import Path

from journal.canon import GENESIS_PREV, entry_hash

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFORMANCE_DIR = REPO_ROOT / "conformance"
GRANTS_DIR = CONFORMANCE_DIR / "grants"

SIG_PLACEHOLDER = {"alg": "ed25519", "bundle": "cGxhY2Vob2xkZXI=", "rekor_index": 0}


def _entry(seq, prev, action, actor, grant=None, ts="2026-08-27T11:00:00Z", paths=None, idem=None):
    return {
        "v": 1, "seq": seq, "prev": prev, "ts": ts,
        "run": {"workflow_run_id": seq, "attempt": 1},
        "idempotency_key": idem or f"17:{seq}",
        "actor": actor, "subject": {"ticket": "17", "grant": grant}, "action": action,
        "inputs": [], "outputs": [],
        "result": "ok", "detail": ({"paths": paths} if paths else {}),
        "sig": SIG_PLACEHOLDER,
    }


def _genesis():
    return {
        "v": 1, "seq": 0, "prev": GENESIS_PREV, "ts": "2026-08-27T10:00:00Z",
        "run": {"workflow_run_id": 0, "attempt": 0}, "idempotency_key": "genesis",
        "actor": {"kind": "human", "id": "bootstrap", "identity": "cengiz"},
        "subject": {"ticket": None, "grant": None}, "action": "journal.genesis",
        "inputs": [], "outputs": [], "result": "ok", "sig": SIG_PLACEHOLDER,
    }


def _write_jsonl(name: str, entries: list[dict]):
    (CONFORMANCE_DIR / name).write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")


def _write_grant(hex_digest: str, **overrides) -> str:
    GRANTS_DIR.mkdir(parents=True, exist_ok=True)
    grant = {
        "v": 1, "ticket": "17",
        "issued_at": "2026-08-27T10:30:00Z", "expires_at": "2026-08-27T14:30:00Z",
        "issued_by": {"kind": "human", "login": "cengiz", "environment": "approval", "approval_run_id": 1},
        "requested_by": "alice", "ticket_digest": "sha256:" + "a" * 64,
        "scope": {"agents": ["coder"], "paths": ["src/verify/**", "tests/**"], "zones": [1, 2], "max_actions": 5},
        "sig": SIG_PLACEHOLDER,
    }
    grant.update(overrides)
    (GRANTS_DIR / f"{hex_digest}.json").write_text(json.dumps(grant), encoding="utf-8")
    return "sha256:" + hex_digest


def main():
    genesis = _genesis()

    # --- good.jsonl: genesis + one valid agent action, self-consistent ---
    good_grant_ref = _write_grant("1" * 64)
    good_action = _entry(1, entry_hash(genesis), "code.changed",
                          {"kind": "agent", "id": "coder"}, grant=good_grant_ref,
                          paths=["src/verify/checks.py"])
    _write_jsonl("good.jsonl", [genesis, good_action])

    # --- bad-schema.jsonl: second entry missing required field 'action' ---
    bad_schema = dict(good_action)
    del bad_schema["action"]
    _write_jsonl("bad-schema.jsonl", [genesis, bad_schema])

    # --- bad-seq-gap.jsonl: second entry jumps to seq 2 (hash chain otherwise consistent) ---
    bad_seq = dict(good_action)
    bad_seq["seq"] = 2
    bad_seq["idempotency_key"] = "17:2"
    _write_jsonl("bad-seq-gap.jsonl", [genesis, bad_seq])

    # --- bad-plaintext-input.jsonl: inputs contains free text instead of a hash ---
    bad_plaintext = dict(good_action)
    bad_plaintext["inputs"] = ["not-a-hash"]
    _write_jsonl("bad-plaintext-input.jsonl", [genesis, bad_plaintext])

    # --- bad-prev-hash.jsonl: prev doesn't match entry_hash(genesis) ---
    bad_prev = dict(good_action)
    bad_prev["prev"] = "sha256:" + "f" * 64
    _write_jsonl("bad-prev-hash.jsonl", [genesis, bad_prev])

    # --- bad-missing-grant.jsonl: grant reference points at a grant that doesn't exist ---
    bad_missing_grant = dict(good_action)
    bad_missing_grant["subject"] = {"ticket": "17", "grant": "sha256:" + "9" * 64}
    _write_jsonl("bad-missing-grant.jsonl", [genesis, bad_missing_grant])

    # --- bad-expired-grant.jsonl: entry ts is after the grant's expires_at ---
    expired_grant_ref = _write_grant("2" * 64, expires_at="2026-08-27T10:45:00Z")
    bad_expired = dict(good_action)
    bad_expired["subject"] = {"ticket": "17", "grant": expired_grant_ref}
    bad_expired["ts"] = "2026-08-27T20:00:00Z"
    _write_jsonl("bad-expired-grant.jsonl", [genesis, bad_expired])

    # --- bad-grant-exhausted.jsonl: two agent entries against a max_actions=1 grant ---
    exhausted_grant_ref = _write_grant("3" * 64, scope={"agents": ["coder"], "paths": ["src/verify/**"], "zones": [1], "max_actions": 1})
    first_use = _entry(1, entry_hash(genesis), "code.changed", {"kind": "agent", "id": "coder"},
                        grant=exhausted_grant_ref, paths=["src/verify/a.py"])
    second_use = _entry(2, entry_hash(first_use), "code.changed", {"kind": "agent", "id": "coder"},
                         grant=exhausted_grant_ref, paths=["src/verify/b.py"])
    _write_jsonl("bad-grant-exhausted.jsonl", [genesis, first_use, second_use])

    # --- bad-self-approval.jsonl: grant's issued_by.login equals requested_by (no journal entries needed) ---
    _write_grant("4" * 64, issued_by={"kind": "human", "login": "cengiz", "environment": "approval", "approval_run_id": 1},
                 requested_by="cengiz")
    _write_jsonl("bad-self-approval.jsonl", [genesis])

    # --- bad-path-out-of-scope.jsonl: entry touches a path not covered by grant.scope.paths ---
    bad_scope = dict(good_action)
    bad_scope["detail"] = {"paths": ["docs/S-05-agents.md"]}
    _write_jsonl("bad-path-out-of-scope.jsonl", [genesis, bad_scope])

    # --- bad-zone-zero.jsonl: agent entry touches a zone-0 path ---
    zone_zero_grant_ref = _write_grant("5" * 64, scope={"agents": ["coder"], "paths": ["src/sign/**"], "zones": [1], "max_actions": 5})
    bad_zone = _entry(1, entry_hash(genesis), "code.changed", {"kind": "agent", "id": "coder"},
                       grant=zone_zero_grant_ref, paths=["src/sign/keyless.py"])
    _write_jsonl("bad-zone-zero.jsonl", [genesis, bad_zone])

    # --- bad-duplicate-key.jsonl: two entries share an idempotency_key ---
    dup1 = dict(good_action)
    dup2 = _entry(2, entry_hash(dup1), "code.changed", {"kind": "agent", "id": "coder"},
                  grant=good_grant_ref, paths=["src/verify/c.py"], idem=dup1["idempotency_key"])
    _write_jsonl("bad-duplicate-key.jsonl", [genesis, dup1, dup2])

    # --- bad-genesis.jsonl: first entry has actor.kind agent instead of human ---
    bad_genesis = dict(genesis)
    bad_genesis["actor"] = {"kind": "agent", "id": "coder", "identity": "x"}
    _write_jsonl("bad-genesis.jsonl", [bad_genesis])

    # --- bad-time-travel.jsonl: second entry's ts precedes genesis's ts ---
    bad_time = dict(good_action)
    bad_time["ts"] = "2026-08-27T09:00:00Z"  # genesis is 10:00:00Z
    _write_jsonl("bad-time-travel.jsonl", [genesis, bad_time])

    print("Fixtures written to", CONFORMANCE_DIR)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run the generator**

Run: `python tests/conformance/generate_fixtures.py`
Expected: prints `Fixtures written to .../conformance`, creates `conformance/good.jsonl`, 13 `bad-*.jsonl` files, and `conformance/grants/*.json`.

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/conformance/test_conformance.py -v`
Expected: 14 passed (1 good + 13 bad fixtures).

- [ ] **Step 6: Run the full test suite to confirm nothing regressed**

Run: `pytest -v`
Expected: all tests across Tasks 1–9 pass (68 tests total: 8 + 5 + 4 + 10 + 3 + 11 + 8 + 5 + 14 — recount after Step 5 if any test was added/removed during implementation).

- [ ] **Step 7: Commit**

```bash
git add tests/conformance/ conformance/
git commit -m "feat: add conformance suite for V-01–V-04 and V-08–V-16"
```

---

## Plan Self-Review Notes

- **Spec coverage:** S-04 §3's 16 checks — 13 implemented and conformance-tested (V-01–V-04, V-08–V-16), 3 explicitly deferred with a loud CLI guard rather than silently skipped (V-05–V-07, Scope Note). S-00's zone-0 list is now consistent between `CLAUDE.md` and `S-00-overview.md` (fixed as a prerequisite to this plan, not part of it). S-02's grant storage gap is resolved by the `journal/grants/<hash>.json` convention, stated explicitly rather than left implicit.
- **Not in this plan:** `src/sign/` (the signer job), `src/ticket/` (GitHub Issues adapter), the GitHub Actions workflow itself, and Plan 2 (real Sigstore signature/Rekor verification). Each needs its own plan.
- **Known follow-up:** once Plan 2 lands, Task 8's `--skip-crypto` requirement and the `_NOT_IMPLEMENTED_CHECKS` list in `verify/cli.py` should be removed, and V-05/V-06/V-07 conformance fixtures (`bad-signature.jsonl`, `bad-identity-claim.jsonl`, `bad-rekor-index.jsonl`) added to Task 9's suite.
- **Gap found, deliberately not fixed here:** S-04 §3's 16 checks validate journal entries against `journal-entry.schema.json`, but none of them validate a loaded grant against `grant.schema.json` — `run_grant_checks` in Task 7 reads `issued_at`, `expires_at`, `issued_by`, `requested_by`, and `scope` directly, trusting their shape. A malformed grant file (e.g. `max_actions` as a string) would raise an uncaught exception rather than a clean check failure. Adding a check for this means adding a new check ID, which is a Zone 2 change to S-04 but still a spec change beyond this plan's agreed scope (13 named checks) — flagging it for a deliberate decision rather than silently patching it in.
