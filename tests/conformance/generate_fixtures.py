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
# V-11 (_check_self_approval) scans every *.json file in its grants_dir
# unconditionally, regardless of whether the journal under test references
# it. Putting the one deliberately self-approved grant in the same shared
# GRANTS_DIR as every other fixture's grants would make V-11 fire on
# every fixture's run, not just bad-self-approval.jsonl's. It gets its
# own directory so it never contaminates the shared one.
SELF_APPROVAL_GRANTS_DIR = CONFORMANCE_DIR / "grants-self-approval"

SIG_PLACEHOLDER = {"alg": "ed25519", "bundle": "cGxhY2Vob2xkZXI=", "rekor_index": 0}

CODER_ACTOR = {"kind": "agent", "id": "coder", "identity": "coder-agent"}


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


def _write_grant(hex_digest: str, *, grants_dir: Path = GRANTS_DIR, **overrides) -> str:
    grants_dir.mkdir(parents=True, exist_ok=True)
    grant = {
        "v": 1, "ticket": "17",
        "issued_at": "2026-08-27T10:30:00Z", "expires_at": "2026-08-27T14:30:00Z",
        "issued_by": {"kind": "human", "login": "cengiz", "environment": "approval", "approval_run_id": 1},
        "requested_by": "alice", "ticket_digest": "sha256:" + "a" * 64,
        "scope": {"agents": ["coder"], "paths": ["src/verify/**", "tests/**"], "zones": [1, 2], "max_actions": 5},
        "sig": SIG_PLACEHOLDER,
    }
    grant.update(overrides)
    (grants_dir / f"{hex_digest}.json").write_text(json.dumps(grant), encoding="utf-8")
    return "sha256:" + hex_digest


def main():
    genesis = _genesis()

    # --- good.jsonl: genesis + one valid agent action, self-consistent ---
    good_grant_ref = _write_grant("1" * 64)
    good_action = _entry(1, entry_hash(genesis), "code.changed",
                          CODER_ACTOR, grant=good_grant_ref,
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
    first_use = _entry(1, entry_hash(genesis), "code.changed", CODER_ACTOR,
                        grant=exhausted_grant_ref, paths=["src/verify/a.py"])
    second_use = _entry(2, entry_hash(first_use), "code.changed", CODER_ACTOR,
                         grant=exhausted_grant_ref, paths=["src/verify/b.py"])
    _write_jsonl("bad-grant-exhausted.jsonl", [genesis, first_use, second_use])

    # --- bad-self-approval.jsonl: grant's issued_by.login equals requested_by (no journal entries needed) ---
    # Isolated in its own grants dir (see SELF_APPROVAL_GRANTS_DIR comment above) so
    # this self-approved grant doesn't make V-11 fire on every other fixture too.
    _write_grant("4" * 64, grants_dir=SELF_APPROVAL_GRANTS_DIR,
                 issued_by={"kind": "human", "login": "cengiz", "environment": "approval", "approval_run_id": 1},
                 requested_by="cengiz")
    _write_jsonl("bad-self-approval.jsonl", [genesis])

    # --- bad-path-out-of-scope.jsonl: entry touches a path not covered by grant.scope.paths ---
    bad_scope = dict(good_action)
    bad_scope["detail"] = {"paths": ["docs/S-05-agents.md"]}
    _write_jsonl("bad-path-out-of-scope.jsonl", [genesis, bad_scope])

    # --- bad-zone-zero.jsonl: agent entry touches a zone-0 path ---
    zone_zero_grant_ref = _write_grant("5" * 64, scope={"agents": ["coder"], "paths": ["src/sign/**"], "zones": [1], "max_actions": 5})
    bad_zone = _entry(1, entry_hash(genesis), "code.changed", CODER_ACTOR,
                       grant=zone_zero_grant_ref, paths=["src/sign/keyless.py"])
    _write_jsonl("bad-zone-zero.jsonl", [genesis, bad_zone])

    # --- bad-duplicate-key.jsonl: two entries share an idempotency_key ---
    dup1 = dict(good_action)
    dup2 = _entry(2, entry_hash(dup1), "code.changed", CODER_ACTOR,
                  grant=good_grant_ref, paths=["src/verify/c.py"], idem=dup1["idempotency_key"])
    _write_jsonl("bad-duplicate-key.jsonl", [genesis, dup1, dup2])

    # --- bad-genesis.jsonl: genesis entry's prev is not the all-zero GENESIS_PREV ---
    # (Mutating actor.kind to "agent" instead would also make the grant checks treat
    # this as an ungranted agent action, firing V-08 alongside V-15. A single-entry
    # journal has no predecessor for V-04 to compare against, so mutating prev here
    # only trips V-15, not V-04.)
    bad_genesis = dict(genesis)
    bad_genesis["prev"] = "sha256:" + "e" * 64
    _write_jsonl("bad-genesis.jsonl", [bad_genesis])

    # --- bad-time-travel.jsonl: second entry's ts precedes genesis's ts ---
    # Uses a human actor (not the coder agent) so the grant checks (which only
    # look at agent-kind entries) don't also fire V-09: an agent entry this
    # early would fall outside the good grant's [issued_at, expires_at) window
    # (10:30-14:30Z) too, tripping V-09 alongside the intended V-16.
    bad_time = dict(good_action)
    bad_time["actor"] = {"kind": "human", "id": "cengiz", "identity": "cengiz"}
    bad_time["subject"] = {"ticket": "17", "grant": None}
    bad_time["ts"] = "2026-08-27T09:00:00Z"  # genesis is 10:00:00Z
    _write_jsonl("bad-time-travel.jsonl", [genesis, bad_time])

    print("Fixtures written to", CONFORMANCE_DIR)


if __name__ == "__main__":
    main()
