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
