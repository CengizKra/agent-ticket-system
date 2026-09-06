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
