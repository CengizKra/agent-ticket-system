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
