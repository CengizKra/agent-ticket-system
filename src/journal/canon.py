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
