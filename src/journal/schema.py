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
