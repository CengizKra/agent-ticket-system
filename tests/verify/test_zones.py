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
