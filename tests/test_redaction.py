from virgent.redaction import find_secrets, redact, redact_mapping

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_" + "a" * 36
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----"


def test_redacts_aws_key():
    text = f"key = {AWS_KEY}"
    out, counts = redact(text)
    assert AWS_KEY not in out
    assert "[REDACTED:aws-access-key]" in out
    assert counts["aws-access-key"] == 1


def test_redacts_github_token_and_private_key():
    text = f"token: {GH_TOKEN}\n{PRIVATE_KEY}"
    out, counts = redact(text)
    assert GH_TOKEN not in out
    assert "MIIEow" not in out
    assert counts["github-token"] == 1
    assert counts["private-key"] == 1


def test_generic_assignment_redacts_value_only():
    text = 'password = "Sup3r-S3cret-Value-91"'
    out, counts = redact(text)
    assert "Sup3r-S3cret-Value-91" not in out
    assert "password" in out  # key survives, value redacted
    assert counts["generic-assignment"] == 1


def test_placeholders_not_redacted():
    for value in ("${DB_PASSWORD}", "<your-password>", "changeme", "xxxxxxxxxx"):
        text = f'password = "{value}"'
        out, counts = redact(text)
        assert counts == {}, value
        assert value in out


def test_find_secrets_reports_line_and_redacted_excerpt():
    text = f"line one\napi_key = \"{AWS_KEY}\"\nline three"
    matches = find_secrets(text)
    assert len(matches) == 1
    m = matches[0]
    assert m.line == 2
    assert AWS_KEY not in m.excerpt
    assert m.kind == "aws-access-key"


def test_redact_mapping_recurses():
    obj = {"a": [f"token {GH_TOKEN}"], "b": {"c": "safe"}}
    out = redact_mapping(obj)
    assert GH_TOKEN not in out["a"][0]
    assert out["b"]["c"] == "safe"
