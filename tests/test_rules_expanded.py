"""Coverage for the expanded rules engines and the sensitivity registry."""
from virgent.access import Sensitivity, sensitivity_for
from virgent.capabilities.iac import check_terraform
from virgent.models import Severity
from virgent.redaction import redact


def test_new_secret_patterns_redacted():
    # samples are assembled from fragments at runtime so no complete synthetic
    # token literal sits in the source (keeps push-protection scanners happy)
    samples = {
        "sendgrid-key": "S" + "G." + "a" * 22 + "." + "b" * 43,
        "npm-token": "npm" + "_" + "c" * 36,
        "slack-webhook": "".join(["https://hooks.slack.com", "/services/",
                                  "T" + "0" * 8, "/B" + "0" * 8, "/" + "X" * 24]),
        "digitalocean-token": "dop" + "_v1_" + "d" * 64,
        "twilio-key": "S" + "K" + "0" * 32,
    }
    for kind, secret in samples.items():
        out, counts = redact(f"token = {secret}")
        assert secret not in out, kind
        assert kind in counts, kind


def test_terraform_rules():
    tf = '''
resource "aws_security_group" "web" {
  ingress { cidr_blocks = ["0.0.0.0/0"] }
}
resource "aws_s3_bucket" "data" {
  acl = "public-read"
  password = "hardc0ded-Secret-Value"
}
'''
    rules = {i["rule"] for i in check_terraform(tf)}
    assert "tf-open-ingress" in rules
    assert "tf-public-bucket" in rules
    assert "tf-hardcoded-secret" in rules
    assert "tf-unencrypted-storage" in rules


def test_terraform_ignores_variables():
    tf = 'resource "x" "y" { password = "${var.db_password}" }'
    assert not any(i["rule"] == "tf-hardcoded-secret" for i in check_terraform(tf))


def test_sensitivity_registry_longest_prefix():
    assert sensitivity_for("scan.secrets") == Sensitivity.OBSERVE
    assert sensitivity_for("collect.web") == Sensitivity.ENRICH
    assert sensitivity_for("pentest.run") == Sensitivity.ACTIVE
    assert sensitivity_for("respond.block_ip") == Sensitivity.RESPOND
    assert sensitivity_for("respond.isolate_host") == Sensitivity.DESTRUCTIVE
    assert sensitivity_for("llm.complete") == Sensitivity.ENRICH


def test_default_policy_has_full_access_block():
    from virgent.policy import DEFAULT_POLICY
    access = DEFAULT_POLICY["access"]
    assert access["roles"] == ["agent", "analyst", "responder", "admin"]
    assert set(access["autonomy"]) == {"observe", "enrich", "active", "respond", "destructive"}
    assert access["min_role"]["destructive"] == "admin"
