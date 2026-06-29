from attest.loader import load_from_file
from attest.matcher import enforce


def test_ssn_blocked():
    policy = load_from_file("policies/pii_redaction.yaml")
    decision = enforce(policy, "give me john's info", "His SSN is 123-45-6789.")
    assert decision.verdict == "block"
    assert decision.matched_rule_id == "block_ssn"


def test_email_redacted():
    policy = load_from_file("policies/pii_redaction.yaml")
    decision = enforce(policy, "contact info?", "Email me at jane@example.com please.")
    assert decision.verdict == "transform"
    assert "[email redacted]" in decision.output
    assert "jane@example.com" not in decision.output


def test_clean_output_allowed():
    policy = load_from_file("policies/pii_redaction.yaml")
    decision = enforce(policy, "hello", "hi there")
    assert decision.verdict == "allow"
    assert decision.matched_rule_id is None


def test_long_output_blocked():
    policy = load_from_file("policies/pii_redaction.yaml")
    long_output = "x" * 5000
    decision = enforce(policy, "hi", long_output)
    assert decision.verdict == "block"
    assert decision.matched_rule_id == "block_long_output"


def test_determinism():
    policy = load_from_file("policies/pii_redaction.yaml")
    a = enforce(policy, "hi", "Email me at foo@bar.com")
    b = enforce(policy, "hi", "Email me at foo@bar.com")
    assert a == b