"""Unit tests for email address sanitizer."""

from cti_core.processors.email_address_sanitizer import EmailSanitizer


def test_defanged_email_refanging():
    raw = "phisher[at]paypal-security[.]com"
    parsed = EmailSanitizer.parse_email(raw)
    assert parsed is not None
    assert parsed["full_email"] == "phisher@paypal-security.com"
    assert parsed["mailbox"] == "phisher"
    assert parsed["sender_domain"] == "paypal-security.com"


def test_valid_standard_email():
    parsed = EmailSanitizer.parse_email("admin@c2-gate.org")
    assert parsed is not None
    assert parsed["sender_domain"] == "c2-gate.org"


def test_invalid_email():
    assert EmailSanitizer.parse_email("not-an-email") is None
