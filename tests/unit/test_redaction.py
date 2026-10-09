"""Unit tests for secret redaction module."""

from app.core.redaction import (
    is_sensitive_key,
    redact_dict,
    redact_sensitive_value,
    redact_text,
)


def test_is_sensitive_key():
    assert is_sensitive_key("password")
    assert is_sensitive_key("db_password")
    assert is_sensitive_key("api_key")
    assert is_sensitive_key("client_secret")
    assert is_sensitive_key("auth_token")
    assert is_sensitive_key("private_key")
    assert not is_sensitive_key("bucket_name")
    assert not is_sensitive_key("cidr_block")


def test_redact_dict_scrubs_sensitive_keys():
    data = {
        "bucket": "my-bucket",
        "admin_password": "super-secret-password-123",
        "nested": {
            "api_key": "abc-xyz-token",
            "safe_param": "safe_value",
        },
        "list_items": [
            {"token": "token-123"},
            {"name": "resource-1"},
        ],
    }
    scrubbed = redact_dict(data)
    assert scrubbed["bucket"] == "my-bucket"
    assert scrubbed["admin_password"] == "[REDACTED]"
    assert scrubbed["nested"]["api_key"] == "[REDACTED]"
    assert scrubbed["nested"]["safe_param"] == "safe_value"
    assert scrubbed["list_items"][0]["token"] == "[REDACTED]"
    assert scrubbed["list_items"][1]["name"] == "resource-1"


def test_redact_text_matches_credentials():
    evidence = "Resource has password = 'PlaintextPass123' configured in plaintext"
    sanitized = redact_text(evidence)
    assert "PlaintextPass123" not in sanitized
    assert (
        "password = '[REDACTED]'" in sanitized
        or "password='[REDACTED]'" in sanitized
        or "[REDACTED]" in sanitized
    )


def test_redact_aws_key_and_private_keys():
    text = "Key: AKIAIOSFODNN7EXAMPLE was detected"
    sanitized = redact_text(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
    assert "[REDACTED_SECRET]" in sanitized

    pk_text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
    pk_sanitized = redact_sensitive_value(pk_text)
    assert "MIIEowIBAAKCAQEA" not in pk_sanitized
    assert "[REDACTED_SECRET]" in pk_sanitized
