"""Secret redaction utilities for sanitized normalization, findings, and reports.

Protects against accidental leakage of sensitive credentials, API keys, tokens,
and private keys in static analysis evidence, normalized properties, and scan reports.
"""

from __future__ import annotations

import re
from typing import Any

SENSITIVE_KEY_PATTERNS = [
    re.compile(
        r"(password|secret|api[_-]?key|token|credential|private[_-]?key|auth)", re.IGNORECASE
    ),
]

SECRET_VALUE_PATTERNS = [
    re.compile(
        r"-----BEGIN [A-Z ]+ PRIVATE KEY-----.*?-----END [A-Z ]+ PRIVATE KEY-----", re.DOTALL
    ),
    re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),  # AWS Access Key ID
    re.compile(r"\b(ghp_[0-9a-zA-Z]{36})\b"),  # GitHub PAT
]


def is_sensitive_key(key: str) -> bool:
    """Check if a dictionary key or property name indicates sensitive content."""
    return any(pattern.search(key) for pattern in SENSITIVE_KEY_PATTERNS)


def redact_sensitive_value(value: Any) -> Any:
    """Recursively redact sensitive content from primitives, lists, and dicts."""
    if isinstance(value, str):
        redacted = value
        for pattern in SECRET_VALUE_PATTERNS:
            redacted = pattern.sub("[REDACTED_SECRET]", redacted)
        return redacted
    elif isinstance(value, dict):
        return redact_dict(value)
    elif isinstance(value, list):
        return [redact_sensitive_value(item) for item in value]
    return value


def redact_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively scrub sensitive keys and token values in dictionaries."""
    cleaned: dict[str, Any] = {}
    for k, v in data.items():
        if is_sensitive_key(k):
            cleaned[k] = "[REDACTED]"
        elif isinstance(v, dict):
            cleaned[k] = redact_dict(v)
        elif isinstance(v, list):
            cleaned[k] = [
                redact_dict(item) if isinstance(item, dict) else redact_sensitive_value(item)
                for item in v
            ]
        else:
            cleaned[k] = redact_sensitive_value(v)
    return cleaned


def redact_text(text: str) -> str:
    """Redact embedded credentials and tokens from string text / evidence."""
    if not text:
        return text
    redacted = text
    for pattern in SECRET_VALUE_PATTERNS:
        redacted = pattern.sub("[REDACTED_SECRET]", redacted)
    # Redact key-value pairings e.g. password = "xyz" or secret: '123'
    redacted = re.sub(
        r'((?i:password|secret|api[_-]?key|token|credential|private[_-]?key)\s*[:=]\s*["\']?)([^"\'\s,;]+)(["\']?)',
        r"\1[REDACTED]\3",
        redacted,
    )
    return redacted
