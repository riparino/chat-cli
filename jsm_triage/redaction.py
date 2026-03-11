"""Sensitive text redaction before external model calls."""

import re

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def redact_text(value: str) -> str:
    value = _EMAIL_RE.sub("[REDACTED_EMAIL]", value or "")
    value = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_ID]", value)
    return value
