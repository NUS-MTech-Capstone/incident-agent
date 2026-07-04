from __future__ import annotations

import re

_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)(api[_-]?key\s*[=:]\s*)[^\s]+"),
    re.compile(r"(?i)(password\s*[=:]\s*)[^\s]+"),
    re.compile(r"(?i)(secret\s*[=:]\s*)[^\s]+"),
]
_WHOLE_SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
]


def text(value: str, max_bytes: int) -> str:
    redacted = value or ""
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(r"\1[REDACTED]", redacted)
    for pattern in _WHOLE_SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    encoded = redacted.encode("utf-8")
    if max_bytes > 0 and len(encoded) > max_bytes:
        return encoded[:max_bytes].decode("utf-8", errors="ignore") + "\n[TRUNCATED]"
    return redacted
