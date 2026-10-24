"""Best-effort secret redaction utilities for logs and messages."""

import re

# Regex patterns targeting common secret formats in logs and config
_SECRET_PATTERNS = [
    # Bearer tokens and JWTs
    re.compile(r"(Bearer\s+)[A-Za-z0-9_\-\.=]+", re.IGNORECASE),
    # Key-value secret assignments: password=..., token: ..., secret=..., etc.
    re.compile(
        r"(\b(?:password|passwd|pwd|secret|token|api_key|apikey|access_key|auth_token)\s*[:=]\s*['\"]?)([^\s'\",;&]+)(['\"]?)",
        re.IGNORECASE,
    ),
    # Common API key prefixes: sk-..., gh[pousr]-..., etc.
    re.compile(r"\b(sk-[a-zA-Z0-9]{20,})\b"),
    re.compile(r"\b(gh[pousr]-[A-Za-z0-9_]{36,})\b"),
    # AWS Access Key ID
    re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    # Generic Private Key header
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
]


def redact_secrets(text: str) -> str:
    """Best-effort redaction of credentials and secrets from text.

    Note: This is heuristic and best-effort. Users must not submit unredacted
    secrets in incident files.
    """
    if not text:
        return text

    sanitized = text
    for pattern in _SECRET_PATTERNS:
        # Check if pattern has capturing groups for prefix preservation
        if pattern.groups == 1 and pattern.pattern.startswith("(Bearer"):
            sanitized = pattern.sub(r"\1[REDACTED]", sanitized)
        elif pattern.groups == 3:
            sanitized = pattern.sub(r"\1[REDACTED]\3", sanitized)
        else:
            sanitized = pattern.sub("[REDACTED]", sanitized)

    return sanitized
