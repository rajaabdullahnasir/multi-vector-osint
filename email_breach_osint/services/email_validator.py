"""
Email validation for breach checks (SRS-22 input hygiene).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)

_BLOCKED_LOCAL = frozenset({"test", "example", "invalid", "localhost"})
_BLOCKED_DOMAINS = frozenset(
    {"example.com", "example.org", "test.com", "localhost", "invalid"}
)


@dataclass(frozen=True)
class EmailValidationResult:
    ok: bool
    email: str = ""
    error: str | None = None


class EmailValidator:
    def validate(self, raw: str) -> EmailValidationResult:
        candidate = raw.strip().lower()
        if not candidate:
            return EmailValidationResult(ok=False, error="Email address is required.")

        if len(candidate) > 254:
            return EmailValidationResult(ok=False, error="Email address is too long.")

        if " " in candidate or ".." in candidate:
            return EmailValidationResult(ok=False, error="Invalid email format.")

        if not _EMAIL_RE.match(candidate):
            return EmailValidationResult(
                ok=False,
                error="Please enter a valid email address (e.g. user@example.com).",
            )

        local, _, domain = candidate.partition("@")
        if local in _BLOCKED_LOCAL or domain in _BLOCKED_DOMAINS:
            return EmailValidationResult(
                ok=False,
                error="This email domain cannot be checked.",
            )

        return EmailValidationResult(ok=True, email=candidate)
