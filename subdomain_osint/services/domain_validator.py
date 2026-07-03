"""
Domain name validation for subdomain scans (SRS-14).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

DOMAIN_REGEX = (
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)
DOMAIN_HTML_PATTERN = (
    r"([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}"
)

_DOMAIN_RE = re.compile(DOMAIN_REGEX)

_BLOCKED_EXACT = frozenset({"localhost", "localhost.localdomain"})
_BLOCKED_TLDS = frozenset({"local", "test", "invalid", "internal"})


@dataclass(frozen=True)
class DomainValidationResult:
    ok: bool
    domain: str = ""
    error: str | None = None


class DomainValidator:
    def validate(self, raw: str) -> DomainValidationResult:
        candidate = raw.strip().lower()
        if candidate.startswith(("http://", "https://")):
            return DomainValidationResult(
                ok=False,
                error="Enter a domain only (e.g. example.com), not a full URL.",
            )
        if "/" in candidate or "?" in candidate:
            return DomainValidationResult(ok=False, error="Invalid domain format.")

        candidate = candidate.rstrip(".")
        if candidate.startswith("www."):
            candidate = candidate[4:]

        if not candidate:
            return DomainValidationResult(ok=False, error="Domain name is required.")

        if len(candidate) > 253:
            return DomainValidationResult(ok=False, error="Domain name is too long.")

        if not _DOMAIN_RE.match(candidate):
            return DomainValidationResult(
                ok=False,
                error="Please enter a valid domain name (e.g. example.com).",
            )

        if candidate in _BLOCKED_EXACT:
            return DomainValidationResult(ok=False, error="This domain cannot be queried.")

        tld = candidate.rsplit(".", 1)[-1]
        if tld in _BLOCKED_TLDS:
            return DomainValidationResult(ok=False, error="This TLD cannot be queried.")

        return DomainValidationResult(ok=True, domain=candidate)
