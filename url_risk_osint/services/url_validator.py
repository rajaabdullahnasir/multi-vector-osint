"""
URL validation for risk analysis (SRS-28).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

_BLOCKED_HOSTS = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
    }
)
_BLOCKED_SCHEMES = frozenset({"javascript", "data", "file", "vbscript"})


@dataclass(frozen=True)
class UrlValidationResult:
    ok: bool
    url: str = ""
    error: str | None = None


class UrlValidator:
    def validate(self, raw: str) -> UrlValidationResult:
        candidate = (raw or "").strip()
        if not candidate:
            return UrlValidationResult(ok=False, error="URL is required.")
        if len(candidate) > 2048:
            return UrlValidationResult(ok=False, error="URL is too long (max 2048 characters).")

        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", candidate):
            candidate = f"https://{candidate}"

        parsed = urlparse(candidate)
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            return UrlValidationResult(
                ok=False,
                error="Only http:// and https:// URLs are supported.",
            )
        if scheme in _BLOCKED_SCHEMES:
            return UrlValidationResult(ok=False, error="This URL scheme is not allowed.")

        host = (parsed.hostname or "").lower()
        if not host:
            return UrlValidationResult(ok=False, error="URL must include a valid host.")

        if host in _BLOCKED_HOSTS or host.endswith(".localhost"):
            return UrlValidationResult(ok=False, error="Local or loopback URLs cannot be analyzed.")

        if self._is_private_or_reserved(host):
            return UrlValidationResult(ok=False, error="Private or reserved IP addresses are not allowed.")

        if "@" in parsed.netloc:
            return UrlValidationResult(
                ok=False,
                error="URLs with embedded credentials (@) are not accepted for analysis.",
            )

        normalized = urlunparse(
            (
                scheme,
                parsed.netloc.lower(),
                parsed.path or "/",
                parsed.params,
                parsed.query,
                "",
            )
        )
        return UrlValidationResult(ok=True, url=normalized)

    def _is_private_or_reserved(self, host: str) -> bool:
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return False
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local
