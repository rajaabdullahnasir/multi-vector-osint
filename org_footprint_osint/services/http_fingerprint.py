"""
Passive HTTP fingerprint — reads response headers only (server banner,
framework hints, and presence of standard security headers). Never inspects
authenticated areas or crawls beyond the single root document.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import requests

SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
)

_USER_AGENT = "OSINT-Vector-Analyzer-FYP (passive footprint scan)"


@dataclass
class HttpFingerprintResult:
    success: bool
    scheme: str = ""
    status_code: int | None = None
    server_header: str = ""
    powered_by: str = ""
    security_headers_present: list[str] = field(default_factory=list)
    security_headers_missing: list[str] = field(default_factory=list)
    error: str | None = None


class HttpFingerprinter:
    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout

    def fetch(self, domain: str) -> HttpFingerprintResult:
        for scheme in ("https", "http"):
            try:
                response = requests.get(
                    f"{scheme}://{domain}/",
                    timeout=self.timeout,
                    headers={"User-Agent": _USER_AGENT},
                    allow_redirects=True,
                )
            except requests.RequestException:
                continue

            present = [h for h in SECURITY_HEADERS if h in response.headers]
            missing = [h for h in SECURITY_HEADERS if h not in response.headers]

            return HttpFingerprintResult(
                success=True,
                scheme=scheme,
                status_code=response.status_code,
                server_header=response.headers.get("Server", ""),
                powered_by=response.headers.get("X-Powered-By", ""),
                security_headers_present=present,
                security_headers_missing=missing,
            )

        return HttpFingerprintResult(
            success=False,
            error="Site did not respond over HTTPS or HTTP.",
        )
