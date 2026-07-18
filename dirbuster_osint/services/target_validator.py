"""
Target validation for directory brute-forcing. Blocks private/loopback/
reserved targets the same way ip_intel_osint and org_footprint_osint do.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)

_BLOCKED_HOSTNAMES = frozenset({"localhost"})


@dataclass(frozen=True)
class TargetValidationResult:
    ok: bool
    base_url: str = ""
    host: str = ""
    error: str | None = None


class TargetValidator:
    def validate(self, raw: str) -> TargetValidationResult:
        candidate = (raw or "").strip()
        if not candidate:
            return TargetValidationResult(ok=False, error="Enter a target URL or domain.")

        if not candidate.startswith(("http://", "https://")):
            candidate = f"https://{candidate}"

        parsed = urlparse(candidate)
        host = parsed.hostname or ""
        if not host:
            return TargetValidationResult(ok=False, error="Could not parse a host from that input.")

        host = host.lower()

        if host in _BLOCKED_HOSTNAMES:
            return TargetValidationResult(ok=False, error="This host cannot be scanned.")

        try:
            ip_obj = ipaddress.ip_address(host)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
                return TargetValidationResult(
                    ok=False, error="Private, loopback, and reserved IP ranges cannot be scanned."
                )
        except ValueError:
            if not _DOMAIN_RE.match(host):
                return TargetValidationResult(ok=False, error="Enter a valid domain or URL.")

        scheme = parsed.scheme if parsed.scheme in ("http", "https") else "https"
        port_part = f":{parsed.port}" if parsed.port else ""
        base_url = f"{scheme}://{host}{port_part}"

        return TargetValidationResult(ok=True, base_url=base_url, host=host)
