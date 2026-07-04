"""
Accepts either a raw IP address (v4/v6) or a domain name and resolves to a
single public IP for geolocation/RDAP lookups.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

import dns.exception
import dns.resolver

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)
DOMAIN_HTML_PATTERN = r"([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}"

_PRIVATE_RANGE_ERROR = "Private, loopback, and reserved IP ranges cannot be queried."


@dataclass(frozen=True)
class IPInputResult:
    ok: bool
    ip: str = ""
    query_input: str = ""
    was_domain: bool = False
    error: str | None = None


class IPInputResolver:
    def resolve(self, raw: str) -> IPInputResult:
        candidate = raw.strip().lower()
        if not candidate:
            return IPInputResult(ok=False, error="Enter an IP address or domain name.")

        if candidate.startswith(("http://", "https://")) or "/" in candidate:
            return IPInputResult(
                ok=False, error="Enter a bare IP address or domain, not a URL."
            )

        # Try as raw IP first.
        try:
            ip_obj = ipaddress.ip_address(candidate)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
                return IPInputResult(ok=False, error=_PRIVATE_RANGE_ERROR)
            return IPInputResult(
                ok=True, ip=str(ip_obj), query_input=candidate, was_domain=False
            )
        except ValueError:
            pass

        # Fall back to domain resolution.
        domain = candidate
        if domain.startswith("www."):
            domain = domain[4:]
        if not _DOMAIN_RE.match(domain):
            return IPInputResult(
                ok=False,
                error="Enter a valid IP address (e.g. 8.8.8.8) or domain (e.g. example.com).",
            )

        resolved_ip = self._resolve_domain(domain)
        if resolved_ip is None:
            return IPInputResult(ok=False, error=f"Could not resolve {domain} to an IP address.")

        try:
            ip_obj = ipaddress.ip_address(resolved_ip)
        except ValueError:
            return IPInputResult(ok=False, error="Resolved address was not a valid IP.")

        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
            return IPInputResult(ok=False, error=_PRIVATE_RANGE_ERROR)

        return IPInputResult(
            ok=True, ip=str(ip_obj), query_input=candidate, was_domain=True
        )

    @staticmethod
    def _resolve_domain(domain: str) -> str | None:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 5.0
        for record_type in ("A", "AAAA"):
            try:
                answers = resolver.resolve(domain, record_type)
                for answer in answers:
                    return answer.to_text()
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except dns.exception.DNSException:
                continue
        return None
