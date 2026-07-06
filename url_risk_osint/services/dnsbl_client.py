"""
DNS-based blocklist (DNSBL) reputation checks — real, live threat
intelligence with zero signup and zero API key.

This is the same technique mail servers and web proxies use in production:
query `<host>.dbl.spamhaus.org` (or another DNSBL zone). If the domain is
listed, the zone resolves to a 127.0.1.x address whose last octet encodes
the listing category. NXDOMAIN means "not listed". No account, no key, no
rate-limit signup — just a normal DNS query.

Spamhaus DBL return codes: https://www.spamhaus.org/dbl/
  127.0.1.2   spam domain
  127.0.1.4   phishing domain
  127.0.1.5   malware domain
  127.0.1.6   botnet C&C domain
  127.0.1.102 abused legit spam
  127.0.1.103 abused legit spam (redirector)
  127.0.1.104 abused legit phish
  127.0.1.105 abused legit malware
  127.0.1.106 abused legit botnet C&C

SURBL is queried the same way against multi.surbl.org and treated as a
simple listed/not-listed boolean (its categories are combined bitmasks that
aren't worth surfacing individually here).
"""

from __future__ import annotations

from dataclasses import dataclass, field

import dns.exception
import dns.resolver

_DBL_CATEGORY_MAP: dict[str, str] = {
    "127.0.1.2": "spam domain",
    "127.0.1.4": "phishing domain",
    "127.0.1.5": "malware domain",
    "127.0.1.6": "botnet command-and-control domain",
    "127.0.1.102": "abused legitimate service (spam)",
    "127.0.1.103": "abused legitimate service (spam redirector)",
    "127.0.1.104": "abused legitimate service (phishing)",
    "127.0.1.105": "abused legitimate service (malware)",
    "127.0.1.106": "abused legitimate service (botnet C&C)",
}

# Spamhaus explicitly returns 127.0.1.255 for zones queried too fast / abuse
# of the free tier — this is not a listing, it's a rate-limit signal.
_DBL_RATE_LIMITED = "127.0.1.255"


@dataclass
class DnsblResult:
    checked: bool
    host: str
    listed: bool = False
    categories: list[str] = field(default_factory=list)
    lists_hit: list[str] = field(default_factory=list)
    lists_errored: list[str] = field(default_factory=list)
    rate_limited: bool = False
    error: str | None = None

    @property
    def fully_verified(self) -> bool:
        """True only if every configured list actually answered (listed or
        genuinely clean) — false if any list's query failed/timed out,
        since a failed query must never be presented as 'not listed'."""
        return self.checked and not self.lists_errored


class DnsblClient:
    def __init__(self, timeout: float = 4.0):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def check(self, host: str) -> DnsblResult:
        host = (host or "").strip().lower().rstrip(".")
        if not host:
            return DnsblResult(checked=False, host=host, error="No host to check.")

        result = DnsblResult(checked=True, host=host)

        dbl_status, dbl_codes, dbl_err = self._query(f"{host}.dbl.spamhaus.org")
        if dbl_status == "listed":
            if _DBL_RATE_LIMITED in dbl_codes:
                result.rate_limited = True
            else:
                result.listed = True
                result.lists_hit.append("Spamhaus DBL")
                for code in dbl_codes:
                    category = _DBL_CATEGORY_MAP.get(code, f"listed ({code})")
                    if category not in result.categories:
                        result.categories.append(category)
        elif dbl_status == "error":
            result.lists_errored.append("Spamhaus DBL")

        surbl_status, surbl_codes, surbl_err = self._query(f"{host}.multi.surbl.org")
        if surbl_status == "listed":
            result.listed = True
            result.lists_hit.append("SURBL")
            if "listed on SURBL (spam/phishing/malware aggregate)" not in result.categories:
                result.categories.append("listed on SURBL (spam/phishing/malware aggregate)")
        elif surbl_status == "error":
            result.lists_errored.append("SURBL")

        if result.lists_errored:
            reasons = []
            if "Spamhaus DBL" in result.lists_errored:
                reasons.append(f"Spamhaus DBL ({dbl_err})")
            if "SURBL" in result.lists_errored:
                reasons.append(f"SURBL ({surbl_err})")
            result.error = "Query failed for: " + "; ".join(reasons)

        return result

    def _query(self, name: str) -> tuple[str, list[str], str]:
        """Returns (status, codes, error_reason).
        status is one of: 'listed', 'clean', 'error'.
        'clean' (genuine NXDOMAIN) and 'error' (timeout/DNS failure) must
        stay distinguishable — collapsing them was the bug: a failed query
        used to look identical to a verified-clean result.
        """
        try:
            answers = self.resolver.resolve(name, "A")
            return "listed", [answer.to_text() for answer in answers], ""
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return "clean", [], ""
        except dns.exception.DNSException as exc:
            return "error", [], exc.__class__.__name__
