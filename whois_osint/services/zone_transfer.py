"""
DNS zone transfer (AXFR) test — checks whether any of a domain's
authoritative nameservers will hand over the entire zone file to an
unauthenticated request. This is a well-known, serious misconfiguration:
a proper nameserver only allows AXFR to specific secondary servers, not
to anyone who asks. Standard technique in tools like dnsrecon/fierce,
and just a normal DNS protocol query — nothing more invasive than any
other DNS lookup this project already does.

Pure Python via dnspython, no external service.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import dns.exception
import dns.query
import dns.resolver
import dns.zone


@dataclass(frozen=True)
class ZoneTransferAttempt:
    nameserver: str
    vulnerable: bool
    record_count: int = 0
    sample_records: tuple[str, ...] = ()
    error: str = ""


@dataclass
class ZoneTransferResult:
    success: bool
    domain: str = ""
    attempts: list[ZoneTransferAttempt] = field(default_factory=list)
    error: str | None = None

    @property
    def any_vulnerable(self) -> bool:
        return any(a.vulnerable for a in self.attempts)

    @property
    def vulnerable_nameservers(self) -> list[str]:
        return [a.nameserver for a in self.attempts if a.vulnerable]


_TIMEOUT = 6.0
_MAX_SAMPLE_RECORDS = 8


class ZoneTransferTester:
    def __init__(self, timeout: float = _TIMEOUT):
        self.timeout = timeout

    def test(self, domain: str, name_servers: list[str] | None) -> ZoneTransferResult:
        if not name_servers:
            return ZoneTransferResult(
                success=False, domain=domain,
                error="No nameservers known — run WHOIS/DNS lookup first.",
            )

        attempts: list[ZoneTransferAttempt] = []
        for ns in name_servers:
            attempts.append(self._attempt_one(domain, ns))

        return ZoneTransferResult(success=True, domain=domain, attempts=attempts)

    def _attempt_one(self, domain: str, nameserver: str) -> ZoneTransferAttempt:
        ns_host = nameserver.rstrip(".")
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            answers = resolver.resolve(ns_host, "A")
            ns_ip = str(answers[0])
        except dns.exception.DNSException as exc:
            return ZoneTransferAttempt(
                nameserver=nameserver, vulnerable=False,
                error=f"Could not resolve nameserver IP: {exc.__class__.__name__}",
            )

        try:
            zone = dns.zone.from_xfr(
                dns.query.xfr(ns_ip, domain, timeout=self.timeout, lifetime=self.timeout)
            )
        except ConnectionRefusedError:
            return ZoneTransferAttempt(
                nameserver=nameserver, vulnerable=False,
                error="Connection refused (expected — AXFR correctly restricted).",
            )
        except dns.exception.FormError:
            return ZoneTransferAttempt(
                nameserver=nameserver, vulnerable=False,
                error="Transfer refused by server (expected — properly configured).",
            )
        except dns.exception.DNSException as exc:
            return ZoneTransferAttempt(
                nameserver=nameserver, vulnerable=False,
                error=f"{exc.__class__.__name__} (transfer not permitted).",
            )
        except OSError as exc:
            return ZoneTransferAttempt(
                nameserver=nameserver, vulnerable=False,
                error=f"Network error: {exc}",
            )

        # If we got here, the server handed over the FULL zone unauthenticated.
        names = sorted(str(name) for name in zone.nodes.keys())
        return ZoneTransferAttempt(
            nameserver=nameserver,
            vulnerable=True,
            record_count=len(names),
            sample_records=tuple(names[:_MAX_SAMPLE_RECORDS]),
        )
