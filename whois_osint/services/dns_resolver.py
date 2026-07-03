"""
Passive DNS resolution via dnspython (SRS-15 DNS records).
"""

from __future__ import annotations

from dataclasses import dataclass, field

import dns.exception
import dns.resolver


@dataclass
class DnsRecord:
    record_type: str
    value: str
    ttl: int | None = None
    priority: int | None = None


@dataclass
class DnsLookupResult:
    success: bool
    domain: str
    records: list[DnsRecord] = field(default_factory=list)
    sections: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    error: str | None = None


class DnsResolver:
    """Resolves public DNS records without port scanning."""

    RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")

    def __init__(self, timeout: float = 5.0):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def lookup(self, domain: str) -> DnsLookupResult:
        records: list[DnsRecord] = []
        sections: dict[str, list[dict[str, str]]] = {}
        errors: list[str] = []

        for rtype in self.RECORD_TYPES:
            try:
                answers = self.resolver.resolve(domain, rtype)
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NXDOMAIN:
                return DnsLookupResult(
                    success=False,
                    domain=domain,
                    error=f"NXDOMAIN — {domain} does not exist in DNS.",
                )
            except dns.exception.DNSException as exc:
                errors.append(f"{rtype}: {exc}")
                continue

            rows: list[dict[str, str]] = []
            for answer in answers:
                ttl = answers.rrset.ttl if answers.rrset else None
                if rtype == "MX":
                    priority = answer.preference
                    host = str(answer.exchange).rstrip(".")
                    value = f"{priority} {host}"
                    records.append(
                        DnsRecord("MX", host, ttl=ttl, priority=priority)
                    )
                elif rtype == "TXT":
                    text = answer.to_text().strip('"')
                    value = text[:500] + ("…" if len(text) > 500 else "")
                    records.append(DnsRecord("TXT", value, ttl=ttl))
                else:
                    value = str(answer).rstrip(".")
                    records.append(DnsRecord(rtype, value, ttl=ttl))

                row = {"Value": value}
                if ttl is not None:
                    row["TTL"] = str(ttl)
                if rtype == "MX":
                    row["Priority"] = str(answer.preference)
                rows.append(row)

            if rows:
                sections[rtype] = rows

        if not records and errors:
            return DnsLookupResult(
                success=False,
                domain=domain,
                error="; ".join(errors),
            )

        return DnsLookupResult(
            success=True,
            domain=domain,
            records=records,
            sections=sections,
            error="; ".join(errors) if errors else None,
        )
