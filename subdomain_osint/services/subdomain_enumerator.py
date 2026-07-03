"""
Passive subdomain discovery — DNS label probing + Certificate Transparency (crt.sh).

DNS probes run in parallel; CT fetch overlaps with wordlist probing.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import dns.exception
import dns.resolver

from .ct_client import fetch_ct_hosts
from .subdomain_wordlist import COMMON_SUBDOMAIN_LABELS, PRIORITY_SUBDOMAIN_LABELS

_WILDCARD_RE = re.compile(r"^\*\.")
_MAX_STORED = 400
_MAX_CT_HOSTS = 500
_DNS_TIMEOUT = 1.2
_DNS_WORKERS = 28
_MAX_CT_VERIFY = 50


@dataclass(frozen=True)
class DiscoveredSubdomain:
    host: str
    sources: tuple[str, ...]
    records: tuple[str, ...] = ()
    dns_verified: bool = False

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "sources": list(self.sources),
            "records": list(self.records),
            "dns_verified": self.dns_verified,
        }


@dataclass
class SubdomainLookupResult:
    success: bool
    domain: str
    subdomains: list[DiscoveredSubdomain] = field(default_factory=list)
    sources_used: list[str] = field(default_factory=list)
    error: str | None = None
    warnings: list[str] = field(default_factory=list)
    truncated: bool = False

    @property
    def count(self) -> int:
        return len(self.subdomains)

    @property
    def dns_verified_count(self) -> int:
        return sum(1 for s in self.subdomains if s.dns_verified)


class SubdomainEnumerator:
    """Discover subdomains via DNS probing and CT log search."""

    def __init__(self, dns_timeout: float = _DNS_TIMEOUT):
        self.dns_timeout = dns_timeout

    def enumerate(self, domain: str) -> SubdomainLookupResult:
        domain = domain.strip().lower().rstrip(".")
        merged: dict[str, dict] = {}
        sources_used: list[str] = []
        errors: list[str] = []

        warnings: list[str] = []

        with ThreadPoolExecutor(max_workers=2) as pool:
            dns_future = pool.submit(self._probe_common_labels, domain)
            ct_future = pool.submit(
                fetch_ct_hosts, domain, max_hosts=_MAX_CT_HOSTS
            )
            dns_found = dns_future.result()
            ct_hosts, ct_warning = ct_future.result()

        if dns_found:
            sources_used.append("dns-bruteforce")
        for host, records in dns_found.items():
            self._merge_host(merged, host, "dns-bruteforce", records)

        if ct_hosts:
            sources_used.append("certificate-transparency (crt.sh)")
        elif ct_warning:
            warnings.append(ct_warning)
            extended = self._probe_extended_labels(domain, dns_found)
            if extended:
                sources_used.append("dns-bruteforce (extended)")
                for host, records in extended.items():
                    self._merge_host(merged, host, "dns-bruteforce", records)
                dns_found = {**dns_found, **extended}

        for host in ct_hosts:
            self._merge_host(merged, host, "certificate-transparency")

        if not merged and errors:
            return SubdomainLookupResult(
                success=False,
                domain=domain,
                error="; ".join(errors),
                sources_used=sources_used,
            )

        unresolved = [
            host
            for host, meta in merged.items()
            if not meta["records"] and not _WILDCARD_RE.match(host)
        ][: _MAX_CT_VERIFY]
        if unresolved:
            for host, records in self._resolve_hosts_parallel(unresolved).items():
                if records:
                    meta = merged[host]
                    meta["records"] = records
                    meta["dns_verified"] = True

        subdomains = self._build_results(merged, domain)
        truncated = len(subdomains) > _MAX_STORED
        if truncated:
            subdomains = subdomains[:_MAX_STORED]

        return SubdomainLookupResult(
            success=True,
            domain=domain,
            subdomains=subdomains,
            sources_used=sources_used,
            error="; ".join(errors) if errors else None,
            warnings=warnings,
            truncated=truncated,
        )

    def _probe_common_labels(self, domain: str) -> dict[str, list[str]]:
        hosts = [f"{label}.{domain}" for label in PRIORITY_SUBDOMAIN_LABELS]
        return self._resolve_hosts_parallel(hosts)

    def _probe_extended_labels(
        self, domain: str, already_found: dict[str, list[str]]
    ) -> dict[str, list[str]]:
        """Extra DNS labels when CT is unavailable (no duplicate hosts)."""
        extra_labels = [
            label
            for label in COMMON_SUBDOMAIN_LABELS
            if label not in PRIORITY_SUBDOMAIN_LABELS
        ]
        hosts = [
            f"{label}.{domain}"
            for label in extra_labels
            if f"{label}.{domain}" not in already_found
        ]
        if not hosts:
            return {}
        return self._resolve_hosts_parallel(hosts)

    def _resolve_hosts_parallel(self, hosts: list[str]) -> dict[str, list[str]]:
        found: dict[str, list[str]] = {}
        if not hosts:
            return found

        with ThreadPoolExecutor(max_workers=_DNS_WORKERS) as pool:
            futures = {
                pool.submit(self._resolve_host, host): host for host in hosts
            }
            for future in as_completed(futures):
                host = futures[future]
                try:
                    records = future.result()
                except Exception:
                    continue
                if records:
                    found[host] = records
        return found

    def _make_resolver(self) -> dns.resolver.Resolver:
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.dns_timeout
        resolver.lifetime = self.dns_timeout
        return resolver

    def _resolve_host(self, host: str) -> list[str]:
        """Fast existence check: A then CNAME; NXDOMAIN stops immediately."""
        if _WILDCARD_RE.match(host):
            return []

        resolver = self._make_resolver()
        values: list[str] = []

        try:
            answers = resolver.resolve(host, "A")
            for answer in answers:
                values.append(f"A {str(answer).rstrip('.')}")
            if values:
                return values
        except dns.resolver.NXDOMAIN:
            return []
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
            dns.exception.DNSException,
        ):
            pass

        try:
            answers = resolver.resolve(host, "CNAME")
            for answer in answers:
                values.append(f"CNAME {str(answer).rstrip('.')}")
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
            dns.exception.DNSException,
        ):
            pass

        return values

    @staticmethod
    def _merge_host(
        merged: dict[str, dict],
        host: str,
        source: str,
        records: list[str] | None = None,
    ) -> None:
        host = host.lower().rstrip(".")
        entry = merged.setdefault(
            host,
            {"sources": set(), "records": [], "dns_verified": False},
        )
        entry["sources"].add(source)
        if records:
            entry["records"] = records
            entry["dns_verified"] = True

    def _build_results(
        self, merged: dict[str, dict], domain: str
    ) -> list[DiscoveredSubdomain]:
        items: list[DiscoveredSubdomain] = []
        for host in sorted(merged.keys()):
            meta = merged[host]
            records = tuple(meta["records"])
            dns_verified = bool(meta["dns_verified"] or records)
            items.append(
                DiscoveredSubdomain(
                    host=host,
                    sources=tuple(sorted(meta["sources"])),
                    records=records,
                    dns_verified=dns_verified,
                )
            )
        items.sort(
            key=lambda s: (
                0 if s.host == domain else 1,
                0 if s.dns_verified else 1,
                s.host,
            )
        )
        return items
