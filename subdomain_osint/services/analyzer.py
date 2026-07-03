"""
Subdomain scan orchestrator — passive DNS + Certificate Transparency.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .domain_validator import DomainValidator
from .subdomain_enumerator import SubdomainEnumerator


@dataclass
class SubdomainScanReport:
    success: bool
    domain: str = ""
    error: str | None = None
    validation_failed: bool = False
    sections: dict[str, Any] | None = None
    subdomains: list[dict[str, Any]] | None = None
    subdomain_count: int = 0
    dns_verified_count: int = 0
    sources_used: list[str] | None = None
    warnings: list[str] | None = None
    risk_flags: list[str] | None = None

    def to_storage_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "domain": self.domain,
            "error": self.error,
            "validation_failed": self.validation_failed,
            "sections": self.sections,
            "subdomains": self.subdomains,
            "subdomain_count": self.subdomain_count,
            "dns_verified_count": self.dns_verified_count,
            "sources_used": self.sources_used,
            "warnings": self.warnings,
            "risk_flags": self.risk_flags,
        }


class SubdomainAnalyzer:
    def __init__(self):
        self.validator = DomainValidator()
        self.enumerator = SubdomainEnumerator()

    def analyze(self, domain_input: str) -> SubdomainScanReport:
        validation = self.validator.validate(domain_input)
        if not validation.ok:
            return SubdomainScanReport(
                success=False,
                error=validation.error,
                validation_failed=True,
            )

        domain = validation.domain
        sections: dict[str, Any] = {
            "Target": {
                "Domain": domain,
                "Scan Type": "Passive (DNS labels + Certificate Transparency)",
            },
        }

        result = self.enumerator.enumerate(domain)
        subdomains_payload = [s.to_dict() for s in result.subdomains]

        if not result.success:
            return SubdomainScanReport(
                success=False,
                domain=domain,
                error=result.error or "Subdomain scan failed.",
                sections=sections,
            )

        if result.subdomains:
            sections["Scan Summary"] = {
                "Total discovered": str(result.count),
                "DNS verified": str(result.dns_verified_count),
                "Sources": ", ".join(result.sources_used) or "—",
            }
            if result.truncated:
                sections["Scan Summary"]["Note"] = (
                    "List truncated in storage; export JSON for the full set."
                )
            if result.warnings:
                sections["Scan Summary"]["Certificate Transparency"] = "; ".join(
                    result.warnings
                )
        elif result.warnings:
            sections["Scan Summary"] = {"Notice": "; ".join(result.warnings)}
        elif result.error:
            sections["Scan Summary"] = {"Warning": result.error}

        risk_flags = self._derive_risk_flags(result, domain)

        return SubdomainScanReport(
            success=True,
            domain=domain,
            sections=sections,
            subdomains=subdomains_payload,
            subdomain_count=result.count,
            dns_verified_count=result.dns_verified_count,
            sources_used=result.sources_used,
            warnings=result.warnings or None,
            risk_flags=risk_flags,
        )

    def _derive_risk_flags(self, result, domain: str) -> list[str]:
        flags: list[str] = []
        if result.count >= 25:
            flags.append(
                f"Large subdomain footprint ({result.count} hosts) — "
                "review exposed services and certificate history."
            )
        sensitive_labels = frozenset(
            {"admin", "staging", "stage", "dev", "test", "vpn", "internal"}
        )
        admin_hosts = [
            s.host
            for s in result.subdomains
            if s.dns_verified and _host_has_sensitive_label(s.host, domain, sensitive_labels)
        ]
        if admin_hosts[:3]:
            flags.append(f"Sensitive-looking subdomains resolved: {', '.join(admin_hosts[:3])}.")
        if result.count == 0 and (result.error or result.warnings):
            flags.append(
                "No subdomains found. crt.sh may be slow or down — try again later."
            )
        return flags


def _host_has_sensitive_label(host: str, domain: str, labels: frozenset[str]) -> bool:
    if host == domain or not host.endswith(f".{domain}"):
        return False
    prefix = host[: -(len(domain) + 1)]
    return any(part in labels for part in prefix.split("."))
