"""
Domain intelligence orchestrator — WHOIS + DNS (passive footprinting).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .dns_resolver import DnsResolver
from .domain_validator import DomainValidator
from .whois_client import WhoisClient
from .whois_parser import WhoisParser


@dataclass
class DomainIntelReport:
    success: bool
    domain: str = ""
    error: str | None = None
    validation_failed: bool = False
    whois_raw: str = ""
    whois_servers_queried: list[str] | None = None
    sections: dict[str, Any] | None = None
    name_servers: list[str] | None = None
    dns_records_count: int = 0
    risk_flags: list[str] | None = None

    def to_storage_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "domain": self.domain,
            "error": self.error,
            "validation_failed": self.validation_failed,
            "whois_raw": self.whois_raw,
            "whois_servers_queried": self.whois_servers_queried,
            "sections": self.sections,
            "name_servers": self.name_servers,
            "dns_records_count": self.dns_records_count,
            "risk_flags": self.risk_flags,
        }


class DomainIntelAnalyzer:
    def __init__(self):
        self.validator = DomainValidator()
        self.whois_client = WhoisClient()
        self.whois_parser = WhoisParser()
        self.dns_resolver = DnsResolver()

    def analyze(self, domain_input: str) -> DomainIntelReport:
        validation = self.validator.validate(domain_input)
        if not validation.ok:
            return DomainIntelReport(
                success=False,
                error=validation.error,
                validation_failed=True,
            )

        domain = validation.domain
        sections: dict[str, Any] = {
            "Target": {"Domain": domain, "Lookup Type": "Passive (WHOIS + DNS)"},
        }

        whois_result = self.whois_client.lookup(domain)
        if not whois_result.success:
            return DomainIntelReport(
                success=False,
                domain=domain,
                error=whois_result.error,
                whois_servers_queried=whois_result.queries,
            )

        parsed = self.whois_parser.parse(whois_result.raw_text)
        for name, fields in parsed.sections.items():
            if fields:
                sections[f"WHOIS — {name}"] = fields

        if parsed.name_servers:
            sections["WHOIS — Name Servers"] = {
                f"NS {i + 1}": ns for i, ns in enumerate(parsed.name_servers)
            }

        dns_result = self.dns_resolver.lookup(domain)
        if dns_result.success:
            for rtype, rows in dns_result.sections.items():
                sections[f"DNS — {rtype}"] = {
                    f"Record {i + 1}": self._format_dns_row(row)
                    for i, row in enumerate(rows)
                }
        elif dns_result.error and "NXDOMAIN" in dns_result.error:
            sections["DNS"] = {"Status": dns_result.error}
        elif dns_result.error:
            sections["DNS"] = {"Warning": dns_result.error}

        risk_flags = self._derive_risk_flags(parsed, dns_result)

        return DomainIntelReport(
            success=True,
            domain=domain,
            whois_raw=whois_result.raw_text,
            whois_servers_queried=whois_result.queries,
            sections=sections,
            name_servers=parsed.name_servers,
            dns_records_count=len(dns_result.records) if dns_result.success else 0,
            risk_flags=risk_flags,
        )

    @staticmethod
    def _format_dns_row(row: dict[str, str]) -> str:
        parts = [row.get("Value", "")]
        if row.get("Priority"):
            parts.insert(0, f"priority {row['Priority']}")
        if row.get("TTL"):
            parts.append(f"TTL {row['TTL']}")
        return " · ".join(p for p in parts if p)

    def _derive_risk_flags(self, parsed, dns_result) -> list[str]:
        flags: list[str] = []
        flat = parsed.flat
        expiry = flat.get("Registry Expiry Date", "")
        if expiry:
            flags.append(f"Registry expiry listed: {expiry} — verify renewal status.")
        status = " ".join(parsed.status_lines).lower()
        if "prohibited" in status or "hold" in status:
            flags.append("Domain status may indicate transfer or registration restrictions.")
        if dns_result.success and not dns_result.records:
            flags.append("No DNS records returned — domain may be parked or misconfigured.")
        if not parsed.name_servers and dns_result.success:
            flags.append("WHOIS name servers missing but DNS responded — possible privacy/redaction.")
        dnssec = flat.get("DNSSEC", "").lower()
        if dnssec and "unsigned" in dnssec:
            flags.append("DNSSEC unsigned — DNS spoofing risk in hostile networks.")
        return flags
