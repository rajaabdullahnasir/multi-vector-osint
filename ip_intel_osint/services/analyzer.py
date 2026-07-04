"""
Geolocation / IP Intelligence orchestrator — combines IP/domain resolution,
RDAP network registration data, and free geolocation lookup into a single
report. Every source is free and requires no API key.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .ip_geolocation_client import IPGeolocationClient
from .ip_validator import IPInputResolver
from .rdap_client import RdapClient


@dataclass
class IPIntelReport:
    success: bool
    query_input: str = ""
    ip: str = ""
    was_domain: bool = False
    error: str | None = None
    validation_failed: bool = False
    sections: dict[str, Any] | None = None
    ptr_hostname: str = ""
    asn: str = ""
    isp: str = ""
    org_name: str = ""
    country: str = ""
    region: str = ""
    city: str = ""
    latitude: float | None = None
    longitude: float | None = None
    timezone: str = ""
    is_proxy_or_vpn: bool = False
    is_hosting: bool = False
    risk_flags: list[str] | None = None

    def to_storage_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "query_input": self.query_input,
            "ip": self.ip,
            "was_domain": self.was_domain,
            "error": self.error,
            "validation_failed": self.validation_failed,
            "sections": self.sections,
            "risk_flags": self.risk_flags,
        }


class IPIntelAnalyzer:
    def __init__(self):
        self.resolver = IPInputResolver()
        self.rdap_client = RdapClient()
        self.geo_client = IPGeolocationClient()

    def analyze(self, raw_input: str) -> IPIntelReport:
        resolution = self.resolver.resolve(raw_input)
        if not resolution.ok:
            return IPIntelReport(success=False, error=resolution.error, validation_failed=True)

        ip = resolution.ip
        sections: dict[str, Any] = {
            "Target": {
                "Query": resolution.query_input,
                "Resolved IP": ip,
                "Source": "Domain resolution (A/AAAA)" if resolution.was_domain else "Direct IP input",
            }
        }

        geo = self.geo_client.lookup(ip)
        if geo.ok:
            sections["Geolocation"] = {
                "Country": f"{geo.country} ({geo.country_code})" if geo.country else "—",
                "Region": geo.region or "—",
                "City": geo.city or "—",
                "Coordinates": (
                    f"{geo.latitude}, {geo.longitude}"
                    if geo.latitude is not None and geo.longitude is not None
                    else "—"
                ),
                "Timezone": geo.timezone or "—",
            }
            sections["Network"] = {
                "ISP": geo.isp or "—",
                "Organization": geo.org or "—",
                "ASN": geo.asn or "—",
                "Reverse DNS": geo.reverse_dns or "—",
                "Proxy / VPN detected": "Yes" if geo.is_proxy_or_vpn else "No",
                "Hosting / Datacenter IP": "Yes" if geo.is_hosting else "No",
            }
        else:
            sections["Geolocation"] = {"Notice": geo.error or "Geolocation lookup failed."}
            sections["Network"] = {"Notice": "Unavailable — geolocation lookup failed."}

        rdap = self.rdap_client.lookup(ip)
        if rdap.ok:
            sections["RDAP Registration"] = {
                "Network Name": rdap.network_name or "—",
                "Network Range": rdap.network_range or "—",
                "Registered Entity": rdap.entity_name or "—",
                "Country (RDAP)": rdap.country or "—",
            }
            if rdap.remarks:
                sections["RDAP Registration"]["Remarks"] = " / ".join(rdap.remarks)
        else:
            sections["RDAP Registration"] = {"Notice": rdap.error or "RDAP lookup failed."}

        risk_flags = self._derive_risk_flags(geo)

        return IPIntelReport(
            success=True,
            query_input=resolution.query_input,
            ip=ip,
            was_domain=resolution.was_domain,
            sections=sections,
            ptr_hostname=geo.reverse_dns if geo.ok else "",
            asn=geo.asn if geo.ok else "",
            isp=geo.isp if geo.ok else "",
            org_name=(geo.org if geo.ok else "") or (rdap.entity_name if rdap.ok else ""),
            country=geo.country_code if geo.ok else (rdap.country if rdap.ok else ""),
            region=geo.region if geo.ok else "",
            city=geo.city if geo.ok else "",
            latitude=geo.latitude if geo.ok else None,
            longitude=geo.longitude if geo.ok else None,
            timezone=geo.timezone if geo.ok else "",
            is_proxy_or_vpn=geo.is_proxy_or_vpn if geo.ok else False,
            is_hosting=geo.is_hosting if geo.ok else False,
            risk_flags=risk_flags,
        )

    def _derive_risk_flags(self, geo) -> list[str]:
        flags: list[str] = []
        if not geo.ok:
            return flags
        if geo.is_proxy_or_vpn:
            flags.append("This IP is flagged as a known proxy or VPN exit node.")
        if geo.is_hosting:
            flags.append(
                "This IP belongs to a hosting/datacenter provider rather than a residential ISP."
            )
        return flags
