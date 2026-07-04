"""
Organization identity — reuses whois_osint's WHOIS client/parser (no duplicate
socket logic) to pull registrant organization, country, and privacy-proxy signal.
"""

from __future__ import annotations

from dataclasses import dataclass

from whois_osint.services.whois_client import WhoisClient
from whois_osint.services.whois_parser import WhoisParser

_PRIVACY_MARKERS = (
    "privacy",
    "whoisguard",
    "redacted for privacy",
    "data protected",
    "proxy",
    "perfect privacy",
)


@dataclass
class OrgIdentity:
    success: bool
    org_name: str = ""
    country: str = ""
    registrar: str = ""
    whois_privacy: bool = False
    raw_text: str = ""
    error: str | None = None


class OrgIdentityLookup:
    def __init__(self):
        self.client = WhoisClient()
        self.parser = WhoisParser()

    def lookup(self, domain: str) -> OrgIdentity:
        result = self.client.lookup(domain)
        if not result.success:
            return OrgIdentity(success=False, error=result.error)

        parsed = self.parser.parse(result.raw_text)
        flat = parsed.flat

        org_name = (
            flat.get("Registrant Organization")
            or flat.get("Admin Organization")
            or flat.get("Organization")
            or ""
        )
        country = flat.get("Registrant Country") or flat.get("Country") or ""
        registrar = flat.get("Registrar", "")

        lowered = result.raw_text.lower()
        privacy = any(marker in lowered for marker in _PRIVACY_MARKERS) or (
            "redacted" in org_name.lower() if org_name else False
        )

        return OrgIdentity(
            success=True,
            org_name=org_name,
            country=country,
            registrar=registrar,
            whois_privacy=privacy,
            raw_text=result.raw_text,
        )
