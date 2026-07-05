"""
Company / Domain Footprint orchestrator — combines passive WHOIS org
identity, mail-security posture (SPF/DMARC/DKIM), HTTP header fingerprint,
and official platform presence into a single report.

Every underlying check is passive (no login, no scraping of personal data,
no port scanning) and reuses the same no-API-key philosophy as the other
modules in this project.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .domain_validator import DomainValidator
from .http_fingerprint import HttpFingerprinter
from .mail_security import MailSecurityAnalyzer
from .org_identity import OrgIdentityLookup
from .social_presence import SocialPresenceChecker


@dataclass
class OrgFootprintReport:
    success: bool
    domain: str = ""
    error: str | None = None
    validation_failed: bool = False
    sections: dict[str, Any] | None = None
    org_name: str = ""
    org_country: str = ""
    whois_privacy: bool = False
    spf_status: str = ""
    dmarc_status: str = ""
    dkim_selector_count: int = 0
    security_header_score: int = 0
    social_platform_count: int = 0
    risk_flags: list[str] | None = None

    def to_storage_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "domain": self.domain,
            "error": self.error,
            "validation_failed": self.validation_failed,
            "sections": self.sections,
            "risk_flags": self.risk_flags,
        }


class OrgFootprintAnalyzer:
    def __init__(self):
        self.validator = DomainValidator()
        self.identity_lookup = OrgIdentityLookup()
        self.mail_analyzer = MailSecurityAnalyzer()
        self.http_fingerprinter = HttpFingerprinter()
        self.social_checker = SocialPresenceChecker()

    def analyze(self, domain_input: str) -> OrgFootprintReport:
        validation = self.validator.validate(domain_input)
        if not validation.ok:
            return OrgFootprintReport(
                success=False,
                error=validation.error,
                validation_failed=True,
            )

        domain = validation.domain
        sections: dict[str, Any] = {
            "Target": {
                "Domain": domain,
                "Scan Type": "Passive (WHOIS + DNS + HTTP headers + platform presence)",
            }
        }

        identity = self.identity_lookup.lookup(domain)
        if identity.success:
            if identity.registry_withholds_data:
                sections["Organization Identity"] = {
                    "Notice": (
                        "This domain's registry does not publish registrant/organization "
                        "details via WHOIS (common for several ccTLDs). Only nameservers, "
                        "dates, and status are available."
                    ),
                    "Registrar": identity.registrar or "—",
                }
            else:
                sections["Organization Identity"] = {
                    "Organization": identity.org_name or "—",
                    "Country": identity.country or "—",
                    "Registrar": identity.registrar or "—",
                    "WHOIS Privacy": "Enabled" if identity.whois_privacy else "Not detected",
                }
        else:
            sections["Organization Identity"] = {"Notice": identity.error or "WHOIS lookup failed."}

        mail = self.mail_analyzer.analyze(domain)
        sections["Mail Security Posture"] = {
            "SPF": mail.spf_record if mail.spf_present else "Not found",
            "DMARC": mail.dmarc_record if mail.dmarc_present else "Not found",
            "DMARC Policy": mail.dmarc_policy or "—",
            "DKIM Selectors Found": (
                ", ".join(mail.dkim_selectors_found) if mail.dkim_selectors_found else "None of the common selectors resolved"
            ),
        }

        http_result = self.http_fingerprinter.fetch(domain)
        if http_result.success:
            sections["HTTP Fingerprint"] = {
                "Scheme": http_result.scheme.upper(),
                "Status Code": str(http_result.status_code),
                "Server": http_result.server_header or "—",
                "X-Powered-By": http_result.powered_by or "—",
                "Security Headers Present": (
                    ", ".join(http_result.security_headers_present) or "None"
                ),
                "Security Headers Missing": (
                    ", ".join(http_result.security_headers_missing) or "None"
                ),
            }
        else:
            sections["HTTP Fingerprint"] = {"Notice": http_result.error or "No response."}

        social = self.social_checker.check(domain)
        sections["Official Platform Presence"] = {
            check.platform: (
                f"Confirmed — {check.url}"
                if check.found
                else ("Unverifiable (bot-protected)" if not check.verifiable else "Not found")
            )
            for check in social.checks
        }
        sections["Official Platform Presence"]["Guessed handle"] = social.slug

        risk_flags = self._derive_risk_flags(identity, mail, http_result)

        return OrgFootprintReport(
            success=True,
            domain=domain,
            sections=sections,
            org_name=identity.org_name if identity.success else "",
            org_country=identity.country if identity.success else "",
            whois_privacy=identity.whois_privacy if identity.success else False,
            spf_status="present" if mail.spf_present else "missing",
            dmarc_status=(mail.dmarc_policy or "none") if mail.dmarc_present else "missing",
            dkim_selector_count=len(mail.dkim_selectors_found),
            security_header_score=(
                len(http_result.security_headers_present) if http_result.success else 0
            ),
            social_platform_count=social.found_count,
            risk_flags=risk_flags,
        )

    def _derive_risk_flags(self, identity, mail, http_result) -> list[str]:
        flags: list[str] = []

        if not mail.spf_present:
            flags.append("No SPF record found — domain is more exposed to email spoofing.")
        if not mail.dmarc_present:
            flags.append("No DMARC record found — spoofed mail using this domain may not be rejected.")
        elif mail.dmarc_policy == "none":
            flags.append("DMARC policy is 'p=none' — spoofed mail is monitored but not blocked.")

        if http_result.success and len(http_result.security_headers_missing) >= 3:
            flags.append(
                "Most standard security headers are missing "
                f"({', '.join(http_result.security_headers_missing)})."
            )

        if identity.success and identity.whois_privacy:
            flags.append("WHOIS registrant details appear to be privacy-protected.")

        return flags
