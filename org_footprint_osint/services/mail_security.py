"""
Passive mail-security posture check — SPF/DMARC TXT records and a small,
well-known DKIM selector probe list. DNS only, no port scanning, no auth.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import dns.exception
import dns.resolver

# A short, widely-documented list of common DKIM selectors. Probing these is
# equivalent to a normal DNS TXT lookup — it does not touch the mail server.
COMMON_DKIM_SELECTORS = (
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "dkim",
    "mail",
    "smtp",
)


@dataclass
class MailSecurityResult:
    success: bool
    domain: str
    spf_present: bool = False
    spf_record: str = ""
    dmarc_present: bool = False
    dmarc_record: str = ""
    dmarc_policy: str = ""  # none / quarantine / reject
    dkim_selectors_found: list[str] = field(default_factory=list)
    error: str | None = None


class MailSecurityAnalyzer:
    def __init__(self, timeout: float = 5.0):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def analyze(self, domain: str) -> MailSecurityResult:
        result = MailSecurityResult(success=True, domain=domain)

        spf_record = self._first_txt_matching(domain, "v=spf1")
        if spf_record:
            result.spf_present = True
            result.spf_record = spf_record

        dmarc_record = self._first_txt_matching(f"_dmarc.{domain}", "v=dmarc1")
        if dmarc_record:
            result.dmarc_present = True
            result.dmarc_record = dmarc_record
            result.dmarc_policy = self._extract_dmarc_policy(dmarc_record)

        for selector in COMMON_DKIM_SELECTORS:
            record = self._first_txt_matching(
                f"{selector}._domainkey.{domain}", "v=dkim1", strict=False
            )
            if record is not None:
                result.dkim_selectors_found.append(selector)

        return result

    def _first_txt_matching(
        self, name: str, marker: str, strict: bool = True
    ) -> str | None:
        try:
            answers = self.resolver.resolve(name, "TXT")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return None
        except dns.exception.DNSException:
            return None

        for answer in answers:
            text = answer.to_text().strip('"').replace('" "', "")
            if not strict:
                # DKIM selector existing at all (even without full v=DKIM1 tag)
                # is a signal worth surfacing.
                return text[:300]
            if marker.lower() in text.lower():
                return text[:500]
        return None

    @staticmethod
    def _extract_dmarc_policy(record: str) -> str:
        for part in record.split(";"):
            part = part.strip()
            if part.lower().startswith("p="):
                return part.split("=", 1)[1].strip().lower()
        return ""
