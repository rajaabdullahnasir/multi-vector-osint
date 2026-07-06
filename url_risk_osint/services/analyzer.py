"""
URL risk analysis orchestrator (SRS-28–29).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .blacklist import check_blacklist
from .dnsbl_client import DnsblClient
from .lexical_analyzer import analyze_lexical
from .risk_scorer import RISK_DANGEROUS, RISK_SAFE, RISK_SUSPICIOUS, score_risk
from .url_validator import UrlValidator


@dataclass
class UrlRiskReport:
    success: bool
    url: str = ""
    error: str | None = None
    validation_failed: bool = False
    risk_level: str = RISK_SAFE
    risk_score: int = 0
    sections: dict[str, Any] | None = None
    lexical_findings: list[dict[str, Any]] | None = None
    blacklist_hits: list[dict[str, Any]] | None = None
    risk_flags: list[str] | None = None
    parsed: dict[str, str] | None = None

    def to_storage_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "url": self.url,
            "error": self.error,
            "validation_failed": self.validation_failed,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "sections": self.sections,
            "lexical_findings": self.lexical_findings,
            "blacklist_hits": self.blacklist_hits,
            "risk_flags": self.risk_flags,
            "parsed": self.parsed,
        }


class UrlRiskAnalyzer:
    def __init__(self):
        self.validator = UrlValidator()
        self.dnsbl_client = DnsblClient()

    def analyze(self, url_input: str) -> UrlRiskReport:
        validation = self.validator.validate(url_input)
        if not validation.ok:
            return UrlRiskReport(
                success=False,
                error=validation.error,
                validation_failed=True,
            )

        url = validation.url
        parsed = urlparse(url)
        parsed_info = {
            "Scheme": parsed.scheme,
            "Host": parsed.hostname or "",
            "Port": str(parsed.port or ("443" if parsed.scheme == "https" else "80")),
            "Path": parsed.path or "/",
            "Query": parsed.query or "—",
        }

        lexical = analyze_lexical(url)
        blacklist = check_blacklist(url)
        dnsbl = self.dnsbl_client.check(parsed.hostname or "")
        assessment = score_risk(lexical, blacklist, dnsbl)

        sections: dict[str, Any] = {
            "Target": {
                "URL": url,
                "Method": "Lexical analysis + static blacklist + live DNSBL reputation (Spamhaus DBL, SURBL)",
            },
            "Summary": {
                "Risk level": assessment.risk_level.title(),
                "Risk score": str(assessment.risk_score),
                "Lexical score": str(assessment.lexical_score),
                "Blacklist score": str(assessment.blacklist_score),
                "DNSBL score": str(assessment.dnsbl_score),
                "Lexical findings": str(len(lexical)),
                "Blacklist hits": str(len(blacklist)),
            },
        }

        if dnsbl.checked:
            if dnsbl.listed:
                sections["Live Threat Feed (DNSBL)"] = {
                    "Status": "LISTED",
                    "Lists": ", ".join(dnsbl.lists_hit),
                    "Categories": ", ".join(dnsbl.categories) or "—",
                }
                if dnsbl.lists_errored:
                    sections["Live Threat Feed (DNSBL)"]["Note"] = (
                        f"Could not query: {', '.join(dnsbl.lists_errored)} — "
                        "listing above is from the list(s) that did respond."
                    )
            elif dnsbl.rate_limited:
                sections["Live Threat Feed (DNSBL)"] = {
                    "Status": "Unavailable — rate limited by Spamhaus's free tier right now.",
                }
            elif dnsbl.lists_errored and len(dnsbl.lists_errored) == 2:
                # Both lists failed — we verified NOTHING. Must not imply "safe".
                sections["Live Threat Feed (DNSBL)"] = {
                    "Status": "Could not be verified — both threat feeds failed to respond.",
                    "Detail": dnsbl.error or "Unknown DNS error.",
                }
            elif dnsbl.lists_errored:
                # One list answered clean, the other failed — say exactly that.
                checked_ok = "SURBL" if "Spamhaus DBL" in dnsbl.lists_errored else "Spamhaus DBL"
                sections["Live Threat Feed (DNSBL)"] = {
                    "Status": f"Not listed on {checked_ok} — the other feed could not be reached.",
                    "Detail": dnsbl.error or "Unknown DNS error.",
                }
            else:
                sections["Live Threat Feed (DNSBL)"] = {
                    "Status": "Not listed on Spamhaus DBL or SURBL.",
                }
        else:
            sections["Live Threat Feed (DNSBL)"] = {
                "Status": dnsbl.error or "Could not be checked (no resolvable host).",
            }

        risk_flags = self._derive_risk_flags(assessment.risk_level, lexical, blacklist, dnsbl)

        return UrlRiskReport(
            success=True,
            url=url,
            risk_level=assessment.risk_level,
            risk_score=assessment.risk_score,
            sections=sections,
            lexical_findings=[f.to_dict() for f in lexical],
            blacklist_hits=[h.to_dict() for h in blacklist],
            risk_flags=risk_flags,
            parsed=parsed_info,
        )

    def _derive_risk_flags(self, level: str, lexical, blacklist, dnsbl=None) -> list[str]:
        flags: list[str] = []
        if dnsbl and dnsbl.listed:
            categories = ", ".join(dnsbl.categories) or "unspecified abuse"
            flags.append(
                f"Live threat feed match: listed on {', '.join(dnsbl.lists_hit)} ({categories})."
            )
        if level == RISK_DANGEROUS:
            flags.append("High risk — avoid visiting; possible phishing or malware.")
        elif level == RISK_SUSPICIOUS:
            flags.append("Suspicious indicators present — verify destination before use.")
        else:
            flags.append("No strong risk indicators from lexical/blacklist/DNSBL checks.")
        if dnsbl and dnsbl.checked and dnsbl.lists_errored and not dnsbl.listed:
            if len(dnsbl.lists_errored) == 2:
                flags.append(
                    "DNSBL check could not be verified — both threat feeds failed to "
                    "respond. This is NOT a confirmed-safe result for that check."
                )
            else:
                flags.append(
                    f"{dnsbl.lists_errored[0]} could not be reached — DNSBL result is "
                    "based on the other feed only."
                )
        if blacklist:
            flags.append(f"{len(blacklist)} blacklist rule(s) matched.")
        if lexical:
            flags.append(f"{len(lexical)} lexical heuristic(s) triggered.")
        flags.append(
            "Static + DNSBL analysis only — does not replace VirusTotal or live sandboxing."
        )
        return flags
