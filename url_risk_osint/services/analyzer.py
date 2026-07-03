"""
URL risk analysis orchestrator (SRS-28–29).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .blacklist import check_blacklist
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
        assessment = score_risk(lexical, blacklist)

        sections: dict[str, Any] = {
            "Target": {
                "URL": url,
                "Method": "Lexical analysis + static blacklist",
            },
            "Summary": {
                "Risk level": assessment.risk_level.title(),
                "Risk score": str(assessment.risk_score),
                "Lexical score": str(assessment.lexical_score),
                "Blacklist score": str(assessment.blacklist_score),
                "Lexical findings": str(len(lexical)),
                "Blacklist hits": str(len(blacklist)),
            },
        }

        risk_flags = self._derive_risk_flags(assessment.risk_level, lexical, blacklist)

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

    def _derive_risk_flags(self, level: str, lexical, blacklist) -> list[str]:
        flags: list[str] = []
        if level == RISK_DANGEROUS:
            flags.append("High risk — avoid visiting; possible phishing or malware.")
        elif level == RISK_SUSPICIOUS:
            flags.append("Suspicious indicators present — verify destination before use.")
        else:
            flags.append("No strong risk indicators from lexical/blacklist checks.")
        if blacklist:
            flags.append(f"{len(blacklist)} blacklist rule(s) matched.")
        if lexical:
            flags.append(f"{len(lexical)} lexical heuristic(s) triggered.")
        flags.append(
            "Static analysis only — does not replace VirusTotal or live sandboxing."
        )
        return flags
