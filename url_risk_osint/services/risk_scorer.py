"""
Combine lexical findings, blacklist hits, and live DNSBL reputation into a
risk level (SRS-28).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .blacklist import BlacklistHit
from .dnsbl_client import DnsblResult
from .lexical_analyzer import LexicalFinding

RISK_SAFE = "safe"
RISK_SUSPICIOUS = "suspicious"
RISK_DANGEROUS = "dangerous"

THRESHOLD_SUSPICIOUS = 25
THRESHOLD_DANGEROUS = 55

# A live DNSBL listing is a strong, real-time signal — worth more than any
# static heuristic since it reflects current, third-party-verified abuse.
DNSBL_SCORE = 70


@dataclass(frozen=True)
class RiskAssessment:
    risk_level: str
    risk_score: int
    lexical_score: int
    blacklist_score: int
    dnsbl_score: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "lexical_score": self.lexical_score,
            "blacklist_score": self.blacklist_score,
            "dnsbl_score": self.dnsbl_score,
        }


def score_risk(
    lexical: list[LexicalFinding],
    blacklist: list[BlacklistHit],
    dnsbl: DnsblResult | None = None,
) -> RiskAssessment:
    lexical_score = sum(f.score for f in lexical)
    blacklist_score = 0
    for hit in blacklist:
        blacklist_score += 40 if hit.severity == "high" else 20

    dnsbl_score = DNSBL_SCORE if (dnsbl and dnsbl.listed) else 0

    total = min(100, lexical_score + blacklist_score + dnsbl_score)

    if (
        (dnsbl and dnsbl.listed)
        or any(h.severity == "high" for h in blacklist)
        or total >= THRESHOLD_DANGEROUS
    ):
        level = RISK_DANGEROUS
    elif total >= THRESHOLD_SUSPICIOUS or blacklist:
        level = RISK_SUSPICIOUS
    else:
        level = RISK_SAFE

    return RiskAssessment(
        risk_level=level,
        risk_score=total,
        lexical_score=lexical_score,
        blacklist_score=blacklist_score,
        dnsbl_score=dnsbl_score,
    )
