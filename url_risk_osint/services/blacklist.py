"""
Static blacklist checks — domains, patterns, and phishing keywords (SRS-28).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

# Curated examples for education/demo — not a live threat feed.
BLOCKED_DOMAINS = frozenset(
    {
        "malware-traffic-analysis.net",
        "phishing.example",
        "evil.com",
        "badguy.ru",
        "stealer-login.xyz",
        "secure-login-verify.top",
        "account-update.click",
        "free-gift-card.win",
    }
)

BLOCKED_DOMAIN_SUFFIXES = (
    ".zip",
    ".mov",
    ".top",
    ".xyz",
    ".click",
    ".loan",
    ".work",
    ".gq",
    ".tk",
    ".ml",
    ".cf",
)

BLOCKED_HOST_SUBSTRINGS = (
    "phish",
    "malware",
    "stealer",
    "keylog",
    "cryptolocker",
)

PATH_KEYWORDS = frozenset(
    {
        "login",
        "signin",
        "sign-in",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "password",
        "banking",
        "wallet",
        "confirm",
        "suspend",
        "unlock",
        "credential",
        "2fa",
        "mfa",
    }
)

SHORTENER_DOMAINS = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "cutt.ly",
        "rebrand.ly",
    }
)

_SUSPICIOUS_REGEX = (
    re.compile(r"login[_-]?secure", re.I),
    re.compile(r"paypal[_-]?security", re.I),
    re.compile(r"apple[_-]?id[_-]?verify", re.I),
    re.compile(r"microsoft[_-]?365[_-]?login", re.I),
)


@dataclass(frozen=True)
class BlacklistHit:
    source: str
    rule: str
    severity: str  # high | medium

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "rule": self.rule,
            "severity": self.severity,
        }


def check_blacklist(url: str) -> list[BlacklistHit]:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    full = url.lower()
    hits: list[BlacklistHit] = []

    if host in BLOCKED_DOMAINS:
        hits.append(
            BlacklistHit(
                source="domain",
                rule=f"Blocked domain: {host}",
                severity="high",
            )
        )

    for suffix in BLOCKED_DOMAIN_SUFFIXES:
        if host.endswith(suffix) or path.endswith(suffix):
            hits.append(
                BlacklistHit(
                    source="tld",
                    rule=f"High-risk TLD or extension: {suffix}",
                    severity="medium",
                )
            )
            break

    for needle in BLOCKED_HOST_SUBSTRINGS:
        if needle in host:
            hits.append(
                BlacklistHit(
                    source="hostname",
                    rule=f"Suspicious hostname contains '{needle}'",
                    severity="high",
                )
            )

    for keyword in PATH_KEYWORDS:
        if keyword in path or keyword in full:
            hits.append(
                BlacklistHit(
                    source="path",
                    rule=f"Phishing-related keyword in URL: '{keyword}'",
                    severity="medium",
                )
            )

    for pattern in _SUSPICIOUS_REGEX:
        if pattern.search(full):
            hits.append(
                BlacklistHit(
                    source="pattern",
                    rule=f"Matches suspicious pattern: {pattern.pattern}",
                    severity="high",
                )
            )

    if host in SHORTENER_DOMAINS:
        hits.append(
            BlacklistHit(
                source="shortener",
                rule=f"URL shortener domain: {host}",
                severity="medium",
            )
        )

    # Deduplicate by rule text
    seen: set[str] = set()
    unique: list[BlacklistHit] = []
    for hit in hits:
        if hit.rule not in seen:
            seen.add(hit.rule)
            unique.append(hit)
    return unique
