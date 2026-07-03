"""
Lexical URL risk heuristics — structure, encoding, and impersonation signals.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

_IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HEX_ENCODE_RE = re.compile(r"%[0-9a-fA-F]{2}")
_BRAND_KEYWORDS = (
    "paypal",
    "apple",
    "google",
    "microsoft",
    "amazon",
    "facebook",
    "instagram",
    "netflix",
    "binance",
    "coinbase",
)


@dataclass(frozen=True)
class LexicalFinding:
    category: str
    description: str
    score: int

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "description": self.description,
            "score": self.score,
        }


def analyze_lexical(url: str) -> list[LexicalFinding]:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    findings: list[LexicalFinding] = []

    if parsed.scheme == "http":
        findings.append(
            LexicalFinding(
                category="transport",
                description="Uses HTTP (no TLS encryption)",
                score=15,
            )
        )

    if len(url) > 120:
        findings.append(
            LexicalFinding(
                category="length",
                description=f"Very long URL ({len(url)} characters)",
                score=10,
            )
        )
    elif len(url) > 75:
        findings.append(
            LexicalFinding(
                category="length",
                description=f"Long URL ({len(url)} characters)",
                score=5,
            )
        )

    if _IP_HOST_RE.match(host):
        findings.append(
            LexicalFinding(
                category="host",
                description="Host is a raw IP address instead of a domain name",
                score=20,
            )
        )

    if host.startswith("xn--") or "xn--" in host:
        findings.append(
            LexicalFinding(
                category="host",
                description="Punycode domain (possible homograph attack)",
                score=25,
            )
        )

    label_count = host.count(".")
    if label_count >= 4:
        findings.append(
            LexicalFinding(
                category="host",
                description=f"Many subdomains ({label_count} dots in host)",
                score=15,
            )
        )
    elif label_count == 3:
        findings.append(
            LexicalFinding(
                category="host",
                description="Multiple subdomains in hostname",
                score=8,
            )
        )

    if host.count("-") >= 3:
        findings.append(
            LexicalFinding(
                category="host",
                description="Many hyphens in domain (common in phishing)",
                score=10,
            )
        )

    digit_ratio = sum(c.isdigit() for c in host) / max(len(host), 1)
    if digit_ratio > 0.35:
        findings.append(
            LexicalFinding(
                category="host",
                description="High proportion of digits in hostname",
                score=12,
            )
        )

    encode_count = len(_HEX_ENCODE_RE.findall(url))
    if encode_count >= 6:
        findings.append(
            LexicalFinding(
                category="encoding",
                description=f"Heavy percent-encoding ({encode_count} sequences)",
                score=15,
            )
        )

    if "//" in path.replace("//", "", 1):
        findings.append(
            LexicalFinding(
                category="path",
                description="Double slashes in path (obfuscation)",
                score=10,
            )
        )

    segments = [s for s in path.split("/") if s]
    if len(segments) >= 5:
        findings.append(
            LexicalFinding(
                category="path",
                description=f"Deep path ({len(segments)} segments)",
                score=8,
            )
        )

    query_params = parse_qs(parsed.query)
    if len(query_params) >= 5:
        findings.append(
            LexicalFinding(
                category="query",
                description=f"Many query parameters ({len(query_params)})",
                score=8,
            )
        )

    if parsed.port and parsed.port not in (80, 443):
        findings.append(
            LexicalFinding(
                category="port",
                description=f"Non-standard port :{parsed.port}",
                score=12,
            )
        )

    def _official_brand_host(brand: str) -> bool:
        return (
            host == f"{brand}.com"
            or host == f"www.{brand}.com"
            or host.endswith(f".{brand}.com")
        )

    for brand in _BRAND_KEYWORDS:
        if brand in host and not _official_brand_host(brand):
            findings.append(
                LexicalFinding(
                    category="impersonation",
                    description=f"Brand keyword '{brand}' in hostname (possible impersonation)",
                    score=18,
                )
            )
        elif brand in path.lower() and not _official_brand_host(brand):
            findings.append(
                LexicalFinding(
                    category="impersonation",
                    description=f"Brand keyword '{brand}' in path on non-official host",
                    score=14,
                )
            )

    if re.search(r"\d{4,}", host):
        findings.append(
            LexicalFinding(
                category="host",
                description="Long numeric sequence in hostname",
                score=8,
            )
        )

    return findings
