"""
Official company-page presence check across common platforms.

This checks HTTP status of a *guessed* official page URL only — it never
scrapes profile content, connections, posts, or any personal data. It is the
organizational equivalent of the existing Username OSINT module's public
profile-URL check (username_osint), scoped to company/org handles only.

Some platforms (notably LinkedIn) actively block automated HEAD/GET requests
and return non-200 codes even for real pages — this is surfaced as
"unverifiable" rather than a false "not found".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import requests

_USER_AGENT = "OSINT-Vector-Analyzer-FYP (passive footprint scan)"

PLATFORM_PATTERNS: dict[str, str] = {
    "GitHub": "https://github.com/{slug}",
    "LinkedIn (company)": "https://www.linkedin.com/company/{slug}/",
    "X / Twitter": "https://x.com/{slug}",
    "Facebook": "https://www.facebook.com/{slug}",
    "Instagram": "https://www.instagram.com/{slug}/",
    "Crunchbase": "https://www.crunchbase.com/organization/{slug}",
}

# Platforms known to block bots regardless of page existence.
_UNVERIFIABLE_PLATFORMS = {"LinkedIn (company)", "Facebook", "Instagram", "Crunchbase"}


@dataclass
class PlatformCheck:
    platform: str
    url: str
    found: bool
    verifiable: bool
    status_code: int | None = None


@dataclass
class SocialPresenceResult:
    slug: str
    checks: list[PlatformCheck] = field(default_factory=list)

    @property
    def found_count(self) -> int:
        return sum(1 for c in self.checks if c.found)


class SocialPresenceChecker:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def slug_from_domain(self, domain: str) -> str:
        label = domain.split(".")[0]
        slug = re.sub(r"[^a-z0-9-]", "", label.lower())
        return slug or label.lower()

    def check(self, domain: str) -> SocialPresenceResult:
        slug = self.slug_from_domain(domain)
        checks: list[PlatformCheck] = []

        for platform, template in PLATFORM_PATTERNS.items():
            url = template.format(slug=slug)
            verifiable = platform not in _UNVERIFIABLE_PLATFORMS
            status_code = None
            found = False
            try:
                response = requests.get(
                    url,
                    timeout=self.timeout,
                    headers={"User-Agent": _USER_AGENT},
                    allow_redirects=True,
                )
                status_code = response.status_code
                if verifiable:
                    found = status_code == 200
                else:
                    # Bot-blocking platforms: treat only a clean 200 as a weak
                    # positive signal; anything else stays "unverifiable".
                    found = status_code == 200
            except requests.RequestException:
                status_code = None

            checks.append(
                PlatformCheck(
                    platform=platform,
                    url=url,
                    found=found,
                    verifiable=verifiable,
                    status_code=status_code,
                )
            )

        return SocialPresenceResult(slug=slug, checks=checks)
