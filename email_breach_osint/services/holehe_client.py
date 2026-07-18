"""
Holehe-style email→account-existence checks — small, deliberately
conservative set. The real Holehe project covers ~120 platforms by
reverse-engineering each site's signup/password-reset API response
shape; those contracts change often and undocumented, unverified
guesses from memory risk silently returning wrong answers for a
security tool, which is exactly the failure class this project has
spent real effort eliminating elsewhere.

Only includes checks built on a long-standing, well-documented public
pattern, and treats anything unexpected as inconclusive rather than
guessing. This is intentionally a starting set, not a claim of parity
with Holehe's full platform list.
"""

from __future__ import annotations

from dataclasses import dataclass

import requests

_TIMEOUT = 6.0
_USER_AGENT = "OSINT-Vector-Analyzer-FYP (passive account existence check)"


@dataclass
class AccountCheckResult:
    platform: str
    registered: bool | None  # True / False / None = inconclusive
    detail: str = ""
    error: str | None = None


class HoleheStyleChecker:
    def __init__(self, timeout: float = _TIMEOUT):
        self.timeout = timeout

    def check_all(self, email: str) -> list[AccountCheckResult]:
        return [self._check_duolingo(email)]

    def _check_duolingo(self, email: str) -> AccountCheckResult:
        # Duolingo's public user-lookup-by-email endpoint has been a
        # widely documented example (including in mainstream security
        # coverage) of a signup-adjacent API that discloses registration
        # status and username without authentication.
        try:
            response = requests.get(
                "https://www.duolingo.com/2017-06-30/users",
                params={"email": email},
                timeout=self.timeout,
                headers={"User-Agent": _USER_AGENT},
            )
        except requests.RequestException as exc:
            return AccountCheckResult(
                platform="Duolingo", registered=None,
                error=f"Could not reach Duolingo: {exc}",
            )

        if response.status_code != 200:
            return AccountCheckResult(
                platform="Duolingo", registered=None,
                error=f"Unexpected HTTP {response.status_code} — treating as inconclusive.",
            )

        try:
            data = response.json()
        except ValueError:
            return AccountCheckResult(
                platform="Duolingo", registered=None,
                error="Unexpected response format — treating as inconclusive.",
            )

        users = data.get("users") if isinstance(data, dict) else None
        if users:
            username = users[0].get("username", "") if isinstance(users[0], dict) else ""
            return AccountCheckResult(
                platform="Duolingo", registered=True,
                detail=f"Registered account found (username: {username})." if username else "Registered account found.",
            )
        if users == []:
            return AccountCheckResult(
                platform="Duolingo", registered=False,
                detail="No account registered with this email.",
            )
        return AccountCheckResult(
            platform="Duolingo", registered=None,
            error="Unexpected response shape — treating as inconclusive.",
        )
