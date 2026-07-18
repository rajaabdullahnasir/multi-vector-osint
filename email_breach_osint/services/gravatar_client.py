"""
Gravatar reverse email lookup — the free, no-key technique that products
like Epieos build on top of (Epieos itself is a paid commercial API we
don't have a key for, so this implements the underlying public method
directly rather than pretending to wrap the product).

Two independent signals, both public, no authentication:
1. Avatar existence: GET /avatar/{md5}?d=404 — 200 means an image is
   set for this email (a real signal the email is a real, used account
   somewhere), 404 means none is set.
2. Public profile JSON: GET /{md5}.json — if the account has a public
   Gravatar profile, returns name/bio/links; many accounts have an
   avatar but no public profile, which is itself an honest, separate
   result, not an error.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

import requests

_TIMEOUT = 6.0
_USER_AGENT = "OSINT-Vector-Analyzer-FYP (passive reverse email lookup)"


@dataclass
class GravatarResult:
    success: bool
    email_hash: str = ""
    has_avatar: bool = False
    has_public_profile: bool = False
    display_name: str = ""
    profile_url: str = ""
    links: list[str] = field(default_factory=list)
    error: str | None = None


def _email_hash(email: str) -> str:
    normalized = email.strip().lower().encode("utf-8")
    return hashlib.md5(normalized).hexdigest()  # noqa: S324 — Gravatar's documented identifier, not a security use


class GravatarClient:
    def __init__(self, timeout: float = _TIMEOUT):
        self.timeout = timeout

    def lookup(self, email: str) -> GravatarResult:
        email_hash = _email_hash(email)
        result = GravatarResult(success=True, email_hash=email_hash)

        try:
            avatar_resp = requests.get(
                f"https://www.gravatar.com/avatar/{email_hash}",
                params={"d": "404"},
                timeout=self.timeout,
                headers={"User-Agent": _USER_AGENT},
                allow_redirects=True,
            )
            result.has_avatar = avatar_resp.status_code == 200
        except requests.RequestException as exc:
            return GravatarResult(
                success=False, email_hash=email_hash,
                error=f"Could not reach Gravatar: {exc}",
            )

        try:
            profile_resp = requests.get(
                f"https://www.gravatar.com/{email_hash}.json",
                timeout=self.timeout,
                headers={"User-Agent": _USER_AGENT},
            )
            if profile_resp.status_code == 200:
                data = profile_resp.json()
                entries = data.get("entry") or []
                if entries:
                    entry = entries[0]
                    result.has_public_profile = True
                    result.display_name = entry.get("displayName", "")
                    result.profile_url = entry.get("profileUrl", "")
                    result.links = [
                        url.get("url", "")
                        for url in entry.get("urls", [])
                        if url.get("url")
                    ]
        except (requests.RequestException, ValueError):
            # Profile endpoint being unavailable doesn't invalidate the
            # avatar-existence signal already captured above — degrade
            # gracefully rather than failing the whole lookup.
            pass

        return result
