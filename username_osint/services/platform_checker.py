"""
Parallel HTTP checks against public profile URLs (passive OSINT).
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

import requests
from django.conf import settings

from .platforms import PLATFORMS, Platform

_last_batch_at = 0.0


@dataclass(frozen=True)
class PlatformHit:
    platform: str
    category: str
    url: str
    status_code: int
    found: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "category": self.category,
            "url": self.url,
            "status_code": self.status_code,
            "found": self.found,
        }


@dataclass
class PlatformScanResult:
    success: bool
    username: str = ""
    hits: list[PlatformHit] = field(default_factory=list)
    checked_count: int = 0
    error: str | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def found_count(self) -> int:
        return sum(1 for h in self.hits if h.found)


def _user_agent() -> str:
    return getattr(settings, "USERNAME_OSINT_USER_AGENT", "OSINT-Vector-Analyzer-FYP")


def _timeout() -> float:
    return float(getattr(settings, "USERNAME_OSINT_REQUEST_TIMEOUT", 8.0))


def _max_workers() -> int:
    return int(getattr(settings, "USERNAME_OSINT_MAX_WORKERS", 10))


def _throttle_batch() -> None:
    global _last_batch_at
    interval = float(getattr(settings, "USERNAME_OSINT_MIN_BATCH_INTERVAL", 0.5))
    now = time.monotonic()
    wait = interval - (now - _last_batch_at)
    if wait > 0:
        time.sleep(wait)
    _last_batch_at = time.monotonic()


def _profile_url(platform: Platform, username: str) -> str:
    return platform.url_template.format(username=username)


def _check_one(platform: Platform, username: str) -> PlatformHit:
    url = _profile_url(platform, username)
    headers = {
        "User-Agent": _user_agent(),
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
    }
    status_code = 0
    text = ""

    try:
        resp = requests.get(
            url,
            headers=headers,
            timeout=_timeout(),
            allow_redirects=True,
        )
        status_code = resp.status_code
        text = (resp.text or "")[:120_000].lower()
    except requests.Timeout:
        return PlatformHit(
            platform=platform.name,
            category=platform.category,
            url=url,
            status_code=0,
            found=False,
        )
    except requests.RequestException:
        return PlatformHit(
            platform=platform.name,
            category=platform.category,
            url=url,
            status_code=0,
            found=False,
        )

    if status_code in platform.not_found_status:
        return PlatformHit(
            platform=platform.name,
            category=platform.category,
            url=url,
            status_code=status_code,
            found=False,
        )

    if platform.not_found_phrases and any(p in text for p in platform.not_found_phrases):
        return PlatformHit(
            platform=platform.name,
            category=platform.category,
            url=url,
            status_code=status_code,
            found=False,
        )

    if platform.found_phrases:
        found = any(p in text for p in platform.found_phrases)
        return PlatformHit(
            platform=platform.name,
            category=platform.category,
            url=url,
            status_code=status_code,
            found=found and status_code in platform.exists_status,
        )

    found = status_code in platform.exists_status
    return PlatformHit(
        platform=platform.name,
        category=platform.category,
        url=url,
        status_code=status_code,
        found=found,
    )


def scan_username(username: str) -> PlatformScanResult:
    _throttle_batch()
    platforms = PLATFORMS
    hits: list[PlatformHit] = []
    warnings: list[str] = []

    workers = min(_max_workers(), len(platforms))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_check_one, platform, username): platform
            for platform in platforms
        }
        for future in as_completed(futures):
            try:
                hits.append(future.result())
            except Exception as exc:
                platform = futures[future]
                warnings.append(f"{platform.name}: {exc}")

    hits.sort(key=lambda h: (not h.found, h.platform.lower()))
    return PlatformScanResult(
        success=True,
        username=username,
        hits=hits,
        checked_count=len(platforms),
        warnings=warnings,
    )
