"""
Pwned Passwords k-anonymity client (SRS-29).

Same flow as the reference C# implementation:
  1. SHA1(password) -> uppercase hex string
  2. prefix = hash[0:5], suffix = hash[5:]
  3. GET https://api.pwnedpasswords.com/range/{prefix}
  4. is_pwned = response contains suffix (then read exposure count from that line)

Only the 5-character prefix is sent over the network.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any

import requests
from django.conf import settings

_last_request_at = 0.0


@dataclass(frozen=True)
class HttpRequest:
    method: str
    url: str
    headers: dict[str, str]


@dataclass
class HttpResponse:
    status_code: int
    ok: bool
    text: str
    error: str | None = None


@dataclass
class PwnedPasswordResult:
    ok: bool
    is_pwned: bool = False
    exposure_count: int = 0
    sha1_hash: str = ""
    hash_prefix: str = ""
    hash_suffix: str = ""
    error: str | None = None
    request: HttpRequest | None = None
    response: HttpResponse | None = None

    def to_storage_dict(self) -> dict[str, Any]:
        return {
            "is_pwned": self.is_pwned,
            "exposure_count": self.exposure_count,
            "hash_prefix": self.hash_prefix,
            "hash_suffix": self.hash_suffix,
            "sha1_hash": self.sha1_hash,
            "k_anonymity": "SHA-1 range (prefix sent to api.pwnedpasswords.com only)",
        }


def _api_base() -> str:
    return getattr(
        settings,
        "PWNED_PASSWORDS_API_BASE",
        "https://api.pwnedpasswords.com/range",
    ).rstrip("/")


def _user_agent() -> str:
    return getattr(
        settings,
        "PWNED_PASSWORDS_USER_AGENT",
        "OSINT-Vector-Analyzer-FYP",
    )


def _min_interval() -> float:
    return float(getattr(settings, "PWNED_PASSWORDS_MIN_REQUEST_INTERVAL", 1.6))


def _throttle() -> None:
    global _last_request_at
    interval = _min_interval()
    now = time.monotonic()
    wait = interval - (now - _last_request_at)
    if wait > 0:
        time.sleep(wait)
    _last_request_at = time.monotonic()


def sha1_hex(password: str) -> str:
    """SHA1 UTF-8 bytes -> uppercase hex (matches C# BitConverter.ToString, no dashes)."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def split_hash(hash_hex: str) -> tuple[str, str]:
    """prefix = first 5 chars, suffix = remainder (C# Substring)."""
    digest = hash_hex.upper()
    return digest[:5], digest[5:]


def get(url: str) -> tuple[HttpRequest, HttpResponse]:
    _throttle()
    req = HttpRequest(
        method="GET",
        url=url,
        headers={"User-Agent": _user_agent()},
    )
    try:
        resp = requests.get(req.url, headers=req.headers, timeout=20)
    except requests.Timeout:
        return req, HttpResponse(0, False, "", error="Pwned Passwords request timed out.")
    except requests.RequestException as exc:
        return req, HttpResponse(0, False, "", error=f"Could not reach Pwned Passwords: {exc}")

    if resp.status_code == 429:
        return req, HttpResponse(
            resp.status_code,
            False,
            resp.text,
            error="Rate limit reached. Please wait and try again.",
        )

    if resp.status_code >= 400:
        return req, HttpResponse(
            resp.status_code,
            False,
            resp.text,
            error=f"Pwned Passwords HTTP error {resp.status_code}.",
        )

    return req, HttpResponse(resp.status_code, resp.ok, resp.text or "")


def response_contains_suffix(response_text: str, suffix: str) -> bool:
    """C#: response.Contains(suffix) — API lines use uppercase hex suffixes."""
    return suffix.upper() in response_text.upper()


def exposure_count_for_suffix(response_text: str, suffix: str) -> int:
    """Read COUNT from the matching SUFFIX:COUNT line when present."""
    target = suffix.upper()
    for line in response_text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        hash_suffix, _, count_str = line.partition(":")
        if hash_suffix.upper() == target:
            try:
                return int(count_str)
            except ValueError:
                return 0
    return 0


def check_password(password: str) -> PwnedPasswordResult:
    # SHA1 hash
    digest = sha1_hex(password)
    prefix, suffix = split_hash(digest)

    url = f"{_api_base()}/{prefix}"
    req, resp = get(url)
    if resp.error:
        return PwnedPasswordResult(
            ok=False,
            sha1_hash=digest,
            hash_prefix=prefix,
            hash_suffix=suffix,
            error=resp.error,
            request=req,
            response=resp,
        )

    is_pwned = response_contains_suffix(resp.text, suffix)
    count = exposure_count_for_suffix(resp.text, suffix) if is_pwned else 0

    return PwnedPasswordResult(
        ok=True,
        is_pwned=is_pwned,
        exposure_count=count,
        sha1_hash=digest,
        hash_prefix=prefix,
        hash_suffix=suffix,
        request=req,
        response=resp,
    )
