"""
IP geolocation client — ip-api.com free endpoint (no signup, no API key for
non-commercial use, rate limited to 45 req/min per source IP by the provider).

GET http://ip-api.com/json/{ip}?fields=...
Docs: https://ip-api.com/docs/api:json
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import requests
from django.conf import settings

_last_request_at = 0.0

_FIELDS = ",".join(
    [
        "status",
        "message",
        "country",
        "countryCode",
        "regionName",
        "city",
        "lat",
        "lon",
        "timezone",
        "isp",
        "org",
        "as",
        "proxy",
        "hosting",
        "reverse",
        "query",
    ]
)


def _api_base() -> str:
    return getattr(settings, "IP_GEOLOCATION_API_BASE", "http://ip-api.com/json").rstrip("/")


def _user_agent() -> str:
    return getattr(settings, "IP_GEOLOCATION_USER_AGENT", "OSINT-Vector-Analyzer-FYP")


def _min_interval() -> float:
    return float(getattr(settings, "IP_GEOLOCATION_MIN_REQUEST_INTERVAL", 1.4))


def _throttle() -> None:
    global _last_request_at
    interval = _min_interval()
    now = time.monotonic()
    wait = interval - (now - _last_request_at)
    if wait > 0:
        time.sleep(wait)
    _last_request_at = time.monotonic()


@dataclass
class GeolocationResult:
    ok: bool
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    latitude: float | None = None
    longitude: float | None = None
    timezone: str = ""
    isp: str = ""
    org: str = ""
    asn: str = ""
    is_proxy_or_vpn: bool = False
    is_hosting: bool = False
    reverse_dns: str = ""
    raw: dict[str, Any] | None = None
    error: str | None = None


class IPGeolocationClient:
    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout

    def lookup(self, ip: str) -> GeolocationResult:
        _throttle()
        url = f"{_api_base()}/{ip}?fields={_FIELDS}"
        try:
            response = requests.get(url, timeout=self.timeout, headers={"User-Agent": _user_agent()})
        except requests.Timeout:
            return GeolocationResult(ok=False, error="Geolocation request timed out.")
        except requests.RequestException as exc:
            return GeolocationResult(ok=False, error=f"Could not reach geolocation service: {exc}")

        if response.status_code == 429:
            return GeolocationResult(ok=False, error="Geolocation rate limit reached. Try again shortly.")
        if response.status_code >= 400:
            return GeolocationResult(ok=False, error=f"Geolocation service returned HTTP {response.status_code}.")

        try:
            data = response.json()
        except ValueError:
            return GeolocationResult(ok=False, error="Geolocation service returned an unreadable response.")

        if data.get("status") != "success":
            return GeolocationResult(
                ok=False, error=data.get("message", "Geolocation lookup failed.")
            )

        return GeolocationResult(
            ok=True,
            country=data.get("country", ""),
            country_code=data.get("countryCode", ""),
            region=data.get("regionName", ""),
            city=data.get("city", ""),
            latitude=data.get("lat"),
            longitude=data.get("lon"),
            timezone=data.get("timezone", ""),
            isp=data.get("isp", ""),
            org=data.get("org", ""),
            asn=data.get("as", ""),
            is_proxy_or_vpn=bool(data.get("proxy", False)),
            is_hosting=bool(data.get("hosting", False)),
            reverse_dns=data.get("reverse", ""),
            raw=data,
        )
