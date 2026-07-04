"""
RDAP client — the modern successor to WHOIS for IP address registration data.

GET https://rdap.org/ip/{ip} automatically redirects to the correct Regional
Internet Registry (ARIN/RIPE/APNIC/LACNIC/AFRINIC). No API key required.
Docs: https://rdap.org
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import requests
from django.conf import settings

_last_request_at = 0.0


def _api_base() -> str:
    return getattr(settings, "RDAP_API_BASE", "https://rdap.org").rstrip("/")


def _user_agent() -> str:
    return getattr(settings, "RDAP_USER_AGENT", "OSINT-Vector-Analyzer-FYP")


def _min_interval() -> float:
    return float(getattr(settings, "RDAP_MIN_REQUEST_INTERVAL", 1.0))


def _throttle() -> None:
    global _last_request_at
    interval = _min_interval()
    now = time.monotonic()
    wait = interval - (now - _last_request_at)
    if wait > 0:
        time.sleep(wait)
    _last_request_at = time.monotonic()


@dataclass
class RdapResult:
    ok: bool
    network_name: str = ""
    network_range: str = ""
    country: str = ""
    entity_name: str = ""
    remarks: list[str] = field(default_factory=list)
    raw: dict[str, Any] | None = None
    error: str | None = None


class RdapClient:
    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout

    def lookup(self, ip: str) -> RdapResult:
        _throttle()
        url = f"{_api_base()}/ip/{ip}"
        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                headers={"User-Agent": _user_agent(), "Accept": "application/rdap+json"},
            )
        except requests.Timeout:
            return RdapResult(ok=False, error="RDAP request timed out.")
        except requests.RequestException as exc:
            return RdapResult(ok=False, error=f"Could not reach RDAP service: {exc}")

        if response.status_code == 404:
            return RdapResult(ok=False, error="No RDAP registration record found for this IP.")
        if response.status_code >= 400:
            return RdapResult(ok=False, error=f"RDAP service returned HTTP {response.status_code}.")

        try:
            data = response.json()
        except ValueError:
            return RdapResult(ok=False, error="RDAP service returned an unreadable response.")

        network_name = data.get("name", "")
        start = data.get("startAddress", "")
        end = data.get("endAddress", "")
        network_range = f"{start} – {end}" if start and end else ""
        country = data.get("country", "")

        entity_name = ""
        for entity in data.get("entities", []):
            vcard = entity.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) > 1:
                for item in vcard[1]:
                    if isinstance(item, list) and item and item[0] == "fn":
                        entity_name = item[-1]
                        break
            if entity_name:
                break
            handle = entity.get("handle", "")
            if handle and not entity_name:
                entity_name = handle

        remarks = []
        for remark in data.get("remarks", []):
            for line in remark.get("description", []):
                remarks.append(line)

        return RdapResult(
            ok=True,
            network_name=network_name,
            network_range=network_range,
            country=country,
            entity_name=entity_name,
            remarks=remarks[:5],
            raw=data,
        )
