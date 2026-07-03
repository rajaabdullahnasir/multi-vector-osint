"""
XposedOrNot free API — check-email only (SRS-22).

GET https://api.xposedornot.com/v1/check-email/{email}

Success: {"breaches": [["Name", ...]], "email": "...", "status": "success"}
Not found: {"Error": "Not found"}

Docs: https://xposedornot.com/api_doc
"""

from __future__ import annotations

import os
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import requests
from django.conf import settings


def _api_base() -> str:
    return getattr(
        settings,
        "XPOSEDORNOT_API_BASE",
        "https://api.xposedornot.com/v1",
    ).rstrip("/")


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
    body: dict[str, Any] | list[Any] | None
    text: str
    error: str | None = None


@dataclass(frozen=True)
class BreachRecord:
    name: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "title": self.name}


@dataclass
class BreachCheckResult:
    ok: bool
    email: str = ""
    breaches: list[BreachRecord] = field(default_factory=list)
    error: str | None = None
    no_breaches: bool = False
    api_status: str = ""
    request: HttpRequest | None = None
    response: HttpResponse | None = None

    @property
    def breach_count(self) -> int:
        return len(self.breaches)


def _user_agent() -> str:
    return getattr(settings, "XPOSEDORNOT_USER_AGENT", "OSINT-Vector-Analyzer-FYP")


def _min_interval() -> float:
    return float(getattr(settings, "XPOSEDORNOT_MIN_REQUEST_INTERVAL", 1.0))


def _http_proxy() -> str | None:
    proxy = getattr(settings, "XPOSEDORNOT_HTTP_PROXY", None) or os.environ.get(
        "XPOSEDORNOT_HTTP_PROXY"
    )
    return proxy.strip() if proxy else None


def is_geo_or_cloudflare_block(status_code: int, text: str) -> bool:
    if status_code != 403:
        return False
    lower = (text or "").lower()
    return (
        "just a moment" in lower
        or "cloudflare" in lower
        or "forbidden" in lower
        or "<!doctype html>" in lower
    )


def geo_block_error_message() -> str:
    return (
        "XposedOrNot returned HTTP 403 from your network (common on Pakistani IPs — "
        "Cloudflare geo-block). The API still works via VPN or a proxy. "
        "Set XPOSEDORNOT_HTTP_PROXY to your VPN proxy URL (e.g. http://127.0.0.1:8080), "
        "or host the open-source API yourself and set XPOSEDORNOT_API_BASE. "
        "See docs/MODULE_04_EMAIL_BREACH.md."
    )


def _throttle() -> None:
    global _last_request_at
    interval = _min_interval()
    now = time.monotonic()
    wait = interval - (now - _last_request_at)
    if wait > 0:
        time.sleep(wait)
    _last_request_at = time.monotonic()


def get(url: str) -> tuple[HttpRequest, HttpResponse]:
    """Simple GET: build request, send, return (req, response)."""
    _throttle()

    req = HttpRequest(
        method="GET",
        url=url,
        headers={
            "User-Agent": _user_agent(),
            "Accept": "application/json",
        },
    )

    proxies = None
    proxy_url = _http_proxy()
    if proxy_url:
        proxies = {"http": proxy_url, "https": proxy_url}

    try:
        resp = requests.get(req.url, headers=req.headers, timeout=25, proxies=proxies)
    except requests.Timeout:
        return req, HttpResponse(
            status_code=0,
            ok=False,
            body=None,
            text="",
            error="XposedOrNot request timed out.",
        )
    except requests.RequestException as exc:
        return req, HttpResponse(
            status_code=0,
            ok=False,
            body=None,
            text="",
            error=f"Could not reach XposedOrNot: {exc}",
        )

    text = resp.text or ""
    body: dict[str, Any] | list[Any] | None = None
    try:
        parsed = resp.json()
        if isinstance(parsed, (dict, list)):
            body = parsed
    except ValueError:
        pass

    if resp.status_code == 429:
        return req, HttpResponse(
            status_code=resp.status_code,
            ok=False,
            body=body,
            text=text,
            error="XposedOrNot rate limit reached. Please wait and try again.",
        )

    if is_geo_or_cloudflare_block(resp.status_code, text):
        return req, HttpResponse(
            status_code=resp.status_code,
            ok=False,
            body=body,
            text=text,
            error=geo_block_error_message(),
        )

    if resp.status_code >= 400:
        if isinstance(body, dict) and body.get("Error"):
            return req, HttpResponse(
                status_code=resp.status_code,
                ok=True,
                body=body,
                text=text,
            )
        return req, HttpResponse(
            status_code=resp.status_code,
            ok=False,
            body=body,
            text=text,
            error=f"XposedOrNot HTTP error {resp.status_code}.",
        )

    return req, HttpResponse(
        status_code=resp.status_code,
        ok=resp.ok,
        body=body,
        text=text,
    )


def _check_email_url(email: str) -> str:
    encoded = urllib.parse.quote(email, safe="")
    return f"{_api_base()}/check-email/{encoded}"


def _is_not_found(data: dict | list | None) -> bool:
    if not isinstance(data, dict):
        return False
    return str(data.get("Error", "")).strip().lower() == "not found"


def _parse_breach_names(data: dict) -> list[str]:
    raw = data.get("breaches") or []
    names: list[str] = []
    for item in raw:
        if isinstance(item, list):
            names.extend(str(x).strip() for x in item if str(x).strip())
        elif isinstance(item, str) and item.strip():
            names.append(item.strip())
    return sorted({n for n in names if n})


def check_breached_account(email: str) -> BreachCheckResult:
    req, resp = get(_check_email_url(email))

    if resp.error:
        return BreachCheckResult(
            ok=False,
            email=email,
            error=resp.error,
            request=req,
            response=resp,
        )

    data = resp.body
    if _is_not_found(data):
        return BreachCheckResult(
            ok=True,
            email=email,
            breaches=[],
            no_breaches=True,
            request=req,
            response=resp,
        )

    if not isinstance(data, dict):
        return BreachCheckResult(
            ok=False,
            email=email,
            error="Unexpected response from XposedOrNot.",
            request=req,
            response=resp,
        )

    if data.get("Error"):
        err = str(data.get("Error"))
        if err.lower() == "not found":
            return BreachCheckResult(
                ok=True,
                email=email,
                breaches=[],
                no_breaches=True,
                request=req,
                response=resp,
            )
        return BreachCheckResult(
            ok=False,
            email=email,
            error=err,
            request=req,
            response=resp,
        )

    names = _parse_breach_names(data)
    api_status = str(data.get("status") or "")

    if not names:
        return BreachCheckResult(
            ok=True,
            email=str(data.get("email") or email),
            breaches=[],
            no_breaches=True,
            api_status=api_status,
            request=req,
            response=resp,
        )

    return BreachCheckResult(
        ok=True,
        email=str(data.get("email") or email),
        breaches=[BreachRecord(name=n) for n in names],
        api_status=api_status,
        request=req,
        response=resp,
    )
