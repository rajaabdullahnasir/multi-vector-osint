"""
Certificate Transparency lookup via crt.sh with retries and fallbacks.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

_WILDCARD_RE = re.compile(r"^\*\.")
_MAX_RESPONSE_BYTES = 4_000_000
_READ_CHUNK = 65_536
_CONNECT_TIMEOUT = 8.0
_READ_TIMEOUT = 28.0
_RETRIES = 2
_RETRY_DELAY = 1.5


def _build_urls(domain: str) -> list[str]:
    wildcard = f"%.{domain}"
    return [
        f"https://crt.sh/json?q={urllib.parse.quote(domain)}&deduplicate=Y",
        (
            "https://crt.sh/?"
            + urllib.parse.urlencode(
                {
                    "q": wildcard,
                    "output": "json",
                    "deduplicate": "Y",
                    "exclude": "expired",
                }
            )
        ),
        f"https://crt.sh/json?Identity={urllib.parse.quote(domain)}",
    ]


def _normalize_ct_host(raw: str, domain: str, suffix: str) -> str | None:
    if not raw:
        return None
    host = raw.lower().rstrip(".")
    if host == domain:
        return host
    if host.endswith(suffix):
        return host
    if _WILDCARD_RE.match(host) and host[2:].endswith(suffix):
        return host
    return None


def _extract_hosts(rows: list, domain: str, max_hosts: int) -> set[str]:
    hosts: set[str] = set()
    suffix = f".{domain}"
    for row in rows[: max_hosts * 3]:
        if not isinstance(row, dict):
            continue
        names: list[str] = []
        name_value = row.get("name_value") or row.get("common_name") or ""
        if isinstance(name_value, str):
            names.extend(name_value.splitlines())
        for raw in names:
            host = _normalize_ct_host(raw.strip(), domain, suffix)
            if host:
                hosts.add(host)
            if len(hosts) >= max_hosts:
                return hosts
    return hosts


def _read_limited_response(response, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total < max_bytes:
        block = response.read(min(_READ_CHUNK, max_bytes - total))
        if not block:
            break
        chunks.append(block)
        total += len(block)
    return b"".join(chunks)


def _fetch_url(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "OSINT-Vector/1.0 (passive subdomain lookup)",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(
        request, timeout=_CONNECT_TIMEOUT + _READ_TIMEOUT
    ) as response:
        return _read_limited_response(response, _MAX_RESPONSE_BYTES)


def _parse_payload(payload: bytes, domain: str, max_hosts: int) -> set[str]:
    text = payload.decode("utf-8", errors="replace").strip()
    if not text:
        return set()
    rows = json.loads(text)
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list):
        return set()
    return _extract_hosts(rows, domain, max_hosts)


def fetch_ct_hosts(domain: str, *, max_hosts: int = 500) -> tuple[set[str], str | None]:
    """
    Return (hosts, warning). warning is set only when lookup failed or partial.
    """
    last_issue = "Certificate Transparency lookup failed."
    for attempt in range(_RETRIES):
        if attempt:
            time.sleep(_RETRY_DELAY)
        for url in _build_urls(domain):
            try:
                payload = _fetch_url(url)
                hosts = _parse_payload(payload, domain, max_hosts)
                if hosts:
                    return hosts, None
                last_issue = "Certificate Transparency returned no hostnames."
            except urllib.error.HTTPError as exc:
                if exc.code in (502, 503, 429, 504):
                    last_issue = (
                        f"crt.sh temporarily unavailable (HTTP {exc.code})."
                    )
                    continue
                last_issue = f"Certificate Transparency HTTP error {exc.code}."
            except TimeoutError:
                last_issue = "Certificate Transparency lookup timed out."
            except urllib.error.URLError as exc:
                last_issue = f"Certificate Transparency unavailable: {exc.reason}"
            except json.JSONDecodeError:
                last_issue = "Certificate Transparency returned invalid JSON."
            except OSError as exc:
                last_issue = f"Certificate Transparency failed: {exc}"

    return set(), (
        f"{last_issue} DNS probing results are still included."
    )
