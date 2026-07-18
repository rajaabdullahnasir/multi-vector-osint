"""
HTTP liveness probing for discovered subdomains — turns a bare hostname
list into live web-asset intel (status code, page title, server banner).
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

import requests

_MAX_HOSTS_TO_PROBE = 30
_PROBE_TIMEOUT = 4.0
_PROBE_WORKERS = 12
_USER_AGENT = "OSINT-Vector-Analyzer-FYP (passive liveness probe)"
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


@dataclass(frozen=True)
class HttpProbeResult:
    host: str
    live: bool
    scheme: str = ""
    status_code: int | None = None
    title: str = ""
    server: str = ""

    def to_dict(self) -> dict:
        return {
            "http_live": self.live,
            "http_scheme": self.scheme,
            "http_status": self.status_code,
            "http_title": self.title,
            "http_server": self.server,
        }


class HttpProber:
    def __init__(self, timeout: float = _PROBE_TIMEOUT, max_hosts: int = _MAX_HOSTS_TO_PROBE):
        self.timeout = timeout
        self.max_hosts = max_hosts

    def probe_all(self, hosts: list[str]) -> dict[str, HttpProbeResult]:
        targets = hosts[: self.max_hosts]
        results: dict[str, HttpProbeResult] = {}
        if not targets:
            return results

        with ThreadPoolExecutor(max_workers=_PROBE_WORKERS) as executor:
            future_map = {executor.submit(self._probe_one, host): host for host in targets}
            for future in as_completed(future_map):
                host = future_map[future]
                try:
                    results[host] = future.result()
                except Exception:
                    results[host] = HttpProbeResult(host=host, live=False)
        return results

    def _probe_one(self, host: str) -> HttpProbeResult:
        for scheme in ("https", "http"):
            try:
                response = requests.get(
                    f"{scheme}://{host}/",
                    timeout=self.timeout,
                    headers={"User-Agent": _USER_AGENT},
                    allow_redirects=True,
                    stream=True,
                )
                body = next(response.iter_content(chunk_size=8192, decode_unicode=False), b"")
                response.close()

                title_match = _TITLE_RE.search(body.decode("utf-8", errors="ignore"))
                title = title_match.group(1).strip()[:150] if title_match else ""

                return HttpProbeResult(
                    host=host,
                    live=True,
                    scheme=scheme,
                    status_code=response.status_code,
                    title=title,
                    server=response.headers.get("Server", ""),
                )
            except requests.RequestException:
                continue
        return HttpProbeResult(host=host, live=False)
