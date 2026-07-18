"""
Directory/file brute-forcing engine with automatic soft-404 baseline
calibration — filters false positives from sites that return a non-404
status for every path (SPA routing, catch-all pages).
"""

from __future__ import annotations

import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import requests

_PROBE_TIMEOUT = 5.0
_WORKERS = 10
_USER_AGENT = "OSINT-Vector-Analyzer-FYP (authorized directory enumeration)"
_BASELINE_PROBES = 3
_CONTENT_LENGTH_TOLERANCE = 32
_MAX_READ_BYTES = 4096

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_FORBIDDEN_STATUSES = frozenset({401, 403})
_NOT_FOUND_STATUSES = frozenset({404, 410})


@dataclass(frozen=True)
class DirEntry:
    path: str
    url: str
    status_code: int | None
    content_length: int
    category: str
    redirect_location: str = ""
    error_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "url": self.url,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "category": self.category,
            "redirect_location": self.redirect_location,
            "error_reason": self.error_reason,
        }


@dataclass
class DirBusterResult:
    success: bool
    host: str = ""
    base_url: str = ""
    checked_count: int = 0
    baseline_detected: bool = False
    baseline_status: int | None = None
    baseline_length: int = 0
    entries: list[DirEntry] = field(default_factory=list)
    error: str | None = None

    @property
    def found(self) -> list[DirEntry]:
        return [e for e in self.entries if e.category == "found"]

    @property
    def redirects(self) -> list[DirEntry]:
        return [e for e in self.entries if e.category == "redirect"]

    @property
    def forbidden(self) -> list[DirEntry]:
        return [e for e in self.entries if e.category == "forbidden"]

    @property
    def soft_404_filtered(self) -> list[DirEntry]:
        return [e for e in self.entries if e.category == "soft_404_filtered"]

    @property
    def errored(self) -> list[DirEntry]:
        return [e for e in self.entries if e.category == "error"]


class DirBusterEngine:
    def __init__(self, timeout: float = _PROBE_TIMEOUT, workers: int = _WORKERS):
        self.timeout = timeout
        self.workers = workers

    def scan(self, base_url: str, host: str, wordlist: tuple[str, ...]) -> DirBusterResult:
        baseline_status, baseline_length, baseline_detected = self._calibrate_baseline(base_url)

        entries: list[DirEntry] = []
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            future_map = {
                executor.submit(
                    self._probe_path, base_url, path, baseline_detected, baseline_status, baseline_length
                ): path
                for path in wordlist
            }
            for future in as_completed(future_map):
                entries.append(future.result())

        order = {path: i for i, path in enumerate(wordlist)}
        entries.sort(key=lambda e: order.get(e.path, 0))

        return DirBusterResult(
            success=True,
            host=host,
            base_url=base_url,
            checked_count=len(wordlist),
            baseline_detected=baseline_detected,
            baseline_status=baseline_status,
            baseline_length=baseline_length,
            entries=entries,
        )

    def _calibrate_baseline(self, base_url: str) -> tuple[int | None, int, bool]:
        statuses: list[int] = []
        lengths: list[int] = []

        for _ in range(_BASELINE_PROBES):
            random_path = "".join(random.choices(string.ascii_lowercase + string.digits, k=24))
            try:
                response = requests.get(
                    f"{base_url}/{random_path}-nonexistent-probe",
                    timeout=self.timeout,
                    headers={"User-Agent": _USER_AGENT},
                    allow_redirects=False,
                    stream=True,
                )
                body = response.raw.read(_MAX_READ_BYTES, decode_content=True)
                response.close()
                statuses.append(response.status_code)
                lengths.append(len(body))
            except requests.RequestException:
                continue

        if not statuses:
            return None, 0, False

        most_common_status = max(set(statuses), key=statuses.count)
        if most_common_status in _NOT_FOUND_STATUSES:
            return most_common_status, 0, False

        avg_length = sum(lengths) // len(lengths) if lengths else 0
        return most_common_status, avg_length, True

    def _probe_path(
        self,
        base_url: str,
        path: str,
        baseline_detected: bool,
        baseline_status: int | None,
        baseline_length: int,
    ) -> DirEntry:
        url = f"{base_url}/{path.lstrip('/')}"
        try:
            response = requests.get(
                url,
                timeout=self.timeout,
                headers={"User-Agent": _USER_AGENT},
                allow_redirects=False,
                stream=True,
            )
            body = response.raw.read(_MAX_READ_BYTES, decode_content=True)
            response.close()
            status = response.status_code
            length = len(body)
        except requests.Timeout:
            return DirEntry(
                path=path, url=url, status_code=None, content_length=0,
                category="error", error_reason="Timed out",
            )
        except requests.RequestException as exc:
            return DirEntry(
                path=path, url=url, status_code=None, content_length=0,
                category="error", error_reason=exc.__class__.__name__,
            )

        if (
            baseline_detected
            and status == baseline_status
            and abs(length - baseline_length) <= _CONTENT_LENGTH_TOLERANCE
        ):
            return DirEntry(
                path=path, url=url, status_code=status, content_length=length,
                category="soft_404_filtered",
            )

        if status in _NOT_FOUND_STATUSES:
            return DirEntry(
                path=path, url=url, status_code=status, content_length=length,
                category="not_found",
            )

        if status in _REDIRECT_STATUSES:
            return DirEntry(
                path=path, url=url, status_code=status, content_length=length,
                category="redirect", redirect_location=response.headers.get("Location", ""),
            )

        if status in _FORBIDDEN_STATUSES:
            return DirEntry(
                path=path, url=url, status_code=status, content_length=length,
                category="forbidden",
            )

        if 200 <= status < 300:
            return DirEntry(
                path=path, url=url, status_code=status, content_length=length,
                category="found",
            )

        return DirEntry(
            path=path, url=url, status_code=status, content_length=length,
            category="not_found",
        )
