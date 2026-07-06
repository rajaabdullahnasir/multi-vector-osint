"""
Username OSINT orchestrator (SRS-26–27).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .platform_checker import PlatformScanResult, scan_username
from .platforms import PLATFORMS
from .username_validator import UsernameValidator


@dataclass
class UsernameOsintReport:
    success: bool
    username: str = ""
    error: str | None = None
    validation_failed: bool = False
    found_count: int = 0
    checked_count: int = 0
    sections: dict[str, Any] | None = None
    platforms: list[dict[str, Any]] | None = None
    risk_flags: list[str] | None = None

    def to_storage_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "username": self.username,
            "error": self.error,
            "validation_failed": self.validation_failed,
            "found_count": self.found_count,
            "checked_count": self.checked_count,
            "sections": self.sections,
            "platforms": self.platforms,
            "risk_flags": self.risk_flags,
        }


class UsernameOsintAnalyzer:
    def __init__(self):
        self.validator = UsernameValidator()

    def analyze(self, username_input: str) -> UsernameOsintReport:
        validation = self.validator.validate(username_input)
        if not validation.ok:
            return UsernameOsintReport(
                success=False,
                error=validation.error,
                validation_failed=True,
            )

        username = validation.username
        sections: dict[str, Any] = {
            "Target": {
                "Username": username,
                "Method": "Passive HTTP profile checks",
                "Platforms scanned": str(len(PLATFORMS)),
            },
        }

        scan: PlatformScanResult = scan_username(username)
        if not scan.success:
            return UsernameOsintReport(
                success=False,
                username=username,
                error=scan.error or "Scan failed.",
                sections=sections,
            )

        platforms_payload = [h.to_dict() for h in scan.hits]
        found_count = scan.found_count
        inconclusive_count = scan.inconclusive_count
        not_found_count = scan.checked_count - found_count - inconclusive_count

        sections["Target"]["Platforms scanned"] = str(scan.checked_count)
        sections["Summary"] = {
            "Profiles found": str(found_count),
            "Confirmed no match": str(not_found_count),
            "Inconclusive (blocked/rate-limited/error)": str(inconclusive_count),
            "Platforms checked": str(scan.checked_count),
            "Status": "Accounts detected" if found_count else "No confirmed profiles found",
        }

        risk_flags = self._derive_risk_flags(username, found_count, inconclusive_count, scan)

        return UsernameOsintReport(
            success=True,
            username=username,
            found_count=found_count,
            checked_count=scan.checked_count,
            sections=sections,
            platforms=platforms_payload,
            risk_flags=risk_flags,
        )

    def _derive_risk_flags(
        self, username: str, found_count: int, inconclusive_count: int, scan: PlatformScanResult
    ) -> list[str]:
        flags: list[str] = []
        if found_count == 0:
            flags.append(
                f"No confirmed public profiles for '{username}' on the platforms that could be checked."
            )
        else:
            flags.append(
                f"Username appears on {found_count} platform(s) — review linked profiles for attribution."
            )
        if inconclusive_count:
            flags.append(
                f"{inconclusive_count} platform(s) blocked the automated check, rate-limited it, "
                "or errored out — these are NOT confirmed as absent and should be checked manually."
            )
        if scan.warnings:
            flags.append(f"{len(scan.warnings)} platform check(s) had unexpected errors.")
        flags.append(
            "Results are heuristic (HTTP status/body). Verify manually before reporting."
        )
        return flags
