"""
Directory Buster orchestrator — validates the target, picks the wordlist
tier, runs the engine, and builds a report with the soft-404 filtering
made fully transparent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .dirbuster_engine import DirBusterEngine
from .target_validator import TargetValidator
from .wordlists import WORDLIST_LABELS, WORDLIST_TIERS


@dataclass
class DirBusterReport:
    success: bool
    target: str = ""
    base_url: str = ""
    host: str = ""
    wordlist_tier: str = ""
    error: str | None = None
    validation_failed: bool = False
    sections: dict[str, Any] | None = None
    found_count: int = 0
    redirect_count: int = 0
    forbidden_count: int = 0
    filtered_count: int = 0
    checked_count: int = 0
    entries: list[dict[str, Any]] | None = None
    risk_flags: list[str] = field(default_factory=list)

    def to_storage_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "target": self.target,
            "base_url": self.base_url,
            "host": self.host,
            "wordlist_tier": self.wordlist_tier,
            "error": self.error,
            "validation_failed": self.validation_failed,
            "sections": self.sections,
            "entries": self.entries,
            "risk_flags": self.risk_flags,
        }


_INTERESTING_LABELS = frozenset(
    {
        "admin", "administrator", "phpmyadmin", "config", "config.php",
        ".env", ".git", ".git/config", "backup", "backup.zip",
        "backup.sql", "wp-config.php", ".aws/credentials", "id_rsa",
        "secrets", "secrets.json", ".env.production", "database.sql",
        "dump.sql",
    }
)


class DirBusterAnalyzer:
    def __init__(self):
        self.validator = TargetValidator()
        self.engine = DirBusterEngine()

    def analyze(self, target_input: str, wordlist_tier: str = "quick") -> DirBusterReport:
        validation = self.validator.validate(target_input)
        if not validation.ok:
            return DirBusterReport(success=False, error=validation.error, validation_failed=True)

        tier = wordlist_tier if wordlist_tier in WORDLIST_TIERS else "quick"
        wordlist = WORDLIST_TIERS[tier]

        result = self.engine.scan(validation.base_url, validation.host, wordlist)

        entries_payload = [e.to_dict() for e in result.entries]

        sections: dict[str, Any] = {
            "Target": {
                "URL": validation.base_url,
                "Host": validation.host,
                "Wordlist": WORDLIST_LABELS.get(tier, tier),
                "Paths checked": str(result.checked_count),
            },
            "Baseline Calibration": (
                {
                    "Soft-404 detected": "Yes",
                    "Baseline status": str(result.baseline_status),
                    "Baseline response size": f"~{result.baseline_length} bytes",
                    "Note": (
                        "This server returns a non-404 response for nonexistent paths "
                        "(common with SPA routing or a catch-all page). Hits matching this "
                        "exact signature are filtered out below as false positives, not "
                        "reported as real findings."
                    ),
                }
                if result.baseline_detected
                else {
                    "Soft-404 detected": "No",
                    "Note": "Server returns a normal 404 for nonexistent paths — no filtering needed.",
                }
            ),
            "Scan Summary": {
                "Found (2xx)": str(len(result.found)),
                "Redirects (3xx)": str(len(result.redirects)),
                "Forbidden (401/403)": str(len(result.forbidden)),
                "Filtered as soft-404": str(len(result.soft_404_filtered)),
                "Errors/timeouts": str(len(result.errored)),
            },
        }

        risk_flags = self._derive_risk_flags(result)

        return DirBusterReport(
            success=True,
            target=target_input,
            base_url=validation.base_url,
            host=validation.host,
            wordlist_tier=tier,
            sections=sections,
            found_count=len(result.found),
            redirect_count=len(result.redirects),
            forbidden_count=len(result.forbidden),
            filtered_count=len(result.soft_404_filtered),
            checked_count=result.checked_count,
            entries=entries_payload,
            risk_flags=risk_flags,
        )

    def _derive_risk_flags(self, result) -> list[str]:
        flags: list[str] = []
        interesting_hits = [
            e for e in result.found + result.forbidden
            if e.path.lower() in _INTERESTING_LABELS
        ]
        if interesting_hits:
            names = ", ".join(sorted({e.path for e in interesting_hits})[:5])
            flags.append(
                f"Path(s) matching common admin/config/credential naming responded: {names}. "
                "A response only confirms a page exists at that path — it does not confirm "
                "the content is actually sensitive (e.g. on user-namespaced sites like GitHub, "
                "'/admin' or '/config' may simply be a registered username). Open each one "
                "manually to verify before treating it as a real exposure."
            )
        if result.forbidden:
            flags.append(
                f"{len(result.forbidden)} path(s) returned 401/403 — they exist but access "
                "is restricted. Still worth reviewing for misconfigured auth."
            )
        if result.baseline_detected:
            flags.append(
                f"Soft-404 behavior detected and {len(result.soft_404_filtered)} false "
                "positive(s) were automatically filtered out — see Baseline Calibration."
            )
        if not result.found and not result.forbidden and not result.baseline_detected:
            flags.append("No accessible paths found from this wordlist tier.")
        return flags
