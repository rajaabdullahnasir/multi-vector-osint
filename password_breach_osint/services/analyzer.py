"""
Password breach check — k-anonymity via Pwned Passwords (SRS-29).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .password_validator import PasswordValidator
from .pwned_passwords_client import PwnedPasswordResult, check_password, sha1_hex


@dataclass
class PasswordBreachReport:
    success: bool
    error: str | None = None
    validation_failed: bool = False
    is_pwned: bool = False
    exposure_count: int = 0
    sha1_hash: str = ""
    hash_prefix: str = ""
    sections: dict[str, Any] | None = None
    risk_flags: list[str] | None = None
    k_anonymity_note: str = ""

    def to_storage_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "error": self.error,
            "validation_failed": self.validation_failed,
            "is_pwned": self.is_pwned,
            "exposure_count": self.exposure_count,
            "sha1_hash": self.sha1_hash,
            "hash_prefix": self.hash_prefix,
            "sections": self.sections,
            "risk_flags": self.risk_flags,
            "k_anonymity_note": self.k_anonymity_note,
            "plaintext_stored": False,
        }


class PasswordBreachAnalyzer:
    def __init__(self):
        self.validator = PasswordValidator()

    def analyze(self, password_input: str) -> PasswordBreachReport:
        validation = self.validator.validate(password_input)
        if not validation.ok:
            return PasswordBreachReport(
                success=False,
                error=validation.error,
                validation_failed=True,
            )

        # Hash locally before any network call
        digest = sha1_hex(password_input)
        prefix = digest[:5]

        sections: dict[str, Any] = {
            "Target": {
                "Check type": "Password exposure (k-anonymity)",
                "API": "Pwned Passwords range query",
                "Sent to API": f"First 5 chars of SHA-1 only ({prefix}…)",
            },
        }

        result: PwnedPasswordResult = check_password(password_input)
        if not result.ok:
            return PasswordBreachReport(
                success=False,
                error=result.error,
                sha1_hash=result.sha1_hash,
                hash_prefix=result.hash_prefix,
                sections=sections,
            )

        note = (
            "Password was hashed locally with SHA-1. Only the first 5 hex characters "
            "of the hash were sent to the API. Plaintext is not stored."
        )

        sections["Summary"] = {
            "Exposed": "Yes" if result.is_pwned else "No",
            "Exposure count": str(result.exposure_count),
            "SHA-1 prefix queried": result.hash_prefix,
        }

        risk_flags = self._derive_risk_flags(result)

        return PasswordBreachReport(
            success=True,
            is_pwned=result.is_pwned,
            exposure_count=result.exposure_count,
            sha1_hash=result.sha1_hash,
            hash_prefix=result.hash_prefix,
            sections=sections,
            risk_flags=risk_flags,
            k_anonymity_note=note,
        )

    def _derive_risk_flags(self, result: PwnedPasswordResult) -> list[str]:
        if not result.is_pwned:
            return [
                "Password not found in the Pwned Passwords corpus.",
                "Still use a unique, strong password — absence here does not guarantee safety.",
            ]
        flags = [
            f"Password seen {result.exposure_count:,} time(s) in breach corpuses — change it immediately.",
            "Never reuse this password on any other site.",
        ]
        if result.exposure_count > 100_000:
            flags.append("Extremely common breached password — high credential-stuffing risk.")
        return flags
