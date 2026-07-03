"""
Email breach check — XposedOrNot check-email only (SRS-23, SRS-25).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .email_validator import EmailValidator
from .xposedornot_client import BreachCheckResult, check_breached_account


@dataclass
class EmailBreachReport:
    success: bool
    email: str = ""
    error: str | None = None
    validation_failed: bool = False
    breach_count: int = 0
    is_pwned: bool = False
    sections: dict[str, Any] | None = None
    breaches: list[dict[str, Any]] | None = None
    risk_flags: list[str] | None = None
    no_breaches: bool = False

    def to_storage_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "email": self.email,
            "error": self.error,
            "validation_failed": self.validation_failed,
            "breach_count": self.breach_count,
            "is_pwned": self.is_pwned,
            "sections": self.sections,
            "breaches": self.breaches,
            "risk_flags": self.risk_flags,
            "no_breaches": self.no_breaches,
        }


class EmailBreachAnalyzer:
    def __init__(self):
        self.validator = EmailValidator()

    def analyze(self, email_input: str) -> EmailBreachReport:
        validation = self.validator.validate(email_input)
        if not validation.ok:
            return EmailBreachReport(
                success=False,
                error=validation.error,
                validation_failed=True,
            )

        email = validation.email
        sections: dict[str, Any] = {
            "Target": {
                "Email": email,
                "API": "GET /v1/check-email/{email}",
                "Source": "XposedOrNot (free)",
            },
        }

        result: BreachCheckResult = check_breached_account(email)
        if not result.ok:
            return EmailBreachReport(
                success=False,
                email=email,
                error=result.error,
                sections=sections,
            )

        breaches_payload = [b.to_dict() for b in result.breaches]
        breach_count = result.breach_count
        is_pwned = breach_count > 0

        sections["Summary"] = {
            "Breach count": str(breach_count),
            "Status": "Exposed in known breaches" if is_pwned else "No breaches found",
        }
        if result.api_status:
            sections["Summary"]["API status"] = result.api_status

        if is_pwned:
            sections["Breaches"] = {
                f"{i + 1}": name for i, name in enumerate(b.name for b in result.breaches)
            }

        risk_flags = self._derive_risk_flags(result)

        return EmailBreachReport(
            success=True,
            email=result.email or email,
            breach_count=breach_count,
            is_pwned=is_pwned,
            sections=sections,
            breaches=breaches_payload,
            risk_flags=risk_flags,
            no_breaches=result.no_breaches,
        )

    def _derive_risk_flags(self, result: BreachCheckResult) -> list[str]:
        if result.no_breaches or result.breach_count == 0:
            return ["No known public breaches for this address in XposedOrNot."]
        return [
            f"Email found in {result.breach_count} breach(es) — rotate passwords and enable MFA.",
        ]
