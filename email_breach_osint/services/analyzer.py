"""
Email breach check — XposedOrNot check-email, plus Gravatar reverse
lookup and Holehe-style account existence checks under "Email
Intelligence" (SRS-23, SRS-25).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .email_validator import EmailValidator
from .gravatar_client import GravatarClient
from .holehe_client import HoleheStyleChecker
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
    has_gravatar: bool = False
    gravatar_name: str = ""
    accounts_found: list[str] | None = None

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
            "has_gravatar": self.has_gravatar,
            "gravatar_name": self.gravatar_name,
            "accounts_found": self.accounts_found,
        }


class EmailBreachAnalyzer:
    def __init__(self):
        self.validator = EmailValidator()
        self.gravatar_client = GravatarClient()
        self.holehe_checker = HoleheStyleChecker()

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

        # --- Email Intelligence: Gravatar reverse lookup + account checks ---
        gravatar = self.gravatar_client.lookup(email)
        accounts_found: list[str] = []

        if gravatar.success:
            if gravatar.has_avatar or gravatar.has_public_profile:
                sections["Email Intelligence — Gravatar"] = {
                    "Avatar set": "Yes" if gravatar.has_avatar else "No",
                    "Public profile": "Yes" if gravatar.has_public_profile else "No",
                }
                if gravatar.has_public_profile:
                    sections["Email Intelligence — Gravatar"]["Display name"] = gravatar.display_name or "—"
                    sections["Email Intelligence — Gravatar"]["Profile URL"] = gravatar.profile_url or "—"
                    if gravatar.links:
                        sections["Email Intelligence — Gravatar"]["Linked URLs"] = ", ".join(gravatar.links)
                    accounts_found.append("Gravatar (public profile)")
                elif gravatar.has_avatar:
                    accounts_found.append("Gravatar (avatar only)")
            else:
                sections["Email Intelligence — Gravatar"] = {
                    "Result": "No Gravatar avatar or public profile found for this email.",
                }
        else:
            sections["Email Intelligence — Gravatar"] = {"Notice": gravatar.error or "Lookup failed."}

        account_checks = self.holehe_checker.check_all(email)
        check_rows: dict[str, str] = {}
        for check in account_checks:
            if check.registered is True:
                check_rows[check.platform] = f"Registered — {check.detail}" if check.detail else "Registered"
                accounts_found.append(check.platform)
            elif check.registered is False:
                check_rows[check.platform] = "Not registered"
            else:
                check_rows[check.platform] = f"Inconclusive — {check.error}" if check.error else "Inconclusive"
        if check_rows:
            sections["Email Intelligence — Account Checks"] = check_rows
            sections["Email Intelligence — Account Checks"]["Method"] = (
                "Holehe-style: checks a small set of platforms' public "
                "signup/lookup endpoints. Starting set, not comprehensive — "
                "'Inconclusive' means the check itself failed, not that the "
                "account doesn't exist."
            )

        risk_flags = self._derive_risk_flags(result, gravatar, accounts_found)

        return EmailBreachReport(
            success=True,
            email=result.email or email,
            breach_count=breach_count,
            is_pwned=is_pwned,
            sections=sections,
            breaches=breaches_payload,
            risk_flags=risk_flags,
            no_breaches=result.no_breaches,
            has_gravatar=gravatar.has_avatar or gravatar.has_public_profile,
            gravatar_name=gravatar.display_name,
            accounts_found=accounts_found,
        )

    def _derive_risk_flags(
        self, result: BreachCheckResult, gravatar, accounts_found: list[str]
    ) -> list[str]:
        flags: list[str] = []
        if result.no_breaches or result.breach_count == 0:
            flags.append("No known public breaches for this address in XposedOrNot.")
        else:
            flags.append(
                f"Email found in {result.breach_count} breach(es) — rotate passwords and enable MFA."
            )
        if accounts_found:
            flags.append(
                f"Email linked to {len(accounts_found)} public account signal(s): "
                f"{', '.join(accounts_found)} — correlate with other findings for attribution."
            )
        return flags
