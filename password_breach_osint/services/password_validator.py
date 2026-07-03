from __future__ import annotations

from dataclasses import dataclass

from django.conf import settings


def _max_length() -> int:
    return int(getattr(settings, "PASSWORD_BREACH_MAX_LENGTH", 128))


@dataclass(frozen=True)
class PasswordValidationResult:
    ok: bool
    error: str | None = None


class PasswordValidator:
    """Validates input length only — plaintext is never stored."""

    def validate(self, raw: str) -> PasswordValidationResult:
        if raw is None or not str(raw):
            return PasswordValidationResult(ok=False, error="Password is required.")
        if len(raw) > _max_length():
            return PasswordValidationResult(
                ok=False,
                error=f"Password must be at most {_max_length()} characters.",
            )
        return PasswordValidationResult(ok=True)
