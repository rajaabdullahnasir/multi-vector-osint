from __future__ import annotations

from dataclasses import dataclass

from django.conf import settings

from .hash_engine import ALGORITHMS


def _max_length() -> int:
    return int(getattr(settings, "PASSWORD_HASHER_MAX_INPUT_LENGTH", 256))


@dataclass(frozen=True)
class InputValidationResult:
    ok: bool
    value: str = ""
    error: str | None = None


class PasswordInputValidator:
    def validate_text(self, raw: str, *, field_name: str = "Input") -> InputValidationResult:
        if raw is None:
            return InputValidationResult(ok=False, error=f"{field_name} is required.")
        value = str(raw)
        if not value:
            return InputValidationResult(ok=False, error=f"{field_name} is required.")
        if len(value) > _max_length():
            return InputValidationResult(
                ok=False,
                error=f"{field_name} must be at most {_max_length()} characters.",
            )
        return InputValidationResult(ok=True, value=value)

    def validate_algorithms(self, selected: list[str]) -> InputValidationResult:
        if not selected:
            return InputValidationResult(
                ok=False,
                error="Select at least one algorithm.",
            )
        valid = [a for a in selected if a in ALGORITHMS]
        if not valid:
            return InputValidationResult(
                ok=False,
                error="No valid algorithms selected.",
            )
        return InputValidationResult(ok=True, value=",".join(valid))
