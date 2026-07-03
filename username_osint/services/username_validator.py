import re
from dataclasses import dataclass

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9._-]{1,30}[a-zA-Z0-9])?$")
_RESERVED = frozenset(
    {
        "admin",
        "administrator",
        "root",
        "system",
        "null",
        "undefined",
        "test",
        "guest",
        "support",
        "help",
        "api",
        "www",
    }
)


@dataclass(frozen=True)
class UsernameValidationResult:
    ok: bool
    username: str = ""
    error: str | None = None


class UsernameValidator:
    def validate(self, raw: str) -> UsernameValidationResult:
        value = (raw or "").strip()
        if not value:
            return UsernameValidationResult(ok=False, error="Username is required.")
        if len(value) < 3:
            return UsernameValidationResult(ok=False, error="Username must be at least 3 characters.")
        if len(value) > 32:
            return UsernameValidationResult(ok=False, error="Username must be at most 32 characters.")
        if not _USERNAME_RE.match(value):
            return UsernameValidationResult(
                ok=False,
                error=(
                    "Use letters, numbers, dots, hyphens, or underscores. "
                    "Must start and end with a letter or number."
                ),
            )
        if value.lower() in _RESERVED:
            return UsernameValidationResult(ok=False, error="This username cannot be searched.")
        return UsernameValidationResult(ok=True, username=value)
