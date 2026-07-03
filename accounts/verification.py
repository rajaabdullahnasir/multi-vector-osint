"""
Email verification token handling — URL-safe tokens and normalization.
"""

from __future__ import annotations

import re
import secrets
from urllib.parse import unquote

from django.http import HttpRequest
from django.urls import reverse

# Hex tokens avoid copy/paste issues with '_' and '-' from token_urlsafe.
TOKEN_PATTERN = re.compile(r"^[a-f0-9]{48}$", re.IGNORECASE)
LEGACY_URLSAFE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{40,64}$")


def generate_verification_token() -> str:
    return secrets.token_hex(24)


def normalize_verification_token(raw: str | None) -> str:
    if not raw:
        return ""
    token = unquote(raw.strip())
    # Strip trailing punctuation from broken copy/paste (email clients, terminals).
    return token.rstrip(".,;)>]}\"'")
    # Note: do not strip '_' or '-' — they are valid in legacy urlsafe tokens.


def is_token_format_valid(token: str) -> bool:
    if not token:
        return False
    return bool(TOKEN_PATTERN.match(token) or LEGACY_URLSAFE_PATTERN.match(token))


def build_verification_url(request: HttpRequest, token: str) -> str:
    """
    Prefer query-string URL — survives line wraps and special chars better than long paths.
    """
    path = reverse("accounts:verify_email")
    return request.build_absolute_uri(f"{path}?token={token}")
