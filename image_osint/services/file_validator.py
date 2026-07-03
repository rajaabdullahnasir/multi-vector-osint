"""
Binary-level image validation — does not trust file extensions alone.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import BinaryIO

from django.conf import settings


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    mime_type: str | None = None
    detected_format: str | None = None
    error: str | None = None
    size_bytes: int = 0


class ImageFileValidator:
    """
    Validates uploads against SRS-30 constraints using magic-byte detection.
    """

    MAX_BYTES = property(lambda self: settings.IMAGE_OSINT_MAX_BYTES)
    ALLOWED_MIME = property(lambda self: settings.IMAGE_OSINT_ALLOWED_MIME)

    def validate(self, file_obj: BinaryIO, declared_name: str = "") -> ValidationResult:
        file_obj.seek(0, 2)
        size = file_obj.tell()
        file_obj.seek(0)

        if size == 0:
            return ValidationResult(ok=False, error="Uploaded file is empty.", size_bytes=0)

        if size > settings.IMAGE_OSINT_MAX_BYTES:
            max_mb = settings.IMAGE_OSINT_MAX_BYTES // (1024 * 1024)
            return ValidationResult(
                ok=False,
                error=f"File too large. Maximum size is {max_mb}MB.",
                size_bytes=size,
            )

        header = file_obj.read(32)
        file_obj.seek(0)

        detected = self._detect_format(header)
        if not detected:
            return ValidationResult(
                ok=False,
                error="Unsupported or unrecognized image format. Use JPG, PNG, TIFF, or WebP.",
                size_bytes=size,
            )

        mime = self._format_to_mime(detected)
        if mime not in settings.IMAGE_OSINT_ALLOWED_MIME:
            return ValidationResult(
                ok=False,
                error=f"Format '{detected}' is not permitted for this module.",
                size_bytes=size,
            )

        return ValidationResult(
            ok=True,
            mime_type=mime,
            detected_format=detected,
            size_bytes=size,
        )

    def _detect_format(self, header: bytes) -> str | None:
        if header.startswith(b"\xff\xd8\xff"):
            return "jpeg"
        if header.startswith(b"\x89PNG\r\n\x1a\n"):
            return "png"
        if header[:4] in (b"II*\x00", b"MM\x00*"):
            return "tiff"
        if header[:4] == b"RIFF" and len(header) >= 12 and header[8:12] == b"WEBP":
            return "webp"
        return None

    def _format_to_mime(self, fmt: str) -> str:
        mapping = {
            "jpeg": "image/jpeg",
            "png": "image/png",
            "tiff": "image/tiff",
            "webp": "image/webp",
        }
        return mapping[fmt]
