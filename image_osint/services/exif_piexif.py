"""
Full JPEG EXIF extraction via piexif (reads all standard IFDs from original file bytes).
"""

from __future__ import annotations

from typing import Any

import piexif
from piexif import ExifIFD, GPSIFD, ImageIFD

try:
    from piexif import InteropIFD
except ImportError:
    InteropIFD = None  # type: ignore[misc, assignment]

from .exif_labels import label_for_tag
from .exif_values import decode_tag_value

# IFD name → (piexif IFD key in dict, tag id → name map builder)
def _ifd_specs() -> list[tuple[str, str, type]]:
    specs: list[tuple[str, str, type]] = [
        ("IFD0", "0th", ImageIFD),
        ("Exif", "Exif", ExifIFD),
        ("GPS", "GPS", GPSIFD),
        ("Thumbnail", "1st", ImageIFD),
    ]
    if InteropIFD is not None:
        specs.insert(3, ("Interop", "Interop", InteropIFD))
    return specs

_TAG_NAME_CACHE: dict[str, dict[int, str]] = {}


def _tag_names(ifd_cls: type) -> dict[int, str]:
    key = ifd_cls.__name__
    if key not in _TAG_NAME_CACHE:
        mapping: dict[int, str] = {}
        for name in dir(ifd_cls):
            if name.startswith("_"):
                continue
            val = getattr(ifd_cls, name, None)
            if isinstance(val, int):
                mapping[val] = name
        _TAG_NAME_CACHE[key] = mapping
    return _TAG_NAME_CACHE[key]


def load_piexif_dict(file_bytes: bytes) -> dict[str, Any] | None:
    try:
        return piexif.load(file_bytes)
    except Exception:
        return None


def extract_from_piexif(
    exif_dict: dict[str, Any],
    *,
    format_value,
) -> tuple[dict[str, Any], dict[str, dict[str, str]], bytes | None]:
    """
    Returns (flat_raw_tags, grouped_sections, exif_bytes_for_endian).
    """
    flat: dict[str, Any] = {}
    grouped: dict[str, dict[str, str]] = {}

    for section_label, ifd_key, ifd_cls in _ifd_specs():
        ifd_data = exif_dict.get(ifd_key)
        if not ifd_data or not isinstance(ifd_data, dict):
            continue
        tag_map = _tag_names(ifd_cls)
        section: dict[str, str] = {}
        for tag_id, value in ifd_data.items():
            tag_name = tag_map.get(tag_id, str(tag_id))
            flat_key = f"GPS_{tag_name}" if ifd_key == "GPS" else tag_name
            flat[flat_key] = value
            display = label_for_tag(flat_key if ifd_key == "GPS" else tag_name)
            section[display] = format_value(tag_name, value)
        if section:
            grouped[section_label] = section

    if exif_dict.get("thumbnail"):
        grouped.setdefault("Thumbnail", {})
        grouped["Thumbnail"]["Thumbnail Data"] = (
            f"{len(exif_dict['thumbnail'])} bytes embedded"
        )

    # MakerNote summary (vendor binary — full parse needs ExifTool)
    maker = flat.get("MakerNote")
    if maker and isinstance(maker, bytes):
        grouped.setdefault("MakerNote", {})
        grouped["MakerNote"]["MakerNote Size"] = f"{len(maker)} bytes"
        grouped["MakerNote"]["MakerNote Preview"] = maker[:64].hex()
        grouped["MakerNote"]["Note"] = (
            "Vendor-specific MakerNote. Standard tags are listed under EXIF."
        )

    return flat, grouped


def detect_exif_byte_order(file_bytes: bytes) -> str:
    marker = file_bytes.find(b"Exif\x00\x00")
    if marker >= 0 and marker + 8 < len(file_bytes):
        endian = file_bytes[marker + 6 : marker + 8]
        if endian == b"II":
            return "Little-endian (Intel, II)"
        if endian == b"MM":
            return "Big-endian (Motorola, MM)"
    return "Unknown"


def decode_user_comment(data: bytes) -> str:
    if len(data) < 8:
        return data.hex()
    encoding = data[:8].rstrip(b"\x00")
    payload = data[8:]
    enc = encoding.decode("ascii", errors="replace").upper()
    if enc in ("ASCII", "UNICODE", "JIS", ""):
        try:
            if enc == "UNICODE":
                return payload.decode("utf-16-be", errors="replace").strip("\x00")
            return payload.decode("utf-8", errors="replace").strip("\x00")
        except Exception:
            pass
    return payload.decode("utf-8", errors="replace").strip("\x00") or data.hex()


def format_piexif_value(tag_name: str, value: Any) -> str:
    if tag_name == "UserComment" and isinstance(value, bytes):
        return decode_user_comment(value)
    if tag_name == "MakerNote" and isinstance(value, bytes):
        return f"<binary data, {len(value)} bytes>"
    decoded = decode_tag_value(tag_name, value)
    if decoded:
        return decoded
    if isinstance(value, bytes):
        try:
            text = value.decode("utf-8", errors="replace").strip("\x00")
            if text.isprintable() or text:
                return text
        except Exception:
            pass
        if len(value) <= 32:
            return value.hex()
        return f"{value[:32].hex()}… ({len(value)} bytes)"
    if isinstance(value, tuple):
        if len(value) == 2 and all(isinstance(x, int) for x in value):
            num, den = value
            if den:
                result = num / den
                if 0 < result < 1:
                    return f"1/{max(1, round(den / num))}"
                if result >= 10:
                    return str(int(round(result)))
                return f"{result:.2f}".rstrip("0").rstrip(".")
            return str(num)
        return ", ".join(format_piexif_value(tag_name, v) for v in value)
    return str(value)
