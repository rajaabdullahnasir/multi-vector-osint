"""
Minimal ICC color profile summary parser (no third-party deps).
"""

from __future__ import annotations

import struct
from typing import Any


def _fourcc(data: bytes, offset: int = 0) -> str:
    raw = data[offset : offset + 4]
    return raw.decode("latin-1", errors="replace").strip()


def _decode_text(data: bytes) -> str:
    try:
        return data.decode("utf-8", errors="replace").strip("\x00")
    except Exception:
        return data.hex()


def parse_icc_profile(profile_bytes: bytes) -> dict[str, str]:
    if not profile_bytes or len(profile_bytes) < 128:
        return {}

    header = profile_bytes[:128]
    result: dict[str, str] = {}

    size = struct.unpack(">I", header[0:4])[0]
    result["Profile Size"] = str(size)
    result["Profile CMM Type"] = _fourcc(header, 4) or "Unknown"
    major, minor, patch = header[8], header[9], header[10]
    result["Profile Version"] = f"{major}.{minor}.{patch}"
    result["Profile Class"] = _profile_class(_fourcc(header, 12))
    result["Color Space Data"] = _color_space(_fourcc(header, 16))
    result["Profile Connection Space"] = _color_space(_fourcc(header, 20))

    try:
        year = struct.unpack(">H", header[24:26])[0]
        month, day = header[26], header[27]
        hour, minute, second = header[28], header[29], header[30]
        result["Profile Date Time"] = f"{year:04d}:{month:02d}:{day:02d} {hour:02d}:{minute:02d}:{second:02d}"
    except Exception:
        pass

    result["Profile File Signature"] = _fourcc(header, 36)
    result["Primary Platform"] = _fourcc(header, 40) or "Unknown"
    flags = struct.unpack(">I", header[44:48])[0]
    result["CMM Flags"] = "Embedded" if flags & 1 else "Not Embedded"
    result["Device Manufacturer"] = _fourcc(header, 48) or "Unknown"
    result["Device Model"] = _fourcc(header, 52) or "Unknown"
    result["Rendering Intent"] = _rendering_intent(struct.unpack(">I", header[64:68])[0])

    # Tag table for description / copyright
    if len(profile_bytes) >= 132:
        tag_count = struct.unpack(">I", profile_bytes[128:132])[0]
        offset = 132
        for _ in range(min(tag_count, 64)):
            if offset + 12 > len(profile_bytes):
                break
            sig, tag_offset, tag_size = struct.unpack(">4sII", profile_bytes[offset : offset + 12])
            offset += 12
            sig_str = sig.decode("latin-1", errors="replace")
            if tag_offset + tag_size > len(profile_bytes):
                continue
            tag_data = profile_bytes[tag_offset : tag_offset + tag_size]
            parsed = _parse_icc_tag(sig_str, tag_data)
            if parsed:
                result.update(parsed)

    return result


def _parse_icc_tag(signature: str, data: bytes) -> dict[str, str]:
    if len(data) < 8:
        return {}
    tag_type = _fourcc(data)
    payload = data[8:]

    if signature == "desc" and tag_type == "mluc" and len(payload) >= 12:
        count = struct.unpack(">I", payload[:4])[0]
        if count > 0:
            text_start = 12
            if text_start < len(payload):
                return {"Profile Description": _decode_text(payload[text_start:])}
    if signature == "desc" and tag_type == "text":
        return {"Profile Description": _decode_text(payload)}

    if signature == "cprt" and tag_type == "text":
        return {"Profile Copyright": _decode_text(payload)}

    if signature == "wtpt" and len(payload) >= 12:
        x, y, z = struct.unpack(">III", payload[:12])
        return {"Media White Point": f"{x / 65536:.5f} {y / 65536:.5f} {z / 65536:.5f}"}

    if signature in ("rXYZ", "gXYZ", "bXYZ") and len(payload) >= 12:
        x, y, z = struct.unpack(">III", payload[:12])
        label = {"rXYZ": "Red Matrix Column", "gXYZ": "Green Matrix Column", "bXYZ": "Blue Matrix Column"}[signature]
        return {label: f"{x / 65536:.5f} {y / 65536:.5f} {z / 65536:.5f}"}

    return {}


def _profile_class(code: str) -> str:
    mapping = {
        "scnr": "Input Device Profile",
        "mntr": "Display Device Profile",
        "prtr": "Output Device Profile",
        "link": "DeviceLink Profile",
        "spac": "ColorSpace Conversion Profile",
        "abst": "Abstract Profile",
        "nmcl": "NamedColor Profile",
    }
    return mapping.get(code, code or "Unknown")


def _color_space(code: str) -> str:
    mapping = {"RGB": "RGB", "GRAY": "Gray", "CMYK": "CMYK", "XYZ": "XYZ", "Lab": "Lab"}
    return mapping.get(code, code or "Unknown")


def _rendering_intent(value: int) -> str:
    intents = ["Perceptual", "Media-Relative Colorimetric", "Saturation", "ICC-Absolute Colorimetric"]
    if 0 <= value < len(intents):
        return intents[value]
    return str(value)
