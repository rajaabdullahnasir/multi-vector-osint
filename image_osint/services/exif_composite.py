"""
Computed / composite metadata fields (ExifTool-style derivations).
"""

from __future__ import annotations

import math
from typing import Any


def build_composite(
    flat: dict[str, Any],
    *,
    width: int,
    height: int,
    file_size: int | None = None,
    filename: str = "",
) -> dict[str, str]:
    out: dict[str, str] = {}

    if filename:
        out["Filename"] = filename
    if file_size is not None:
        out["File Size"] = _format_size(file_size)

    if width and height:
        out["Image Size"] = f"{width}x{height}"
        megapixels = (width * height) / 1_000_000
        out["Megapixels"] = f"{megapixels:.1f}"

    fnumber = _parse_float(flat.get("FNumber"))
    if fnumber:
        out["Aperture"] = str(fnumber)

    exposure = flat.get("ExposureTime")
    if exposure is not None:
        out["Shutter Speed"] = _format_exposure(exposure)

    focal = _parse_focal(flat.get("FocalLength"))
    focal_35 = _parse_focal(flat.get("FocalLengthIn35mmFilm"))
    crop_factor = None
    if focal and focal_35 and focal > 0:
        crop_factor = focal_35 / focal
        out["Focal Length"] = f"{focal:.1f} mm (35 mm equivalent: {focal_35:.1f} mm)"
        out["Scale Factor To 35 mm Equivalent"] = f"{crop_factor:.1f}"
    elif focal:
        out["Focal Length"] = f"{focal:.1f} mm"

    for src, label in (
        ("DateTimeOriginal", "Date/Time Original"),
        ("DateTime", "Modify Date"),
        ("DateTimeDigitized", "Create Date"),
    ):
        composite_dt = _datetime_with_subsec(flat, src)
        if composite_dt:
            out[label] = composite_dt

    iso = _parse_float(flat.get("ISOSpeedRatings") or flat.get("PhotographicSensitivity"))
    exposure_s = _parse_float(flat.get("ExposureTime"))
    if fnumber and exposure_s and exposure_s > 0:
        ev = math.log2((fnumber**2) / exposure_s)
        if iso and iso > 0:
            ev -= math.log2(iso / 100)
        out["Light Value"] = f"{ev:.1f}"

    if focal and focal_35 and width and height and focal > 0:
        crop = focal_35 / focal
        sensor_width_mm = 36.0 / crop
        sensor_height_mm = 24.0 / crop
        diag_mm = math.sqrt(sensor_width_mm**2 + sensor_height_mm**2)
        fov_rad = 2 * math.atan(diag_mm / (2 * focal))
        out["Field Of View"] = f"{math.degrees(fov_rad):.1f} deg"
        coc_mm = 0.03 / crop
        out["Circle Of Confusion"] = f"{coc_mm:.3f} mm"
        if fnumber and coc_mm > 0:
            hyperfocal_mm = (focal**2) / (fnumber * coc_mm) + focal
            out["Hyperfocal Distance"] = f"{hyperfocal_mm / 1000:.2f} m"

    return out


def _format_size(num: int) -> str:
    if num < 1024:
        return f"{num} bytes"
    if num < 1024 * 1024:
        return f"{num / 1024:.1f} KB"
    return f"{num / (1024 * 1024):.1f} MB"


def _parse_float(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, tuple) and len(value) == 2:
        num, den = value
        return float(num) / float(den) if den else None
    if hasattr(value, "numerator"):
        return float(value.numerator) / float(value.denominator)
    if isinstance(value, bytes):
        try:
            return float(value.decode().strip())
        except (TypeError, ValueError):
            return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _parse_focal(value: Any) -> float | None:
    return _parse_float(value)


def _format_exposure(value: Any) -> str:
    parsed = _parse_float(value)
    if parsed is None:
        return str(value)
    if parsed >= 1:
        return f"{parsed:.0f}"
    if parsed > 0:
        denom = round(1 / parsed)
        return f"1/{denom}"
    return str(value)


def _datetime_with_subsec(flat: dict[str, Any], field: str) -> str | None:
    base = flat.get(field)
    if not base:
        return None
    if isinstance(base, bytes):
        base = base.decode("utf-8", errors="replace")
    base_str = str(base)
    sub_key = {
        "DateTimeOriginal": "SubSecTimeOriginal",
        "DateTime": "SubsecTime",
        "DateTimeDigitized": "SubSecTimeDigitized",
    }.get(field, "")
    sub = flat.get(sub_key) or flat.get("SubsecTime")
    offset = flat.get("OffsetTimeOriginal") or flat.get("OffsetTime")
    if sub:
        if isinstance(sub, bytes):
            sub = sub.decode("utf-8", errors="replace")
        base_str = f"{base_str}.{sub}"
    if offset:
        if isinstance(offset, bytes):
            offset = offset.decode("utf-8", errors="replace")
        if field in ("DateTimeOriginal", "DateTimeDigitized"):
            base_str = f"{base_str}{offset}"
    return base_str
