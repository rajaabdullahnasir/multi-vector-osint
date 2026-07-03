"""
Decode raw EXIF values to human-readable strings (ExifTool-style).
"""

from __future__ import annotations

from typing import Any

ORIENTATION = {
    0: "Unknown (0)",
    1: "Horizontal (normal)",
    2: "Mirror horizontal",
    3: "Rotate 180",
    4: "Mirror vertical",
    5: "Mirror horizontal and rotate 270 CW",
    6: "Rotate 90 CW",
    7: "Mirror horizontal and rotate 90 CW",
    8: "Rotate 270 CW",
}

RESOLUTION_UNIT = {1: "None", 2: "inches", 3: "centimeters"}

EXPOSURE_PROGRAM = {
    0: "Not Defined",
    1: "Manual",
    2: "Program AE",
    3: "Aperture-priority AE",
    4: "Shutter speed priority AE",
    5: "Creative (Slow speed)",
    6: "Action (High speed)",
    7: "Portrait",
    8: "Landscape",
    9: "Bulb",
}

METERING_MODE = {
    0: "Unknown",
    1: "Average",
    2: "Center-weighted average",
    3: "Spot",
    4: "Multi-spot",
    5: "Pattern",
    6: "Partial",
    255: "Other",
}

LIGHT_SOURCE = {
    0: "Unknown",
    1: "Daylight",
    2: "Fluorescent",
    3: "Tungsten (Incandescent)",
    4: "Flash",
    9: "Fine Weather",
    10: "Cloudy",
    11: "Shade",
    12: "Daylight Fluorescent",
    13: "Day White Fluorescent",
    14: "Cool White Fluorescent",
    15: "White Fluorescent",
    17: "Standard Light A",
    18: "Standard Light B",
    19: "Standard Light C",
    20: "D55",
    21: "D65",
    22: "D75",
    23: "D50",
    24: "ISO Studio Tungsten",
    255: "Other",
}

WHITE_BALANCE = {0: "Auto", 1: "Manual"}

EXPOSURE_MODE = {0: "Auto", 1: "Manual", 2: "Auto bracket"}

SCENE_CAPTURE_TYPE = {
    0: "Standard",
    1: "Landscape",
    2: "Portrait",
    3: "Night",
}

SCENE_TYPE = {1: "Directly photographed"}

COLOR_SPACE = {1: "sRGB", 65535: "Uncalibrated"}

SENSITIVITY_TYPE = {
    0: "Unknown",
    1: "Standard Output Sensitivity (SOS)",
    2: "Recommended Exposure Index (REI)",
    3: "ISO Speed",
}


def decode_tag_value(tag_name: str, value: Any) -> str:
    if value is None:
        return ""

    if tag_name == "Orientation":
        return ORIENTATION.get(int(value) if str(value).isdigit() else 0, str(value))
    if tag_name == "ResolutionUnit":
        return RESOLUTION_UNIT.get(int(value), str(value))
    if tag_name == "ExposureProgram":
        return EXPOSURE_PROGRAM.get(int(value), str(value))
    if tag_name == "MeteringMode":
        return METERING_MODE.get(int(value), str(value))
    if tag_name == "LightSource":
        return LIGHT_SOURCE.get(int(value), str(value))
    if tag_name == "WhiteBalance":
        return WHITE_BALANCE.get(int(value), str(value))
    if tag_name == "ExposureMode":
        return EXPOSURE_MODE.get(int(value), str(value))
    if tag_name == "SceneCaptureType":
        return SCENE_CAPTURE_TYPE.get(int(value), str(value))
    if tag_name == "SceneType" and isinstance(value, bytes):
        return SCENE_TYPE.get(value[0], value.hex())
    if tag_name == "ColorSpace":
        try:
            return COLOR_SPACE.get(int(value), str(value))
        except (TypeError, ValueError):
            return str(value)
    if tag_name == "SensitivityType":
        return SENSITIVITY_TYPE.get(int(value), str(value))
    if tag_name == "Flash":
        return _decode_flash(value)
    if tag_name in (
        "ExposureTime",
        "FNumber",
        "FocalLength",
        "DigitalZoomRatio",
        "BrightnessValue",
        "ShutterSpeedValue",
        "ApertureValue",
        "MaxApertureValue",
        "ExposureBiasValue",
    ):
        return _decode_rational(value)
    if tag_name in ("ExifVersion", "FlashpixVersion", "InteroperabilityVersion"):
        if isinstance(value, bytes):
            return ".".join(str(b) for b in value)
    if tag_name == "ComponentsConfiguration" and isinstance(value, bytes):
        parts = []
        mapping = {1: "Y", 2: "Cb", 3: "Cr", 4: "R", 5: "G", 6: "B"}
        for b in value:
            parts.append(mapping.get(b, "-"))
        return ", ".join(parts)
    if tag_name == "UserComment" and isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace").strip("\x00")
        return text if text.isprintable() else value.hex()[:120]

    return ""  # caller uses generic stringify


def _decode_rational(value: Any) -> str:
    if isinstance(value, tuple) and len(value) == 2:
        num, den = value
        if den == 0:
            return str(num)
        result = num / den
        if 0 < result < 1:
            denom = max(1, round(den / num))
            return f"1/{denom}"
        if result >= 10:
            return str(int(round(result)))
        if abs(result - round(result)) < 0.05:
            return str(int(round(result)))
        return f"{result:.1f}"
    return str(value)


def _decode_flash(value: Any) -> str:
    try:
        v = int(value)
    except (TypeError, ValueError):
        return str(value)
    fired = "Fired" if v & 1 else "Off, Did not fire"
    return fired
