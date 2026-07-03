"""
EXIF and image metadata extraction engine.

Uses Pillow only as a binary parser; all interpretation, GPS conversion,
section grouping, and presentation logic is implemented in this module.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from fractions import Fraction
from io import BytesIO
from typing import Any

from PIL import ExifTags, Image

from .exif_composite import build_composite
from .exif_labels import label_for_tag
from .exif_piexif import (
    detect_exif_byte_order,
    extract_from_piexif,
    format_piexif_value,
    load_piexif_dict,
)
from .exif_values import decode_tag_value
from .icc_parser import parse_icc_profile
from .jpeg_info import read_jpeg_info

_GPS_TAG_ID: dict[str, int] = {name: tag_id for tag_id, name in ExifTags.GPSTAGS.items()}


def _gps_tag_id(name: str) -> int | None:
    return _GPS_TAG_ID.get(name)


@dataclass
class GpsCoordinates:
    latitude: float | None = None
    longitude: float | None = None
    altitude_meters: float | None = None
    google_maps_url: str | None = None
    raw_ref: dict[str, str] = field(default_factory=dict)


@dataclass
class ExifExtractionResult:
    has_exif: bool
    format: str
    width: int
    height: int
    mode: str
    camera: dict[str, str] = field(default_factory=dict)
    capture: dict[str, str] = field(default_factory=dict)
    image_props: dict[str, str] = field(default_factory=dict)
    software: dict[str, str] = field(default_factory=dict)
    gps: GpsCoordinates | None = None
    png_text: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    tag_count: int = 0
    raw_tags: dict[str, str] = field(default_factory=dict)
    sections: dict[str, dict[str, str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


class ExifExtractor:
    """
    Extracts comprehensive metadata grouped into ExifTool-style sections.
    """

    _CAMERA_TAGS = {"Make", "Model", "LensModel", "LensMake", "LensSpecification", "BodySerialNumber"}
    _CAPTURE_TAGS = {
        "DateTimeOriginal",
        "DateTimeDigitized",
        "DateTime",
        "ExposureTime",
        "FNumber",
        "ISOSpeedRatings",
        "PhotographicSensitivity",
        "FocalLength",
        "Flash",
        "WhiteBalance",
        "Orientation",
    }
    _IMAGE_TAGS = {
        "ImageWidth",
        "ImageLength",
        "XResolution",
        "YResolution",
        "ResolutionUnit",
        "ColorSpace",
        "Compression",
    }
    _SOFTWARE_TAGS = {"Software", "ProcessingSoftware", "HostComputer", "Artist"}

    def extract(
        self,
        file_bytes: bytes,
        *,
        filename: str = "",
        file_size: int | None = None,
    ) -> ExifExtractionResult:
        warnings: list[str] = []
        try:
            image = Image.open(BytesIO(file_bytes))
        except Exception as exc:
            return ExifExtractionResult(
                has_exif=False,
                format="unknown",
                width=0,
                height=0,
                mode="",
                warnings=[f"Could not open image: {exc}"],
            )

        width, height = image.size
        fmt = (image.format or "unknown").lower()
        size = file_size if file_size is not None else len(file_bytes)

        result = ExifExtractionResult(
            has_exif=False,
            format=fmt,
            width=width,
            height=height,
            mode=image.mode,
            warnings=warnings,
        )

        sections: dict[str, dict[str, str]] = {}
        file_section = self._build_file_section(image, fmt, filename, size, width, height)
        if fmt in ("jpeg", "jpg"):
            file_section.update(read_jpeg_info(file_bytes))
        sections["File"] = file_section

        if fmt in ("jpeg", "jpg"):
            result = self._extract_jpeg_piexif(
                file_bytes, image, result, sections, filename, size, width, height
            )
            image.close()
            return result

        if fmt == "png":
            self._extract_png_metadata(image, result, sections)
            sections["Composite"] = build_composite(
                {}, width=width, height=height, file_size=size, filename=filename
            )
            result.sections = sections
            image.close()
            return result

        try:
            exif = image.getexif()
        except Exception:
            exif = None

        icc = image.info.get("icc_profile") if image.info else None
        if icc:
            sections["ICC_Profile"] = {k: v for k, v in parse_icc_profile(icc).items()}

        if not exif:
            result.warnings.append(
                "No EXIF metadata found. The image may have been stripped or edited."
            )
            sections["Composite"] = build_composite(
                {}, width=width, height=height, file_size=size, filename=filename
            )
            result.sections = sections
            image.close()
            return result

        result.has_exif = True
        flat, gps_ifd, grouped = self._extract_all_ifds(exif)
        endian = getattr(exif, "endian", "<")
        byte_order = (
            "Little-endian (Intel, II)" if endian == "<" else "Big-endian (Motorola, MM)"
        )

        exif_section: dict[str, str] = {"Exif Byte Order": byte_order}
        for part in ("IFD0", "Exif", "Interop"):
            exif_section.update(grouped.pop(part, {}))
        if exif_section:
            sections["EXIF"] = exif_section

        if "GPS" in grouped:
            sections["GPS"] = grouped.pop("GPS")

        if gps_ifd:
            gps = self._parse_gps(gps_ifd)
            if gps:
                result.gps = gps
                gps_block = sections.setdefault("GPS", {})
                gps_block["Latitude"] = str(gps.latitude)
                gps_block["Longitude"] = str(gps.longitude)
                if gps.altitude_meters is not None:
                    gps_block["Altitude"] = f"{gps.altitude_meters} m"
                gps_block["Google Maps"] = gps.google_maps_url or ""
            elif not sections.get("GPS"):
                result.warnings.append("GPS tags present but could not be parsed completely.")

        flat_strings = {k: self._format_tag_value(k, v) for k, v in flat.items()}
        result.tag_count = len(flat_strings)
        result.raw_tags = dict(sorted(flat_strings.items()))
        sections["Composite"] = build_composite(
            flat,
            width=width,
            height=height,
            file_size=size,
            filename=filename,
        )

        for tag_name, text in flat_strings.items():
            if tag_name in self._CAMERA_TAGS:
                result.camera[tag_name] = text
            elif tag_name in self._CAPTURE_TAGS:
                result.capture[tag_name] = text
            elif tag_name in self._IMAGE_TAGS:
                result.image_props[tag_name] = text
            elif tag_name in self._SOFTWARE_TAGS:
                result.software[tag_name] = text

        result.sections = sections
        image.close()
        return result

    def _extract_jpeg_piexif(
        self,
        file_bytes: bytes,
        image: Image.Image,
        result: ExifExtractionResult,
        sections: dict[str, dict[str, str]],
        filename: str,
        size: int,
        width: int,
        height: int,
    ) -> ExifExtractionResult:
        icc = image.info.get("icc_profile") if image.info else None
        if icc:
            sections["ICC_Profile"] = parse_icc_profile(icc)

        piexif_dict = load_piexif_dict(file_bytes)
        if not piexif_dict:
            result.warnings.append(
                "No EXIF block found in JPEG. Metadata may have been stripped before upload."
            )
            sections["Composite"] = build_composite(
                {}, width=width, height=height, file_size=size, filename=filename
            )
            result.sections = sections
            return result

        has_tags = any(
            piexif_dict.get(key) for key in ("0th", "Exif", "GPS", "Interop", "1st")
        )
        if not has_tags:
            result.warnings.append("EXIF structure present but contains no tags.")
            sections["Composite"] = build_composite(
                {}, width=width, height=height, file_size=size, filename=filename
            )
            result.sections = sections
            return result

        result.has_exif = True
        flat, grouped = extract_from_piexif(piexif_dict, format_value=format_piexif_value)

        exif_section: dict[str, str] = {
            "Exif Byte Order": detect_exif_byte_order(file_bytes),
        }
        for part in ("IFD0", "Exif", "Interop"):
            exif_section.update(grouped.pop(part, {}))
        sections["EXIF"] = exif_section

        if "GPS" in grouped:
            sections["GPS"] = grouped.pop("GPS")
        if "MakerNote" in grouped:
            sections["MakerNote"] = grouped.pop("MakerNote")
        if "Thumbnail" in grouped:
            sections["Thumbnail"] = grouped.pop("Thumbnail")

        gps_ifd = piexif_dict.get("GPS") or {}
        if gps_ifd:
            gps = self._parse_gps(gps_ifd)
            if gps:
                result.gps = gps
                gps_block = sections.setdefault("GPS", {})
                gps_block["Latitude"] = str(gps.latitude)
                gps_block["Longitude"] = str(gps.longitude)
                if gps.altitude_meters is not None:
                    gps_block["Altitude"] = f"{gps.altitude_meters} m"
                gps_block["Google Maps"] = gps.google_maps_url or ""

        flat_strings = {
            k: format_piexif_value(
                k[4:] if k.startswith("GPS_") else k, v
            )
            for k, v in flat.items()
        }
        result.tag_count = len(flat_strings)
        result.raw_tags = dict(sorted(flat_strings.items()))

        sections["Composite"] = build_composite(
            flat, width=width, height=height, file_size=size, filename=filename
        )

        for tag_name, text in flat_strings.items():
            clean = tag_name[4:] if tag_name.startswith("GPS_") else tag_name
            if clean in self._CAMERA_TAGS:
                result.camera[clean] = text
            elif clean in self._CAPTURE_TAGS:
                result.capture[clean] = text
            elif clean in self._IMAGE_TAGS:
                result.image_props[clean] = text
            elif clean in self._SOFTWARE_TAGS:
                result.software[clean] = text

        result.sections = sections
        return result

    def _build_file_section(
        self,
        image: Image.Image,
        fmt: str,
        filename: str,
        file_size: int,
        width: int,
        height: int,
    ) -> dict[str, str]:
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else fmt
        mime = {
            "jpeg": "image/jpeg",
            "jpg": "image/jpeg",
            "png": "image/png",
            "tiff": "image/tiff",
            "webp": "image/webp",
        }.get(fmt if fmt != "jpeg" else "jpeg", f"image/{fmt}")

        section = {
            "File Type": fmt.upper() if fmt != "jpeg" else "JPEG",
            "File Type Extension": ext,
            "MIME Type": mime,
            "Image Width": str(width),
            "Image Height": str(height),
        }
        if filename:
            section["Filename"] = filename
        section["File Size"] = self._format_size(file_size)

        if fmt in ("jpeg", "jpg"):
            section["Encoding Process"] = "Baseline DCT, Huffman coding"
        section["Bits Per Sample"] = "8"
        if image.mode:
            components = len(image.getbands())
            section["Color Components"] = str(components)

        jfif = image.info.get("jfif") if image.info else None
        if jfif:
            section["JFIF Version"] = str(jfif)

        return section

    def _extract_all_ifds(self, exif) -> tuple[dict[str, Any], dict | None, dict[str, dict[str, str]]]:
        flat: dict[str, Any] = {}
        grouped: dict[str, dict[str, str]] = {}
        gps_ifd = None

        ifd_map = [
            ("IFD0", None),
            ("Exif", ExifTags.IFD.Exif),
            ("GPS", ExifTags.IFD.GPSInfo),
            ("Interop", ExifTags.IFD.Interop),
        ]

        # IFD0 — main image tags
        ifd0: dict[str, str] = {}
        for tag_id, value in exif.items():
            if tag_id in ExifTags.IFD:
                continue
            name = ExifTags.TAGS.get(tag_id, str(tag_id))
            flat[name] = value
            ifd0[label_for_tag(name)] = self._format_tag_value(name, value)
        if ifd0:
            grouped["IFD0"] = ifd0

        for section_name, ifd_key in ifd_map[1:]:
            try:
                ifd = exif.get_ifd(ifd_key)
            except (KeyError, AttributeError):
                continue
            if section_name == "GPS":
                gps_ifd = ifd
            section_data: dict[str, str] = {}
            tag_names = ExifTags.GPSTAGS if section_name == "GPS" else ExifTags.TAGS
            for tag_id, value in ifd.items():
                name = tag_names.get(tag_id, str(tag_id))
                flat_key = f"GPS_{name}" if section_name == "GPS" else name
                flat[flat_key] = value
                label = label_for_tag(flat_key if section_name == "GPS" else name)
                section_data[label] = self._format_tag_value(name, value)
            if section_data:
                grouped[section_name] = section_data

        return flat, gps_ifd, grouped

    def _format_tag_value(self, tag_name: str, value: Any) -> str:
        decoded = decode_tag_value(tag_name, value)
        if decoded:
            return decoded
        return self._stringify(value)

    def _extract_png_metadata(
        self,
        image: Image.Image,
        result: ExifExtractionResult,
        sections: dict[str, dict[str, str]],
    ) -> None:
        info = image.info or {}
        text_chunks: dict[str, str] = {}
        for key, value in info.items():
            if key == "icc_profile":
                continue
            if isinstance(value, (str, bytes)):
                text_chunks[str(key)] = self._stringify(value)
        if text_chunks:
            result.has_exif = True
            result.png_text = text_chunks
            result.tag_count = len(text_chunks)
            sections["PNG"] = text_chunks
        else:
            result.warnings.append("PNG contains no textual metadata chunks.")

        icc = info.get("icc_profile")
        if icc:
            sections["ICC_Profile"] = parse_icc_profile(icc)

    def _gps_ifd_value(self, gps_ifd: dict, tag_name: str, default=None):
        tag_id = _gps_tag_id(tag_name)
        if tag_id is None:
            return default
        return gps_ifd.get(tag_id, default)

    def _parse_gps(self, gps_ifd: dict | None) -> GpsCoordinates | None:
        if not gps_ifd or not isinstance(gps_ifd, dict):
            return None

        lat = self._gps_to_decimal(
            self._gps_ifd_value(gps_ifd, "GPSLatitude"),
            self._gps_ifd_value(gps_ifd, "GPSLatitudeRef", b"N"),
        )
        lon = self._gps_to_decimal(
            self._gps_ifd_value(gps_ifd, "GPSLongitude"),
            self._gps_ifd_value(gps_ifd, "GPSLongitudeRef", b"E"),
        )
        alt = self._gps_altitude(self._gps_ifd_value(gps_ifd, "GPSAltitude"))

        if lat is None or lon is None:
            return None

        return GpsCoordinates(
            latitude=round(lat, 6),
            longitude=round(lon, 6),
            altitude_meters=alt,
            google_maps_url=f"https://www.google.com/maps?q={lat},{lon}",
            raw_ref={
                "lat_ref": self._stringify(self._gps_ifd_value(gps_ifd, "GPSLatitudeRef")),
                "lon_ref": self._stringify(self._gps_ifd_value(gps_ifd, "GPSLongitudeRef")),
            },
        )

    def _gps_to_decimal(self, dms: Any, ref: Any) -> float | None:
        if not dms or not isinstance(dms, (list, tuple)) or len(dms) < 3:
            return None
        try:
            degrees = self._ratio_to_float(dms[0])
            minutes = self._ratio_to_float(dms[1])
            seconds = self._ratio_to_float(dms[2])
        except (TypeError, ValueError, ZeroDivisionError):
            return None

        decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
        ref_str = self._stringify(ref).upper()
        if ref_str in ("S", "W"):
            decimal = -decimal
        return decimal

    def _gps_altitude(self, value: Any) -> float | None:
        if value is None:
            return None
        try:
            return round(self._ratio_to_float(value), 2)
        except (TypeError, ValueError, ZeroDivisionError):
            return None

    def _ratio_to_float(self, value: Any) -> float:
        if isinstance(value, Fraction):
            return float(value)
        if hasattr(value, "numerator") and hasattr(value, "denominator"):
            return float(value.numerator) / float(value.denominator)
        if isinstance(value, tuple) and len(value) == 2:
            num, den = value
            return float(num) / float(den) if den else 0.0
        return float(value)

    def _stringify(self, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            try:
                return value.decode("utf-8", errors="replace")
            except Exception:
                return value.hex()
        if isinstance(value, (tuple, list)):
            if len(value) == 2 and all(isinstance(v, (int, float)) for v in value):
                return self._format_tag_value("", value)
            return ", ".join(self._stringify(v) for v in value)
        if isinstance(value, datetime):
            return value.isoformat()
        return str(value)

    @staticmethod
    def _format_size(num: int) -> str:
        if num < 1024 * 1024:
            return f"{num / 1024:.1f} KB"
        return f"{num / (1024 * 1024):.1f} MB"
