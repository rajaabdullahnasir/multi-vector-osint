"""
Orchestrates Module 1 pipeline: validate → EXIF → fingerprint → reverse links.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, BinaryIO

from .exif_extractor import ExifExtractor
from .file_validator import ImageFileValidator
from .geo_context import GeoContextClient
from .perceptual_hash import PerceptualHashEngine
from .reverse_search import ReverseSearchLink, ReverseSearchLinkBuilder


@dataclass
class ImageAnalysisReport:
    success: bool
    error: str | None = None
    validation: dict[str, Any] | None = None
    exif: dict[str, Any] | None = None
    fingerprint: dict[str, str] | None = None
    reverse_search: list[dict[str, str]] | None = None
    reverse_search_notice: str = ""
    geo_context: dict[str, Any] | None = None
    risk_flags: list[str] | None = None

    def to_storage_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "error": self.error,
            "validation": self.validation,
            "exif": self.exif,
            "fingerprint": self.fingerprint,
            "reverse_search": self.reverse_search,
            "reverse_search_notice": self.reverse_search_notice,
            "geo_context": self.geo_context,
            "risk_flags": self.risk_flags,
        }


class ImageOsintAnalyzer:
    def __init__(self):
        self.validator = ImageFileValidator()
        self.exif_extractor = ExifExtractor()
        self.hash_engine = PerceptualHashEngine()
        self.reverse_builder = ReverseSearchLinkBuilder()
        self.geo_client = GeoContextClient()

    def analyze(
        self,
        file_obj: BinaryIO,
        *,
        declared_name: str = "",
        public_image_url: str | None = None,
    ) -> ImageAnalysisReport:
        validation = self.validator.validate(file_obj, declared_name)
        if not validation.ok:
            return ImageAnalysisReport(
                success=False,
                error=validation.error,
                validation={
                    "size_bytes": validation.size_bytes,
                    "mime_type": validation.mime_type,
                },
            )

        file_obj.seek(0)
        file_bytes = file_obj.read()
        file_obj.seek(0)

        exif_result = self.exif_extractor.extract(
            file_bytes,
            filename=declared_name,
            file_size=validation.size_bytes,
        )
        fingerprint = self.hash_engine.compute(file_bytes)
        reverse_links = self.reverse_builder.build(
            sha256_file=fingerprint["sha256_file"],
            public_image_url=public_image_url,
            original_filename=declared_name,
        )

        risk_flags = self._derive_risk_flags(exif_result.to_dict())

        geo_context_payload = None
        if exif_result.gps and exif_result.gps.latitude is not None and exif_result.gps.longitude is not None:
            geo_result = self.geo_client.build(exif_result.gps.latitude, exif_result.gps.longitude)
            geo_context_payload = {
                "latitude": geo_result.latitude,
                "longitude": geo_result.longitude,
                "address": geo_result.address,
                "address_error": geo_result.address_error,
                "landmarks": [
                    {
                        "name": l.name, "category": l.category,
                        "distance_m": l.distance_m, "latitude": l.latitude, "longitude": l.longitude,
                    }
                    for l in geo_result.landmarks
                ],
                "landmark_count_total": geo_result.landmark_count_total,
                "landmarks_error": geo_result.landmarks_error,
                "overpass_turbo_url": geo_result.overpass_turbo_url,
                "osm_url": geo_result.osm_url,
            }
            if geo_result.landmark_count_total > 0:
                risk_flags.append(
                    f"{geo_result.landmark_count_total} named landmark(s) found within "
                    f"{self.geo_client.radius_m}m of the GPS coordinates — see Geolocation Context."
                )

        return ImageAnalysisReport(
            success=True,
            validation={
                "size_bytes": validation.size_bytes,
                "mime_type": validation.mime_type,
                "detected_format": validation.detected_format,
            },
            exif=exif_result.to_dict(),
            fingerprint=fingerprint,
            reverse_search=[self._link_to_dict(link) for link in reverse_links],
            reverse_search_notice=self.reverse_builder.automation_notice(),
            geo_context=geo_context_payload,
            risk_flags=risk_flags,
        )

    def _link_to_dict(self, link: ReverseSearchLink) -> dict[str, str]:
        return {
            "provider": link.provider,
            "url": link.url,
            "method": link.method,
            "notes": link.notes,
        }

    def _derive_risk_flags(self, exif_dict: dict) -> list[str]:
        flags: list[str] = []
        gps = exif_dict.get("gps") or {}
        if gps.get("latitude") is not None:
            flags.append("GPS coordinates exposed — potential location leak.")
        software = exif_dict.get("software") or {}
        if software:
            flags.append("Editing software metadata present — verify authenticity.")
        if not exif_dict.get("has_exif"):
            flags.append("Metadata stripped or absent — may indicate intentional sanitization.")
        capture = exif_dict.get("capture") or {}
        if capture.get("DateTimeOriginal"):
            flags.append("Capture timestamp available for timeline analysis.")
        return flags
