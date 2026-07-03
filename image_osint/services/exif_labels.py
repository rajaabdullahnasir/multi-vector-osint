"""
Human-readable EXIF field labels (ExifTool-style naming).
"""

from __future__ import annotations

import re

# Tag name → display label
EXIF_LABELS: dict[str, str] = {
    "Make": "Make",
    "Model": "Camera Model Name",
    "ImageDescription": "Image Description",
    "Orientation": "Orientation",
    "XResolution": "X Resolution",
    "YResolution": "Y Resolution",
    "ResolutionUnit": "Resolution Unit",
    "Software": "Software",
    "DateTime": "Modify Date",
    "Artist": "Artist",
    "Copyright": "Copyright",
    "ExifOffset": "Exif Offset",
    "GPSInfo": "GPS Info",
    "ExposureTime": "Exposure Time",
    "FNumber": "F Number",
    "ExposureProgram": "Exposure Program",
    "ISOSpeedRatings": "ISO",
    "PhotographicSensitivity": "ISO",
    "ExifVersion": "Exif Version",
    "DateTimeOriginal": "Date/Time Original",
    "DateTimeDigitized": "Create Date",
    "OffsetTime": "Offset Time",
    "OffsetTimeOriginal": "Offset Time Original",
    "OffsetTimeDigitized": "Offset Time Digitized",
    "ComponentsConfiguration": "Components Configuration",
    "CompressedBitsPerPixel": "Compressed Bits Per Pixel",
    "ShutterSpeedValue": "Shutter Speed Value",
    "ApertureValue": "Aperture Value",
    "BrightnessValue": "Brightness Value",
    "ExposureBiasValue": "Exposure Compensation",
    "MaxApertureValue": "Max Aperture Value",
    "MeteringMode": "Metering Mode",
    "LightSource": "Light Source",
    "Flash": "Flash",
    "FocalLength": "Focal Length",
    "UserComment": "User Comment",
    "SubsecTime": "Sub Sec Time",
    "SubSecTimeOriginal": "Sub Sec Time Original",
    "SubSecTimeDigitized": "Sub Sec Time Digitized",
    "FlashpixVersion": "Flashpix Version",
    "ColorSpace": "Color Space",
    "PixelXDimension": "Exif Image Width",
    "PixelYDimension": "Exif Image Height",
    "ExifImageWidth": "Exif Image Width",
    "ExifImageHeight": "Exif Image Height",
    "InteroperabilityIndex": "Interoperability Index",
    "InteroperabilityVersion": "Interoperability Version",
    "FocalLengthIn35mmFilm": "Focal Length In 35mm Format",
    "SceneCaptureType": "Scene Capture Type",
    "LensModel": "Lens Model",
    "LensMake": "Lens Make",
    "WhiteBalance": "White Balance",
    "DigitalZoomRatio": "Digital Zoom Ratio",
    "SceneType": "Scene Type",
    "ExposureMode": "Exposure Mode",
    "SensitivityType": "Sensitivity Type",
    "RecommendedExposureIndex": "Recommended Exposure Index",
    "YCbCrPositioning": "Y Cb Cr Positioning",
    "YCbCrSubSampling": "Y Cb Cr Sub Sampling",
    "Compression": "Compression",
    "JPEGInterchangeFormat": "Thumbnail Offset",
    "JPEGInterchangeFormatLength": "Thumbnail Length",
    "ProcessingSoftware": "Processing Software",
    "HostComputer": "Host Computer",
}


def label_for_tag(tag_name: str) -> str:
    if tag_name in EXIF_LABELS:
        return EXIF_LABELS[tag_name]
    if tag_name.startswith("GPS_"):
        gps_name = tag_name[4:]
        return f"GPS {EXIF_LABELS.get(gps_name, _spacify(gps_name))}"
    return _spacify(tag_name)


def _spacify(name: str) -> str:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return spaced.replace("_", " ")
