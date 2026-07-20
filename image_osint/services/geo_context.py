"""
Geolocation context for EXIF GPS coordinates — reverse geocoding and
nearby named landmarks via OpenStreetMap's free, public infrastructure.
No API key required for either service.

Two independent OSM services, used the way a human analyst would:
  - Nominatim (nominatim.openstreetmap.org): reverse geocode the raw
    coordinates into a human-readable address.
  - Overpass API (overpass-api.de): query for named points of interest
    within a radius — what's actually near these coordinates (a school,
    a mosque, a specific shop), which is often more useful for placing
    a photo than a bare address.

Also builds a direct Overpass Turbo link so the person can open the same
query in the interactive map tool for manual exploration — this module
automates the common case, Overpass Turbo is there for going further.

Both services are shared public infrastructure with real usage policies
(Nominatim: max ~1 request/second, requires an identifying User-Agent).
This client throttles accordingly and degrades gracefully — a failure in
one service does not take down the other, matching the same pattern used
throughout this project (WHOIS org lookup, Company Footprint, etc.).
"""

from __future__ import annotations

import math
import time
import urllib.parse
from dataclasses import dataclass, field

import requests
from django.conf import settings

_NOMINATIM_MIN_INTERVAL = 1.1  # Nominatim usage policy: max ~1 req/sec
_OVERPASS_MIN_INTERVAL = 1.0
_last_nominatim_at = 0.0
_last_overpass_at = 0.0

_DEFAULT_RADIUS_M = 200
_MAX_LANDMARKS_SHOWN = 10

_POI_TAG_PRIORITY = ("amenity", "tourism", "shop", "leisure", "office", "building", "man_made")


@dataclass(frozen=True)
class Landmark:
    name: str
    category: str
    distance_m: int
    latitude: float
    longitude: float


@dataclass
class GeoContextResult:
    success: bool
    latitude: float = 0.0
    longitude: float = 0.0
    address: str = ""
    address_error: str | None = None
    landmarks: list[Landmark] = field(default_factory=list)
    landmark_count_total: int = 0
    landmarks_error: str | None = None
    overpass_turbo_url: str = ""
    osm_url: str = ""


def _user_agent() -> str:
    return getattr(
        settings, "OSM_USER_AGENT",
        "OSINT-Vector-Analyzer-FYP (contact: set OSM_USER_AGENT in settings)",
    )


def _throttle_nominatim() -> None:
    global _last_nominatim_at
    wait = _NOMINATIM_MIN_INTERVAL - (time.monotonic() - _last_nominatim_at)
    if wait > 0:
        time.sleep(wait)
    _last_nominatim_at = time.monotonic()


def _throttle_overpass() -> None:
    global _last_overpass_at
    wait = _OVERPASS_MIN_INTERVAL - (time.monotonic() - _last_overpass_at)
    if wait > 0:
        time.sleep(wait)
    _last_overpass_at = time.monotonic()


def _haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6_371_000  # Earth radius, meters
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlambda / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


class GeoContextClient:
    def __init__(self, timeout: float = 10.0, radius_m: int = _DEFAULT_RADIUS_M):
        self.timeout = timeout
        self.radius_m = radius_m

    def build(self, latitude: float, longitude: float) -> GeoContextResult:
        result = GeoContextResult(
            success=True,
            latitude=latitude,
            longitude=longitude,
            overpass_turbo_url=self._overpass_turbo_url(latitude, longitude),
            osm_url=(
                f"https://www.openstreetmap.org/?mlat={latitude}&mlon={longitude}"
                f"#map=18/{latitude}/{longitude}"
            ),
        )

        address, address_error = self._reverse_geocode(latitude, longitude)
        result.address = address
        result.address_error = address_error

        landmarks, total, landmarks_error = self._nearby_landmarks(latitude, longitude)
        result.landmarks = landmarks
        result.landmark_count_total = total
        result.landmarks_error = landmarks_error

        return result

    def _reverse_geocode(self, lat: float, lon: float) -> tuple[str, str | None]:
        _throttle_nominatim()
        try:
            response = requests.get(
                "https://nominatim.openstreetmap.org/reverse",
                params={"format": "jsonv2", "lat": lat, "lon": lon, "zoom": 18, "addressdetails": 0},
                timeout=self.timeout,
                headers={"User-Agent": _user_agent()},
            )
        except requests.RequestException as exc:
            return "", f"Could not reach Nominatim: {exc}"

        if response.status_code != 200:
            return "", f"Nominatim returned HTTP {response.status_code}."

        try:
            data = response.json()
        except ValueError:
            return "", "Nominatim returned an unreadable response."

        display_name = data.get("display_name", "")
        if not display_name:
            return "", "No address found for these coordinates."
        return display_name, None

    def _nearby_landmarks(
        self, lat: float, lon: float
    ) -> tuple[list[Landmark], int, str | None]:
        _throttle_overpass()
        query = (
            "[out:json][timeout:15];"
            f"(node(around:{self.radius_m},{lat},{lon})[name];"
            f"way(around:{self.radius_m},{lat},{lon})[name];);"
            "out center 40;"
        )
        try:
            response = requests.post(
                "https://overpass-api.de/api/interpreter",
                data={"data": query},
                timeout=self.timeout,
                headers={"User-Agent": _user_agent()},
            )
        except requests.RequestException as exc:
            return [], 0, f"Could not reach Overpass API: {exc}"

        if response.status_code == 429:
            return [], 0, "Overpass API rate limit reached — try again shortly."
        if response.status_code != 200:
            return [], 0, f"Overpass API returned HTTP {response.status_code}."

        try:
            data = response.json()
        except ValueError:
            return [], 0, "Overpass API returned an unreadable response."

        landmarks: list[Landmark] = []
        for element in data.get("elements", []):
            tags = element.get("tags") or {}
            name = tags.get("name")
            if not name:
                continue

            elem_lat = element.get("lat") or (element.get("center") or {}).get("lat")
            elem_lon = element.get("lon") or (element.get("center") or {}).get("lon")
            if elem_lat is None or elem_lon is None:
                continue

            category = "place"
            for tag_key in _POI_TAG_PRIORITY:
                if tag_key in tags:
                    category = f"{tag_key}={tags[tag_key]}"
                    break

            distance = round(_haversine_m(lat, lon, elem_lat, elem_lon))
            landmarks.append(
                Landmark(
                    name=name, category=category, distance_m=distance,
                    latitude=elem_lat, longitude=elem_lon,
                )
            )

        landmarks.sort(key=lambda l: l.distance_m)
        total = len(landmarks)
        return landmarks[:_MAX_LANDMARKS_SHOWN], total, None

    def _overpass_turbo_url(self, lat: float, lon: float) -> str:
        query = (
            f"[out:json][timeout:25];\n"
            f"(\n  node(around:{self.radius_m},{lat},{lon})[name];\n"
            f"  way(around:{self.radius_m},{lat},{lon})[name];\n);\n"
            f"out center;"
        )
        encoded_query = urllib.parse.quote(query)
        return f"https://overpass-turbo.eu/?Q={encoded_query}&C={lat};{lon};18"
