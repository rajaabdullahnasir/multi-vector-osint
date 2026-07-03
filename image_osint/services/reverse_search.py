"""
Reverse image search link builder — no third-party API.

Automated reverse search requires external APIs (Google Vision, TinEye, etc.).
This module generates investigator-ready search URLs and documents when APIs
are needed. Optional public URL enables Yandex/TinEye parameter links.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote


@dataclass(frozen=True)
class ReverseSearchLink:
    provider: str
    url: str
    method: str
    notes: str


class ReverseSearchLinkBuilder:
    """
    Builds manual reverse-search workflows for analysts.
    """

    def build(
        self,
        *,
        sha256_file: str,
        public_image_url: str | None = None,
        original_filename: str = "",
    ) -> list[ReverseSearchLink]:
        links: list[ReverseSearchLink] = []

        links.append(
            ReverseSearchLink(
                provider="Google Images",
                url="https://images.google.com/",
                method="manual_upload",
                notes=(
                    "Open Google Images → camera icon → upload the saved investigation file. "
                    "No server-side Google API is configured."
                ),
            )
        )

        links.append(
            ReverseSearchLink(
                provider="Yandex Images",
                url="https://yandex.com/images/",
                method="manual_upload",
                notes="Use Yandex visual search with the same uploaded file.",
            )
        )

        links.append(
            ReverseSearchLink(
                provider="TinEye",
                url="https://tineye.com/",
                method="manual_upload",
                notes="TinEye requires manual upload or a paid API for automation.",
            )
        )

        if public_image_url:
            encoded = quote(public_image_url, safe="")
            links.append(
                ReverseSearchLink(
                    provider="Yandex (by URL)",
                    url=f"https://yandex.com/images/search?rpt=imageview&url={encoded}",
                    method="url_parameter",
                    notes="Works only if the image URL is publicly reachable.",
                )
            )

        links.append(
            ReverseSearchLink(
                provider="File fingerprint (SHA-256)",
                url=f"https://www.google.com/search?q={quote(sha256_file)}",
                method="hash_lookup",
                notes=(
                    f"Search the web for this file hash. SHA-256: {sha256_file[:16]}… "
                    f"Filename hint: {original_filename or 'n/a'}"
                ),
            )
        )

        return links

    @staticmethod
    def automation_notice() -> str:
        return (
            "Automated reverse image search is not enabled. To integrate TinEye, "
            "Google Custom Search, or SerpAPI, provide API credentials and approve "
            "third-party usage."
        )
