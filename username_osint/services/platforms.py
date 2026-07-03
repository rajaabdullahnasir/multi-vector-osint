"""
Curated platforms for passive username enumeration (Sherlock-style).

Each entry uses public profile URLs and HTTP status / body heuristics only.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Platform:
    name: str
    category: str
    url_template: str
    exists_status: tuple[int, ...] = (200,)
    not_found_status: tuple[int, ...] = (404,)
    not_found_phrases: tuple[str, ...] = ()
    found_phrases: tuple[str, ...] = ()


PLATFORMS: tuple[Platform, ...] = (
    Platform("GitHub", "development", "https://github.com/{username}"),
    Platform("GitLab", "development", "https://gitlab.com/{username}"),
    Platform("Bitbucket", "development", "https://bitbucket.org/{username}/"),
    Platform("Docker Hub", "development", "https://hub.docker.com/u/{username}"),
    Platform("npm", "development", "https://www.npmjs.com/~{username}"),
    Platform("Dev.to", "development", "https://dev.to/{username}"),
    Platform("Reddit", "social", "https://www.reddit.com/user/{username}/"),
    Platform("Pinterest", "social", "https://www.pinterest.com/{username}/"),
    Platform("Medium", "social", "https://medium.com/@{username}"),
    Platform("Twitch", "social", "https://www.twitch.tv/{username}"),
    Platform("Steam", "gaming", "https://steamcommunity.com/id/{username}"),
    Platform("Roblox", "gaming", "https://www.roblox.com/user.aspx?username={username}"),
    Platform("SoundCloud", "media", "https://soundcloud.com/{username}"),
    Platform("Vimeo", "media", "https://vimeo.com/{username}"),
    Platform("Flickr", "media", "https://www.flickr.com/people/{username}/"),
    Platform("Behance", "creative", "https://www.behance.net/{username}"),
    Platform("Patreon", "creative", "https://www.patreon.com/{username}"),
    Platform("Keybase", "security", "https://keybase.io/{username}"),
    Platform(
        "TryHackMe",
        "security",
        "https://tryhackme.com/p/{username}",
        not_found_phrases=("page not found", "doesn't exist"),
    ),
    Platform(
        "HackerOne",
        "security",
        "https://hackerone.com/{username}",
        not_found_phrases=("page not found",),
    ),
    Platform(
        "Telegram",
        "social",
        "https://t.me/{username}",
        not_found_phrases=("if you have telegram", "you can contact"),
        found_phrases=("tgme_page", "tgme_page_photo"),
    ),
)
