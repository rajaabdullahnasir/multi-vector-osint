"""
Expanded platforms for passive username enumeration (Sherlock-style).

Each entry uses public profile URLs and HTTP status / body heuristics
only - no login, no scraping APIs. Detection accuracy varies by site:
platforms with a well-documented, stable "not found" page get
not_found_phrases for higher confidence; everything else uses plain
status-code detection (200 = exists, 404 = not found), with the
platform_checker's existing ambiguous-status handling (401/403/429/503)
automatically marking those as inconclusive rather than a false negative.

Deliberately excludes financial apps (Venmo, Cash App, etc.) even though
some are technically public by default - those enable financial-account
correlation in a way plain social/dev/creative profiles don't, so they're
left out of this list as a matter of caution.
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
    # --- Development / tech ---
    Platform("GitHub", "development", "https://github.com/{username}"),
    Platform("GitLab", "development", "https://gitlab.com/{username}"),
    Platform("Bitbucket", "development", "https://bitbucket.org/{username}/"),
    Platform("Docker Hub", "development", "https://hub.docker.com/u/{username}"),
    Platform("npm", "development", "https://www.npmjs.com/~{username}"),
    Platform("PyPI", "development", "https://pypi.org/user/{username}/"),
    Platform("RubyGems", "development", "https://rubygems.org/profiles/{username}"),
    Platform("Crates.io", "development", "https://crates.io/users/{username}"),
    Platform("Dev.to", "development", "https://dev.to/{username}"),
    Platform("Hashnode", "development", "https://hashnode.com/@{username}"),
    Platform("CodePen", "development", "https://codepen.io/{username}"),
    Platform("Replit", "development", "https://replit.com/@{username}"),
    Platform("HackerRank", "development", "https://www.hackerrank.com/{username}"),
    Platform("LeetCode", "development", "https://leetcode.com/{username}/"),
    Platform("Kaggle", "development", "https://www.kaggle.com/{username}"),
    Platform("Stack Overflow", "development", "https://stackoverflow.com/users/{username}"),
    Platform("SourceForge", "development", "https://sourceforge.net/u/{username}/"),
    Platform("Launchpad", "development", "https://launchpad.net/~{username}"),
    Platform("Codeberg", "development", "https://codeberg.org/{username}"),
    Platform("Product Hunt", "development", "https://www.producthunt.com/@{username}"),
    Platform("Trello", "development", "https://trello.com/{username}"),

    # --- Security / OSINT-adjacent ---
    Platform("Keybase", "security", "https://keybase.io/{username}"),
    Platform(
        "TryHackMe", "security", "https://tryhackme.com/p/{username}",
        not_found_phrases=("page not found", "doesn't exist"),
    ),
    Platform(
        "HackerOne", "security", "https://hackerone.com/{username}",
        not_found_phrases=("page not found",),
    ),
    Platform("Hack The Box", "security", "https://app.hackthebox.com/users/{username}"),
    Platform("Bugcrowd", "security", "https://bugcrowd.com/{username}"),

    # --- Social ---
    Platform("Reddit", "social", "https://www.reddit.com/user/{username}/"),
    Platform("Pinterest", "social", "https://www.pinterest.com/{username}/"),
    Platform("Medium", "social", "https://medium.com/@{username}"),
    Platform("Twitch", "social", "https://www.twitch.tv/{username}"),
    Platform(
        "Telegram", "social", "https://t.me/{username}",
        not_found_phrases=("if you have telegram", "you can contact"),
        found_phrases=("tgme_page", "tgme_page_photo"),
    ),
    Platform(
        "Instagram", "social", "https://www.instagram.com/{username}/",
        not_found_phrases=("sorry, this page isn't available", "page not found"),
    ),
    Platform(
        "X / Twitter", "social", "https://x.com/{username}",
        not_found_phrases=("this account doesn't exist", "page doesn't exist"),
    ),
    Platform(
        "Facebook", "social", "https://www.facebook.com/{username}",
        not_found_phrases=("this content isn't available", "page not found"),
    ),
    Platform(
        "TikTok", "social", "https://www.tiktok.com/@{username}",
        not_found_phrases=("couldn't find this account", "page not available"),
    ),
    Platform("Tumblr", "social", "https://{username}.tumblr.com/", not_found_status=(404, 999)),
    Platform("VK", "social", "https://vk.com/{username}"),
    Platform("Mastodon.social", "social", "https://mastodon.social/@{username}"),
    Platform("Bluesky", "social", "https://bsky.app/profile/{username}"),
    Platform("Threads", "social", "https://www.threads.net/@{username}"),
    Platform("Quora", "social", "https://www.quora.com/profile/{username}"),
    Platform("Disqus", "social", "https://disqus.com/by/{username}/"),
    Platform("Gravatar", "social", "https://gravatar.com/{username}"),
    Platform("About.me", "social", "https://about.me/{username}"),
    Platform("Linktree", "social", "https://linktr.ee/{username}"),
    Platform("Carrd", "social", "https://{username}.carrd.co/"),

    # --- Gaming ---
    Platform("Steam", "gaming", "https://steamcommunity.com/id/{username}"),
    Platform(
        "Roblox", "gaming", "https://www.roblox.com/user.aspx?username={username}",
        not_found_phrases=("page cannot be found",),
    ),
    Platform("Chess.com", "gaming", "https://www.chess.com/member/{username}"),
    Platform("Lichess", "gaming", "https://lichess.org/@/{username}"),
    Platform("Kongregate", "gaming", "https://www.kongregate.com/accounts/{username}"),
    Platform("itch.io", "gaming", "https://{username}.itch.io/"),
    Platform("Speedrun.com", "gaming", "https://www.speedrun.com/user/{username}"),
    Platform("osu!", "gaming", "https://osu.ppy.sh/users/{username}"),
    Platform("Backloggd", "gaming", "https://www.backloggd.com/u/{username}/"),

    # --- Media / creative ---
    Platform("SoundCloud", "media", "https://soundcloud.com/{username}"),
    Platform("Vimeo", "media", "https://vimeo.com/{username}"),
    Platform("Flickr", "media", "https://www.flickr.com/people/{username}/"),
    Platform("Behance", "creative", "https://www.behance.net/{username}"),
    Platform("Patreon", "creative", "https://www.patreon.com/{username}"),
    Platform("DeviantArt", "creative", "https://www.deviantart.com/{username}"),
    Platform("ArtStation", "creative", "https://www.artstation.com/{username}"),
    Platform("500px", "media", "https://500px.com/p/{username}"),
    Platform("Unsplash", "media", "https://unsplash.com/@{username}"),
    Platform("VSCO", "media", "https://vsco.co/{username}"),
    Platform("Last.fm", "media", "https://www.last.fm/user/{username}"),
    Platform("Bandcamp", "media", "https://{username}.bandcamp.com/"),
    Platform("Mixcloud", "media", "https://www.mixcloud.com/{username}/"),
    Platform("Genius", "media", "https://genius.com/{username}"),
    Platform("Goodreads", "media", "https://www.goodreads.com/{username}"),
    Platform("Letterboxd", "media", "https://letterboxd.com/{username}/"),
    Platform("AniList", "media", "https://anilist.co/user/{username}/"),
    Platform("MyAnimeList", "media", "https://myanimelist.net/profile/{username}"),
    Platform("YouTube", "media", "https://www.youtube.com/@{username}"),
    Platform("Spotify", "media", "https://open.spotify.com/user/{username}"),

    # --- Blogging / publishing ---
    Platform("Substack", "creative", "https://{username}.substack.com/"),
    Platform("Ko-fi", "creative", "https://ko-fi.com/{username}"),
    Platform("Buy Me a Coffee", "creative", "https://www.buymeacoffee.com/{username}"),
    Platform("Wordpress.com", "creative", "https://{username}.wordpress.com/"),
    Platform("Blogger", "creative", "https://{username}.blogspot.com/"),
    Platform("Gumroad", "creative", "https://{username}.gumroad.com/"),
    Platform("Fiverr", "creative", "https://www.fiverr.com/{username}"),

    # --- Forums / Q&A / community ---
    Platform("HackerNews", "social", "https://news.ycombinator.com/user?id={username}"),
    Platform("Lobsters", "social", "https://lobste.rs/~{username}"),
    Platform("Slashdot", "social", "https://slashdot.org/~{username}"),
    Platform("Kik", "social", "https://kik.me/{username}"),
)
