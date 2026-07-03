"""
WHOIS protocol client (TCP/43) — no third-party WHOIS API.
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field

from django.conf import settings

# Common TLD → WHOIS server (passive registry queries).
TLD_WHOIS_SERVERS: dict[str, str] = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "biz": "whois.biz",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "edu": "whois.educause.edu",
    "gov": "whois.dotgov.gov",
    "uk": "whois.nic.uk",
    "us": "whois.nic.us",
    "de": "whois.denic.de",
    "fr": "whois.nic.fr",
    "au": "whois.auda.org.au",
    "ca": "whois.cira.ca",
    "in": "whois.registry.in",
    "pk": "whois.pknic.net.pk",
    "me": "whois.nic.me",
    "xyz": "whois.nic.xyz",
    "app": "whois.nic.google",
    "dev": "whois.nic.google",
}


@dataclass
class WhoisQueryResult:
    success: bool
    domain: str
    whois_server: str
    raw_text: str = ""
    error: str | None = None
    referral_server: str | None = None
    queries: list[str] = field(default_factory=list)


class WhoisClient:
    def __init__(self, timeout: float | None = None):
        self.timeout = timeout or getattr(settings, "WHOIS_TIMEOUT_SECONDS", 12)

    def lookup(self, domain: str) -> WhoisQueryResult:
        primary_server = self._resolve_whois_server(domain)
        queries: list[str] = []

        try:
            raw = self._query_server(primary_server, domain)
            queries.append(f"{primary_server} ← {domain}")
        except OSError as exc:
            return WhoisQueryResult(
                success=False,
                domain=domain,
                whois_server=primary_server,
                error=f"WHOIS query failed: {exc}",
                queries=queries,
            )

        referral = self._extract_referral_server(raw)
        if referral and referral.lower() != primary_server.lower():
            try:
                referral_raw = self._query_server(referral, domain)
                queries.append(f"{referral} ← {domain} (referral)")
                raw = f"{raw.rstrip()}\n\n{'=' * 40}\nREFERRAL: {referral}\n{'=' * 40}\n\n{referral_raw}"
            except OSError:
                raw += f"\n\n[Referral server {referral} unreachable]"

        return WhoisQueryResult(
            success=True,
            domain=domain,
            whois_server=primary_server,
            raw_text=raw,
            referral_server=referral,
            queries=queries,
        )

    def _resolve_whois_server(self, domain: str) -> str:
        parts = domain.lower().split(".")
        if len(parts) >= 2:
            compound = ".".join(parts[-2:])
            if compound in ("co.uk", "org.uk", "ac.uk", "com.au", "co.jp"):
                return TLD_WHOIS_SERVERS.get(parts[-1], "whois.iana.org")
        tld = parts[-1]
        if tld in TLD_WHOIS_SERVERS:
            return TLD_WHOIS_SERVERS[tld]
        return self._iana_whois_server(tld)

    def _iana_whois_server(self, tld: str) -> str:
        try:
            response = self._query_server("whois.iana.org", tld)
        except OSError:
            return "whois.iana.org"
        match = re.search(r"^whois:\s*(\S+)", response, re.MULTILINE | re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return "whois.iana.org"

    def _query_server(self, host: str, query: str) -> str:
        payload = f"{query}\r\n".encode("utf-8")
        with socket.create_connection((host, 43), timeout=self.timeout) as sock:
            sock.sendall(payload)
            chunks: list[bytes] = []
            while True:
                try:
                    data = sock.recv(4096)
                except socket.timeout:
                    break
                if not data:
                    break
                chunks.append(data)
                if len(data) < 4096:
                    break
        raw = b"".join(chunks)
        return raw.decode("utf-8", errors="replace")

    @staticmethod
    def _extract_referral_server(raw: str) -> str | None:
        patterns = [
            r"Registrar WHOIS Server:\s*(\S+)",
            r"Whois Server:\s*(\S+)",
            r"refer:\s*(\S+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, raw, re.IGNORECASE)
            if match:
                server = match.group(1).strip().lower()
                if server and server != "whois.iana.org":
                    return server
        return None
