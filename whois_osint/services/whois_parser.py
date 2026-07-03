"""
Parse raw WHOIS text into structured sections.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ParsedWhois:
    sections: dict[str, dict[str, str]] = field(default_factory=dict)
    flat: dict[str, str] = field(default_factory=dict)
    name_servers: list[str] = field(default_factory=list)
    status_lines: list[str] = field(default_factory=list)


# Normalize heterogeneous registrar field names.
_FIELD_ALIASES: dict[str, str] = {
    "domain name": "Domain Name",
    "domain": "Domain Name",
    "registry domain id": "Registry Domain ID",
    "registrar": "Registrar",
    "registrar whois server": "Registrar WHOIS Server",
    "registrar url": "Registrar URL",
    "creation date": "Creation Date",
    "created": "Creation Date",
    "registration time": "Creation Date",
    "registered on": "Creation Date",
    "registry expiry date": "Registry Expiry Date",
    "registrar registration expiration date": "Registry Expiry Date",
    "expiry date": "Registry Expiry Date",
    "expiration date": "Registry Expiry Date",
    "expires on": "Registry Expiry Date",
    "updated date": "Updated Date",
    "last updated": "Updated Date",
    "last modified": "Updated Date",
    "modified": "Updated Date",
    "dnssec": "DNSSEC",
    "domain status": "Domain Status",
}


class WhoisParser:
    def parse(self, raw_text: str) -> ParsedWhois:
        result = ParsedWhois()
        if not raw_text.strip():
            return result

        current_section = "WHOIS"
        result.sections[current_section] = {}

        for line in raw_text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("%") or stripped.startswith("#"):
                continue
            if set(stripped) <= {"=", "-"}:
                continue

            if stripped.endswith(":") and ":" not in stripped[:-1]:
                current_section = stripped[:-1].strip() or "WHOIS"
                result.sections.setdefault(current_section, {})
                continue

            if ":" in stripped:
                key, _, value = stripped.partition(":")
                key = key.strip()
                value = value.strip()
                if not key:
                    continue
                norm_key = _FIELD_ALIASES.get(key.lower(), key)
                self._store(result, current_section, norm_key, value)
            elif stripped.lower().startswith("nserver:"):
                _, _, ns = stripped.partition(":")
                self._add_nameserver(result, ns.strip())
            elif stripped.lower().startswith("name server:"):
                _, _, ns = stripped.partition(":")
                self._add_nameserver(result, ns.strip())

        # Promote key registration fields to summary section
        summary = self._build_summary(result)
        if summary:
            result.sections["Registration"] = summary

        return result

    def _store(self, result: ParsedWhois, section: str, key: str, value: str) -> None:
        if not value:
            return
        result.sections.setdefault(section, {})
        if key in result.sections[section]:
            if value not in result.sections[section][key]:
                result.sections[section][key] = f"{result.sections[section][key]}; {value}"
        else:
            result.sections[section][key] = value

        result.flat[key] = value

        if key.lower() in ("name server", "nserver"):
            self._add_nameserver(result, value.split()[0])
        if key == "Domain Status":
            result.status_lines.append(value)

    def _add_nameserver(self, result: ParsedWhois, ns: str) -> None:
        host = ns.lower().rstrip(".")
        if host and host not in result.name_servers:
            result.name_servers.append(host)

    def _build_summary(self, parsed: ParsedWhois) -> dict[str, str]:
        priority = [
            "Domain Name",
            "Registry Domain ID",
            "Registrar",
            "Registrar WHOIS Server",
            "Registrar URL",
            "Creation Date",
            "Updated Date",
            "Registry Expiry Date",
            "DNSSEC",
            "Domain Status",
        ]
        summary: dict[str, str] = {}
        for key in priority:
            if key in parsed.flat:
                summary[key] = parsed.flat[key]
        return summary
