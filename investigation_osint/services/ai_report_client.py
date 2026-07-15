"""
AI-generated narrative report client — Groq's OpenAI-compatible Chat
Completions API (free tier, no card required). Optional add-on: every
other part of this project works with zero AI dependency. This only
activates if GROQ_API_KEY is configured.

Strict grounding rule: the model is instructed to write ONLY from the
structured findings it's given, and to say so plainly when data is
missing or a check failed, rather than inventing anything. This is a
narrative summary of already-verified tool output, not an independent
source of truth — the report itself says so.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import requests
from django.conf import settings

_SYSTEM_PROMPT = """You are a cybersecurity analyst writing a professional OSINT reconnaissance \
report for an authorized security assessment (e.g. a company auditing its own external footprint, \
or a penetration tester documenting recon before a client engagement).

STRICT GROUNDING RULE: Write ONLY from the structured findings JSON provided below. Never invent \
domains, IPs, names, emails, breach counts, or any fact not present in the input. If a module \
failed or a value is missing, say so plainly ("X could not be determined because...") rather than \
guessing or filling gaps. Every inference or risk judgement you make beyond directly restating a \
finding must be clearly framed as your assessment, not presented as an established fact.

Note on entity lists: under "discovered_entities", each type has a "count" (the real total) and \
"examples" (a capped sample list, possibly not the full set — check "truncated"). Always report the \
real "count" as the total; only use "examples" to illustrate what kind of hosts/entities were found, \
and never claim the examples list is exhaustive when "truncated" is true.

Structure the report with these sections, in this order:
1. Executive Summary (3-5 sentences, plain language, for a non-technical stakeholder)
2. Infrastructure & DNS Overview (registrar, nameservers, DNS posture)
3. Email & Domain Security Posture (SPF/DMARC/DKIM, security headers, what they mean practically)
4. Digital Footprint (subdomains discovered, what the footprint size/shape suggests, social/platform presence and its attribution caveats)
5. IP & Geolocation Findings (notable IPs, hosting vs proxy/VPN flags, any concentration/pattern worth noting)
6. Breach Exposure (email breach results, or explicitly note if none were checked/available)
7. Consolidated Risk Assessment (synthesize across all sections — don't just repeat the risk flags list)
8. Prioritized Recommendations (ranked highest-impact first, concrete and actionable, tied to specific findings above)

Write in clear, professional prose — not a wall of bullet points, though short lists are fine within \
sections. End with a short note that this is an AI-generated synthesis of tool output and requires \
independent verification before being used for any decision.
"""


@dataclass
class AIReportResult:
    success: bool
    narrative: str = ""
    model_used: str = ""
    error: str | None = None


def _api_key() -> str:
    return getattr(settings, "GROQ_API_KEY", "") or ""


def is_configured() -> bool:
    return bool(_api_key())


_MAX_NODES_PER_TYPE = 15
_MAX_OUTCOME_SUMMARY_CHARS = 220


def _compact_investigation_summary(
    investigation_data: dict[str, Any],
    max_examples: int = _MAX_NODES_PER_TYPE,
    max_summary_chars: int = _MAX_OUTCOME_SUMMARY_CHARS,
) -> dict[str, Any]:
    """
    Build a compact summary instead of dumping the raw investigation JSON.

    A real domain with a large subdomain footprint (e.g. 77 hosts) blew
    past Groq's free-tier per-minute token limit on its first live test
    (8000 TPM for openai/gpt-oss-120b, request needed 14329) because the
    raw dump repeats risk flags in both the consolidated list AND every
    individual outcome's risk_contribution, and lists every single
    subdomain verbatim. This trims that redundancy — the model doesn't
    need duplicate copies of the same risk flag, or all 77 subdomains
    to describe "a large, sprawling subdomain footprint including admin/
    dev/internal hosts" accurately.
    """
    outcomes = investigation_data.get("outcomes") or []
    compact_outcomes = [
        {
            "label": o.get("label", ""),
            "summary": (o.get("summary") or "")[:max_summary_chars],
            "ok": o.get("ok", True),
        }
        for o in outcomes
    ]

    nodes = investigation_data.get("nodes") or []
    nodes_by_type: dict[str, list[str]] = {}
    for node in nodes:
        node_type = node.get("type", "other")
        nodes_by_type.setdefault(node_type, []).append(node.get("label", node.get("id", "")))

    compact_entities: dict[str, Any] = {}
    for node_type, labels in nodes_by_type.items():
        compact_entities[node_type] = {
            "count": len(labels),
            "examples": labels[:max_examples],
            "truncated": len(labels) > max_examples,
        }

    # Risk flags already carry everything an outcome's risk_contribution
    # would repeat — one consolidated, deduplicated copy is enough.
    risk_flags = investigation_data.get("risk_flags") or []

    return {
        "domain": investigation_data.get("domain", ""),
        "modules_run": investigation_data.get("modules_run") or [],
        "module_outcomes": compact_outcomes,
        "discovered_entities": compact_entities,
        "consolidated_risk_flags": risk_flags,
    }


class GroqReportClient:
    def __init__(self, timeout: float | None = None):
        self.timeout = timeout or getattr(settings, "GROQ_HTTP_TIMEOUT_SECONDS", 90)
        self.model = getattr(settings, "GROQ_MODEL", "openai/gpt-oss-120b")
        self.api_base = getattr(settings, "GROQ_API_BASE", "https://api.groq.com/openai/v1").rstrip("/")
        self.max_tokens = getattr(settings, "GROQ_MAX_COMPLETION_TOKENS", 3000)

    def generate(self, investigation_data: dict[str, Any]) -> AIReportResult:
        api_key = _api_key()
        if not api_key:
            return AIReportResult(
                success=False,
                error=(
                    "No Groq API key configured. Get a free key at "
                    "https://console.groq.com/keys and set GROQ_API_KEY in your environment."
                ),
            )

        compact_data = _compact_investigation_summary(investigation_data)
        findings_json = json.dumps(compact_data, indent=2, default=str)

        # Rough, conservative token estimate (~4 chars/token for JSON-ish
        # text). If even the compact summary would push a tight free-tier
        # budget (e.g. 8000 TPM), trim harder instead of sending and
        # hoping — the whole point of this fix was to stop guessing.
        estimated_tokens = len(_SYSTEM_PROMPT) // 4 + len(findings_json) // 4 + self.max_tokens
        safe_budget = getattr(settings, "GROQ_SAFE_TOKEN_BUDGET", 7000)
        if estimated_tokens > safe_budget:
            compact_data = _compact_investigation_summary(
                investigation_data, max_examples=5, max_summary_chars=120
            )
            findings_json = json.dumps(compact_data, indent=2, default=str)

        findings_json = findings_json[:20_000]

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": f"Structured investigation findings (JSON):\n\n{findings_json}",
                },
            ],
            "max_completion_tokens": self.max_tokens,
            "temperature": 0.4,
        }

        try:
            response = requests.post(
                f"{self.api_base}/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=self.timeout,
            )
        except requests.Timeout:
            return AIReportResult(
                success=False,
                error="Report generation timed out. Groq is usually fast — try again shortly.",
            )
        except requests.RequestException as exc:
            return AIReportResult(success=False, error=f"Could not reach Groq: {exc}")

        if response.status_code == 401:
            return AIReportResult(
                success=False,
                error="Groq rejected the API key (HTTP 401). Check GROQ_API_KEY is correct and active.",
            )
        if response.status_code == 429:
            return AIReportResult(
                success=False,
                error="Groq rate limit reached (HTTP 429) — this is generous on the free tier but "
                "not unlimited. Wait a bit and try again.",
            )
        if response.status_code >= 400:
            detail = ""
            try:
                detail = response.json().get("error", {}).get("message", "")
            except ValueError:
                detail = response.text[:300]
            return AIReportResult(
                success=False, error=f"Groq returned HTTP {response.status_code}: {detail}"
            )

        try:
            data = response.json()
            narrative = data["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError):
            return AIReportResult(success=False, error="Groq returned an unexpected response format.")

        if not narrative or not narrative.strip():
            return AIReportResult(success=False, error="Groq returned an empty report.")

        return AIReportResult(success=True, narrative=narrative.strip(), model_used=self.model)
