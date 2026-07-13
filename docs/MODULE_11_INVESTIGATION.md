# Module 11 — Investigation (Multi-Vector Correlation Engine)

## Overview

This is the feature that makes "multi-vector-osint" actually true. Every
other module (1–10) is a standalone tool: you give it one input, it gives
you one report. **Investigation** is the orchestration layer on top — you
give it a domain, and it pivots automatically the way a human analyst
would, chaining real results from module to module:

```
domain
  ├─ WHOIS & DNS ──────────────► nameservers, registrant email (if published)
  ├─ Subdomain Finder ─────────► discovered hosts + resolved IPs
  │     └─ each IP ────────────► IP Intelligence (geolocation, ASN, proxy/hosting)
  ├─ Company Footprint ────────► SPF/DMARC, DMARC report email, guessed social handle
  ├─ URL Risk ─────────────────► lexical + blacklist + live DNSBL on the main site
  ├─ discovered/hinted emails ─► Email Breach (breach exposure)
  └─ hinted or guessed handle ─► Username OSINT (cross-platform presence)
```

## Design principle: zero duplicated logic

`InvestigationEngine` does not reimplement a single piece of detection
logic. It imports and calls the exact same `Analyzer` class each
standalone module already uses (`DomainIntelAnalyzer`, `SubdomainAnalyzer`,
`OrgFootprintAnalyzer`, `UrlRiskAnalyzer`, `IPIntelAnalyzer`,
`EmailBreachAnalyzer`, `UsernameOsintAnalyzer`) — so every bug fix applied
to those modules automatically benefits Investigation too, and there is
exactly one implementation of "what does a WHOIS lookup do" in the whole
codebase.

It also **writes a real row into each module's own table** via that
module's own `upsert_for_user`, using the same dataclasses and model
schemas already in production. This means:

- Every sub-result is visible in that module's own "recent" history, not
  just buried inside the Investigation record.
- The Investigation detail page can link directly to the full individual
  report for any pivot (`{% url outcome.url_name outcome.record_id %}`).
- If you delete an Investigation, the individual module records it created
  remain untouched — deleting a summary shouldn't destroy the underlying
  data.

## Pivot logic

| Step | Trigger | Cap |
|---|---|---|
| WHOIS | always | — |
| Subdomain Finder | always | — |
| Company Footprint | always | — |
| URL Risk (`https://{domain}`) | always | — |
| IP Intelligence | one call per unique IP resolved from subdomain A-records | 5 IPs |
| Email Breach | hint + emails regex-extracted from WHOIS raw text + DMARC `rua=` address | 3 emails |
| Username OSINT | hint, else domain slug, else a social handle guessed by Company Footprint | 2 usernames |

Caps exist because IP Intelligence, Email Breach, and Username OSINT each
call external free-tier services with real rate limits (`ip-api.com` at
~45 req/min, HIBP's k-anonymity range API, and 21 platform checks per
username respectively) — an investigation must not accidentally hammer
someone else's free service into a rate-limit wall.

## Risk aggregation

Every sub-report's `risk_flags` are collected, source-prefixed (e.g.
`[IP 82.25.88.206] ...`), and deduplicated into one consolidated list.
`overall_risk_level` is a simple, explainable rollup:

- **critical** — the main site's URL Risk came back `dangerous`, or any
  checked email came back genuinely pwned
- **elevated** — 4+ risk flags accumulated across all modules
- **moderate** — 1–3 risk flags accumulated
- **low** — nothing flagged anywhere

This is intentionally simple and legible rather than a black-box score —
an FYP examiner (or you, six months from now) should be able to read the
logic in about 30 seconds.

## Known limitation: this is synchronous and can take 30–90+ seconds

Running 6 external analyzers in sequence (plus up to 5+3+2 pivot calls)
inside one Django view is a real trade-off: simple to build and debug, but
slow, and any one module timing out slows the whole chain. This is
acceptable for an FYP demo but is the natural place to add a background
task queue (Celery, Django-Q) if this were headed to production — a
concrete, honest limitation worth stating in a viva rather than glossing
over.

## AI-generated narrative report (optional, free)

The Investigation detail page has a **"Generate report"** button that produces
a full narrative write-up via Groq's free-tier API (OpenAI-compatible Chat
Completions, no card required — get a key at
[console.groq.com/keys](https://console.groq.com/keys)).

This is entirely optional — every other part of this project, including
the rest of Investigation, works with zero AI dependency. Set `GROQ_API_KEY`
in your environment to enable it; without it, the button shows a clear
message explaining how to get a free key instead of failing silently.

**Grounding, not generation from scratch.** The system prompt instructs
the model to write *only* from the structured findings this investigation
already produced (the same `report_json` used by the entity map and
module outcomes above it) and explicitly forbids inventing facts. Where a
module failed or a value is missing, the model is told to say so plainly
rather than filling the gap. The report itself ends with a note that it's
an AI synthesis of tool output, not an independent source of truth.

The report covers: Executive Summary, Infrastructure & DNS Overview,
Email & Domain Security Posture, Digital Footprint, IP & Geolocation
Findings, Breach Exposure, Consolidated Risk Assessment, and Prioritized
Recommendations.

Model defaults to `openai/gpt-oss-120b` (Groq deprecated the older
Llama chat models — don't revert to `llama-3.3-70b-versatile` or similar).
Override via `GROQ_MODEL`, `GROQ_API_BASE`, `GROQ_HTTP_TIMEOUT_SECONDS`,
and `GROQ_MAX_COMPLETION_TOKENS` environment variables if needed.

## Files

```
investigation_osint/
  models.py                          Investigation
  forms.py                           InvestigationForm (domain + optional hints)
  views.py                           module_home, run_investigation, investigation_detail, export_json, delete_investigation
  urls.py
  admin.py
  services/
    investigation_engine.py          InvestigationEngine — the orchestrator
    ai_report_client.py              GroqReportClient — optional AI narrative report
  tests/
    test_models.py
    test_services.py                 full pivot chain tested with real dataclass fakes (not just Mocks)
    test_views.py
templates/investigation_osint/
  home.html
  detail.html                        entity map + module-by-module outcome cards
```
