# Module 9 — Company / Domain Footprint (Complete)

## Overview

Module 9 implements **Company / Domain Footprint OSINT** — a passive, correlation-style
module that builds an organization-level picture of a target domain by combining
four independent, no-API-key checks. It follows the same architectural
conventions as Modules 1–8: a `DomainValidator`, a set of stateless service
classes, an orchestrating `analyzer`, and a Django app wired into the shared
dashboard/nav.

| Capability | Implementation | Third-party? |
|------------|----------------|---------------|
| Org identity | `OrgIdentityLookup` — reuses `whois_osint`'s `WhoisClient` + `WhoisParser` (no duplicate WHOIS socket code) | No — raw WHOIS (TCP/43) |
| Mail security posture | `MailSecurityAnalyzer` — SPF/DMARC TXT records + a fixed 8-selector DKIM probe via `dnspython` | No — plain DNS |
| HTTP fingerprint | `HttpFingerprinter` — reads `Server`, `X-Powered-By`, and 4 standard security headers from a single GET | No — plain HTTP(S) |
| Official platform presence | `SocialPresenceChecker` — status-only check of guessed official company pages (GitHub, LinkedIn, X, Facebook, Instagram, Crunchbase) | No — status code only, no content scraping |

## Ethical scope (read before extending)

This module is intentionally **organization-level only**. It never:

- Scrapes personal profile content, employee lists, connections, or posts.
- Attempts to bypass authentication or CAPTCHA on any platform.
- Performs port scanning (only well-known WHOIS/DNS/HTTP protocols).

Platforms known to block automated requests (LinkedIn, Facebook, Instagram,
Crunchbase) are surfaced as **"Unverifiable (bot-protected)"** rather than a
false "not found" — the module does not try to work around this blocking.

## Architecture

```
Domain form (home.html)
    → OrgFootprintAnalyzer.analyze(domain)
         → DomainValidator
         → OrgIdentityLookup       (WHOIS org / country / privacy signal)
         → MailSecurityAnalyzer    (SPF / DMARC / DKIM selectors)
         → HttpFingerprinter       (headers + security-header presence)
         → SocialPresenceChecker   (official page status checks)
    → OrgFootprintReport (sections + risk_flags)
    → OrgFootprint model (upsert per user+domain)
    → detail.html
```

## Risk flags

Derived in `OrgFootprintAnalyzer._derive_risk_flags`:

- Missing SPF record
- Missing DMARC record, or DMARC policy is `p=none` (monitoring only, not enforced)
- 3+ of the 4 standard security headers missing from the HTTP response
- WHOIS registrant details appear privacy-protected

## Known environment limitation

Raw WHOIS (TCP/43) requires an unrestricted outbound socket. In network-locked
environments (e.g. some CI sandboxes or corporate proxies) the WHOIS step may
fail while DNS/HTTP/platform checks still succeed — the report degrades
gracefully and shows a notice in **Organization Identity** rather than
failing the whole scan.

## Files

```
org_footprint_osint/
  models.py                  OrgFootprint
  forms.py                   OrgFootprintForm
  views.py                   module_home, run_scan, scan_detail, export_json, delete_scan
  urls.py
  admin.py
  services/
    domain_validator.py
    org_identity.py
    mail_security.py
    http_fingerprint.py
    social_presence.py
    analyzer.py               OrgFootprintAnalyzer orchestrator
  tests/
    test_models.py
    test_services.py
    test_views.py
templates/org_footprint_osint/
  home.html
  detail.html
```
