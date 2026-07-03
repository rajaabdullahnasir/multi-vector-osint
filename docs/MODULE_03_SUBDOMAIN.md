# Module 3 — Subdomain Finder (Complete)

## Overview

Passive subdomain enumeration for an apex domain: DNS label probing and Certificate Transparency (crt.sh). No port scanning.

| Capability | Implementation | Third-party? |
|------------|----------------|--------------|
| Domain validation | `DomainValidator` | No |
| DNS probing | `SubdomainEnumerator` + wordlist | No (dnspython) |
| CT discovery | crt.sh JSON API | **crt.sh** (HTTPS) |
| Risk flags | Footprint size, sensitive hosts | No |
| Deduped storage | `SubdomainScan.upsert_for_user` | No |

## Routes

| URL | Name |
|-----|------|
| `/modules/subdomain/` | `subdomain_osint:home` |
| `/modules/subdomain/scan/` | POST scan |
| `/modules/subdomain/<uuid>/` | Detail |
| `/modules/subdomain/<uuid>/export.json` | JSON export |

## Architecture

```
Domain input
  → DomainValidator
  → SubdomainEnumerator (DNS labels + crt.sh)
  → SubdomainAnalyzer → sections + risk flags
  → SubdomainScan model + detail UI
```

## Performance

- DNS wordlist and crt.sh run **in parallel** (two threads).
- ~70 priority labels resolved with **28 concurrent** DNS workers (~1.2s timeout each).
- Probes use **A then CNAME** only; `NXDOMAIN` skips extra queries.
- CT-only hosts: at most **50** follow-up DNS checks.

Typical scan: ~15–45s (crt.sh latency dominates). Previously: several minutes (sequential ~180×3 queries).

## Tests

```bash
python manage.py test subdomain_osint
```

## Next module

Module 4 — **Email Breach** — see [MODULE_04_EMAIL_BREACH.md](MODULE_04_EMAIL_BREACH.md).
