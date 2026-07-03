# Module 2 — WHOIS & Domain Intelligence (Complete)

## Overview

Passive domain reconnaissance per FYP spec (SRS-14–17): WHOIS registration data, name servers, and public DNS records.

| Capability | Implementation | Third-party? |
|------------|----------------|--------------|
| Domain validation | `DomainValidator` | No |
| WHOIS query | `WhoisClient` — TCP port 43 + referral | No |
| WHOIS parsing | `WhoisParser` — normalized fields | No |
| DNS records | `DnsResolver` — dnspython | **dnspython** (no stdlib DNS for MX/NS) |
| Risk flags | Expiry, DNSSEC, status, NXDOMAIN | No |

## Routes

| URL | Name |
|-----|------|
| `/modules/whois/` | `whois_osint:home` |
| `/modules/whois/lookup/` | POST lookup |
| `/modules/whois/<uuid>/` | Detail |
| `/modules/whois/<uuid>/export.json` | JSON export |

## Architecture

```
Domain input
  → DomainValidator
  → WhoisClient (primary + referral server)
  → WhoisParser → sections
  → DnsResolver (A, AAAA, MX, NS, TXT, CNAME)
  → DomainLookup model + detail UI
```

## WHOIS client details

- Resolves registry host by TLD map or **IANA whois** referral
- Follows `Registrar WHOIS Server` / `Whois Server` in response
- Stores full raw text for audit/export

## DNS

Requires outbound UDP/TCP 53 (system resolver). Uses configured DNS resolver via dnspython.

## Tests

```bash
python manage.py test whois_osint
```

## Next module

Module 3 — **Subdomain Finder** — see [MODULE_03_SUBDOMAIN.md](MODULE_03_SUBDOMAIN.md).
