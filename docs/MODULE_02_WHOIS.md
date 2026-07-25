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

## DNS zone transfer (AXFR) test, added

For each nameserver returned by WHOIS, checks whether it will hand over
the full DNS zone to an unauthenticated request (AXFR) — a serious,
well-known misconfiguration (properly configured nameservers only allow
AXFR to specific authorized secondaries). Standard technique used by
tools like dnsrecon/fierce; this is just a normal DNS protocol query,
nothing more invasive than any other DNS lookup this module already does.

If any nameserver is vulnerable, the leaked record count and a sample of
disclosed hostnames are shown, plus a CRITICAL risk flag — a real zone
transfer commonly reveals internal hostnames/IPs not otherwise
discoverable. If all nameservers correctly refuse, the report says so
plainly rather than silently omitting the check.

Files: whois_osint/services/zone_transfer.py (ZoneTransferTester).
