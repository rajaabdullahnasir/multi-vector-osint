# Module 10 — Geolocation / IP Intelligence (Complete)

## Overview

Module 10 accepts an **IP address or domain name**, resolves it to a public
IP if needed, and builds a report from three free, no-API-key sources.

| Capability | Implementation | Source |
|------------|----------------|--------|
| Input resolution | `IPInputResolver` — accepts raw IPv4/IPv6 or a domain (resolved via A/AAAA), rejects private/loopback/reserved ranges | Local `dnspython` resolution |
| Geolocation, ISP, ASN, proxy/hosting flags | `IPGeolocationClient` | `ip-api.com` free JSON endpoint (no key, ~45 req/min limit) |
| Network registration (range, registered entity, country) | `RdapClient` | `rdap.org` — auto-routes to the correct RIR (ARIN/RIPE/APNIC/LACNIC/AFRINIC), the modern successor to WHOIS for IPs |

Both external clients follow the exact throttling/settings pattern already
used by `password_breach_osint`'s Pwned Passwords client and
`email_breach_osint`'s XposedOrNot client — a settings-overridable API base,
a fixed `User-Agent`, and a minimum request interval enforced in-process.

## Why two sources instead of one

`ip-api.com` gives fast, rich geolocation + proxy/hosting detection but is a
single commercial-adjacent service. `rdap.org` gives the authoritative
registration data straight from the responsible Regional Internet Registry.
Cross-referencing both gives more confidence than either alone, and if one
is down or rate-limited the report still returns partial results instead of
failing outright.

## Risk flags

Derived in `IPIntelAnalyzer._derive_risk_flags`:

- IP is a known proxy/VPN exit node (`ip-api.com`'s `proxy` field)
- IP belongs to a hosting/datacenter provider rather than a residential ISP (`hosting` field)

## Ethical scope

- IP geolocation is inherently city-level at best — the detail page includes
  an explicit caption warning against treating it as precise, and links out
  to OpenStreetMap rather than embedding a map that implies exactness.
- Private, loopback, link-local, and reserved IP ranges are rejected before
  any external request is made (`ipaddress.ip_address(...).is_private` etc.).
- No personal data is requested or returned — only network/infrastructure
  metadata about the IP itself.

## Known environment limitation

Both `ip-api.com` and `rdap.org` require outbound internet access. In
network-locked environments (restrictive egress proxies, some CI sandboxes)
these calls may return connection errors or HTTP 403 from the proxy itself
— the report degrades gracefully (shows a notice per section) rather than
failing the whole scan. Confirmed working end-to-end against `8.8.8.8` in a
normal internet-connected environment.

## Files

```
ip_intel_osint/
  models.py                       IPIntelligence
  forms.py                        IPIntelForm
  views.py                        module_home, run_scan, scan_detail, export_json, delete_scan
  urls.py
  admin.py
  services/
    ip_validator.py                IPInputResolver (validation + domain resolution)
    rdap_client.py                 RdapClient
    ip_geolocation_client.py       IPGeolocationClient
    analyzer.py                    IPIntelAnalyzer orchestrator
  tests/
    test_models.py
    test_services.py
    test_views.py
templates/ip_intel_osint/
  home.html
  detail.html
```
