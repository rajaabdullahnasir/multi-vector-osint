# Module 12 — Directory Buster (Complete)

Plus: Subdomain Finder enhancement — HTTP liveness probing.

## Directory Buster

Brute-forces common paths using three built-in wordlist tiers (no external
files needed): Quick (47 paths), Common (237), Extended (382).

### Soft-404 false-positive filtering

Many sites return HTTP 200 for every path (SPA routing, catch-all pages).
`DirBusterEngine` calibrates a baseline first by requesting random
nonexistent paths; if the response is consistently non-404, matching real
scan hits are filtered as `soft_404_filtered` — shown separately, never
silently dropped. Verified with tests covering: normal 404 sites (no
filtering), full SPA catch-alls (zero false "found"), and mixed cases
(real hit still surfaces despite a noisy baseline).

### Honesty about what a "found" result proves

Live testing against `github.com` showed `/admin`, `/config` etc.
returning genuine 200s — real registered GitHub usernames, not an actual
admin panel. The risk-flag wording says explicitly that a 2xx only
confirms a page exists, not that the content is sensitive — same lesson
as the earlier Company Footprint overclaim fix.

### Safety

Private/loopback/reserved targets rejected before any request
(`TargetValidator`). Response bodies capped at 4096 bytes read. Threaded,
10 workers, deterministic result ordering.

## Subdomain Finder: HTTP liveness probing

Every DNS-verified host (capped at 30) is now probed for HTTP liveness —
status, page title, Server header — turning a bare hostname list into
live web-asset intel. Feeds a stronger risk flag when a sensitive-looking
subdomain (admin/dev/internal) is not just DNS-resolved but actually
serving live content right now. Detail page links each live host directly
into Directory Buster via `?target=`.

## Files

```
dirbuster_osint/
  models.py, forms.py, views.py, urls.py, admin.py
  services/wordlists.py, target_validator.py, dirbuster_engine.py, analyzer.py
  tests/
templates/dirbuster_osint/home.html, detail.html
subdomain_osint/services/http_prober.py
```
