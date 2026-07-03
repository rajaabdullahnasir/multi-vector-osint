# Module 6 — Username OSINT (Complete)

## Overview

Passive username enumeration across public profile URLs (SRS-26–27), inspired by Sherlock-style checks without wrapping external CLI tools.

| Capability | Implementation |
|------------|----------------|
| Username validation | `UsernameValidator` — 3–32 chars, reserved names blocked |
| Platform catalog | `platforms.py` — 20+ curated sites |
| Profile checks | `platform_checker.py` — parallel HTTP GET |
| Report / storage | `UsernameLookup` model + JSON export |

## Method

For each platform, the app requests the public profile URL and applies heuristics:

- HTTP **404** (or configured not-found status) → not found
- Optional **not-found phrases** in HTML body
- Optional **found phrases** (e.g. Telegram page markers)
- Default: HTTP **200** → profile likely exists

Results are **heuristic** — sites change layouts and may rate-limit. Always verify manually.

## Routes

| URL | Name |
|-----|------|
| `/modules/username/` | `username_osint:home` |
| `/modules/username/scan/` | POST scan |
| `/modules/username/<uuid>/` | Detail |
| `/modules/username/<uuid>/export.json` | JSON export |

## Configuration

```python
USERNAME_OSINT_USER_AGENT = "OSINT-Vector-Analyzer-FYP"
USERNAME_OSINT_REQUEST_TIMEOUT = 8.0
USERNAME_OSINT_MAX_WORKERS = 10
USERNAME_OSINT_MIN_BATCH_INTERVAL = 0.5
```

## Tests

```bash
python manage.py test username_osint
```

## Ethics

Public profile URLs only. No authentication bypass, no credential stuffing. For authorized OSINT and education.
