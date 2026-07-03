# Module 5 — Password Breach Check (Complete)

## Overview

Password exposure check using **k-anonymity** via the free [Pwned Passwords](https://haveibeenpwned.com/Passwords) range API (SRS-29).

| Step | Action |
|------|--------|
| 1 | `SHA1(password)` → uppercase hex (UTF-8), same as C# `SHA1.ComputeHash` |
| 2 | `prefix = hash[0:5]`, `suffix = hash[5:]` |
| 3 | `GET https://api.pwnedpasswords.com/range/{prefix}` |
| 4 | Pwned if response **contains** `suffix`; count from `suffix:count` line |

Example `test123` → SHA-1 `7288EDD0…` → API query uses only `7288E`.

**Plaintext is never stored** in the database. Only the SHA-1 fingerprint is kept for history/upsert.

## Privacy

- Rate limit: ~1.6s between requests (HIBP guidance)
- Authorized testing only

## Routes

| URL | Name |
|-----|------|
| `/modules/password-breach/` | `password_breach_osint:home` |
| `/modules/password-breach/check/` | POST check |
| `/modules/password-breach/<uuid>/` | Detail |

## Configuration

```python
PWNED_PASSWORDS_API_BASE = "https://api.pwnedpasswords.com/range"
PWNED_PASSWORDS_USER_AGENT = "OSINT-Vector-Analyzer-FYP"
PWNED_PASSWORDS_MIN_REQUEST_INTERVAL = 1.6
PASSWORD_BREACH_MAX_LENGTH = 128
```

## Live test

```bash
python manage.py test_pwned_passwords_api
python manage.py test_pwned_passwords_api --password "password"
```

## Tests

```bash
python manage.py test password_breach_osint
```
