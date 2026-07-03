# Module 4 — Email Breach Check (Complete)

## Overview

Email breach lookup via the **free** XposedOrNot `check-email` endpoint only (SRS-22–25).

| Capability | Implementation |
|------------|----------------|
| Email validation | `EmailValidator` |
| Breach lookup | `GET /v1/check-email/{email}` |
| Not found | `{"Error":"Not found"}` |
| Storage / export | `EmailBreachCheck` + JSON |

## API

```
GET https://api.xposedornot.com/v1/check-email/{email}
```

Docs: https://xposedornot.com/api_doc · Open source: https://github.com/XposedOrNot/XposedOrNot-API

## Configuration

```python
XPOSEDORNOT_API_BASE = "https://api.xposedornot.com/v1"
XPOSEDORNOT_USER_AGENT = "OSINT-Vector-Analyzer-FYP"
XPOSEDORNOT_MIN_REQUEST_INTERVAL = 1.0
XPOSEDORNOT_HTTP_PROXY = ""  # optional VPN/proxy URL
```

### Environment variables

```bash
# Windows PowerShell — route through local VPN proxy
$env:XPOSEDORNOT_HTTP_PROXY = "http://127.0.0.1:8080"

# Or point to your own self-hosted XposedOrNot API (outside blocked region)
$env:XPOSEDORNOT_API_BASE = "https://your-vps.example.com/v1"
```

## Troubleshooting — HTTP 403 (Pakistan / geo-block)

`api.xposedornot.com` sits behind **Cloudflare**. Many Pakistani (and some corporate) IPs get **403 Forbidden** with an HTML “Just a moment…” page — not an app bug.

**Workarounds (XposedOrNot only):**

1. **VPN + HTTP proxy** — Connect VPN, expose its local proxy port, then:
   ```powershell
   $env:XPOSEDORNOT_HTTP_PROXY = "http://127.0.0.1:YOUR_PROXY_PORT"
   python manage.py runserver
   ```

2. **Self-host** — Deploy [XposedOrNot-API](https://github.com/XposedOrNot/XposedOrNot-API) on a VPS outside the blocked region, then set `XPOSEDORNOT_API_BASE` to your instance.

3. **Verify** — After configuring proxy or self-host:
   ```bash
   python manage.py test_xposedornot_api user@domain.com
   ```

The web UI at https://xposedornot.com may work in a browser from Pakistan even when server-side `requests` is blocked — browser traffic uses different Cloudflare rules.

## Routes

| URL | Name |
|-----|------|
| `/modules/email-breach/` | `email_breach_osint:home` |
| `/modules/email-breach/check/` | POST |
| `/modules/email-breach/<uuid>/` | Detail |

## Tests

```bash
python manage.py test email_breach_osint
```
