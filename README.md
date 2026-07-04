# OSINT Vector — Multi-Vector OSINT Analyzer

Web platform for ethical, passive OSINT — built for iSeeWaves / FYP specification.

## Status

| Module | Status |
|--------|--------|
| Auth & dashboard | ✅ |
| 1. Image OSINT | ✅ Complete |
| 2. WHOIS & DNS | ✅ Complete |
| 3. Subdomain Finder | ✅ Complete |
| 4. Email Breach | ✅ Complete |
| 5. Password Breach | ✅ Complete |
| 6. Username OSINT | ✅ Complete |
| 7. URL Risk | ✅ Complete |
| 8. Password Hasher | ✅ Complete |
| 9. Company / Domain Footprint | ✅ Complete |

## Quick start

```bash
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

Register → verify email (link printed in console) → login → **Image OSINT**.

## Design system

See `design-system/DESIGN_SYSTEM.md`. App templates use `ov-*` classes via `theme.css`.

## Documentation

- [Module 1 — Image OSINT](docs/MODULE_01_IMAGE_OSINT.md)
- [Module 2 — WHOIS & DNS](docs/MODULE_02_WHOIS.md)
- [Module 3 — Subdomain Finder](docs/MODULE_03_SUBDOMAIN.md)
- [Module 4 — Email Breach](docs/MODULE_04_EMAIL_BREACH.md)
- [Module 5 — Password Breach](docs/MODULE_05_PASSWORD_BREACH.md)
- [Module 6 — Username OSINT](docs/MODULE_06_USERNAME.md)
- [Module 7 — URL Risk](docs/MODULE_07_URL_RISK.md)
- [Module 8 — Password Hasher](docs/MODULE_08_PASSWORD_HASHER.md)
- [Module 9 — Company / Domain Footprint](docs/MODULE_09_ORG_FOOTPRINT.md)

### Email Breach (XposedOrNot)

Uses the **free public** [XposedOrNot API](https://xposedornot.com/api_doc) ([open source](https://github.com/XposedOrNot/XposedOrNot-API)) — no API key, no Plus tier.
