# Module 7 — URL Risk Detection (Complete)

## Overview

Passive URL risk assessment per FYP spec (SRS-28–29): **lexical analysis** plus **static blacklist** rules, producing **Safe**, **Suspicious**, or **Dangerous**.

| Capability | Implementation |
|------------|----------------|
| URL validation | `UrlValidator` — http/https only, no localhost/private IPs |
| Lexical heuristics | `lexical_analyzer.py` — structure, encoding, impersonation |
| Blacklist | `blacklist.py` — domains, TLDs, path keywords, patterns |
| Scoring | `risk_scorer.py` — combined score 0–100, level thresholds |
| Storage / export | `UrlRiskCheck` + JSON |

## Risk levels

| Level | Typical condition |
|-------|-----------------|
| **Safe** | Score &lt; 25, no blacklist hits |
| **Suspicious** | Score 25–54 or medium blacklist hits |
| **Dangerous** | Score ≥ 55 or high-severity blacklist hit |

## Routes

| URL | Name |
|-----|------|
| `/modules/url-risk/` | `url_risk_osint:home` |
| `/modules/url-risk/check/` | POST analyze |
| `/modules/url-risk/<uuid>/` | Detail |
| `/modules/url-risk/<uuid>/export.json` | JSON export |

## Limits

- **No live HTTP fetch** — analysis is offline/static (fast, safe for lab use).
- Blacklist is a **demo/education** set — not a live threat intelligence feed.
- For production triage, integrate VirusTotal, URLhaus, or similar with explicit API approval.

## Tests

```bash
python manage.py test url_risk_osint
```
