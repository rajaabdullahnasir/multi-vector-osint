# Module 1 — Image OSINT (Complete)

## Overview

Module 1 implements **Image OSINT** per the FYP specification (EXIF extraction, optional reverse search, 10MB limit, JPG/PNG/TIFF/WebP).

| Capability | Implementation | Third-party? |
|------------|----------------|--------------|
| File validation | `ImageFileValidator` — magic bytes | No |
| EXIF / metadata | `ExifExtractor` + **piexif** (full IFD read from original bytes) | piexif reads JPEG EXIF; labels/composites are ours |
| JPEG structure | `jpeg_info.py` — SOF/JFIF (YCbCr subsampling, etc.) | No |
| Upload handling | Analyze **original bytes** before save (EXIF not stripped) | No |
| GPS conversion | DMS → decimal in-house | No |
| Perceptual fingerprint | `PerceptualHashEngine` — 8×8 aHash | No |
| File digest | SHA-256 via stdlib `hashlib` | No |
| Reverse image search | `ReverseSearchLinkBuilder` — manual links | **No API** — ask before adding |

## Architecture

```
Upload (form)
    → ImageAnalysis model (stored file)
    → ImageOsintAnalyzer
         → ImageFileValidator
         → ExifExtractor
         → PerceptualHashEngine
         → ReverseSearchLinkBuilder
    → report_json + detail template
```

## Routes

| URL | Name |
|-----|------|
| `/modules/image/` | `image_osint:home` |
| `/modules/image/analyze/` | POST analyze |
| `/modules/image/<uuid>/` | Detail |
| `/modules/image/<uuid>/export.json` | JSON export |

## Reverse search — approval needed

Automated reverse search requires a **third-party API**. Current build provides:

- Google / Yandex / TinEye **manual upload** links
- Yandex-by-URL when the image is served from `/media/` (dev only)
- SHA-256 web search helper

To enable automation, provide one of:

- TinEye API key
- SerpAPI / Google Custom Search credentials
- Other approved provider

## Important: re-upload required

Earlier versions analyzed the **saved** image after Pillow stripped most EXIF. The app now:

1. Reads your **original upload bytes** for analysis  
2. Saves the original file unchanged (`ContentFile`)  
3. Uses **piexif** to read every standard IFD (0th, Exif, GPS, Interop, thumbnail)

**You must upload the image again** to see the full metadata (50+ EXIF fields, ICC, composites).

## Run locally

```bash
cd d:\OSINT
pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser  # optional
python manage.py runserver
```

1. Register at `/accounts/register/`
2. Copy verification URL from the **terminal console** (email backend)
3. Log in → Dashboard → **Image OSINT**

## Tests

```bash
python manage.py test image_osint
```

## Next module

Module 2 will be **WHOIS & Domain Intelligence** (custom WHOIS socket/parser or your approved API).
