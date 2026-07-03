# Module 8 — Password Hasher (Complete)

## Overview

Educational hashing and comparison utilities (SRS-31–32). **No plaintext is stored** in the database — only digests and comparison metadata.

| Capability | Implementation |
|------------|----------------|
| Hash generation | MD5, SHA-1, SHA-256, SHA-512, Base64 encode/decode |
| Hash compare | Plaintext vs hex digest (MD5/SHA family) |
| History | `HashJob` per operation (append-only) |
| Export | JSON report |

## Security notes

- MD5 and SHA-1 are marked **weak** — suitable for learning, not for password storage.
- Use **SHA-256** or better (bcrypt/Argon2) in real systems.
- Authorized testing only — do not use on third-party credentials without permission.

## Routes

| URL | Name |
|-----|------|
| `/modules/hasher/` | `password_hasher_osint:home` |
| `/modules/hasher/hash/` | POST generate |
| `/modules/hasher/compare/` | POST compare |
| `/modules/hasher/<uuid>/` | Detail |

## Configuration

```python
PASSWORD_HASHER_MAX_INPUT_LENGTH = 256
```

## Tests

```bash
python manage.py test password_hasher_osint
```
