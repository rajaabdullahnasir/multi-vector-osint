"""
Django settings for OSINT Vector (Multi-Vector OSINT Analyzer).
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = "django-insecure-dev-only-change-in-production"
DEBUG = True
ALLOWED_HOSTS = ["localhost", "127.0.0.1"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "accounts.apps.AccountsConfig",
    "core.apps.CoreConfig",
    "image_osint.apps.ImageOsintConfig",
    "whois_osint.apps.WhoisOsintConfig",
    "subdomain_osint.apps.SubdomainOsintConfig",
    "email_breach_osint.apps.EmailBreachOsintConfig",
    "username_osint.apps.UsernameOsintConfig",
    "url_risk_osint.apps.UrlRiskOsintConfig",
    "password_hasher_osint.apps.PasswordHasherOsintConfig",
    "password_breach_osint.apps.PasswordBreachOsintConfig",
    "org_footprint_osint.apps.OrgFootprintOsintConfig",
    "ip_intel_osint.apps.IpIntelOsintConfig",
    "investigation_osint.apps.InvestigationOsintConfig",
    "dirbuster_osint.apps.DirbusterOsintConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "core.context_processors.navigation",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "accounts.validators.StrongPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATICFILES_DIRS = [
    BASE_DIR / "design-system",
]
STATIC_ROOT = BASE_DIR / "staticfiles"

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "accounts:login"
LOGIN_REDIRECT_URL = "core:dashboard"
LOGOUT_REDIRECT_URL = "accounts:login"

# OSINT Vector — Module 1 (Image OSINT)
IMAGE_OSINT_MAX_BYTES = 10 * 1024 * 1024  # SRS-30: 10MB
IMAGE_OSINT_ALLOWED_MIME = {
    "image/jpeg",
    "image/png",
    "image/tiff",
    "image/webp",
}
IMAGE_OSINT_UPLOAD_SUBDIR = "image_osint/uploads"

# Module 2 — WHOIS & DNS
WHOIS_TIMEOUT_SECONDS = 12
WHOIS_MAX_RESPONSE_BYTES = 1_000_000  # safety cap against a misbehaving server

# Module 4 — Email Breach (XposedOrNot free public API, SRS-22)
# https://xposedornot.com/api_doc — no API key; open-source https://github.com/XposedOrNot
XPOSEDORNOT_API_BASE = os.environ.get(
    "XPOSEDORNOT_API_BASE", "https://api.xposedornot.com/v1"
)
XPOSEDORNOT_USER_AGENT = "OSINT-Vector-Analyzer-FYP"
XPOSEDORNOT_MIN_REQUEST_INTERVAL = 1.0
# Route API via VPN/proxy when blocked (e.g. Pakistan). Example: http://127.0.0.1:8080
XPOSEDORNOT_HTTP_PROXY = os.environ.get("XPOSEDORNOT_HTTP_PROXY", "")

# Module 6 — Username OSINT (SRS-26–27)
USERNAME_OSINT_USER_AGENT = "OSINT-Vector-Analyzer-FYP"
USERNAME_OSINT_REQUEST_TIMEOUT = 8.0
USERNAME_OSINT_MAX_WORKERS = 10
USERNAME_OSINT_MIN_BATCH_INTERVAL = 0.5

# Module 5 — Password Breach (Pwned Passwords k-anonymity, SRS-29)
PWNED_PASSWORDS_API_BASE = "https://api.pwnedpasswords.com/range"
PWNED_PASSWORDS_USER_AGENT = "OSINT-Vector-Analyzer-FYP"
PWNED_PASSWORDS_MIN_REQUEST_INTERVAL = 1.6
PASSWORD_BREACH_MAX_LENGTH = 128

# Module 8 — Password Hasher (SRS-31–32)
PASSWORD_HASHER_MAX_INPUT_LENGTH = 256

# Module 9 — Company / Domain Footprint (passive WHOIS + DNS + HTTP headers)
ORG_FOOTPRINT_HTTP_TIMEOUT_SECONDS = 6.0
ORG_FOOTPRINT_DNS_TIMEOUT_SECONDS = 5.0

# Module 10 — Geolocation / IP Intelligence (RDAP + free geolocation)
RDAP_API_BASE = os.environ.get("RDAP_API_BASE", "https://rdap.org")
RDAP_USER_AGENT = "OSINT-Vector-Analyzer-FYP"
RDAP_MIN_REQUEST_INTERVAL = 1.0

IP_GEOLOCATION_API_BASE = os.environ.get(
    "IP_GEOLOCATION_API_BASE", "http://ip-api.com/json"
)
IP_GEOLOCATION_USER_AGENT = "OSINT-Vector-Analyzer-FYP"
IP_GEOLOCATION_MIN_REQUEST_INTERVAL = 1.4

# Module 11 — AI-generated narrative report (Groq, OpenAI-compatible, free tier)
# GROQ_API_KEY is required for this feature only — everything else in the
# app works with zero AI dependency. Get a free key at https://console.groq.com
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_API_BASE = os.environ.get("GROQ_API_BASE", "https://api.groq.com/openai/v1")
# gpt-oss-120b for report-writing quality; gpt-oss-20b is faster if preferred.
# Groq deprecated the older llama-3.x chat models — don't revert to those.
GROQ_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")
GROQ_HTTP_TIMEOUT_SECONDS = 90
GROQ_MAX_COMPLETION_TOKENS = 2000  # free tier TPM is tight (e.g. 8000 for gpt-oss-120b); leave headroom for input
GROQ_SAFE_TOKEN_BUDGET = 7000  # trim harder if the estimated request would exceed this

# Account lockout (SRS-12)
AUTH_LOCKOUT_MAX_ATTEMPTS = 5
AUTH_LOCKOUT_MINUTES = 15

EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
DEFAULT_FROM_EMAIL = "noreply@osintvector.local"
