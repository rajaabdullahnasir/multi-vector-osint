from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from django.db.models import Count, Sum
from django.db.models.functions import TruncDate
from django.utils import timezone

from dirbuster_osint.models import DirBusterScan
from email_breach_osint.models import EmailBreachCheck
from image_osint.models import ImageAnalysis
from investigation_osint.models import Investigation
from ip_intel_osint.models import IPIntelligence
from org_footprint_osint.models import OrgFootprint
from password_breach_osint.models import PasswordBreachCheck
from password_hasher_osint.models import HashJob
from subdomain_osint.models import SubdomainScan
from url_risk_osint.models import UrlRiskCheck
from username_osint.models import UsernameLookup
from whois_osint.models import DomainLookup

ACTIVITY_DAYS = 14

MODULE_MODELS = {
    "image": ("Image OSINT", ImageAnalysis),
    "whois": ("WHOIS & DNS", DomainLookup),
    "subdomain": ("Subdomain Finder", SubdomainScan),
    "email-breach": ("Email Breach", EmailBreachCheck),
    "password-breach": ("Password Breach", PasswordBreachCheck),
    "username": ("Username OSINT", UsernameLookup),
    "url-risk": ("URL Risk", UrlRiskCheck),
    "hasher": ("Password Hasher", HashJob),
    "org-footprint": ("Company Footprint", OrgFootprint),
    "ip-intel": ("IP Intelligence", IPIntelligence),
    "investigation": ("Investigation", Investigation),
    "dirbuster": ("Directory Buster", DirBusterScan),
}


def _user_qs(model, user):
    return model.objects.filter(user=user)


def _daily_counts(qs, days: int = ACTIVITY_DAYS) -> dict:
    start = timezone.localdate() - timedelta(days=days - 1)
    start_dt = timezone.make_aware(datetime.combine(start, datetime.min.time()))
    rows = (
        qs.filter(created_at__gte=start_dt)
        .annotate(day=TruncDate("created_at"))
        .values("day")
        .annotate(count=Count("id"))
    )
    return {row["day"]: row["count"] for row in rows}


def _merge_daily_series(*maps: dict, days: int = ACTIVITY_DAYS) -> tuple[list[str], list[int]]:
    merged: dict = defaultdict(int)
    for m in maps:
        for day, count in m.items():
            merged[day] += count

    start = timezone.localdate() - timedelta(days=days - 1)
    labels: list[str] = []
    values: list[int] = []
    for offset in range(days):
        day = start + timedelta(days=offset)
        labels.append(day.strftime("%b %d"))
        values.append(merged.get(day, 0))
    return labels, values


def build_dashboard_analytics(user) -> dict:
    module_counts: dict[str, int] = {}
    daily_maps = []
    for slug, (_, model) in MODULE_MODELS.items():
        qs = _user_qs(model, user)
        module_counts[slug] = qs.count()
        daily_maps.append(_daily_counts(qs))

    total_investigations = sum(module_counts.values())
    modules_used = sum(1 for c in module_counts.values() if c > 0)

    activity_labels, activity_values = _merge_daily_series(*daily_maps)
    week_total = sum(activity_values[-7:]) if activity_values else 0

    module_labels = [MODULE_MODELS[slug][0] for slug in MODULE_MODELS]
    module_values = [module_counts[slug] for slug in MODULE_MODELS]

    url_qs = _user_qs(UrlRiskCheck, user)
    url_safe = url_qs.filter(risk_level=UrlRiskCheck.RiskLevel.SAFE).count()
    url_suspicious = url_qs.filter(risk_level=UrlRiskCheck.RiskLevel.SUSPICIOUS).count()
    url_dangerous = url_qs.filter(risk_level=UrlRiskCheck.RiskLevel.DANGEROUS).count()

    email_pwned = _user_qs(EmailBreachCheck, user).filter(is_pwned=True).count()
    password_pwned = _user_qs(PasswordBreachCheck, user).filter(is_pwned=True).count()
    risk_signals = email_pwned + password_pwned + url_dangerous

    image_qs = _user_qs(ImageAnalysis, user)
    images_with_exif = image_qs.filter(has_exif=True).count()
    image_total = module_counts["image"]

    subdomain_qs = _user_qs(SubdomainScan, user)
    subdomains_found = subdomain_qs.aggregate(total=Sum("subdomain_count"))["total"] or 0

    username_qs = _user_qs(UsernameLookup, user)
    profiles_found = username_qs.aggregate(total=Sum("found_count"))["total"] or 0

    stats = [
        {
            "label": "Total investigations",
            "value": total_investigations,
            "hint": "Saved lookups across all modules",
            "icon": "bar-chart",
        },
        {
            "label": "Active modules",
            "value": f"{modules_used}/12",
            "hint": "Modules you have used at least once",
            "icon": "layers",
        },
        {
            "label": "This week",
            "value": week_total,
            "hint": "Investigations in the last 7 days",
            "icon": "activity",
        },
        {
            "label": "Risk signals",
            "value": risk_signals,
            "hint": "Pwned credentials and dangerous URLs",
            "icon": "shield-alert",
        },
    ]

    chart_data = {
        "activity": {"labels": activity_labels, "values": activity_values},
        "modules": {"labels": module_labels, "values": module_values},
        "urlRisk": {
            "labels": ["Safe", "Suspicious", "Dangerous"],
            "values": [url_safe, url_suspicious, url_dangerous],
        },
        "exposure": {
            "labels": ["Pwned emails", "Pwned passwords", "Dangerous URLs"],
            "values": [email_pwned, password_pwned, url_dangerous],
        },
    }

    highlights = {
        "images_with_exif": images_with_exif,
        "image_total": image_total,
        "subdomains_found": subdomains_found,
        "profiles_found": profiles_found,
        "email_pwned": email_pwned,
        "password_pwned": password_pwned,
    }

    return {
        "stats": stats,
        "module_counts": module_counts,
        "chart_data": chart_data,
        "highlights": highlights,
        "total_investigations": total_investigations,
    }
