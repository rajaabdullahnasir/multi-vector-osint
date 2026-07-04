from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from core.context_processors import resolve_module_nav
from core.dashboard_analytics import build_dashboard_analytics
from email_breach_osint.models import EmailBreachCheck
from image_osint.models import ImageAnalysis
from org_footprint_osint.models import OrgFootprint
from password_breach_osint.models import PasswordBreachCheck
from password_hasher_osint.models import HashJob
from subdomain_osint.models import SubdomainScan
from url_risk_osint.models import UrlRiskCheck
from username_osint.models import UsernameLookup
from whois_osint.models import DomainLookup


@login_required
def dashboard(request):
    analytics = build_dashboard_analytics(request.user)
    module_counts = analytics["module_counts"]

    module_tiles = []
    for mod in resolve_module_nav():
        tile = dict(mod)
        tile["count"] = module_counts.get(mod["slug"], 0)
        module_tiles.append(tile)

    recent_images = ImageAnalysis.objects.filter(user=request.user)[:5]
    recent_domains = DomainLookup.objects.filter(user=request.user)[:5]
    recent_email_checks = EmailBreachCheck.objects.filter(user=request.user)[:5]
    recent_username_lookups = UsernameLookup.objects.filter(user=request.user)[:5]
    recent_url_checks = UrlRiskCheck.objects.filter(user=request.user)[:5]
    recent_subdomain_scans = SubdomainScan.objects.filter(user=request.user)[:5]
    recent_password_checks = PasswordBreachCheck.objects.filter(user=request.user)[:5]
    recent_hash_jobs = HashJob.objects.filter(user=request.user)[:5]
    recent_org_footprints = OrgFootprint.objects.filter(user=request.user)[:5]

    has_recent = any(
        [
            recent_images,
            recent_domains,
            recent_email_checks,
            recent_username_lookups,
            recent_url_checks,
            recent_subdomain_scans,
            recent_password_checks,
            recent_hash_jobs,
            recent_org_footprints,
        ]
    )

    return render(
        request,
        "core/dashboard.html",
        {
            "stats": analytics["stats"],
            "highlights": analytics["highlights"],
            "chart_data": analytics["chart_data"],
            "module_tiles": module_tiles,
            "total_investigations": analytics["total_investigations"],
            "recent_images": recent_images,
            "recent_domains": recent_domains,
            "recent_email_checks": recent_email_checks,
            "recent_username_lookups": recent_username_lookups,
            "recent_url_checks": recent_url_checks,
            "recent_subdomain_scans": recent_subdomain_scans,
            "recent_password_checks": recent_password_checks,
            "recent_hash_jobs": recent_hash_jobs,
            "recent_org_footprints": recent_org_footprints,
            "has_recent": has_recent,
        },
    )
