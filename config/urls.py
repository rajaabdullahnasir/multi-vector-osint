from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("core.urls")),
    path("accounts/", include("accounts.urls")),
    path("modules/image/", include(("image_osint.urls", "image_osint"))),
    path("modules/whois/", include(("whois_osint.urls", "whois_osint"))),
    path("modules/subdomain/", include(("subdomain_osint.urls", "subdomain_osint"))),
    path(
        "modules/email-breach/",
        include(("email_breach_osint.urls", "email_breach_osint")),
    ),
    path(
        "modules/password-breach/",
        include(("password_breach_osint.urls", "password_breach_osint")),
    ),
    path(
        "modules/username/",
        include(("username_osint.urls", "username_osint")),
    ),
    path(
        "modules/url-risk/",
        include(("url_risk_osint.urls", "url_risk_osint")),
    ),
    path(
        "modules/hasher/",
        include(("password_hasher_osint.urls", "password_hasher_osint")),
    ),
    path(
        "modules/org-footprint/",
        include(("org_footprint_osint.urls", "org_footprint_osint")),
    ),
]

if settings.DEBUG:
    from django.contrib.staticfiles.urls import staticfiles_urlpatterns

    urlpatterns += staticfiles_urlpatterns()
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
