from django.contrib import admin

from .models import SubdomainScan


@admin.register(SubdomainScan)
class SubdomainScanAdmin(admin.ModelAdmin):
    list_display = (
        "domain",
        "user",
        "status",
        "subdomain_count",
        "dns_verified_count",
        "updated_at",
    )
    list_filter = ("status",)
    search_fields = ("domain", "user__email")
    readonly_fields = ("report_json", "created_at", "updated_at")
