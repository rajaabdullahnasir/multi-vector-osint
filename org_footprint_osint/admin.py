from django.contrib import admin

from .models import OrgFootprint


@admin.register(OrgFootprint)
class OrgFootprintAdmin(admin.ModelAdmin):
    list_display = (
        "domain",
        "user",
        "status",
        "spf_status",
        "dmarc_status",
        "security_header_score",
        "updated_at",
    )
    list_filter = ("status", "spf_status", "dmarc_status")
    search_fields = ("domain", "org_name", "user__username", "user__email")
    readonly_fields = ("id", "created_at", "updated_at")
