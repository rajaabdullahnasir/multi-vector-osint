from django.contrib import admin

from .models import IPIntelligence


@admin.register(IPIntelligence)
class IPIntelligenceAdmin(admin.ModelAdmin):
    list_display = (
        "query_input",
        "ip_address",
        "user",
        "country",
        "city",
        "is_proxy_or_vpn",
        "status",
        "updated_at",
    )
    list_filter = ("status", "is_proxy_or_vpn", "is_hosting", "country")
    search_fields = ("query_input", "ip_address", "org_name", "user__username", "user__email")
    readonly_fields = ("id", "created_at", "updated_at")
