from django.contrib import admin

from .models import Investigation


@admin.register(Investigation)
class InvestigationAdmin(admin.ModelAdmin):
    list_display = (
        "target_domain",
        "user",
        "status",
        "overall_risk_level",
        "emails_checked",
        "ips_checked",
        "usernames_checked",
        "updated_at",
    )
    list_filter = ("status", "overall_risk_level")
    search_fields = ("target_domain", "email_hint", "username_hint", "user__username")
    readonly_fields = ("id", "created_at", "updated_at")
