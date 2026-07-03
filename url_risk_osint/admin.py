from django.contrib import admin

from .models import UrlRiskCheck


@admin.register(UrlRiskCheck)
class UrlRiskCheckAdmin(admin.ModelAdmin):
    list_display = ("url", "user", "risk_level", "risk_score", "status", "updated_at")
    list_filter = ("risk_level", "status")
    search_fields = ("url", "user__username")
    readonly_fields = ("created_at", "updated_at")
