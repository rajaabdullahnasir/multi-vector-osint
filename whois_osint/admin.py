from django.contrib import admin

from .models import DomainLookup


@admin.register(DomainLookup)
class DomainLookupAdmin(admin.ModelAdmin):
    list_display = ("domain", "user", "status", "registrar", "created_at")
    list_filter = ("status",)
    search_fields = ("domain", "registrar", "user__email")
    readonly_fields = ("report_json", "created_at", "updated_at")
