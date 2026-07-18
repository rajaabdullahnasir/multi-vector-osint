from django.contrib import admin

from .models import DirBusterScan


@admin.register(DirBusterScan)
class DirBusterScanAdmin(admin.ModelAdmin):
    list_display = (
        "target", "host", "wordlist_tier", "found_count", "forbidden_count",
        "filtered_count", "status", "user", "updated_at",
    )
    list_filter = ("status", "wordlist_tier")
    search_fields = ("target", "host", "user__username")
    readonly_fields = ("id", "created_at", "updated_at")
