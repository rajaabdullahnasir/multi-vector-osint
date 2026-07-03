from django.contrib import admin

from .models import PasswordBreachCheck


@admin.register(PasswordBreachCheck)
class PasswordBreachCheckAdmin(admin.ModelAdmin):
    list_display = (
        "hash_prefix",
        "user",
        "is_pwned",
        "exposure_count",
        "status",
        "updated_at",
    )
    list_filter = ("status", "is_pwned")
    search_fields = ("password_sha1", "user__username")
    readonly_fields = ("created_at", "updated_at")
