from django.contrib import admin

from .models import HashJob


@admin.register(HashJob)
class HashJobAdmin(admin.ModelAdmin):
    list_display = ("mode", "user", "digest_count", "matched", "status", "created_at")
    list_filter = ("mode", "status")
    search_fields = ("user__username",)
    readonly_fields = ("created_at", "updated_at")
