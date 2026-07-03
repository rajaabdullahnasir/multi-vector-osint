from django.contrib import admin

from .models import UsernameLookup


@admin.register(UsernameLookup)
class UsernameLookupAdmin(admin.ModelAdmin):
    list_display = ("username", "user", "found_count", "checked_count", "status", "updated_at")
    list_filter = ("status",)
    search_fields = ("username", "user__username")
    readonly_fields = ("created_at", "updated_at")
