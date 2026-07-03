from django.contrib import admin

from .models import EmailBreachCheck


@admin.register(EmailBreachCheck)
class EmailBreachCheckAdmin(admin.ModelAdmin):
    list_display = ("email", "user", "status", "breach_count", "is_pwned", "updated_at")
    list_filter = ("status", "is_pwned")
    search_fields = ("email", "user__email")
    readonly_fields = ("report_json", "created_at", "updated_at")
