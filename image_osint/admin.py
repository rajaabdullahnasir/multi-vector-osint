from django.contrib import admin

from .models import ImageAnalysis


@admin.register(ImageAnalysis)
class ImageAnalysisAdmin(admin.ModelAdmin):
    list_display = (
        "original_filename",
        "user",
        "status",
        "has_exif",
        "created_at",
    )
    list_filter = ("status", "has_exif", "detected_format")
    search_fields = ("original_filename", "sha256_file", "user__email")
    readonly_fields = ("report_json", "created_at", "updated_at")
