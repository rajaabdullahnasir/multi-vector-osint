import uuid

from django.conf import settings
from django.db import models


def image_upload_path(instance, filename):
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "bin"
    return f"{settings.IMAGE_OSINT_UPLOAD_SUBDIR}/{instance.pk}/{uuid.uuid4().hex[:12]}.{ext}"


class ImageAnalysis(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="image_analyses",
    )
    original_filename = models.CharField(max_length=255)
    image = models.ImageField(upload_to=image_upload_path)
    file_size_bytes = models.PositiveIntegerField(default=0)
    mime_type = models.CharField(max_length=64, blank=True)
    detected_format = models.CharField(max_length=16, blank=True)
    width = models.PositiveIntegerField(default=0)
    height = models.PositiveIntegerField(default=0)
    has_exif = models.BooleanField(default=False)
    perceptual_hash = models.CharField(max_length=32, blank=True)
    sha256_file = models.CharField(max_length=64, blank=True, db_index=True)
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.PENDING,
    )
    error_message = models.TextField(blank=True)
    report_json = models.JSONField(default=dict, blank=True)
    risk_flags = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name_plural = "Image analyses"

    def __str__(self):
        return f"{self.original_filename} ({self.id})"

    @property
    def public_image_url(self):
        if self.image:
            return self.image.url
        return None
