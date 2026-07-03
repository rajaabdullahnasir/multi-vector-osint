import uuid

from django.conf import settings
from django.db import models


class HashJob(models.Model):
    class Mode(models.TextChoices):
        HASH = "hash", "Generate hashes"
        COMPARE = "compare", "Compare hash"

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="hash_jobs",
    )
    mode = models.CharField(max_length=16, choices=Mode.choices)
    algorithms = models.JSONField(default=list, blank=True)
    digest_count = models.PositiveSmallIntegerField(default=0)
    matched = models.BooleanField(null=True, blank=True)
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

    def __str__(self):
        return f"{self.mode} ({self.id})"

    @property
    def summary_label(self) -> str:
        if self.mode == self.Mode.COMPARE:
            if self.matched is True:
                return "Match"
            if self.matched is False:
                return "No match"
            return "Compare"
        return f"{self.digest_count} digest(s)"
