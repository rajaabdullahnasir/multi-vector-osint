import uuid

from django.conf import settings
from django.db import models


class DirBusterScan(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="dirbuster_scans",
    )
    target = models.CharField(max_length=512, db_index=True)
    base_url = models.CharField(max_length=512, blank=True)
    host = models.CharField(max_length=253, blank=True)
    wordlist_tier = models.CharField(max_length=16, blank=True)

    checked_count = models.PositiveSmallIntegerField(default=0)
    found_count = models.PositiveSmallIntegerField(default=0)
    redirect_count = models.PositiveSmallIntegerField(default=0)
    forbidden_count = models.PositiveSmallIntegerField(default=0)
    filtered_count = models.PositiveSmallIntegerField(default=0)

    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    error_message = models.TextField(blank=True)
    report_json = models.JSONField(default=dict, blank=True)
    risk_flags = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at", "-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["user", "target"],
                name="dirbuster_user_target_uniq",
            ),
        ]

    def __str__(self):
        return f"{self.target} ({self.id})"

    @classmethod
    def upsert_for_user(cls, user, target: str, **fields) -> tuple["DirBusterScan", bool]:
        target = target.strip()
        record = cls.objects.filter(user=user, target=target).first()
        if record is None:
            return cls.objects.create(user=user, target=target, **fields), True
        for key, value in fields.items():
            setattr(record, key, value)
        record.save(update_fields=[*fields.keys(), "updated_at"])
        return record, False
