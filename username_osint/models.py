import uuid

from django.conf import settings
from django.db import models


class UsernameLookup(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="username_lookups",
    )
    username = models.CharField(max_length=32, db_index=True)
    found_count = models.PositiveSmallIntegerField(default=0)
    checked_count = models.PositiveSmallIntegerField(default=0)
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
        ordering = ["-updated_at", "-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["user", "username"],
                name="username_lookup_user_username_uniq",
            ),
        ]

    def __str__(self):
        return f"{self.username} ({self.id})"

    @classmethod
    def upsert_for_user(cls, user, username: str, **fields) -> tuple["UsernameLookup", bool]:
        username = username.strip()
        row = cls.objects.filter(user=user, username=username).first()
        if row is None:
            return cls.objects.create(user=user, username=username, **fields), True
        for key, value in fields.items():
            setattr(row, key, value)
        row.save(update_fields=[*fields.keys(), "updated_at"])
        return row, False
