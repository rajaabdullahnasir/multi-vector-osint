import uuid

from django.conf import settings
from django.db import models


class PasswordBreachCheck(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="password_breach_checks",
    )
    password_sha1 = models.CharField(max_length=40, db_index=True)
    hash_prefix = models.CharField(max_length=5, blank=True)
    exposure_count = models.PositiveIntegerField(default=0)
    is_pwned = models.BooleanField(default=False)
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
                fields=["user", "password_sha1"],
                name="password_breach_user_sha1_uniq",
            ),
        ]

    def __str__(self):
        return f"{self.hash_prefix}… ({self.id})"

    @property
    def masked_sha1(self) -> str:
        if len(self.password_sha1) < 12:
            return self.password_sha1
        return f"{self.password_sha1[:5]}…{self.password_sha1[-4:]}"

    @classmethod
    def upsert_for_user(cls, user, password_sha1: str, **fields) -> tuple["PasswordBreachCheck", bool]:
        password_sha1 = password_sha1.upper()
        row = cls.objects.filter(user=user, password_sha1=password_sha1).first()
        if row is None:
            return cls.objects.create(user=user, password_sha1=password_sha1, **fields), True
        for key, value in fields.items():
            setattr(row, key, value)
        row.save(update_fields=[*fields.keys(), "updated_at"])
        return row, False
