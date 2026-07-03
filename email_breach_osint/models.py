import uuid

from django.conf import settings
from django.db import models


class EmailBreachCheck(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="email_breach_checks",
    )
    email = models.CharField(max_length=254, db_index=True)
    breach_count = models.PositiveSmallIntegerField(default=0)
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
                fields=["user", "email"],
                name="email_breach_check_user_email_uniq",
            ),
        ]

    def __str__(self):
        return f"{self.email} ({self.id})"

    @classmethod
    def upsert_for_user(cls, user, email: str, **fields) -> tuple["EmailBreachCheck", bool]:
        email = email.strip().lower()
        row = cls.objects.filter(user=user, email=email).first()
        if row is None:
            return cls.objects.create(user=user, email=email, **fields), True
        for key, value in fields.items():
            setattr(row, key, value)
        row.save(update_fields=[*fields.keys(), "updated_at"])
        return row, False
