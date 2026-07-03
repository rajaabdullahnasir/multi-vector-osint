import uuid

from django.conf import settings
from django.db import models


class UrlRiskCheck(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    class RiskLevel(models.TextChoices):
        SAFE = "safe", "Safe"
        SUSPICIOUS = "suspicious", "Suspicious"
        DANGEROUS = "dangerous", "Dangerous"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="url_risk_checks",
    )
    url = models.CharField(max_length=2048, db_index=True)
    risk_level = models.CharField(
        max_length=16,
        choices=RiskLevel.choices,
        default=RiskLevel.SAFE,
    )
    risk_score = models.PositiveSmallIntegerField(default=0)
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
                fields=["user", "url"],
                name="url_risk_check_user_url_uniq",
            ),
        ]

    def __str__(self):
        return f"{self.url[:80]} ({self.id})"

    @classmethod
    def upsert_for_user(cls, user, url: str, **fields) -> tuple["UrlRiskCheck", bool]:
        row = cls.objects.filter(user=user, url=url).first()
        if row is None:
            return cls.objects.create(user=user, url=url, **fields), True
        for key, value in fields.items():
            setattr(row, key, value)
        row.save(update_fields=[*fields.keys(), "updated_at"])
        return row, False
