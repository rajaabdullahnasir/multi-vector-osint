import uuid

from django.conf import settings
from django.db import models


class Investigation(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="investigations",
    )
    target_domain = models.CharField(max_length=253, db_index=True)
    email_hint = models.CharField(max_length=254, blank=True)
    username_hint = models.CharField(max_length=64, blank=True)

    modules_run = models.JSONField(default=list, blank=True)
    emails_checked = models.PositiveSmallIntegerField(default=0)
    ips_checked = models.PositiveSmallIntegerField(default=0)
    usernames_checked = models.PositiveSmallIntegerField(default=0)
    overall_risk_level = models.CharField(max_length=16, default="low")

    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    error_message = models.TextField(blank=True)
    report_json = models.JSONField(default=dict, blank=True)
    risk_flags = models.JSONField(default=list, blank=True)

    ai_report = models.TextField(blank=True)
    ai_report_generated_at = models.DateTimeField(null=True, blank=True)
    ai_report_error = models.TextField(blank=True)
    ai_report_model = models.CharField(max_length=64, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at", "-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["user", "target_domain"],
                name="investigation_user_domain_uniq",
            ),
        ]

    def __str__(self):
        return f"{self.target_domain} ({self.id})"

    @classmethod
    def upsert_for_user(cls, user, target_domain: str, **fields) -> tuple["Investigation", bool]:
        target_domain = target_domain.strip().lower()
        record = cls.objects.filter(user=user, target_domain=target_domain).first()
        if record is None:
            return cls.objects.create(user=user, target_domain=target_domain, **fields), True
        for key, value in fields.items():
            setattr(record, key, value)
        record.save(update_fields=[*fields.keys(), "updated_at"])
        return record, False
