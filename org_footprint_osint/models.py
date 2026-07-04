import uuid

from django.conf import settings
from django.db import models


class OrgFootprint(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="org_footprints",
    )
    domain = models.CharField(max_length=253, db_index=True)
    org_name = models.CharField(max_length=255, blank=True)
    org_country = models.CharField(max_length=8, blank=True)
    whois_privacy = models.BooleanField(default=False)
    spf_status = models.CharField(max_length=16, blank=True)  # present / missing
    dmarc_status = models.CharField(max_length=16, blank=True)  # none / quarantine / reject / missing
    dkim_selector_count = models.PositiveSmallIntegerField(default=0)
    security_header_score = models.PositiveSmallIntegerField(default=0)  # out of 4
    social_platform_count = models.PositiveSmallIntegerField(default=0)
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
                fields=["user", "domain"],
                name="org_footprint_user_domain_uniq",
            ),
        ]

    def __str__(self):
        return f"{self.domain} ({self.id})"

    @classmethod
    def upsert_for_user(cls, user, domain: str, **fields) -> tuple["OrgFootprint", bool]:
        """Create or refresh the user's footprint scan for this domain (no duplicates)."""
        domain = domain.strip().lower()
        record = cls.objects.filter(user=user, domain=domain).first()
        if record is None:
            return cls.objects.create(user=user, domain=domain, **fields), True
        for key, value in fields.items():
            setattr(record, key, value)
        record.save(update_fields=[*fields.keys(), "updated_at"])
        return record, False
