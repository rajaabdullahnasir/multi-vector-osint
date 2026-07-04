import uuid

from django.conf import settings
from django.db import models


class IPIntelligence(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="ip_intel_lookups",
    )
    query_input = models.CharField(max_length=253, db_index=True)  # what the user typed
    ip_address = models.CharField(max_length=45, blank=True, db_index=True)  # resolved IPv4/IPv6
    ptr_hostname = models.CharField(max_length=255, blank=True)
    asn = models.CharField(max_length=32, blank=True)
    isp = models.CharField(max_length=255, blank=True)
    org_name = models.CharField(max_length=255, blank=True)
    country = models.CharField(max_length=8, blank=True)
    region = models.CharField(max_length=128, blank=True)
    city = models.CharField(max_length=128, blank=True)
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    timezone = models.CharField(max_length=64, blank=True)
    is_proxy_or_vpn = models.BooleanField(default=False)
    is_hosting = models.BooleanField(default=False)
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
                fields=["user", "query_input"],
                name="ip_intel_user_query_uniq",
            ),
        ]

    def __str__(self):
        return f"{self.query_input} ({self.id})"

    @classmethod
    def upsert_for_user(cls, user, query_input: str, **fields) -> tuple["IPIntelligence", bool]:
        """Create or refresh the user's lookup for this query (no duplicates)."""
        query_input = query_input.strip().lower()
        record = cls.objects.filter(user=user, query_input=query_input).first()
        if record is None:
            return cls.objects.create(user=user, query_input=query_input, **fields), True
        for key, value in fields.items():
            setattr(record, key, value)
        record.save(update_fields=[*fields.keys(), "updated_at"])
        return record, False
