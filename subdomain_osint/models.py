import uuid

from django.conf import settings
from django.db import models


class SubdomainScan(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="subdomain_scans",
    )
    domain = models.CharField(max_length=253, db_index=True)
    subdomain_count = models.PositiveSmallIntegerField(default=0)
    dns_verified_count = models.PositiveSmallIntegerField(default=0)
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.PENDING,
    )
    error_message = models.TextField(blank=True)
    sources_used = models.JSONField(default=list, blank=True)
    report_json = models.JSONField(default=dict, blank=True)
    risk_flags = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at", "-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["user", "domain"],
                name="subdomain_scan_user_domain_uniq",
            ),
        ]

    def __str__(self):
        return f"{self.domain} ({self.id})"

    @classmethod
    def upsert_for_user(cls, user, domain: str, **fields) -> tuple["SubdomainScan", bool]:
        domain = domain.strip().lower()
        scan = cls.objects.filter(user=user, domain=domain).first()
        if scan is None:
            return cls.objects.create(user=user, domain=domain, **fields), True
        for key, value in fields.items():
            setattr(scan, key, value)
        scan.save(update_fields=[*fields.keys(), "updated_at"])
        return scan, False
