import uuid

from django.conf import settings
from django.db import models


class DomainLookup(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="domain_lookups",
    )
    domain = models.CharField(max_length=253, db_index=True)
    registrar = models.CharField(max_length=255, blank=True)
    creation_date = models.CharField(max_length=64, blank=True)
    expiry_date = models.CharField(max_length=64, blank=True)
    name_server_count = models.PositiveSmallIntegerField(default=0)
    dns_record_count = models.PositiveSmallIntegerField(default=0)
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
                name="whois_domainlookup_user_domain_uniq",
            ),
        ]

    def __str__(self):
        return f"{self.domain} ({self.id})"

    @classmethod
    def upsert_for_user(cls, user, domain: str, **fields) -> tuple["DomainLookup", bool]:
        """Create or refresh the user's lookup for this domain (no duplicates)."""
        domain = domain.strip().lower()
        lookup = cls.objects.filter(user=user, domain=domain).first()
        if lookup is None:
            return cls.objects.create(user=user, domain=domain, **fields), True
        for key, value in fields.items():
            setattr(lookup, key, value)
        lookup.save(update_fields=[*fields.keys(), "updated_at"])
        return lookup, False
