from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone

from .verification import generate_verification_token


class UserProfile(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="profile",
    )
    organization = models.CharField(max_length=255, blank=True)
    email_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Profile({self.user.username})"


class EmailVerificationToken(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="verification_tokens",
    )
    token = models.CharField(max_length=128, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    used_at = models.DateTimeField(null=True, blank=True)

    @classmethod
    def create_for_user(cls, user):
        # Invalidate older unused tokens so only the latest link works.
        cls.objects.filter(user=user, used_at__isnull=True).delete()
        return cls.objects.create(
            user=user,
            token=generate_verification_token(),
        )

    def mark_used(self):
        self.used_at = timezone.now()
        self.save(update_fields=["used_at"])

    @property
    def is_valid(self):
        if self.used_at:
            return False
        expiry = self.created_at + timedelta(hours=48)
        return timezone.now() < expiry


class LoginAttemptTracker(models.Model):
    """Tracks failed logins for SRS-12 account lockout."""

    email = models.EmailField(db_index=True)
    failed_count = models.PositiveIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    last_attempt_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Login attempt tracker"

    @property
    def is_locked(self):
        if self.locked_until and timezone.now() < self.locked_until:
            return True
        return False
