from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.utils import timezone

from .models import EmailVerificationToken, LoginAttemptTracker, UserProfile
from .verification import (
    build_verification_url,
    is_token_format_valid,
    normalize_verification_token,
)

User = get_user_model()


def get_or_create_profile(user):
    profile, _ = UserProfile.objects.get_or_create(user=user)
    return profile


def send_verification_email(request, user):
    token_obj = EmailVerificationToken.create_for_user(user)
    verify_url = build_verification_url(request, token_obj.token)
    send_mail(
        subject="Verify your OSINT Vector account",
        message=(
            f"Hello {user.get_full_name() or user.username},\n\n"
            f"Click the link below to verify your email:\n{verify_url}\n\n"
            "This link expires in 48 hours."
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )
    return token_obj


def verify_email_token(raw_token: str):
    token = normalize_verification_token(raw_token)
    if not is_token_format_valid(token):
        return None, (
            "Invalid verification link. The link may be incomplete — "
            "copy the full URL or request a new verification email."
        )

    try:
        record = EmailVerificationToken.objects.select_related("user").get(token=token)
    except EmailVerificationToken.DoesNotExist:
        return None, (
            "Invalid verification link. It may have been replaced by a newer email, "
            "or the link was copied incorrectly. Request a new verification email below."
        )

    if not record.is_valid:
        return None, "This verification link has expired or was already used."

    record.mark_used()
    profile = get_or_create_profile(record.user)
    profile.email_verified = True
    profile.save(update_fields=["email_verified"])
    return record.user, None


def resend_verification_email(request, email: str):
    email = email.lower().strip()
    try:
        user = User.objects.get(email__iexact=email)
    except User.DoesNotExist:
        return False, "No account found with that email."

    profile = get_or_create_profile(user)
    if profile.email_verified:
        return False, "This email is already verified. You can log in."

    token_obj = send_verification_email(request, user)
    verify_url = build_verification_url(request, token_obj.token)
    return True, verify_url


def check_login_lockout(email):
    tracker, _ = LoginAttemptTracker.objects.get_or_create(email=email.lower())
    if tracker.is_locked:
        remaining = tracker.locked_until - timezone.now()
        minutes = max(1, int(remaining.total_seconds() // 60))
        return True, f"Account locked. Try again in {minutes} minute(s)."
    return False, None


def record_failed_login(email):
    tracker, _ = LoginAttemptTracker.objects.get_or_create(email=email.lower())
    tracker.failed_count += 1
    tracker.last_attempt_at = timezone.now()
    if tracker.failed_count >= settings.AUTH_LOCKOUT_MAX_ATTEMPTS:
        tracker.locked_until = timezone.now() + timedelta(
            minutes=settings.AUTH_LOCKOUT_MINUTES
        )
    tracker.save()
    return tracker


def record_successful_login(email):
    LoginAttemptTracker.objects.filter(email=email.lower()).delete()
