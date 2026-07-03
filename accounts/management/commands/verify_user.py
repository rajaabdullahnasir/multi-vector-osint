from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from accounts.services import get_or_create_profile

User = get_user_model()


class Command(BaseCommand):
    help = "Manually mark a user's email as verified (recovery if links fail)."

    def add_arguments(self, parser):
        parser.add_argument("email", type=str, help="User email address")

    def handle(self, *args, **options):
        email = options["email"].lower().strip()
        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist as exc:
            raise CommandError(f"No user with email: {email}") from exc

        profile = get_or_create_profile(user)
        profile.email_verified = True
        profile.save(update_fields=["email_verified"])
        self.stdout.write(self.style.SUCCESS(f"Verified: {email}"))
