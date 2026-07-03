"""
Live-test Pwned Passwords k-anonymity API.

Usage:
    python manage.py test_pwned_passwords_api
    python manage.py test_pwned_passwords_api --password your-test-password
"""

from django.core.management.base import BaseCommand

from password_breach_osint.services.pwned_passwords_client import check_password, sha1_hex


class Command(BaseCommand):
    help = "Live-test Pwned Passwords range API."

    def add_arguments(self, parser):
        parser.add_argument(
            "--password",
            default="password",
            help="Password to check (default: password)",
        )

    def handle(self, *args, **options):
        pwd = options["password"]
        digest = sha1_hex(pwd)
        self.stdout.write(self.style.NOTICE(f"SHA-1: {digest[:5]}…{digest[-4:]} (full hash not sent)\n"))

        result = check_password(pwd)
        if not result.ok:
            self.stdout.write(self.style.ERROR(f"FAIL: {result.error}"))
            return

        if result.is_pwned:
            self.stdout.write(
                self.style.WARNING(
                    f"PWNED — seen {result.exposure_count:,} time(s) "
                    f"(prefix {result.hash_prefix})"
                )
            )
        else:
            self.stdout.write(self.style.SUCCESS("Not found in Pwned Passwords corpus."))
