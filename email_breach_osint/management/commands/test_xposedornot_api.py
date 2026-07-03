"""
Test XposedOrNot check-email endpoint from this machine.

Usage:
    python manage.py test_xposedornot_api
    python manage.py test_xposedornot_api user@domain.com
"""

import json

from django.core.management.base import BaseCommand

from email_breach_osint.services.xposedornot_client import (
    _check_email_url,
    check_breached_account,
    get,
)


class Command(BaseCommand):
    help = "Live-test XposedOrNot check-email endpoint."

    def add_arguments(self, parser):
        parser.add_argument(
            "email",
            nargs="?",
            default="test@example.com",
            help="Email to query (default: test@example.com)",
        )

    def handle(self, *args, **options):
        email = options["email"].strip().lower()
        url = _check_email_url(email)

        self.stdout.write(self.style.NOTICE("Request"))
        self.stdout.write(f"  GET {url}\n")

        req, resp = get(url)

        self.stdout.write(self.style.NOTICE("Response"))
        self.stdout.write(f"  HTTP {resp.status_code}")
        if resp.error:
            self.stdout.write(self.style.ERROR(f"  Error: {resp.error}"))
        elif isinstance(resp.body, dict) and resp.body.get("Error"):
            self.stdout.write(self.style.WARNING(f'  {{"Error": "{resp.body["Error"]}"}}'))
        else:
            self.stdout.write(self.style.SUCCESS("  OK"))
            if resp.body is not None:
                self.stdout.write(json.dumps(resp.body, indent=2)[:2000])

        self.stdout.write("\n" + "-" * 60 + "\nModule check:\n")
        result = check_breached_account(email)
        if result.ok:
            self.stdout.write(
                self.style.SUCCESS(
                    f"SUCCESS — {result.breach_count} breach name(s), "
                    f"status={result.api_status or 'n/a'}"
                )
            )
            if result.breach_count:
                sample = ", ".join(b.name for b in result.breaches[:8])
                self.stdout.write(f"Sample: {sample}")
        else:
            self.stdout.write(self.style.ERROR(f"FAIL: {result.error}"))
