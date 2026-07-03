from django.contrib.auth import get_user_model
from django.test import TestCase

from password_breach_osint.models import PasswordBreachCheck

User = get_user_model()


class PasswordBreachCheckModelTests(TestCase):
    def test_upsert_by_sha1(self):
        user = User.objects.create_user(
            username="pw@test.com",
            email="pw@test.com",
            password="TestPass1!",
        )
        sha1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        PasswordBreachCheck.upsert_for_user(
            user,
            sha1,
            status=PasswordBreachCheck.Status.COMPLETED,
            hash_prefix="5BAA6",
            exposure_count=100,
            is_pwned=True,
        )
        check, created = PasswordBreachCheck.upsert_for_user(
            user,
            sha1,
            status=PasswordBreachCheck.Status.COMPLETED,
            hash_prefix="5BAA6",
            exposure_count=200,
            is_pwned=True,
        )
        self.assertFalse(created)
        self.assertEqual(check.exposure_count, 200)
