from django.contrib.auth import get_user_model
from django.test import TestCase

from email_breach_osint.models import EmailBreachCheck

User = get_user_model()


class EmailBreachCheckUpsertTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="upsert@test.com",
            email="upsert@test.com",
            password="TestPass1!",
        )

    def test_upsert_same_email(self):
        first, created = EmailBreachCheck.upsert_for_user(
            self.user,
            "User@Mail.COM",
            status=EmailBreachCheck.Status.COMPLETED,
            breach_count=1,
            is_pwned=True,
            report_json={"v": 1},
        )
        self.assertTrue(created)
        second, created = EmailBreachCheck.upsert_for_user(
            self.user,
            "user@mail.com",
            status=EmailBreachCheck.Status.COMPLETED,
            breach_count=3,
            is_pwned=True,
            report_json={"v": 2},
        )
        self.assertFalse(created)
        self.assertEqual(first.pk, second.pk)
        self.assertEqual(EmailBreachCheck.objects.filter(user=self.user).count(), 1)
