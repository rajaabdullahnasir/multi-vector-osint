from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from password_breach_osint.models import PasswordBreachCheck
from password_breach_osint.services.analyzer import PasswordBreachReport

User = get_user_model()


class PasswordBreachViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="pb@test.com",
            email="pb@test.com",
            password="TestPass1!",
        )
        self.client = Client()
        self.client.login(username="pb@test.com", password="TestPass1!")

    def test_check_saves_without_plaintext(self):
        report = PasswordBreachReport(
            success=True,
            is_pwned=True,
            exposure_count=100,
            sha1_hash="5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8",
            hash_prefix="5BAA6",
            sections={},
            risk_flags=[],
        )
        with patch(
            "password_breach_osint.views.PasswordBreachAnalyzer.analyze",
            return_value=report,
        ):
            response = self.client.post(
                reverse("password_breach_osint:check"),
                {"password": "password"},
                HTTP_X_REQUESTED_WITH="XMLHttpRequest",
                HTTP_ACCEPT="application/json",
            )
        self.assertEqual(response.status_code, 200)
        check = PasswordBreachCheck.objects.get(user=self.user)
        self.assertNotIn("password", str(check.report_json).lower())
