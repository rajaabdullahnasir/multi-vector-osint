from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from username_osint.models import UsernameLookup
from username_osint.services.analyzer import UsernameOsintReport

User = get_user_model()


class UsernameViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="un@test.com",
            email="un@test.com",
            password="TestPass1!",
        )
        self.client = Client()
        self.client.login(username="un@test.com", password="TestPass1!")

    def test_home_requires_login(self):
        anon = Client()
        response = anon.get(reverse("username_osint:home"))
        self.assertEqual(response.status_code, 302)

    def test_scan_creates_lookup(self):
        report = UsernameOsintReport(
            success=True,
            username="johndoe",
            found_count=2,
            checked_count=20,
            sections={"Summary": {"Profiles found": "2"}},
            platforms=[],
            risk_flags=[],
        )
        with patch(
            "username_osint.views.UsernameOsintAnalyzer.analyze",
            return_value=report,
        ):
            response = self.client.post(
                reverse("username_osint:scan"),
                {"username": "johndoe"},
                HTTP_X_REQUESTED_WITH="XMLHttpRequest",
                HTTP_ACCEPT="application/json",
            )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(UsernameLookup.objects.filter(user=self.user, username="johndoe").exists())
