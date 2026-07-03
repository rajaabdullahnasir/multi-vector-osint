from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from url_risk_osint.models import UrlRiskCheck
from url_risk_osint.services.analyzer import UrlRiskReport
from url_risk_osint.services.risk_scorer import RISK_SAFE

User = get_user_model()


class UrlRiskViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="ur@test.com",
            email="ur@test.com",
            password="TestPass1!",
        )
        self.client = Client()
        self.client.login(username="ur@test.com", password="TestPass1!")

    def test_home_redirects_anon(self):
        response = Client().get(reverse("url_risk_osint:home"))
        self.assertEqual(response.status_code, 302)

    def test_check_saves_result(self):
        report = UrlRiskReport(
            success=True,
            url="https://example.com",
            risk_level=RISK_SAFE,
            risk_score=10,
            sections={},
            lexical_findings=[],
            blacklist_hits=[],
            risk_flags=[],
        )
        with patch("url_risk_osint.views.UrlRiskAnalyzer.analyze", return_value=report):
            response = self.client.post(
                reverse("url_risk_osint:check"),
                {"url": "https://example.com"},
                HTTP_X_REQUESTED_WITH="XMLHttpRequest",
                HTTP_ACCEPT="application/json",
            )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            UrlRiskCheck.objects.filter(user=self.user, url="https://example.com").exists()
        )
