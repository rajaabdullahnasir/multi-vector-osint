from django.contrib.auth import get_user_model
from django.test import TestCase

from url_risk_osint.models import UrlRiskCheck

User = get_user_model()


class UrlRiskCheckModelTests(TestCase):
    def test_upsert_same_url(self):
        user = User.objects.create_user(
            username="url@test.com",
            email="url@test.com",
            password="TestPass1!",
        )
        UrlRiskCheck.upsert_for_user(
            user,
            "https://example.com",
            status=UrlRiskCheck.Status.COMPLETED,
            risk_level=UrlRiskCheck.RiskLevel.SAFE,
            risk_score=5,
        )
        check, created = UrlRiskCheck.upsert_for_user(
            user,
            "https://example.com",
            status=UrlRiskCheck.Status.COMPLETED,
            risk_level=UrlRiskCheck.RiskLevel.SUSPICIOUS,
            risk_score=40,
        )
        self.assertFalse(created)
        self.assertEqual(check.risk_score, 40)
