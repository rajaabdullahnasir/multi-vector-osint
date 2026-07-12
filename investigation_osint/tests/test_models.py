from django.contrib.auth import get_user_model
from django.test import TestCase

from investigation_osint.models import Investigation

User = get_user_model()


class InvestigationUpsertTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="invupsert@test.com",
            email="invupsert@test.com",
            password="TestPass1!",
        )

    def test_upsert_creates_then_updates_same_row(self):
        first, created = Investigation.upsert_for_user(
            self.user, "Example.COM", status=Investigation.Status.COMPLETED, overall_risk_level="low"
        )
        self.assertTrue(created)
        self.assertEqual(first.target_domain, "example.com")

        second, created = Investigation.upsert_for_user(
            self.user, "example.com", status=Investigation.Status.COMPLETED, overall_risk_level="critical"
        )
        self.assertFalse(created)
        self.assertEqual(second.pk, first.pk)
        self.assertEqual(Investigation.objects.filter(user=self.user).count(), 1)
        second.refresh_from_db()
        self.assertEqual(second.overall_risk_level, "critical")

    def test_different_domains_remain_separate(self):
        Investigation.upsert_for_user(self.user, "a.com", status=Investigation.Status.COMPLETED)
        Investigation.upsert_for_user(self.user, "b.com", status=Investigation.Status.COMPLETED)
        self.assertEqual(Investigation.objects.filter(user=self.user).count(), 2)
