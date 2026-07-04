from django.contrib.auth import get_user_model
from django.test import TestCase

from ip_intel_osint.models import IPIntelligence

User = get_user_model()


class IPIntelUpsertTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="ipupsert@test.com",
            email="ipupsert@test.com",
            password="TestPass1!",
        )

    def test_upsert_creates_then_updates_same_row(self):
        first, created = IPIntelligence.upsert_for_user(
            self.user,
            "8.8.8.8",
            status=IPIntelligence.Status.COMPLETED,
            country="US",
            report_json={"v": 1},
        )
        self.assertTrue(created)

        second, created = IPIntelligence.upsert_for_user(
            self.user,
            "8.8.8.8",
            status=IPIntelligence.Status.COMPLETED,
            country="US-updated",
            report_json={"v": 2},
        )
        self.assertFalse(created)
        self.assertEqual(second.pk, first.pk)
        self.assertEqual(IPIntelligence.objects.filter(user=self.user).count(), 1)
        second.refresh_from_db()
        self.assertEqual(second.country, "US-updated")

    def test_different_queries_remain_separate(self):
        IPIntelligence.upsert_for_user(
            self.user, "8.8.8.8", status=IPIntelligence.Status.COMPLETED
        )
        IPIntelligence.upsert_for_user(
            self.user, "example.com", status=IPIntelligence.Status.COMPLETED
        )
        self.assertEqual(IPIntelligence.objects.filter(user=self.user).count(), 2)
