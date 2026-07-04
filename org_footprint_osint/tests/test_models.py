from django.contrib.auth import get_user_model
from django.test import TestCase

from org_footprint_osint.models import OrgFootprint

User = get_user_model()


class OrgFootprintUpsertTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="upsert@test.com",
            email="upsert@test.com",
            password="TestPass1!",
        )

    def test_upsert_creates_then_updates_same_row(self):
        first, created = OrgFootprint.upsert_for_user(
            self.user,
            "Example.COM",
            status=OrgFootprint.Status.COMPLETED,
            org_name="Old Org",
            report_json={"v": 1},
        )
        self.assertTrue(created)
        self.assertEqual(first.domain, "example.com")

        second, created = OrgFootprint.upsert_for_user(
            self.user,
            "example.com",
            status=OrgFootprint.Status.COMPLETED,
            org_name="New Org",
            report_json={"v": 2},
        )
        self.assertFalse(created)
        self.assertEqual(second.pk, first.pk)
        self.assertEqual(OrgFootprint.objects.filter(user=self.user).count(), 1)
        second.refresh_from_db()
        self.assertEqual(second.org_name, "New Org")
        self.assertEqual(second.report_json, {"v": 2})

    def test_different_domains_remain_separate(self):
        OrgFootprint.upsert_for_user(
            self.user, "a.com", status=OrgFootprint.Status.COMPLETED
        )
        OrgFootprint.upsert_for_user(
            self.user, "b.com", status=OrgFootprint.Status.COMPLETED
        )
        self.assertEqual(OrgFootprint.objects.filter(user=self.user).count(), 2)
