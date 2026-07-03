from django.contrib.auth import get_user_model
from django.test import TestCase

from whois_osint.models import DomainLookup

User = get_user_model()


class DomainLookupUpsertTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="upsert@test.com",
            email="upsert@test.com",
            password="TestPass1!",
        )

    def test_upsert_creates_then_updates_same_row(self):
        first, created = DomainLookup.upsert_for_user(
            self.user,
            "Example.COM",
            status=DomainLookup.Status.COMPLETED,
            registrar="Old Registrar",
            report_json={"v": 1},
        )
        self.assertTrue(created)
        self.assertEqual(first.domain, "example.com")

        second, created = DomainLookup.upsert_for_user(
            self.user,
            "example.com",
            status=DomainLookup.Status.COMPLETED,
            registrar="New Registrar",
            report_json={"v": 2},
        )
        self.assertFalse(created)
        self.assertEqual(second.pk, first.pk)
        self.assertEqual(DomainLookup.objects.filter(user=self.user).count(), 1)
        second.refresh_from_db()
        self.assertEqual(second.registrar, "New Registrar")
        self.assertEqual(second.report_json, {"v": 2})

    def test_different_domains_remain_separate(self):
        DomainLookup.upsert_for_user(
            self.user, "a.com", status=DomainLookup.Status.COMPLETED
        )
        DomainLookup.upsert_for_user(
            self.user, "b.com", status=DomainLookup.Status.COMPLETED
        )
        self.assertEqual(DomainLookup.objects.filter(user=self.user).count(), 2)
