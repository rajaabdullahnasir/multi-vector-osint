from django.contrib.auth import get_user_model
from django.test import TestCase

from subdomain_osint.models import SubdomainScan

User = get_user_model()


class SubdomainScanUpsertTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="sub@test.com",
            email="sub@test.com",
            password="TestPass1!",
        )

    def test_upsert_updates_same_domain(self):
        first, created = SubdomainScan.upsert_for_user(
            self.user,
            "Example.COM",
            status=SubdomainScan.Status.COMPLETED,
            subdomain_count=3,
            dns_verified_count=2,
            report_json={"v": 1},
        )
        self.assertTrue(created)

        second, created = SubdomainScan.upsert_for_user(
            self.user,
            "example.com",
            status=SubdomainScan.Status.COMPLETED,
            subdomain_count=10,
            dns_verified_count=8,
            report_json={"v": 2},
        )
        self.assertFalse(created)
        self.assertEqual(second.pk, first.pk)
        self.assertEqual(SubdomainScan.objects.filter(user=self.user).count(), 1)
        second.refresh_from_db()
        self.assertEqual(second.subdomain_count, 10)
