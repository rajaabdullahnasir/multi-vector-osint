import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from dirbuster_osint.models import DirBusterScan
from dirbuster_osint.services.analyzer import DirBusterReport

User = get_user_model()


class DirBusterScanUpsertTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="dbupsert@test.com", email="dbupsert@test.com", password="TestPass1!"
        )

    def test_upsert_creates_then_updates(self):
        first, created = DirBusterScan.upsert_for_user(
            self.user, "https://example.com", status=DirBusterScan.Status.COMPLETED, found_count=1
        )
        self.assertTrue(created)
        second, created = DirBusterScan.upsert_for_user(
            self.user, "https://example.com", status=DirBusterScan.Status.COMPLETED, found_count=3
        )
        self.assertFalse(created)
        self.assertEqual(second.pk, first.pk)


class RunScanViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="dbview@test.com", email="dbview@test.com", password="TestPass1!"
        )
        self.user.profile.email_verified = True
        self.user.profile.save()
        self.client.login(username="dbview@test.com", password="TestPass1!")
        self.url = reverse("dirbuster_osint:scan")

    def test_requires_login(self):
        self.client.logout()
        response = self.client.post(self.url, {"target": "example.com", "wordlist_tier": "quick"})
        self.assertEqual(response.status_code, 302)

    def test_private_ip_rejected_without_scanning(self):
        with patch("dirbuster_osint.views.DirBusterAnalyzer") as mock_analyzer_cls:
            response = self.client.post(
                self.url, {"target": "192.168.1.1", "wordlist_tier": "quick"},
                HTTP_X_REQUESTED_WITH="XMLHttpRequest", HTTP_ACCEPT="application/json",
            )
            mock_analyzer_cls.assert_not_called()
        self.assertEqual(response.status_code, 422)
        data = json.loads(response.content)
        self.assertFalse(data["ok"])
        self.assertTrue(data["error"])

    @patch("dirbuster_osint.views.DirBusterAnalyzer")
    def test_successful_scan_saves_and_redirects(self, mock_analyzer_cls):
        mock_analyzer_cls.return_value.analyze.return_value = DirBusterReport(
            success=True, target="example.com", base_url="https://example.com", host="example.com",
            wordlist_tier="quick", sections={"Target": {"URL": "https://example.com"}},
            found_count=2, redirect_count=0, forbidden_count=1, filtered_count=0,
            checked_count=47, entries=[], risk_flags=[],
        )
        response = self.client.post(self.url, {"target": "example.com", "wordlist_tier": "quick"})
        self.assertEqual(DirBusterScan.objects.count(), 1)
        record = DirBusterScan.objects.get()
        self.assertRedirects(response, reverse("dirbuster_osint:detail", kwargs={"pk": record.pk}))

    def test_prefill_from_query_param(self):
        response = self.client.get(reverse("dirbuster_osint:home") + "?target=https://example.com/")
        self.assertEqual(response.status_code, 200)


class ScanDetailViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="dbdetail@test.com", email="dbdetail@test.com", password="TestPass1!"
        )
        self.user.profile.email_verified = True
        self.user.profile.save()
        self.client.login(username="dbdetail@test.com", password="TestPass1!")
        self.record = DirBusterScan.objects.create(
            user=self.user, target="https://example.com", host="example.com",
            status=DirBusterScan.Status.COMPLETED, found_count=1,
            report_json={
                "sections": {"Target": {"URL": "https://example.com"}},
                "entries": [
                    {"path": "admin", "url": "https://example.com/admin", "status_code": 200,
                     "content_length": 100, "category": "found", "redirect_location": "", "error_reason": ""},
                ],
            },
            risk_flags=["test flag"],
        )

    def test_detail_view_renders(self):
        response = self.client.get(reverse("dirbuster_osint:detail", kwargs={"pk": self.record.pk}))
        self.assertEqual(response.status_code, 200)

    def test_other_users_cannot_view_record(self):
        other = User.objects.create_user(
            username="dbother@test.com", email="dbother@test.com", password="TestPass1!"
        )
        other.profile.email_verified = True
        other.profile.save()
        self.client.logout()
        self.client.login(username="dbother@test.com", password="TestPass1!")
        response = self.client.get(reverse("dirbuster_osint:detail", kwargs={"pk": self.record.pk}))
        self.assertEqual(response.status_code, 404)

    def test_export_json(self):
        response = self.client.get(reverse("dirbuster_osint:export_json", kwargs={"pk": self.record.pk}))
        self.assertEqual(response.status_code, 200)

    def test_delete_record(self):
        response = self.client.post(reverse("dirbuster_osint:delete", kwargs={"pk": self.record.pk}))
        self.assertRedirects(response, reverse("dirbuster_osint:home"))
