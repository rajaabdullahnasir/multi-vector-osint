import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from ip_intel_osint.models import IPIntelligence
from ip_intel_osint.services.analyzer import IPIntelReport

User = get_user_model()


class RunScanViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="ipintel@test.com",
            email="ipintel@test.com",
            password="TestPass1!",
        )
        self.user.profile.email_verified = True
        self.user.profile.save()
        self.client.login(username="ipintel@test.com", password="TestPass1!")
        self.url = reverse("ip_intel_osint:scan")

    def test_private_ip_not_saved_html(self):
        before = IPIntelligence.objects.count()
        response = self.client.post(self.url, {"query": "192.168.1.1"})
        self.assertEqual(IPIntelligence.objects.count(), before)
        self.assertEqual(response.status_code, 200)

    def test_invalid_input_not_saved_ajax(self):
        before = IPIntelligence.objects.count()
        response = self.client.post(
            self.url,
            {"query": "not an ip!!"},
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(IPIntelligence.objects.count(), before)
        self.assertEqual(response.status_code, 422)
        data = json.loads(response.content)
        self.assertFalse(data["ok"])

    def test_requires_login(self):
        self.client.logout()
        response = self.client.post(self.url, {"query": "8.8.8.8"})
        self.assertEqual(response.status_code, 302)

    @patch("ip_intel_osint.views.IPIntelAnalyzer")
    def test_successful_scan_saves_record_and_redirects(self, mock_analyzer_cls):
        mock_analyzer_cls.return_value.analyze.return_value = IPIntelReport(
            success=True,
            query_input="8.8.8.8",
            ip="8.8.8.8",
            was_domain=False,
            sections={"Target": {"Query": "8.8.8.8"}},
            country="US",
            city="Mountain View",
            isp="Google LLC",
            asn="AS15169 Google LLC",
            is_proxy_or_vpn=False,
            is_hosting=True,
            risk_flags=["This IP belongs to a hosting/datacenter provider."],
        )
        response = self.client.post(self.url, {"query": "8.8.8.8"})
        self.assertEqual(IPIntelligence.objects.count(), 1)
        record = IPIntelligence.objects.get()
        self.assertEqual(record.query_input, "8.8.8.8")
        self.assertEqual(record.city, "Mountain View")
        self.assertTrue(record.is_hosting)
        self.assertEqual(record.status, IPIntelligence.Status.COMPLETED)
        self.assertRedirects(
            response, reverse("ip_intel_osint:detail", kwargs={"pk": record.pk})
        )


class ScanDetailViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="ipdetail@test.com",
            email="ipdetail@test.com",
            password="TestPass1!",
        )
        self.user.profile.email_verified = True
        self.user.profile.save()
        self.client.login(username="ipdetail@test.com", password="TestPass1!")
        self.record = IPIntelligence.objects.create(
            user=self.user,
            query_input="8.8.8.8",
            ip_address="8.8.8.8",
            country="US",
            city="Mountain View",
            status=IPIntelligence.Status.COMPLETED,
            report_json={"sections": {"Target": {"Query": "8.8.8.8"}}},
            risk_flags=["This IP belongs to a hosting/datacenter provider."],
        )

    def test_detail_view_renders(self):
        response = self.client.get(
            reverse("ip_intel_osint:detail", kwargs={"pk": self.record.pk})
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "8.8.8.8")
        self.assertContains(response, "hosting/datacenter provider")

    def test_other_users_cannot_view_record(self):
        other = User.objects.create_user(
            username="ipother@test.com", email="ipother@test.com", password="TestPass1!"
        )
        other.profile.email_verified = True
        other.profile.save()
        self.client.logout()
        self.client.login(username="ipother@test.com", password="TestPass1!")
        response = self.client.get(
            reverse("ip_intel_osint:detail", kwargs={"pk": self.record.pk})
        )
        self.assertEqual(response.status_code, 404)

    def test_export_json(self):
        response = self.client.get(
            reverse("ip_intel_osint:export_json", kwargs={"pk": self.record.pk})
        )
        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.content)
        self.assertEqual(payload["ip_address"], "8.8.8.8")

    def test_delete_record(self):
        response = self.client.post(
            reverse("ip_intel_osint:delete", kwargs={"pk": self.record.pk})
        )
        self.assertRedirects(response, reverse("ip_intel_osint:home"))
        self.assertEqual(IPIntelligence.objects.count(), 0)
