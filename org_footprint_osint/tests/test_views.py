import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from org_footprint_osint.models import OrgFootprint
from org_footprint_osint.services.analyzer import OrgFootprintReport

User = get_user_model()


class RunScanViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="footprint@test.com",
            email="footprint@test.com",
            password="TestPass1!",
        )
        self.user.profile.email_verified = True
        self.user.profile.save()
        self.client.login(username="footprint@test.com", password="TestPass1!")
        self.url = reverse("org_footprint_osint:scan")

    def test_invalid_domain_not_saved_html(self):
        before = OrgFootprint.objects.count()
        response = self.client.post(self.url, {"domain": "not valid!!!"})
        self.assertEqual(OrgFootprint.objects.count(), before)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "valid domain")

    def test_invalid_domain_not_saved_ajax(self):
        before = OrgFootprint.objects.count()
        response = self.client.post(
            self.url,
            {"domain": "not valid!!!"},
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(OrgFootprint.objects.count(), before)
        self.assertEqual(response.status_code, 422)
        data = json.loads(response.content)
        self.assertFalse(data["ok"])
        self.assertTrue(data["validation_failed"])

    def test_requires_login(self):
        self.client.logout()
        response = self.client.post(self.url, {"domain": "example.com"})
        self.assertEqual(response.status_code, 302)

    @patch("org_footprint_osint.views.OrgFootprintAnalyzer")
    def test_successful_scan_saves_record_and_redirects(self, mock_analyzer_cls):
        mock_analyzer_cls.return_value.analyze.return_value = OrgFootprintReport(
            success=True,
            domain="example.com",
            sections={"Target": {"Domain": "example.com"}},
            org_name="Example Inc.",
            org_country="US",
            whois_privacy=False,
            spf_status="present",
            dmarc_status="reject",
            dkim_selector_count=1,
            security_header_score=3,
            social_platform_count=2,
            risk_flags=[],
        )
        response = self.client.post(self.url, {"domain": "example.com"})
        self.assertEqual(OrgFootprint.objects.count(), 1)
        record = OrgFootprint.objects.get()
        self.assertEqual(record.domain, "example.com")
        self.assertEqual(record.org_name, "Example Inc.")
        self.assertEqual(record.status, OrgFootprint.Status.COMPLETED)
        self.assertRedirects(
            response, reverse("org_footprint_osint:detail", kwargs={"pk": record.pk})
        )


class ScanDetailViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="detail@test.com",
            email="detail@test.com",
            password="TestPass1!",
        )
        self.user.profile.email_verified = True
        self.user.profile.save()
        self.client.login(username="detail@test.com", password="TestPass1!")
        self.record = OrgFootprint.objects.create(
            user=self.user,
            domain="example.com",
            org_name="Example Inc.",
            status=OrgFootprint.Status.COMPLETED,
            report_json={"sections": {"Target": {"Domain": "example.com"}}},
            risk_flags=["No DMARC record found."],
        )

    def test_detail_view_renders(self):
        response = self.client.get(
            reverse("org_footprint_osint:detail", kwargs={"pk": self.record.pk})
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "example.com")
        self.assertContains(response, "No DMARC record found.")

    def test_other_users_cannot_view_record(self):
        other = User.objects.create_user(
            username="other@test.com", email="other@test.com", password="TestPass1!"
        )
        other.profile.email_verified = True
        other.profile.save()
        self.client.logout()
        self.client.login(username="other@test.com", password="TestPass1!")
        response = self.client.get(
            reverse("org_footprint_osint:detail", kwargs={"pk": self.record.pk})
        )
        self.assertEqual(response.status_code, 404)

    def test_export_json(self):
        response = self.client.get(
            reverse("org_footprint_osint:export_json", kwargs={"pk": self.record.pk})
        )
        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.content)
        self.assertEqual(payload["domain"], "example.com")

    def test_delete_record(self):
        response = self.client.post(
            reverse("org_footprint_osint:delete", kwargs={"pk": self.record.pk})
        )
        self.assertRedirects(response, reverse("org_footprint_osint:home"))
        self.assertEqual(OrgFootprint.objects.count(), 0)
