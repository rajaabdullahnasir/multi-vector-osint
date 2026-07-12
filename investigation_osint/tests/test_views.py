import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from investigation_osint.models import Investigation
from investigation_osint.services.investigation_engine import InvestigationReport, ModuleOutcome

User = get_user_model()


class RunInvestigationViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="invview@test.com", email="invview@test.com", password="TestPass1!"
        )
        self.user.profile.email_verified = True
        self.user.profile.save()
        self.client.login(username="invview@test.com", password="TestPass1!")
        self.url = reverse("investigation_osint:run")

    def test_requires_login(self):
        self.client.logout()
        response = self.client.post(self.url, {"domain": "example.com"})
        self.assertEqual(response.status_code, 302)

    def test_invalid_domain_rejected_without_running_engine(self):
        with patch("investigation_osint.views.InvestigationEngine") as mock_engine_cls:
            response = self.client.post(
                self.url,
                {"domain": "not a domain!!!"},
                HTTP_X_REQUESTED_WITH="XMLHttpRequest",
                HTTP_ACCEPT="application/json",
            )
            mock_engine_cls.assert_not_called()
        self.assertEqual(response.status_code, 422)
        data = json.loads(response.content)
        self.assertFalse(data["ok"])

    @patch("investigation_osint.views.InvestigationEngine")
    def test_successful_investigation_saves_and_redirects(self, mock_engine_cls):
        mock_engine_cls.return_value.run.return_value = InvestigationReport(
            success=True,
            domain="example.com",
            modules_run=["whois", "subdomain"],
            outcomes=[
                ModuleOutcome(
                    module="whois", label="WHOIS & DNS", key="example.com",
                    record_id="12345678-1234-5678-1234-567812345678",
                    url_name="whois_osint:detail", summary="ok",
                )
            ],
            emails_checked=1,
            ips_checked=2,
            usernames_checked=1,
            overall_risk_level="moderate",
            risk_flags=["[WHOIS] some flag"],
        )
        response = self.client.post(self.url, {"domain": "example.com"})
        self.assertEqual(Investigation.objects.count(), 1)
        record = Investigation.objects.get()
        self.assertEqual(record.target_domain, "example.com")
        self.assertEqual(record.overall_risk_level, "moderate")
        self.assertEqual(record.emails_checked, 1)
        self.assertRedirects(
            response, reverse("investigation_osint:detail", kwargs={"pk": record.pk})
        )


class InvestigationDetailViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="invdetail@test.com", email="invdetail@test.com", password="TestPass1!"
        )
        self.user.profile.email_verified = True
        self.user.profile.save()
        self.client.login(username="invdetail@test.com", password="TestPass1!")
        self.record = Investigation.objects.create(
            user=self.user,
            target_domain="example.com",
            status=Investigation.Status.COMPLETED,
            overall_risk_level="low",
            modules_run=["whois"],
            report_json={
                "outcomes": [{"module": "whois", "label": "WHOIS & DNS", "summary": "ok", "ok": True}],
                "nodes": [{"id": "example.com", "type": "domain", "label": "example.com"}],
                "edges": [],
            },
            risk_flags=["[WHOIS] test flag"],
        )

    def test_detail_view_renders(self):
        response = self.client.get(
            reverse("investigation_osint:detail", kwargs={"pk": self.record.pk})
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "example.com")
        self.assertContains(response, "test flag")

    def test_other_users_cannot_view_record(self):
        other = User.objects.create_user(
            username="invother@test.com", email="invother@test.com", password="TestPass1!"
        )
        other.profile.email_verified = True
        other.profile.save()
        self.client.logout()
        self.client.login(username="invother@test.com", password="TestPass1!")
        response = self.client.get(
            reverse("investigation_osint:detail", kwargs={"pk": self.record.pk})
        )
        self.assertEqual(response.status_code, 404)

    def test_export_json(self):
        response = self.client.get(
            reverse("investigation_osint:export_json", kwargs={"pk": self.record.pk})
        )
        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.content)
        self.assertEqual(payload["target_domain"], "example.com")

    def test_delete_record(self):
        response = self.client.post(
            reverse("investigation_osint:delete", kwargs={"pk": self.record.pk})
        )
        self.assertRedirects(response, reverse("investigation_osint:home"))
        self.assertEqual(Investigation.objects.count(), 0)
