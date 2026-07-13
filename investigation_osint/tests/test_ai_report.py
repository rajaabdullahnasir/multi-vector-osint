import json
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from investigation_osint.models import Investigation
from investigation_osint.services.ai_report_client import AIReportResult, GroqReportClient, is_configured

User = get_user_model()


class GroqConfigTests(TestCase):
    @override_settings(GROQ_API_KEY="")
    def test_not_configured_without_key(self):
        self.assertFalse(is_configured())

    @override_settings(GROQ_API_KEY="fake-key-123")
    def test_configured_with_key(self):
        self.assertTrue(is_configured())

    @override_settings(GROQ_API_KEY="")
    def test_generate_fails_cleanly_without_key(self):
        result = GroqReportClient().generate({"target_domain": "example.com"})
        self.assertFalse(result.success)
        self.assertIn("console.groq.com", result.error)


class GroqReportClientTests(TestCase):
    def _mock_response(self, status_code, json_body):
        resp = Mock()
        resp.status_code = status_code
        resp.json.return_value = json_body
        resp.text = json.dumps(json_body)
        return resp

    @override_settings(GROQ_API_KEY="fake-key-123")
    @patch("investigation_osint.services.ai_report_client.requests.post")
    def test_successful_generation(self, mock_post):
        mock_post.return_value = self._mock_response(
            200,
            {"choices": [{"message": {"content": "This is the narrative report."}}]},
        )
        result = GroqReportClient().generate({"target_domain": "example.com"})
        self.assertTrue(result.success)
        self.assertEqual(result.narrative, "This is the narrative report.")
        self.assertEqual(result.model_used, "openai/gpt-oss-120b")

    @override_settings(GROQ_API_KEY="bad-key")
    @patch("investigation_osint.services.ai_report_client.requests.post")
    def test_invalid_key_reported_honestly(self, mock_post):
        mock_post.return_value = self._mock_response(401, {"error": {"message": "invalid key"}})
        result = GroqReportClient().generate({"target_domain": "example.com"})
        self.assertFalse(result.success)
        self.assertIn("401", result.error)

    @override_settings(GROQ_API_KEY="fake-key-123")
    @patch("investigation_osint.services.ai_report_client.requests.post")
    def test_rate_limit_reported_honestly(self, mock_post):
        mock_post.return_value = self._mock_response(429, {})
        result = GroqReportClient().generate({"target_domain": "example.com"})
        self.assertFalse(result.success)
        self.assertIn("rate limit", result.error.lower())

    @override_settings(GROQ_API_KEY="fake-key-123")
    @patch("investigation_osint.services.ai_report_client.requests.post")
    def test_empty_completion_treated_as_failure_not_silent_success(self, mock_post):
        mock_post.return_value = self._mock_response(
            200, {"choices": [{"message": {"content": "   "}}]}
        )
        result = GroqReportClient().generate({"target_domain": "example.com"})
        self.assertFalse(result.success)

    @override_settings(GROQ_API_KEY="fake-key-123")
    @patch("investigation_osint.services.ai_report_client.requests.post")
    def test_timeout_reported_honestly(self, mock_post):
        import requests

        mock_post.side_effect = requests.Timeout()
        result = GroqReportClient().generate({"target_domain": "example.com"})
        self.assertFalse(result.success)
        self.assertIn("timed out", result.error.lower())


class GenerateAiReportViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="airpt@test.com", email="airpt@test.com", password="TestPass1!"
        )
        self.user.profile.email_verified = True
        self.user.profile.save()
        self.client.login(username="airpt@test.com", password="TestPass1!")
        self.record = Investigation.objects.create(
            user=self.user,
            target_domain="example.com",
            status=Investigation.Status.COMPLETED,
            report_json={"target_domain": "example.com"},
        )
        self.url = reverse("investigation_osint:generate_ai_report", kwargs={"pk": self.record.pk})

    def test_requires_login(self):
        self.client.logout()
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 302)

    @override_settings(GROQ_API_KEY="")
    def test_missing_key_shows_message_without_calling_api(self):
        with patch("investigation_osint.views.GroqReportClient") as mock_client_cls:
            response = self.client.post(self.url, follow=True)
            mock_client_cls.assert_not_called()
        self.record.refresh_from_db()
        self.assertEqual(self.record.ai_report, "")

    @override_settings(GROQ_API_KEY="fake-key-123")
    @patch("investigation_osint.views.GroqReportClient")
    def test_successful_generation_saves_to_record(self, mock_client_cls):
        mock_client_cls.return_value.generate.return_value = AIReportResult(
            success=True, narrative="Full narrative text.", model_used="openai/gpt-oss-120b"
        )
        response = self.client.post(self.url)
        self.record.refresh_from_db()
        self.assertEqual(self.record.ai_report, "Full narrative text.")
        self.assertIsNotNone(self.record.ai_report_generated_at)
        self.assertEqual(self.record.ai_report_error, "")
        self.assertRedirects(
            response, reverse("investigation_osint:detail", kwargs={"pk": self.record.pk})
        )

    @override_settings(GROQ_API_KEY="fake-key-123")
    @patch("investigation_osint.views.GroqReportClient")
    def test_failed_generation_saves_error_not_blank_success(self, mock_client_cls):
        mock_client_cls.return_value.generate.return_value = AIReportResult(
            success=False, error="Groq returned HTTP 500: server error."
        )
        self.client.post(self.url)
        self.record.refresh_from_db()
        self.assertEqual(self.record.ai_report, "")
        self.assertIn("500", self.record.ai_report_error)

    def test_other_users_cannot_trigger_generation_on_someone_elses_record(self):
        other = User.objects.create_user(
            username="airptother@test.com", email="airptother@test.com", password="TestPass1!"
        )
        other.profile.email_verified = True
        other.profile.save()
        self.client.logout()
        self.client.login(username="airptother@test.com", password="TestPass1!")
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 404)
