from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from email_breach_osint.services.gravatar_client import GravatarClient, _email_hash
from email_breach_osint.services.holehe_client import HoleheStyleChecker


class GravatarClientTests(SimpleTestCase):
    def _mock_resp(self, status_code, json_body=None, raise_json_error=False):
        resp = Mock()
        resp.status_code = status_code
        if raise_json_error:
            resp.json.side_effect = ValueError()
        else:
            resp.json.return_value = json_body or {}
        return resp

    def test_email_hash_is_deterministic_lowercase_trimmed(self):
        h1 = _email_hash("Test@Example.com")
        h2 = _email_hash(" test@example.com ")
        self.assertEqual(h1, h2)

    @patch("email_breach_osint.services.gravatar_client.requests.get")
    def test_avatar_and_public_profile_found(self, mock_get):
        avatar_resp = self._mock_resp(200)
        profile_resp = self._mock_resp(200, {
            "entry": [{"displayName": "Jane Doe", "profileUrl": "https://gravatar.com/jane",
                       "urls": [{"url": "https://janedoe.com"}]}]
        })
        mock_get.side_effect = [avatar_resp, profile_resp]

        result = GravatarClient().lookup("jane@gmail.com")
        self.assertTrue(result.success)
        self.assertTrue(result.has_avatar)
        self.assertTrue(result.has_public_profile)
        self.assertEqual(result.display_name, "Jane Doe")
        self.assertEqual(result.links, ["https://janedoe.com"])

    @patch("email_breach_osint.services.gravatar_client.requests.get")
    def test_no_avatar_no_profile(self, mock_get):
        mock_get.side_effect = [self._mock_resp(404), self._mock_resp(404)]
        result = GravatarClient().lookup("nobody@gmail.com")
        self.assertTrue(result.success)
        self.assertFalse(result.has_avatar)
        self.assertFalse(result.has_public_profile)

    @patch("email_breach_osint.services.gravatar_client.requests.get")
    def test_avatar_but_no_public_profile_still_a_success(self, mock_get):
        mock_get.side_effect = [self._mock_resp(200), self._mock_resp(404)]
        result = GravatarClient().lookup("someone@example.com")
        self.assertTrue(result.success)
        self.assertTrue(result.has_avatar)
        self.assertFalse(result.has_public_profile)

    @patch("email_breach_osint.services.gravatar_client.requests.get")
    def test_network_error_on_avatar_check_fails_cleanly(self, mock_get):
        import requests
        mock_get.side_effect = requests.ConnectionError()
        result = GravatarClient().lookup("someone@example.com")
        self.assertFalse(result.success)
        self.assertIsNotNone(result.error)

    @patch("email_breach_osint.services.gravatar_client.requests.get")
    def test_profile_endpoint_failure_does_not_lose_avatar_signal(self, mock_get):
        import requests
        avatar_resp = self._mock_resp(200)
        mock_get.side_effect = [avatar_resp, requests.ConnectionError()]
        result = GravatarClient().lookup("someone@example.com")
        self.assertTrue(result.success)
        self.assertTrue(result.has_avatar)
        self.assertFalse(result.has_public_profile)


class HoleheStyleCheckerTests(SimpleTestCase):
    def _mock_resp(self, status_code, json_body=None):
        resp = Mock()
        resp.status_code = status_code
        resp.json.return_value = json_body if json_body is not None else {}
        return resp

    @patch("email_breach_osint.services.holehe_client.requests.get")
    def test_registered_account_found(self, mock_get):
        mock_get.return_value = self._mock_resp(200, {"users": [{"username": "janedoe"}]})
        results = HoleheStyleChecker().check_all("jane@gmail.com")
        duolingo = next(r for r in results if r.platform == "Duolingo")
        self.assertTrue(duolingo.registered)
        self.assertIn("janedoe", duolingo.detail)

    @patch("email_breach_osint.services.holehe_client.requests.get")
    def test_no_account_registered(self, mock_get):
        mock_get.return_value = self._mock_resp(200, {"users": []})
        results = HoleheStyleChecker().check_all("nobody@gmail.com")
        duolingo = next(r for r in results if r.platform == "Duolingo")
        self.assertFalse(duolingo.registered)

    @patch("email_breach_osint.services.holehe_client.requests.get")
    def test_unexpected_status_is_inconclusive_not_false(self, mock_get):
        mock_get.return_value = self._mock_resp(500)
        results = HoleheStyleChecker().check_all("someone@example.com")
        duolingo = next(r for r in results if r.platform == "Duolingo")
        self.assertIsNone(duolingo.registered)
        self.assertIsNotNone(duolingo.error)

    @patch("email_breach_osint.services.holehe_client.requests.get")
    def test_network_error_is_inconclusive_not_false(self, mock_get):
        import requests
        mock_get.side_effect = requests.ConnectionError()
        results = HoleheStyleChecker().check_all("someone@example.com")
        duolingo = next(r for r in results if r.platform == "Duolingo")
        self.assertIsNone(duolingo.registered)

    @patch("email_breach_osint.services.holehe_client.requests.get")
    def test_unexpected_json_shape_is_inconclusive(self, mock_get):
        mock_get.return_value = self._mock_resp(200, {"unexpected": "shape"})
        results = HoleheStyleChecker().check_all("someone@example.com")
        duolingo = next(r for r in results if r.platform == "Duolingo")
        self.assertIsNone(duolingo.registered)


class AnalyzerEmailIntelligenceIntegrationTests(SimpleTestCase):
    @patch("email_breach_osint.services.analyzer.check_breached_account")
    @patch("email_breach_osint.services.analyzer.HoleheStyleChecker")
    @patch("email_breach_osint.services.analyzer.GravatarClient")
    def test_gravatar_and_account_signals_feed_risk_flags(
        self, mock_gravatar_cls, mock_holehe_cls, mock_breach_check
    ):
        from email_breach_osint.services.analyzer import EmailBreachAnalyzer
        from email_breach_osint.services.gravatar_client import GravatarResult
        from email_breach_osint.services.holehe_client import AccountCheckResult
        from email_breach_osint.services.xposedornot_client import BreachCheckResult

        mock_breach_check.return_value = BreachCheckResult(
            ok=True, email="jane@gmail.com", no_breaches=True, breaches=[]
        )
        mock_gravatar_cls.return_value.lookup.return_value = GravatarResult(
            success=True, has_avatar=True, has_public_profile=True, display_name="Jane Doe"
        )
        mock_holehe_cls.return_value.check_all.return_value = [
            AccountCheckResult(platform="Duolingo", registered=True, detail="found")
        ]

        report = EmailBreachAnalyzer().analyze("jane@gmail.com")
        self.assertTrue(report.has_gravatar)
        self.assertIn("Gravatar (public profile)", report.accounts_found)
        self.assertIn("Duolingo", report.accounts_found)
        joined = " ".join(report.risk_flags)
        self.assertIn("public account signal", joined)

    @patch("email_breach_osint.services.analyzer.check_breached_account")
    @patch("email_breach_osint.services.analyzer.HoleheStyleChecker")
    @patch("email_breach_osint.services.analyzer.GravatarClient")
    def test_no_signals_found_does_not_crash_or_overclaim(
        self, mock_gravatar_cls, mock_holehe_cls, mock_breach_check
    ):
        from email_breach_osint.services.analyzer import EmailBreachAnalyzer
        from email_breach_osint.services.gravatar_client import GravatarResult
        from email_breach_osint.services.holehe_client import AccountCheckResult
        from email_breach_osint.services.xposedornot_client import BreachCheckResult

        mock_breach_check.return_value = BreachCheckResult(
            ok=True, email="nobody@gmail.com", no_breaches=True, breaches=[]
        )
        mock_gravatar_cls.return_value.lookup.return_value = GravatarResult(success=True)
        mock_holehe_cls.return_value.check_all.return_value = [
            AccountCheckResult(platform="Duolingo", registered=False)
        ]

        report = EmailBreachAnalyzer().analyze("nobody@gmail.com")
        self.assertFalse(report.has_gravatar)
        self.assertEqual(report.accounts_found, [])
