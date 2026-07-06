from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from username_osint.services.analyzer import UsernameOsintAnalyzer
from username_osint.services.platform_checker import PlatformHit, PlatformScanResult, _check_one
from username_osint.services.platforms import Platform
from username_osint.services.username_validator import UsernameValidator


class UsernameValidatorTests(SimpleTestCase):
    def test_accepts_valid_username(self):
        result = UsernameValidator().validate("John_Doe-1")
        self.assertTrue(result.ok)
        self.assertEqual(result.username, "John_Doe-1")

    def test_rejects_reserved(self):
        result = UsernameValidator().validate("admin")
        self.assertFalse(result.ok)


class UsernameAnalyzerTests(SimpleTestCase):
    def test_analyzer_aggregates_hits(self):
        scan = PlatformScanResult(
            success=True,
            username="johndoe",
            hits=[
                PlatformHit("GitHub", "development", "https://github.com/johndoe", 200, True),
                PlatformHit("Reddit", "social", "https://reddit.com/user/johndoe", 404, False),
            ],
            checked_count=2,
        )
        with patch(
            "username_osint.services.analyzer.scan_username",
            return_value=scan,
        ):
            report = UsernameOsintAnalyzer().analyze("johndoe")

        self.assertTrue(report.success)
        self.assertEqual(report.found_count, 1)
        self.assertEqual(report.checked_count, 2)
        self.assertEqual(len(report.platforms), 2)


class InconclusiveStatusRegressionTests(SimpleTestCase):
    """
    Regression tests for a real bug found via live testing: 403 (bot-blocked),
    429 (rate limited), and network errors were silently classified as
    "not found" alongside genuine 404s. These are NOT confirmations of
    absence and must be surfaced separately.
    """

    def _platform(self, **overrides) -> Platform:
        defaults = dict(
            name="TestPlatform",
            category="test",
            url_template="https://example.test/{username}",
        )
        defaults.update(overrides)
        return Platform(**defaults)

    def _mock_response(self, status_code, text=""):
        resp = Mock()
        resp.status_code = status_code
        resp.text = text
        return resp

    @patch("username_osint.services.platform_checker.requests.get")
    def test_403_is_inconclusive_not_confirmed_absent(self, mock_get):
        mock_get.return_value = self._mock_response(403)
        hit = _check_one(self._platform(), "someuser")
        self.assertFalse(hit.found)
        self.assertTrue(hit.inconclusive)
        self.assertIn("blocked", hit.inconclusive_reason.lower())

    @patch("username_osint.services.platform_checker.requests.get")
    def test_429_is_inconclusive_not_confirmed_absent(self, mock_get):
        mock_get.return_value = self._mock_response(429)
        hit = _check_one(self._platform(), "someuser")
        self.assertFalse(hit.found)
        self.assertTrue(hit.inconclusive)
        self.assertIn("rate limited", hit.inconclusive_reason.lower())

    @patch("username_osint.services.platform_checker.requests.get")
    def test_genuine_404_is_confirmed_not_found_not_inconclusive(self, mock_get):
        mock_get.return_value = self._mock_response(404)
        hit = _check_one(self._platform(), "someuser")
        self.assertFalse(hit.found)
        self.assertFalse(hit.inconclusive)

    @patch("username_osint.services.platform_checker.requests.get")
    def test_platform_can_override_403_as_genuine_not_found(self, mock_get):
        # A platform that has verified 403 really does mean "no such user"
        # can explicitly declare that via not_found_status, taking
        # precedence over the generic ambiguous-block treatment.
        mock_get.return_value = self._mock_response(403)
        platform = self._platform(not_found_status=(403, 404))
        hit = _check_one(platform, "someuser")
        self.assertFalse(hit.found)
        self.assertFalse(hit.inconclusive)

    @patch("username_osint.services.platform_checker.requests.get")
    def test_network_error_is_inconclusive(self, mock_get):
        import requests

        mock_get.side_effect = requests.ConnectionError("boom")
        hit = _check_one(self._platform(), "someuser")
        self.assertFalse(hit.found)
        self.assertTrue(hit.inconclusive)
        self.assertIn("network error", hit.inconclusive_reason.lower())

    @patch("username_osint.services.platform_checker.requests.get")
    def test_timeout_is_inconclusive(self, mock_get):
        import requests

        mock_get.side_effect = requests.Timeout("boom")
        hit = _check_one(self._platform(), "someuser")
        self.assertFalse(hit.found)
        self.assertTrue(hit.inconclusive)
        self.assertIn("timed out", hit.inconclusive_reason.lower())

    def test_scan_result_inconclusive_count(self):
        scan = PlatformScanResult(
            success=True,
            hits=[
                PlatformHit("A", "c", "u", 200, True),
                PlatformHit("B", "c", "u", 404, False),
                PlatformHit("C", "c", "u", 403, False, inconclusive=True, inconclusive_reason="blocked"),
                PlatformHit("D", "c", "u", 429, False, inconclusive=True, inconclusive_reason="rate limited"),
            ],
            checked_count=4,
        )
        self.assertEqual(scan.found_count, 1)
        self.assertEqual(scan.inconclusive_count, 2)

    def test_analyzer_summary_separates_all_three_buckets(self):
        scan = PlatformScanResult(
            success=True,
            username="johndoe",
            hits=[
                PlatformHit("GitHub", "dev", "u", 200, True),
                PlatformHit("Reddit", "social", "u", 404, False),
                PlatformHit("GitLab", "dev", "u", 403, False, inconclusive=True, inconclusive_reason="blocked"),
            ],
            checked_count=3,
        )
        with patch(
            "username_osint.services.analyzer.scan_username",
            return_value=scan,
        ):
            report = UsernameOsintAnalyzer().analyze("johndoe")

        summary = report.sections["Summary"]
        self.assertEqual(summary["Profiles found"], "1")
        self.assertEqual(summary["Confirmed no match"], "1")
        self.assertEqual(summary["Inconclusive (blocked/rate-limited/error)"], "1")
        joined_flags = " ".join(report.risk_flags)
        self.assertIn("NOT confirmed as absent", joined_flags)
