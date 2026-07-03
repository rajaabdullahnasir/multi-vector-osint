from unittest.mock import patch

from django.test import SimpleTestCase

from username_osint.services.analyzer import UsernameOsintAnalyzer
from username_osint.services.platform_checker import PlatformHit, PlatformScanResult
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
