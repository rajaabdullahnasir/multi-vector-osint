from unittest.mock import patch

from django.test import SimpleTestCase

from password_breach_osint.services.analyzer import PasswordBreachAnalyzer
from password_breach_osint.services.pwned_passwords_client import (
    check_password,
    sha1_hex,
)


class PwnedPasswordsClientTests(SimpleTestCase):
    def test_sha1_test123_matches_csharp_flow(self):
        digest = sha1_hex("test123")
        self.assertEqual(digest, "7288EDD0FC3FFCBE93A0CF06E3568E28521687BC")
        self.assertEqual(digest[:5], "7288E")
        self.assertEqual(digest[5:], "DD0FC3FFCBE93A0CF06E3568E28521687BC")

    def test_sha1_known(self):
        self.assertEqual(
            sha1_hex("password"),
            "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8",
        )

    def test_contains_suffix_match(self):
        from password_breach_osint.services.pwned_passwords_client import (
            response_contains_suffix,
        )

        body = "DD0FC3FFCBE93A0CF06E3568E28521687BC:42\r\n"
        self.assertTrue(
            response_contains_suffix(body, "DD0FC3FFCBE93A0CF06E3568E28521687BC")
        )
        self.assertFalse(response_contains_suffix(body, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"))

    def test_pwned_password(self):
        suffix = sha1_hex("password")[5:]
        body = f"{suffix}:3861493\r\nDDDD1:1\r\n"
        mock_resp = type("R", (), {"status_code": 200, "ok": True, "text": body})()

        with patch(
            "password_breach_osint.services.pwned_passwords_client.requests.get",
            return_value=mock_resp,
        ):
            result = check_password("password")

        self.assertTrue(result.ok)
        self.assertTrue(result.is_pwned)
        self.assertEqual(result.exposure_count, 3861493)

    def test_clean_password(self):
        suffix = sha1_hex("unique-random-test-string-xyz")[5:]
        body = f"FFFFF:1\r\n"
        mock_resp = type("R", (), {"status_code": 200, "ok": True, "text": body})()

        with patch(
            "password_breach_osint.services.pwned_passwords_client.requests.get",
            return_value=mock_resp,
        ):
            result = check_password("unique-random-test-string-xyz")

        self.assertTrue(result.ok)
        self.assertFalse(result.is_pwned)


class PasswordBreachAnalyzerTests(SimpleTestCase):
    def test_analyzer_never_stores_plaintext_in_report(self):
        suffix = sha1_hex("password")[5:]
        body = f"{suffix}:100\r\n"
        mock_resp = type("R", (), {"status_code": 200, "ok": True, "text": body})()

        with patch(
            "password_breach_osint.services.pwned_passwords_client.requests.get",
            return_value=mock_resp,
        ):
            report = PasswordBreachAnalyzer().analyze("password")

        self.assertTrue(report.success)
        stored = report.to_storage_dict()
        self.assertFalse(stored.get("plaintext_stored"))
        self.assertNotIn("plaintext", stored)
        self.assertIn("sha1_hash", stored)
