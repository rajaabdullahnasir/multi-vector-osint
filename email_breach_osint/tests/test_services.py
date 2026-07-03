from django.test import SimpleTestCase, override_settings

from email_breach_osint.services.email_validator import EmailValidator
from email_breach_osint.services.xposedornot_client import (
    HttpRequest,
    HttpResponse,
    check_breached_account,
    geo_block_error_message,
    is_geo_or_cloudflare_block,
)


class EmailValidatorTests(SimpleTestCase):
    def test_accepts_valid_email(self):
        result = EmailValidator().validate("User@Company.COM")
        self.assertTrue(result.ok)
        self.assertEqual(result.email, "user@company.com")

    def test_rejects_example_domain(self):
        result = EmailValidator().validate("test@example.com")
        self.assertFalse(result.ok)


class XposedOrNotClientTests(SimpleTestCase):
    def test_geo_block_detection(self):
        html = "<!DOCTYPE html><title>Just a moment...</title>"
        self.assertTrue(is_geo_or_cloudflare_block(403, html))

    def test_geo_block_error_mentions_proxy_not_hibp(self):
        msg = geo_block_error_message().lower()
        self.assertIn("proxy", msg)
        self.assertNotIn("hibp", msg)

    def test_parses_check_email_success(self):
        from unittest.mock import patch

        payload = {
            "breaches": [["Tesco", "KiwiFarms", "SweClockers"]],
            "email": "test@example.com",
            "status": "success",
        }
        http_resp = HttpResponse(
            status_code=200,
            ok=True,
            body=payload,
            text="",
        )

        with patch(
            "email_breach_osint.services.xposedornot_client.get",
            return_value=(HttpRequest("GET", "http://test", {}), http_resp),
        ):
            result = check_breached_account("test@example.com")

        self.assertTrue(result.ok)
        self.assertEqual(result.breach_count, 3)

    def test_not_found(self):
        from unittest.mock import patch

        http_resp = HttpResponse(
            status_code=200,
            ok=True,
            body={"Error": "Not found"},
            text='{"Error":"Not found"}',
        )

        with patch(
            "email_breach_osint.services.xposedornot_client.get",
            return_value=(HttpRequest("GET", "http://test", {}), http_resp),
        ):
            result = check_breached_account("clean@company.com")

        self.assertTrue(result.ok)
        self.assertTrue(result.no_breaches)

    @override_settings(XPOSEDORNOT_HTTP_PROXY="http://127.0.0.1:9999")
    def test_uses_proxy_when_configured(self):
        from unittest.mock import patch

        captured = {}

        def fake_get(url, headers, timeout, proxies):
            captured["proxies"] = proxies
            mock = type("R", (), {})()
            mock.status_code = 200
            mock.ok = True
            mock.text = '{"Error":"Not found"}'
            mock.json = lambda: {"Error": "Not found"}
            return mock

        with patch(
            "email_breach_osint.services.xposedornot_client.requests.get",
            side_effect=fake_get,
        ):
            check_breached_account("user@company.com")

        self.assertEqual(
            captured["proxies"],
            {"http": "http://127.0.0.1:9999", "https": "http://127.0.0.1:9999"},
        )
