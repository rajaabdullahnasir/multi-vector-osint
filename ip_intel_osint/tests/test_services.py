from unittest.mock import patch

from django.test import SimpleTestCase

from ip_intel_osint.services.analyzer import IPIntelAnalyzer
from ip_intel_osint.services.ip_geolocation_client import GeolocationResult
from ip_intel_osint.services.ip_validator import IPInputResolver


class IPInputResolverTests(SimpleTestCase):
    def test_accepts_public_ipv4(self):
        result = IPInputResolver().resolve("8.8.8.8")
        self.assertTrue(result.ok)
        self.assertEqual(result.ip, "8.8.8.8")
        self.assertFalse(result.was_domain)

    def test_rejects_private_ip(self):
        result = IPInputResolver().resolve("192.168.1.1")
        self.assertFalse(result.ok)
        self.assertIn("Private", result.error)

    def test_rejects_loopback(self):
        result = IPInputResolver().resolve("127.0.0.1")
        self.assertFalse(result.ok)

    def test_rejects_url_input(self):
        result = IPInputResolver().resolve("https://example.com")
        self.assertFalse(result.ok)

    def test_rejects_garbage_input(self):
        result = IPInputResolver().resolve("not an ip or domain!!")
        self.assertFalse(result.ok)

    @patch.object(IPInputResolver, "_resolve_domain", return_value="93.184.216.34")
    def test_resolves_valid_domain(self, mock_resolve):
        result = IPInputResolver().resolve("example.com")
        self.assertTrue(result.ok)
        self.assertEqual(result.ip, "93.184.216.34")
        self.assertTrue(result.was_domain)

    @patch.object(IPInputResolver, "_resolve_domain", return_value=None)
    def test_domain_resolution_failure_reported(self, mock_resolve):
        result = IPInputResolver().resolve("doesnotexist.invalidtld")
        self.assertFalse(result.ok)


class RiskFlagDerivationTests(SimpleTestCase):
    def setUp(self):
        self.analyzer = IPIntelAnalyzer.__new__(IPIntelAnalyzer)

    def test_flags_proxy_and_hosting(self):
        geo = GeolocationResult(ok=True, is_proxy_or_vpn=True, is_hosting=True)
        flags = self.analyzer._derive_risk_flags(geo)
        joined = " ".join(flags)
        self.assertIn("proxy or VPN", joined)
        self.assertIn("hosting/datacenter", joined)

    def test_no_flags_for_clean_residential_ip(self):
        geo = GeolocationResult(ok=True, is_proxy_or_vpn=False, is_hosting=False)
        flags = self.analyzer._derive_risk_flags(geo)
        self.assertEqual(flags, [])

    def test_no_flags_when_geolocation_failed(self):
        geo = GeolocationResult(ok=False, error="timeout")
        flags = self.analyzer._derive_risk_flags(geo)
        self.assertEqual(flags, [])
