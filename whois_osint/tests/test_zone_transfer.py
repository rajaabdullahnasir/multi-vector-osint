from unittest.mock import Mock, patch

import dns.exception
from django.test import SimpleTestCase

from whois_osint.services.zone_transfer import ZoneTransferTester


class ZoneTransferTests(SimpleTestCase):
    def _mock_resolver(self, ip="1.2.3.4"):
        mock_answers = [Mock(__str__=lambda self: ip)]
        return mock_answers

    @patch("whois_osint.services.zone_transfer.dns.resolver.Resolver")
    def test_no_nameservers_reported_honestly(self, mock_resolver_cls):
        result = ZoneTransferTester().test("example.com", None)
        self.assertFalse(result.success)
        self.assertIn("No nameservers", result.error)

    @patch("whois_osint.services.zone_transfer.dns.zone.from_xfr")
    @patch("whois_osint.services.zone_transfer.dns.query.xfr")
    @patch("whois_osint.services.zone_transfer.dns.resolver.Resolver")
    def test_refused_transfer_is_not_vulnerable(self, mock_resolver_cls, mock_xfr, mock_from_xfr):
        mock_resolver_cls.return_value.resolve.return_value = self._mock_resolver()
        mock_from_xfr.side_effect = dns.exception.FormError()

        result = ZoneTransferTester().test("example.com", ["ns1.example.com"])
        self.assertTrue(result.success)
        self.assertFalse(result.any_vulnerable)
        self.assertFalse(result.attempts[0].vulnerable)
        self.assertIn("expected", result.attempts[0].error.lower())

    @patch("whois_osint.services.zone_transfer.dns.zone.from_xfr")
    @patch("whois_osint.services.zone_transfer.dns.query.xfr")
    @patch("whois_osint.services.zone_transfer.dns.resolver.Resolver")
    def test_connection_refused_is_not_vulnerable(self, mock_resolver_cls, mock_xfr, mock_from_xfr):
        mock_resolver_cls.return_value.resolve.return_value = self._mock_resolver()
        mock_from_xfr.side_effect = ConnectionRefusedError()

        result = ZoneTransferTester().test("example.com", ["ns1.example.com"])
        self.assertFalse(result.any_vulnerable)

    @patch("whois_osint.services.zone_transfer.dns.zone.from_xfr")
    @patch("whois_osint.services.zone_transfer.dns.query.xfr")
    @patch("whois_osint.services.zone_transfer.dns.resolver.Resolver")
    def test_successful_transfer_is_flagged_vulnerable(self, mock_resolver_cls, mock_xfr, mock_from_xfr):
        mock_resolver_cls.return_value.resolve.return_value = self._mock_resolver()
        mock_zone = Mock()
        mock_zone.nodes = {f"host{i}.example.com": Mock() for i in range(15)}
        mock_from_xfr.return_value = mock_zone

        result = ZoneTransferTester().test("example.com", ["ns1.example.com"])
        self.assertTrue(result.success)
        self.assertTrue(result.any_vulnerable)
        attempt = result.attempts[0]
        self.assertTrue(attempt.vulnerable)
        self.assertEqual(attempt.record_count, 15)
        self.assertEqual(len(attempt.sample_records), 8)  # capped sample
        self.assertIn("ns1.example.com", result.vulnerable_nameservers)

    @patch("whois_osint.services.zone_transfer.dns.resolver.Resolver")
    def test_unresolvable_nameserver_reported_honestly_not_crash(self, mock_resolver_cls):
        mock_resolver_cls.return_value.resolve.side_effect = dns.exception.DNSException()
        result = ZoneTransferTester().test("example.com", ["ns-broken.example.com"])
        self.assertTrue(result.success)
        self.assertFalse(result.attempts[0].vulnerable)
        self.assertIn("Could not resolve", result.attempts[0].error)

    @patch("whois_osint.services.zone_transfer.dns.zone.from_xfr")
    @patch("whois_osint.services.zone_transfer.dns.query.xfr")
    @patch("whois_osint.services.zone_transfer.dns.resolver.Resolver")
    def test_multiple_nameservers_each_tested_independently(self, mock_resolver_cls, mock_xfr, mock_from_xfr):
        mock_resolver_cls.return_value.resolve.return_value = self._mock_resolver()

        def side_effect(*args, **kwargs):
            raise dns.exception.FormError()

        mock_from_xfr.side_effect = side_effect
        result = ZoneTransferTester().test("example.com", ["ns1.example.com", "ns2.example.com"])
        self.assertEqual(len(result.attempts), 2)
        self.assertFalse(result.any_vulnerable)
