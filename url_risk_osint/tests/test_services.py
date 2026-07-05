from unittest.mock import patch

import dns.resolver
from django.test import SimpleTestCase

from url_risk_osint.services.analyzer import UrlRiskAnalyzer
from url_risk_osint.services.blacklist import check_blacklist
from url_risk_osint.services.dnsbl_client import DnsblClient
from url_risk_osint.services.risk_scorer import (
    RISK_DANGEROUS,
    RISK_SAFE,
    RISK_SUSPICIOUS,
    score_risk,
)
from url_risk_osint.services.url_validator import UrlValidator


class UrlValidatorTests(SimpleTestCase):
    def test_normalizes_scheme(self):
        result = UrlValidator().validate("example.com/path")
        self.assertTrue(result.ok)
        self.assertTrue(result.url.startswith("https://"))

    def test_blocks_localhost(self):
        result = UrlValidator().validate("http://localhost/admin")
        self.assertFalse(result.ok)


class BlacklistTests(SimpleTestCase):
    def test_blocks_known_domain(self):
        hits = check_blacklist("https://evil.com/login")
        self.assertTrue(any("evil.com" in h.rule for h in hits))


class UrlRiskAnalyzerTests(SimpleTestCase):
    def test_safe_https_url(self):
        report = UrlRiskAnalyzer().analyze("https://www.djangoproject.com/")
        self.assertTrue(report.success)
        self.assertIn(report.risk_level, (RISK_SAFE, RISK_SUSPICIOUS))

    def test_dangerous_blacklisted(self):
        report = UrlRiskAnalyzer().analyze("https://evil.com/verify-login")
        self.assertTrue(report.success)
        self.assertEqual(report.risk_level, RISK_DANGEROUS)
        self.assertGreater(report.risk_score, 50)

    def test_http_adds_lexical_score(self):
        report = UrlRiskAnalyzer().analyze("http://example.com")
        self.assertTrue(report.success)
        self.assertTrue(any(f["category"] == "transport" for f in report.lexical_findings or []))


class DnsblClientTests(SimpleTestCase):
    def _mock_answer(self, ip: str):
        answer = type("A", (), {"to_text": lambda self, ip=ip: ip})()
        return [answer]

    @patch("url_risk_osint.services.dnsbl_client.dns.resolver.Resolver.resolve")
    def test_not_listed_when_both_zones_nxdomain(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()
        result = DnsblClient().check("clean-example.com")
        self.assertTrue(result.checked)
        self.assertFalse(result.listed)
        self.assertEqual(result.categories, [])

    @patch("url_risk_osint.services.dnsbl_client.dns.resolver.Resolver.resolve")
    def test_listed_on_spamhaus_dbl_phishing(self, mock_resolve):
        def side_effect(name, rdtype):
            if "dbl.spamhaus.org" in name:
                return self._mock_answer("127.0.1.4")
            raise dns.resolver.NXDOMAIN()

        mock_resolve.side_effect = side_effect
        result = DnsblClient().check("bad-example.com")
        self.assertTrue(result.listed)
        self.assertIn("Spamhaus DBL", result.lists_hit)
        self.assertIn("phishing domain", result.categories)

    @patch("url_risk_osint.services.dnsbl_client.dns.resolver.Resolver.resolve")
    def test_listed_on_surbl(self, mock_resolve):
        def side_effect(name, rdtype):
            if "multi.surbl.org" in name:
                return self._mock_answer("127.0.0.2")
            raise dns.resolver.NXDOMAIN()

        mock_resolve.side_effect = side_effect
        result = DnsblClient().check("bad-example.com")
        self.assertTrue(result.listed)
        self.assertIn("SURBL", result.lists_hit)

    @patch("url_risk_osint.services.dnsbl_client.dns.resolver.Resolver.resolve")
    def test_rate_limited_response_not_treated_as_listing(self, mock_resolve):
        def side_effect(name, rdtype):
            if "dbl.spamhaus.org" in name:
                return self._mock_answer("127.0.1.255")
            raise dns.resolver.NXDOMAIN()

        mock_resolve.side_effect = side_effect
        result = DnsblClient().check("bad-example.com")
        self.assertFalse(result.listed)
        self.assertTrue(result.rate_limited)

    def test_empty_host_not_checked(self):
        result = DnsblClient().check("")
        self.assertFalse(result.checked)


class RiskScorerDnsblIntegrationTests(SimpleTestCase):
    def test_dnsbl_listing_forces_dangerous_even_with_no_other_signals(self):
        from url_risk_osint.services.dnsbl_client import DnsblResult

        dnsbl = DnsblResult(
            checked=True, host="bad.com", listed=True, lists_hit=["Spamhaus DBL"],
            categories=["malware domain"],
        )
        assessment = score_risk(lexical=[], blacklist=[], dnsbl=dnsbl)
        self.assertEqual(assessment.risk_level, RISK_DANGEROUS)
        self.assertGreater(assessment.dnsbl_score, 0)

    def test_no_dnsbl_hit_does_not_affect_score(self):
        from url_risk_osint.services.dnsbl_client import DnsblResult

        dnsbl = DnsblResult(checked=True, host="clean.com", listed=False)
        assessment = score_risk(lexical=[], blacklist=[], dnsbl=dnsbl)
        self.assertEqual(assessment.dnsbl_score, 0)
        self.assertEqual(assessment.risk_level, RISK_SAFE)

    def test_backward_compatible_without_dnsbl_argument(self):
        # Older call sites (or tests) that don't pass dnsbl at all must
        # still work exactly as before.
        assessment = score_risk(lexical=[], blacklist=[])
        self.assertEqual(assessment.dnsbl_score, 0)
