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


class DnsblQueryFailureRegressionTests(SimpleTestCase):
    """
    Regression tests for a real bug: a DNS timeout/resolution failure was
    caught by the same except clause as a genuine NXDOMAIN ("not listed"),
    so a failed security check silently looked identical to a verified-
    clean result. This is the same false-negative pattern already fixed in
    WHOIS and Username OSINT this session, applied to a threat-intel check
    where it's especially dangerous — it could report a malicious URL as
    "Safe" purely because the DNSBL lookup failed to resolve at all.
    """

    def _mock_answer(self, ip: str):
        answer = type("A", (), {"to_text": lambda self, ip=ip: ip})()
        return [answer]

    @patch("url_risk_osint.services.dnsbl_client.dns.resolver.Resolver.resolve")
    def test_both_lists_erroring_is_not_reported_as_clean(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.Timeout()
        result = DnsblClient().check("some-domain.com")
        self.assertTrue(result.checked)
        self.assertFalse(result.listed)
        self.assertFalse(result.fully_verified)
        self.assertEqual(set(result.lists_errored), {"Spamhaus DBL", "SURBL"})
        self.assertIsNotNone(result.error)

    @patch("url_risk_osint.services.dnsbl_client.dns.resolver.Resolver.resolve")
    def test_one_list_erroring_is_tracked_separately_from_clean(self, mock_resolve):
        def side_effect(name, rdtype):
            if "dbl.spamhaus.org" in name:
                raise dns.resolver.Timeout()
            raise dns.resolver.NXDOMAIN()  # SURBL genuinely clean

        mock_resolve.side_effect = side_effect
        result = DnsblClient().check("some-domain.com")
        self.assertTrue(result.checked)
        self.assertFalse(result.listed)
        self.assertFalse(result.fully_verified)
        self.assertEqual(result.lists_errored, ["Spamhaus DBL"])

    @patch("url_risk_osint.services.dnsbl_client.dns.resolver.Resolver.resolve")
    def test_genuine_nxdomain_on_both_is_fully_verified_clean(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()
        result = DnsblClient().check("clean-example.com")
        self.assertTrue(result.fully_verified)
        self.assertEqual(result.lists_errored, [])

    @patch("url_risk_osint.services.dnsbl_client.dns.resolver.Resolver.resolve")
    def test_listing_still_reported_even_if_other_list_errors(self, mock_resolve):
        def side_effect(name, rdtype):
            if "dbl.spamhaus.org" in name:
                return self._mock_answer("127.0.1.5")  # malware
            raise dns.resolver.Timeout()  # SURBL fails

        mock_resolve.side_effect = side_effect
        result = DnsblClient().check("bad-example.com")
        self.assertTrue(result.listed)
        self.assertIn("malware domain", result.categories)
        self.assertEqual(result.lists_errored, ["SURBL"])


class AnalyzerDnsblHonestyTests(SimpleTestCase):
    """The rendered report text itself must never claim 'Not listed' when
    the query actually failed — this is what a human reads and trusts."""

    def setUp(self):
        self.analyzer = UrlRiskAnalyzer.__new__(UrlRiskAnalyzer)
        from url_risk_osint.services.url_validator import UrlValidator

        self.analyzer.validator = UrlValidator()
        self.analyzer.dnsbl_client = type(
            "Fake", (), {"check": lambda self, host: self._result}
        )()

    def _analyze_with(self, dnsbl_result):
        self.analyzer.dnsbl_client._result = dnsbl_result
        return self.analyzer.analyze("https://example.com")

    def test_total_dnsbl_failure_does_not_say_not_listed(self):
        from url_risk_osint.services.dnsbl_client import DnsblResult

        dnsbl = DnsblResult(
            checked=True,
            host="example.com",
            listed=False,
            lists_errored=["Spamhaus DBL", "SURBL"],
            error="Query failed for: Spamhaus DBL (Timeout); SURBL (Timeout)",
        )
        report = self._analyze_with(dnsbl)
        status = report.sections["Live Threat Feed (DNSBL)"]["Status"]
        self.assertNotIn("Not listed", status)
        self.assertIn("could not be verified", status.lower())
        joined_flags = " ".join(report.risk_flags)
        self.assertIn("NOT a confirmed-safe result", joined_flags)

    def test_partial_failure_names_which_list_actually_answered(self):
        from url_risk_osint.services.dnsbl_client import DnsblResult

        dnsbl = DnsblResult(
            checked=True,
            host="example.com",
            listed=False,
            lists_errored=["Spamhaus DBL"],
            error="Query failed for: Spamhaus DBL (Timeout)",
        )
        report = self._analyze_with(dnsbl)
        status = report.sections["Live Threat Feed (DNSBL)"]["Status"]
        self.assertIn("SURBL", status)
        self.assertIn("could not be reached", status)

    def test_genuine_clean_result_unaffected(self):
        from url_risk_osint.services.dnsbl_client import DnsblResult

        dnsbl = DnsblResult(checked=True, host="example.com", listed=False)
        report = self._analyze_with(dnsbl)
        status = report.sections["Live Threat Feed (DNSBL)"]["Status"]
        self.assertEqual(status, "Not listed on Spamhaus DBL or SURBL.")


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
