from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from org_footprint_osint.services.analyzer import OrgFootprintAnalyzer
from org_footprint_osint.services.domain_validator import DomainValidator
from org_footprint_osint.services.http_fingerprint import HttpFingerprintResult
from org_footprint_osint.services.mail_security import MailSecurityAnalyzer, MailSecurityResult
from org_footprint_osint.services.org_identity import OrgIdentity, OrgIdentityLookup
from org_footprint_osint.services.social_presence import SocialPresenceChecker


class DomainValidatorTests(SimpleTestCase):
    def test_accepts_plain_domain(self):
        result = DomainValidator().validate("example.com")
        self.assertTrue(result.ok)
        self.assertEqual(result.domain, "example.com")

    def test_strips_www_and_https(self):
        result = DomainValidator().validate("https://www.Example.COM/path")
        self.assertFalse(result.ok)

    def test_rejects_localhost(self):
        result = DomainValidator().validate("localhost")
        self.assertFalse(result.ok)

    def test_rejects_test_tld(self):
        result = DomainValidator().validate("app.test")
        self.assertFalse(result.ok)


class DmarcPolicyExtractionTests(SimpleTestCase):
    def test_extracts_reject_policy(self):
        record = "v=DMARC1; p=reject; rua=mailto:reports@example.com"
        policy = MailSecurityAnalyzer._extract_dmarc_policy(record)
        self.assertEqual(policy, "reject")

    def test_missing_policy_tag_returns_empty(self):
        policy = MailSecurityAnalyzer._extract_dmarc_policy("v=DMARC1")
        self.assertEqual(policy, "")


class SlugFromDomainTests(SimpleTestCase):
    def test_simple_label(self):
        slug = SocialPresenceChecker().slug_from_domain("example.com")
        self.assertEqual(slug, "example")

    def test_strips_non_alphanumeric(self):
        slug = SocialPresenceChecker().slug_from_domain("my-cool_site123.co.uk")
        self.assertEqual(slug, "my-coolsite123")


class RiskFlagDerivationTests(SimpleTestCase):
    def setUp(self):
        self.analyzer = OrgFootprintAnalyzer.__new__(OrgFootprintAnalyzer)

    def test_flags_missing_spf_and_dmarc(self):
        identity = OrgIdentity(success=True, org_name="Acme", whois_privacy=False)
        mail = MailSecurityResult(success=True, domain="example.com")
        http_result = HttpFingerprintResult(
            success=True,
            security_headers_present=["Strict-Transport-Security"],
            security_headers_missing=[
                "Content-Security-Policy",
                "X-Content-Type-Options",
                "X-Frame-Options",
            ],
        )
        flags = self.analyzer._derive_risk_flags(identity, mail, http_result)
        joined = " ".join(flags)
        self.assertIn("No SPF record", joined)
        self.assertIn("No DMARC record", joined)
        self.assertIn("security headers are missing", joined)

    def test_dmarc_none_policy_flagged_but_not_missing(self):
        identity = OrgIdentity(success=True)
        mail = MailSecurityResult(
            success=True,
            domain="example.com",
            spf_present=True,
            dmarc_present=True,
            dmarc_policy="none",
        )
        http_result = HttpFingerprintResult(success=True, security_headers_missing=[])
        flags = self.analyzer._derive_risk_flags(identity, mail, http_result)
        joined = " ".join(flags)
        self.assertNotIn("No SPF", joined)
        self.assertNotIn("No DMARC record", joined)
        self.assertIn("p=none", joined)

    def test_whois_privacy_flagged(self):
        identity = OrgIdentity(success=True, whois_privacy=True)
        mail = MailSecurityResult(
            success=True, domain="example.com", spf_present=True, dmarc_present=True, dmarc_policy="reject"
        )
        http_result = HttpFingerprintResult(success=True, security_headers_missing=[])
        flags = self.analyzer._derive_risk_flags(identity, mail, http_result)
        self.assertTrue(any("privacy-protected" in f for f in flags))


class SocialPresenceBotProtectedPlatformTests(SimpleTestCase):
    """
    Regression tests: LinkedIn/Facebook/Instagram/Crunchbase serve a 200
    login-wall or soft-404 page for almost any slug, whether or not the
    company page exists. A 200 from these must never be reported as
    "Confirmed" — only genuinely verifiable platforms (GitHub, X) can be.
    """

    def _mock_response(self, status_code):
        mock_resp = Mock()
        mock_resp.status_code = status_code
        return mock_resp

    @patch("org_footprint_osint.services.social_presence.requests.get")
    def test_linkedin_200_is_never_confirmed(self, mock_get):
        mock_get.return_value = self._mock_response(200)
        result = SocialPresenceChecker().check("example.com")
        linkedin = next(c for c in result.checks if c.platform == "LinkedIn (company)")
        self.assertFalse(linkedin.found)
        self.assertFalse(linkedin.verifiable)

    @patch("org_footprint_osint.services.social_presence.requests.get")
    def test_github_200_is_confirmed(self, mock_get):
        mock_get.return_value = self._mock_response(200)
        result = SocialPresenceChecker().check("example.com")
        github = next(c for c in result.checks if c.platform == "GitHub")
        self.assertTrue(github.found)
        self.assertTrue(github.verifiable)

    @patch("org_footprint_osint.services.social_presence.requests.get")
    def test_github_404_is_not_found(self, mock_get):
        mock_get.return_value = self._mock_response(404)
        result = SocialPresenceChecker().check("example.com")
        github = next(c for c in result.checks if c.platform == "GitHub")
        self.assertFalse(github.found)

    @patch("org_footprint_osint.services.social_presence.requests.get")
    def test_found_count_excludes_unverifiable_platforms(self, mock_get):
        # Every platform returns 200 — only verifiable ones should count.
        mock_get.return_value = self._mock_response(200)
        result = SocialPresenceChecker().check("example.com")
        verifiable_names = {"GitHub", "X / Twitter"}
        expected = sum(1 for c in result.checks if c.platform in verifiable_names)
        self.assertEqual(result.found_count, expected)


class OrgFootprintAnalyzerDisplayTests(SimpleTestCase):
    """Covers the section-rendering logic in analyzer.analyze(), not just the flags."""

    def setUp(self):
        self.analyzer = OrgFootprintAnalyzer.__new__(OrgFootprintAnalyzer)
        self.analyzer.validator = DomainValidator()
        self.analyzer.identity_lookup = Mock()
        self.analyzer.mail_analyzer = Mock()
        self.analyzer.http_fingerprinter = Mock()
        self.analyzer.social_checker = Mock()

    def test_registry_withholding_data_shows_honest_notice_not_blank_dash(self):
        self.analyzer.identity_lookup.lookup.return_value = OrgIdentity(
            success=True, registry_withholds_data=True, registrar="PKNIC"
        )
        self.analyzer.mail_analyzer.analyze.return_value = MailSecurityResult(
            success=True, domain="example.pk"
        )
        self.analyzer.http_fingerprinter.fetch.return_value = HttpFingerprintResult(success=False, error="n/a")
        self.analyzer.social_checker.check.return_value = Mock(checks=[], slug="example")

        report = self.analyzer.analyze("example.pk")
        identity_section = report.sections["Organization Identity"]
        self.assertIn("Notice", identity_section)
        self.assertIn("does not publish", identity_section["Notice"])
        self.assertNotIn("Organization", identity_section)

    def test_normal_registry_shows_full_fields(self):
        self.analyzer.identity_lookup.lookup.return_value = OrgIdentity(
            success=True,
            registry_withholds_data=False,
            org_name="Acme Inc.",
            country="US",
            registrar="GoDaddy",
        )
        self.analyzer.mail_analyzer.analyze.return_value = MailSecurityResult(
            success=True, domain="example.com"
        )
        self.analyzer.http_fingerprinter.fetch.return_value = HttpFingerprintResult(success=False, error="n/a")
        self.analyzer.social_checker.check.return_value = Mock(checks=[], slug="example")

        report = self.analyzer.analyze("example.com")
        identity_section = report.sections["Organization Identity"]
        self.assertEqual(identity_section["Organization"], "Acme Inc.")
        self.assertNotIn("Notice", identity_section)

    def test_platform_match_never_claims_ownership_confirmed(self):
        """
        A matching slug (e.g. github.com/example) is evidence a page exists,
        not evidence this organization owns it — common/short names are
        routinely squatted by unrelated accounts. The report must not use
        language like "Confirmed" that implies verified ownership.
        """
        from org_footprint_osint.services.social_presence import PlatformCheck

        self.analyzer.identity_lookup.lookup.return_value = OrgIdentity(success=False, error="n/a")
        self.analyzer.mail_analyzer.analyze.return_value = MailSecurityResult(
            success=True, domain="example.com"
        )
        self.analyzer.http_fingerprinter.fetch.return_value = HttpFingerprintResult(success=False, error="n/a")
        self.analyzer.social_checker.check.return_value = Mock(
            checks=[
                PlatformCheck(
                    platform="GitHub",
                    url="https://github.com/example",
                    found=True,
                    verifiable=True,
                    status_code=200,
                )
            ],
            slug="example",
            found_count=1,
        )

        report = self.analyzer.analyze("example.com")
        github_text = report.sections["Official Platform Presence"]["GitHub"]
        self.assertNotIn("Confirmed", github_text)
        self.assertIn("verify", github_text.lower())
        self.assertIn("Method", report.sections["Official Platform Presence"])
