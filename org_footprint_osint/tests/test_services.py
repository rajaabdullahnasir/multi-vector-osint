from django.test import SimpleTestCase

from org_footprint_osint.services.analyzer import OrgFootprintAnalyzer
from org_footprint_osint.services.domain_validator import DomainValidator
from org_footprint_osint.services.http_fingerprint import HttpFingerprintResult
from org_footprint_osint.services.mail_security import MailSecurityAnalyzer, MailSecurityResult
from org_footprint_osint.services.org_identity import OrgIdentity
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
