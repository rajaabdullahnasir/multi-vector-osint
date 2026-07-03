from django.test import SimpleTestCase

from url_risk_osint.services.analyzer import UrlRiskAnalyzer
from url_risk_osint.services.blacklist import check_blacklist
from url_risk_osint.services.risk_scorer import RISK_DANGEROUS, RISK_SAFE, RISK_SUSPICIOUS
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
