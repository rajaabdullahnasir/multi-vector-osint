from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from email_breach_osint.models import EmailBreachCheck
from email_breach_osint.services.analyzer import EmailBreachReport
from investigation_osint.services.investigation_engine import InvestigationEngine
from ip_intel_osint.models import IPIntelligence
from ip_intel_osint.services.analyzer import IPIntelReport
from org_footprint_osint.models import OrgFootprint
from org_footprint_osint.services.analyzer import OrgFootprintReport
from subdomain_osint.models import SubdomainScan
from subdomain_osint.services.analyzer import SubdomainScanReport
from url_risk_osint.models import UrlRiskCheck
from url_risk_osint.services.analyzer import UrlRiskReport
from username_osint.models import UsernameLookup
from username_osint.services.analyzer import UsernameOsintReport
from whois_osint.models import DomainLookup
from whois_osint.services.analyzer import DomainIntelReport

User = get_user_model()


class InvestigationValidationTests(TestCase):
    """Invalid input must fail before touching any analyzer or the network."""

    def setUp(self):
        self.user = User.objects.create_user(
            username="invval@test.com", email="invval@test.com", password="TestPass1!"
        )

    def test_invalid_domain_fails_fast(self):
        engine = InvestigationEngine(self.user)
        report = engine.run("not a domain!!!")
        self.assertFalse(report.success)
        self.assertTrue(report.validation_failed)


class InvestigationEnginePivotTests(TestCase):
    """
    Full pivot chain with every underlying analyzer mocked (no real network),
    but using REAL dataclass instances for the fake returns so any field-name
    drift between this engine and the actual module dataclasses fails the
    test immediately instead of silently misbehaving in production.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="invpivot@test.com", email="invpivot@test.com", password="TestPass1!"
        )
        self.engine = InvestigationEngine(self.user)

        self.engine.whois_analyzer.analyze = lambda domain: DomainIntelReport(
            success=True,
            domain=domain,
            whois_raw="Registrant Email: found@registrant-example.com\n",
            name_servers=["ns1.example.com", "ns2.example.com"],
            dns_records_count=4,
            sections={},
            risk_flags=["Registry expiry listed."],
        )
        self.engine.subdomain_analyzer.analyze = lambda domain: SubdomainScanReport(
            success=True,
            domain=domain,
            sections={},
            subdomains=[
                {"host": domain, "sources": ["dns"], "records": ["A 93.184.216.34"], "dns_verified": True},
                {"host": f"mail.{domain}", "sources": ["dns"], "records": ["A 203.0.113.5"], "dns_verified": True},
            ],
            subdomain_count=2,
            dns_verified_count=2,
            sources_used=["dns-bruteforce"],
            risk_flags=[],
        )
        self.engine.org_analyzer.analyze = lambda domain: OrgFootprintReport(
            success=True,
            domain=domain,
            org_name="Example Inc.",
            spf_status="present",
            dmarc_status="reject",
            security_header_score=4,
            sections={
                "Mail Security Posture": {"DMARC": "v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com"},
                "Official Platform Presence": {"Guessed handle": "exampleinc"},
            },
            risk_flags=[],
        )
        self.engine.url_analyzer.analyze = lambda url: UrlRiskReport(
            success=True, url=url, risk_level="safe", risk_score=0, sections={}, risk_flags=[]
        )
        self.engine.ip_analyzer.analyze = lambda ip: IPIntelReport(
            success=True,
            query_input=ip,
            ip=ip,
            country="US",
            city="Ashburn",
            isp="Test ISP",
            is_proxy_or_vpn=False,
            is_hosting=True,
            risk_flags=["This IP belongs to a hosting/datacenter provider."],
        )
        self.engine.email_analyzer.analyze = lambda email: EmailBreachReport(
            success=True, email=email, breach_count=0, is_pwned=False, sections={}, risk_flags=[]
        )
        self.engine.username_analyzer.analyze = lambda username: UsernameOsintReport(
            success=True,
            username=username,
            found_count=3,
            checked_count=21,
            sections={},
            risk_flags=[],
        )

    def test_full_pivot_creates_real_records_in_every_module(self):
        report = self.engine.run("example.com")

        self.assertTrue(report.success)
        self.assertIn("whois", report.modules_run)
        self.assertIn("subdomain", report.modules_run)
        self.assertIn("org-footprint", report.modules_run)
        self.assertIn("url-risk", report.modules_run)
        self.assertIn("ip-intel", report.modules_run)
        self.assertIn("email-breach", report.modules_run)
        self.assertIn("username", report.modules_run)

        # Real rows must exist in each module's own table (cross-navigation depends on this).
        self.assertTrue(DomainLookup.objects.filter(user=self.user, domain="example.com").exists())
        self.assertTrue(SubdomainScan.objects.filter(user=self.user, domain="example.com").exists())
        self.assertTrue(OrgFootprint.objects.filter(user=self.user, domain="example.com").exists())
        self.assertTrue(UrlRiskCheck.objects.filter(user=self.user, url="https://example.com").exists())
        self.assertTrue(IPIntelligence.objects.filter(user=self.user, query_input="93.184.216.34").exists())
        self.assertTrue(IPIntelligence.objects.filter(user=self.user, query_input="203.0.113.5").exists())
        self.assertTrue(
            EmailBreachCheck.objects.filter(user=self.user, email="found@registrant-example.com").exists()
        )
        self.assertTrue(
            EmailBreachCheck.objects.filter(user=self.user, email="dmarc-reports@example.com").exists()
        )
        # Username guessed from domain slug when no hint given.
        self.assertTrue(UsernameLookup.objects.filter(user=self.user, username="example").exists())

    def test_email_hint_is_included_and_capped_total_at_three(self):
        report = self.engine.run("example.com", email_hint="hinted@somewhere.com")
        self.assertTrue(
            EmailBreachCheck.objects.filter(user=self.user, email="hinted@somewhere.com").exists()
        )
        self.assertLessEqual(report.emails_checked, 3)

    def test_username_hint_overrides_guessed_slug(self):
        report = self.engine.run("example.com", username_hint="realhandle")
        self.assertTrue(UsernameLookup.objects.filter(user=self.user, username="realhandle").exists())
        self.assertFalse(UsernameLookup.objects.filter(user=self.user, username="example").exists())

    def test_ip_count_respects_cap(self):
        # Add enough discovered hosts/IPs to exceed the cap and verify no crash / correct capping.
        many_subdomains = [
            {"host": f"h{i}.example.com", "sources": ["dns"], "records": [f"A 10.0.0.{i}"], "dns_verified": True}
            for i in range(10)
        ]
        self.engine.subdomain_analyzer.analyze = lambda domain: SubdomainScanReport(
            success=True, domain=domain, sections={}, subdomains=many_subdomains,
            subdomain_count=10, dns_verified_count=10, sources_used=["dns-bruteforce"], risk_flags=[],
        )
        report = self.engine.run("example.com")
        self.assertEqual(report.ips_checked, 5)  # _MAX_IPS_TO_PIVOT

    def test_overall_risk_critical_when_url_dangerous(self):
        self.engine.url_analyzer.analyze = lambda url: UrlRiskReport(
            success=True, url=url, risk_level="dangerous", risk_score=90, sections={}, risk_flags=["bad"]
        )
        report = self.engine.run("example.com")
        self.assertEqual(report.overall_risk_level, "critical")

    def test_overall_risk_critical_when_email_breached(self):
        self.engine.email_analyzer.analyze = lambda email: EmailBreachReport(
            success=True, email=email, breach_count=5, is_pwned=True, sections={}, risk_flags=["pwned"]
        )
        report = self.engine.run("example.com")
        self.assertEqual(report.overall_risk_level, "critical")

    def test_overall_risk_low_when_everything_clean(self):
        # Remove the one risk flag from the fixture's IP report AND the
        # WHOIS report for a truly clean run — both contribute signals.
        self.engine.ip_analyzer.analyze = lambda ip: IPIntelReport(
            success=True, query_input=ip, ip=ip, country="US", city="Ashburn",
            isp="Test ISP", is_proxy_or_vpn=False, is_hosting=False, risk_flags=[],
        )
        self.engine.whois_analyzer.analyze = lambda domain: DomainIntelReport(
            success=True,
            domain=domain,
            whois_raw="",
            name_servers=["ns1.example.com"],
            dns_records_count=2,
            sections={},
            risk_flags=[],
        )
        report = self.engine.run("example.com")
        self.assertEqual(report.overall_risk_level, "low")

    def test_module_failure_does_not_crash_whole_investigation(self):
        self.engine.whois_analyzer.analyze = lambda domain: DomainIntelReport(
            success=False, error="WHOIS server unreachable."
        )
        report = self.engine.run("example.com")
        self.assertTrue(report.success)  # investigation as a whole still completes
        whois_outcome = next(o for o in report.outcomes if o.module == "whois")
        self.assertFalse(whois_outcome.ok)
        self.assertIn("unreachable", whois_outcome.summary)
