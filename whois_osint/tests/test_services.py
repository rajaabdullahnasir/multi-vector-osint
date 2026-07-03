from django.test import SimpleTestCase

from whois_osint.services.domain_validator import DomainValidator
from whois_osint.services.whois_parser import WhoisParser


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


class WhoisParserTests(SimpleTestCase):
    def test_parses_registration_fields(self):
        raw = """
Domain Name: EXAMPLE.COM
Registrar: Example Registrar, Inc.
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2026-08-13T04:00:00Z
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
DNSSEC: unsigned
"""
        parsed = WhoisParser().parse(raw)
        self.assertEqual(parsed.flat.get("Domain Name"), "EXAMPLE.COM")
        self.assertEqual(len(parsed.name_servers), 2)
        self.assertIn("Registration", parsed.sections)
