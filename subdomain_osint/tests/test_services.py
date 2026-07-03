from django.test import SimpleTestCase

from subdomain_osint.services.domain_validator import DomainValidator


class DomainValidatorTests(SimpleTestCase):
    def test_accepts_plain_domain(self):
        result = DomainValidator().validate("example.com")
        self.assertTrue(result.ok)
        self.assertEqual(result.domain, "example.com")

    def test_rejects_test_tld(self):
        result = DomainValidator().validate("app.test")
        self.assertFalse(result.ok)
