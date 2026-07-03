import json
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase

from subdomain_osint.services.subdomain_enumerator import SubdomainEnumerator


class SubdomainEnumeratorTests(SimpleTestCase):
    def test_dns_probe_finds_resolving_host(self):
        enumerator = SubdomainEnumerator()
        with patch.object(enumerator, "_resolve_host") as resolve:
            resolve.side_effect = lambda host: (
                ["A 93.184.216.34"] if host == "www.example.com" else []
            )
            with patch(
                "subdomain_osint.services.subdomain_enumerator.fetch_ct_hosts",
                return_value=(set(), None),
            ):
                result = enumerator.enumerate("example.com")

        self.assertTrue(result.success)
        self.assertEqual(result.count, 1)
        self.assertEqual(result.subdomains[0].host, "www.example.com")
        self.assertIn("dns-bruteforce", result.subdomains[0].sources)

    def test_ct_hosts_merged_and_deduped(self):
        ct_payload = json.dumps(
            [
                {"name_value": "api.example.com\nwww.example.com"},
                {"common_name": "api.example.com"},
            ]
        ).encode()

        enumerator = SubdomainEnumerator()
        with patch.object(enumerator, "_probe_common_labels", return_value={}):
            with patch.object(enumerator, "_resolve_host", return_value=[]):
                with patch(
                    "subdomain_osint.services.subdomain_enumerator.fetch_ct_hosts",
                    return_value=(
                        {"api.example.com", "www.example.com"},
                        None,
                    ),
                ):
                    result = enumerator.enumerate("example.com")

        self.assertTrue(result.success)
        hosts = {s.host for s in result.subdomains}
        self.assertEqual(hosts, {"api.example.com", "www.example.com"})

    def test_ct_failure_still_returns_dns_with_warning(self):
        enumerator = SubdomainEnumerator()
        with patch.object(
            enumerator,
            "_probe_common_labels",
            return_value={"mail.example.com": ["A 10.0.0.1"]},
        ):
            with patch.object(enumerator, "_probe_extended_labels", return_value={}):
                with patch(
                    "subdomain_osint.services.subdomain_enumerator.fetch_ct_hosts",
                    return_value=(
                        set(),
                        "Certificate Transparency lookup timed out. DNS probing results are still included.",
                    ),
                ):
                    result = enumerator.enumerate("example.com")

        self.assertTrue(result.success)
        self.assertEqual(result.count, 1)
        self.assertTrue(result.warnings)
