import json
from unittest.mock import patch

from django.test import SimpleTestCase

from subdomain_osint.services.ct_client import fetch_ct_hosts


class CtClientTests(SimpleTestCase):
    def test_parses_json_response(self):
        payload = json.dumps(
            [{"name_value": "www.example.com\napi.example.com"}]
        ).encode()

        with patch(
            "subdomain_osint.services.ct_client._fetch_url", return_value=payload
        ):
            hosts, warning = fetch_ct_hosts("example.com", max_hosts=50)

        self.assertIsNone(warning)
        self.assertIn("www.example.com", hosts)
        self.assertIn("api.example.com", hosts)
