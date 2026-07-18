from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from subdomain_osint.services.http_prober import HttpProber


class HttpProberTests(SimpleTestCase):
    def _mock_response(self, status_code, body=b"", headers=None):
        resp = Mock()
        resp.status_code = status_code
        resp.headers = headers or {}
        resp.iter_content.return_value = iter([body])
        resp.close = Mock()
        return resp

    @patch("subdomain_osint.services.http_prober.requests.get")
    def test_live_host_extracts_title_and_server(self, mock_get):
        mock_get.return_value = self._mock_response(
            200, body=b"<html><head><title>Example Dashboard</title></head></html>",
            headers={"Server": "nginx"},
        )
        results = HttpProber().probe_all(["app.example.com"])
        result = results["app.example.com"]
        self.assertTrue(result.live)
        self.assertEqual(result.title, "Example Dashboard")
        self.assertEqual(result.server, "nginx")

    @patch("subdomain_osint.services.http_prober.requests.get")
    def test_dead_host_reported_as_not_live_not_crash(self, mock_get):
        import requests
        mock_get.side_effect = requests.ConnectionError()
        results = HttpProber().probe_all(["dead.example.com"])
        self.assertFalse(results["dead.example.com"].live)

    def test_empty_host_list_returns_empty_dict(self):
        self.assertEqual(HttpProber().probe_all([]), {})

    def test_respects_max_hosts_cap(self):
        prober = HttpProber(max_hosts=2)
        with patch("subdomain_osint.services.http_prober.requests.get") as mock_get:
            import requests
            mock_get.side_effect = requests.ConnectionError()
            results = prober.probe_all(["a.com", "b.com", "c.com", "d.com"])
        self.assertEqual(len(results), 2)
