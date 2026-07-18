from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from dirbuster_osint.services.dirbuster_engine import DirBusterEngine


def _mock_response(status_code, body=b"", headers=None):
    resp = Mock()
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.raw = Mock()
    resp.raw.read.return_value = body
    resp.close = Mock()
    return resp


class NormalSiteBehaviorTests(SimpleTestCase):
    @patch("dirbuster_osint.services.dirbuster_engine.requests.get")
    def test_real_404_site_no_soft_404_detected(self, mock_get):
        def side_effect(url, **kwargs):
            if "admin" in url:
                return _mock_response(200, b"<html>admin panel</html>")
            return _mock_response(404, b"Not Found")

        mock_get.side_effect = side_effect
        result = DirBusterEngine().scan("https://example.com", "example.com", ("admin", "xyz123"))
        self.assertFalse(result.baseline_detected)
        self.assertIn("admin", {e.path for e in result.found})


class SoftFourOhFourFilteringTests(SimpleTestCase):
    @patch("dirbuster_osint.services.dirbuster_engine.requests.get")
    def test_catchall_200_site_produces_zero_false_found(self, mock_get):
        mock_get.return_value = _mock_response(200, b"<html>App shell</html>")
        result = DirBusterEngine().scan(
            "https://spa-example.com", "spa-example.com", ("admin", "config", "backup")
        )
        self.assertTrue(result.baseline_detected)
        self.assertEqual(result.baseline_status, 200)
        self.assertEqual(len(result.found), 0)
        self.assertEqual(len(result.soft_404_filtered), 3)

    @patch("dirbuster_osint.services.dirbuster_engine.requests.get")
    def test_genuine_hit_still_surfaces_despite_soft_404_baseline(self, mock_get):
        catchall_body = b"x" * 500

        def side_effect(url, **kwargs):
            if "real-admin-panel" in url:
                return _mock_response(200, b"<html>Real Admin Login</html>" + b"y" * 2000)
            return _mock_response(200, catchall_body)

        mock_get.side_effect = side_effect
        result = DirBusterEngine().scan(
            "https://spa-example.com", "spa-example.com",
            ("real-admin-panel", "nonexistent1", "nonexistent2"),
        )
        self.assertTrue(result.baseline_detected)
        self.assertIn("real-admin-panel", {e.path for e in result.found})
        self.assertIn("nonexistent1", {e.path for e in result.soft_404_filtered})

    @patch("dirbuster_osint.services.dirbuster_engine.requests.get")
    def test_soft_404_with_redirect_status_also_detected(self, mock_get):
        mock_get.return_value = _mock_response(302, b"", headers={"Location": "/home"})
        result = DirBusterEngine().scan(
            "https://redirect-example.com", "redirect-example.com", ("admin", "config")
        )
        self.assertTrue(result.baseline_detected)
        self.assertEqual(result.baseline_status, 302)
        self.assertEqual(len(result.soft_404_filtered), 2)


class ErrorHandlingTests(SimpleTestCase):
    def test_network_error_reported_as_error_not_not_found(self):
        import requests
        with patch("dirbuster_osint.services.dirbuster_engine.requests.get") as mock_get:
            mock_get.side_effect = requests.ConnectionError()
            result = DirBusterEngine().scan("https://down-example.com", "down-example.com", ("admin",))
        self.assertEqual(result.entries[0].category, "error")

    def test_all_baseline_probes_failing_disables_filtering_gracefully(self):
        import requests
        with patch("dirbuster_osint.services.dirbuster_engine.requests.get") as mock_get:
            mock_get.side_effect = requests.ConnectionError()
            result = DirBusterEngine().scan("https://down-example.com", "down-example.com", ("admin",))
        self.assertFalse(result.baseline_detected)


class CategoryClassificationTests(SimpleTestCase):
    @patch("dirbuster_osint.services.dirbuster_engine.requests.get")
    def test_403_classified_as_forbidden_not_found(self, mock_get):
        def side_effect(url, **kwargs):
            if "secret" in url:
                return _mock_response(403, b"Forbidden")
            return _mock_response(404, b"")
        mock_get.side_effect = side_effect
        result = DirBusterEngine().scan("https://example.com", "example.com", ("secret", "xyz"))
        self.assertEqual(len(result.forbidden), 1)

    def test_checked_count_matches_wordlist_size(self):
        with patch("dirbuster_osint.services.dirbuster_engine.requests.get") as mock_get:
            mock_get.return_value = _mock_response(404, b"")
            result = DirBusterEngine().scan("https://example.com", "example.com", ("a", "b", "c", "d"))
        self.assertEqual(result.checked_count, 4)


class RiskFlagHonestyTests(SimpleTestCase):
    @patch("dirbuster_osint.services.dirbuster_engine.requests.get")
    def test_interesting_path_hit_does_not_overclaim_confirmed_exposure(self, mock_get):
        from dirbuster_osint.services.analyzer import DirBusterAnalyzer

        def side_effect(url, **kwargs):
            if "admin" in url:
                return Mock(status_code=200, headers={}, raw=Mock(read=lambda *a, **k: b"x" * 500), close=Mock())
            return Mock(status_code=404, headers={}, raw=Mock(read=lambda *a, **k: b""), close=Mock())

        mock_get.side_effect = side_effect
        report = DirBusterAnalyzer().analyze("example.com", "quick")
        joined = " ".join(report.risk_flags)
        self.assertNotIn("review immediately", joined)
        self.assertIn("does not confirm", joined)
