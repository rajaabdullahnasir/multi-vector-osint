from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from username_osint.services.platform_checker import scan_username


def _mock_response(status_code, text=""):
    resp = Mock()
    resp.status_code = status_code
    resp.text = text
    return resp


class Soft200FilteringRegressionTests(SimpleTestCase):
    """
    Regression tests for a real bug found via live testing: a scan for
    'iseewaves.pk' returned 19 'found' hits across unrelated platforms
    (AniList, Crates.io, HackerRank, PyPI, Trello, Kik) - a strong signal
    several were false positives from SPA sites returning HTTP 200 for
    any profile URL regardless of whether the account exists.
    """

    @patch("username_osint.services.platform_checker.requests.get")
    def test_platform_returning_200_for_everything_is_downgraded_to_inconclusive(self, mock_get):
        # Every request, real username or random baseline, gets 200.
        mock_get.return_value = _mock_response(200, "<html>app shell</html>")
        result = scan_username("some_real_looking_username")

        # None of these should be trusted as real "found" hits since the
        # baseline (random nonexistent username) also returned 200.
        found_platforms = {h.platform for h in result.hits if h.found}
        self.assertEqual(found_platforms, set())

        inconclusive_platforms = {h.platform for h in result.hits if h.inconclusive}
        self.assertTrue(len(inconclusive_platforms) > 0)
        soft200_hit = next(h for h in result.hits if h.inconclusive)
        self.assertIn("soft-200", soft200_hit.inconclusive_reason)

    @patch("username_osint.services.platform_checker.requests.get")
    def test_platform_with_genuine_404_behavior_stays_found(self, mock_get):
        # Real username exists (200), random baseline genuinely 404s.
        def side_effect(url, **kwargs):
            if "some_real_looking_username" in url:
                return _mock_response(200, "<html>real profile</html>")
            return _mock_response(404, "not found")

        mock_get.side_effect = side_effect
        result = scan_username("some_real_looking_username")

        found_platforms = {h.platform for h in result.hits if h.found}
        self.assertTrue(len(found_platforms) > 0)
        # None of the genuinely-found platforms should be flagged inconclusive.
        for hit in result.hits:
            if hit.platform in found_platforms:
                self.assertFalse(hit.inconclusive)

    @patch("username_osint.services.platform_checker.requests.get")
    def test_no_found_hits_skips_baseline_check_entirely(self, mock_get):
        mock_get.return_value = _mock_response(404, "not found")
        result = scan_username("nonexistent")
        # Every request should be for the real username only - no baseline
        # round trip needed when nothing was "found" in the first place.
        for call in mock_get.call_args_list:
            self.assertIn("nonexistent", call.args[0] if call.args else call.kwargs.get("url", ""))
