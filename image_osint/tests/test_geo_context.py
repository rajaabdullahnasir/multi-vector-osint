from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from image_osint.services.geo_context import GeoContextClient, _haversine_m


class HaversineTests(SimpleTestCase):
    def test_same_point_is_zero_distance(self):
        self.assertEqual(round(_haversine_m(24.86, 67.01, 24.86, 67.01)), 0)

    def test_known_distance_roughly_correct(self):
        # ~0.001 degree latitude is roughly 111 meters.
        dist = _haversine_m(24.860, 67.010, 24.861, 67.010)
        self.assertTrue(100 < dist < 125)


class ReverseGeocodeTests(SimpleTestCase):
    def _mock_response(self, status_code, json_body=None):
        resp = Mock()
        resp.status_code = status_code
        resp.json.return_value = json_body or {}
        return resp

    @patch("image_osint.services.geo_context.requests.get")
    @patch("image_osint.services.geo_context.requests.post")
    def test_successful_reverse_geocode(self, mock_post, mock_get):
        mock_get.return_value = self._mock_response(
            200, {"display_name": "Blue Area, Islamabad, Pakistan"}
        )
        mock_post.return_value = self._mock_response(200, {"elements": []})

        result = GeoContextClient(timeout=1).build(33.7, 73.05)
        self.assertEqual(result.address, "Blue Area, Islamabad, Pakistan")
        self.assertIsNone(result.address_error)

    @patch("image_osint.services.geo_context.requests.get")
    @patch("image_osint.services.geo_context.requests.post")
    def test_reverse_geocode_failure_does_not_block_landmarks(self, mock_post, mock_get):
        import requests
        mock_get.side_effect = requests.ConnectionError()
        mock_post.return_value = self._mock_response(
            200,
            {"elements": [{"lat": 33.7001, "lon": 73.0501, "tags": {"name": "Test Mosque", "amenity": "place_of_worship"}}]},
        )

        result = GeoContextClient(timeout=1).build(33.7, 73.05)
        self.assertEqual(result.address, "")
        self.assertIsNotNone(result.address_error)
        # Landmarks still succeed independently.
        self.assertEqual(len(result.landmarks), 1)
        self.assertEqual(result.landmarks[0].name, "Test Mosque")

    @patch("image_osint.services.geo_context.requests.get")
    def test_nominatim_non_200_reported_honestly(self, mock_get):
        mock_get.return_value = self._mock_response(503)
        client = GeoContextClient(timeout=1)
        address, error = client._reverse_geocode(33.7, 73.05)
        self.assertEqual(address, "")
        self.assertIn("503", error)


class NearbyLandmarksTests(SimpleTestCase):
    def _mock_response(self, status_code, json_body=None):
        resp = Mock()
        resp.status_code = status_code
        resp.json.return_value = json_body or {}
        return resp

    @patch("image_osint.services.geo_context.requests.post")
    def test_extracts_named_elements_only(self, mock_post):
        mock_post.return_value = self._mock_response(
            200,
            {
                "elements": [
                    {"lat": 33.7001, "lon": 73.0501, "tags": {"name": "Named Shop", "shop": "convenience"}},
                    {"lat": 33.7002, "lon": 73.0502, "tags": {}},  # no name — must be skipped
                    {"center": {"lat": 33.7003, "lon": 73.0503}, "tags": {"name": "Named Building", "building": "yes"}},
                ]
            },
        )
        client = GeoContextClient(timeout=1)
        landmarks, total, error = client._nearby_landmarks(33.7, 73.05)
        names = {l.name for l in landmarks}
        self.assertEqual(names, {"Named Shop", "Named Building"})
        self.assertEqual(total, 2)
        self.assertIsNone(error)

    @patch("image_osint.services.geo_context.requests.post")
    def test_sorted_by_distance_ascending(self, mock_post):
        mock_post.return_value = self._mock_response(
            200,
            {
                "elements": [
                    {"lat": 33.71, "lon": 73.06, "tags": {"name": "Far away"}},
                    {"lat": 33.7001, "lon": 73.0501, "tags": {"name": "Very close"}},
                ]
            },
        )
        client = GeoContextClient(timeout=1)
        landmarks, _, _ = client._nearby_landmarks(33.7, 73.05)
        self.assertEqual(landmarks[0].name, "Very close")

    @patch("image_osint.services.geo_context.requests.post")
    def test_rate_limit_reported_honestly(self, mock_post):
        mock_post.return_value = self._mock_response(429)
        client = GeoContextClient(timeout=1)
        landmarks, total, error = client._nearby_landmarks(33.7, 73.05)
        self.assertEqual(landmarks, [])
        self.assertIn("rate limit", error.lower())

    @patch("image_osint.services.geo_context.requests.post")
    def test_network_error_reported_honestly(self, mock_post):
        import requests
        mock_post.side_effect = requests.ConnectionError()
        client = GeoContextClient(timeout=1)
        landmarks, total, error = client._nearby_landmarks(33.7, 73.05)
        self.assertEqual(landmarks, [])
        self.assertIsNotNone(error)

    def test_overpass_turbo_url_contains_coordinates(self):
        client = GeoContextClient(timeout=1)
        url = client._overpass_turbo_url(33.7, 73.05)
        self.assertIn("overpass-turbo.eu", url)
        self.assertIn("33.7;73.05", url)


class BuildResultTests(SimpleTestCase):
    def _mock_response(self, status_code, json_body=None):
        resp = Mock()
        resp.status_code = status_code
        resp.json.return_value = json_body or {}
        return resp

    @patch("image_osint.services.geo_context.requests.get")
    @patch("image_osint.services.geo_context.requests.post")
    def test_build_always_returns_osm_and_overpass_turbo_links(self, mock_post, mock_get):
        mock_get.return_value = self._mock_response(200, {"display_name": "Somewhere"})
        mock_post.return_value = self._mock_response(200, {"elements": []})

        result = GeoContextClient(timeout=1).build(33.7, 73.05)
        self.assertIn("openstreetmap.org", result.osm_url)
        self.assertIn("overpass-turbo.eu", result.overpass_turbo_url)
