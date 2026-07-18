from django.test import SimpleTestCase

from username_osint.services.platforms import PLATFORMS


class ExpandedPlatformListTests(SimpleTestCase):
    def test_substantially_more_than_original_21(self):
        self.assertGreater(len(PLATFORMS), 60)

    def test_no_duplicate_names(self):
        names = [p.name for p in PLATFORMS]
        self.assertEqual(len(names), len(set(names)))

    def test_no_duplicate_url_templates(self):
        templates = [p.url_template for p in PLATFORMS]
        self.assertEqual(len(templates), len(set(templates)))

    def test_all_templates_contain_username_placeholder(self):
        for platform in PLATFORMS:
            with self.subTest(platform=platform.name):
                self.assertIn("{username}", platform.url_template)

    def test_no_financial_apps_included(self):
        names_lower = {p.name.lower() for p in PLATFORMS}
        for financial in ("venmo", "cash app", "cashapp", "paypal.me"):
            self.assertNotIn(financial, names_lower)

    def test_bot_blocking_platforms_have_not_found_phrases(self):
        tricky = {"Instagram", "X / Twitter", "Facebook", "TikTok"}
        for platform in PLATFORMS:
            if platform.name in tricky:
                with self.subTest(platform=platform.name):
                    self.assertTrue(platform.not_found_phrases)
