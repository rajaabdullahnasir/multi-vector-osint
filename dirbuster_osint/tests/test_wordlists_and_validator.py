from django.test import SimpleTestCase

from dirbuster_osint.services.target_validator import TargetValidator
from dirbuster_osint.services.wordlists import (
    COMMON_WORDLIST, EXTENDED_WORDLIST, QUICK_WORDLIST, WORDLIST_TIERS,
)


class WordlistTests(SimpleTestCase):
    def test_no_duplicates_within_each_tier(self):
        for name, wordlist in WORDLIST_TIERS.items():
            with self.subTest(tier=name):
                self.assertEqual(len(wordlist), len(set(wordlist)))

    def test_tiers_are_strictly_increasing_supersets(self):
        self.assertTrue(set(QUICK_WORDLIST).issubset(set(COMMON_WORDLIST)))
        self.assertTrue(set(COMMON_WORDLIST).issubset(set(EXTENDED_WORDLIST)))
        self.assertGreater(len(COMMON_WORDLIST), len(QUICK_WORDLIST))
        self.assertGreater(len(EXTENDED_WORDLIST), len(COMMON_WORDLIST))

    def test_quick_contains_high_signal_admin_paths(self):
        self.assertIn("admin", QUICK_WORDLIST)
        self.assertIn(".env", QUICK_WORDLIST)
        self.assertIn(".git", QUICK_WORDLIST)


class TargetValidatorTests(SimpleTestCase):
    def test_accepts_bare_domain(self):
        result = TargetValidator().validate("example.com")
        self.assertTrue(result.ok)
        self.assertEqual(result.base_url, "https://example.com")

    def test_accepts_full_url_preserves_scheme(self):
        result = TargetValidator().validate("http://example.com")
        self.assertTrue(result.ok)
        self.assertEqual(result.base_url, "http://example.com")

    def test_rejects_localhost(self):
        self.assertFalse(TargetValidator().validate("localhost").ok)

    def test_rejects_private_ip(self):
        self.assertFalse(TargetValidator().validate("192.168.1.1").ok)

    def test_rejects_loopback_ip(self):
        self.assertFalse(TargetValidator().validate("http://127.0.0.1").ok)

    def test_accepts_public_ip(self):
        self.assertTrue(TargetValidator().validate("8.8.8.8").ok)

    def test_rejects_blank(self):
        self.assertFalse(TargetValidator().validate("").ok)
