from django.test import SimpleTestCase

from password_hasher_osint.services.analyzer import PasswordHasherAnalyzer
from password_hasher_osint.services.hash_engine import compare_hash, compute_hash


class HashEngineTests(SimpleTestCase):
    def test_sha1_known_vector(self):
        # "password" SHA-1
        digest = compute_hash("sha1", "password").digest
        self.assertEqual(digest, "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")

    def test_compare_match(self):
        result = compare_hash(
            "sha1",
            "password",
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
        )
        self.assertTrue(result.matched)

    def test_base64_roundtrip_via_decode(self):
        encoded = compute_hash("base64_encode", "hello").digest
        decoded = compute_hash("base64_decode", encoded).digest
        self.assertEqual(decoded, "hello")


class AnalyzerTests(SimpleTestCase):
    def test_generate_multiple(self):
        report = PasswordHasherAnalyzer().generate_hashes(
            "test",
            ["md5", "sha256"],
        )
        self.assertTrue(report.success)
        self.assertEqual(len(report.hashes), 2)

    def test_compare_no_match(self):
        report = PasswordHasherAnalyzer().compare(
            "wrong",
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
            "sha1",
        )
        self.assertTrue(report.success)
        self.assertFalse(report.matched)
