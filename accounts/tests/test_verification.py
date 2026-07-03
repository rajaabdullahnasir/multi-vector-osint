from django.test import SimpleTestCase

from accounts.verification import (
    generate_verification_token,
    is_token_format_valid,
    normalize_verification_token,
)


class VerificationTokenTests(SimpleTestCase):
    def test_hex_token_valid(self):
        token = generate_verification_token()
        self.assertEqual(len(token), 48)
        self.assertTrue(is_token_format_valid(token))

    def test_normalize_strips_trailing_punctuation(self):
        self.assertEqual(
            normalize_verification_token("Uzm7o80E2NYUtk3gDPKs-KxtEb4iNbkFCAhqj_8obN4."),
            "Uzm7o80E2NYUtk3gDPKs-KxtEb4iNbkFCAhqj_8obN4",
        )

    def test_legacy_urlsafe_still_valid(self):
        legacy = "Uzm7o80E2NYUtk3gDPKs-KxtEb4iNbkFCAhqj_8obN4"
        self.assertTrue(is_token_format_valid(legacy))
