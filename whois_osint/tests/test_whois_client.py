"""
Regression coverage for a real bug: _query_server used to stop reading the
instant a single recv() call returned less than the 4096-byte buffer size.
TCP does not guarantee a response arrives in one recv() worth of bytes, so
this silently truncated real WHOIS responses (observed live against
omnitelltech.com's GoDaddy referral, which cut off mid-sentence).
"""

from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase

from whois_osint.services.whois_client import WhoisClient


class _FakeSocket:
    """Simulates a real TCP socket delivering a response across several
    small packets, mimicking real-world WHOIS server behavior where the
    OS can hand back far less than 4096 bytes per recv() even though more
    data is still in flight."""

    def __init__(self, chunks: list[bytes]):
        self._chunks = list(chunks)
        self.sent = b""

    def sendall(self, payload: bytes) -> None:
        self.sent += payload

    def recv(self, bufsize: int) -> bytes:
        if not self._chunks:
            return b""  # connection closed by peer
        return self._chunks.pop(0)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class QueryServerTruncationRegressionTests(SimpleTestCase):
    def _client_with_response(self, chunks: list[bytes]) -> WhoisClient:
        client = WhoisClient(timeout=5)
        fake_socket = _FakeSocket(chunks)
        patcher = patch(
            "whois_osint.services.whois_client.socket.create_connection",
            return_value=fake_socket,
        )
        self.addCleanup(patcher.stop)
        patcher.start()
        return client

    def test_reads_full_response_across_many_small_packets(self):
        # Every chunk here is deliberately far under 4096 bytes — the old
        # code would have stopped after the very first one.
        chunks = [b"Domain Name: EXAMPLE.COM\n"] * 20 + [b"Registrar: Example Inc.\n"]
        expected = b"".join(chunks).decode("utf-8")
        client = self._client_with_response(chunks)

        result = client._query_server("whois.example-test.com", "example.com")

        self.assertEqual(result, expected)
        # Specifically: the response must NOT be cut off after chunk 1.
        self.assertIn("Registrar: Example Inc.", result)

    def test_stops_on_connection_close_not_short_packet(self):
        # A single short packet followed by connection close (empty recv)
        # must still be read as "response complete", and nothing after the
        # close should be invented or lost.
        chunks = [b"short packet under 4096 bytes"]
        client = self._client_with_response(chunks)

        result = client._query_server("whois.example-test.com", "example.com")

        self.assertEqual(result, "short packet under 4096 bytes")

    def test_respects_max_response_bytes_safety_cap(self):
        with self.settings(WHOIS_MAX_RESPONSE_BYTES=10):
            chunks = [b"0123456789", b"this-should-not-appear"]
            client = self._client_with_response(chunks)
            result = client._query_server("whois.example-test.com", "example.com")
            self.assertNotIn("this-should-not-appear", result)


class ReferralAssemblyTests(SimpleTestCase):
    def test_referral_response_is_appended_not_dropped(self):
        client = WhoisClient(timeout=5)

        primary_raw = "Registrar WHOIS Server: whois.godaddy.com\nDomain Name: EXAMPLE.COM\n"
        referral_raw = "Registrant Organization: Example Inc.\nRegistrant Country: US\n"

        call_count = {"n": 0}

        def fake_query_server(host, query):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return primary_raw
            return referral_raw

        with patch.object(client, "_query_server", side_effect=fake_query_server):
            with patch.object(
                client, "_resolve_whois_server", return_value="whois.verisign-grs.com"
            ):
                result = client.lookup("example.com")

        self.assertTrue(result.success)
        self.assertIn("Registrant Organization: Example Inc.", result.raw_text)
        self.assertIn("Domain Name: EXAMPLE.COM", result.raw_text)
        self.assertEqual(result.referral_server, "whois.godaddy.com")
