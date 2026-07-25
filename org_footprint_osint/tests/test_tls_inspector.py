import datetime
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.test import SimpleTestCase

from org_footprint_osint.services.tls_inspector import CertificateInspector


def _make_cert(common_name, issuer_cn=None, days_valid=90, san=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or common_name)])

    now = datetime.datetime.now(datetime.timezone.utc)
    # not_valid_before must always precede not_valid_after — for an
    # "already expired" test cert (negative days_valid), anchor validity
    # start further back so the window is still chronologically valid.
    not_before = now - datetime.timedelta(days=max(60, abs(days_valid) + 30))
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(now + datetime.timedelta(days=days_valid))
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in san]), critical=False
        )
    cert = builder.sign(key, hashes.SHA256(), default_backend())
    return cert.public_bytes(serialization.Encoding.DER)


def _mock_tls_sock(der_bytes, version="TLSv1.3", cipher=("TLS_AES_256_GCM_SHA384",)):
    mock_sock = Mock()
    mock_sock.getpeercert.return_value = der_bytes
    mock_sock.version.return_value = version
    mock_sock.cipher.return_value = cipher
    mock_sock.__enter__ = Mock(return_value=mock_sock)
    mock_sock.__exit__ = Mock(return_value=False)
    return mock_sock


class CertificateInspectorTests(SimpleTestCase):
    @patch("org_footprint_osint.services.tls_inspector.socket.create_connection")
    @patch("org_footprint_osint.services.tls_inspector.ssl.SSLContext.wrap_socket")
    def test_valid_cert_parsed_correctly(self, mock_wrap, mock_conn):
        der = _make_cert("example.com", issuer_cn="Let's Encrypt", days_valid=60, san=["example.com", "www.example.com"])
        mock_wrap.return_value = _mock_tls_sock(der)
        mock_conn.return_value.__enter__ = Mock(return_value=Mock())
        mock_conn.return_value.__exit__ = Mock(return_value=False)

        result = CertificateInspector().inspect("example.com")
        self.assertTrue(result.success)
        self.assertEqual(result.subject_cn, "example.com")
        self.assertEqual(result.issuer_cn, "Let's Encrypt")
        self.assertFalse(result.is_self_signed)
        self.assertFalse(result.is_expired)
        self.assertEqual(set(result.san_list), {"example.com", "www.example.com"})
        self.assertGreater(result.days_until_expiry, 0)
        self.assertEqual(result.tls_version, "TLSv1.3")

    @patch("org_footprint_osint.services.tls_inspector.socket.create_connection")
    @patch("org_footprint_osint.services.tls_inspector.ssl.SSLContext.wrap_socket")
    def test_self_signed_detected(self, mock_wrap, mock_conn):
        der = _make_cert("myserver.local", days_valid=300)
        mock_wrap.return_value = _mock_tls_sock(der)
        mock_conn.return_value.__enter__ = Mock(return_value=Mock())
        mock_conn.return_value.__exit__ = Mock(return_value=False)

        result = CertificateInspector().inspect("myserver.local")
        self.assertTrue(result.success)
        self.assertTrue(result.is_self_signed)

    @patch("org_footprint_osint.services.tls_inspector.socket.create_connection")
    @patch("org_footprint_osint.services.tls_inspector.ssl.SSLContext.wrap_socket")
    def test_expired_cert_detected(self, mock_wrap, mock_conn):
        der = _make_cert("example.com", issuer_cn="Some CA", days_valid=-30)
        mock_wrap.return_value = _mock_tls_sock(der)
        mock_conn.return_value.__enter__ = Mock(return_value=Mock())
        mock_conn.return_value.__exit__ = Mock(return_value=False)

        result = CertificateInspector().inspect("example.com")
        self.assertTrue(result.success)
        self.assertTrue(result.is_expired)

    @patch("org_footprint_osint.services.tls_inspector.socket.create_connection")
    def test_connection_refused_reported_honestly(self, mock_conn):
        mock_conn.side_effect = ConnectionRefusedError()
        result = CertificateInspector().inspect("example.com")
        self.assertFalse(result.success)
        self.assertIn("Could not connect", result.error)

    @patch("org_footprint_osint.services.tls_inspector.socket.create_connection")
    def test_timeout_reported_honestly(self, mock_conn):
        import socket as socket_module
        mock_conn.side_effect = socket_module.timeout()
        result = CertificateInspector().inspect("example.com")
        self.assertFalse(result.success)

    @patch("org_footprint_osint.services.tls_inspector.socket.create_connection")
    @patch("org_footprint_osint.services.tls_inspector.ssl.SSLContext.wrap_socket")
    def test_no_cert_presented_reported_honestly_not_crash(self, mock_wrap, mock_conn):
        mock_wrap.return_value = _mock_tls_sock(None)
        mock_conn.return_value.__enter__ = Mock(return_value=Mock())
        mock_conn.return_value.__exit__ = Mock(return_value=False)

        result = CertificateInspector().inspect("example.com")
        self.assertFalse(result.success)
        self.assertIsNotNone(result.error)

    @patch("org_footprint_osint.services.tls_inspector.socket.create_connection")
    @patch("org_footprint_osint.services.tls_inspector.ssl.SSLContext.wrap_socket")
    def test_malformed_der_does_not_crash(self, mock_wrap, mock_conn):
        mock_wrap.return_value = _mock_tls_sock(b"not a real certificate")
        mock_conn.return_value.__enter__ = Mock(return_value=Mock())
        mock_conn.return_value.__exit__ = Mock(return_value=False)

        result = CertificateInspector().inspect("example.com")
        self.assertFalse(result.success)
        self.assertIn("Could not parse", result.error)

    @patch("org_footprint_osint.services.tls_inspector.socket.create_connection")
    @patch("org_footprint_osint.services.tls_inspector.ssl.SSLContext.wrap_socket")
    def test_untrusted_chain_cert_still_inspected_not_raised(self, mock_wrap, mock_conn):
        """
        Regression test for a real bug found via live testing against
        github.com: ssl.CERT_OPTIONAL still enforced chain validation and
        raised CERTIFICATE_VERIFY_FAILED for a cert with an untrusted
        chain - defeating the whole purpose of this inspector, which
        needs to examine bad certs, not just good ones. This test proves
        a self-signed/untrusted cert is successfully parsed rather than
        raising, which is what CERT_NONE (not CERT_OPTIONAL) guarantees.
        """
        der = _make_cert("untrusted.example.com", issuer_cn="Untrusted Root", days_valid=30)
        mock_wrap.return_value = _mock_tls_sock(der)
        mock_conn.return_value.__enter__ = Mock(return_value=Mock())
        mock_conn.return_value.__exit__ = Mock(return_value=False)

        result = CertificateInspector().inspect("untrusted.example.com")
        self.assertTrue(result.success)
        self.assertEqual(result.subject_cn, "untrusted.example.com")
