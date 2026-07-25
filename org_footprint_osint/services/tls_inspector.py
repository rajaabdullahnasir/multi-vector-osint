"""
TLS/SSL certificate inspection - connects to the domain's HTTPS port and
reads the certificate chain. No external service, no key.

Uses CERT_NONE deliberately (not CERT_OPTIONAL) - detecting a self-signed
or otherwise untrusted certificate IS the point of this check, and
CERT_OPTIONAL still enforces chain validation and raises when a
presented cert fails it, which defeats that purpose. Live testing
confirmed this: CERT_OPTIONAL raised CERTIFICATE_VERIFY_FAILED instead
of letting us inspect the offending certificate. With CERT_NONE, Python's
ssl module returns an empty dict from getpeercert() regardless of
validity, so the raw DER bytes are parsed directly via the `cryptography`
library instead.

Checks: expiry (and days remaining), self-signed detection, negotiated
TLS protocol version, cipher, and the SAN (Subject Alternative Name) list.
"""

from __future__ import annotations

import datetime
import socket
import ssl
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

_TIMEOUT = 6.0


@dataclass
class CertificateResult:
    success: bool
    subject_cn: str = ""
    issuer_cn: str = ""
    san_list: list[str] = field(default_factory=list)
    not_before: str = ""
    not_after: str = ""
    days_until_expiry: int | None = None
    is_expired: bool = False
    is_self_signed: bool = False
    tls_version: str = ""
    cipher: str = ""
    error: str | None = None


def _common_name(name: x509.Name) -> str:
    try:
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else ""
    except Exception:
        return ""


class CertificateInspector:
    def __init__(self, timeout: float = _TIMEOUT):
        self.timeout = timeout

    def inspect(self, host: str, port: int = 443) -> CertificateResult:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        # Deliberately unverified — we want to inspect self-signed and
        # expired certs too, not just fail on them. See module docstring.
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    der_cert = tls_sock.getpeercert(binary_form=True)
                    tls_version = tls_sock.version() or ""
                    cipher_info = tls_sock.cipher()
                    cipher = cipher_info[0] if cipher_info else ""
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
            return CertificateResult(success=False, error=f"Could not connect: {exc}")
        except ssl.SSLError as exc:
            return CertificateResult(success=False, error=f"TLS handshake failed: {exc}")

        if not der_cert:
            return CertificateResult(
                success=False, error="Connected, but no certificate was presented."
            )

        try:
            cert = x509.load_der_x509_certificate(der_cert, default_backend())
        except Exception as exc:
            return CertificateResult(success=False, error=f"Could not parse certificate: {exc}")

        subject_cn = _common_name(cert.subject)
        issuer_cn = _common_name(cert.issuer)

        san_list: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_list = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass

        try:
            not_before_dt = cert.not_valid_before_utc
            not_after_dt = cert.not_valid_after_utc
        except AttributeError:
            # Older cryptography versions: naive datetimes, assume UTC.
            not_before_dt = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
            not_after_dt = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

        delta = not_after_dt - datetime.datetime.now(datetime.timezone.utc)
        days_remaining = delta.days
        is_expired = delta.total_seconds() < 0
        is_self_signed = bool(subject_cn) and subject_cn == issuer_cn

        return CertificateResult(
            success=True,
            subject_cn=subject_cn,
            issuer_cn=issuer_cn,
            san_list=san_list,
            not_before=not_before_dt.strftime("%Y-%m-%d %H:%M UTC"),
            not_after=not_after_dt.strftime("%Y-%m-%d %H:%M UTC"),
            days_until_expiry=days_remaining,
            is_expired=is_expired,
            is_self_signed=is_self_signed,
            tls_version=tls_version,
            cipher=cipher,
        )
