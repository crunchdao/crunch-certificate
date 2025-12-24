from datetime import datetime, timedelta, timezone
from typing import List, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from crunch_certificate.private_key import PrivateKey
from crunch_certificate.private_key import generate as generate_private_key

__all__ = [
    "generate_ca",
    "generate_tls",
    "DEFAULT_DAYS_VALID",
]

DEFAULT_DAYS_VALID = 99 * 365


def generate_ca(
    *,
    common_name: str,
    organization_name: str,
    days_valid: int = DEFAULT_DAYS_VALID,
) -> Tuple[
    PrivateKey,
    x509.Certificate,
]:
    ca_key = generate_private_key(
        type="rsa",
    )

    # Build subject/issuer name (self-signed CA)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
    ])

    now = datetime.now(timezone.utc)

    # Build self-signed CA certificate
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )

    # SubjectKeyIdentifier & AuthorityKeyIdentifier
    ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    builder = builder.add_extension(ski, critical=False)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier(
            key_identifier=ski.digest,
            authority_cert_issuer=None,
            authority_cert_serial_number=None,
        ),
        critical=False,
    )

    ca_cert = builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
    )

    return (
        ca_key,
        ca_cert,
    )


def generate_tls(
    *,
    ca_key: PrivateKey,
    ca_cert: x509.Certificate,
    common_name: str,
    is_client: bool = True,
    is_server: bool = False,
    days_valid: int = DEFAULT_DAYS_VALID,
) -> Tuple[
    PrivateKey,
    x509.Certificate,
]:
    tls_priv = generate_private_key(type="rsa")
    tls_pub = tls_priv.public_key()

    # Subject for this cert
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    issuer = ca_cert.subject

    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(tls_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
    )

    # Extended key usages for TLS client / server
    eku_usages: List[ObjectIdentifier] = []
    if is_client:
        eku_usages.append(ExtendedKeyUsageOID.CLIENT_AUTH)
    if is_server:
        eku_usages.append(ExtendedKeyUsageOID.SERVER_AUTH)

    if eku_usages:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(eku_usages),
            critical=False,
        )

    # Sign with private key
    tls_cert = builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
    )

    return (
        tls_priv,
        tls_cert,
    )
