from abc import ABC, abstractmethod
from base64 import b64encode
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

import crunch_certificate.pem as pem
from crunch_certificate.pem import Certificate, PrivateKey, PublicKey
from crunch_certificate.private_key import generate as generate_private_key

__all__ = [
    "DEFAULT_DAYS_VALID",
    "generate_ca",
    "TlsCertificateIssuer",
    "LocalTlsCertificateIssuer",
    "RemoteTlsCertificateIssuer",
    "generate_tls",
    "get_public_key_as_string",
]

DEFAULT_DAYS_VALID = 99 * 365


def generate_ca(
    *,
    common_name: str,
    organization_name: str,
    days_valid: int = DEFAULT_DAYS_VALID,
) -> Tuple[
    PrivateKey,
    Certificate,
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


class TlsCertificateIssuer(ABC):

    @abstractmethod
    def sign(
        self,
        tls_pub: PublicKey,
        common_name: str,
        is_client: bool = True,
        is_server: bool = False,
        san_dns: Optional[str] = None,
        days_valid: int = DEFAULT_DAYS_VALID,
    ) -> Certificate:
        ...


class LocalTlsCertificateIssuer(TlsCertificateIssuer):

    def __init__(
        self,
        *,
        ca_key: PrivateKey,
        ca_cert: Certificate,
    ):
        self.ca_key = ca_key
        self.ca_cert = ca_cert

    def sign(
        self,
        tls_pub: PublicKey,
        common_name: str,
        is_client: bool = True,
        is_server: bool = False,
        san_dns: Optional[str] = None,
        days_valid: int = DEFAULT_DAYS_VALID,
    ) -> Certificate:
        # Subject for this cert
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        issuer = self.ca_cert.subject

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
            if not san_dns:
                raise ValueError("san_dns is required when is_server=True (gRPC validates SAN, not CN).")

            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(san_dns)]),
                critical=False,
            )
            eku_usages.append(ExtendedKeyUsageOID.SERVER_AUTH)

        if eku_usages:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage(eku_usages),
                critical=False,
            )

        # Sign with private key
        tls_cert = builder.sign(
            private_key=self.ca_key,
            algorithm=hashes.SHA256(),
        )

        return tls_cert


class RemoteTlsCertificateIssuer(TlsCertificateIssuer):

    def __init__(
        self,
        *,
        api_base_url: str,
    ):
        self.api_base_url = api_base_url

    def sign(
        self,
        tls_pub: PublicKey,
        common_name: str,
        is_client: bool = True,
        is_server: bool = False,
        san_dns: Optional[str] = None,
        days_valid: int = DEFAULT_DAYS_VALID,
    ) -> Certificate:
        print(self.api_base_url)
        raise NotImplementedError()


def generate_tls(
    *,
    certificate_issuer: TlsCertificateIssuer,
    common_name: str,
    san_dns: Optional[str] = None,
    is_client: bool = True,
    is_server: bool = False,
    days_valid: int = DEFAULT_DAYS_VALID,
) -> Tuple[
    PrivateKey,
    Certificate,
]:
    tls_priv = generate_private_key(type="rsa")
    tls_pub = tls_priv.public_key()

    tls_cert = certificate_issuer.sign(
        tls_pub=tls_pub,
        common_name=common_name,
        is_client=is_client,
        is_server=is_server,
        san_dns=san_dns,
        days_valid=days_valid,
    )

    return (
        tls_priv,
        tls_cert,
    )


def get_public_key_as_string(
    certificate: Certificate,
) -> str:
    bytes = certificate.public_key().public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

    return b64encode(bytes).decode("ascii")
