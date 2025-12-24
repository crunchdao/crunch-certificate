
from typing import Optional, cast, get_args, overload

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from crunch_certificate.private_key import PrivateKey


@overload
def dumps(
    *,
    private_key: PrivateKey,
) -> str:
    ...


@overload
def dumps(
    *,
    certificate: x509.Certificate,
) -> str:
    ...


def dumps(
    *,
    private_key: Optional[PrivateKey] = None,
    certificate: Optional[x509.Certificate] = None,
) -> str:
    if private_key is not None:
        return (
            private_key
            .private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            .decode()
        )

    elif certificate is not None:
        return (
            certificate
            .public_bytes(serialization.Encoding.PEM)
            .decode()
        )

    else:
        raise TypeError("nothing to stringify")


def loads_certificate(
    pem_string: str,
) -> x509.Certificate:
    return x509.load_pem_x509_certificate(
        pem_string.encode(),
    )


def loads_private_key(
    pem_string: str,
) -> PrivateKey:
    private_key = serialization.load_pem_private_key(
        pem_string.encode(),
        password=None,
    )

    if not isinstance(private_key, get_args(PrivateKey)):
        raise ValueError(f"unsupported key: {type(private_key)}")

    return cast(PrivateKey, private_key)
