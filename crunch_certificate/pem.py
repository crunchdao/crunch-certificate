
from typing import Optional, Union, cast, get_args, overload

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]
PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]
Certificate = x509.Certificate


@overload
def dumps(
    *,
    private_key: PrivateKey,
) -> str:
    ...


@overload
def dumps(
    *,
    public_key: PublicKey,
) -> str:
    ...


@overload
def dumps(
    *,
    certificate: Certificate,
) -> str:
    ...


def dumps(
    *,
    private_key: Optional[PrivateKey] = None,
    public_key: Optional[PublicKey] = None,
    certificate: Optional[Certificate] = None,
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

    if public_key is not None:
        return (
            public_key
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.PKCS1,
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
) -> Certificate:
    return x509.load_pem_x509_certificate(
        pem_string.encode(),
    )


def loads_public_key(
    pem_string: str,
) -> PublicKey:
    public_key = serialization.load_pem_public_key(
        pem_string.encode(),
    )

    if not isinstance(public_key, get_args(PublicKey)):
        raise ValueError(f"unsupported key: {type(public_key)}")

    return cast(PublicKey, public_key)


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
