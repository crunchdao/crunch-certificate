from typing import Literal, Union, overload

from cryptography.hazmat.primitives.asymmetric import ec, rsa

__all__ = [
    "DEFAULT_RSA_KEY_SIZE",
    "PrivateKeyType",
    "PrivateKey",
    "generate",
]

DEFAULT_RSA_KEY_SIZE = 2048

PrivateKeyType = Literal["rsa", "ecdsa"]
PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]


@overload
def generate(
    *,
    type: Literal["rsa"],
    key_size: int = 2048,
) -> rsa.RSAPrivateKey:
    ...


@overload
def generate(
    *,
    type: Literal["ecdsa"],
) -> ec.EllipticCurvePrivateKey:
    ...


def generate(
    *,
    type: PrivateKeyType,
    key_size: int = DEFAULT_RSA_KEY_SIZE,
):
    if type == "rsa":
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

    elif type == "ecdsa":
        return ec.generate_private_key(
            curve=ec.SECP256R1(),
        )

    else:
        raise ValueError(f"unknown type: {type}")
