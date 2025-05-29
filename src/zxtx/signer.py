import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)


def sign_data(private_key, data: bytes) -> bytes:
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    elif isinstance(private_key, ed25519.Ed25519PrivateKey):
        signature = private_key.sign(data)
    elif isinstance(private_key, rsa.RSAPrivateKey):
        return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    elif private_key is None:
        return b""
    else:
        raise TypeError("Unsupported private key type", private_key)
    return signature


def load_private_key(pem_bytes: bytes, password=None):
    try:
        return load_pem_private_key(pem_bytes, password=password)
    except ValueError as error:
        (
            error.add_note(
                "Note: The private key may be encrypted or a invalid password was provided."
            )
            if sys.version_info >= (3, 11)
            else ...
        )

        raise error


def load_public_key(pem_bytes: bytes):
    return load_pem_public_key(pem_bytes)
