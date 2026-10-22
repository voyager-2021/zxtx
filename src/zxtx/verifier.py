from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.x509 import load_pem_x509_certificate

__all__ = ["resolve_verification_key", "verify_signature"]


def resolve_verification_key(value):
    """
    Normalize a verification trust anchor.

    Accepts (and passes through) a ``cryptography`` public key object, or
    PEM-encoded bytes of either an X.509 certificate or a public key.
    Returns ``None`` when ``value`` is ``None``.

    Raises ``ValueError`` for bytes that are neither a valid PEM
    certificate nor a valid PEM public key.
    """
    if value is None:
        return None

    if isinstance(value, (bytes, bytearray, memoryview)):
        pem_bytes = bytes(value)
        try:
            cert = load_pem_x509_certificate(pem_bytes)
        except ValueError:
            cert = None

        if cert is not None:
            return cert.public_key()

        try:
            return load_pem_public_key(pem_bytes)
        except (ValueError, TypeError):
            raise ValueError(
                "verification key must be a cryptography public key object "
                "or PEM-encoded X.509 certificate / public key bytes"
            ) from None

    return value


def verify_signature(cert_or_key, data: bytes, signature: bytes) -> bool:
    """
    Verify ``signature`` over ``data`` with ``cert_or_key``.

    ``cert_or_key`` may be a public key object or PEM bytes of a
    certificate/public key (resolved via ``resolve_verification_key``).

    Returns ``False`` on any verification failure or unsupported key type;
    invalid/truncated inputs raise ``ValueError``.  The supported
    signature schemes mirror ``zxtx.signer.sign_data``:

    * RSA: PKCS#1 v1.5 with SHA-256
    * ECDSA: with SHA-256
    * Ed25519: pure
    """
    if not signature:
        return False

    try:
        key = resolve_verification_key(cert_or_key)
    except ValueError:
        raise
    if key is None:
        return False

    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, data)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        else:
            return False
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
