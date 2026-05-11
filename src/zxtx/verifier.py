from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509 import load_pem_x509_certificate


def verify_signature(
    trusted_cert_bytes: bytes | None,
    embedded_cert_bytes: bytes | None,
    header_bytes: bytes,
    encrypted_payload: bytes,
    signature: bytes,
) -> bool:
    """
    Verify signature using a trusted certificate.

    Args:
        trusted_cert_bytes: The trusted certificate to verify against (provided by caller)
        embedded_cert_bytes: The certificate embedded in the file (must match trusted_cert)
        header_bytes: The serialized header bytes
        encrypted_payload: The full encrypted data (session key + nonce + ciphertext + tag)
        signature: The signature to verify

    Returns:
        True if signature is valid and embedded cert matches trusted cert, False otherwise
    """
    # Validate certificates are present and match

    cert_valid = (
        trusted_cert_bytes is not None
        and len(trusted_cert_bytes) > 0
        and embedded_cert_bytes is not None
        and len(embedded_cert_bytes) > 0
        and trusted_cert_bytes == embedded_cert_bytes
    )

    if not cert_valid:
        return False

    try:
        cert = load_pem_x509_certificate(trusted_cert_bytes)
        public_key = cert.public_key()

    except Exception:
        return False

    data_to_verify = header_bytes + encrypted_payload
    valid = False

    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data_to_verify, ec.ECDSA(hashes.SHA256()))
            valid = True

        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, data_to_verify)
            valid = True

        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, data_to_verify, padding.PKCS1v15(), hashes.SHA256())
            valid = True

    except Exception:
        valid = False

    return valid
