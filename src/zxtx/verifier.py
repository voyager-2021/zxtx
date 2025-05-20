from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509 import load_pem_x509_certificate


def verify_signature(cert_bytes: bytes, data: bytes, signature: bytes) -> bool:
    cert = load_pem_x509_certificate(cert_bytes)
    public_key = cert.public_key()

    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, data)
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        else:
            return False
        return True
    except Exception:
        return False
