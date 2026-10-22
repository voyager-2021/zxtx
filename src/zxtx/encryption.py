import os

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from zxtx.constants import RSA_OAEP_SHA256_OVERHEAD

_HKDF_INFO_CTR_HMAC = b"zxtx-ctr-hmac-v1.1"


def encrypt_key_rsa(public_key, session_key: bytes) -> bytes:
    """
    Wrap (encrypt) a symmetric session key with the recipient's RSA public
    key using RSA-OAEP-SHA256.

    Raises a descriptive ``ValueError`` if the session key does not fit
    under the modulus (OAEP-SHA256 capacity is ``k - 66`` bytes for a
    modulus of ``k`` bytes), instead of the generic padding error.
    """
    key_bytes = public_key.key_size // 8
    capacity = key_bytes - RSA_OAEP_SHA256_OVERHEAD

    if len(session_key) > capacity:
        raise ValueError(
            f"Cannot wrap a {len(session_key)}-byte session key under "
            f"RSA-{public_key.key_size} with OAEP-SHA256 (capacity is "
            f"{capacity} bytes). Use an RSA key of at least "
            f"{(len(session_key) + RSA_OAEP_SHA256_OVERHEAD) * 8} bits; "
            f"2048 bits or more is recommended."
        )

    return public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def derive_ctr_hmac_keys(session_key: bytes, nonce: bytes) -> tuple[bytes, bytes]:
    """
    Derive the AES-CTR encryption key and the HMAC-SHA256 MAC key from a
    32-byte master session key (v1.1 layout).

    The 16-byte CTR nonce is used as the HKDF salt so the derivation is
    file-specific.  Returns ``(enc_key, mac_key)``.
    """
    if len(session_key) != 32:
        raise ValueError("Master session key must be 32 bytes for v1.1 CTR+HMAC")
    if len(nonce) != 16:
        raise ValueError("CTR nonce must be 16 bytes")

    material = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=nonce,
        info=_HKDF_INFO_CTR_HMAC,
    ).derive(session_key)

    return material[:32], material[32:]


def encrypt_data_aes_gcm(
    data: bytes, key: bytes, aad: bytes | None = None
) -> tuple[bytes, bytes]:
    """
    AES-256-GCM encryption.

    Returns ``(ciphertext, nonce)``.  For format version >= 1.1 the header
    identity digest is passed as ``aad`` so the ciphertext is bound to the
    header it belongs to.
    """
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte (256-bit) key")

    nonce = os.urandom(12)
    encrypted = AESGCM(key).encrypt(nonce, data, aad)
    return encrypted, nonce


def encrypt_data_chacha20(
    data: bytes, key: bytes, aad: bytes | None = None
) -> tuple[bytes, bytes]:
    """
    ChaCha20-Poly1305 encryption.

    Returns ``(ciphertext, nonce)``.  For format version >= 1.1 the header
    identity digest is passed as ``aad`` so the ciphertext is bound to the
    header it belongs to.
    """
    if len(key) != 32:
        raise ValueError("ChaCha20-Poly1305 requires a 32-byte (256-bit) key")

    nonce = os.urandom(12)
    encrypted = ChaCha20Poly1305(key).encrypt(nonce, data, aad)
    return encrypted, nonce


def encrypt_data_aes256_ctr_hmac(
    data: bytes, key: bytes, aad: bytes | None = None
) -> tuple[bytes, bytes, bytes]:
    """
    AES-256-CTR encryption with an encrypt-then-MAC HMAC-SHA256 tag
    (v1.1 layout).  The 32-byte *master* session key is split into an
    AES-CTR key and an HMAC key via HKDF-SHA256 (salted with the nonce).

    Returns ``(nonce, ciphertext, tag)``.  The MAC input is
    ``aad || nonce || ciphertext``, binding the body to the header.

    Note: 64-byte legacy (v1.0) keys are only used by the *read* path; the
    writer always produces the 32-byte v1.1 layout.
    """
    if len(key) != 32:
        raise ValueError(
            "AES-256-CTR + HMAC requires a 32-byte master session key "
            "(subkeys are derived via HKDF; 64-byte keys are legacy-read only)"
        )

    nonce = os.urandom(16)  # 128-bit nonce for CTR mode
    enc_key, mac_key = derive_ctr_hmac_keys(key, nonce)

    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update((aad or b"") + nonce + ciphertext)
    tag = h.finalize()

    return nonce, ciphertext, tag
