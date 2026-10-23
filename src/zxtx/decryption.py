from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from zxtx.encryption import derive_ctr_hmac_keys
from zxtx.errors import DecryptionError


def decrypt_key_rsa(private_key, encrypted_key: bytes) -> bytes:
    """
    Unwrap the RSA-OAEP-encrypted session key.  Raises ``ValueError`` when
    the ciphertext is not decryptable with this key (wrong key, truncated
    blob, or the parse-time key-size assumption did not match the writer).
    """
    try:
        return private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except ValueError as error:
        if hasattr(error, "add_note"):
            error.add_note("Note: The private key may be invalid.")
        raise DecryptionError(str(error)) from error


def decrypt_data_aes_gcm(
    encrypted_data: bytes, nonce: bytes, key: bytes, aad: bytes | None = None
) -> bytes:
    """
    AES-256-GCM decryption.  ``aad`` must be the same value used at
    encryption time (``None`` for v1.0 files, the header identity digest
    for v1.1 files) or authentication will fail.
    """
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, encrypted_data, aad)
    except InvalidTag as error:
        raise DecryptionError(
            "Decryption failed: the AEAD authentication tag is invalid "
            "(wrong key or tampered/corrupted data)."
        ) from error


def decrypt_data_chacha20(
    encrypted_data: bytes, nonce: bytes, key: bytes, aad: bytes | None = None
) -> bytes:
    """
    ChaCha20-Poly1305 decryption.  ``aad`` must be the same value used at
    encryption time (``None`` for v1.0 files, the header identity digest
    for v1.1 files) or authentication will fail.
    """
    chacha = ChaCha20Poly1305(key)
    try:
        return chacha.decrypt(nonce, encrypted_data, aad)
    except InvalidTag as error:
        raise DecryptionError(
            "Decryption failed: the AEAD authentication tag is invalid "
            "(wrong key or tampered/corrupted data)."
        ) from error


def decrypt_data_aes256_ctr_hmac(
    ciphertext: bytes, nonce: bytes, tag: bytes, key: bytes, aad: bytes | None = None
) -> bytes:
    """
    AES-256-CTR decryption with HMAC-SHA256 verification (encrypt-then-MAC).

    ``key`` is the *unwrapped session key*:

    * 32 bytes (v1.1): the AES and HMAC subkeys are re-derived via
      HKDF-SHA256 using ``nonce`` as the salt, and the MAC input is
      ``aad || nonce || ciphertext``.
    * 64 bytes (v1.0 legacy): the key is split directly into a 32-byte
      AES key and a 32-byte HMAC key, and the MAC covers ``nonce ||
      ciphertext`` only (``aad`` is ignored for legacy files).

    A bad tag raises ``DecryptionError`` (subclass of ``ValueError``;
    verified *before* any ciphertext is decrypted).
    """
    if len(key) == 64:
        # Legacy v1.0 layout: key = enc_key || mac_key
        enc_key = key[:32]
        mac_key = key[32:]
        aad = b""
    elif len(key) == 32:
        # v1.1 layout: derive subkeys from the 32-byte master key
        enc_key, mac_key = derive_ctr_hmac_keys(key, nonce)
    else:
        raise ValueError(
            f"Session key must be 32 (v1.1) or 64 (v1.0 legacy) bytes, got {len(key)}"
        )

    h = hmac.HMAC(mac_key, hashes.SHA256())
    h.update((aad or b"") + nonce + ciphertext)
    try:
        h.verify(tag)  # raises InvalidSignature if invalid
    except InvalidSignature as error:
        raise DecryptionError(
            "Decryption failed: the encrypt-then-MAC tag does not match "
            "(wrong key or tampered/corrupted data)."
        ) from error

    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext
