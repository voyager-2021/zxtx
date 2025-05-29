import sys

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


def decrypt_key_rsa(private_key, encrypted_key: bytes) -> bytes:
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
        (
            error.add_note("Note: The private key may be invalid.")
            if sys.version_info >= (3, 11)
            else ...
        )

        raise error


def decrypt_data_aes_gcm(encrypted_data: bytes, nonce: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, encrypted_data, associated_data=None)


def decrypt_data_chacha20(encrypted_data: bytes, nonce: bytes, key: bytes) -> bytes:
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, encrypted_data, associated_data=None)


def decrypt_data_aes256_ctr_hmac(
    ciphertext: bytes, nonce: bytes, tag: bytes, key: bytes
) -> bytes:
    if len(key) != 64:
        raise ValueError("Key must be 64 bytes for AES-256-CTR + HMAC")
    enc_key = key[:32]
    hmac_key = key[32:]

    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(nonce + ciphertext)
    h.verify(tag)  # raises InvalidSignature if invalid

    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext
