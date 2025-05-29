import os

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


def encrypt_data_aes_gcm(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(nonce, data, None)
    return encrypted, nonce, key


def encrypt_data_chacha20(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(key)
    encrypted = cipher.encrypt(nonce, data, None)
    return encrypted, nonce, key


def encrypt_data_aes256_ctr_hmac(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    # Split key: 32 bytes encryption key + 32 bytes HMAC key
    if len(key) != 64:
        raise ValueError("Key must be 64 bytes for AES-256-CTR + HMAC")
    enc_key = key[:32]
    hmac_key = key[32:]

    nonce = os.urandom(16)  # 128-bit nonce for CTR

    cipher = Cipher(algorithms.AES(enc_key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(nonce + ciphertext)
    tag = h.finalize()

    return ciphertext, nonce, tag


def encrypt_key_rsa(public_key, session_key: bytes) -> bytes:
    return public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
