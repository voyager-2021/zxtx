import binascii
import hashlib
import lzma
import os
import struct
import time
import uuid
import zlib
from typing import Optional

import brotli

from zxtx.constants import CIPHER_METHOD, COMPRESSION_METHOD, MAGIC_NUMBER
from zxtx.encryption import (
    encrypt_data_aes256_ctr_hmac,
    encrypt_data_aes_gcm,
    encrypt_data_chacha20,
    encrypt_key_rsa,
)
from zxtx.signer import sign_data


def write_zxtx_file(
    data: bytes,
    compression_method: COMPRESSION_METHOD,
    cipher_method: CIPHER_METHOD,
    private_key,
    certificate: Optional[bytes] = None,
    public_key=None,
    version=(1, 0),
) -> bytes:
    uid = uuid.uuid4().bytes
    timestamp = int(time.time())

    # Compress
    match compression_method:
        case COMPRESSION_METHOD.NONE:
            compressed = data
        case COMPRESSION_METHOD.ZLIB:
            compressed = zlib.compress(data)
        case COMPRESSION_METHOD.LZMA:
            compressed = lzma.compress(data)
        case COMPRESSION_METHOD.BROTLI:
            compressed = brotli.compress(data)
        case _:
            raise NotImplementedError("Compression method not supported")

    # Encrypt if cipher method is enabled
    match cipher_method:
        case CIPHER_METHOD.NONE:
            compressed_final = compressed
        case CIPHER_METHOD.AES256_GCM:
            if public_key is None:
                raise ValueError("Public key required for encryption")

            session_key = os.urandom(32)  # AES-256
            encrypted_data, nonce, _ = encrypt_data_aes_gcm(compressed, session_key)
            encrypted_session_key = encrypt_key_rsa(public_key, session_key)

            compressed_final = encrypted_session_key + nonce + encrypted_data
        case CIPHER_METHOD.CHACHA20_POLY1305:
            if public_key is None:
                raise ValueError("Public key required for encryption")

            session_key = os.urandom(32)  # ChaCha20 key length 256-bit
            encrypted_data, nonce, _ = encrypt_data_chacha20(compressed, session_key)
            encrypted_session_key = encrypt_key_rsa(public_key, session_key)
            compressed_final = encrypted_session_key + nonce + encrypted_data
        case CIPHER_METHOD.AES256_CTR_HMAC:
            if public_key is None:
                raise ValueError("Public key required for encryption")

            session_key = os.urandom(64)  # 32 bytes AES-CTR + 32 bytes HMAC
            encrypted_data, nonce, tag = encrypt_data_aes256_ctr_hmac(
                compressed, session_key
            )
            encrypted_session_key = encrypt_key_rsa(public_key, session_key)

            # Format: encrypted_session_key + nonce + ciphertext + tag
            compressed_final = encrypted_session_key + nonce + encrypted_data + tag
        case _:
            raise NotImplementedError(f"Unsupported cipher method '{cipher_method}'")

    if certificate is None:
        certificate = b""

    crc32 = binascii.crc32(compressed_final) & 0xFFFFFFFF
    sha256 = hashlib.sha256(data).digest()

    # Header
    header = bytearray()
    header += MAGIC_NUMBER
    header += struct.pack("BB", version[0], version[1])  # major, minor
    header += uid
    header += struct.pack("BB", compression_method.value, cipher_method.value)
    header += struct.pack(">Q", len(data))
    header += struct.pack(">Q", len(compressed_final))
    header += struct.pack(">d", timestamp)
    header += sha256
    header += struct.pack(">I", crc32)
    header += struct.pack(">H", len(certificate))
    header += certificate

    # Sign the header
    signature = sign_data(private_key, bytes(header))
    header += struct.pack(">H", len(signature))
    header += signature

    return bytes(header) + compressed_final
