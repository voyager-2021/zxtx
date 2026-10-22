import hashlib
import lzma
import os
import struct
import time
import uuid
import zlib

import brotli

from zxtx.constants import (
    CIPHER_METHOD,
    COMPRESSION_METHOD,
    UINT16_MAX,
)
from zxtx.dtypes import (
    FORMAT_VERSION,
    ZXTXHeader,
    header_identity_digest,
    pack_header,
    version_at_least,
)
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
    *,
    certificate: bytes | None = None,
    public_key=None,
    version=FORMAT_VERSION,
) -> bytes:
    """
    Serialize ``data`` into the ZXTX file format.

    Signing (v1.1): the signature covers the packed header *and* the body
    (``header || body``), so any modification of either region invalidates
    it.  For legacy v1.0 output, the signature covers the header only.

    Encryption session keys are 32 bytes and wrapped with the recipient's
    RSA public key.  For CTR + HMAC the AES/HMAC subkeys are derived via
    HKDF-SHA256 from the master key (64-byte raw split keys are a legacy
    v1.0 read-only feature).
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"data must be bytes-like, got {type(data).__name__}")
    data = bytes(data)

    uid = uuid.uuid4().bytes
    timestamp = int(time.time())
    sha256 = hashlib.sha256(data).digest()

    if certificate is None:
        certificate = b""
    if not isinstance(certificate, (bytes, bytearray)):
        raise TypeError(f"certificate must be bytes, got {type(certificate).__name__}")
    certificate = bytes(certificate)
    if len(certificate) > UINT16_MAX:
        raise ValueError(
            f"Embedded certificate is {len(certificate)} bytes; "
            f"the format supports at most {UINT16_MAX}"
        )

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
            raise NotImplementedError(
                f"Compression method not supported: {compression_method!r}"
            )

    # Associated data binding the encrypted body to this header.  Only
    # fields known *before* encryption are covered (compressed size and
    # CRC32 depend on the ciphertext itself and are therefore excluded).
    body_binding: bytes | None = None
    if version_at_least(version, (1, 1)):
        body_binding = header_identity_digest(
            ZXTXHeader(
                version_major=version[0],
                version_minor=version[1],
                uid=uid,
                compression_method=compression_method,
                cipher_method=cipher_method,
                original_size=len(data),
                compressed_size=0,  # placeholder, excluded from the digest
                timestamp=timestamp,
                sha256_hash=sha256,
                crc32=0,  # placeholder, excluded from the digest
                signature=b"",
                certificate=certificate,
            )
        )

    # Encrypt if cipher method is enabled
    match cipher_method:
        case CIPHER_METHOD.NONE:
            compressed_final = compressed
        case CIPHER_METHOD.AES256_GCM:
            if public_key is None:
                raise ValueError("Public key required for encryption")

            session_key = os.urandom(32)  # AES-256
            encrypted_data, nonce = encrypt_data_aes_gcm(
                compressed, session_key, aad=body_binding
            )
            encrypted_session_key = encrypt_key_rsa(public_key, session_key)

            # Format: encrypted_session_key + nonce + ciphertext (+ tag appended by GCM)
            compressed_final = encrypted_session_key + nonce + encrypted_data
        case CIPHER_METHOD.CHACHA20_POLY1305:
            if public_key is None:
                raise ValueError("Public key required for encryption")

            session_key = os.urandom(32)  # ChaCha20-Poly1305
            encrypted_data, nonce = encrypt_data_chacha20(
                compressed, session_key, aad=body_binding
            )
            encrypted_session_key = encrypt_key_rsa(public_key, session_key)
            compressed_final = encrypted_session_key + nonce + encrypted_data
        case CIPHER_METHOD.AES256_CTR_HMAC:
            if public_key is None:
                raise ValueError("Public key required for encryption")

            session_key = os.urandom(32)  # master key; subkeys derived via HKDF
            nonce, encrypted_data, tag = encrypt_data_aes256_ctr_hmac(
                compressed, session_key, aad=body_binding
            )
            encrypted_session_key = encrypt_key_rsa(public_key, session_key)

            # Format: encrypted_session_key + nonce + ciphertext + tag
            compressed_final = encrypted_session_key + nonce + encrypted_data + tag
        case _:
            raise NotImplementedError(f"Unsupported cipher method '{cipher_method}'")

    crc32 = zlib.crc32(compressed_final) & 0xFFFFFFFF

    header = ZXTXHeader(
        version_major=version[0],
        version_minor=version[1],
        uid=uid,
        compression_method=compression_method,
        cipher_method=cipher_method,
        original_size=len(data),
        compressed_size=len(compressed_final),
        timestamp=timestamp,
        sha256_hash=sha256,
        crc32=crc32,
        signature=b"",
        certificate=certificate,
    )

    header_bytes = pack_header(header)

    # Sign the packed header (and, since v1.1, the body as well)
    signed_message = header_bytes + (
        compressed_final if version_at_least(version, (1, 1)) else b""
    )
    signature = sign_data(private_key, signed_message)
    if len(signature) > UINT16_MAX:
        raise ValueError(
            f"Signature is {len(signature)} bytes; "
            f"the format supports at most {UINT16_MAX}"
        )

    header_bytes += struct.pack(">H", len(signature)) + signature

    return header_bytes + compressed_final
