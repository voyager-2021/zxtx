import hashlib
import lzma
import struct
import zlib

import brotli

from zxtx.constants import CIPHER_METHOD, COMPRESSION_METHOD, MAGIC_NUMBER
from zxtx.decryption import (
    decrypt_data_aes256_ctr_hmac,
    decrypt_data_aes_gcm,
    decrypt_data_chacha20,
    decrypt_key_rsa,
)
from zxtx.dtypes import ZXTXBody, ZXTXHeader
from zxtx.utils import bits_to_bytes, is_encrypted


def parse_zxtx_header(
    data: bytes, private_key=None, *, compression_method=None, cipher_method=None
) -> tuple[ZXTXHeader, ZXTXBody]:
    offset = 0

    def read(fmt: str):
        nonlocal offset
        size = struct.calcsize(fmt)
        value = struct.unpack_from(fmt, data, offset)
        offset += size
        return value if len(value) > 1 else value[0]  # type: ignore

    # Magic number
    magic = data[offset : offset + 4]
    if magic != MAGIC_NUMBER:
        raise ValueError("Invalid ZXTX file: bad magic number")

    offset += 4

    version_minor = data[offset + 1]
    version_major = data[offset]
    offset += 2

    uid = data[offset : offset + 16]
    offset += 16

    compression_method = (
        COMPRESSION_METHOD(data[offset])
        if compression_method is None
        else compression_method
    )

    cipher_method = (
        CIPHER_METHOD(data[offset + 1]) if cipher_method is None else cipher_method
    )

    offset += 2

    original_size = read(">Q")
    compressed_size = read(">Q")
    timestamp = read(">d")
    sha256_hash = data[offset : offset + 32]
    offset += 32

    crc32 = read(">I")
    cert_len = read(">H")
    certificate = data[offset : offset + cert_len]
    offset += cert_len

    sig_len = read(">H")
    signature = data[offset : offset + sig_len]
    offset += sig_len

    compressed_data = data[offset : offset + compressed_size]

    if zlib.crc32(compressed_data) != crc32:
        raise ValueError("CRC32 mismatch: file may be corrupted or tampered")

    tag = None

    # If cipher is none, compressed_data is raw compressed data
    # Else, encrypted_data structure: encrypted_session_key + nonce + encrypted_blob
    match cipher_method:
        case CIPHER_METHOD.NONE:
            encrypted_key = None
            nonce = None
            encrypted_blob = compressed_data
            tag = None
        case (
            CIPHER_METHOD.AES256_CTR_HMAC
            | CIPHER_METHOD.AES256_GCM
            | CIPHER_METHOD.CHACHA20_POLY1305
        ):
            if private_key is None:
                # Default to RSA-2048 (256 bytes)
                key_size = 256
            else:
                key_size = bits_to_bytes(bits=private_key.key_size)

            # Set nonce size depending on cipher
            nonce_size = 16 if cipher_method == CIPHER_METHOD.AES256_CTR_HMAC else 12

            encrypted_key = compressed_data[:key_size]
            nonce = compressed_data[key_size : key_size + nonce_size]

            if cipher_method == CIPHER_METHOD.AES256_CTR_HMAC:
                # Last 32 bytes are HMAC tag
                encrypted_blob = compressed_data[key_size + nonce_size : -32]
                tag = compressed_data[-32:]
            else:
                encrypted_blob = compressed_data[key_size + nonce_size :]
                tag = None
        case _:
            raise ValueError(f"Invalid cipher method '{cipher_method}'")

    return (
        ZXTXHeader(
            version_major=version_major,
            version_minor=version_minor,
            uid=uid,
            compression_method=compression_method,
            cipher_method=cipher_method,
            original_size=original_size,
            compressed_size=compressed_size,
            timestamp=timestamp,
            sha256_hash=sha256_hash,
            crc32=crc32,
            certificate=certificate,
            signature=signature,
        ),
        ZXTXBody(
            data=encrypted_blob, nonce=nonce, encrypted_key=encrypted_key, tag=tag
        ),
    )


def read_zxtx_file(header: ZXTXHeader, body: ZXTXBody, private_key) -> bytes:
    if is_encrypted(header) and private_key is None:
        raise ValueError(
            "File appears to be encrypted, but no private key was provided."
        )

    match header.cipher_method:
        case CIPHER_METHOD.NONE:
            decrypted_data = body.data
        case CIPHER_METHOD.AES256_GCM:
            if body.encrypted_key is None or body.nonce is None:
                raise ValueError(
                    "Missing encrypted key or nonce for AES256_GCM decryption"
                )

            if private_key is None:
                raise ValueError("Missing private key for AES256_GCM decryption")

            session_key = decrypt_key_rsa(private_key, body.encrypted_key)
            decrypted_data = decrypt_data_aes_gcm(body.data, body.nonce, session_key)
        case CIPHER_METHOD.CHACHA20_POLY1305:
            if body.encrypted_key is None or body.nonce is None:
                raise ValueError(
                    "Missing encrypted key or nonce for ChaCha20_POLY1305 decryption"
                )

            if private_key is None:
                raise ValueError("Missing private key for ChaCha20_POLY1305 decryption")

            session_key = decrypt_key_rsa(private_key, body.encrypted_key)
            decrypted_data = decrypt_data_chacha20(body.data, body.nonce, session_key)
        case CIPHER_METHOD.AES256_CTR_HMAC:
            if body.encrypted_key is None or body.nonce is None:
                raise ValueError(
                    "Missing encrypted key or nonce for AES256_CTR_HMAC decryption"
                )

            if private_key is None:
                raise ValueError("Missing private key for AES256_CTR_HMAC decryption")

            session_key = decrypt_key_rsa(private_key, body.encrypted_key)
            decrypted_data = decrypt_data_aes256_ctr_hmac(
                body.data, body.nonce, body.tag, session_key  # type: ignore
            )
        case _:
            raise NotImplementedError(
                f"Unsupported cipher method '{header.cipher_method}'"
            )

    # Decompress
    if header.compression_method == COMPRESSION_METHOD.NONE:
        decompressed = decrypted_data
    elif header.compression_method == COMPRESSION_METHOD.ZLIB:
        decompressed = zlib.decompress(decrypted_data)
    elif header.compression_method == COMPRESSION_METHOD.LZMA:
        decompressed = lzma.decompress(decrypted_data)
    elif header.compression_method == COMPRESSION_METHOD.BROTLI:
        decompressed = brotli.decompress(decrypted_data)
    else:
        raise NotImplementedError(
            f"Unsupported compression method '{header.compression_method}'"
        )

    if hashlib.sha256(decompressed).digest() != header.sha256_hash:
        raise ValueError(
            f"SHA-256 hash mismatch: file may be corrupted or tampered, got '{hashlib.sha256(decompressed).hexdigest()}' but expected '{header.sha256_hash.hex()}'"
        )

    return decompressed
