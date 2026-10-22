import hashlib
import lzma
import struct
import zlib
from typing import Optional

import brotli
from cryptography.hazmat.primitives.asymmetric import rsa

from zxtx.constants import (
    CIPHER_METHOD,
    COMPRESSION_METHOD,
    CTR_HMAC_TAG_SIZE,
    MAGIC_NUMBER,
    NONCE_SIZE_AES_CTR,
    NONCE_SIZE_AEAD,
)
from zxtx.decryption import (
    decrypt_data_aes256_ctr_hmac,
    decrypt_data_aes_gcm,
    decrypt_data_chacha20,
    decrypt_key_rsa,
)
from zxtx.dtypes import ZXTXBody, ZXTXHeader, header_identity_digest, pack_header
from zxtx.utils import bits_to_bytes, is_encrypted
from zxtx.verifier import resolve_verification_key, verify_signature

_FIXED_HEADER_SIZE = 4 + 2 + 16 + 2 + 8 + 8 + 8 + 32 + 4 + 2 + 2
_BROTLI_FEED_CHUNK = 8192


def parse_zxtx_header(
    data: bytes,
    private_key=None,
    *,
    compression_method=None,
    cipher_method=None,
    verification_key=None,
) -> tuple[ZXTXHeader, ZXTXBody]:
    """
    Parse the ZXTX header and split out the (encrypted) body.

    Args:
        data: The raw file contents.
        private_key: RSA private key used to size the wrapped session key
            field of the body; must also match the recipient for decryption.
        compression_method / cipher_method: Optional explicit overrides.
            An override that contradicts the file header is rejected.
        verification_key: Optional trust anchor (``cryptography`` public key
            object, or PEM-encoded X.509 certificate / public key bytes).
            When provided, the embedded signature is verified during
            parsing: an invalid signature (or an unsigned file) raises
            ``ValueError``.

    Signature layout:
        * v1.1 files: signature covers ``packed_header || body``.
        * v1.0 files: signature covers ``packed_header`` only (legacy).

    Raises ``ValueError`` on any structural problem (bad magic, unknown
    format version, unknown method IDs, truncated regions, CRC mismatch)
    or on a failed signature verification.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"data must be bytes-like, got {type(data).__name__}")
    data = bytes(data)

    if len(data) < _FIXED_HEADER_SIZE:
        raise ValueError(
            f"Invalid ZXTX file: truncated header "
            f"({len(data)} bytes, need at least {_FIXED_HEADER_SIZE})"
        )

    offset = 0

    def read(fmt: str):
        nonlocal offset
        size = struct.calcsize(fmt)
        if offset + size > len(data):
            raise ValueError("Invalid ZXTX file: truncated header")
        value = struct.unpack_from(fmt, data, offset)
        offset += size
        return value if len(value) > 1 else value[0]  # type: ignore

    def take(n: int, what: str) -> bytes:
        nonlocal offset
        if offset + n > len(data):
            available = len(data) - offset
            raise ValueError(
                f"Invalid ZXTX file: truncated {what} "
                f"(declared {n} bytes, {available} available)"
            )
        value = data[offset : offset + n]
        offset += n
        return value

    # Magic number
    magic = data[offset : offset + 4]
    if magic != MAGIC_NUMBER:
        raise ValueError("Invalid ZXTX file: bad magic number")
    offset += 4

    version_major = data[offset]
    version_minor = data[offset + 1]
    offset += 2

    if version_major != 1:
        raise ValueError(
            f"Unsupported format version: {version_major}.{version_minor} "
            f"(this reader supports major version 1)"
        )

    uid = take(16, "uid")

    comp_id = data[offset]
    cipher_id = data[offset + 1]
    offset += 2

    header_compression_method = _compression_enum(comp_id)
    header_cipher_method = _cipher_enum(cipher_id)

    if (
        compression_method is not None
        and compression_method != header_compression_method
    ):
        raise ValueError(
            f"Explicit compression override {compression_method!r} does not "
            f"match the file header ({header_compression_method!r}); leave "
            f"the override as None to auto-detect"
        )
    if cipher_method is not None and cipher_method != header_cipher_method:
        raise ValueError(
            f"Explicit cipher override {cipher_method!r} does not match the "
            f"file header ({header_cipher_method!r}); leave the override as "
            f"None to auto-detect"
        )

    compression_method = header_compression_method
    cipher_method = header_cipher_method

    original_size = read(">Q")
    compressed_size = read(">Q")
    timestamp = read(">d")
    sha256_hash = take(32, "SHA-256 hash")
    crc32 = read(">I")

    cert_len = read(">H")
    certificate = take(cert_len, "certificate")

    sig_len = read(">H")
    signature = take(sig_len, "signature")

    header = ZXTXHeader(
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
    )

    # Body: exactly ``compressed_size`` bytes after the header
    available = len(data) - offset
    if available < compressed_size:
        raise ValueError(
            f"Invalid ZXTX file: truncated body "
            f"(declared {compressed_size} bytes, {available} available)"
        )
    compressed_data = data[offset : offset + compressed_size]

    if zlib.crc32(compressed_data) != crc32:
        raise ValueError("CRC32 mismatch: file may be corrupted or tampered")

    # Signature verification (only when a trust anchor was provided).
    # v1.1 signs ``packed_header || body``; v1.0 signed the header alone.
    if verification_key is not None:
        key = resolve_verification_key(verification_key)
        if not signature:
            raise ValueError(
                "File is not signed, but a verification key was provided. "
                "Re-open the file without public_key/certificate to read "
                "unsigned files."
            )
        signed_message = pack_header(header) + (
            compressed_data if _is_v1_1(header) else b""
        )
        if not verify_signature(key, signed_message, signature):
            raise ValueError(
                "Signature verification failed: file may be modified or "
                "signed by a different key"
            )

    tag: Optional[bytes] = None

    # If cipher is none, compressed_data is raw compressed data
    # Else, encrypted_data structure:
    #   encrypted_session_key + nonce + encrypted_blob (+ tag for CTR+HMAC)
    match cipher_method:
        case CIPHER_METHOD.NONE:
            encrypted_key = None
            nonce = None
            encrypted_blob = compressed_data
        case (
            CIPHER_METHOD.AES256_CTR_HMAC
            | CIPHER_METHOD.AES256_GCM
            | CIPHER_METHOD.CHACHA20_POLY1305
        ):
            if private_key is None:
                # No key to size the wrapped session key field against:
                # assume the common RSA-2048 modulus.  Decryption is refused
                # later anyway when the key is missing.
                key_size = 256
            else:
                _require_rsa_private_key(private_key)
                key_size = bits_to_bytes(private_key.key_size)

            nonce_size = (
                NONCE_SIZE_AES_CTR
                if cipher_method == CIPHER_METHOD.AES256_CTR_HMAC
                else NONCE_SIZE_AEAD
            )
            min_body = key_size + nonce_size + (
                CTR_HMAC_TAG_SIZE
                if cipher_method == CIPHER_METHOD.AES256_CTR_HMAC
                else 0
            )
            if len(compressed_data) < min_body:
                raise ValueError(
                    f"Invalid ZXTX file: encrypted body too short for the "
                    f"RSA-{key_size * 8} key/nonce layout "
                    f"(declared compressed size {compressed_size}, need at "
                    f"least {min_body})"
                )

            encrypted_key = compressed_data[:key_size]
            nonce = compressed_data[key_size : key_size + nonce_size]

            if cipher_method == CIPHER_METHOD.AES256_CTR_HMAC:
                # Last 32 bytes are the HMAC tag
                encrypted_blob = compressed_data[
                    key_size + nonce_size : -CTR_HMAC_TAG_SIZE
                ]
                tag = compressed_data[-CTR_HMAC_TAG_SIZE:]
            else:
                encrypted_blob = compressed_data[key_size + nonce_size :]
                tag = None
        case _:
            raise ValueError(f"Invalid cipher method '{cipher_method}'")

    body = ZXTXBody(
        data=encrypted_blob, nonce=nonce, encrypted_key=encrypted_key, tag=tag
    )
    return header, body


def _is_v1_1(header: ZXTXHeader) -> bool:
    """True when the file uses v1.1 semantics (body-signed, AAD-bound)."""
    return header.version_major == 1 and header.version_minor >= 1


def _compression_enum(value: int) -> COMPRESSION_METHOD:
    try:
        return COMPRESSION_METHOD(value)
    except ValueError:
        raise ValueError(
            f"Invalid compression method ID {value} in file header"
        ) from None


def _cipher_enum(value: int) -> CIPHER_METHOD:
    try:
        return CIPHER_METHOD(value)
    except ValueError:
        raise ValueError(
            f"Invalid cipher method ID {value} in file header"
        ) from None


def _require_rsa_private_key(private_key) -> None:
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError(
            "Encrypted ZXTX files wrap their session key with RSA; a "
            f"{type(private_key).__name__} private key cannot unwrap it. "
            "Provide the RSA private key of the file's recipient."
        )


def read_zxtx_file(header: ZXTXHeader, body: ZXTXBody, private_key=None) -> bytes:
    """
    Decrypt (if encrypted) and decompress the body of a parsed ZXTX file,
    then verify the declared original size and the SHA-256 digest.

    For v1.1 files the header identity digest is used as associated data
    for AEAD ciphers (and as the HMAC input prefix for CTR + HMAC); v1.0
    files are read with legacy semantics (no AAD).

    Decompression is bounded by the declared original size to blunt
    decompression-bomb attacks on unverified files.
    """
    if is_encrypted(header) and private_key is None:
        raise ValueError(
            "File appears to be encrypted, but no private key was provided."
        )

    aad = header_identity_digest(header) if _is_v1_1(header) else None

    match header.cipher_method:
        case CIPHER_METHOD.NONE:
            decrypted_data = body.data
        case CIPHER_METHOD.AES256_GCM:
            if body.encrypted_key is None or body.nonce is None:
                raise ValueError(
                    "Missing encrypted key or nonce for AES256_GCM decryption"
                )

            session_key = decrypt_key_rsa(private_key, body.encrypted_key)
            decrypted_data = decrypt_data_aes_gcm(
                body.data, body.nonce, session_key, aad=aad
            )
        case CIPHER_METHOD.CHACHA20_POLY1305:
            if body.encrypted_key is None or body.nonce is None:
                raise ValueError(
                    "Missing encrypted key or nonce for CHACHA20_POLY1305 decryption"
                )

            session_key = decrypt_key_rsa(private_key, body.encrypted_key)
            decrypted_data = decrypt_data_chacha20(
                body.data, body.nonce, session_key, aad=aad
            )
        case CIPHER_METHOD.AES256_CTR_HMAC:
            if body.encrypted_key is None or body.nonce is None or body.tag is None:
                raise ValueError(
                    "Missing encrypted key, nonce or tag for AES256_CTR_HMAC "
                    "decryption"
                )

            session_key = decrypt_key_rsa(private_key, body.encrypted_key)
            decrypted_data = decrypt_data_aes256_ctr_hmac(
                body.data, body.nonce, body.tag, session_key, aad=aad
            )
        case _:
            raise NotImplementedError(
                f"Unsupported cipher method '{header.cipher_method}'"
            )

    # Decompress
    if header.compression_method == COMPRESSION_METHOD.NONE:
        decompressed = decrypted_data
    elif header.compression_method == COMPRESSION_METHOD.ZLIB:
        decompressed = _decompress_bounded_zlib(decrypted_data, header.original_size)
    elif header.compression_method == COMPRESSION_METHOD.LZMA:
        decompressed = _decompress_bounded_lzma(decrypted_data, header.original_size)
    elif header.compression_method == COMPRESSION_METHOD.BROTLI:
        decompressed = _decompress_bounded_brotli(
            decrypted_data, header.original_size
        )
    else:
        raise NotImplementedError(
            f"Unsupported compression method '{header.compression_method}'"
        )

    if len(decompressed) != header.original_size:
        raise ValueError(
            f"Decompressed data size ({len(decompressed)}) does not match "
            f"the declared original size ({header.original_size}); file "
            f"may be corrupted or tampered"
        )

    if hashlib.sha256(decompressed).digest() != header.sha256_hash:
        raise ValueError("SHA-256 hash mismatch: file may be corrupted or tampered")

    return decompressed


def _check_bomb(limit: int, produced: int, compressor: str) -> None:
    if produced > limit:
        raise ValueError(
            f"Decompressed data size ({produced}) exceeds the declared "
            f"original size ({limit}) — potential {compressor} "
            f"decompression bomb"
        )


def _decompress_bounded_zlib(data: bytes, limit: int) -> bytes:
    """Streamed zlib decompression that refuses output beyond ``limit``."""
    if limit < 0:
        raise ValueError(f"Invalid declared original size: {limit}")

    decompressor = zlib.decompressobj()
    out = bytearray()
    pending = data

    try:
        while not decompressor.eof:
            if len(out) > limit:
                _check_bomb(limit, len(out), "zlib")

            piece = decompressor.decompress(
                pending, max_length=max(limit - len(out), 0) + 1
            )
            out += piece
            pending = decompressor.unconsumed_tail

            if not piece and not pending and not decompressor.eof:
                raise ValueError(
                    "Invalid compressed data: truncated zlib stream"
                )
    except zlib.error as error:
        raise ValueError(f"Invalid compressed data: {error}") from None

    _check_bomb(limit, len(out), "zlib")
    return bytes(out)


def _decompress_bounded_lzma(data: bytes, limit: int) -> bytes:
    """Streamed LZMA decompression that refuses output beyond ``limit``."""
    if limit < 0:
        raise ValueError(f"Invalid declared original size: {limit}")

    decompressor = lzma.LZMADecompressor(lzma.FORMAT_AUTO)
    out = bytearray()
    source = data

    try:
        while not decompressor.eof:
            budget = max(limit - len(out), 0) + 1

            piece = decompressor.decompress(source, max_length=budget)
            out += piece
            # Get unconsumed input for next iteration (Python 3.3+ has unconsumed_tail,
            # but fall back to manual tracking if not available)
            source = getattr(decompressor, 'unconsumed_tail', b'')

            if not piece and not decompressor.eof:
                raise ValueError("Invalid compressed data: truncated LZMA stream")
            _check_bomb(limit, len(out), "LZMA")
    except lzma.LZMAError as error:
        raise ValueError(f"Invalid compressed data: {error}") from None

    _check_bomb(limit, len(out), "LZMA")
    return bytes(out)


def _decompress_bounded_brotli(data: bytes, limit: int) -> bytes:
    """Chunked Brotli decompression that refuses output beyond ``limit``."""
    if limit < 0:
        raise ValueError(f"Invalid declared original size: {limit}")

    decompressor = brotli.Decompressor()
    out = bytearray()

    try:
        for start in range(0, len(data), _BROTLI_FEED_CHUNK):
            out += decompressor.process(data[start : start + _BROTLI_FEED_CHUNK])
            if len(out) > limit:
                _check_bomb(limit, len(out), "Brotli")
            if decompressor.is_finished():
                break
    except brotli.error as error:
        raise ValueError(f"Invalid compressed data: {error}") from None

    if not decompressor.is_finished():
        raise ValueError("Invalid compressed data: truncated Brotli stream")

    _check_bomb(limit, len(out), "Brotli")
    return bytes(out)
