import datetime as dt
import hashlib
import struct
from dataclasses import dataclass
from typing import Optional

from zxtx.constants import CIPHER_METHOD, COMPRESSION_METHOD, MAGIC_NUMBER

# The format version written by this release.  Readers also accept v1.0
# files, using the (documented) legacy semantics where required.
FORMAT_VERSION = (1, 1)
FORMAT_VERSION_V1 = (1, 0)

UINT16_MAX = 0xFFFF


@dataclass
class ZXTXHeader:
    version_major: int
    version_minor: int
    uid: bytes
    compression_method: COMPRESSION_METHOD
    cipher_method: CIPHER_METHOD
    original_size: int
    compressed_size: int
    timestamp: int
    sha256_hash: bytes
    crc32: int
    signature: bytes
    certificate: Optional[bytes]

    def creation_time(self) -> dt.datetime:
        return dt.datetime.fromtimestamp(self.timestamp)


@dataclass
class ZXTXBody:
    data: bytes
    nonce: Optional[bytes]
    encrypted_key: Optional[bytes]
    tag: Optional[bytes]


@dataclass
class ZXTXData:
    data: bytes


def version_at_least(version: tuple[int, int], minimum: tuple[int, int]) -> bool:
    """Compare (major, minor) version tuples."""
    return version[:2] >= minimum


def pack_header(header: ZXTXHeader) -> bytes:
    """
    Serialize the header up to (and including) the embedded certificate.

    This is exactly the region that the signature is computed over (v1.0),
    so the writer, parser and verifier all share one packing implementation
    to guarantee bit-for-bit parity.  The 2-byte signature length and the
    signature itself are appended separately.

    ``header.signature`` is intentionally excluded; build the signed message
    as ``pack_header(header) + body`` for v1.1 files.
    """
    if not isinstance(header.compression_method, COMPRESSION_METHOD):
        raise TypeError(
            f"compression_method must be a COMPRESSION_METHOD enum, "
            f"got {type(header.compression_method)!r}"
        )
    if not isinstance(header.cipher_method, CIPHER_METHOD):
        raise TypeError(
            f"cipher_method must be a CIPHER_METHOD enum, got {type(header.cipher_method)!r}"
        )
    if not isinstance(header.uid, (bytes, bytearray)) or len(header.uid) != 16:
        raise ValueError("uid must be exactly 16 bytes")
    if not isinstance(header.sha256_hash, (bytes, bytearray)) or len(
        header.sha256_hash
    ) != 32:
        raise ValueError("sha256_hash must be exactly 32 bytes")
    certificate = header.certificate or b""
    if not isinstance(certificate, (bytes, bytearray)):
        raise TypeError(
            f"certificate must be bytes or None, "
            f"got {type(header.certificate)!r}"
        )
    if len(certificate) > UINT16_MAX:
        raise ValueError("Embedded certificate too large (uint16 length field)")

    return (
        MAGIC_NUMBER
        + struct.pack(">BB", header.version_major, header.version_minor)
        + bytes(header.uid)
        + struct.pack(
            ">BB", header.compression_method.value, header.cipher_method.value
        )
        + struct.pack(">Q", header.original_size)
        + struct.pack(">Q", header.compressed_size)
        + struct.pack(">d", header.timestamp)
        + bytes(header.sha256_hash)
        + struct.pack(">I", header.crc32)
        + struct.pack(">H", len(certificate))
        + certificate
    )


def header_identity_digest(header: ZXTXHeader) -> bytes:
    """
    Cryptographic binding between the header and the encrypted body.

    Returns a 32-byte digest over every header field that is known *before*
    the body is encrypted (magic, version, uid, methods, original size,
    plaintext hash, timestamp, embedded certificate).  Fields that depend on
    the encrypted body (compressed size, CRC32) and the signature itself are
    deliberately excluded so this digest can be used as AEAD associated data
    without circular dependencies.

    For v1.1 files this digest is passed to the cipher as associated data
    (GCM/ChaCha) or prefixed to the MAC input (CTR + HMAC), which prevents
    ciphertext splicing: an encrypted body can no longer be transplanted
    into a file with a different header.
    """
    certificate = header.certificate or b""
    payload = (
        b"ZXTX-HDR-AAD-v1.1"
        + struct.pack(">BB", header.version_major, header.version_minor)
        + bytes(header.uid)
        + struct.pack(
            ">BB", header.compression_method.value, header.cipher_method.value
        )
        + struct.pack(">Q", header.original_size)
        + struct.pack(">d", header.timestamp)
        + bytes(header.sha256_hash)
        + struct.pack(">H", len(certificate))
        + certificate
    )
    return hashlib.sha256(payload).digest()

