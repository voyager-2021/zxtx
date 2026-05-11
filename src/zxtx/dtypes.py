import datetime as dt
import struct
from dataclasses import dataclass

from zxtx.constants import CIPHER_METHOD, COMPRESSION_METHOD, MAGIC_NUMBER


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
    certificate: bytes | None

    def creation_time(self) -> dt.datetime:
        return dt.datetime.fromtimestamp(self.timestamp)

    def serialize_for_signature(self) -> bytes:
        """
        Serialize header bytes for signature verification.

        This reconstructs the exact bytes that were signed when creating the ZXTX file.
        The signature covers: magic + version + uid + compression + cipher +
        original_size + compressed_size + timestamp + sha256 + crc32 + certificate
        """
        header = bytearray()
        header += MAGIC_NUMBER
        header += struct.pack("BB", self.version_major, self.version_minor)
        header += self.uid
        header += struct.pack("BB", self.compression_method.value, self.cipher_method.value)
        header += struct.pack(">Q", self.original_size)
        header += struct.pack(">Q", self.compressed_size)
        header += struct.pack(">d", self.timestamp)
        header += self.sha256_hash
        header += struct.pack(">I", self.crc32)

        cert = self.certificate if self.certificate else b""
        header += struct.pack(">H", len(cert))
        header += cert

        return bytes(header)


@dataclass
class ZXTXBody:
    data: bytes
    nonce: bytes | None
    encrypted_key: bytes | None
    tag: bytes | None
    encrypted_payload: bytes  # Full encrypted data (key + nonce + ciphertext + tag) for signature verification


@dataclass
class ZXTXData:
    data: bytes
