import datetime as dt
from dataclasses import dataclass

from zxtx.constants import CIPHER_METHOD, COMPRESSION_METHOD


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


@dataclass
class ZXTXBody:
    data: bytes
    nonce: bytes | None
    encrypted_key: bytes | None
    tag: bytes | None


@dataclass
class ZXTXData:
    data: bytes
