import datetime as dt
from dataclasses import dataclass
from typing import Optional

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
