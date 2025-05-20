from enum import Enum

MAGIC_NUMBER = b"ZXTX"


class COMPRESSION_METHOD(Enum):
    """
    All compression methods supported by the zxtx format.

    Attributes:
        NONE (int): No compression applied.
        ZLIB (int): Use ZLIB compression algorithm.
        LZMA (int): Use LZMA compression algorithm.
        BROTLI (int): Use Brotli compression algorithm.
    """

    NONE = 0
    ZLIB = 1
    LZMA = 2
    BROTLI = 3


class CIPHER_METHOD(Enum):
    """
    All cipher methods supported by the zxtx format.

    Attributes:
        NONE (int): No encryption applied.
        AES256_GCM (int): Use AES-256 in Galois/Counter Mode (GCM).
        CHACHA20_POLY1305 (int): Use ChaCha20-Poly1305 authenticated encryption.
    """

    NONE = 0
    AES256_GCM = 1
    CHACHA20_POLY1305 = 2
    AES256_CTR_HMAC = 3
