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
        AES256_CTR_HMAC (int): Use AES-256-CTR with an HMAC-SHA256 (encrypt-then-MAC).
    """

    NONE = 0
    AES256_GCM = 1
    CHACHA20_POLY1305 = 2
    AES256_CTR_HMAC = 3


#: Largest value storable in a uint16 length field (certificates, signatures).
UINT16_MAX = 0xFFFF

#: RSA-OAEP-SHA256 wraps at most ``k - 2 * hLen - 2`` bytes under an
#: RSA modulus of ``k`` bytes (RFC 8017, section 7.1.1).
RSA_OAEP_SHA256_OVERHEAD = 2 + 2 * 32  # = 66 bytes for SHA-256

#: Recommended minimum RSA key size for wrapping session keys.
RSA_MIN_RECOMMENDED_BITS = 2048

#: Nonce sizes per cipher (also used by the parser to slice the body).
NONCE_SIZE_AES_CTR = 16
NONCE_SIZE_AEAD = 12

#: Tag size of the v1 AES-256-CTR + HMAC body layout.
CTR_HMAC_TAG_SIZE = 32

