# ZXTX File Format Specification

**Version:** 1.1
**Status:** Draft
**Author:** voyager-2021
**Last Updated:** 2026-10-22

## Overview

ZXTX (Zipped & eXtended Text eXchange) is a file format designed for secure, compressed text storage. It supports metadata embedding, lossless compression, optional symmetric encryption, and optional cryptographic signing.

Version 1.1 adds three security properties that were missing in 1.0:

1. **Signature covers the body** — the digital signature is computed over the packed header *and* the compressed body, so tampering with either region invalidates it.
2. **Header-to-body binding (AAD)** — AEAD ciphers treat a digest of the header identity as associated data; encrypted bodies of v1.1 files cannot be transplanted into other files.
3. **Derived CTR+HMAC subkeys** — the master session key is 32 bytes (fits under RSA-1024 with OAEP-SHA256); the AES key and HMAC key are derived with HKDF-SHA256.

Readers MUST continue to accept v1.0 files (see "v1.0 compatibility").

## Byte Layout (Low-Level)

#### A `.zxtx` file consists of the following sections in sequence

| Field                 | Size (bytes) | Description                                                                |
| --------------------- | ------------ | -------------------------------------------------------------------------- |
| Magic Number          | 4            | `b'ZXTX'` — identifies this file format                                    |
| Version               | 2            | Format version: 1 byte major, 1 byte minor (e.g. v1.1 = `0x01 0x01`)       |
| UID                   | 16           | Unique file ID (UUID v4)                                                   |
| Compression Method ID | 1            | Enum for compression algorithm used                                        |
| Cipher Method ID      | 1            | Enum for cipher algorithm used                                             |
| Original Size         | 8            | Original uncompressed text size (uint64, big-endian)                        |
| Compressed Size       | 8            | Stored body size (uint64, big-endian)                                      |
| Timestamp             | 8            | UNIX timestamp (IEEE 754 double) when file was created                     |
| SHA-256 Hash          | 32           | SHA-256 hash of the original uncompressed text                             |
| CRC32 Checksum        | 4            | CRC32 of the stored body (compressed and possibly encrypted)                |
| Certificate Length    | 2            | Length in bytes of the certificate field (uint16, big-endian)               |
| Certificate Data      | Variable     | X.509 or custom certificate for verifying signer                           |
| Signature Length      | 2            | Length in bytes of the digital signature (uint16, big-endian)               |
| Signature             | Variable     | Signature over the packed header **and the stored body** (v1.1; v1.0: header only) |
| Stored Data           | Variable     | Compressed (and possibly encrypted) data                                    |

Notes:

* All multi-byte integers are big-endian. Version bytes are major-first
  (`v1.1` = `01 01`).
* The signed region ("packed header") is every byte from the magic number
  through the certificate data. The signature length and signature itself
  are appended after it; for v1.1 the stored-data bytes are also signed.
* The CRC32 row means "CRC32 of the exact `Stored Data` bytes as laid out
  in the file" — in encrypted files this is the ciphertext, not the
  plaintext. CRC32 is an integrity convenience for transport errors and is
  *not* a security mechanism; authenticity is provided by the signature.

## Encryption Body Layout

For ciphers other than `none`, the Stored Data is:

| Segment                | Size (bytes)            | Description                                       |
| ---------------------- | ----------------------- | ------------------------------------------------- |
| Wrapped Session Key    | RSA modulus size        | Session key encrypted with RSA-OAEP-SHA256         |
| Nonce                  | 16 (CTR+HMAC) / 12 (AEAD)| Per-file fresh random nonce                       |
| Ciphertext             | Variable                | AEAD ciphertext (+ tag for GCM/ChaCha) or CTR text |
| HMAC Tag               | 32 (CTR+HMAC only)      | Encrypt-then-MAC tag                              |

### Session keys

* The master session key is **32 bytes** of CSPRNG output for all ciphers.
* `aes256_gcm` / `chacha20_poly1305`: the master key is used directly.
* `aes256_ctr_hmac` (v1.1): AES and HMAC subkeys are derived via
  `HKDF-SHA256(master, salt=nonce, info="zxtx-ctr-hmac-v1.1", L=64)` and
  split into a 32-byte AES key followed by a 32-byte HMAC key.

### Associated data (v1.1 only)

AEAD ciphers authenticate the ciphertext with associated data equal to:

```
header_identity = SHA-256(
    b"ZXTX-HDR-AAD-v1.1"
    || version_bytes            # major || minor
    || uid
    || compression_method_id || cipher_method_id
    || original_size            # uint64
    || timestamp                # double
    || sha256_hash
    || certificate_length       # uint16
    || certificate
)
```

For `aes256_ctr_hmac`, the MAC input is `header_identity || nonce || ciphertext`.
For v1.0 files, no associated data is used and the MAC input is `nonce || ciphertext`.

## v1.0 compatibility

Readers MUST accept v1.0 files:

* The signature covers the packed header only (verify without the body).
* No associated data is used for AEAD ciphers.
* `aes256_ctr_hmac` files may contain a **64-byte session key** split
  directly into a 32-byte AES key and a 32-byte HMAC key (no HKDF).

## Recommended reading procedure

1. Parse and structurally validate the header (sizes, method IDs).
2. Verify the CRC32 of the stored data.
3. If a verification key is pinned *outside the file* (public key or
   trusted certificate), verify the signature **before** decrypting.
4. Unwrap the session key, decrypt (checking the AEAD tag / HMAC first),
   then decompress with the declared original size as an output bound.
5. Verify the SHA-256 hash and that the decompressed length matches the
   declared original size.
