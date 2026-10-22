ZXTX File Format Specification
==============================

**Version:** 1.1
**Status:** Draft
**Author:** voyager-2021
**Last Updated:** 2026-10-22

Overview
--------

ZXTX (Zipped & eXtended Text eXchange) is a file format designed for secure, compressed text storage. It supports metadata embedding, lossless compression, optional symmetric encryption, and optional cryptographic signing.

Version 1.1 adds:

1. **Signature covers the body** — the digital signature is computed over the packed header *and* the stored body.
2. **Header-to-body binding (AAD)** — AEAD ciphers authenticate a digest of the header identity as associated data, preventing ciphertext splicing.
3. **Derived CTR+HMAC subkeys** — the master session key is 32 bytes; AES/HMAC subkeys are derived via HKDF-SHA256.

Readers MUST still accept v1.0 files (header-only signature, no AAD, 64-byte split session keys for ``aes256_ctr_hmac``).

Byte Layout (Low-Level)
-----------------------

A ``.zxtx`` file consists of the following sections in sequence:

+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| ID    | **Field**             | **Size**     | **Description**                                                            |
|       |                       | (bytes)      |                                                                            |
+=======+=======================+==============+============================================================================+
| MNUM  | Magic Number          | 4            | ``b'ZXTX'`` identifies this file format                                    |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| VER   | Version               | 2            | Format version: 1 byte major, 1 byte minor (e.g. v1.1 = ``0x01 0x01``)     |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| UUID  | UID                   | 16           | Unique file ID (UUID v4)                                                   |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| CMPID | Compression Method ID | 1            | Enum for compression algorithm used                                        |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| CIPID | Cipher Method ID      | 1            | Enum for cipher algorithm used                                             |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| OSIZE | Original Size         | 8            | Original uncompressed text size (uint64, big-endian)                        |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| CSIZE | Compressed Size       | 8            | Stored body size (uint64, big-endian)                                       |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| TSTMP | Timestamp             | 8            | UNIX timestamp (double) when file was created                              |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| HASH  | SHA-256 Hash          | 32           | SHA-256 hash of the original uncompressed text                             |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| CRCC  | CRC32 Checksum        | 4            | CRC32 of the stored body (not a security mechanism)                          |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| CLEN  | Certificate Length    | 2            | Length in bytes of the certificate field (uint16, big-endian)                |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| CERT  | Certificate Data      | Variable     | X.509 or custom certificate describing the signer                            |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| SLEN  | Signature Length      | 2            | Length in bytes of the digital signature (uint16, big-endian)                 |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| SIGN  | Signature             | Variable     | Signature over the packed header **and the stored body** (v1.1; v1.0: header only) |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| CDATA | Stored Data           | Variable     | Compressed (and possibly encrypted) data                                     |

Notes:

* All multi-byte integers are big-endian; version bytes are major-first.
* The *packed header* is every byte from the magic number through the
  certificate data. The signature length/signature follow it; since v1.1
  the stored-data bytes are signed as well.
* CRC32 of the stored body is a transport-integrity convenience, not a
  security mechanism.

