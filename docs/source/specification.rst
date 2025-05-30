ZXTX File Format Specification
==============================

**Version:** 1.0
**Status:** Draft
**Author:** voyager-2021
**Last Updated:** 2025-05-29

Overview
--------

ZXTX (Zipped & eXtended Text eXchange) is a file format designed for secure, compressed text storage. It supports metadata embedding, lossless compression, optional symmetric encryption, and optional cryptographic signing.

Byte Layout (Low-Level)
-----------------------

A ``.zxtx`` file consists of the following sections in sequence:

+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| ID    | **Field**             | **Size**     | **Description**                                                            |
|       |                       | (bytes)      |                                                                            |
+=======+=======================+==============+============================================================================+
| MNUM  | Magic Number          | 4            | ``b'ZXTX'`` identifies this file format                                    |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| VER   | Version               | 2            | Format version: 1 byte major, 1 byte minor (e.g. v1.0 = ``0x01 0x00``)     |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| UUID  | UID                   | 16           | Unique file ID (UUID v4)                                                   |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| CMPID | Compression Method ID | 1            | Enum for compression algorithm used                                        |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| CIPID | Cipher Method ID      | 1            | Enum for cipher/obfuscation algorithm used                                 |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| OSIZE | Original Size         | 8            | Original uncompressed text size (uint64)                                   |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| CSIZE | Compressed Size       | 8            | Compressed data size (uint64)                                              |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| TSTMP | Timestamp             | 8            | UNIX timestamp (double) when file was created                              |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| HASH  | SHA-256 Hash          | 32           | SHA-256 hash of the original uncompressed text                             |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| CRCC  | CRC32 Checksum        | 4            | CRC32 checksum of the compressed data                                      |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| CLEN  | Certificate Length    | 2            | Length in bytes of the certificate field (uint16)                          |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| CERT  | Certificate Data      | Variable     | X.509 for verifying signer                                                 |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| SLEN  | Signature Length      | 2            | Length in bytes of the digital signature (uint16)                          |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| SIGN  | Signature             | Variable     | Signature over header + all fields except compressed data for authenticity |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
| CDATA | Compressed Data       | Variable     | Actual data                                                                |
+-------+-----------------------+--------------+----------------------------------------------------------------------------+
