# ZXTX

[![Test status](https://github.com/voyager-2021/zxtx/actions/workflows/tests.yml/badge.svg)](https://github.com/voyager-2021/zxtx/actions/workflows/tests.yml)

**ZXTX** is a secure, compressed, and verifiable file format for structured text and binary data. It supports optional encryption, compression, and cryptographic signing, making it ideal for transmitting sensitive files safely.

> Built in Python (3.10+). Powered by `cryptography`.

## Features

- **AES-256-CTR + HMAC**, **AES-256-GCM**, and **ChaCha20-Poly1305** authenticated encryption
- **LZMA**, **Zlib**, and **Brotli** compression support
- **Ed25519** and **RSA** signing and verification
- Signatures cover the header **and** the body (format v1.1)
- AEAD associated-data binding between header and body prevents ciphertext splicing
- **Structured file format** with typed headers and bodies
- **Command-line interface (CLI)** for reading, writing, and inspecting `.zxtx` files

## Installation

```bash
pip install zxtx
```

Or with [PDM](https://pdm.fming.dev):

```bash
pdm add zxtx
```

## Usage

### Writing a ZXTX file

Methods are passed as numeric ids (run `zxtx -h` for the full list):

```bash
# id 3 = aes256_ctr_hmac, id 2 = lzma
zxtx write input.txt output.zxtx --cipher 3 --compression 2 \
    --private-key mykey.pem --certificate mycert.pem --public-key mykey_pub.pem \
    --password "key-file-password"
```

- `--private-key` signs the file (a file without it remains unsigned).
- `--public-key` wraps the content-encryption session key (required for ciphers 1–3).
- `--password` decrypts a password-protected private key file.

### Reading a ZXTX file

```bash
zxtx read example.zxtx output.txt --private-key mykey.pem --public-key pubkey.pem --password "key-file-password"
```

Providing `--public-key` or `--certificate` turns on signature verification:
a modified or foreign-signed file is rejected, and an *unsigned* file read with those flags fails loudly (re-run without verification flags to read unsigned files).

### Dumping metadata

```bash
zxtx dump example.zxtx --public-key pubkey.pem
```

---

## Supported Methods

### Cipher Methods
- `0` — `none`
- `1` — `aes256_gcm`
- `2` — `chacha20_poly1305`
- `3` — `aes256_ctr_hmac`

### Compression Methods
- `0` — `none`
- `1` — `zlib`
- `2` — `lzma`
- `3` — `brotli`

## Format Specification

The ZXTX file format is formally documented in [`SPECIFICATION.md`](SPECIFICATION.md). It defines:

- Magic header
- Versioning (`v1.1` current; `v1.0` files remain readable)
- Field layout
- Signature coverage (header + body) and AAD binding
- Session-key wrapping and HKDF subkey derivation, etc

## Security Notes

- ZXTX uses AEAD or encrypt-then-MAC (authenticated encryption) to prevent tampering.
- Since format v1.1, signatures cover the header **and** the body, and encrypted bodies are cryptographically bound to their header via associated data. Verifying a file therefore detects any tampering — provided the verification key is pinned outside the file (pass `--public-key`/`--certificate` when reading). A certificate merely *embedded in the file* is not a trust anchor by itself.
- CRC32 is a transport-integrity convenience only, never a security check.
- Decompression is bounded by the declared original size to blunt decompression bombs.
- Private keys can be password-encrypted; passwords are only used to unlock PEM files and are not kept after loading.
- Writes are atomic (temp file + rename), so an interrupted write cannot corrupt the previous file.
- Don't share your private key. Use a certificate for signing and a public key for verification.

## Python API

```python
from zxtx.highlevel import open

with open("file.zxtx", password=b"secret", public_key=b"...") as f:
    data = f.read_bytes()
```

`ZXTXFileHandle.signature_verified` reports the verification state of the loaded file: `True` (verified), `False` (signed but no verification key given), or `None` (unsigned). When writing, pass `create=True` to replace an existing file without parsing its previous contents.

See the `zxtx.highlevel` module for full API details.

## License

#### [`MIT License`](LICENSE) – Copyright (c) 2025 voyager-2021 (ZXTX)

