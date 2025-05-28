# ZXTX

[![Test status](https://github.com/voyager-2021/zxtx/actions/workflows/tests.yml/badge.svg)](https://github.com/voyager-2021/zxtx/actions/workflows/tests.yml)

**ZXTX** is a secure, compressed, and verifiable file format for structured text and binary data. It supports optional encryption, compression, and cryptographic signing, making it ideal for transmitting sensitive files safely.

> Built in Python. Powered by `cryptography`.

## Features

- **AES-256-CTR + HMAC** authenticated encryption
- **LZMA** and **Zlib** compression support
- **Ed25519** and **RSA** signing and verification
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

```bash
zxtx write input.txt output.zxtx --cipher aes256_ctr_hmac --compression zstd --private-key mykey.pem --certificate mycert.pem --password "supersecret"
```

### Reading a ZXTX file

```bash
zxtx read example.zxtx output.txt --private-key mykey.pem --public-key pubkey.pem --password "supersecret"
```

### Dumping metadata

```bash
zxtx dump example.zxtx --public-key pubkey.pem
```

---

## Supported Methods

### Cipher Methods
- `none`
- `aes256_gcm`
- `chacha20_poly1305`

### Compression Methods
- `none`
- `zlib`
- `lzma`
- `brotli`

## Format Specification

The ZXTX file format is formally documented in [`SPECIFICATION.md`](https://github.com/voyager-2021/zxtx/blob/master/SPECIFICATION.md). It defines:

- Magic header
- Versioning
- Field layout
- Signature embedding, etc

## Security Notes

- ZXTX uses AEAD (authenticated encryption) to prevent tampering.
- Private keys can be password-encrypted.
- Signature verification ensures authenticity.
- Don't share your private key. Use a certificate for signing and a public key for verification.

## Python API

```python
from zxtx.highlevel import open

with open("file.zxtx", password=b"secret", public_key=b"...") as f:
    data = f.read_bytes()
```

See the `zxtx.highlevel` module for full API details.

## License

#### [`MIT License`](https://github.com/voyager-2021/zxtx/blob/master/LICENSE) – Copyright (c) 2025 voyager-2021 (ZXTX)
