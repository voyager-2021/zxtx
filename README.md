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
zxtx write input.txt output.zxtx --cipher aes256_gcm --compression zlib --private-key mykey.pem --certificate mycert.pem
```

### Reading a ZXTX file

```bash
zxtx read example.zxtx output.txt --private-key mykey.pem --public-key pubkey.pem
```

### Dumping metadata

```bash
zxtx dump example.zxtx --public-key pubkey.pem
```

### Streaming (stdin/stdout)

ZXTX supports streaming via `-` for stdin/stdout, enabling pipe chains:

```bash
# Encrypt from stdin, write to file
echo "secret data" | zxtx write - output.zxtx --cipher aes256_gcm

# Read from file, write to stdout
zxtx read input.zxtx - > output.txt

# Full pipe chain: encrypt, then decrypt
cat data.txt | zxtx write - - --cipher aes256_gcm | zxtx read - - > decrypted.txt
```

### Signature Verification

Verify signatures during read operations:

```bash
zxtx read signed.zxtx output.txt --verify --certificate cert.pem
```

### Interactive Password Prompt

If a private key is password-protected and no password is provided, ZXTX will prompt interactively:

```bash
zxtx read encrypted.zxtx output.txt --private-key mykey.pem
# Prompts: Enter private key password (or press Enter for none):
```

### Progress Bars

When writing to files in an interactive terminal, ZXTX displays progress bars:

```bash
zxtx write largefile.bin output.zxtx --compression lzma
# Shows: Writing ZXTX file [████████████] 100%
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

### Basic File Operations

```python
from zxtx.highlevel import open

with open("file.zxtx", password=b"secret", public_key=b"...") as f:
    data = f.read_bytes()
```

### Streaming API

Stream data without loading entire files into memory:

```python
from zxtx.highlevel import read_stream, write_stream, read_stdin, write_stdout

# Read from any binary stream
with open("input.zxtx", "rb") as f:
    data = read_stream(f, private_key=private_key)

# Write to any binary stream
with open("output.zxtx", "wb") as f:
    write_stream(b"secret data", f, cipher=CIPHER_METHOD.AES256_GCM, public_key=public_key)

# Convenience functions for stdin/stdout
data = read_stdin(private_key=private_key)
write_stdout(b"data", cipher=CIPHER_METHOD.AES256_GCM, public_key=public_key)
```

### Chunked Streaming for Large Files

Process large files in chunks to minimize memory usage:

```python
from zxtx.highlevel import read_stream_chunked, write_stream_chunked

# Stream large file with progress callback
with open("large_input.bin", "rb") as infile, open("output.zxtx", "wb") as outfile:
    def progress(current, total):
        print(f"Processed: {current}/{total} bytes")

    write_stream_chunked(
        infile, outfile,
        compression=COMPRESSION_METHOD.ZLIB,
        chunk_size=1024*1024,  # 1MB chunks
        progress_callback=progress
    )

# Read back with chunked streaming
with open("output.zxtx", "rb") as infile, open("recovered.bin", "wb") as outfile:
    read_stream_chunked(infile, outfile, private_key=private_key)
```

See the `zxtx.highlevel` module for full API details.

## License

#### [`MIT License`](https://github.com/voyager-2021/zxtx/blob/master/LICENSE) – Copyright (c) 2025 voyager-2021 (ZXTX)
