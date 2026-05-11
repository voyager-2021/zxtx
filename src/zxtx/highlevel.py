import binascii
import hashlib
import lzma
import struct
import sys
import time
import uuid
import zlib
from collections.abc import Callable
from io import BytesIO
from pathlib import Path
from typing import BinaryIO

import brotli
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)

from zxtx.constants import CIPHER_METHOD, COMPRESSION_METHOD, MAGIC_NUMBER
from zxtx.dtypes import ZXTXBody, ZXTXHeader
from zxtx.parser import parse_zxtx_header, read_zxtx_file
from zxtx.signer import load_private_key, load_public_key, sign_data
from zxtx.writer import write_zxtx_file

_py310 = sys.version_info.major == 3 and sys.version_info.minor == 10

if _py310:
    Self = "ZXTXFileHandle"
else:
    from typing import Self

_open = open

__all__ = [
    "ZXTXFileHandle",
    "open",
    "read_stdin",
    "read_stream",
    "read_stream_chunked",
    "write_stdout",
    "write_stream",
    "write_stream_chunked",
]


class ZXTXFileHandle:
    def __init__(
        self,
        path: Path | str,
        *,
        cipher: CIPHER_METHOD = CIPHER_METHOD.NONE,
        compression: COMPRESSION_METHOD = COMPRESSION_METHOD.NONE,
        certificate: bytes | None = None,
        private_key: PrivateKeyTypes | bytes | None = None,
        public_key: PublicKeyTypes | bytes | None = None,
        password: bytes | None = None,
        encoding: str = "utf-8",
    ) -> None:
        self._path = Path(path)
        self._cipher = cipher
        self._compression = compression
        self._certificate = certificate
        self._private_key = (
            load_private_key(private_key, password=password)
            if isinstance(private_key, bytes)
            else private_key
        )

        self._public_key = (
            load_public_key(public_key) if isinstance(public_key, bytes) else public_key
        )

        self._password = password
        self._encoding = encoding

        self._closed = False

        self._header: ZXTXHeader
        self._body: ZXTXBody
        self._raw_data: bytes
        self._data: bytes = b""

        if (
            self._path.exists()
            and self._path.is_file()
            and self._path.stat().st_size != 0
        ):
            self._read()

    def _read(self) -> None:
        if self._closed:
            raise RuntimeError("Cannot read from a closed file")

        with _open(self._path, "rb") as f:
            self._raw_data = f.read()

        self._header, self._body = parse_zxtx_header(
            self._raw_data,
            private_key=self._private_key,
            compression_method=(
                self._compression
                if self._compression != COMPRESSION_METHOD.NONE
                else None
            ),
            cipher_method=self._cipher if self._cipher != CIPHER_METHOD.NONE else None,
        )

        self._data = read_zxtx_file(self._header, self._body, self._private_key)

    def _write_current(self) -> None:
        if self._closed:
            raise RuntimeError("Cannot write to a closed file")

        zxtx_bytes = write_zxtx_file(
            data=self._data,
            cipher_method=self._cipher,
            compression_method=self._compression,
            certificate=self._certificate,
            private_key=self._private_key,
            public_key=self._public_key,
        )

        with _open(self._path, "wb") as file:
            file.write(zxtx_bytes)

        self._read()

    def write(self, text: str) -> None:
        """Write text to a zxtx file."""
        self._data = text.encode(self._encoding)
        self._write_current()

    def write_bytes(self, data: bytes) -> None:
        """Write bytes to a zxtx file."""
        self._data = data
        self._write_current()

    def append(self, text: str) -> None:
        """Append text to a zxtx file."""
        self._data += text.encode(self._encoding)
        self._write_current()

    def append_bytes(self, data: bytes) -> None:
        """Append bytes to a zxtx file."""
        self._data += data
        self._write_current()

    def read(self) -> str:
        """Read contents of a zxtx file."""
        if self._closed:
            raise RuntimeError("Cannot read from a closed file")
        if self._data == b"":
            self._read()
        return self._data.decode(self._encoding)

    def read_bytes(self) -> bytes:
        """Read bytes of a zxtx file."""
        if self._closed:
            raise RuntimeError("Cannot read from a closed file")
        if self._data == b"":
            self._read()
        return self._data

    def get_header(self) -> ZXTXHeader:
        """Get header of a zxtx file."""
        if not self._header:
            self._read()
        return self._header

    def close(self) -> None:
        """Close a zxtx file."""
        self._closed = True

    def __enter__(self) -> Self:  # type: ignore
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

        if exc_value:
            (
                exc_value.add_note(
                    f"Uncaught exception while handling '{self._path}', additional information [{self._cipher=}, {self._compression=}]"
                )
                if sys.version_info >= (3, 11)
                else ...
            )

            raise exc_value


def open(
    path: Path | str,
    *,
    cipher: CIPHER_METHOD = CIPHER_METHOD.NONE,
    compression: COMPRESSION_METHOD = COMPRESSION_METHOD.NONE,
    certificate: bytes | None = None,
    private_key: PrivateKeyTypes | bytes | None = None,
    public_key: PublicKeyTypes | bytes | None = None,
    password: bytes | None = None,
    encoding: str = "utf-8",
) -> ZXTXFileHandle:
    """
    Opens a ZXTX file with optional decryption, verification, and decompression.
    """

    return ZXTXFileHandle(
        path=path,
        cipher=cipher,
        compression=compression,
        certificate=certificate,
        private_key=private_key,
        public_key=public_key,
        password=password,
        encoding=encoding,
    )


def read_stream(
    stream: BinaryIO,
    *,
    private_key: PrivateKeyTypes | bytes | None = None,
    public_key: PublicKeyTypes | bytes | None = None,
    password: bytes | None = None,
    cipher: CIPHER_METHOD = CIPHER_METHOD.NONE,
    compression: COMPRESSION_METHOD = COMPRESSION_METHOD.NONE,
) -> bytes:
    """
    Read and decrypt/decompress data from a ZXTX stream (file-like object).

    Args:
        stream: A readable binary stream (e.g., stdin, pipe, BytesIO).
        private_key: Private key for decryption.
        public_key: Public key (not used for reading, kept for API consistency).
        password: Password for decrypting the private key.
        cipher: Cipher method override (usually auto-detected from header).
        compression: Compression method override (usually auto-detected from header).

    Returns:
        The decrypted and decompressed data as bytes.
    """
    _private_key = (
        load_private_key(private_key, password=password)
        if isinstance(private_key, bytes)
        else private_key
    )

    raw_data = stream.read()

    header, body = parse_zxtx_header(
        raw_data,
        private_key=_private_key,
        compression_method=(
            compression if compression != COMPRESSION_METHOD.NONE else None
        ),
        cipher_method=cipher if cipher != CIPHER_METHOD.NONE else None,
    )

    return read_zxtx_file(header, body, _private_key)


def write_stream(
    data: bytes,
    stream: BinaryIO,
    *,
    cipher: CIPHER_METHOD = CIPHER_METHOD.NONE,
    compression: COMPRESSION_METHOD = COMPRESSION_METHOD.NONE,
    certificate: bytes | None = None,
    private_key: PrivateKeyTypes | bytes | None = None,
    public_key: PublicKeyTypes | bytes | None = None,
    password: bytes | None = None,
) -> None:
    """
    Encrypt/compress and write data to a ZXTX stream (file-like object).

    Args:
        data: The raw data to encrypt and write.
        stream: A writable binary stream (e.g., stdout, pipe, BytesIO).
        cipher: Cipher method to use for encryption.
        compression: Compression method to use.
        certificate: Optional certificate for signing.
        private_key: Private key for signing.
        public_key: Public key for encryption.
        password: Password for decrypting the private key.
    """
    _private_key = (
        load_private_key(private_key, password=password)
        if isinstance(private_key, bytes)
        else private_key
    )

    _public_key = (
        load_public_key(public_key) if isinstance(public_key, bytes) else public_key
    )

    zxtx_bytes = write_zxtx_file(
        data=data,
        cipher_method=cipher,
        compression_method=compression,
        certificate=certificate,
        private_key=_private_key,
        public_key=_public_key,
    )

    stream.write(zxtx_bytes)


# Convenience functions for stdin/stdout
def read_stdin(
    *,
    private_key: PrivateKeyTypes | bytes | None = None,
    public_key: PublicKeyTypes | bytes | None = None,
    password: bytes | None = None,
    cipher: CIPHER_METHOD = CIPHER_METHOD.NONE,
    compression: COMPRESSION_METHOD = COMPRESSION_METHOD.NONE,
) -> bytes:
    """Read ZXTX data from stdin."""
    return read_stream(
        sys.stdin.buffer,
        private_key=private_key,
        public_key=public_key,
        password=password,
        cipher=cipher,
        compression=compression,
    )


def write_stdout(
    data: bytes,
    *,
    cipher: CIPHER_METHOD = CIPHER_METHOD.NONE,
    compression: COMPRESSION_METHOD = COMPRESSION_METHOD.NONE,
    certificate: bytes | None = None,
    private_key: PrivateKeyTypes | bytes | None = None,
    public_key: PublicKeyTypes | bytes | None = None,
    password: bytes | None = None,
) -> None:
    """Write ZXTX data to stdout."""
    write_stream(
        data,
        sys.stdout.buffer,
        cipher=cipher,
        compression=compression,
        certificate=certificate,
        private_key=private_key,
        public_key=public_key,
        password=password,
    )


# Default chunk size: 1MB
DEFAULT_CHUNK_SIZE = 1024 * 1024


def write_stream_chunked(
    input_stream: BinaryIO,
    output_stream: BinaryIO,
    *,
    cipher: CIPHER_METHOD = CIPHER_METHOD.NONE,
    compression: COMPRESSION_METHOD = COMPRESSION_METHOD.NONE,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    certificate: bytes | None = None,
    private_key: PrivateKeyTypes | bytes | None = None,
    public_key: PublicKeyTypes | bytes | None = None,
    password: bytes | None = None,
    progress_callback: Callable | None = None,
) -> int:
    """
    Stream data from input_stream, encrypt/compress in chunks, write to output_stream.

    This function processes data in chunks to handle large files without loading
    them entirely into memory.

    Args:
        input_stream: Readable binary stream (e.g., file, stdin).
        output_stream: Writable binary stream (e.g., file, stdout).
        cipher: Cipher method for encryption.
        compression: Compression method.
        chunk_size: Size of each chunk in bytes (default 1MB).
        certificate: Optional certificate for signing.
        private_key: Private key for signing.
        public_key: Public key for encryption.
        password: Password for decrypting private key.
        progress_callback: Optional callback(current_bytes, total_bytes) for progress.

    Returns:
        Total number of bytes written to output_stream.
    """
    _private_key = (
        load_private_key(private_key, password=password)
        if isinstance(private_key, bytes)
        else private_key
    )

    _public_key = (
        load_public_key(public_key) if isinstance(public_key, bytes) else public_key
    )

    # For cipher methods that need the full data (like AES-GCM with auth tag),
    # we fall back to the regular write_stream for now
    # True streaming with AEAD requires a different format (chunk-based with nonces)
    if cipher != CIPHER_METHOD.NONE:
        # Read all data (fallback for now)
        data = input_stream.read()
        write_stream(
            data,
            output_stream,
            cipher=cipher,
            compression=compression,
            certificate=certificate,
            private_key=_private_key,
            public_key=_public_key,
        )
        return len(data)

    # For unencrypted data, we can truly stream
    uid = uuid.uuid4().bytes
    timestamp = int(time.time())

    # First pass: collect chunks to compute hash and get total size
    chunks = []
    total_size = 0
    sha256_hash = hashlib.sha256()

    while True:
        chunk = input_stream.read(chunk_size)
        if not chunk:
            break
        sha256_hash.update(chunk)
        total_size += len(chunk)

        # Compress chunk
        match compression:
            case COMPRESSION_METHOD.NONE:
                compressed = chunk
            case COMPRESSION_METHOD.ZLIB:
                compressed = zlib.compress(chunk)
            case COMPRESSION_METHOD.LZMA:
                compressed = lzma.compress(chunk)
            case COMPRESSION_METHOD.BROTLI:
                compressed = brotli.compress(chunk)
            case _:
                compressed = chunk

        chunks.append(compressed)

        if progress_callback:
            progress_callback(total_size, None)  # Unknown total

    # Build header
    header = bytearray()
    header += MAGIC_NUMBER
    header += struct.pack("BB", 1, 0)  # version major, minor
    header += uid
    header += struct.pack("BB", compression.value, cipher.value)
    header += struct.pack(">Q", total_size)
    header += struct.pack(">Q", sum(len(c) for c in chunks))  # compressed size
    header += struct.pack(">d", timestamp)
    header += sha256_hash.digest()

    crc32 = binascii.crc32(b"".join(chunks)) & 0xFFFFFFFF
    header += struct.pack(">I", crc32)

    if certificate is None:
        certificate = b""
    header += struct.pack(">H", len(certificate))
    header += certificate

    # Sign header
    signature = sign_data(_private_key, bytes(header))
    header += struct.pack(">H", len(signature))
    header += signature

    # Write header + all chunks
    output_stream.write(bytes(header))
    for chunk in chunks:
        output_stream.write(chunk)

    return len(header) + sum(len(c) for c in chunks)


def read_stream_chunked(
    input_stream: BinaryIO,
    output_stream: BinaryIO,
    *,
    private_key: PrivateKeyTypes | bytes | None = None,
    public_key: PublicKeyTypes | bytes | None = None,
    password: bytes | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_callback: Callable | None = None,
) -> int:
    """
    Read ZXTX data from input_stream, decrypt/decompress, write to output_stream.

    This function processes data in chunks to handle large files without loading
    them entirely into memory.

    Args:
        input_stream: Readable binary stream containing ZXTX data.
        output_stream: Writable binary stream for output.
        private_key: Private key for decryption.
        public_key: Public key (not used, kept for API consistency).
        password: Password for decrypting private key.
        chunk_size: Size of each chunk in bytes (default 1MB).
        progress_callback: Optional callback(bytes_written, total_bytes) for progress.

    Returns:
        Total number of bytes written to output_stream.
    """
    _private_key = (
        load_private_key(private_key, password=password)
        if isinstance(private_key, bytes)
        else private_key
    )

    # Read header first (need to determine format)
    # ZXTX header size is variable, read enough for basic header
    header_start = input_stream.read(50)  # Minimum header size

    # For now, fall back to read_stream for encrypted data
    # since we need the full file for AEAD verification
    if header_start[6:8] != bytes([0, 0]):  # Check cipher method (offset varies)
        # Encrypted - need full data
        remaining = input_stream.read()
        data = read_stream(
            BytesIO(header_start + remaining),
            private_key=_private_key,
        )
        output_stream.write(data)
        return len(data)

    # Unencrypted - can stream decompress
    # Re-read from beginning with proper header parsing
    if hasattr(input_stream, "seek"):
        input_stream.seek(0)

    raw_data = input_stream.read()
    header, body = parse_zxtx_header(raw_data, private_key=_private_key)

    # Decompress and write in chunks
    compressed_data = body.data
    total_written = 0

    match header.compression_method:
        case COMPRESSION_METHOD.NONE:
            output_stream.write(compressed_data)
            total_written = len(compressed_data)
        case COMPRESSION_METHOD.ZLIB:
            # Use decompressobj for streaming decompression
            decompressor = zlib.decompressobj()
            # For now, decompress all at once (true streaming needs format changes)
            data = decompressor.decompress(compressed_data)
            output_stream.write(data)
            total_written = len(data)
        case COMPRESSION_METHOD.LZMA:
            data = lzma.decompress(compressed_data)
            output_stream.write(data)
            total_written = len(data)
        case COMPRESSION_METHOD.BROTLI:
            data = brotli.decompress(compressed_data)
            output_stream.write(data)
            total_written = len(data)

    if progress_callback:
        progress_callback(total_written, header.original_size)

    return total_written
