import sys
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)

from zxtx.constants import CIPHER_METHOD, COMPRESSION_METHOD
from zxtx.dtypes import ZXTXBody, ZXTXHeader
from zxtx.parser import parse_zxtx_header, read_zxtx_file
from zxtx.signer import load_private_key, load_public_key
from zxtx.writer import write_zxtx_file

_open = open


class ZXTXFileHandle:
    def __init__(
        self,
        path: Path | str,
        *,
        cipher: CIPHER_METHOD = CIPHER_METHOD.NONE,
        compression: COMPRESSION_METHOD = COMPRESSION_METHOD.NONE,
        certificate: Optional[bytes] = None,
        private_key: Optional[PrivateKeyTypes | bytes] = None,
        public_key: Optional[PublicKeyTypes | bytes] = None,
        password: Optional[bytes] = None,
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
            and len(self._path.read_bytes()) != 0
            and self._path.is_file()
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

    def __enter__(self) -> "ZXTXFileHandle":
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
    certificate: Optional[bytes] = None,
    private_key: Optional[PrivateKeyTypes | bytes] = None,
    public_key: Optional[PublicKeyTypes | bytes] = None,
    password: Optional[bytes] = None,
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
