import os
import sys
import tempfile
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

_py310 = sys.version_info.major == 3 and sys.version_info.minor == 10

if _py310:
    Self = "ZXTXFileHandle"
else:
    from typing import Self

_open = open


def _atomic_write(target: Path, payload: bytes) -> None:
    """Write ``payload`` to ``target`` atomically (temp file + rename)."""
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=parent)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, target)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


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
        create: bool = False,
    ) -> None:
        """
        Args:
            path: target ``.zxtx`` file.
            cipher / compression: method for new writes; when reading,
                ``NONE`` means "auto-detect from the file header".
            certificate: X.509 PEM bytes embedded when writing; also used
                as the signature verification anchor when reading (unless
                ``public_key`` is provided).
            private_key / public_key: key objects or PEM bytes.
            password: password used to decrypt an encrypted private key.
            encoding: text encoding for text-level read/write.
            create: when True the existing file at ``path`` is never
                parsed/decrypted; the handle starts empty and only
                ``write`` / ``append`` populate it (used by ``zxtx write``
                so pre-existing invalid target files do not abort the
                overwrite).
        """
        self._path = Path(path)
        self._cipher = cipher
        self._compression = compression
        self._certificate = certificate
        self._create = create

        self._private_key = (
            load_private_key(private_key, password=password)
            if isinstance(private_key, bytes)
            else private_key
        )

        self._public_key = (
            load_public_key(public_key) if isinstance(public_key, bytes) else public_key
        )

        # Verification anchor when reading: a public key if provided,
        # otherwise the supplied X.509 certificate bytes.
        self._verification_key = (
            self._public_key
            if self._public_key is not None
            else self._certificate
        )

        # The password is only needed once, to decrypt the private key
        # PEM; do not retain it for the lifetime of the handle.
        self._password = None
        self._encoding = encoding

        self._closed = False

        self._header: Optional[ZXTXHeader] = None
        self._body: Optional[ZXTXBody] = None
        self._raw_data: bytes = b""
        self._data: bytes = b""
        self._loaded = False
        self._signature_verified: Optional[bool] = None

        if self._path.exists():
            if not self._path.is_file():
                raise ValueError(f"Not a file: {self._path}")

            if create:
                # Overwrite-only mode: never read or parse existing content.
                return

            if self._path.stat().st_size == 0:
                # An empty file is valid for writing but has no contents
                # to read yet.
                return

            self._read()

    def _read(self, *, verify: bool = True) -> None:
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
            # Inline self-checks after our own writes re-validate the
            # round trip but skip signature verification (the file was
            # this process' own output moments ago).
            verification_key=self._verification_key if verify else None,
        )

        self._data = read_zxtx_file(self._header, self._body, self._private_key)
        self._loaded = True

        # Deterministic verification state:
        #   True  — signature verified against the supplied anchor
        #   False — signed file, but no anchor was provided
        #   None  — unsigned file
        if verify and self._verification_key is not None:
            self._signature_verified = True  # parse would raise otherwise
        elif self._header.signature:
            self._signature_verified = False
        else:
            self._signature_verified = None

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

        _atomic_write(self._path, zxtx_bytes)

        if self._cipher == CIPHER_METHOD.NONE or self._private_key is not None:
            # Round-trip self-check whenever we can decrypt our own output.
            # Verify the freshly written signature when we hold both the
            # signing key and a verification anchor; without the signing
            # key the file is unsigned and the anchor must not reject it.
            self._read(
                verify=self._verification_key is not None
                and self._private_key is not None
            )
        else:
            # Encrypting for a recipient whose private key we do not hold:
            # the round trip cannot be validated locally.  Reading this
            # handle will raise a clear "no private key" error on demand.
            self._loaded = False

    def write(self, text: str) -> None:
        """Write text to a zxtx file."""
        if self._closed:
            raise RuntimeError("Cannot write to a closed file")
        self._data = text.encode(self._encoding)
        self._write_current()

    def write_bytes(self, data: bytes) -> None:
        """Write bytes to a zxtx file."""
        if self._closed:
            raise RuntimeError("Cannot write to a closed file")
        self._data = data
        self._write_current()

    def append(self, text: str) -> None:
        """Append text to a zxtx file."""
        if self._closed:
            raise RuntimeError("Cannot write to a closed file")
        self._data += text.encode(self._encoding)
        self._write_current()

    def append_bytes(self, data: bytes) -> None:
        """Append bytes to a zxtx file."""
        if self._closed:
            raise RuntimeError("Cannot write to a closed file")
        self._data += data
        self._write_current()

    def read(self) -> str:
        """Read contents of a zxtx file."""
        if self._closed:
            raise RuntimeError("Cannot read from a closed file")
        if not self._loaded:
            self._read()
        return self._data.decode(self._encoding)

    def read_bytes(self) -> bytes:
        """Read bytes of a zxtx file."""
        if self._closed:
            raise RuntimeError("Cannot read from a closed file")
        if not self._loaded:
            self._read()
        return self._data

    def get_header(self) -> ZXTXHeader:
        """Get header of a zxtx file."""
        if self._closed:
            raise RuntimeError("Cannot read from a closed file")
        if not self._loaded:
            self._read()
        return self._header

    def get_body(self) -> ZXTXBody:
        """Get the parsed body of a zxtx file."""
        if self._closed:
            raise RuntimeError("Cannot read from a closed file")
        if not self._loaded:
            self._read()
        return self._body

    @property
    def signature_verified(self) -> Optional[bool]:
        """
        Verification state of the loaded file:

        * ``True``  — signed and verified against a provided anchor
        * ``False`` — signed, but no verification key was provided
        * ``None``  — file is unsigned

        Returns ``None`` while nothing has been read yet.
        """
        if not self._loaded:
            return None
        return self._signature_verified

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
    certificate: Optional[bytes] = None,
    private_key: Optional[PrivateKeyTypes | bytes] = None,
    public_key: Optional[PublicKeyTypes | bytes] = None,
    password: Optional[bytes] = None,
    encoding: str = "utf-8",
    create: bool = False,
) -> ZXTXFileHandle:
    """
    Opens a ZXTX file handle with optional decryption, decompression and
    signature verification.

    When ``public_key`` or ``certificate`` is provided, the file's
    signature is verified before any content is returned, and reading
    fails closed on an invalid signature.
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
        create=create,
    )

