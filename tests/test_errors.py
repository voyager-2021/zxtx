"""T12: exception hierarchy.

``ZXTXError(ValueError)`` with ``FormatError``, ``SignatureError`` and
``DecryptionError``.  Subclassing ``ValueError`` keeps existing callers
(``except ValueError``) working.
"""

import os

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from zxtx.constants import CIPHER_METHOD, COMPRESSION_METHOD
from zxtx.errors import (
    DecryptionError,
    FormatError,
    SignatureError,
    ZXTXError,
)
from zxtx.parser import parse_zxtx_header, read_zxtx_file
from zxtx.writer import write_zxtx_file


def test_hierarchy_is_valueerror_based():
    for cls in (ZXTXError, FormatError, SignatureError, DecryptionError):
        assert issubclass(cls, ValueError)


def test_bad_magic_is_format_error():
    with pytest.raises(FormatError):
        parse_zxtx_header(b"XXXX" + os.urandom(84))


def test_bad_signature_is_signature_error():
    signer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    raw = write_zxtx_file(
        data=b"signed payload",
        compression_method=COMPRESSION_METHOD.NONE,
        cipher_method=CIPHER_METHOD.NONE,
        private_key=signer,
    )
    with pytest.raises(SignatureError):
        parse_zxtx_header(raw, verification_key=other.public_key())


def test_wrong_recipient_key_is_decryption_error():
    recipient = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    stranger = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    raw = write_zxtx_file(
        data=b"for someone else",
        compression_method=COMPRESSION_METHOD.NONE,
        cipher_method=CIPHER_METHOD.AES256_GCM,
        private_key=None,
        public_key=recipient.public_key(),
    )
    header, body = parse_zxtx_header(raw, private_key=stranger)
    with pytest.raises(DecryptionError):
        read_zxtx_file(header, body, stranger)


def test_type_errors_stay_outside_the_hierarchy() -> None:
    # usage errors (e.g. wrong input type) are deliberately outside the
    # caught-by-ValueError hierarchy
    with pytest.raises(TypeError):
        parse_zxtx_header("not bytes")  # type: ignore[arg-type]
