import pytest
import struct
import sys
import os
from io import BytesIO
from zxtx.constants import CIPHER_METHOD, COMPRESSION_METHOD
from zxtx.highlevel import write_stream_chunked, read_stream_chunked
from zxtx.parser import parse_zxtx_header

def test_truncated_header_raises_value_error():
    # Empty bytes
    with pytest.raises(ValueError, match="bad magic number"):
        parse_zxtx_header(b"")

    # Only magic number
    with pytest.raises(ValueError, match="truncated or malformed header"):
        parse_zxtx_header(b"ZXTX")

    # Truncated versions
    with pytest.raises(ValueError, match="truncated or malformed header"):
        parse_zxtx_header(b"ZXTX\x01")


class NonSeekableBytesIO(BytesIO):
    def seek(self, *args, **kwargs):
        raise OSError("Stream is not seekable")

    def seekable(self):
        return False


def test_chunked_streaming_unencrypted_seekable():
    data = b"Hello, seekable chunked stream world! " * 100
    in_stream = BytesIO(data)
    out_stream = BytesIO()

    write_stream_chunked(
        in_stream,
        out_stream,
        cipher=CIPHER_METHOD.NONE,
        compression=COMPRESSION_METHOD.ZLIB,
    )

    out_stream.seek(0)
    recovered_stream = BytesIO()
    read_stream_chunked(out_stream, recovered_stream)

    assert recovered_stream.getvalue() == data


def test_chunked_streaming_unencrypted_non_seekable():
    data = b"Hello, non-seekable chunked stream world! " * 100
    in_stream = BytesIO(data)
    out_stream = BytesIO()

    write_stream_chunked(
        in_stream,
        out_stream,
        cipher=CIPHER_METHOD.NONE,
        compression=COMPRESSION_METHOD.ZLIB,
    )

    # Wrap in non-seekable class
    non_seekable_out = NonSeekableBytesIO(out_stream.getvalue())
    recovered_stream = BytesIO()
    read_stream_chunked(non_seekable_out, recovered_stream)

    assert recovered_stream.getvalue() == data


def test_cli_load_private_key_with_prompt_unencrypted(tmp_path):
    from zxtx.cli import load_private_key_with_prompt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    # Generate an unencrypted private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_path = tmp_path / "unencrypted.pem"
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    key_obj, password = load_private_key_with_prompt(str(key_path))
    assert key_obj is not None
    assert password is None


def test_cli_load_private_key_with_prompt_encrypted(tmp_path, monkeypatch):
    from zxtx.cli import load_private_key_with_prompt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    # Generate an encrypted private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_path = tmp_path / "encrypted.pem"
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b"secret_pass"),
        )
    )

    # 1. With password provided
    key_obj, password = load_private_key_with_prompt(str(key_path), b"secret_pass")
    assert key_obj is not None
    assert password == b"secret_pass"

    # 2. Mocking prompt (user provides password)
    monkeypatch.setattr("zxtx.cli.get_password_interactive", lambda: b"secret_pass")
    key_obj, password = load_private_key_with_prompt(str(key_path), None)
    assert key_obj is not None
    assert password == b"secret_pass"
