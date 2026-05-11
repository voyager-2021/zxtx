"""Tests for streaming functionality."""

import datetime
import os
import sys
from io import BytesIO
from itertools import product

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from zxtx.constants import CIPHER_METHOD, COMPRESSION_METHOD
from zxtx.highlevel import read_stream, write_stream
from zxtx.signer import load_private_key, load_public_key
from zxtx.writer import write_zxtx_file

_py310 = sys.version_info.major == 3 and sys.version_info.minor == 10

# Same parametrization as test_rsa.py
key_sizes = [1024, 2048, 3072, 4096]
passwords = [
    None,
    b"password123",
    os.urandom(1023),
]

params = []
ids = []
for key_size in key_sizes:
    for pw in passwords:
        mark = (
            pytest.mark.slow
            if key_size > 1024
            else pytest.mark.skipif(False, reason="not slow")
        )
        label = (
            "NONE"
            if pw is None
            else (
                "PASSWORD123"
                if pw == b"password123"
                else (
                    "ANOTHERPASSWORD"
                    if pw == b"anotherpassword"
                    else f"URANDOM{len(pw)}"
                )
            )
        )
        params.append(pytest.param((key_size, pw), marks=mark))
        ids.append(f"{key_size}-{label}")

data_sizes = [
    os.urandom(1024),
    os.urandom(1024 * 64),
]

test_params = list(
    product(
        [
            CIPHER_METHOD.NONE,
            CIPHER_METHOD.AES256_GCM,
            CIPHER_METHOD.CHACHA20_POLY1305,
        ],
        [
            COMPRESSION_METHOD.NONE,
            COMPRESSION_METHOD.ZLIB,
            COMPRESSION_METHOD.LZMA,
            COMPRESSION_METHOD.BROTLI,
        ],
        data_sizes,
    )
)


@pytest.fixture(params=params, ids=ids)
def keypair_and_cert(tmp_path, request):
    key_size, password = request.param

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()

    # Key integrity sanity check
    assert public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ) == private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ), "Public and private keys do not match!"

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZXTX"),
            x509.NameAttribute(NameOID.COMMON_NAME, "ZXTX Signing Key"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(
            datetime.datetime.now(datetime.UTC if not _py310 else datetime.timezone.utc)
        )
        .not_valid_after(
            datetime.datetime.now(datetime.UTC if not _py310 else datetime.timezone.utc)
            + datetime.timedelta(days=3650)
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )

    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )

    priv_path = tmp_path / "private_key.pem"
    pub_path = tmp_path / "public_key.pem"
    cert_path = tmp_path / "certificate.pem"

    priv_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )
    )
    pub_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    return key_size, priv_path, pub_path, cert_path, password


def generate_rsa_keys():
    """Generate RSA keypair for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def generate_certificate(private_key, public_key):
    """Generate self-signed certificate for testing."""
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZXTX"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        )
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


class TestWriteStream:
    """Tests for write_stream function."""

    def test_write_stream_no_encryption(self):
        """Test writing uncompressed/unencrypted data to stream."""
        output_stream = BytesIO()
        data = b"Hello, streaming world!"

        write_stream(
            data,
            output_stream,
            cipher=CIPHER_METHOD.NONE,
            compression=COMPRESSION_METHOD.NONE,
        )

        output_stream.seek(0)
        result = output_stream.read()

        # Should be a valid ZXTX file
        assert result.startswith(b"ZXTX")

    def test_write_stream_with_compression(self):
        """Test writing compressed data to stream."""
        output_stream = BytesIO()
        data = b"Hello, streaming world! " * 100

        write_stream(
            data,
            output_stream,
            cipher=CIPHER_METHOD.NONE,
            compression=COMPRESSION_METHOD.ZLIB,
        )

        output_stream.seek(0)
        result = output_stream.read()

        assert result.startswith(b"ZXTX")
        # Compressed data should be smaller
        assert len(result) < len(data) + 100  # Header overhead

    def test_write_stream_with_encryption(self):
        """Test writing encrypted data to stream."""
        private_key, public_key = generate_rsa_keys()
        output_stream = BytesIO()
        data = b"Secret streaming message"

        write_stream(
            data,
            output_stream,
            cipher=CIPHER_METHOD.AES256_GCM,
            compression=COMPRESSION_METHOD.NONE,
            private_key=private_key,
            public_key=public_key,
        )

        output_stream.seek(0)
        result = output_stream.read()

        assert result.startswith(b"ZXTX")
        assert len(result) > len(data)  # Encrypted should be larger


class TestReadStream:
    """Tests for read_stream function."""

    def test_read_stream_no_encryption(self):
        """Test reading uncompressed/unencrypted data from stream."""
        # First write to stream
        output_stream = BytesIO()
        original_data = b"Hello, streaming world!"

        write_stream(
            original_data,
            output_stream,
            cipher=CIPHER_METHOD.NONE,
            compression=COMPRESSION_METHOD.NONE,
        )

        # Now read from stream
        output_stream.seek(0)
        result = read_stream(output_stream)

        assert result == original_data

    def test_read_stream_with_compression(self):
        """Test reading compressed data from stream."""
        output_stream = BytesIO()
        original_data = b"Hello, streaming world! " * 100

        write_stream(
            original_data,
            output_stream,
            cipher=CIPHER_METHOD.NONE,
            compression=COMPRESSION_METHOD.ZLIB,
        )

        output_stream.seek(0)
        result = read_stream(output_stream)

        assert result == original_data

    def test_read_stream_with_encryption(self):
        """Test reading encrypted data from stream."""
        private_key, public_key = generate_rsa_keys()
        output_stream = BytesIO()
        original_data = b"Secret streaming message"

        write_stream(
            original_data,
            output_stream,
            cipher=CIPHER_METHOD.AES256_GCM,
            compression=COMPRESSION_METHOD.NONE,
            private_key=private_key,
            public_key=public_key,
        )

        output_stream.seek(0)
        result = read_stream(output_stream, private_key=private_key)

        assert result == original_data

    def test_read_stream_all_ciphers(self):
        """Test read/write with all supported cipher methods."""
        private_key, public_key = generate_rsa_keys()
        original_data = b"Test data for all ciphers"

        ciphers = [
            CIPHER_METHOD.NONE,
            CIPHER_METHOD.AES256_GCM,
            CIPHER_METHOD.CHACHA20_POLY1305,
            CIPHER_METHOD.AES256_CTR_HMAC,
        ]

        for cipher in ciphers:
            output_stream = BytesIO()

            write_stream(
                original_data,
                output_stream,
                cipher=cipher,
                compression=COMPRESSION_METHOD.NONE,
                private_key=private_key,
                public_key=public_key,
            )

            output_stream.seek(0)
            result = read_stream(output_stream, private_key=private_key)

            assert result == original_data, f"Failed for cipher {cipher}"


class TestRoundtrip:
    """Tests for write/read roundtrip via streams."""

    def test_roundtrip_bytesio(self):
        """Test full roundtrip using BytesIO."""
        private_key, public_key = generate_rsa_keys()
        original_data = b"Roundtrip test data"

        # Write
        stream = BytesIO()
        write_stream(
            original_data,
            stream,
            cipher=CIPHER_METHOD.AES256_GCM,
            compression=COMPRESSION_METHOD.ZLIB,
            private_key=private_key,
            public_key=public_key,
        )

        # Read back
        stream.seek(0)
        result = read_stream(stream, private_key=private_key)

        assert result == original_data

    def test_roundtrip_large_data(self):
        """Test roundtrip with larger data."""
        private_key, public_key = generate_rsa_keys()
        original_data = b"X" * (1024 * 1024)  # 1MB of data

        stream = BytesIO()
        write_stream(
            original_data,
            stream,
            cipher=CIPHER_METHOD.AES256_GCM,
            compression=COMPRESSION_METHOD.ZLIB,
            private_key=private_key,
            public_key=public_key,
        )

        stream.seek(0)
        result = read_stream(stream, private_key=private_key)

        assert result == original_data


class TestStreamingVsFileAPI:
    """Tests comparing streaming API with file API."""

    def test_stream_and_file_produce_same_output(self, tmp_path):
        """Verify that streaming and file APIs produce identical ZXTX files."""

        private_key, public_key = generate_rsa_keys()
        data = b"Test data for comparison"

        # Write via stream API
        stream = BytesIO()
        write_stream(
            data,
            stream,
            cipher=CIPHER_METHOD.AES256_GCM,
            compression=COMPRESSION_METHOD.ZLIB,
            private_key=private_key,
            public_key=public_key,
        )
        stream_output = stream.getvalue()

        # Write via low-level API
        file_output = write_zxtx_file(
            data=data,
            cipher_method=CIPHER_METHOD.AES256_GCM,
            compression_method=COMPRESSION_METHOD.ZLIB,
            private_key=private_key,
            public_key=public_key,
        )

        # Both should produce valid ZXTX files
        assert stream_output.startswith(b"ZXTX")
        assert file_output.startswith(b"ZXTX")

        # The outputs should have the same structure (sizes may vary slightly due to random nonces)
        assert len(stream_output) == len(file_output)


class TestStreamingEdgeCases:
    """Tests for edge cases in streaming."""

    def test_empty_data(self):
        """Test streaming empty data."""
        stream = BytesIO()

        write_stream(
            b"",
            stream,
            cipher=CIPHER_METHOD.NONE,
            compression=COMPRESSION_METHOD.NONE,
        )

        stream.seek(0)
        result = read_stream(stream)

        assert result == b""

    def test_binary_data_with_null_bytes(self):
        """Test streaming binary data with null bytes."""
        original_data = bytes(range(256)) * 10  # All byte values repeated

        stream = BytesIO()
        write_stream(
            original_data,
            stream,
            cipher=CIPHER_METHOD.NONE,
            compression=COMPRESSION_METHOD.NONE,
        )

        stream.seek(0)
        result = read_stream(stream)

        assert result == original_data


class TestStreamingWithRSA:
    """Tests for streaming with RSA encryption."""

    @pytest.mark.parametrize(
        ("cipher", "compression", "original_data"),
        test_params,
        ids=lambda val: (
            f"DATA_{len(val) // 1024}KB" if isinstance(val, bytes) else str(val)
        ),
    )
    def test_streaming_encrypted_compressed_rsa(
        self, tmp_path, keypair_and_cert, cipher, compression, original_data
    ):
        """Test streaming encryption/compression with parametrized RSA keys."""
        _, priv_path, pub_path, cert_path, password = keypair_and_cert
        private_key = load_private_key(priv_path.read_bytes(), password=password)
        public_key = load_public_key(pub_path.read_bytes())
        certificate = cert_path.read_bytes()

        # Write via streaming API
        stream = BytesIO()
        write_stream(
            original_data,
            stream,
            cipher=cipher,
            compression=compression,
            private_key=private_key,
            public_key=public_key,
            certificate=certificate,
        )

        stream.seek(0)
        zxtx_bytes = stream.read()

        # Verify it's a valid ZXTX file
        assert zxtx_bytes.startswith(b"ZXTX")

        # Read back via streaming API
        stream.seek(0)
        decrypted = read_stream(stream, private_key=private_key)

        assert decrypted == original_data


class TestStreamingWithAES256CTRHMAC:
    """Additional tests for AES256_CTR_HMAC cipher which requires 64-byte session keys."""

    def test_aes256_ctr_hmac_streaming_2048(self):
        """Test AES256_CTR_HMAC with RSA-2048 (minimum required)."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        original_data = os.urandom(1024)

        stream = BytesIO()
        write_stream(
            original_data,
            stream,
            cipher=CIPHER_METHOD.AES256_CTR_HMAC,
            compression=COMPRESSION_METHOD.ZLIB,
            private_key=private_key,
            public_key=public_key,
        )

        stream.seek(0)
        decrypted = read_stream(stream, private_key=private_key)

        assert decrypted == original_data
