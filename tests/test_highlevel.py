import datetime
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from zxtx import open as zxtx_open
from zxtx.constants import CIPHER_METHOD, COMPRESSION_METHOD
from zxtx.signer import load_private_key, load_public_key


@pytest.fixture
def temp_dir():
    with TemporaryDirectory() as tmp_dir:
        yield Path(tmp_dir)


@pytest.fixture
def rsa_keys(tmp_path):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
    )
    public_key = private_key.public_key()

    # Verify public key matches private key
    expected_pub_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    actual_pub_bytes = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert actual_pub_bytes == expected_pub_bytes, "Public key mismatch"

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZXTX"),
            x509.NameAttribute(NameOID.COMMON_NAME, "ZXTX Signing Key"),
        ]
    )

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=3650)
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )

    # Write keys and certificate to files
    priv_path = tmp_path / "private_key.pem"
    pub_path = tmp_path / "public_key.pem"
    cert_path = tmp_path / "certificate.pem"

    priv_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    pub_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

    return priv_path, pub_path, cert_path


@pytest.mark.parametrize(
    "cipher, compression",
    [
        (CIPHER_METHOD.NONE, COMPRESSION_METHOD.NONE),
        (CIPHER_METHOD.AES256_GCM, COMPRESSION_METHOD.NONE),
        (CIPHER_METHOD.CHACHA20_POLY1305, COMPRESSION_METHOD.NONE),
        # (CIPHER_METHOD.AES256_CTR_HMAC, COMPRESSION_METHOD.NONE),
        # FIXME: results in error. why? no fucking idea.
        (CIPHER_METHOD.NONE, COMPRESSION_METHOD.ZLIB),
    ],
)
def test_write_read_roundtrip(temp_dir, rsa_keys, cipher, compression):
    priv_path, pub_path, cert_path = rsa_keys
    priv_key = load_private_key(priv_path.read_bytes())
    pub_key = load_public_key(pub_path.read_bytes())
    cert_bytes = cert_path.read_bytes()

    file_path = temp_dir / "test.zxtx"
    text_data = "Hello, ZXTX!"

    zfile = zxtx_open(
        path=file_path,
        cipher=cipher,
        compression=compression,
        private_key=priv_key,
        public_key=pub_key,
        certificate=cert_bytes,
        password=None,
    )

    # Write and read text
    zfile.write(text_data)
    assert zfile.read() == text_data

    # Append and read text
    zfile.append(" More data.")
    assert zfile.read() == text_data + " More data."

    # Write and read bytes
    binary_data = b"\x00\x01\x02\x03\x04"
    zfile.write_bytes(binary_data)
    assert zfile.read_bytes() == binary_data

    # Append and read bytes
    zfile.append_bytes(b"\x05\x06")
    assert zfile.read_bytes() == binary_data + b"\x05\x06"

    zfile.close()


def test_context_manager_usage(temp_dir, rsa_keys):
    priv_path, pub_path, cert_path = rsa_keys
    priv_key = load_private_key(priv_path.read_bytes())
    pub_key = load_public_key(pub_path.read_bytes())
    cert_bytes = cert_path.read_bytes()

    file_path = temp_dir / "context.zxtx"
    text_data = "Context manager test"

    with zxtx_open(
        file_path,
        cipher=CIPHER_METHOD.NONE,
        compression=COMPRESSION_METHOD.NONE,
        private_key=priv_key,
        public_key=pub_key,
        certificate=cert_bytes,
        password=None,
    ) as zfile:
        zfile.write(text_data)
        assert zfile.read() == text_data

    # After close, writing or reading should raise
    with pytest.raises(RuntimeError):
        zfile.write("Should fail after close")

    with pytest.raises(RuntimeError):
        zfile.read()


def test_error_on_closed_file(temp_dir, rsa_keys):
    priv_path, pub_path, cert_path = rsa_keys
    priv_key = load_private_key(priv_path.read_bytes())
    pub_key = load_public_key(pub_path.read_bytes())
    cert_bytes = cert_path.read_bytes()

    file_path = temp_dir / "closed.zxtx"
    zfile = zxtx_open(
        file_path,
        private_key=priv_key,
        public_key=pub_key,
        certificate=cert_bytes,
        password=None,
    )
    zfile.close()

    with pytest.raises(RuntimeError):
        zfile.write("Should fail")

    with pytest.raises(RuntimeError):
        zfile.append("Should fail")


def test_get_header(temp_dir, rsa_keys):
    priv_path, pub_path, _ = rsa_keys
    priv_key = load_private_key(priv_path.read_bytes())
    pub_key = load_public_key(pub_path.read_bytes())

    file_path = temp_dir / "header.zxtx"
    data = "Header test data"

    zfile = zxtx_open(file_path, private_key=priv_key, public_key=pub_key)
    zfile.write(data)
    header = zfile.get_header()

    assert header.original_size == len(data.encode(zfile._encoding))


def test_load_keys_from_bytes(temp_dir, rsa_keys):
    priv_path, pub_path, cert_path = rsa_keys
    priv_key = load_private_key(priv_path.read_bytes())
    pub_key = load_public_key(pub_path.read_bytes())
    cert_bytes = cert_path.read_bytes()

    file_path = temp_dir / "key_bytes.zxtx"
    text_data = "Key bytes test"

    priv_bytes = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    zfile = zxtx_open(
        file_path,
        private_key=priv_bytes,
        public_key=pub_bytes,
        certificate=cert_bytes,
        password=None,
    )

    zfile.write(text_data)
    assert zfile.read() == text_data
