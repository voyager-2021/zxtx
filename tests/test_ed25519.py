import datetime
import os
from itertools import product

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from zxtx.constants import CIPHER_METHOD, COMPRESSION_METHOD
from zxtx.parser import parse_zxtx_header, read_zxtx_file
from zxtx.signer import load_private_key, load_public_key
from zxtx.writer import write_zxtx_file

data_sizes = [
    os.urandom(1024),
    os.urandom(1024 * 64),
]

test_params = list(
    product(
        [
            COMPRESSION_METHOD.NONE,
            COMPRESSION_METHOD.ZLIB,
            COMPRESSION_METHOD.LZMA,
            COMPRESSION_METHOD.BROTLI,
        ],
        data_sizes,
    )
)


@pytest.fixture(
    params=[
        None,
        b"password123",
        b"anotherpassword",
        os.urandom(128),
        os.urandom(256),
        os.urandom(512),
        os.urandom(1023),
    ],
    ids=[
        "none".upper(),
        "password123".upper(),
        "anotherpassword".upper(),
        "urandom128".upper(),
        "urandom256".upper(),
        "urandom512".upper(),
        "urandom1023".upper(),
    ],
)
def keypair_and_cert(tmp_path, request):
    """Parametrized: Generates keypair + cert using password param."""
    password = request.param

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

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
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=3650)
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, None)
    )

    # Save to files
    priv_path = tmp_path / "private_key.pem"
    pub_path = tmp_path / "public_key.pem"
    cert_path = tmp_path / "certificate.pem"

    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )

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

    return priv_path, pub_path, cert_path, password


@pytest.mark.parametrize(
    ("compression", "original_data"),
    test_params,
    ids=lambda val: f"DATA_{len(val)//1024}KB" if isinstance(val, bytes) else str(val),
)
def test_unencrypted_compressed_ed25519(
    tmp_path, keypair_and_cert, compression, original_data
):
    priv_path, pub_path, cert_path, password = keypair_and_cert
    private_key = load_private_key(priv_path.read_bytes(), password=password)
    public_key = load_public_key(pub_path.read_bytes())
    certificate = cert_path.read_bytes()

    zxtx_bytes = write_zxtx_file(
        data=original_data,
        compression_method=compression,
        cipher_method=CIPHER_METHOD.NONE,
        private_key=private_key,
        public_key=public_key,
        certificate=certificate,
    )

    zxtx_path = tmp_path / "test.zxtx"
    zxtx_path.write_bytes(zxtx_bytes)

    header, body = parse_zxtx_header(zxtx_path.read_bytes(), private_key=private_key)

    decrypted = read_zxtx_file(header, body, private_key=private_key)

    # Parse header
    parsed_header, _ = parse_zxtx_header(zxtx_path.read_bytes())
    assert parsed_header.original_size == len(original_data)

    # Decrypt and read
    assert decrypted == original_data
