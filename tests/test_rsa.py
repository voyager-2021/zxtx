import datetime
import os
from itertools import product

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from zxtx.constants import CIPHER_METHOD, COMPRESSION_METHOD
from zxtx.parser import parse_zxtx_header, read_zxtx_file
from zxtx.signer import load_private_key, load_public_key
from zxtx.writer import write_zxtx_file

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
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=3650)
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


@pytest.mark.parametrize(
    ("cipher", "compression", "original_data"),
    test_params,
    ids=lambda val: f"DATA_{len(val)//1024}KB" if isinstance(val, bytes) else str(val),
)
def test_encrypted_compressed_rsa(
    tmp_path, keypair_and_cert, cipher, compression, original_data
):
    _, priv_path, pub_path, cert_path, password = keypair_and_cert
    private_key = load_private_key(priv_path.read_bytes(), password=password)
    public_key = load_public_key(pub_path.read_bytes())
    certificate = cert_path.read_bytes()

    zxtx_bytes = write_zxtx_file(
        data=original_data,
        compression_method=compression,
        cipher_method=cipher,
        private_key=private_key,
        public_key=public_key,
        certificate=certificate,
    )

    zxtx_path = tmp_path / "test.zxtx"
    zxtx_path.write_bytes(zxtx_bytes)
    zxtx_bytes = zxtx_path.read_bytes()

    header, body = parse_zxtx_header(zxtx_bytes, private_key=private_key)
    assert header.original_size == len(original_data)

    decrypted = read_zxtx_file(header, body, private_key=private_key)
    assert decrypted == original_data
