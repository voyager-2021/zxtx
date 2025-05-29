import datetime
import os
from itertools import product

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from zxtx.signer import load_private_key, sign_data
from zxtx.verifier import verify_signature

key_sizes = [1024, 2048, 3072, 4096]
passwords = [
    None,
    b"password123",
    b"anotherpassword",
    os.urandom(16),
    os.urandom(32),
    os.urandom(64),
    os.urandom(1023),
]

params = []
for key_size in key_sizes:
    for pw in passwords:
        mark = (
            pytest.mark.slow
            if key_size > 2048
            else pytest.mark.skipif(False, reason="not slow")
        )
        params.append(pytest.param((key_size, pw), marks=mark))


@pytest.fixture(
    params=params,
    ids=[
        f"{key_size}-{label}"
        for key_size, label in product(
            [1024, 2048, 3072, 4096],
            [
                "NONE",
                "PASSWORD123",
                "ANOTHERPASSWORD",
                "URANDOM16",
                "URANDOM32",
                "URANDOM64",
                "URANDOM1023",
            ],
        )
    ],
)
def keypair_and_cert(tmp_path, request):
    key_size, password = request.param

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
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


def test_sign_and_verify_success(keypair_and_cert):
    _, priv_path, _, cert_path, password = keypair_and_cert
    private_key = load_private_key(priv_path.read_bytes(), password=password)
    certificate = cert_path.read_bytes()

    data = b"Important test data to sign"
    signature = sign_data(private_key, data)
    assert verify_signature(certificate, data, signature)


def test_verify_fails_on_modified_data(keypair_and_cert):
    _, priv_path, _, cert_path, password = keypair_and_cert
    private_key = load_private_key(priv_path.read_bytes(), password=password)
    certificate = cert_path.read_bytes()

    data = b"Important test data to sign"
    signature = sign_data(private_key, data)
    tampered_data = data + b"tampered"

    assert not verify_signature(certificate, tampered_data, signature)


def test_verify_fails_on_wrong_signature(keypair_and_cert):
    _, _, _, cert_path, _ = keypair_and_cert
    certificate = cert_path.read_bytes()

    data = b"Important test data to sign"
    signature = b"not-a-valid-signature"

    assert not verify_signature(certificate, data, signature)
