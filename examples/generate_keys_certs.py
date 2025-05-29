import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# 1. Generate RSA Private Key
# private_key = ed25519.Ed25519PrivateKey.generate(
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=1024,
)

public_key = private_key.public_key()

# 2. Save private key to PEM
with open("private_key.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
            # or use BestAvailableEncryption(b"password")
        )
    )

# 3. Save public key to PEM
with open("public_key.pem", "wb") as f:
    f.write(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

# 3. Generate a self-signed certificate
subject = issuer = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FI"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Finland"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Helsinki"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZXTX"),
        x509.NameAttribute(NameOID.COMMON_NAME, "ZXTX Signing Key"),
    ]
)

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.UTC))
    .not_valid_after(
        # Valid for 10 years
        datetime.datetime.now(datetime.UTC)
        + datetime.timedelta(days=3650)
    )
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )
    .sign(private_key, hashes.SHA256())
)

# 4. Save certificate to PEM
with open("certificate.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
