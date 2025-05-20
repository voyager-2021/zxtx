from pathlib import Path

from zxtx.constants import CIPHER_METHOD, COMPRESSION_METHOD
from zxtx.signer import load_private_key, load_public_key
from zxtx.writer import write_zxtx_file

# Load private key
with open(
    Path(
        f"~/Documents/.id_rsa/zxtx_root_private_key.pem"
    ).expanduser(),  # Replace with your own private key
    "rb",
) as f:
    private_key = load_private_key(f.read(), password=None)

# Load public key
with open(
    Path("~/Documents/.id_rsa/zxtx_root_public_key.pem").expanduser(), "rb"
) as f:  # Replace with your own public key or use zxtx root public key
    public_key = load_public_key(f.read())

# Load cert
with open(
    Path("~/Documents/.id_rsa/zxtx_root_cert.pem").expanduser(), "rb"
) as f:  # Replace with your own cert or use zxtx root cert
    certificate = f.read()

# Write ZXTX file
zxtx_bytes = write_zxtx_file(
    data="Hello world from ZXTX!".encode(),
    compression_method=COMPRESSION_METHOD.LZMA,
    cipher_method=CIPHER_METHOD.AES256_GCM,
    private_key=private_key,
    public_key=public_key,
    certificate=certificate,
)

# Save to file
with open("example2.zxtx", "wb") as f:
    f.write(zxtx_bytes)
