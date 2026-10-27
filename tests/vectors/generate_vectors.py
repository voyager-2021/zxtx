"""Golden test vectors for the ZXTX v1.0 and v1.1 readers.

Regenerate with::

    python tests/vectors/generate_vectors.py

The script writes fixed RSA-2048 recipient/signing keys under ``keys/``
and one file per (format version, signed, cipher, compression) into
``v<1_0|1_1>/{signed,unsigned}/``.  OAEP wrapping uses its own internal
randomness, so re-running the script changes ciphertext bytes; only the
committed artifacts are treated as golden files.

The v1.0 CTR+HMAC files are hand-built legacy files (64-byte session key
split directly into AES/HMAC keys, no HKDF, no AAD, header-only
signature), matching the documented v1.0 layout.
"""

import hashlib
import os
import struct
import uuid
import zlib
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as crypto_hmac
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from zxtx.constants import CIPHER_METHOD, COMPRESSION_METHOD
from zxtx.dtypes import FORMAT_VERSION, FORMAT_VERSION_V1, ZXTXHeader, pack_header
from zxtx.signer import load_private_key, load_public_key, sign_data
from zxtx.writer import write_zxtx_file

# The exact plaintext every golden file encodes.  Kept deterministic so
# tests can assert the full payload after a read.
GOLDEN_PAYLOAD = (
    b"ZXTX golden vector payload for reader compatibility tests\n" * 4
    + b"tail with binary bytes \x00\x01\x02\x7f\xff"
)

VECTORS = Path(__file__).parent
KEYS_DIR = VECTORS / "keys"

CIPHERS = {
    "none": CIPHER_METHOD.NONE,
    "aes256_gcm": CIPHER_METHOD.AES256_GCM,
    "chacha20_poly1305": CIPHER_METHOD.CHACHA20_POLY1305,
    "aes256_ctr_hmac": CIPHER_METHOD.AES256_CTR_HMAC,
}
COMPRESSIONS = {
    "none": COMPRESSION_METHOD.NONE,
    "zlib": COMPRESSION_METHOD.ZLIB,
    "lzma": COMPRESSION_METHOD.LZMA,
    "brotli": COMPRESSION_METHOD.BROTLI,
}


def _write_key_files(recipient, signer) -> None:
    KEYS_DIR.mkdir(exist_ok=True)
    (KEYS_DIR / "recipient_private.pem").write_bytes(
        recipient.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    (KEYS_DIR / "recipient_public.pem").write_bytes(
        recipient.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )
    )
    (KEYS_DIR / "signer_private.pem").write_bytes(
        signer.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    (KEYS_DIR / "signer_public.pem").write_bytes(
        signer.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )


def _load_key_files():
    return (
        load_private_key((KEYS_DIR / "recipient_private.pem").read_bytes()),
        load_public_key((KEYS_DIR / "recipient_public.pem").read_bytes()),
        load_private_key((KEYS_DIR / "signer_private.pem").read_bytes()),
        load_public_key((KEYS_DIR / "signer_public.pem").read_bytes()),
    )


def build_v1_0_ctr_hmac_body(recipient_public, data: bytes):
    """Legacy v1.0 body: 64-byte session key split into AES/HMAC halves."""
    legacy_session = os.urandom(64)  # enc_key || mac_key, no HKDF
    nonce = os.urandom(16)

    encryptor = Cipher(algorithms.AES(legacy_session[:32]), modes.CTR(nonce)).encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    mac = crypto_hmac.HMAC(legacy_session[32:], hashes.SHA256())
    mac.update(nonce + ciphertext)  # v1.0: MAC covers nonce || ciphertext only
    tag = mac.finalize()

    wrapped = recipient_public.encrypt(
        legacy_session,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return wrapped + nonce + ciphertext + tag


def make_v1_0_ctr_hmac_file(recipient, recipient_public, signer, data: bytes, *, signed: bool) -> bytes:
    body = build_v1_0_ctr_hmac_body(recipient.public_key(), data)
    header = ZXTXHeader(
        version_major=1,
        version_minor=0,
        uid=uuid.uuid4().bytes,
        compression_method=COMPRESSION_METHOD.NONE,
        cipher_method=CIPHER_METHOD.AES256_CTR_HMAC,
        original_size=len(data),
        compressed_size=len(body),
        timestamp=int(datetime.now(timezone.utc).timestamp()),
        sha256_hash=hashlib.sha256(data).digest(),
        crc32=zlib.crc32(body),
        signature=b"",
        certificate=b"",
    )
    signed_message = pack_header(header)  # v1.0: header only
    signature = sign_data(signer if signed else None, signed_message)
    return pack_header(header) + struct.pack(">H", len(signature)) + signature + body


def generate() -> int:
    recipient_private_pem = KEYS_DIR / "recipient_private.pem"
    if not recipient_private_pem.exists():
        print("Generating RSA-2048 recipient/signing keys ...")
        recipient = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        signer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _write_key_files(recipient, signer)

    recipient, _recipient_public, signer, _signer_public = _load_key_files()
    count = 0
    for major, minor, version in ((1, 0, FORMAT_VERSION_V1), (1, 1, FORMAT_VERSION)):
        version_dir = VECTORS / f"v{major}_{minor}"
        for signed in (True, False):
            signed_dir = version_dir / ("signed" if signed else "unsigned")
            signed_dir.mkdir(parents=True, exist_ok=True)
            for cipher_name, cipher in CIPHERS.items():
                for comp_name, compression in COMPRESSIONS.items():
                    target = signed_dir / f"{cipher_name}-{comp_name}.zxtx"
                    if (version, cipher_name) == (FORMAT_VERSION_V1, "aes256_ctr_hmac"):
                        raw = make_v1_0_ctr_hmac_file(
                            recipient, recipient.public_key(), signer, GOLDEN_PAYLOAD,
                            signed=signed,
                        )
                    else:
                        raw = write_zxtx_file(
                            data=GOLDEN_PAYLOAD,
                            compression_method=compression,
                            cipher_method=cipher,
                            private_key=signer if signed else None,
                            public_key=recipient.public_key(),
                            version=version,
                        )
                    target.write_bytes(raw)
                    count += 1
                    print(f"wrote {target.relative_to(VECTORS)} ({len(raw)} bytes)")
    return count


if __name__ == "__main__":
    total = generate()
    print(f"Generated {total} golden files under {VECTORS}")
