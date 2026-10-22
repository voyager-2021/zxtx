"""
Regression tests for the 0.2.0 security/correctness fixes:

* signature verification is actually performed (and covers header + body)
* AES256_CTR_HMAC works with small RSA keys (32-byte master key + HKDF)
* v1.0 legacy files (64-byte split key, header-only signature) still read
* malformed/truncated files raise ``ValueError``, never ``struct.error``
* decompression is bounded (no zip bombs)
* ``get_header`` / lazy-reading semantics no longer crash or re-read
* writer output can be re-parsed bit-for-bit (packed-header parity)
"""

import os
import struct
import zlib

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from zxtx import open as zxtx_open
from zxtx.constants import CIPHER_METHOD, COMPRESSION_METHOD
from zxtx.dtypes import ZXTXHeader, pack_header
from zxtx.parser import (
    _decompress_bounded_brotli,
    _decompress_bounded_lzma,
    _decompress_bounded_zlib,
    parse_zxtx_header,
    read_zxtx_file,
)
from zxtx.signer import load_private_key, load_public_key, sign_data
from zxtx.verifier import resolve_verification_key
from zxtx.writer import write_zxtx_file

CRC32_OFFSET = 4 + 2 + 16 + 2 + 8 + 8 + 8 + 32  # CRC32 field offset
ORIGINAL_SIZE_OFFSET = 4 + 2 + 16 + 2  # original_size field offset


def get_body_start(raw: bytes) -> int:
    header, _ = parse_zxtx_header(raw)
    return len(raw) - header.compressed_size


@pytest.fixture
def keypair(tmp_path):
    """RSA-2048 keypair + self-signed certificate, written as PEM files."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import NameOID

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "FI"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZXTX"),
            x509.NameAttribute(NameOID.COMMON_NAME, "ZXTX Signing Key"),
        ]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .sign(private_key, hashes.SHA256())
    )

    priv_path = tmp_path / "private_key.pem"
    pub_path = tmp_path / "public_key.pem"
    cert_path = tmp_path / "certificate.pem"

    priv_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pub_path.write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    return priv_path, pub_path, cert_path


# ---------------------------------------------------------------------------
# 1. CTR + HMAC with RSA-1024 (the previously impossible combination)
# ---------------------------------------------------------------------------


@pytest.fixture
def keypair_1024(tmp_path):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    public_key = private_key.public_key()

    priv_path = tmp_path / "private_key_1024.pem"
    pub_path = tmp_path / "public_key_1024.pem"

    from cryptography.hazmat.primitives import serialization

    priv_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pub_path.write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return priv_path, pub_path


def test_ctr_hmac_with_rsa_1024(tmp_path, keypair_1024):
    """The 64-byte session key used to overflow RSA-1024 OAEP; with the
    32-byte master key + HKDF derivation this round trip must succeed."""
    priv_path, pub_path = keypair_1024
    private_key = load_private_key(priv_path.read_bytes())
    public_key = load_public_key(pub_path.read_bytes())

    zxtx_bytes = write_zxtx_file(
        data=b"small RSA key, big HMAC",
        compression_method=COMPRESSION_METHOD.NONE,
        cipher_method=CIPHER_METHOD.AES256_CTR_HMAC,
        private_key=private_key,
        public_key=public_key,
    )

    header, body = parse_zxtx_header(zxtx_bytes, private_key=private_key)
    assert read_zxtx_file(header, body, private_key=private_key) == b"small RSA key, big HMAC"


# ---------------------------------------------------------------------------
# 2. Signature verification actually happens
# ---------------------------------------------------------------------------


def test_tampered_header_fails_verification(keypair):
    priv_path, pub_path, _ = keypair
    private_key = load_private_key(priv_path.read_bytes())
    public_key = load_public_key(pub_path.read_bytes())

    zxtx_bytes = write_zxtx_file(
        data=b"integrity matters",
        compression_method=COMPRESSION_METHOD.NONE,
        cipher_method=CIPHER_METHOD.NONE,
        private_key=private_key,
        public_key=public_key,
    )

    tampered = bytearray(zxtx_bytes)
    # Flip the least-significant byte of original_size (signed by v1.1)
    tampered[ORIGINAL_SIZE_OFFSET + 7] ^= 0x01

    with pytest.raises(ValueError, match="Signature verification failed"):
        parse_zxtx_header(bytes(tampered), verification_key=public_key)


def test_tampered_body_fails_verification(keypair):
    priv_path, pub_path, _ = keypair
    private_key = load_private_key(priv_path.read_bytes())
    public_key = load_public_key(pub_path.read_bytes())

    zxtx_bytes = write_zxtx_file(
        data=b"integrity matters very much",
        compression_method=COMPRESSION_METHOD.NONE,
        cipher_method=CIPHER_METHOD.NONE,
        private_key=private_key,
        public_key=public_key,
    )

    tampered = bytearray(zxtx_bytes)
    tampered[-1] ^= 0xFF  # flip a body byte
    # An attacker without the signing key can still recompute CRC32, which
    # alone is not a security check — the header signature must catch this.
    body_start = get_body_start(zxtx_bytes)
    new_crc = zlib.crc32(bytes(tampered[body_start:]))
    tampered[CRC32_OFFSET : CRC32_OFFSET + 4] = struct.pack(">I", new_crc)

    with pytest.raises(ValueError, match="Signature verification failed"):
        parse_zxtx_header(bytes(tampered), verification_key=public_key)


def test_unsigned_file_with_verification_key_is_rejected(keypair):
    """Providing a verification anchor for an unsigned file must be a loud
    error, never silent acceptance."""

    _, pub_path, _ = keypair
    public_key = load_public_key(pub_path.read_bytes())

    # No private key => no signature
    raw = write_zxtx_file(
        data=b"unsigned and honest",
        compression_method=COMPRESSION_METHOD.NONE,
        cipher_method=CIPHER_METHOD.NONE,
        private_key=None,
    )

    with pytest.raises(ValueError, match="not signed"):
        parse_zxtx_header(raw, verification_key=public_key)


def test_wrong_key_fails_verification(keypair, tmp_path):
    priv_path, _, _ = keypair
    private_key = load_private_key(priv_path.read_bytes())

    other_public = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_priv = other_public.public_key()

    raw = write_zxtx_file(
        data=b"signed by A",
        compression_method=COMPRESSION_METHOD.NONE,
        cipher_method=CIPHER_METHOD.NONE,
        private_key=private_key,
    )

    with pytest.raises(ValueError, match="Signature verification failed"):
        parse_zxtx_header(raw, verification_key=other_priv)


def test_bad_verification_key_bytes_raise_privately(keypair):
    priv_path, pub_path, _ = keypair
    private_key = load_private_key(priv_path.read_bytes())

    raw = write_zxtx_file(
        data=b"signed",
        compression_method=COMPRESSION_METHOD.NONE,
        cipher_method=CIPHER_METHOD.NONE,
        private_key=private_key,
    )

    with pytest.raises(ValueError, match="verification key"):
        parse_zxtx_header(raw, verification_key=b"definitely not PEM")


def test_resolve_verification_key_from_public_pem(keypair):
    _, pub_path, _ = keypair
    key = resolve_verification_key(pub_path.read_bytes())
    assert key is not None


# ---------------------------------------------------------------------------
# 3. Structural validation
# ---------------------------------------------------------------------------


def test_truncated_body_is_rejected(keypair):
    priv_path, pub_path, _ = keypair
    private_key = load_private_key(priv_path.read_bytes())
    public_key = load_public_key(pub_path.read_bytes())

    raw = write_zxtx_file(
        data=b"x" * 64,
        compression_method=COMPRESSION_METHOD.ZLIB,
        cipher_method=CIPHER_METHOD.NONE,
        private_key=private_key,
    )

    with pytest.raises(ValueError, match="truncated"):
        parse_zxtx_header(raw[:-4])


def test_truncated_header_is_rejected():
    with pytest.raises(ValueError, match="truncated"):
        parse_zxtx_header(b"ZXTX\x01\x01" + os.urandom(10))


def test_unknown_cipher_id_is_rejected():
    # magic + version + 16-byte uid with uid=0, compression=NONE(0),
    # cipher=153 (undefined) + zero padding up to the minimum header size
    raw = b"ZXTX" + b"\x01\x01" + b"\x00" * 16 + b"\x00\x99" + b"\x00" * 64
    assert len(raw) == 88
    with pytest.raises(ValueError, match="Invalid cipher method ID"):
        parse_zxtx_header(raw)


def test_cipher_override_mismatch_is_rejected():
    raw = write_zxtx_file(
        data=b"plain",
        compression_method=COMPRESSION_METHOD.NONE,
        cipher_method=CIPHER_METHOD.NONE,
        private_key=None,
    )
    with pytest.raises(ValueError, match="does not|override"):
        parse_zxtx_header(raw, cipher_method=CIPHER_METHOD.AES256_GCM)


# ---------------------------------------------------------------------------
# 4. Decompression bombs are bounded
# ---------------------------------------------------------------------------


def test_zlib_bomb_is_bounded():
    bomb = zlib.compress(b"\x00" * (1 << 20), 9)
    with pytest.raises(ValueError, match="exceeds the declared original size"):
        _decompress_bounded_zlib(bomb, limit=1024)


def test_lzma_bomb_is_bounded():
    import lzma

    bomb = lzma.compress(b"\x00" * (1 << 15))
    with pytest.raises(ValueError, match="exceeds the declared original size"):
        _decompress_bounded_lzma(bomb, limit=128)


def test_brotli_bomb_is_bounded():
    import brotli

    bomb = brotli.compress(b"\x00" * 20000)
    with pytest.raises(ValueError, match="exceeds the declared original size"):
        _decompress_bounded_brotli(bomb, limit=64)


def test_bounded_decompression_legit_roundtrip():
    payload = os.urandom(3000)
    assert _decompress_bounded_zlib(zlib.compress(payload), limit=3000) == payload
    assert _decompress_bounded_zlib(zlib.compress(b""), limit=0) == b""


# ---------------------------------------------------------------------------
# 5. Packed-header parity between writer, parser and verifier
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_dir():
    from pathlib import Path
    from tempfile import TemporaryDirectory

    with TemporaryDirectory() as tmp:
        yield Path(tmp)


# ---------------------------------------------------------------------------
# 5. Packed-header parity between writer, parser and verifier
# ---------------------------------------------------------------------------


def test_packed_header_roundtrip_matches_file_bytes(temp_dir, keypair):
    priv_path, pub_path, cert_path = keypair
    private_key = load_private_key(priv_path.read_bytes())
    public_key = load_public_key(pub_path.read_bytes())

    raw = write_zxtx_file(
        data=b"pack me",
        compression_method=COMPRESSION_METHOD.ZLIB,
        cipher_method=CIPHER_METHOD.CHACHA20_POLY1305,
        private_key=private_key,
        public_key=public_key,
        certificate=cert_path.read_bytes(),
    )

    header, _ = parse_zxtx_header(raw, private_key=private_key)

    prefix_len = len(raw) - 2 - len(header.signature) - header.compressed_size
    assert pack_header(header) == raw[:prefix_len]
    assert raw[prefix_len + 2 + len(header.signature) :]  # body follows the sig


# ---------------------------------------------------------------------------
# 6. v1.0 legacy compatibility (64-byte split key, header-only signature)
# ---------------------------------------------------------------------------


def test_legacy_v1_0_ctr_hmac_file_still_reads(keypair):
    from cryptography.hazmat.primitives import hmac as crypto_hmac
    from cryptography.hazmat.primitives.asymmetric import padding

    priv_path, pub_path, _ = keypair
    private_key = load_private_key(priv_path.read_bytes())
    public_key = load_public_key(pub_path.read_bytes())

    data = b"v1.0 legacy CTR+HMAC file"
    legacy_session = os.urandom(64)  # enc_key || mac_key, no HKDF
    nonce = os.urandom(16)

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    encryptor = Cipher(algorithms.AES(legacy_session[:32]), modes.CTR(nonce)).encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    mac = crypto_hmac.HMAC(legacy_session[32:], hashes.SHA256())
    mac.update(nonce + ciphertext)  # v1.0: MAC covers nonce || ciphertext only
    tag = mac.finalize()

    wrapped = public_key.encrypt(
        legacy_session,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    body = wrapped + nonce + ciphertext + tag

    import hashlib
    import uuid
    from datetime import datetime, timezone

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

    # v1.0 signature covers the packed header only — no body hash/bytes.
    signature = sign_data(private_key, pack_header(header))
    v1_raw = pack_header(header) + struct.pack(">H", len(signature)) + signature + body

    parsed_header, parsed_body = parse_zxtx_header(v1_raw, verification_key=public_key)
    assert (parsed_header.version_major, parsed_header.version_minor) == (1, 0)
    assert read_zxtx_file(parsed_header, parsed_body, private_key=private_key) == data


# ---------------------------------------------------------------------------
# 7. High-level file-handle semantics
# ---------------------------------------------------------------------------


def test_get_header_requires_contents(temp_dir, keypair):
    """get_header no longer crashes with AttributeError on unread files."""

    priv_path, pub_path, _ = keypair

    handle = zxtx_open(
        temp_dir / "missing.zxtx",
        private_key=load_private_key(priv_path.read_bytes()),
        public_key=load_public_key(pub_path.read_bytes()),
    )
    with pytest.raises(FileNotFoundError):
        handle.get_header()

    empty_path = temp_dir / "empty.zxtx"
    empty_path.write_bytes(b"")
    handle = zxtx_open(empty_path)
    with pytest.raises(ValueError):
        handle.get_header()


def test_write_over_existing_invalid_file(temp_dir, keypair):
    """CLI 'write' relies on create=True to overwrite invalid targets."""
    priv_path, pub_path, _ = keypair

    target = temp_dir / "out.zxtx"
    target.write_bytes(b"this is not a zxtx file")

    handle = zxtx_open(
        target,
        cipher=CIPHER_METHOD.AES256_GCM,
        private_key=load_private_key(priv_path.read_bytes()),
        public_key=load_public_key(pub_path.read_bytes()),
        create=True,
    )
    handle.write_bytes(b"replacement payload")
    assert handle.read_bytes() == b"replacement payload"

    # Existing invalid content no longer prevents writing:
    handle.close()
    handle2 = zxtx_open(target, create=True)
    handle2.write_bytes(b"second overwrite")
    assert handle2.read_bytes() == b"second overwrite"


def test_closed_handle_blocks_every_read(temp_dir):
    handle = zxtx_open(temp_dir / "closed.zxtx")
    handle.close()

    with pytest.raises(RuntimeError):
        handle.read()
    with pytest.raises(RuntimeError):
        handle.read_bytes()
    with pytest.raises(RuntimeError):
        handle.get_header()
    with pytest.raises(RuntimeError):
        handle.write_bytes(b"x")


def test_empty_file_no_repeated_reads(temp_dir):
    """A legitimately empty zxtx file must not be re-parsed on every read."""
    handle = zxtx_open(temp_dir / "empty_payload.zxtx")
    handle.write_bytes(b"")

    assert handle.read_bytes() == b""
    assert handle.read() == ""
    assert handle.read_bytes() == b""


def test_signature_verified_flag(temp_dir, keypair):
    priv_path, pub_path, _ = keypair
    private_key = load_private_key(priv_path.read_bytes())

    handle = zxtx_open(
        temp_dir / "signed.zxtx",
        private_key=private_key,
        public_key=load_public_key(pub_path.read_bytes()),
    )
    handle.write_bytes(b"verifiable")
    assert handle.signature_verified is True
    handle.close()

    fresh = zxtx_open(temp_dir / "signed.zxtx")
    fresh.read_bytes()
    assert fresh.signature_verified is False  # signed, no anchor provided
    fresh.close()
