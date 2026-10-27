"""T1: split the signing key from the RSA decryption key.

``private_key`` is the signing key on write and doubles as the RSA
decryption key on read (and the write self-check).  Signing with
Ed25519 key A and encrypting to RSA recipient B used to fail *after*
the file was written ("RSA-only ValueError" in the self-check) and
reading required overloading the signing-key parameter.

New contract:

* ``decryption_key`` parameter on ``zxtx.open`` / ``ZXTXFileHandle``
  (falls back to ``private_key`` for back-compat);
* the write self-check only runs when the decryption key is the RSA key
  matching the recipient public key;
* CLI ``--decrypt-key``.
"""

import os
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from zxtx.constants import CIPHER_METHOD, COMPRESSION_METHOD
from zxtx.errors import FormatError, SignatureError
from zxtx.highlevel import open as zxtx_open
from zxtx.signer import load_private_key, load_public_key


@pytest.fixture
def signer_a_pems(tmp_path):
    """Ed25519 signing key A as PEM files (like a CLI user would have)."""
    key = ed25519.Ed25519PrivateKey.generate()

    priv = tmp_path / "signer_a_private.pem"
    pub = tmp_path / "signer_a_public.pem"
    priv.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    pub.write_bytes(
        key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    return key, priv, pub


@pytest.fixture
def recipient_b_pems(tmp_path):
    """RSA-2048 recipient B as PEM files."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    priv = tmp_path / "recipient_b_private.pem"
    pub = tmp_path / "recipient_b_public.pem"
    priv.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    pub.write_bytes(
        key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    return key, priv, pub


def test_write_signed_by_ed25519_encrypted_to_rsa_succeeds_new_contract(
    tmp_path, signer_a_pems, recipient_b_pems
):
    """The old contract crashed on this shape *after* writing; the new
    one completes the write and defers the unreadability to read time
    (covered in detail by ``test_ed25519_signer_rsa_recipient_roundtrip``
    below).  Kept as the task's headline scenario."""
    key_a, _priv_a, _pub_a = signer_a_pems
    key_b, _priv_b, _pub_b = recipient_b_pems

    target = tmp_path / "headline.zxtx"
    handle = zxtx_open(
        target,
        cipher=CIPHER_METHOD.AES256_GCM,
        compression=COMPRESSION_METHOD.NONE,
        private_key=key_a,
        public_key=key_b.public_key(),
        create=True,
    )
    handle.write_bytes(b"signed by A, encrypted to B")
    assert target.stat().st_size > 0


def test_ed25519_signer_rsa_recipient_roundtrip(
    tmp_path, signer_a_pems, recipient_b_pems
):
    key_a, priv_a, pub_a = signer_a_pems
    _key_b, _priv_b, pub_b = recipient_b_pems

    target = tmp_path / "mixed-signers.zxtx"
    public_key = load_public_key(pub_b.read_bytes())
    handle = zxtx_open(
        target,
        cipher=CIPHER_METHOD.AES256_GCM,
        compression=COMPRESSION_METHOD.NONE,
        private_key=key_a,
        public_key=public_key,
        create=True,
    )
    handle.write_bytes(b"signed by A, encrypted to B")
    assert target.exists()

    # A does not hold B's private key.  A fresh handle fails *during
    # construction* (eager parse) with the clear RSA message instead of
    # crashing the write.
    with pytest.raises(FormatError, match="cannot unwrap"):
        zxtx_open(target, decryption_key=key_a)


def test_recipient_reads_with_decryption_key(tmp_path, signer_a_pems, recipient_b_pems):
    """B uses his RSA key for decryption and A's public key for verification."""
    _, priv_a, pub_a = signer_a_pems
    _, priv_b, pub_b = recipient_b_pems

    target = tmp_path / "mixed-signers.zxtx"
    handle = zxtx_open(
        target,
        cipher=CIPHER_METHOD.AES256_GCM,
        compression=COMPRESSION_METHOD.NONE,
        private_key=load_private_key(priv_a.read_bytes()),
        public_key=load_public_key(pub_b.read_bytes()),
        create=True,
    )
    handle.write_bytes(b"signed by A, encrypted to B")

    reader = zxtx_open(
        target,
        decryption_key=load_private_key(priv_b.read_bytes()),
        public_key=load_public_key(pub_a.read_bytes()),
    )
    assert reader.read_bytes() == b"signed by A, encrypted to B"
    assert reader.signature_verified is True
    reader.close()


def test_backcompat_private_key_still_signs_and_decrypts(tmp_path, recipient_b_pems):
    """A single RSA private key (sign + decrypt) keeps working."""
    key_b, priv_b, _pub_b = recipient_b_pems
    target = tmp_path / "one-key.zxtx"

    handle = zxtx_open(
        target,
        cipher=CIPHER_METHOD.AES256_GCM,
        private_key=load_private_key(priv_b.read_bytes()),
        public_key=key_b.public_key(),
        create=True,
    )
    handle.write_bytes(b"same key signs and decrypts")
    assert handle.read_bytes() == b"same key signs and decrypts"
    assert handle.signature_verified is True


def test_decrypt_key_overrides_private_key(tmp_path, recipient_b_pems):
    """``decryption_key`` wins over the (fallback) signing key."""
    key_b, _priv_b, _pub_b = recipient_b_pems
    stranger = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    target = tmp_path / "override.zxtx"

    write_handle = zxtx_open(
        target,
        cipher=CIPHER_METHOD.AES256_GCM,
        private_key=stranger,  # unrelated signing key
        public_key=key_b.public_key(),
        create=True,
    )
    write_handle.write_bytes(b"explicit decryption key")
    write_handle.close()

    reader = zxtx_open(
        target,
        decryption_key=load_private_key(
            key_b.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        ),
    )
    assert reader.read_bytes() == b"explicit decryption key"


def test_decrypt_key_mismatched_recipient_writes_but_cannot_read(tmp_path, recipient_b_pems):
    """Writing for B while holding C's private key: no local self-check,
    the error surfaces on read."""
    key_b, _priv_b, _pub_b = recipient_b_pems
    stranger = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    target = tmp_path / "mismatched.zxtx"
    handle = zxtx_open(
        target,
        cipher=CIPHER_METHOD.AES256_GCM,
        private_key=stranger,
        public_key=key_b.public_key(),
        create=True,
    )
    handle.write_bytes(b"for B, written by a stranger")
    assert target.read_bytes()  # the file was fully written

    # Reading with the same (mismatched) anchor fails verification, which
    # is the honest outcome: the file is signed by the stranger key.
    with pytest.raises(SignatureError):
        zxtx_open(target, private_key=stranger, public_key=key_b.public_key())


def test_cli_decrypt_key(tmp_path, signer_a_pems, recipient_b_pems):
    _key_a, priv_a, pub_a = signer_a_pems
    _key_b, priv_b, pub_b = recipient_b_pems

    plain = tmp_path / "payload.bin"
    plain.write_bytes(os.urandom(64))
    target = tmp_path / "mixed-signers.zxtx"

    write = subprocess.run(
        [
            sys.executable, "-m", "zxtx", "write",
            str(plain), str(target),
            "-c", "1",
            "-u", str(priv_a),
            "-k", str(pub_b),
        ],
        capture_output=True,
        check=False,
    )
    assert write.returncode == 0, write.stderr

    out = tmp_path / "out.bin"
    read = subprocess.run(
        [
            sys.executable, "-m", "zxtx", "read",
            str(target), str(out),
            "--decrypt-key", str(priv_b),
            "-k", str(pub_a),
        ],
        capture_output=True,
        check=False,
    )
    assert read.returncode == 0, read.stderr
    assert out.read_bytes() == plain.read_bytes()
