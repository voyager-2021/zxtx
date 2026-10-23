"""ZXTX exception hierarchy.

All format-level errors raised by :mod:`zxtx.parser`,
:mod:`zxtx.decryption` and the verification path derive from
:class:`ZXTXError`, which itself subclasses :class:`ValueError` so that
existing ``except ValueError`` call sites keep working unchanged.

Classes:

* :class:`FormatError` — the byte stream is not a well-formed ZXTX file
  (bad magic, unknown version or method IDs, truncated or trailing
  regions, CRC mismatch, declared-size/content mismatches).
* :class:`SignatureError` — the embedded signature is missing, invalid,
  or verification failed against the provided anchor.
* :class:`DecryptionError` — the body could not be decrypted
  (unwrapping the session key failed, an AEAD/HMAC tag did not
  authenticate, or no usable private key was provided).

Errors *outside* this hierarchy (``TypeError`` for wrong argument
types, ``FileNotFoundError`` for missing files, ...) are deliberate:
they indicate API misuse rather than a ZXTX problem.
"""

__all__ = ["DecryptionError", "FormatError", "SignatureError", "ZXTXError"]


class ZXTXError(ValueError):
    """Base class for every ZXTX format/decryption/signature error."""


class FormatError(ZXTXError):
    """The file is not a well-formed ZXTX asset (structure or content)."""


class SignatureError(ZXTXError):
    """Signature missing, invalid, or not verifiable with the given anchor."""


class DecryptionError(ZXTXError):
    """The encrypted body could not be decrypted with the given key."""
