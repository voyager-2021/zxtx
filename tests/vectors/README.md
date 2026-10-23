# Golden test vectors

Static `.zxtx` files pinning the **v1.0** and **v1.1** on-disk format for
regression protection.  Phase 1 tasks must keep every file in this tree
readable — the on-disk format is not allowed to change.

Layout:

```
keys/              fixed RSA-2048 recipient + signer (PEM, unencrypted)
v1_0/signed/       16 files (4 ciphers x 4 compressions, header-only signature)
v1_0/unsigned/     16 files (no signature)
v1_1/signed/       16 files (signature covers header + body)
v1_1/unsigned/     16 files (no signature)
```

Notes:

* All encrypted files wrap a 32-byte session key under the recipient
  RSA-2048 key (OAEP-SHA256).
* The v1.0 `aes256_ctr_hmac-*` files use the documented **legacy**
  layout: a 64-byte session key split directly into AES/HMAC halves,
  no HKDF, no associated data, and a signature over the packed header.
* Every file decodes the exact payload `GOLDEN_PAYLOAD` defined in
  `generate_vectors.py`.

Regenerate on demand (not deterministic due to RSA-OAEP randomness):

```
python tests/vectors/generate_vectors.py
```

Then run the reader test:

```
pytest tests/test_golden_vectors.py
```
