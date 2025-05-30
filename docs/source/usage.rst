ZXTX Usage Guide
================

The `ZXTXFileHandle` class provides a simple, high-level interface for reading and writing ZXTX files
with optional compression, encryption, and signing support.

Opening Files
-------------

Use the `open()` function to open a ZXTX file, supporting options for cipher, compression, certificates,
and keys.

.. code-block:: python

    from zxtx import open
    from zxtx.constants import CIPHER_METHOD, COMPRESSION_METHOD

    # Open a ZXTX file for reading
    with open("example.zxtx") as zfile:
        content = zfile.read()
        print(content)

Writing and Appending Data
--------------------------

You can write text or bytes to a ZXTX file. Writing replaces the entire file content,
while appending adds to the existing content.

.. code-block:: python

    # Write text to a ZXTX file
    with open("example.zxtx") as zfile:
        zfile.write("Hello, ZXTX!")

    # Append more data
    with open("example.zxtx") as zfile:
        zfile.append(" More data.")

Reading Data
------------

Read the entire contents of a ZXTX file as text or bytes:

.. code-block:: python

    with open("example.zxtx") as zfile:
        text_data = zfile.read()
        bytes_data = zfile.read_bytes()

Advanced Options
----------------

- `cipher`: Select a cipher from `CIPHER_METHOD` enum for encryption/decryption.
- `compression`: Select compression method from `COMPRESSION_METHOD` enum.
- `certificate`: Optional bytes containing certificate data.
- `private_key`: Private key object or bytes for decryption/signing.
- `public_key`: Public key object or bytes for verification.
- `password`: Password bytes used for decrypting private keys.
- `encoding`: Text encoding used for text read/write operations (default: "utf-8").

Example with encryption and compression:

.. code-block:: python

    from zxtx.constants import CIPHER_METHOD, COMPRESSION_METHOD
    from zxtx import open

    with open(
        "secure.zxtx",
        cipher=CIPHER_METHOD.AES256_CTR_HMAC,
        compression=COMPRESSION_METHOD.ZSTD,
        private_key=b"---PRIVATE KEY BYTES---",
        public_key=b"---PUBLIC KEY BYTES---",
        password=b"mypassword"
    ) as secure_file:
        secure_file.write("Sensitive data here")
        print(secure_file.read())

Context Manager Support
-----------------------

ZXTXFileHandle supports the context manager protocol for safe opening and closing:

.. code-block:: python

    with open("example.zxtx") as zfile:
        data = zfile.read()
        # file is automatically closed at block exit

API Reference Summary
---------------------

.. autoclass:: zxtx.ZXTXFileHandle
    :members:
    :undoc-members:
    :show-inheritance:
    :noindex:

.. autofunction:: zxtx.open
    :noindex:

---

For more details, refer to the full API documentation and the ZXTX specification file.
