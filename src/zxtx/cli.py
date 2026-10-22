import argparse
import sys
from importlib.metadata import version
from pathlib import Path
from typing import Optional

from zxtx.constants import CIPHER_METHOD, COMPRESSION_METHOD
from zxtx.dtypes import ZXTXBody, ZXTXData, ZXTXHeader
from zxtx.highlevel import _open, open
from zxtx.utils import error, note, warning

try:
    from rich.pretty import pprint
except ImportError:
    from pprint import pprint


def get_bytes(path: str | None) -> bytes | None:
    if path:
        return Path(path).read_bytes()
    return None


def clean_error(e: Exception) -> str:
    return str(e).removeprefix("[Errno 2]").removeprefix("[Errno 13]").lstrip(" ")


def explain_error(e: Exception):
    error_str = str(e)
    error_repr = repr(e)

    if error_str == "Decryption failed":
        note("This may be caused by the following reasons:")
        note("  - The private key is incorrect.")
        note("  - The password of the private key is incorrect.")
        note("  - A wrong cipher or compression method is used,")
        note("    this should be left to the parser to determine.")
    elif error_repr == "InvalidTag()":
        note("This may be caused by the following reasons:")
        note("  - You've provided an invalid cipher method,")
        note("    this should be left to the parser to determine.")
        note("  - The header identity data was tampered with (v1.1 files).")


def _maybe_warn_unverified(zxtx_file) -> None:
    state = zxtx_file.signature_verified
    if state is False:
        warning(
            "File is signed, but no verification key was provided "
            "(use --public-key or --certificate); signature NOT verified."
        )


def write_cmd(args):
    password_bytes = args.password.encode() if args.password else None

    try:
        with (
            _open(args.input_path, "rb") as input_file,
            open(
                args.output_path,
                cipher=CIPHER_METHOD(args.cipher),
                compression=COMPRESSION_METHOD(args.compression),
                password=password_bytes,
                certificate=get_bytes(args.certificate),
                private_key=get_bytes(args.private_key),
                public_key=get_bytes(args.public_key),
                create=True,
            ) as output_file,
        ):
            output_file.write_bytes(input_file.read())

    except Exception as e:
        error(f"{clean_error(e)}")
        sys.exit(1)


def read_cmd(args):
    password_bytes = args.password.encode() if args.password else None

    try:
        with open(
            args.input_path,
            password=password_bytes,
            public_key=get_bytes(args.public_key),
            private_key=get_bytes(args.private_key),
            certificate=get_bytes(args.certificate),
            cipher=CIPHER_METHOD(args.cipher),
            compression=COMPRESSION_METHOD(args.compression),
        ) as file:
            data = file.read_bytes()
            _maybe_warn_unverified(file)

        if args.output_path:
            Path(args.output_path).write_bytes(data)
        else:
            try:
                print(data.decode("utf-8"))
            except UnicodeDecodeError:
                print(repr(data))

    except Exception as e:
        error(f"{clean_error(e)}")
        sys.exit(1)


def dump_cmd(args):
    password_bytes = args.password.encode() if args.password else None

    try:
        with open(
            args.input_path,
            password=password_bytes,
            public_key=get_bytes(args.public_key),
            private_key=get_bytes(args.private_key),
            certificate=get_bytes(args.certificate),
            cipher=CIPHER_METHOD(args.cipher),
            compression=COMPRESSION_METHOD(args.compression),
        ) as zxtx_file:
            header: ZXTXHeader = zxtx_file.get_header()
            body: ZXTXBody = zxtx_file.get_body()
            data: bytes = zxtx_file.read_bytes()

            _maybe_warn_unverified(zxtx_file)

            pprint(header)
            pprint(body)
            pprint(ZXTXData(data=data))

    except Exception as e:
        error_msg = clean_error(e)
        error_repr = repr(e)

        if error_msg.strip():
            error(f"{error_msg}")
        elif error_repr == "InvalidTag()":
            error("[bold magenta]cryptography.exceptions.InvalidTag[/bold magenta]")
        else:
            error(f"{error_repr}")

        explain_error(e)
        sys.exit(1)


def add_common_options(p):
    p.add_argument(
        "-c",
        "--cipher",
        type=int,
        default=0,
        choices=[c.value for c in CIPHER_METHOD],
        metavar="{0..3}",
        help=(
            "Cipher method id: 0=none (auto-detect when reading), "
            "1=aes256_gcm, 2=chacha20_poly1305, 3=aes256_ctr_hmac."
        ),
    )
    p.add_argument(
        "-z",
        "--compression",
        type=int,
        default=0,
        choices=[c.value for c in COMPRESSION_METHOD],
        metavar="{0..3}",
        help=(
            "Compression method id: 0=none (auto-detect when reading), "
            "1=zlib, 2=lzma, 3=brotli."
        ),
    )
    p.add_argument(
        "-p",
        "--password",
        type=str,
        help="Password to decrypt private key (if needed).",
    )
    p.add_argument(
        "-k",
        "--public-key",
        type=str,
        help=(
            "Path to public key file. Used to wrap the session key when "
            "encrypting and to verify signatures when reading."
        ),
    )
    p.add_argument(
        "-u",
        "--private-key",
        type=str,
        help="Path to private key file (sign when writing, decrypt when reading).",
    )
    p.add_argument(
        "-C",
        "--certificate",
        type=str,
        help=(
            "Path to X.509 certificate to embed when writing; also used as "
            "a verification anchor when reading."
        ),
    )

    p.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"zxtx {version('zxtx')}",
        help="Print version and exit",
    )


def main():
    parser = argparse.ArgumentParser(description="ZXTX CLI")
    subparsers = parser.add_subparsers(dest="command")

    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"zxtx {version('zxtx')}",
        help="Print version and exit",
    )

    write_parser = subparsers.add_parser("write", help="Write a ZXTX file.")
    write_parser.add_argument("input_path", type=Path, help="Input file path.")
    write_parser.add_argument("output_path", type=Path, help="Output .zxtx file path.")
    add_common_options(write_parser)
    write_parser.set_defaults(func=write_cmd)

    read_parser = subparsers.add_parser("read", help="Read a ZXTX file.")
    read_parser.add_argument("input_path", type=Path, help="Input .zxtx file path.")
    read_parser.add_argument(
        "output_path",
        type=Path,
        nargs="?",
        help="Where to save extracted output (optional).",
    )
    add_common_options(read_parser)
    read_parser.set_defaults(func=read_cmd)

    dump_parser = subparsers.add_parser("dump", help="Dump ZXTX file metadata.")
    dump_parser.add_argument("input_path", type=Path, help="Input .zxtx file path.")
    add_common_options(dump_parser)
    dump_parser.set_defaults(func=dump_cmd)

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()

