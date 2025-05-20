import argparse
from pathlib import Path
from typing import Optional

from zxtx.constants import CIPHER_METHOD, COMPRESSION_METHOD
from zxtx.dtypes import ZXTXBody, ZXTXData, ZXTXHeader
from zxtx.highlevel import _open, open

try:
    from rich.pretty import pprint
except ImportError:
    from pprint import pprint


def get_bytes(path: Optional[str]) -> Optional[bytes]:
    return Path(path).read_bytes() if path else None


def write_cmd(args):
    password_bytes = args.password.encode() if args.password else None

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
        ) as output_file,
    ):
        output_file.write_bytes(input_file.read())


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

        if args.output_path:
            Path(args.output_path).write_bytes(data)
        else:
            try:
                print(data.decode("utf-8"))
            except UnicodeDecodeError:
                print(repr(data))

    except Exception as e:
        print(f"error: {e}")
        exit(1)


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
            header: ZXTXHeader = zxtx_file._header
            body: ZXTXBody = zxtx_file._body
            data: bytes = zxtx_file._data

            zxtx_file._read()

            pprint(header)

            pprint(body)

            pprint(ZXTXData(data=data))

    except Exception as e:
        print(f"error: {e}")
        exit(1)


def main():
    parser = argparse.ArgumentParser(description="ZXTX CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Shared options
    def add_common_options(p):
        p.add_argument(
            "--cipher",
            type=int,
            default=0,
            choices=[c.value for c in CIPHER_METHOD],
            help="Cipher method (int).",
        )
        p.add_argument(
            "--compression",
            type=int,
            default=0,
            choices=[c.value for c in COMPRESSION_METHOD],
            help="Compression method (int).",
        )
        p.add_argument(
            "--password", type=str, help="Password to decrypt private key (if needed)."
        )
        p.add_argument("--public-key", type=str, help="Path to public key file.")
        p.add_argument("--private-key", type=str, help="Path to private key file.")
        p.add_argument("--certificate", type=str, help="Path to certificate file.")

    # write
    write_parser = subparsers.add_parser("write", help="Write a ZXTX file.")
    write_parser.add_argument("input_path", type=Path, help="Input file path.")
    write_parser.add_argument("output_path", type=Path, help="Output .zxtx file path.")
    add_common_options(write_parser)
    write_parser.set_defaults(func=write_cmd)

    # read
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

    # dump
    dump_parser = subparsers.add_parser("dump", help="Dump ZXTX file metadata.")
    dump_parser.add_argument("input_path", type=Path, help="Input .zxtx file path.")
    add_common_options(dump_parser)
    dump_parser.set_defaults(func=dump_cmd)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
