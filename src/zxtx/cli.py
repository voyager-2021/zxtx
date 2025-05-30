import argparse
import re
import sys
from importlib.metadata import version
from pathlib import Path
from typing import Optional

from zxtx.constants import CIPHER_METHOD, COMPRESSION_METHOD
from zxtx.dtypes import ZXTXBody, ZXTXData, ZXTXHeader
from zxtx.highlevel import _open, open
from zxtx.utils import error, note

# Preserve original print for DummyConsole fallback
_print = print

# Regex patterns to clean style tags
STYLE_TAG_PATTERN = re.compile(
    r"""
    (?<!\\)            # not preceded by backslash
    (?<!\[)            # not a double opening bracket
    \[/?[^\[\]]+?\]    # match [style] or [/]
    (?!\])             # not a double closing bracket
    """,
    re.VERBOSE,
)

DOUBLE_BRACKET_PATTERN = re.compile(r"\[\[([^\[\]]+?)\]\]")


def strip_style_tags(text: str) -> str:
    text = DOUBLE_BRACKET_PATTERN.sub(r"[\1]", text)
    text = STYLE_TAG_PATTERN.sub("", text)
    return text.replace("\\[", "[").replace("\\]", "]")


try:
    from rich.pretty import pprint

except ImportError:
    from pprint import pprint


def get_bytes(path: Optional[str]) -> Optional[bytes]:
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
            header: ZXTXHeader = zxtx_file._header
            body: ZXTXBody = zxtx_file._body
            data: bytes = zxtx_file._data

            zxtx_file._read()

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
        help="Cipher method (int).",
    )
    p.add_argument(
        "-z",
        "--compression",
        type=int,
        default=0,
        choices=[c.value for c in COMPRESSION_METHOD],
        help="Compression method (int).",
    )
    p.add_argument(
        "-p",
        "--password",
        type=str,
        help="Password to decrypt private key (if needed).",
    )
    p.add_argument("-k", "--public-key", type=str, help="Path to public key file.")
    p.add_argument("-u", "--private-key", type=str, help="Path to private key file.")
    p.add_argument("-C", "--certificate", type=str, help="Path to certificate file.")

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
