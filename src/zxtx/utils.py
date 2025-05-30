import re
import sys

from zxtx.constants import CIPHER_METHOD
from zxtx.dtypes import ZXTXHeader

_print = print

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


class DummyConsole:
    def print(self, *args, **kwargs):
        cleaned_args = [strip_style_tags(str(arg)) for arg in args]
        _print(*cleaned_args, **kwargs)


try:
    from rich.console import Console

    console = Console()
except ImportError:
    console = DummyConsole()


def bits_to_bytes(bits: int) -> int:
    return bits // 8


def is_encrypted(header: ZXTXHeader) -> bool:
    return header.cipher_method != CIPHER_METHOD.NONE


def error(message, error_sound=True):
    if error_sound:
        sys.stdout.write("\a")
        sys.stdout.flush()

    console.print(
        f"[bold white]zxtx:[/bold white] [bold red]error:[/bold red] {message}"
    )


def warning(message):
    console.print(
        f"[bold white]zxtx:[/bold white] [bold yellow]warning:[/bold yellow] {message}"
    )


def info(message):
    console.print(
        f"[bold white]zxtx:[/bold white] [bold green]info:[/bold green] {message}"
    )


def note(message):
    console.print(
        f"[bold white]zxtx:[/bold white] [bold blue]note:[/bold blue] {message}"
    )


def debug(message):
    console.print(f"[bold white]zxtx:[/bold white] [dim]debug:[/dim] {message}")
