"""Phase 0 baseline: every golden v1.0 / v1.1 vector must still read.

These files pin the on-disk format (all 4 ciphers x 4 compressions,
signed and unsigned) BEFORE any parser/writer work in later tasks.
"""

from pathlib import Path

import pytest

from zxtx.parser import parse_zxtx_header, read_zxtx_file
from zxtx.signer import load_private_key, load_public_key
from tests.vectors.generate_vectors import GOLDEN_PAYLOAD

VECTORS = Path(__file__).parent / "vectors"
KEYS_DIR = VECTORS / "keys"


def _golden_files():
    files = sorted(VECTORS.glob("v1_*/[su]*/*.zxtx"))
    return files


@pytest.mark.parametrize("path", _golden_files(), ids=lambda p: str(p.relative_to(VECTORS)))
def test_golden_vector_reads(path):
    private_key = load_private_key((KEYS_DIR / "recipient_private.pem").read_bytes())

    verification_key = None
    if path.parent.name == "signed":
        verification_key = load_public_key((KEYS_DIR / "signer_public.pem").read_bytes())

    raw = path.read_bytes()
    header, body = parse_zxtx_header(raw, private_key=private_key, verification_key=verification_key)
    payload = read_zxtx_file(header, body, private_key)

    assert payload == GOLDEN_PAYLOAD
