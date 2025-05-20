from pathlib import Path

from zxtx.parser import parse_zxtx_header, read_zxtx_file
from zxtx.signer import load_private_key

with open(
    Path(f"~/Documents/.id_rsa/zxtx_root_private_key.pem").expanduser(),
    "rb",  # Replace with your own private key
) as f:
    private_key = load_private_key(f.read(), password=None)

with open("example.zxtx", "rb") as f:
    data = f.read()

header, body = parse_zxtx_header(data, private_key=private_key)

decrypted_data = read_zxtx_file(header, body, private_key=private_key)
print(decrypted_data)
