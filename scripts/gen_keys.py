"""generate an ed25519 keypair, print as base64.

usage: python scripts/gen_keys.py
copy the two lines into .env (private) and somewhere safe (public).
"""

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main() -> None:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    print(f"ATTEST_SIGNING_KEY={base64.b64encode(priv_bytes).decode()}")
    print(f"ATTEST_VERIFY_KEY={base64.b64encode(pub_bytes).decode()}")


if __name__ == "__main__":
    main()