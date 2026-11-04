"""CLI helpers.

    python -m mudrika keygen          # print an Ed25519 keypair as JSON
"""
import argparse
import json

from .canonical import generate_keypair


def main() -> None:
    parser = argparse.ArgumentParser(prog="mudrika")
    parser.add_argument("command", choices=["keygen"])
    args = parser.parse_args()
    keys = generate_keypair()
    print(json.dumps({"secret_key_hex": keys.secret_hex, "public_key_hex": keys.public_hex}, indent=2))


if __name__ == "__main__":
    main()
