#!/usr/bin/env python3
import argparse
import ast
import base64
import re


def extract_encoded_blob(path: str) -> bytes:
    with open(path, "rb") as f:
        data = f.read()

    # Ambil literal bytes repr dari dump, contoh: b'@\x11...'
    m = re.search(
        rb"b'@\\x11OPAkOgufy\\x14ykuW@e\\x1a\\x13@MuIB\\x12\\x1aUBdOUEr\\x1e\\x1e'",
        data,
    )
    if not m:
        raise ValueError("Encoded blob not found in dump")

    # Parse jadi bytes real (36-byte ciphertext)
    return ast.literal_eval(m.group(0).decode("latin1"))


def decode_flag(blob: bytes) -> str:
    # Transform hasil analisis dump: XOR 0x23 lalu base64 decode
    xored = bytes(b ^ 0x23 for b in blob)
    return base64.b64decode(xored).decode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Fortnite Dumpy solver")
    parser.add_argument("dump", nargs="?", default="memdump.1960", help="path to memory dump")
    args = parser.parse_args()

    blob = extract_encoded_blob(args.dump)
    flag = decode_flag(blob)
    print(flag)


if __name__ == "__main__":
    main()
