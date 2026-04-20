#!/usr/bin/env python3
import argparse
import base64
import hashlib
import re
from pathlib import Path

from Crypto.Hash import MD4


def is_base64_text(s: str) -> bool:
    s = s.strip()
    if not s or len(s) % 4 != 0:
        return False
    return re.fullmatch(r"[A-Za-z0-9+/=\n\r]+", s) is not None


def peel_onion(data: str):
    cur = data.strip()
    layers = []

    while is_base64_text(cur):
        try:
            decoded = base64.b64decode(cur, validate=True)
        except Exception:
            break

        try:
            nxt = decoded.decode("utf-8")
        except UnicodeDecodeError:
            break

        layers.append(nxt.strip())
        cur = nxt.strip()

    return layers, cur


def crack_32hex_hash(token: str, wordlist: str):
    if not re.fullmatch(r"[0-9a-f]{32}", token):
        return None

    with open(wordlist, "rb") as f:
        for line in f:
            w = line.rstrip(b"\r\n")
            if not w:
                continue

            if hashlib.md5(w).hexdigest() == token:
                return "md5", w.decode("latin-1", "ignore")

            md4_raw = MD4.new()
            md4_raw.update(w)
            if md4_raw.hexdigest() == token:
                return "md4", w.decode("latin-1", "ignore")

            md4_ntlm = MD4.new()
            md4_ntlm.update(w.decode("latin-1", "ignore").encode("utf-16le"))
            if md4_ntlm.hexdigest() == token:
                return "ntlm", w.decode("latin-1", "ignore")

    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--input", default="chall.txt")
    ap.add_argument("-w", "--wordlist", default="/usr/share/wordlists/rockyou.txt")
    args = ap.parse_args()

    blob = Path(args.input).read_text().strip()
    layers, final = peel_onion(blob)

    print(f"peeled_layers={len(layers)}")
    print(f"final={final}")

    cracked = crack_32hex_hash(final, args.wordlist)
    if cracked:
        algo, plain = cracked
        print(f"hash_type={algo}")
        print(f"plaintext={plain}")
        print(f"CIT{{{plain}}}")


if __name__ == "__main__":
    main()
