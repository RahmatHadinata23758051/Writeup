#!/usr/bin/env python3
from math import gcd
import json
import re
from Crypto.PublicKey import RSA


def main() -> None:
    pub = RSA.import_key(open("relay_pub.pem", "rb").read())
    n, e = pub.n, pub.e

    diag = json.load(open("relay_diag.json", "r", encoding="utf-8"))
    fingerprint = int(diag["relay_fingerprint"], 16)

    # Prime reuse: modulus and fingerprint share one prime factor.
    p = gcd(n, fingerprint)
    if p in (1, n):
        raise RuntimeError("GCD attack failed: no shared prime factor found")
    q = n // p

    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    ct = open("tx_fragment.bin", "rb").read()
    c = int.from_bytes(ct, "big")
    m = pow(c, d, n)

    k = (n.bit_length() + 7) // 8
    pt = m.to_bytes(k, "big")

    # PKCS#1 v1.5 unpadding for encryption block type 2.
    if not pt.startswith(b"\x00\x02"):
        raise RuntimeError("Unexpected plaintext format (not PKCS#1 v1.5 block type 2)")
    sep = pt.find(b"\x00", 2)
    if sep < 0:
        raise RuntimeError("Invalid PKCS#1 v1.5 padding: separator not found")

    msg = pt[sep + 1 :]
    print(msg.decode("utf-8", errors="replace"))

    match = re.search(rb"[A-Za-z0-9_]+\{[^}]+\}", msg)
    if not match:
        raise RuntimeError("Flag pattern not found")

    flag = match.group().decode()
    print(f"\n<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
