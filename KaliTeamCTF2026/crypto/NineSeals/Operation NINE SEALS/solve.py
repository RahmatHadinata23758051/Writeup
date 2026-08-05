#!/usr/bin/env python3
import re
from pathlib import Path

import sympy as sp
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, inverse, long_to_bytes


ROOT = Path(__file__).resolve().parent


def read_public_key():
    text = (ROOT / "rsa_pub.txt").read_text()
    n = int(re.search(r"N\s*=\s*(\d+)", text).group(1))
    e = int(re.search(r"e\s*=\s*(\d+)", text).group(1))
    return n, e


def recover_rsa_private_key(n, e):
    factors = sp.factorint(n)
    if len(factors) != 2 or any(exp != 1 for exp in factors.values()):
        raise RuntimeError(f"unexpected factorization: {factors}")

    p, q = map(int, factors.keys())
    phi = (p - 1) * (q - 1)
    d = int(inverse(e, phi))
    return RSA.construct((n, e, d, p, q))


def decrypt_aes_key(rsa_key):
    encrypted = (ROOT / "enc_aes_key.bin").read_bytes()

    # The RSA ciphertext is OAEP padded with SHA-256.
    return PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256).decrypt(encrypted)


def decrypt_flag(aes_key):
    blob = (ROOT / "flag.bin").read_bytes()

    # Layout: nonce(12) || tag(16) || ciphertext.
    nonce = blob[:12]
    tag = blob[12:28]
    ciphertext = blob[28:]

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def main():
    n, e = read_public_key()
    rsa_key = recover_rsa_private_key(n, e)
    aes_key = decrypt_aes_key(rsa_key)
    flag = decrypt_flag(aes_key)
    print(flag.decode())


if __name__ == "__main__":
    main()
