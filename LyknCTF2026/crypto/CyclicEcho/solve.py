#!/usr/bin/env python3
import json
import socket
import sys

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF


DEFAULT_HOST = "51.79.140.18"
DEFAULT_PORT = 19705
KDF_INFO = b"lyknctf-2026"


def recv_instance(host: str, port: int) -> dict:
    data = b""

    with socket.create_connection((host, port), timeout=10) as sock:
        sock.settimeout(3)

        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break

            if not chunk:
                break

            data += chunk

            # Coba parse segera kalau JSON sudah lengkap.
            start = data.find(b"{")
            end = data.rfind(b"}")

            if start != -1 and end > start:
                try:
                    return json.loads(data[start:end + 1])
                except json.JSONDecodeError:
                    pass

    start = data.find(b"{")
    end = data.rfind(b"}")

    if start == -1 or end <= start:
        raise RuntimeError(f"Remote tidak mengirim JSON valid:\n{data!r}")

    return json.loads(data[start:end + 1])


def derive_key(s_alg: int, n: int, q: int, salt: bytes) -> bytes:
    ikm = (
        s_alg.to_bytes(2, "big")
        + n.to_bytes(2, "big")
        + q.to_bytes(2, "big")
    )

    return HKDF(
        master=ikm,
        key_len=32,
        salt=salt,
        hashmod=SHA256,
        context=KDF_INFO,
    )


def solve(instance: dict) -> tuple[int, bytes]:
    params = instance["parameters"]
    encrypted = instance["encrypted_flag"]

    n = int(params["N"])
    q = int(params["q"])
    q_prime = int(params["q_prime"])

    salt = bytes.fromhex(encrypted["salt"])
    nonce = bytes.fromhex(encrypted["nonce"])
    ciphertext = bytes.fromhex(encrypted["ciphertext"])
    tag = bytes.fromhex(encrypted["tag"])

    print(f"[*] Brute-forcing s_alg modulo {q_prime}...")

    for s_alg in range(q_prime):
        key = derive_key(s_alg, n, q, salt)

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            continue

        return s_alg, plaintext

    raise RuntimeError("Tidak ada kandidat s_alg yang valid")


def main():
    host = sys.argv[1] if len(sys.argv) >= 2 else DEFAULT_HOST
    port = int(sys.argv[2]) if len(sys.argv) >= 3 else DEFAULT_PORT

    print(f"[*] Connecting to {host}:{port}")
    instance = recv_instance(host, port)

    s_alg, plaintext = solve(instance)

    print(f"[+] s_alg = {s_alg}")
    print(f"[+] flag  = {plaintext.decode()}")


if __name__ == "__main__":
    main()
