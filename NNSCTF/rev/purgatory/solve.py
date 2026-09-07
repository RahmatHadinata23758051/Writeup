#!/usr/bin/env python3
import re
import socket
import ssl
import sys

OLD_FIRST = [
    (0, 247, 40, 120), (1, 195, 0, 68), (2, 89, 105, 45),
    (3, 77, 179, 70), (4, 107, 221, 62), (5, 37, 117, 101),
    (6, 11, 232, 52), (7, 205, 46, 5), (8, 93, 161, 36),
    (9, 47, 220, 181), (10, 195, 222, 49), (11, 191, 233, 251),
    (12, 69, 35, 108),
]

NEW_SECOND = [
    (13, 87, 33, 108), (14, 233, 61, 201), (15, 197, 97, 245),
    (16, 155, 124, 72), (17, 75, 219, 93), (18, 115, 213, 5),
    (19, 219, 87, 227), (20, 221, 230, 166), (21, 69, 83, 123),
    (22, 139, 156, 253), (23, 193, 229, 111), (24, 93, 241, 181),
]

OLD_MASK = [114, 157, 234, 123, 50, 120, 87, 159, 59, 45, 110, 181]


def invert_safe(a, b, c):
    hits = []
    for x in range(256):
        if ((x * a) + b) & 0xFF == c:
            hits.append(x)

    if len(hits) != 1:
        raise RuntimeError(f"bad inverse for {(a, b, c)} -> {hits}")

    return hits[0]


def recover_passphrase():
    out = bytearray(25)

    for idx, a, b, c in OLD_FIRST:
        out[idx] = invert_safe(a, b, c)

    for mask_byte, (idx, a, b, c) in zip(OLD_MASK, NEW_SECOND):
        out[idx] = invert_safe(a, b, c) ^ mask_byte

    return bytes(out)


def recv_all(sock, timeout=2.0):
    sock.settimeout(timeout)
    data = b""

    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break

        if not chunk:
            break

        data += chunk

        if b"}" in data:
            break

    return data


def solve_remote(host, port, passphrase):
    raw = socket.create_connection((host, port), timeout=10)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with ctx.wrap_socket(raw, server_hostname=host) as s:
        banner = recv_all(s, timeout=1.0)
        if banner:
            print(banner.decode(errors="replace"), end="")

        s.sendall(passphrase + b"\n")

        res = recv_all(s, timeout=3.0)
        print(res.decode(errors="replace"), end="")

        m = re.search(rb"[A-Za-z0-9_]+\{[^}\n]+\}", res)
        if m:
            print(f"\n<FLAG>{m.group(0).decode(errors='replace')}</FLAG>")


def main():
    passphrase = recover_passphrase()
    print("[+] passphrase:", passphrase.decode())

    if len(sys.argv) != 3:
        print(f"usage: python3 {sys.argv[0]} HOST PORT")
        print()
        print("contoh:")
        print(f"  python3 {sys.argv[0]} chall.host 443")
        return

    host = sys.argv[1]
    port = int(sys.argv[2])

    solve_remote(host, port, passphrase)


if __name__ == "__main__":
    main()
