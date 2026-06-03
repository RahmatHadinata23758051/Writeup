#!/usr/bin/env sage -python
import base64
import concurrent.futures
import json
import re
from collections import defaultdict

import requests
from sage.all import GF, PolynomialRing


BASE = "https://aes.chals.cyberjousting.com"
USERNAME_LEN = 98
WORKERS = 24


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * ((4 - len(s) % 4) % 4))


def b64e(b):
    return base64.urlsafe_b64encode(b).decode()


def make_plain(uid, username, role="user"):
    return json.dumps(
        {"id": uid, "role": role, "username": username},
        separators=(",", ":"),
    ).encode()


def get_cookie(i):
    username = "A" * (USERNAME_LEN - 2) + f"{i:02d}"
    session = requests.Session()
    r = session.post(
        BASE + "/api/register",
        data={"username": username, "password": "x"},
        allow_redirects=False,
        timeout=15,
    )
    cookie = session.cookies.get("session")
    if cookie is None:
        m = re.search(r"session=([^;]+)", r.headers.get("set-cookie", ""))
        cookie = m.group(1) if m else None
    r = session.get(BASE + "/", timeout=15)
    return {
        "raw": b64d(cookie),
        "uid": r.headers["X-User-ID"],
        "username": username,
    }


RED = 0xE1000000000000000000000000000000


def gmul(x, y):
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ RED
        else:
            v >>= 1
    return z


def ghash_blocks(ct):
    blocks = [ct[i : i + 16] for i in range(0, len(ct), 16)]
    if blocks and len(blocks[-1]) < 16:
        blocks[-1] += b"\0" * (16 - len(blocks[-1]))
    blocks.append((0).to_bytes(8, "big") + (len(ct) * 8).to_bytes(8, "big"))
    return [int.from_bytes(block, "big") for block in blocks]


def ghash(h, ct):
    y = 0
    for x in ghash_blocks(ct):
        y = gmul(y ^ x, h)
    return y


def recover_h(group):
    pbin = PolynomialRing(GF(2), "x")
    x = pbin.gen()
    field = GF(2**128, name="a", modulus=x**128 + x**7 + x**2 + x + 1)
    ring = PolynomialRing(field, "z")
    z = ring.gen()

    def elem(n):
        v = 0
        for i in range(128):
            if (n >> (127 - i)) & 1:
                v |= 1 << i
        return field.from_integer(v)

    def unelem(e):
        v = int(e.to_integer())
        n = 0
        for i in range(128):
            if (v >> i) & 1:
                n |= 1 << (127 - i)
        return n

    a, b, c = group[:3]
    xs_a = ghash_blocks(a["ct"])
    xs_b = ghash_blocks(b["ct"])
    poly = ring(0)
    degree = len(xs_a)
    for i, (xa, xb) in enumerate(zip(xs_a, xs_b)):
        delta = xa ^ xb
        if delta:
            poly += elem(delta) * z ** (degree - i)
    poly += elem(int.from_bytes(a["tag"], "big") ^ int.from_bytes(b["tag"], "big"))

    for root, _ in poly.roots():
        h = unelem(root)
        s = int.from_bytes(a["tag"], "big") ^ ghash(h, a["ct"])
        if (
            s ^ ghash(h, b["ct"]) == int.from_bytes(b["tag"], "big")
            and s ^ ghash(h, c["ct"]) == int.from_bytes(c["tag"], "big")
        ):
            return h, s
    raise RuntimeError("no valid GHASH key found")


def main():
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        items = list(ex.map(get_cookie, range(WORKERS)))

    groups = defaultdict(list)
    for item in items:
        groups[item["raw"][:12]].append(item)
    nonce, group = max(groups.items(), key=lambda kv: len(kv[1]))
    if len(group) < 3:
        raise RuntimeError("not enough same-nonce cookies; run again")

    for item in group:
        item["ct"] = item["raw"][12:-16]
        item["tag"] = item["raw"][-16:]
        item["pt"] = make_plain(item["uid"], item["username"])
        assert len(item["pt"]) == len(item["ct"])

    h, s = recover_h(group)
    source = group[0]
    target = make_plain(source["uid"], "owned", role="admin")
    keystream = bytes(p ^ c for p, c in zip(source["pt"], source["ct"]))
    forged_ct = bytes(p ^ k for p, k in zip(target, keystream))
    forged_tag = (s ^ ghash(h, forged_ct)).to_bytes(16, "big")
    forged_cookie = b64e(nonce + forged_ct + forged_tag)

    r = requests.get(BASE + "/", cookies={"session": forged_cookie}, timeout=15)
    print(r.text)
    flags = re.findall(r"[A-Za-z0-9_]+\\{[^}]+\\}", r.text)
    if flags:
        print(flags[0])


if __name__ == "__main__":
    main()
