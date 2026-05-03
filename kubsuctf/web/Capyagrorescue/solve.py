#!/usr/bin/env python3
import sys
import uuid

import requests


BASE_URL = "http://45.146.165.92"
API_KEY = "test_key_123"
SAFE_TEMP = 24
SAFE_HUMIDITY = 60


def main() -> int:
    session = requests.Session()

    username = f"u{uuid.uuid4().hex[:8]}"
    email = f"{username}@a.a"
    password = "Passw0rd!"

    register_response = session.post(
        f"{BASE_URL}/register",
        data={"username": username, "email": email, "password": password},
        timeout=10,
    )
    register_response.raise_for_status()

    login_response = session.post(
        f"{BASE_URL}/login",
        data={"username": username, "password": password},
        timeout=10,
        allow_redirects=True,
    )
    login_response.raise_for_status()

    if "/dashboard" not in login_response.url:
        print("login failed", file=sys.stderr)
        return 1

    headers = {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json",
    }

    sectors_response = session.get(
        f"{BASE_URL}/api/capyagro/sectors",
        headers=headers,
        timeout=10,
    )
    sectors_response.raise_for_status()
    sectors = sectors_response.json().get("sectors", [])
    if not sectors:
        print("no CapyAgro sectors returned", file=sys.stderr)
        return 1

    sector_id = sectors[0]["id"]
    adjust_response = session.post(
        f"{BASE_URL}/api/sector/{sector_id}/adjust",
        headers=headers,
        json={"temp": SAFE_TEMP, "humidity": SAFE_HUMIDITY},
        timeout=10,
    )
    adjust_response.raise_for_status()

    payload = adjust_response.json()
    flag = payload.get("flag")
    if not flag:
        print("flag not found in response", file=sys.stderr)
        print(payload, file=sys.stderr)
        return 1

    print(flag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
